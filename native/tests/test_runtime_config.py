import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from action_policy import UNITS
from runtime_config import addresses, canonical_path, load, protected_directory, protected_file, CONTROL_PEERS
from canonical_store import CanonicalStore
from service_executor import Executor
from redis_wire import Redis


class RuntimeBoundaryTests(unittest.TestCase):
    def test_closed_private_addresses_and_no_symlink_bind(self):
        result = addresses('172.30.66.0/24')
        self.assertEqual(set(result), set(UNITS)); self.assertEqual(len(set(result.values())), 18)
        self.assertEqual(result['dovecot-mailcow'], '172.30.66.250')
        for invalid in ('8.8.8.0/24', '172.30.66.4/24', '172.30.66.0/16'):
            with self.assertRaises(ValueError): addresses(invalid)

    @unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'Real protected ancestry requires Linux root')
    def test_bind_roots_and_ancestors_are_stable(self):
        with tempfile.TemporaryDirectory(dir='/run') as directory:
            root = Path(directory); (root / 'safe').mkdir(); (root / 'safe/config').write_text('fixture')
            self.assertEqual(canonical_path(root, 'safe/config'), root / 'safe/config')
            (root / 'escaped').symlink_to(root / 'safe', target_is_directory=True)
            for source in ('../safe', '/safe', 'escaped/config'):
                with self.assertRaises((ValueError, OSError)): canonical_path(root, source)
            protected_directory(root)
            secret = root / 'operator.json'; secret.write_text('{}'); secret.chmod(0o600)
            self.assertEqual(protected_file(secret), b'{}')
            # A root-owned final 0700/0600 leaf cannot repair a writable or
            # application-owned ancestor. App ownership is legal only at the
            # whole bind leaf, whose parent is stable and never exposed writable.
            (root / 'safe').chmod(0o777)
            with self.assertRaises(PermissionError): canonical_path(root, 'safe/config')
            root.chmod(0o777)
            with self.assertRaises(PermissionError): protected_file(secret)
            root.chmod(0o700); (root / 'safe').chmod(0o755)
            os.chown(root / 'safe', 999, 999)
            self.assertEqual(canonical_path(root, 'safe'), root / 'safe')
            with self.assertRaises(PermissionError): canonical_path(root, 'safe/config')
            with self.assertRaises(PermissionError): protected_directory(root / 'safe')

    def test_host_password_write_cannot_follow_service_parent_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); outside = root / 'outside'; outside.mkdir()
            protected = outside / 'password.inc'; protected.write_text('unrelated fixture must remain')
            canonical = root / 'canonical'; canonical.mkdir(); (canonical / 'config').symlink_to(outside, target_is_directory=True)
            executor = object.__new__(Executor); executor.store = SimpleNamespace(root=canonical)
            unit = UNITS['rspamd-mailcow']; executor.password_files = {unit: canonical / 'config/password.inc'}
            executor.command = lambda *_: (0, b'$2$aaaa$bbbb')
            with self.assertRaises(OSError): executor.password(SimpleNamespace(unit=unit), {'raw': 'synthetic'})
            self.assertEqual(protected.read_text(), 'unrelated fixture must remain')
            (canonical / 'config').unlink(); (canonical / 'config').mkdir()
            destination = canonical / 'config/password.inc'; destination.write_text('fixture old'); destination.chmod(0o600)
            with patch('service_executor.bounded', return_value=(0, b'')):
                result = executor.password(SimpleNamespace(unit=unit), {'raw': 'synthetic'})
            self.assertIn(b'success', result.body)
            self.assertEqual(destination.read_text(), 'enable_password = "$2$aaaa$bbbb";\n')
            self.assertEqual(os.stat(destination).st_mode & 0o777, 0o600)
            self.assertEqual(sorted(path.name for path in destination.parent.iterdir()), ['password.inc'])

    def test_failed_redis_auth_closes_both_resources(self):
        stream = io.BytesIO(b'-ERR synthetic authentication failure\r\n')
        class Connection:
            closed = False
            def makefile(self, *_): return stream
            def sendall(self, *_): pass
            def close(self): self.closed = True
        connection = Connection()
        with patch('redis_wire.socket.create_connection', return_value=connection):
            with self.assertRaises(RuntimeError): Redis(('127.0.0.1', 6379), b'fixture').connect()
        self.assertTrue(stream.closed); self.assertTrue(connection.closed)

    @unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'Protected operator load requires off-host Linux root')
    def test_protected_complete_config_keeps_credentials_outside_bindings(self):
        with tempfile.TemporaryDirectory(dir='/run') as directory:
            base = Path(directory); canonical = base / 'canonical'; release = base / 'release'
            for root in (canonical, release): root.mkdir(mode=0o700)
            operator = canonical / 'operator'; operator.mkdir(mode=0o700)
            environment = operator / 'environment'; environment.mkdir(mode=0o700)
            store = CanonicalStore(canonical); store.activate('native', lambda: [])
            for service in UNITS:
                (release / 'roots' / service / 'rootfs').mkdir(parents=True)
                path = environment / service; path.write_text('MASTER=fixture\n'); path.chmod(0o600)
            config = {'schema': 1, 'mode': 'offhost-rehearsal', 'project': 'fixture', 'canonicalRoot': str(canonical),
                      'releaseRoot': str(release), 'networkTag': 'aaaaaaaa', 'ipv4Network': '172.30.66.0/24',
                      'profiles': {service: {'readOnly': [], 'writable': []} for service in UNITS}, 'replication': {'enabled': False}}
            path = operator / 'runtime.json'; path.write_text(json.dumps(config)); path.chmod(0o600)
            _, _, profiles, network = load(path)
            self.assertEqual(len(profiles), 18); self.assertEqual(set(network), set(UNITS))
            for service, unit in UNITS.items():
                profile = profiles[unit]
                self.assertIn((store.control, '/run/mailcow-lease'), profile.readonly)
                socket_bound = (operator / 'control.sock', '/run/mailcow-control.sock') in profile.readonly
                self.assertEqual(socket_bound, service in CONTROL_PEERS)
                self.assertFalse(any(source == operator for source, _ in (*profile.readonly, *profile.writable)))
            config['profiles']['dovecot-mailcow']['readOnly'] = [{'source': 'operator', 'destination': '/exposed'}]
            path.write_text(json.dumps(config))
            with self.assertRaises(PermissionError): load(path)
            config['profiles']['dovecot-mailcow']['readOnly'] = []
            (canonical / 'data').mkdir(); (canonical / 'data/web').mkdir(); (canonical / 'data/web/cache').mkdir()
            config['profiles']['php-fpm-mailcow']['writable'] = [{'source': 'data/web', 'destination': '/web'}]
            config['profiles']['nginx-mailcow']['readOnly'] = [{'source': 'data/web/cache', 'destination': '/cache'}]
            path.write_text(json.dumps(config))
            with self.assertRaises(PermissionError): load(path)
            # Whole-root shared read-only binding preserves the normal PHP /
            # nginx web volume without trusting a writable ancestor path.
            config['profiles']['nginx-mailcow']['readOnly'][0]['source'] = 'data/web'
            path.write_text(json.dumps(config)); load(path)
            config['mode'] = 'production'
            path.write_text(json.dumps(config))
            with self.assertRaises(PermissionError): load(path)


if __name__ == '__main__': unittest.main(verbosity=2)
