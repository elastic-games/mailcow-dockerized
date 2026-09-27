import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from action_policy import UNITS, PolicyError
from control_protocol import Dispatcher, Reply, CallerDenied
from control_server import ControlServer
from peer_policy import PeerDenied
from replication_auth import ReplicaAuth


class FixtureRuntime:
    def __init__(self): self.calls = []; self.messages = []
    def state(self, unit): return {'Running': True, 'StartedAt': '2026-09-27T00:00:00Z', 'Status': 'running'}
    def execute(self, plan, request): self.calls.append(plan); return Reply.json({'type': 'success', 'msg': 'command completed successfully'})
    def broadcast(self, plan, message): self.messages.append(message)
    def host_stats(self): return {'cpu': {'cores': 2, 'usage': 0}, 'memory': {'total': 1024, 'usage': 0, 'swap': [0, 0, 0, 0, 0]}, 'uptime': 1, 'system_time': '27.09.2026 00:00:00', 'architecture': 'x86_64'}
    def stats_history(self, unit, identifier): return []


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.runtime = FixtureRuntime()
        self.dispatcher = Dispatcher(self.runtime, 'fixture', {service: '192.0.2.1' for service in UNITS})

    def target(self, service, action):
        identifier = next(identifier for identifier, name in self.dispatcher.ids.items() if name == service)
        return '/containers/' + identifier + '/' + action

    def test_legacy_discovery_and_id_binding(self):
        result = json.loads(self.dispatcher.dispatch('php', 'GET', '/containers/json?all=true', {}).body)
        self.assertEqual(len(result), 18)
        for identifier, value in result.items():
            self.assertEqual(identifier, value['Id']); self.assertEqual(value['Config']['Labels']['com.docker.compose.project'], 'fixture')
            self.assertNotIn('Env', value['Config'])
        result = json.loads(self.dispatcher.dispatch('php', 'GET', '/containers/' + '0' * 64 + '/json', {}).body)
        self.assertEqual(result, {'type': 'danger', 'msg': 'no container found'})

    def test_actual_caller_permissions_and_forged_identity(self):
        for caller, service, action, body in [('acme', 'dovecot-mailcow', 'restart', {}), ('dovecot', 'rspamd-mailcow', 'restart', {}), ('watchdog', 'php-fpm-mailcow', 'top', {})]:
            self.assertEqual(self.dispatcher.dispatch(caller, 'POST', self.target(service, action), body).status, 200)
        for caller, service, action, body in [('acme', 'mysql-mailcow', 'stop', {'caller': 'php'}), ('dovecot', 'postfix-mailcow', 'restart', {'caller': 'php'}), ('watchdog', 'dovecot-mailcow', 'exec', {'cmd': 'maildir', 'task': 'cleanup', 'maildir': 'fixture.invalid/user', 'caller': 'php'})]:
            with self.assertRaises(CallerDenied): self.dispatcher.dispatch(caller, 'POST', self.target(service, action), body)
        self.assertEqual(len(self.runtime.calls), 3)

    def test_broadcast_only_actual_upstream_families(self):
        message = {'api_call': 'container_post', 'container_name': 'dovecot-mailcow', 'post_action': 'exec', 'request': {'cmd': 'maildir', 'task': 'cleanup', 'maildir': 'fixture.invalid/user'}}
        self.assertEqual(json.loads(self.dispatcher.dispatch('php', 'POST', '/broadcast', message).body), True)
        with self.assertRaises(CallerDenied): self.dispatcher.dispatch('watchdog', 'POST', '/broadcast', message)
        message['request'] = {'cmd': 'system', 'task': 'fts_rescan', 'all': True}
        with self.assertRaises(PolicyError): self.dispatcher.dispatch('php', 'POST', '/broadcast', message)

    def test_real_unix_http_and_framing(self):
        # Parser test injects identity. Separate Linux rehearsal proves actual
        # kernel identity against two UID0 units sharing the same socket bind.
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'control.sock'
            server = ControlServer(path, self.dispatcher, lambda connection, registry: 'watchdog')
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            def send(raw):
                with socket.socket(socket.AF_UNIX) as client:
                    client.settimeout(3); client.connect(str(path)); client.sendall(raw); client.shutdown(socket.SHUT_WR)
                    data = bytearray()
                    while part := client.recv(65536): data.extend(part)
                    return bytes(data)
            try:
                good = send(b'GET /containers/json HTTP/1.0\r\nX-Caller: php\r\n\r\n')
                self.assertIn(b'200 OK', good); self.assertEqual(len(json.loads(good.split(b'\r\n\r\n')[1])), 18)
                denied = send(('POST ' + self.target('mysql-mailcow', 'stop') + ' HTTP/1.0\r\nX-Caller: php\r\n\r\n').encode())
                self.assertIn(b'403 Forbidden', denied)
                for headers, body in [(b'Content-Length: 2\r\nContent-Length: 2', b'{}'), (b'Transfer-Encoding: chunked', b'0\r\n\r\n'), (b'Content-Length: 999999', b'{}'), (b'Content-Length: 3', b'{}'), (b'Content-Length: 2', b'[]')]:
                    response = send(b'POST /broadcast HTTP/1.0\r\n' + headers + b'\r\n\r\n' + body)
                    self.assertIn(b'400 Bad Request', response)
                server.peer_authorizer = lambda *_: (_ for _ in ()).throw(PeerDenied('test'))
                self.assertIn(b'403 Forbidden', send(b'GET /health HTTP/1.0\r\n\r\n'))
            finally: server.shutdown(); server.server_close(); thread.join()

    def test_signed_replica_payload_expiry_scope_and_tampering(self):
        auth = ReplicaAuth('origin-fixture', b'x' * 32, {'origin-fixture': b'x' * 32}, 'fixture', now=lambda: 1000)
        message = {'api_call': 'container_post', 'container_name': 'dovecot-mailcow', 'post_action': 'exec', 'request': {'cmd': 'maildir', 'task': 'move', 'old_maildir': 'fixture.invalid/old', 'new_maildir': 'fixture.invalid/new'}}
        signed = auth.sign(message); plan, base, nonce = auth.verify(signed)
        self.assertEqual(base, message); self.assertEqual(plan.operation, 'exec__maildir__move')
        for altered in [message, {**signed, 'native_mac': '0' * 64}, {**signed, 'container_name': 'postfix-mailcow'}, {**signed, 'native_auth': {**signed['native_auth'], 'project': 'other'}}, {**signed, 'native_auth': {**signed['native_auth'], 'origin': 'unknown'}}]:
            with self.assertRaises(PolicyError): auth.verify(altered)
        expired = ReplicaAuth('origin-fixture', b'x' * 32, {'origin-fixture': b'x' * 32}, 'fixture', now=lambda: 1121)
        with self.assertRaises(PolicyError): expired.verify(signed)


if __name__ == '__main__': unittest.main(verbosity=2)
