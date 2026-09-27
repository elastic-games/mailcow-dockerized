import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from prepare_fixture_stack import image_path, verified_archive, environment_rows, write_environment
from stack_units import command, quote, render
from service_executor import Profile
from action_policy import UNITS


class StackPreparationTests(unittest.TestCase):
    def test_absolute_image_symlinks_never_select_host_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'var').mkdir(); (root / 'run').mkdir()
            (root / 'var/run').symlink_to('/run'); (root / 'run/store').mkdir()
            self.assertEqual(image_path(root, '/var/run/store'), root / 'run/store')
            (root / 'run/relative').symlink_to('../var')
            self.assertEqual(image_path(root, '/run/relative/run/store'), root / 'run/store')
            (root / 'cycle').symlink_to('/cycle')
            with self.assertRaises(ValueError): image_path(root, '/cycle')

    def test_sealed_archive_cannot_change_after_verified_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); source = base / 'public'; source.write_bytes(b'fixture archive')
            pin = {'archiveBytes': source.stat().st_size, 'archiveSHA256': hashlib.sha256(source.read_bytes()).hexdigest()}
            target = verified_archive(source, base / 'sealed', pin)
            source.write_bytes(b'altered'); self.assertEqual(target.read_bytes(), b'fixture archive')
            with self.assertRaises(ValueError): verified_archive(source, base / 'rejected', pin)
            symlink = base / 'link'; symlink.symlink_to(source)
            with self.assertRaises(OSError): verified_archive(symlink, base / 'not-followed', pin)

    def test_packaged_numeric_user_keeps_its_supplementary_groups(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'etc').mkdir()
            (root / 'etc/passwd').write_text('root:x:0:0::/root:/bin/sh\nmemcache:x:11211:11211::/home:/bin/sh\n')
            (root / 'etc/group').write_text('root:x:0:root\nmemcache:x:11211:memcache\nmailread:x:2222:memcache\n')
            profile = Profile(UNITS['memcached-mailcow'], root, Path('/run/netns/synthetic'), (), ())
            self.assertEqual(profile.account('11211'), ('11211', '11211', '2222,11211'))
            unit = render('memcached-mailcow', profile,
                          {'imageUser':'11211', 'workingDirectory':'/', 'entrypoint':['memcached'], 'command':[]},
                          {'entrypointTemplate':None, 'commandTemplate':None})
            self.assertIn('"--uid" "11211" "--gid" "11211" "--groups" "2222,11211"', unit)

    def test_exact_compose_defaults_and_literal_unit_arguments(self):
        values = environment_rows({'environment': ['A=${A:-fallback}', 'B=${B-default}', 'EMPTY=${EMPTY}', 'PORT=9000']}, {'A':'', 'B':''})
        self.assertEqual(values, {'A':'fallback', 'B':'', 'EMPTY':'', 'PORT':'9000'})
        self.assertEqual(command({'entrypoint':['entry'], 'command':['original']}, {'entrypointTemplate':None,'commandTemplate':'one "two words"'}), ['entry','one','two words'])
        self.assertEqual(quote('$MASTER 100%'), '"$$MASTER 100%%"')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'environment'
            with self.assertRaises(ValueError): write_environment(path, {'VALUE':'bad\nSECOND=injected'})
            with self.assertRaises(ValueError): write_environment(path, {'VALUE\nSECOND':'injected'})


if __name__ == '__main__': unittest.main(verbosity=2)
