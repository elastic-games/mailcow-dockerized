import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('rooted',ROOT/'native/rooted_paths.py')
module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class RootedPathTests(unittest.TestCase):
    def test_root_and_parent_child_symlinks_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);root=base/'mail';root.mkdir();outside=base/'outside';outside.mkdir()
            (root/'example.test').mkdir();(root/'example.test'/'fixture').mkdir()
            with module.rooted_directory(root,('example.test','fixture')) as fd:
                self.assertTrue(os.fstat(fd).st_ino)
            (base/'root-link').symlink_to(root,target_is_directory=True)
            (root/'domain-link').symlink_to(outside,target_is_directory=True)
            (root/'example.test'/'user-link').symlink_to(outside,target_is_directory=True)
            for candidate,parts in [(base/'root-link',('example.test','fixture')),(root,('domain-link',)),(root,('example.test','user-link'))]:
                with self.assertRaises(OSError):
                    with module.rooted_directory(candidate,parts): pass
            for parts in [('../outside',),('..',),('example.test','/absolute')]:
                with self.assertRaises(ValueError):
                    with module.rooted_directory(root,parts): pass


if __name__=='__main__':unittest.main(verbosity=2)
