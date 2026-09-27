from pathlib import Path
import ctypes
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from action_policy import compile_action
from maildir_transaction import MaildirTransaction, rename_no_replace


@unittest.skipUnless(sys.platform == 'linux', 'Actual Linux renameat2 required')
class MaildirTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.mail, self.index = Path(self.temp.name) / 'mail', Path(self.temp.name) / 'index'
        self.mail.mkdir(); self.index.mkdir(); (self.mail / 'fixture.invalid').mkdir()
        self.old = self.mail / 'fixture.invalid/old'; self.old.mkdir(); (self.old / 'new-arrival').write_text('synthetic')
        (self.index / 'old@fixture.invalid').mkdir()
        self.transaction = MaildirTransaction(self.mail, self.index)
    def tearDown(self): self.temp.cleanup()
    def plan(self, task, **fields): return compile_action('dovecot-mailcow', 'exec', {'cmd': 'maildir', 'task': task, **fields})

    def test_move_and_cleanup_preserve_mail_and_index(self):
        before = self.old.stat().st_ino
        self.transaction.execute(self.plan('move', old_maildir='fixture.invalid/old', new_maildir='fixture.invalid/new'))
        self.assertEqual((self.mail / 'fixture.invalid/new').stat().st_ino, before)
        self.assertTrue((self.index / 'new@fixture.invalid_index').is_dir())
        self.transaction.execute(self.plan('cleanup', maildir='fixture.invalid/new'))
        self.assertFalse((self.mail / 'fixture.invalid/new').exists())
        self.assertEqual(len(list((self.mail / '_garbage').iterdir())), 1)

    def test_symlink_and_existing_destination_never_escape_or_merge(self):
        outside = Path(self.temp.name) / 'outside'; outside.mkdir(); (outside / 'secret').write_text('keep')
        (self.mail / 'evil.invalid').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError): self.transaction.execute(self.plan('cleanup', maildir='evil.invalid/secret'))
        self.assertEqual((outside / 'secret').read_text(), 'keep')
        target = self.mail / 'fixture.invalid/new'; target.mkdir()
        with self.assertRaises(FileExistsError): self.transaction.execute(self.plan('move', old_maildir='fixture.invalid/old', new_maildir='fixture.invalid/new'))
        self.assertTrue(self.old.exists()); self.assertEqual(list(target.iterdir()), [])

    def test_crash_after_first_rename_recovers_exact_second_inode(self):
        name = 'synthetic-crash.json'
        moves = [{'sourceRoot': 'mail', 'source': ['fixture.invalid', 'old'], 'destRoot': 'mail', 'dest': ['fixture.invalid', 'new'], 'inode': [self.old.stat().st_dev, self.old.stat().st_ino], 'complete': False},
                 {'sourceRoot': 'index', 'source': ['old@fixture.invalid'], 'destRoot': 'index', 'dest': ['new@fixture.invalid_index'], 'inode': [(self.index / 'old@fixture.invalid').stat().st_dev, (self.index / 'old@fixture.invalid').stat().st_ino], 'complete': False}]
        journal = {'moves': moves, 'complete': False}; self.transaction.save(name, journal)
        self.old.rename(self.mail / 'fixture.invalid/new')
        self.transaction.apply(name, journal)
        self.assertTrue(journal['complete']); self.assertTrue((self.index / 'new@fixture.invalid_index').is_dir())
        with self.assertRaises(ValueError): self.transaction.apply(name, {'moves': [{**moves[0], 'dest': ['../../escape']}], 'complete': False})

    @unittest.skipUnless(os.uname().machine == 'x86_64', 'Reviewed amd64 musl fallback')
    def test_real_kernel_syscall_without_libc_wrapper_remains_no_replace(self):
        real_library = ctypes.CDLL(None, use_errno=True)
        class WithoutWrapper:
            syscall = real_library.syscall
        target = self.mail / 'fixture.invalid/new'; target.mkdir()
        with patch('maildir_transaction.ctypes.CDLL', return_value=WithoutWrapper()):
            with self.assertRaises(FileExistsError): self.transaction.execute(self.plan('move', old_maildir='fixture.invalid/old', new_maildir='fixture.invalid/new'))
            self.assertTrue(self.old.exists()); self.assertEqual(list(target.iterdir()), [])
            target.rmdir()
            self.transaction.execute(self.plan('move', old_maildir='fixture.invalid/old', new_maildir='fixture.invalid/new'))
            self.assertTrue((target / 'new-arrival').is_file())


if __name__ == '__main__': unittest.main(verbosity=2)
