"""Recoverable two-root mailbox/index renames, run inside Dovecot as vmail.

All traversal remains descriptor-relative and no-symlink. Linux renameat2 with
RENAME_NOREPLACE rejects a concurrent destination instead of merging mailboxes.
The protected per-mailstore journal records inode identity before each move.
Existing upstream _index destination spelling is preserved deliberately.
"""
from contextlib import ExitStack
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import stat
import sys
import time
import uuid
from action_policy import compile_action
from rooted_paths import rooted_directory, DIRECTORY_FLAGS


def rename_no_replace(source_fd, source, dest_fd, dest):
    library = ctypes.CDLL(None, use_errno=True)
    arguments = (ctypes.c_int(source_fd), ctypes.c_char_p(os.fsencode(source)),
                 ctypes.c_int(dest_fd), ctypes.c_char_p(os.fsencode(dest)), ctypes.c_uint(1))
    try:
        function = library.renameat2
        function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        function.restype = ctypes.c_int
        result = function(*arguments)
    except AttributeError:
        # The exact pinned Alpine musl root lacks the libc renameat2 wrapper.
        # Use the SAME kernel no-replace primitive, never a check+rename race.
        # Exported runtime is Linux amd64 only; reject every other ABI before
        # mutation. Linux arch/x86/entry/syscalls/syscall_64.tbl assigns 316.
        if sys.platform != 'linux' or os.uname().machine != 'x86_64' or ctypes.sizeof(ctypes.c_void_p) != 8:
            raise RuntimeError('No reviewed no-replace rename ABI available') from None
        function = library.syscall
        function.argtypes = [ctypes.c_long]; function.restype = ctypes.c_long
        result = function(ctypes.c_long(316), *arguments)
    if result:
        value = ctypes.get_errno()
        raise OSError(value, os.strerror(value))


class MaildirTransaction:
    def __init__(self, mail=Path('/var/vmail'), index=Path('/var/vmail_index')):
        self.roots = {'mail': Path(mail), 'index': Path(index)}
        self.journal = self.roots['mail'] / '.native-transactions'
        self.journal.mkdir(mode=0o700, exist_ok=True)
        info = self.journal.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise PermissionError('Owned protected maildir journal required')

    def save(self, name, value):
        with rooted_directory(self.journal, ()) as directory:
            temporary = '.write-' + uuid.uuid4().hex
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            try:
                with os.fdopen(fd, 'w') as file: json.dump(value, file); file.flush(); os.fsync(file.fileno())
                os.rename(temporary, name, src_dir_fd=directory, dst_dir_fd=directory); os.fsync(directory)
            finally:
                try: os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError: pass

    def load(self, directory, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > 16384:
                raise PermissionError('Owned bounded maildir journal required')
            with os.fdopen(fd, 'r', closefd=False) as file: return json.load(file)
        finally: os.close(fd)

    @staticmethod
    def identity(directory, name):
        if not isinstance(name, str) or not name or name in ('.', '..') or '/' in name or '\\' in name or '\x00' in name:
            raise ValueError('One no-symlink directory name required')
        try: fd = os.open(name, DIRECTORY_FLAGS, dir_fd=directory)
        except FileNotFoundError: return None
        try:
            info = os.fstat(fd)
            return [info.st_dev, info.st_ino]
        finally: os.close(fd)

    def apply(self, name, journal):
        if not isinstance(journal, dict) or set(journal) != {'moves', 'complete'} or not isinstance(journal['moves'], list) or len(journal['moves']) > 2:
            raise ValueError('Invalid bounded transaction journal')
        for move in journal['moves']:
            if set(move) != {'sourceRoot', 'source', 'destRoot', 'dest', 'inode', 'complete'} or move['sourceRoot'] not in self.roots or move['destRoot'] not in self.roots:
                raise ValueError('Invalid transaction roots')
            if not isinstance(move['inode'], list) or len(move['inode']) != 2 or any(type(value) is not int or value < 0 for value in move['inode']):
                raise ValueError('Invalid transaction inode identity')
            for path in (move['source'], move['dest']):
                if not isinstance(path, (tuple, list)) or not 1 <= len(path) <= 2 or any(not isinstance(part, str) or not part or part in ('.', '..') or '/' in part or '\\' in part or '\x00' in part for part in path):
                    raise ValueError('Invalid transaction path components')
            with ExitStack() as stack:
                source = stack.enter_context(rooted_directory(self.roots[move['sourceRoot']], tuple(move['source'][:-1])))
                dest = stack.enter_context(rooted_directory(self.roots[move['destRoot']], tuple(move['dest'][:-1])))
                before = self.identity(source, move['source'][-1]); after = self.identity(dest, move['dest'][-1])
                if before == move['inode'] and after is None:
                    rename_no_replace(source, move['source'][-1], dest, move['dest'][-1]); os.fsync(source); os.fsync(dest)
                elif before is None and after == move['inode']: pass  # Crash after rename, before journal update.
                else: raise RuntimeError('Maildir transaction conflict; preserve journal for recovery')
                move['complete'] = True; self.save(name, journal)
        journal['complete'] = True; self.save(name, journal)

    def execute(self, plan):
        if plan.primitive != 'maildir-transaction': raise ValueError('Maildir plan required')
        with rooted_directory(self.journal, ()) as directory:
            lease = os.open('lease', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            try:
                info = os.fstat(lease)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o077:
                    raise PermissionError('Owned maildir lock required')
                fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                for name in os.listdir(directory):
                    if name.endswith('.json'):
                        journal = self.load(directory, name)
                        if not journal['complete']: self.apply(name, journal)
                        os.unlink(name, dir_fd=directory); os.fsync(directory)
                fields = dict(plan.fields); cleanup = plan.operation == 'exec__maildir__cleanup'
                old = fields['maildir'] if cleanup else fields['old_maildir']
                parts = tuple(old.split('/')); index = parts[1] + '@' + parts[0]
                nonce = str(int(time.time())) + '_' + uuid.uuid4().hex
                if cleanup:
                    garbage = self.roots['mail'] / '_garbage'; garbage.mkdir(mode=0o700, exist_ok=True)
                    with rooted_directory(self.roots['mail'], ('_garbage',)): pass
                    dest = ('_garbage', nonce); index_dest = ('_garbage', nonce + '_index')
                else:
                    dest = tuple(fields['new_maildir'].split('/'))
                    index_dest = (dest[1] + '@' + dest[0] + '_index',)
                moves = []
                for root, source, target_root, target in (('mail', parts, 'mail', dest), ('index', (index,), 'mail' if cleanup else 'index', index_dest)):
                    try:
                        with rooted_directory(self.roots[root], source[:-1]) as parent:
                            inode = self.identity(parent, source[-1])
                    except FileNotFoundError: inode = None
                    if inode is not None:
                        with rooted_directory(self.roots[target_root], target[:-1]) as parent:
                            if self.identity(parent, target[-1]) is not None: raise FileExistsError('Maildir destination exists')
                        moves.append({'sourceRoot': root, 'source': source, 'destRoot': target_root, 'dest': target, 'inode': inode, 'complete': False})
                name = uuid.uuid4().hex + '.json'; journal = {'moves': moves, 'complete': False}
                self.save(name, journal); self.apply(name, journal)
                os.unlink(name, dir_fd=directory); os.fsync(directory)
            finally: os.close(lease)


if __name__ == '__main__':
    request = json.loads(sys.stdin.buffer.read(65537))
    plan = compile_action('dovecot-mailcow', 'exec', request)
    MaildirTransaction().execute(plan)
