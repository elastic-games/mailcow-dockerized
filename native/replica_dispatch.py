"""Protected durable replay journal for the narrow distributed maildir adapter.

Claim is written before action. A crash in-flight is retained as uncertain and
blocks automatic re-execution, allowing the maildir transaction journal to be
recovered explicitly rather than repeating a rename/delete. Pubsub does not
promise delivery; the legacy contract also has no acknowledgement/retry.
"""
import json
import os
from pathlib import Path
import stat
import threading
from replication_auth import canonical
from action_policy import PolicyError


class ReplicaDispatch:
    def __init__(self, auth, ledger, redis, execute, enabled=False, replicas_accepted=False):
        self.auth, self.ledger, self.redis, self.execute = auth, Path(ledger), redis, execute
        self.enabled, self.accepted, self.lock = enabled, replicas_accepted, threading.RLock()
        info = self.ledger.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise PermissionError('Root-owned protected replica ledger required')
        if enabled and not replicas_accepted: raise PermissionError('Every configured replica must pass signed adapter acceptance')

    def prune_completed(self):
        # Every reader and atomic completion replacement uses the same lock.
        with self.lock:
            self._prune_completed()

    def _prune_completed(self):
        # Authentic envelopes expire after 120s. Keep completed replay records
        # for 240s and never prune uncertain/incomplete records automatically.
        for path in self.ledger.iterdir():
            # A crash before atomic replacement can leave a partial temporary
            # completion file. The original incomplete claim remains blocking;
            # only committed records participate in pruning. Temporary files
            # still count toward the bounded directory maintenance threshold.
            if path.name.startswith('.completion-'): continue
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > 1024:
                    raise PermissionError('Protected bounded replay record required')
                with os.fdopen(fd, 'r', closefd=False) as file: record = json.load(file)
            finally: os.close(fd)
            if record.get('complete') is True and type(record.get('issued')) is int and self.auth.now() - record['issued'] > 240:
                path.unlink()

    def receive(self, raw):
        message = json.loads(raw)
        plan, base, nonce = self.auth.verify(message)
        if not self.enabled: raise PolicyError('Replication is disabled')
        # Filename is hash of authenticated nonce; no caller path selection.
        import hashlib
        name = hashlib.sha256(nonce.encode()).hexdigest() + '.json'
        with self.lock:
            self.prune_completed()
            if len(list(self.ledger.iterdir())) >= 4096 and not (self.ledger / name).exists():
                raise RuntimeError('Replica journal maintenance required')
            try: fd = os.open(self.ledger / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            except FileExistsError: return False
            with os.fdopen(fd, 'wb') as file: file.write(canonical({'nonce': nonce, 'issued': message['native_auth']['issued'], 'complete': False})); file.flush(); os.fsync(file.fileno())
            directory = os.open(self.ledger, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try: os.fsync(directory)
            finally: os.close(directory)
        reply = self.execute(plan, base['request'])
        if reply.status != 200 or json.loads(reply.body).get('type') != 'success':
            raise RuntimeError('Replica action needs journal recovery')
        # Keep replay id after completion; root operator may prune records older
        # than authenticated expiry only after confirming no uncertain action.
        import tempfile
        with self.lock:
            fd, temp = tempfile.mkstemp(dir=self.ledger, prefix='.completion-')
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, 'wb') as file: file.write(canonical({'nonce': nonce, 'issued': message['native_auth']['issued'], 'complete': True})); file.flush(); os.fsync(file.fileno())
                os.replace(temp, self.ledger / name)
                directory = os.open(self.ledger, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try: os.fsync(directory)
                finally: os.close(directory)
            finally:
                if os.path.exists(temp): os.unlink(temp)
        return True

    def broadcast(self, plan, base):
        if not self.enabled or not self.accepted: raise PolicyError('Replication is disabled or unaccepted')
        message = self.auth.sign(base)
        # Publish then accept locally; a concurrent subscription uses the exact
        # same durable nonce and can never execute the origin twice.
        self.redis.command('PUBLISH', 'MC_CHANNEL', canonical(message))
        self.receive(canonical(message))
