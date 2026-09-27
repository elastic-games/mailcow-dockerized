"""Anonymous, budgeted result files; never persist a mail body after response.

Budget is explicit operator storage policy. One message may be100 MiB (the
deployed Postfix limit); RAM buffering never scales with message size. Read-only
text operations may be refused at the storage ceiling before exposing a partial
result. Caller disconnect/timeout closes the file and releases every byte.
"""
import os
import tempfile
import threading


class SpoolBudget:
    def __init__(self, directory, maximum):
        self.directory, self.maximum, self.used, self.lock = directory, maximum, 0, threading.Lock()

    def allocate(self, size):
        with self.lock:
            if self.used + size > self.maximum: raise ValueError('Mail response storage budget exceeded')
            self.used += size

    def release(self, size):
        with self.lock: self.used -= size

    def open(self, maximum): return Spool(self, maximum)


class Spool:
    def __init__(self, budget, maximum):
        self.budget, self.maximum, self.size, self.closed = budget, maximum, 0, False
        self.file = tempfile.TemporaryFile(mode='w+b', dir=budget.directory)
        os.fchmod(self.file.fileno(), 0o600)

    def write(self, data):
        if self.size + len(data) > self.maximum: raise ValueError('Mail response limit exceeded')
        self.budget.allocate(len(data))
        try: self.file.write(data); self.size += len(data)
        except BaseException: self.budget.release(len(data)); raise

    def chunks(self):
        self.file.flush(); self.file.seek(0)
        while part := self.file.read(65536): yield part

    def close(self):
        if not self.closed:
            self.closed = True; self.file.close(); self.budget.release(self.size)

    def __del__(self): self.close()
