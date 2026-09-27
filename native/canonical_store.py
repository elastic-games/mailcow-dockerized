"""Protected canonical state, exclusive generation transition and same-store recovery.

Operator-side primitives; not exposed by the mail admin request dispatcher.
Native/legacy startup wrappers must hold a shared lease for their whole lifetime.
Transitions additionally require an independent closed cgroup/container writer
probe, so a crashed lease holder cannot hide surviving writers. Legacy Docker
restart/boot must be disabled outside its guarded launcher before acceptance.
"""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import stat
import tempfile

GENERATIONS=frozenset(('legacy','native'))
DIRECTORY_FLAGS=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
ACTION_CGROUP=Path('/sys/fs/cgroup/mailcow.slice/mailcow-actions.slice')


class StoreBusy(RuntimeError):
    pass


class CanonicalStore:
    def __init__(self,root):
        self.root=Path(root)
        info=self.root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:
            raise PermissionError('Canonical root must be root-owned0700, without symlink')
        self.control=self.root/'.control';self.control.mkdir(mode=0o700,exist_ok=True)
        cinfo=self.control.lstat()
        if not stat.S_ISDIR(cinfo.st_mode) or cinfo.st_uid!=0 or stat.S_IMODE(cinfo.st_mode)!=0o700:
            raise PermissionError('Protected control directory required')

    def _atomic(self,name,value):
        fd,path=tempfile.mkstemp(dir=self.control,prefix='.journal-')
        try:
            os.fchmod(fd,0o600)
            with os.fdopen(fd,'w') as file:json.dump(value,file);file.flush();os.fsync(file.fileno())
            os.replace(path,self.control/name)
            parent=os.open(self.control,DIRECTORY_FLAGS)
            try:os.fsync(parent)
            finally:os.close(parent)
        finally:
            if os.path.exists(path):os.unlink(path)

    def _read(self,name):
        fd=os.open(self.control/name,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077 or info.st_size>65536:
                raise PermissionError('Protected bounded journal required')
            with os.fdopen(fd,'r',closefd=False) as file:return json.load(file)
        finally:os.close(fd)

    @contextmanager
    def _lock(self,exclusive):
        fd=os.open(self.control/'lease.lock',os.O_RDONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077 or info.st_nlink!=1:
                raise PermissionError('Protected lease inode required')
            try:fcntl.flock(fd,(fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)|fcntl.LOCK_NB)
            except BlockingIOError:raise StoreBusy('Existing writer lease blocks transition') from None
            yield
        finally:os.close(fd)

    @staticmethod
    def _no_writers(probe):
        if not callable(probe):raise ValueError('Independent writer probe required')
        if probe():raise StoreBusy('Independent probe detects active/stale writer')

    def activate(self,generation,writer_probe):
        if generation not in GENERATIONS:raise ValueError('Unknown runtime generation')
        with self._lock(True):
            self._no_writers(writer_probe)
            self._atomic('generation.json',{'generation':generation})

    @contextmanager
    def lease(self,generation):
        if generation not in GENERATIONS:raise ValueError('Unknown runtime generation')
        with self._lock(False):
            if self._read('generation.json').get('generation')!=generation:
                raise StoreBusy('Requested runtime is not canonical writer generation')
            yield self.root/'data'

    def relocate(self,source_parent,source_name,writer_probe):
        """Atomic same-filesystem move retains IDs/inodes/xattrs, without copying.

        Source parent must be operator-owned and not writable by mail services.
        Cross-filesystem migration is deliberately rejected; requires a separate
        consistent-copy/write-pause plan. Never merge or overwrite destination.
        """
        if not isinstance(source_name,str) or not source_name or '/' in source_name or source_name in ('.','..'):
            raise ValueError('One exact source directory required')
        with self._lock(True):
            self._no_writers(writer_probe)
            parent=os.open(source_parent,DIRECTORY_FLAGS);dest=os.open(self.root,DIRECTORY_FLAGS)
            try:
                pinfo=os.fstat(parent)
                if pinfo.st_uid!=0 or pinfo.st_mode&0o022:raise PermissionError('Protected source parent required')
                child=os.open(source_name,DIRECTORY_FLAGS,dir_fd=parent)
                try:
                    if os.fstat(child).st_dev!=os.fstat(dest).st_dev:raise ValueError('Cross-filesystem relocation requires separate migration')
                finally:os.close(child)
                try:os.stat('data',dir_fd=dest,follow_symlinks=False)
                except FileNotFoundError:pass
                else:raise FileExistsError('Canonical data destination already exists')
                journal={'sourceParent':str(Path(source_parent).resolve()),'sourceName':source_name,'complete':False}
                self._atomic('relocation.json',journal)
                os.rename(source_name,'data',src_dir_fd=parent,dst_dir_fd=dest)
                os.fsync(parent);os.fsync(dest)
                journal['complete']=True;self._atomic('relocation.json',journal)
            finally:os.close(parent);os.close(dest)

    def recover_relocation(self,writer_probe):
        with self._lock(True):
            self._no_writers(writer_probe);journal=self._read('relocation.json')
            source=Path(journal['sourceParent'])/journal['sourceName'];destination=self.root/'data'
            if source.exists()==destination.exists():raise RuntimeError('Conflicting or missing stores; preserve for operator review')
            journal['complete']=destination.exists();self._atomic('relocation.json',journal)
            return journal['complete']


class ClosedCgroupProbe:
    """Fixed registered host cgroups only; never trust a request-supplied PID.

    Real rollout must combine this with exact old Docker container-state checks
    and fail closed when its legacy engine cannot be observed. A host root
    process can bypass these primitives; application units cannot access .control.
    """
    def __init__(self,paths):
        self.paths=tuple(dict.fromkeys([*(Path(path) for path in paths),ACTION_CGROUP]))
        if any((path!=ACTION_CGROUP and not str(path).startswith('/sys/fs/cgroup/system.slice/')) or '..' in path.parts for path in self.paths):
            raise ValueError('Closed systemd cgroup paths required')

    def __call__(self):
        active=[]
        for path in self.paths:
            try:events=dict(line.split() for line in (path/'cgroup.events').read_text().splitlines())
            except FileNotFoundError:continue
            if events.get('populated')!='0':active.append(path.name)
        return active
