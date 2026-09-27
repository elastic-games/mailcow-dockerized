"""Off-host kernel flock, same-store recovery and stale systemd writer test."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from canonical_store import CanonicalStore,ClosedCgroupProbe,StoreBusy


def deny(call):
    try:call()
    except StoreBusy:return
    raise AssertionError('Writer overlap not denied')


def run():
    if sys.platform!='linux' or os.geteuid()!=0:raise RuntimeError('Off-host root Linux builder required')
    with tempfile.TemporaryDirectory(prefix='canonical-mail-store-') as temp:
        parent=Path(temp);old=parent/'old';old.mkdir();source=old/'data';source.mkdir()
        note=source/'messages';note.write_text('legacy-message\n');os.chown(note,999,999);note.chmod(0o600)
        os.setxattr(note,'user.native_fixture',b'synthetic');inode=note.stat().st_ino
        root=parent/'canonical';root.mkdir(mode=0o700);store=CanonicalStore(root)
        store.relocate(old,'data',lambda:[])
        canonical=root/'data/messages'
        assert canonical.stat().st_ino==inode and canonical.stat().st_uid==999 and canonical.stat().st_mode&0o777==0o600
        assert os.getxattr(canonical,'user.native_fixture')==b'synthetic' and not source.exists()
        assert store.recover_relocation(lambda:[])
        store.activate('legacy',lambda:[])
        with store.lease('legacy'):
            deny(lambda:store.activate('native',lambda:[]))
            # A different runtime can acquire shared flock, but its generation
            # check must deny it before any data access/writer spawn.
            def wrong_generation():
                with store.lease('native'):pass
            deny(wrong_generation)
        # Model a lost/crashed launcher after its child closed inherited lease:
        # a real systemd cgroup still has a surviving unleased writer.
        unit='mailcow-store-fixture-'+uuid.uuid4().hex[:12]
        subprocess.run(['systemd-run','--quiet','--unit='+unit,'--property=RuntimeMaxSec=30','--property=MemoryMax=32M',
                        '/usr/bin/python3','-c','import time;time.sleep(25)'],check=True,timeout=10)
        probe=ClosedCgroupProbe(['/sys/fs/cgroup/system.slice/'+unit+'.service'])
        try:
            assert probe();deny(lambda:store.activate('native',probe))
        finally:subprocess.run(['systemctl','stop',unit],check=True,timeout=10)
        assert not probe();store.activate('native',probe)
        with store.lease('native') as data:
            with (data/'messages').open('a') as file:file.write('new-native-arrival\n');file.flush();os.fsync(file.fileno())
        # Compatible old runtime takes the SAME current store after stopping new
        # writers. A copied stale snapshot is never selected by rollback.
        store.activate('legacy',probe)
        with store.lease('legacy') as data:
            assert (data/'messages').read_text()=='legacy-message\nnew-native-arrival\n'
            assert (data/'messages').stat().st_ino==inode
        # Protected ancestor prevents an unrelated host app with overlapping999
        # from reaching data despite exact legacy ownership being preserved.
        code='import os;os.setgroups([]);os.setgid(999);os.setuid(999);\ntry:open('+repr(str(canonical))+').read()\nexcept PermissionError:pass\nelse:raise AssertionError("Unrelated host UID999 traversed canonical root")'
        subprocess.run(['/usr/bin/python3','-c',code],check=True,timeout=10)
        return {'passed':True,'sameFilesystemMovePreservesInodeOwnerModeXattr':True,'sharedWriterLeaseBlocksSwitch':True,
                'wrongGenerationDenied':True,'unleasedSurvivingSystemdWriterBlocksSwitch':True,
                'recoveryAfterWriterStops':True,'rollbackUsesSameStoreIncludingNewArrival':True,
                'hostOverlappingUid999Denied':True,'noProductionData':True,'cleaned':True}


if __name__=='__main__':print(json.dumps(run(),indent=2))
