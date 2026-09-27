"""Off-host pinned Dovecot native profile with disposable IMAP/FTS state.

No production accounts/configuration/mail. Root/master transitions and chroot
are tested within full user/PID/mount/private-network namespaces, with attempted
host/proc escapes under the same capabilities required by the actual daemon.
"""
import argparse
import imaplib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from rehearse_unbound import run,validate

CAPS=['CHOWN','DAC_OVERRIDE','DAC_READ_SEARCH','FOWNER','FSETID','SETGID','SETUID','SYS_CHROOT','KILL']


def mail_probe():
    with imaplib.IMAP4('127.0.0.1',143,timeout=3) as client:
        assert client.login('fixture@example.invalid','fixture-test-only')[0]=='OK'
        assert client.select('INBOX')[0]=='OK'
        message=b'Subject: Synthetic native acceptance\r\nFrom: fixture@example.invalid\r\nTo: fixture@example.invalid\r\n\r\nuniqueparityword\r\n'
        assert client.append('INBOX','\\Seen',None,message)[0]=='OK'
        assert client.select('INBOX')[1]==[b'1']
        assert client.search(None,'BODY','uniqueparityword')[1]==[b'1']
        assert b'\\Seen' in client.fetch('1','FLAGS')[1][0]
        assert client.create('NativeFixture')[0]=='OK'
        assert client.copy('1','NativeFixture')[0]=='OK'
        assert client.select('NativeFixture')[1]==[b'1']
    # LMTP listener and Pigeonhole ManageSieve must actually answer, not merely
    # exist as binaries. Full delivery/Sieve tests are separate parity gates.
    for port,expected in ((24,b'220'),(4190,b'IMPLEMENTATION')):
        with socket.create_connection(('127.0.0.1',port),timeout=3) as client:
            assert expected in client.recv(4096)


def rehearse(artifacts,output):
    if sys.platform!='linux' or os.geteuid()!=0:raise RuntimeError('Off-host root Linux builder required')
    version=run(['systemctl','--version'],stdout=subprocess.PIPE).stdout.decode().splitlines()[0]
    if int(version.split()[1])<259:raise RuntimeError('Matching systemd >=259 required')
    artifact,source=validate(artifacts,'dovecot-mailcow')
    name='mailcow-native-dovecot-'+uuid.uuid4().hex[:12];namespace=name;created=False;started=False
    with tempfile.TemporaryDirectory(prefix='native-dovecot-') as temp:
        scratch=Path(temp);root=scratch/'root';root.mkdir()
        run(['tar','--numeric-owner','--same-owner','--same-permissions','--xattrs','--acls','-xzf',str(artifact),'-C',str(root)])
        store=scratch/'mailstore';store.mkdir();os.chown(store,5000,5000)
        secret=scratch/'host-secret';secret.write_text('synthetic host marker');secret.chmod(0o600)
        overlapping=scratch/'uid999-state';overlapping.write_text('synthetic legacy-owner state');os.chown(overlapping,999,999);overlapping.chmod(0o600)
        # Canonical state retains legacy IDs beneath root0700 host ancestors.
        # The unrelated host app sharing UID999 must not traverse to this file.
        host_probe='import os;os.setgroups([]);os.setgid(999);os.setuid(999);\ntry:open('+repr(str(overlapping))+').read()\nexcept PermissionError:pass\nelse:raise AssertionError("Host UID999 crossed protected ancestor")'
        run(['/usr/bin/python3','-c',host_probe])
        config=scratch/'dovecot.conf'
        config.write_text('''protocols = imap lmtp sieve
listen = 127.0.0.1
base_dir = /run/dovecot
state_dir = /run/dovecot/state
log_path = /dev/stderr
info_log_path = /dev/stderr
ssl = no
disable_plaintext_auth = no
auth_mechanisms = plain login
mail_location = maildir:/var/vmail/%u/Maildir
mail_plugins = fts fts_flatcurve
first_valid_uid = 5000
passdb {
  driver = static
  args = password=fixture-test-only
}
userdb {
  driver = static
  args = uid=5000 gid=5000 home=/var/vmail/%u
}
service auth {
  unix_listener auth-userdb {
    mode = 0600
    user = vmail
  }
}
service imap-login {
  user = dovenull
  process_min_avail = 1
}
service lmtp {
  user = vmail
  inet_listener lmtp {
    port = 24
  }
}
plugin {
  fts = flatcurve
  fts_autoindex = yes
  fts_languages = en
  fts_tokenizers = generic email-address
  fts_filters = normalizer-icu snowball stopwords
  fts_filters_en = lowercase snowball english-possessive stopwords
}
''')
        properties=['RootDirectory='+str(root),'NetworkNamespacePath=/run/netns/'+namespace,
                    'BindReadOnlyPaths='+str(config)+':/etc/dovecot/native-fixture.conf',
                    'BindPaths='+str(store)+':/var/vmail','ReadWritePaths=/var/vmail',
                    'BindReadOnlyPaths='+str(overlapping)+':/run/legacy-uid999-state',
                    'PrivateUsers=full','PrivatePIDs=yes','MountAPIVFS=yes','PrivateDevices=yes','BindLogSockets=no',
                    'ProtectSystem=strict','ProtectHome=yes','NoNewPrivileges=yes','ProtectControlGroups=strict',
                    'ProtectKernelTunables=yes','ProtectKernelModules=yes','ProtectKernelLogs=yes',
                    'RestrictNamespaces=yes','RestrictSUIDSGID=yes','RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK',
                    'SystemCallFilter=~mount umount2 pivot_root move_mount open_tree fsopen fsconfig fsmount mount_setattr @module @reboot @swap @raw-io',
                    'SystemCallErrorNumber=EPERM','CapabilityBoundingSet='+' '.join('CAP_'+x for x in CAPS),
                    'TemporaryFileSystem=/run /tmp','MemoryMax=256M','CPUQuota=50%','TasksMax=64',
                    'RuntimeMaxSec=90','KillMode=control-group','TimeoutStopSec=5']
        try:
            run(['ip','netns','add',namespace]);created=True
            run(['ip','-n',namespace,'link','set','lo','up'])
            run(['ip','netns','exec',namespace,'sysctl','-qw','net.ipv4.ip_unprivileged_port_start=0'])
            run(['systemd-run','--quiet','--unit='+name,*['--property='+x for x in properties],
                 '/usr/sbin/dovecot','-F','-c','/etc/dovecot/native-fixture.conf']);started=True
            deadline=time.monotonic()+20
            while True:
                tested=subprocess.run(['ip','netns','exec',namespace,'/usr/bin/python3',str(Path(__file__).resolve()),'--probe-mail'],capture_output=True,timeout=10)
                if tested.returncode==0:break
                # Don't retry a partially executed mailbox write transaction.
                if list(store.rglob('cur/*')) or list(store.rglob('new/*')):
                    raise RuntimeError('Mail fixture transaction failed: '+tested.stderr.decode()[-2000:])
                if time.monotonic()>deadline:raise RuntimeError('Native mail protocol missing: '+tested.stderr.decode()[-2000:])
                time.sleep(.25)
            attack='''import os,socket
secret={secret!r}
assert not os.path.exists(secret)
assert not os.path.exists('/run/dbus/system_bus_socket')
assert not os.path.exists('/var/run/docker.sock')
for entry in os.listdir('/proc'):
    if entry.isdigit():assert not os.path.exists('/proc/'+entry+'/root'+secret)
# Exercise available SYS_CHROOT, saved cwd and repeated parent traversal. This
# may escape a child jail but must not escape the complete service root mount.
child=os.fork()
if child==0:
    os.setgroups([999]);os.setgid(999);os.setuid(999)
    assert open('/run/legacy-uid999-state').read()=='synthetic legacy-owner state'
    os._exit(0)
assert os.waitpid(child,0)[1]==0
fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY);os.mkdir('/tmp/jail');os.chroot('/tmp/jail');os.fchdir(fd)
for _ in range(20):os.chdir('..')
os.chroot('.');os.chdir('/')
assert not os.path.exists(secret)
for entry in os.listdir('/proc'):
    if entry.isdigit():assert not os.path.exists('/proc/'+entry+'/root'+secret)
'''.format(secret=str(secret))
            run(['systemd-run','--quiet','--wait','--pipe','--unit='+name+'-escape-probe',*['--property='+x for x in properties],
                 '/usr/bin/python3','-c',attack])
            memory=int(run(['systemctl','show',name,'--property=MemoryCurrent','--value'],stdout=subprocess.PIPE).stdout)
            index_count=len(list(store.rglob('fts-flatcurve*')))
            if index_count<1:raise RuntimeError('Real flatcurve index missing')
            result={'passed':True,'service':'dovecot-mailcow','systemdVersion':version,'sourceImage':source['sourceImage'],
                    'capabilityProfile':CAPS,'privateUsersFull':True,'privatePIDs':True,'privateNamespaceUnprivilegedPortStart':0,
                    'realImapLoginAppendFlagsCopySearch':True,'realFlatcurveIndex':True,'lmtpBanner':True,'manageSieveBanner':True,
                    'sysChrootCwdEscapeCannotReachHost':True,'procRootHostSecretDenied':True,'hostControlSocketsAbsent':True,'hostOverlappingUid999Denied':True,'insideBoundUid999StateReadable':True,
                    'memoryCurrentBytes':memory,'memoryMaxBytes':256*1024*1024,'noProductionData':True,
                    'publicListeners':False,'outboundNetwork':False}
        except Exception:
            subprocess.run(['journalctl','--unit='+name,'--no-pager','--lines=60'],check=False,timeout=10)
            raise
        finally:
            if started:subprocess.run(['systemctl','stop',name],check=False,timeout=15)
            if created:subprocess.run(['ip','netns','delete',namespace],check=True,timeout=10)
            subprocess.run(['systemctl','reset-failed',name],check=False,capture_output=True,timeout=10)
        result['cleaned']=True;output.write_text(json.dumps(result,indent=2)+'\n');return result


if __name__=='__main__':
    if sys.argv[1:]==['--probe-mail']:mail_probe();raise SystemExit(0)
    parser=argparse.ArgumentParser();parser.add_argument('--artifacts',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(rehearse(args.artifacts,args.output),indent=2))
