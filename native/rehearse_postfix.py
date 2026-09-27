"""Off-host pinned Postfix SMTP + durable queue/local-sink recovery rehearsal.

Synthetic local sender/recipient only. Namespace contains loopback, no external
routes or DNS; never an authorized outbound production-mail test.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import smtplib
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from rehearse_unbound import run,validate

CAPS=('CHOWN','DAC_OVERRIDE','DAC_READ_SEARCH','FOWNER','FSETID','SETGID','SETUID','SYS_CHROOT','KILL')
MESSAGE=b'Subject: Synthetic queue recovery\r\nFrom: fixture@native.invalid\r\nTo: sink@recipient.invalid\r\n\r\nonly disposable native fixture\r\n'


def local_sink(receipt):
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);server.bind(('127.0.0.1',2525));server.listen(1);server.settimeout(25)
        with server.accept()[0] as connection:
            connection.settimeout(5);file=connection.makefile('rb');connection.sendall(b'220 native synthetic sink\r\n');data=False;message=[]
            while line:=file.readline(65536):
                if data:
                    if line==b'.\r\n':
                        assert b'only disposable native fixture' in b''.join(message)
                        receipt.write_text(json.dumps({'received':1,'syntheticBodyMatched':True,'noProductionData':True}))
                        connection.sendall(b'250 local receipt\r\n');data=False
                    else:message.append(line)
                elif line.upper().startswith((b'EHLO',b'HELO')):connection.sendall(b'250 native sink\r\n')
                elif line.upper().startswith((b'MAIL',b'RCPT',b'RSET')):connection.sendall(b'250 ok\r\n')
                elif line.upper().startswith(b'DATA'):connection.sendall(b'354 message\r\n');data=True
                elif line.upper().startswith(b'QUIT'):connection.sendall(b'221 done\r\n');break
                else:raise RuntimeError('Unexpected synthetic sink command')


def smtp_submit():
    with smtplib.SMTP('127.0.0.1',25,timeout=5) as client:
        assert client.sendmail('fixture@native.invalid',['sink@recipient.invalid'],MESSAGE)=={}


def rehearse(artifacts,output):
    if sys.platform!='linux' or os.geteuid()!=0:raise RuntimeError('Off-host root Linux builder required')
    version=run(['systemctl','--version'],stdout=subprocess.PIPE).stdout.decode().splitlines()[0]
    if int(version.split()[1])<259:raise RuntimeError('Matching systemd >=259 required')
    artifact,source=validate(artifacts,'postfix-mailcow')
    name='mailcow-native-postfix-'+uuid.uuid4().hex[:12];namespace=name;created=False;started=False;sink=None
    with tempfile.TemporaryDirectory(prefix='native-postfix-') as temp:
        scratch=Path(temp);root=scratch/'root';root.mkdir()
        run(['tar','--numeric-owner','--same-owner','--same-permissions','--xattrs','--acls','-xzf',str(artifact),'-C',str(root)])
        queue=scratch/'queue';data=scratch/'data';config=scratch/'config'
        for source_dir,destination in ((root/'var/spool/postfix',queue),(root/'var/lib/postfix',data),(root/'etc/postfix',config)):
            run(['cp','-a',str(source_dir),str(destination)])
        # Fixture logfile is shared only by root/postfix inside this isolated
        # root0700 ancestor; this permissive synthetic mode is not production
        # logging policy. Journal sockets cannot be reopened via /dev/stdout.
        data.chmod(0o755);log=data/'native-fixture.log';log.touch();log.chmod(0o666)
        (config/'main.cf').write_text('''compatibility_level = 3.10
myhostname = native-fixture.invalid
myorigin = native-fixture.invalid
mydestination =
inet_interfaces = 127.0.0.1
inet_protocols = ipv4
mynetworks = 127.0.0.0/8
relayhost = [127.0.0.1]:2525
queue_directory = /var/spool/postfix
data_directory = /var/lib/postfix
mail_owner = postfix
setgid_group = postdrop
smtpd_relay_restrictions = permit_mynetworks,reject
smtpd_tls_security_level = none
smtp_tls_security_level = none
smtpd_sasl_auth_enable = no
alias_maps =
alias_database =
maillog_file = /var/lib/postfix/native-fixture.log
smtp_connect_timeout = 2s
smtp_helo_timeout = 2s
minimal_backoff_time = 2s
maximal_backoff_time = 5s
queue_run_delay = 2s
''')
        # Keep packaged service map; execute cleanup chroot like the upstream
        # sender-cleanup service while avoiding unrelated fixture jail services.
        master=[]
        for line in (config/'master.cf').read_text().splitlines():
            if line and not line.startswith(('#',' ','\t')):
                fields=line.split()
                if len(fields)>=8:
                    fields[4]='y' if fields[0]=='cleanup' else 'n';line=' '.join(fields)
            master.append(line)
        (config/'master.cf').write_text('\n'.join(master)+'\n')
        # OCI runtime normally supplies these jail devices; fixture state must
        # contain them for cleanup's actual SYS_CHROOT transition.
        (queue/'dev').mkdir(exist_ok=True)
        import stat
        for device,minor in (('null',3),('zero',5),('random',8),('urandom',9)):
            target=queue/'dev'/device
            if not target.exists():os.mknod(target,stat.S_IFCHR|0o666,os.makedev(1,minor))
        secret=scratch/'host-secret';secret.write_text('synthetic host marker');secret.chmod(0o600)
        properties=['RootDirectory='+str(root),'NetworkNamespacePath=/run/netns/'+namespace,
                    'BindReadOnlyPaths='+str(config)+':/etc/postfix','BindPaths='+str(queue)+':/var/spool/postfix '+str(data)+':/var/lib/postfix',
                    'ReadWritePaths=/var/spool/postfix /var/lib/postfix','PrivateUsers=full','PrivatePIDs=yes','MountAPIVFS=yes',
                    'PrivateDevices=yes','BindLogSockets=no','ProtectSystem=strict','ProtectHome=yes','NoNewPrivileges=yes',
                    'ProtectControlGroups=strict','ProtectKernelTunables=yes','ProtectKernelModules=yes','ProtectKernelLogs=yes',
                    'RestrictNamespaces=yes','RestrictSUIDSGID=yes','RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK',
                    'CapabilityBoundingSet='+' '.join('CAP_'+x for x in CAPS),
                    'SystemCallFilter=~mount umount2 pivot_root move_mount open_tree fsopen fsconfig fsmount mount_setattr @module @reboot @swap @raw-io',
                    'SystemCallErrorNumber=EPERM','TemporaryFileSystem=/run /tmp','MemoryMax=256M','CPUQuota=50%','TasksMax=64',
                    'RuntimeMaxSec=90','KillMode=control-group','TimeoutStopSec=5']
        def start():
            run(['systemd-run','--quiet','--unit='+name,*['--property='+x for x in properties],'/usr/sbin/postfix','start-fg'])
        def queued():
            return [path for directory in ('incoming','active','deferred','hold') for path in (queue/directory).rglob('*') if path.is_file()]
        try:
            run(['ip','netns','add',namespace]);created=True
            run(['ip','-n',namespace,'link','set','lo','up'])
            run(['ip','netns','exec',namespace,'sysctl','-qw','net.ipv4.ip_unprivileged_port_start=0'])
            start();started=True;deadline=time.monotonic()+20
            # Wait for connection before the one and only submission attempt.
            while True:
                ready=subprocess.run(['ip','netns','exec',namespace,'/usr/bin/python3','-c',
                                      'import socket;socket.create_connection(("127.0.0.1",25),timeout=1).close()'],capture_output=True,timeout=3)
                if ready.returncode==0:break
                if time.monotonic()>deadline:raise RuntimeError('Native SMTP listener absent')
                time.sleep(.25)
            run(['ip','netns','exec',namespace,'/usr/bin/python3',str(Path(__file__).resolve()),'--submit'])
            deadline=time.monotonic()+10
            while not queued():
                if time.monotonic()>deadline:raise RuntimeError('Accepted message absent from durable queue')
                time.sleep(.1)
            pending=queued();assert len(pending)==1;inode=pending[0].stat().st_ino
            run(['systemctl','stop',name]);started=False
            assert queued() and queued()[0].stat().st_ino==inode
            receipt=scratch/'sink-receipt.json'
            sink=subprocess.Popen(['ip','netns','exec',namespace,'/usr/bin/python3',str(Path(__file__).resolve()),'--sink',str(receipt)])
            start();started=True;deadline=time.monotonic()+20
            while not receipt.exists() or queued():
                if time.monotonic()>deadline:raise RuntimeError('Same-queue restart did not deliver to local sink')
                time.sleep(.2)
            assert json.loads(receipt.read_text())['received']==1
            attack='''import os
secret={secret!r}
assert not os.path.exists(secret) and not os.path.exists('/run/dbus/system_bus_socket') and not os.path.exists('/var/run/docker.sock')
for entry in os.listdir('/proc'):
    if entry.isdigit():assert not os.path.exists('/proc/'+entry+'/root'+secret)
fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY);os.mkdir('/tmp/jail');os.chroot('/tmp/jail');os.fchdir(fd)
for _ in range(20):os.chdir('..')
os.chroot('.');os.chdir('/');assert not os.path.exists(secret)
'''.format(secret=str(secret))
            run(['systemd-run','--quiet','--wait','--pipe','--unit='+name+'-escape',*['--property='+x for x in properties],'/usr/bin/python3','-c',attack])
            memory=int(run(['systemctl','show',name,'--property=MemoryCurrent','--value'],stdout=subprocess.PIPE).stdout)
            result={'passed':True,'service':'postfix-mailcow','systemdVersion':version,'sourceImage':source['sourceImage'],
                    'capabilityProfile':CAPS,'privateUsersFull':True,'privatePIDs':True,'lowPortSmtpBind':True,
                    'syntheticSmtpAcceptedDurably':True,'sameQueueInodeSurvivesStop':True,'sameQueueRestartDeliversToLocalSink':True,
                    'queueDrainedAfterDelivery':True,'sysChrootCwdEscapeCannotReachHost':True,'procRootHostSecretDenied':True,
                    'hostControlSocketsAbsent':True,'memoryCurrentBytes':memory,'publicListeners':False,'outboundNetwork':False,'noProductionData':True}
        except Exception:
            subprocess.run(['journalctl','--unit='+name,'--no-pager','--lines=80'],check=False,timeout=10)
            if log.exists():print(log.read_text(errors='replace')[-12000:])
            raise
        finally:
            if started:subprocess.run(['systemctl','stop',name],check=False,timeout=15)
            if sink:
                if sink.poll() is None:sink.terminate()
                sink.wait(timeout=10)
            if created:subprocess.run(['ip','netns','delete',namespace],check=True,timeout=10)
            subprocess.run(['systemctl','reset-failed',name],check=False,capture_output=True,timeout=10)
        result['cleaned']=True;output.write_text(json.dumps(result,indent=2)+'\n');return result


if __name__=='__main__':
    if sys.argv[1:]==['--submit']:smtp_submit();raise SystemExit(0)
    if sys.argv[1:2]==['--sink']:local_sink(Path(sys.argv[2]));raise SystemExit(0)
    parser=argparse.ArgumentParser();parser.add_argument('--artifacts',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(rehearse(args.artifacts,args.output),indent=2))
