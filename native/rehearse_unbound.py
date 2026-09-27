"""Off-host systemd/RootDirectory rehearsal of one pinned rootfs.

Synthetic local DNS fixture only. Private network namespace has loopback alone;
no public listener, outbound DNS, mail/config/state or production credentials.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import sys
import struct
import subprocess
import tempfile
import threading
import time
import uuid

from peer_policy import authorize,PeerDenied


def run(argv, **kwargs):
    return subprocess.run(argv,check=True,timeout=60,**kwargs)


def validate(artifacts):
    receipt=json.loads((artifacts/'unbound-mailcow.receipt.json').read_text())
    pins=json.loads(Path(__file__).with_name('pinned-images.json').read_text())
    expected=next(row['image'] for row in pins if row['service']=='unbound-mailcow')
    if receipt.get('service')!='unbound-mailcow' or receipt.get('sourceImage')!=expected or not receipt.get('probePassed'):
        raise ValueError('Reviewed pinned Unbound artifact required')
    artifact=artifacts/'unbound-mailcow.rootfs.tar.gz'
    with artifact.open('rb') as source:
        digest=hashlib.file_digest(source,'sha256').hexdigest()
    if digest!=receipt['artifactSHA256']:raise ValueError('Rootfs artifact digest mismatch')
    return artifact,receipt


def dns_fixture():
    labels=b''.join(bytes([len(p)])+p.encode() for p in 'native-fixture.invalid'.split('.'))+b'\0'
    request=struct.pack('!6H',0x5A17,0x0100,1,0,0,0)+labels+struct.pack('!2H',1,1)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
        client.settimeout(1);client.sendto(request,('127.0.0.1',53));response,_=client.recvfrom(4096)
    identifier,flags,questions,answers,_,_=struct.unpack('!6H',response[:12])
    assert identifier==0x5A17 and flags&0x8000 and flags&15==0 and questions==1 and answers==1
    assert response.endswith(socket.inet_aton('198.51.100.7'))


def rehearse(artifacts,output):
    if platform.system()!='Linux' or os.geteuid()!=0:raise RuntimeError('Off-host root Linux builder required')
    version=run(['systemctl','--version'],stdout=subprocess.PIPE).stdout.decode().splitlines()[0]
    if int(version.split()[1])<259:raise RuntimeError('Matching systemd >=259 required')
    artifact,source=validate(artifacts)
    suffix=uuid.uuid4().hex[:12];unit='mailcow-native-rehearsal-'+suffix;namespace=unit
    activated=False;created=False
    with tempfile.TemporaryDirectory(prefix='mailcow-native-rehearsal-') as temp:
        scratch=Path(temp);root=scratch/'root';root.mkdir()
        secret=scratch/'host-secret';secret.write_text('synthetic private host marker');secret.chmod(0o600)
        mailstore=scratch/'synthetic-mailstore';mailstore.mkdir();os.chown(mailstore,5000,5000)
        control=scratch/'host-control.sock'
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(str(control));listener.listen(2);listener.settimeout(25)
        peer_receipts=[]
        allowed_unit=unit+'-allowed.service'
        def controller():
            for _ in range(2):
                with listener.accept()[0] as connection:
                    try:authorize(connection,{allowed_unit:'synthetic-test-only'});answer=b'ALLOWED'
                    except PeerDenied:answer=b'DENIED'
                    peer_receipts.append(answer.decode());connection.sendall(answer)
        thread=threading.Thread(target=controller,daemon=True);thread.start()
        run(['tar','--numeric-owner','--same-owner','--same-permissions','--xattrs','--acls','-xzf',str(artifact),'-C',str(root)])
        conf=scratch/'unbound.conf'
        conf.write_text('''server:
    interface: 127.0.0.1
    port: 53
    username: "unbound"
    chroot: ""
    directory: "/etc/unbound"
    pidfile: ""
    logfile: ""
    use-syslog: no
    do-ip6: no
    do-daemonize: no
    num-threads: 1
    auto-trust-anchor-file: ""
    module-config: "iterator"
    local-zone: "native-fixture.invalid." static
    local-data: "native-fixture.invalid. 60 IN A 198.51.100.7"
''')
        properties=['RootDirectory='+str(root),'NetworkNamespacePath=/run/netns/'+namespace,
                    'BindReadOnlyPaths='+str(conf)+':/etc/unbound/unbound.conf','ProtectSystem=strict',
                    'ProtectHome=yes','PrivateDevices=yes','NoNewPrivileges=yes','CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_NET_BIND_SERVICE',
                    'PrivateUsers=full','PrivatePIDs=yes','MountAPIVFS=yes','BindLogSockets=no',
                    'ProtectKernelTunables=yes','ProtectKernelModules=yes','ProtectKernelLogs=yes',
                    'ProtectControlGroups=strict','RestrictNamespaces=yes','RestrictSUIDSGID=yes',
                    'RestrictAddressFamilies=AF_UNIX AF_INET','SystemCallFilter=~@mount @module @reboot @swap @raw-io','SystemCallErrorNumber=EPERM',
                    'TemporaryFileSystem=/run /tmp','MemoryMax=128M','CPUQuota=25%','TasksMax=32',
                    'RuntimeMaxSec=60','KillMode=control-group','TimeoutStopSec=5']
        try:
            run(['ip','netns','add',namespace]);created=True
            run(['ip','-n',namespace,'link','set','lo','up'])
            run(['systemd-run','--quiet','--unit='+unit,*['--property='+x for x in properties],
                 '/usr/sbin/unbound','-d','-c','/etc/unbound/unbound.conf']);activated=True
            # A real DNS transaction proves systemd root mount/bind/listener and
            # packaged native libc/module execution, beyond a --version probe.
            probe_command=['/usr/bin/python3',str(Path(__file__).resolve()),'--probe-dns']
            deadline=time.monotonic()+20
            while True:
                response=subprocess.run(['ip','netns','exec',namespace,*probe_command],capture_output=True,timeout=3)
                if response.returncode==0:break
                if time.monotonic()>deadline:raise RuntimeError('Synthetic native DNS response missing')
                time.sleep(.25)
            links=json.loads(run(['ip','-j','-n',namespace,'link'],stdout=subprocess.PIPE).stdout)
            if [row['ifname'] for row in links]!=['lo']:raise RuntimeError('Rehearsal network isolation changed')
            # Both test services run numeric UID0 and see the identical socket,
            # even through a read-only bind. Only the registered unit is accepted.
            for role in ('allowed','denied'):
                client="""import errno,os,socket
secret={secret!r}
assert not os.path.exists(secret)
for name in os.listdir('/proc'):
    if name.isdigit():assert not os.path.exists('/proc/'+name+'/root'+secret)
try:os.chroot('/')
except PermissionError:pass
else:raise AssertionError('Unexpected chroot capability')
try:
    forbidden=socket.socket(socket.AF_UNIX);forbidden.connect({control!r})
except FileNotFoundError:pass
else:raise AssertionError('Host control path escaped root')
s=socket.socket(socket.AF_UNIX);s.connect('/run/control.sock');assert s.recv(32)=={answer!r}
pid=os.fork()
if pid==0:
    os.setgroups([5000]);os.setgid(5000);os.setuid(5000)
    with open('/run/mailstore/synthetic-mail','w') as f:f.write('fixture')
    os._exit(0)
assert os.waitpid(pid,0)[1]==0
""".format(secret=str(secret),control=str(control),answer=b'ALLOWED' if role=='allowed' else b'DENIED')
                run(['systemd-run','--quiet','--wait','--pipe','--unit='+unit+'-'+role,*['--property='+x for x in properties],
                     '--property=BindReadOnlyPaths='+str(control)+':/run/control.sock',
                     '--property=BindPaths='+str(mailstore)+':/run/mailstore',
                     '--property=ReadWritePaths=/run/mailstore',
                     '/usr/bin/python3','-c',client])
            thread.join(timeout=3)
            if peer_receipts!=['ALLOWED','DENIED']:raise RuntimeError('Control service authorization failed')
            active=run(['systemctl','is-active',unit],stdout=subprocess.PIPE).stdout.decode().strip()
            pid=int(run(['systemctl','show',unit,'--property=MainPID','--value'],stdout=subprocess.PIPE).stdout)
            if (Path('/proc')/str(pid)).stat().st_uid!=100:raise RuntimeError('Unbound privilege drop missing')
            memory=run(['systemctl','show',unit,'--property=MemoryCurrent','--value'],stdout=subprocess.PIPE).stdout.decode().strip()
            result={'passed':active=='active','service':'unbound-mailcow','sourceImage':source['sourceImage'],
                    'artifactBytes':source['artifactBytes'],'artifactSHA256':source['artifactSHA256'],
                    'systemdVersion':version,'privateUsersFull':True,'privatePIDs':True,'capabilityProfile':['SETUID','SETGID','NET_BIND_SERVICE'],'lowPortDnsBind':True,'daemonDroppedToUid100':True,
                    'legacyUid5000SetuidSetgroupsWrite':True,'chrootAttemptDenied':True,'procRootHostSecretDenied':True,
                    'hostSecretDenied':True,'controlAllowedServiceAccepted':True,'controlUnallowedSameUidDenied':True,
                    'systemdRootDirectory':True,'readOnlyConfigurationBind':True,'realSyntheticDnsResponse':True,
                    'loopbackOnlyNamespace':True,'publicListeners':False,'outboundNetwork':False,
                    'memoryCurrentBytes':int(memory),'memoryMaxBytes':128*1024*1024,'noProductionData':True}
        except Exception:
            subprocess.run(['journalctl','--unit='+unit,'--no-pager','--lines=30'],check=False,timeout=10)
            raise
        finally:
            if activated:subprocess.run(['systemctl','stop',unit],check=False,timeout=15)
            listener.close()
            if created:subprocess.run(['ip','netns','delete',namespace],check=True,timeout=10)
            subprocess.run(['systemctl','reset-failed',unit],check=False,capture_output=True,timeout=10)
        result['cleaned']=True
        output.write_text(json.dumps(result,indent=2)+'\n');return result


if __name__=='__main__':
    if sys.argv[1:]==['--probe-dns']:dns_fixture();raise SystemExit(0)
    parser=argparse.ArgumentParser();parser.add_argument('--artifacts',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(rehearse(args.artifacts,args.output),indent=2))
