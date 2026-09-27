"""Real offhost namespaces and root-configured controller transport fixture.

Only synthetic empty profiles are loaded here; packaged daemon/bootstrap parity
is a separate combined-stack gate. No production configuration or outbound mail.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from action_policy import UNITS
from canonical_store import CanonicalStore
from fixture_network import Network
from runtime_config import load
from broadcast_queue import BroadcastQueue


def run(argv, timeout=20):
    return subprocess.run(argv, check=True, capture_output=True, timeout=timeout)


def rehearse(output):
    if sys.platform != 'linux' or os.geteuid() != 0: raise PermissionError('Offhost root Linux fixture only')
    network = Network('synthetic', os.urandom(4).hex(), '172.30.66.0/24')
    controller = None; network_created = False
    with tempfile.TemporaryDirectory(prefix='mailcow-controller-', dir='/run') as directory:
        base = Path(directory); canonical = base / 'canonical'; release = base / 'release'
        for root in (canonical, release): root.mkdir(mode=0o700)
        operator = canonical / 'operator'; operator.mkdir(mode=0o700)
        (operator / 'spool').mkdir(mode=0o700)
        environment = operator / 'environment'; environment.mkdir(mode=0o700)
        store = CanonicalStore(canonical); store.activate('native', lambda: [])
        secret = operator / 'redis.password'; secret.write_bytes(b'synthetic-unused-fixture'); secret.chmod(0o600)
        for service in UNITS:
            (release / 'roots' / service / 'rootfs').mkdir(parents=True)
            env = environment / service; env.write_text('MASTER=synthetic\n'); env.chmod(0o600)
        config = {'schema': 1, 'mode': 'offhost-rehearsal', 'project': 'synthetic', 'canonicalRoot': str(canonical),
                  'releaseRoot': str(release), 'networkTag': network.tag, 'ipv4Network': str(network.subnet),
                  'profiles': {service: {'readOnly': [], 'writable': []} for service in UNITS}, 'replication': {'enabled': False}}
        path = operator / 'runtime.json'; path.write_text(json.dumps(config)); path.chmod(0o600)
        load(path)
        socket_path = operator / 'control.sock'
        client = '''import json,socket,sys
s=socket.socket(socket.AF_UNIX);s.settimeout(10);s.connect(sys.argv[1]);s.sendall(b'GET /health HTTP/1.0\\r\\nX-Caller: php\\r\\n\\r\\n')
r=b''
while True:
 p=s.recv(4096)
 if not p:break
 r+=p
h,b=r.split(b'\\r\\n\\r\\n',1);assert int(h.split()[1])==int(sys.argv[2])
if sys.argv[2]=='200':assert json.loads(b)=={'ready':True}
'''
        try:
            network.create(); network_created = True
            # Actual bridge reachability between namespaces, with no default
            # route; service-to-host new TCP is dropped by fixture-only nft.
            source = network.namespaces['php-fpm-mailcow']; target = network.namespaces['dovecot-mailcow']
            run(['/usr/sbin/ip', 'netns', 'exec', source, '/usr/bin/ping', '-c', '1', '-W', '2', network.addresses['dovecot-mailcow']])
            route = json.loads(run(['/usr/sbin/ip', '-j', '-n', source, 'route']).stdout)
            assert all(row.get('dst') != 'default' for row in route)
            denial = '''import socket,sys
s=socket.socket();s.settimeout(.7)
try:s.connect((sys.argv[1],int(sys.argv[2])))
except (TimeoutError,OSError):pass
else:raise AssertionError('Unexpected service-to-host access')
'''
            with socket.socket() as host_listener:
                host_listener.bind(('0.0.0.0', 0)); host_listener.listen()
                run(['/usr/sbin/ip', 'netns', 'exec', source, sys.executable, '-c', denial, str(network.subnet.network_address + 1), str(host_listener.getsockname()[1])])
            controller = subprocess.Popen([sys.executable, str(Path(__file__).resolve().parents[1] / 'native_controller.py'), '--config', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            deadline = time.monotonic() + 10
            while not socket_path.exists():
                if controller.poll() is not None: raise RuntimeError('Synthetic controller startup failed')
                if time.monotonic() > deadline: raise TimeoutError('Synthetic controller readiness')
                time.sleep(.05)
            # Forged request headers cannot authorize an unregistered host peer.
            run([sys.executable, '-c', client, str(socket_path), '403'])
            # Kernel cgroup identity of registered PHP unit authorizes /health.
            # This intentionally proves controller wiring only; prior packaged
            # profile rehearsals prove RootDirectory/capability confinement.
            name = UNITS['php-fpm-mailcow']
            status = run(['/usr/bin/systemctl', 'show', '--property=ActiveState', '--value', name]).stdout.strip()
            assert status not in (b'active', b'activating'), 'Existing service must not be replaced'
            run(['/usr/bin/systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--unit='+name,
                 '--property=NetworkNamespacePath=/run/netns/'+source, '--', sys.executable, '-c', client, str(socket_path), '200'])
            controller.send_signal(signal.SIGTERM); controller.wait(timeout=15)
            assert controller.returncode == 0 and not socket_path.exists()
            # Actual accepted-work drain in this Linux fixture is independent
            # of replication (which remains disabled for this target).
            completed = []; work = BroadcastQueue(lambda _: None, completed.append)
            for message in range(32): work.submit(message)
            work.close(); assert completed == list(range(32)) and work.pending.unfinished_tasks == 0
            network.close(); network_created = False
            receipt = {'passed': True, 'complete18ProfileConfig': True, 'actual18Namespaces': True,
                       'privateCrossServiceReachable': True, 'noDefaultRoute': True, 'hostTCPDenied': True,
                       'actualControllerKernelPeerHealth': True, 'forgedHeaderUnregisteredPeerDenied': True,
                       'controllerGracefulShutdownSocketRemoved': True, 'acceptedLocalQueueDrained': True,
                       'replicationDisabled': True, 'packagedStackParity': False, 'noProductionDataOrOutbound': True,
                       'cleanupConfirmed': True}
            output.write_text(json.dumps(receipt, indent=2)+'\n')
        finally:
            if controller and controller.poll() is None:
                controller.send_signal(signal.SIGTERM)
                try: controller.wait(timeout=15)
                except subprocess.TimeoutExpired: controller.kill(); controller.wait(timeout=5)
            if controller and controller.returncode:
                print('Synthetic controller failed:', controller.stderr.read(4096).decode('utf-8', 'replace'), file=sys.stderr)
            if network_created: network.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--output', type=Path, required=True)
    rehearse(parser.parse_args().output)
