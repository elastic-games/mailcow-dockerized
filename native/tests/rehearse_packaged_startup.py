"""Actual pinned Redis, MariaDB and PHP bootstrap in one isolated stack.

Only synthetic schema/assets, private namespaces, no external mail route. This
is a first combined subset; remaining packaged services/user flows are gates.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import yaml
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from action_policy import UNITS
from fixture_network import Network
from prepare_fixture_stack import prepare
from runtime_config import load
from stack_units import render
from service_executor import manager_unit_absent, ACTION_CGROUP, JOB_CGROUP
from redis_wire import Redis
from runtime_config import protected_file


def run(argv, timeout=30):
    return subprocess.run(argv, check=True, timeout=timeout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def state(unit):
    result = run(['systemctl', 'show', unit, '--property=ActiveState,SubState,ExecMainStatus', '--no-pager'])
    return dict(line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line)


def until(unit, check, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = state(unit)
        if status.get('ActiveState') == 'failed': raise RuntimeError('Packaged service ' + unit + ' failed during startup')
        try:
            if check(): return
        except (OSError, subprocess.SubprocessError): pass
        time.sleep(.25)
    raise TimeoutError('Packaged service ' + unit + ' readiness')


def no_preexisting_unit_or_job(unit):
    status = run(['systemctl', 'show', unit, '--property=LoadState,ActiveState', '--no-pager'])
    fields = dict(line.split('=', 1) for line in status.stdout.decode().splitlines() if '=' in line)
    if fields != {'LoadState':'not-found', 'ActiveState':'inactive'}:
        raise FileExistsError('Loaded or active mail fixture unit must not be replaced')
    result = run(['/usr/bin/busctl', '--json=short', 'call', 'org.freedesktop.systemd1',
                  '/org/freedesktop/systemd1', 'org.freedesktop.systemd1.Manager', 'ListJobs'])
    jobs = json.loads(result.stdout)
    if jobs.get('type') != 'a(usssoo)' or len(jobs.get('data', [])) != 1 or not isinstance(jobs['data'][0], list):
        raise ValueError('Unobservable manager jobs refused')
    if any(row[1] == unit for row in jobs['data'][0]): raise FileExistsError('Pending mail fixture job refused')


def cgroups_empty(paths):
    for path in paths:
        event = path / 'cgroup.events'
        if not event.exists(): continue
        fields = dict(line.split() for line in event.read_text().splitlines())
        if fields.get('populated') != '0': return False
    return True


def rehearse(artifacts, output):
    if sys.platform != 'linux' or os.geteuid() != 0: raise PermissionError('Offhost root Linux only')
    if shutil.disk_usage('/var/lib').free < 9 * 1024**3: raise RuntimeError('Offhost fixture needs >=9GiB free')
    installed = []; started = []; controller = None; network = None; network_active = False
    base = Path(tempfile.mkdtemp(prefix='mailcow-pinned-stack-', dir='/var/lib'))
    result = None; operation_error = None
    units = ('redis-mailcow', 'mysql-mailcow', 'php-fpm-mailcow')
    try:
        for service in units: no_preexisting_unit_or_job(UNITS[service])
        root = base / 'stack'; config_path, prepared = prepare(artifacts, root)
        config, store, profiles, _ = load(config_path)
        network = Network(config['project'], config['networkTag'], config['ipv4Network'])
        images = json.loads((store.root / 'operator/image-metadata.json').read_text())
        compose = yaml.safe_load((Path(__file__).resolve().parents[2] / 'docker-compose.yml').read_text())['services']
        network.create(); network_active = True
        controller = subprocess.Popen([sys.executable, str(root / 'release/native/native_controller.py'), '--config', str(config_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        control = store.root / 'operator/control.sock'; deadline = time.monotonic() + 10
        while not control.exists():
            if controller.poll() is not None: raise RuntimeError('Native controller startup failed')
            if time.monotonic() > deadline: raise TimeoutError('Native controller socket readiness')
            time.sleep(.05)
        for service in units:
            unit = UNITS[service]; path = Path('/run/systemd/system') / unit
            if path.exists(): raise FileExistsError('Existing target fixture unit refused')
            path.write_text(render(service, profiles[unit], images[service], compose[service]))
            installed.append((unit, path))
        run(['systemd-analyze', 'verify', *[str(path) for _, path in installed]])
        run(['systemctl', 'daemon-reload'])
        for service in units:
            unit = UNITS[service]
            started.append(unit)
            run(['systemctl', 'start', '--no-block', unit])
            if service == 'redis-mailcow':
                redis = Redis((network.addresses[service], 6379), protected_file(store.root / 'operator/redis.password'))
                def ready(): return redis.command('PING') == b'PONG'
            elif service == 'mysql-mailcow':
                sockets = [source / 'mysqld.sock' for source, target in profiles[unit].writable
                           if target.rstrip('/') in ('/var/run/mysqld', '/run/mysqld')]
                if len(sockets) != 1: raise ValueError('One shared packaged SQL socket required')
                def ready():
                    with socket.socket(socket.AF_UNIX) as client:
                        client.settimeout(.3); client.connect(str(sockets[0]))
                        return bool(client.recv(1))
            else:
                def ready():
                    with socket.create_connection((network.addresses[service], 9000), timeout=.3): return True
            until(unit, ready, 90 if service != 'php-fpm-mailcow' else 180)
        mysql = UNITS['mysql-mailcow']
        sockets = [source / 'mysqld.sock' for source, target in profiles[mysql].writable
                   if target.rstrip('/') in ('/var/run/mysqld', '/run/mysqld')]
        admin = store.root / 'data/generated/mysql-admin.cnf'
        query = run(['/usr/bin/mariadb', '--defaults-extra-file=' + str(admin), '--socket=' + str(sockets[0]),
                     '--batch', '--skip-column-names', '--execute',
                     "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='mailcow' AND table_name='versions';"])
        if query.stdout.strip() != b'1': raise RuntimeError('PHP schema bootstrap incomplete')
        result = {'passed': True, 'prepared18ExactRootTrees': prepared['prepared18ExactRootTrees'],
                  'actualRedisAuthenticatedPing': True, 'actualMariaDBSocketHandshake': True,
                  'actualPHPFpmListeningAndSchemaVersionsObserved': True,
                  'nativeControlSocket': control.exists(), 'privateNetwork': network_active,
                  'full18ServiceParity': False, 'noProductionDataOrOutboundMail': True}
    except BaseException as error:
        operation_error = error
    try:
        for unit in reversed(started):
            run(['systemctl', 'stop', unit], timeout=110)
        for unit, _ in installed:
            if not manager_unit_absent(unit): raise RuntimeError('Manager still observes fixture unit or job')
        groups = [Path('/sys/fs/cgroup/system.slice') / unit for unit, _ in installed]
        if not cgroups_empty([*groups, ACTION_CGROUP, JOB_CGROUP]):
            raise RuntimeError('Unresolved native fixture writer cgroup')
        if controller is not None:
            if controller.poll() is None: controller.send_signal(signal.SIGTERM)
            controller.wait(timeout=30)
            if controller.returncode != 0: raise RuntimeError('Native controller exited abnormally')
            if (root / 'canonical/operator/control.sock').exists():
                raise RuntimeError('Native controller socket still present')
        if network and (network_active or network.created or network.links or network.bridge_created or network.firewall_created):
            network.close(); network_active = False
        for _, path in installed: path.unlink()
        if installed: run(['systemctl', 'daemon-reload'])
        shutil.rmtree(base)
    except BaseException as cleanup_error:
        # No recursive data deletion or unit removal on uncertain state. The
        # offhost runner is ephemeral, but preserve exact evidence until exit.
        raise RuntimeError('Synthetic packaged stack retained: cleanup requires operator review') from cleanup_error
    if operation_error: raise operation_error
    result['cleanupConfirmed'] = True
    output.write_text(json.dumps(result, indent=2)+'\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); rehearse(args.artifacts, args.output)
