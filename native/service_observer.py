"""Docker-shaped observations from fixed native units/cgroups/private netns.

Never expose command arguments or environment. The one watchdog-required PHP
database-init command is recognized by its exact fixed argv; everything else
uses only kernel comm names. No request may select a host PID, cgroup or netns.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading
import time
from action_policy import UNITS
from service_executor import bounded


class Observer:
    def __init__(self, profiles, redis):
        if set(profiles) != set(UNITS.values()): raise ValueError('Closed observation registry required')
        self.profiles, self.redis, self.histories, self.lock = dict(profiles), redis, {}, threading.Lock()
        self.previous_cpu = None

    def cgroup(self, unit):
        if unit not in self.profiles: raise ValueError('Unknown service')
        return Path('/sys/fs/cgroup/system.slice') / unit

    def state(self, unit):
        if unit not in self.profiles: raise ValueError('Unknown service')
        code, output = bounded(['/usr/bin/systemctl', 'show', '--property=ActiveState,ExecMainStartTimestamp,ExecMainStatus', '--', unit], timeout=5)
        if code: raise RuntimeError('Mail unit state unavailable')
        fields = dict(line.split('=', 1) for line in output.decode().splitlines() if '=' in line)
        running = fields.get('ActiveState') == 'active'
        stamp = fields.get('ExecMainStartTimestamp', '')
        started = datetime.strptime(stamp, '%a %Y-%m-%d %H:%M:%S %Z').replace(tzinfo=timezone.utc).isoformat() if stamp else '0001-01-01T00:00:00Z'
        return {'Running': running, 'Status': 'running' if running else 'exited', 'StartedAt': started, 'ExitCode': int(fields.get('ExecMainStatus', '0'))}

    def top(self, unit):
        rows = []
        try: pids = (self.cgroup(unit) / 'cgroup.procs').read_text().splitlines()
        except FileNotFoundError: pids = []
        for pid in pids:
            try:
                root = Path('/proc') / pid
                comm = (root / 'comm').read_text().strip()
                command = comm
                if unit == UNITS['php-fpm-mailcow'] and comm == 'php':
                    argv = (root / 'cmdline').read_bytes().split(b'\0')
                    if argv[1:6] == [b'-c', b'/usr/local/etc/php', b'-f', b'/web/inc/init_db.inc.php', b'']:
                        command = 'php -c /usr/local/etc/php -f /web/inc/init_db.inc.php'
                rows.append([pid, command])
            except FileNotFoundError: continue
        return {'Titles': ['PID', 'CMD'], 'Processes': rows}

    def stats(self, unit):
        group = self.cgroup(unit)
        def read(name, default='0'):
            try: return (group / name).read_text().strip()
            except FileNotFoundError: return default
        cpu = dict(line.split() for line in read('cpu.stat', 'usage_usec 0').splitlines())
        usage = int(cpu['usage_usec']) * 1000
        host_cpu = sum(map(int, Path('/proc/stat').read_text().splitlines()[0].split()[1:])) * 1_000_000_000 // os.sysconf('SC_CLK_TCK')
        memory = int(read('memory.current'))
        limit = read('memory.max', 'max')
        if limit == 'max': limit = int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemTotal:'))) * 1024
        io = {'read': 0, 'write': 0}
        for row in read('io.stat', '').splitlines():
            fields = dict(item.split('=', 1) for item in row.split()[1:])
            io['read'] += int(fields.get('rbytes', 0)); io['write'] += int(fields.get('wbytes', 0))
        code, output = bounded(['/usr/sbin/ip', '-j', '-n', self.profiles[unit].network_namespace.name, '-s', 'link'], timeout=5)
        if code: raise RuntimeError('Private mail network stats unavailable')
        networks = {}
        for interface in json.loads(output):
            values = interface.get('stats64') or interface.get('stats') or {}
            networks[interface['ifname']] = {'rx_bytes': values.get('rx', {}).get('bytes', 0), 'tx_bytes': values.get('tx', {}).get('bytes', 0)}
        return {'read': datetime.now(timezone.utc).isoformat(), 'cpu_stats': {'cpu_usage': {'total_usage': usage}, 'system_cpu_usage': host_cpu, 'online_cpus': os.cpu_count()},
                'memory_stats': {'usage': memory, 'limit': int(limit)}, 'pids_stats': {'current': int(read('pids.current'))},
                'blkio_stats': {'io_service_bytes_recursive': [{'op': op, 'value': amount} for op, amount in io.items()]}, 'networks': networks}

    def stats_history(self, unit, identifier):
        with self.lock:
            history = self.histories.get(unit, [])
            history = (history + [self.stats(unit)])[-3:]
            self.histories[unit] = history
            self.redis.command('SET', identifier + '_stats', json.dumps(history), 'EX', 60)
            return history

    def host_stats(self):
        memory = {line.split(':', 1)[0]: int(line.split()[1]) * 1024 for line in Path('/proc/meminfo').read_text().splitlines()}
        cpu = list(map(int, Path('/proc/stat').read_text().splitlines()[0].split()[1:])); total, idle = sum(cpu), cpu[3] + cpu[4]
        usage = 0
        with self.lock:
            if self.previous_cpu and total > self.previous_cpu[0]: usage = 100 * (1 - (idle - self.previous_cpu[1]) / (total - self.previous_cpu[0]))
            self.previous_cpu = (total, idle)
        vm = dict(line.split() for line in Path('/proc/vmstat').read_text().splitlines())
        swap = memory['SwapTotal']; used = swap - memory['SwapFree']; page = os.sysconf('SC_PAGE_SIZE')
        result = {'cpu': {'cores': os.cpu_count(), 'usage': usage}, 'memory': {'total': memory['MemTotal'], 'usage': 100 * (1 - memory['MemAvailable'] / memory['MemTotal']),
                  'swap': [swap, used, swap - used, 100 * used / swap if swap else 0, int(vm.get('pswpin', 0)) * page, int(vm.get('pswpout', 0)) * page]},
                  'uptime': float(Path('/proc/uptime').read_text().split()[0]), 'system_time': datetime.now().strftime('%d.%m.%Y %H:%M:%S'), 'architecture': os.uname().machine}
        self.redis.command('SET', 'host_stats', json.dumps(result), 'EX', 10)
        return result
