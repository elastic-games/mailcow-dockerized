"""Concrete off-host 18-service bridge/namespaces, no public routes or writers.

This is combined-stack rehearsal plumbing. Production IPv6, mail-specific
host firewall/DNAT, egress and netfilter adapter acceptance remain separate
gates; this module cannot publish ports or install a default route/NAT rule.
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from action_policy import UNITS
from runtime_config import addresses


class Network:
    def __init__(self, project, tag, subnet):
        if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,62}', project) or not re.fullmatch(r'[0-9a-f]{8}', tag): raise ValueError('Fixed fixture identity required')
        self.project, self.tag, self.subnet = project, tag, ipaddress.ip_network(subnet, strict=True)
        self.addresses = addresses(subnet)
        self.bridge, self.table = 'mcbr-' + tag, 'mcfixture_' + tag
        self.namespaces = {service: 'mc-' + tag + '-' + str(index) for index, service in enumerate(UNITS)}
        self.created = []; self.links = []; self.bridge_created = self.firewall_created = False

    def aliases(self):
        manifest = json.loads(Path(__file__).with_name('runtime-manifest.json').read_text())
        result = {}
        for row in manifest['services']:
            names = {row['service'], row['service'].removesuffix('-mailcow')}
            for network in row['networkTemplates'].values(): names.update(network.get('aliases', []))
            for name in names:
                for alias in (name, name + '.' + self.project + '_mailcow-network'):
                    if alias in result and result[alias] != self.addresses[row['service']]: raise ValueError('Conflicting DNS identity')
                    result[alias] = self.addresses[row['service']]
        return result

    def resolver_files(self):
        # dig does not use /etc/hosts, so Unbound authoritative local-data is
        # required in addition to hosts for the actual bootstrap consumers.
        aliases = self.aliases()
        hosts = '127.0.0.1 localhost\n::1 localhost\n' + ''.join(address + ' ' + name + '\n' for name, address in sorted(aliases.items()))
        unbound = 'server:\n' + ''.join('  local-data: "' + name + ' A ' + address + '"\n' for name, address in sorted(aliases.items()))
        resolv = 'nameserver ' + self.addresses['unbound-mailcow'] + '\nsearch ' + self.project + '_mailcow-network\noptions timeout:2 attempts:2\n'
        return {'hosts': hosts, 'unbound-local.conf': unbound, 'resolv.conf': resolv}

    def firewall(self):
        # New service-to-host connections and every routed external packet are
        # denied. Host controller initiated private connections get replies.
        return ('table inet ' + self.table + ' {\n'
                ' chain input { type filter hook input priority -5; policy accept;\n'
                '  iifname "' + self.bridge + '" ct state established,related accept\n'
                '  iifname "' + self.bridge + '" drop\n }\n'
                ' chain forward { type filter hook forward priority -5; policy accept;\n'
                '  iifname "' + self.bridge + '" oifname != "' + self.bridge + '" drop\n }\n}\n')

    @staticmethod
    def run(argv, data=None):
        return subprocess.run(argv, input=data, check=True, timeout=15, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    def create(self):
        if sys.platform != 'linux' or os.geteuid() != 0: raise PermissionError('Off-host root Linux fixture operator required')
        if Path('/sys/class/net', self.bridge).exists() or any(Path('/run/netns', name).exists() for name in self.namespaces.values()):
            raise FileExistsError('Existing network identity must not be replaced')
        table = subprocess.run(['/usr/sbin/nft', 'list', 'table', 'inet', self.table], timeout=15, capture_output=True)
        if table.returncode == 0: raise FileExistsError('Existing fixture firewall identity must not be modified')
        if b'No such file or directory' not in table.stderr: raise RuntimeError('Firewall ownership cannot be observed safely')
        self.run(['/usr/sbin/ip', 'link', 'add', self.bridge, 'type', 'bridge']); self.bridge_created = True
        try:
            self.run(['/usr/sbin/ip', 'address', 'add', str(self.subnet.network_address + 1) + '/24', 'dev', self.bridge])
            self.run(['/usr/sbin/ip', 'link', 'set', self.bridge, 'up'])
            # No host-wide sysctl, default route, MASQUERADE or port publication.
            self.run(['/usr/sbin/nft', '-f', '-'], self.firewall().encode()); self.firewall_created = True
            for index, service in enumerate(UNITS):
                namespace = self.namespaces[service]
                self.run(['/usr/sbin/ip', 'netns', 'add', namespace]); self.created.append(namespace)
                host, peer = 'mcv-' + self.tag + '-' + str(index), 'mcp-' + self.tag + '-' + str(index)
                self.run(['/usr/sbin/ip', 'link', 'add', host, 'type', 'veth', 'peer', 'name', peer])
                self.links.append(host)
                self.run(['/usr/sbin/ip', 'link', 'set', peer, 'netns', namespace])
                self.run(['/usr/sbin/ip', 'link', 'set', host, 'master', self.bridge])
                self.run(['/usr/sbin/ip', 'link', 'set', host, 'up'])
                self.run(['/usr/sbin/ip', '-n', namespace, 'link', 'set', peer, 'name', 'eth0'])
                self.run(['/usr/sbin/ip', '-n', namespace, 'address', 'add', self.addresses[service] + '/24', 'dev', 'eth0'])
                self.run(['/usr/sbin/ip', '-n', namespace, 'link', 'set', 'lo', 'up'])
                self.run(['/usr/sbin/ip', '-n', namespace, 'link', 'set', 'eth0', 'up'])
                self.run(['/usr/sbin/ip', 'netns', 'exec', namespace, '/usr/sbin/sysctl', '-qw', 'net.ipv4.ip_unprivileged_port_start=0'])
        except BaseException:
            self.close(); raise

    def close(self):
        # Fixture daemons must already be stopped; never kill clients to tear
        # down the network. Names are only those this object actually created.
        while self.created:
            namespace = self.created[-1]
            pids = subprocess.check_output(['/usr/sbin/ip', 'netns', 'pids', namespace], timeout=15).strip()
            if pids: raise RuntimeError('Active fixture process prevents network removal')
            self.run(['/usr/sbin/ip', 'netns', 'delete', namespace])
            self.created.pop()
        while self.links:
            link = self.links[-1]
            if Path('/sys/class/net', link).exists():
                try: self.run(['/usr/sbin/ip', 'link', 'delete', link])
                except subprocess.CalledProcessError:
                    # Namespace removal can delete the veth pair between the
                    # existence check and ip link. Only confirmed absence is
                    # safe to accept; retain a live link for operator review.
                    if Path('/sys/class/net', link).exists(): raise
            self.links.pop()
        if self.firewall_created:
            self.run(['/usr/sbin/nft', 'delete', 'table', 'inet', self.table]); self.firewall_created = False
        if self.bridge_created:
            self.run(['/usr/sbin/ip', 'link', 'delete', self.bridge]); self.bridge_created = False
