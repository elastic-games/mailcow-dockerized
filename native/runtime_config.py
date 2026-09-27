"""Protected operator configuration for the off-host native control rehearsal.

No application request selects roots, mounts, network identities or secrets.
Configuration/credentials remain outside the lease directory exposed read-only
to foreground guards. Production activation is not a supported mode yet.
"""
from contextlib import contextmanager
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
from action_policy import UNITS
from canonical_store import CanonicalStore
from rooted_paths import DIRECTORY_FLAGS
from service_executor import Profile

CONTROL_PEERS = frozenset(('php-fpm-mailcow', 'watchdog-mailcow', 'acme-mailcow', 'dovecot-mailcow'))
FIXED_HOSTS = {'unbound-mailcow': 254, 'redis-mailcow': 249, 'sogo-mailcow': 248,
               'dovecot-mailcow': 250, 'postfix-mailcow': 253}


@contextmanager
def controlled_directory(path):
    """Pin each ancestor; root ownership and no group/other writes to '/'."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Absolute stable operator ancestry required')
    handles = []
    try:
        handles.append(os.open('/', DIRECTORY_FLAGS))
        for component in (None, *path.parts[1:]):
            if component is not None:
                handles.append(os.open(component, DIRECTORY_FLAGS, dir_fd=handles[-1]))
            info = os.fstat(handles[-1])
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise PermissionError('Root-controlled non-writable ancestry required')
        yield handles[-1]
    finally:
        for handle in reversed(handles): os.close(handle)


def protected_file(path, maximum=1048576):
    path = Path(path)
    if not path.is_absolute(): raise ValueError('Absolute protected operator path required')
    with controlled_directory(path.parent) as parent:
        info = os.fstat(parent)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700: raise PermissionError('Root-owned 0700 operator directory required')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > maximum:
                raise PermissionError('Protected bounded operator file required')
            with os.fdopen(fd, 'rb', closefd=False) as file: return file.read(maximum + 1)
        finally: os.close(fd)


def protected_directory(path):
    path = Path(path)
    if not path.is_absolute(): raise ValueError('Absolute runtime ancestor required')
    with controlled_directory(path) as directory:
        info = os.fstat(directory)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700: raise PermissionError('Root-owned 0700 runtime ancestor required')
    return path


def canonical_path(root, relative):
    if not isinstance(relative, str) or Path(relative).is_absolute() or not relative or '..' in Path(relative).parts:
        raise ValueError('Fixed relative canonical bind source required')
    parts = Path(relative).parts
    if not parts: raise ValueError('Named canonical bind source required')
    if parts[0] in ('operator', '.control'): raise PermissionError('Operator credentials/control are not service bind sources')
    with controlled_directory(root / Path(*parts[:-1])) as parent:
        info = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)): raise PermissionError('Regular no-symlink bind source required')
    return root / relative


def addresses(network):
    subnet = ipaddress.ip_network(network, strict=True)
    private = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')
    if subnet.version != 4 or subnet.prefixlen != 24 or not any(subnet.subnet_of(ipaddress.ip_network(range_)) for range_ in private):
        raise ValueError('Reviewed RFC1918 IPv4 /24 required')
    next_host = iter(range(10, 100))
    return {service: str(subnet.network_address + (FIXED_HOSTS[service] if service in FIXED_HOSTS else next(next_host))) for service in UNITS}


def load(path):
    config = json.loads(protected_file(path))
    if set(config) != {'schema', 'mode', 'project', 'canonicalRoot', 'releaseRoot', 'networkTag', 'ipv4Network', 'profiles', 'replication'} or type(config['schema']) is not int or config['schema'] != 1:
        raise ValueError('Exact operator configuration schema required')
    if config['mode'] != 'offhost-rehearsal': raise PermissionError('Production native mail activation remains gated')
    if not isinstance(config['networkTag'], str) or not re.fullmatch(r'[0-9a-f]{8}', config['networkTag']): raise ValueError('Fixed network tag required')
    if set(config['profiles']) != set(UNITS): raise ValueError('Complete registered service inventory required')
    canonical = protected_directory(config['canonicalRoot']); release = protected_directory(config['releaseRoot'])
    operator = protected_directory(canonical / 'operator')
    if Path(path) != operator / 'runtime.json': raise ValueError('Configuration outside fixed operator area')
    store = CanonicalStore(canonical)
    with store.lease('native'): pass
    network = addresses(config['ipv4Network'])
    profiles = {}
    for index, (service, unit) in enumerate(UNITS.items()):
        row = config['profiles'][service]
        if set(row) != {'readOnly', 'writable'}: raise ValueError('Exact bind profile schema required')
        root = release / 'roots' / service / 'rootfs'
        with controlled_directory(root.parent) as parent:
            info = os.stat(root.name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode): raise PermissionError('Stable immutable runtime root required')
        readonly = [(release / 'native', '/run/mailcow-native'), (release / 'bin/mailcow-log-pipe', '/run/mailcow-log-pipe'),
                    (store.control, '/run/mailcow-lease')]
        if service in CONTROL_PEERS: readonly.append((operator / 'control.sock', '/run/mailcow-control.sock'))
        writable = []
        for key, output in (('readOnly', readonly), ('writable', writable)):
            for binding in row[key]:
                if set(binding) != {'source', 'destination'}: raise ValueError('Exact canonical bind shape required')
                destination = binding['destination']
                if not isinstance(destination, str): raise ValueError('Absolute service destination required')
                if destination.startswith('/var/run/'): destination = '/run/' + destination[9:]
                reserved = ('/run/mailcow-lease', '/run/mailcow-control.sock', '/run/mailcow-native', '/run/mailcow-log-pipe')
                if any(destination == item or destination.startswith(item + '/') or item.startswith(destination.rstrip('/') + '/') for item in reserved):
                    raise PermissionError('Foreground operator binding cannot be overridden')
                output.append((canonical_path(canonical, binding['source']), binding['destination']))
        environment = operator / 'environment' / service
        protected_file(environment)
        namespace = Path('/run/netns') / ('mc-' + config['networkTag'] + '-' + str(index))
        profiles[unit] = Profile(unit, root, namespace, tuple(readonly), tuple(writable), environment)
    # A privileged service can mutate every parent exposed through a writable
    # mount, even if its host uid/mode presently appear root-controlled. Keep
    # bind roots whole and stable; never later mount a descendant via that parent.
    sources = [source for profile in profiles.values() for source, _ in (*profile.readonly, *profile.writable)]
    writable_sources = {source for profile in profiles.values() for source, _ in profile.writable}
    for writable_source in writable_sources:
        if any(source != writable_source and source.is_relative_to(writable_source) for source in sources):
            raise PermissionError('Bind source beneath service-writable ancestor rejected')
    return config, store, profiles, network
