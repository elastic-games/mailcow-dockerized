"""Prepare actual pinned packaged stack/state from public artifacts offhost.

Fresh synthetic store only. No production data/config input, Docker socket,
certificate import, live unit installation or public/outbound route. This stage
prepares daemon roots and commands; readiness/workflow acceptance is separate.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import stat
from canonical_store import CanonicalStore
from fixture_network import Network
from image_metadata import metadata
from runtime_config import controlled_directory

SOURCE = Path(__file__).resolve().parents[1]
NATIVE = SOURCE / 'native'
BASELINE = '02552ffefdf0869f988edf4a7e03822e8b467b34'
# Whole image config trees can change; generated script files are mounted
# separately, never a writable entire /usr or arbitrary host ancestor.
MUTABLE = {
 'dovecot-mailcow': ('/var/volatile', '/usr/lib/dovecot/sieve', '/source_env.sh', '/usr/local/bin/maildir_gc.sh', '/usr/local/bin/quota_notify.py'),
 'php-fpm-mailcow': ('/usr/local/etc/php',),
 'postfix-mailcow': ('/var/spool/postfix', '/var/lib/postfix'),
 'postfix-tlspol-mailcow': ('/var/lib/postfix-tlspol',),
 'sogo-mailcow': ('/var/lib/sogo', '/var/log/sogo'),
 'redis-mailcow': ('/redis.conf',),
}


def run(argv):
    return subprocess.run(argv, check=True, timeout=120, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def sha(path):
    result = hashlib.sha256()
    with path.open('rb') as file:
        for block in iter(lambda: file.read(1048576), b''): result.update(block)
    return result.hexdigest()


def environment_rows(compose, variables):
    rows = compose.get('environment', [])
    if isinstance(rows, dict): rows = [key + '=' + str(value) for key, value in rows.items()]
    output = {}
    def interpolate(match):
        name, operator, default = match.groups()
        if operator == ':-': return variables.get(name) or default or ''
        if operator == '-': return variables.get(name, default or '')
        return variables.get(name, '')
    for row in rows:
        key, value = row.split('=', 1) if '=' in row else (row, variables.get(row, ''))
        if not re.fullmatch(r'[A-Z][A-Z0-9_]*', key): raise ValueError('Closed Compose environment key required')
        value = re.sub(r'\$\{([A-Z][A-Z0-9_]*)(:-|-)?([^}]*)\}', interpolate, value)
        if '\x00' in value or '\n' in value or '\r' in value: raise ValueError('Single-line synthetic environment required')
        output[key] = value
    return output


def write_environment(path, values):
    # systemd EnvironmentFile has no shell substitution. Quote its literal
    # values, retaining generated synthetic secrets within operator0700 only.
    if any(not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key) or not isinstance(value, str) or any(char in value for char in ('\x00', '\n', '\r')) for key, value in values.items()):
        raise ValueError('Typed literal environment required')
    text = ''.join(key + '="' + value.replace('\\', '\\\\').replace('"', '\\"').replace('`', '\\`').replace('$', '\\$') + '"\n' for key, value in sorted(values.items()))
    path.write_text(text); path.chmod(0o600)


def copy_tree(source, destination, preserve=False):
    if preserve and source.exists():
        run(['cp', '--archive', '--preserve=all', '--no-dereference', '--', str(source), str(destination)])
        return
    if source.is_dir(): shutil.copytree(source, destination, symlinks=True)
    elif source.exists(): shutil.copy2(source, destination, follow_symlinks=False)
    else: destination.mkdir()


def image_path(root, absolute):
    """Resolve public image symlinks using chroot semantics, never host '/run'."""
    if not Path(absolute).is_absolute(): raise ValueError('Absolute image path required')
    pending = list(Path(absolute).parts[1:]); resolved = []; links = 0
    while pending:
        part = pending.pop(0)
        if part in ('', '.'): continue
        if part == '..':
            if resolved: resolved.pop()
            continue
        candidate = root.joinpath(*resolved, part)
        try: info = candidate.lstat()
        except FileNotFoundError: resolved.append(part); continue
        if stat.S_ISLNK(info.st_mode):
            links += 1
            if links > 40: raise ValueError('Image symlink cycle')
            target = os.readlink(candidate)
            if target.startswith('/'): resolved = []
            pending = [*Path(target).parts[1 if target.startswith('/') else 0:], *pending]
        else: resolved.append(part)
    return root.joinpath(*resolved)


def public_source(relative):
    """Read only public source paths, without traversing checkout symlinks."""
    parts = Path(relative).parts
    if not parts or parts[0] != 'data' or any(part in ('', '.', '..') for part in parts):
        raise ValueError('Public data source required')
    current = SOURCE
    for part in parts:
        current /= part
        try: mode = current.lstat().st_mode
        except FileNotFoundError: return SOURCE.joinpath(*parts)
        if stat.S_ISLNK(mode): raise PermissionError('Public source symlink not followed')
    return current


def verified_archive(source, destination, pin):
    """Seal copied bytes before privileged tar reopens a pathname."""
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    hasher = hashlib.sha256(); total = 0
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode): raise ValueError('Regular pinned archive required')
        with os.fdopen(fd, 'rb', closefd=False) as file, destination.open('xb') as output:
            os.chmod(destination, 0o600)
            for block in iter(lambda: file.read(1048576), b''):
                total += len(block)
                if total > pin['archiveBytes']: raise ValueError('Pinned archive size exceeded')
                hasher.update(block); output.write(block)
            output.flush(); os.fsync(output.fileno())
        if total != pin['archiveBytes'] or hasher.hexdigest() != pin['archiveSHA256']:
            raise ValueError('Exact reviewed root archive required')
    finally: os.close(fd)
    return destination


def prepare(artifacts, destination):
    if sys.platform != 'linux' or os.geteuid() != 0: raise PermissionError('Offhost root Linux only')
    if destination.exists(): raise FileExistsError('Fresh synthetic stack root only')
    with controlled_directory(destination.parent): pass
    destination.mkdir(mode=0o700)
    release = destination / 'release'; canonical = destination / 'canonical'
    for root in (release, canonical): root.mkdir(mode=0o700)
    operator = canonical / 'operator'; operator.mkdir(mode=0o700)
    (operator / 'environment').mkdir(mode=0o700); (operator / 'spool').mkdir(mode=0o700)
    (operator / 'archives').mkdir(mode=0o700)
    CanonicalStore(canonical).activate('native', lambda: [])
    (canonical / 'data').mkdir(); (canonical / 'data/binds').mkdir(); (canonical / 'data/generated').mkdir()
    shutil.copytree(NATIVE, release / 'native', ignore=shutil.ignore_patterns('__pycache__'))
    (release / 'bin').mkdir(); run(['gcc', '-static', '-Os', '-Wall', '-Werror', '-s', '-o', str(release / 'bin/mailcow-log-pipe'), str(NATIVE / 'log_pipe.c')])
    manifest = json.loads((NATIVE / 'runtime-manifest.json').read_text())
    pins = json.loads((NATIVE / 'rootfs-artifact-pins.json').read_text())['images']
    source_pins = {row['service']: row['image'] for row in json.loads((NATIVE / 'pinned-images.json').read_text())}
    import yaml
    compose = yaml.safe_load((SOURCE / 'docker-compose.yml').read_text())['services']
    network = Network('synthetic', os.urandom(4).hex(), '172.30.66.0/24')
    variables = {'MAILCOW_HOSTNAME': 'mail.fixture.invalid', 'DBNAME': 'mailcow', 'DBUSER': 'mailcow',
                 'DBPASS': os.urandom(16).hex(), 'DBROOT': os.urandom(16).hex(), 'REDISPASS': os.urandom(16).hex(),
                 'TZ': 'America/New_York', 'COMPOSE_PROJECT_NAME': 'synthetic', 'IPV4_NETWORK': '172.30.66',
                 'IPV6_NETWORK': 'fd4d:6169:6c63:6f77::/64', 'MASTER': 'y', 'SKIP_LETS_ENCRYPT': 'y',
                 'MAILDIR_GC_TIME': '7200', 'MAILCOW_PASS_SCHEME': 'BLF-CRYPT', 'USE_WATCHDOG': 'n'}
    password = operator / 'redis.password'; password.write_text(variables['REDISPASS']); password.chmod(0o600)
    config = {'schema': 1, 'mode': 'offhost-rehearsal', 'project': 'synthetic', 'canonicalRoot': str(canonical),
              'releaseRoot': str(release), 'networkTag': network.tag, 'ipv4Network': str(network.subnet),
              'profiles': {}, 'replication': {'enabled': False}}
    images = {}; bind_cache = {}; missing_public = set(); empty_generated_dirs = set()
    for pin in pins:
        service = pin['service']
        if source_pins[service] != pin['sourceImage']: raise ValueError('Archive source differs from pinned image')
        directory = artifacts / ('native-rootfs-' + service)
        archive = verified_archive(directory / (service + '.rootfs.tar.gz'), operator / 'archives' / (service + '.tar.gz'), pin)
        root = release / 'roots' / service / 'rootfs'; root.mkdir(parents=True)
        run(['tar', '--numeric-owner', '--same-owner', '--same-permissions', '--xattrs', '--acls', '-xzf', str(archive), '-C', str(root)])
        archive.unlink()
        images[service] = metadata(pin)
        row = {'readOnly': [], 'writable': []}; config['profiles'][service] = row
        def bind(path, target, readonly=False):
            row['readOnly' if readonly else 'writable'].append({'source': str(path.relative_to(canonical)), 'destination': target})
        # Entire /etc is a stable leaf; sub-bind sources remain separate whole
        # volume roots with root-controlled parents, not descendants of /etc.
        etc = canonical / 'data/generated' / (service + '-etc'); copy_tree(image_path(root, '/etc'), etc, preserve=True)
        bind(etc, '/etc')
        for name, content in network.resolver_files().items():
            if name == 'unbound-local.conf': continue
            target = etc / name
            if target.is_symlink(): target.unlink()
            target.write_text(content)
        for mount in next(item for item in manifest['services'] if item['service'] == service)['mounts']:
            source = mount['sourceTemplate']; target = mount['destination']
            if source.startswith('/'):
                if source not in ('/var/run/docker.sock', '/lib/modules'): raise ValueError('Unexpected host mount')
                continue  # Native controller/jobs and fixed firewall adapter replace these.
            if source not in bind_cache:
                parent = canonical / 'data/binds' / hashlib.sha256(source.encode()).hexdigest()[:16]; parent.mkdir()
                path = parent / 'value'
                if source.startswith('./data/'):
                    original = public_source(source[2:])
                    if not original.exists(): missing_public.add(source)
                    copy_tree(original, path)
                elif re.fullmatch(r'[a-z0-9-]+', source):
                    initial = image_path(root, target)
                    copy_tree(initial, path, preserve=True)
                else: raise ValueError('Unreviewed public Compose source')
                bind_cache[source] = path
            bind(bind_cache[source], target, mount['readOnly'])
        for target in MUTABLE.get(service, ()):
            if any(Path(item['destination']) == Path(target) for item in row['writable']): continue
            path = canonical / 'data/generated' / (service + '-' + target.strip('/').replace('/', '-'))
            source = image_path(root, target)
            if source.exists(): copy_tree(source, path, preserve=True)
            elif target in ('/source_env.sh', '/redis.conf'): path.write_bytes(b'')
            elif target in ('/var/volatile', '/var/lib/postfix-tlspol', '/var/lib/postfix', '/var/lib/sogo', '/var/log/sogo', '/var/spool/postfix'):
                path.mkdir(); empty_generated_dirs.add(service + ':' + target)
            else: raise ValueError('Packaged mutable bootstrap source absent')
            bind(path, target)
        values = {}
        for item in images[service]['environment']:
            key, value = item.split('=', 1); values[key] = value
        values.update(environment_rows(compose[service], variables)); values['MAILCOW_NATIVE_CONTROL'] = '1'
        write_environment(operator / 'environment' / service, values)
    # Exact supported admin client defaults, private inside SQL actions only.
    # Synthetic root password stays out of command argv and public receipts.
    admin = canonical / 'data/generated/mysql-admin.cnf'
    admin.write_text('[client]\nuser=root\npassword=' + variables['DBROOT'] + '\nsocket=/run/mysqld/mysqld.sock\n')
    mysql_root = release / 'roots/mysql-mailcow/rootfs'
    account = next(row.split(':') for row in (mysql_root / 'etc/passwd').read_text().splitlines() if row.startswith('mysql:'))
    os.chown(admin, int(account[2]), int(account[3])); admin.chmod(0o600)
    config['profiles']['mysql-mailcow']['readOnly'].append({'source': str(admin.relative_to(canonical)), 'destination': '/run/mailcow-mysql-admin.cnf'})
    # Only principal Docker-dependent bootstrap changed in this first actual
    # subset; the packaged file was verified byte-identical to public baseline.
    service = 'php-fpm-mailcow'; original = release / 'roots' / service / 'rootfs/docker-entrypoint.sh'
    baseline = run(['git', '-C', str(SOURCE), 'show', BASELINE + ':data/Dockerfiles/phpfpm/docker-entrypoint.sh']).stdout
    if original.read_bytes() != baseline: raise ValueError('Packaged PHP bootstrap differs from reviewed source')
    native_bootstrap = (SOURCE / 'data/Dockerfiles/phpfpm/docker-entrypoint.sh').read_bytes()
    fd = os.open(original, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
    with os.fdopen(fd, 'wb') as file: file.write(native_bootstrap)
    # Changes occur only during this fresh protected offhost build. Daemon units
    # mount the finished root read-only; the exact original archive is retained.
    overlay = [{'service': service, 'path': '/docker-entrypoint.sh',
                'beforeSHA256': hashlib.sha256(baseline).hexdigest(),
                'afterSHA256': hashlib.sha256(native_bootstrap).hexdigest(),
                'change': 'reviewed-native-control-caller'}]
    (release / 'native-overlay.json').write_text(json.dumps(overlay, indent=2)+'\n')
    config_path = operator / 'runtime.json'; config_path.write_text(json.dumps(config, indent=2)+'\n'); config_path.chmod(0o600)
    (operator / 'image-metadata.json').write_text(json.dumps(images, indent=2)+'\n'); (operator / 'image-metadata.json').chmod(0o600)
    receipt = {'prepared18ExactRootTrees': True, 'syntheticTimezone': variables['TZ'], 'noProductionDataOrOutbound': True,
               'bootstrapsActivated': False, 'fullStackParity': False,
               'missingPublicGeneratedAssetTemplates': sorted(missing_public),
               'initiallyEmptyMutableStateDirs': sorted(empty_generated_dirs),
               'remainingRequiredAdapters': ['netfilter-host-module-firewall', 'docker-control-and-ofelia-replacements', 'acme-renewal-reload', 'packaged-bootstrap-mutable-output', 'logging', 'jobs-lifecycle', 'readiness', 'all18-combined-workflows-and-same-store-recovery']}
    return config_path, receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args(); path, receipt = prepare(args.artifacts, args.destination)
    print(json.dumps(receipt, indent=2))
