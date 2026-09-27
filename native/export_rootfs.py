"""Off-host Linux root-tree exporter from digest-pinned public OCI inputs.

No production credentials/data/config input. Target builder must be root Linux
x86_64 with skopeo/umoci/GNU tar/unshare. Never run this on the production VPS.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile

PINS = Path(__file__).with_name('pinned-images.json')
PROBES = {
    'unbound-mailcow': ['/usr/sbin/unbound', '-V'], 'dovecot-mailcow': ['/usr/sbin/dovecot', '--version'],
    'postfix-mailcow': ['/usr/sbin/postconf', '-h', 'mail_version'], 'rspamd-mailcow': ['/usr/bin/rspamd', '--version'],
    'nginx-mailcow': ['/usr/sbin/nginx', '-v'], 'clamd-mailcow': ['/usr/sbin/clamd', '--version'],
    'redis-mailcow': ['/usr/local/bin/redis-server', '--version'], 'mysql-mailcow': ['/usr/bin/mariadb', '--version'],
    'memcached-mailcow': ['/usr/local/bin/memcached', '-V'], 'php-fpm-mailcow': ['/usr/local/bin/php', '-v'],
    'sogo-mailcow': ['/usr/sbin/sogo-tool', '--help'],
    'olefy-mailcow': ['/usr/bin/python3', '-c', 'import oletools.olevba; print("oletools-import-ok")'],
}


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, timeout=600, **kwargs)


def export(service, output):
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'amd64') or os.geteuid() != 0:
        raise RuntimeError('Off-host root Linux x86_64 builder required')
    pins = json.loads(PINS.read_text())
    row = next((row for row in pins if row['service'] == service), None)
    if row is None or not re.fullmatch(r'[a-z0-9./_-]+@sha256:[0-9a-f]{64}', row['image']):
        raise ValueError('Unknown service or unpinned OCI source')
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='mailcow-native-build-') as temp:
        scratch = Path(temp); layout = scratch/'oci'; bundle = scratch/'bundle'
        raw = run(['skopeo', 'inspect', '--raw', 'docker://'+row['image']], stdout=subprocess.PIPE).stdout
        source_digest = hashlib.sha256(raw).hexdigest()
        if source_digest != row['image'].split('sha256:')[1]:
            raise RuntimeError('Registry source manifest digest mismatch')
        # Preserve digests; fail rather than silently re-encode a source manifest.
        run(['skopeo', '--override-os', 'linux', '--override-arch', 'amd64', 'copy', '--preserve-digests',
             'docker://'+row['image'], 'oci:'+str(layout)+':mailcow'])
        run(['umoci', 'unpack', '--image', str(layout)+':mailcow', str(bundle)])
        root = bundle/'rootfs'
        config = json.loads((bundle/'config.json').read_text())
        image_index = json.loads((layout/'index.json').read_text())
        probe = PROBES.get(service)
        receipt = {'service':service, 'sourceImage':row['image'], 'sourceManifestSHA256':source_digest,
                   'ociManifestDescriptors':image_index['manifests'], 'architecture':'linux/amd64',
                   'nativeArgs':config['process']['args'], 'imageEnvironmentKeys': sorted(x.split('=',1)[0] for x in config['process'].get('env',[])),
                   'sourceUser':config['process']['user'], 'sourceRootfsByteHint':row['unpackedBytes'],
                   'probe':probe, 'probePassed':False, 'probeOutput':None, 'noProductionData':True}
        if probe:
            # Isolated PID/mount/network; versions/help/import only. No daemon
            # listener, mail writer, scheduler, production state or public route.
            checked = run(['unshare', '--mount', '--net', '--pid', '--fork', 'chroot', str(root), *probe], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            receipt['probePassed'] = True
            receipt['probeOutput'] = checked.stdout.decode(errors='replace')[:2000]
        # Numeric IDs, modes, xattrs, hardlinks/ACLs and sparse files retained.
        artifact = output/(service+'.rootfs.tar.gz')
        run(['tar', '--numeric-owner', '--xattrs', '--acls', '--sparse', '--one-file-system', '-czf', str(artifact), '-C', str(root), '.'])
        receipt['artifactBytes'] = artifact.stat().st_size
        with artifact.open('rb') as source:
            hasher = hashlib.sha256()
            while block := source.read(1024*1024): hasher.update(block)
        receipt['artifactSHA256'] = hasher.hexdigest()
        (output/(service+'.receipt.json')).write_text(json.dumps(receipt,indent=2)+'\n')
        (output/(service+'.rootfs.tar.gz.sha256')).write_text(receipt['artifactSHA256']+'  '+artifact.name+'\n')
        return receipt


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--service',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(export(args.service,args.output),indent=2))
