"""Verify raw public pinned manifest/config before using packaged defaults.

Only immutable public registry metadata is read. No Docker daemon, live config,
registry login or production environment is accepted by this offhost builder.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess


def raw_inspect(image, config=False):
    argv = ['skopeo', 'inspect', '--raw', '--no-creds', '--tls-verify=true']
    if config: argv.append('--config')
    result = subprocess.run([*argv, 'docker://' + image], check=True, timeout=90, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if len(result.stdout) > 4 * 1024 * 1024: raise ValueError('Bounded public image metadata required')
    return result.stdout


def metadata(pin):
    source = pin['sourceImage']
    if not re.fullmatch(r'[a-z0-9./_-]+@sha256:[0-9a-f]{64}', source): raise ValueError('Pinned public image required')
    selected = pin['selectedManifestDigest']
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', selected): raise ValueError('Pinned selected manifest required')
    top = raw_inspect(source)
    if hashlib.sha256(top).hexdigest() != source.split('sha256:')[1]: raise ValueError('Public source manifest changed')
    document = json.loads(top)
    if 'manifests' in document:
        descriptor = next((row for row in document['manifests'] if row['digest'] == selected), None)
        if not descriptor or descriptor.get('platform', {}).get('architecture') != 'amd64' or descriptor['platform'].get('os') != 'linux':
            raise ValueError('Selected public manifest not native Linux amd64')
    elif selected != 'sha256:' + hashlib.sha256(top).hexdigest():
        raise ValueError('Unexpected single-image manifest selection')
    image = source.split('@')[0] + '@' + selected
    manifest = raw_inspect(image)
    if 'sha256:' + hashlib.sha256(manifest).hexdigest() != selected: raise ValueError('Selected manifest changed')
    config_raw = raw_inspect(image, True)
    if 'sha256:' + hashlib.sha256(config_raw).hexdigest() != json.loads(manifest)['config']['digest']:
        raise ValueError('Public image configuration changed')
    config = json.loads(config_raw)
    if config.get('architecture') != 'amd64' or config.get('os') != 'linux': raise ValueError('Native image ABI required')
    process = config['config']
    return {'entrypoint': process.get('Entrypoint') or [], 'command': process.get('Cmd') or [],
            'environment': process.get('Env') or [], 'workingDirectory': process.get('WorkingDir') or '/',
            'imageUser': process.get('User') or '', 'configSHA256': hashlib.sha256(config_raw).hexdigest()}
