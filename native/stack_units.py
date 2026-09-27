"""Fixed packaged-daemon systemd units, canonical foreground generation guard.

Ofelia and DockerApi are replaced by native jobs/controller. Netfilter host
adapter is a separate mandatory gate; never start its old privileged container
entrypoint with access to host netns/modules. No installation/activation here.
"""
from pathlib import Path
import re
import shlex
from action_policy import UNITS

REPLACED = frozenset(('ofelia-mailcow', 'dockerapi-mailcow', 'netfilter-mailcow'))


def quote(value):
    if not isinstance(value, str) or '\x00' in value or '\n' in value or '\r' in value: raise ValueError('Typed single-line unit argument required')
    # systemd does not use a shell; quote whitespace and suppress unit/env
    # expansion so exact packaged argv reaches the immutable foreground guard.
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%').replace('$', '$$') + '"'


def command(image, compose, variables=None):
    # The real Compose source uses entrypoint/command, while the inventory's
    # *Template keys are descriptive evidence, not executable Compose fields.
    entry = compose.get('entrypoint')
    tail = compose.get('command')
    if entry is None: entry = image['entrypoint']
    if tail is None: tail = image['command']
    variables = variables or {}
    def expand(value):
        def replace(match):
            name = match.group(1)
            if name not in variables: raise ValueError('Unresolved packaged command variable')
            return variables[name]
        return re.sub(r'\$\{([A-Z][A-Z0-9_]*)\}', replace, value)
    if isinstance(entry, str): entry = shlex.split(expand(entry))
    if isinstance(tail, str): tail = shlex.split(expand(tail))
    if not isinstance(entry, list) or not isinstance(tail, list) or not entry and not tail: raise ValueError('Packaged command required')
    return [expand(item) for item in entry + tail]


def render(service, profile, image, compose, variables=None):
    if service not in UNITS or profile.unit != UNITS[service] or service in REPLACED: raise ValueError('Registered packaged daemon required')
    cwd = image['workingDirectory']
    if not Path(cwd).is_absolute() or '..' in Path(cwd).parts: raise ValueError('Packaged root-contained cwd required')
    # User0 remains inside its private user/pid/mount boundary. Mature bootstrap
    # drops to the packaged daemon UID itself; each required cap is reviewed.
    user = image['imageUser'] or 'root'
    if ':' in user: raise ValueError('Explicit image group override requires reviewed account mapping')
    uid, gid, groups = profile.account(user)
    argv = ['/run/mailcow-log-pipe', '--lease-dir', '/run/mailcow-lease', '--generation', 'native',
            '--uid', uid, '--gid', gid, '--groups', groups, '--', *command(image, compose, variables)]
    lines = ['[Unit]', 'Description=Packaged native mail daemon ' + service,
             'After=network.target', '[Service]', 'Type=exec', 'Restart=on-failure', 'RestartSec=3',
             'TimeoutStartSec=infinity', 'TimeoutStopSec=90', 'WorkingDirectory=' + quote(cwd)]
    lines.extend(prop.replace('%', '%%').replace('$', '$$') for prop in profile.properties(action_wrapper=True))
    lines.extend(['ExecStart=' + ' '.join(quote(arg) for arg in argv), 'StandardOutput=journal', 'StandardError=journal',
                  '# Resource caps retain deployed unlimited semantics pending full-stack measurement.',
                  'MemoryMax=infinity', 'TasksMax=infinity', '[Install]', 'WantedBy=multi-user.target', ''])
    return '\n'.join(lines)
