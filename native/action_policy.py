"""Typed native replacement policy for Mailcow DockerApi's complete action set.

This is the compile/authorization boundary, deliberately separate from a
privileged executor. No request can choose an executable, arbitrary unit, shell,
credential, or filesystem root. Integration remains staged until native replay
and all mail parity gates pass. HTTP and MC_CHANNEL share the same compiler.
"""
from dataclasses import dataclass
import re
from typing import Any

SERVICES = ('unbound', 'mysql', 'redis', 'clamd', 'rspamd', 'php-fpm', 'sogo',
            'dovecot', 'postfix', 'postfix-tlspol', 'memcached', 'nginx', 'acme',
            'netfilter', 'watchdog', 'dockerapi', 'olefy', 'ofelia')
UNITS = {service + '-mailcow': 'mailcow-' + ('mariadb' if service == 'mysql' else service) + '.service' for service in SERVICES}
RIGHTS = frozenset(('admin', 'create', 'delete', 'expunge', 'insert', 'lookup', 'post', 'read', 'write', 'write-deleted', 'write-seen'))
EXEC_ACTIONS = {
    'mailq': ('delete', 'hold', 'cat', 'unhold', 'deliver', 'list', 'flush', 'super_delete'),
    'system': ('fts_rescan', 'df', 'mysql_upgrade', 'mysql_tzinfo_to_sql'),
    'reload': ('dovecot', 'postfix', 'nginx'),
    'sieve': ('list', 'print'),
    'maildir': ('cleanup', 'move'),
    'rspamd': ('worker_password',),
    'sogo': ('rename_user',),
    'doveadm': ('get_acl', 'delete_acl', 'set_acl'),
}
OPERATIONS = frozenset(['stop', 'start', 'restart', 'top', 'stats'] + ['exec__' + cmd + '__' + task for cmd, tasks in EXEC_ACTIONS.items() for task in tasks])


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Plan:
    operation: str
    unit: str
    primitive: str
    argv: tuple[str, ...] = ()
    fields: tuple[tuple[str, Any], ...] = ()


def text(value, name, limit=1024):
    if not isinstance(value, str) or not value or len(value) > limit or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise PolicyError('Invalid ' + name)
    return value


def maildir(value):
    value = text(value, 'maildir', 512)
    parts = value.split('/')
    if len(parts) != 2 or any(not part or part in ('.', '..') or part.startswith('.') for part in parts) or '\\' in value:
        raise PolicyError('Maildir must be one exact domain/user namespace')
    return value


def compile_action(service, action, request):
    if service not in UNITS or not isinstance(request, dict):
        raise PolicyError('Unknown native mail service or request')
    unit = UNITS[service]
    operation = action
    if action == 'exec':
        operation = 'exec__' + str(request.get('cmd', '')) + '__' + str(request.get('task', ''))
    if operation not in OPERATIONS:
        raise PolicyError('Unknown native mail action')
    if operation in ('start', 'stop', 'restart'):
        return Plan(operation, unit, 'unit-control', ('/usr/bin/systemctl', operation, '--', unit))
    if operation in ('top', 'stats'):
        return Plan(operation, unit, 'unit-observation')
    cmd, task = request['cmd'], request['task']
    required = {'mailq': 'postfix-mailcow', 'sieve': 'dovecot-mailcow', 'maildir': 'dovecot-mailcow',
                'rspamd': 'rspamd-mailcow', 'sogo': 'sogo-mailcow', 'doveadm': 'dovecot-mailcow'}.get(cmd)
    if cmd == 'reload': required = task + '-mailcow'
    if cmd == 'system':
        required = {'fts_rescan': 'dovecot-mailcow', 'mysql_upgrade': 'mysql-mailcow', 'mysql_tzinfo_to_sql': 'mysql-mailcow'}.get(task)
    if required and service != required:
        raise PolicyError('Action target mismatch')
    if cmd == 'mailq':
        fixed = {'list': ('/usr/sbin/postqueue', '-j'), 'flush': ('/usr/sbin/postqueue', '-f'), 'super_delete': ('/usr/sbin/postsuper', '-d', 'ALL')}
        if task in fixed: return Plan(operation, unit, 'argv', fixed[task])
        items = request.get('items')
        if not isinstance(items, list) or not 1 <= len(items) <= 1000 or any(not isinstance(item, str) or not re.fullmatch('[0-9a-fA-F]+', item) or len(item) > 64 for item in items):
            raise PolicyError('Invalid queue IDs')
        if task == 'cat': return Plan(operation, unit, 'argv', ('/usr/sbin/postcat', '-q', *items))
        if task == 'deliver': return Plan(operation, unit, 'queue-delivery-batch', fields=(('items', tuple(items)),))
        flag = {'delete': '-d', 'hold': '-h', 'unhold': '-H'}[task]
        return Plan(operation, unit, 'argv', ('/usr/sbin/postsuper', *(item for queue_id in items for item in (flag, queue_id))))
    if cmd == 'reload': return Plan(operation, unit, 'unit-control', ('/usr/bin/systemctl', 'reload', '--', unit))
    if cmd == 'system':
        if task == 'fts_rescan':
            argv = ('/usr/bin/doveadm', 'fts', 'rescan')
            if 'username' in request: argv += ('-u', text(request['username'], 'username'))
            elif 'all' in request: argv += ('-A',)
            else: raise PolicyError('Missing rescan scope')
            return Plan(operation, unit, 'argv', argv)
        if task == 'df':
            directory = text(request.get('dir'), 'disk path')
            if directory not in ('/var/vmail', '/var/vmail_index', '/var/lib/mysql', '/var/spool/postfix'):
                raise PolicyError('Disk path outside mail state')
            return Plan(operation, unit, 'disk-observation', ('/bin/df', '-H', '--', directory))
        # Root-only helpers use local MariaDB Unix socket/defaults-file. No DBROOT
        # password travels in argv, request, Redis message or generated plan.
        return Plan(operation, unit, 'database-maintenance', fields=(('task', task),))
    if cmd == 'sieve':
        argv = ('/usr/bin/doveadm', 'sieve', 'list' if task == 'list' else 'get', '-u', text(request.get('username'), 'username'))
        if task == 'print': argv += (text(request.get('script_name'), 'Sieve script'),)
        return Plan(operation, unit, 'argv', argv)
    if cmd == 'maildir':
        if task == 'cleanup': fields = (('maildir', maildir(request.get('maildir'))),)
        else: fields = (('old_maildir', maildir(request.get('old_maildir'))), ('new_maildir', maildir(request.get('new_maildir'))))
        return Plan(operation, unit, 'maildir-transaction', fields=fields)
    if cmd == 'rspamd':
        # Secret belongs in an in-memory/stdin envelope, never printable Plan.
        raw = text(request.get('raw'), 'Rspamd controller secret', 4096)
        return Plan(operation, unit, 'rspamd-controller-password', fields=(('secretProvided', bool(raw)),))
    if cmd == 'sogo':
        return Plan(operation, unit, 'argv', ('/usr/sbin/sogo-tool', 'rename-user', text(request.get('old_username'), 'old username'), text(request.get('new_username'), 'new username')))
    if cmd == 'doveadm':
        if task == 'get_acl':
            return Plan(operation, unit, 'acl-inventory', fields=(('id', text(request.get('id'), 'ACL identity')),))
        user, mailbox, identity = (text(request.get(field), field) for field in ('user', 'mailbox', 'id'))
        argv = ('/usr/bin/doveadm', 'acl', 'delete' if task == 'delete_acl' else 'set', '-u', user, mailbox, 'user=' + identity)
        if task == 'set_acl':
            rights = request.get('rights')
            if not isinstance(rights, list) or not rights or any(not isinstance(right, str) or right.lower() not in RIGHTS for right in rights):
                raise PolicyError('Invalid ACL rights')
            argv += tuple(right.lower() for right in rights)
        return Plan(operation, unit, 'argv', argv)
    raise PolicyError('Uncompiled operation')


def compile_pubsub(message):
    if not isinstance(message, dict) or message.get('api_call') != 'container_post':
        raise PolicyError('Unknown MC_CHANNEL message')
    return compile_action(message.get('container_name'), message.get('post_action'), message.get('request') or {})
