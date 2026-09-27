"""Closed typed executor for immutable service roots and canonical state binds.

Run as the root operator's controller, never inside an application root. All
profiles are operator-owned; clients can select only action_policy operations.
Transient commands use the same isolation as their target foreground daemon.
No shell, arbitrary unit/property/path, secret argv or delegated host cgroup.
"""
from __future__ import annotations
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import threading
import time
import uuid
from action_policy import Plan, UNITS, compile_action
from control_protocol import Reply

MAX_OUTPUT = 4 * 1024 * 1024
MASTER_CAPS = ('CHOWN', 'DAC_OVERRIDE', 'DAC_READ_SEARCH', 'FOWNER', 'FSETID', 'SETGID', 'SETUID', 'SYS_CHROOT', 'KILL')
CAPS = {'mailcow-unbound.service': ('SETUID', 'SETGID'),
        'mailcow-postfix.service': MASTER_CAPS, 'mailcow-dovecot.service': MASTER_CAPS}


def manager_unit_absent(unit, runner=None):
    """Confirm manager reachable, no active unit and no pending job.

    systemctl's --output=json changes journal output, not list-units/list-jobs.
    Use the documented typed Manager D-Bus arrays via busctl JSON instead.
    Never treat an error string or missing cgroup alone as manager proof.
    """
    runner = runner or bounded
    base = ['/usr/bin/busctl', '--json=short', 'call', 'org.freedesktop.systemd1', '/org/freedesktop/systemd1', 'org.freedesktop.systemd1.Manager']
    for method, signature, width, index in (('ListUnits', 'a(ssssssouso)', 10, 0), ('ListJobs', 'a(usssoo)', 6, 1)):
        code, output = runner([*base, method], timeout=8)
        if code: return False
        response = json.loads(output)
        if response.get('type') != signature or not isinstance(response.get('data'), list) or len(response['data']) != 1 or not isinstance(response['data'][0], list):
            raise ValueError('Unexpected manager schema')
        for row in response['data'][0]:
            if not isinstance(row, list) or len(row) != width: raise ValueError('Unexpected manager row')
            if row[index] == unit:
                if method == 'ListJobs' or row[3] not in ('inactive', 'failed') or row[7] != 0: return False
    return True


def bounded(argv, data=b'', timeout=60, spool=None):
    """Capture bounded output; never echo argv/input on failure."""
    with subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          start_new_session=True) as child:
        # Inputs are bounded by HTTP/SQL limits. Write in a thread so a child
        # producing output before consuming stdin cannot deadlock the reader.
        def feed():
            try: child.stdin.write(data); child.stdin.close()
            except (BrokenPipeError, OSError): pass
        writer = threading.Thread(target=feed, daemon=True); writer.start()
        selector = selectors.DefaultSelector(); selector.register(child.stdout, selectors.EVENT_READ)
        output = bytearray(); deadline = time.monotonic() + timeout if timeout is not None else None
        try:
            while selector.get_map():
                if deadline is not None and time.monotonic() > deadline: raise TimeoutError('Native operation timed out')
                for key, _ in selector.select(.1):
                    part = os.read(key.fd, 65536)
                    if not part: selector.unregister(key.fileobj)
                    else:
                        if spool: spool.write(part)
                        else:
                            # Diagnostic/status output has a bounded prefix;
                            # never kill a state mutation because its log grows.
                            output.extend(part[:max(0, MAX_OUTPUT - len(output))])
            return child.wait(timeout=max(.1, deadline - time.monotonic()) if deadline is not None else None), spool if spool else bytes(output)
        except BaseException:
            os.killpg(child.pid, signal.SIGKILL); child.wait(timeout=5); raise
        finally: selector.close(); writer.join(timeout=1)


def safe_path(path):
    value = str(path)
    if not value.startswith('/') or any(c.isspace() or c in ':\\\x00' for c in value) or '..' in Path(value).parts:
        raise ValueError('Unambiguous absolute operator path required')
    return value


@dataclass(frozen=True)
class Profile:
    unit: str
    root: Path
    network_namespace: Path
    readonly: tuple[tuple[Path, str], ...]
    writable: tuple[tuple[Path, str], ...]
    environment_file: Path | None = None

    def properties(self, user='root'):
        if self.unit not in UNITS.values(): raise ValueError('Unregistered service profile')
        # Resolve inside immutable root, not host passwd (UID999 overlaps).
        rows = [line.split(':') for line in (self.root / 'etc/passwd').read_text().splitlines()]
        account = next((row for row in rows if row[0] == user), None)
        if not account or not account[2].isdigit() or not account[3].isdigit():
            raise ValueError('Packaged service account absent')
        properties = ['RootDirectory=' + safe_path(self.root), 'NetworkNamespacePath=' + safe_path(self.network_namespace),
                      'User=' + account[2], 'Group=' + account[3], 'PrivateUsers=full', 'PrivatePIDs=yes',
                      'MountAPIVFS=yes', 'PrivateDevices=yes', 'BindLogSockets=no', 'ProtectSystem=strict',
                      'ProtectHome=yes', 'NoNewPrivileges=yes', 'ProtectControlGroups=strict',
                      'ProtectKernelTunables=yes', 'ProtectKernelModules=yes', 'ProtectKernelLogs=yes',
                      'RestrictNamespaces=yes', 'RestrictSUIDSGID=yes',
                      'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK',
                      'SystemCallFilter=~mount umount2 pivot_root move_mount open_tree fsopen fsconfig fsmount mount_setattr @module @reboot @swap @raw-io',
                      'SystemCallErrorNumber=EPERM', 'CapabilityBoundingSet=' + ' '.join('CAP_' + cap for cap in CAPS.get(self.unit, ()) if user == 'root'),
                      # Foreground lease/log wrapper execs the packaged daemon;
                      # required capabilities must survive that extra exec.
                      'AmbientCapabilities=' + ' '.join('CAP_' + cap for cap in CAPS.get(self.unit, ()) if user == 'root'),
                      'TemporaryFileSystem=/run /tmp', 'KillMode=control-group']
        for field, bindings in (('BindReadOnlyPaths', self.readonly), ('BindPaths', self.writable)):
            for source, destination in bindings:
                if destination in ('/var/run/docker.sock', '/run/dbus/system_bus_socket') or '..' in Path(destination).parts:
                    raise ValueError('Host control bind denied')
                properties.append(field + '=' + safe_path(source) + ':' + safe_path(destination))
        if self.writable: properties.append('ReadWritePaths=' + ' '.join(safe_path(destination) for _, destination in self.writable))
        if self.environment_file: properties.append('EnvironmentFile=' + safe_path(self.environment_file))
        return properties


class Executor:
    def __init__(self, profiles, observer, broadcast, password_files, store, spool_budget, mail_maximum=104857600):
        if set(profiles) != set(UNITS.values()): raise ValueError('Complete closed executor profile registry required')
        self.profiles, self.observer = dict(profiles), observer
        self.broadcast_handler, self.password_files = broadcast, dict(password_files)
        self.store, self.spool_budget, self.mail_maximum = store, spool_budget, mail_maximum
        self.locks = {unit: threading.Lock() for unit in UNITS.values()}

    def command(self, unit, argv, user='root', data=b'', text_maximum=None):
        if unit not in self.profiles or not argv or not argv[0].startswith('/'): raise ValueError('Fixed service command required')
        action_unit = 'mailcow-action-' + uuid.uuid4().hex + '.service'
        command = ['/usr/bin/systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--slice=mailcow-actions.slice', '--unit=' + action_unit,
                   *['--property=' + value for value in self.profiles[unit].properties(user)], '--', *argv]
        spool = self.spool_budget.open(text_maximum) if text_maximum is not None else None
        with self.store.lease('native'):
            try:
                # Old HTTP caller timeout60s did not kill Docker exec. Keep the
                # operation supervised and leased until it actually finishes.
                return bounded(command, data, timeout=None, spool=spool)
            except BaseException:
                # Retain lease through stop AND verified absence. Unobservable
                # systemd state or an uninterruptible task must stay blocking.
                group = Path('/sys/fs/cgroup/mailcow.slice/mailcow-actions.slice') / action_unit
                pause = 1
                while True:
                    try:
                        bounded(['/usr/bin/systemctl', 'kill', '--kill-whom=all', '--signal=KILL', '--', action_unit], timeout=8)
                        bounded(['/usr/bin/systemctl', 'stop', '--no-block', '--', action_unit], timeout=8)
                        try: populated = dict(line.split() for line in (group / 'cgroup.events').read_text().splitlines()).get('populated') != '0'
                        except FileNotFoundError: populated = False
                        if not populated and manager_unit_absent(action_unit): break
                    except (OSError, ValueError, TimeoutError): pass
                    time.sleep(pause); pause = min(30, pause * 2)
                if spool: spool.close()
                raise

    def state(self, unit): return self.observer.state(unit)
    def host_stats(self): return self.observer.host_stats()
    def stats_history(self, unit, identifier): return self.observer.stats_history(unit, identifier)
    def broadcast(self, plan, payload): return self.broadcast_handler(plan, payload)

    @staticmethod
    def generic(code, output, success='command completed successfully'):
        return Reply.json({'type': 'success', 'msg': success} if code == 0 else
                          {'type': 'danger', 'msg': 'command failed; inspect protected service diagnostics'})

    def execute(self, plan, request):
        # Recompile at execution boundary; never accept caller-created Plan.
        service = next((name for name, unit in UNITS.items() if unit == plan.unit), None)
        action = 'exec' if plan.operation.startswith('exec__') else plan.operation
        if service is None or compile_action(service, action, request) != plan: raise ValueError('Untrusted execution plan')
        with self.locks[plan.unit], self.store.lease('native'):
            if plan.primitive == 'unit-control':
                with self.store.lease('native'): code, output = bounded(list(plan.argv), timeout=None)
                return self.generic(code, output)
            if plan.primitive == 'unit-observation':
                value = self.observer.top(plan.unit) if plan.operation == 'top' else self.observer.stats(plan.unit)
                return Reply.json({'type': 'success', 'msg': value})
            if plan.primitive in ('argv', 'disk-observation'):
                text = plan.operation in ('exec__mailq__cat', 'exec__mailq__list', 'exec__sieve__list', 'exec__sieve__print')
                # postcat includes queue metadata/envelope beyond message body.
                # Multiple selected IDs preserve the corresponding size bound.
                text_limit = ((self.mail_maximum + 1024 * 1024) * len(request['items']) if plan.operation == 'exec__mailq__cat' else self.spool_budget.maximum) if text else None
                code, output = self.command(plan.unit, plan.argv, plan.user, text_maximum=text_limit)
                if plan.primitive == 'disk-observation':
                    value = ','.join(output.decode('utf-8', 'replace').strip().splitlines()[-1].split()) if code == 0 else '0,0,0,0,0,0'
                    return Reply.json(value)
                if text:
                    return Reply(output, 'text/plain')
                success = 'fts_rescan: rescan triggered' if plan.operation == 'exec__system__fts_rescan' else 'command completed successfully'
                return self.generic(code, output, success)
            if plan.primitive == 'queue-delivery-batch':
                for queue_id in dict(plan.fields)['items']:
                    code, output = self.command(plan.unit, ('/usr/sbin/postqueue', '-i', queue_id), plan.user)
                    if code: return self.generic(code, output)
                return self.generic(0, b'', 'Scheduled immediate delivery')
            if plan.primitive == 'acl-inventory': return self.acls(plan)
            if plan.primitive == 'database-maintenance': return self.database(plan)
            if plan.primitive == 'maildir-transaction':
                code, output = self.command(plan.unit, ('/usr/bin/python3', '-B', '/run/mailcow-native/maildir_transaction.py'),
                                            plan.user, json.dumps(request).encode())
                return self.generic(code, output)
            if plan.primitive == 'rspamd-controller-password': return self.password(plan, request)
            raise ValueError('Unregistered execution primitive')

    def acls(self, plan):
        identity = dict(plan.fields)['id']
        code, output = self.command(plan.unit, ('/usr/bin/doveadm', 'mailbox', 'list', '-u', identity))
        if code: return self.generic(code, output)
        result, seen = [], set()
        for folder in output.decode('utf-8').splitlines():
            owner, mailbox = identity, folder
            shared = 'Shared' in folder
            if shared:
                bits = folder.split('/')
                if len(bits) < 3: continue
                owner, mailbox = bits[1], '/'.join(bits[2:])
            if mailbox in seen: continue
            code, acl = self.command(plan.unit, ('/usr/bin/doveadm', 'acl', 'get', '-u', owner, '--', mailbox))
            if code: return self.generic(code, acl)
            for line in acl.decode('utf-8').strip().splitlines()[1:]:
                principal, rights = line.split(maxsplit=1)
                if not principal.startswith('user='): continue
                peer = principal[5:]
                if not shared or peer == identity:
                    seen.add(mailbox)
                    result.append({'user': owner, 'id': peer, 'mailbox': mailbox, 'rights': rights.split()})
        return Reply.json(result)

    def database(self, plan):
        task = dict(plan.fields)['task']
        # Defaults file is provisioned root operator-side, bound explicitly
        # into this unit with mysql ownership0600; never credential argv/env.
        defaults = '--defaults-extra-file=/run/mailcow-mysql-admin.cnf'
        if task == 'mysql_upgrade':
            code, output = self.command(plan.unit, ('/usr/bin/mysql_upgrade', defaults, '-uroot'), 'mysql')
            applied = code == 0 and b'is already upgraded to' not in output
            if applied: bounded(['/usr/bin/systemctl', 'restart', '--', plan.unit])
            return Reply.json({'type': 'error' if code else ('warning' if applied else 'success'),
                               'msg': 'mysql_upgrade: ' + ('error running command' if code else ('upgrade was applied' if applied else 'already upgraded')),
                               'text': '' if code else output.decode('utf-8', 'replace')})
        code, sql = self.command(plan.unit, ('/usr/bin/mysql_tzinfo_to_sql', '/usr/share/zoneinfo'), 'mysql')
        if not code:
            sql = sql.replace(b'Local time zone must be set--see zic manual page', b'FCTY')
            code, sql = self.command(plan.unit, ('/usr/bin/mysql', defaults, '-uroot', 'mysql'), 'mysql', sql)
        return Reply.json({'type': 'error' if code else 'info',
                           'msg': 'mysql_tzinfo_to_sql: ' + ('error running command' if code else 'command completed successfully'),
                           'text': '' if code else sql.decode('utf-8', 'replace')})

    def password(self, plan, request):
        # Rspamd4.1.4 pw.c reads passphrase from stdin when -p is absent.
        code, output = self.command(plan.unit, ('/usr/bin/rspamadm', 'pw', '-e'), '_rspamd', request['raw'].encode() + b'\n')
        hashes = re.findall(rb'\$2\$[a-zA-Z0-9]+\$[a-zA-Z0-9]+', output)
        if code or len(hashes) != 1: return self.generic(1, b'password derivation failed')
        path = self.password_files[plan.unit]
        # Fixed operator-selected override file; atomic write retains owner/mode.
        import stat, tempfile
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1: raise ValueError('Fixed regular password file required')
        fd, temp = tempfile.mkstemp(dir=path.parent, prefix='.native-password-')
        try:
            os.fchown(fd, before.st_uid, before.st_gid); os.fchmod(fd, stat.S_IMODE(before.st_mode))
            with os.fdopen(fd, 'wb') as file: file.write(b'enable_password = "' + hashes[0] + b'";\n'); file.flush(); os.fsync(file.fileno())
            os.replace(temp, path)
        finally:
            if os.path.exists(temp): os.unlink(temp)
        code, output = bounded(['/usr/bin/systemctl', 'restart', '--', plan.unit])
        return self.generic(code, output)
