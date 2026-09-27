"""Off-host actual Dovecot actions, kernel caller policy, large/slow lifetimes.

No live configuration, accounts, endpoints or outbound mail. This proves the
control execution plumbing; it is not full18-service/groupware acceptance.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from action_policy import UNITS
from canonical_store import CanonicalStore, StoreBusy, ClosedCgroupProbe
from control_protocol import Dispatcher
from control_server import ControlServer
from rehearse_unbound import run, validate
from rehearse_dovecot import mail_probe
from service_executor import Profile, Executor, bounded, manager_unit_absent
from service_observer import Observer
from result_spool import SpoolBudget
from replication_auth import ReplicaAuth, canonical
from replica_dispatch import ReplicaDispatch


class FixtureRedis:
    def __init__(self): self.messages = []
    def command(self, *parts):
        self.messages.append(parts)
        return 1


def rehearse(artifacts, output):
    if sys.platform != 'linux' or os.geteuid() != 0: raise RuntimeError('Off-host root Linux only')
    artifact, source = validate(artifacts, 'dovecot-mailcow')
    units = ['mailcow-dovecot.service', 'mailcow-php-fpm.service', 'mailcow-watchdog.service', 'mailcow-unregistered-fixture.service', 'mailcow-slow-fixture.service']
    namespace = 'mailcow-control-fixture'
    active = []; created = False; server = None
    with tempfile.TemporaryDirectory(prefix='native-control-') as temp:
        scratch = Path(temp); root = scratch / 'root'; root.mkdir()
        run(['tar', '--numeric-owner', '--same-owner', '--same-permissions', '--xattrs', '--acls', '-xzf', str(artifact), '-C', str(root)])
        canonical_root = scratch / 'canonical'; canonical_root.mkdir(mode=0o700)
        store = CanonicalStore(canonical_root); store.activate('native', lambda: [])
        mail, index, runtime = (scratch / name for name in ('mail', 'index', 'runtime'))
        for path in (mail, index, runtime): path.mkdir(); os.chown(path, 5000, 5000)
        spool_path = scratch / 'spool'; spool_path.mkdir(mode=0o700)
        budget = SpoolBudget(spool_path, 512 * 1024 * 1024)
        helpers = Path(__file__).resolve().parents[1]
        adapter = scratch / 'log-pipe'
        run(['gcc', '-static', '-Os', '-Wall', '-Werror', '-s', '-o', str(adapter), str(helpers / 'log_pipe.c')])
        conf = scratch / 'dovecot.conf'
        conf.write_text('''protocols = imap lmtp sieve
listen = 127.0.0.1
base_dir = /run/dovecot
state_dir = /run/dovecot/state
log_path = /dev/stderr
info_log_path = /dev/stderr
ssl = no
disable_plaintext_auth = no
auth_mechanisms = plain login
mail_location = maildir:/var/vmail/%u/Maildir
mail_plugins = fts fts_flatcurve acl
first_valid_uid = 5000
passdb {
 driver = static
 args = password=fixture-test-only
}
userdb {
 driver = static
 args = uid=5000 gid=5000 home=/var/vmail/%u
}
service auth {
 unix_listener auth-userdb {
  mode = 0600
  user = vmail
 }
}
service imap-login {
 user = dovenull
 process_min_avail = 1
}
service lmtp {
 user = vmail
 inet_listener lmtp {
  port = 24
 }
}
plugin {
 fts = flatcurve
 fts_autoindex = yes
 fts_languages = en
 fts_tokenizers = generic email-address
 fts_filters = normalizer-icu snowball stopwords
 fts_filters_en = lowercase snowball english-possessive stopwords
 acl = vfile
 sieve = file:~/sieve;active=~/.dovecot.sieve
}
''')
        readonly = ((conf, '/etc/dovecot/dovecot.conf'), (helpers, '/run/mailcow-native'),
                    (store.control, '/run/mailcow-lease'), (adapter, '/run/mailcow-log-pipe'))
        writable = ((mail, '/var/vmail'), (index, '/var/vmail_index'), (runtime, '/run/dovecot'))
        profiles = {unit: Profile(unit, root, Path('/run/netns') / namespace, readonly, writable) for unit in UNITS.values()}
        redis = FixtureRedis(); observer = Observer(profiles, redis)
        executor = Executor(profiles, observer, lambda *_: None, {}, store, budget)
        dispatcher = Dispatcher(executor, 'synthetic', {service: '127.0.0.1' for service in UNITS})
        socket_path = scratch / 'control.sock'; server = ControlServer(socket_path, dispatcher)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        def unit_command(name, argv, extra=()):
            profile = Profile('mailcow-dovecot.service', root, Path('/run/netns') / namespace,
                              readonly + ((socket_path, '/run/mailcow-control.sock'),), writable)
            return ['/usr/bin/systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--unit=' + name,
                    *['--property=' + prop for prop in profile.properties()], *['--property=' + prop for prop in extra], '--', *argv]
        def call(caller, target, request=None, expect_status=200):
            body = json.dumps(request or {}).encode()
            client = '''import socket,sys,json
s=socket.socket(socket.AF_UNIX);s.settimeout(90);s.connect('/run/mailcow-control.sock')
body=sys.argv[2].encode();s.sendall(('POST '+sys.argv[1]+' HTTP/1.0\\r\\nX-Caller: php\\r\\nContent-Length: '+str(len(body))+'\\r\\n\\r\\n').encode()+body)
raw=b''
while True:
 part=s.recv(65536)
 if not part:break
 raw+=part
header,response=raw.split(b'\\r\\n\\r\\n',1);assert int(header.split()[1])==int(sys.argv[3])
if int(sys.argv[3])==200:
 try:
  value=json.loads(response)
  if isinstance(value,dict) and 'type' in value:assert value['type']=='success',value
 except json.JSONDecodeError:pass
'''
            run(unit_command(caller, ['/usr/bin/python3', '-c', client, target, body.decode(), str(expect_status)]))
        def action_target(service, action):
            identifier = next(identifier for identifier, name in dispatcher.ids.items() if name == service)
            return '/containers/' + identifier + '/' + action
        try:
            run(['ip', 'netns', 'add', namespace]); created = True
            run(['ip', '-n', namespace, 'link', 'set', 'lo', 'up'])
            run(['ip', 'netns', 'exec', namespace, 'sysctl', '-qw', 'net.ipv4.ip_unprivileged_port_start=0'])
            properties = profiles['mailcow-dovecot.service'].properties()
            run(['/usr/bin/systemd-run', '--quiet', '--unit=mailcow-dovecot.service', *['--property=' + prop for prop in properties],
                 '--', '/run/mailcow-log-pipe', '--lease-dir', '/run/mailcow-lease', '--generation', 'native', '--', '/usr/sbin/dovecot', '-F'])
            active.append('mailcow-dovecot.service')
            deadline = time.monotonic() + 20
            while True:
                result = subprocess.run(['ip', 'netns', 'exec', namespace, '/usr/bin/python3', str(Path(__file__).resolve().parents[1] / 'rehearse_dovecot.py'), '--probe-mail'], capture_output=True, timeout=10)
                if not result.returncode: break
                if list(mail.rglob('cur/*')) or list(mail.rglob('new/*')) or time.monotonic() > deadline:
                    raise RuntimeError('Synthetic Dovecot fixture failed: ' + result.stderr.decode()[-2000:])
                time.sleep(.25)
            route = action_target('dovecot-mailcow', 'exec')
            call('mailcow-php-fpm.service', route, {'cmd': 'sieve', 'task': 'list', 'username': 'fixture@example.invalid'})
            call('mailcow-php-fpm.service', route, {'cmd': 'system', 'task': 'fts_rescan', 'username': 'fixture@example.invalid'})
            call('mailcow-php-fpm.service', route, {'cmd': 'doveadm', 'task': 'set_acl', 'user': 'fixture@example.invalid', 'mailbox': 'INBOX', 'id': 'peer@example.invalid', 'rights': ['lookup', 'read']})
            call('mailcow-php-fpm.service', route, {'cmd': 'doveadm', 'task': 'get_acl', 'id': 'fixture@example.invalid'})
            call('mailcow-php-fpm.service', route, {'cmd': 'doveadm', 'task': 'delete_acl', 'user': 'fixture@example.invalid', 'mailbox': 'INBOX', 'id': 'peer@example.invalid'})
            call('mailcow-watchdog.service', route, {'cmd': 'system', 'task': 'fts_rescan', 'all': True}, 403)
            call('mailcow-unregistered-fixture.service', route, {'cmd': 'system', 'task': 'fts_rescan', 'all': True}, 403)
            for name in ('old',):
                path = mail / 'fixture.invalid' / name; path.mkdir(parents=True); os.chown(path.parent, 5000, 5000); os.chown(path, 5000, 5000)
                content = path / 'mail'; content.write_text('synthetic arrival'); os.chown(content, 5000, 5000)
            before = (mail / 'fixture.invalid/old').stat().st_ino
            path = index / 'old@fixture.invalid'; path.mkdir(); os.chown(path, 5000, 5000)
            call('mailcow-php-fpm.service', route, {'cmd': 'maildir', 'task': 'move', 'old_maildir': 'fixture.invalid/old', 'new_maildir': 'fixture.invalid/new'})
            assert (mail / 'fixture.invalid/new').stat().st_ino == before
            call('mailcow-php-fpm.service', route, {'cmd': 'maildir', 'task': 'cleanup', 'maildir': 'fixture.invalid/new'})
            assert not (mail / 'fixture.invalid/new').exists()
            # Full advertised100 MiB body is spooled with bounded RAM and no
            # persistent pathname; body is entirely synthetic repeated bytes.
            spool = budget.open(105906176)
            code, result = bounded(['/usr/bin/python3', '-c', 'import sys;\nfor _ in range(1600):sys.stdout.buffer.write(b"x"*65536)'], timeout=30, spool=spool)
            assert code == 0 and result.size == 104857600 and budget.used == result.size
            assert not list(spool_path.iterdir()); result.close(); assert budget.used == 0
            # Signed same-message delivery claims once, rejects raw Redis and
            # survives process replacement with the same protected journal.
            ledger = scratch / 'replicas'; ledger.mkdir(mode=0o700)
            auth = ReplicaAuth('fixture-origin', b'x' * 32, {'fixture-origin': b'x' * 32}, 'synthetic')
            executions = []
            from control_protocol import Reply
            adapter_dispatch = ReplicaDispatch(auth, ledger, redis, lambda plan, request: (executions.append(plan) or Reply.json({'type': 'success'})), True, True)
            message = {'api_call': 'container_post', 'container_name': 'dovecot-mailcow', 'post_action': 'exec', 'request': {'cmd': 'maildir', 'task': 'cleanup', 'maildir': 'fixture.invalid/replica'}}
            signed = canonical(auth.sign(message)); assert adapter_dispatch.receive(signed); assert not adapter_dispatch.receive(signed)
            replacement = ReplicaDispatch(auth, ledger, redis, lambda *_: (_ for _ in ()).throw(AssertionError('duplicate execution')), True, True)
            assert not replacement.receive(signed) and len(executions) == 1
            run(['/usr/bin/systemctl', 'stop', '--', 'mailcow-dovecot.service'])
            active.remove('mailcow-dovecot.service')
            # A deliberately killed controller loses its flock, while its
            # independently supervised action still writes/exists. Dedicated
            # fixed action slice must block transition without any PID journal.
            controller_code = '''import sys,time,subprocess
sys.path.insert(0,sys.argv[1]);from canonical_store import CanonicalStore
with CanonicalStore(sys.argv[2]).lease('native'):
 subprocess.run(['/usr/bin/systemd-run','--quiet','--unit=mailcow-action-crash-fixture.service','--slice=mailcow-actions.slice','/bin/sleep','30'],check=True)
 print('ready',flush=True);time.sleep(60)
'''
            controller = subprocess.Popen(['/usr/bin/python3', '-c', controller_code, str(helpers), str(canonical_root)], stdout=subprocess.PIPE)
            assert controller.stdout.readline().strip() == b'ready'
            controller.kill(); controller.wait(timeout=5)
            try: store.activate('legacy', ClosedCgroupProbe(['/sys/fs/cgroup/system.slice/mailcow-dovecot.service']))
            except StoreBusy: pass
            else: raise AssertionError('Surviving action after controller death allowed switch')
            run(['/usr/bin/systemctl', 'stop', '--', 'mailcow-action-crash-fixture.service'])
            assert manager_unit_absent('mailcow-action-already-collected-fixture.service')
            # Slow supervised command exceeds old PHP60s wait without killing
            # valid work; wrapper reopens /dev/stdout and holds writer lease.
            slow = unit_command('mailcow-slow-fixture.service', ['/run/mailcow-log-pipe', '--lease-dir', '/run/mailcow-lease', '--generation', 'native', '--',
                                '/usr/bin/python3', '-c', 'import time;f=open("/dev/stdout","w");f.write("pipe-reopened\\n");f.flush();time.sleep(65);print("completed-after-caller-timeout")'])
            started = time.monotonic(); process = subprocess.Popen(slow, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            active.append('mailcow-slow-fixture.service'); time.sleep(1)
            try: store.activate('legacy', lambda: [])
            except StoreBusy: pass
            else: raise AssertionError('Active foreground/action lease allowed switch')
            stdout, stderr = process.communicate(timeout=90)
            assert process.returncode == 0 and time.monotonic() - started >= 65
            assert b'pipe-reopened' in stdout and b'completed-after-caller-timeout' in stdout
            store.activate('legacy', lambda: [])
            receipt = {'passed': True, 'sourceImage': source['sourceImage'], 'actualKernelCallerPolicy': True,
                       'forgedHeaderIgnored': True, 'unregisteredUID0Denied': True, 'actualSieveFTSACLCommands': True,
                       'vmailMaildirMoveCleanup': True, 'maildirInodePreserved': True, 'full100MiBAnonymousSpool': True,
                       'spoolBudgetReleased': True, 'signedDuplicateAfterRestartDenied': True,
                       'supervisedBeyond60sCompleted': True, 'writerLeaseBlockedTransition': True,
                       'killedControllerSurvivingActionBlockedTransition': True,
                       'devStdoutReopenPreserved': True, 'noProductionDataOrOutbound': True}
        finally:
            # Fresh disposable CI units only: logs contain synthetic fixtures,
            # no host configuration/accounts/credentials. Keep diagnostics for
            # actual namespace/socket/ABI failures instead of guessing fixes.
            subprocess.run(['/usr/bin/journalctl', '--no-pager', '-u', 'mailcow-dovecot.service', '-n', '60'], timeout=10)
            for name in units: subprocess.run(['/usr/bin/systemctl', 'stop', '--', name], capture_output=True, timeout=15)
            if server: server.shutdown(); server.server_close(); thread.join(timeout=5)
            if created: run(['ip', 'netns', 'delete', namespace])
        receipt['cleanupConfirmed'] = budget.used == 0
        output.write_text(json.dumps(receipt, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--artifacts', type=Path, required=True); parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); rehearse(args.artifacts, args.output)
