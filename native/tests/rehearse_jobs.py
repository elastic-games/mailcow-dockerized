"""Off-host systemd schedule/overlap/queued-generation fixture, no real jobs.

All 14 source units are parsed without installation. Only explicitly named
synthetic fixture units are installed temporarily; no network or mail jobs run.
"""
from dataclasses import replace
import json
from pathlib import Path
import subprocess
import time
from canonical_store import ClosedCgroupProbe
from job_policy import render_units, quote_exec


def run(argv, **kwargs): return subprocess.run(argv, check=True, timeout=30, **kwargs)


def rehearse_jobs(profiles, store, scratch, adapter):
    profile = profiles['mailcow-dovecot.service']
    environment = scratch / 'job-environment'; environment.write_text('MASTER=fixture\nTZ=America/New_York\n'); environment.chmod(0o600)
    reviewed = {unit: replace(value, environment_file=environment) for unit, value in profiles.items()}
    rendered = render_units(reviewed, Path(__file__).resolve().parents[1] / 'job_launcher.py', 'America/New_York')
    # verify checks ExecStart against the HOST path, without RootDirectory or
    # runtime binds. The actual isolated guard path is separately exercised by
    # the scoped admin fixture. Supply its same static executable on this fresh
    # disposable builder only while verifying; never overwrite an existing one.
    host_guard = Path('/run/mailcow-log-pipe')
    unit_dir = scratch / 'rendered-jobs'; unit_dir.mkdir()
    for name, body in rendered.items(): (unit_dir / name).write_text(body)
    with host_guard.open('xb') as file: file.write(adapter.read_bytes())
    try:
        host_guard.chmod(0o755)
        try: run(['/usr/bin/systemd-analyze', 'verify', '--man=no', *map(str, unit_dir.iterdir())], capture_output=True)
        except subprocess.CalledProcessError as error:
            raise RuntimeError('Synthetic unit verification failed: ' + error.stderr.decode()[-8192:]) from None
    finally: host_guard.unlink()
    dst = run(['/usr/bin/systemd-analyze', 'calendar', '--base-time=2026-03-08 00:00:00 UTC', '--iterations=2',
               '*-*-* 00:00:00 America/New_York'], capture_output=True, text=True).stdout
    assert '2026-03-08 05:00:00' in dst and '2026-03-09 04:00:00' in dst
    names = ['mailcow-job-nooverlap-fixture.service', 'mailcow-job-overlap-fixture@.service',
             'mailcow-job-literal-fixture.service', 'mailcow-job-delay-fixture.service',
             'mailcow-job-every-fixture.service', 'mailcow-job-every-fixture.timer',
             'mailcow-pending-fixture.service']
    installed = []; instances = []; activated = False
    system = Path('/run/systemd/system')
    properties = '\n'.join(value.replace('%', '%%') for value in reviewed[profile.unit].properties('root', action_wrapper=True))
    def unit(argv, extra=''):
        command = ('/run/mailcow-log-pipe', '--lease-dir', '/run/mailcow-lease', '--generation', 'native', '--', *argv)
        return '[Unit]\n' + extra + '[Service]\nType=exec\nSlice=mailcow-jobs.slice\n' + properties + '\nExecStart=' + ' '.join(map(quote_exec, command)) + '\n'
    counter = 'import os,time;f=os.open("/var/vmail/schedule-fixture",os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600);os.write(f,b"started\\n");os.close(f);time.sleep(15)'
    files = {
        names[0]: unit(('/usr/bin/python3', '-c', counter)),
        names[1]: unit(('/usr/bin/python3', '-c', counter)),
        names[2]: unit(('/bin/bash', '-c', 'printf "%s:%s\\n" "${MASTER}" "100%literal" > /var/vmail/literal-fixture')),
        names[3]: unit(('/usr/bin/python3', '-c', 'open("/var/vmail/wrong-generation-fixture","w").write("must not run")'), 'After=mailcow-pending-fixture.service\n'),
        names[4]: '[Service]\nType=oneshot\nSlice=mailcow-jobs.slice\nExecStart=/usr/bin/true\n',
        names[5]: '[Timer]\nUnit=mailcow-job-every-fixture.service\nOnActiveSec=24h\nOnUnitActiveSec=24h\nAccuracySec=1s\n',
        names[6]: '[Service]\nType=oneshot\nExecStart=/usr/bin/sleep 4\n',
    }
    mail = next(source for source, target in profile.writable if target == '/var/vmail')
    def status(name): return run(['/usr/bin/systemctl', 'show', '--property=ActiveState', '--value', name], capture_output=True, text=True).stdout.strip()
    def next_elapsed():
        base = ['/usr/bin/busctl', '--json=short', 'call', 'org.freedesktop.systemd1', '/org/freedesktop/systemd1', 'org.freedesktop.systemd1.Manager', 'GetUnit', 's', names[5]]
        path = json.loads(run(base, capture_output=True).stdout)['data'][0]
        data = json.loads(run(['/usr/bin/busctl', '--json=short', 'get-property', 'org.freedesktop.systemd1', path,
                              'org.freedesktop.systemd1.Timer', 'NextElapseUSecMonotonic'], capture_output=True).stdout)['data']
        return (data[0] if isinstance(data, list) else data) / 1000000
    try:
        for name, body in files.items():
            path = system / name
            with path.open('x') as file: file.write(body)
            installed.append(path)
        run(['/usr/bin/systemctl', 'daemon-reload'])
        run(['/usr/bin/systemctl', 'start', names[2]])
        # Type=exec start acknowledges exec of the lease guard, not completion
        # of its child. Observe child completion before checking output.
        deadline = time.monotonic() + 10
        while status(names[2]) in ('active', 'activating'):
            if time.monotonic() > deadline: raise TimeoutError('Literal fixture did not finish')
            time.sleep(.1)
        assert (mail / 'literal-fixture').read_text() == 'fixture:100%literal\n'
        run(['/usr/bin/systemctl', 'start', '--no-block', names[0]])
        deadline = time.monotonic() + 10
        while not (mail / 'schedule-fixture').exists():
            if time.monotonic() > deadline: raise TimeoutError('Synthetic job did not start')
            time.sleep(.1)
        run(['/usr/bin/systemctl', 'start', '--no-block', names[0]])
        assert (mail / 'schedule-fixture').read_text().count('started') == 1
        run(['/usr/bin/systemctl', 'stop', names[0]])
        (mail / 'schedule-fixture').unlink()
        instances = ['mailcow-job-overlap-fixture@' + token * 32 + '.service' for token in ('a', 'b')]
        run(['/usr/bin/systemctl', 'start', *instances])
        deadline = time.monotonic() + 10
        while not (mail / 'schedule-fixture').exists() or (mail / 'schedule-fixture').read_text().count('started') < 2:
            if time.monotonic() > deadline: raise TimeoutError('Overlapping synthetic jobs did not start')
            time.sleep(.1)
        assert all(status(name) == 'active' for name in instances)
        run(['/usr/bin/systemctl', 'stop', *instances])
        run(['/usr/bin/systemctl', 'start', names[5]])
        assert abs(next_elapsed() - time.monotonic() - 86400) < 3
        time.sleep(2); run(['/usr/bin/systemctl', 'start', names[4]])
        assert abs(next_elapsed() - time.monotonic() - 86400) < 3
        run(['/usr/bin/systemctl', 'stop', names[5]])
        run(['/usr/bin/systemctl', 'start', '--no-block', names[6]])
        run(['/usr/bin/systemctl', 'start', '--no-block', names[3]])
        store.activate('legacy', ClosedCgroupProbe(['/sys/fs/cgroup/system.slice/mailcow-dovecot.service'])); activated = True
        deadline = time.monotonic() + 15
        while True:
            result = run(['/usr/bin/systemctl', 'show', '--property=ExecMainStatus', '--value', names[3]], capture_output=True, text=True).stdout.strip()
            if result == '111' and status(names[3]) in ('failed', 'inactive'): break
            if time.monotonic() > deadline: raise TimeoutError('Delayed generation guard did not resolve')
            time.sleep(.25)
        assert result == '111' and not (mail / 'wrong-generation-fixture').exists()
        return {'rendered14UnitsParsed': True, 'literalEnvironmentAndPercentPreserved': True,
                'calendarAmericaNewYorkDSTPreserved': True, 'elapsed24hFirstAndNext': True,
                'actualNoOverlapAndConcurrentTemplates': True, 'queuedOldGenerationRejectedBeforeWrite': True,
                'onlySyntheticJobsExecuted': True}
    finally:
        for name in [*names, *instances]: subprocess.run(['/usr/bin/systemctl', 'stop', '--', name], capture_output=True, timeout=15)
        for path in installed: path.unlink()
        run(['/usr/bin/systemctl', 'daemon-reload'])
        if activated: store.activate('native', ClosedCgroupProbe(['/sys/fs/cgroup/system.slice/mailcow-dovecot.service']))
