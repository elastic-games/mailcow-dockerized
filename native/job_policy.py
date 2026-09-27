"""Closed scheduling contract for the 14 pinned upstream Ofelia jobs.

Commands are committed policy, not operator-request or HTTP input. The fixed
bash snippets deliberately preserve upstream MASTER checks, gosu accounts,
source_env handling and exit semantics. Rendering does not activate timers.
"""
from dataclasses import dataclass
import re
import shlex
from zoneinfo import ZoneInfo
from action_policy import UNITS
from service_executor import safe_path

JOB_SLICE = 'mailcow-jobs.slice'


@dataclass(frozen=True)
class Job:
    name: str
    service: str
    schedule: str
    script: str
    no_overlap: bool = False

    @property
    def unit(self): return 'mailcow-job-' + self.name + ('.service' if self.no_overlap else '@.service')

    @property
    def argv(self): return ('/bin/bash', '-c', self.script)


JOBS = (
    Job('phpfpm_keycloak_sync', 'php-fpm-mailcow', '0 * * * * *', 'php /crons/keycloak-sync.php || exit 0', True),
    Job('phpfpm_ldap_sync', 'php-fpm-mailcow', '0 * * * * *', 'php /crons/ldap-sync.php || exit 0', True),
    Job('sogo_backup', 'sogo-mailcow', '0 0 0 * * *', '[[ ${MASTER} == y ]] && /usr/local/bin/gosu sogo /usr/sbin/sogo-tool backup /sogo_backup ALL || exit 0'),
    Job('sogo_ealarms', 'sogo-mailcow', '0 * * * * *', '[[ ${MASTER} == y ]] && /usr/local/bin/gosu sogo /usr/sbin/sogo-ealarms-notify -p /etc/sogo/cron.creds || exit 0'),
    Job('sogo_eautoreply', 'sogo-mailcow', '0 */5 * * * *', '[[ ${MASTER} == y ]] && /usr/local/bin/gosu sogo /usr/sbin/sogo-tool update-autoreply -p /etc/sogo/sieve.creds || exit 0'),
    Job('sogo_sessions', 'sogo-mailcow', '0 * * * * *', '[[ ${MASTER} == y ]] && /usr/local/bin/gosu sogo /usr/sbin/sogo-tool -v expire-sessions ${SOGO_EXPIRE_SESSION} || exit 0'),
    Job('dovecot_clean_q_aged', 'dovecot-mailcow', '0 0 0 * * *', '[[ ${MASTER} == y ]] && /usr/local/bin/gosu vmail /usr/local/bin/clean_q_aged.sh || exit 0'),
    Job('dovecot_fts', 'dovecot-mailcow', '0 0 0 * * *', '/usr/local/bin/gosu vmail /usr/local/bin/optimize-fts.sh'),
    Job('dovecot_imapsync_runner', 'dovecot-mailcow', '0 * * * * *', '[[ ${MASTER} == y ]] && /usr/local/bin/gosu nobody /usr/local/bin/imapsync_runner.pl || exit 0', True),
    Job('dovecot_maildir_gc', 'dovecot-mailcow', '0 */30 * * * *', 'source /source_env.sh ; /usr/local/bin/gosu vmail /usr/local/bin/maildir_gc.sh'),
    Job('dovecot_quarantine', 'dovecot-mailcow', '0 */20 * * * *', '[[ ${MASTER} == y ]] && /usr/local/bin/gosu vmail /usr/local/bin/quarantine_notify.py || exit 0'),
    Job('dovecot_repl_health', 'dovecot-mailcow', '0 */5 * * * *', '/usr/local/bin/gosu vmail /usr/local/bin/repl_health.sh'),
    Job('dovecot_sarules', 'dovecot-mailcow', '@every 24h', '/usr/local/bin/sa-rules.sh'),
    Job('dovecot_trim_logs', 'dovecot-mailcow', '0 * * * * *', '[[ ${MASTER} == y ]] && /usr/local/bin/gosu vmail /usr/local/bin/trim_logs.sh || exit 0'),
)
BY_NAME = {job.name: job for job in JOBS}


def validate_manifest(rows):
    expected = {job.name: job for job in JOBS}
    if len(rows) != len(expected) or {row.get('name') for row in rows} != set(expected):
        raise ValueError('Exact upstream job inventory required')
    for row in rows:
        job = expected[row['name']]
        if set(row) != {'name', 'service', 'schedule', 'commandTemplate', 'noOverlap'} or (
                row['service'] != job.service or row['schedule'] != job.schedule or
                row['noOverlap'] is not job.no_overlap or
                tuple(shlex.split(row['commandTemplate'].replace('$$', '$'))) != job.argv):
            raise ValueError('Job source changed; review upstream semantics before rendering')


def quote_exec(argument):
    if any(char in argument for char in '\n\r\x00'): raise ValueError('Single-line unit argument required')
    # systemd performs both specifier and environment expansion before bash.
    # The closed shell script must reach bash literally, including ${MASTER}.
    return '"' + argument.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%').replace('$', '$$') + '"'


def calendar(job, timezone):
    if not isinstance(timezone, str) or not re.fullmatch(r'[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*', timezone):
        raise ValueError('Explicit reviewed IANA scheduler timezone required')
    ZoneInfo(timezone)
    expression = {'0 * * * * *': '*-*-* *:*:00', '0 0 0 * * *': '*-*-* 00:00:00',
            '0 */5 * * * *': '*-*-* *:0/5:00', '0 */20 * * * *': '*-*-* *:0/20:00',
            '0 */30 * * * *': '*-*-* *:0/30:00'}.get(job.schedule)
    return expression + ' ' + timezone if expression else None


def render_units(profiles, launcher, timezone):
    if set(profiles) != set(UNITS.values()): raise ValueError('Complete closed service profile registry required')
    safe_path(launcher)
    units = {JOB_SLICE: '[Unit]\nDescription=Isolated mail scheduled jobs\n[Slice]\nMemoryAccounting=yes\nTasksAccounting=yes\n'}
    for job in JOBS:
        profile = profiles[UNITS[job.service]]
        if profile.environment_file is None: raise ValueError('Reviewed packaged job environment required')
        properties = '\n'.join(value.replace('%', '%%') for value in profile.properties('root', action_wrapper=True))
        argv = ('/run/mailcow-log-pipe', '--lease-dir', '/run/mailcow-lease', '--generation', 'native', '--', *job.argv)
        units[job.unit] = ('[Unit]\nDescription=Mail scheduled job ' + job.name + '\n[Service]\nType=exec\nSlice=' + JOB_SLICE +
                           '\n' + properties + '\nExecStart=' + ' '.join(map(quote_exec, argv)) + '\n')
        scheduled_unit = job.unit
        if not job.no_overlap:
            scheduled_unit = 'mailcow-job-trigger-' + job.name + '.service'
            # Host root helper can only start one closed job template. It does
            # not accept unit names, scripts, properties or environment input.
            units[scheduled_unit] = ('[Unit]\nDescription=Schedule mail job ' + job.name + '\n[Service]\nType=oneshot\nUser=root\nGroup=root\nSlice=' + JOB_SLICE +
                                     '\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nExecStart=' +
                                     ' '.join(map(quote_exec, ('/usr/bin/python3', '-I', str(launcher), job.name))) + '\n')
        timer = '[Unit]\nDescription=Mail timer ' + job.name + '\n[Timer]\nUnit=' + scheduled_unit + '\nAccuracySec=1s\nRandomizedDelaySec=0\n'
        if job.schedule == '@every 24h': timer += 'OnActiveSec=24h\nOnUnitActiveSec=24h\n'
        else: timer += 'OnCalendar=' + calendar(job, timezone) + '\n'
        units['mailcow-job-' + job.name + '.timer'] = timer + '[Install]\nWantedBy=timers.target\n'
    return units
