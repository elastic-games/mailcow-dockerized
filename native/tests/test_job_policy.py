import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from action_policy import UNITS
from control_protocol import CALLERS
from job_policy import JOBS, validate_manifest, render_units, calendar
from job_launcher import launch
from peer_policy import authorize, PeerDenied
from service_executor import Profile


class JobTests(unittest.TestCase):
    def test_all_upstream_schedules_commands_accounts_and_overlap_match(self):
        rows = json.loads((Path(__file__).resolve().parents[1] / 'runtime-manifest.json').read_text())['jobs']
        validate_manifest(rows)
        changed = json.loads(json.dumps(rows)); changed[0]['commandTemplate'] += ' ; touch /unreviewed'
        with self.assertRaises(ValueError): validate_manifest(changed)
        for job in JOBS: subprocess.run(['/bin/bash', '-n', '-c', job.script], check=True, capture_output=True)
        self.assertEqual(sum(job.no_overlap for job in JOBS), 3)

    def test_units_preserve_literal_environment_overlap_and_no_catchup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'etc').mkdir()
            (root / 'etc/passwd').write_text('root:x:0:0:root:/root:/bin/sh\n')
            (root / 'etc/group').write_text('root:x:0:\n')
            profiles = {unit: Profile(unit, root, Path('/run/netns/fixture'), (), (), root / 'environment') for unit in UNITS.values()}
            units = render_units(profiles, root / 'job_launcher.py', 'America/New_York')
            self.assertEqual(sum(name.endswith('.timer') for name in units), 14)
            self.assertEqual(sum('@.service' in name for name in units), 11)
            self.assertIn('$${MASTER}', units['mailcow-job-sogo_backup@.service'])
            for job in JOBS:
                self.assertIn('Slice=mailcow-jobs.slice', units[job.unit])
                timer = units['mailcow-job-' + job.name + '.timer']
                self.assertNotIn('Persistent=true', timer)
                if job.no_overlap: self.assertIn('Unit=' + job.unit + '\n', timer)
                else: self.assertIn('Unit=mailcow-job-trigger-' + job.name + '.service\n', timer)
                if job.schedule != '@every 24h': self.assertIn('America/New_York', timer)
            self.assertIn('OnActiveSec=24h\nOnUnitActiveSec=24h', units['mailcow-job-dovecot_sarules.timer'])

    def test_closed_launcher_and_job_peer_family(self):
        calls = []
        with patch('job_launcher.os.geteuid', return_value=0):
            launch('dovecot_sarules', lambda argv, **kwargs: calls.append(argv))
            for bad in ('phpfpm_keycloak_sync', '../dovecot_sarules', 'dovecot_sarules;stop', 'unknown'):
                with self.assertRaises(ValueError): launch(bad, lambda *_: None)
        self.assertRegex(calls[0][-1], r'^mailcow-job-dovecot_sarules@[0-9a-f]{32}\.service$')
        prefix = '/mailcow.slice/mailcow-jobs.slice/mailcow-job-'
        for name, permitted in [('dovecot_sarules@' + 'a' * 32, True), ('dovecot_fts@' + 'a' * 32, False), ('dovecot_sarules@admin', False), ('php-fpm', False)]:
            with patch('peer_policy.peer_unit', return_value=prefix + name + '.service'):
                if permitted:
                    self.assertEqual(authorize(None, CALLERS), 'dovecot')
                    with self.assertRaises(PeerDenied): authorize(None, {})
                else:
                    with self.assertRaises(PeerDenied): authorize(None, {})

    @unittest.skipUnless(sys.platform == 'linux', 'Actual systemd calendar parser is Linux-only')
    def test_actual_systemd_calendar_parser(self):
        for expression in set(calendar(job, 'America/New_York') for job in JOBS) - {None}:
            subprocess.run(['/usr/bin/systemd-analyze', 'calendar', expression], check=True, capture_output=True)


if __name__ == '__main__': unittest.main(verbosity=2)
