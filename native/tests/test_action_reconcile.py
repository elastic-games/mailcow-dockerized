import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from service_executor import manager_unit_absent
from canonical_store import ClosedCgroupProbe, ACTION_CGROUP


class ReconcileTests(unittest.TestCase):
    def runner(self, units=(), jobs=(), unavailable=False):
        def call(argv, **kwargs):
            if unavailable: return 1, b'manager unreachable'
            method = argv[-1]
            return 0, json.dumps({'type': 'a(ssssssouso)' if method == 'ListUnits' else 'a(usssoo)', 'data': [list(units if method == 'ListUnits' else jobs)]}).encode()
        return call

    def test_absent_collected_unit_vs_unobservable_manager(self):
        unit = 'mailcow-action-fixture.service'
        self.assertTrue(manager_unit_absent(unit, self.runner()))
        self.assertFalse(manager_unit_absent(unit, self.runner(unavailable=True)))
        self.assertFalse(manager_unit_absent(unit, self.runner(jobs=[[1, unit, 'start', 'waiting', '/job/1', '/unit/1']])))
        row = [unit, 'fixture', 'loaded', 'active', 'running', '', '/unit/1', 0, '', '/']
        self.assertFalse(manager_unit_absent(unit, self.runner(units=[row])))
        row[3] = 'inactive'
        self.assertTrue(manager_unit_absent(unit, self.runner(units=[row])))

    def test_missing_daemon_inventory_rejected_and_fixed_actions_included(self):
        with self.assertRaises(ValueError): ClosedCgroupProbe([])
        probe = ClosedCgroupProbe(['/sys/fs/cgroup/system.slice/mailcow-dovecot.service'])
        self.assertIn(ACTION_CGROUP, probe.paths)


if __name__ == '__main__': unittest.main(verbosity=2)
