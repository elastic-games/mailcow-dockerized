from pathlib import Path
import os
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from result_spool import SpoolBudget
from service_executor import bounded, Profile, Executor


class SpoolTests(unittest.TestCase):
    def test_anonymous_file_budget_cleanup_and_chunked_read(self):
        with tempfile.TemporaryDirectory() as directory:
            budget = SpoolBudget(directory, 200000)
            result = budget.open(150000)
            result.write(b'x' * 140000)
            self.assertEqual(budget.used, 140000)
            self.assertEqual(sum(map(len, result.chunks())), 140000)
            self.assertEqual(os.listdir(directory), [])
            other = budget.open(100000)
            with self.assertRaises(ValueError): other.write(b'y' * 70000)
            self.assertEqual(budget.used, 140000)
            result.close(); other.close(); self.assertEqual(budget.used, 0)

    def test_supervised_status_output_truncates_without_killing_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'complete'
            code, output = bounded([sys.executable, '-c', 'import sys,pathlib;sys.stdout.buffer.write(b"x"*5000000);pathlib.Path(sys.argv[1]).touch()', str(marker)], timeout=None)
            self.assertEqual(code, 0); self.assertTrue(marker.exists()); self.assertEqual(len(output), 4 * 1024 * 1024)
            error = Executor.generic(1, b'synthetic secret-bearing diagnostic')
            self.assertNotIn(b'secret-bearing', error.body)

    def test_profile_has_no_universal_maintenance_kill_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'etc').mkdir(); (root / 'etc/passwd').write_text('root:x:0:0:root:/root:/bin/sh\n')
            profile = Profile('mailcow-dovecot.service', root, Path('/run/netns/fixture'), (), ())
            values = profile.properties()
            for key in ('RuntimeMaxSec', 'MemoryMax', 'CPUQuota', 'TasksMax', 'TimeoutStopSec'):
                self.assertFalse(any(value.startswith(key + '=') for value in values))


if __name__ == '__main__': unittest.main(verbosity=2)
