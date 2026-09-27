import subprocess
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fixture_network import Network


class NetworkCleanupTests(unittest.TestCase):
    def test_disappearing_veth_is_reconciled(self):
        network = Network('synthetic', '1234abcd', '172.30.66.0/24')
        network.links = ['mcv-1234abcd-0']
        with patch('fixture_network.Path') as path, patch.object(network, 'run', side_effect=subprocess.CalledProcessError(1, ['ip', 'link', 'delete'])):
            path.return_value.exists.side_effect = [True, False]
            network.close()
        self.assertEqual(network.links, [])

    def test_persistent_veth_failure_retains_cleanup_evidence(self):
        network = Network('synthetic', '1234abcd', '172.30.66.0/24')
        network.links = ['mcv-1234abcd-0']
        with patch('fixture_network.Path') as path, patch.object(network, 'run', side_effect=subprocess.CalledProcessError(1, ['ip', 'link', 'delete'])):
            path.return_value.exists.side_effect = [True, True]
            with self.assertRaises(subprocess.CalledProcessError): network.close()
        self.assertEqual(network.links, ['mcv-1234abcd-0'])


if __name__ == '__main__': unittest.main()
