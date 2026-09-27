import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from control_protocol import Reply
from replica_dispatch import ReplicaDispatch
from replication_auth import ReplicaAuth, canonical


@unittest.skipUnless(os.geteuid() == 0, 'Protected ledger tests require off-host root')
class ReplicaLedgerTests(unittest.TestCase):
    def message(self):
        return {'api_call': 'container_post', 'container_name': 'dovecot-mailcow',
                'post_action': 'exec', 'request': {'cmd': 'maildir', 'task': 'cleanup', 'maildir': 'fixture.invalid/user'}}

    def setup_dispatch(self, ledger, execute):
        clock = [1000]
        auth = ReplicaAuth('fixture', b'x' * 32, {'fixture': b'x' * 32}, 'fixture', now=lambda: clock[0])
        return ReplicaDispatch(auth, ledger, None, execute, True, True), clock

    def test_concurrent_completion_and_pruning_preserve_uncertain_records(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory); ledger.chmod(0o700)
            barrier = threading.Barrier(13)
            def execute(*_):
                barrier.wait(timeout=5)
                return Reply.json({'type': 'success'})
            dispatch, clock = self.setup_dispatch(ledger, execute)
            uncertain = ledger / ('a' * 64 + '.json')
            expired = ledger / ('b' * 64 + '.json')
            for path, complete in ((uncertain, False), (expired, True)):
                path.write_bytes(canonical({'nonce': 'fixture', 'issued': 700, 'complete': complete})); path.chmod(0o600)
            # Interrupted pre-replace temporary output must not poison reads.
            partial = ledger / '.completion-crash'; partial.write_bytes(b'{'); partial.chmod(0o600)
            messages = [canonical(dispatch.auth.sign(self.message())) for _ in range(12)]
            def prune():
                barrier.wait(timeout=5)
                for _ in range(100): dispatch.prune_completed()
            with concurrent.futures.ThreadPoolExecutor(max_workers=13) as pool:
                calls = [pool.submit(dispatch.receive, message) for message in messages]
                pruning = pool.submit(prune)
                self.assertTrue(all(call.result(timeout=10) for call in calls)); pruning.result(timeout=10)
            self.assertFalse(expired.exists()); self.assertTrue(uncertain.exists()); self.assertTrue(partial.exists())
            for message in messages:
                self.assertFalse(dispatch.receive(message))
                value = json.loads(message); nonce = 'fixture:' + value['native_auth']['nonce']
                self.assertTrue(json.loads((ledger / (hashlib.sha256(nonce.encode()).hexdigest() + '.json')).read_bytes())['complete'])
            clock[0] = 1500; dispatch.prune_completed()
            self.assertEqual(set(path.name for path in ledger.iterdir()), {uncertain.name, partial.name})

    def test_failed_atomic_completion_keeps_incomplete_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = Path(directory); ledger.chmod(0o700)
            dispatch, clock = self.setup_dispatch(ledger, lambda *_: Reply.json({'type': 'success'}))
            message = canonical(dispatch.auth.sign(self.message()))
            with patch('replica_dispatch.os.replace', side_effect=OSError('synthetic pre-replace failure')):
                with self.assertRaises(OSError): dispatch.receive(message)
            records = list(ledger.iterdir()); self.assertEqual(len(records), 1)
            self.assertFalse(json.loads(records[0].read_bytes())['complete'])
            self.assertFalse(dispatch.receive(message))
            clock[0] = 1500; dispatch.prune_completed(); self.assertTrue(records[0].exists())


if __name__ == '__main__': unittest.main(verbosity=2)
