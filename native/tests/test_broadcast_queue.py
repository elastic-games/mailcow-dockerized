import queue
from pathlib import Path
import sys
import threading
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from broadcast_queue import BroadcastQueue


class BroadcastQueueTests(unittest.TestCase):
    def test_capacity_reserved_before_publish_and_exact_drain(self):
        published = []; received = []; entered = threading.Event(); release = threading.Event()
        def receive(message):
            entered.set(); release.wait(3); received.append(message)
        work = BroadcastQueue(published.append, receive, capacity=2)
        work.submit(b'first'); self.assertTrue(entered.wait(2)); work.submit(b'second')
        with self.assertRaises(queue.Full): work.submit(b'never-published')
        self.assertEqual(published, [b'first', b'second'])
        finished = threading.Event()
        closing = threading.Thread(target=lambda: (work.close(), finished.set())); closing.start()
        self.assertFalse(finished.wait(.05))
        release.set(); closing.join(3)
        self.assertTrue(finished.is_set()); self.assertEqual(received, published)
        self.assertEqual(work.pending.unfinished_tasks, 0); self.assertFalse(work.worker.is_alive())
        with self.assertRaises(RuntimeError): work.submit(b'after-close')
        self.assertEqual(len(published), 2)

    def test_publication_failure_releases_reservation(self):
        received = []; calls = []
        def publish(message):
            calls.append(message)
            if message == b'failed': raise OSError('synthetic Redis unavailable')
        work = BroadcastQueue(publish, received.append, capacity=1)
        with self.assertRaises(OSError): work.submit(b'failed')
        work.submit(b'accepted'); work.close()
        self.assertEqual(received, [b'accepted']); self.assertEqual(work.pending.unfinished_tasks, 0)

    def test_close_waits_already_publishing_handler_then_drains(self):
        started = threading.Event(); release = threading.Event(); received = []
        def publish(message): started.set(); release.wait(3)
        work = BroadcastQueue(publish, received.append, capacity=1)
        producer = threading.Thread(target=lambda: work.submit(b'acknowledged'))
        producer.start(); self.assertTrue(started.wait(2))
        closing = threading.Thread(target=work.close); closing.start()
        release.set(); producer.join(3); closing.join(3)
        self.assertFalse(closing.is_alive()); self.assertEqual(received, [b'acknowledged'])
        self.assertEqual(work.pending.unfinished_tasks, 0)


if __name__ == '__main__': unittest.main(verbosity=2)
