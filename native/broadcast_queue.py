"""Bounded publication admission and orderly local pubsub action completion."""
import queue
import threading


class BroadcastQueue:
    """receive must contain action failures and signal protected operator review.

    The controller supplies that no-throw wrapper; an execution error must not
    terminate this worker or silently strand acknowledged maintenance work.
    """
    def __init__(self, publish, receive, capacity=32):
        self.publish, self.receive = publish, receive
        self.capacity = threading.BoundedSemaphore(capacity)
        self.pending = queue.Queue(maxsize=capacity)
        self.lock = threading.Lock()
        self.closed = False
        self.worker = threading.Thread(target=self.run)
        self.worker.start()

    def submit(self, message):
        # Reserve before publication: full local capacity must not publish an
        # action remotely then fail to retain its required local execution.
        if not self.capacity.acquire(blocking=False): raise queue.Full
        queued = False
        try:
            with self.lock:
                if self.closed: raise RuntimeError('Broadcast admission closed')
                self.publish(message)
                self.pending.put_nowait(message)
                queued = True
        finally:
            if not queued: self.capacity.release()

    def run(self):
        while True:
            message = self.pending.get()
            try:
                if message is None: return
                self.receive(message)
            finally:
                if message is not None: self.capacity.release()
                self.pending.task_done()

    def close(self):
        # Called after listener shutdown and all HTTP handlers finish. The lock
        # also reconciles an already publishing producer before admission closes.
        with self.lock: self.closed = True
        self.pending.join()
        self.pending.put(None)
        self.worker.join()
        self.pending.join()
