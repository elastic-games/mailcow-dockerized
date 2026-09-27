"""Runnable off-host control bridge, using fixed operator configuration only.

No public listener, Docker socket, application-selected identity or live mail
activation. Production mode is rejected until full-stack parity is reviewed.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import threading
sys_path = str(Path(__file__).resolve().parent)
import sys
sys.path.insert(0, sys_path)
from broadcast_queue import BroadcastQueue
from action_policy import UNITS
from control_protocol import Dispatcher
from control_server import ControlServer
from replica_dispatch import ReplicaDispatch
from replication_auth import ReplicaAuth, canonical
from redis_wire import Redis
from result_spool import SpoolBudget
from runtime_config import load, protected_file, protected_directory
from service_executor import Executor
from service_observer import Observer


def serve(path):
    if sys.platform != 'linux' or os.geteuid() != 0: raise PermissionError('Off-host root Linux operator required')
    config, store, profiles, network = load(path)
    operator = store.root / 'operator'
    redis = Redis((network['redis-mailcow'], 6379), protected_file(operator / 'redis.password', 65536))
    budget = SpoolBudget(protected_directory(operator / 'spool'), 512 * 1024 * 1024)
    observer = Observer(profiles, redis)
    settings = config['replication']
    stopped = threading.Event(); subscription_stopped = threading.Event(); local_queue = None; replica = None
    def broadcast(plan, base):
        if replica is None: raise PermissionError('Replication is disabled')
        # Match legacy response lifetime: authenticated publication completes,
        # while local maintenance runs asynchronously and remains supervised.
        message = canonical(replica.auth.sign(base))
        local_queue.submit(message)
    password_file = store.root / 'data/config/rspamd/etc/rspamd/override.d/worker-controller-password.inc'
    executor = Executor(profiles, observer, broadcast, {UNITS['rspamd-mailcow']: password_file}, store, budget)
    if settings == {'enabled': False}: pass
    elif set(settings) == {'enabled', 'replicasAccepted', 'origin', 'trustedOrigins'} and settings['enabled'] is True and settings['replicasAccepted'] is True:
        if not isinstance(settings['trustedOrigins'], list) or not settings['trustedOrigins'] or len(settings['trustedOrigins']) > 32:
            raise ValueError('Bounded accepted replica inventory required')
        def key(origin):
            if not isinstance(origin, str) or not origin.isascii() or not origin.replace('-', '').replace('_', '').isalnum() or len(origin) > 128:
                raise ValueError('Fixed accepted origin required')
            return protected_file(operator / 'replica-keys' / origin, 128)
        auth = ReplicaAuth(settings['origin'], key(settings['origin']), {name: key(name) for name in settings['trustedOrigins']}, config['project'])
        ledger = protected_directory(operator / 'replica-ledger')
        replica = ReplicaDispatch(auth, ledger, redis, executor.execute, True, True)
    else: raise PermissionError('Replication requires every replica acceptance')
    dispatcher = Dispatcher(executor, config['project'], network)
    socket_path = operator / 'control.sock'
    # Refuse a stale/foreign socket rather than deleting a possibly active peer.
    server = ControlServer(socket_path, dispatcher)
    server.daemon_threads = False
    workers = []
    def receive(raw):
        try: replica.receive(raw)
        except Exception: print('native replica action requires protected operator review', file=sys.stderr)
    def subscription():
        pause = 1
        while not subscription_stopped.is_set():
            try: redis.subscribe(subscription_stopped, receive); pause = 1
            except Exception:
                subscription_stopped.wait(pause); pause = min(30, pause * 2)
    if replica:
        local_queue = BroadcastQueue(lambda message: redis.command('PUBLISH', 'MC_CHANNEL', message), receive)
        worker = threading.Thread(target=subscription); worker.start(); workers.append(worker)
    serving = threading.Thread(target=server.serve_forever); serving.start()
    def stop(*_): stopped.set()
    signal.signal(signal.SIGTERM, stop); signal.signal(signal.SIGINT, stop)
    try: stopped.wait()
    finally:
        server.shutdown(); server.server_close(); serving.join()
        if local_queue: local_queue.close()
        subscription_stopped.set()
        # Existing actions retain their foreground lease/cgroup supervision.
        # Threads finish instead of claiming that incomplete work disappeared.
        for worker in workers: worker.join()
        socket_path.unlink()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    try: serve(args.config)
    except Exception: raise SystemExit('Native mail controller configuration/runtime rejected') from None
