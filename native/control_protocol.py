"""DockerApi-compatible routes with kernel-authenticated service permissions.

The target container id selects a fixed registered mail service, never the
caller. Caller identity comes exclusively from peer_policy's host cgroup.
Transport and executor are separate to allow differential response tests.
"""
from dataclasses import dataclass
import hashlib
import json
import re
from urllib.parse import urlsplit, parse_qs
from action_policy import compile_action, compile_pubsub, PolicyError, UNITS

CALLERS = {
    'mailcow-php-fpm.service': 'php',
    'mailcow-watchdog.service': 'watchdog',
    'mailcow-acme.service': 'acme',
    'mailcow-dovecot.service': 'dovecot',
    '/mailcow.slice/mailcow-jobs.slice/mailcow-job-dovecot_sarules@.service': 'dovecot',
}
RELOAD_TARGETS = frozenset(('nginx-mailcow', 'dovecot-mailcow', 'postfix-mailcow'))
BROADCAST_OPERATIONS = frozenset(('exec__maildir__move', 'exec__maildir__cleanup'))


class CallerDenied(PermissionError):
    pass


@dataclass(frozen=True)
class Reply:
    body: object  # bytes, or anonymous result_spool.Spool with size/chunks/close.
    media: str = 'application/json'
    status: int = 200

    @classmethod
    def json(cls, value, status=200):
        return cls(json.dumps(value, ensure_ascii=False).encode(), status=status)


def authorize_plan(caller, service, plan):
    if caller == 'php': return
    if caller == 'watchdog' and plan.operation in ('top', 'stats', 'restart'): return
    if caller == 'acme' and service in RELOAD_TARGETS and (plan.operation == 'restart' or plan.operation == 'exec__reload__' + service.removesuffix('-mailcow')): return
    if caller == 'dovecot' and service == 'rspamd-mailcow' and plan.operation == 'restart': return
    raise CallerDenied('Caller cannot perform this mail action')


class Dispatcher:
    def __init__(self, runtime, project, network_addresses):
        if not isinstance(project, str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,63}', project):
            raise ValueError('One fixed Compose project required')
        if set(network_addresses) != set(UNITS): raise ValueError('Complete closed service network registry required')
        self.runtime, self.project, self.addresses = runtime, project, dict(network_addresses)
        self.ids = {hashlib.sha256(('mailcow-native:' + project + ':' + service).encode()).hexdigest(): service for service in UNITS}

    def info(self, service):
        state = self.runtime.state(UNITS[service])
        return {'Id': next(identifier for identifier, target in self.ids.items() if target == service),
                'Config': {'Labels': {'com.docker.compose.project': self.project,
                                     'com.docker.compose.service': service}},
                'State': state,
                'NetworkSettings': {'Networks': {self.project + '_mailcow-network': {'IPAddress': self.addresses[service]}}}}

    def dispatch(self, caller, method, target, payload):
        if caller not in set(CALLERS.values()): raise CallerDenied('Unknown authenticated caller')
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or parsed.fragment: raise PolicyError('Local request path required')
        path = parsed.path
        if method == 'GET' and path == '/health': return Reply.json({'ready': True})
        if method == 'GET' and path == '/containers/json':
            all_services = parse_qs(parsed.query).get('all', ['false'])[0].lower() in ('true', '1')
            result = {}
            for service in UNITS:
                info = self.info(service)
                if all_services or info['State']['Running']: result[info['Id']] = info
            return Reply.json(result)
        if method == 'GET' and path == '/host/stats':
            if caller != 'php': raise CallerDenied('Host stats require admin caller')
            return Reply.json(self.runtime.host_stats())
        if method == 'POST' and path == '/broadcast':
            if caller != 'php': raise CallerDenied('Broadcast requires admin caller')
            plan = compile_pubsub(payload)
            if plan.operation not in BROADCAST_OPERATIONS: raise PolicyError('Unsupported replication broadcast family')
            # This is the only upstream broadcast producer family. Runtime signs
            # messages for authenticated replica consumers and deduplicates the
            # local origin, rather than executing unauthenticated Redis input.
            self.runtime.broadcast(plan, payload)
            return Reply.json(True)
        match = re.fullmatch(r'/containers/([0-9a-f]{64})/(json|[a-zA-Z0-9_]+)', path)
        stats = re.fullmatch(r'/container/([0-9a-f]{64})/stats/update', path)
        if match or stats:
            identifier = (match or stats)[1]
            service = self.ids.get(identifier)
            if not service: return Reply.json({'type': 'danger', 'msg': 'no container found'})
            if stats and method == 'POST':
                if caller != 'php': raise CallerDenied('Stats history requires admin caller')
                return Reply.json(self.runtime.stats_history(UNITS[service], identifier))
            action = match[2]
            if method == 'GET' and action == 'json': return Reply.json(self.info(service))
            if method == 'POST' and action != 'json':
                plan = compile_action(service, action, payload)
                authorize_plan(caller, service, plan)
                return self.runtime.execute(plan, payload)
        return Reply.json({'type': 'danger', 'msg': 'unknown native mail route'}, 404)
