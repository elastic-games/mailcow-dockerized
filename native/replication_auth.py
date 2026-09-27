"""Authenticate MC_CHANNEL replicas without trusting Redis publisher identity.

Keys are supplied by the root operator, never source/config exported to git.
Only the two actual upstream broadcast maildir actions are valid. Consumers
must persist replay ids before execution; keys/clock/namespace are deployment
gates, not implicit trust in a message's container_name or claimed sender.
"""
import hashlib
import hmac
import json
import time
import uuid
from action_policy import compile_pubsub, PolicyError
from control_protocol import BROADCAST_OPERATIONS

BASE_FIELDS = frozenset(('api_call', 'container_name', 'post_action', 'request'))


def canonical(message):
    return json.dumps(message, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


class ReplicaAuth:
    def __init__(self, origin, key, trusted_origins, project, now=time.time):
        if not isinstance(key, bytes) or len(key) < 32: raise ValueError('Protected high-entropy origin key required')
        self.origin, self.key, self.trusted, self.project, self.now = origin, key, dict(trusted_origins), project, now

    def sign(self, message):
        if set(message) != BASE_FIELDS: raise PolicyError('Exact broadcast shape required')
        plan = compile_pubsub(message)
        if plan.operation not in BROADCAST_OPERATIONS: raise PolicyError('Replica action denied')
        fields = {'cmd', 'task', 'maildir'} if plan.operation.endswith('__cleanup') else {'cmd', 'task', 'old_maildir', 'new_maildir'}
        if set(message['request']) != fields: raise PolicyError('Exact replication request fields required')
        unsigned = {**message, 'native_auth': {'origin': self.origin, 'project': self.project,
                                             'issued': int(self.now()), 'nonce': uuid.uuid4().hex}}
        return {**unsigned, 'native_mac': hmac.new(self.key, canonical(unsigned), hashlib.sha256).hexdigest()}

    def verify(self, message):
        if not isinstance(message, dict) or set(message) != BASE_FIELDS | {'native_auth', 'native_mac'}:
            raise PolicyError('Unsigned or ambiguous replica message')
        auth = message['native_auth']
        if not isinstance(auth, dict) or set(auth) != {'origin', 'project', 'issued', 'nonce'}:
            raise PolicyError('Invalid replica envelope')
        if not isinstance(auth['origin'], str) or not 1 <= len(auth['origin']) <= 128: raise PolicyError('Replica origin invalid')
        key = self.trusted.get(auth['origin'])
        if not isinstance(key, bytes) or len(key) < 32 or auth['project'] != self.project:
            raise PolicyError('Replica origin denied')
        if type(auth['issued']) is not int or abs(self.now() - auth['issued']) > 120:
            raise PolicyError('Replica envelope expired')
        if not isinstance(auth['nonce'], str) or len(auth['nonce']) != 32 or any(c not in '0123456789abcdef' for c in auth['nonce']):
            raise PolicyError('Replica nonce invalid')
        unsigned = {key: value for key, value in message.items() if key != 'native_mac'}
        mac = message['native_mac']
        if not isinstance(mac, str) or not hmac.compare_digest(hmac.new(key, canonical(unsigned), hashlib.sha256).hexdigest(), mac):
            raise PolicyError('Replica signature invalid')
        base = {key: message[key] for key in BASE_FIELDS}
        plan = compile_pubsub(base)
        if plan.operation not in BROADCAST_OPERATIONS: raise PolicyError('Replica action denied')
        fields = {'cmd', 'task', 'maildir'} if plan.operation.endswith('__cleanup') else {'cmd', 'task', 'old_maildir', 'new_maildir'}
        if set(base['request']) != fields: raise PolicyError('Exact replication request fields required')
        return plan, base, auth['origin'] + ':' + auth['nonce']
