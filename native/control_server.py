"""Bounded stdlib HTTP-over-Unix transport; no TCP listener or identity proxy.

Every connection is authenticated using the actual kernel peer before parsing
any request. One request per connection avoids transferring its authority to
an unrelated later peer. No request/header/body logging or exception repr.
"""
import json
import os
import socketserver
import threading
from http.server import BaseHTTPRequestHandler
from action_policy import PolicyError
from control_protocol import CALLERS, CallerDenied, Reply
from peer_policy import authorize, PeerDenied

MAX_BODY = 64 * 1024


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'

    def log_message(self, *_): pass

    def handle(self):
        self.request.settimeout(10)
        try: self.caller = self.server.peer_authorizer(self.request, CALLERS)
        except PeerDenied:
            self.request.sendall(b'HTTP/1.0 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            return
        super().handle()

    def do_GET(self): self._dispatch()
    def do_POST(self): self._dispatch()

    def _dispatch(self):
        try:
            lengths = self.headers.get_all('Content-Length', [])
            if self.headers.get('Transfer-Encoding') or len(lengths) > 1:
                raise PolicyError('Ambiguous request framing')
            size = int(lengths[0]) if lengths else 0
            if size < 0 or size > MAX_BODY: raise PolicyError('Request body exceeds limit')
            raw = self.rfile.read(size)
            if len(raw) != size: raise PolicyError('Truncated request body')
            payload = json.loads(raw) if raw else {}
            if not isinstance(payload, dict): raise PolicyError('JSON object required')
            reply = self.server.dispatcher.dispatch(self.caller, self.command, self.path, payload)
        except CallerDenied: reply = Reply.json({'type': 'danger', 'msg': 'caller action denied'}, 403)
        except (PolicyError, ValueError, UnicodeError): reply = Reply.json({'type': 'danger', 'msg': 'invalid native mail request'}, 400)
        except Exception:
            # Commands may contain secret input. Never echo raw exceptions.
            reply = Reply.json({'type': 'danger', 'msg': 'native mail operation failed'}, 503)
        streamed = not isinstance(reply.body, bytes)
        try:
            self.send_response(reply.status)
            self.send_header('Content-Type', reply.media)
            self.send_header('Content-Length', str(reply.body.size if streamed else len(reply.body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            if streamed:
                for part in reply.body.chunks(): self.wfile.write(part)
            else: self.wfile.write(reply.body)
        finally:
            if streamed: reply.body.close()
            self.close_connection = True


class ControlServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, path, dispatcher, peer_authorizer=authorize):
        self.dispatcher, self.peer_authorizer = dispatcher, peer_authorizer
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(str(path), Handler)
        os.chmod(path, 0o666)  # Only explicitly bound peers can reach host0700 ancestor.

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close(); return
        try: super().process_request(request, address)
        except Exception: self.slots.release(); raise

    def process_request_thread(self, request, address):
        try: super().process_request_thread(request, address)
        finally: self.slots.release()
