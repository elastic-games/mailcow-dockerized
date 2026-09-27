"""Small bounded RESP2 client for fixed private Redis compatibility keys.

Endpoint/credentials are root operator configuration. Requests cannot choose
Redis commands or keys. Subscription carries signed replication messages only;
publisher identity is never inferred from a Redis message.
"""
import socket
import threading

MAX_BULK = 4 * 1024 * 1024


def encode(parts):
    parts = [value if isinstance(value, bytes) else str(value).encode() for value in parts]
    return b'*' + str(len(parts)).encode() + b'\r\n' + b''.join(b'$' + str(len(value)).encode() + b'\r\n' + value + b'\r\n' for value in parts)


def decode(file, depth=0):
    if depth > 4: raise ValueError('Redis nesting limit')
    line = file.readline(65537)
    if len(line) > 65536 or not line.endswith(b'\r\n'): raise ValueError('Truncated Redis frame')
    kind, content = line[:1], line[1:-2]
    if kind == b'+': return content
    if kind == b'-': raise RuntimeError('Redis command rejected')
    if kind == b':': return int(content)
    size = int(content)
    if kind == b'$':
        if size == -1: return None
        if size < 0 or size > MAX_BULK: raise ValueError('Redis bulk limit')
        data = file.read(size + 2)
        if len(data) != size + 2 or not data.endswith(b'\r\n'): raise ValueError('Truncated Redis bulk')
        return data[:-2]
    if kind == b'*':
        if size == -1: return None
        if size < 0 or size > 128: raise ValueError('Redis array limit')
        return [decode(file, depth + 1) for _ in range(size)]
    raise ValueError('Invalid Redis frame')


class Redis:
    def __init__(self, address, password, username=None):
        self.address, self.password, self.username = address, password, username

    def connect(self):
        connection = socket.create_connection(self.address, timeout=5)
        file = connection.makefile('rb')
        try:
            if self.password:
                connection.sendall(encode(['AUTH', self.username, self.password] if self.username else ['AUTH', self.password]))
                if decode(file) != b'OK': raise RuntimeError('Private Redis authentication failed')
            return connection, file
        except BaseException:
            file.close(); connection.close(); raise

    def command(self, *parts):
        connection, file = self.connect()
        try: connection.sendall(encode(parts)); return decode(file)
        finally: file.close(); connection.close()

    def subscribe(self, stop, callback):
        connection, file = self.connect()
        try:
            connection.sendall(encode(['SUBSCRIBE', 'MC_CHANNEL'])); decode(file)
            while not stop.is_set():
                message = decode(file)
                if isinstance(message, list) and len(message) == 3 and message[:2] == [b'message', b'MC_CHANNEL']:
                    callback(message[2])
        finally: file.close(); connection.close()
