"""The vetting forward proxy the screenshot browser is forced through (``cveFeed.web_shot``).

Why a proxy: a browser follows redirects inside its own network stack, and Playwright's request interception does not see them, so a page that
redirects to ``http://127.0.0.1:6379/`` or a cloud metadata address would be fetched before any check ran. Here every connection the
browser makes, for the page, each redirect hop and every sub-resource, arrives at this loopback listener, which asks ``admit(page, host, port)`` (the
platform's guards: the organization's exclusions, the bug bounty scope, the addresses a scanner may never touch) and, when the answer is yes,
connects to the address that was vetted, never to a name the browser resolves for itself: a DNS rebind between the check and the connection
has nothing to rebind. The connection goes out through ``connect`` (``cveFeed.pinned_transport.open_socket``), which sends it through Settings >
Proxy when one is set, and never directly instead of it.

It speaks just enough HTTP/1.1 proxying for Chromium: ``CONNECT host:port`` (every HTTPS request) is answered 200 and spliced; a plain ``GET
http://host/path`` is rewritten to origin form with ``Connection: close`` so one connection is one request and a later request to another host can
never ride the connection that was admitted for the first. A refused plain request is closed without an answer (the browser reports a failure and
never renders a page of ours); a refused CONNECT is a 403. The page being captured is identified by the proxy credentials its browser context
carries (user = the page key, password = a secret for this batch), so no other process in the container can use the listener.

It binds ``127.0.0.1`` on an ephemeral port, caps the bytes of one connection and the connections open at once, and drops idle ones.
"""
import base64
import hmac
import logging
import socket
import threading
import time
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

MAX_HEAD = 64 * 1024
HEAD_TIMEOUT = 15            # seconds for a browser to send a request head
IDLE_TIMEOUT = 40            # seconds a connection may sit without a byte before it is dropped
MAX_LIFETIME = 150           # seconds one connection may live at all
MAX_BYTES = 25 * 1024 * 1024  # a page and its sub-resources are far smaller; a media stream or a tarpit is cut off
MAX_CONNECTIONS = 64
CONNECT_TIMEOUT = 12
HOP_BY_HOP = {'proxy-authorization', 'proxy-connection', 'connection', 'keep-alive', 'proxy-authenticate', 'te', 'trailer', 'upgrade'}


def _split_authority(authority):
    """``(host, port)`` of a ``host:port`` or ``[v6]:port`` authority, or ``(None, None)``."""
    try:
        parts = urlsplit('//' + authority)
        return (parts.hostname or '').lower().rstrip('.') or None, parts.port
    except ValueError:
        return None, None


class VettingProxy:
    """``admit(page, host, port)`` returns ``(target, '')`` to let the connection through (``target`` is handed back to ``connect``) or
    ``(None, reason)``. ``connect(target, host, port, timeout)`` returns a connected socket or raises ``OSError``/``ValueError``."""

    def __init__(self, admit, connect, secret, bind='127.0.0.1'):
        self.admit, self.connect, self.secret, self.bind = admit, connect, str(secret), bind
        self._listener = None
        self._stop = threading.Event()
        self._open = 0
        self._lock = threading.Lock()
        self.port = 0

    @property
    def server(self):
        return f'http://{self.bind}:{self.port}'

    def start(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.bind, 0))
        listener.listen(128)
        self._listener, self.port = listener, listener.getsockname()[1]
        threading.Thread(target=self._accept, name='shot-proxy', daemon=True).start()
        return self.port

    def stop(self):
        self._stop.set()
        listener, self._listener = self._listener, None
        if listener is not None:
            try:
                listener.shutdown(socket.SHUT_RDWR)  # a thread blocked in accept() would otherwise keep the port open after close()
            except OSError:
                pass
            try:
                listener.close()
            except OSError:
                pass

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    # ------------------------------------------------------------------------- connections

    def _accept(self):
        while not self._stop.is_set():
            try:
                client, _ = self._listener.accept()
            except (OSError, AttributeError):
                return
            with self._lock:
                if self._open >= MAX_CONNECTIONS:
                    _close(client)
                    continue
                self._open += 1
            threading.Thread(target=self._serve, args=(client,), name='shot-proxy-conn', daemon=True).start()

    def _serve(self, client):
        upstream = None
        try:
            client.settimeout(HEAD_TIMEOUT)
            head, rest = _read_head(client)
            if head is None:
                return
            lines = head.split('\r\n')
            parts = lines[0].split(' ')
            if len(parts) != 3 or not parts[2].startswith('HTTP/'):
                return _reply(client, 400, 'Bad Request')
            method, target = parts[0].upper(), parts[1]
            headers = [(k.strip(), v.strip()) for k, _, v in (line.partition(':') for line in lines[1:]) if k.strip()]
            page = self._authenticate(headers)
            if page is None:
                return _reply(client, 407, 'Proxy Authentication Required', {'Proxy-Authenticate': 'Basic realm="cvengine-screenshot"'})
            if method == 'CONNECT':
                host, port = _split_authority(target)
                if not host or not port:
                    return _reply(client, 400, 'Bad Request')
                upstream, why = self._open_upstream(page, host, port)
                if upstream is None:
                    return _reply(client, 403 if why == 'refused' else 502, 'Forbidden' if why == 'refused' else 'Bad Gateway')
                client.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                outgoing = rest
            else:
                try:
                    url = urlsplit(target)
                    host, port = (url.hostname or '').lower().rstrip('.'), url.port or 80
                except ValueError:
                    return _reply(client, 400, 'Bad Request')
                if url.scheme != 'http' or not host:
                    return _reply(client, 400, 'Bad Request')
                upstream, why = self._open_upstream(page, host, port)
                if upstream is None:
                    return  # no answer at all: the browser reports a failed load, and no page of ours is ever drawn
                path = (url.path or '/') + (f'?{url.query}' if url.query else '')
                kept = [(k, v) for k, v in headers if k.lower() not in HOP_BY_HOP]
                request = f'{method} {path} {parts[2]}\r\n' + ''.join(f'{k}: {v}\r\n' for k, v in kept) + 'Connection: close\r\n\r\n'
                outgoing = request.encode('latin-1', 'replace') + rest
            self._splice(client, upstream, outgoing)
        except (OSError, ValueError):
            pass
        except Exception:  # noqa: BLE001 - one connection never takes the proxy down
            logger.debug('screenshot proxy connection failed', exc_info=True)
        finally:
            _close(client)
            _close(upstream)
            with self._lock:
                self._open -= 1

    def _authenticate(self, headers):
        for key, value in headers:
            if key.lower() != 'proxy-authorization':
                continue
            scheme, _, token = value.partition(' ')
            if scheme.lower() != 'basic':
                return None
            try:
                user, _, password = base64.b64decode(token.strip()).decode('utf-8').partition(':')
            except (ValueError, UnicodeDecodeError):
                return None
            return user if hmac.compare_digest(password.encode(), self.secret.encode()) else None
        return None

    def _open_upstream(self, page, host, port):
        """``(socket, '')``, or ``(None, 'refused')`` when the guards say no, or ``(None, 'failed')`` when the connection could not be made."""
        try:
            target, why = self.admit(page, host, port)
        except Exception:  # noqa: BLE001 - a guard that cannot answer is a refusal
            logger.warning('screenshot guard failed', exc_info=True)
            return None, 'refused'
        if target is None:
            return None, 'refused'
        try:
            return self.connect(target, host, port, CONNECT_TIMEOUT), ''
        except Exception:  # noqa: BLE001 - OSError, ValueError, a proxy that is down: all "could not connect", never a direct attempt
            return None, 'failed'

    def _splice(self, client, upstream, outgoing):
        deadline = time.monotonic() + MAX_LIFETIME
        counter = {'bytes': 0}
        client.settimeout(IDLE_TIMEOUT)
        upstream.settimeout(IDLE_TIMEOUT)
        if outgoing:
            upstream.sendall(outgoing)
        forward = threading.Thread(target=_pump, args=(client, upstream, counter, deadline), daemon=True)
        forward.start()
        _pump(upstream, client, counter, deadline)
        forward.join(timeout=5)


def _pump(source, sink, counter, deadline):
    """Copy ``source`` to ``sink`` until either ends, the lifetime or the byte cap is reached; then end the sink's writing side."""
    try:
        while time.monotonic() < deadline:
            data = source.recv(65536)
            if not data:
                break
            counter['bytes'] += len(data)
            if counter['bytes'] > MAX_BYTES:
                break
            sink.sendall(data)
    except OSError:
        pass
    finally:
        try:
            sink.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _read_head(sock):
    data = b''
    while b'\r\n\r\n' not in data:
        chunk = sock.recv(8192)
        if not chunk:
            return None, b''
        data += chunk
        if len(data) > MAX_HEAD:
            return None, b''
    head, _, rest = data.partition(b'\r\n\r\n')
    return head.decode('latin-1'), rest


def _reply(sock, status, text, headers=None):
    extra = ''.join(f'{k}: {v}\r\n' for k, v in (headers or {}).items())
    try:
        sock.sendall(f'HTTP/1.1 {status} {text}\r\n{extra}Content-Length: 0\r\nConnection: close\r\n\r\n'.encode('ascii'))
    except OSError:
        pass


def _close(sock):
    if sock is None:
        return
    try:
        sock.close()
    except OSError:
        pass
