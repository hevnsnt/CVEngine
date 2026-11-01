#!/usr/bin/env python3
"""Real-browser smoke test of the web screenshot capture path (cveFeed/web_shot.py and cveFeed/shot_worker.py). Not part of the Django suite
(which never launches a browser); run it by hand, or in the built image, to prove Chromium starts and the capture code produces a picture:

  cd web && python3 ../scripts/smoke_web_shot.py

It serves a small page, a redirect and a page that loads an image from a host the guard refuses, all on 127.0.0.1, then runs the real child process
(one browser, a fresh context per page) over them through the real vetting proxy (``cveFeed/shot_proxy.py``) with a stand-in guard, and checks: a non-empty PNG and a
thumbnail, the title, the HTTP status, a redirect hop that the guard refuses (blocked, with the reason), a sub-resource that is dropped (the page
is still photographed), an allowed redirect (its final URL is recorded) and a closed port (unreachable). Exit status 0 when all of that holds."""
import http.server
import os
import shutil
import sys
import tempfile
import threading
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'web'))

PAGE = b"""<!doctype html><html><head><title>Smoke Test Page</title><style>body{background:#1a3d7c;color:#fff;font:40px sans-serif}
div{padding:40px;background:linear-gradient(90deg,#e33,#fc0)}</style></head><body><h1>cvENGINE smoke</h1><div>Hello from a local page</div>
<img src="http://blocked.example.test/x.png" width="10" height="10"></body></html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        port = self.server.server_address[1]
        if self.path.startswith('/to-blocked'):
            return self._redirect(f'http://blocked.example.test:{port}/page')
        if self.path.startswith('/to-localhost'):
            return self._redirect(f'http://localhost:{port}/page')
        if self.path.startswith('/to-metadata'):
            return self._redirect('http://169.254.169.254/latest/meta-data/')
        if self.path.startswith('/to-loopback-port'):
            return self._redirect('http://[::1]:6379/')
        if self.path.startswith('/page') or self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(PAGE)))
            self.end_headers()
            return self.wfile.write(PAGE)
        self.send_response(404)
        self.end_headers()

    def _redirect(self, where):
        self.send_response(302)
        self.send_header('Location', where)
        self.end_headers()

    def log_message(self, *args):
        pass


def serve_tls(workdir):
    """An HTTPS twin of the page on its own port with a throw-away self-signed certificate (the browser must ignore the error, and the request
    reaches the proxy as CONNECT). ``None`` when openssl is not available."""
    import ssl
    import subprocess
    cert, key = os.path.join(workdir, 'cert.pem'), os.path.join(workdir, 'key.pem')
    try:
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=localhost'],
                       check=True, capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    secure = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    secure.socket = context.wrap_socket(secure.socket, server_side=True)
    threading.Thread(target=secure.serve_forever, daemon=True).start()
    return secure


def main():
    from cveFeed import shots, web_shot
    if not web_shot.browser_installed() and not os.environ.get('CVENGINE_SMOKE_ANY_BROWSER'):
        print('Chromium for this Playwright release is not installed (PLAYWRIGHT_BROWSERS_PATH=%s)' % web_shot.browsers_dir())
        return 2
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    workdir = web_shot.make_workdir()
    import socket

    from cveFeed import shot_proxy
    admitted = []
    real = web_shot.Guard(0, '127.0.0.1', True, gate=type('Open', (), {'refusal': lambda *a, **k: ''})(), excluded=frozenset())  # the platform's own rules

    def admit(page, host, port):
        """This test's own server is 127.0.0.1 and ``localhost``, which the real rules would refuse, so those two are let through by hand; every other
        host is judged by the real guard (``web_shot.Guard``: the address rules of ``targetApp.target_types``), and one name is refused by hand."""
        admitted.append((page, host, port))
        if host in ('127.0.0.1', 'localhost'):
            return '127.0.0.1', ''
        if host == 'blocked.example.test':
            return None, f'{host} cannot be visited: stand-in guard'
        return real.admit(host, port)

    secure = serve_tls(workdir)
    secret = 'smoke-secret'
    with socket.socket() as probe:  # a port nothing listens on
        probe.bind(('127.0.0.1', 0))
        closed_port = probe.getsockname()[1]
    pages = {'page': f'http://127.0.0.1:{port}/page', 'redirect-blocked': f'http://127.0.0.1:{port}/to-blocked',
             'redirect-allowed': f'http://127.0.0.1:{port}/to-localhost', 'redirect-metadata': f'http://127.0.0.1:{port}/to-metadata',
             'redirect-loopback': f'http://127.0.0.1:{port}/to-loopback-port', 'closed': f'http://127.0.0.1:{closed_port}/'}
    if secure is not None:
        pages['https'] = f'https://127.0.0.1:{secure.server_address[1]}/page'  # a self-signed certificate, through CONNECT
    targets = [{'key': key, 'url': url, 'out': os.path.join(workdir, f'{key}.png')} for key, url in pages.items()]
    results = {}
    with shot_proxy.VettingProxy(admit, lambda target, host, number, timeout: socket.create_connection((target, number), timeout), secret) as proxy:
        job = {'targets': targets, 'proxy': {'server': proxy.server, 'password': secret}, 'settings': {'total_seconds': 20, 'nav_timeout_ms': 12000}}
        failure = web_shot.run_child(job, lambda message: results.__setitem__(message['key'], message), 120, heavy=False, workdir=workdir)
    problems = []
    if failure:
        problems.append(f'the child ended early: {failure}')
    page = results.get('page') or {}
    if page.get('outcome') != 'ok':
        problems.append(f'page: {page}')
    else:
        data = open(page['path'], 'rb').read()
        if not data.startswith(b'\x89PNG\r\n\x1a\n') or len(data) < 1000:
            problems.append(f'the picture is not a real PNG ({len(data)} bytes)')
        thumb = shots.thumbnail_path(page['path'])
        if not thumb or os.path.getsize(thumb) == 0:
            problems.append('no thumbnail')
        if page.get('title') != 'Smoke Test Page' or page.get('status') != 200:
            problems.append(f'title or status wrong: {page.get("title")!r} {page.get("status")}')
        print(f'page: ok, {len(data)} bytes, thumbnail {os.path.getsize(thumb)} bytes, title {page["title"]!r}, status {page["status"]}')
    blocked = results.get('redirect-blocked') or {}
    if blocked.get('outcome') == 'ok' or not any(host == 'blocked.example.test' for _page, host, _port in admitted):
        problems.append(f'the redirect hop to the refused host was not stopped at the proxy: {blocked}')
    else:
        print('redirect hop to a refused host: stopped at the proxy; the browser saw', blocked['outcome'], '-', blocked['reason'])
    allowed = results.get('redirect-allowed') or {}
    if allowed.get('outcome') != 'ok' or 'localhost' not in allowed.get('final_url', ''):
        problems.append(f'allowed redirect: {allowed}')
    else:
        print('allowed redirect: ok, final URL', allowed['final_url'])
    if secure is not None:
        tls = results.get('https') or {}
        if tls.get('outcome') != 'ok' or tls.get('title') != 'Smoke Test Page':
            problems.append(f'https page with a self-signed certificate: {tls}')
        else:
            print('https with a self-signed certificate: ok (through CONNECT)')
    if not {'127.0.0.1', 'localhost'} <= {host for _page, host, _port in admitted}:
        problems.append('loopback requests did not go through the proxy')
    for key, host in (('redirect-metadata', '169.254.169.254'), ('redirect-loopback', '::1')):  # the real address rules, on a hop the browser followed itself
        refused = [reason for hop, reason in real.denied if hop == host]
        if (results.get(key) or {}).get('outcome') == 'ok' or not refused or 'internal or reserved' not in refused[0]:
            problems.append(f'{key}: the hop to {host} was not refused by the platform\'s address rules: {results.get(key)} {real.denied}')
        else:
            print(f'{key}: refused at the proxy by the real address rules ({refused[0]})')
    closed = results.get('closed') or {}
    if closed.get('outcome') != 'unreachable':
        problems.append(f'closed port: {closed}')
    else:
        print('closed port: unreachable,', closed['reason'])
    shutil.rmtree(workdir, ignore_errors=True)
    server.shutdown()
    if secure is not None:
        secure.shutdown()
    for line in problems:
        print('FAIL', line)
    print('smoke test', 'FAILED' if problems else 'passed')
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
