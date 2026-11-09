#!/usr/bin/env python3
"""A throwaway front proxy for measuring the dashboard: serves /staticfiles/ straight from web/static (what the production proxy does, with no
application hop) and forwards everything else to the application server, so a browser measurement times the API calls and not the static files.

    python scripts/scale/devproxy.py 8811 127.0.0.1:8801        # then point scripts/scale/dashboard_measure.py at http://127.0.0.1:8811
"""
import http.client
import mimetypes
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATIC = os.path.abspath(os.environ.get('STATIC_DIR') or os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'web', 'static'))  # STATIC_DIR: another tree's web/static
HOP = {'connection', 'keep-alive', 'transfer-encoding', 'te', 'trailer', 'upgrade', 'proxy-authorization', 'proxy-authenticate'}


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    upstream = None

    def log_message(self, *a):
        pass

    def static(self):
        rel = re.sub(r'^.*?/staticfiles/', '', self.path).split('?')[0]
        path = os.path.join(STATIC, rel)
        if not os.path.abspath(path).startswith(STATIC) or not os.path.isfile(path):
            return False
        body = open(path, 'rb').read()
        self.send_response(200)
        self.send_header('Content-Type', mimetypes.guess_type(path)[0] or 'application/octet-stream')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return True

    def forward(self):
        if self.path.startswith('/staticfiles/') and self.command == 'GET' and self.static():
            return
        length = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(length) if length else None
        conn = http.client.HTTPConnection(*self.upstream, timeout=300)
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
        conn.request(self.command, self.path, body=body, headers=headers)
        r = conn.getresponse()
        data = r.read()
        self.send_response(r.status)
        for k, v in r.getheaders():
            if k.lower() not in HOP and k.lower() != 'content-length':
                self.send_header(k, v)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        conn.close()

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = forward


if __name__ == '__main__':
    host, port = sys.argv[2].split(':')
    Handler.upstream = (host, int(port))
    ThreadingHTTPServer(('127.0.0.1', int(sys.argv[1])), Handler).serve_forever()
