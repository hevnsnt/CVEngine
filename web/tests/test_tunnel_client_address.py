"""Behind a Cloudflare Tunnel (docs/HOSTING-ONLINE.md, "Through a Cloudflare Tunnel") the application must see each visitor's own address, from the
bundled proxy's X-Forwarded-For, and must not be talkable into a wrong one. Three layers are checked here:

* the bundled proxy (config/nginx/rengine.conf, run by a real nginx when one is installed here, skipped otherwise): from an untrusted peer a forged
  X-Forwarded-For is replaced; from a peer listed in state/trusted-upstreams.conf it is kept and the peer is appended; the Sentinel result route and
  the seed import route behave the same;
* reNgine.client_ip on the chain the proxy then sends (what Cloudflare sends: the visitor's address appended to whatever the visitor wrote);
* the IP allowlist middleware, the abuse ban and the sign-in throttle: one visitor's ban does not touch another behind the same tunnel."""
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

from django.core.cache import cache
from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase, TestCase

from reNgine.client_ip import client_ip

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
CONF = open(os.path.join(REPO, 'config', 'nginx', 'rengine.conf'), encoding='utf-8').read()
CONNECTOR = '172.18.0.7'   # cloudflared as the web container's proxy sees it (a Docker address)
ALICE, BOB = '198.51.100.20', '203.0.113.30'
FORGED = '10.0.0.99'
TRUSTED = '172.16.0.0/12'


class ClientAddressTests(SimpleTestCase):
    """reNgine.client_ip on the chains the tunnel produces. Cloudflare appends the address that connected to it to any X-Forwarded-For the visitor
    sent (https://developers.cloudflare.com/fundamentals/reference/http-headers/), so the visitor's real address is the right-most one."""

    def ip(self, xff, remote='172.18.0.5', trusted=TRUSTED):
        request = RequestFactory().get('/', REMOTE_ADDR=remote, HTTP_X_FORWARDED_FOR=xff)
        with mock.patch.dict(os.environ, {'CVENGINE_TRUSTED_PROXIES': trusted}):
            return client_ip(request)

    def test_the_visitor_is_the_right_most_address_that_is_not_the_connector(self):
        self.assertEqual(self.ip(f'{ALICE}, {CONNECTOR}'), ALICE)

    def test_what_the_visitor_wrote_on_the_left_is_never_picked(self):
        self.assertEqual(self.ip(f'{FORGED}, {ALICE}, {CONNECTOR}'), ALICE)
        self.assertEqual(self.ip(f'garbage, {ALICE}, {CONNECTOR}'), ALICE)

    def test_a_peer_that_is_not_trusted_cannot_choose_its_address(self):
        self.assertEqual(self.ip(f'{FORGED}, {ALICE}', remote='192.0.2.50'), '192.0.2.50')

    def test_with_no_visitor_address_every_visitor_is_the_connector(self):
        # the failure the docs tell the administrator to check for: the header is missing (a Cloudflare transform removed it, or the proxy does not
        # trust the connector), so all visitors share one address
        self.assertEqual(self.ip('', remote=CONNECTOR), CONNECTOR)


class FakeUpstream(BaseHTTPRequestHandler):
    seen = []

    def do_POST(self):  # noqa: N802
        self.do_GET()

    def do_GET(self):  # noqa: N802
        type(self).seen.append({'xff': self.headers.get('X-Forwarded-For'), 'proto': self.headers.get('X-Forwarded-Proto'), 'host': self.headers.get('Host')})
        self.send_response(200)
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'ok')

    def log_message(self, *args):
        pass


@unittest.skipUnless(shutil.which('nginx'), 'needs an nginx binary')
class BundledProxyTests(SimpleTestCase):
    """config/nginx/rengine.conf under a real nginx with a fake application behind it. The test client connects from 127.0.0.1, which stands for
    cloudflared (or for anything else that connects)."""

    def run_proxy(self, trusted_file):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        os.makedirs(f'{tmp}/state')
        stock = open(os.path.join(REPO, 'config', 'nginx', 'trusted-upstreams.conf'), encoding='utf-8').read()
        with open(f'{tmp}/trusted-upstreams.conf', 'w') as f:  # the stock file (comments only) unless the test mounts its own
            f.write(stock if trusted_file is None else trusted_file)
        upstream = HTTPServer(('127.0.0.1', 0), FakeUpstream)
        FakeUpstream.seen = []
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        self.addCleanup(upstream.shutdown)
        head = CONF[:CONF.index('\nserver {')].replace('/etc/nginx/trusted-upstreams.conf', f'{tmp}/trusted-upstreams.conf')
        server = CONF[CONF.index('    location / {'):]
        server = server[:server.index('\n    }') + 6].replace('http://rengine:8000/', f'http://127.0.0.1:{upstream.server_port}/')
        server = server.replace('/etc/nginx/state/', f'{tmp}/state/')
        sock = __import__('socket').socket()
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
        sock.close()
        with open(f'{tmp}/nginx.conf', 'w') as f:
            f.write(f'daemon off; pid {tmp}/nginx.pid; error_log {tmp}/error.log;\nevents {{}}\nhttp {{\n'
                    f'client_body_temp_path {tmp}/b; proxy_temp_path {tmp}/p; fastcgi_temp_path {tmp}/f; uwsgi_temp_path {tmp}/u; scgi_temp_path {tmp}/s;\n'
                    f'access_log off;\n{head}\nserver {{ listen 127.0.0.1:{port};\n{server}\n}}\n}}\n')
        check = subprocess.run(['nginx', '-t', '-c', f'{tmp}/nginx.conf'], capture_output=True, text=True)
        self.assertEqual(check.returncode, 0, check.stderr)
        proc = subprocess.Popen(['nginx', '-c', f'{tmp}/nginx.conf'], stderr=subprocess.DEVNULL)
        self.addCleanup(proc.wait)
        self.addCleanup(proc.terminate)
        for _ in range(50):
            try:
                urllib.request.urlopen(f'http://127.0.0.1:{port}/', timeout=1).read()
                break
            except Exception:  # noqa: BLE001
                time.sleep(0.1)
        FakeUpstream.seen = []
        return port

    def get(self, port, xff=None):
        request = urllib.request.Request(f'http://127.0.0.1:{port}/', headers={'X-Forwarded-For': xff} if xff else {})
        urllib.request.urlopen(request, timeout=5).read()
        return FakeUpstream.seen[-1]['xff']

    def test_by_default_a_forged_chain_is_replaced_by_the_peer(self):
        port = self.run_proxy(None)  # the stock (comment-only) file: a plain install
        self.assertEqual(self.get(port, f'{FORGED}, {ALICE}'), '127.0.0.1')
        self.assertEqual(self.get(port), '127.0.0.1')

    def test_a_peer_that_is_not_listed_is_not_believed(self):
        port = self.run_proxy('192.0.2.0/24 1;\n')
        self.assertEqual(self.get(port, f'{FORGED}, {ALICE}'), '127.0.0.1')

    def test_a_listed_peer_has_its_chain_kept_and_itself_appended(self):
        port = self.run_proxy('127.0.0.0/8 1;\n')
        self.assertEqual(self.get(port, ALICE), f'{ALICE}, 127.0.0.1')
        self.assertEqual(self.get(port, f'{FORGED}, {ALICE}'), f'{FORGED}, {ALICE}, 127.0.0.1')
        self.assertEqual(self.get(port), '127.0.0.1')  # no chain: the peer alone, with no stray comma

    def test_end_to_end_the_application_picks_the_visitor_behind_a_listed_peer(self):
        port = self.run_proxy('127.0.0.0/8 1;\n')
        for visitor in (ALICE, BOB):
            for written in ('', f'{FORGED}, '):  # what the visitor wrote before Cloudflare appended the address it saw
                chain = self.get(port, f'{written}{visitor}')
                request = RequestFactory().get('/', REMOTE_ADDR='172.18.0.2', HTTP_X_FORWARDED_FOR=chain.replace('127.0.0.1', '172.18.0.7'))
                with mock.patch.dict(os.environ, {'CVENGINE_TRUSTED_PROXIES': TRUSTED}):
                    self.assertEqual(client_ip(request), visitor)

    def test_every_proxied_route_uses_the_same_rule(self):
        self.assertEqual(len(re.findall(r'X-Forwarded-For \$cvengine_forwarded_for;', CONF)), 3)
        self.assertNotIn('X-Forwarded-For $remote_addr', CONF)


def ok_view(request):
    return HttpResponse('ok')


class OneVisitorsBanIsNotEveryonesTests(TestCase):
    """Behind the tunnel the web container's peer is always the proxy. A ban, the allowlist and the sign-in throttle act on the visitor taken from the
    chain, so banning Alice leaves Bob in, and the connector's own address is never banned."""

    def setUp(self):
        cache.clear()
        from reNgine import input_guard, ip_allowlist
        input_guard.invalidate_cache()
        ip_allowlist.invalidate_cache()
        patch = mock.patch.dict(os.environ, {'CVENGINE_TRUSTED_PROXIES': TRUSTED})
        patch.start()
        self.addCleanup(patch.stop)

    def through_the_tunnel(self, visitor, forged=''):
        from reNgine.ip_allowlist import IpAllowlistMiddleware
        request = RequestFactory().get('/', REMOTE_ADDR='172.18.0.2', HTTP_X_FORWARDED_FOR=f'{forged}{visitor}, {CONNECTOR}')
        return IpAllowlistMiddleware(ok_view)(request).status_code

    def test_a_ban_hits_only_that_visitor(self):
        from dashboard.models import AbuseBan
        from reNgine import input_guard
        AbuseBan.objects.create(ip=ALICE, reason='test')
        input_guard.invalidate_cache()
        self.assertEqual(self.through_the_tunnel(ALICE), 403)
        self.assertEqual(self.through_the_tunnel(BOB), 200)

    def test_a_banned_visitor_cannot_hide_behind_a_forged_left_hand_address(self):
        from dashboard.models import AbuseBan
        from reNgine import input_guard
        AbuseBan.objects.create(ip=ALICE, reason='test')
        input_guard.invalidate_cache()
        self.assertEqual(self.through_the_tunnel(ALICE, forged=f'{BOB}, '), 403)

    def test_a_visitor_cannot_borrow_another_visitors_clean_record_by_forging_it(self):
        from dashboard.models import AbuseBan
        from reNgine import input_guard
        AbuseBan.objects.create(ip=ALICE, reason='test')
        input_guard.invalidate_cache()
        self.assertEqual(self.through_the_tunnel(BOB, forged=f'{ALICE}, '), 200)  # Bob is not punished for what Alice's name was written next to

    def test_the_allowlist_sees_the_visitor_not_the_connector(self):
        from dashboard.models import IpAccessControl, IpAllowlistEntry
        from reNgine import ip_allowlist
        control = IpAccessControl.current()
        control.enabled = True
        control.save()
        IpAllowlistEntry.objects.create(cidr='198.51.100.0/24')
        ip_allowlist.invalidate_cache()
        self.assertEqual(self.through_the_tunnel(ALICE), 200)
        self.assertEqual(self.through_the_tunnel(BOB), 403)
        self.assertEqual(self.through_the_tunnel(BOB, forged=f'{ALICE}, '), 403)

    def test_the_connectors_own_address_is_never_banned_by_the_guard(self):
        from reNgine.input_guard import _ip_is_banable
        self.assertFalse(_ip_is_banable(CONNECTOR))

    def test_sign_in_failures_are_counted_per_visitor(self):
        from tenancy.views import _login_keys
        a = _login_keys(RequestFactory().post('/', REMOTE_ADDR='172.18.0.2', HTTP_X_FORWARDED_FOR=f'{ALICE}, {CONNECTOR}'), 'admin')
        b = _login_keys(RequestFactory().post('/', REMOTE_ADDR='172.18.0.2', HTTP_X_FORWARDED_FOR=f'{BOB}, {CONNECTOR}'), 'admin')
        self.assertNotEqual(a['ip'], b['ip'])
        self.assertNotEqual(a['pair'], b['pair'])
        self.assertIn(ALICE, a['ip'])
