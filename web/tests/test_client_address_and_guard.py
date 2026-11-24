"""Review r3 S1 to S3: the abuse guard can no longer be aimed at an account by a link, the real client address reaches the application through a
host nginx, and only the bundled proxy can name the client address.

* S1 (input guard): the review's demonstration tests, inverted. A GET a link can start (Sec-Fetch-Site none or same-origin) is refused and kept
  for the record but never counted; at the threshold the guard ends the offending browser session and bans a public address, and never disables
  an account or revokes a token.
* S2 and S3 (client address): reNgine.client_ip over the shipped default (CVENGINE_TRUSTED_PROXIES = the proxy's fixed address), the production
  chain, spoofing peers, the gateway and IPv6; the compose layout that gives the proxy that address; the probe route and the check script; and
  the proxy container itself (nginx:alpine, the shipped conf and template, a fixed-subnet network) end to end.
"""
import json
import os
import re
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.management import call_command
from django.test import Client, RequestFactory, SimpleTestCase, TestCase
from django.utils import timezone

from agentapi.auth import create_token
from dashboard.models import AbuseBan, AbuseStrike, ApiToken, AuditLog, Org, OrgMembership, Project
from reNgine import client_probe
from reNgine import input_guard as guard
from reNgine.client_ip import client_ip

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / 'docker-compose.yml'
COMPOSE_TEXT = COMPOSE.read_text() if COMPOSE.is_file() else ''
_default = re.search(r'CVENGINE_PROXY_ADDRESS:-([0-9.]+)\}', COMPOSE_TEXT)
PROXY = _default.group(1) if _default else '172.16.238.10'  # the proxy's fixed address, which is also the default of CVENGINE_TRUSTED_PROXIES
SHIPPED = {'CVENGINE_TRUSTED_PROXIES': PROXY}
OLD_RANGE = {'CVENGINE_TRUSTED_PROXIES': '172.16.0.0/12'}  # the default before this change
GATEWAY = '172.16.238.1'   # what the proxy sees when a host nginx connects through Docker's port publishing
SCANNER = '172.20.0.3'     # the built-in scanner on scanner_network, which reaches web:8000 directly
REVIEWER = '172.18.0.6'    # the AI reviewer on rengine_network
REAL, OTHER = '8.8.4.4', '9.9.9.9'  # public addresses (the documentation ranges count as private, and private addresses are never banned)


def through(remote, xff=None, env=SHIPPED, **extra):
    meta = {'REMOTE_ADDR': remote, **extra}
    if xff is not None:
        meta['HTTP_X_FORWARDED_FOR'] = xff
    request = RequestFactory().get('/', **meta)
    with mock.patch.dict(os.environ, env):
        return client_ip(request)


class LinkCannotLockAnAccountTests(TestCase):
    """S1. The review's OneClickAccountLockout, inverted: a navigation a link can start (a link in a mail or chat app, a bookmark, a link inside the
    app) with a path traversal in its query string leaves the account active and every token, Sentinel tokens included, intact."""

    @classmethod
    def setUpTestData(cls):
        org = Org.objects.create(name='R', slug='r')
        cls.project = Project.objects.create(name='R', slug='r-p', insert_date=timezone.now(), org=org)
        cls.victim = User.objects.create_user('analyst', password='x')
        cls.root = User.objects.create_superuser('root', 'r@x.test', 'x')
        OrgMembership.objects.create(user=cls.victim, org=org, role='user')

    def setUp(self):
        guard.invalidate_cache()
        self.addCleanup(guard.invalidate_cache)
        create_token(self.victim, 'laptop')
        create_token(self.victim, 'sentinel-like', scope='sentinel')
        patch = mock.patch.dict(os.environ, SHIPPED)
        patch.start()
        self.addCleanup(patch.stop)

    def signed_in(self):
        c = Client()
        c.force_login(self.victim)
        return c

    def assert_untouched(self):
        self.victim.refresh_from_db()
        self.assertTrue(self.victim.is_active)
        self.assertEqual(ApiToken.objects.filter(user=self.victim, revoked=False).count(), 2)
        self.assertFalse(AbuseBan.objects.exists())

    def test_link_opened_from_a_mail_app_is_refused_and_changes_nothing(self):
        # through the proxy from a real public address: before this change a strike here would also have banned the victim's address
        r = self.signed_in().get('/cve/cves/?q=..%2F..%2Fetc%2Fpasswd', REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=REAL, HTTP_SEC_FETCH_SITE='none')
        self.assertEqual(r.status_code, 400)
        self.assert_untouched()
        strike = AbuseStrike.objects.get()  # kept for the record, with what was sent and from where
        self.assertEqual((strike.weight, strike.category, strike.username, strike.ip), (0, 'path_traversal', 'analyst', REAL))

    def test_same_origin_link_is_refused_and_changes_nothing(self):
        c = self.signed_in()
        for _ in range(5):  # however many times: weight 0 never adds up
            r = c.get('/cve/r-p/hosts/?q=a%3B%20cat%20%2Fetc%2Fpasswd', REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=REAL, HTTP_SEC_FETCH_SITE='same-origin')
            self.assertEqual(r.status_code, 400)
        self.assert_untouched()
        self.assertEqual(AbuseStrike.objects.filter(weight=0).count(), 5)
        self.assertEqual(c.get('/cve/', REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=REAL).status_code, 200)  # still signed in

    def test_a_head_navigation_is_not_counted_either(self):
        self.signed_in().head('/cve/?x=..%2F..%2Fetc%2Fpasswd', REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=REAL, HTTP_SEC_FETCH_SITE='none')
        self.assert_untouched()

    def test_cross_site_is_still_refused_without_any_record(self):
        self.signed_in().get('/cve/?x=..%2F..%2Fetc%2Fpasswd', REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=REAL, HTTP_SEC_FETCH_SITE='cross-site')
        self.assert_untouched()
        self.assertFalse(AbuseStrike.objects.exists())

    def test_a_request_a_link_cannot_make_ends_the_session_and_bans_the_address_but_keeps_the_account(self):
        c = self.signed_in()
        r = c.post('/api/v1/projects/r-p/targets', json.dumps({'value': 'example.com; cat /etc/passwd'}), content_type='application/json',
                   REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=REAL, HTTP_SEC_FETCH_SITE='same-origin')
        self.assertEqual(r.status_code, 403)
        self.victim.refresh_from_db()
        self.assertTrue(self.victim.is_active)
        self.assertEqual(ApiToken.objects.filter(user=self.victim, revoked=False).count(), 2)
        self.assertTrue(AuditLog.objects.filter(action='abuse.session_ended', target='analyst').exists())
        self.assertTrue(AuditLog.objects.filter(action='abuse.ip_banned', target=REAL).exists())
        self.assertTrue(AbuseBan.objects.filter(ip=REAL, lifted=False).exists())
        guard.invalidate_cache()
        # the session is gone (sign in again), and the banned address is refused; another address is not
        self.assertEqual(c.get('/cve/', REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=OTHER).status_code, 302)
        self.assertEqual(Client().get('/login/', REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=REAL).status_code, 403)
        self.assertEqual(Client().get('/login/', REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=OTHER).status_code, 200)

    def test_an_unauthenticated_scanner_without_the_header_is_still_banned(self):
        r = Client().get('/cve/?x=..%2F..%2Fetc%2Fpasswd', REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=REAL)
        self.assertEqual(r.status_code, 403)
        self.assertTrue(AbuseBan.objects.filter(ip=REAL).exists())
        self.assertEqual(AbuseStrike.objects.get().weight, 3)

    def test_a_token_caller_at_the_threshold_keeps_its_token_and_the_admin_is_told(self):
        _, tok = create_token(self.victim, 'cli')
        r = Client().post('/api/v1/projects/r-p/targets', json.dumps({'value': 'a.com|id'}), content_type='application/json',
                          HTTP_AUTHORIZATION=f'Bearer {tok}', REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR='10.1.2.3')  # a private address: no ban
        self.assertEqual(r.status_code, 400)
        self.assertEqual(ApiToken.objects.filter(user=self.victim, revoked=False).count(), 3)
        self.victim.refresh_from_db()
        self.assertTrue(self.victim.is_active)
        self.assertTrue(AuditLog.objects.filter(action='abuse.user_flagged', target='analyst').exists())
        self.assertNotEqual(Client().get('/api/v1/projects', HTTP_AUTHORIZATION=f'Bearer {tok}', REMOTE_ADDR=PROXY,
                                         HTTP_X_FORWARDED_FOR='10.1.2.3').status_code, 401)

    def test_superusers_are_only_flagged(self):
        c = Client()
        c.force_login(self.root)
        c.post('/api/v1/projects/r-p/targets', json.dumps({'value': 'a.com|id'}), content_type='application/json',
               REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=REAL, HTTP_SEC_FETCH_SITE='same-origin')
        self.root.refresh_from_db()
        self.assertTrue(self.root.is_active)
        self.assertTrue(AuditLog.objects.filter(action='abuse.superuser_flagged').exists())
        self.assertFalse(AbuseBan.objects.exists())
        self.assertEqual(str(c.session.get('_auth_user_id')), str(self.root.pk))  # session kept

    def test_counted_is_decided_by_method_and_label(self):
        rf = RequestFactory()
        for method, site, counted in (('get', 'none', False), ('get', 'same-origin', False), ('head', 'none', False), ('get', '', True),
                                      ('get', 'cross-site', False), ('post', 'same-origin', True), ('post', '', True), ('post', 'none', True),
                                      ('post', 'same-site', False), ('delete', 'same-origin', True), ('get', ' None ', False)):
            request = getattr(rf, method)('/', HTTP_SEC_FETCH_SITE=site)
            self.assertEqual(guard._counted(request), counted, (method, site))


class ClientAddressMatrixTests(SimpleTestCase):
    """S2 and S3: which address the application takes, with the shipped default (the proxy's one address)."""

    def test_the_shipped_default_is_the_proxys_fixed_address(self):
        self.assertIn('CVENGINE_TRUSTED_PROXIES=${CVENGINE_TRUSTED_PROXIES:-${CVENGINE_PROXY_ADDRESS:-' + PROXY + '}}', COMPOSE_TEXT)

    def test_through_the_trusted_proxy_the_visitor_is_taken(self):
        self.assertEqual(through(PROXY, REAL), REAL)
        self.assertEqual(through(PROXY, f'10.0.0.99, {REAL}'), REAL)  # what a client wrote on the left is never picked
        self.assertEqual(through(PROXY, ''), PROXY)  # no chain: the proxy itself (nothing forged)
        self.assertEqual(through(PROXY, 'garbage'), PROXY)

    def test_the_production_chain_resolves_each_visitor(self):
        # Cloudflare, host nginx (X-Forwarded-For $remote_addr after real_ip), docker-proxy, the bundled proxy (443, the secret: chain kept), web
        self.assertEqual(through(PROXY, REAL), REAL)
        self.assertEqual(through(PROXY, OTHER), OTHER)
        # without the secret the proxy overwrites the chain with its peer, the gateway: every visitor is the gateway, as before (degrades safely)
        self.assertEqual(through(PROXY, GATEWAY), GATEWAY)

    def test_an_untrusted_peer_cannot_choose_its_address(self):
        for peer in (SCANNER, REVIEWER, GATEWAY, '172.16.238.200', '192.168.1.5', '8.8.8.8'):
            self.assertEqual(through(peer, REAL), peer)
            self.assertEqual(through(peer, f'{REAL}, {PROXY}'), peer)  # naming the proxy in the chain does not help

    def test_the_old_range_let_any_container_choose_and_the_new_default_does_not(self):
        self.assertEqual(through(SCANNER, REAL, env=OLD_RANGE), REAL)  # the review's S3
        self.assertEqual(through(SCANNER, REAL), SCANNER)

    def test_ipv6(self):
        v6 = {'CVENGINE_TRUSTED_PROXIES': 'fd00:cafe::10'}
        self.assertEqual(through('fd00:cafe::10', '2001:db8::5', env=v6), '2001:db8::5')
        self.assertEqual(through('fd00:cafe::10', f'2001:db8::6, {REAL}', env=v6), REAL)
        self.assertEqual(through('fd00:cafe::99', '2001:db8::5', env=v6), 'fd00:cafe::99')  # untrusted v6 peer
        self.assertEqual(through('2001:db8::7', REAL), '2001:db8::7')  # a v6 peer is never in an IPv4 trust list
        self.assertEqual(through(f'::ffff:{PROXY}', REAL), REAL)  # an IPv4-mapped peer is the IPv4 proxy
        self.assertEqual(through(PROXY, f'::ffff:{REAL}'), REAL)


class AddressConsequencesTests(TestCase):
    """The review's ProductionClientAddressCollapses and InternalPeerSpoofsClientAddress, inverted, with the shipped default."""

    def setUp(self):
        cache.clear()
        guard.invalidate_cache()
        self.addCleanup(guard.invalidate_cache)
        patch = mock.patch.dict(os.environ, SHIPPED)
        patch.start()
        self.addCleanup(patch.stop)

    def test_a_stranger_cannot_lock_the_owner_out_of_the_login_form(self):
        User.objects.create_user('owner', password='correct-horse-battery-1')
        stranger = Client()
        for _ in range(5):
            stranger.post('/login/', {'username': 'owner', 'password': 'wrong'}, REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=OTHER)
        owner = Client()
        r = owner.post('/login/', {'username': 'owner', 'password': 'correct-horse-battery-1'}, REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=REAL)
        self.assertNotEqual(r.status_code, 429)
        self.assertEqual(r.status_code, 302)

    def test_the_scanner_container_cannot_get_a_public_address_banned(self):
        r = Client().get('/cve/?x=..%2F..%2Fetc%2Fpasswd', REMOTE_ADDR=SCANNER, HTTP_X_FORWARDED_FOR=REAL)
        self.assertIn(r.status_code, (400, 403))
        self.assertFalse(AbuseBan.objects.filter(ip=REAL).exists())
        self.assertEqual(AbuseStrike.objects.get().ip, SCANNER)  # counted against the container that sent it, which is never banned
        guard.invalidate_cache()
        self.assertEqual(Client().get('/login/', REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=REAL).status_code, 200)

    def test_the_unsubscribe_limit_is_per_client(self):
        for _ in range(35):
            Client().get('/unsubscribe/test/', REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=OTHER)
        self.assertNotEqual(Client().get('/unsubscribe/test/', REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=REAL).status_code, 429)
        self.assertEqual(Client().get('/unsubscribe/test/', REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=OTHER).status_code, 429)


class ProbeRouteTests(TestCase):
    """The route scripts/client-address-check.sh uses: open, always 204, records only for a token the server issued, once."""

    def setUp(self):
        cache.clear()
        patch = mock.patch.dict(os.environ, SHIPPED)
        patch.start()
        self.addCleanup(patch.stop)

    def test_an_issued_token_records_the_address_the_server_took(self):
        token = client_probe.start()
        self.assertEqual(client_probe.read(token), '')
        r = Client().get(f'/client-address-probe/{token}/', REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=REAL)
        self.assertEqual(r.status_code, 204)
        self.assertEqual(client_probe.read(token), REAL)
        Client().get(f'/client-address-probe/{token}/', REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=OTHER)
        self.assertEqual(client_probe.read(token), REAL)  # the first answer stays

    def test_a_token_the_server_did_not_issue_records_nothing(self):
        token = 'a' * 32
        self.assertEqual(Client().get(f'/client-address-probe/{token}/', REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=REAL).status_code, 204)
        self.assertIsNone(client_probe.read(token))
        self.assertIsNone(cache.get(f'client_address_probe:{token}'))
        self.assertEqual(Client().get('/client-address-probe/not-a-token/').status_code, 204)

    def test_only_get(self):
        token = client_probe.start()
        self.assertEqual(Client().post(f'/client-address-probe/{token}/').status_code, 405)
        self.assertEqual(client_probe.read(token), '')

    def test_the_management_command(self):
        from io import StringIO
        out = StringIO()
        call_command('client_address_probe', 'start', stdout=out)
        token = out.getvalue().strip().removeprefix('probe: ')
        self.assertRegex(token, r'^[0-9a-f]{32}$')
        Client().get(f'/client-address-probe/{token}/', REMOTE_ADDR=PROXY, HTTP_X_FORWARDED_FOR=REAL)
        out = StringIO()
        call_command('client_address_probe', 'read', token, stdout=out)
        self.assertEqual(out.getvalue().strip(), f'probe: {REAL}')
        out = StringIO()
        call_command('client_address_probe', 'trusted', stdout=out)
        self.assertEqual(out.getvalue().strip(), f'probe: {PROXY}/32')
        with self.assertRaises(SystemExit):
            call_command('client_address_probe', 'read', 'b' * 32, stdout=StringIO())


def compose(name='docker-compose.yml'):
    return yaml.safe_load((ROOT / name).read_text())


@unittest.skipUnless(yaml and COMPOSE.is_file(), 'needs PyYAML and the compose files')
class ComposeLayoutTests(unittest.TestCase):
    """S3: the proxy has a fixed address on a network only it and web share, web trusts that address alone, and web publishes no port."""

    def test_web_publishes_no_port_and_the_opt_in_overlay_does_on_loopback_only(self):
        self.assertNotIn('ports', compose()['services']['web'])
        self.assertEqual(compose('docker-compose.webport.yml')['services']['web']['ports'], ['127.0.0.1:${CVENGINE_WEB_HOST_PORT:-8000}:8000'])
        self.assertIn('- "127.0.0.1:${CVENGINE_WEB_HOST_PORT:-8000}:8000"', (ROOT / 'docker-compose.hostnet.yml').read_text())  # (it uses !reset)

    def test_the_proxy_has_a_fixed_address_inside_the_subnet_and_outside_the_dynamic_range(self):
        import ipaddress
        doc = compose()
        net = doc['networks']['proxy_network']['ipam']['config'][0]
        subnet = ipaddress.ip_network(re.search(r':-([^}]+)\}', net['subnet']).group(1))
        dynamic = ipaddress.ip_network(re.search(r':-([^}]+)\}', net['ip_range']).group(1))
        address = ipaddress.ip_address(re.search(r':-([^}]+)\}', doc['services']['proxy']['networks']['proxy_network']['ipv4_address']).group(1))
        self.assertEqual(str(address), PROXY)
        self.assertIn(address, subnet)
        self.assertNotIn(address, dynamic)
        self.assertTrue(dynamic.subnet_of(subnet))
        # outside Docker's default address pools (172.17.0.0/16 to 172.31.0.0/16, 192.168.0.0/16), so Docker never hands it to another network
        for pool in ['192.168.0.0/16'] + [f'172.{n}.0.0/16' for n in range(17, 32)]:
            self.assertFalse(subnet.overlaps(ipaddress.ip_network(pool)), pool)

    def test_only_the_proxy_and_web_are_on_the_proxy_network_and_the_upstream_name_exists_only_there(self):
        services = compose()['services']
        on = sorted(name for name, svc in services.items() if 'proxy_network' in (svc.get('networks') or {}))
        self.assertEqual(on, ['proxy', 'web'])
        web = services['web']['networks']
        self.assertEqual(web['proxy_network']['aliases'], ['rengine'])  # the name config/nginx/rengine.conf proxies to
        self.assertFalse((web['rengine_network'] or {}).get('aliases'))  # so the proxy always reaches web from its fixed address
        conf = (ROOT / 'config' / 'nginx' / 'rengine.conf').read_text()
        self.assertEqual(set(re.findall(r'\$cvengine_web (http://[^;]+);', conf)), {'http://rengine:8000'})

    def test_web_and_celery_trust_the_proxy_alone_by_default(self):
        for svc in ('web', 'celery'):
            env = compose()['services'][svc]['environment']
            line = next(e for e in env if e.startswith('CVENGINE_TRUSTED_PROXIES='))
            self.assertEqual(line, 'CVENGINE_TRUSTED_PROXIES=${CVENGINE_TRUSTED_PROXIES:-${CVENGINE_PROXY_ADDRESS:-' + PROXY + '}}')

    def test_the_scanner_and_the_reviewer_still_reach_web_on_a_shared_network(self):
        services = compose()['services']
        web_nets = set(services['web']['networks'])
        self.assertIn('scanner_network', set(services['scanner']['networks']) & web_nets)
        self.assertIn('rengine_network', set(services['reviewer']['networks']) & web_nets)
        self.assertEqual(services['reviewer']['environment']['CVENGINE_REVIEWER_SERVER'], 'http://web:8000')
        self.assertIn('web', services['scanner']['environment']['NO_PROXY'])

    def test_the_proxy_gets_its_secret_and_the_template(self):
        proxy = compose()['services']['proxy']
        self.assertEqual(proxy['environment']['CVENGINE_UPSTREAM_SECRET'], '${CVENGINE_UPSTREAM_SECRET:-}')
        self.assertIn('./config/nginx/templates:/etc/nginx/templates:ro', proxy['volumes'])
        self.assertTrue((ROOT / 'config' / 'nginx' / 'templates' / 'cvengine-upstream-secret.inc.template').is_file())
        self.assertTrue((ROOT / 'config' / 'nginx' / 'templates' / 'cvengine-upstream-exact.inc.template').is_file())  # the case-sensitive match
        self.assertNotIn('POSTGRES_PASSWORD', json.dumps(proxy))

    def test_the_host_snippet_overwrites_the_chain_and_sends_the_secret(self):
        snippet = (ROOT / 'config' / 'nginx' / 'host-proxy-client-address.conf').read_text()
        code = [line.strip() for line in snippet.splitlines() if line.strip() and not line.lstrip().startswith('#')]
        self.assertEqual(code, ['proxy_set_header X-Forwarded-For $remote_addr;', 'proxy_set_header X-CVEngine-Upstream "@CVENGINE_UPSTREAM_SECRET@";'])


FAKE_DOCKER = r'''#!/usr/bin/env python3
import json, sys
state = json.load(open(%(state)r))
args = sys.argv[1:]
log = open(%(log)r, 'a'); log.write(' '.join(args) + '\n'); log.close()
joined = ' '.join(args)
if 'exec' in args and 'proxy' in args:
    print(state.get('rendered', '1')); sys.exit(0)
if 'client_address_probe start' in joined:
    print('banner line'); print('probe: ' + 'c' * 32); sys.exit(0)
if 'client_address_probe read' in joined:
    if state.get('recorded'): print('probe: ' + state['recorded']); sys.exit(0)
    sys.exit(1)
if 'client_address_probe trusted' in joined:
    print('probe: ' + state.get('trusted', '172.16.238.10/32')); sys.exit(0)
sys.exit(0)
'''


class Trace(BaseHTTPRequestHandler):
    ip = ''

    def do_GET(self):  # noqa: N802
        body = f'fl=1\nip={type(self).ip}\nts=1\n'.encode() if self.path == '/cdn-cgi/trace' and type(self).ip else b''
        self.send_response(200 if body else 204)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@unittest.skipUnless(shutil.which('bash') and shutil.which('python3'), 'needs bash and python3')
class CheckScriptTests(unittest.TestCase):
    """scripts/client-address.sh: the secret it generates, the snippet it prints, and the report the update logs (with a fake docker)."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)
        (self.dir / 'scripts').mkdir()
        (self.dir / 'config' / 'nginx').mkdir(parents=True)
        shutil.copy(ROOT / 'scripts' / 'client-address.sh', self.dir / 'scripts')
        shutil.copy(ROOT / 'config' / 'nginx' / 'host-proxy-client-address.conf', self.dir / 'config' / 'nginx')
        (self.dir / '.env').write_text('DOMAIN_NAME=scanner.example.com\n')
        (self.dir / '.env').chmod(0o600)
        self.bin = self.dir / 'bin'
        self.bin.mkdir()
        self.state = self.dir / 'state.json'
        self.log = self.dir / 'docker.log'
        self.set_state()
        (self.bin / 'docker').write_text(FAKE_DOCKER % {'state': str(self.state), 'log': str(self.log)})
        (self.bin / 'docker').chmod(0o755)

    def set_state(self, **state):
        self.state.write_text(json.dumps(state))

    def bash(self, code, **env):
        return subprocess.run(['bash', '-c', f'. scripts/client-address.sh; {code}'], cwd=self.dir, capture_output=True, text=True, timeout=120,
                              env={'PATH': f'{self.bin}:{os.environ["PATH"]}', 'HOME': str(self.dir), **env})

    def value(self, key, name='.env'):
        found = re.findall(rf'(?m)^{key}=(.*)$', (self.dir / name).read_text())
        return found[-1] if found else None

    def test_a_secret_is_generated_once_and_kept(self):
        self.assertEqual(self.bash('cvengine_ensure_upstream_secret').returncode, 0)
        first = self.value('CVENGINE_UPSTREAM_SECRET')
        self.assertRegex(first, r'^[A-Za-z0-9]{48}$')
        self.assertEqual(self.bash('cvengine_ensure_upstream_secret').returncode, 1)
        self.assertEqual(self.value('CVENGINE_UPSTREAM_SECRET'), first)
        self.assertEqual(oct((self.dir / '.env').stat().st_mode & 0o777), '0o600')
        self.assertNotIn(first, self.bash('cvengine_ensure_upstream_secret').stdout + self.bash('cvengine_ensure_upstream_secret').stderr)

    def test_the_compose_env_file_gets_the_same_secret(self):
        (self.dir / '.env.vps').write_text('X=1')
        self.assertEqual(self.bash('cvengine_ensure_upstream_secret .env.vps').returncode, 0)
        self.assertEqual(self.value('CVENGINE_UPSTREAM_SECRET', '.env.vps'), self.value('CVENGINE_UPSTREAM_SECRET'))

    def test_the_snippet_carries_this_installs_secret(self):
        self.bash('cvengine_ensure_upstream_secret')
        out = self.bash('cvengine_client_address_snippet docker compose')
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn(f'proxy_set_header X-CVEngine-Upstream "{self.value("CVENGINE_UPSTREAM_SECRET")}";', out.stdout)
        self.assertNotIn('@CVENGINE_UPSTREAM_SECRET@', out.stdout)

    def test_no_snippet_without_a_valid_secret(self):
        with open(self.dir / '.env', 'a') as f:
            f.write('CVENGINE_UPSTREAM_SECRET=short\n')
        out = self.bash('cvengine_client_address_snippet docker compose')
        self.assertNotEqual(out.returncode, 0)
        self.assertEqual(out.stdout, '')

    def serve(self, ip):
        Trace.ip = ip
        server = HTTPServer(('127.0.0.1', 0), Trace)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        return f'http://127.0.0.1:{server.server_port}'

    def report(self, url):
        self.bash('cvengine_ensure_upstream_secret')
        out = self.bash('cvengine_client_address_report docker compose', CVENGINE_CLIENT_ADDRESS_URL=url)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertTrue(all(line.startswith('client address: ') for line in out.stdout.splitlines()), out.stdout)
        self.assertNotIn(self.value('CVENGINE_UPSTREAM_SECRET'), out.stdout + out.stderr + self.log.read_text())  # the secret is never printed
        return out.stdout

    def test_the_report_says_ok_when_the_server_took_the_address_cloudflare_saw(self):
        self.set_state(recorded=REAL)
        self.assertIn(f'ok: a request through', self.report(self.serve(REAL)))

    def test_the_report_names_the_problem_when_every_visitor_is_the_proxy(self):
        self.set_state(recorded=GATEWAY)
        out = self.report(self.serve(REAL))
        self.assertIn('PROBLEM', out)
        self.assertIn('--snippet', out)

    def test_the_report_without_cloudflare_and_without_an_answer(self):
        self.set_state(recorded=GATEWAY)
        self.assertIn('an internal address', self.report(self.serve('')))
        self.set_state()
        self.assertIn('did not reach the server', self.report(self.serve('')))

    def test_the_report_warns_about_a_trusted_range_and_an_unloaded_secret(self):
        self.set_state(recorded=REAL, trusted='172.16.0.0/12', rendered='0')
        out = self.report(self.serve(REAL))
        self.assertIn('warning: CVENGINE_TRUSTED_PROXIES is 172.16.0.0/12', out)
        self.assertIn('no upstream secret loaded', out)


def docker_ok():
    if not shutil.which('docker'):
        return False
    try:
        return subprocess.run(['docker', 'image', 'inspect', 'nginx:alpine'], capture_output=True, timeout=60).returncode == 0 or \
            subprocess.run(['docker', 'pull', 'nginx:alpine'], capture_output=True, timeout=300).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


class SecretShapeCheckTests(SimpleTestCase):
    """The update's report checks the secret in .env on the host and the rendered one in the proxy (nginx:alpine, whose grep is musl's). musl
    refuses a regex bound above 255, so `{32,256}` made both checks read a good secret as broken on every install: the update log said the secret
    was malformed and that the running proxy had none loaded."""

    SCRIPT = ROOT / 'scripts' / 'client-address.sh'

    def test_no_regex_in_the_script_has_a_bound_musl_refuses(self):
        bounds = [int(m) for m in re.findall(r'\{\d+,(\d+)\}', self.SCRIPT.read_text())]
        self.assertFalse([b for b in bounds if b > 255], bounds)

    @unittest.skipUnless(shutil.which('bash'), 'needs bash')
    def test_the_shape_check_takes_32_to_256_letters_digits_dash_and_underscore(self):
        cases = {'a' * 31: 1, 'a' * 32: 0, 'Zq8-_' * 10: 0, 'a' * 256: 0, 'a' * 257: 1, 'a' * 40 + '!': 1, '': 1}
        for secret, want in cases.items():
            out = subprocess.run(['bash', '-c', f'. "{self.SCRIPT}"; cvengine_ca_secret_ok "$1"', 'check', secret], capture_output=True, text=True)
            self.assertEqual(out.returncode, want, (len(secret), out.stderr))


class ProxyContainerTests(SimpleTestCase):
    """The bundled proxy as compose runs it: nginx:alpine with the shipped conf, the template rendered by the image's own entrypoint from
    CVENGINE_UPSTREAM_SECRET, a fixed address on a fixed-subnet network, and a fake web container named "rengine" that echoes what it receives. The
    test client connects through the published port, as a host nginx does through docker-proxy, so the proxy sees the gateway."""

    def setUp(self):
        if not docker_ok():
            if os.environ.get('CI'):
                self.fail('CI is set but the nginx:alpine image cannot be used: the proxy test must run in CI')
            self.skipTest('needs docker and nginx:alpine')
        self.tag = f'cvca{os.getpid()}{int(time.time()) % 100000}'
        self.tmp = tempfile.mkdtemp()
        os.chmod(self.tmp, 0o755)
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.names = []
        self.addCleanup(lambda: [subprocess.run(['docker', 'rm', '-f', n], capture_output=True) for n in self.names])
        for third in range(240, 256):  # a free /24 in 172.16.0.0/16, like the shipped default
            self.subnet = f'172.16.{third}'
            made = subprocess.run(['docker', 'network', 'create', '--subnet', f'{self.subnet}.0/24', '--ip-range', f'{self.subnet}.128/25',
                                   f'{self.tag}-net'], capture_output=True, text=True)
            if made.returncode == 0:
                break
        else:
            self.skipTest('no free 172.16.x.0/24 for the test network')
        self.addCleanup(lambda: subprocess.run(['docker', 'network', 'rm', f'{self.tag}-net'], capture_output=True))

    def start(self, secret):
        certs = f'{self.tmp}/certs'
        os.makedirs(certs, exist_ok=True)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', f'{certs}/rengine_rsa.key', '-out', f'{certs}/rengine.pem',
                        '-subj', '/CN=rengine', '-days', '2'], check=True, capture_output=True)
        shutil.copy(f'{certs}/rengine.pem', f'{certs}/rengine_chain.pem')
        for name in os.listdir(certs):
            os.chmod(f'{certs}/{name}', 0o644)
        state = f'{self.tmp}/state'
        os.makedirs(state, exist_ok=True)
        os.chmod(state, 0o755)
        echo = f'{self.tmp}/echo.conf'
        with open(echo, 'w') as f:
            f.write('server { listen 8000; location / { default_type text/plain; '
                    'return 200 "remote=$remote_addr\\nxff=$http_x_forwarded_for\\nupstream=$http_x_cvengine_upstream\\n"; } }\n')
        os.chmod(echo, 0o644)
        web = f'{self.tag}-web'
        self.names.append(web)
        subprocess.run(['docker', 'run', '-d', '--name', web, '--network', f'{self.tag}-net', '--network-alias', 'rengine', '-v',
                        f'{echo}:/etc/nginx/conf.d/default.conf:ro', 'nginx:alpine'], check=True, capture_output=True)
        proxy = f'{self.tag}-proxy'
        self.names.append(proxy)
        nginx = ROOT / 'config' / 'nginx'
        subprocess.run(['docker', 'run', '-d', '--name', proxy, '--network', f'{self.tag}-net', '--ip', f'{self.subnet}.10', '-p', '127.0.0.1::443',
                        '-e', f'CVENGINE_UPSTREAM_SECRET={secret}',
                        '-v', f'{nginx}/rengine.conf:/etc/nginx/conf.d/rengine.conf:ro', '-v', f'{nginx}/templates:/etc/nginx/templates:ro',
                        '-v', f'{nginx}/trusted-upstreams.conf:/etc/nginx/trusted-upstreams.conf:ro', '-v', f'{certs}:/etc/nginx/certs:ro',
                        '-v', f'{state}:/etc/nginx/state:ro',
                        '-v', f'{ROOT / "web" / "static" / "cve" / "maintenance.html"}:/usr/share/nginx/maintenance/maintenance.html:ro',
                        'nginx:alpine'], check=True, capture_output=True)
        port = int(subprocess.run(['docker', 'port', proxy, '443/tcp'], capture_output=True, text=True, check=True).stdout.split(':')[-1])
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.fetch(port).get('remote'):
                return port
            time.sleep(0.5)
        logs = subprocess.run(['docker', 'logs', proxy], capture_output=True, text=True)
        self.fail(f'the proxy never answered: {logs.stderr[-2000:]}')

    def fetch(self, port, xff=None, secret=None, path='/'):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        headers = {'Host': 'rengine'}
        if xff:
            headers['X-Forwarded-For'] = xff
        if secret is not None:
            headers['X-CVEngine-Upstream'] = secret
        try:
            with urllib.request.urlopen(urllib.request.Request(f'https://127.0.0.1:{port}{path}', headers=headers), timeout=5, context=ctx) as reply:
                text = reply.read().decode()
        except Exception:  # noqa: BLE001
            return {}
        return dict(line.split('=', 1) for line in text.splitlines() if '=' in line)

    SECRET = 'Zq8rT2vW9xY3bN5mK7pL4sD6fG1hJ0aEcUuu'

    def test_the_production_chain_through_the_real_proxy(self):
        port = self.start(self.SECRET)
        vouched = self.fetch(port, REAL, self.SECRET)
        self.assertEqual(vouched['remote'], f'{self.subnet}.10')  # web is always reached from the proxy's fixed address
        self.assertEqual(vouched['xff'], REAL)
        self.assertEqual(vouched['upstream'], '')  # the secret stops at the proxy
        stranger = self.fetch(port, REAL, 'wrong' * 8)
        self.assertNotEqual(stranger['xff'], REAL)  # overwritten with the peer (the gateway)
        self.assertTrue(stranger['xff'].startswith('172.'), stranger)
        self.assertNotEqual(self.fetch(port, REAL)['xff'], REAL)
        self.assertNotEqual(self.fetch(port, REAL, self.SECRET.swapcase())['xff'], REAL)  # the secret is compared with its case
        # what web then takes, with the trusted set compose gives it for this network
        env = {'CVENGINE_TRUSTED_PROXIES': f'{self.subnet}.10'}
        self.assertEqual(through(vouched['remote'], vouched['xff'], env=env), REAL)
        self.assertEqual(through(stranger['remote'], stranger['xff'], env=env), stranger['xff'])
        # and the probe route passes the maintenance page
        with open(f'{self.tmp}/state/maintenance', 'w'):
            pass
        os.chmod(f'{self.tmp}/state/maintenance', 0o644)
        self.assertEqual(self.fetch(port, REAL, self.SECRET, path='/client-address-probe/x/')['xff'], REAL)
        self.assertEqual(self.fetch(port, REAL, self.SECRET), {})  # every other route shows the maintenance page (503)

    def test_with_an_empty_secret_nothing_is_believed(self):
        port = self.start('')
        for sent in (None, '', 'k', self.SECRET):
            self.assertNotEqual(self.fetch(port, REAL, sent)['xff'], REAL, sent)
