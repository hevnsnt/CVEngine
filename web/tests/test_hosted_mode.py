"""Hosted mode (hosted/README.md): everything is OFF unless the environment turns it on, and a normal installation behaves exactly as before.

Layers, each tested on its own:

* the bundled proxy (config/nginx/rengine.conf under a real nginx, as test_tunnel_client_address does): with the stock empty edge-auth file nothing is
  refused and no header is believed; with a generated file a request needs a listed secret (current or previous) or gets 403, and the client address is
  taken from X-CVL-Client-IP only when the secret passed, so a spoofed header without it is ignored;
* reNgine.client_ip never reads the edge headers itself;
* ensure_fleet_token: least privilege, rotation, revoke, disable and enable, and a refusal when hosted mode is off;
* CVENGINE_PUBLIC_API_URL in Sentinel enrollment URLs, falling back to DOMAIN_NAME;
* the hosted/ scripts under stubs (no Docker, no network, no root): shellcheck clean, and each one's contract (stdout, exit status, files, no secrets in
  arguments or logs);
* docker-compose.hosted.yml: nothing but 443 published, bind volumes, restart policies; and the base Compose file only mounts the stock empty file."""
import http.client
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import StringIO
from pathlib import Path
from unittest import mock

from django.contrib.auth.models import User
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import RequestFactory, SimpleTestCase, TestCase
from django.utils import timezone

from reNgine.client_ip import client_ip
from tests.test_agentapi import call
from tests.test_tunnel_client_address import CONF, nginx_runner

ROOT = Path(__file__).resolve().parents[2]
HOSTED = ROOT / 'hosted'
CURRENT = 'C' * 20 + 'urrent_secret-0123456789'
PREVIOUS = 'P' * 20 + 'revious_secret-0123456789'
OTHER = 'O' * 20 + 'ther_secret-0123456789ab'
ALICE, FORGED = '198.51.100.20', '203.0.113.99'


def bash_env(**extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith(('CVL_', 'CVENGINE_'))}
    env.update(extra)
    return env


# ----------------------------------------------------------------------------------------------------------------------------------------------
# the bundled proxy
# ----------------------------------------------------------------------------------------------------------------------------------------------

class Recorder(BaseHTTPRequestHandler):
    seen = []

    def do_POST(self):  # noqa: N802
        self.do_GET()

    def do_GET(self):  # noqa: N802
        type(self).seen.append({'path': self.path, '_raw': [(k.lower(), v) for k, v in self.headers.items()], **{k.lower(): v for k, v in self.headers.items()}})
        self.send_response(200)
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'ok')

    def log_message(self, *args):
        pass


def free_port():
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def generate_edge_file(current=CURRENT, previous=None):
    """The file hosted/gen-edge-auth.sh writes for these secrets (the real generator, not a copy of its output)."""
    etc = tempfile.mkdtemp()
    os.chmod(etc, 0o700)
    Path(etc, 'edge-secret').write_text(current + '\n')
    if previous:
        Path(etc, 'edge-secret.previous').write_text(previous + '\n')
    subprocess.run(['bash', str(HOSTED / 'gen-edge-auth.sh')], env=bash_env(CVL_ETC=etc), check=True, capture_output=True)
    text = Path(etc, 'edge-auth.conf').read_text()
    shutil.rmtree(etc, True)
    return text


class ProxyBase(SimpleTestCase):
    """rengine.conf's top level and its location blocks (plus the server-level refusal) in front of a recording upstream. The test client connects from
    127.0.0.1; ``plain`` stands for 443 and ``tunnel`` for 8443 (given a free number)."""

    def setUp(self):
        self.runner = nginx_runner()
        if self.runner is None:
            if os.environ.get('CI'):
                self.fail('CI is set but nginx cannot be run: the proxy test must run in CI, not be skipped')
            self.skipTest('needs an nginx binary or docker')

    def run_proxy(self, edge_text=None, trusted_file=None, locations=('    location / {',), access_log=None):
        tmp = tempfile.mkdtemp()
        os.chmod(tmp, 0o755)
        self.addCleanup(shutil.rmtree, tmp, True)
        stock = (ROOT / 'config' / 'nginx' / 'edge-auth.conf.example').read_text()
        for name, text in (('edge-auth.conf', stock if edge_text is None else edge_text),
                           ('trusted-upstreams.conf', (ROOT / 'config' / 'nginx' / 'trusted-upstreams.conf').read_text() if trusted_file is None else trusted_file)):
            Path(tmp, name).write_text(text)
            os.chmod(f'{tmp}/{name}', 0o644)
        upstream = HTTPServer(('127.0.0.1', 0), Recorder)
        Recorder.seen = []
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        self.addCleanup(upstream.shutdown)
        plain, tunnel = free_port(), free_port()
        etc = tmp if self.runner == 'local' else '/t'
        head = CONF[:CONF.index('\nserver {')]
        head = head.replace('/etc/nginx/trusted-upstreams.conf', f'{etc}/trusted-upstreams.conf').replace('/etc/nginx/edge-auth.conf', f'{etc}/edge-auth.conf')
        head = head.replace('"~^8443:1:.+"', f'"~^{tunnel}:1:.+"')
        refusal = '    if ($cvl_edge_deny) { return 403; }\n'
        self.assertIn(refusal, CONF[CONF.index('\nserver {', CONF.index('listen                                          443 ssl') - 200):])
        location = ''
        for marker in locations:  # the location blocks to run (the default is the catch-all)
            block = CONF[CONF.index(marker):]
            location += block[:block.index('\n    }') + 6].replace('http://rengine:8000', f'http://127.0.0.1:{upstream.server_port}') + '\n'
        location = location.replace('/etc/nginx/state/', f'{etc}/state/')
        scratch = f'{tmp}/scratch' if self.runner == 'local' else '/tmp'
        os.makedirs(scratch, exist_ok=True)
        self.scratch = scratch
        text = (f'daemon off; pid {scratch}/nginx.pid; error_log stderr;\nevents {{}}\nhttp {{\n'
                f'client_body_temp_path {scratch}/b; proxy_temp_path {scratch}/p; fastcgi_temp_path {scratch}/f; uwsgi_temp_path {scratch}/u; scgi_temp_path {scratch}/s;\n'
                f'{"access_log off;" if access_log is None else access_log.replace("@TMP@", scratch)}\n{head}\nserver {{ listen 127.0.0.1:{plain}; listen 127.0.0.1:{tunnel};\n{refusal}{location}\n}}\n}}\n')
        Path(tmp, 'nginx.conf').write_text(text)
        os.chmod(f'{tmp}/nginx.conf', 0o644)
        if self.runner == 'local':
            check = subprocess.run(['nginx', '-t', '-c', f'{tmp}/nginx.conf'], capture_output=True, text=True)
            self.assertEqual(check.returncode, 0, check.stderr)
            proc = subprocess.Popen(['nginx', '-c', f'{tmp}/nginx.conf'], stderr=subprocess.DEVNULL)
            self.addCleanup(proc.wait)
            self.addCleanup(proc.terminate)
        else:
            run = ['docker', 'run', '--rm', '--network', 'host', '-v', f'{tmp}:/t:ro', 'nginx:alpine', 'nginx', '-c', '/t/nginx.conf']
            check = subprocess.run(run[:-3] + ['nginx', '-t', '-c', '/t/nginx.conf'], capture_output=True, text=True)
            self.assertEqual(check.returncode, 0, check.stderr)
            name = f'cvengine-hostedtest-{os.getpid()}-{plain}'
            subprocess.run(['docker', 'run', '-d', '--rm', '--name', name] + run[3:], check=True, capture_output=True)
            self.addCleanup(lambda: subprocess.run(['docker', 'rm', '-f', name], capture_output=True))
        for _ in range(100):
            try:
                self.fetch(plain, '/', {})
                self.fetch(tunnel, '/', {})
                break
            except OSError:
                time.sleep(0.1)
        Recorder.seen = []
        return plain, tunnel

    def fetch(self, port, path='/', headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        conn.request('GET', path, headers=headers or {})
        status = conn.getresponse().status
        conn.close()
        return status

    def upstream_saw(self, port, path='/', headers=None):
        """(status, headers the upstream received or None when the request never reached it)"""
        Recorder.seen = []
        status = self.fetch(port, path, headers)
        return status, (Recorder.seen[-1] if Recorder.seen else None)


class StockProxyTests(ProxyBase):
    """The stock (empty) edge-auth file: hosted mode is off and the proxy is what it always was."""

    def test_the_stock_file_has_no_entries(self):
        stock = (ROOT / 'config' / 'nginx' / 'edge-auth.conf.example').read_text()
        self.assertEqual([line for line in stock.splitlines() if line.strip() and not line.lstrip().startswith('#')], [])

    def test_nothing_is_refused_whatever_the_request_carries(self):
        plain, tunnel = self.run_proxy()
        for port in (plain, tunnel):
            self.assertEqual(self.upstream_saw(port)[0], 200)
            self.assertEqual(self.upstream_saw(port, '/anything/at/all', {'X-CVL-Edge-Auth': CURRENT})[0], 200)
            self.assertEqual(self.upstream_saw(port, '/x', {'X-CVL-Edge-Auth': ''})[0], 200)

    def test_the_edge_client_address_is_not_believed_even_with_a_secret_shaped_header(self):
        plain, tunnel = self.run_proxy()
        for port in (plain, tunnel):
            status, seen = self.upstream_saw(port, '/', {'X-CVL-Edge-Auth': CURRENT, 'X-CVL-Client-IP': FORGED, 'X-Forwarded-For': FORGED})
            self.assertEqual((status, seen['x-forwarded-for']), (200, '127.0.0.1'))

    def test_the_application_never_receives_the_edge_headers(self):
        plain, _ = self.run_proxy()
        _, seen = self.upstream_saw(plain, '/', {'X-CVL-Edge-Auth': CURRENT, 'X-CVL-Client-IP': FORGED})
        self.assertNotIn('x-cvl-edge-auth', seen)
        self.assertNotIn('x-cvl-client-ip', seen)

    def test_the_tunnel_rule_is_unchanged(self):
        plain, tunnel = self.run_proxy(trusted_file='127.0.0.1 1;\n')
        self.assertEqual(self.upstream_saw(tunnel, '/', {'X-Forwarded-For': ALICE})[1]['x-forwarded-for'], f'{ALICE}, 127.0.0.1')
        self.assertEqual(self.upstream_saw(plain, '/', {'X-Forwarded-For': ALICE})[1]['x-forwarded-for'], '127.0.0.1')


class HostedProxyTests(ProxyBase):
    """A generated edge-auth file (hosted/gen-edge-auth.sh): current and previous secret accepted, everything else refused, the edge's client address
    believed only behind a valid secret."""

    def hosted(self, previous=None, **kwargs):
        return self.run_proxy(generate_edge_file(CURRENT, previous), **kwargs)

    def test_a_request_without_the_secret_is_refused_and_never_reaches_the_application(self):
        plain, tunnel = self.hosted()
        for port in (plain, tunnel):
            for path in ('/', '/cve/', '/api/v1/sentinel/heartbeat', '/staticfiles/x.css', '/health/x'):
                status, seen = self.upstream_saw(port, path if path != '/' else '/nothing')
                self.assertEqual((status, seen), (403, None), path)

    def test_a_wrong_secret_a_prefix_or_a_suffix_is_refused(self):
        plain, _ = self.hosted()
        for value in (OTHER, CURRENT[:-1], CURRENT + 'x', CURRENT[1:], '', PREVIOUS):
            self.assertEqual(self.upstream_saw(plain, '/x', {'X-CVL-Edge-Auth': value}), (403, None), repr(value))

    def test_the_current_secret_passes_and_is_not_forwarded(self):
        plain, _ = self.hosted()
        status, seen = self.upstream_saw(plain, '/x', {'X-CVL-Edge-Auth': CURRENT})
        self.assertEqual(status, 200)
        self.assertNotIn('x-cvl-edge-auth', seen)

    def test_during_a_rotation_the_previous_secret_also_passes_and_after_it_does_not(self):
        plain, _ = self.hosted(previous=PREVIOUS)
        self.assertEqual(self.upstream_saw(plain, '/x', {'X-CVL-Edge-Auth': PREVIOUS})[0], 200)
        self.assertEqual(self.upstream_saw(plain, '/x', {'X-CVL-Edge-Auth': CURRENT})[0], 200)
        self.assertEqual(self.upstream_saw(plain, '/x', {'X-CVL-Edge-Auth': OTHER})[0], 403)
        plain2, _ = self.hosted()  # the previous secret dropped
        self.assertEqual(self.upstream_saw(plain2, '/x', {'X-CVL-Edge-Auth': PREVIOUS})[0], 403)

    def test_the_client_address_comes_from_the_edge_header_when_the_secret_passes(self):
        plain, tunnel = self.hosted()
        for port in (plain, tunnel):  # port 443 believes it on this ground alone, without any trusted-upstreams entry
            status, seen = self.upstream_saw(port, '/x', {'X-CVL-Edge-Auth': CURRENT, 'X-CVL-Client-IP': ALICE})
            self.assertEqual((status, seen['x-forwarded-for']), (200, f'{ALICE}, 127.0.0.1'))
        _, seen = self.upstream_saw(plain, '/x', {'X-CVL-Edge-Auth': CURRENT, 'X-CVL-Client-IP': '2001:db8::1'})
        self.assertEqual(seen['x-forwarded-for'], '2001:db8::1, 127.0.0.1')

    def test_a_forged_forwarded_for_behind_a_valid_secret_is_replaced(self):
        plain, _ = self.hosted()
        _, seen = self.upstream_saw(plain, '/x', {'X-CVL-Edge-Auth': CURRENT, 'X-CVL-Client-IP': ALICE, 'X-Forwarded-For': f'{FORGED}, {FORGED}'})
        self.assertEqual(seen['x-forwarded-for'], f'{ALICE}, 127.0.0.1')
        _, seen = self.upstream_saw(plain, '/x', {'X-CVL-Edge-Auth': CURRENT, 'X-Forwarded-For': FORGED})  # no edge address: the peer alone
        self.assertEqual(seen['x-forwarded-for'], '127.0.0.1')

    def test_a_spoofed_client_address_without_the_secret_is_ignored(self):
        """The proof: the header is sent with no secret, a wrong secret and an empty one. Where the request is allowed at all (the loopback probe of
        "/"), the application is handed the real peer, never the address the header names."""
        plain, tunnel = self.hosted()
        for port in (plain, tunnel):
            for secret in ({}, {'X-CVL-Edge-Auth': OTHER}, {'X-CVL-Edge-Auth': ''}):
                self.assertEqual(self.upstream_saw(port, '/x', {'X-CVL-Client-IP': FORGED, **secret}), (403, None))
                status, seen = self.upstream_saw(port, '/', {'X-CVL-Client-IP': FORGED, 'X-Forwarded-For': FORGED, **secret})
                self.assertEqual((status, seen['x-forwarded-for']), (200, '127.0.0.1'))

    def test_a_malformed_client_address_is_ignored_even_behind_a_valid_secret(self):
        plain, _ = self.hosted()
        for value in ('not-an-address!', f'{ALICE}, {FORGED}', f'{ALICE};x', '<script>', 'a' * 60, '1', ''):
            _, seen = self.upstream_saw(plain, '/x', {'X-CVL-Edge-Auth': CURRENT, 'X-CVL-Client-IP': value})
            self.assertEqual(seen['x-forwarded-for'], '127.0.0.1', repr(value))

    def test_this_machines_loopback_may_probe_only_the_root_and_health(self):
        plain, _ = self.hosted()
        self.assertEqual(self.upstream_saw(plain, '/')[0], 200)
        self.assertEqual(self.upstream_saw(plain, '/health')[0], 200)
        for path in ('/health/', '/cve/', '/health/../cve/', '/admin', '/api/v1/sentinel/heartbeat'):
            self.assertEqual(self.upstream_saw(plain, path), (403, None), path)

    def test_end_to_end_the_application_picks_the_address_the_edge_sent(self):
        plain, _ = self.hosted()
        _, seen = self.upstream_saw(plain, '/x', {'X-CVL-Edge-Auth': CURRENT, 'X-CVL-Client-IP': ALICE})
        chain = seen['x-forwarded-for'].replace('127.0.0.1', '172.18.0.7')  # the proxy as the web container sees it: a Docker address
        request = RequestFactory().get('/', REMOTE_ADDR='172.18.0.7', HTTP_X_FORWARDED_FOR=chain)
        with mock.patch.dict(os.environ, {'CVENGINE_TRUSTED_PROXIES': '172.16.0.0/12'}):
            self.assertEqual(client_ip(request), ALICE)


class ClientIpIgnoresEdgeHeadersTests(SimpleTestCase):
    """The application itself never reads the edge headers: only the proxy's X-Forwarded-For counts, so a header that got past the proxy changes nothing."""

    def test_the_edge_headers_are_never_read(self):
        request = RequestFactory().get('/', REMOTE_ADDR='172.18.0.7', HTTP_X_FORWARDED_FOR=f'{ALICE}, 172.18.0.7',
                                       HTTP_X_CVL_CLIENT_IP=FORGED, HTTP_X_CVL_EDGE_AUTH=CURRENT)
        with mock.patch.dict(os.environ, {'CVENGINE_TRUSTED_PROXIES': '172.16.0.0/12'}):
            self.assertEqual(client_ip(request), ALICE)
        direct = RequestFactory().get('/', REMOTE_ADDR='192.0.2.9', HTTP_X_CVL_CLIENT_IP=FORGED)
        with mock.patch.dict(os.environ, {'CVENGINE_TRUSTED_PROXIES': '172.16.0.0/12'}):
            self.assertEqual(client_ip(direct), '192.0.2.9')
        self.assertNotIn('X_CVL', Path(ROOT / 'web' / 'reNgine' / 'client_ip.py').read_text())


class DefaultOffConfigTests(SimpleTestCase):
    def test_the_proxy_conf_refuses_nothing_until_a_file_has_entries(self):
        self.assertIn('include                         /etc/nginx/edge-auth.conf;', CONF)
        # no "default" of its own in the map the file is included in: with an empty file the variable is empty, and only "0" refuses
        block = CONF[CONF.index('map $http_x_cvl_edge_auth $cvl_edge_ok {'):]
        block = block[:block.index('}')]
        self.assertNotIn('default', block)
        self.assertIn('if ($cvl_edge_deny) { return 403; }', CONF)
        self.assertEqual(len(re.findall(r'X-Forwarded-For \$cvengine_forwarded_for;', CONF)), 3)

    def test_the_base_compose_file_mounts_only_the_stock_empty_file(self):
        compose = (ROOT / 'docker-compose.yml').read_text()
        self.assertIn('./config/nginx/edge-auth.conf.example:/etc/nginx/edge-auth.conf:ro', compose)
        code = '\n'.join(re.sub(r'\s#.*$', '', line) for line in compose.splitlines() if not line.lstrip().startswith('#'))  # a comment may name the overlay
        for word in ('/etc/cvl', 'docker-compose.hosted', 'CVENGINE_HOSTED', 'CVL_'):
            self.assertNotIn(word, code)

    def test_no_normal_path_names_the_hosted_overlay_or_turns_hosted_on(self):
        for name in ('install.sh', 'Makefile', '.env.example', 'scripts/init-env.sh', 'scripts/update.sh', 'scripts/watchdog.sh', 'scripts/apply-update.sh'):
            text = (ROOT / name).read_text()
            self.assertNotIn('docker-compose.hosted.yml', text, name)
            self.assertNotRegex(text, r'CVENGINE_HOSTED=1', name)

    def test_the_hosted_flag_is_only_ever_read_from_the_environment_or_dot_env(self):
        from agentapi import fleet_token
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop('CVENGINE_HOSTED', None)
            self.assertFalse(fleet_token.hosted_enabled())
        for value in ('', '0', 'false', 'No', 'off'):
            with mock.patch.dict(os.environ, {'CVENGINE_HOSTED': value}):
                self.assertFalse(fleet_token.hosted_enabled(), value)
        with mock.patch.dict(os.environ, {'CVENGINE_HOSTED': '1'}):
            self.assertTrue(fleet_token.hosted_enabled())


def _load_compose(path):
    import yaml

    class Loader(yaml.SafeLoader):
        pass
    for tag in ('!reset', '!override'):
        Loader.add_constructor(tag, lambda loader, node: ('TAG', loader.construct_sequence(node) if isinstance(node, yaml.SequenceNode) else None))
    return yaml.load(Path(path).read_text(), Loader=Loader)  # noqa: S506 - a safe loader with two extra tags


class HostedComposeTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.overlay = _load_compose(ROOT / 'docker-compose.hosted.yml')
        cls.base = _load_compose(ROOT / 'docker-compose.yml')

    def test_only_443_is_published_and_the_other_published_ports_are_dropped(self):
        services = self.overlay['services']
        self.assertEqual(services['proxy']['ports'], ('TAG', ['${CVENGINE_HTTPS_PORT:-443}:443/tcp']))
        for name in ('db', 'web'):  # the two other published ports of docker-compose.yml (127.0.0.1:5432 and 127.0.0.1:8000)
            self.assertEqual(services[name]['ports'], ('TAG', []))
            self.assertTrue(self.base['services'][name]['ports'])
        published = [name for name, service in self.base['services'].items() if service.get('ports') and name not in ('db', 'web', 'proxy')]
        self.assertEqual(published, [], 'a service gained a published port: the overlay must reset it too')

    def test_the_volumes_are_bind_mounts_on_the_data_volume(self):
        for name, folder in (('postgres18_data', 'postgres'), ('scan_results', 'scan_results')):
            volume = self.overlay['volumes'][name]
            self.assertEqual(volume['driver_opts']['type'], 'none')
            self.assertEqual(volume['driver_opts']['o'], 'bind')
            self.assertEqual(volume['driver_opts']['device'], '${CVL_DATA_DIR:-/mnt/cvl-data}/' + folder)
            self.assertIn(name, self.base['volumes'])

    def test_every_long_running_service_restarts(self):
        for name in ('db', 'redis', 'celery', 'celery-beat', 'web', 'proxy'):
            self.assertEqual(self.overlay['services'][name]['restart'], 'always', name)

    def test_the_proxy_gets_the_generated_edge_file_in_place_of_the_stock_one(self):
        mounts = self.overlay['services']['proxy']['volumes']
        self.assertEqual(mounts, ['${CVL_EDGE_AUTH_CONF:-/etc/cvl/edge-auth.conf}:/etc/nginx/edge-auth.conf:ro'])
        self.assertTrue(any(v.endswith(':/etc/nginx/edge-auth.conf:ro') for v in self.base['services']['proxy']['volumes']))

    def test_it_changes_nothing_about_the_scanners_capabilities(self):
        text = (ROOT / 'docker-compose.hosted.yml').read_text()
        for word in ('cap_add', 'cap_drop', 'privileged', 'security_opt', 'network_mode'):
            self.assertNotIn(word + ':', text)

    def test_compose_merges_it_as_described_when_compose_is_available(self):
        if not shutil.which('docker') or subprocess.run(['docker', 'compose', 'version'], capture_output=True).returncode != 0:
            self.skipTest('needs the docker compose CLI (it does not need a daemon)')
        env = bash_env(POSTGRES_DB='a', POSTGRES_USER='a', POSTGRES_PASSWORD='a', POSTGRES_PORT='5432', POSTGRES_HOST='db', DOMAIN_NAME='s.example.test')
        out = subprocess.run(['docker', 'compose', '--env-file', '/dev/null', '-f', 'docker-compose.yml', '-f', 'docker-compose.hosted.yml', 'config', '--format', 'json'],
                             cwd=ROOT, env=env, capture_output=True, text=True)
        if out.returncode != 0:
            self.skipTest('this Compose cannot render the files here: ' + out.stderr[:200])
        config = json.loads(out.stdout)
        ports = {n: s.get('ports') for n, s in config['services'].items() if s.get('ports')}
        self.assertEqual(list(ports), ['proxy'])
        self.assertEqual([(p['target'], str(p['published'])) for p in ports['proxy']], [(443, '443')])
        self.assertEqual(config['volumes']['postgres18_data']['driver_opts']['device'], '/mnt/cvl-data/postgres')


# ----------------------------------------------------------------------------------------------------------------------------------------------
# ensure_fleet_token
# ----------------------------------------------------------------------------------------------------------------------------------------------

def run_fleet(*args, hosted='1', **options):
    out = StringIO()
    env = {'CVENGINE_HOSTED': hosted} if hosted is not None else {}
    with mock.patch.dict(os.environ, env):
        if hosted is None:
            os.environ.pop('CVENGINE_HOSTED', None)
        call_command('ensure_fleet_token', *args, stdout=out, **options)
    return out.getvalue()


class FleetTokenTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser('owner', 'o@example.test', 'x')

    def ensure(self, *args, **options):
        out = run_fleet(*args, **options)
        lines = out.strip().splitlines()
        self.assertEqual(len(lines), 1, 'stdout is one JSON line and nothing else')
        return json.loads(lines[0])

    def heartbeat(self, token):
        return call(token, 'POST', '/api/v1/sentinel/heartbeat', {})[0]

    def test_it_refuses_to_run_unless_hosted_mode_is_on(self):
        from agentapi.models import Agent
        for hosted in (None, '', '0', 'off'):
            with self.assertRaisesRegex(CommandError, 'hosted mode is off'):
                run_fleet(hosted=hosted)
        self.assertFalse(Agent.objects.exists())

    def test_it_needs_an_app_admin_to_own_the_token(self):
        User.objects.all().delete()
        with self.assertRaisesRegex(CommandError, 'no active App Admin'):
            run_fleet()

    def test_it_creates_one_external_sentinel_with_a_sentinel_scope_token(self):
        from agentapi.models import Agent
        from dashboard.models import ApiToken
        out = self.ensure()
        self.assertEqual(out['state'], 'created')
        self.assertTrue(out['token'].startswith('cve_'))
        agent = Agent.objects.get()
        self.assertEqual((agent.kind, agent.network, agent.status, agent.name), ('scanner', 'external', 'active', 'cvENGINE Scanner Fleet'))
        token = ApiToken.objects.get(pk=agent.token_id)
        self.assertEqual((token.scope, token.user_id, token.revoked, token.read_only), ('sentinel', self.admin.pk, False, False))
        self.assertEqual(token.key_hash, __import__('agentapi.auth', fromlist=['hash_token']).hash_token(out['token']))
        self.assertNotIn(out['token'], json.dumps([token.key_hash, token.name, token.prefix, token.suffix]))
        self.assertEqual(self.heartbeat(out['token']), 200)

    def test_it_is_least_privilege_never_internal_and_never_the_built_in_kinds(self):
        from agentapi import sentinel_broker
        from agentapi.models import Agent
        self.ensure()
        agent = Agent.objects.get()
        self.assertNotIn('network:internal', agent.capabilities)
        self.assertNotIn('network:internal', agent.limits['capabilities'])
        self.assertFalse(set(sentinel_broker.BUILTIN_KINDS) & set(agent.capabilities))
        self.assertIn('nmap', agent.capabilities)
        self.assertEqual(agent.limits['capabilities'], agent.capabilities)
        self.assertEqual(agent.scope['hosts'], [])
        # even if the fleet registered itself as internal and with every kind, the server credits it with neither
        Agent.objects.filter(pk=agent.pk).update(capabilities=['network:internal', 'path_probe', 'nuclei_validate', 'nmap'])
        eff = sentinel_broker.effective(Agent.objects.get(pk=agent.pk))
        self.assertEqual(eff.caps, {'nmap'})
        self.assertNotIn('network:internal', sentinel_broker.effective_capabilities(Agent.objects.get(pk=agent.pk)))

    def test_the_token_reaches_the_sentinel_endpoints_and_nothing_else(self):
        token = self.ensure()['token']
        for path in ('/api/v1/projects', '/api/v1/agents', '/mcp/'):
            self.assertEqual(call(token, 'GET', path)[0], 403, path)

    def test_running_again_rotates_the_token_and_keeps_one_agent(self):
        from agentapi.models import Agent
        first = self.ensure()
        second = self.ensure()
        self.assertEqual((first['state'], second['state']), ('created', 'rotated'))
        self.assertNotEqual(first['token'], second['token'])
        self.assertEqual(Agent.objects.count(), 1)
        self.assertEqual(first['agent_id'], second['agent_id'])
        self.assertEqual(call(first['token'], 'POST', '/api/v1/sentinel/heartbeat', {})[0], 401)
        self.assertEqual(self.heartbeat(second['token']), 200)

    def test_a_rotation_puts_back_what_was_widened(self):
        from agentapi.models import Agent
        self.ensure()
        Agent.objects.update(network='internal', capabilities=['network:internal'], limits={}, max_concurrent=10)
        self.ensure(max_concurrent=3)
        agent = Agent.objects.get()
        self.assertEqual((agent.network, agent.max_concurrent), ('external', 3))
        self.assertNotIn('network:internal', agent.capabilities)
        self.assertEqual(agent.limits, {'capabilities': agent.capabilities})

    def test_a_sentinel_that_enrolled_itself_under_the_same_name_is_never_adopted(self):
        from agentapi.models import Agent
        from agentapi.auth import SCOPE_SENTINEL, create_token
        token, _ = create_token(self.admin, 'sentinel:cvENGINE Scanner Fleet', scope=SCOPE_SENTINEL)
        impostor = Agent.objects.create(token=token, name='cvENGINE Scanner Fleet', kind='scanner', network='internal', capabilities=['network:internal'], status='active')
        out = self.ensure()
        self.assertEqual(out['state'], 'created')
        impostor.refresh_from_db()
        self.assertEqual((impostor.network, impostor.status, impostor.token.revoked), ('internal', 'active', False))

    def test_the_owner_can_be_chosen_and_must_be_an_active_app_admin(self):
        from dashboard.models import ApiToken
        User.objects.create_superuser('second', 's@example.test', 'x')
        User.objects.create_user('plain', 'p@example.test', 'x')
        self.ensure('--user', 'second')
        self.assertEqual(ApiToken.objects.get(name='fleet:cvl', revoked=False).user.username, 'second')
        with self.assertRaisesRegex(CommandError, 'no active App Admin named "plain"'):
            run_fleet('--user', 'plain')

    def test_max_concurrent_is_bounded(self):
        with self.assertRaisesRegex(CommandError, 'max_concurrent'):
            run_fleet(max_concurrent=11)

    def test_revoke_ends_the_identity_for_good(self):
        from agentapi.models import Agent
        token = self.ensure()['token']
        out = json.loads(run_fleet('--revoke'))
        self.assertEqual((out['state'], Agent.objects.get().status), ('revoked', 'revoked'))
        self.assertEqual(self.heartbeat(token), 401)
        with self.assertRaisesRegex(CommandError, 'was revoked'):
            run_fleet('--enable')
        with self.assertRaisesRegex(CommandError, 'was revoked'):
            run_fleet('--disable')
        again = self.ensure()  # a plain run issues a new token for the same Agent
        self.assertEqual((again['state'], again['status']), ('rotated', 'active'))
        self.assertEqual(self.heartbeat(again['token']), 200)

    def test_revoking_what_does_not_exist_is_not_an_error(self):
        self.assertEqual(json.loads(run_fleet('--revoke')), {'state': 'absent'})

    def test_disable_suspends_and_enable_resumes_the_same_token(self):
        from agentapi.models import Agent
        token = self.ensure()['token']
        self.assertEqual(json.loads(run_fleet('--disable'))['state'], 'disabled')
        self.assertEqual(Agent.objects.get().status, 'suspended')
        self.assertEqual(self.heartbeat(token), 401)
        self.assertEqual(json.loads(run_fleet('--enable'))['state'], 'enabled')
        self.assertEqual(Agent.objects.get().status, 'active')
        self.assertEqual(self.heartbeat(token), 200)
        self.assertNotIn('token', json.loads(run_fleet('--disable')))

    def test_disable_gives_back_the_tasks_it_holds(self):
        from agentapi.models import Agent, SentinelTask
        from dashboard.models import Org, Project
        self.ensure()
        agent = Agent.objects.get()
        org = Org.objects.create(name='o', slug='o')
        project = Project.objects.create(name='p', slug='p', org=org, insert_date=timezone.now())
        task = SentinelTask.objects.create(project=project, kind='nmap', status='claimed', agent=agent)
        run_fleet('--disable')
        task.refresh_from_db()
        self.assertNotEqual((task.status, task.agent_id), ('claimed', agent.pk))

    def test_enable_does_not_override_an_administrators_suspension(self):
        from agentapi.models import Agent
        self.ensure()
        Agent.objects.update(status='suspended', status_note='an administrator suspended it')
        with self.assertRaisesRegex(CommandError, 'administrator'):
            run_fleet('--enable')

    def test_nothing_to_disable_or_enable_is_an_error(self):
        for flag in ('--disable', '--enable'):
            with self.assertRaisesRegex(CommandError, 'no fleet token'):
                run_fleet(flag)

    def test_the_audit_log_has_no_secret_in_it(self):
        from dashboard.models import AuditLog
        out = self.ensure()
        self.ensure()
        run_fleet('--disable')
        run_fleet('--revoke')
        text = json.dumps(list(AuditLog.objects.values('action', 'target', 'detail')), default=str)
        self.assertNotIn(out['token'], text)
        self.assertNotIn(out['token'][4:], text)
        self.assertIn('agent.register', text)

    def test_the_options_exclude_each_other(self):
        with self.assertRaises(CommandError):
            run_fleet('--revoke', '--disable')


# ----------------------------------------------------------------------------------------------------------------------------------------------
# CVENGINE_PUBLIC_API_URL
# ----------------------------------------------------------------------------------------------------------------------------------------------

class PublicApiUrlTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser('root-admin', 'a@example.test', 'x')

    def url(self, **env):
        base = {'DOMAIN_NAME': 's-abc12345.cvengine.live', 'CVENGINE_PUBLIC_API_URL': ''}
        base.update(env)
        with mock.patch.dict(os.environ, base):
            from agentapi import sentinel_broker
            return sentinel_broker._server_url()

    def test_unset_it_is_the_current_behaviour(self):
        self.assertEqual(self.url(), 'https://s-abc12345.cvengine.live')
        self.assertEqual(self.url(DOMAIN_NAME='localhost'), 'http://localhost')
        self.assertEqual(self.url(DOMAIN_NAME='scan.example.com'), 'https://scan.example.com')
        with mock.patch.dict(os.environ, {'DOMAIN_NAME': 'scan.example.com'}):
            os.environ.pop('CVENGINE_PUBLIC_API_URL', None)
            from agentapi import sentinel_broker
            self.assertEqual(sentinel_broker._server_url(), 'https://scan.example.com')

    def test_set_it_is_used(self):
        self.assertEqual(self.url(CVENGINE_PUBLIC_API_URL='https://api-acme.cvengine.live'), 'https://api-acme.cvengine.live')
        self.assertEqual(self.url(CVENGINE_PUBLIC_API_URL=' https://api-acme.cvengine.live/ '), 'https://api-acme.cvengine.live')
        self.assertEqual(self.url(CVENGINE_PUBLIC_API_URL='https://api.example.com:8443'), 'https://api.example.com:8443')
        self.assertEqual(self.url(CVENGINE_PUBLIC_API_URL='http://127.0.0.1:8000'), 'http://127.0.0.1:8000')

    def test_anything_unusable_falls_back(self):
        for bad in ('http://api.example.com', 'ftp://x.example', 'api.example.com', 'https://', 'https://user:pw@api.example.com', 'https://api.example.com/v1',
                    'https://api.example.com?x=1', 'https://api.example.com#x', 'https://api exam.ple', 'https://api.example.com:notaport', 'javascript:alert(1)'):
            self.assertEqual(self.url(CVENGINE_PUBLIC_API_URL=bad), 'https://s-abc12345.cvengine.live', bad)

    def test_the_enrollment_a_person_generates_carries_it(self):
        with mock.patch.dict(os.environ, {'CVENGINE_PUBLIC_API_URL': 'https://api-acme.cvengine.live', 'DOMAIN_NAME': 's-abc12345.cvengine.live'}):
            status, out = call(self.admin, 'GET', '/api/v1/sentinels/enroll')
        self.assertEqual(status, 201, out)
        self.assertEqual(out['server_url'], 'https://api-acme.cvengine.live')
        with mock.patch.dict(os.environ, {'DOMAIN_NAME': 's-abc12345.cvengine.live'}):
            os.environ.pop('CVENGINE_PUBLIC_API_URL', None)
            status, out = call(self.admin, 'GET', '/api/v1/sentinels/enroll')
        self.assertEqual(out['server_url'], 'https://s-abc12345.cvengine.live')

    def test_the_built_in_scanner_still_reaches_the_server_by_the_compose_service(self):
        from agentapi import builtin_scanner
        with mock.patch.dict(os.environ, {'CVENGINE_PUBLIC_API_URL': 'https://api-acme.cvengine.live'}):
            self.assertEqual(builtin_scanner.server_url(), 'http://web:8000')


# ----------------------------------------------------------------------------------------------------------------------------------------------
# the scripts under stubs
# ----------------------------------------------------------------------------------------------------------------------------------------------

STUB_DOCKER = r'''#!/usr/bin/env bash
# a stand-in for docker: records its arguments (never any environment), answers what the hosted scripts ask
echo "docker $*" >> "$STUB_DIR/log"
case "$*" in
  "compose version"*) echo "Docker Compose version v2.30.0"; exit 0 ;;
  *"ps -q --status running proxy"*) [ "${STUB_PROXY_RUNNING:-1}" = 1 ] && echo abc123; exit 0 ;;
  *"ps -q --status running db"*) [ "${STUB_DB_RUNNING:-1}" = 1 ] && echo def456; exit 0 ;;
  *"exec -T proxy nginx -t"*) exit "${STUB_NGINX_T_RC:-0}" ;;
  *"exec -T proxy nginx -s reload"*) echo reload >> "$STUB_DIR/events"; exit 0 ;;
  *"exec -T web python3 -c"*) exit "${STUB_WEB_RC:-0}" ;;
  *"manage.py link_sso_identity"*) echo "link $*" >> "$STUB_DIR/events"; exit "${STUB_LINK_RC:-0}" ;;
  *"manage.py create_admin"*)
    echo "$*" | grep -q -- "--reset" && reset=1 || reset=0
    if [ "${STUB_ADMIN_EXISTS:-0}" = 1 ] && [ "$reset" = 0 ]; then echo 'The account "admin" already exists; nothing was changed.'; exit 0; fi
    echo "================================================================"
    echo "  CVEngine admin account"
    echo "    Address   : https://x/"
    echo "    Username  : admin"
    echo "    Password  : ${STUB_PASSWORD:-Gen3ratedPassw0rd}"
    echo "================================================================"
    exit 0 ;;
  *"manage.py ensure_fleet_token"*) echo "some framework noise"; echo '{"state":"created","agent_id":1,"token":"cve_stubFleetToken123","network":"external"}'; exit "${STUB_FLEET_RC:-0}" ;;
  *"manage.py migrate"*) echo migrate >> "$STUB_DIR/events"; exit 0 ;;
  *"manage.py import_cve_seed"*) echo seed >> "$STUB_DIR/events"; exit 0 ;;
  *"exec -T db sh -c"*) printf 'PGDMP-this-is-a-fake-plaintext-dump-%0300d' 0; exit 0 ;;
  *"compose "*" up "*|*"compose "*" stop "*|*"compose -f docker-compose.setup.yml run"*) echo "$*" | sed 's/^/compose-action: /' >> "$STUB_DIR/events"; exit 0 ;;
esac
exit 0
'''
STUB_AGE = r'''#!/usr/bin/env bash
echo "age $*" >> "$STUB_DIR/log"
printf 'AGE-ENCRYPTED:'; cat
'''
STUB_AWS = r'''#!/usr/bin/env bash
echo "aws $*" >> "$STUB_DIR/log"
case "$1 $2" in
  "s3 cp") cat > "$STUB_DIR/uploaded"; exit "${STUB_AWS_CP_RC:-0}" ;;
  "s3api head-object") [ -f "$STUB_DIR/uploaded" ] && wc -c < "$STUB_DIR/uploaded" || exit 1 ;;
esac
'''
STUB_TIMEDATECTL = r'''#!/usr/bin/env bash
echo "timedatectl $*" >> "$STUB_DIR/log"
if [ -n "${STUB_NTP_AFTER:-}" ]; then  # synchronised only after that many questions
  n=$(cat "$STUB_DIR/ntp" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$STUB_DIR/ntp"
  if [ "$n" -gt "$STUB_NTP_AFTER" ]; then echo yes; else echo no; fi
  exit 0
fi
echo "${STUB_NTP:-yes}"
'''
STUB_SIMPLE = {
    'mountpoint': '#!/usr/bin/env bash\n[ "${STUB_MOUNTED:-0}" = 1 ]\n',
    'blkid': '#!/usr/bin/env bash\ncase "$*" in *"-s UUID"*) echo 1111-2222; exit 0;; esac\n[ "${STUB_HAS_FS:-0}" = 1 ]\n',
    'mkfs.ext4': '#!/usr/bin/env bash\necho "mkfs $*" >> "$STUB_DIR/events"\n',
    'mount': '#!/usr/bin/env bash\necho "mount $*" >> "$STUB_DIR/events"\n',
}


class ScriptCase(SimpleTestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.stub = self.tmp / 'stub'
        (self.stub / 'bin').mkdir(parents=True)
        self.write_stub('docker', STUB_DOCKER)
        self.write_stub('age', STUB_AGE)
        self.write_stub('aws', STUB_AWS)
        self.write_stub('timedatectl', STUB_TIMEDATECTL)
        for name, body in STUB_SIMPLE.items():
            self.write_stub(name, body)
        self.etc, self.state, self.data = self.tmp / 'etc', self.tmp / 'state', self.tmp / 'data'
        self.repo = self.tmp / 'repo'
        shutil.copytree(ROOT / 'scripts', self.repo / 'scripts', ignore=shutil.ignore_patterns('__pycache__', 'demo', 'inventory', 'scale'))
        shutil.copy(ROOT / '.env.example', self.repo / '.env.example')
        for name in ('docker-compose.yml', 'docker-compose.hosted.yml', 'docker-compose.setup.yml'):
            shutil.copy(ROOT / name, self.repo / name)
        (self.repo / 'config' / 'nginx' / 'state').mkdir(parents=True)

    def write_stub(self, name, body):
        path = self.stub / 'bin' / name
        path.write_text(body)
        path.chmod(0o755)

    def env(self, **extra):
        env = bash_env(PATH=f'{self.stub / "bin"}:{os.environ["PATH"]}', STUB_DIR=str(self.stub), CVL_ETC=str(self.etc), CVL_STATE=str(self.state),
                       CVL_DATA=str(self.data), CVL_REPO=str(self.repo), CVL_ALLOW_NONROOT='1', CVL_POLL_SECONDS='0', CVL_FSTAB=str(self.tmp / 'fstab'),
                       CVL_DOCKER_DAEMON_JSON=str(self.tmp / 'daemon.json'))
        env.update(extra)
        return env

    def run_script(self, name, stdin='', args=(), **extra):
        return subprocess.run(['bash', str(HOSTED / name), *args], input=stdin, env=self.env(**extra), capture_output=True, text=True, timeout=120)

    def log(self):
        path = self.stub / 'log'
        return path.read_text() if path.exists() else ''

    def events(self):
        path = self.stub / 'events'
        return path.read_text().splitlines() if path.exists() else []

    def mode(self, path):
        return stat.S_IMODE(os.stat(path).st_mode)

    def env_file(self):
        return dict(line.split('=', 1) for line in (self.repo / '.env').read_text().splitlines() if '=' in line and not line.startswith('#'))


class ShellcheckTests(SimpleTestCase):
    def test_every_hosted_script_is_shellcheck_clean(self):
        shellcheck = shutil.which('shellcheck')
        if not shellcheck:
            if os.environ.get('CI'):
                self.fail('CI is set but shellcheck is not installed')
            self.skipTest('shellcheck is not installed')
        files = sorted(str(p) for p in HOSTED.rglob('*.sh')) + [str(ROOT / 'scripts' / 'hosted-edge.sh')]
        self.assertGreaterEqual(len(files), 7)
        result = subprocess.run([shellcheck, '-x', '-S', 'style', *files], capture_output=True, text=True, cwd=HOSTED)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_every_script_is_strict_bash(self):
        for path in HOSTED.glob('*.sh'):
            text = path.read_text()
            self.assertTrue(text.startswith('#!/usr/bin/env bash\n'), path.name)
            self.assertIn('set -euo pipefail', text, path.name)
            self.assertTrue(os.access(path, os.X_OK), f'{path.name} is not executable')
            self.assertNotRegex(text, r'(?m)^\s*set -[a-z]*x', path.name)  # never a trace: it would print secrets


class EdgeSecretScriptTests(ScriptCase):
    def set_secret(self, secret, *args, **extra):
        return self.run_script('cvl-set-edge-secret.sh', secret + '\n', args, **extra)

    def test_generator_writes_the_nginx_file_and_the_curl_header_privately(self):
        self.etc.mkdir()
        (self.etc / 'edge-secret').write_text(CURRENT + '\n')
        done = subprocess.run(['bash', str(HOSTED / 'gen-edge-auth.sh')], env=self.env(), capture_output=True, text=True)
        self.assertEqual((done.returncode, done.stdout), (0, ''), done.stderr)
        self.assertEqual((self.etc / 'edge-auth.conf').read_text().splitlines()[1:], ['default 0;', f'"{CURRENT}" 1;'])
        self.assertEqual((self.etc / 'edge-header').read_text(), f'X-CVL-Edge-Auth: {CURRENT}\n')
        for name in ('edge-auth.conf', 'edge-header'):
            self.assertEqual(self.mode(self.etc / name), 0o600)

    def test_the_generator_rejects_a_value_nginx_could_read_as_syntax(self):
        self.etc.mkdir()
        for bad in ('short', 'x' * 40 + '";', 'x' * 40 + ' 1;', 'x' * 40 + '$a', 'x' * 129):
            (self.etc / 'edge-secret').write_text(bad + '\n')
            done = subprocess.run(['bash', str(HOSTED / 'gen-edge-auth.sh')], env=self.env(), capture_output=True, text=True)
            self.assertNotEqual(done.returncode, 0, bad)
            self.assertNotIn(bad, done.stderr + done.stdout)

    def test_generator_writes_in_place_so_a_single_file_bind_mount_follows(self):
        self.etc.mkdir()
        (self.etc / 'edge-secret').write_text(CURRENT + '\n')
        subprocess.run(['bash', str(HOSTED / 'gen-edge-auth.sh')], env=self.env(), check=True)
        inode = os.stat(self.etc / 'edge-auth.conf').st_ino
        (self.etc / 'edge-secret').write_text(OTHER + '\n')
        subprocess.run(['bash', str(HOSTED / 'gen-edge-auth.sh')], env=self.env(), check=True)
        self.assertEqual(os.stat(self.etc / 'edge-auth.conf').st_ino, inode)
        self.assertIn(OTHER, (self.etc / 'edge-auth.conf').read_text())

    def test_first_set_then_a_rotation_keeps_the_previous_until_it_is_dropped(self):
        done = self.set_secret(CURRENT, '--no-previous')
        self.assertEqual((done.returncode, json.loads(done.stdout)), (0, {'ok': True, 'previous': False, 'reloaded': True}), done.stderr)
        self.assertEqual(self.events().count('reload'), 1)
        done = self.set_secret(PREVIOUS)  # rotate: PREVIOUS becomes current, CURRENT the previous
        self.assertEqual(json.loads(done.stdout)['previous'], True, done.stderr)
        conf = (self.etc / 'edge-auth.conf').read_text()
        self.assertIn(f'"{PREVIOUS}" 1;', conf)
        self.assertIn(f'"{CURRENT}" 1;', conf)
        self.assertEqual((self.etc / 'edge-secret').read_text().strip(), PREVIOUS)
        self.assertEqual(self.mode(self.etc / 'edge-secret.previous'), 0o600)
        done = self.run_script('cvl-set-edge-secret.sh', '', ['--drop-previous'])
        self.assertEqual(json.loads(done.stdout)['previous'], False, done.stderr)
        self.assertNotIn(CURRENT, (self.etc / 'edge-auth.conf').read_text())
        self.assertFalse((self.etc / 'edge-secret.previous').exists())
        self.assertEqual(self.events().count('reload'), 3)

    def test_the_secret_is_never_on_a_command_line_in_a_log_or_on_stdout_or_stderr(self):
        done = self.set_secret(CURRENT, '--no-previous')
        self.set_secret(OTHER)
        for text in (self.log(), done.stdout, done.stderr, ' '.join(self.events())):
            self.assertNotIn(CURRENT, text)
            self.assertNotIn(OTHER, text)

    def test_a_bad_secret_or_argument_is_refused_before_anything_changes(self):
        self.set_secret(CURRENT, '--no-previous')
        for bad in ('', 'short', CURRENT + '";'):
            done = self.set_secret(bad)
            self.assertNotEqual(done.returncode, 0, bad)
            self.assertEqual(done.stdout, '')
        self.assertEqual((self.etc / 'edge-secret').read_text().strip(), CURRENT)
        self.assertNotEqual(self.set_secret(CURRENT, '--secret', OTHER).returncode, 0)  # no secret on the command line, ever

    def test_nginx_rejecting_the_file_means_no_reload_and_a_failure(self):
        done = self.set_secret(CURRENT, '--no-previous', STUB_NGINX_T_RC='1')
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(self.events().count('reload'), 0)

    def test_no_reload_and_a_stopped_proxy_both_skip_the_reload(self):
        done = self.set_secret(CURRENT, '--no-previous', '--no-reload')
        self.assertEqual(json.loads(done.stdout)['reloaded'], False)
        done = self.set_secret(OTHER, STUB_PROXY_RUNNING='0')
        self.assertEqual((done.returncode, json.loads(done.stdout)['reloaded']), (0, False))
        self.assertEqual(self.events().count('reload'), 0)

    def test_rotating_to_the_same_secret_does_not_keep_it_as_previous(self):
        self.set_secret(CURRENT, '--no-previous', '--no-reload')
        done = self.set_secret(CURRENT, '--no-reload')
        self.assertEqual(json.loads(done.stdout)['previous'], False)
        self.assertEqual((self.etc / 'edge-auth.conf').read_text().count(CURRENT), 1)


class HostedEdgeHelperTests(SimpleTestCase):
    """scripts/hosted-edge.sh: the curl arguments of the local checks (update.sh, install.sh)."""

    def args(self, env_file_text=None, header=True, **env):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / '.env').write_text(env_file_text or '')
        if header:
            (tmp / 'edge-header').write_text('X-CVL-Edge-Auth: abc\n')
        script = f'. {ROOT}/scripts/hosted-edge.sh; cvengine_hosted_edge_args; IFS="|"; printf "%s" "${{CVL_EDGE_CURL[*]-}}"'
        done = subprocess.run(['bash', '-uc', script], cwd=tmp, env=bash_env(PATH=os.environ['PATH'], CVL_EDGE_HEADER_FILE=str(tmp / 'edge-header'), **env),
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout, tmp, done.stderr

    def test_a_normal_installation_adds_nothing(self):
        self.assertEqual(self.args()[0], '')
        self.assertEqual(self.args('CVENGINE_HOSTED=0\n')[0], '')
        self.assertEqual(self.args('CVENGINE_HOSTED=\n')[0], '')

    def test_hosted_mode_reads_the_header_from_the_file_never_the_secret_itself(self):
        out, tmp, _ = self.args('CVENGINE_HOSTED=1\n')
        self.assertEqual(out, f'-H|@{tmp}/edge-header')
        self.assertNotIn('abc', out)
        self.assertTrue(self.args(CVENGINE_HOSTED='true')[0].startswith('-H|@'))

    def test_hosted_mode_without_the_file_warns_and_adds_nothing(self):
        out, _, err = self.args('CVENGINE_HOSTED=1\n', header=False)
        self.assertEqual(out, '')
        self.assertIn('cannot be read', err)

    def test_the_readiness_checks_use_it_and_nothing_else_does(self):
        update = (ROOT / 'scripts' / 'update.sh').read_text()
        install = (ROOT / 'install.sh').read_text()
        self.assertIn('${CVL_EDGE_CURL[@]+"${CVL_EDGE_CURL[@]}"} "$ready_url"', update)
        self.assertIn('${CVL_EDGE_CURL[@]+"${CVL_EDGE_CURL[@]}"} "https://127.0.0.1:$https_port/"', install)
        for path in (ROOT / 'scripts').glob('*.sh'):  # no other script asks the proxy for a page (the watchdog and the other updaters work through `docker compose exec`)
            if path.name in ('update.sh', 'hosted-edge.sh'):
                continue
            self.assertNotRegex(path.read_text(), r'curl[^\n]*https://127\.0\.0\.1', path.name)


class FirstbootScriptTests(ScriptCase):
    def setUp(self):
        super().setUp()
        self.device = self.tmp / 'volume-device'
        self.device.write_text('')

    def firstboot(self, **extra):
        return self.run_script('cvl-firstboot.sh', **{'CVL_VOLUME_DEVICE': str(self.device), 'CVL_SKIP_SEED': '', **extra})

    def test_a_first_boot_prepares_everything_and_marks_the_server_ready(self):
        done = self.firstboot(CVL_ORIGIN_HOST='s-abcd1234.cvengine.live')
        self.assertEqual((done.returncode, done.stdout), (0, ''), done.stderr)
        self.assertTrue((self.state / 'ready').is_file())
        self.assertEqual((self.state / 'origin-host').read_text().strip(), 's-abcd1234.cvengine.live')
        env = self.env_file()
        self.assertEqual(env['DOMAIN_NAME'], 's-abcd1234.cvengine.live')
        self.assertEqual(env['CVENGINE_HOSTED'], '1')
        self.assertEqual(env['CVENGINE_CSRF_TRUSTED_ORIGINS'], 'https://scanner.cvengine.live')
        self.assertEqual(env['CVENGINE_HSTS_SECONDS'], '31536000')
        self.assertEqual(env['CVENGINE_COMPOSE_FILES'], 'docker-compose.yml,docker-compose.hosted.yml')
        self.assertEqual(env['CVENGINE_BUILTIN_SCANNER'], '0')
        for key in ('POSTGRES_PASSWORD', 'AUTHORITY_PASSWORD', 'REDIS_PASSWORD', 'CVENGINE_FIELD_KEY'):
            self.assertRegex(env[key], r'^[A-Za-z0-9]{24}$', key)  # init-env.sh made its own: the golden image carries none
        self.assertEqual(self.mode(self.repo / '.env'), 0o600)
        self.assertEqual(self.events().index('migrate') < self.events().index('seed'), True)

    def test_the_origin_name_is_generated_as_s_and_eight_characters(self):
        self.firstboot()
        origin = (self.state / 'origin-host').read_text().strip()
        self.assertRegex(origin, r'^s-[a-z0-9]{8}\.cvengine\.live$')
        self.assertEqual(self.env_file()['DOMAIN_NAME'], origin)

    def test_the_edge_secret_placeholder_is_random_private_and_closes_the_proxy(self):
        self.firstboot()
        secret = (self.etc / 'edge-secret').read_text().strip()
        self.assertRegex(secret, r'^[A-Za-z0-9_-]{43}$')
        self.assertEqual(self.mode(self.etc / 'edge-secret'), 0o600)
        self.assertEqual(self.mode(self.etc), 0o700)
        self.assertIn(f'"{secret}" 1;', (self.etc / 'edge-auth.conf').read_text())
        self.assertIn('default 0;', (self.etc / 'edge-auth.conf').read_text())

    def test_the_stack_is_started_with_the_hosted_overlay_and_never_with_make_up(self):
        self.firstboot()
        log = self.log()
        self.assertRegex(log, r'docker compose -f docker-compose\.yml -f docker-compose\.hosted\.yml up -d db redis web celery celery-beat proxy')
        self.assertNotIn('make', log)

    def test_the_data_volume_is_formatted_only_when_empty_mounted_and_remembered(self):
        self.firstboot()
        self.assertTrue(any(e.startswith('mkfs ') for e in self.events()))
        self.assertTrue(any(e.startswith('mount ') and str(self.data) in e for e in self.events()))
        self.assertIn('UUID=1111-2222', (self.tmp / 'fstab').read_text())
        self.assertTrue((self.data / 'postgres').is_dir() and (self.data / 'scan_results').is_dir())

    def test_a_volume_that_already_holds_a_filesystem_is_never_formatted(self):
        self.firstboot(STUB_HAS_FS='1')
        self.assertFalse(any(e.startswith('mkfs ') for e in self.events()))

    def test_without_a_volume_it_refuses_rather_than_use_the_root_disk(self):
        done = self.run_script('cvl-firstboot.sh', CVL_VOLUME_DEVICE='', CVL_SKIP_SEED='1')
        if 'no data volume found' not in done.stderr:  # a machine that happens to have a DigitalOcean volume device
            self.skipTest('this machine has a by-id volume device')
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse((self.state / 'ready').exists())
        self.assertFalse((self.repo / '.env').exists())

    def test_it_is_safe_to_run_again(self):
        self.firstboot(CVL_ORIGIN_HOST='s-abcd1234.cvengine.live')
        env_before, secret = (self.repo / '.env').read_text(), (self.etc / 'edge-secret').read_text()
        done = self.firstboot()  # no origin given this time: the one on disk is kept
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual((self.repo / '.env').read_text(), env_before)
        self.assertEqual((self.etc / 'edge-secret').read_text(), secret)

    def test_a_failure_leaves_no_ready_marker(self):
        done = self.firstboot(STUB_WEB_RC='1', CVL_WAIT_SECONDS='1', CVL_POLL_SECONDS='1')
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse((self.state / 'ready').exists())

    def test_the_origin_name_must_be_a_plain_host_name(self):
        done = self.firstboot(CVL_ORIGIN_HOST='bad host;rm -rf')
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse((self.repo / '.env').exists())

    def test_it_warns_about_the_userland_proxy_and_stays_quiet_when_it_is_off(self):
        self.assertIn('userland proxy is on', self.firstboot().stderr)
        (self.tmp / 'daemon.json').write_text('{"userland-proxy": false}')
        self.assertNotIn('userland proxy is on', self.firstboot().stderr)


class PersonalizeScriptTests(ScriptCase):
    def setUp(self):
        super().setUp()
        self.state.mkdir()
        (self.state / 'ready').write_text('x\n')
        (self.repo / '.env').write_text('CVENGINE_HOSTED=1\nCVENGINE_COMPOSE_FILES=docker-compose.yml,docker-compose.hosted.yml\nDOMAIN_NAME=s-abcd1234.cvengine.live\n')

    def personalize(self, payload, **extra):
        return self.run_script('cvl-personalize.sh', payload if isinstance(payload, str) else json.dumps(payload), **extra)

    GOOD = {'customer_slug': 'acme', 'email': 'owner@acme.example', 'ignored': 'x'}

    def test_stdout_is_exactly_the_one_json_object_of_the_contract(self):
        done = self.personalize(self.GOOD)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(len(done.stdout.strip().splitlines()), 1)
        self.assertEqual(json.loads(done.stdout), {'username': 'admin', 'password': 'Gen3ratedPassw0rd', 'fleet_token': 'cve_stubFleetToken123',
                                                   'api_base': 'https://api-acme.cvengine.live'})

    def test_the_api_address_is_set_and_the_web_service_restarted_once(self):
        self.personalize(self.GOOD)
        self.assertEqual(self.env_file()['CVENGINE_PUBLIC_API_URL'], 'https://api-acme.cvengine.live')
        self.assertEqual(len(re.findall(r'up -d --no-deps --force-recreate web', self.log())), 1)
        self.personalize(self.GOOD)  # a retry: already set, no second restart
        self.assertEqual(len(re.findall(r'up -d --no-deps --force-recreate web', self.log())), 1)

    def test_no_secret_is_in_a_command_line_a_file_or_stderr(self):
        done = self.personalize(self.GOOD, STUB_PASSWORD='Sup3rSecretPassw0rd')
        self.assertIn('Sup3rSecretPassw0rd', done.stdout)
        self.assertNotIn('Sup3rSecretPassw0rd', done.stderr + self.log())
        self.assertNotIn('cve_stubFleetToken123', done.stderr + self.log())
        for path in list(self.repo.rglob('.env')) + list(self.state.rglob('*')) + list(self.etc.rglob('*')):
            if path.is_file():
                self.assertNotIn('Sup3rSecretPassw0rd', path.read_text())
                self.assertNotIn('cve_stubFleetToken123', path.read_text())

    def test_an_existing_admin_gets_a_reset_password_on_a_retry(self):
        done = self.personalize(self.GOOD, STUB_ADMIN_EXISTS='1', STUB_PASSWORD='N3wPassw0rdAfterReset')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(done.stdout)['password'], 'N3wPassw0rdAfterReset')
        self.assertIn('--reset', self.log())

    def test_the_username_is_optional_and_checked(self):
        done = self.personalize({**self.GOOD, 'username': 'owner.one'})
        self.assertEqual(json.loads(done.stdout)['username'], 'owner.one')
        self.assertIn('--username owner.one', self.log())
        for bad in ('-rf', 'a b', 'x;y', ''):
            done = self.personalize({**self.GOOD, 'username': bad})
            self.assertNotEqual(done.returncode, 0, bad)
            self.assertEqual(done.stdout, '')

    def test_bad_input_is_refused_with_nothing_on_stdout_and_nothing_changed(self):
        before = (self.repo / '.env').read_text()
        for payload in ('', 'not json', '[]', {'email': 'a@b.example'}, {'customer_slug': 'acme'}, {'customer_slug': 'Acme', 'email': 'a@b.example'},
                        {'customer_slug': 'a_b', 'email': 'a@b.example'}, {'customer_slug': '-a', 'email': 'a@b.example'}, {'customer_slug': 'a' * 60, 'email': 'a@b.example'},
                        {'customer_slug': 'acme', 'email': 'two@a.example,three@a.example'}, {'customer_slug': 'acme', 'email': 'no-at-sign'},
                        {'customer_slug': 'ac.me', 'email': 'a@b.example'}, {'customer_slug': 'acme$(id)', 'email': 'a@b.example'}):
            done = self.personalize(payload)
            self.assertNotEqual(done.returncode, 0, payload)
            self.assertEqual(done.stdout, '', payload)
            self.assertTrue(done.stderr.strip())
        self.assertEqual((self.repo / '.env').read_text(), before)
        self.assertNotIn('create_admin', self.log())

    def test_a_server_that_is_not_ready_or_not_hosted_is_refused(self):
        (self.state / 'ready').unlink()
        self.assertNotEqual(self.personalize(self.GOOD).returncode, 0)
        (self.state / 'ready').write_text('x')
        (self.repo / '.env').write_text('DOMAIN_NAME=x\n')
        done = self.personalize(self.GOOD)
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(done.stdout, '')
        self.assertNotIn('create_admin', self.log())

    def test_a_server_belongs_to_one_customer(self):
        self.assertEqual(self.personalize(self.GOOD).returncode, 0)
        done = self.personalize({**self.GOOD, 'customer_slug': 'other'})
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(done.stdout, '')
        self.assertEqual(self.env_file()['CVENGINE_PUBLIC_API_URL'], 'https://api-acme.cvengine.live')

    def test_a_failing_step_fails_the_script_with_nothing_on_stdout(self):
        done = self.personalize(self.GOOD, STUB_FLEET_RC='1')
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(done.stdout, '')
        self.assertFalse((self.state / 'personalized').exists())

    def test_the_marker_holds_only_the_slug(self):
        self.personalize(self.GOOD)
        self.assertEqual((self.state / 'personalized').read_text(), 'acme\n')


class ExportScriptTests(ScriptCase):
    AGE_KEY = 'age1' + 'q' * 58

    def export(self, *args, **extra):
        env = {'CVL_S3_BUCKET': 'cvl-backups', 'CVL_S3_ENDPOINT': 'https://nyc3.digitaloceanspaces.com', 'CVL_AGE_RECIPIENT': self.AGE_KEY,
               'AWS_ACCESS_KEY_ID': 'AKIDSTUBACCESSKEY', 'AWS_SECRET_ACCESS_KEY': 'stubSecretKeyValue123', **extra}
        (self.repo / '.env').write_text('CVENGINE_HOSTED=1\nCVENGINE_COMPOSE_FILES=docker-compose.yml,docker-compose.hosted.yml\n')
        return self.run_script('cvl-export.sh', '', args, **env)

    def test_the_dump_is_encrypted_before_it_leaves_and_the_result_is_one_json_line(self):
        done = self.export('--key', 'acme/2026-11-15/final.dump.age')
        self.assertEqual(done.returncode, 0, done.stderr)
        out = json.loads(done.stdout)
        self.assertEqual((out['ok'], out['bucket'], out['key']), (True, 'cvl-backups', 'acme/2026-11-15/final.dump.age'))
        uploaded = (self.stub / 'uploaded').read_bytes()
        self.assertTrue(uploaded.startswith(b'AGE-ENCRYPTED:'))
        self.assertEqual(out['bytes'], len(uploaded))
        self.assertIn('age -r ' + self.AGE_KEY, self.log())
        self.assertIn('--endpoint-url https://nyc3.digitaloceanspaces.com', self.log())

    def test_the_bucket_keys_never_appear_in_arguments_or_output(self):
        done = self.export('--key', 'a/b.age')
        for text in (self.log(), done.stdout, done.stderr):
            self.assertNotIn('stubSecretKeyValue123', text)
            self.assertNotIn('AKIDSTUBACCESSKEY', text)

    def test_no_recipient_means_no_upload(self):
        done = self.export('--key', 'a/b.age', CVL_AGE_RECIPIENT='')
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse((self.stub / 'uploaded').exists())
        self.assertEqual(done.stdout, '')
        for bad in ('not-a-key', 'age1short', 'ssh-ed25519 AAAA'):
            self.assertNotEqual(self.export('--key', 'a/b.age', CVL_AGE_RECIPIENT=bad).returncode, 0, bad)

    def test_the_application_is_stopped_first_unless_told_not_to(self):
        self.export('--key', 'a/b.age')
        self.assertTrue(any('stop celery celery-beat web' in e for e in self.events()))
        (self.stub / 'events').unlink()
        self.export('--key', 'a/c.age', '--no-quiesce')
        self.assertFalse(any(' stop ' in e for e in self.events()))

    def test_a_failed_upload_or_an_empty_object_is_a_failure(self):
        done = self.export('--key', 'a/b.age', STUB_AWS_CP_RC='1')
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(done.stdout, '')

    def test_bad_keys_endpoints_and_buckets_are_refused(self):
        for args in (('--key', '../x'), ('--key', 'a b'), ('--key', ''), ('--key', '/abs')):
            self.assertNotEqual(self.export(*args).returncode, 0, args)
        self.assertNotEqual(self.export('--key', 'a/b', CVL_S3_ENDPOINT='http://insecure.example').returncode, 0)
        self.assertNotEqual(self.export('--key', 'a/b', CVL_S3_BUCKET='Bad_Bucket').returncode, 0)
        self.assertNotEqual(self.export('--key', 'a/b', AWS_SECRET_ACCESS_KEY='').returncode, 0)

    def test_a_stopped_database_is_a_failure_before_anything_is_stopped(self):
        done = self.export('--key', 'a/b.age', STUB_DB_RUNNING='0')
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse(any(' stop ' in e for e in self.events()))
