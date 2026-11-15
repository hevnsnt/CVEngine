"""The bundled proxy (config/nginx/rengine.conf) must follow the web container's current address.

Incident: the web container was recreated on its own (docker compose up -d web) and got a new address on the compose network; the proxy container was not
recreated, kept sending to the old address (nginx looked "rengine" up once, at start), and the site was down until the proxy was restarted. The conf now
puts the address in a variable and has a resolver (Docker's DNS, 127.0.0.11, valid=10s), so nginx looks it up again.

Checked here with a real nginx (the proxy's own nginx:alpine image; in CI a missing docker is a failure, not a skip, as in test_tunnel_client_address):
* the whole conf passes nginx -t, and the proxy starts (and answers with the maintenance page) while "rengine" does not resolve at all;
* on a user-defined docker network the upstream is removed and recreated at another address and the proxy, never restarted, reaches the new one;
  the same scenario with the old conf is run as a control and does not follow;
* each of the three proxied locations sends the upstream the same path and query as the old conf did, for a list of awkward request targets."""
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from django.test import SimpleTestCase

from tests.test_tunnel_client_address import CONF, REPO, free_port, nginx_runner

# how the three routes looked before: the first with a trailing slash (and so the cleaned-up path), the other two without a URI (the raw one)
OLD_FORMS = (('location / {', 'http://rengine:8000/'), ('location ~ ^/api/v1/sentinel/tasks', 'http://rengine:8000'), ('location = /cve/api/settings/cve_seed/import {', 'http://rengine:8000'))


def old_conf():
    """The current conf turned back into the form it had before: a fixed name in proxy_pass, no variable, no rewrite."""
    text = re.sub(r'^\s*set\s+\$cvengine_web [^\n]*\n', '', CONF, flags=re.M)
    text = re.sub(r'^\s*rewrite\s+\^ \$uri break;\n', '', text, flags=re.M)
    text = re.sub(r'^\s*resolver(_timeout)?\s[^\n]*\n', '', text, flags=re.M)
    for start, target in OLD_FORMS:
        at = text.index(start)
        found = re.compile(r'^[ \t]*proxy_pass[ \t]+\S+;', re.M).search(text, at)
        text = text[:found.start()] + f'        proxy_pass                                  {target};' + text[found.end():]
    return text


def docker(*args, check=True, timeout=120):
    return subprocess.run(['docker', *args], capture_output=True, text=True, timeout=timeout, check=check)


class NeedsNginx(SimpleTestCase):
    runner = None

    def setUp(self):
        self.runner = nginx_runner()
        if self.runner is None:
            if os.environ.get('CI'):
                self.fail('CI is set but the nginx:alpine image cannot be used (needs docker): the proxy tests must run in CI, not be skipped')
            self.skipTest('needs an nginx binary or docker')


class ConfShapeTests(SimpleTestCase):
    def test_the_conf_has_a_resolver_and_no_fixed_upstream_name_in_proxy_pass(self):
        self.assertRegex(CONF, r'resolver\s+127\.0\.0\.11 valid=10s ipv6=off;')
        self.assertNotRegex(CONF, r'(?m)^\s*proxy_pass\s+http://')  # a name written in proxy_pass is looked up once, at start
        self.assertEqual(len(re.findall(r'(?m)^\s*proxy_pass\s+\$cvengine_web;', CONF)), 3)
        self.assertEqual(len(re.findall(r'set\s+\$cvengine_web http://rengine:8000;', CONF)), 3)

    def test_the_old_form_helper_really_gives_the_old_form(self):
        old = old_conf()
        self.assertEqual(re.findall(r'(?m)^\s*proxy_pass\s+(\S+);', old), ['http://rengine:8000/', 'http://rengine:8000', 'http://rengine:8000'])
        code = re.sub(r'(?m)^\s*#.*$', '', old)
        self.assertNotIn('cvengine_web', code)
        self.assertNotIn('resolver', code)


class RawUpstream(BaseHTTPRequestHandler):
    seen = []

    def do_GET(self):  # noqa: N802
        type(self).seen.append((self.command, self.path))
        self.send_response(200)
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'ok')

    do_POST = do_GET

    def log_message(self, *args):
        pass


def raw_request(port, method, target):
    """Send the request line exactly as given (urllib would tidy it) and return the status line."""
    body = b'x=1' if method == 'POST' else b''
    head = f'{method} {target} HTTP/1.1\r\nHost: cvengine.test\r\nConnection: close\r\nContent-Length: {len(body)}\r\n\r\n'.encode()
    with socket.create_connection(('127.0.0.1', port), timeout=10) as conn:
        conn.sendall(head + body)
        reply = b''
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            reply += chunk
    return reply.split(b'\r\n')[0].decode()


# what a client may send: (method, request target). Compared old conf against new conf, one request at a time.
TARGETS = [
    ('GET', '/'), ('GET', '/a'), ('GET', '/a/'), ('GET', '/api/v1/x/?a=%2F&b=1'), ('GET', '/api/v1/x?a=%2F&b=1'), ('GET', '/?a=%2F&b=1'),
    ('GET', '/a%2Fb'), ('GET', '/a%2fb?q=%2f'), ('GET', '/a%20b'), ('GET', '/a%3Fb?c=d'), ('GET', '/a%23b'), ('GET', '//a//b'), ('GET', '/a/../b'),
    ('GET', '/a/./b'), ('GET', '/a/..'), ('GET', '/%7Euser'), ('GET', '/caf%C3%A9'), ('GET', '/%E2%82%AC?x=%E2%82%AC'), ('GET', '/a%25b'),
    ('GET', '/a+b?x=a+b'), ('GET', '/?'), ('GET', '/x?'), ('GET', '/a/?'), ('GET', '/a;b=c'), ('GET', '/a%2e%2e/b'), ('GET', '/a/%2E/b'), ('GET', '/a%7f'),
    ('GET', '/a%ff'), ('GET', '/a?%ff'), ('GET', '/a?x=1&&y'), ('GET', '/a?x=%26&y=%3D'), ('GET', '/%2e%2e/x'), ('GET', '/a%00b'), ('GET', '/a%zz'),
    ('POST', '/api/v1/sentinel/tasks/12/result'), ('POST', '/api/v1/sentinel/tasks/12/partial?a=%2F&b=1'), ('GET', '/api/v1/sentinel/tasks/12/result?x=%2F'),
    ('POST', '/cve/api/settings/cve_seed/import'), ('POST', '/cve/api/settings/cve_seed/import?a=%2F&b=1'), ('GET', '/cve/api/settings/cve_seed/import//x'),
    ('POST', '/api/v1/sentinel/tasks/12%2Fresult'), ('POST', '/api//v1/sentinel/tasks/12/result'),
]
# Characters RFC 3986 does not allow in a path, which a browser does not send raw (and Django reads the escaped form as the same path): the old conf
# passed them through, the new one writes them as percent-codes. The only difference found; the upstream decodes both to the same text.
RAW_ILLEGAL = [('GET', '/a"b', '/a%22b'), ('GET', '/a<b>', '/a%3Cb%3E'), ('GET', '/a|b', '/a%7Cb'), ('GET', '/a{b}', '/a%7Bb%7D')]


class UpstreamPathTests(NeedsNginx):
    """Both confs run in turn in front of the same recording upstream; every request must reach it with the same path and query (or the same refusal)."""

    def run_locations(self, conf_text):
        tmp = tempfile.mkdtemp()
        os.chmod(tmp, 0o755)
        self.addCleanup(shutil.rmtree, tmp, True)
        stock = open(os.path.join(REPO, 'config', 'nginx', 'trusted-upstreams.conf'), encoding='utf-8').read()
        with open(f'{tmp}/trusted-upstreams.conf', 'w') as f:
            f.write(stock)
        os.chmod(f'{tmp}/trusted-upstreams.conf', 0o644)
        upstream = HTTPServer(('127.0.0.1', 0), RawUpstream)
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        self.addCleanup(upstream.shutdown)
        etc = tmp if self.runner == 'local' else '/t'
        scratch = f'{tmp}/scratch' if self.runner == 'local' else '/tmp'
        os.makedirs(scratch, exist_ok=True)
        head = conf_text[:conf_text.index('\nserver {')].replace('/etc/nginx/trusted-upstreams.conf', f'{etc}/trusted-upstreams.conf')
        server = conf_text[conf_text.index('    location / {'):conf_text.index('    location /staticfiles/')]
        server = server.replace('http://rengine:8000', f'http://127.0.0.1:{upstream.server_port}').replace('/etc/nginx/state/', f'{etc}/state/')
        port = free_port()
        text = (f'daemon off; pid {scratch}/nginx.pid; error_log stderr;\nevents {{}}\nhttp {{\n'
                f'client_body_temp_path {scratch}/b; proxy_temp_path {scratch}/p; fastcgi_temp_path {scratch}/f; uwsgi_temp_path {scratch}/u; scgi_temp_path {scratch}/s;\n'
                f'access_log off;\n{head}\nserver {{ listen 127.0.0.1:{port};\n{server}\n}}\n}}\n')
        with open(f'{tmp}/nginx.conf', 'w') as f:
            f.write(text)
        os.chmod(f'{tmp}/nginx.conf', 0o644)
        if self.runner == 'local':
            check = subprocess.run(['nginx', '-t', '-c', f'{tmp}/nginx.conf'], capture_output=True, text=True)
            self.assertEqual(check.returncode, 0, check.stderr)
            proc = subprocess.Popen(['nginx', '-c', f'{tmp}/nginx.conf'], stderr=subprocess.DEVNULL)
            self.addCleanup(proc.wait)
            self.addCleanup(proc.terminate)
        else:
            name = f'cvengine-pathtest-{os.getpid()}-{port}'
            run = ['--network', 'host', '-v', f'{tmp}:/t:ro', 'nginx:alpine', 'nginx', '-c', '/t/nginx.conf']
            check = docker('run', '--rm', *run[:-3], 'nginx', '-t', '-c', '/t/nginx.conf', check=False)
            self.assertEqual(check.returncode, 0, check.stderr)
            docker('run', '-d', '--rm', '--name', name, *run)
            self.addCleanup(lambda: docker('rm', '-f', name, check=False))
        for _ in range(100):
            try:
                raw_request(port, 'GET', '/')
                break
            except OSError:
                time.sleep(0.1)
        results = {}
        for method, target in TARGETS + [(m, t) for m, t, _ in RAW_ILLEGAL]:
            RawUpstream.seen = []
            status = raw_request(port, method, target)
            results[(method, target)] = (status, list(RawUpstream.seen))
        return results

    def test_every_location_passes_the_upstream_what_it_passed_before(self):
        before = self.run_locations(old_conf())
        after = self.run_locations(CONF)
        sent = [key for key, (status, seen) in before.items() if seen]
        self.assertGreater(len(sent), 30, 'the comparison must cover requests that reach the upstream')
        for key in before:
            if key[1] in {t for _, t, _ in RAW_ILLEGAL}:
                continue
            self.assertEqual(after[key], before[key], f'{key}: before {before[key]}, after {after[key]}')

    def test_the_cleaned_up_path_of_the_slash_location_and_the_raw_path_of_the_others_are_kept(self):
        after = self.run_locations(CONF)
        self.assertEqual(after[('GET', '/api/v1/x/?a=%2F&b=1')][1], [('GET', '/api/v1/x/?a=%2F&b=1')])
        self.assertEqual(after[('GET', '/a%2Fb')][1], [('GET', '/a/b')])      # location / : the path is cleaned up, as before
        self.assertEqual(after[('GET', '//a//b')][1], [('GET', '/a/b')])
        self.assertEqual(after[('GET', '/a%3Fb?c=d')][1], [('GET', '/a%3Fb?c=d')])
        self.assertEqual(after[('POST', '/cve/api/settings/cve_seed/import?a=%2F&b=1')][1], [('POST', '/cve/api/settings/cve_seed/import?a=%2F&b=1')])
        self.assertEqual(after[('POST', '/api/v1/sentinel/tasks/12/partial?a=%2F&b=1')][1], [('POST', '/api/v1/sentinel/tasks/12/partial?a=%2F&b=1')])

    def test_the_only_difference_is_how_four_illegal_raw_characters_are_written(self):
        before = self.run_locations(old_conf())
        after = self.run_locations(CONF)
        for method, raw, escaped in RAW_ILLEGAL:
            self.assertEqual(before[(method, raw)][1], [(method, raw)])
            self.assertEqual(after[(method, raw)][1], [(method, escaped)])


class WholeConfTests(NeedsNginx):
    """The conf as the proxy container runs it (all of it: certificates, the maintenance page, the flag directory), in nginx:alpine on a user-defined
    network, which is where Docker's DNS at 127.0.0.11 exists. Needs docker itself (not a local nginx binary)."""

    def setUp(self):
        super().setUp()
        if self.runner != 'docker':
            self.skipTest('needs docker (a user-defined network and Docker DNS)')
        self.tag = f'cvtest{os.getpid()}{int(time.time()) % 100000}'
        self.net = f'{self.tag}-net'
        self.names = []
        docker('network', 'create', self.net)
        self.addCleanup(lambda: docker('network', 'rm', self.net, check=False))
        self.addCleanup(self.remove_containers)
        self.tmp = tempfile.mkdtemp()
        os.chmod(self.tmp, 0o755)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def remove_containers(self):
        for name in self.names:
            docker('rm', '-f', name, check=False)

    def certs(self):
        d = f'{self.tmp}/certs'
        os.makedirs(d)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', f'{d}/rengine_rsa.key', '-out', f'{d}/rengine.pem', '-subj', '/CN=rengine', '-days', '2'],
                       check=True, capture_output=True)
        shutil.copy(f'{d}/rengine.pem', f'{d}/rengine_chain.pem')
        for name in os.listdir(d):
            os.chmod(f'{d}/{name}', 0o644)
        return d

    def proxy_args(self, conf_text):
        conf = f'{self.tmp}/rengine.conf'
        with open(conf, 'w') as f:
            f.write(conf_text)
        os.chmod(conf, 0o644)
        state = f'{self.tmp}/state'
        os.makedirs(state, exist_ok=True)
        os.chmod(state, 0o755)
        trusted = f'{self.tmp}/trusted-upstreams.conf'
        shutil.copy(os.path.join(REPO, 'config', 'nginx', 'trusted-upstreams.conf'), trusted)
        os.chmod(trusted, 0o644)
        certs = self.certs()
        return ['-v', f'{conf}:/etc/nginx/conf.d/rengine.conf:ro', '-v', f'{certs}:/etc/nginx/certs:ro', '-v', f'{state}:/etc/nginx/state:ro',
                '-v', f'{trusted}:/etc/nginx/trusted-upstreams.conf:ro',
                '-v', f'{os.path.join(REPO, "web", "static", "cve", "maintenance.html")}:/usr/share/nginx/maintenance/maintenance.html:ro']

    def start_proxy(self, conf_text):
        name = f'{self.tag}-proxy'
        self.names.append(name)
        docker('run', '-d', '--name', name, '--network', self.net, '-p', '127.0.0.1::443', *self.proxy_args(conf_text), 'nginx:alpine')
        port = int(docker('port', name, '443/tcp').stdout.split(':')[-1])
        return name, port

    def start_upstream(self, label, alias='rengine'):
        """A fake web container answering <label> on 8000 under the name "rengine" on the network. Returns its address."""
        conf = f'{self.tmp}/up-{label}.conf'
        with open(conf, 'w') as f:
            f.write(f'server {{ listen 8000; location / {{ return 200 "{label}"; }} }}\n')
        os.chmod(conf, 0o644)
        name = f'{self.tag}-up-{label}'
        self.names.append(name)
        docker('run', '-d', '--name', name, '--network', self.net, '--network-alias', alias, '-v', f'{conf}:/etc/nginx/conf.d/default.conf:ro', 'nginx:alpine')
        return docker('inspect', '-f', f'{{{{(index .NetworkSettings.Networks "{self.net}").IPAddress}}}}', name).stdout.strip(), name

    def fetch(self, port, path='/', timeout=4):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(urllib.request.Request(f'https://127.0.0.1:{port}{path}', headers={'Host': 'rengine'}), timeout=timeout, context=context) as reply:
                return reply.status, reply.read().decode()
        except urllib.error.HTTPError as err:
            return err.code, err.read().decode(errors='replace')
        except (OSError, ssl.SSLError):
            return None, ''

    def wait_for(self, port, wanted, seconds):
        deadline = time.time() + seconds
        last = None
        while time.time() < deadline:
            last = self.fetch(port)
            if last == wanted:
                return time.time()
            time.sleep(1)
        return None

    def test_the_conf_passes_nginx_t(self):
        check = docker('run', '--rm', '--network', self.net, *self.proxy_args(CONF), 'nginx:alpine', 'nginx', '-t', check=False)
        self.assertEqual(check.returncode, 0, check.stderr)

    def test_the_proxy_starts_while_rengine_does_not_resolve_and_serves_the_maintenance_page(self):
        name, port = self.start_proxy(CONF)
        deadline = time.time() + 30
        reply = (None, '')
        while time.time() < deadline and reply[0] is None:
            reply = self.fetch(port)
            time.sleep(0.5)
        self.assertIn(reply[0], (502, 503, 504), f'the proxy must answer an error page, got {reply}')
        self.assertIn('data-maint', reply[1])  # the maintenance page, not nginx's bare error
        self.assertEqual(docker('inspect', '-f', '{{.State.Running}}', name).stdout.strip(), 'true')
        # and once the web container appears under that name, the same proxy reaches it
        self.start_upstream('first')
        self.assertIsNotNone(self.wait_for(port, (200, 'first'), 40), 'the proxy did not pick up the upstream that appeared after it started')

    def test_the_old_conf_refuses_to_start_without_the_name(self):
        control = docker('run', '--rm', '--network', self.net, *self.proxy_args(old_conf()), 'nginx:alpine', 'nginx', '-t', check=False)
        self.assertNotEqual(control.returncode, 0)
        self.assertIn('host not found in upstream', control.stderr)

    def recreate_scenario(self, conf_text):
        """Start an upstream and the proxy, remove the upstream and create another at a different address; returns (proxy, port, old_ip, new_ip)."""
        old_ip, old_name = self.start_upstream('first')
        name, port = self.start_proxy(conf_text)
        self.assertIsNotNone(self.wait_for(port, (200, 'first'), 40), 'the proxy never reached the first upstream')
        started = docker('inspect', '-f', '{{.State.StartedAt}}', name).stdout.strip()
        docker('rm', '-f', old_name)
        self.names.remove(old_name)
        # something else takes the freed address, as the celery-beat container did in the incident
        filler = f'{self.tag}-filler'
        self.names.append(filler)
        docker('run', '-d', '--name', filler, '--network', self.net, 'nginx:alpine')
        new_ip, _ = self.start_upstream('second')
        self.assertNotEqual(new_ip, old_ip, 'the recreated upstream got the same address, so this run proves nothing')
        return name, port, started, old_ip, new_ip

    def test_recreating_the_upstream_at_a_new_address_needs_no_proxy_restart(self):
        name, port, started, old_ip, new_ip = self.recreate_scenario(CONF)
        reached = self.wait_for(port, (200, 'second'), 40)  # the resolver's validity is 10 s
        self.assertIsNotNone(reached, f'the proxy still did not reach the recreated upstream ({new_ip}, it was {old_ip}) after 40 s')
        self.assertEqual(docker('inspect', '-f', '{{.State.StartedAt}}', name).stdout.strip(), started, 'the proxy must not have been restarted')

    def test_control_the_old_conf_keeps_sending_to_the_old_address(self):
        name, port, started, old_ip, new_ip = self.recreate_scenario(old_conf())
        self.assertIsNone(self.wait_for(port, (200, 'second'), 25), 'the old conf followed the new address: the control no longer shows the incident')
