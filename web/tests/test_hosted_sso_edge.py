"""Single sign-on plumbing of hosted mode (hosted/README.md, "Single sign-on"): nginx headers, the Compose overlay, and the hosted/ scripts. Everything is
OFF by default; these tests prove that a stock install and a hosted install without SSO behave as before, and that nothing a client sends can pass for
what the proxy sets. No network, no Docker daemon, no secrets: nginx runs for real (as in test_hosted_mode), the scripts run under stubs."""
import base64
import http.client
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from django.test import SimpleTestCase

from tests.test_hosted_mode import (CURRENT, FORGED, HOSTED, OTHER, ROOT, ProxyBase, Recorder, ScriptCase, _load_compose, bash_env, generate_edge_file)
from tests.test_tunnel_client_address import CONF

SID = '0123456789abcdef0123456789abcdef'
SUB = 'user_0123-ABCD'
EDGE = {'X-CVL-Edge-Auth': CURRENT}
SENTINEL = '    location ~ ^/api/v1/sentinel/tasks/[0-9]+/(result|partial)$ {'
SEED = '    location = /cve/api/settings/cve_seed/import {'
ALL_LOCATIONS = ('    location / {', SENTINEL, SEED)
PATHS = {'    location / {': '/x', SENTINEL: '/api/v1/sentinel/tasks/7/result', SEED: '/cve/api/settings/cve_seed/import'}
SSO_HEADERS = ('x-cvl-edge-verified', 'x-cvl-sso-sub', 'x-cvl-sso-sid', 'x-cvl-sso-exchange')


def b64u(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')


def key(kid='k1', seed=1, status='current', **extra):
    return {'kid': kid, 'kty': 'OKP', 'crv': 'Ed25519', 'x': b64u(bytes([seed]) * 32), 'status': status, **extra}


def raw_request(port, path, header_lines):
    """GET with the header lines exactly as given (duplicates and odd names included): [(name, value), ...] -> status"""
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    conn.putrequest('GET', path, skip_host=False, skip_accept_encoding=True)
    for name, value in header_lines:
        conn.putheader(name, value)
    conn.endheaders()
    status = conn.getresponse().status
    conn.close()
    return status


class SsoProxyBase(ProxyBase):
    def seen_at(self, port, marker, headers=None, path=None):
        Recorder.seen = []
        status = self.fetch(port, path or PATHS[marker], headers)
        return status, (Recorder.seen[-1] if Recorder.seen else None)


class StockSsoProxyTests(SsoProxyBase):
    """The stock (empty) edge-auth file: no secret is ever listed, so the SSO headers can never be believed."""

    def test_the_verified_flag_is_zero_and_nothing_else_is_forwarded(self):
        plain, tunnel = self.run_proxy(locations=ALL_LOCATIONS)
        forged = {'X-CVL-Edge-Verified': '1', 'X-CVL-SSO-Sub': SUB, 'X-CVL-SSO-Sid': SID, 'X-CVL-SSO-Exchange': '1'}
        for port in (plain, tunnel):
            for marker in ALL_LOCATIONS:
                for extra in ({}, EDGE):  # a secret-shaped header changes nothing on a stock install
                    status, seen = self.seen_at(port, marker, {**forged, **extra})
                    self.assertEqual(status, 200, marker)
                    self.assertEqual(seen['x-cvl-edge-verified'], '0', marker)
                    for name in SSO_HEADERS[1:]:
                        self.assertNotIn(name, seen, (marker, name))

    def test_the_rest_of_the_request_is_what_it_was(self):
        plain, _ = self.run_proxy()
        _, seen = self.upstream_saw(plain, '/x', {'X-Forwarded-For': FORGED, 'X-CVL-Edge-Auth': CURRENT})
        self.assertEqual(seen['x-forwarded-for'], '127.0.0.1')
        self.assertNotIn('x-cvl-edge-auth', seen)
        self.assertNotIn('x-cvl-client-ip', seen)


class HostedSsoProxyTests(SsoProxyBase):
    """A generated edge-auth file. Without the secret a request is refused (or, for the loopback probe of "/", handled with every SSO header blank); with
    it the proxy forwards the verified flag and the binding headers, after checking their shape."""

    def hosted(self, **kwargs):
        return self.run_proxy(generate_edge_file(CURRENT, None), **kwargs)

    def test_with_the_secret_the_flag_is_one_and_the_binding_headers_pass_in_every_location(self):
        plain, tunnel = self.hosted(locations=ALL_LOCATIONS)
        for port in (plain, tunnel):
            for marker in ALL_LOCATIONS:
                status, seen = self.seen_at(port, marker, {**EDGE, 'X-CVL-SSO-Sub': SUB, 'X-CVL-SSO-Sid': SID, 'X-CVL-SSO-Exchange': '1'})
                self.assertEqual(status, 200, marker)
                self.assertEqual((seen['x-cvl-edge-verified'], seen['x-cvl-sso-sub'], seen['x-cvl-sso-sid'], seen['x-cvl-sso-exchange']), ('1', SUB, SID, '1'), marker)
                self.assertNotIn('x-cvl-edge-auth', seen)
                self.assertNotIn('x-cvl-client-ip', seen)

    def test_with_the_secret_and_no_sso_headers_only_the_flag_is_set(self):
        plain, _ = self.hosted()
        _, seen = self.upstream_saw(plain, '/x', EDGE)
        self.assertEqual(seen['x-cvl-edge-verified'], '1')
        for name in SSO_HEADERS[1:]:
            self.assertNotIn(name, seen)

    def test_a_client_supplied_flag_is_overwritten_when_the_secret_passes(self):
        plain, _ = self.hosted(locations=ALL_LOCATIONS)
        for marker in ALL_LOCATIONS:
            for forged in ('0', '1', '', 'yes', '1, 1', ' 1'):
                _, seen = self.seen_at(plain, marker, {**EDGE, 'X-CVL-Edge-Verified': forged})
                self.assertEqual(seen['x-cvl-edge-verified'], '1', (marker, forged))
        status = raw_request(plain, '/x', [('X-CVL-Edge-Auth', CURRENT), ('X-CVL-Edge-Verified', '0'), ('X-CVL-Edge-Verified', '0')])  # duplicates
        self.assertEqual(status, 200)
        self.assertEqual([v for k, v in Recorder.seen[-1]['_raw'] if k == 'x-cvl-edge-verified'], ['1'])

    def test_without_the_secret_the_loopback_probe_gets_flag_zero_and_blank_sso_headers(self):
        """The only request this proxy lets through without a secret is the probe of "/" from loopback: whatever SSO headers it carries are not forwarded and
        the flag the application sees is 0, with no secret, a wrong one or an empty one."""
        plain, tunnel = self.hosted(locations=ALL_LOCATIONS)
        forged = {'X-CVL-Edge-Verified': '1', 'X-CVL-SSO-Sub': SUB, 'X-CVL-SSO-Sid': SID, 'X-CVL-SSO-Exchange': '1'}
        for port in (plain, tunnel):
            for secret in ({}, {'X-CVL-Edge-Auth': OTHER}, {'X-CVL-Edge-Auth': ''}):
                status, seen = self.seen_at(port, '    location / {', {**forged, **secret}, path='/')
                self.assertEqual(status, 200)
                self.assertEqual(seen['x-cvl-edge-verified'], '0')
                for name in SSO_HEADERS[1:]:
                    self.assertNotIn(name, seen, name)
                # and everywhere else the request never reaches the application at all
                for marker in ALL_LOCATIONS:
                    self.assertEqual(self.seen_at(port, marker, {**forged, **secret}), (403, None), marker)

    def test_a_binding_header_with_the_wrong_shape_is_not_forwarded_even_with_the_secret(self):
        plain, _ = self.hosted()
        for bad_sub in ('', 'a b', 'a;b', 'a,b', 'x' * 65, '<s>', 'a\x7fb', 'é'):
            try:
                _, seen = self.upstream_saw(plain, '/x', {**EDGE, 'X-CVL-SSO-Sub': bad_sub})
            except UnicodeEncodeError:
                continue
            self.assertNotIn('x-cvl-sso-sub', seen, repr(bad_sub))
        for bad_sid in ('', SID[:-1], SID + '0', SID.upper(), 'g' * 32, SID + 'x', f'{SID},{SID}'):
            _, seen = self.upstream_saw(plain, '/x', {**EDGE, 'X-CVL-SSO-Sid': bad_sid})
            self.assertNotIn('x-cvl-sso-sid', seen, repr(bad_sid))
        for bad_exchange in ('0', 'true', '11', ''):
            _, seen = self.upstream_saw(plain, '/x', {**EDGE, 'X-CVL-SSO-Exchange': bad_exchange})
            self.assertNotIn('x-cvl-sso-exchange', seen, repr(bad_exchange))

    def test_underscore_spellings_and_duplicate_binding_headers_never_get_through(self):
        plain, _ = self.hosted()
        status = raw_request(plain, '/x', [('X-CVL-Edge-Auth', CURRENT), ('X_CVL_Edge_Verified', '1'), ('X_CVL_SSO_Sub', SUB), ('X-CVL-SSO-Sub', SUB)])
        self.assertEqual(status, 200)
        names = [k for k, _ in Recorder.seen[-1]['_raw']]
        self.assertFalse([n for n in names if '_' in n], names)
        self.assertEqual(names.count('x-cvl-sso-sub'), 1)
        # the same spellings without the secret never reach the application (loopback probe of "/")
        raw_request(plain, '/', [('X_CVL_Edge_Verified', '1'), ('X-CVL-Edge-Verified', '1')])
        self.assertEqual([v for k, v in Recorder.seen[-1]['_raw'] if k == 'x-cvl-edge-verified'], ['0'])
        self.assertFalse([k for k, _ in Recorder.seen[-1]['_raw'] if '_' in k])

    def test_a_valid_secret_on_the_tunnel_listener_behaves_the_same(self):
        _, tunnel = self.hosted()
        _, seen = self.upstream_saw(tunnel, '/x', {**EDGE, 'X-CVL-SSO-Sub': SUB, 'X-CVL-SSO-Sid': SID})
        self.assertEqual((seen['x-cvl-edge-verified'], seen['x-cvl-sso-sub'], seen['x-cvl-sso-sid']), ('1', SUB, SID))

    def test_the_secret_and_the_binding_headers_reach_no_log(self):
        if self.runner != 'local':
            self.skipTest('the access log is only readable with a local nginx binary')
        log_format = "log_format full '$remote_addr \"$request\" $status \"$http_referer\" \"$http_user_agent\"';\naccess_log @TMP@/access.log full;"
        plain, _ = self.hosted(access_log=log_format)
        self.upstream_saw(plain, '/x', {**EDGE, 'X-CVL-SSO-Sub': SUB, 'X-CVL-SSO-Sid': SID})
        self.upstream_saw(plain, '/x', {'X-CVL-Edge-Auth': OTHER})
        log = Path(self.scratch, 'access.log').read_text()
        self.assertIn('/x', log)
        for secret in (CURRENT, OTHER, SUB, SID):
            self.assertNotIn(secret, log)


class ProxyConfigStaticTests(SimpleTestCase):
    """What the real-nginx tests cannot see: every proxied location carries the lines, and nothing logs a secret."""

    def proxied_locations(self):
        blocks = re.findall(r'\n    (location [^\n]*\{\n.*?\n    \})', CONF, flags=re.S)
        return [b for b in blocks if 'proxy_pass' in b]

    def test_every_proxied_location_sets_the_flag_and_the_binding_headers(self):
        blocks = self.proxied_locations()
        self.assertEqual(len(blocks), 3)
        for block in blocks:
            for name, value in (('X-CVL-Edge-Verified', '$cvl_edge_ok_flag'), ('X-CVL-SSO-Sub', '$cvl_sso_sub'), ('X-CVL-SSO-Sid', '$cvl_sso_sid'),
                                ('X-CVL-SSO-Exchange', '$cvl_sso_exchange'), ('X-CVL-Edge-Auth', '""'), ('X-CVL-Client-IP', '""')):
                self.assertRegex(block, rf'proxy_set_header\s+{name}\s+{re.escape(value)};', block.splitlines()[0] + name)

    def test_the_flag_is_derived_from_the_secret_check_alone(self):
        self.assertRegex(CONF, r'map \$cvl_edge_ok \$cvl_edge_ok_flag \{\s+default\s+0;\s+1\s+1;\s+\}')
        for variable in ('cvl_sso_sub', 'cvl_sso_sid', 'cvl_sso_exchange'):
            self.assertRegex(CONF, rf'map "\$cvl_edge_ok:\$http_x_cvl_{variable[4:]}" \${variable} \{{\s+default\s+"";')
        self.assertIn('underscores_in_headers                          off;', CONF)

    def test_no_log_format_or_header_ever_writes_a_secret(self):
        self.assertNotIn('log_format', CONF)
        for line in CONF.splitlines():
            code = line.split('#', 1)[0]
            if re.search(r'access_log|add_header|error_log|return\s+\d+\s+["\$]', code):
                self.assertNotRegex(code, r'http_x_cvl|cvl_edge|cvl_sso', code)

    def test_the_stock_edge_file_is_still_empty(self):
        stock = (ROOT / 'config' / 'nginx' / 'edge-auth.conf.example').read_text()
        self.assertEqual([line for line in stock.splitlines() if line.strip() and not line.lstrip().startswith('#')], [])


class SsoComposeTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.overlay = _load_compose(ROOT / 'docker-compose.hosted.yml')

    def test_the_web_service_gets_the_key_file_read_only(self):
        self.assertEqual(self.overlay['services']['web']['volumes'], ['${CVL_SSO_KEYS_FILE:-/etc/cvl/sso-keys.json}:/etc/cvl/sso-keys.json:ro'])

    def test_the_settings_are_passed_through_with_no_value_and_so_no_default(self):
        env = self.overlay['services']['web']['environment']
        self.assertEqual(env, ['CVENGINE_SSO', 'CVENGINE_SSO_ENFORCE', 'CVENGINE_SSO_ISSUER', 'CVENGINE_SSO_AUDIENCE', 'CVENGINE_SSO_MAX_AUTH_AGE',
                               'CVENGINE_SSO_STEPUP_AGE', 'CVENGINE_SSO_BREAKGLASS_UNTIL'])
        for entry in env:
            self.assertNotIn('=', entry)

    def test_the_stock_compose_file_knows_nothing_about_it(self):
        self.assertNotIn('sso', (ROOT / 'docker-compose.yml').read_text().lower())

    def test_compose_merges_it_when_the_cli_is_available(self):
        if not shutil.which('docker') or subprocess.run(['docker', 'compose', 'version'], capture_output=True).returncode != 0:
            self.skipTest('needs the docker compose CLI (it does not need a daemon)')
        base = bash_env(POSTGRES_DB='a', POSTGRES_USER='a', POSTGRES_PASSWORD='a', POSTGRES_PORT='5432', POSTGRES_HOST='db', DOMAIN_NAME='s.example.test')

        def render(**extra):
            out = subprocess.run(['docker', 'compose', '--env-file', '/dev/null', '-f', 'docker-compose.yml', '-f', 'docker-compose.hosted.yml', 'config', '--format', 'json'],
                                 cwd=ROOT, env={**base, **extra}, capture_output=True, text=True)
            if out.returncode != 0:
                self.skipTest('this Compose cannot render the files here: ' + out.stderr[:200])
            return json.loads(out.stdout)['services']['web']

        web = render()
        self.assertEqual([(v['source'], v['target'], v.get('read_only')) for v in web['volumes'] if v['target'].endswith('sso-keys.json')],
                         [('/etc/cvl/sso-keys.json', '/etc/cvl/sso-keys.json', True)])
        self.assertFalse([k for k, v in web['environment'].items() if k.startswith('CVENGINE_SSO') and v not in (None, '')])
        moved = render(CVL_SSO_KEYS_FILE='/srv/keys.json', CVENGINE_SSO='1')
        self.assertIn('/srv/keys.json', [v['source'] for v in moved['volumes']])
        self.assertEqual(moved['environment']['CVENGINE_SSO'], '1')


# ----------------------------------------------------------------------------------------------------------------------------------------------
# scripts
# ----------------------------------------------------------------------------------------------------------------------------------------------

class SsoKeysScriptTests(ScriptCase):
    def setUp(self):
        super().setUp()
        self.target = self.etc / 'sso-keys.json'

    def push(self, payload, *args, **extra):
        text = payload if isinstance(payload, str) else json.dumps(payload)
        return self.run_script('cvl-set-sso-keys.sh', text, args, **extra)

    def test_a_valid_set_is_installed_privately_and_the_stdout_is_one_json_line(self):
        done = self.push({'keys': [key('a', 1), key('b', 2, 'next'), key('c', 3, 'retiring')]})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout, '{"ok":true,"kids":["a","b","c"]}\n')
        self.assertEqual(self.mode(self.target), 0o600)
        self.assertEqual(json.loads(self.target.read_text())['keys'][1], key('b', 2, 'next'))

    def test_zero_keys_and_eight_keys_are_fine(self):
        self.assertEqual(self.push({'keys': []}).stdout, '{"ok":true,"kids":[]}\n')
        self.assertEqual(json.loads(self.target.read_text()), {'keys': []})
        done = self.push({'keys': [key(f'k{i}', i + 1) for i in range(8)]})
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_unknown_members_are_accepted_and_dropped(self):
        done = self.push({'keys': [key('a', 1, use='sig', alg='EdDSA', d='SECRETPRIVATEPART', extra={'x': 1})], 'note': 'ignored'})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(self.target.read_text()), {'keys': [key('a', 1)]})
        self.assertNotIn('SECRETPRIVATEPART', self.target.read_text() + done.stdout + done.stderr)

    def test_the_file_keeps_its_inode_and_mode_when_it_changes(self):
        self.push({'keys': [key('a', 1)]})
        before = self.target.stat()
        link = self.tmp / 'second-name'
        os.link(self.target, link)  # a second name for the inode: a rename-over would leave it with the OLD content
        os.chmod(self.target, 0o644)
        self.assertEqual(self.push({'keys': [key('b', 2)]}).returncode, 0)
        after = self.target.stat()
        self.assertEqual((before.st_ino, self.mode(self.target)), (after.st_ino, 0o600))
        self.assertEqual(json.loads(link.read_text())['keys'][0]['kid'], 'b')

    def test_pushing_the_same_set_again_changes_nothing(self):
        payload = {'keys': [key('a', 1), key('b', 2, 'next')]}
        first = self.push(payload)
        stat_before = self.target.stat()
        text_before = self.target.read_text()
        second = self.push(payload)
        self.assertEqual((first.stdout, first.returncode), (second.stdout, second.returncode))
        self.assertEqual(self.target.read_text(), text_before)
        self.assertEqual(self.target.stat().st_mtime_ns, stat_before.st_mtime_ns)  # not even rewritten

    def test_a_set_that_differs_only_by_unknown_members_is_the_same_set(self):
        self.push({'keys': [key('a', 1)]})
        mtime = self.target.stat().st_mtime_ns
        self.push({'keys': [key('a', 1, use='sig')]})
        self.assertEqual(self.target.stat().st_mtime_ns, mtime)

    def test_the_invalid_input_matrix_is_refused_with_nothing_on_stdout_and_nothing_changed(self):
        self.push({'keys': [key('keep', 9)]})
        before = self.target.read_text()
        good = key('a', 1)
        x31 = b64u(b'\x01' * 31)
        x33 = b64u(b'\x01' * 33)
        padded = b64u(b'\x01' * 32) + '='
        noncanonical = b64u(b'\x01' * 32)[:-1] + 'B'  # same 32 bytes, different trailing bits
        cases = {
            'empty': '', 'not json': 'nope', 'json array': '[]', 'null': 'null', 'no keys member': '{}', 'keys not a list': '{"keys":{}}',
            'nan': '{"keys":[NaN]}', 'key not object': {'keys': ['a']}, 'nine keys': {'keys': [key(f'k{i}', i + 1) for i in range(9)]},
            'missing kid': {'keys': [{k: v for k, v in good.items() if k != 'kid'}]}, 'kid int': {'keys': [{**good, 'kid': 1}]},
            'kid empty': {'keys': [{**good, 'kid': ''}]}, 'kid with space': {'keys': [{**good, 'kid': 'a b'}]}, 'kid with newline': {'keys': [{**good, 'kid': 'a\nb'}]},
            'kid with quote': {'keys': [{**good, 'kid': 'a"b'}]}, 'kid too long': {'keys': [{**good, 'kid': 'k' * 129}]},
            'duplicate kid': {'keys': [key('a', 1), key('a', 2)]},
            'kty RSA': {'keys': [{**good, 'kty': 'RSA'}]}, 'kty EC': {'keys': [{**good, 'kty': 'EC'}]}, 'kty missing': {'keys': [{k: v for k, v in good.items() if k != 'kty'}]},
            'crv Ed448': {'keys': [{**good, 'crv': 'Ed448'}]}, 'crv X25519': {'keys': [{**good, 'crv': 'X25519'}]}, 'crv lowercase': {'keys': [{**good, 'crv': 'ed25519'}]},
            'x missing': {'keys': [{k: v for k, v in good.items() if k != 'x'}]}, 'x short': {'keys': [{**good, 'x': x31}]}, 'x long': {'keys': [{**good, 'x': x33}]},
            'x padded': {'keys': [{**good, 'x': padded}]}, 'x standard base64': {'keys': [{**good, 'x': b64u(b'\xfb' * 32).replace('-', '+').replace('_', '/')}]},
            'x non canonical': {'keys': [{**good, 'x': noncanonical}]}, 'x int': {'keys': [{**good, 'x': 5}]}, 'x hex': {'keys': [{**good, 'x': 'ab' * 32}]},
            'status revoked': {'keys': [{**good, 'status': 'revoked'}]}, 'status unknown': {'keys': [{**good, 'status': 'active'}]},
            'status missing': {'keys': [{k: v for k, v in good.items() if k != 'status'}]}, 'status upper': {'keys': [{**good, 'status': 'Current'}]},
            'one bad among good': {'keys': [key('ok', 1), {**good, 'kid': 'bad', 'crv': 'P-256'}]}, 'too big': '{"keys":[],"pad":"' + 'a' * 70000 + '"}',
        }
        for name, payload in cases.items():
            done = self.push(payload)
            self.assertNotEqual(done.returncode, 0, name)
            self.assertEqual(done.stdout, '', name)
            self.assertTrue(done.stderr.strip(), name)
            self.assertEqual(self.target.read_text(), before, name)

    def test_no_key_material_is_ever_printed(self):
        secret_x = b64u(bytes(range(100, 132)))
        done = self.push({'keys': [{**key('a', 1), 'x': secret_x, 'crv': 'P-256'}]})
        self.assertNotIn(secret_x, done.stdout + done.stderr)
        done = self.push({'keys': [{**key('a', 1), 'x': secret_x}]})
        self.assertNotIn(secret_x, done.stdout + done.stderr + self.log())
        self.assertEqual(done.stdout, '{"ok":true,"kids":["a"]}\n')

    def test_check_lists_the_installed_kids_and_changes_nothing(self):
        self.push({'keys': [key('a', 1), key('b', 2, 'next')]})
        stat_before, text_before = self.target.stat(), self.target.read_text()
        done = self.run_script('cvl-set-sso-keys.sh', '', ['--check'])
        self.assertEqual((done.returncode, done.stdout), (0, '{"ok":true,"kids":["a","b"]}\n'), done.stderr)
        self.assertEqual((self.target.read_text(), self.target.stat().st_mtime_ns), (text_before, stat_before.st_mtime_ns))
        # stdin is ignored by --check: it never replaces the set
        done = self.run_script('cvl-set-sso-keys.sh', json.dumps({'keys': []}), ['--check'])
        self.assertEqual(done.stdout, '{"ok":true,"kids":["a","b"]}\n')
        self.assertEqual(self.target.read_text(), text_before)

    def test_check_fails_for_a_missing_or_corrupt_file(self):
        done = self.run_script('cvl-set-sso-keys.sh', '', ['--check'])
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(done.stdout, '')
        self.assertFalse(self.target.exists())
        self.etc.mkdir(parents=True)
        self.target.write_text('{"keys":[{"kid":"a"}]}')
        done = self.run_script('cvl-set-sso-keys.sh', '', ['--check'])
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(done.stdout, '')

    def test_the_stock_file_first_boot_writes_passes_check(self):
        self.etc.mkdir(parents=True)
        self.target.write_text('{"keys":[]}\n')
        self.assertEqual(self.run_script('cvl-set-sso-keys.sh', '', ['--check']).stdout, '{"ok":true,"kids":[]}\n')

    def test_a_directory_in_the_way_is_refused(self):
        self.target.mkdir(parents=True)
        done = self.push({'keys': []})
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(done.stdout, '')

    def test_an_unknown_argument_is_refused_and_the_file_override_is_honoured(self):
        done = self.push({'keys': []}, '--force')
        self.assertNotEqual(done.returncode, 0)
        elsewhere = self.tmp / 'moved' / 'keys.json'
        done = self.push({'keys': [key('a', 1)]}, CVL_SSO_KEYS_FILE=str(elsewhere))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue(elsewhere.is_file())
        self.assertFalse(self.target.exists())

    def test_it_refuses_a_non_root_caller_unless_the_test_switch_is_set(self):
        if os.getuid() == 0:
            self.skipTest('running as root')
        done = self.push({'keys': []}, CVL_ALLOW_NONROOT='')
        self.assertNotEqual(done.returncode, 0)


class SsoPersonalizeTests(ScriptCase):
    GOOD = {'customer_slug': 'acme', 'email': 'owner@acme.example'}

    def setUp(self):
        super().setUp()
        self.state.mkdir()
        (self.state / 'ready').write_text('x\n')
        self.write_env()

    def write_env(self, extra=''):
        (self.repo / '.env').write_text('CVENGINE_HOSTED=1\nCVENGINE_COMPOSE_FILES=docker-compose.yml,docker-compose.hosted.yml\nDOMAIN_NAME=s-abcd1234.cvengine.live\n' + extra)

    def personalize(self, payload, **extra):
        return self.run_script('cvl-personalize.sh', payload if isinstance(payload, str) else json.dumps(payload), **extra)

    def links(self):
        return [e for e in self.events() if e.startswith('link ')]

    def test_without_sso_the_subject_is_ignored_and_the_output_is_unchanged(self):
        done = self.personalize({**self.GOOD, 'sso_subject': 'user_0123456'})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(done.stdout), {'username': 'admin', 'password': 'Gen3ratedPassw0rd', 'fleet_token': 'cve_stubFleetToken123',
                                                   'api_base': 'https://api-acme.cvengine.live'})
        self.assertEqual(self.links(), [])

    def test_with_sso_on_the_identity_is_linked_after_the_admin_is_made(self):
        self.write_env('CVENGINE_SSO=1\n')
        done = self.personalize({**self.GOOD, 'sso_subject': 'user_0123456'})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn('password', json.loads(done.stdout))
        self.assertEqual(self.links(), ['link compose -f docker-compose.yml -f docker-compose.hosted.yml exec -T web python3 manage.py link_sso_identity '
                                        '--email=owner@acme.example --subject=user_0123456'])
        log = self.log()
        self.assertLess(log.index('create_admin'), log.index('link_sso_identity'))

    def test_with_sso_on_but_no_subject_nothing_is_linked(self):
        self.write_env('CVENGINE_SSO=1\n')
        self.assertEqual(self.personalize(self.GOOD).returncode, 0)
        self.assertEqual(self.links(), [])
        self.assertNotIn('link_sso_identity', self.log())

    def test_a_falsey_setting_counts_as_off(self):
        for value in ('0', 'false', 'No', 'OFF', ''):
            self.write_env(f'CVENGINE_SSO={value}\n')
            self.assertEqual(self.personalize({**self.GOOD, 'sso_subject': 'user_0123456'}).returncode, 0)
        self.assertEqual(self.links(), [])

    def test_a_link_failure_is_a_hard_error_with_nothing_on_stdout(self):
        self.write_env('CVENGINE_SSO=1\n')
        done = self.personalize({**self.GOOD, 'sso_subject': 'user_0123456'}, STUB_LINK_RC='1')
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(done.stdout, '')
        self.assertIn('link_sso_identity failed', done.stderr)
        self.assertFalse((self.state / 'personalized').exists())

    def test_enforce_omits_the_password_and_keeps_every_other_key(self):
        self.write_env('CVENGINE_SSO=1\nCVENGINE_SSO_ENFORCE=1\n')
        done = self.personalize({**self.GOOD, 'sso_subject': 'user_0123456'}, STUB_PASSWORD='Sup3rSecretPassw0rd')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(len(done.stdout.strip().splitlines()), 1)
        self.assertEqual(json.loads(done.stdout), {'username': 'admin', 'fleet_token': 'cve_stubFleetToken123', 'api_base': 'https://api-acme.cvengine.live'})
        self.assertNotIn('Sup3rSecretPassw0rd', done.stdout + done.stderr + self.log())

    def test_retries_stay_idempotent_in_enforce_mode(self):
        self.write_env('CVENGINE_SSO=1\nCVENGINE_SSO_ENFORCE=1\n')
        payload = {**self.GOOD, 'sso_subject': 'user_0123456'}
        first = self.personalize(payload)
        second = self.personalize(payload, STUB_ADMIN_EXISTS='1')
        self.assertEqual((first.returncode, second.returncode), (0, 0), second.stderr)
        self.assertEqual(json.loads(first.stdout), json.loads(second.stdout))
        self.assertEqual(len(self.links()), 2)
        self.assertEqual((self.state / 'personalized').read_text(), 'acme\n')

    def test_a_bad_subject_is_refused_before_anything_changes(self):
        before = (self.repo / '.env').read_text()
        for bad in ('short', 'x' * 65, 'has space1', 'semi;colon1', '$(id)abcdef', 'é' * 8, 12345678, ['a' * 8], '', 'a\nb' + 'c' * 8):
            done = self.personalize({**self.GOOD, 'sso_subject': bad})
            self.assertNotEqual(done.returncode, 0, repr(bad))
            self.assertEqual(done.stdout, '', repr(bad))
        self.assertEqual((self.repo / '.env').read_text(), before)
        self.assertNotIn('create_admin', self.log())
        for ok in ('--email-x', 'abcdefgh', 'A' * 64, 'u-1_2-3_4', '0' * 8):
            self.assertEqual(self.personalize({**self.GOOD, 'sso_subject': ok}).returncode, 0, ok)

    def test_a_null_subject_is_the_same_as_none(self):
        self.write_env('CVENGINE_SSO=1\n')
        self.assertEqual(self.personalize({**self.GOOD, 'sso_subject': None}).returncode, 0)
        self.assertEqual(self.links(), [])


class SsoFirstbootTests(ScriptCase):
    def setUp(self):
        super().setUp()
        self.device = self.tmp / 'volume-device'
        self.device.write_text('')

    def firstboot(self, **extra):
        return self.run_script('cvl-firstboot.sh', **{'CVL_VOLUME_DEVICE': str(self.device), 'CVL_ORIGIN_HOST': 's-abcd1234.cvengine.live', **extra})

    def test_it_asks_the_clock_and_goes_on_when_it_is_synchronised(self):
        done = self.firstboot()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn('timedatectl show -p NTPSynchronized --value', self.log())
        self.assertTrue((self.state / 'ready').is_file())

    def test_an_unsynchronised_clock_fails_with_a_clear_message_before_anything_is_made(self):
        done = self.firstboot(STUB_NTP='no', CVL_NTP_WAIT_SECONDS='1', CVL_POLL_SECONDS='1')
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(done.stdout, '')
        self.assertIn('clock is not synchronised', done.stderr)
        self.assertFalse((self.state / 'ready').exists())
        self.assertFalse((self.repo / '.env').exists())
        self.assertFalse((self.etc / 'sso-keys.json').exists())
        self.assertNotIn('docker compose', self.log())

    def test_it_waits_for_the_clock_to_synchronise(self):
        done = self.firstboot(STUB_NTP_AFTER='2', CVL_NTP_WAIT_SECONDS='30', CVL_POLL_SECONDS='0')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertGreaterEqual(self.log().count('timedatectl'), 3)

    def test_a_missing_timedatectl_is_a_clear_failure(self):
        (self.stub / 'bin' / 'timedatectl').unlink()
        done = self.firstboot(PATH=f'{self.stub / "bin"}:{self.tmp / "nothing"}:/usr/bin:/bin')
        if shutil.which('timedatectl', path='/usr/bin:/bin'):
            self.skipTest('this machine has a real timedatectl in /usr/bin')
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('timedatectl is not installed', done.stderr)

    def test_the_development_switch_skips_only_the_clock(self):
        done = self.firstboot(STUB_NTP='no', CVL_ALLOW_NO_NTP='1')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertNotIn('timedatectl', self.log())

    def test_the_stock_key_file_is_the_empty_set_with_mode_600(self):
        self.assertEqual(self.firstboot().returncode, 0)
        target = self.etc / 'sso-keys.json'
        self.assertEqual(json.loads(target.read_text()), {'keys': []})
        self.assertEqual(self.mode(target), 0o600)
        check = self.run_script('cvl-set-sso-keys.sh', '', ['--check'])
        self.assertEqual(check.stdout, '{"ok":true,"kids":[]}\n')

    def test_the_key_file_exists_before_the_stack_starts(self):
        self.write_stub('docker', (self.stub / 'bin' / 'docker').read_text().replace(
            'echo "docker $*" >> "$STUB_DIR/log"', 'echo "docker $*" >> "$STUB_DIR/log"; [ -s "$CVL_ETC/sso-keys.json" ] && echo "keys-present" >> "$STUB_DIR/seen-keys" || true'))
        self.assertEqual(self.firstboot().returncode, 0)
        self.assertIn('keys-present', (self.stub / 'seen-keys').read_text())

    def test_an_installed_key_set_survives_a_second_first_boot(self):
        self.assertEqual(self.firstboot().returncode, 0)
        self.assertEqual(self.run_script('cvl-set-sso-keys.sh', json.dumps({'keys': [key('a', 1)]})).returncode, 0)
        before = (self.etc / 'sso-keys.json').read_text()
        self.assertEqual(self.firstboot().returncode, 0)
        self.assertEqual((self.etc / 'sso-keys.json').read_text(), before)

    def test_a_directory_at_the_key_file_path_is_refused(self):
        (self.etc / 'sso-keys.json').mkdir(parents=True)
        done = self.firstboot()
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('is a directory', done.stderr)
        self.assertFalse((self.state / 'ready').exists())

    def test_the_env_gets_sso_off_defaults_and_nothing_is_enabled(self):
        self.assertEqual(self.firstboot().returncode, 0)
        env = self.env_file()
        self.assertEqual(env['CVENGINE_SSO'], '0')
        self.assertEqual(env['CVENGINE_SSO_ENFORCE'], '0')
        self.assertEqual(env['CVENGINE_SSO_ISSUER'], 'https://cvengine.live')
        self.assertEqual(env['CVENGINE_SSO_AUDIENCE'], 'https://s-abcd1234.cvengine.live')
        self.assertEqual((env['CVENGINE_SSO_MAX_AUTH_AGE'], env['CVENGINE_SSO_STEPUP_AGE']), ('43200', '900'))
        self.assertNotIn('CVENGINE_SSO_BREAKGLASS_UNTIL', env)

    def test_a_second_run_never_undoes_a_changed_mode(self):
        self.assertEqual(self.firstboot().returncode, 0)
        text = (self.repo / '.env').read_text().replace('CVENGINE_SSO=0', 'CVENGINE_SSO=1').replace('CVENGINE_SSO_ENFORCE=0', 'CVENGINE_SSO_ENFORCE=1')
        (self.repo / '.env').write_text(text + 'CVENGINE_SSO_BREAKGLASS_UNTIL=1\n')
        self.assertEqual(self.firstboot().returncode, 0)
        env = self.env_file()
        self.assertEqual((env['CVENGINE_SSO'], env['CVENGINE_SSO_ENFORCE'], env['CVENGINE_SSO_BREAKGLASS_UNTIL']), ('1', '1', '1'))


class SsoModeScriptTests(ScriptCase):
    NOW = 1_800_000_000

    def setUp(self):
        super().setUp()
        self.state.mkdir()
        (self.state / 'ready').write_text('x\n')
        self.write_env('CVENGINE_SSO=0\nCVENGINE_SSO_ENFORCE=0\n')

    def write_env(self, extra=''):
        (self.repo / '.env').write_text('CVENGINE_HOSTED=1\nCVENGINE_COMPOSE_FILES=docker-compose.yml,docker-compose.hosted.yml\nDOMAIN_NAME=s-abcd1234.cvengine.live\n' + extra)

    def install_keys(self, *keys):
        self.assertEqual(self.run_script('cvl-set-sso-keys.sh', json.dumps({'keys': list(keys)})).returncode, 0)

    def mode_cmd(self, *args, **extra):
        return self.run_script('cvl-sso-mode.sh', '', args, CVL_NOW=str(self.NOW), **extra)

    def recreations(self):
        return len(re.findall(r'up -d --no-deps --force-recreate web', self.log()))

    def refused(self, *args, **extra):
        before = (self.repo / '.env').read_text()
        recreated = self.recreations()
        done = self.mode_cmd(*args, **extra)
        self.assertNotEqual(done.returncode, 0, args)
        self.assertEqual(done.stdout, '', args)
        self.assertTrue(done.stderr.strip(), args)
        self.assertEqual((self.repo / '.env').read_text(), before, args)
        self.assertEqual(self.recreations(), recreated, args)
        return done

    def test_sso_on_edits_env_in_place_recreates_only_web_and_reports_json(self):
        inode = (self.repo / '.env').stat().st_ino
        done = self.mode_cmd('--sso', 'on')
        self.assertEqual((done.returncode, done.stdout), (0, '{"ok":true,"sso":true,"enforce":false,"breakglass_until":null}\n'), done.stderr)
        env = self.env_file()
        self.assertEqual((env['CVENGINE_SSO'], env['CVENGINE_SSO_ENFORCE']), ('1', '0'))
        self.assertEqual(((self.repo / '.env').stat().st_ino, self.mode(self.repo / '.env')), (inode, 0o600))
        self.assertEqual(self.recreations(), 1)
        self.assertNotRegex(self.log(), r'force-recreate (?!web)')
        self.assertIn('--no-deps', self.log())

    def test_a_repeat_changes_nothing_and_recreates_nothing(self):
        self.mode_cmd('--sso', 'on')
        before = (self.repo / '.env').read_text()
        done = self.mode_cmd('--sso', 'on')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual((self.repo / '.env').read_text(), before)
        self.assertEqual(self.recreations(), 1)

    def test_enforce_is_refused_unless_sso_is_on(self):
        self.refused('--enforce', 'on')
        self.install_keys(key('a', 1))
        self.refused('--enforce', 'on')  # keys alone are not enough
        self.refused('--sso', 'off', '--enforce', 'on')

    def test_enforce_is_refused_with_no_keys_or_an_unreadable_key_file(self):
        self.mode_cmd('--sso', 'on')
        done = self.refused('--enforce', 'on')  # no key file at all
        self.assertIn('key set', done.stderr)
        self.install_keys()
        self.refused('--enforce', 'on')  # the empty set
        (self.etc / 'sso-keys.json').write_text('garbage')
        self.refused('--enforce', 'on')
        self.refused('--sso', 'on', '--enforce', 'on')

    def test_enforce_on_with_sso_and_a_key_works_alone_or_in_one_command(self):
        self.install_keys(key('a', 1))
        self.assertEqual(self.mode_cmd('--sso', 'on', '--enforce', 'on').stdout, '{"ok":true,"sso":true,"enforce":true,"breakglass_until":null}\n')
        self.assertEqual((self.env_file()['CVENGINE_SSO'], self.env_file()['CVENGINE_SSO_ENFORCE']), ('1', '1'))
        self.assertEqual(self.mode_cmd('--enforce', 'off').stdout, '{"ok":true,"sso":true,"enforce":false,"breakglass_until":null}\n')
        self.assertEqual(self.mode_cmd('--enforce', 'on').returncode, 0)

    def test_sso_off_also_turns_enforcement_and_breakglass_off(self):
        self.install_keys(key('a', 1))
        self.mode_cmd('--sso', 'on', '--enforce', 'on', '--breakglass', '10')
        done = self.mode_cmd('--sso', 'off')
        self.assertEqual(done.stdout, '{"ok":true,"sso":false,"enforce":false,"breakglass_until":null}\n', done.stderr)
        env = self.env_file()
        self.assertEqual((env['CVENGINE_SSO'], env['CVENGINE_SSO_ENFORCE']), ('0', '0'))
        self.assertNotIn('CVENGINE_SSO_BREAKGLASS_UNTIL', env)

    def test_breakglass_sets_a_window_of_at_most_an_hour(self):
        self.install_keys(key('a', 1))
        self.mode_cmd('--sso', 'on', '--enforce', 'on')
        done = self.mode_cmd('--breakglass', '30')
        self.assertEqual(done.stdout, f'{{"ok":true,"sso":true,"enforce":true,"breakglass_until":{self.NOW + 1800}}}\n', done.stderr)
        self.assertEqual(self.env_file()['CVENGINE_SSO_BREAKGLASS_UNTIL'], str(self.NOW + 1800))
        self.assertEqual(self.mode_cmd('--breakglass', '60').stdout.count(str(self.NOW + 3600)), 1)
        done = self.mode_cmd('--breakglass', 'off')
        self.assertEqual(done.stdout, '{"ok":true,"sso":true,"enforce":true,"breakglass_until":null}\n')
        self.assertNotIn('CVENGINE_SSO_BREAKGLASS_UNTIL', self.env_file())
        self.assertEqual(self.mode_cmd('--breakglass', 'off').returncode, 0)  # already off: fine

    def test_breakglass_outside_one_to_sixty_minutes_is_refused(self):
        self.mode_cmd('--sso', 'on')
        for bad in ('0', '00', '61', '100', '-5', '1.5', 'abc', '', '30m', '1e1', '+5', ' 5'):
            self.refused('--breakglass', bad)
        for good in ('1', '01', '9', '60'):
            self.assertEqual(self.mode_cmd('--breakglass', good).returncode, 0, good)

    def test_breakglass_needs_sso_on(self):
        self.refused('--breakglass', '10')
        self.refused('--sso', 'off', '--breakglass', '10')

    def test_a_window_that_has_passed_is_reported_as_closed(self):
        self.write_env(f'CVENGINE_SSO=1\nCVENGINE_SSO_ENFORCE=0\nCVENGINE_SSO_BREAKGLASS_UNTIL={self.NOW - 5}\n')
        self.assertEqual(self.mode_cmd('--sso', 'on').stdout, '{"ok":true,"sso":true,"enforce":false,"breakglass_until":null}\n')

    def test_usage_errors_change_nothing(self):
        for args in ((), ('--sso',), ('--sso', 'maybe'), ('--enforce', 'yes'), ('--sso', 'on', '--bogus', 'x'), ('on',), ('--sso', 'on', 'extra')):
            self.refused(*args)

    def test_a_server_that_is_not_ready_or_not_hosted_is_refused(self):
        (self.state / 'ready').unlink()
        self.refused('--sso', 'on')
        (self.state / 'ready').write_text('x')
        (self.repo / '.env').write_text('CVENGINE_SSO=0\n')
        self.refused('--sso', 'on')

    def test_a_web_service_that_does_not_come_back_is_an_error_without_stdout(self):
        done = self.mode_cmd('--sso', 'on', STUB_WEB_RC='1', CVL_WAIT_SECONDS='1', CVL_POLL_SECONDS='1')
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(done.stdout, '')

    def test_it_never_touches_other_env_lines_and_the_keys_are_not_logged(self):
        self.install_keys(key('a', 1))
        secret = (self.etc / 'sso-keys.json').read_text()
        self.write_env('CVENGINE_SSO=0\nCVENGINE_SSO_ENFORCE=0\nPOSTGRES_PASSWORD=pw123\nOTHER=a=b\n')
        done = self.mode_cmd('--sso', 'on', '--enforce', 'on')
        self.assertEqual(done.returncode, 0, done.stderr)
        env = self.env_file()
        self.assertEqual((env['POSTGRES_PASSWORD'], env['OTHER']), ('pw123', 'a=b'))
        self.assertNotIn(json.loads(secret)['keys'][0]['x'], done.stdout + done.stderr + self.log())


class SsoScriptHygieneTests(SimpleTestCase):
    def test_the_new_scripts_exist_are_executable_and_strict(self):
        for name in ('cvl-set-sso-keys.sh', 'cvl-sso-mode.sh'):
            path = HOSTED / name
            text = path.read_text()
            self.assertTrue(text.startswith('#!/usr/bin/env bash\n'), name)
            self.assertIn('set -euo pipefail', text)
            self.assertTrue(os.access(path, os.X_OK), name)

    def test_the_new_scripts_are_shellcheck_clean(self):
        shellcheck = shutil.which('shellcheck')
        if not shellcheck:
            if os.environ.get('CI'):
                self.fail('CI is set but shellcheck is not installed')
            self.skipTest('shellcheck is not installed')
        files = [str(HOSTED / n) for n in ('cvl-set-sso-keys.sh', 'cvl-sso-mode.sh', 'cvl-personalize.sh', 'cvl-firstboot.sh', 'lib/common.sh')]
        result = subprocess.run([shellcheck, '-x', '-S', 'style', *files], capture_output=True, text=True, cwd=HOSTED)
        self.assertEqual(result.returncode, 0, result.stdout)
