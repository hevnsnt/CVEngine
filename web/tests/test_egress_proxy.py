"""Settings > Proxy applied to the scans that run on this server: the helper, each integration point, the pinned transport's proxy path
(the SSRF decision stays), a live run against a tiny forward-proxy fixture, and the encrypted storage."""
import http.server
import importlib
import os
import shutil
import socket
import socketserver
import ssl
import struct
import tempfile
import threading
import time
import unittest
from unittest import mock

from django.db import connection
from django.test import SimpleTestCase, TestCase

from cveFeed import db_exposure, egress_proxy, nuclei_scan, pinned_transport as transport, route_auth, testssl_scan, waf_scan, wpscan_scan
from reNgine import bbot, crypto_fields
from scanEngine.models import Proxy

HTTP_PROXY = 'http://203.0.113.50:3128'
SOCKS_PROXY = 'socks5://203.0.113.51:1080'
LOGIN_PROXY = 'http://bob:hunter2@203.0.113.52:3128'


def spec(line):
    parsed = egress_proxy.parse(line)
    assert parsed is not None, line
    return parsed


def answer(ip, port, family=socket.AF_INET):
    address = (ip, port) if family == socket.AF_INET else (ip, port, 0, 0)
    return family, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', address


def fake_dns(table):
    """A ``getaddrinfo`` that answers names from ``table`` and leaves every other lookup (the loopback proxy fixture) to the real one."""
    real = socket.getaddrinfo

    def lookup(host, port, *args, **kwargs):
        if host in table:
            return [answer(table[host], int(port))]
        return real(host, port, *args, **kwargs)
    return lookup


def clean_environment(case):
    """No bypass list from the machine running the tests (a CI or sandbox NO_PROXY would hide what the cases check)."""
    patcher = mock.patch.dict(os.environ)
    patcher.start()
    case.addCleanup(patcher.stop)
    for name in ('CVENGINE_PROXY_BYPASS', 'NO_PROXY', 'no_proxy', 'CELERY_BROKER', 'CELERY_BACKEND', 'POSTGRES_HOST'):
        os.environ.pop(name, None)


class ProxyOn:
    """Mixin: a stored Settings > Proxy row, and a cache that never leaks from one test to the next."""
    def setUp(self):
        clean_environment(self)
        egress_proxy.reset_cache()
        self.addCleanup(egress_proxy.reset_cache)

    def turn_on(self, *lines, use=True):
        Proxy.objects.all().delete()
        Proxy.objects.create(use_proxy=use, proxies='\n'.join(lines))
        egress_proxy.reset_cache()


class ParseTests(SimpleTestCase):
    def test_the_four_schemes_parse_with_default_ports_and_a_login(self):
        self.assertEqual((spec('http://203.0.113.1:8080').scheme, spec('http://203.0.113.1:8080').port), ('http', 8080))
        self.assertEqual(spec('https://p.example.com').port, 443)
        self.assertEqual(spec('socks5://p.example.com').port, 1080)
        self.assertEqual(spec('SOCKS5H://P.example.com:9050').scheme, 'socks5h')
        login = spec('http://bob:p%40ss@203.0.113.1:8080/')
        self.assertEqual((login.username, login.password, login.url), ('bob', 'p@ss', 'http://bob:p%40ss@203.0.113.1:8080'))

    def test_anything_else_is_skipped(self):
        for bad in ('', ' ', 'socks4://203.0.113.1:1080', 'ftp://203.0.113.1', 'file:///etc/passwd', 'not a proxy', 'http://', 'http://:8080',
                    'http://203.0.113.1:99999', 'http://203.0.113.1:0', 'http://203.0.113.1:8080/path', 'http://203.0.113.1:8080?x=1',
                    'http://203.0.113.1:8080 extra', 'http://u:p\r\nX: y@203.0.113.1:8080', 'http://' + 'a' * 500 + ':80'):
            self.assertIsNone(egress_proxy.parse(bad), bad)

    def test_a_spec_never_shows_its_password(self):
        s = spec(LOGIN_PROXY)
        for text in (repr(s), str(s), egress_proxy.describe(s), f'{s}', '%s' % (s,)):
            self.assertNotIn('hunter2', text)
        self.assertEqual(egress_proxy.describe(s), 'http://203.0.113.52:3128 (with login)')


class BypassTests(SimpleTestCase):
    def setUp(self):
        clean_environment(self)

    def test_loopback_localhost_and_the_stack_never_go_through_a_proxy(self):
        for host in ('127.0.0.1', '127.8.8.8', '::1', '[::1]', 'localhost', 'app.localhost', 'LOCALHOST.', 'redis', 'db', 'web', 'celery', 'celery-beat',
                     '0.0.0.0', ''):
            self.assertTrue(egress_proxy.bypass(host), host)
        for host in ('203.0.113.5', 'www.example.com', '2001:db8::1', 'redis.example.com'):
            self.assertFalse(egress_proxy.bypass(host), host)

    def test_private_link_local_and_tailnet_addresses_skip_the_proxy_unless_asked(self):
        private = ('10.0.0.5', '172.16.4.4', '192.168.1.9', '169.254.1.1', '100.100.1.1', 'fd00::5', 'fe80::1')
        for host in private:
            self.assertTrue(egress_proxy.bypass(host), host)
        with mock.patch.dict(os.environ, {'CVENGINE_PROXY_PRIVATE': '1'}):
            for host in private:
                self.assertFalse(egress_proxy.bypass(host), host)
            self.assertTrue(egress_proxy.bypass('127.0.0.1'))

    def test_the_stack_hosts_of_the_environment_are_included(self):
        with mock.patch.dict(os.environ, {'CELERY_BROKER': 'redis://:pw@cache.internal:6379/0', 'POSTGRES_HOST': 'pg.internal'}):
            self.assertTrue(egress_proxy.bypass('cache.internal'))
            self.assertTrue(egress_proxy.bypass('pg.internal'))
        with mock.patch.dict(os.environ, {'POSTGRES_HOST': '/var/run/postgresql'}):
            self.assertFalse(egress_proxy.bypass('/var/run/postgresql'.strip('/')))

    def test_the_operators_list_takes_names_suffixes_ips_and_ranges(self):
        with mock.patch.dict(os.environ, {'CVENGINE_PROXY_BYPASS': 'lab.example.com, .corp.example.com ,10.0.0.0/8,192.0.2.7', 'NO_PROXY': '*.intranet.example'}):
            for host in ('lab.example.com', 'x.lab.example.com', 'a.corp.example.com', '10.9.8.7', '192.0.2.7', 'h.intranet.example'):
                self.assertTrue(egress_proxy.bypass(host), host)
            for host in ('example.com', 'notlab.example.com', '11.0.0.1', '192.0.2.8'):
                self.assertFalse(egress_proxy.bypass(host), host)


class SelectionTests(ProxyOn, TestCase):
    def test_off_means_direct_and_a_row_with_only_bad_lines_is_off(self):
        self.assertIsNone(egress_proxy.pick('www.example.com'))
        self.assertEqual(egress_proxy.requests_proxies('www.example.com'), {})
        self.turn_on(HTTP_PROXY, use=False)
        self.assertIsNone(egress_proxy.pick('www.example.com'))
        self.turn_on('socks4://203.0.113.1:1080', 'garbage')
        self.assertIsNone(egress_proxy.pick('www.example.com'))
        self.assertFalse(egress_proxy.enabled())

    def test_round_robin_over_the_valid_lines_and_bad_lines_are_skipped(self):
        self.turn_on(HTTP_PROXY, 'garbage', SOCKS_PROXY, 'socks4://203.0.113.9:1')
        seen = [egress_proxy.pick('www.example.com').plain_url for _ in range(6)]
        self.assertEqual(set(seen), {HTTP_PROXY, SOCKS_PROXY})
        self.assertEqual(seen[0::2].count(seen[0]), 3)  # alternates
        self.assertNotEqual(seen[0], seen[1])

    def test_a_bypassed_destination_is_direct(self):
        self.turn_on(HTTP_PROXY)
        self.assertIsNone(egress_proxy.pick('127.0.0.1'))
        self.assertEqual(egress_proxy.requests_proxies('localhost'), {})
        self.assertEqual(egress_proxy.requests_proxies('www.example.com'), {'http': HTTP_PROXY, 'https': HTTP_PROXY})

    def test_a_proxy_no_client_can_use_fails_closed(self):
        self.turn_on('https://203.0.113.5:443')
        with self.assertRaises(egress_proxy.ProxyUnavailable):
            egress_proxy.pick('www.example.com', schemes=egress_proxy.IN_PROCESS_SCHEMES)
        self.assertEqual(egress_proxy.pick('www.example.com').scheme, 'https')

    def test_the_setting_is_cached_for_a_few_seconds_not_read_per_call(self):
        self.turn_on(HTTP_PROXY)
        with self.assertNumQueries(1):
            for _ in range(20):
                egress_proxy.pick('www.example.com')
        Proxy.objects.update(use_proxy=False)
        self.assertIsNotNone(egress_proxy.pick('www.example.com'))  # still the cached answer
        with mock.patch('cveFeed.egress_proxy.time.monotonic', return_value=time.monotonic() + egress_proxy.CACHE_SECONDS + 1):
            self.assertIsNone(egress_proxy.pick('www.example.com'))
        egress_proxy.reset_cache()
        self.assertIsNone(egress_proxy.pick('www.example.com'))

    def test_a_database_failure_keeps_the_last_known_setting_and_logs_no_url(self):
        self.turn_on(LOGIN_PROXY)
        self.assertTrue(egress_proxy.enabled())
        with mock.patch('cveFeed.egress_proxy.time.monotonic', return_value=time.monotonic() + 60), \
                mock.patch('cveFeed.egress_proxy._load', side_effect=RuntimeError('boom hunter2')), \
                self.assertLogs('cveFeed.egress_proxy', level='WARNING') as logs:
            self.assertTrue(egress_proxy.enabled())
        self.assertNotIn('hunter2', '\n'.join(logs.output))


class ToolFragmentTests(ProxyOn, TestCase):
    def test_direct_when_off_or_when_every_destination_is_loopback(self):
        for tool in egress_proxy.TOOLS:
            self.assertEqual(egress_proxy.for_tool(tool), [])
        self.turn_on(HTTP_PROXY)
        self.assertEqual(egress_proxy.for_tool('nuclei', ['127.0.0.1:8080', 'http://localhost:9']), [])
        self.assertEqual(egress_proxy.for_tool('nuclei', ['127.0.0.1:8080', 'www.example.com']), ['-proxy', HTTP_PROXY])

    def test_each_tool_gets_its_own_arguments(self):
        self.turn_on(LOGIN_PROXY)
        self.assertEqual(egress_proxy.for_tool('nuclei', ['www.example.com']), ['-proxy', LOGIN_PROXY])
        self.assertEqual(egress_proxy.for_tool('wafw00f', ['www.example.com']), ['-p', LOGIN_PROXY])
        self.assertEqual(egress_proxy.for_tool('wpscan', ['www.example.com']), ['--proxy', 'http://203.0.113.52:3128', '--proxy-auth', 'bob:hunter2'])
        self.assertEqual(egress_proxy.for_tool('bbot'), ['-c', f'web.http_proxy={LOGIN_PROXY}'])

    def test_testssl_takes_a_plain_http_proxy_only(self):
        self.turn_on(LOGIN_PROXY, SOCKS_PROXY)
        with self.assertRaises(egress_proxy.ProxyUnavailable):
            egress_proxy.for_tool('testssl', ['www.example.com'])
        self.turn_on(LOGIN_PROXY, HTTP_PROXY)
        self.assertEqual(egress_proxy.for_tool('testssl', ['www.example.com']), ['--proxy', '203.0.113.50:3128'])

    def test_a_tool_that_cannot_use_any_proxy_fails_closed(self):
        self.turn_on('socks5h://203.0.113.5:1080')
        with self.assertRaises(egress_proxy.ProxyUnavailable) as raised:
            egress_proxy.for_tool('nuclei', ['www.example.com'])
        self.assertNotIn('203.0.113.5', str(raised.exception))
        self.assertEqual(egress_proxy.for_tool('wpscan', ['www.example.com'])[0], '--proxy')


class IntegrationTests(ProxyOn, TestCase):
    def test_argv_builders_add_the_proxy_only_when_given(self):
        self.assertNotIn('-proxy', nuclei_scan.build_flags())
        self.assertEqual(nuclei_scan.build_flags(proxy_args=['-proxy', HTTP_PROXY])[-2:], ['-proxy', HTTP_PROXY])
        self.assertNotIn('--proxy', wpscan_scan.wpscan_args(600))
        self.assertEqual(wpscan_scan.wpscan_args(600, proxy_args=['--proxy', HTTP_PROXY])[-2:], ['--proxy', HTTP_PROXY])
        self.assertNotIn('--proxy', testssl_scan.command('a.example.com', '203.0.113.5', 443, None, '/tmp/x'))
        args = testssl_scan.command('a.example.com', '203.0.113.5', 443, None, '/tmp/x', ['--proxy', '203.0.113.50:3128'])
        self.assertEqual((args[args.index('--proxy') + 1], args[-1]), ('203.0.113.50:3128', 'a.example.com:443'))

    def run_nuclei(self, hosts):
        path = tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False)
        self.addCleanup(os.unlink, path.name)
        path.write('\n'.join(hosts) + '\n')
        path.close()
        captured = {}

        class Stop(Exception):
            pass

        def popen(argv, **kwargs):
            captured['argv'] = argv
            raise Stop

        with mock.patch.object(nuclei_scan.subprocess, 'Popen', popen), \
                mock.patch.object(nuclei_scan, 'approved_templates', return_value=('/tmp/templates', None, None)):
            try:
                list(nuclei_scan.stream_nuclei(path.name))
            except Stop:
                pass
        return captured.get('argv')

    def test_nuclei_runs_through_the_proxy_when_on_and_directly_when_off(self):
        self.assertNotIn('-proxy', self.run_nuclei(['www.example.com']))
        self.turn_on(HTTP_PROXY, use=False)
        self.assertNotIn('-proxy', self.run_nuclei(['www.example.com']))
        self.turn_on(HTTP_PROXY)
        argv = self.run_nuclei(['www.example.com', '203.0.113.9:8443'])
        self.assertEqual(argv[argv.index('-proxy') + 1], HTTP_PROXY)
        self.assertNotIn('-proxy', self.run_nuclei(['127.0.0.1:8080']))  # a loopback fixture stays local
        self.turn_on('socks5h://203.0.113.5:1080')
        with self.assertRaises(egress_proxy.ProxyUnavailable):  # never a direct run behind the administrator's back
            self.run_nuclei(['www.example.com'])

    def test_wafw00f_wpscan_and_testssl_runs(self):
        from cveFeed import heavy_process
        seen = []

        def fake_run(kind, argv, timeout, **kwargs):
            seen.append(argv)
            out = argv[argv.index('-o') + 1] if '-o' in argv else None
            if out:
                with open(out, 'w') as handle:
                    handle.write('[]')
            return mock.Mock(returncode=0, stderr='')

        with mock.patch.object(heavy_process, 'run', fake_run):
            waf_scan.run_wafw00f('https://www.example.com/')
            self.assertNotIn('-p', seen[-1])
            self.turn_on(HTTP_PROXY)
            waf_scan.run_wafw00f('https://www.example.com/')
            self.assertEqual((seen[-1][seen[-1].index('-p') + 1], seen[-1][-1]), (HTTP_PROXY, 'https://www.example.com/'))
            waf_scan.run_wafw00f('http://127.0.0.1:8080/')
            self.assertNotIn('-p', seen[-1])
            self.turn_on('socks5h://203.0.113.5:1080')
            self.assertIn('cannot use', waf_scan.run_wafw00f('https://www.example.com/')['error'])
            self.turn_on(LOGIN_PROXY)
            try:
                wpscan_scan.run_wpscan_process('https://www.example.com/', '', timeout=120)
            except Exception:  # the fake wrote no report: only the arguments matter here
                pass
            wp = seen[-1]
            self.assertEqual((wp[wp.index('--proxy') + 1], wp[wp.index('--proxy-auth') + 1]), ('http://203.0.113.52:3128', 'bob:hunter2'))
            self.turn_on(SOCKS_PROXY)
            with self.assertRaises(testssl_scan.TestsslError) as raised:
                testssl_scan.run_testssl('www.example.com', '203.0.113.5', 443)
            self.assertIn('testssl', str(raised.exception))

        captured = []
        self.turn_on(HTTP_PROXY)
        with self.assertRaises(testssl_scan.TestsslError):
            testssl_scan.run_testssl('www.example.com', '203.0.113.5', 443, runner=lambda args, env, timeout: captured.append(args))
        self.assertEqual(captured[0][captured[0].index('--proxy') + 1], '203.0.113.50:3128')  # a runner that writes no report: only the args matter

    def test_bbot_gets_the_proxy_in_its_private_config_file_never_on_the_command_line(self):
        seen = {}

        def fake(targets, presets, mode, timeout, extra_args, **kwargs):
            seen['args'] = list(extra_args)
            seen['secrets'] = kwargs.get('secrets')
            seen['file'] = None
            if bbot.PRESET_FLAG in extra_args:
                path = extra_args[extra_args.index(bbot.PRESET_FLAG) + 1]
                seen['mode'] = oct(os.stat(path).st_mode & 0o777)
                with open(path) as handle:
                    seen['file'] = handle.read()
            return iter(())

        with mock.patch.object(bbot, '_stream_events', fake):
            list(bbot.stream_events(['example.com']))
            self.assertEqual((seen['args'], seen['file']), ([], None))  # off: nothing added, no preset file
            self.turn_on(LOGIN_PROXY)
            list(bbot.stream_events(['example.com'], extra_args=['-c', 'modules.shodan_dns.api_key=abc123']))
        self.assertNotIn('hunter2', ' '.join(seen['args']))
        self.assertNotIn('web.http_proxy', ' '.join(seen['args']))
        self.assertIn('http_proxy: http://bob:hunter2@203.0.113.52:3128', seen['file'])
        self.assertIn('api_key: abc123', seen['file'])
        self.assertEqual(seen['mode'], '0o600')
        self.assertIn(LOGIN_PROXY, seen['secrets'])  # redacted from bbot's error output like an API key


# ----------------------------------------------------------------------------- a tiny forward proxy that records what it is asked

ORIGIN_BODY = b'<html><head><title>origin behind the proxy</title></head><body>hello</body></html>'


def origin_response():
    return b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: origin-fixture\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % len(ORIGIN_BODY) + ORIGIN_BODY


def read_head(stream):
    head = b''
    while not head.endswith(b'\r\n\r\n'):
        byte = stream.recv(1)
        if not byte:
            break
        head += byte
    return head.decode('latin-1')


class ForwardProxy:
    """HTTP (CONNECT and absolute-URI) or SOCKS5 proxy on loopback. It records every request line and header, then answers the way the origin
    behind it would, so a probe that went through it gets a normal page and the test sees exactly what the proxy was asked for."""

    def __init__(self, kind='http', login=None, certificate=None):
        self.kind, self.login, self.certificate = kind, login, certificate
        self.records = []  # one dict per request seen
        fixture = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    (fixture._socks if fixture.kind == 'socks5' else fixture._http)(self.request)
                except (OSError, ssl.SSLError):
                    pass

        self.server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.url_without_login = f'{kind}://127.0.0.1:{self.port}'
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def _serve_origin(self, conn, record):
        if self.certificate:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(*self.certificate)
            context.sni_callback = lambda _sock, name, _context: record.__setitem__('sni', name)
            conn = context.wrap_socket(conn, server_side=True)
        record['origin_request'] = read_head(conn)
        conn.sendall(origin_response())

    def _http(self, conn):
        head = read_head(conn)
        lines = head.split('\r\n')
        record = {'line': lines[0], 'headers': {k.lower(): v for k, _, v in (ln.partition(': ') for ln in lines[1:] if ': ' in ln)}}
        self.records.append(record)
        if self.login and record['headers'].get('proxy-authorization') != self.login:
            conn.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n')
            return
        if lines[0].startswith('CONNECT '):
            conn.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
            self._serve_origin(conn, record)
        else:
            conn.sendall(origin_response())

    def _socks(self, conn):
        record = {'kind': 'socks5'}
        self.records.append(record)
        count = conn.recv(2)[1]
        methods = conn.recv(count)
        if self.login:
            if 2 not in methods:
                conn.sendall(b'\x05\xff')
                return
            conn.sendall(b'\x05\x02')
            conn.recv(1)
            user = conn.recv(conn.recv(1)[0]).decode()
            password = conn.recv(conn.recv(1)[0]).decode()
            record['login'] = f'{user}:{password}'
            if record['login'] != self.login:
                conn.sendall(b'\x01\x01')
                return
            conn.sendall(b'\x01\x00')
        else:
            conn.sendall(b'\x05\x00')
        _version, _command, _reserved, kind = conn.recv(4)
        host = socket.inet_ntop(socket.AF_INET if kind == 1 else socket.AF_INET6, conn.recv(4 if kind == 1 else 16))
        port = struct.unpack('>H', conn.recv(2))[0]
        record['destination'] = (host, port)
        conn.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        self._serve_origin(conn, record)


def self_signed(directory):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'app.example.test')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=2)).sign(key, hashes.SHA256()))
    cert_path, key_path = os.path.join(directory, 'cert.pem'), os.path.join(directory, 'key.pem')
    with open(cert_path, 'wb') as handle:
        handle.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, 'wb') as handle:
        handle.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_path, key_path


class LiveProxyTests(ProxyOn, TestCase):
    """A real probe, real sockets, a real proxy process-in-a-thread: the traffic must arrive at the proxy, addressed to the vetted IP."""
    DNS = {'app.example.test': '203.0.113.10'}

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.directory = tempfile.mkdtemp(prefix='egress-test-')
        cls.certificate = self_signed(cls.directory)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.directory, ignore_errors=True)
        super().tearDownClass()

    def proxy(self, **kwargs):
        fixture = ForwardProxy(**kwargs)
        self.addCleanup(fixture.close)
        return fixture

    def probe(self, url, **kwargs):
        with mock.patch.object(socket, 'getaddrinfo', fake_dns(self.DNS)):
            return route_auth.probe_url(url, **kwargs)

    def test_plain_http_goes_to_the_proxy_as_an_absolute_uri_for_the_vetted_address_with_the_original_host(self):
        fixture = self.proxy()
        self.turn_on(fixture.url_without_login)
        page = self.probe('http://app.example.test:8080/admin?x=1')
        self.assertEqual((page['status'], page['title'], page['server']), (200, 'origin behind the proxy', 'origin-fixture'))
        record = fixture.records[0]
        self.assertEqual(record['line'], 'GET http://203.0.113.10:8080/admin?x=1 HTTP/1.1')  # the numeric address that was vetted, never the name
        self.assertEqual(record['headers']['host'], 'app.example.test:8080')
        self.assertNotIn('proxy-authorization', record['headers'])

    def test_https_is_a_connect_to_the_vetted_address_with_the_original_sni_and_host(self):
        fixture = self.proxy(certificate=self.certificate)
        self.turn_on(fixture.url_without_login)
        page = self.probe('https://app.example.test/login')
        self.assertEqual((page['status'], page['title']), (200, 'origin behind the proxy'))
        record = fixture.records[0]
        self.assertEqual(record['line'], 'CONNECT 203.0.113.10:443 HTTP/1.1')
        self.assertIn('Host: app.example.test', record['origin_request'])
        self.assertIn('GET /login HTTP/1.1', record['origin_request'])
        self.assertEqual(record['sni'], 'app.example.test')

    def test_a_proxy_login_is_sent_to_the_proxy_and_a_wrong_one_is_a_failure_not_a_page(self):
        import base64
        good = 'Basic ' + base64.b64encode(b'bob:hunter2').decode()
        fixture = self.proxy(login=good)
        self.turn_on(fixture.url_without_login.replace('http://', 'http://bob:hunter2@'))
        self.assertEqual(self.probe('http://app.example.test/')['status'], 200)
        self.assertEqual(fixture.records[0]['headers']['proxy-authorization'], good)
        self.turn_on(fixture.url_without_login.replace('http://', 'http://bob:wrong@'))
        with self.assertRaises(OSError) as raised:
            self.probe('http://app.example.test/')
        self.assertNotIn('wrong', str(raised.exception))
        fixture = self.proxy(certificate=self.certificate, login=good)
        self.turn_on(fixture.url_without_login.replace('http://', 'http://bob:hunter2@'))
        self.assertEqual(self.probe('https://app.example.test/')['status'], 200)
        self.assertEqual(fixture.records[0]['headers']['proxy-authorization'], good)
        self.turn_on(fixture.url_without_login)  # no login at all: the proxy refuses the tunnel
        with self.assertRaises(OSError) as raised:
            self.probe('https://app.example.test/')
        self.assertIn('status 407', str(raised.exception))

    def test_socks5_tunnels_to_the_vetted_ip_with_and_without_a_login(self):
        fixture = self.proxy(kind='socks5')
        self.turn_on(fixture.url_without_login)
        self.assertEqual(self.probe('http://app.example.test:8080/x')['title'], 'origin behind the proxy')
        self.assertEqual(fixture.records[0]['destination'], ('203.0.113.10', 8080))
        self.assertIn('Host: app.example.test:8080', fixture.records[0]['origin_request'])
        fixture = self.proxy(kind='socks5', login='bob:hunter2', certificate=self.certificate)
        self.turn_on(fixture.url_without_login.replace('socks5://', 'socks5h://bob:hunter2@'))
        self.assertEqual(self.probe('https://app.example.test/')['status'], 200)
        self.assertEqual((fixture.records[0]['destination'], fixture.records[0]['login']), (('203.0.113.10', 443), 'bob:hunter2'))
        self.turn_on(fixture.url_without_login.replace('socks5://', 'socks5://bob:nope@'))
        with self.assertRaises(OSError):
            self.probe('https://app.example.test/')

    def test_ipv6_destinations_are_sent_as_numeric_addresses_too(self):
        fixture = self.proxy(kind='socks5')
        self.turn_on(fixture.url_without_login)
        real = socket.getaddrinfo

        def lookup(host, port, *args, **kwargs):
            if host == 'v6.example.test':
                return [answer('2001:db8::7', int(port), socket.AF_INET6)]
            return real(host, port, *args, **kwargs)
        with mock.patch.object(socket, 'getaddrinfo', lookup):
            route_auth.probe_url('http://v6.example.test/')
        self.assertEqual(fixture.records[0]['destination'], ('2001:db8::7', 80))

    def test_a_dead_proxy_fails_the_request_and_never_falls_back_to_a_direct_connection(self):
        dead = socket.socket()
        dead.bind(('127.0.0.1', 0))
        port = dead.getsockname()[1]
        dead.close()
        self.turn_on(f'http://127.0.0.1:{port}')
        connected = []
        real_connect = socket.socket.connect

        def spy(sock, address):
            connected.append(address)
            return real_connect(sock, address)
        with mock.patch.object(socket.socket, 'connect', spy):
            with self.assertRaises(OSError):
                self.probe('https://app.example.test/')
            with self.assertRaises(OSError):
                self.probe('http://app.example.test/')
        self.assertTrue(connected)
        self.assertTrue(all(address[0] == '127.0.0.1' for address in connected), connected)  # only the dead proxy was tried

    def test_loopback_fixtures_never_go_through_the_proxy(self):
        fixture = self.proxy()
        self.turn_on(fixture.url_without_login)

        class Origin(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(b'<title>local fixture</title>')

            def log_message(self, *args):
                pass
        origin = http.server.HTTPServer(('127.0.0.1', 0), Origin)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        self.addCleanup(origin.shutdown)
        with mock.patch.object(transport, 'is_scannable_ip', return_value=True):  # the gate refuses loopback; the fixture tests lift that
            page = route_auth.probe_url(f'http://127.0.0.1:{origin.server_port}/')
        self.assertEqual(page['title'], 'local fixture')
        self.assertEqual(fixture.records, [])

    def test_the_ssrf_decision_is_unchanged_a_prohibited_answer_never_reaches_the_proxy(self):
        fixture = self.proxy()
        self.turn_on(fixture.url_without_login)
        for ip in ('127.0.0.1', '169.254.169.254', '10.1.2.3'):
            with mock.patch.object(socket, 'getaddrinfo', fake_dns({'evil.example.test': ip})), self.assertRaises(ValueError):
                route_auth.probe_url('http://evil.example.test/')
        with mock.patch.object(socket, 'getaddrinfo', fake_dns({'mixed.example.test': '203.0.113.10'})):
            addresses = transport.resolve('mixed.example.test', 80)
        with mock.patch.object(transport, 'is_scannable_ip', return_value=False), self.assertRaises(ValueError):
            transport.open_socket(addresses, 3)  # re-vetted at connect: refused before any byte goes to the proxy
        with mock.patch.object(transport, 'is_scannable_ip', return_value=False), self.assertRaises(ValueError):
            transport.HTTPConnection('mixed.example.test', 80, addresses, 3).connect()
        self.assertEqual(fixture.records, [])
        with self.assertRaises(ValueError):  # the vetted connect_ip path too
            route_auth.probe_url('http://app.example.test/', connect_ip='169.254.169.254')
        self.assertEqual(fixture.records, [])

    def test_off_means_a_direct_connection_exactly_as_before(self):
        fixture = self.proxy()
        self.turn_on(fixture.url_without_login, use=False)
        sock = mock.Mock()
        with mock.patch.object(socket, 'getaddrinfo', fake_dns(self.DNS)), mock.patch.object(socket, 'socket', return_value=sock):
            addresses = transport.resolve('app.example.test', 443)
            self.assertIs(transport.open_socket(addresses, 3), sock)
        sock.connect.assert_called_once_with(('203.0.113.10', 443))
        self.assertEqual(fixture.records, [])

    def test_db_exposure_http_checks_use_the_proxy_through_requests(self):
        fixture = self.proxy()
        self.turn_on(fixture.url_without_login)
        body = b'{"cluster_name": "c1", "version": {"number": "8.1"}}'
        fixture_response = (b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % len(body)) + body
        with mock.patch(__name__ + '.origin_response', return_value=fixture_response):
            self.assertTrue(db_exposure.check_elasticsearch('203.0.113.20', 9200))
        self.assertEqual(fixture.records[0]['line'], 'GET http://203.0.113.20:9200/ HTTP/1.1')
        self.turn_on(fixture.url_without_login, use=False)
        with mock.patch('requests.sessions.Session.get', side_effect=OSError('direct')) as get:
            self.assertFalse(db_exposure.check_elasticsearch('203.0.113.20', 9200))
        self.assertEqual(get.call_args.kwargs['proxies'], {})

    @unittest.skipUnless(shutil.which('wafw00f'), 'wafw00f is not installed')
    def test_the_real_wafw00f_sends_its_requests_to_the_proxy(self):
        fixture = self.proxy()
        self.turn_on(fixture.url_without_login)
        result = waf_scan.run_wafw00f('http://203.0.113.9:8080/', timeout_s=60)
        self.assertEqual(result['error'], '')
        self.assertTrue(any(r['line'].startswith('GET http://203.0.113.9:8080/') for r in fixture.records), fixture.records[:3])


class PinnedForwardingUnitTests(ProxyOn, TestCase):
    def test_a_missing_host_header_still_names_the_original_host_not_the_ip(self):
        connection = transport.HTTPConnection('app.example.test', 8080, ((socket.AF_INET, ('203.0.113.10', 8080)),), 3)
        sent = []

        class Sock:
            def settimeout(self, value):
                pass

            def sendall(self, data):
                sent.append(data)

            def close(self):
                pass
        self.turn_on(HTTP_PROXY)
        with mock.patch.object(egress_proxy, 'connect_proxy', return_value=Sock()):
            connection.connect()
            connection.putrequest('GET', '/p')
            connection.endheaders()
        text = b''.join(sent).decode()
        self.assertTrue(text.startswith('GET http://203.0.113.10:8080/p HTTP/1.1\r\n'), text)
        self.assertIn('Host: app.example.test:8080', text)
        self.assertNotIn('Host: 203.0.113.10', text)

    def test_an_https_proxy_cannot_carry_the_in_process_checks_and_says_so(self):
        self.turn_on('https://203.0.113.5:443')
        with mock.patch.object(socket, 'socket') as direct, self.assertRaises(egress_proxy.ProxyUnavailable):
            transport.open_socket(((socket.AF_INET, ('203.0.113.10', 443)),), 3)
        direct.assert_not_called()


# ----------------------------------------------------------------------------- stored encrypted, masked on the way out

class StorageTests(ProxyOn, TestCase):
    def stored(self):
        with connection.cursor() as cursor:
            cursor.execute('SELECT proxies FROM "scanEngine_proxy" ORDER BY id LIMIT 1')
            return cursor.fetchone()[0]

    def test_the_list_is_encrypted_at_rest_and_read_back_in_clear(self):
        self.turn_on(LOGIN_PROXY, HTTP_PROXY)
        raw = self.stored()
        self.assertTrue(raw.startswith(crypto_fields.PREFIX))
        self.assertNotIn('hunter2', raw)
        self.assertEqual(Proxy.objects.get().proxies, f'{LOGIN_PROXY}\n{HTTP_PROXY}')
        self.assertEqual(len(egress_proxy.configured()), 2)

    def test_the_rotation_command_finds_the_field(self):
        self.assertIn(['proxies'], [names for model, names in crypto_fields.encrypted_fields() if model is Proxy])

    def test_the_migration_encrypts_existing_rows_and_reverses(self):
        migration = importlib.import_module('scanEngine.migrations.0006_encrypt_proxy_list')
        from django.apps import apps
        with connection.cursor() as cursor:
            cursor.execute('INSERT INTO "scanEngine_proxy" (use_proxy, proxies) VALUES (true, %s), (false, NULL), (false, %s)', [LOGIN_PROXY, ''])
        with connection.schema_editor() as editor:
            migration.encrypt_existing(apps, editor)
            with connection.cursor() as cursor:
                cursor.execute('SELECT proxies FROM "scanEngine_proxy" ORDER BY id')
                rows = [r[0] for r in cursor.fetchall()]
            self.assertTrue(rows[0].startswith(crypto_fields.PREFIX))
            self.assertEqual((rows[1], rows[2]), (None, ''))
            migration.encrypt_existing(apps, editor)  # running again leaves it encrypted once
            migration.decrypt_existing(apps, editor)
        self.assertEqual(self.stored(), LOGIN_PROXY)


class SettingsApplyTests(ProxyOn, TestCase):
    def setUp(self):
        super().setUp()
        from django.contrib.auth.models import User

        from tests.test_tenancy import client_for
        self.c = client_for(User.objects.create_superuser('proot', 'p@example.com', 'x'))

    def test_a_save_takes_effect_at_once_and_is_stored_encrypted(self):
        from tests.test_settings import send
        self.assertIsNone(egress_proxy.pick('www.example.com'))  # primes the cache with "off"
        self.assertEqual(send(self.c, 'PUT', 'proxy', {'use_proxy': True, 'proxies': 'http://bob:hunter2@203.0.113.5:8080'})[0], 200)
        self.assertEqual(egress_proxy.pick('www.example.com').url, 'http://bob:hunter2@203.0.113.5:8080')
        with connection.cursor() as cursor:
            cursor.execute('SELECT proxies FROM "scanEngine_proxy"')
            self.assertTrue(cursor.fetchone()[0].startswith(crypto_fields.PREFIX))
        send(self.c, 'PUT', 'proxy', {'use_proxy': False})
        self.assertIsNone(egress_proxy.pick('www.example.com'))

    def test_only_the_kinds_the_scanners_speak_are_accepted(self):
        from tests.test_settings import send
        for line in ('socks4://203.0.113.5:1080', 'socks4a://203.0.113.5:1080', 'http://203.0.113.5:8080/path', 'http://'):
            self.assertEqual(send(self.c, 'PUT', 'proxy', {'proxies': line})[0], 400, line)
        for line in ('http://203.0.113.5:8080', 'https://203.0.113.5:8443', 'socks5://203.0.113.5:1080', 'socks5h://u:p@203.0.113.5:1080'):
            self.assertEqual(send(self.c, 'PUT', 'proxy', {'proxies': line})[0], 200, line)
