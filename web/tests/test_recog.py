"""Rapid7 Recog on stored banners (cveFeed.recog, source_versions.recog_readings): the vendored data is the pinned commit, every fingerprint loaded
matches Recog's own example vectors, the Ruby patterns read the same in Python, catastrophic patterns are refused and the matcher stays fast;
each banner source cvENGINE stores becomes a ``vsrc:recog`` reading, never over a better first-party version; a Recog CPE is matched first; an
operating system is a hint unless it is a network operating system; ``vsource:recog`` and ``tech:`` find the readings; the update backfill."""
import hashlib
import importlib.util
import json
import tempfile
import time
from io import StringIO
from pathlib import Path
from unittest import mock

from django.core.management import call_command
from django.test import SimpleTestCase, TestCase

from cveFeed import correlation, recog, source_versions, upgrade_backfills, version_sources
from cveFeed.models import CVEEntry, CVEMatch, ProbeObservation, RouteAuth
from startScan.models import IpAddress, Port, Subdomain
from tests.test_source_versions import cve, names
from tests.test_version_sources import VersionFixture

ROOT = Path(__file__).resolve().parents[2]


def update_script():
    spec = importlib.util.spec_from_file_location('update_recog', ROOT / 'scripts' / 'update_recog.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DataTests(SimpleTestCase):
    def test_the_vendored_files_are_the_pinned_commit(self):
        manifest = json.loads((recog.DATA / 'manifest.json').read_text())
        self.assertRegex(manifest['commit'], r'^[0-9a-f]{40}$')
        self.assertEqual(manifest['license'], 'BSD-2-Clause')
        for name, digest in manifest['files'].items():
            self.assertEqual(hashlib.sha256((recog.DATA / name).read_bytes()).hexdigest(), digest, name)
        self.assertEqual(set(update_script().FILES), set(recog.DATABASES.values()))  # the refresh fetches exactly what the matcher reads
        self.assertTrue(set(recog.DATABASES.values()) | {'LICENSE', 'COPYING'} <= set(manifest['files']))
        self.assertIn(manifest['commit'], (recog.DATA / 'README.md').read_text())
        self.assertIn('Rapid7', (recog.DATA / 'COPYING').read_text())
        self.assertEqual(sorted(p.name for p in recog.DATA.glob('*.xml')), sorted(recog.DATABASES.values()))  # nothing unused is vendored

    def test_every_loaded_fingerprint_matches_its_own_examples(self):
        checked = 0
        for database, fingerprints in recog.databases().items():
            self.assertTrue(fingerprints, database)
            for fp in fingerprints:
                for text, expected in fp.examples:
                    got = fp.match(text[:recog.MAX_INPUT])
                    self.assertIsNotNone(got, (database, fp.pattern, text))
                    for key, value in expected.items():
                        self.assertEqual(got.get(key), value, (database, fp.pattern, text, key))
                    checked += 1
        self.assertGreater(checked, 2000)
        info = recog.stats()
        self.assertGreater(info['loaded'], 1900)
        self.assertLessEqual(sum(info['skipped'].values()), 20)  # the few refused are counted, never silently lost
        self.assertEqual(info['skipped'], {'backtracking': 2})

    def test_ruby_patterns_read_the_same_in_python(self):
        self.assertEqual(recog.translate(r'(?<ver>\d+)\h\z'), r'(?P<ver>\d+)[0-9a-fA-F]\Z')
        self.assertEqual(recog.translate(r'[[:digit:]\h]+\Z'), r'[0-9' + '0-9a-fA-F]+(?=\\n?\\Z)')
        self.assertEqual(recog.translate(r'(?m:a.b)'), r'(?s:a.b)')
        self.assertEqual(recog.translate(r'(?<=x)(?<!y)'), r'(?<=x)(?<!y)')
        self.assertIsNone(recog.translate(r'^a(?i)b'))  # a flag for the rest of the pattern, mid-pattern: no Python equivalent
        self.assertIsNone(recog.translate(r'\p{Alpha}'))
        # Ruby's ^ and $ match at every line; REG_DOT_NEWLINE lets the dot cross one
        fps, skipped = recog._load_file(self.xml('<fingerprint pattern="^b$" flags="REG_DOT_NEWLINE,REG_ICASE"><example>a\nB\nc</example>'
                                                 '<param pos="0" name="service.product" value="B"/></fingerprint>'
                                                 '<fingerprint pattern="a.c" flags="REG_DOT_NEWLINE"><example>a\nc</example></fingerprint>'
                                                 '<fingerprint pattern="a.c"><example>a\nc</example></fingerprint>'))
        self.assertEqual((len(fps), skipped), (2, {'examples': 1}))  # the last one's example does not match without the flag: not loaded

    def test_catastrophic_patterns_are_refused(self):
        for pattern in (r'(.+)*x', r'^(\w+\s?)+$', r'(a|b+)*c', r'(?:[ \t]+[^ \t]+)*$'):
            self.assertTrue(recog.risky(pattern), pattern)
        for pattern in (r'^gunicorn/(\d+(?:\.\d+)*)$', r'((?:\d+\.)*\d+)', r'(?:-[a-z]+)*', r'^([\d.]+)$'):
            self.assertFalse(recog.risky(pattern), pattern)
        fps, skipped = recog._load_file(self.xml('<fingerprint pattern="^(a+)+$"><example>aaa</example></fingerprint>'))
        self.assertEqual((fps, skipped), ([], {'backtracking': 1}))

    def test_input_is_clipped_and_nul_dropped(self):
        self.assertIsNone(recog.match('ssh.banner', ''))
        self.assertIsNone(recog.match('ssh.banner', None))
        got = recog.match('ssh.banner', 'OpenSSH_7.4\x00')
        self.assertEqual(got['service.version'], '7.4')
        self.assertIsNone(recog.match('ssh.banner', 'x' * 100000 + 'OpenSSH_7.4'))  # only MAX_INPUT characters are read

    def test_values_cpe_and_interpolation(self):
        got = recog.results(recog.match('ssh.banner', 'OpenSSH_9.6p1 Ubuntu-3ubuntu13.5'))
        self.assertEqual([(r['label'], r['vendor'], r['version'], r['cpe']) for r in got if r['part'] == 'service'],
                         [('OpenSSH', 'OpenBSD', '9.6p1', 'cpe:/a:openbsd:openssh:9.6p1')])
        got, = recog.results(recog.match('http_header.server', 'Microsoft-IIS/10.0'))
        self.assertEqual((got['label'], got['cpe']), ('Microsoft IIS', 'cpe:/a:microsoft:iis:10.0'))  # a generic product name keeps its vendor
        fps, _ = recog._load_file(self.xml('<fingerprint pattern="^x/?(\\d\\.\\d)?$"><example>x</example>'
                                           '<param pos="1" name="service.version"/><param pos="0" name="service.product" value="X"/>'
                                           '<param pos="0" name="service.cpe23" value="cpe:/a:x:x:{service.version}"/></fingerprint>'))
        self.assertEqual(fps[0].match('x/1.2')['service.cpe23'], 'cpe:/a:x:x:1.2')
        self.assertNotIn('service.cpe23', fps[0].match('x'))  # a CPE naming a param the match did not give is not stated

    def test_an_operating_system_is_a_network_os_only_by_name(self):
        ios, = [r for r in recog.results(recog.match('snmp.sys_description', 'Cisco IOS XR Software (ASR9K), Version 7.4.1  Copyright (c) '
                                                                                 '2013-2021 by Cisco Systems, Inc.')) if r['part'] == 'os']
        self.assertEqual((ios['label'], ios['version'], ios['network_os']), ('Cisco IOS XR', '7.4.1', True))
        linux = [r for r in recog.results(recog.match('mysql.banners', '5.7.33-0ubuntu0.18.04.1')) if r['part'] == 'os']
        self.assertEqual([(r['product'], r['network_os']) for r in linux], [('Linux', False)])

    def test_matching_a_thousand_banners_is_fast_once_loaded(self):
        recog.databases()
        samples = [('ssh.banner', 'OpenSSH_9.6p1 Ubuntu-3ubuntu13.5'), ('http_header.server', 'Apache/2.4.41 (Ubuntu)'),
                   ('http_header.server', 'nginx'), ('smtp.banner', 'mail.example.com ESMTP Postfix (Ubuntu)'),
                   ('ftp.banner', '(vsFTPd 3.0.3)'), ('snmp.sys_description', 'Linux web1 5.15.0-91-generic #101-Ubuntu SMP x86_64'),
                   ('snmp.sys_description', 'nothing any fingerprint knows ' * 30),  # every pattern of the largest database fails on it
                   ('http_header.server', 'a' * 5000), ('telnet.banner', ' ' * 2000 + '\n' * 200),
                   ('pop3.banner', 'x.example Cyrus POP3 v2.3.14 server ready'), ('mysql.banners', '8.0.35'),
                   ('http_header.cookie', 'PHPSESSID=' + '9' * 900)]
        start = time.monotonic()
        for i in range(1000):
            recog.match(*samples[i % len(samples)])
        self.assertLess(time.monotonic() - start, 10.0)  # about 2 ms for a banner no pattern matches

    def xml(self, body):
        handle = tempfile.NamedTemporaryFile('w', suffix='.xml', delete=False)
        handle.write(f'<?xml version="1.0"?><fingerprints matches="x">{body}</fingerprints>')
        handle.close()
        self.addCleanup(Path(handle.name).unlink)
        return handle.name


class TextTests(SimpleTestCase):
    """What each stored banner is handed to Recog as."""

    def port(self, number, banner='', service='', protocol='tcp', scripts=None):
        return Port(number=number, banner=banner, service_name=service, protocol=protocol, extra={'scripts': scripts} if scripts else {})

    def test_banners(self):
        cases = {
            ('SSH-2.0-OpenSSH_7.4', 22, 'ssh'): ('ssh.banner', 'OpenSSH_7.4'),
            ('220 foo.bar (IMail 12.4.2.27 21349-1) NT-ESMTP Server X1', 25, 'smtp'): ('smtp.banner', 'foo.bar (IMail 12.4.2.27 21349-1) NT-ESMTP Server X1'),
            ('220-mx.example ESMTP Exim 4.96\r\n220 hi', 2525, ''): ('smtp.banner', 'mx.example ESMTP Exim 4.96'),
            ('220 ProFTPD 1.3.5e Server (Debian) [::ffff:203.0.113.5]', 21, 'ftp'): ('ftp.banner', 'ProFTPD 1.3.5e Server (Debian) [::ffff:203.0.113.5]'),
            ('220 (vsFTPd 3.0.3)', 2121, ''): ('ftp.banner', '(vsFTPd 3.0.3)'),
            ('+OK Dovecot ready.', 110, 'pop3'): ('pop3.banner', 'Dovecot ready.'),
            ('* OK [CAPABILITY IMAP4rev1 STARTTLS] Dovecot ready.', 143, 'imap'): ('imap4.banner', 'Dovecot ready.'),
            ('MikroTik v6.42.3 (stable)\r\nLogin:', 23, 'telnet'): ('telnet.banner', 'MikroTik v6.42.3 (stable)\nLogin:'),
        }
        for (banner, number, service), want in cases.items():
            got = recog.banner_texts(self.port(number, banner, service))
            self.assertEqual([(db, text) for db, text, _said in got], [want], banner)
        self.assertEqual(recog.banner_texts(self.port(8080, 'HTTP/1.1 400 Bad Request', 'http')), [])

    def test_scripts(self):
        port = self.port(8080, scripts={
            'http-server-header': 'lighttpd/1.4.35',
            'http-headers': '\n  Server: Stronghold/4.0 Apache/1.3.22 (Unix)\n  Set-Cookie: ncentral_version=2026.3.0.5; Path=/\n'
                            '  Set-Cookie: PHPSESSID=x\n  (Request type: HEAD)',
            'mysql-info': '\n  Protocol: 10\n  Version: 5.7.33-0ubuntu0.18.04.1\n  Thread ID: 4',
            'ntp-info': '\n  receive time stamp: Tue Oct 27 10:00:00 2026\n  version: ntpd 4.2.8p15@1.3728-o Wed Sep 23 11:46:38 UTC 2020 (1)\n'
                        '  processor: x86_64\n  system: Linux/5.15.0'})
        got = [(db, text) for db, text, _said in recog.script_texts(port)]
        self.assertEqual(got[:5], [('http_header.server', 'lighttpd/1.4.35'), ('http_header.server', 'Stronghold/4.0 Apache/1.3.22 (Unix)'),
                                   ('http_header.cookie', 'ncentral_version=2026.3.0.5; Path=/'), ('http_header.cookie', 'PHPSESSID=x'),
                                   ('mysql.banners', '5.7.33-0ubuntu0.18.04.1')])
        self.assertEqual(got[5], ('ntp.banner', 'version="ntpd 4.2.8p15@1.3728-o Wed Sep 23 11:46:38 UTC 2020 (1)", processor="x86_64", '
                                                'system="Linux/5.15.0"'))
        snmp = self.port(161, protocol='udp', scripts={'snmp-sysdescr': 'Cisco IOS XR Software (ASR9K), Version 7.4.1\n  System uptime: 41d3h'})
        self.assertEqual([(db, text) for db, text, _s in recog.script_texts(snmp)], [('snmp.sys_description', 'Cisco IOS XR Software (ASR9K), Version 7.4.1')])

    def test_routes(self):
        got = recog.route_texts([{'server': 'lighttpd/1.4.35', 'headers': {'server': 'lighttpd/1.4.35'}, 'cookies': ['PHPSESSID', 'bad name;']},
                                 'not a dict'])
        self.assertEqual([(db, text) for db, text, _s in got], [('http_header.server', 'lighttpd/1.4.35'), ('http_header.cookie', 'PHPSESSID=')])


NTP_INFO = ('\n  receive time stamp: Tue Oct 27 10:00:00 2026\n  version: ntpd 4.2.8p15@1.3728-o Wed Sep 23 11:46:38 UTC 2020 (1)\n'
            '  processor: x86_64\n  system: Linux/5.15.0')


def recog_rows():
    return {(r.port, r.kind, r.product): r for r in ProbeObservation.objects.filter(probe=source_versions.RECOG_PROBE)}


class StoredBannerTests(VersionFixture, TestCase):
    """Each wired banner source, from a realistic stored row to a ``vsrc:recog`` reading."""

    def host(self, ports=(), webserver=''):
        scan = self.host_scan(web=False)
        ip = IpAddress.objects.get(address=self.ADDRESS)
        for kw in ports:
            ip.ports.add(Port.objects.create(state='open', **kw))
        sub = scan.subdomain_set.get()
        if webserver:
            sub.webserver = webserver
            sub.save(update_fields=['webserver'])
        return scan, self.fresh(sub)

    def fresh(self, sub):
        return Subdomain.objects.select_related('target_domain', 'scan_history').prefetch_related('technologies', 'ip_addresses__ports').get(pk=sub.pk)

    def test_every_wired_banner_source_becomes_a_reading(self):
        _scan, sub = self.host(ports=(
            {'number': 21, 'service_name': 'ftp', 'banner': '220 ProFTPD 1.3.5e Server (Debian) [::ffff:203.0.113.5]'},
            {'number': 22, 'service_name': 'ssh', 'product': 'OpenSSH', 'banner': 'SSH-2.0-OpenSSH_7.4'},  # nmap named it, without a version
            {'number': 25, 'service_name': 'smtp', 'banner': '220 foo.bar (IMail 12.4.2.27 21349-1) NT-ESMTP Server X1'},
            {'number': 110, 'service_name': 'pop3', 'banner': '+OK Lotus Notes POP3 server version Release 8.5.1FP5 ready on foo/US.'},
            {'number': 143, 'service_name': 'imap', 'banner': '* OK Microsoft Exchange Server 2003 IMAP4rev1 server version 6.5.7638.1 (foo.bar) ready.'},
            {'number': 23, 'service_name': 'telnet', 'banner': 'MikroTik v6.42.3 (stable)\r\nLogin:'},
            {'number': 8080, 'service_name': 'http', 'extra': {'scripts': {
                'http-server-header': 'lighttpd/1.4.35',
                'http-headers': '\n  Server: lighttpd/1.4.35\n  Set-Cookie: ncentral_version=2026.3.0.5; Path=/\n  (Request type: HEAD)'}}},
            {'number': 3306, 'service_name': 'mysql', 'product': 'MySQL', 'extra': {'scripts': {'mysql-info': '\n  Protocol: 10\n  Version: 5.7.33-0ubuntu0.18.04.1'}}},
            {'number': 123, 'protocol': 'udp', 'service_name': 'ntp', 'extra': {'scripts': {'ntp-info': NTP_INFO}}},
            {'number': 161, 'protocol': 'udp', 'service_name': 'snmp', 'extra': {'scripts': {
                'snmp-sysdescr': 'Cisco IOS XR Software (ASR9K), Version 7.4.1  Copyright (c) 2013-2021 by Cisco Systems, Inc.\n  System uptime: 41d'}}},
        ), webserver='Logitech Media Server (7.9.3 - 1586752599)')
        RouteAuth.objects.create(project=self.project, domain=self.domain, host='app.rt.test', url='https://app.rt.test:8443/', path='/',
                                 auth_state='open', evidence={'server': 'Boa/0.94.14rc21', 'cookies': []})
        version_sources.refresh_host(sub)
        got = {key: (r.version, r.evidence.get('cpe', '')) for key, r in recog_rows().items()}
        want = {
            (21, 'version', 'ProFTPD'): ('1.3.5e', 'cpe:/a:proftpd:proftpd:1.3.5e'),                      # ftp.banner
            (22, 'version', 'OpenSSH'): ('7.4', 'cpe:/a:openbsd:openssh:7.4'),                            # ssh.banner: nmap stated no version
            (25, 'version', 'IMail Server'): ('12.4.2.27', 'cpe:/a:ipswitch:imail_server:12.4.2.27'),     # smtp.banner
            (110, 'version', 'Lotus Domino'): ('8.5.1FP5', 'cpe:/a:ibm:lotus_domino:8.5.1FP5'),           # pop3.banner
            (143, 'version', 'Exchange 2003 Server'): ('6.5.7638.1', 'cpe:/a:microsoft:exchange_server:6.5.7638.1'),  # imap4.banner
            (23, 'version', 'RouterOS'): ('6.42.3', 'cpe:/o:mikrotik:routeros:6.42.3'),                   # telnet.banner: a network OS
            (8080, 'version', 'N-central'): ('2026.3.0.5', 'cpe:/a:n-able:n-central:2026.3.0.5'),         # http_header.cookie
            (3306, 'hint', 'Ubuntu Linux'): ('18.04', ''),                                                # mysql.banners: the OS, a hint
            (123, 'hint', 'Linux'): ('5.15.0', ''),                                                       # ntp.banner: the OS, a hint
            (161, 'version', 'Cisco IOS XR'): ('7.4.1', ''),                                              # snmp.sys_description: a network OS
            (0, 'version', 'Squeezebox'): ('7.9.3', ''),                                                  # http_header.server: Subdomain.webserver
            (0, 'version', 'Boa'): ('0.94.14rc21', 'cpe:/a:boa:boa:0.94.14rc21'),              # http_header.server: a live route
        }
        for key, value in want.items():
            self.assertEqual(got.get(key), value, key)
        # lighttpd: the http-server-header line is vsrc:nmap's reading already; MySQL: mysql-info's; NTP: nmap's port row would be; none twice
        self.assertNotIn((8080, 'version', 'lighttpd'), got)
        self.assertNotIn((3306, 'version', 'MySQL'), got)
        self.assertTrue({'ProFTPD:1.3.5e', 'OpenSSH:7.4', 'RouterOS:6.42.3', 'Cisco IOS XR:7.4.1'} <= names(sub))
        self.assertFalse({n for n in names(sub) if n.startswith(('Linux', 'Ubuntu'))})  # an operating system hint is never a technology
        evidence = recog_rows()[(21, 'version', 'ProFTPD')].evidence
        self.assertEqual((evidence['source'], evidence['version_source']), ('recog', True))
        self.assertIn('FTP banner: 220 ProFTPD', evidence['said'])
        self.assertIn('Recog ftp_banners.xml', evidence['said'])

    def test_a_recog_version_never_overrides_a_first_party_one(self):
        _scan, sub = self.host(ports=(
            {'number': 22, 'service_name': 'ssh', 'product': 'OpenSSH', 'version': '8.9p1', 'cpe': 'cpe:/a:openbsd:openssh:8.9p1',
             'banner': 'SSH-2.0-OpenSSH_8.9 Ubuntu-3ubuntu0.6'},  # nmap says 8.9p1: Recog's own reading of the banner gives way
            {'number': 21, 'service_name': 'ftp', 'product': 'ProFTPD', 'version': '1.3.6', 'banner': '220 ProFTPD 1.3.5e Server (Debian)'},
            {'number': 80, 'service_name': 'http', 'product': 'Apache httpd', 'version': '2.4.41'},
        ), webserver='Apache/2.4 (Ubuntu)')
        version_sources.refresh_host(sub)
        products = {(p, k) for (_n, k, p) in recog_rows()}
        self.assertNotIn(('OpenSSH', 'version'), products)
        self.assertNotIn(('ProFTPD', 'version'), products)
        self.assertNotIn(('Apache HTTPD', 'version'), products)
        self.assertNotIn('OpenSSH:8.9', names(sub))
        self.assertNotIn('ProFTPD:1.3.5e', names(sub))
        # another reader's reading of the same product (here vsrc:testssl's nginx) counts too
        _scan2, other = self.host(ports=({'number': 8443, 'service_name': 'https', 'extra': {'scripts': {'http-server-header': 'nginx/1.18.0'}}},))
        ProbeObservation.objects.create(project=self.project, domain=self.domain, host='app.rt.test', probe=source_versions.TESTSSL_PROBE, port=443,
                                        kind='version', product='nginx', version='1.20.1', outcome='found', evidence={'version_source': True})
        self.assertEqual(source_versions.recog_readings(other, version_sources._ports(other)), [])

    def test_a_reading_goes_when_the_banner_goes_and_a_refresh_is_stable(self):
        _scan, sub = self.host(ports=({'number': 21, 'service_name': 'ftp', 'banner': '220 (vsFTPd 3.0.3)'},))
        version_sources.refresh_host(sub)
        self.assertIn((21, 'version', 'vsFTPd'), recog_rows())
        version_sources.refresh_host(self.fresh(sub))  # its own technology (vsFTPd:3.0.3) never makes it give way to itself
        self.assertIn((21, 'version', 'vsFTPd'), recog_rows())
        Port.objects.filter(number=21).update(banner='')
        version_sources.refresh_host(self.fresh(sub))
        self.assertEqual(recog_rows(), {})

    def test_a_udp_sweep_reads_the_sysdescr_with_recog(self):
        self.host(ports=({'number': 161, 'protocol': 'udp', 'service_name': 'snmp', 'extra': {'scripts': {
            'snmp-sysdescr': 'Cisco IOS XR Software (ASR9K), Version 7.4.1  Copyright (c) 2013-2021 by Cisco Systems, Inc.'}}},))
        with mock.patch('cveFeed.udp_scan.finding_hosts', return_value=[(self.domain, 'app.rt.test')]), mock.patch('cveFeed.probes.recorrelate') as again:
            version_sources.refresh_snmp(IpAddress.objects.get(address=self.ADDRESS))
        self.assertIn((161, 'version', 'Cisco IOS XR'), recog_rows())
        again.assert_called_once()

    def test_the_recog_cpe_is_matched_first(self):
        row = cve('CVE-2026-310001', 'proftpd', 'proftpd', '1.3.5', '1.3.6')
        other = cve('CVE-2026-310002', 'someoneelse', 'proftpd', '1.3.5', '1.3.6')  # another vendor's "proftpd": the CPE's vendor rules it out
        scan, sub = self.host(ports=({'number': 21, 'service_name': 'ftp', 'banner': '220 ProFTPD 1.3.5e Server (Debian) [::ffff:203.0.113.5]'},))
        version_sources.refresh_host(sub)
        self.assertEqual(source_versions.technology_cpes(self.fresh(sub))['ProFTPD:1.3.5e'], 'cpe:/a:proftpd:proftpd:1.3.5e')
        cve_by_id, index = correlation.cve_pool()
        correlation.correlate_subdomains(list(correlation.candidate_subdomains(index).filter(scan_history=scan)), index, cve_by_id, min_confidence=0.4)
        match = CVEMatch.objects.get(cve_entry=row, source='tech')
        self.assertEqual((match.matched_version, match.evidence['cpe']), ('1.3.5e', 'cpe:/a:proftpd:proftpd:1.3.5e'))
        self.assertFalse(CVEMatch.objects.filter(cve_entry=other).exists())

    def test_an_os_hint_is_never_matched(self):
        CVEEntry.objects.create(cve_id='CVE-2026-310003', title='x', cvss=9.8, affected=[
            {'vendor': 'canonical', 'product': 'ubuntu_linux', 'ranges': [{'type': 'ECOSYSTEM', 'introduced': '18.04', 'fixed': '18.05'}]}])
        scan, sub = self.host(ports=({'number': 3306, 'service_name': 'mysql', 'product': 'MySQL',
                                      'extra': {'scripts': {'mysql-info': '  Version: 5.7.33-0ubuntu0.18.04.1'}}},))
        version_sources.refresh_host(sub)
        self.assertIn((3306, 'hint', 'Ubuntu Linux'), recog_rows())
        cve_by_id, index = correlation.cve_pool()
        correlation.correlate_subdomains(list(correlation.candidate_subdomains(index).filter(scan_history=scan)), index, cve_by_id, min_confidence=0.4)
        self.assertFalse(CVEMatch.objects.filter(cve_entry__cve_id='CVE-2026-310003').exists())

    def test_vsource_and_tech_search_find_the_readings(self):
        from agentapi import services
        _scan, sub = self.host(ports=({'number': 21, 'service_name': 'ftp', 'banner': '220 ProFTPD 1.3.5e Server (Debian) [::ffff:203.0.113.5]'},))
        version_sources.refresh_host(sub)
        self.assertEqual({r.product for r in version_sources.search_rows('vsource', 'recog')}, {'ProFTPD'})
        self.assertEqual(source_versions.SEARCH['recog'], source_versions.RECOG_PROBE)
        sub.technologies.clear()  # found through the reading itself, not only the technology it also made
        Port.objects.filter(number=21).update(banner='')  # nor the banner's text
        for q in ('proftpd', 'proftpd@1.3.5e', 'proftpd@known'):
            hits = set(Subdomain.objects.filter(services._term_filter('tech', q, self.project)).values_list('name', flat=True))
            self.assertEqual(hits, {'app.rt.test'}, q)
        hits = set(Subdomain.objects.filter(services._term_filter('tech', 'proftpd@1.3.6', self.project)).values_list('name', flat=True))
        self.assertEqual(hits, set())


class BackfillTests(VersionFixture, TestCase):
    def test_the_backfill_reads_stored_banners_and_correlates(self):
        row = cve('CVE-2026-310004', 'vsftpd_project', 'vsftpd', '3.0.0', '3.0.4')
        scan = self.host_scan(web=False)
        scan.scan_status = 2
        scan.save(update_fields=['scan_status'])
        IpAddress.objects.get(address=self.ADDRESS).ports.add(Port.objects.create(number=21, service_name='ftp', state='open', banner='220 (vsFTPd 3.0.3)'))
        self.assertEqual(source_versions.catch_up_recog(apply=False), {'hosts': 1, 'readings': 0, 'matches': 0})
        self.assertEqual(recog_rows(), {})
        out = source_versions.catch_up_recog(apply=True)
        self.assertEqual(out['readings'], 1)
        self.assertEqual(recog_rows()[(21, 'version', 'vsFTPd')].version, '3.0.3')
        match = CVEMatch.objects.get(cve_entry=row)
        self.assertEqual(match.evidence.get('cpe'), 'cpe:/a:vsftpd_project:vsftpd:3.0.3')
        source_versions.catch_up_recog(apply=True)  # idempotent
        self.assertEqual(ProbeObservation.objects.filter(probe=source_versions.RECOG_PROBE).count(), 1)
        self.assertEqual(CVEMatch.objects.filter(cve_entry=row).count(), 1)

    def test_it_is_registered_before_the_rescore_and_runs_as_a_command(self):
        self.assertIn('backfill_recog_readings', upgrade_backfills.BACKFILLS)
        self.assertLess(upgrade_backfills.BACKFILLS.index('backfill_source_versions'), upgrade_backfills.BACKFILLS.index('backfill_recog_readings'))
        self.assertLess(upgrade_backfills.BACKFILLS.index('backfill_recog_readings'), upgrade_backfills.BACKFILLS.index('rerate_findings'))
        out = StringIO()
        call_command('backfill_recog_readings', stdout=out)
        self.assertIn('Dry run', out.getvalue())
        self.assertIn('fingerprints loaded', out.getvalue())
