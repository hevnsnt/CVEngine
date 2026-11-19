"""The web service features (cveFeed.service_features with the Sentinel's probes.service_reads): HTTP/3, PHP on Windows, WebDAV, the VPN and
gateway portals, and SLP. The rules quote the advisories' own words; a reading rules a match out, raises it within the ceiling, or changes nothing."""
import datetime
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cvengine_scanner.probes import version_probes
from cveFeed import correlation, hygiene, probes, service_features
from cveFeed.detection_classes import feature_preconditions
from cveFeed.models import CVEEntry, CVEMatch, ServiceFeature, ServiceRun
from dashboard.models import Org, Project
from startScan.models import IpAddress, Port, Subdomain, Technology
from targetApp.models import Domain
from tests.fake_scanner import FakeScanner, assert_ran_nowhere_locally
from tests.test_route_auth import RouteFixture

# the advisories' own words, as the feed (the CNA's description) has them
NGINX_QUIC = ('CVE-2024-24989', 'When NGINX Plus or NGINX OSS are configured to use the HTTP/3 QUIC module, undisclosed requests can cause NGINX '
                                'worker processes to terminate.  Note: The HTTP/3 QUIC module is not enabled by default and is considered experimental.')
NGINX_QUIC_MTU = ('CVE-2024-34161', 'When NGINX Plus or NGINX OSS are configured to use the HTTP/3 QUIC module and the network infrastructure supports '
                                    'a Maximum Transmission Unit (MTU) of 4096 or greater without fragmentation, undisclosed QUIC packets can cause NGINX '
                                    'worker processes to leak previously freed memory.')
PHP_4577 = ('CVE-2024-4577', 'In PHP versions 8.1.* before 8.1.29, 8.2.* before 8.2.20, 8.3.* before 8.3.8, when using Apache and PHP-CGI on Windows, '
                             'if the system is set up to use certain code pages, Windows may use "Best-Fit" behavior to replace characters in command '
                             'line given to Win32 API functions.')
PHP_KEV = ('CVE-2024-4577', 'PHP, specifically Windows-based PHP used in CGI mode, contains an OS command injection vulnerability that allows for '
                            'arbitrary code execution.')
PHP_8926 = ('CVE-2024-8926', 'In PHP versions 8.1.* before 8.1.30, 8.2.* before 8.2.24, 8.3.* before 8.3.12, when using a certain non-standard '
                             'configurations of Windows codepages, the fixes for CVE-2024-4577 may still be bypassed and the same command injection '
                             'related to Windows "Best Fit" codepage behavior can be achieved.')
PHP_1823 = ('CVE-2012-1823', 'sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when configured as a CGI script (aka php-cgi), does '
                             'not properly handle query strings that lack an = (equals sign) character.')
IIS_7269 = ('CVE-2017-7269', 'Buffer overflow in the ScStoragePathFromUrl function in the WebDAV service in Internet Information Services (IIS) 6.0 '
                             'in Microsoft Windows Server 2003 R2 allows remote attackers to execute arbitrary code via a long header beginning with '
                             '"If: <http://" in a PROPFIND request.')
APACHE_DAV = ('CVE-2013-6438', 'The dav_xml_get_cdata function in main/util.c in the mod_dav module in the Apache HTTP Server before 2.4.8 does not '
                               'properly remove whitespace characters from CDATA sections, which allows remote attackers to cause a denial of service.')
APACHE_CACHE_DAV = ('CVE-2010-1452', 'The (1) mod_cache and (2) mod_dav modules in the Apache HTTP Server 2.2.x before 2.2.16 allow remote attackers to '
                                     'cause a denial of service (process crash) via a request that lacks a path.')
WINDOWS_WEBDAV_CLIENT = ('CVE-2025-33053', 'Microsoft Windows contains an external control of file name or path vulnerability that could allow an '
                                           'attacker to execute code from a remote WebDAV location specified by the WorkingDirectory attribute of '
                                           'Internet Shortcut files.')
FORTI_42475 = ('CVE-2022-42475', 'A heap-based buffer overflow vulnerability [CWE-122] in FortiOS SSL-VPN 7.2.0 through 7.2.2, 7.0.0 through 7.0.8 and '
                                 'FortiProxy SSL-VPN 7.2.0 through 7.2.1 may allow a remote unauthenticated attacker to execute arbitrary code or '
                                 'commands via specifically crafted requests.')
FORTI_13379 = ('CVE-2018-13379', 'An Improper Limitation of a Pathname to a Restricted Directory ("Path Traversal") in Fortinet FortiOS 6.0.0 to 6.0.4, '
                                 '5.6.3 to 5.6.7 and 5.4.6 to 5.4.12 under SSL VPN web portal allows an unauthenticated attacker to download system '
                                 'files via special crafted HTTP resource requests.')
FORTI_12812 = ('CVE-2020-12812', 'An improper authentication vulnerability in SSL VPN in FortiOS 6.4.0, 6.2.0 to 6.2.3, 6.0.9 and below may result in a '
                                 'user being able to log in successfully without being prompted for the second factor of authentication.')
PANOS_1579 = ('CVE-2019-1579', 'Remote Code Execution in PAN-OS 7.1.18 and earlier, PAN-OS 8.0.11-h1 and earlier, and PAN-OS 8.1.2 and earlier with '
                               'GlobalProtect Portal or GlobalProtect Gateway Interface enabled may allow an unauthenticated remote attacker to execute '
                               'arbitrary code.')
PANOS_3400 = ('CVE-2024-3400', 'A command injection as a result of arbitrary file creation vulnerability in the GlobalProtect feature of Palo Alto '
                               'Networks PAN-OS software for specific PAN-OS versions and distinct feature configurations may enable an unauthenticated '
                               'attacker to execute arbitrary code with root privileges on the firewall.')
PANOS_2034 = ('CVE-2020-2034', 'An OS Command Injection vulnerability in the PAN-OS GlobalProtect portal allows an unauthenticated network based attacker '
                               'to execute arbitrary OS commands with root privileges. This issue can not be exploited if GlobalProtect portal feature is '
                               'not enabled.')
PANOS_3064 = ('CVE-2021-3064', 'A memory corruption vulnerability exists in Palo Alto Networks GlobalProtect portal and gateway interfaces that enables '
                               'an unauthenticated network-based attacker to disrupt system processes.')
PANOS_SAML = ('CVE-2020-2021', 'When Security Assertion Markup Language (SAML) authentication is enabled ... Resources protected by SAML-based single '
                               'sign-on (SSO) authentication are: GlobalProtect Gateway, GlobalProtect Portal, GlobalProtect Clientless VPN, '
                               'Authentication and Captive Portal, PAN-OS next-generation firewalls and Panorama web interfaces.')
GP_APP = ('CVE-2099-0002', 'A privilege escalation in the GlobalProtect app on Windows allows a local user to execute programs with elevated privileges.')
ASA_3452 = ('CVE-2020-3452', 'A vulnerability in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower '
                             'Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct directory traversal attacks. The '
                             'web services file system is enabled when the affected device is configured with either WebVPN or AnyConnect features.')
ASA_0101 = ('CVE-2018-0101', 'A vulnerability in the Secure Sockets Layer (SSL) VPN functionality of the Cisco Adaptive Security Appliance (ASA) '
                             'Software could allow an unauthenticated, remote attacker to cause a reload. The vulnerability is due to an attempt to '
                             'double free a region of memory when the webvpn feature is enabled on the Cisco ASA device.')
ASA_20333 = ('CVE-2025-20333', 'A vulnerability in the VPN web server of Cisco Secure Firewall Adaptive Security Appliance (ASA) Software and Cisco '
                               'Secure Firewall Threat Defense (FTD) Software could allow an authenticated, remote attacker to execute arbitrary code.')
ASA_20353 = ('CVE-2024-20353', 'A vulnerability in the management and VPN web servers for Cisco Adaptive Security Appliance (ASA) Software and Cisco '
                               'Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to cause the device to reload.')
ANYCONNECT_CLIENT = ('CVE-2020-3433', 'A vulnerability in the interprocess communication (IPC) channel of Cisco AnyConnect Secure Mobility Client for '
                                      'Windows could allow an authenticated, local attacker to perform a DLL hijacking attack.')
CITRIX_4966 = ('CVE-2023-4966', 'Sensitive information disclosure in NetScaler ADC and NetScaler Gateway when configured as a Gateway (VPN virtual '
                                'server, ICA Proxy, CVPN, RDP Proxy) or AAA  virtual server.')
CITRIX_5777 = ('CVE-2025-5777', 'Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual '
                                'server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server')
CITRIX_7775 = ('CVE-2025-7775', 'Memory overflow vulnerability leading to Remote Code Execution and/or Denial of Service in NetScaler ADC and NetScaler '
                                'Gateway when NetScaler is configured as Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) or AAA virtual server  '
                                '(OR)  NetScaler ADC and NetScaler Gateway 13.1, 14.1: LB virtual servers of type (HTTP, SSL or HTTP_QUIC) bound with '
                                'IPv6 services')
ESXI_21974 = ('CVE-2021-21974', 'OpenSLP as used in ESXi (7.0 before ESXi70U1c-17325551) has a heap-overflow vulnerability. A malicious actor residing '
                                'within the same network segment as ESXi who has access to port 427 may be able to trigger the heap-overflow issue in '
                                'OpenSLP service resulting in remote code execution.')
ESXI_3992 = ('CVE-2020-3992', 'OpenSLP as used in VMware ESXi has a use-after-free issue. A malicious actor residing in the management network who has '
                              'access to port 427 on an ESXi machine may be able to trigger a use-after-free in the OpenSLP service.')
ESXI_5544 = ('CVE-2019-5544', 'OpenSLP as used in ESXi and the Horizon DaaS appliances has a heap overwrite issue.')
SLP_29552 = ('CVE-2023-29552', 'The Service Location Protocol (SLP, RFC 2608) allows an unauthenticated, remote attacker to register arbitrary services. '
                               'This could allow the attacker to use spoofed UDP traffic to conduct a denial-of-service attack with a significant '
                               'amplification factor.')
NGINX_HTTP2 = ('CVE-2099-0003', 'A crafted request to nginx can crash the worker process.')


def needs(advisory):
    return feature_preconditions('', advisory[1])


class RuleTests(SimpleTestCase):
    """Each rule, with the advisory sentence it quotes."""

    def check(self, advisory, feature, rule_out, clears, quote):
        got = needs(advisory).get(feature)
        self.assertIsNotNone(got, advisory[0])
        self.assertEqual((got['rule_out'], got['exposed'], got['clears']), (rule_out, ('yes',), clears), advisory[0])
        self.assertIn(quote, got['quote'], advisory[0])

    def test_http3_needs_the_quic_module_and_is_never_ruled_out_by_a_header(self):
        self.check(NGINX_QUIC, 'http3', True, (), 'configured to use the HTTP/3 QUIC module')
        self.check(NGINX_QUIC_MTU, 'http3', True, (), 'configured to use the HTTP/3 QUIC module')
        self.assertNotIn('http3', needs(NGINX_HTTP2))

    def test_php_cgi_on_windows(self):
        self.check(PHP_4577, 'php_windows', True, ('no',), 'when using Apache and PHP-CGI on Windows')
        self.check(PHP_KEV, 'php_windows', True, ('no',), 'Windows-based PHP used in CGI mode')
        self.check(PHP_8926, 'php_windows', True, ('no',), 'non-standard configurations of Windows codepages')
        self.assertNotIn('php_windows', needs(PHP_1823))  # php-cgi on any system: the operating system is no precondition

    def test_webdav_in_iis_rules_out_and_a_module_only_raises(self):
        self.check(IIS_7269, 'webdav', True, ('no',), 'the WebDAV service in Internet Information Services (IIS) 6.0')
        self.check(APACHE_DAV, 'webdav', True, (), 'the mod_dav module in the Apache HTTP Server')
        self.assertNotIn('webdav', needs(APACHE_CACHE_DAV))  # mod_cache is enough
        self.assertNotIn('webdav', needs(WINDOWS_WEBDAV_CLIENT))  # the WebDAV client, not a server

    def test_fortinet_ssl_vpn(self):
        self.check(FORTI_42475, 'vpn_fortinet', True, ('no',), 'FortiOS SSL-VPN')
        self.check(FORTI_13379, 'vpn_fortinet', True, ('no',), 'under SSL VPN web portal')
        self.check(FORTI_12812, 'vpn_fortinet', True, ('no',), 'SSL VPN in FortiOS')
        self.assertNotIn('vpn_fortinet', needs(('x', 'A flaw in the FortiOS administrative interface and SSL-VPN web portal ...')))

    def test_globalprotect_portal_or_gateway(self):
        self.check(PANOS_1579, 'vpn_globalprotect', True, ('no',), 'with GlobalProtect Portal or GlobalProtect Gateway Interface enabled')
        self.check(PANOS_3400, 'vpn_globalprotect', True, ('no',), 'in the GlobalProtect feature of Palo Alto Networks PAN-OS')
        self.check(PANOS_2034, 'vpn_globalprotect', True, ('no',), 'PAN-OS GlobalProtect portal')
        self.check(PANOS_3064, 'vpn_globalprotect', True, ('no',), 'GlobalProtect portal and gateway interfaces')
        self.assertNotIn('vpn_globalprotect', needs(PANOS_SAML))  # also the captive portal and the web interfaces
        self.assertNotIn('vpn_globalprotect', needs(GP_APP))  # the client app

    def test_cisco_webvpn_or_anyconnect(self):
        self.check(ASA_3452, 'vpn_cisco', True, ('no',), 'configured with either WebVPN or AnyConnect features')
        self.check(ASA_0101, 'vpn_cisco', True, ('no',), 'when the webvpn feature is enabled')
        self.check(ASA_20333, 'vpn_cisco', True, ('no',), 'the VPN web server of Cisco Secure Firewall')
        self.assertNotIn('vpn_cisco', needs(ASA_20353))  # the management web server too
        self.assertNotIn('vpn_cisco', needs(ANYCONNECT_CLIENT))

    def test_netscaler_gateway_or_aaa(self):
        self.check(CITRIX_4966, 'vpn_citrix', True, ('no',), 'when configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy)')
        self.check(CITRIX_5777, 'vpn_citrix', True, ('no',), 'configured as a Gateway (VPN virtual server')
        self.assertNotIn('vpn_citrix', needs(CITRIX_7775))  # an LB virtual server is enough too

    def test_openslp_needs_port_427_and_udp_is_never_ruled_out_by_tcp(self):
        self.check(ESXI_21974, 'slp', True, ('no',), 'OpenSLP as used in ESXi')
        self.check(ESXI_3992, 'slp', True, ('no',), 'OpenSLP as used in VMware ESXi')
        self.check(ESXI_5544, 'slp', True, ('no',), 'OpenSLP as used in ESXi')
        self.check(SLP_29552, 'slp', False, ('no',), 'The Service Location Protocol (SLP, RFC 2608)')

    def test_every_rule_word_passes_the_database_prefilter(self):
        import re

        from cveFeed.detection_classes import FEATURE_PREFILTER
        prefilter = re.compile(FEATURE_PREFILTER.replace(r'\m', r'\b').replace(r'\M', r'\b'), re.I)
        for advisory in (NGINX_QUIC, PHP_4577, PHP_KEV, PHP_8926, IIS_7269, APACHE_DAV, FORTI_42475, FORTI_13379, PANOS_1579, PANOS_3400, ASA_3452,
                         ASA_0101, ASA_20333, CITRIX_4966, ESXI_21974, ESXI_5544, SLP_29552):
            self.assertTrue(prefilter.search(advisory[1]), advisory[0])

    def test_every_feature_has_its_server_words(self):
        for key in ('http3', 'php_windows', 'webdav', 'http_methods', 'vpn_fortinet', 'vpn_globalprotect', 'vpn_cisco', 'vpn_citrix', 'vpn_ivanti', 'slp'):
            self.assertIn(key, service_features.FEATURES)
            self.assertNotEqual(service_features.server(key).label, key)


class WebCase(TestCase):
    def setUp(self):
        service_features.reset_index()
        self.addCleanup(service_features.reset_index)
        now = timezone.now()
        self.project = Project.objects.create(name='W', slug='sfw', insert_date=now, org=Org.objects.create(name='W', slug='sfwo'))
        self.domain = Domain.objects.create(name='example.test', project=self.project, insert_date=now)
        self.sub = Subdomain.objects.create(name='vpn.example.test', target_domain=self.domain)
        self.ip = IpAddress.objects.create(address='192.0.2.9')
        self.sub.ip_addresses.add(self.ip)
        self.ip.ports.add(Port.objects.create(number=443, service_name='https'))

    def cve(self, advisory):
        return CVEEntry.objects.create(cve_id=advisory[0], status='PUBLISHED', published_at=timezone.now(), title='', original_description=advisory[1],
                                       affected=[{'vendor': 'v', 'product': 'p', 'ranges': [{'introduced': '1.0', 'fixed': '9.0'}]}])

    def match(self, cve):
        return CVEMatch.objects.create(cve_entry=cve, subdomain=self.sub, source='tech', matched_product='p', matched_version='2.0',
                                       version_in_range=True, confidence=0.85, evidence={'source': 'tech'})

    def reading(self, feature, value, port=443, detail='read'):
        ServiceFeature.objects.update_or_create(domain=self.domain, host=self.sub.name, port=port, feature=feature, defaults={
            'value': value, 'detail': detail, 'source': 'http_probe', 'observed_at': timezone.now()})

    def state(self, cve):
        sub = Subdomain.objects.select_related('target_domain').get(pk=self.sub.pk)
        items = service_features.preconditions_for(sub, cve)
        return items[0]['state'] if items else None


class AssessTests(WebCase):
    def test_a_portal_that_is_not_served_closes_the_vpn_match_with_its_words(self):
        cve = self.cve(FORTI_42475)
        match = self.match(cve)
        self.reading('vpn_fortinet', 'no', detail='Fortinet SSL-VPN portal: not served (/remote/login not found)')
        self.assertEqual(service_features.reevaluate(self.project.pk, {self.sub.name})['closed'], 1)
        match = CVEMatch.objects.get(pk=match.pk)
        self.assertTrue(match.ai_reason.startswith(correlation.PRECONDITION_CLOSED))
        self.assertIn('serves no SSL-VPN web portal', match.ai_reason)
        self.assertIn('FortiOS SSL-VPN', match.ai_reason)
        self.reading('vpn_fortinet', 'yes', detail='Fortinet SSL-VPN portal answers')
        self.assertEqual(service_features.reevaluate(self.project.pk, {self.sub.name})['reopened'], 1)
        self.assertEqual(CVEMatch.objects.get(pk=match.pk).confidence, 0.9)

    def test_a_vpn_port_that_was_not_read_keeps_it_unknown(self):
        cve = self.cve(PANOS_3400)
        self.ip.ports.add(Port.objects.create(number=10443, service_name='https'))
        self.reading('vpn_globalprotect', 'no')
        self.assertEqual(self.state(cve), 'unknown')
        self.reading('vpn_globalprotect', 'no', port=10443)
        self.assertEqual(self.state(cve), 'ruled_out')

    def test_http3_advertised_raises_and_not_advertised_never_rules_out(self):
        cve = self.cve(NGINX_QUIC)
        self.reading('http3', 'no')
        self.assertEqual(self.state(cve), 'unknown')
        self.reading('http3', 'yes')
        self.assertEqual(self.state(cve), 'exposed')

    def test_webdav_off_rules_out_the_iis_flaw_but_not_a_modules(self):
        iis, module = self.cve(IIS_7269), self.cve(APACHE_DAV)
        self.reading('webdav', 'no', port=80)  # one port speaks for the server
        self.assertEqual(self.state(iis), 'ruled_out')
        self.assertEqual(self.state(module), 'unknown')
        self.reading('webdav', 'yes', port=80)
        self.assertEqual(self.state(module), 'exposed')

    def test_php_not_on_windows_closes_4577(self):
        cve = self.cve(PHP_4577)
        match = self.match(cve)
        self.reading('php_windows', 'no', detail='PHP/8.1.2-1ubuntu2.14 not on Windows')
        service_features.reevaluate(self.project.pk, {self.sub.name})
        self.assertIn('runs PHP on an operating system other than Windows', CVEMatch.objects.get(pk=match.pk).ai_reason)

    def test_slp_refused_closes_the_openslp_flaw_but_not_the_udp_amplification(self):
        openslp, amplification = self.cve(ESXI_21974), self.cve(SLP_29552)
        first, second = self.match(openslp), self.match(amplification)
        self.ip.ports.add(Port.objects.create(number=427, service_name='svrloc'))
        self.reading('slp', 'no', port=427, detail='427/tcp refused the connection; UDP 427 is not read')
        service_features.reevaluate(self.project.pk, {self.sub.name})
        self.assertIn('refuses TCP 427 (SLP)', CVEMatch.objects.get(pk=first.pk).ai_reason)
        self.assertEqual(CVEMatch.objects.get(pk=second.pk).ai_verdict, '')

    def test_a_vpn_reading_behind_an_edge_is_unknown(self):
        cve = self.cve(CITRIX_4966)
        Subdomain.objects.filter(pk=self.sub.pk).update(is_cdn=True, cdn_name='cloudflare')
        self.reading('vpn_citrix', 'no')
        self.assertEqual(self.state(cve), 'unknown')


class PlanTests(RouteFixture, TestCase):
    """The probe stage asks for the feature reads where they matter, through the http_probe kind, and stores what comes back."""

    def setUp(self):
        super().setUp()
        service_features.reset_index()
        self.addCleanup(service_features.reset_index)
        self.scan_obj = self.scan(names=('vpn.rt.test', 'plain.rt.test'))
        Subdomain.objects.get(scan_history=self.scan_obj, name='vpn.rt.test').technologies.add(Technology.objects.create(name='FortiGate:7.2.1'))
        self.http_guard = assert_ran_nowhere_locally(self, 'http_probe')
        self.tasks, self.calls = [], []
        self.fake = FakeScanner(kinds=['http_probe'], responders={'http_probe': self.report}).start_for(self)

    def serve(self, url, _policy=None, method='GET', **kwargs):
        path = '/' + url.split('://', 1)[1].split('/', 1)[1]
        self.calls.append((method, url.split('/')[2], path))
        page = {'status': 404, 'headers': {}, 'raw_headers': {}, 'body': '', 'title': '', 'content_type': 'text/html', 'server': '', 'powered_by': '',
                'url': url, 'location': '', 'bytes': 0}
        if method == 'OPTIONS':
            return {**page, 'status': 200, 'raw_headers': {'allow': 'GET, HEAD, OPTIONS'}}
        if path == '/':
            return {**page, 'status': 200, 'raw_headers': {'alt-svc': 'h3=":443"'}, 'body': '<html></html>'}
        if path == '/remote/login':
            body = '<form action="/remote/logincheck"></form>'
            return {**page, 'status': 200, 'body': body, 'bytes': len(body)}
        return page

    def report(self, task):
        """What the library's own http_probe batch reads for ``task`` over ``self.serve`` (no network)."""
        self.tasks.append(task)
        with mock.patch.object(version_probes, 'REQUEST_GAP', 0):
            return {'outcome': 'done', **version_probes.run_batch(task['target'], probe=self.serve, sleep=lambda s: None)}

    def stage(self, **kw):
        with mock.patch('cveFeed.probes.recorrelate'), mock.patch('cveFeed.route_auth.host_allowed', return_value=True):
            return probes.run_for_scan(self.scan_obj.id, **kw)

    def test_a_vendor_host_gets_its_portal_read_and_the_readings_are_stored(self):
        self.stage()
        entries = [p for t in self.tasks for p in t['target']['probes']]
        mine = [p for p in entries if p['host'] == 'vpn.rt.test' and p.get('features')]
        self.assertEqual([(p['probe'], p['features']) for p in mine], [('headers-root', ['webdav', 'vpn_fortinet'])])
        self.assertFalse(any(p['host'] == 'plain.rt.test' and p.get('features') for p in entries))  # nothing names a feature there
        rows = dict(((r.feature, r.port), r.value) for r in ServiceFeature.objects.filter(host='vpn.rt.test'))
        self.assertEqual(rows, {('http3', 443): 'yes', ('webdav', 443): 'no', ('http_methods', 443): 'none', ('vpn_fortinet', 443): 'yes'})
        self.assertNotIn(('GET', 'plain.rt.test', '/remote/login'), self.calls)
        self.assertTrue(ServiceRun.objects.filter(service=probes.FEATURE_SERVICE, status='done', asset__startswith='vpn.rt.test|features|').exists())
        # inside the ledger window nothing is read again
        asked = len(self.calls)
        self.stage()
        self.assertEqual(len([c for c in self.calls[asked:] if c[0] == 'OPTIONS' or c[2] == '/remote/login']), 0)

    def test_a_host_whose_match_needs_a_web_feature_is_read(self):
        plain = Subdomain.objects.get(scan_history=self.scan_obj, name='plain.rt.test')
        cve = CVEEntry.objects.create(cve_id=IIS_7269[0], status='PUBLISHED', published_at=timezone.now(), title='', original_description=IIS_7269[1],
                                      affected=[{'vendor': 'microsoft', 'product': 'iis', 'ranges': [{'introduced': '6.0', 'lastAffected': '6.0'}]}])
        CVEMatch.objects.create(cve_entry=cve, subdomain=plain, source='tech', matched_product='iis', matched_version='6.0', version_in_range=True,
                                confidence=0.85, evidence={'source': 'tech'})
        self.assertEqual(probes.features_needed(self.project.pk, {'plain.rt.test'}), {'plain.rt.test': {'webdav'}})
        self.stage()
        entries = [p for t in self.tasks for p in t['target']['probes'] if p['host'] == 'plain.rt.test']
        self.assertEqual([p.get('features') for p in entries], [['webdav']])
        self.assertEqual(ServiceFeature.objects.get(host='plain.rt.test', feature='webdav').value, 'no')

    def test_the_read_rides_on_a_due_headers_root_probe_of_the_same_base(self):
        sub = Subdomain.objects.filter(scan_history=self.scan_obj, name='vpn.rt.test').prefetch_related('technologies', 'ip_addresses__ports').get()
        entry = {'probe': 'headers-root', 'target': {'base': 'https://vpn.rt.test'}, 'for': ['x']}
        todo = {'vpn.rt.test|headers-root|https://vpn.rt.test': entry}
        probes._add_feature_read(sub, todo, (), False, self.project.pk)
        self.assertEqual(list(todo), ['vpn.rt.test|headers-root|https://vpn.rt.test'])
        ridden = todo['vpn.rt.test|headers-root|https://vpn.rt.test']
        self.assertEqual((ridden['features'], ridden['feature_asset']), (['webdav', 'vpn_fortinet'], 'vpn.rt.test|features|https://vpn.rt.test'))
        self.assertIsNone(probes.feature_entry(sub, (), edge_fronted=True))  # an edge would answer every read


class SlpPlanTests(TestCase):
    def setUp(self):
        now = timezone.now()
        self.project = Project.objects.create(name='S', slug='slp', insert_date=now, org=Org.objects.create(name='S', slug='slpo'))
        self.domain = Domain.objects.create(name='example.test', project=self.project, insert_date=now)

    def host(self, name, ports=(), tech=None):
        sub = Subdomain.objects.create(name=name, target_domain=self.domain)
        ip = IpAddress.objects.create(address=f'192.0.2.{Subdomain.objects.count()}')
        sub.ip_addresses.add(ip)
        for number, service, product in ports:
            ip.ports.add(Port.objects.create(number=number, service_name=service, product=product, state='open'))
        if tech:
            sub.technologies.add(Technology.objects.create(name=tech))
        return sub

    def test_only_esxi_hosts_and_hosts_with_427_open_are_asked(self):
        self.host('esx1.example.test', ports=((443, 'https', 'VMware ESXi SOAP API'),))
        self.host('esx2.example.test', ports=((902, 'vmware-auth', 'VMware Authentication Daemon'),))
        self.host('slp.example.test', ports=((427, 'svrloc', ''),))
        self.host('www.example.test', ports=((443, 'https', 'nginx'),), tech='nginx')
        with mock.patch('targetApp.target_types.scannable_hosts', side_effect=lambda hosts, project=None: list(hosts)):
            got = hygiene.slp_targets(self.domain)
        self.assertEqual(got, [('esx1.example.test', 427), ('esx2.example.test', 427), ('slp.example.test', 427)])

    def test_the_hygiene_check_sends_them_and_stores_the_slp_reading(self):
        from tests import hygiene_harness
        self.host('esx1.example.test', ports=((443, 'https', 'VMware ESXi SOAP API'),))
        sent = []
        base = hygiene_harness.responder()

        def answer(task):
            sent.append(task['target'].get('slp'))
            out = base(task)
            out['service_features'] = [{'host': t['host'], 'port': t['port'], 'transport': 'tcp', 'feature': 'slp', 'value': 'yes',
                                        'detail': 'SLPv2 SrvRply on 427/tcp (error 0, 1 service URL)'} for t in task['target'].get('slp') or []]
            return out
        with mock.patch('targetApp.target_types.scannable_hosts', side_effect=lambda hosts, project=None: list(hosts)), \
                FakeScanner(kinds=['hygiene_check'], responders={'hygiene_check': answer}):
            hygiene.run_hygiene(self.domain.id)
        self.assertEqual(sent, [[{'host': 'esx1.example.test', 'port': 427}]])
        row = ServiceFeature.objects.get(host='esx1.example.test', feature='slp')
        self.assertEqual((row.port, row.value, row.source), (427, 'yes', 'hygiene_check'))
