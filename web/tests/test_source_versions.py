"""Every version a source already sent (cveFeed.source_versions): per source, a real-shaped answer whose version becomes a technology or a matchable
reading, the third-party freshness rule (a first-party reading always wins, stale passive data never keeps a closed match alive), tenancy, search and
the payload, and the one-time backfill."""
import json
from datetime import timedelta
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import correlation, db_exposure, port_inventory, runzero, runzero_sync, source_versions, tls_audit, upgrade_backfills, version_sources
from cveFeed.models import CVEEntry, CVEMatch, DiscoveryEvent, ProbeObservation
from dashboard.models import Project
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Technology, Vulnerability
from targetApp.models import Domain
from tests.test_version_sources import VersionFixture

FIXTURES = Path(__file__).with_name('fixtures') / 'source_versions'


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


def cve(cve_id, vendor, product, introduced, fixed, kev=False):
    return CVEEntry.objects.create(cve_id=cve_id, title=cve_id, kev=kev, cvss=9.8, published_at=timezone.now(),
                                   affected=[{'vendor': vendor, 'product': product,
                                              'ranges': [{'type': 'ECOSYSTEM', 'introduced': introduced, 'fixed': fixed}]}])


def rows(probe, **kw):
    return {(r.kind, r.product, r.port): r for r in ProbeObservation.objects.filter(probe=probe, **kw)}


def names(sub):
    return {t.name for t in Subdomain.objects.get(pk=sub.pk).technologies.all()}


class ReaderTests(SimpleTestCase):
    """The pure readers, on the exact text each source sends."""

    def test_db_probe_replies(self):
        replies = fixture('db_probe_replies.json')
        got = {db: [(r['label'], r['version']) for r in source_versions.db_readings(item['evidence'])] for db, item in replies.items()}
        self.assertEqual(got, {'redis': [('Redis', '7.2.4')], 'memcached': [('Memcached', '1.6.21')], 'postgres': [('PostgreSQL', '15.4')],
                               'elastic': [('Elasticsearch', '8.11.1')], 'mysql': [('MySQL', '8.0.35')], 'mariadb': [('MariaDB', '10.6.12')],
                               'couchdb': [], 'mongodb': []})
        self.assertEqual(source_versions.db_readings('PONG (redis 7.2.4) and more'), [])  # anchored: a database's own text adds nothing

    def test_a_cpe_is_a_reading_with_its_cpe_and_an_os_cpe_or_a_bare_one_is_none(self):
        got = source_versions.reported_cpe('cpe:/a:openbsd:openssh:8.9p1')
        self.assertEqual((got['label'], got['version'], got['cpe']), ('openbsd openssh', '8.9p1', 'cpe:/a:openbsd:openssh:8.9p1'))
        # every CPE InternetDB hands bbot is a reading, labelled "vendor product": an operating system and an unversioned one too (no version)
        got = [(r['label'], r['version'], r['cpe']) for r in map(source_versions.reported_cpe, (
            'cpe:/o:canonical:ubuntu_linux', 'cpe:/a:igor_sysoev:nginx', 'cpe:/a:apache:http_server', 'cpe:/a:nginx:nginx:1.18.0',
            'cpe:/a:jquery:jquery:3.5.1'))]
        self.assertEqual(got, [('canonical ubuntu linux', '', 'cpe:/o:canonical:ubuntu_linux'), ('igor sysoev nginx', '', 'cpe:/a:igor_sysoev:nginx'),
                               ('apache http server', '', 'cpe:/a:apache:http_server'), ('nginx', '1.18.0', 'cpe:/a:nginx:nginx:1.18.0'),
                               ('jquery', '', 'cpe:/a:jquery:jquery:3.5.1')])  # a library's version is read from its own file only
        self.assertIsNone(source_versions.reported_cpe('nginx:1.18.0'))

    def test_testssl_banners(self):
        got = [(r['label'], r['version'], r['kind']) for r in source_versions.testssl_readings(fixture('testssl_banners.json')['items'], 443)]
        self.assertEqual(got, [('nginx', '1.18.0', 'product'), ('PHP', '7.4.3', 'runtime')])
        self.assertEqual(source_versions.testssl_readings([{'id': 'banner_server', 'finding': 'No Server banner line in header, interesting!'}]), [])

    def test_wpscan_headers(self):
        got = [(r['label'], r['version'], r['kind']) for r in source_versions.wpscan_readings(fixture('wpscan_headers.json')['report'])]
        self.assertEqual(got, [('Apache HTTP Server', '2.4.29', 'product'), ('PHP', '7.2.24', 'runtime')])

    def test_runzero_block(self):
        block = runzero_sync._block(runzero.parse_asset(fixture('runzero_asset.json')), [])
        got, = source_versions.runzero_readings(block)
        self.assertEqual((got['label'], got['version']), ('Cisco IOS', '15.2(4)M7'))
        self.assertEqual(source_versions.runzero_readings({**block, 'os_version': ''}), [])


    # nmap's own vmware-version output (scripts/vmware-version.nse: "Server version", "Build", "Locale version", "OS type", "Product Line ID"),
    # once as the normal output prints it and once as the -oX output attribute a Sentinel sends
    VMWARE_NORMAL = ('| vmware-version:\n|   Server version: VMware ESXi 7.0.3\n|   Build: 21930508\n|   Locale version: INTL 000\n'
                     '|   OS type: vmnix-x86\n|_  Product Line ID: embeddedEsx')
    VMWARE_XML = '  Server version: VMware ESXi 7.0.3\n  Build: 21930508\n  Locale version: INTL 000\n  OS type: vmnix-x86\n  Product Line ID: embeddedEsx'

    def test_vmware_version_states_esxi_with_its_build(self):
        for text in (self.VMWARE_NORMAL, self.VMWARE_XML):
            got, = source_versions.vmware_readings(text)
            self.assertEqual((got['label'], got['version'], got['build'], got['cpe'], got['source']),
                             ('VMware ESXi', '7.0.3-21930508', '21930508', 'cpe:/o:vmware:esxi:7.0.3', 'nse:vmware-version'))
            self.assertIn('Product Line ID: embeddedEsx', got['evidence'])
        # vCenter's advisories name update letters, not builds: the release is its version, the build only evidence
        got, = source_versions.vmware_readings('  Server version: VMware vCenter Server 7.0.3\n  Build: 20150588\n  Locale version: INTL 000\n'
                                               '  OS type: linux-x64\n  Product Line ID: vpx')
        self.assertEqual((got['label'], got['version'], got['cpe'], 'build' in got), ('VMware vCenter Server', '7.0.3', 'cpe:/a:vmware:vcenter_server:7.0.3', False))
        self.assertIn('Build: 20150588', got['evidence'])
        # the classic ESX the script's own documentation shows
        got, = source_versions.vmware_readings('| vmware-version:\n|   Server version: VMware ESX 4.1.0\n|   Build: 348481\n'
                                               '|   Locale version: INTL 000\n|   OS type: vmnix-x86\n|_  Product Line ID: esx')
        self.assertEqual((got['label'], got['version']), ('VMware ESX', '4.1.0-348481'))
        for junk in ('', 'Server version: Totally ESXi 7.0.3', '  Server version: VMware ESXi\n  Build: 1', '  Server version: VMware ESXi 7.0.3 <script>'):
            self.assertEqual(source_versions.vmware_readings(junk), [])
        got, = source_versions.vmware_readings('  Server version: VMware ESXi 8.0.2\n  Build: not-a-build')
        self.assertEqual((got['version'], 'build' in got), ('8.0.2', False))  # no build stated: the release alone

    def test_the_other_version_scripts_with_a_fixed_form(self):
        scripts = {  # the outputs nmap's scripts document (amqp-info.nse, docker-version.nse, wdb-version.nse), as -oX writes them
            'amqp-info': ('  capabilities: \n    publisher_confirms: YES\n    exchange_exchange_bindings: YES\n    basic.nack: YES\n'
                          '    consumer_cancel_notify: YES\n  copyright: Copyright (C) 2007-2011 VMware, Inc.\n'
                          '  information: Licensed under the MPL.  See http://www.rabbitmq.com/\n  platform: Erlang/OTP\n  product: RabbitMQ\n'
                          '  version: 2.4.0\n  mechanisms: PLAIN AMQPLAIN\n  locales: en_US'),
            'docker-version': ('  Version: 1.11.2\n  BuildTime: 2016-06-01T21:47:50.269346868+00:00\n  Arch: amd64\n  KernelVersion: 3.13.0-91-generic\n'
                               '  Os: linux\n  ApiVersion: 1.23\n  GitCommit: b9f10c9\n  GoVersion: go1.5.4'),
            'wdb-version': ('  VULNERABLE: Wind River Systems VxWorks debug service enabled. See http://www.kb.cert.org/vuls/id/362332\n'
                            '  Agent version: 2.0\n  VxWorks version: VxWorks5.4.2\n  Board Support Package: PCD ARM940T REV 1\n  Boot line: host:vxWorks.z'),
            'rpcinfo': '  program version    port/proto  service\n  100000  2,3,4        111/tcp   rpcbind',  # a table, no product version
            'hnap-info': '  Type: GatewayWithWiFi\n  Device: Ingraham\n  Vendor: Linksys\n  Firmware: 1.0.00 build 11',
        }
        got = [(r['label'], r['version'], r['source'], r.get('cpe', '')) for r in source_versions.version_script_readings(scripts)]
        self.assertEqual(got, [('RabbitMQ', '2.4.0', 'nse:amqp-info', ''), ('Docker', '1.11.2', 'nse:docker-version', ''),
                               ('VxWorks', '5.4.2', 'nse:wdb-version', 'cpe:/o:windriver:vxworks:5.4.2')])
        self.assertEqual(source_versions.version_script_readings({'amqp-info': '  capabilities: \n    version: 9.9.9\n    product: Evil'}), [])
        self.assertEqual(source_versions.version_script_readings('not a dict'), [])

    def test_runzero_services_are_readings_per_port(self):
        services = [runzero.parse_service(r) for r in fixture('runzero_services_page.json')['services']]
        services = [s for s in services if s and s['address'] == '203.0.113.5']
        block = runzero_sync._block(runzero.parse_asset(fixture('runzero_asset.json')), [], services)
        got = [(port, r['label'], r['version'], r.get('cpe', ''), when[:10]) for port, r, when in source_versions.runzero_service_readings(block)]
        self.assertEqual(got, [(22, 'OpenSSH', '8.2p1', 'cpe:/a:openbsd:openssh:8.2p1', '2025-11-17'),
                               (80, 'Apache HTTPD', '2.4.41', 'cpe:/a:apache:http_server:2.4.41', '2025-11-16'),
                               (80, 'PHP', '7.4.3', 'cpe:/a:php:php:7.4.3', '2025-11-16'),
                               (8080, 'Jetty', '9.4.41', 'cpe:/a:eclipse:jetty:9.4.41', '2025-11-17')])
        self.assertEqual(source_versions.runzero_service_readings({'services': [{'port': 'x'}, {'port': 22, 'attributes': 'x'}, 'junk']}), [])

    def test_runzero_hardware_firmware_is_a_hint(self):
        block = runzero_sync._block(runzero.parse_asset({**fixture('runzero_asset.json'), 'hw': 'Ubiquiti UniFi AP 6.5.28'}), [])
        _os, hw = source_versions.runzero_readings(block)
        self.assertEqual((hw['label'], hw['version'], hw['confidence'], hw['hint'], hw['part']), ('Ubiquiti UniFi AP', '6.5.28', 'weak', True, 'hw'))
        for model in ('Cisco ISR4321', 'Dell PowerEdge 2500', 'Apple Mac Mini (Late 2018)'):  # a model number is no firmware version
            block = runzero_sync._block(runzero.parse_asset({**fixture('runzero_asset.json'), 'hw': model}), [])
            self.assertEqual([r['part'] for r in source_versions.runzero_readings(block)], ['os'])


class NmapTests(VersionFixture, TestCase):
    def stored(self):
        scan = self.host_scan(web=False)
        port_inventory.persist_inventory(fixture('nmap_centos.json')['hosts'], os_reliable=True)
        sub = Subdomain.objects.select_related('target_domain').prefetch_related('technologies', 'ip_addresses__ports').get(scan_history=scan)
        version_sources.refresh_host(sub)
        return scan, sub

    def test_the_other_cpes_extrainfo_modules_and_script_versions_become_technologies_and_readings(self):
        _scan, sub = self.stored()
        got = {k: (r.version, r.evidence.get('cpe', '')) for k, r in rows(source_versions.NMAP_PROBE).items()}
        self.assertEqual(got[('version', 'OpenSSL', 80)], ('1.0.2k-fips', 'cpe:/a:openssl:openssl:1.0.2k'))  # extrainfo's spelling, the CPE kept
        self.assertEqual(got[('runtime', 'PHP', 80)], ('5.4.16', ''))
        self.assertEqual(got[('version', 'MariaDB', 3306)], ('10.6.12', ''))
        self.assertEqual(got[('version', 'Redis', 6379)], ('7.2.4', ''))
        self.assertNotIn(('version', 'Apache HTTP Server', 80), got)  # the port row already states Apache httpd 2.4.6: not stored twice
        self.assertTrue({'OpenSSL:1.0.2k-fips', 'MariaDB:10.6.12', 'Redis:7.2.4'} <= names(sub))
        self.assertEqual(source_versions.technology_cpes(sub)['OpenSSL:1.0.2k-fips'], 'cpe:/a:openssl:openssl:1.0.2k')

    def test_the_cpe_feeds_cpe_first_matching(self):
        row = cve('CVE-2026-300001', 'openssl', 'openssl', '1.0.2', '1.0.2zz')
        other = cve('CVE-2026-300002', 'someoneelse', 'openssl', '1.0.2', '1.0.2zz')  # another vendor's "openssl": the CPE's vendor rules it out
        scan, _sub = self.stored()
        cve_by_id, index = correlation.cve_pool()
        correlation.correlate_subdomains(list(correlation.candidate_subdomains(index).filter(scan_history=scan)), index, cve_by_id, min_confidence=0.4)
        match = CVEMatch.objects.get(cve_entry=row, source='tech')
        self.assertEqual((match.matched_version, match.evidence['cpe']), ('1.0.2k-fips', 'cpe:/a:openssl:openssl:1.0.2k'))
        self.assertFalse(CVEMatch.objects.filter(cve_entry=other).exists())

    def test_a_reading_the_port_stops_stating_is_dropped(self):
        _scan, sub = self.stored()
        port = Port.objects.get(number=6379)
        port.extra = {**port.extra, 'scripts': {}}
        port.save(update_fields=['extra'])
        sub = Subdomain.objects.prefetch_related('technologies', 'ip_addresses__ports').get(pk=sub.pk)
        version_sources.refresh_host(sub)
        self.assertNotIn(('version', 'Redis', 6379), rows(source_versions.NMAP_PROBE))

    def test_search_and_payload(self):
        _scan, sub = self.stored()
        self.assertEqual({r.product for r in version_sources.search_rows('vsource', 'nmap')}, {'OpenSSL', 'PHP', 'MariaDB', 'Redis', 'mod_perl'} & {
            r.product for r in ProbeObservation.objects.filter(probe=source_versions.NMAP_PROBE)})
        listed = version_sources.readings_for([self.project.id], ['app.rt.test'])[(self.project.id, 'app.rt.test')]
        self.assertIn(('OpenSSL', '1.0.2k-fips', 'nmap', 'cpe:/a:openssl:openssl:1.0.2k'),
                      {(i['product'], i['version'], i['source'], i['cpe']) for i in listed})


class TestsslTests(VersionFixture, TestCase):
    def test_banners_become_readings_and_go_when_the_banner_goes(self):
        sub = self.host_scan().subdomain_set.select_related('target_domain').get()
        with mock.patch('cveFeed.probes.recorrelate') as recorrelate:
            tls_audit.store_banners(sub, 443, fixture('testssl_banners.json')['items'])
        recorrelate.assert_called_once()
        got = rows(source_versions.TESTSSL_PROBE)
        self.assertEqual(got[('version', 'nginx', 443)].version, '1.18.0')
        self.assertEqual(got[('runtime', 'PHP', 443)].version, '7.4.3')
        self.assertIn('nginx:1.18.0', names(sub))
        with mock.patch('cveFeed.probes.recorrelate'):
            tls_audit.store_banners(sub, 443, [{'id': 'banner_server', 'severity': 'INFO', 'finding': 'No Server banner line in header, interesting!'}])
        self.assertEqual(rows(source_versions.TESTSSL_PROBE), {})


class WpscanTests(VersionFixture, TestCase):
    def test_the_headers_finding_becomes_readings(self):
        from cveFeed import wpscan_scan
        scan = self.host_scan(names=('blog.rt.test',))
        sub = scan.subdomain_set.select_related('target_domain').get()
        wpscan_scan.persist_report(scan, sub, 'https://blog.rt.test/', fixture('wpscan_headers.json')['report'])
        got = rows(source_versions.WPSCAN_PROBE)
        self.assertEqual(got[('version', 'Apache HTTP Server', 443)].version, '2.4.29')
        self.assertEqual(got[('runtime', 'PHP', 443)].version, '7.2.24')
        self.assertTrue({'Apache HTTP Server:2.4.29', 'WordPress:6.4.2'} <= names(sub))


class DbProbeTests(VersionFixture, TestCase):
    def test_the_reply_of_an_open_database_becomes_a_reading(self):
        scan = self.host_scan(names=('db.rt.test',), web=False, ports=((6379, 'redis', '', ''),))
        sub = scan.subdomain_set.get()

        from tests.test_db_exposure import db_probe_dispatch
        with db_probe_dispatch(lambda host, port: (True, fixture('db_probe_replies.json')['redis']['evidence'])):
            db_exposure.run_db_exposure_checks(scan.id)
        self.assertTrue(Vulnerability.objects.filter(source='db_exposure').exists())
        self.assertEqual(rows(source_versions.DB_PROBE)[('version', 'Redis', 6379)].version, '7.2.4')
        self.assertIn('Redis:7.2.4', names(sub))


OPENSSH = ('openbsd', 'openssh', '8.0', '9.3p2')


class ReportedFixture(VersionFixture):
    def discover(self, events=None):
        """A discovery whose bbot batch carries what Shodan's InternetDB said (shodan_idb), stored the way every batch is."""
        from cveFeed import discovery
        from tests.discovery_fixtures import sentinel_discovery
        with mock.patch('cveFeed.tasks.run_bbot_discovery.delay'):
            scan = discovery.start_discovery(self.domain)
        with mock.patch('cveFeed.tasks.correlate_cves.delay'), sentinel_discovery(events or fixture('shodan_idb_events.json')):
            discovery.run_discovery(scan.id)
        return Subdomain.objects.get(scan_history=scan, name='app.rt.test')

    def correlate(self, row):
        cve_by_id, index = correlation.cve_pool()
        subs = correlation.candidate_subdomains(index)
        correlation.correlate_subdomains(list(subs), index, cve_by_id, min_confidence=0.4)
        return [m for m in CVEMatch.objects.filter(cve_entry=row) if m.ai_verdict != 'not_affected']

    def reported(self, sub, product='openssh', version='8.9p1', cpe='cpe:/a:openbsd:openssh:8.9p1', when=None, port=0, project=None):
        reading = source_versions.product_reading(product, version, source_versions.SHODAN_PROVIDER, cpe=cpe)
        project = project or sub.target_domain.project
        source_versions.store_reported(project.id, sub.target_domain_id, sub.name, source_versions.SHODAN_PROBE, [reading],
                                       source_versions.SHODAN_PROVIDER, when or timezone.now(), port=port, undated=True)


class ShodanTests(ReportedFixture, TestCase):
    def test_a_versioned_cpe_is_a_reported_reading_not_a_technology_and_is_matched_cpe_first(self):
        row = cve('CVE-2026-300010', *OPENSSH)
        sub = self.discover()
        reading = ProbeObservation.objects.get(probe=source_versions.SHODAN_PROBE, product='openbsd openssh')
        self.assertEqual((reading.kind, reading.outcome, reading.product, reading.version, reading.project_id),
                         ('reported', 'reported', 'openbsd openssh', '8.9p1', self.project.id))
        self.assertEqual((reading.evidence['cpe'], reading.evidence['provider'], reading.evidence['undated']),
                         ('cpe:/a:openbsd:openssh:8.9p1', 'shodan_idb', True))
        self.assertNotIn('openssh:8.9p1', names(sub))  # never a first-party technology
        # the operating system CPE and the library's are readings too (never a technology named "cpe:/o:..."), the library's without a version
        others = dict(ProbeObservation.objects.filter(probe=source_versions.SHODAN_PROBE).exclude(pk=reading.pk).values_list('product', 'version'))
        self.assertEqual(others, {'canonical ubuntu linux': '', 'jquery': ''})
        self.assertEqual(names(sub), set())
        match, = self.correlate(row)
        self.assertEqual((match.source, match.matched_version, match.version_in_range), ('tech', '8.9p1', True))
        self.assertLessEqual(match.confidence, source_versions.REPORTED_CONFIDENCE)
        self.assertEqual((match.evidence['reported_by'], match.evidence['cpe']), ('shodan_idb', 'cpe:/a:openbsd:openssh:8.9p1'))
        from cveFeed import match_policy
        self.assertFalse(match_policy.version_proven(match))

    def test_a_fresh_first_party_reading_wins_and_closes_the_stale_passive_match(self):
        row = cve('CVE-2026-300011', *OPENSSH)
        sub = self.discover()
        self.assertEqual(len(self.correlate(row)), 1)
        ip = sub.ip_addresses.first()
        ip.ports.add(Port.objects.create(number=22, service_name='ssh', product='OpenSSH', version='9.6p1', cpe='cpe:/a:openbsd:openssh:9.6p1',
                                         state='open', source='nmap'))
        self.assertEqual(self.correlate(row), [])  # 9.6p1 is past the fix; the 8.9p1 Shodan saw is superseded, its match closed
        closed = CVEMatch.objects.get(cve_entry=row)
        self.assertEqual(closed.ai_verdict, 'not_affected')
        Port.objects.filter(number=22).update(state='closed')
        self.assertEqual(self.correlate(row), [])  # the service closed since: the old passive reading does not bring the match back

    def test_a_first_party_sighting_with_no_version_is_not_given_the_passive_version(self):
        row = cve('CVE-2026-300012', *OPENSSH)
        sub = self.discover()
        sub.ip_addresses.first().ports.add(Port.objects.create(number=22, service_name='ssh', product='OpenSSH', state='open', source='nmap'))
        self.assertEqual(self.correlate(row), [])

    def test_a_reading_older_than_the_window_is_shown_but_never_matched(self):
        row = cve('CVE-2026-300013', *OPENSSH)
        sub = self.host_scan(web=False).subdomain_set.select_related('target_domain').get()
        self.reported(sub, when=timezone.now() - timedelta(days=source_versions.REPORTED_MAX_AGE_DAYS + 1))
        self.assertEqual(self.correlate(row), [])
        item, = version_sources.readings_for([self.project.id], ['app.rt.test'])[(self.project.id, 'app.rt.test')]
        self.assertEqual((item['stale'], item['matched'], item['reported']['by']), (True, False, 'shodan_idb'))
        self.reported(sub)  # seen again today
        self.assertEqual(len(self.correlate(row)), 1)

    def test_a_port_specific_reading_gives_way_to_our_scan_of_that_port(self):
        row = cve('CVE-2026-300014', 'eclipse', 'jetty', '9.4.0', '9.4.52')
        sub = self.host_scan(web=False, ports=((8080, 'http', 'nginx', '1.25.3'),)).subdomain_set.select_related('target_domain').get()
        self.reported(sub, product='jetty', version='9.4.41', cpe='cpe:/a:eclipse:jetty:9.4.41', port=8080)
        self.assertEqual(self.correlate(row), [])  # our scan sees nginx on 8080
        Port.objects.filter(number=8080).update(product='', version='', state='closed')
        self.assertEqual(self.correlate(row), [])  # and then the port closed
        self.assertEqual(source_versions.verdict(ProbeObservation.objects.get(product='jetty'), source_versions.first_party(sub)), 'port_closed')

    def test_search_finds_reported_readings(self):
        sub = self.host_scan(web=False).subdomain_set.select_related('target_domain').get()
        self.reported(sub)
        self.assertEqual([r.product for r in version_sources.search_rows('vsource', 'shodan-idb')], ['openssh'])
        self.assertEqual([r.product for r in version_sources.search_rows('vsource', 'reported')], ['openssh'])


class TenancyTests(ReportedFixture, TestCase):
    def other(self):
        project = Project.objects.create(name='Q', slug='pq', insert_date=timezone.now(), org=self.project.org)
        domain = Domain.objects.create(name='other.test', project=project, insert_date=timezone.now())
        scan = ScanHistory.objects.create(domain=domain, scan_type=self.engine, start_scan_date=timezone.now(), scan_status=1, tasks=[], results_dir='x')
        sub = Subdomain.objects.create(name='app.rt.test', target_domain=domain, scan_history=scan)
        ip = IpAddress.objects.get(address=self.ADDRESS)
        ip.org = self.project.org  # one organization's row for the address, which both projects' hosts resolve to
        ip.save(update_fields=['org'])
        sub.ip_addresses.add(ip)
        return project, sub

    def test_a_reading_belongs_to_its_project_only(self):
        row = cve('CVE-2026-300020', *OPENSSH)
        mine = self.host_scan(web=False).subdomain_set.select_related('target_domain').get()
        project, theirs = self.other()
        self.reported(theirs, project=project)
        # the other project's reading matches its own host only, never this project's host of the same name on the same address
        self.assertEqual([m.subdomain_id for m in self.correlate(row)], [theirs.pk])
        self.assertFalse(source_versions.in_use(Subdomain.objects.get(pk=mine.pk)))

    def test_a_runzero_block_gives_readings_to_the_project_that_synced_it(self):
        mine = self.host_scan(web=False).subdomain_set.select_related('target_domain').get()
        project, theirs = self.other()
        asset = runzero.parse_asset(fixture('runzero_asset.json'))
        runzero_sync._enrich(project, {self.ADDRESS: asset}, [])
        self.assertEqual(IpAddress.objects.get(address=self.ADDRESS).fingerprint['runzero']['project_id'], project.id)
        reading, = ProbeObservation.objects.filter(probe=source_versions.RUNZERO_PROBE)
        self.assertEqual((reading.project_id, reading.product, reading.version, reading.kind), (project.id, 'Cisco IOS', '15.2(4)M7', 'reported'))
        self.assertTrue(reading.evidence['reported_at'].startswith('2025-11-17'))  # the asset's last_seen, not when it was synced
        version_sources.refresh_host(Subdomain.objects.select_related('target_domain').prefetch_related('ip_addresses__ports', 'technologies').get(pk=mine.pk))
        self.assertEqual(ProbeObservation.objects.filter(probe=source_versions.RUNZERO_PROBE, project=self.project).count(), 0)
        self.assertEqual(theirs.target_domain.project_id, project.id)

    def test_a_block_written_before_the_project_was_recorded_counts_only_for_a_project_with_a_runzero_token(self):
        sub = self.host_scan(web=False).subdomain_set.select_related('target_domain').get()
        ip = IpAddress.objects.get(address=self.ADDRESS)
        ip.fingerprint = {'runzero': runzero_sync._block(runzero.parse_asset(fixture('runzero_asset.json')), [])}
        ip.save(update_fields=['fingerprint'])
        with mock.patch('cveFeed.runzero_sync.configured_project_ids', return_value=set()):
            self.assertFalse(source_versions.refresh_runzero(Subdomain.objects.prefetch_related('ip_addresses').get(pk=sub.pk)))
        with mock.patch('cveFeed.runzero_sync.configured_project_ids', return_value={self.project.id}):
            self.assertTrue(source_versions.refresh_runzero(Subdomain.objects.prefetch_related('ip_addresses').get(pk=sub.pk)))


class BackfillTests(ReportedFixture, TestCase):
    def test_the_backfill_reads_what_is_still_stored_and_correlates(self):
        row = cve('CVE-2026-300030', *OPENSSH)
        scan = self.host_scan(web=False, ports=((6379, 'redis', 'Redis key-value store', '', {'scripts': {'redis-info': '  Version: 7.2.4'}}),))
        scan.scan_status = 2
        scan.save(update_fields=['scan_status'])
        sub = scan.subdomain_set.get()
        # an earlier discovery stored Shodan's CPE as a first-party technology; the feed kept the event
        stale_tech, _ = Technology.objects.get_or_create(name='openssh:8.9p1')
        sub.technologies.add(stale_tech)
        DiscoveryEvent.objects.create(scan=scan, domain=self.domain, type='TECHNOLOGY', label='cpe:/a:openbsd:openssh:8.9p1 on app.rt.test',
                                      host='app.rt.test', module='shodan_idb')
        Vulnerability.objects.create(scan_history=scan, target_domain=self.domain, subdomain=sub, name='Unauthenticated Memcached exposure',
                                     source='db_exposure', severity=4, http_url='memcached://203.0.113.5:11211', extracted_results=['VERSION 1.6.21'])
        self.assertEqual(source_versions.catch_up(apply=False), {'hosts': 1, 'readings': 0, 'matches': 0})
        out = source_versions.catch_up(apply=True)
        self.assertGreaterEqual(out['readings'], 3)
        self.assertEqual(rows(source_versions.NMAP_PROBE)[('version', 'Redis', 6379)].version, '7.2.4')
        self.assertEqual(rows(source_versions.DB_PROBE)[('version', 'Memcached', 11211)].version, '1.6.21')
        self.assertEqual(rows(source_versions.SHODAN_PROBE)[('reported', 'openbsd openssh', 0)].version, '8.9p1')
        self.assertNotIn('openssh:8.9p1', names(sub))  # the CPE technology gave way to the reported reading
        match, = [m for m in CVEMatch.objects.filter(cve_entry=row)]
        self.assertTrue(match.evidence.get('reported'))
        again = source_versions.catch_up(apply=True)  # idempotent
        self.assertEqual(ProbeObservation.objects.filter(probe__in=source_versions.PROBES).count(), 3)
        self.assertEqual(CVEMatch.objects.filter(cve_entry=row).count(), 1)
        self.assertEqual(again['hosts'], 1)

    def test_it_is_registered_and_runs_as_a_command(self):
        from io import StringIO

        from django.core.management import call_command
        self.assertIn('backfill_source_versions', upgrade_backfills.BACKFILLS)
        self.assertLess(upgrade_backfills.BACKFILLS.index('backfill_source_versions'), upgrade_backfills.BACKFILLS.index('rerate_findings'))
        out = StringIO()
        call_command('backfill_source_versions', stdout=out)
        self.assertIn('Dry run', out.getvalue())


class WebserverTests(VersionFixture, TestCase):
    def test_the_stored_server_header_becomes_readings_less_what_a_port_states(self):
        scan = self.host_scan(web=True, ports=((8443, 'https', 'Apache httpd', '2.4.37'),))
        sub = scan.subdomain_set.select_related('target_domain').prefetch_related('technologies', 'ip_addresses__ports').get()
        sub.webserver = 'Apache/2.4.37 (Red Hat Enterprise Linux) OpenSSL/1.1.1k mod_wsgi/4.6.4 Python/3.6'
        sub.save(update_fields=['webserver'])
        version_sources.refresh_host(sub)
        got = {(r.kind, r.product): r.version for r in ProbeObservation.objects.filter(probe=source_versions.WEBSERVER_PROBE)}
        self.assertEqual(got, {('version', 'OpenSSL'): '1.1.1k', ('version', 'mod_wsgi'): '4.6.4'})  # Apache is the port's; Python is vsrc:passive's
        self.assertIn('OpenSSL:1.1.1k', names(sub))


# CVE-2025-22224 as cve.now carries it: VMware writes each fix as the patch release and its build
ESXI_22224 = [{'vendor': 'VMware', 'product': 'ESXi', 'ranges': [{'introduced': '8.0', 'fixed': 'ESXi80U3d-24585383'},
                                                                 {'introduced': '8.0', 'fixed': 'ESXi80U2d-24585300'},
                                                                 {'introduced': '7.0', 'fixed': 'ESXi70U3s-24585291'}]}]
ESXI_OLD = [{'vendor': 'VMware', 'product': 'ESXi', 'ranges': [{'introduced': '7.0', 'fixed': 'ESXi70U3c-19193900'}]}]  # fixed before 21930508


class VersionScriptTests(VersionFixture, TestCase):
    def stored(self):
        scan = self.host_scan(web=False)
        port_inventory.persist_inventory(fixture('nmap_vmware.json')['hosts'], os_reliable=True)
        sub = Subdomain.objects.select_related('target_domain').prefetch_related('technologies', 'ip_addresses__ports').get(scan_history=scan)
        version_sources.refresh_host(sub)
        return scan, sub

    def correlate(self, scan):
        cve_by_id, index = correlation.cve_pool()
        correlation.correlate_subdomains(list(correlation.candidate_subdomains(index).filter(scan_history=scan)), index, cve_by_id, min_confidence=0.4)

    def test_the_esxi_build_is_a_reading_and_a_technology_though_the_port_states_the_release(self):
        _scan, sub = self.stored()
        self.assertTrue(Port.objects.get(number=443).extra['version_scripts']['vmware-version'].startswith('  Server version: VMware ESXi 7.0.3'))
        row = rows(source_versions.NMAP_PROBE)[('version', 'VMware ESXi', 443)]
        self.assertEqual((row.version, row.evidence['build'], row.evidence['cpe'], row.evidence['source']),
                         ('7.0.3-21930508', '21930508', 'cpe:/o:vmware:esxi:7.0.3', 'nse:vmware-version'))
        self.assertIn('VMware ESXi:7.0.3-21930508', names(sub))

    def test_correlation_decides_by_the_build(self):
        hit = CVEEntry.objects.create(cve_id='CVE-2025-22224', title='VMX TOCTOU', kev=True, cvss=9.3, published_at=timezone.now(), affected=ESXI_22224)
        old = CVEEntry.objects.create(cve_id='CVE-2026-300040', title='fixed earlier', cvss=9.8, published_at=timezone.now(), affected=ESXI_OLD)
        scan, _sub = self.stored()
        self.correlate(scan)
        match = CVEMatch.objects.get(cve_entry=hit, source='tech')
        self.assertEqual((match.matched_product, match.matched_version, match.version_in_range), ('ESXi', '7.0.3-21930508', True))
        self.assertEqual(match.evidence['range'], {'introduced': '7.0.3', 'fixed': '7.0.3-24585291'})
        # build 21930508 is past the earlier fix (19193900): no match from the build, and the port's bare "7.0.3" is no proof either way
        self.assertFalse(CVEMatch.objects.filter(cve_entry=old, version_in_range=True).exclude(ai_verdict='not_affected').exists())

    def test_search_finds_the_reading(self):
        self.stored()
        self.assertEqual({r.product for r in version_sources.search_rows('component', 'vmware esxi')}, {'VMware ESXi'})
        self.assertIn('VMware ESXi', {r.product for r in version_sources.search_rows('vsource', 'nmap')})
        self.assertEqual({r.product for r in source_versions.os_rows('esxi')}, {'VMware ESXi'})  # its operating system CPE: os:esxi

    def test_the_backfill_reads_stored_version_scripts_and_correlates(self):
        hit = CVEEntry.objects.create(cve_id='CVE-2025-22224', title='VMX TOCTOU', kev=True, cvss=9.3, published_at=timezone.now(), affected=ESXI_22224)
        scan, sub = self.stored()
        ProbeObservation.objects.filter(probe=source_versions.NMAP_PROBE).delete()  # stored before this reader existed
        sub.technologies.clear()
        scan.scan_status = 2
        scan.save(update_fields=['scan_status'])
        self.assertEqual(source_versions.catch_up_version_scripts(apply=False), {'hosts': 1, 'readings': 0, 'matches': 0})
        out = source_versions.catch_up_version_scripts(apply=True)
        self.assertEqual(out['readings'], 1)
        self.assertEqual(rows(source_versions.NMAP_PROBE)[('version', 'VMware ESXi', 443)].version, '7.0.3-21930508')
        self.assertTrue(CVEMatch.objects.filter(cve_entry=hit, version_in_range=True).exists())
        source_versions.catch_up_version_scripts(apply=True)  # idempotent
        self.assertEqual(ProbeObservation.objects.filter(probe=source_versions.NMAP_PROBE, product='VMware ESXi').count(), 1)
        self.assertIn('backfill_version_scripts', upgrade_backfills.BACKFILLS)
        self.assertLess(upgrade_backfills.BACKFILLS.index('backfill_version_scripts'), upgrade_backfills.BACKFILLS.index('rerate_findings'))


class RunZeroServiceTests(ReportedFixture, TestCase):
    def synced(self, hw='Cisco ISR4321', services=None):
        sub = self.host_scan(web=False).subdomain_set.select_related('target_domain').get()
        ip = IpAddress.objects.get(address=self.ADDRESS)
        ip.org = self.project.org
        ip.save(update_fields=['org'])
        asset = runzero.parse_asset({**fixture('runzero_asset.json'), 'hw': hw, 'last_seen': int(timezone.now().timestamp())})
        if services is None:
            services = [runzero.parse_service({**r, 'service_updated_at': int(timezone.now().timestamp())})
                        for r in fixture('runzero_services_page.json')['services']]
        runzero_sync._enrich(self.project, {self.ADDRESS: asset}, [], services=[s for s in services if s])
        return sub

    def test_services_are_reported_readings_on_their_port_and_matched_while_fresh(self):
        row = cve('CVE-2026-300050', 'eclipse', 'jetty', '9.4.0', '9.4.52')
        self.synced()
        got = {(r.kind, r.product, r.port): (r.version, r.evidence.get('cpe'), r.evidence['provider']) for r in
               ProbeObservation.objects.filter(probe=source_versions.RUNZERO_PROBE)}
        self.assertEqual(got[('reported', 'OpenSSH', 22)], ('8.2p1', 'cpe:/a:openbsd:openssh:8.2p1', 'runzero'))
        self.assertEqual(got[('reported', 'Jetty', 8080)], ('9.4.41', 'cpe:/a:eclipse:jetty:9.4.41', 'runzero'))
        self.assertEqual(got[('reported', 'Cisco IOS', 0)][0], '15.2(4)M7')  # the asset's operating system, as before
        self.assertFalse(Port.objects.filter(number__in=(22, 80, 8080)).exists())  # runZero's services make no port row
        match, = self.correlate(row)
        self.assertEqual((match.source, match.matched_version, match.evidence['reported_by']), ('tech', '9.4.41', 'runzero'))
        self.assertLessEqual(match.confidence, source_versions.REPORTED_CONFIDENCE)
        # our own scan of 8080 sees it closed: the third-party reading of that port is no longer matched
        IpAddress.objects.get(address=self.ADDRESS).ports.add(Port.objects.create(number=8080, service_name='http', state='closed', source='nmap'))
        self.assertEqual(self.correlate(row), [])

    def test_a_service_runzero_no_longer_lists_is_dropped(self):
        sub = self.synced()
        asset = runzero.parse_asset({**fixture('runzero_asset.json'), 'last_seen': int(timezone.now().timestamp())})
        runzero_sync._enrich(self.project, {self.ADDRESS: asset}, [], services=[])
        self.assertEqual({r.product for r in ProbeObservation.objects.filter(probe=source_versions.RUNZERO_PROBE)}, {'Cisco IOS'})
        self.assertTrue(sub.pk)

    def test_the_firmware_hint_is_shown_and_searched_never_matched(self):
        row = cve('CVE-2026-300051', 'ubiquiti', 'unifi ap', '6.0.0', '6.6.0')
        self.synced(hw='Ubiquiti UniFi AP 6.5.28', services=[])
        hint = ProbeObservation.objects.get(probe=source_versions.RUNZERO_PROBE, product='Ubiquiti UniFi AP')
        self.assertEqual((hint.version, hint.port, hint.evidence['hint'], hint.evidence['part']), ('6.5.28', 0, True, 'hw'))
        self.assertEqual(self.correlate(row), [])
        listed = {i['product']: i for i in version_sources.readings_for([self.project.id], ['app.rt.test'])[(self.project.id, 'app.rt.test')]}
        self.assertEqual((listed['Ubiquiti UniFi AP']['matched'], listed['Ubiquiti UniFi AP']['hint']), (False, True))
        self.assertEqual({r.product for r in version_sources.search_rows('component', 'ubiquiti unifi ap')}, {'Ubiquiti UniFi AP'})

    def test_os_search_finds_the_operating_system_never_a_service_or_the_hardware(self):
        self.synced(hw='Ubiquiti UniFi AP 6.5.28')
        self.assertEqual({r.product for r in source_versions.os_rows('cisco')}, {'Cisco IOS'})
        self.assertEqual(list(source_versions.os_rows('openssh')), [])
        self.assertEqual(list(source_versions.os_rows('unifi')), [])
        self.assertEqual({r.product for r in version_sources.search_rows('vsource', 'runzero')},
                         {'Cisco IOS', 'Ubiquiti UniFi AP', 'OpenSSH', 'Apache HTTPD', 'PHP', 'Jetty'})
