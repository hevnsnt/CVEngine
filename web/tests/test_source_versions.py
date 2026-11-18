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
        self.assertEqual((got['label'], got['version'], got['cpe']), ('openssh', '8.9p1', 'cpe:/a:openbsd:openssh:8.9p1'))
        self.assertIsNone(source_versions.reported_cpe('cpe:/o:canonical:ubuntu_linux'))
        self.assertIsNone(source_versions.reported_cpe('cpe:/a:igor_sysoev:nginx'))
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

        def check(host, port):
            db_exposure._note(host, port, fixture('db_probe_replies.json')['redis']['evidence'])
            return True
        db_exposure.run_db_exposure_checks(scan.id, checks={'redis': ('Redis', check)})
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
        reading = ProbeObservation.objects.get(probe=source_versions.SHODAN_PROBE)
        self.assertEqual((reading.kind, reading.outcome, reading.product, reading.version, reading.project_id),
                         ('reported', 'reported', 'openssh', '8.9p1', self.project.id))
        self.assertEqual((reading.evidence['cpe'], reading.evidence['provider'], reading.evidence['undated']),
                         ('cpe:/a:openbsd:openssh:8.9p1', 'shodan_idb', True))
        self.assertNotIn('openssh:8.9p1', names(sub))  # never a first-party technology
        self.assertIn('jQuery', names(sub))  # a library's CPE keeps the library rule: the name, no version
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
        self.assertEqual(rows(source_versions.SHODAN_PROBE)[('reported', 'openssh', 0)].version, '8.9p1')
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
