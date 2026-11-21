"""Tomcat's HTTP connector version is never Tomcat's: the port scan's "Apache Tomcat/Coyote JSP engine 1.1" (and the Server header's
"Apache-Coyote/1.1") is Tomcat with no version, an unversioned lead, never a version below every branch a Tomcat advisory fixes.

``protocol_versions`` in cveFeed/data/product_aliases.json (cveFeed.correlation.stated_version), the matches the connector version made
closing on the next correlation, and the update backfill that correlates the hosts carrying it (``backfill_protocol_versions``)."""
import io

from django.core.management import call_command
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import correlation, match_policy, upgrade_backfills
from tests.test_tech_normalisation import Pool

CONNECTOR = 'Apache Tomcat/Coyote JSP engine'
STALE = ('Closed automatically: the host no longer matches this CVE (the version moved out of the affected range or the product is gone).')


def tomcat():
    # every release before 9.0.31, the shape a record with only "versions before" takes: a "1.1" is inside it
    return {'vendor': 'Apache Software Foundation', 'product': 'Apache Tomcat', 'ranges': [{'introduced': '0', 'fixed': '9.0.31'}]}


def tomcat_branches():
    # a branch-by-branch fix list: a "1.1" is below every branch it lists, which the end-of-life rule takes as evidence
    return {'vendor': 'Apache Software Foundation', 'product': 'Apache Tomcat', 'ranges': [
        {'introduced': '8.5', 'fixed': '8.5.51'}, {'introduced': '9.0', 'fixed': '9.0.31'}]}


class ConnectorVersionTests(SimpleTestCase):
    def test_the_connector_version_is_no_tomcat_version(self):
        self.assertEqual(correlation.split_port_product(CONNECTOR, '1.1'), (CONNECTOR, '', ''))
        self.assertEqual(correlation.split_port_product('Apache-Coyote/1.1'), ('Apache-Coyote', '', ''))
        self.assertEqual(correlation.split_name_version('Apache Coyote:1.1'), ('Apache Coyote', ''))
        self.assertEqual(correlation.stated_version(CONNECTOR, '1.1'), '')
        self.assertEqual(correlation.stated_version('Apache Tomcat', '9.0.30'), '9.0.30')  # Tomcat's own release is kept

    def test_the_connector_is_still_tomcat_and_a_lead(self):
        pool = Pool(tomcat())
        self.assertEqual(pool.reach(CONNECTOR), {1})
        self.assertEqual(pool.reach('Apache-Coyote'), {1})

    def test_the_connector_version_read_as_tomcats_was_hard_evidence(self):
        # what the bug did: 1.1 inside "every release before 9.0.31", or below every branch of a fix list (the end-of-life rule)
        pool = Pool(tomcat(), tomcat_branches())
        pool.cves[1].kev = True  # the end-of-life rule passes an "ice" CVE by
        details = {}
        found = {cve.id: in_range for cve, _p, in_range in correlation._match_candidates(
            CONNECTOR, correlation.parse_version('1.1'), correlation._norm(CONNECTOR), pool.index, pool.by_id, details=details, raw='1.1')}
        self.assertEqual(found, {1: True, 2: None})
        self.assertTrue(match_policy.hard_version_evidence(None, details[2]))

    def test_the_unverified_product_lead_has_no_version(self):
        class Port:
            id, number, protocol, cpe, service_name = 7, 8080, 'tcp', 'cpe:/a:apache:tomcat', 'http'
            product, version = CONNECTOR, '1.1'
        leads = match_policy.unversioned_leads([], [('192.0.2.5', Port)])
        self.assertEqual([lead['name'] for lead in leads], [CONNECTOR])


class CorrelationTests(TestCase):
    def setUp(self):
        from cveFeed.models import CVEEntry
        from dashboard.models import Org, Project
        from scanEngine.models import EngineType
        from startScan.models import IpAddress, Port, ScanHistory, Subdomain
        from targetApp.models import Domain
        correlation._INDEX_CACHE.update(key=None, value=None)
        org = Org.objects.create(name='A', slug='a')
        project = Project.objects.create(name='P', slug='pa', insert_date=timezone.now(), org=org)
        domain = Domain.objects.create(name='tc.test', project=project, insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
        scan = ScanHistory.objects.create(domain=domain, scan_type=engine, scan_status=2, start_scan_date=timezone.now())
        self.cve = CVEEntry.objects.create(cve_id='CVE-2099-0001', kev=True, cvss=9.8, published_at=timezone.now(), affected=[tomcat()])
        self.sub = Subdomain.objects.create(name='app.tc.test', target_domain=domain, scan_history=scan)
        self.ip = IpAddress.objects.create(address='192.0.2.50')
        self.sub.ip_addresses.add(self.ip)
        self.port = Port.objects.create(number=8080, product=CONNECTOR, version='1.1', cpe='cpe:/a:apache:tomcat', state='open', service_name='http')
        self.ip.ports.add(self.port)

    def correlate(self):
        cve_by_id, index = correlation.cve_pool()
        leads = {}
        rows = correlation.collect_subdomain_matches(self.sub, index, cve_by_id, leads=leads)
        return rows, leads

    def test_a_connector_port_gives_no_tomcat_version_and_no_match_only_a_lead(self):
        rows, leads = self.correlate()
        self.assertEqual(rows, [])
        self.assertEqual(leads, {self.cve.pk: {(self.sub.target_domain_id, self.sub.name)}})

    def test_an_existing_match_the_connector_version_made_closes_on_the_next_correlation(self):
        from cveFeed.models import CVEMatch
        stale = CVEMatch.objects.create(cve_entry=self.cve, subdomain=self.sub, source='port', matched_product='Apache Tomcat',
                                        matched_version='1.1', version_in_range=True, confidence=0.6,
                                        evidence={'source': 'port', 'source_id': self.port.pk, 'raw_version': '1.1'})
        cve_by_id, index = correlation.cve_pool()
        correlation.correlate_subdomains([self.sub], index, cve_by_id)
        stale.refresh_from_db()
        self.assertEqual((stale.ai_verdict, stale.ai_reason, stale.confidence), ('not_affected', STALE, 0.0))
        self.assertEqual(CVEMatch.objects.count(), 1)  # nothing new opened

    def test_a_real_tomcat_version_from_another_source_still_matches(self):
        from startScan.models import Port, Technology
        self.sub.technologies.add(Technology.objects.create(name='Apache Tomcat:9.0.30'))  # the release notes or the error page read it
        rows, _leads = self.correlate()
        self.assertEqual([(r['source'], r['matched_version'], r['version_in_range']) for r in rows], [('tech', '9.0.30', True)])
        other = Port.objects.create(number=8443, product='Apache Tomcat', version='9.0.30', state='open', service_name='https')
        self.ip.ports.add(other)  # nmap's error-page fingerprint states the release itself
        rows, _leads = self.correlate()
        self.assertEqual(sorted((r['source'], r['matched_version'], r['version_in_range']) for r in rows),
                         [('port', '9.0.30', True), ('tech', '9.0.30', True)])

    def test_the_backfill_correlates_the_hosts_carrying_the_connector(self):
        from cveFeed.models import CVEMatch
        from cveFeed.management.commands.backfill_protocol_versions import touched_hosts
        stale = CVEMatch.objects.create(cve_entry=self.cve, subdomain=self.sub, source='port', matched_product='Apache Tomcat',
                                        matched_version='1.1', version_in_range=True, confidence=0.6,
                                        evidence={'source': 'port', 'source_id': self.port.pk, 'raw_version': '1.1'})
        self.assertEqual(list(touched_hosts().values_list('name', flat=True)), ['app.tc.test'])
        out = io.StringIO()
        call_command('backfill_protocol_versions', stdout=out)
        self.assertIn('dry run: 1 current hosts', out.getvalue())
        stale.refresh_from_db()
        self.assertNotEqual(stale.ai_verdict, 'not_affected')  # a dry run changes nothing
        call_command('backfill_protocol_versions', apply=True, stdout=out)
        stale.refresh_from_db()
        self.assertEqual((stale.ai_verdict, stale.ai_reason), ('not_affected', STALE))
        call_command('backfill_protocol_versions', apply=True, stdout=out)  # again: nothing changes
        self.assertEqual(CVEMatch.objects.count(), 1)

    def test_the_backfill_of_730_reaches_these_hosts_too(self):
        from cveFeed.management.commands.backfill_name_versions import hosts_for
        self.assertEqual(list(hosts_for([], []).values_list('name', flat=True)), ['app.tc.test'])

    def test_the_backfill_runs_with_the_update_before_the_rescore(self):
        names = upgrade_backfills.BACKFILLS
        self.assertLess(names.index('backfill_name_versions'), names.index('backfill_protocol_versions'))
        self.assertLess(names.index('backfill_protocol_versions'), names.index('rerate_findings'))
