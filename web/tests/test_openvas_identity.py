"""OpenVAS CVE matches and the product-identity check (#414).

An OpenVAS match is keyed by its NVT and port ("OpenVAS NVT <oid> on 22/tcp"). The identity check compared that name with the advisory's
products, never matched, and closed every match an NVT did not confirm as "different product". These tests rebuild that shape with
synthetic records (192.0.2.0/24, example.com): a remote-banner result (QoD 30) with "Installed version" / "Fixed version" text is imported,
stays open and records what the NVT identified; the identity check and its sweep leave it alone; triage sees the scanner's evidence; a
confirmed match is attributed to OpenVAS; and the backfill command reopens only the automatic closures, and only with --apply."""
from io import StringIO
from unittest import mock

from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone
from lxml import etree

from cveFeed import correlation, openvas_scan as ov, triage
from cveFeed.models import CVEEntry, CVEMatch, Triage
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain

OID_BIND = '1.3.6.1.4.1.25623.1.0.145867'
OID_SSH = '1.3.6.1.4.1.25623.1.0.114680'
BIND_TEXT = 'Installed version: 9.11.3\nFixed version:     9.11.31\nInstallation\npath / port:       53/tcp'


def result_xml(oid=OID_BIND, name='ISC BIND 9.x DoS Vulnerability (CVE-2021-25216) - Linux', port='53/tcp', qod=30,
               qod_type='remote_banner_unreliable', cve='CVE-2021-25216', description=BIND_TEXT, cpe='cpe:/a:isc:bind:9.11.3', severity=8.1):
    """One <result> as gvmd prints it, with the <detection> block that names the product the detection NVT identified."""
    detection = (f'<detection><result id="d1"><details><detail><name>product</name><value>{cpe}</value></detail>'
                 f'<detail><name>location</name><value>{port}</value></detail>'
                 f'<detail><name>source_oid</name><value>1.3.6.1.4.1.25623.1.0.10028</value></detail></details></result></detection>') if cpe else ''
    return etree.fromstring(
        f'<result id="r1"><name>{name}</name><host>192.0.2.10<hostname>ns.example.com</hostname></host><port>{port}</port>'
        f'<nvt oid="{oid}"><type>nvt</type><name>{name}</name><family>Denial of Service</family>'
        f'<tags>cvss_base_vector=AV:N/AC:L/Au:N/C:N/I:N/A:C|summary=A flaw.|solution_type=VendorFix</tags>'
        f'<refs><ref type="cve" id="{cve}"/></refs></nvt><threat>High</threat><severity>{severity}</severity>'
        f'<qod><value>{qod}</value><type>{qod_type}</type></qod><description>{description}</description>{detection}</result>')


class Fixture:
    def setUp(self):
        org = Org.objects.create(name='Example', slug='example-org')
        self.project = Project.objects.create(name='Example', slug='example', insert_date=timezone.now(), org=org)
        self.domain = Domain.objects.create(name='example.com', project=self.project, insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
        scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=timezone.now(), scan_status=2, tasks=[],
                                          results_dir='x')
        self.sub = Subdomain.objects.create(name='ns.example.com', target_domain=self.domain, scan_history=scan)
        self.bind = CVEEntry.objects.create(cve_id='CVE-2021-25216', title='BIND GSS-TSIG buffer overflow', published_at=timezone.now(),
                                            cvss=8.1, affected=[{'vendor': 'ISC', 'product': 'BIND9',
                                                                 'ranges': [{'introduced': '9.5.0', 'fixed': '9.11.31'}]}])
        self.ssh = CVEEntry.objects.create(cve_id='CVE-2024-6387', title='regreSSHion', published_at=timezone.now(), cvss=8.1,
                                           affected=[{'vendor': 'OpenBSD', 'product': 'OpenSSH', 'ranges': [{'introduced': '8.5p1', 'fixed': '9.8p1'}]}])
        mock.patch('cveFeed.scoring.rescore_for_matches').start()
        mock.patch('reNgine.tasks.geo_localize.delay').start()
        mock.patch('cveFeed.tasks.run_hygiene_task.delay').start()
        self.addCleanup(mock.patch.stopall)

    def import_(self, *xml):
        found = [ov.parse_result(x) for x in xml]
        ov.record_observations(self.project.pk, self.domain.pk, self.sub.name, found, scanned_now=True)
        return ov.apply_observations(self.sub)


class ImportTests(Fixture, TestCase):


    def test_a_tech_match_with_the_same_kind_of_name_is_still_closed(self):
        """The exemption is OpenVAS's only: a correlated sighting whose name is not the advisory's product still closes."""
        m = CVEMatch.objects.create(cve_entry=self.bind, subdomain=self.sub, source='tech', matched_product='Some Other DNS Server',
                                    matched_version='9.11.3', version_in_range=True, evidence={'source': 'tech'})
        self.assertIn('different product', correlation.invalid_identity_reason(m))


class TriagePayloadTests(Fixture, TestCase):


    def test_any_other_match_has_no_openvas_block(self):
        m = CVEMatch.objects.create(cve_entry=self.bind, subdomain=self.sub, source='port', matched_product='BIND', matched_version='9.11.3',
                                    version_in_range=True, evidence={'source': 'port', 'qod': 99, 'result': 'x'})
        m = CVEMatch.objects.select_related('cve_entry', 'subdomain__target_domain').get(pk=m.pk)
        self.assertNotIn('openvas', triage.describe_cve_match(m)['payload'])


class ConfirmedReasonTests(Fixture, TestCase):

    def test_a_nuclei_hit_keeps_its_wording(self):
        _floor, found = triage.hard_evidence('cve_match', {'template_result': 'vulnerable'})
        self.assertIn('a nuclei template check matched this host', found)


class ReopenCommandTests(Fixture, TestCase):
    def closed(self, cve, port, **over):
        m = CVEMatch.objects.create(cve_entry=cve, subdomain=self.sub, source='openvas', matched_product=f'OpenVAS NVT 1.2.3 on {port}',
                                    evidence={'source': 'openvas', 'qod': 30, 'port': port}, ai_verdict='not_affected', confidence=0.0,
                                    ai_model='deterministic-correlation',
                                    ai_reason=f'{correlation.DIFFERENT_PRODUCT}; it was recorded as "OpenVAS NVT 1.2.3 on {port}", but the advisory '
                                              'covers "BIND9". This closes this candidate match only.')
        for key, value in over.items():
            setattr(m, key, value)
        m.save()
        Triage.objects.create(project=self.project, domain=self.domain, host=self.sub.name, kind='cve_match', match=m, status='triaged',
                              classification='not_applicable', reason=m.ai_reason)
        return m

    def run_it(self, *args):
        out = StringIO()
        call_command('reopen_openvas_identity_closures', *args, stdout=out)
        return out.getvalue()

    def setUp(self):
        super().setUp()
        self.automatic = self.closed(self.bind, '53/tcp')
        self.person = self.closed(self.ssh, '22/tcp', remediation_status='accepted_risk')  # a person worked it
        self.ai = self.closed(self.bind, '953/tcp', ai_model='claude', ai_reason='The host runs a patched build.')
        self.other = self.closed(self.ssh, '2222/tcp', ai_reason='Closed automatically: a later OpenVAS scan of this host no longer reports this result.')
        self.tech = self.closed(self.bind, '54/tcp', source='tech')

    def state(self):
        return {name: (m.ai_verdict, m.triage.classification) for name, m in
                ((n, CVEMatch.objects.select_related('triage').get(pk=x.pk)) for n, x in
                 (('automatic', self.automatic), ('person', self.person), ('ai', self.ai), ('other', self.other), ('tech', self.tech)))}

    def test_the_dry_run_lists_per_project_and_writes_nothing(self):
        before = self.state()
        out = self.run_it()
        self.assertIn('example: would reopen 1', out)
        self.assertIn('CVE-2021-25216 on ns.example.com', out)
        self.assertEqual(self.state(), before)

    def test_apply_reopens_only_the_automatic_openvas_closures(self):
        out = self.run_it('--apply', '--project', 'example')
        self.assertIn('example: reopened 1', out)
        state = self.state()
        self.assertEqual(state['automatic'], ('', ''))
        for name in ('person', 'ai', 'other', 'tech'):
            self.assertEqual(state[name], ('not_affected', 'not_applicable'), name)
        m = CVEMatch.objects.get(pk=self.automatic.pk)
        self.assertEqual((m.ai_reason, m.ai_model, m.confidence), ('', '', 0.3))
        self.assertEqual(m.triage.status, 'pending')
        self.assertIn('identity_reopened_at', m.evidence)
        self.assertIn('would reopen (dry run, nothing written) 0', self.run_it())  # idempotent: nothing left to reopen

    def test_another_project_is_not_touched(self):
        other = Project.objects.create(name='Other', slug='other', insert_date=timezone.now(), org=self.project.org)
        self.run_it('--apply', '--project', other.slug)
        self.assertEqual(self.state()['automatic'], ('not_affected', 'not_applicable'))
