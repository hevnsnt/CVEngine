"""Dangling-DNS findings (bbot's baddns) rated by what an outsider can claim: cveFeed.dangling_dns, its use when bbot findings are stored, the
rerate_dangling_dns backfill, and the ownership check before bucket names are guessed (cveFeed.domain_ownership).

Every fixture is synthetic (example.com/.net/.org, documentation addresses) and keeps only the shape of a stored bad input. No test sends a DNS
or HTTP request: the network is a fake (FakeDns) that answers like authoritative servers do."""
import io
import os
from unittest import mock

from django.core.management import call_command
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import dangling_dns as dd
from cveFeed import domain_ownership as own
from dashboard.models import Org, Project
from reNgine import discovery_events as bbot_lib
from tests.fake_scanner import FakeScanner
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain

GCLOUD = [f'ns-cloud-c{i}.googledomains.com' for i in range(1, 5)]


def baddns(head, trigger, signature='GENERIC', confidence='LOW', indicator='DNSWalk Analysis', module='NS'):
    """A description the way bbot's baddns module writes it."""
    return (f'{head}. Confidence: [{confidence}] Signature: [{signature}] Indicator: [{indicator}] Trigger: [{", ".join(trigger)}] '
            f'baddns Module: [{module}]')


NS_HEAD = 'Dangling NS Records (NS records without SOA) with known impact'
NX_HEAD = 'Dangling CNAME, possible subdomain takeover (NXDOMAIN technique)'
HTTP_HEAD = 'Dangling CNAME, probable subdomain takeover (HTTP String Match)'






class ParseTests(SimpleTestCase):
    def test_the_three_rated_kinds_and_their_trigger(self):
        p = dd.parse(baddns(NS_HEAD, GCLOUD, signature='cloud.google.com'))
        self.assertEqual((p.kind, p.signature, p.triggers), (dd.KIND_NS, 'cloud.google.com', GCLOUD))
        self.assertEqual(dd.parse(baddns(NX_HEAD, ['x.example.net'], module='CNAME')).kind, dd.KIND_NXDOMAIN)
        self.assertEqual(dd.parse(baddns(HTTP_HEAD, ['email.example.com', 'mailgun.org'], module='CNAME')).triggers,
                         ['email.example.com', 'mailgun.org'])
        self.assertIsNone(dd.parse(baddns('No DMARC record found', ['_dmarc.example.com'], module='DMARC')))
        self.assertIsNone(dd.parse('Subdomain takeover: dangling CNAME'))

    def test_a_stored_note_is_not_read_as_baddns_text_and_is_replaced_not_stacked(self):
        text = baddns(NS_HEAD, GCLOUD)
        once = dd.with_note(text, dd.Rating(note='first'))
        twice = dd.with_note(once, dd.Rating(note='second'))
        self.assertEqual(twice, text + dd.NOTE_MARKER + 'second')
        self.assertEqual(dd.parse(twice).triggers, GCLOUD)









class Stored(TestCase):
    def setUp(self):
        org = Org.objects.create(name='D', slug='d-dd')
        self.project = Project.objects.create(name='P', slug='p-dd', insert_date=timezone.now(), org=org)
        self.domain = Domain.objects.create(name='example.com', project=self.project, insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
        self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=timezone.now(), scan_status=1, tasks=[],
                                               results_dir='x')
        self.ctx = {'scan_history_id': self.scan.id, 'domain_id': self.domain.id, 'subdomain_id': None, 'subscan_id': None}
        mock.patch('reNgine.tasks.geo_localize.delay').start()
        self.addCleanup(mock.patch.stopall)
        mock.patch('agentapi.sentinel_dispatch._resolves', return_value=True).start()
        mock.patch('time.sleep').start()
        self.rated = {'dev.d.fs.app.example.com': {'state': 'rated', 'severity': 3, 'drop': False, 'zone': 'd.fs.app.example.com',
                                                   'note': 'd.fs.app.example.com is delegated to Google Cloud DNS and no zone is there: anyone with an account can claim it'},
                      'vision.example.com': {'state': 'rated', 'severity': None, 'drop': True, 'zone': '',
                                             'note': 'vision.example.com is a CNAME to abc123.up.railway.app: the provider answers for it'}}

    def event(self, host, description):
        return {'type': 'FINDING', 'id': host, 'host': host, 'module': 'baddns', 'data': None,
                'data_json': {'host': host, 'severity': 'MEDIUM', 'description': description}}

    def scanner(self):
        """A Sentinel that rates each finding as ``self.rated`` says (by host; a host it names no rating for is one it could not answer)."""
        def serve(task):
            rows = [{'id': c['id'], **self.rated.get(c['host'], {'state': 'unknown'})} for c in task['target']['checks']]
            return {'outcome': 'done', 'ratings': rows, 'touched': [], 'refused': []}
        return FakeScanner(kinds=['dangling_dns_check'], responders={'dangling_dns_check': serve})

    def persist(self, *events):
        from reNgine.tasks import persist_bbot_result
        from tests.discovery_fixtures import fold_findings
        result = fold_findings(events)
        with self.scanner():
            persist_bbot_result(result, ctx=self.ctx)


class StoredFindingTests(Stored):
    def test_a_claimable_delegation_is_stored_hot_with_its_host_and_a_provider_zone_is_not_stored(self):
        self.persist(self.event('dev.d.fs.app.example.com', baddns(NS_HEAD, GCLOUD, signature='cloud.google.com')),
                     self.event('vision.example.com', baddns('Dangling NS Records (NS records without SOA)', ['ns1.railway.app'])))
        v = Vulnerability.objects.get()
        self.assertEqual((v.severity, v.subdomain.name, v.http_url), (3, 'dev.d.fs.app.example.com', 'dev.d.fs.app.example.com'))
        self.assertIn(dd.NOTE_MARKER + 'd.fs.app.example.com is delegated to Google Cloud DNS', v.description)
        from cveFeed.threat import finding_heat
        self.assertEqual(finding_heat(v), 'fire')

    def test_a_stale_cname_is_stored_as_ice_and_the_row_key_does_not_change(self):
        description = baddns(NX_HEAD, ['internal-lb-1.us-east-1.elb.amazonaws.com'], confidence='MEDIUM', module='CNAME')
        self.rated = {'pda.example.com': {'state': 'rated', 'severity': 1, 'drop': False, 'zone': '', 'note': 'the target does not resolve: stale, nobody else can claim it'}}
        self.persist(self.event('pda.example.com', description))
        self.persist(self.event('pda.example.com', description))  # seen again: the same row
        v = Vulnerability.objects.get()
        self.assertEqual((v.severity, v.matcher_name), (1, bbot_lib.finding_key(description)))
        from cveFeed.threat import finding_heat
        self.assertEqual(finding_heat(v), 'ice')


class RerateCommandTests(Stored):
    def row(self, host, description, severity=2, sub=True):
        subdomain = Subdomain.objects.create(scan_history=self.scan, target_domain=self.domain, name=host) if sub else None
        return Vulnerability.objects.create(name='x', severity=severity, description=description, source='bbot', type='bbot', template_id='baddns',
                                            target_domain=self.domain, scan_history=self.scan, subdomain=subdomain, http_url=host)

    def run_command(self, *args):
        out = io.StringIO()
        with self.scanner():
            call_command('rerate_dangling_dns', *args, stdout=out)
        return out.getvalue()

    def test_dry_run_reports_and_writes_nothing_then_apply_writes(self):
        ns = self.row('dev.d.fs.app.example.com', baddns(NS_HEAD, GCLOUD), sub=False)  # stored with no host
        cname = self.row('vision.example.com', baddns('Dangling NS Records (NS records without SOA)', ['ns1.railway.app']))
        closed = self.row('other.d.fs.app.example.com', baddns(NS_HEAD, GCLOUD))
        closed.remediation_status = 'false_positive'
        closed.save()
        report = self.run_command()
        self.assertIn('dry run', report)
        self.assertIn('p-dd: examined: 2, host filled: 1, medium -> high: 1, medium -> info: 1', report)
        ns.refresh_from_db()
        self.assertEqual((ns.severity, ns.subdomain_id), (2, None))
        report = self.run_command('--apply')
        self.assertIn('written: 2', report)
        ns.refresh_from_db()
        cname.refresh_from_db()
        closed.refresh_from_db()
        self.assertEqual((ns.severity, ns.subdomain.name, cname.severity, closed.severity), (3, 'dev.d.fs.app.example.com', 0, 2))
        self.assertIn('is a CNAME to abc123.up.railway.app', cname.description)


class OwnershipTests(SimpleTestCase):
    """Item 21: no bucket names are guessed from a domain that shows another owner."""

    class Lookup:
        def __init__(self, records, registrants=None):
            self.recs, self.regs = records, registrants or {}

        def records(self, name, rtype):
            return self.recs.get((name, rtype), [])

        def registrant(self, domain):
            return self.regs.get(domain, '')

    INFRA = {('example.com', 'NS'): ['ns1.example-dns.net.', 'ns2.example-dns.org.'], ('example.com', 'MX'): ['10 smtp.example-retail.net.'],
             ('example-client.com', 'NS'): ['ns1.markmonitor.com.'], ('example-client.com', 'MX'): ['10 aspmx.l.google.com.']}

    def test_another_companys_name_and_mail_servers_mean_another_owner(self):
        reason = own.foreign_owner('example.com', ['example-client.com'], self.Lookup(self.INFRA))
        self.assertIn('example-dns.net', reason)
        self.assertIn('example-retail.net', reason)

    def test_a_different_published_registrant_means_another_owner_and_the_same_one_means_the_same(self):
        regs = {'example.com': 'Example Retail, Inc.', 'example-client.com': 'Example Client LLC'}
        self.assertIn('"Example Retail, Inc."', own.foreign_owner('example.com', ['example-client.com'], self.Lookup({}, regs)))
        regs['example-client.com'] = 'EXAMPLE RETAIL INC'
        self.assertIsNone(own.foreign_owner('example.com', ['example-client.com'], self.Lookup(self.INFRA, regs)))

    def test_no_verdict_without_positive_evidence(self):
        lookup = self.Lookup({**self.INFRA, ('example.com', 'MX'): ['10 aspmx.l.google.com.']})  # mail at a shared provider
        self.assertIsNone(own.foreign_owner('example.com', ['example-client.com'], lookup))
        shared = self.Lookup({**self.INFRA, ('example.com', 'NS'): ['ns1.markmonitor.com.']})  # what the client's other domain uses
        self.assertIsNone(own.foreign_owner('example.com', ['example-client.com'], shared))
        self.assertIsNone(own.foreign_owner('example.com', [], self.Lookup(self.INFRA)))  # nothing to compare with
        redacted = self.Lookup({}, {'example.com': 'REDACTED FOR PRIVACY', 'example-client.com': 'Example Client LLC'})
        self.assertIsNone(own.foreign_owner('example.com', ['example-client.com'], redacted))

        class Failing(self.Lookup):
            def records(self, name, rtype):
                return None
        self.assertIsNone(own.foreign_owner('example.com', ['example-client.com'], Failing({})))


class BucketGuessOwnershipTests(TestCase):
    def setUp(self):
        org = Org.objects.create(name='B', slug='b-own')
        self.project = Project.objects.create(name='BP', slug='bp-own', insert_date=timezone.now(), org=org)
        for name in ('example.com', 'example-client.com'):
            Domain.objects.create(name=name, project=self.project, insert_date=timezone.now())
        mock.patch.dict(os.environ, {'CVENGINE_BUCKETS_GUESS': '1'}).start()
        self.addCleanup(mock.patch.stopall)

    def test_no_names_are_guessed_from_a_domain_of_another_owner(self):
        from cveFeed import bucket_scan as bs
        asked, skipped = [], {}

        def check(domain, others):
            asked.append((domain, others))
            return 'it is registered to another company' if domain == 'example.com' else None
        candidates, complete = bs.collect(self.project.id, owner_check=check, skipped=skipped)
        names = {c.name for c in candidates if c.tier == 'guess'}
        self.assertFalse(names & {n for _p, n in bs.guess_names('example', 'example.com')})  # nothing from the other owner's domain
        self.assertIn('example-client', names)
        self.assertEqual(skipped, {'example.com': 'it is registered to another company'})
        self.assertIn(('example.com', ['example-client.com']), asked)
        self.assertIn('guess', complete)

    def test_the_sweep_says_why_and_an_earlier_guess_finding_for_that_domain_resolves(self):
        from cveFeed import bucket_scan as bs
        from cveFeed.models import HygieneFinding
        from tests.test_bucket_scan import Net
        domain = Domain.objects.get(name='example.com')
        old = HygieneFinding.objects.create(domain=domain, host='example-assets.storage.googleapis.com', check_name='bkt_listing', severity=2,
                                            title='Google Cloud Storage bucket example-assets lists its objects to anyone (name guess, ownership unconfirmed)',
                                            evidence={'tier': 'guess'})
        with mock.patch.dict(os.environ, {'CVENGINE_BUCKETS_MAX_PER_SWEEP': '1'}):
            out = bs.sweep(self.project.id, fetch=Net(), dns=lambda host: False,
                           owner_check=lambda d, others: 'another registrant' if d == 'example.com' else None)
        self.assertEqual(out['not_guessed'], ['example.com'])
        old.refresh_from_db()
        self.assertEqual(old.status, 'resolved')
