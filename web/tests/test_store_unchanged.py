"""The stores that see the same facts on every scan write a row only when what it holds changed: ProbeObservation (cveFeed.probes.upsert_many),
HygieneFinding (cveFeed.hygiene.store_findings) and the secrets inventory (cveFeed.secrets_inventory.record). A row found again unchanged only has
its seen time moved. The redirect alias fold reads only the hygiene rows of the hosts it folds (cveFeed.finding_lifecycle)."""
from datetime import timedelta

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from cveFeed import finding_lifecycle, hygiene, probes, secrets_inventory as inv
from cveFeed.models import HygieneFinding, ProbeObservation, SecretFinding
from dashboard.models import Org, Project
from targetApp.models import Domain


def writes(ctx, table):
    """The INSERT and UPDATE statements ``ctx`` captured on ``table``."""
    return [q['sql'] for q in ctx.captured_queries if table in q['sql'] and q['sql'].lstrip().upper().startswith(('INSERT', 'UPDATE'))]


class Base(TestCase):
    def setUp(self):
        now = timezone.now()
        self.project = Project.objects.create(name='U', slug='unchanged', insert_date=now, org=Org.objects.create(name='U', slug='unchanged'))
        self.domain = Domain.objects.create(name='example.com', project=self.project, insert_date=now)


class UpsertManyTests(Base):
    def obs(self, product='nginx', version='1.24.0', evidence=None, port=443, now=None):
        return ({'project_id': self.project.pk, 'host': 'www.example.com', 'probe': 'error-page', 'port': port, 'kind': 'version', 'product': product},
                {'domain_id': self.domain.pk, 'version': version, 'outcome': 'found', 'confidence': 0.95, 'source': 'body',
                 'evidence': evidence if evidence is not None else {'line': 'nginx/1.24.0', 'paths': ['/x']}, 'observed_at': now or timezone.now()})

    def test_new_rows_are_created_as_update_or_create_would_and_returned_in_order(self):
        rows = probes.upsert_many([self.obs('nginx'), self.obs('php', '8.2.1')])
        self.assertEqual([r.product for r in rows], ['nginx', 'php'])
        self.assertTrue(all(r.pk for r in rows))
        stored = ProbeObservation.objects.get(product='php')
        self.assertEqual((stored.version, stored.outcome, stored.domain_id, stored.evidence), ('8.2.1', 'found', self.domain.pk, {'line': 'nginx/1.24.0', 'paths': ['/x']}))

    def test_a_row_found_again_unchanged_only_has_its_observed_at_moved(self):
        first = probes.upsert_many([self.obs('nginx'), self.obs('php', '8.2.1')])
        later = timezone.now() + timedelta(hours=1)
        with CaptureQueriesContext(connection) as ctx:
            again = probes.upsert_many([self.obs('nginx', now=later), self.obs('php', '8.2.1', now=later)])
        sql = writes(ctx, 'cveFeed_probeobservation')
        self.assertEqual(len(sql), 1)  # one UPDATE for the batch, no INSERT
        self.assertTrue(sql[0].lstrip().upper().startswith('UPDATE'))
        self.assertNotIn('evidence', sql[0])
        self.assertEqual([r.pk for r in again], [r.pk for r in first])
        for row in ProbeObservation.objects.all():
            self.assertEqual(row.observed_at, later)

    def test_a_changed_row_is_written_and_an_unchanged_one_is_only_touched(self):
        probes.upsert_many([self.obs('nginx'), self.obs('php', '8.2.1')])
        later = timezone.now() + timedelta(hours=1)
        probes.upsert_many([self.obs('nginx', '1.25.0', evidence={'line': 'nginx/1.25.0'}, now=later), self.obs('php', '8.2.1', now=later)])
        nginx = ProbeObservation.objects.get(product='nginx')
        self.assertEqual((nginx.version, nginx.evidence, nginx.observed_at), ('1.25.0', {'line': 'nginx/1.25.0'}, later))
        self.assertEqual(ProbeObservation.objects.get(product='php').observed_at, later)
        self.assertEqual(ProbeObservation.objects.count(), 2)

    def test_evidence_that_json_stores_the_same_way_is_unchanged(self):
        probes.upsert_many([self.obs(evidence={'paths': ['/a', '/b']})])
        with CaptureQueriesContext(connection) as ctx:
            probes.upsert_many([self.obs(evidence={'paths': ('/a', '/b')})])
        self.assertNotIn('evidence', ' '.join(writes(ctx, 'cveFeed_probeobservation')))

    def test_a_key_named_twice_is_one_row_with_the_last_defaults(self):
        rows = probes.upsert_many([self.obs('nginx', '1.24.0'), self.obs('nginx', '1.25.0')])
        self.assertIs(rows[0], rows[1])
        self.assertEqual(ProbeObservation.objects.get().version, '1.25.0')
        probes.upsert_many([self.obs('nginx', '1.25.0'), self.obs('nginx', '1.26.0')])
        self.assertEqual(ProbeObservation.objects.get().version, '1.26.0')

    def test_a_port_given_as_text_finds_the_stored_row(self):
        probes.upsert_many([self.obs(port=443)])
        probes.upsert_many([self.obs(port='443', version='1.25.0')])
        self.assertEqual(ProbeObservation.objects.get().version, '1.25.0')

    def test_rows_the_call_does_not_name_are_left_alone(self):
        probes.upsert_many([self.obs('nginx'), self.obs('php', '8.2.1')])
        before = ProbeObservation.objects.get(product='php').observed_at
        probes.upsert_many([self.obs('nginx', now=timezone.now() + timedelta(hours=1))])
        self.assertEqual(ProbeObservation.objects.get(product='php').observed_at, before)

    def test_record_with_the_rows_already_read_reads_nothing_again(self):
        observation = {'port': 443, 'kind': 'version', 'product': 'nginx', 'version': '1.24.0', 'variant': '', 'url': '/', 'outcome': 'found',
                       'confidence': 0.95, 'source': 'body', 'evidence': {'line': 'nginx/1.24.0'}}
        probes.record(self.project.pk, self.domain.pk, 'WWW.example.com', 'error-page', [observation])
        existing = list(ProbeObservation.objects.filter(project=self.project, host='www.example.com', probe='error-page'))
        with self.assertNumQueries(1):  # the observed_at UPDATE alone
            rows = probes.record(self.project.pk, self.domain.pk, 'www.example.com', 'error-page', [observation], existing=existing)
        self.assertEqual(rows[0].pk, existing[0].pk)


class HygieneStoreTests(Base):
    def found(self, severity=2, evidence=None):
        return [hygiene.Finding('tls_expiring', severity, 'Certificate expires', host='www.example.com:443', evidence=evidence or {'not_after': '2026-12-01'}),
                hygiene.Finding('dmarc_missing', 2, 'No DMARC record', host='example.com')]

    def test_a_finding_seen_again_unchanged_only_moves_last_seen(self):
        hygiene.store_findings(self.domain, self.found())
        first = {r.check_name: r.last_seen for r in HygieneFinding.objects.all()}
        with CaptureQueriesContext(connection) as ctx:
            hygiene.store_findings(self.domain, self.found())
        sql = writes(ctx, 'cveFeed_hygienefinding')
        self.assertEqual(len(sql), 1)
        self.assertNotIn('"evidence"', sql[0])
        for row in HygieneFinding.objects.all():
            self.assertGreater(row.last_seen, first[row.check_name])
        self.assertEqual(HygieneFinding.objects.count(), 2)

    def test_a_changed_finding_is_written_and_a_persons_status_is_kept(self):
        hygiene.store_findings(self.domain, self.found())
        HygieneFinding.objects.filter(check_name='tls_expiring').update(remediation_status='accepted', remediation_note='known')
        hygiene.store_findings(self.domain, self.found(severity=3, evidence={'not_after': '2026-12-02'}))
        row = HygieneFinding.objects.get(check_name='tls_expiring')
        self.assertEqual((row.severity, row.evidence, row.status), (3, {'not_after': '2026-12-02'}, 'open'))
        self.assertEqual((row.remediation_status, row.remediation_note), ('accepted', 'known'))

    def test_a_finding_not_seen_again_is_resolved_and_reopens_when_it_is_back(self):
        hygiene.store_findings(self.domain, self.found())
        HygieneFinding.objects.filter(check_name='dmarc_missing').update(remediation_status='fixed')
        hygiene.store_findings(self.domain, self.found()[:1])
        row = HygieneFinding.objects.get(check_name='dmarc_missing')
        self.assertEqual(row.status, 'resolved')
        self.assertIsNotNone(row.resolved_at)
        hygiene.store_findings(self.domain, self.found())
        row.refresh_from_db()
        self.assertEqual((row.status, row.remediation_status, row.resolved_at), ('open', 'open', None))
        self.assertIn('Reopened', row.remediation_note)


class SecretsRecountTests(Base):
    def setUp(self):
        super().setUp()
        inv.reset_key_cache()
        self.addCleanup(inv.reset_key_cache)

    def record(self, url='https://www.example.com/'):
        return inv.record(self.project.pk, host=None, url=url, source='kingfisher', rule_id='betterleaks.gcp-api-key',
                          value='AIzaSy...TUVw', domain_id=self.domain.pk)

    def test_a_repeat_sighting_does_not_recount_and_a_new_place_does(self):
        self.record()
        self.record('https://api.example.com/app.js')
        row = SecretFinding.objects.get()
        self.assertEqual((row.occurrence_count, row.host_count), (2, 2))
        with CaptureQueriesContext(connection) as ctx:
            self.record()
        self.assertFalse([q for q in ctx.captured_queries if 'COUNT(' in q['sql'].upper() and 'cveFeed_secretoccurrence' in q['sql']])
        row.refresh_from_db()
        self.assertEqual((row.occurrence_count, row.host_count), (2, 2))


class AliasHostsTests(Base):
    def test_the_host_filter_keeps_a_name_alone_or_with_a_port_and_nothing_else(self):
        for host in ('example.com', 'Example.COM:443', 'www.example.com:8443', 'xexample.com', 'example.com.evil.test', 'example.com:abc', 'examplexcom'):
            HygieneFinding.objects.create(domain=self.domain, host=host, check_name='c', severity=1, title='t')
        kept = set(HygieneFinding.objects.filter(finding_lifecycle._hosts_q({'example.com', 'www.example.com'})).values_list('host', flat=True))
        self.assertEqual(kept, {'example.com', 'Example.COM:443', 'www.example.com:8443'})
        self.assertFalse(HygieneFinding.objects.filter(finding_lifecycle._hosts_q(set())).exists())

    def test_the_host_filter_holds_many_names(self):
        names = {f'h{i}.example.com' for i in range(finding_lifecycle.HOSTS_CHUNK + 3)}
        HygieneFinding.objects.create(domain=self.domain, host=f'h{finding_lifecycle.HOSTS_CHUNK + 2}.example.com:443', check_name='c', severity=1, title='t')
        self.assertEqual(HygieneFinding.objects.filter(finding_lifecycle._hosts_q(names)).count(), 1)
