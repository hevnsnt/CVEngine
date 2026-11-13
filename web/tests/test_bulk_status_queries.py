"""Marking many findings fixed at once (``POST .../findings/status``) costs a number of queries that does not grow with the number of findings (DB-8),
and still does for each finding what a single change does: the status and who and when, the audit event, the retest (queued, or "no check"), the activity
line of the retest and the host rescored."""
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed.models import AgentActivity, CVEEntry, CVEMatch, FindingAuditEvent, FixRetest, HygieneFinding, Triage
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_agentapi import call
from tests.test_fix_retest import HIT_STEP

BASE = '/api/v1/projects/bq-proj'


class BulkStatus(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        cls.org = Org.objects.create(name='Bq', slug='bq-org')
        cls.proj = Project.objects.create(name='Bq', slug='bq-proj', insert_date=now, org=cls.org)
        cls.domain = Domain.objects.create(name='bq.example', project=cls.proj, insert_date=now)
        cls.engine = EngineType.objects.create(engine_name='bq-e', yaml_configuration='x', default_engine=True)
        cls.scan = ScanHistory.objects.create(domain=cls.domain, scan_type=cls.engine, scan_status=2, start_scan_date=now)
        cls.alice = User.objects.create_user('bq-alice', password='x')
        ProjectMembership.objects.create(user=cls.alice, project=cls.proj, role='user')
        cls.token = create_token(cls.alice, 'bq')[1]
        cls.cve = CVEEntry.objects.create(cve_id='CVE-2099-7101', cvss=9.8, kev=True, published_at=now, affected=[])
        cls.made = 0

    def setUp(self):
        self.queued = mock.patch('cveFeed.tasks.retest_fixed_finding.apply_async').start()
        self.addCleanup(mock.patch.stopall)

    def findings(self, count, proof=False):
        """``count`` of each kind (a CVE match, a scanner finding, a hygiene finding), on a host each; the matches have a stored proof when ``proof``."""
        out = []
        for _ in range(count):
            type(self).made += 1
            n = self.made
            sub = Subdomain.objects.create(name=f'h{n}.bq.example', target_domain=self.domain, scan_history=self.scan)
            match = CVEMatch.objects.create(cve_entry=self.cve, subdomain=sub, source='tech', matched_product='panel', matched_version='1.2', version_in_range=True,
                                            confidence=0.8, ai_verdict='uncertain', scan_history=self.scan, evidence={'ip': '192.0.2.10', 'port': 443})
            Triage.objects.create(project=self.proj, domain=self.domain, host=sub.name, kind='cve_match', signature='s', match=match, validation_status='hit',
                                  validation_steps=[dict(HIT_STEP, target=sub.name)] if proof else [], validated_at=timezone.now())
            vuln = Vulnerability.objects.create(name='Exposed panel', severity=3, subdomain=sub, target_domain=self.domain, open_status=True, source='nuclei',
                                                http_url=f'https://{sub.name}/')
            hyg = HygieneFinding.objects.create(domain=self.domain, host=sub.name, check_name='spf_missing', severity=2, title='No SPF')
            out += [{'kind': 'match', 'id': match.pk}, {'kind': 'vulnerability', 'id': vuln.pk}, {'kind': 'hygiene', 'id': hyg.pk}]
        return out

    def bulk(self, items, status='fixed', note='patched'):
        with CaptureQueriesContext(connection) as q:
            code, body = call(self.token, 'POST', f'{BASE}/findings/status', {'items': items, 'status': status, 'note': note})
        self.assertEqual((code, body['failed']), (200, []), body)
        self.assertEqual(body['updated'], len(items))
        return q

    def test_the_cost_does_not_grow_with_the_number_of_findings(self):
        small = len(self.bulk(self.findings(2)))
        large = len(self.bulk(self.findings(60)))  # 180 findings
        self.assertLessEqual(large, small + 3, (small, large))
        self.assertLessEqual(large, 60, large)

    def test_the_same_with_a_stored_proof_to_retest(self):
        small = len(self.bulk(self.findings(2, proof=True)))
        large = len(self.bulk(self.findings(60, proof=True)))
        self.assertLessEqual(large, small + 3, (small, large))
        self.assertLessEqual(large, 80, large)

    def test_each_finding_gets_what_a_single_change_gives_it(self):
        items = self.findings(4, proof=True)
        self.bulk(items, 'fixed', 'patched it')
        for item in items:
            event = FindingAuditEvent.objects.get(project=self.proj, finding_kind=item['kind'], finding_id=item['id'])
            self.assertEqual((event.event, event.actor, event.before, event.after), ('status', self.alice, {'status': 'open'}, {'status': 'fixed', 'note': 'patched it'}))
        for match in CVEMatch.objects.filter(pk__in=[i['id'] for i in items if i['kind'] == 'match']):
            self.assertEqual((match.remediation_status, match.remediation_note, match.remediation_by), ('fixed', 'patched it', self.alice))
            self.assertIsNotNone(match.remediation_updated_at)
            self.assertEqual(match.triage.retest_state, 'verifying')
        self.assertEqual(FixRetest.objects.filter(project=self.proj, source='automatic', requested_by=self.alice, status='queued').count(), 4)
        self.assertEqual(self.queued.call_count, 4)  # one broker publish for each
        self.assertEqual(AgentActivity.objects.filter(project=self.proj, kind='validate', message__startswith='Retest queued for finding #').count(), 4)
        self.assertTrue(AgentActivity.objects.filter(project=self.proj, kind='remediation', message__startswith='bulk marked 12 finding(s) on 4 host(s) fixed').exists())
        for vuln in Vulnerability.objects.filter(pk__in=[i['id'] for i in items if i['kind'] == 'vulnerability']):
            self.assertEqual((vuln.remediation_status, vuln.remediation_note), ('fixed', 'patched it'))

    def test_a_finding_with_nothing_to_repeat_says_so_and_a_reopened_one_starts_over(self):
        items = self.findings(2)
        self.bulk(items, 'fixed')
        for match in CVEMatch.objects.filter(pk__in=[i['id'] for i in items if i['kind'] == 'match']):
            self.assertEqual((match.triage.retest_state, match.triage.retest_reason), ('no_check', 'no stored check or evidence to repeat'))
        self.assertEqual(FixRetest.objects.count(), 0)
        self.bulk(items, 'open', None)
        for match in CVEMatch.objects.filter(pk__in=[i['id'] for i in items if i['kind'] == 'match']):
            self.assertEqual((match.remediation_status, match.triage.retest_state), ('open', ''))

    def test_one_bad_item_does_not_stop_the_rest_and_a_repeat_is_harmless(self):
        items = self.findings(2, proof=True)
        mixed = [items[0], {'kind': 'match', 'id': 99999999}, {'kind': 'nope', 'id': 1}, {'id': 3}, items[0], items[3]]
        code, body = call(self.token, 'POST', f'{BASE}/findings/status', {'items': mixed, 'status': 'fixed'})
        self.assertEqual(code, 200)
        self.assertEqual(body['updated'], 3)
        self.assertEqual([(f['kind'], f['id']) for f in body['failed']], [('match', 99999999), ('nope', 1), (None, 3)])
        self.assertEqual(FixRetest.objects.count(), 2)  # the repeated one is queued once
