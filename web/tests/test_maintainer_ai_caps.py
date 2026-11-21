"""Every AI cap is a maintainer signal, and a cap used up or a triage backlog is an operations check (the AI review coverage fixes, F6)."""
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import maintainer_signals as ms
from cveFeed import maintainer_checks as mc, reviewer, triage
from cveFeed.models import AIJob, FindingReview, HostReview, ReviewerSettings, Triage, TriageCall
from tests.test_maintainer_checks import patched_signals
from tests.test_alerts_tell_the_truth import Base
from tests.test_triage import TriageDbBase


class SpendTests(TriageDbBase):
    def setUp(self):
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)

    def test_the_review_guidance_planning_and_per_project_caps_are_signals(self):
        from dashboard.models import AIProviderSettings
        AIProviderSettings.objects.create(enabled=True, plan_daily_total=10, plan_daily_per_project=2, cve_guidance_daily=3)
        ReviewerSettings.objects.create(enabled=True, review_daily_max=4, host_review_daily_max=7)
        m = self.match('a.tr.test')
        row = triage.track(triage.with_cves([m]))[0][0]
        FindingReview.objects.create(triage=row, project=self.project, review_key='k' * 40, verdict='true_open')
        HostReview.objects.create(project=self.project, domain=self.domain, host='a.tr.test', state_key='a' * 40)
        later = timezone.now() + timedelta(minutes=5)
        for n in range(2):
            TriageCall.objects.create(kind='validation_plan', signature=f's{n}', project=self.project, expires_at=later)
        TriageCall.objects.create(kind='cve_match', signature='t', project=self.project, expires_at=later)
        AIJob.objects.create(kind='cve_detection', stage='cve_detection', dedupe='cve_detection:1:author')
        rows = {r['key']: r for r in ms.ai_spend()['caps']}
        for key in ms.AI_CAP_KEYS + ms.OTHER_AI_CAP_KEYS:
            self.assertIn(key, rows)
        self.assertEqual((rows['review_daily_max']['used'], rows['review_daily_max']['cap']), (1, 4))
        self.assertEqual((rows['host_review_daily_max']['used'], rows['host_review_daily_max']['cap']), (1, 7))
        self.assertEqual((rows['cve_guidance_daily']['used'], rows['cve_guidance_daily']['cap']), (1, 3))
        self.assertEqual((rows['plan_daily_total']['used'], rows['plan_daily_per_project']['used'], rows['plan_daily_per_project']['percent_of_cap']),
                         (2, 2, 100.0))
        self.assertEqual((rows['triage_max_per_project_day']['used'], rows['triage_max_per_project_day']['scope']), (1, 'busiest project'))

    def test_one_unreadable_cap_is_unknown_and_the_others_are_read(self):
        with mock.patch('cveFeed.detection_author.ai_used_last_day', side_effect=RuntimeError('x')):
            out = ms.ai_spend()
        rows = {r['key']: r for r in out['caps']}
        self.assertEqual((rows['cve_guidance_daily']['state'], rows['cve_guidance_daily']['used']), ('unknown', None))
        self.assertEqual(rows['review_daily_max']['state'], 'known')
        self.assertEqual(out['state'], 'partial')


class BacklogSignalTests(TriageDbBase):
    def setUp(self):
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)

    def test_the_oldest_pending_row_of_the_current_inventory(self):
        from startScan.models import Vulnerability
        m = self.match('a.tr.test')
        closed = Vulnerability.objects.create(source='nuclei', name='Old', severity=2, discovered_date=timezone.now(), target_domain=self.domain,
                                              subdomain=m.subdomain, open_status=False)
        triage.track(triage.with_cves([m]) + triage.vulnerabilities(Vulnerability.objects.filter(pk=closed.pk)))
        Triage.objects.filter(match=m).update(updated_at=timezone.now() - timedelta(hours=7))
        Triage.objects.filter(vulnerability=closed).update(updated_at=timezone.now() - timedelta(days=30))  # not waiting for anything: not counted
        got = ms.triage_backlog()
        self.assertEqual((got['state'], got['pending'], got['errors']), ('known', 1, 0))
        self.assertGreaterEqual(got['oldest_pending_age_seconds'], 7 * 3600)
        self.assertLess(got['oldest_pending_age_seconds'], 8 * 3600)


class CheckVerdictTests(SimpleTestCase):
    def spend(self, *rows, state='known'):
        return {'ai_spend': {'state': state, 'caps': list(rows)}}

    def test_a_cap_used_up_is_a_warning_and_a_cap_of_zero_is_not(self):
        full = {'key': 'review_daily_max', 'label': 'AI finding reviews a day', 'cap': 300, 'used': 300, 'state': 'known', 'window': 'since UTC midnight'}
        off = {'key': 'plan_daily_total', 'label': 'plans', 'cap': 0, 'used': 0, 'state': 'known'}
        room = {'key': 'triage_max_per_day', 'label': 'triage', 'cap': 2000, 'used': 5, 'state': 'known'}
        got = mc.ai_budget(self.spend(full, off, room))
        self.assertEqual(got['state'], 'warning')
        self.assertIn('AI finding reviews a day: 300 of 300', got['detail'])
        self.assertEqual([r['key'] for r in got['facts']['exhausted']], ['review_daily_max'])
        self.assertEqual(mc.ai_budget(self.spend(off, room))['state'], 'ok')
        self.assertEqual(mc.ai_budget({})['state'], 'unknown')
        self.assertEqual(mc.ai_budget(self.spend({'key': 'x', 'state': 'unknown'}, state='partial'))['state'], 'unknown')

    def test_the_backlog_is_judged_by_the_oldest_wait(self):
        sig = lambda age, err=None: {'triage_backlog': {'state': 'known', 'pending': 3, 'errors': 1 if err else 0,  # noqa: E731
                                                        'oldest_pending_age_seconds': age, 'oldest_error_age_seconds': err}}
        self.assertEqual(mc.triage_backlog(sig(3600))['state'], 'ok')
        self.assertEqual(mc.triage_backlog(sig(7 * 3600))['state'], 'warning')
        self.assertEqual(mc.triage_backlog(sig(None, 50 * 3600))['state'], 'problem')
        self.assertIn('3 findings of the current inventory wait', mc.triage_backlog(sig(7 * 3600))['detail'])
        self.assertEqual(mc.triage_backlog({})['state'], 'unknown')

    def test_the_brief_carries_the_backlog(self):
        out = mc.brief({'triage_backlog': {'state': 'known', 'pending': 2, 'errors': 0, 'oldest_pending_age_seconds': 10, 'oldest_error_age_seconds': None}})
        self.assertEqual(out['signals']['triage_backlog'], {'pending': 2, 'errors': 0, 'oldest_pending_age_seconds': 10})


class OpsCheckTests(Base):
    def test_the_two_checks_are_operations_checks_with_codes(self):
        spend = {'state': 'known', 'caps': [{'key': 'review_daily_max', 'label': 'reviews', 'cap': 1, 'used': 1, 'state': 'known'}]}
        backlog = {'state': 'known', 'pending': 1, 'errors': 0, 'oldest_pending_age_seconds': 9 * 3600, 'oldest_error_age_seconds': None}
        with patched_signals(ai_spend=spend, triage_backlog=backlog):
            found = {c['code']: c for c in reviewer.ops_checks()}
        for code in ('ai_budget', 'triage_backlog'):
            self.assertIn(code, reviewer.OPS_CODES)
            self.assertEqual(found[code]['state'], 'warning')
        with patched_signals():
            found = {c['code']: c for c in reviewer.ops_checks()}
        self.assertEqual((found['ai_budget']['state'], found['triage_backlog']['state']), ('unknown', 'unknown'))
