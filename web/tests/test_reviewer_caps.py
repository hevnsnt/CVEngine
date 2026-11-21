"""The finding reviewer's daily cap and order (the AI review coverage fixes, docs/AI-REVIEWER.md): the verdicts a host review writes are counted by
the host review's cap, not the finding reviewer's (F3); the hottest findings are reviewed first, whatever their kind (F4); a verdict past the
day's cap is refused like a refusal is (F12)."""
from datetime import timedelta

from django.core.cache import cache
from django.utils import timezone

from cveFeed import reviewer, triage
from cveFeed.models import CVEEntry, CVEMatch, FindingReview, HostReview, ReviewerSettings, Triage
from startScan.models import Subdomain, Vulnerability
from tests.test_agentapi import call
from tests.test_reviewer import Fixture


class HostReviewCountTests(Fixture):
    def test_host_review_verdicts_do_not_use_up_the_finding_reviewers_day(self):
        row = Triage.objects.get(match=self.match)
        review = HostReview.objects.create(project=self.proj, domain=self.domain, host='www.example.com', state_key='a' * 40)
        FindingReview.objects.bulk_create([FindingReview(triage=row, project=self.proj, review_key='k' * 40, verdict='true_open', host_review=review)
                                           for _ in range(60)])
        self.assertEqual(reviewer.reviews_today(), 0)
        FindingReview.objects.create(triage=row, project=self.proj, review_key='k' * 40, verdict='true_open')
        self.assertEqual(reviewer.reviews_today(), 1)
        ReviewerSettings.objects.update(review_daily_max=5)
        self.assertEqual(call(self.raw, 'GET', '/api/v1/reviewer/config')[1]['reviews_left_today'], 4)


class HeatOrderTests(Fixture):
    def test_a_hot_finding_is_reviewed_before_a_cold_one_whatever_its_kind_or_age(self):
        kev = CVEEntry.objects.create(cve_id='CVE-2099-7702', cvss=9.8, kev=True, published_at=timezone.now(), affected=[])
        sub = Subdomain.objects.create(name='kev.example.com', target_domain=self.domain, scan_history=self.scan)
        hot = CVEMatch.objects.create(cve_entry=kev, subdomain=sub, source='tech', matched_product='lib-b', matched_version='2.0',
                                      version_in_range=True, confidence=0.8, scan_history=self.scan, evidence={'source': 'tech'}, distro_status='vulnerable')
        triage.track(triage.with_cves([hot]))
        Triage.objects.filter(match=hot).update(last_seen=timezone.now() - timedelta(days=30))  # older: the old order put it last
        self.assertEqual(reviewer.due(1)[0][0], Triage.objects.get(match=hot).pk)
        cache.clear()
        # a scanner finding that rates hotter than a cold CVE match comes before it (the old order put every CVE match first)
        CVEMatch.objects.filter(pk=hot.pk).delete()
        vuln = Vulnerability.objects.create(source='nuclei', name='Exposed admin', severity=4, discovered_date=timezone.now(), target_domain=self.domain,
                                            subdomain=self.sub, scan_history=self.scan, open_status=True, template_id='exposed-admin')
        triage.track([vuln])
        rows = Triage.objects.filter(pk__in=[t for t, _ in reviewer.due(5)]).annotate(heat=reviewer.heat_rank_expr())
        heat = {r.kind: r.heat for r in rows}
        self.assertGreater(heat['nuclei'], heat['cve_match'])
        cache.clear()
        self.assertEqual(Triage.objects.get(pk=reviewer.due(1)[0][0]).kind, 'nuclei')

    def test_a_heat_a_person_set_orders_too(self):
        cold = Triage.objects.get(match=self.match)
        Triage.objects.filter(pk=cold.pk).update(heat_override='fire')
        self.assertEqual(Triage.objects.filter(pk=cold.pk).annotate(heat=reviewer.heat_rank_expr()).get().heat, 3)


class VerdictCapTests(Fixture):
    def test_a_verdict_past_the_days_cap_is_refused(self):
        packet = self.packet()
        ReviewerSettings.objects.update(review_daily_max=1)
        row = Triage.objects.get(match=self.match)
        FindingReview.objects.create(triage=row, project=self.proj, review_key='z' * 40, verdict='true_open')
        status, data = self.verdict(packet)
        self.assertEqual(status, 429)
        self.assertFalse(FindingReview.objects.filter(review_key=packet['review_key']).exists())
        ReviewerSettings.objects.update(review_daily_max=5)
        self.assertEqual(self.verdict(packet)[0], 200)
