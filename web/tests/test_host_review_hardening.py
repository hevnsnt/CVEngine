"""Fixes from the independent security review of the host review (HR-1 ... HR-7). Each test fails without its fix."""
from datetime import timedelta
from unittest import mock

from django.utils import timezone

from cveFeed import host_actions, host_review, situations, triage
from cveFeed.models import (CVEEntry, CVEMatch, FindingReview, HostExclusion, HostReview, HostState, ProjectSettings, TlsCertificate, Triage)
from startScan.models import Port, Subdomain
from tests.test_host_ai_review import HOSTILE
from tests.test_host_review_job import HOST, Fixture

NOT_CLOSED = 'open'


class Base(Fixture):
    def kev_match(self, sub=None, scan=None, **over):
        """A match on the KEV: Situations ranks it Likely until something demotes it."""
        self.counter += 1
        cve = CVEEntry.objects.create(cve_id=f'CVE-2098-{6000 + self.counter}', cvss=9.8, kev=True, published_at=timezone.now(), affected=[], original_description='A flaw.')
        row = CVEMatch.objects.create(cve_entry=cve, subdomain=sub or self.sub, source='tech', matched_product=f'lib-{self.counter}', matched_version='1.2',
                                      version_in_range=True, confidence=0.8, ai_verdict='uncertain', scan_history=scan or self.scan, evidence={'source': 'tech'}, **over)
        triage.track([row])
        return row

    def tier_of(self, match):
        qs = situations._matches([self.proj.pk])[0]
        return qs.filter(pk=match.pk).values_list('tier', 'disputed').first()

    def fp(self, ref='f1', confidence='high'):
        return {ref: {'verdict': 'false_positive', 'confidence': confidence, 'reason_code': 'version_not_affected', 'same_as': '', 'note': 'The version shown is outside the range.'}}

    def reply(self, review, verdicts, **kw):
        with mock.patch.object(host_actions, 'run', return_value={'action': 'x', 'target': '', 'state': 'started', 'detail': 'ok'}) as run:
            review = self.deliver(review, self.body(verdicts, **kw))
        return review, run


class DemotionTests(Base):
    """HR-1: a verdict the server refused does not demote the finding in Situations (the rule of cveFeed.situations._disputed), for a host review too."""

    def test_a_low_confidence_false_positive_on_a_host_with_planted_text_keeps_the_finding_likely(self):
        match = self.kev_match()
        Port.objects.filter(pk=self.port.pk).update(banner='SSH-2.0-OpenSSH_8.9 ' + HOSTILE)
        self.assertEqual(self.tier_of(match), (situations.LIKELY, False))
        review, _ = self.reply(self.queue(), self.fp(confidence='low'))
        row = FindingReview.objects.get(host_review=review)
        self.assertEqual((row.verdict, row.confidence, row.outcome), ('false_positive', 'low', 'held'))
        self.assertEqual(self.tier_of(match), (situations.LIKELY, False))

    def test_a_high_confidence_false_positive_refused_for_hard_evidence_keeps_the_finding_likely(self):
        match = self.kev_match(template_result='vulnerable')
        self.assertEqual(self.tier_of(match)[0], situations.LIKELY)
        review, _ = self.reply(self.queue(), self.fp())
        row = FindingReview.objects.get(host_review=review)
        self.assertEqual((row.verdict, row.outcome), ('false_positive', 'disputed'))
        self.assertEqual(self.tier_of(match), (situations.LIKELY, False))

    def test_a_high_confidence_false_positive_held_for_planted_text_keeps_the_finding_likely(self):
        match = self.kev_match()
        Port.objects.filter(pk=self.port.pk).update(banner='SSH-2.0-OpenSSH_8.9 ' + HOSTILE)
        review, _ = self.reply(self.queue(), self.fp())
        self.assertEqual(FindingReview.objects.get(host_review=review).outcome, 'held')
        self.assertEqual(self.tier_of(match), (situations.LIKELY, False))


class PlantedTextTests(Base):
    """HR-3: planted text is looked for in what the host said, as stored, before the sanitiser removes it from the packet."""

    def check(self, plant):
        match = self.kev_match()
        plant()
        review = self.queue()
        self.assertTrue(review.injection, 'the planted text is found')
        with mock.patch.object(host_actions, 'run') as run:
            review = self.deliver(review, self.body(self.fp(), action='validate_match', target='f1', reason='needs_check'))
        run.assert_not_called()
        self.assertEqual((review.step_mode, review.step_state), ('recommend', 'proposed'))
        row = FindingReview.objects.get(host_review=review)
        self.assertEqual((row.verdict, row.outcome), ('false_positive', 'held'))
        self.assertEqual(CVEMatch.objects.get(pk=match.pk).remediation_status, NOT_CLOSED)

    def test_in_the_port_banner_only(self):
        self.check(lambda: Port.objects.filter(pk=self.port.pk).update(banner='SSH-2.0-OpenSSH_8.9 ' + HOSTILE))

    def test_in_the_page_title_only(self):
        self.check(lambda: Subdomain.objects.filter(pk=self.sub.pk).update(page_title=HOSTILE))

    def test_in_the_service_details_only(self):
        self.check(lambda: Port.objects.filter(pk=self.port.pk).update(service_extra=HOSTILE[:250], http={'title': HOSTILE}))

    def test_in_a_certificate_only(self):
        self.check(lambda: TlsCertificate.objects.create(domain=self.domain, host=HOST, port=443, issuer=HOSTILE[:400], subject=HOSTILE[:400]))


class EarlierVerdictTests(Base):
    """HR-2: an earlier real verdict on the same state of a finding holds a later host review's closure."""

    def earlier(self, match, verdict='true_open', confidence='high', key=None):
        from cveFeed import reviewer
        row = Triage.objects.get(match=match)
        key = key or reviewer.review_key(row, HostState.objects.get(project=self.proj, host=HOST).fingerprint)
        return FindingReview.objects.create(triage=row, project=self.proj, review_key=key, verdict=verdict, confidence=confidence, outcome='recorded')

    def test_a_host_review_cannot_close_a_finding_the_reviewer_already_called_real_for_this_state(self):
        match = self.match()
        self.earlier(match)
        review, _ = self.reply(self.queue(), self.fp())
        row = FindingReview.objects.get(host_review=review)
        self.assertEqual((row.verdict, row.outcome), ('false_positive', 'held'))
        self.assertIn('contradicts the earlier verdict', row.held_reason)
        self.assertEqual(CVEMatch.objects.get(pk=match.pk).remediation_status, NOT_CLOSED)
        self.assertFalse(self.tier_of(match)[1])  # and the held verdict does not mark the finding disputed in Situations

    def test_the_same_holds_when_the_earlier_real_verdict_was_a_host_reviews_own_and_a_person_asks_again(self):
        match = self.match()
        first, _ = self.reply(self.queue(), {'f1': ('true_open', 'high')})
        HostReview.objects.filter(pk=first.pk).update(status='stale')  # a person asks again ("Review now") on the same state
        second, _ = self.reply(self.queue(), self.fp())
        self.assertEqual(FindingReview.objects.get(host_review=second).outcome, 'held')
        self.assertEqual(CVEMatch.objects.get(pk=match.pk).remediation_status, NOT_CLOSED)

    def test_an_earlier_verdict_on_another_state_does_not_hold_it(self):
        match = self.match()
        self.earlier(match, key='0' * 40)  # the evidence changed since: a new state, a new review
        review, _ = self.reply(self.queue(), self.fp())
        self.assertEqual(FindingReview.objects.get(host_review=review).outcome, 'closed')

    def test_an_earlier_uncertain_verdict_does_not_hold_it(self):
        match = self.match()
        self.earlier(match, verdict='uncertain', confidence='low')
        review, _ = self.reply(self.queue(), self.fp())
        self.assertEqual(FindingReview.objects.get(host_review=review).outcome, 'closed')


class SweepStarvationTests(Base):
    """HR-4: hosts that cannot be reviewed (excluded, or too large for one packet) never use up the sweep's places."""

    def host(self, name, ip, score):
        sub = self.host_of(self.domain, self.scan, name, self.proj, ip)
        HostState.objects.filter(project=self.proj, host=name).update(score=score)
        self.match(sub=sub)
        return sub

    def test_excluded_hosts_with_a_high_score_do_not_starve_the_sweep(self):
        for i in range(3):
            name = f'x{i}.example.com'
            self.host(name, f'192.0.2.{60 + i}', 1000)
            HostExclusion.objects.create(org=self.org, host=name)
        self.match()  # the normal host (www.example.com), score 0
        out = host_review.sweep(limit=3)
        self.assertEqual(out['queued'], 1, out)
        self.assertEqual(list(HostReview.objects.values_list('host', flat=True)), [HOST])

    def test_a_host_whose_packet_cannot_be_built_is_recorded_so_it_is_not_picked_again_for_a_day(self):
        self.host('big.example.com', '192.0.2.70', 1000)
        self.match()
        real = host_review.build

        def build(project, host, **kw):
            if host == 'big.example.com':
                raise host_review.HostReviewError('the packet is too large (176979 characters)')
            return real(project, host, **kw)
        with mock.patch.object(host_review, 'build', side_effect=build):
            out = host_review.sweep(limit=1)
            self.assertEqual(out['queued'], 1, out)  # the normal host still gets its review in the same run
            row = HostReview.objects.get(host='big.example.com')
            self.assertEqual(row.status, 'failed')
            self.assertIn('too large', row.step_detail)
            HostReview.objects.filter(host=HOST).delete()
            from cveFeed.models import AIJob
            AIJob.objects.all().delete()
            self.assertEqual([h for _, h in host_review.due_hosts(5)], [HOST])  # the large one waits out the day
            HostReview.objects.filter(pk=row.pk).update(created_at=timezone.now() - timedelta(days=2), decided_at=timezone.now() - timedelta(days=2))
            self.assertEqual({h for _, h in host_review.due_hosts(5)}, {HOST, 'big.example.com'})
