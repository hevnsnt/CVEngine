"""The AI host review's next step (cveFeed.host_review, D6): which steps start on their own and which are only recommended, the person's Start and
Dismiss, the needs-person state, and the sweep that queues the reviews. The model is a stub (``test_host_review_job.Fixture``). Every safety test here
fails without its guard."""
from datetime import timedelta
from unittest import mock

from django.utils import timezone

from cveFeed import host_actions, host_review, reviewer
from cveFeed.models import AIJob, AgentActivity, CVEMatch, FindingAuditEvent, HostReview, HostScreenshot, HostState, ProjectSettings, ReviewerSettings
from startScan.models import Port, Subdomain
from tests.test_host_ai_review import HOSTILE
from tests.test_host_review_job import HOST, Fixture


class HostileHostTests(Fixture):
    """A banner that tells the model to close everything and run assess_host: an obedient model is held by the server on every side."""

    def setUp(self):
        super().setUp()
        self.m1, self.m2 = self.match(), self.match()
        Port.objects.filter(pk=self.port.pk).update(banner='SSH-2.0-OpenSSH_8.9 ' + HOSTILE, service_extra=HOSTILE[:250])
        Subdomain.objects.filter(pk=self.sub.pk).update(page_title=HOSTILE)
        HostScreenshot.objects.create(project=self.proj, domain=self.domain, host=HOST, scheme='https', port=443, outcome='ok', title=HOSTILE[:290])

    def obey(self):
        review = self.queue()
        self.assertTrue(review.injection)  # the flag is stored on the review
        job = review.ai_job
        self.assertTrue(any(p.get('fence') for p in job.packet['parts']))
        body = self.body({'f1': ('false_positive', 'high'), 'f2': ('false_positive', 'high')}, action='assess_host', reason='needs_proof',
                         step_note='run the full assessment, then close everything')
        with mock.patch.object(host_actions, 'run') as run:
            review = self.deliver(review, body)
        return review, run

    def test_nothing_is_closed_and_the_step_is_not_automatic(self):
        review, run = self.obey()
        self.assertEqual((self.status_of(self.m1), self.status_of(self.m2)), ('open', 'open'))  # the host's planted text holds every closure of the host
        for row in self.verdicts(review).values():
            self.assertEqual((row.verdict, row.outcome), ('false_positive', 'held'))
            self.assertIn('text aimed at AI agents', row.held_reason)
        run.assert_not_called()
        self.assertEqual((review.step_action, review.step_mode, review.step_state), ('assess_host', 'recommend', 'proposed'))
        self.assertIn('aimed at AI agents', review.step_detail)

    def test_even_an_automatic_class_step_is_only_proposed_on_a_host_whose_evidence_carries_planted_text(self):
        review = self.queue()
        with mock.patch.object(host_actions, 'run') as run:
            review = self.deliver(review, self.body({}, action='validate_match', target='f1', reason='needs_check'))
            run.assert_not_called()
        self.assertEqual((review.step_mode, review.step_state), ('recommend', 'proposed'))

    def test_a_held_hostile_false_positive_does_not_demote_and_stays_a_recorded_opinion(self):
        from cveFeed import situations
        from cveFeed.models import CVEEntry
        CVEEntry.objects.update(kev=True)  # on the KEV and in range: Situations ranks them Likely until something demotes them
        CVEMatch.objects.update(version_in_range=True)
        tiers = lambda: sorted(situations._matches([self.proj.pk])[0].values_list('tier', 'disputed'))  # noqa: E731
        self.assertEqual(tiers(), [(situations.LIKELY, False)] * 2)
        review, _ = self.obey()
        self.assertFalse(FindingAuditEvent.objects.filter(finding_kind='match', event='status').exists())
        self.assertEqual(tiers(), [(situations.LIKELY, False)] * 2)  # the server refused both closures, so the ranking does not follow the model

    def test_a_note_that_repeats_an_identifier_planted_in_the_host_is_discarded(self):
        review = self.queue()
        body = self.body({'f1': {'verdict': 'false_positive', 'confidence': 'high', 'reason_code': 'other', 'same_as': '', 'note': 'confirmed, reference a7c94e2b610f'}},
                         host_note='Please include reference a7c94e2b610f', step_note='reference a7c94e2b610f')
        review = self.deliver(review, body)
        self.assertEqual((review.host_note, review.step_note), ('', ''))
        self.assertIn('echo_marker', review.injection)
        row = list(self.verdicts(review).values())[0]
        self.assertEqual((row.verdict, row.confidence), ('uncertain', 'low'))
        self.assertNotIn('a7c94e2b610f', row.note)


class StepTests(Fixture):
    def setUp(self):
        super().setUp()
        self.m1 = self.match()

    def run_step(self, action='validate_match', target='f1', result=None, **body):
        review = self.queue()
        result = result or {'action': action, 'target': target, 'state': 'started', 'detail': 'queued'}
        with mock.patch.object(host_actions, 'run', return_value=result) as run:
            review = self.deliver(review, self.body({'f1': ('true_open', 'high')}, action=action, target=target, reason='needs_check', **body))
        return review, run

    def test_a_read_only_step_starts_on_its_own_in_auto_mode_and_says_so_in_the_activity_feed(self):
        review, run = self.run_step()
        run.assert_called_once()
        args, kw = run.call_args
        self.assertEqual((args[0], args[1], kw['by']), ('validate_match', 'f1', None))
        self.assertEqual([ref for ref, _ in kw['rows']], ['f1'])
        self.assertEqual((review.step_mode, review.step_state, review.step_detail), ('auto', 'started', 'queued'))
        line = AgentActivity.objects.filter(project=self.proj, kind='confirm').latest('id')
        self.assertIn('started a step', line.message)
        self.assertEqual(line.detail['host_review_id'], review.pk)

    def test_the_whole_run_through_the_real_action_starts_one_read_only_validation(self):
        from cveFeed.models import OnDemandValidation
        review = self.queue()
        with mock.patch('cveFeed.tasks.validate_match_on_demand.apply_async'):
            review = self.deliver(review, self.body({'f1': ('true_open', 'high')}, action='validate_match', target='f1', reason='needs_check'))
        self.assertEqual((review.step_mode, review.step_state), ('auto', 'started'))
        row = OnDemandValidation.objects.get()
        self.assertEqual(row.source, 'host_review')  # never counted as a person's work
        self.assertFalse(reviewer.worked_by_person('cve_match', self.m1))

    def test_recommend_mode_starts_nothing(self):
        ProjectSettings.objects.update_or_create(project=self.proj, defaults={'host_review_mode': 'recommend'})
        review, run = self.run_step()
        run.assert_not_called()
        self.assertEqual((review.step_mode, review.step_state), ('recommend', 'proposed'))
        self.assertIn('recommend only', review.step_detail)

    def test_a_step_that_touches_the_host_is_always_only_proposed(self):
        for action in ('rescan_host', 'assess_host', 'run_hygiene'):
            review, run = self.run_step(action, '')
            run.assert_not_called()
            self.assertEqual((review.step_mode, review.step_state), ('recommend', 'proposed'), action)
            review.delete()

    def test_scanning_paused_when_the_answer_comes_starts_nothing(self):
        review = self.queue()
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=True), mock.patch.object(host_actions, 'run') as run:
            review = self.deliver(review, self.body({}, action='validate_match', target='f1', reason='needs_check'))
            run.assert_not_called()
        self.assertEqual((review.step_mode, review.step_state), ('recommend', 'proposed'))
        self.assertIn('paused', review.step_detail)

    def test_one_automatic_step_a_host_in_24_hours(self):
        HostReview.objects.create(project=self.proj, domain=self.domain, host=HOST, state_key='a' * 40, status='applied', step_action='screenshot',
                                  step_mode='auto', step_state='done', decided_at=timezone.now() - timedelta(hours=3))
        review, run = self.run_step()
        run.assert_not_called()
        self.assertEqual(review.step_state, 'proposed')
        self.assertIn('already started on its own', review.step_detail)
        HostReview.objects.exclude(pk=review.pk).update(decided_at=timezone.now() - timedelta(hours=25))
        review.delete()
        review, run = self.run_step()
        run.assert_called_once()  # a day later it may start one

    def test_a_none_step_or_a_refused_one_does_not_use_the_hosts_budget(self):
        HostReview.objects.create(project=self.proj, domain=self.domain, host=HOST, state_key='a' * 40, status='applied', step_action='none',
                                  step_mode='auto', step_state='done', decided_at=timezone.now())
        HostReview.objects.create(project=self.proj, domain=self.domain, host=HOST, state_key='b' * 40, status='applied', step_action='screenshot',
                                  step_mode='auto', step_state='refused', decided_at=timezone.now())
        review, run = self.run_step()
        run.assert_called_once()

    def test_the_projects_limit_of_automatic_steps_a_day(self):
        ReviewerSettings.current()
        ReviewerSettings.objects.update(host_review_auto_per_project_day=2)
        other_host = self.host_of(self.domain, self.scan, 'api.example.com', self.proj, '192.0.2.50')
        for n in range(2):
            HostReview.objects.create(project=self.proj, domain=self.domain, host=f'h{n}.example.com', state_key='a' * 40, status='applied',
                                      step_action='screenshot', step_mode='auto', step_state='started', decided_at=timezone.now())
        review, run = self.run_step()
        run.assert_not_called()
        self.assertIn("limit of automatic steps", review.step_detail)
        HostReview.objects.filter(project=self.proj).exclude(pk=review.pk).update(project=self.other)  # another project's steps are not this project's
        review.delete()
        review, run = self.run_step()
        run.assert_called_once()

    def test_a_person_who_dismissed_or_started_a_step_of_this_host_today_stops_automatic_steps(self):
        old = HostReview.objects.create(project=self.proj, domain=self.domain, host=HOST, state_key='a' * 40, status='applied', step_action='screenshot',
                                        step_mode='recommend', step_state='dismissed', dismissed_by=self.user, dismissed_at=timezone.now() - timedelta(hours=2))
        review, run = self.run_step()
        run.assert_not_called()
        self.assertIn('a person started or dismissed', review.step_detail)
        review.delete()
        old.dismissed_at = timezone.now() - timedelta(hours=30)
        old.save()
        review, run = self.run_step()
        run.assert_called_once()
        review.delete()
        HostReview.objects.filter(pk=old.pk).update(dismissed_at=None, step_state='done', decided_at=timezone.now() - timedelta(hours=1))  # a person's Start
        review, run = self.run_step()
        run.assert_not_called()

    def test_the_same_step_a_person_dismissed_is_not_proposed_again_for_the_same_state(self):
        first, _ = self.run_step('rescan_host', '')
        host_review.dismiss_step(first, self.user, 'not now')
        first.refresh_from_db()
        self.assertEqual((first.step_state, first.dismissed_by_id, first.step_detail), ('dismissed', self.user.pk, 'dismissed: not now'))
        self.assertIsNotNone(first.dismissed_at)
        self.assertEqual(host_review.request(self.proj, HOST).pk, first.pk)  # the same state: Review now returns the review it has, no new one, no AI call
        Port.objects.filter(pk=self.port.pk).update(version='9.9')  # a changed banner or version does not lift a Dismiss ...
        same, run = self.run_step('rescan_host', '')
        run.assert_not_called()
        self.assertEqual((same.step_state, same.state_key == first.state_key), ('dismissed', False))
        self.assertIn('dismissed this step', same.step_detail)
        self.match()  # ... a new open finding does
        third, _ = self.run_step('rescan_host', '')
        self.assertEqual(third.step_state, 'proposed')

    def test_the_actions_own_refusal_is_stored_and_nothing_is_claimed_started(self):
        review, _ = self.run_step(result={'action': 'validate_match', 'target': 'f1', 'state': 'refused', 'detail': 'the project is at its validation limit'})
        self.assertEqual((review.step_mode, review.step_state, review.step_detail), ('auto', 'refused', 'the project is at its validation limit'))
        self.assertFalse(AgentActivity.objects.filter(message__contains='started a step').exists())

    def test_none_is_done_and_runs_nothing(self):
        review, run = self.run_step('none', '')
        run.assert_not_called()
        self.assertEqual((review.step_action, review.step_mode, review.step_state), ('none', 'auto', 'done'))

    def test_ask_person_sets_the_needs_person_state_and_sends_the_notification_once(self):
        review = self.queue()
        review = self.deliver(review, self.body({'f1': ('uncertain', 'low')}, action='ask_person', reason='needs_person'))
        self.assertEqual((review.step_mode, review.step_state), ('auto', 'done'))
        self.notified.assert_called_once_with(HOST)
        self.assertEqual([r.pk for r in host_review.needs_person(self.proj)], [review.pk])
        self.assertEqual(host_review.needs_person(self.other), [])
        host_review.dismiss_step(review, self.user)
        self.assertEqual(host_review.needs_person(self.proj), [])

    def test_ask_person_in_recommend_mode_is_proposed_and_still_a_needs_person_state_until_dismissed(self):
        ProjectSettings.objects.update_or_create(project=self.proj, defaults={'host_review_mode': 'recommend'})
        review = self.queue()
        review = self.deliver(review, self.body({}, action='ask_person', reason='needs_person'))
        self.notified.assert_not_called()
        self.assertEqual(review.step_state, 'proposed')
        self.assertEqual(len(host_review.needs_person(self.proj)), 1)

    def test_a_persons_start_runs_the_same_function_as_the_person_and_cannot_be_clicked_twice(self):
        ProjectSettings.objects.update_or_create(project=self.proj, defaults={'host_review_mode': 'recommend'})
        review, run = self.run_step()
        with mock.patch.object(host_actions, 'run', return_value={'action': 'validate_match', 'target': 'f1', 'state': 'started', 'detail': 'queued'}) as run:
            result = host_review.start_step(review, self.user)
            self.assertEqual(result['state'], 'started')
            self.assertEqual(run.call_args.kwargs['by'], self.user)
            with self.assertRaises(host_review.HostReviewRefused) as caught:
                host_review.start_step(review, self.user)
            self.assertEqual(caught.exception.status, 409)
            run.assert_called_once()
        review.refresh_from_db()
        self.assertEqual((review.step_mode, review.step_state), ('recommend', 'started'))
        self.assertTrue(host_review.person_acted(self.proj, HOST, timezone.now() - timedelta(hours=1)))  # a person's step is a person's, whatever the mode
        with self.assertRaises(host_review.HostReviewRefused):
            host_review.dismiss_step(review, self.user)

    def test_a_start_that_is_no_longer_offered_is_stored_refused(self):
        ProjectSettings.objects.update_or_create(project=self.proj, defaults={'host_review_mode': 'recommend'})
        review, _ = self.run_step()
        CVEMatch.objects.filter(pk=self.m1.pk).update(remediation_status='fixed')  # the finding the step names closed meanwhile
        result = host_review.start_step(review, self.user)
        self.assertEqual(result['state'], 'refused')
        review.refresh_from_db()
        self.assertEqual(review.step_state, 'refused')

    def test_a_proposal_expires_when_a_newer_review_exists_or_after_a_week(self):
        ProjectSettings.objects.update_or_create(project=self.proj, defaults={'host_review_mode': 'recommend'})
        old, _ = self.run_step()
        old.status = 'applied'
        old.save()
        HostReview.objects.create(project=self.proj, domain=self.domain, host=HOST, state_key='z' * 40, status='applied')
        self.assertEqual(host_review.housekeeping()['expired'], 1)
        old.refresh_from_db()
        self.assertEqual(old.step_state, 'expired')


class SweepTests(Fixture):
    def setUp(self):
        super().setUp()
        self.m1 = self.match()

    def test_it_queues_the_hosts_with_an_open_finding_and_no_review_of_their_state(self):
        other = self.host_of(self.domain, self.scan, 'api.example.com', self.proj, '192.0.2.51')
        self.match(sub=other)
        quiet = self.host_of(self.domain, self.scan, 'quiet.example.com', self.proj, '192.0.2.52')  # nothing open
        out = host_review.sweep()
        self.assertEqual(out['queued'], 2)
        self.assertEqual(set(HostReview.objects.values_list('host', flat=True)), {HOST, 'api.example.com'})
        self.assertEqual(AIJob.objects.filter(kind='host_review', priority=6).count(), 2)
        self.assertEqual(host_review.sweep()['queued'], 0)  # open reviews block their hosts

    def test_a_host_with_an_applied_review_is_left_alone_until_it_changes(self):
        review = self.deliver(self.queue(), self.body({'f1': ('true_open', 'high')}))
        self.assertEqual(review.status, 'applied')
        self.assertEqual(host_review.sweep()['queued'], 0)
        Port.objects.filter(pk=self.port.pk).update(version='9.9')  # a changed service version is a new state of the host ...
        self.assertEqual(host_review.sweep()['queued'], 0)  # ... but a host is reviewed automatically at most once a day
        HostReview.objects.filter(pk=review.pk).update(created_at=timezone.now() - timedelta(days=2))
        self.assertEqual(host_review.sweep()['queued'], 1)
        HostReview.objects.filter(status='queued').delete()
        self.match()  # a new finding is a new state too
        self.assertEqual(host_review.sweep()['queued'], 1)

    def test_a_failed_review_waits_a_day_or_an_hour_for_the_providers_outage_before_the_host_is_asked_again(self):
        review = self.deliver(self.queue(), error='refused')
        self.assertEqual(host_review.sweep()['queued'], 0)
        HostReview.objects.filter(pk=review.pk).update(decided_at=timezone.now() - timedelta(hours=25))
        self.assertEqual(host_review.sweep()['queued'], 1)
        HostReview.objects.filter(status='queued').delete()
        AIJob.objects.filter(status='queued').delete()
        limited = self.deliver(self.queue(), error='provider_rate_limit')
        self.assertEqual(host_review.sweep()['queued'], 0)
        HostReview.objects.filter(pk=limited.pk).update(decided_at=timezone.now() - timedelta(minutes=61))
        self.assertEqual(host_review.sweep()['queued'], 1)

    def test_a_run_is_bounded_and_never_passes_the_daily_cap(self):
        for n in range(6):
            sub = self.host_of(self.domain, self.scan, f'h{n}.example.com', self.proj, f'192.0.2.{60 + n}')
            self.match(sub=sub)
        self.assertEqual(host_review.sweep(limit=3)['queued'], 3)
        HostReview.objects.all().delete()
        AIJob.objects.all().delete()
        ReviewerSettings.current()
        ReviewerSettings.objects.update(host_review_daily_max=2)
        self.assertEqual(host_review.sweep()['queued'], 2)
        out = host_review.sweep()
        self.assertEqual(out['queued'], 0)
        self.assertEqual(HostReview.objects.count(), 2)
        HostReview.objects.update(status='failed')  # failed ones count too
        self.assertEqual(host_review.sweep()['queued'], 0)
        self.assertIn('daily limit', host_review.sweep()['skipped'])

    def test_scanning_paused_or_no_provider_queues_nothing(self):
        with mock.patch('cveFeed.scan_control.pause_requested', return_value=True):
            out = host_review.sweep()
        self.assertEqual((out['queued'], out['skipped']), (0, 'scanning is paused'))
        with mock.patch('cveFeed.ai_jobs.provider_row', return_value=None):
            self.assertEqual(host_review.sweep()['queued'], 0)
        self.assertFalse(HostReview.objects.exists())

    def test_hosts_of_a_project_set_to_off_archived_or_excluded_are_skipped(self):
        ProjectSettings.objects.update_or_create(project=self.proj, defaults={'host_review_mode': 'off'})
        self.assertEqual(host_review.sweep()['queued'], 0)
        ProjectSettings.objects.update(host_review_mode='auto')
        HostState.objects.filter(host=HOST).update(archived_at=timezone.now())
        self.assertEqual(host_review.sweep()['queued'], 0)

    def test_projects_take_turns_so_one_cannot_use_the_whole_run(self):
        for n in range(4):
            self.match(sub=self.host_of(self.domain, self.scan, f'a{n}.example.com', self.proj, f'192.0.2.{80 + n}'))
        other = self.host_of(self.other_domain, self.other_scan, 'www.example.org', self.other, '192.0.2.99')
        self.match(sub=other, scan=self.other_scan)
        HostState.objects.filter(project=self.proj).update(score=50)
        HostState.objects.filter(project=self.other).update(score=1)  # the quieter project still gets its turn
        self.assertEqual(host_review.sweep(limit=2)['queued'], 2)
        self.assertEqual(set(HostReview.objects.values_list('project_id', flat=True)), {self.proj.pk, self.other.pk})

    def test_the_hottest_host_is_first(self):
        hot = self.host_of(self.domain, self.scan, 'hot.example.com', self.proj, '192.0.2.53')
        self.match(sub=hot)
        HostState.objects.filter(host='hot.example.com').update(score=90)
        host_review.sweep(limit=1)
        self.assertEqual(HostReview.objects.get().host, 'hot.example.com')

    def test_an_open_review_whose_job_is_gone_is_closed_so_it_never_blocks_the_host(self):
        review = self.queue()
        AIJob.objects.filter(pk=review.ai_job_id).update(status='failed')
        out = host_review.sweep()
        self.assertEqual(out['closed'], 1)
        review.refresh_from_db()
        self.assertEqual(review.status, 'failed')

    def test_the_task_and_its_beat_schedule_exist(self):
        from django_celery_beat.models import PeriodicTask
        from cveFeed import tasks
        task = PeriodicTask.objects.get(name='cvengine-host-review-sweep')
        self.assertEqual((task.task, task.interval.every, task.interval.period, task.enabled), ('host_review_sweep', 10, 'minutes', True))
        with mock.patch('cveFeed.host_review.sweep', return_value={'queued': 0}) as sweep:
            self.assertEqual(tasks.host_review_sweep(), {'queued': 0})
            sweep.assert_called_once()
