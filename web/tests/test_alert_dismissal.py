"""A dismissed notice stays dismissed unless the problem really changes (cveFeed.reviewer: ``plain_text``, ``dismissal_holds``,
``carried_dismissal``, ``after_update``, ``sentinel_heard``; cveFeed.watchdog.notice).

The live install showed three notices back after they were dismissed: the ``system`` problem line carried a live count ("12 open findings ...",
"last ran 14 minutes ago"), ``sentinel_waiting`` named the kinds that waited (a set that moves with the workload) and ``triage_backlog`` had a
fact that flips between null and a number. Checks that flap from a problem to ok and back opened a new row each time, without the dismissal. And
two alerts raised in the seconds after an update restarted the server said no Sentinel was live while both were back a minute later."""
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from cveFeed import reviewer, watchdog
from cveFeed.models import AdminAlert, ScanControl
from tests.test_alerts_tell_the_truth import Base


def check(code='system', state='problem', facts=None, severity=None):
    return reviewer._check(code, state, f'{code} title', f'{code} detail', facts if facts is not None else {}, severity=severity)


def system(*problems):
    return check('system', facts={'problems': list(problems)})


ORPHANS = '12 open findings point at hosts not in the inventory (gone from the latest full scan or archived); python3 manage.py audit_finding_hosts --apply closes them'
CONDUCTOR = 'work: the work conductor last ran 14 minutes ago, though it is scheduled every minute'


class DismissalTests(Base):
    def shown(self, now=None):
        return [a['code'] for a in reviewer.open_alerts(now=now)]

    def dismiss(self, code, at):
        alert = AdminAlert.objects.get(code=code, resolved_at__isnull=True)
        self.assertTrue(reviewer.dismiss_alert(alert.pk, self.admin, now=at))
        return alert

    def test_a_number_or_a_time_moving_inside_a_problem_line_keeps_it_dismissed(self):
        t0 = timezone.now() - timedelta(hours=10)
        reviewer.sync_alerts([system(ORPHANS, CONDUCTOR)], t0)
        self.dismiss('system', t0)
        later = t0 + timedelta(hours=9)  # long past the hold: only the digest decides
        reviewer.sync_alerts([system(ORPHANS.replace('12 open findings', '13 open findings'),
                                     CONDUCTOR.replace('14 minutes', 'an hour'))], later)
        self.assertEqual(self.shown(later), [])
        self.assertEqual(reviewer.plain_text('last at 15:43 UTC on {{time:2026-11-23T14:21:35Z}}, 2,048 MB'), 'last at # on #, # MB')
        self.assertEqual(reviewer.plain_text('nmap_verify'), 'nmap_verify', 'a word without a space (a kind, a name) is kept exactly')

    def test_a_real_new_problem_line_brings_it_back_after_the_hold(self):
        t0 = timezone.now() - timedelta(hours=10)
        reviewer.sync_alerts([system(ORPHANS)], t0)
        self.dismiss('system', t0)
        within = t0 + timedelta(hours=1)
        reviewer.sync_alerts([system(ORPHANS, 'schedules past due: nightly_sweep')], within)
        self.assertEqual(self.shown(within), [], 'inside the hold a change does not bring it back')
        after = t0 + reviewer.ALERT_DISMISS_HOLD + timedelta(minutes=1)
        reviewer.sync_alerts([system(ORPHANS, 'schedules past due: nightly_sweep')], after)
        self.assertEqual(self.shown(after), ['system'])

    def test_the_hold_then_the_digest_rule(self):
        facts = {'waited': 80, 'by_kind': {'nmap': 80}, 'falling_behind': False, 'saturated': True}
        t0 = timezone.now() - timedelta(hours=10)
        reviewer.sync_alerts([check('sentinel_waiting', 'warning', facts, severity='info')], t0)
        self.dismiss('sentinel_waiting', t0)
        churned = {**facts, 'by_kind': {'nmap': 50, 'http_probe': 30}}  # the kinds that waited moved with the workload
        at = t0 + timedelta(hours=3)
        reviewer.sync_alerts([check('sentinel_waiting', 'warning', churned, severity='info')], at)
        self.assertEqual(self.shown(at), [], 'a changed by_kind inside the hold stays hidden')
        at = t0 + reviewer.ALERT_DISMISS_HOLD + timedelta(minutes=1)
        reviewer.sync_alerts([check('sentinel_waiting', 'warning', churned, severity='info')], at)
        self.assertEqual(self.shown(at), ['sentinel_waiting'], 'after the hold a changed digest brings it back, as before')
        reviewer.sync_alerts([check('sentinel_waiting', 'warning', facts, severity='info')], at)
        self.assertEqual(self.shown(at), [], 'and the dismissed digest hides it again')

    def test_a_flipping_fact_inside_the_hold_stays_hidden(self):
        facts = {'pending': 576, 'errors': 0, 'oldest_error_age_seconds': None, 'oldest_pending_age_seconds': 357905}
        t0 = timezone.now() - timedelta(hours=1)
        reviewer.sync_alerts([check('triage_backlog', 'problem', facts)], t0)
        self.dismiss('triage_backlog', t0)
        reviewer.sync_alerts([check('triage_backlog', 'problem', {**facts, 'oldest_error_age_seconds': 120})], t0 + timedelta(minutes=30))
        self.assertEqual(self.shown(t0 + timedelta(minutes=30)), [])

    def test_a_severity_rise_ends_the_hold(self):
        t0 = timezone.now() - timedelta(hours=1)
        reviewer.sync_alerts([check('sentinels_offline', 'problem', {'silent': ['s1']}, severity='warning')], t0)
        self.dismiss('sentinels_offline', t0)
        at = t0 + timedelta(minutes=30)
        reviewer.sync_alerts([check('sentinels_offline', 'problem', {'silent': ['s1', 's2']}, severity='warning')], at)
        self.assertEqual(self.shown(at), [], 'the same severity: held')
        reviewer.sync_alerts([check('sentinels_offline', 'problem', {'silent': ['s1', 's2']}, severity='critical')], at)
        self.assertEqual(self.shown(at), ['sentinels_offline'], 'warning to critical shows it inside the hold')

    def test_resolve_then_reopen_within_six_hours_keeps_the_dismissal_and_later_does_not(self):
        t0 = timezone.now() - timedelta(hours=20)
        reviewer.sync_alerts([system(ORPHANS)], t0)
        first = self.dismiss('system', t0)
        reviewer.sync_alerts([check('system', 'ok')], t0 + timedelta(hours=5))
        at = t0 + timedelta(hours=10)  # past the hold, 5 hours after the resolve
        reviewer.sync_alerts([system(ORPHANS)], at)
        reopened = AdminAlert.objects.get(code='system', resolved_at__isnull=True)
        self.assertNotEqual(reopened.pk, first.pk)
        self.assertEqual((reopened.dismissed_at, reopened.dismissed_by_id), (t0, self.admin.pk))
        self.assertEqual(self.shown(at), [])
        reviewer.sync_alerts([check('system', 'ok')], at + timedelta(minutes=5))
        late = at + timedelta(minutes=5) + reviewer.ALERT_REOPEN_CARRY + timedelta(minutes=1)
        reviewer.sync_alerts([system(ORPHANS)], late)
        self.assertEqual(self.shown(late), ['system'], 'resolved more than six hours ago: a new alert is shown')
        self.assertIsNone(AdminAlert.objects.get(code='system', resolved_at__isnull=True).dismissed_at)

    def test_a_reopened_alert_that_says_something_else_after_the_hold_is_shown(self):
        t0 = timezone.now() - timedelta(hours=10)
        reviewer.sync_alerts([system(ORPHANS)], t0)
        self.dismiss('system', t0)
        reviewer.sync_alerts([check('system', 'ok')], t0 + timedelta(hours=5))
        at = t0 + timedelta(hours=6)
        reviewer.sync_alerts([system('celery beat has not ticked for 3 minutes; no schedule is being dispatched')], at)
        self.assertEqual(self.shown(at), ['system'])

    def test_a_dismissal_stored_before_the_severity_letter_still_hides_its_digest(self):
        t0 = timezone.now() - timedelta(hours=10)
        reviewer.sync_alerts([check('sentinels_idle', 'warning', {'live': 1, 'backlog': False})], t0)
        alert = AdminAlert.objects.get(code='sentinels_idle', resolved_at__isnull=True)
        AdminAlert.objects.filter(pk=alert.pk).update(dismissed_at=t0, dismissed_digest=alert.digest)  # as an older release stored it
        self.assertEqual(self.shown(t0 + timedelta(hours=9)), [])

    def test_an_alert_dismissed_under_the_old_digest_is_moved_to_the_new_one(self):
        t0 = timezone.now() - timedelta(hours=10)
        old = system(ORPHANS)
        reviewer.sync_alerts([old], t0)
        alert = AdminAlert.objects.get(code='system', resolved_at__isnull=True)
        legacy = reviewer._legacy_digest(old)
        AdminAlert.objects.filter(pk=alert.pk).update(digest=legacy, dismissed_at=t0, dismissed_digest=legacy)  # stored and dismissed by the older release
        later = t0 + timedelta(hours=9)
        reviewer.sync_alerts([old], later)
        self.assertEqual(self.shown(later), [], 'the new way of reading the same facts does not bring it back')

    def test_the_existing_rules_hold_resolved_and_not_dismissed(self):
        t0 = timezone.now()
        reviewer.sync_alerts([system(ORPHANS)], t0)
        self.assertEqual(self.shown(t0), ['system'])
        reviewer.sync_alerts([check('system', 'ok')], t0)
        self.assertEqual(self.shown(t0), [])


class WatchdogNoticeTests(Base):
    def test_a_time_in_the_title_does_not_bring_a_dismissed_notice_back_and_a_flap_keeps_it(self):
        watchdog.notice('R1', 'info', 'The workers stopped answering at {{time:2026-11-23T14:21:35Z}}; the watchdog restarted them', 'd')
        alert = AdminAlert.objects.get(code='watchdog_r1', resolved_at__isnull=True)
        reviewer.dismiss_alert(alert.pk, self.admin, now=timezone.now() - timedelta(hours=5))
        watchdog.notice('R1', 'info', 'The workers stopped answering at {{time:2026-11-23T15:01:07Z}}; the watchdog restarted them', 'd')
        self.assertEqual(reviewer.open_alerts(), [])
        watchdog.resolve_notice('R1')
        watchdog.notice('R1', 'info', 'The workers stopped answering at {{time:2026-11-23T16:01:07Z}}; the watchdog restarted them', 'd')
        self.assertEqual(AdminAlert.objects.filter(code='watchdog_r1').count(), 2)
        self.assertEqual(reviewer.open_alerts(), [])
        watchdog.notice('R1', 'critical', 'The workers stopped answering; the watchdog could not fix it', 'd')
        self.assertEqual([a['code'] for a in reviewer.open_alerts()], ['watchdog_r1'])


class AfterAnUpdateTests(Base):
    """An update restarts the web and the database; the checks that ran in the seconds after it found no live Sentinel (live: two Sentinels back
    a minute later, the alerts open until the next half-hourly run)."""

    def update(self, ended_ago):
        now = timezone.now()
        ScanControl.objects.update_or_create(pk=1, defaults={'update_started_at': now - ended_ago - timedelta(minutes=10), 'update_ended_at': now - ended_ago,
                                                             'update_grace_until': now - ended_ago + timedelta(minutes=10)})

    def silent(self):
        self.live(1)
        self.fakes[0].go_offline()

    def test_inside_the_grace_the_liveness_checks_give_no_verdict(self):
        self.silent()
        self.update(timedelta(seconds=5))
        self.assertEqual(self.check('sentinels_offline')['state'], 'unknown')
        reviewer.run_ops_checks()
        self.assertFalse(AdminAlert.objects.filter(code='sentinels_offline').exists())

    def test_after_the_grace_it_raises_as_before(self):
        self.silent()
        self.update(reviewer.ALERT_UPDATE_GRACE + timedelta(minutes=1))
        found = self.check('sentinels_offline')
        self.assertEqual((found['state'], found['severity']), ('problem', 'warning'))

    def test_a_running_update_is_inside_the_grace_and_none_is_outside(self):
        self.assertFalse(reviewer.after_update())
        ScanControl.objects.update_or_create(pk=1, defaults={'update_started_at': timezone.now() - timedelta(minutes=3), 'update_ended_at': None})
        self.assertTrue(reviewer.after_update())

    def test_the_grace_does_not_hide_a_template_problem_with_sentinels_live(self):
        self.live(1)
        self.update(timedelta(seconds=5))
        with mock.patch('cveFeed.templatevalidate.problem', return_value={'code': 'no_sentinel', 'title': 'AI-written checks cannot be tested yet', 'detail': 'd',
                                                                         'facts': {'pending': 2, 'live_sentinels': 1}}):
            self.assertEqual(self.check('generated_templates')['state'], 'warning')
        with mock.patch('cveFeed.templatevalidate.problem', return_value={'code': 'no_sentinel', 'title': 'AI-written checks cannot be tested yet', 'detail': 'd',
                                                                         'facts': {'pending': 2, 'live_sentinels': 0}}):
            self.fakes[0].go_offline()
            self.assertEqual(self.check('generated_templates')['state'], 'unknown')


class HeartbeatResolvesTests(Base):
    def setUp(self):
        super().setUp()
        cache.delete(reviewer.HEARD_GATE_KEY)

    def raised(self):
        self.live(1)
        self.fakes[0].go_offline()
        reviewer.run_ops_checks()
        self.assertTrue(AdminAlert.objects.filter(code='sentinels_offline', resolved_at__isnull=True).exists())
        AdminAlert.objects.create(code='generated_templates', severity='warning', title='AI-written checks cannot be tested yet', detail='d',
                                  facts={'pending': 2, 'live_sentinels': 0}, digest='x')
        cache.delete(reviewer.HEARD_GATE_KEY)

    def test_an_alert_raised_with_no_live_sentinel_resolves_on_the_first_heartbeat(self):
        self.raised()
        with mock.patch('agentapi.sentinel_dispatch.nuclei_validate_ready', return_value=None):
            self.fakes[0].heartbeat()
        self.assertFalse(AdminAlert.objects.filter(code__in=('sentinels_offline', 'generated_templates'), resolved_at__isnull=True).exists())

    def test_a_templates_alert_stays_while_no_live_sentinel_runs_template_checks(self):
        from cvengine.resources import ScannerUnavailable
        self.raised()
        with mock.patch('agentapi.sentinel_dispatch.nuclei_validate_ready', side_effect=ScannerUnavailable('none')):
            self.fakes[0].heartbeat()
        self.assertFalse(AdminAlert.objects.filter(code='sentinels_offline', resolved_at__isnull=True).exists())
        self.assertTrue(AdminAlert.objects.filter(code='generated_templates', resolved_at__isnull=True).exists())

    def test_no_more_than_one_alert_query_a_minute(self):
        self.live(1)
        cache.delete(reviewer.HEARD_GATE_KEY)
        alert_reads = lambda queries: [q['sql'] for q in queries if '"cveFeed_adminalert"' in q['sql']]  # noqa: E731
        with CaptureQueriesContext(connection) as first:
            reviewer.sentinel_heard()
        self.assertEqual(len(alert_reads(first.captured_queries)), 1)
        with CaptureQueriesContext(connection) as again:
            for _ in range(5):
                self.fakes[0].heartbeat()
        self.assertEqual(alert_reads(again.captured_queries), [], 'inside the minute the gate answers from the cache')
        with self.assertNumQueries(0):
            reviewer.sentinel_heard()
