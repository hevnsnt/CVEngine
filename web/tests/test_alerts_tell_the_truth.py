"""The administrator alerts tell the truth (issue 140).

Fixtures are the numbers one real install showed over six hours, with example data: two live remote Sentinels that completed 2951 tasks, ten tasks
that expired waiting for a claim (some across two update restarts), 722 slot waits, 77 discoveries that hit a data provider's quota, 17 targets the
private-address guard refused, clean-up lines after a restart and validations whose AI step was put off. None of those is a failure to alert on."""
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.utils import timezone

from agentapi.models import Agent, SentinelTask
from cveFeed import activity, fleet, reviewer
from cveFeed.models import AgentActivity, GeneratedTemplate
from tests.fake_scanner import FakeScanner
from tests.test_reviewer import Fixture

WAIT = 'no Sentinel claimed the task in time; the targets stay due until a scanner can take the work'
LEASE = 'the lease expired without a report'
LIMIT = 'You have exceeded the usage limits for your account'


def now():
    return timezone.now()


class Base(Fixture):
    def setUp(self):
        super().setUp()
        self.fakes = []

    def live(self, count=2, slots=4):
        for index in range(count):
            self.fakes.append(FakeScanner(external=True, name=f'sentinel-{index + 1}', kinds=['hygiene_check', 'nmap'], max_concurrent=slots).start_for(self))

    def busy(self, count=8):
        """``count`` tasks the Sentinels hold right now: their slots are in use (with none, tasks that expire unclaimed mean the Sentinels are not claiming, see test_maintainer_checks)."""
        SentinelTask.objects.bulk_create([SentinelTask(project=self.proj, kind='nmap', target={}, status='running', claimed_at=now()) for _ in range(count)])

    def tasks(self, count, status, error='', kind='hygiene_check', ago=timedelta(hours=1), agent=None, claimed_ago=None):
        """``agent``: a Sentinel's name; the task was claimed ``claimed_ago`` before now when that is given. A task that ends as expired loses its agent"""
        who = Agent.objects.get(name=agent) if agent else None
        SentinelTask.objects.bulk_create([SentinelTask(project=self.proj, kind=kind, target={}, status=status, error=error, finished_at=now() - ago, agent=who,
                                                       claimed_at=now() - claimed_ago if claimed_ago else None) for _ in range(count)])

    def lost(self, count, agent, ago, claimed_ago=None, kind='nmap'):
        """``count`` tasks a Sentinel held and never reported on, ended the way the broker ends them (its lease expired), ``ago`` before now."""
        from agentapi import sentinel_broker
        who = Agent.objects.get(name=agent)
        for _ in range(count):
            task = SentinelTask.objects.create(project=self.proj, kind=kind, target={}, status='claimed', agent=who, claimed_at=now() - (claimed_ago or ago + timedelta(minutes=20)))
            self.assertTrue(sentinel_broker._end_as_expired(task, LEASE, now()))
        SentinelTask.objects.filter(status='expired', error=LEASE, finished_at__gte=now() - timedelta(minutes=1)).update(finished_at=now() - ago)

    def updated(self, agent, status, ago):
        Agent.objects.filter(name=agent).update(info={'update': {'status': status, 'at': (now() - ago).isoformat()}})

    def check(self, code):
        return {c['code']: c for c in reviewer.ops_checks()}[code]


class SentinelErrorsJudgedAgainstVolumeTests(Base):
    """(d) a fraction of a percent of expiries while Sentinels are live and completing work is no alert."""

    def test_production_numbers_raise_no_alert(self):
        self.live()
        self.tasks(2951, 'done')
        self.tasks(7, 'expired', LEASE)
        self.tasks(3, 'expired', WAIT)
        self.assertEqual(self.check('sentinel_errors')['state'], 'ok')

    def test_tasks_that_expired_across_an_update_restart_are_not_counted(self):
        self.live()
        self.tasks(100, 'done')
        self.lost(6, 'sentinel-1', timedelta(minutes=30), claimed_ago=timedelta(minutes=50))
        self.assertEqual(self.check('sentinel_errors')['state'], 'problem', 'six of 106 with nothing to explain them is a real rate')
        self.updated('sentinel-1', 'done', timedelta(minutes=32))
        self.assertEqual(self.check('sentinel_errors')['state'], 'ok')

    def test_the_server_clean_up_line_does_not_excuse_a_sentinels_lost_tasks(self):
        """The clean-up line (``a restarted worker left``) is about the server's workers; the Sentinel tasks are not touched by it, so it opens no window."""
        self.live()
        self.tasks(100, 'done')
        self.lost(6, 'sentinel-1', timedelta(minutes=30), claimed_ago=timedelta(minutes=50))
        entry = activity.log('validate', 'Expired stuck jobs a restarted worker left behind: 7 AgentActivity running', status='notice')
        AgentActivity.objects.filter(pk=entry.pk).update(created_at=now() - timedelta(minutes=29))
        self.assertEqual(self.check('sentinel_errors')['state'], 'problem')

    def test_a_real_failure_rate_is_still_an_alert_and_carries_the_numbers(self):
        self.live()
        self.tasks(100, 'done')
        self.tasks(8, 'failed', 'the tool crashed', kind='nmap')
        found = self.check('sentinel_errors')
        self.assertEqual(found['state'], 'problem')
        self.assertEqual((found['facts']['failed'], found['facts']['completed'], found['facts']['live_sentinels']), (8, 100, 2))
        for text in ('8', '100', '2 live Sentinels'):
            self.assertIn(text, found['detail'])

    def test_failures_with_no_live_sentinel_or_no_completed_work_are_still_an_alert(self):
        self.tasks(2951, 'done')
        self.tasks(5, 'failed', 'boom', kind='nmap')
        self.assertEqual(self.check('sentinel_errors')['state'], 'problem', 'no Sentinel is live')
        self.live()
        SentinelTask.objects.filter(status='done').delete()
        self.assertEqual(self.check('sentinel_errors')['state'], 'problem', 'live, but nothing completed')


class SentinelWaitingSaysWhereItStandsTests(Base):
    """(e) slots, completed count, and whether the backlog is growing; capacity advice only when work is falling behind."""

    def waits(self, early, late):
        self.tasks(early, 'expired', WAIT, kind='nmap', ago=timedelta(hours=5))
        self.tasks(late, 'expired', WAIT, kind='nmap', ago=timedelta(hours=1))

    def test_production_numbers_say_the_sentinels_are_keeping_up(self):
        self.live(2, slots=4)
        self.tasks(2951, 'done')
        self.waits(361, 361)
        found = self.check('sentinel_waiting')
        facts = found['facts']
        self.assertEqual((facts['slots'], facts['completed'], facts['waited'], facts['falling_behind']), (8, 2951, 722, False))
        for text in ('8 slots', '2951 completed', '722'):
            self.assertIn(text, found['detail'])
        self.assertNotIn('add one', found['detail'])
        self.assertNotIn('more slots', found['detail'])

    def test_a_growing_backlog_that_the_queue_confirms_advises_capacity(self):
        self.live(2, slots=4)
        self.busy()
        self.tasks(300, 'done')
        self.waits(100, 400)
        SentinelTask.objects.bulk_create([SentinelTask(project=self.proj, kind='nmap', target={}, status='queued') for _ in range(20)])
        found = self.check('sentinel_waiting')
        self.assertTrue(found['facts']['falling_behind'])
        self.assertTrue(found['facts']['growing'])
        self.assertIn('falling behind', found['detail'])
        self.assertIn('more slots', found['detail'])

    def test_a_grown_wait_count_alone_with_an_empty_queue_is_not_falling_behind(self):
        self.live(2, slots=4)
        self.tasks(300, 'done')
        self.waits(100, 400)
        self.assertFalse(self.check('sentinel_waiting')['facts']['falling_behind'])


class FleetFactsAndTheAdviceGuardTests(Base):
    """(f) the facts handed to the AI say how many Sentinels are live and whether there is a built-in scanner; advice that contradicts them is dropped."""

    def test_the_snapshot_carries_the_fleet(self):
        self.live()
        fleet = reviewer.snapshot()['fleet']
        self.assertEqual((fleet['live_sentinels'], fleet['builtin_scanner']), (2, False))

    def test_the_guard_drops_the_two_false_claims(self):
        remote = {'live_sentinels': 2, 'builtin_scanner': False}
        for text in ('No Sentinel is online to take the work, so tasks expire. Start the built-in Sentinel on the Sentinels page.',
                     'There is no Sentinel online right now.', 'Start the built-in Sentinel from the Sentinels page and wait.',
                     'Bring the built-in scanner up to date.'):
            self.assertTrue(fleet.contradicts_fleet(text, remote), text)
        self.assertFalse(fleet.contradicts_fleet('Both Sentinels are live and completing work; the expiries are a small share, no action is needed.', remote))

    def test_the_guard_allows_what_is_true(self):
        down = {'live_sentinels': 0, 'builtin_scanner': True}
        self.assertFalse(fleet.contradicts_fleet('No Sentinel is online. Start the built-in Sentinel on the Sentinels page.', down))
        self.assertTrue(fleet.contradicts_fleet('Start the built-in Sentinel.', {'live_sentinels': 0, 'builtin_scanner': False}))

    def test_a_contradicting_diagnosis_is_not_stored(self):
        self.live()
        self.tasks(100, 'done')
        self.tasks(8, 'failed', 'the tool crashed', kind='nmap')
        bad = ('No Sentinel is online to take the work, so the tasks expired and failed. Open the Sentinels page and start the built-in Sentinel, '
               'then confirm in docker compose logs celery that the tasks run again.')
        reviewer.apply_ops_report({'alerts': [{'code': 'sentinel_errors', 'severity': 'warning', 'diagnosis': bad}], 'actions': [], 'model': 'm'})
        from cveFeed.models import AdminAlert
        self.assertEqual(AdminAlert.objects.get(code='sentinel_errors', resolved_at__isnull=True).ai_detail, '')


    def test_advice_stored_before_the_guard_is_not_shown_either(self):
        from cveFeed.models import AdminAlert
        self.live()
        AdminAlert.objects.create(code='sentinel_errors', severity='critical', title='Sentinel tasks are failing', detail='x',
                                  ai_detail='No Sentinel is online to take the work, so tasks expire and fail. Start the built-in Sentinel on the Sentinels page '
                                            'and then confirm in docker compose logs celery that the tasks run again.')
        shown = reviewer.open_alerts()
        self.assertEqual([a['ai_detail'] for a in shown], [''])


class TemplateAlertTextTests(Base):
    """(g) the text of 'AI-written checks cannot be tested yet' is true for an install of remote Sentinels with no built-in one."""

    def stuck(self):
        from cveFeed import templatevalidate
        from cveFeed.models import ReviewerSettings
        ReviewerSettings.current()
        ReviewerSettings.objects.update(template_validation_enabled=True)  # the validator ships off; these texts are about it running
        for _ in range(20):
            GeneratedTemplate.objects.create(cve_entry=self.cve, yaml='x', status=GeneratedTemplate.STATUS_DRAFT,
                                             validation_started_at=now() - templatevalidate.STUCK_AFTER - timedelta(hours=1))
        from reNgine.resources import ScannerUnavailable
        return mock.patch('agentapi.sentinel_dispatch.nuclei_validate_ready', side_effect=ScannerUnavailable('nuclei_validate', 'none'))

    def test_remote_sentinels_and_no_built_in_one(self):
        self.live()
        with self.stuck():
            found = self.check('generated_templates')
        self.assertEqual(found['state'], 'warning')
        text = found['detail'].lower()
        self.assertIn('20 ai-written check(s)', text)
        self.assertNotIn('start the built-in', text)
        self.assertNotIn('built-in sentinel', text)
        self.assertIn('2 live sentinels', text)
        self.assertEqual((found['facts']['live_sentinels'], found['facts']['builtin_scanner']), (2, False))

    def test_no_sentinel_at_all_names_the_sentinels_page_not_a_built_in_one(self):
        with self.stuck():
            found = self.check('generated_templates')
        self.assertIn('no Sentinel that runs template checks is online', found['detail'])
        self.assertNotIn('built-in', found['detail'])

    def test_an_install_with_a_built_in_scanner_that_is_down_may_be_told_to_start_it(self):
        fake = FakeScanner(kinds=['nmap']).start_for(self)
        fake.go_offline()
        with self.stuck():
            found = self.check('generated_templates')
        self.assertTrue(found['facts']['builtin_scanner'])
        self.assertIn('built-in', found['detail'])


class KeyOverItsLimitTests(Base):
    """(a) a key the provider says is over its limit or rate-limited is left out for a while and noted once; nothing is written as failed per discovery."""

    def setUp(self):
        super().setUp()
        from dashboard.models import ApiCredential
        ApiCredential.objects.create(project=self.proj, service='securitytrails', value={'api_key': 'st-key'})
        ApiCredential.objects.create(project=self.proj, service='shodan', value={'api_key': 'sh-key'})
        from cveFeed.api_credentials import bbot_config_args
        self.args = bbot_config_args(self.proj)

    def report(self, module='securitytrails', reason=LIMIT):
        from cveFeed import discovery
        discovery._report_key_problems([(module, reason)], self.args, self.scan)

    def test_seventy_seven_discoveries_leave_one_notice_and_no_failed_line(self):
        for index in range(77):
            self.report(reason=LIMIT if index % 2 else 'Too many requests')
        self.assertEqual(AgentActivity.objects.filter(status='failed').count(), 0)
        notes = list(AgentActivity.objects.filter(kind='discovery', status='notice'))
        self.assertEqual(len(notes), 1, [n.message for n in notes])
        for text in ('SecurityTrails', "over its plan's limit", 'discovery continues without it'):
            self.assertIn(text, notes[0].message)

    def test_the_key_is_not_sent_again_for_a_while_and_others_still_are(self):
        from cveFeed.api_credentials import bbot_config_args
        self.assertIn('modules.securitytrails.api_key=st-key', bbot_config_args(self.proj))
        self.report()
        after = bbot_config_args(self.proj)
        self.assertNotIn('modules.securitytrails.api_key=st-key', after)
        self.assertIn('modules.shodan_dns.api_key=sh-key', after)
        cache.clear()
        self.assertIn('modules.securitytrails.api_key=st-key', bbot_config_args(self.proj))

    def test_the_pause_is_sensible(self):
        from cveFeed import key_limits
        self.assertTrue(30 * 60 <= key_limits.PAUSE_SECONDS <= 24 * 3600)

    def test_every_keyed_discovery_source_gets_the_same_treatment(self):
        from cveFeed.api_credentials import SERVICES
        seen = 0
        for service, (label, _fields, mapping) in SERVICES.items():
            if not mapping:
                continue
            cache.clear()
            AgentActivity.objects.all().delete()
            module = mapping[0][0].split('.')[1]
            self.args = ['-c', f'{mapping[0][0]}=x']
            self.report(module=module, reason='HTTP 429 Too many requests')
            self.report(module=module, reason='quota exceeded for this key')
            self.assertEqual(AgentActivity.objects.filter(status='failed').count(), 0, service)
            notes = AgentActivity.objects.filter(status='notice')
            self.assertEqual(notes.count(), 1, service)
            self.assertIn(label, notes[0].message)
            seen += 1
        self.assertGreaterEqual(seen, 10)

    def test_a_key_that_is_simply_wrong_is_still_a_failed_line(self):
        self.report(reason='401 Unauthorized: invalid API key')
        self.assertEqual(AgentActivity.objects.filter(status='failed', kind='discovery').count(), 1)


class RefusedTargetIsARefusalTests(Base):
    """(b) a target the private-address guard refuses is recorded once per host as skipped, stays visible on the host, and is not tried every cycle."""

    def setUp(self):
        super().setUp()
        from startScan.models import ScanHistory
        from targetApp.models import Domain
        self.host = Domain.objects.create(name='internal.example.com', project=self.proj, insert_date=now())
        self.make = lambda: ScanHistory.objects.create(domain=self.host, scan_type=self.scan.scan_type, scan_status=-1, start_scan_date=now())

    def run_one(self):
        from cveFeed import discovery
        scan = self.make()
        with mock.patch('targetApp.target_types.resolves_to_blocked', return_value=True), \
                mock.patch('targetApp.target_types.sentinel_only_target', return_value=False):
            discovery.run_discovery(scan.pk)
        scan.refresh_from_db()
        return scan

    def test_it_is_skipped_not_failed_and_written_once_for_the_host(self):
        first, second, third = self.run_one(), self.run_one(), self.run_one()
        self.assertEqual(AgentActivity.objects.filter(status='failed').count(), 0, list(AgentActivity.objects.values_list('message', flat=True)))
        lines = list(AgentActivity.objects.filter(kind='discovery', status='skipped', message__contains='internal.example.com'))
        self.assertEqual(len(lines), 1)
        self.assertIn('refused', lines[0].message)
        self.assertEqual(AgentActivity.objects.filter(status='running').count(), 0)
        for scan in (first, second, third):
            self.assertIn('refused', scan.error_message)  # visible on the host's own scan history

    def test_the_conductor_does_not_pick_it_again_while_it_is_still_internal(self):
        from cveFeed import conductor
        self.assertIn(self.host.pk, conductor.next_targets(10))
        self.run_one()
        from startScan.models import ScanHistory
        ScanHistory.objects.filter(domain=self.host).update(start_scan_date=now() - timedelta(days=30))
        self.assertNotIn(self.host.pk, conductor.next_targets(10))
        cache.clear()  # the refusal is remembered for a few hours, then the name is looked up again
        self.assertIn(self.host.pk, conductor.next_targets(10))


class NotFailuresAreNotCountedTests(Base):
    """(c) clean-up after a restart and an AI step that was put off are not failures."""

    def test_restart_clean_up_is_a_notice(self):
        from cveFeed import tasks
        with mock.patch('cveFeed.reaper.reap', return_value={'AgentActivity:running': 7}), mock.patch('cveFeed.reaper.expire_orphaned_running', return_value={}), \
                mock.patch('cveFeed.reaper.redispatch_queued_assessments', return_value=0):
            tasks._reap_stuck_jobs()
        line = AgentActivity.objects.get(message__startswith='Expired stuck jobs a restarted worker left behind')
        self.assertEqual(line.status, 'notice')

    def test_checks_ran_and_the_ai_step_was_put_off(self):
        from cveFeed import hot_validation
        for ai in ('deferred', 'queued'):
            status, words = hot_validation.line_outcome({'ran': 3}, 'checked', ai, False)  # every check ran and none failed: only the AI step is put off
            self.assertNotEqual(status, 'failed', ai)
            self.assertNotIn('failed', words)
        self.assertEqual(hot_validation.line_outcome({'ran': 3}, 'checked', 'failed', False)[0], 'failed')
        self.assertEqual(hot_validation.line_outcome({'failed': 1}, 'not_run', 'deferred', False)[0], 'failed')

    def test_none_of_these_lines_makes_the_failing_alert(self):
        for status, kind in (('notice', 'validate'), ('skipped', 'discovery'), ('deferred', 'validate'), ('notice', 'discovery')):
            AgentActivity.objects.bulk_create([AgentActivity(kind=kind, message=f'{status} {i}', status=status) for i in range(40)])
        self.assertEqual(self.check('scan_errors')['state'], 'ok')
        AgentActivity.objects.bulk_create([AgentActivity(kind='run_check', message=f'real {i}', status='failed') for i in range(25)])
        self.assertEqual(self.check('scan_errors')['state'], 'problem')


class EachSentinelAndKindIsJudgedOnItsOwnTests(Base):
    """Second pass, D1 and D2: one failed share over every kind and every Sentinel hid a kind that fails every time, and one dead Sentinel among several."""

    def setUp(self):
        super().setUp()
        self.live(3)
        self.tasks(3000, 'done')

    def errors(self):
        return self.check('sentinel_errors')

    def test_a_kind_that_fails_every_time_is_an_alert_at_any_volume(self):
        for count in (5, 100, 157, 158, 300):
            SentinelTask.objects.filter(status='failed').delete()
            self.tasks(count, 'failed', 'hygiene tool crashed', kind='nuclei', agent='sentinel-1')
            found = self.errors()
            self.assertEqual(found['state'], 'problem', count)
            self.assertIn('sentinel-1', found['detail'])
            self.assertIn('nuclei', found['detail'])

    def test_a_kind_that_fails_half_the_time_on_one_sentinel_is_an_alert(self):
        self.tasks(100, 'done', kind='nmap', agent='sentinel-2')
        self.tasks(100, 'failed', 'boom', kind='nmap', agent='sentinel-2')
        found = self.errors()
        self.assertEqual(found['state'], 'problem')
        self.assertIn('sentinel-2', found['detail'])

    def test_a_low_rate_on_a_busy_group_stays_quiet(self):
        self.tasks(900, 'done', kind='nmap', agent='sentinel-2')
        self.tasks(20, 'failed', 'boom', kind='nmap', agent='sentinel-2')
        self.assertEqual(self.errors()['state'], 'ok')

    def test_a_single_failure_with_nothing_completed_by_that_group_is_an_alert(self):
        self.tasks(1, 'failed', 'boom', kind='openvas', agent='sentinel-3')
        found = self.errors()
        self.assertEqual(found['state'], 'problem')
        self.assertIn('openvas', found['detail'])

    def test_a_task_a_person_cancelled_and_a_task_with_no_known_sentinel_are_no_alert_alone(self):
        self.tasks(3, 'expired', 'cancelled by a person', kind='nmap')
        self.tasks(2, 'expired', 'the dispatch wait timed out; the targets stay due', kind='nmap')
        self.assertEqual(self.errors()['state'], 'ok')

    def test_a_dead_sentinel_among_live_ones_is_an_alert_and_is_named(self):
        self.lost(40, 'sentinel-3', timedelta(hours=1))
        found = self.errors()
        self.assertEqual(found['state'], 'problem')
        self.assertIn('sentinel-3', found['detail'])
        self.assertEqual(found['facts']['groups'][0]['sentinel'], 'sentinel-3')

    def test_a_sentinel_that_keeps_its_agent_on_an_expired_task_is_named_too(self):
        self.tasks(40, 'expired', LEASE, kind='nmap', agent='sentinel-3')
        self.assertIn('sentinel-3', self.errors()['detail'])

    def test_a_task_that_is_expired_keeps_who_held_it(self):
        """The broker clears the task's agent when a lease expires; the check reads who held it from the result."""
        self.lost(1, 'sentinel-3', timedelta(hours=1))
        task = SentinelTask.objects.get(status='expired', error=LEASE)
        self.assertIsNone(task.agent_id)
        self.assertEqual(task.result.get('expired_agent'), Agent.objects.get(name='sentinel-3').pk)


class RestartGraceIsOneSidedAndPerSentinelTests(Base):
    """Second pass, D3: the grace is from the restart moment to 15 minutes after, for that Sentinel's own tasks claimed before it, after a finished update."""

    def setUp(self):
        super().setUp()
        self.live(2)
        self.tasks(100, 'done')

    def verdict(self):
        return self.check('sentinel_errors')['state']

    def test_tasks_lost_before_the_restart_are_not_excused(self):
        self.lost(30, 'sentinel-1', timedelta(minutes=50), claimed_ago=timedelta(minutes=80))
        self.updated('sentinel-1', 'done', timedelta(minutes=40))
        self.assertEqual(self.verdict(), 'problem')

    def test_another_sentinels_update_excuses_nothing(self):
        self.lost(30, 'sentinel-2', timedelta(minutes=30), claimed_ago=timedelta(minutes=50))
        self.updated('sentinel-1', 'done', timedelta(minutes=35))
        self.assertEqual(self.verdict(), 'problem')

    def test_a_failed_update_excuses_nothing(self):
        self.lost(30, 'sentinel-1', timedelta(minutes=30), claimed_ago=timedelta(minutes=50))
        self.updated('sentinel-1', 'failed', timedelta(minutes=35))
        self.assertEqual(self.verdict(), 'problem')

    def test_a_task_claimed_after_the_restart_is_not_excused(self):
        self.lost(30, 'sentinel-1', timedelta(minutes=30), claimed_ago=timedelta(minutes=33))
        self.updated('sentinel-1', 'done', timedelta(minutes=35))
        self.assertEqual(self.verdict(), 'problem', 'claimed after the restart moment: the restart did not cut it off')

    def test_tasks_lost_long_after_the_restart_are_not_excused(self):
        self.lost(30, 'sentinel-1', timedelta(minutes=10), claimed_ago=timedelta(minutes=70))
        self.updated('sentinel-1', 'done', timedelta(minutes=40))
        self.assertEqual(self.verdict(), 'problem')

    def test_the_own_tasks_inside_the_window_are_excused(self):
        self.lost(30, 'sentinel-1', timedelta(minutes=30), claimed_ago=timedelta(minutes=50))
        self.updated('sentinel-1', 'done', timedelta(minutes=35))
        self.assertEqual(self.verdict(), 'ok')

    def test_failed_tasks_in_the_window_are_still_counted(self):
        self.tasks(30, 'failed', 'x', kind='nmap', ago=timedelta(minutes=30), agent='sentinel-1', claimed_ago=timedelta(minutes=50))
        self.updated('sentinel-1', 'done', timedelta(minutes=35))
        self.assertEqual(self.verdict(), 'problem')


class HotValidationLineOutcomeTests(Base):
    """Second pass, D4: a line whose checks failed or were blocked is a failure, not deferred, whatever the AI step did."""

    def test_failed_checks_are_a_failure_not_deferred(self):
        from cveFeed import hot_validation
        for ai in ('deferred', 'queued'):
            status, words = hot_validation.line_outcome({'failed': 2, 'ran': 3}, 'checked', ai, False)
            self.assertEqual(status, 'failed', ai)
            self.assertNotIn('deferred', words)
            self.assertNotIn('waiting', words)

    def test_blocked_checks_are_never_deferred_but_held_as_before(self):
        from cveFeed import hot_validation
        for ai in ('deferred', 'queued', 'done'):
            status, words = hot_validation.line_outcome({'blocked': 1, 'ran': 2}, 'checked', ai, False)
            self.assertNotIn('deferred', words, ai)
            self.assertNotIn('waiting', words, ai)
            self.assertIn('held', words, ai)

    def test_clean_checks_with_a_put_off_ai_step_are_still_deferred(self):
        from cveFeed import hot_validation
        self.assertEqual(hot_validation.line_outcome({'ran': 3}, 'checked', 'queued', False)[0], 'deferred')


class NoLiveSentinelIsAProblemTests(Base):
    """Second pass, D5: with no live Sentinel the waiting alert says so and is a warning, not info, and a registered Sentinel that is gone is its own alert."""

    def test_the_waiting_alert_is_a_warning_when_no_sentinel_is_live(self):
        self.tasks(7, 'expired', WAIT, kind='nmap', ago=timedelta(hours=1))
        found = self.check('sentinel_waiting')
        self.assertEqual((found['state'], found['severity']), ('problem', 'warning'))
        self.assertIn('No Sentinel is live', found['detail'])

    def test_with_live_sentinels_it_stays_a_note(self):
        self.live()
        self.busy()
        self.tasks(7, 'expired', WAIT, kind='nmap', ago=timedelta(hours=1))
        found = self.check('sentinel_waiting')
        self.assertEqual((found['state'], found['severity']), ('warning', 'info'))

    def test_a_registered_sentinel_that_is_not_live_is_an_alert_even_with_no_waits(self):
        self.live(1)
        self.fakes[0].go_offline()
        found = self.check('sentinels_offline')
        self.assertEqual((found['state'], found['severity']), ('problem', 'warning'))
        self.assertIn('sentinel-1', found['detail'])

    def test_it_is_ok_while_one_is_live_or_none_was_ever_registered(self):
        self.assertEqual(self.check('sentinels_offline')['state'], 'ok')
        self.live(2)
        self.fakes[0].go_offline()
        self.assertEqual(self.check('sentinels_offline')['state'], 'ok')


class WaitingAlertSaysWhenTheSentinelsAreSaturatedTests(Base):
    """Second pass, D6: a flat but heavy wait is not "keeping up, no action needed"."""

    def test_the_owners_flat_numbers_do_not_say_no_action_is_needed(self):
        self.live(2, slots=4)
        self.busy()
        self.tasks(2951, 'done')
        self.tasks(361, 'expired', WAIT, kind='nmap', ago=timedelta(hours=5))
        self.tasks(361, 'expired', WAIT, kind='nmap', ago=timedelta(hours=1))
        found = self.check('sentinel_waiting')
        self.assertTrue(found['facts']['saturated'])
        self.assertFalse(found['facts']['falling_behind'])
        self.assertNotIn('no action is needed', found['detail'])
        self.assertNotIn('keeping up', found['detail'])
        self.assertIn('at capacity', found['detail'])
        self.assertIn('Nothing is broken', found['detail'])

    def test_a_small_flat_wait_still_says_keeping_up(self):
        self.live(2, slots=4)
        self.tasks(2951, 'done')
        self.tasks(3, 'expired', WAIT, kind='nmap', ago=timedelta(hours=5))
        self.tasks(3, 'expired', WAIT, kind='nmap', ago=timedelta(hours=1))
        found = self.check('sentinel_waiting')
        self.assertFalse(found['facts']['saturated'])
        self.assertIn('keeping up', found['detail'])


class AdviceGuardKeepsTrueAdviceTests(Base):
    """Second pass, D7: only the sentences the server's numbers contradict are dropped, true advice stays, more false claims are caught."""
    REMOTE = {'live_sentinels': 2, 'builtin_scanner': False}

    def test_true_advice_is_not_dropped(self):
        for text in ('No live Sentinel offers nuclei template checks, so the AI checks wait. Bring a nuclei-capable Sentinel online.',
                     'No Sentinel is online with the wpscan capability.', 'Do not run the built-in scanner; this install has none.',
                     'Check that the built-in scanner is not expected to run; it does not exist here.', 'No Sentinel that runs template checks is online.',
                     'There is no built-in scanner on this install; check the remote Sentinels page instead.'):
            self.assertFalse(fleet.contradicts_fleet(text, self.REMOTE), text)

    def test_more_false_claims_are_caught(self):
        for text in ('Your Sentinels are offline.', 'All Sentinels are down.', 'The Sentinel is not connected.', 'No Sentinels have checked in.',
                     'Restart the built in sentinel.', 'Enable the bundled scanner.', 'Switch on the local Sentinel.'):
            self.assertTrue(fleet.contradicts_fleet(text, self.REMOTE), text)
        self.assertTrue(fleet.contradicts_fleet('Both Sentinels are live and healthy.', {'live_sentinels': 0, 'builtin_scanner': True}))
        self.assertFalse(fleet.contradicts_fleet('Both Sentinels are live and healthy.', self.REMOTE))

    def test_only_the_false_sentence_goes_and_the_rest_of_the_diagnosis_stays(self):
        text = ('No Sentinel is online to take the work. The nmap tasks failed with the same crash after the last update, so roll the Sentinel back to the previous '
                'release and confirm that the crash stops. Start the built-in Sentinel on the Sentinels page.')
        kept = fleet.without_contradictions(text, self.REMOTE)
        self.assertIn('roll the Sentinel back', kept)
        self.assertNotIn('No Sentinel is online', kept)
        self.assertNotIn('built-in', kept)
        self.assertEqual(fleet.without_contradictions('No Sentinel is online. Start the built-in Sentinel.', self.REMOTE), '')

    def test_a_stored_diagnosis_with_one_false_sentence_keeps_the_rest(self):
        from cveFeed.models import AdminAlert
        self.live()
        self.tasks(100, 'done')
        self.tasks(8, 'failed', 'the tool crashed', kind='nmap')
        text = ('No Sentinel is online to take the work. The nmap tasks failed with the same crash after the last update, so roll the Sentinel back to the previous '
                'release and confirm that the crash stops.')
        reviewer.apply_ops_report({'alerts': [{'code': 'sentinel_errors', 'severity': 'warning', 'diagnosis': text}], 'actions': [], 'model': 'm'})
        shown = AdminAlert.objects.get(code='sentinel_errors', resolved_at__isnull=True).ai_detail
        self.assertIn('roll the Sentinel back', shown)
        self.assertNotIn('No Sentinel is online', shown)


class KeyPauseSecondPassTests(KeyOverItsLimitTests):
    """Second pass, D8: a replaced key is not paused, a pause that cannot be taken is still reported, the limit words are narrow, a streak is said once, tenancy."""

    def test_a_replaced_key_is_sent_at_once(self):
        from dashboard.models import ApiCredential
        from cveFeed.api_credentials import bbot_config_args
        self.report()
        self.assertNotIn('modules.securitytrails.api_key=st-key', bbot_config_args(self.proj))
        ApiCredential.objects.filter(project=self.proj, service='securitytrails').update(value={'api_key': 'st-key-new'})
        self.assertIn('modules.securitytrails.api_key=st-key-new', bbot_config_args(self.proj))

    def test_a_pause_that_cannot_be_taken_still_reports_the_refusal(self):
        from cveFeed import key_limits
        with mock.patch.object(key_limits, 'pause', return_value=None):
            self.report()
        lines = AgentActivity.objects.filter(kind='discovery', status='failed')
        self.assertEqual(lines.count(), 1)
        self.assertIn('the key was not accepted', lines[0].message)

    def test_the_limit_words_are_anchored_on_a_limit(self):
        from cveFeed import key_limits
        for reason in ('You have exceeded the usage limits for your account', 'HTTP 429', 'Too many requests', 'quota exceeded', 'monthly limit exceeded: upgrade',
                       'rate limit hit'):
            self.assertTrue(key_limits.is_limit(reason), reason)
        for reason in ('Your account has been disabled, quota 0', 'API key invalid; limit exceeded of invalid attempts', 'credit limit reached: account suspended',
                       'Unauthorized: key invalid, rate limit not applicable', 'Invalid API key', '401 Unauthorized', 'API key is not valid',
                       'Forbidden: subscription expired', '503 Service Unavailable', 'something was exceeded'):
            self.assertFalse(key_limits.is_limit(reason), reason)

    def test_a_key_over_its_limit_for_a_day_raises_one_failed_line(self):
        from cveFeed import key_limits
        from cveFeed.api_credentials import key_fingerprint_from_args
        fp = key_fingerprint_from_args('securitytrails', self.args)
        for _ in range(key_limits.STREAK_WARNING + 3):
            cache.delete(key_limits._key(self.proj.pk, 'securitytrails', fp))  # the pause ran out
            self.report()
        from django.db.models import Sum
        self.assertEqual(AgentActivity.objects.filter(status='notice').aggregate(n=Sum('repeat'))['n'], key_limits.STREAK_WARNING + 3)  # equal lines in a row are one row with a repeat count
        failed = AgentActivity.objects.filter(status='failed')
        self.assertEqual(failed.count(), 1)
        self.assertIn('pauses in a row', failed[0].message)

    def test_one_projects_quota_never_pauses_another_projects_key(self):
        from dashboard.models import ApiCredential, Project
        from cveFeed.api_credentials import bbot_config_args
        other = Project.objects.create(name='Other', slug='other-proj', insert_date=now())  # no org: another tenant with the very same key value
        ApiCredential.objects.create(project=other, service='securitytrails', value={'api_key': 'st-key'})
        self.report()
        self.assertNotIn('modules.securitytrails.api_key=st-key', bbot_config_args(self.proj))
        self.assertIn('modules.securitytrails.api_key=st-key', bbot_config_args(other))

    def test_a_refusal_of_one_target_never_hides_another_targets(self):
        from cveFeed import discovery
        discovery.note_refused(self.domain.pk)
        self.assertTrue(discovery.refusal_pending(self.domain.pk))
        self.assertFalse(discovery.refusal_pending(self.domain.pk + 1000))


class NewActivityStatusesAreDocumentedAndDrawnTests(Base):
    """Second pass, D9: notice, skipped and deferred are drawn in the feed and named in the model comment and the API descriptions."""

    def test_the_feed_has_a_look_for_each_status(self):
        from pathlib import Path
        css = (Path(__file__).resolve().parent.parent / 'static' / 'cve' / 'cve.css').read_text()
        for status in ('notice', 'skipped', 'deferred'):
            self.assertIn(f'.agent li.a-{status}::before', css)

    def test_the_statuses_are_listed_where_a_client_looks(self):
        from pathlib import Path
        root = Path(__file__).resolve().parent.parent
        self.assertIn('notice', (root / 'cveFeed' / 'models.py').read_text().split('class AgentActivity')[1][:900])
        rest = (root / 'agentapi' / 'rest.py').read_text()
        self.assertIn('skipped', rest[rest.index("/activity', 'What the AI engine did"):][:900])
        mcp = (root / 'agentapi' / 'mcp.py').read_text()
        self.assertIn('skipped', mcp[mcp.index("('list_activity'"):][:900])

    def test_a_status_filter_still_ignores_the_new_statuses(self):
        for status in ('notice', 'skipped', 'deferred'):
            AgentActivity.objects.create(kind='validate', message=status, status=status)
        from cveFeed import counts
        self.assertEqual(counts.background_running().count(), 0)


class SmallTextsTests(Base):
    def test_one_remote_sentinel_reads_in_the_singular(self):
        self.live(1)
        with TemplateAlertTextTests.stuck(self):
            found = self.check('generated_templates')
        self.assertIn('1 live Sentinel is remote', found['detail'])
        self.assertNotIn('1 live Sentinel are', found['detail'])


class DismissedAlertStaysDismissedTests(Base):
    """AM-10: a dismissed alert comes back when the problem changes, not when a count inside it moves."""

    def waiting_alert(self):
        return [a for a in reviewer.open_alerts() if a['code'] == 'sentinel_waiting']

    def test_one_more_waited_task_does_not_bring_a_dismissed_alert_back(self):
        from django.contrib.auth.models import User
        self.live(count=2, slots=4)
        self.tasks(500, 'done', ago=timedelta(hours=2))
        self.tasks(40, 'expired', WAIT, kind='nmap', ago=timedelta(hours=4))
        self.tasks(40, 'expired', WAIT, kind='nmap', ago=timedelta(hours=1))
        reviewer.run_ops_checks()
        root = User.objects.create_superuser('dis_root', 'd@x.io', 'x')
        reviewer.dismiss_alert(self.waiting_alert()[0]['id'], root)
        before = [a['code'] for a in reviewer.open_alerts()]
        self.assertNotIn('sentinel_waiting', before)
        self.tasks(1, 'expired', WAIT, kind='nmap', ago=timedelta(minutes=5))
        reviewer.run_ops_checks()
        self.assertEqual(sorted(a['code'] for a in reviewer.open_alerts()), sorted(before))  # the same alerts, whatever their order

    def test_a_new_kind_waiting_or_falling_behind_brings_it_back(self):
        facts = {'waited': 80, 'by_kind': {'nmap': 80}, 'slots': 8, 'falling_behind': False, 'saturated': True, 'waited_recent': 40, 'growing': False}
        check = lambda f: {'code': 'sentinel_waiting', 'state': 'warning', 'severity': 'info', 'title': 't', 'detail': 'd', 'facts': f, 'actions': []}
        base = reviewer._digest(check(facts))
        self.assertEqual(reviewer._digest(check({**facts, 'waited': 95, 'by_kind': {'nmap': 95}, 'waited_recent': 3})), base)
        self.assertNotEqual(reviewer._digest(check({**facts, 'falling_behind': True})), base)
        self.assertNotEqual(reviewer._digest(check({**facts, 'by_kind': {'nmap': 80, 'nuclei': 2}})), base)
        failing = lambda groups: check({'groups': groups, 'failed': 12})
        one = [{'sentinel': 's1', 'kind': 'nmap', 'failed': 12, 'completed': 0}]
        self.assertEqual(reviewer._digest(failing([{**one[0], 'failed': 15}])), reviewer._digest(failing(one)))
        self.assertNotEqual(reviewer._digest(failing(one + [{'sentinel': 's2', 'kind': 'nmap', 'failed': 12, 'completed': 0}])), reviewer._digest(failing(one)))


class TheModelCannotQuietAWarningTests(Base):
    """AM-12: the operations model's severity is taken upwards only."""

    def report(self, severity, state='warning', check_severity=None):
        from cveFeed.models import AdminAlert
        check = {'code': 'sentinels_offline', 'state': state, 'severity': check_severity or ('critical' if state == 'problem' else 'warning'),
                 'title': 'No Sentinel is live', 'detail': 'd', 'facts': {}, 'actions': []}
        with mock.patch.object(reviewer, 'ops_checks', return_value=[check]):
            reviewer.apply_ops_report({'alerts': [{'code': 'sentinels_offline', 'severity': severity, 'diagnosis': 'Check that the Sentinel is running and can reach this server, then look at the Sentinels page.'}],
                                       'actions': [], 'model': 'm'})
        return AdminAlert.objects.get(code='sentinels_offline', resolved_at__isnull=True).severity

    def test_info_does_not_lower_a_warning(self):
        self.assertEqual(self.report('info'), 'warning')

    def test_warning_stays_and_critical_is_not_taken_for_a_warning_check(self):
        self.assertEqual(self.report('warning'), 'warning')
        self.assertEqual(self.report('critical'), 'warning')

    def test_a_note_can_be_raised_to_a_warning_and_a_problem_is_never_changed(self):
        self.assertEqual(self.report('warning', state='warning', check_severity='info'), 'warning')
        self.assertEqual(self.report('info', state='warning', check_severity='info'), 'info')
        self.assertEqual(self.report('info', state='problem'), 'critical')
