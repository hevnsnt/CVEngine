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

    def tasks(self, count, status, error='', kind='hygiene_check', ago=timedelta(hours=1)):
        SentinelTask.objects.bulk_create([SentinelTask(project=self.proj, kind=kind, target={}, status=status, error=error, finished_at=now() - ago)
                                          for _ in range(count)])

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
        self.tasks(6, 'expired', LEASE, ago=timedelta(minutes=30))
        self.assertEqual(self.check('sentinel_errors')['state'], 'problem', 'six of 106 with nothing to explain them is a real rate')
        Agent.objects.filter(name='sentinel-1').update(info={'update': {'status': 'done', 'at': (now() - timedelta(minutes=32)).isoformat()}})
        self.assertEqual(self.check('sentinel_errors')['state'], 'ok')

    def test_the_server_clean_up_after_its_own_restart_also_explains_expiries(self):
        self.live()
        self.tasks(100, 'done')
        self.tasks(6, 'expired', LEASE, ago=timedelta(minutes=30))
        entry = activity.log('validate', 'Expired stuck jobs a restarted worker left behind: 7 AgentActivity running', status='notice')
        AgentActivity.objects.filter(pk=entry.pk).update(created_at=now() - timedelta(minutes=29))
        self.assertEqual(self.check('sentinel_errors')['state'], 'ok')

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
            status, words = hot_validation.line_outcome({'ran': 3, 'failed': 1}, 'checked', ai, False)
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
