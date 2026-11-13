"""The knobs that fix the incidents (1.4.0 WP5, review findings AM-5, AM-6, AM-7): lane concurrency (a Celery lane killed for memory is lowered, and raised back only
inside the remembered-trouble ceiling and never above what a person configured), the share of the discovery pool host assessments may hold while scans wait (the
18 scans that waited 16 hours behind 360 assessments), a Sentinel kind pause that always ends by itself, and a claim outage that is not Sentinel capacity trouble.
Each has a safe range in the registry, a rule that maps its trouble to it, a verify step, and a replay of the incident."""
import os
from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

from django.core.management import call_command
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import sentinel_policy
from agentapi.models import Agent, SentinelTask
from cveFeed import autotune, autotune_policy as policy, autotune_signals as signals, host_assessment, scan_concurrency as sc
from cveFeed.models import AutoTuneSettings, HostAssessment, TuningDecision
from reNgine import resources
from tests.test_alerts_tell_the_truth import Base as SentinelBase, WAIT
from tests.test_autotune import BASE, NOW, Isolated, change, decide, history, merge

LANE_FEED = policy.Setting('lane.cve_feed', 'lane:cve_feed', 'cve feed lane', 1, 4, 1, 'more', 4, 4)
LANE_CLASSIC = policy.Setting('lane.classic', 'lane:classic', 'classic lane', 3, 10, 1, 'more', 10, 10)
SHARE = policy.Setting('assess_share_percent', 'assess_share', 'assessment share', 25, 75, 10, 'more', 75, 75)
LANE_AT_LIMIT = {'lanes': {'cve_feed': {'percent': 95, 'restarts_24h': 0}, 'classic': {'percent': 30, 'restarts_24h': 0}}}
LANE_CALM = {'lanes': {'cve_feed': {'percent': 40, 'restarts_24h': 0}, 'classic': {'percent': 30, 'restarts_24h': 0}}}
STARVED = {'starve': {'scans_queued': 18, 'scan_age_s': 16 * 3600}, 'assess': {'queued': 360, 'running': 8, 'oldest_s': 20 * 3600}}


class RegistryTests(SimpleTestCase):
    def test_every_knob_is_in_the_registry_with_a_safe_range_and_auto_tuned(self):
        keys = autotune.by_key()
        feed, classic, share = keys['lane.cve_feed'].setting, keys['lane.classic'].setting, keys['assess_share_percent'].setting
        self.assertEqual((feed.low, feed.high, feed.kind), (1, 4, 'lane:cve_feed'))  # never below 1, never above the shipped 4
        self.assertEqual((classic.low, classic.high, classic.kind), (3, 10, 'lane:classic'))
        self.assertEqual((share.low, share.high, share.kind), (25, 75, 'assess_share'))
        for key in ('lane.cve_feed', 'lane.classic', 'assess_share_percent'):
            self.assertTrue(sc.BY_KEY[key].auto_tunable)
            self.assertLessEqual(sc.BY_KEY[key].auto_max, sc.BY_KEY[key].high)
        self.assertEqual(sc.BY_KEY['lane.cve_feed'].group, 'lanes')
        self.assertIn('lanes', sc.GROUP_TITLES)

    def test_the_configured_number_is_the_ceiling_a_person_can_lower_it_in_the_environment_and_the_tuner_never_goes_above(self):
        with mock.patch.dict(os.environ, {'CLASSIC_CONCURRENCY': '6', 'CVE_FEED_CONCURRENCY': 'junk'}):
            self.assertEqual(sc._lane_default('CLASSIC_CONCURRENCY', 10), 6)
            self.assertEqual(sc._lane_default('CVE_FEED_CONCURRENCY', 4), 4)
        self.assertEqual(policy.size_for(LANE_FEED, {}, current=2)[0], 4)  # the target is the configured number, known
        self.assertTrue(policy.size_for(LANE_FEED, {}, current=2)[2])

    def test_no_knob_raises_a_memory_limit_or_spends_money(self):
        # the three knobs are numbers of concurrency and share; none is an AI spend cap or a container limit
        for m in autotune.managed():
            self.assertNotIn('MEM_LIMIT', m.env_name or '')
        from cveFeed import tunables
        self.assertFalse(any(t.auto_tunable and t.group == 'ai_spend' for t in tunables.TUNABLES))


class LanePolicyTests(SimpleTestCase):
    def test_a_lane_at_its_memory_limit_in_two_measurements_in_a_row_backs_off_and_one_blip_does_not(self):
        plan = decide(LANE_FEED, 4, 4, history(3, **LANE_AT_LIMIT))
        self.assertEqual((plan['phase'], plan['pressure'], plan['new']), ('back_off', True, 2))
        self.assertIn('95% of its memory limit', plan['reason'])
        blip = history(3, **LANE_CALM)
        blip[-1] = merge(blip[-1], LANE_AT_LIMIT)
        self.assertIsNone(policy.trouble(LANE_FEED, blip))
        self.assertNotEqual(decide(LANE_FEED, 4, 4, blip)['phase'], 'back_off')

    def test_a_lane_restart_and_a_kernel_kill_with_the_lane_large_are_trouble_and_unknown_is_not(self):
        samples = [merge(BASE, {'t': NOW - 600, 'lanes': {'cve_feed': {'percent': 50, 'restarts_24h': 1}}}),
                   merge(BASE, {'t': NOW, 'lanes': {'cve_feed': {'percent': 50, 'restarts_24h': 2}}})]
        self.assertIn('restarted', policy.trouble(LANE_FEED, samples))
        self.assertIsNone(policy.trouble(LANE_CLASSIC, samples))  # another lane's restart is not this lane's trouble
        oom = [merge(BASE, {'t': NOW - 600, 'maint': {'oom_kills_24h': 0}, 'lanes': {'cve_feed': {'percent': 80, 'restarts_24h': 0}}}),
               merge(BASE, {'t': NOW, 'maint': {'oom_kills_24h': 1}, 'lanes': {'cve_feed': {'percent': 80, 'restarts_24h': 0}}})]
        self.assertIn('kernel killed', policy.trouble(LANE_FEED, oom))
        oom[-1]['lanes']['cve_feed']['percent'] = 20  # the lane was small: the kill was something else's
        self.assertIsNone(policy.trouble(LANE_FEED, oom))
        unknown = history(3, lanes={'cve_feed': {'percent': None, 'restarts_24h': None}}, maint={'oom_kills_24h': None})
        self.assertIsNone(policy.trouble(LANE_FEED, unknown))
        self.assertIsNone(policy.trouble(LANE_FEED, history(3)))  # no lane record at all

    def test_never_below_one_and_a_lane_already_at_its_minimum_stays(self):
        plan = decide(LANE_FEED, 1, 4, history(3, **LANE_AT_LIMIT))
        self.assertIsNone(plan['new'])
        self.assertIn('already at the auto-tuning minimum', plan['reason'])
        self.assertEqual(policy.backoff(LANE_CLASSIC, 3), 3)  # the classic lane's floor is 3

    def test_a_lane_is_raised_back_one_step_at_a_time_inside_the_remembered_trouble_ceiling_and_never_above_the_configured_number(self):
        calm = history(15, **LANE_CALM)  # 140 minutes without trouble
        past = [change(5 * 3600, 4, 2, 'back_off', pressure=True)]  # 4 caused trouble five hours ago
        plan = decide(LANE_FEED, 2, 4, calm, past)
        self.assertEqual((plan['phase'], plan['new']), ('probe', 3))
        self.assertEqual(decide(LANE_FEED, 3, 4, calm, past)['new'], None)  # 4 is the level that caused trouble
        self.assertIn('caused trouble', decide(LANE_FEED, 3, 4, calm, past)['why_not_raised'])
        # a day later the memory of it is gone, and the configured number is the most there is
        old = [change(30 * 3600, 4, 2, 'back_off', pressure=True)]
        self.assertEqual(decide(LANE_FEED, 3, 4, calm, old)['new'], 4)
        self.assertIsNone(decide(LANE_FEED, 4, 4, calm, old)['new'])
        # a lane that still holds most of its memory is not raised
        busy = history(15, lanes={'cve_feed': {'percent': 75, 'restarts_24h': 0}})
        self.assertIn('holds 75% of its memory limit', decide(LANE_FEED, 2, 4, busy, past)['why_not_raised'])

    def test_what_a_lane_change_expects_and_is_judged_by(self):
        self.assertEqual(policy.expectation(LANE_FEED, 'less'), 'trouble')
        trouble = history(3, **LANE_AT_LIMIT)
        self.assertEqual(policy.measure(LANE_FEED, trouble, 'less')['trouble'], 1)
        self.assertEqual(policy.verdict(policy.measure(LANE_FEED, trouble, 'less'), policy.measure(LANE_FEED, history(3, **LANE_CALM), 'less')).outcome, 'helped')


class SharePolicyTests(SimpleTestCase):
    def test_replay_18_scans_behind_360_assessments_lowers_the_share_once_three_measurements_show_it(self):
        starved = history(3, **STARVED)
        self.assertIn('queued scans waited 960 min', policy.trouble(SHARE, starved))
        plan = decide(SHARE, 75, 75, starved)
        self.assertEqual((plan['phase'], plan['pressure'], plan['new']), ('back_off', True, 55))
        self.assertIsNone(policy.trouble(SHARE, history(2, **STARVED)))  # two measurements are not enough
        fresh = history(3, starve={'scans_queued': 2, 'scan_age_s': 300}, assess={'queued': 360, 'running': 8, 'oldest_s': 100})
        self.assertIsNone(policy.trouble(SHARE, fresh))  # a scan that has waited five minutes is normal
        none_running = history(3, starve={'scans_queued': 5, 'scan_age_s': 7200}, assess={'queued': 0, 'running': 0, 'oldest_s': None})
        self.assertIsNone(policy.trouble(SHARE, none_running))  # not the assessments' doing
        self.assertIsNone(policy.trouble(SHARE, history(3)))  # nothing measured

    def test_the_share_never_goes_below_25_and_comes_back_to_75_when_no_scan_waits(self):
        self.assertEqual(policy.backoff(SHARE, 35), 25)
        self.assertEqual(policy.backoff(SHARE, 25), 25)
        calm = history(15, starve={'scans_queued': 0, 'scan_age_s': None}, assess={'queued': 40, 'running': 4, 'oldest_s': 3600})
        past = [change(5 * 3600, 75, 55, 'back_off', pressure=True)]
        self.assertEqual(decide(SHARE, 55, 75, calm, past)['new'], 65)  # 75 itself caused the trouble: the ceiling is one step below it
        self.assertIsNone(decide(SHARE, 65, 75, calm, past)['new'])
        old = [change(30 * 3600, 75, 55, 'back_off', pressure=True)]
        plan = decide(SHARE, 65, 75, calm, old)
        self.assertEqual(plan['new'], 75)  # the memory of the trouble is a day old: back to what is configured
        waiting = history(15, starve={'scans_queued': 3, 'scan_age_s': 100}, assess={'queued': 40, 'running': 4, 'oldest_s': 3600})
        self.assertIn('a scan is waiting', decide(SHARE, 55, 75, waiting, [change(5 * 3600, 65, 55, 'back_off')])['why_not_raised'])

    def test_what_a_share_change_expects(self):
        self.assertEqual(policy.expectation(SHARE, 'less'), 'scan_oldest_s')
        self.assertEqual(policy.expectation(SHARE, 'more'), 'assess_oldest_s')
        self.assertEqual(policy.measure(SHARE, history(3, **STARVED), 'less')['value'], 57600.0)
        quiet = history(3, starve={'scans_queued': 0, 'scan_age_s': None})
        self.assertEqual(policy.verdict(policy.measure(SHARE, history(3, **STARVED), 'less'), policy.measure(SHARE, quiet, 'less')).outcome, 'helped')
        self.assertIsNone(policy.measure(SHARE, history(3), 'less')['value'])  # not measured is not zero


class RunTests(Isolated, TestCase):
    """The incidents replayed through the whole round: the decision, its verify step, and what the workers read."""

    def setUp(self):
        super().setUp()
        self.start = timezone.now()

    def run_at(self, minutes, over=None):
        resources.redis_client().delete('cvengine:sweep:autotune')
        sample = merge(BASE, {'t': (self.start + timedelta(minutes=minutes)).timestamp(), **(over or {})})
        with mock.patch.object(signals, 'collect', return_value=sample):
            return autotune.run(self.start + timedelta(minutes=minutes))

    def test_replay_a_lane_killed_for_memory_is_lowered_verified_and_what_a_restart_reads_is_the_lowered_number(self):
        self.run_at(0, LANE_AT_LIMIT)
        summary = self.run_at(10, LANE_AT_LIMIT)
        changes = {c['setting']: c for c in summary['changes']}
        self.assertEqual((changes['lane.cve_feed']['from'], changes['lane.cve_feed']['to'], changes['lane.cve_feed']['applied']), (4, 2, True))
        self.assertNotIn('lane.classic', changes)  # the other lane was fine
        d = TuningDecision.objects.get(setting='lane.cve_feed')
        self.assertEqual((d.source, d.layer), ('controller', 'auto'))
        self.assertEqual((d.phase, d.pressure, d.expected), ('back_off', True, 'trouble'))
        self.assertIsNotNone(d.verify_at)  # judged after 30 minutes
        resources.invalidate_auto()
        self.assertEqual(sc.resolve('lane.cve_feed'), {'value': 2, 'source': 'auto'})
        self.assertEqual(sc.bootstrap_value('lane.cve_feed'), 2)  # what the entrypoint starts the lane with
        self.assertGreaterEqual(self.resized.call_count, 1)  # the live resize was asked for
        for minutes in (20, 30, 40):
            summary = self.run_at(minutes, LANE_CALM)
        d.refresh_from_db()
        self.assertEqual((d.outcome, d.resolution), ('helped', ''))
        self.assertEqual(AutoTuneSettings.current().values['lane.cve_feed'], 2)  # kept

    def test_replay_18_scans_behind_360_assessments_lowers_the_share_and_judges_it_by_the_scan_wait(self):
        for minutes in (0, 10):
            self.run_at(minutes, STARVED)
        summary = self.run_at(20, STARVED)
        changes = {c['setting']: c for c in summary['changes']}
        self.assertEqual((changes['assess_share_percent']['from'], changes['assess_share_percent']['to']), (75, 55))
        d = TuningDecision.objects.get(setting='assess_share_percent')
        self.assertEqual((d.phase, d.pressure, d.expected), ('back_off', True, 'scan_oldest_s'))
        self.assertEqual(d.baseline['value'], 57600.0)
        resources.invalidate_auto()
        self.assertEqual(sc.resolve('assess_share_percent'), {'value': 55, 'source': 'auto'})
        for minutes in (30, 40, 50):
            summary = self.run_at(minutes, {'starve': {'scans_queued': 1, 'scan_age_s': 120}, 'assess': {'queued': 300, 'running': 5, 'oldest_s': 3600}})
        d.refresh_from_db()
        self.assertEqual(d.outcome, 'helped')

    def test_a_pinned_lane_is_never_moved_by_the_tuner(self):
        sc.update({'lane.cve_feed': 3}, SimpleNamespace(username='root', pk=None, is_authenticated=True, is_superuser=True))
        for minutes in (0, 10, 20):
            summary = self.run_at(minutes, LANE_AT_LIMIT)
        self.assertEqual(summary['settings']['lane.cve_feed']['state'], 'pinned')
        self.assertFalse(TuningDecision.objects.filter(setting='lane.cve_feed').exists())


class ApplyLaneTests(Isolated, TestCase):
    def fake_app(self, ceilings):
        app = mock.MagicMock()
        app.control.inspect.return_value.stats.return_value = {name: {'autoscaler': {'max': n}} for name, n in ceilings.items()}
        app.control.broadcast.side_effect = lambda cmd, arguments, destination, reply, timeout: [{destination[0]: {'ok': f'autoscale max={arguments["max"]}'}}]
        return app

    def test_a_tuned_number_resizes_the_running_lane_and_the_discovery_pool_is_left_alone(self):
        row = AutoTuneSettings.current()
        row.values = {'lane.cve_feed': 2}
        row.save()
        app = self.fake_app({'celery@cve_feed_worker': 4, 'celery@classic_worker': 10, 'celery@discovery_worker': 8})
        out = sc.apply_lanes(app=app, saved={})
        self.assertEqual(out['lane.cve_feed'], {'want': 2, 'workers': {'celery@cve_feed_worker': 2}, 'changed': ['celery@cve_feed_worker']})
        self.assertEqual(out['lane.classic']['changed'], [])
        sent = [c.kwargs['destination'] for c in app.control.broadcast.call_args_list]
        self.assertEqual(sent, [['celery@cve_feed_worker']])

    def test_a_lane_that_does_not_answer_keeps_what_it_has_and_a_save_asks_for_the_resize(self):
        app = mock.MagicMock()
        app.control.inspect.return_value.stats.return_value = {}
        self.assertEqual(sc.apply_lanes(app=app, saved={})['lane.cve_feed']['workers'], {})
        with mock.patch.object(sc, 'request_apply') as asked:
            sc.after_saved(['lane.classic'], {'lane.classic': 5})
            asked.assert_called_once()

    def test_the_entrypoint_starts_each_lane_with_the_resolved_number(self):
        text = open(os.path.join(os.path.dirname(__file__), '..', 'celery-entrypoint.sh')).read()
        self.assertIn('lane_concurrency lane.cve_feed "${CVE_FEED_CONCURRENCY:-4}"', text)
        self.assertIn('lane_concurrency lane.classic "${CLASSIC_CONCURRENCY:-10}"', text)
        self.assertIn('generate_worker_command "cve_feed_queue" "$cve_feed_concurrency"', text)
        self.assertIn('generate_worker_command "$classic_queues" "$classic_concurrency"', text)
        row = AutoTuneSettings.current()
        row.values = {'lane.classic': 4}
        row.save()
        from io import StringIO
        buffer = StringIO()
        call_command('scan_concurrency_value', 'lane.classic', stdout=buffer)
        self.assertEqual(buffer.getvalue().strip(), '4')


class ShareGateTests(Isolated, TestCase):
    """The limit itself: while a scan waits, assessments hold at most their share of the discovery pool."""

    def setUp(self):
        super().setUp()
        from dashboard.models import Project
        from scanEngine.models import EngineType
        from startScan.models import ScanHistory
        from targetApp.models import Domain
        now = timezone.now()
        self.project = Project.objects.create(name='S', slug='share-proj', insert_date=now)
        self.domain = Domain.objects.create(name='share.example.com', project=self.project, insert_date=now)
        self.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x')
        self.ScanHistory = ScanHistory
        sc.update({'discovery_concurrency': 8, 'assess_batch': 1}, SimpleNamespace(username='root', pk=None, is_authenticated=True, is_superuser=True))

    def assessments(self, running):
        for i in range(running):
            HostAssessment.objects.create(project=self.project, domain=self.domain, host=f'h{i}.share.example.com', status='running', source='topup')

    def scan(self):
        self.ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, start_scan_date=timezone.now() - timedelta(hours=1), scan_status=-1)

    def test_the_limit_is_a_share_of_the_pool_of_at_least_one(self):
        self.assertEqual(host_assessment.share_limit(), 6)  # 75 percent of 8
        sc.update({'assess_share_percent': 25}, SimpleNamespace(username='root', pk=None, is_authenticated=True, is_superuser=True))
        self.assertEqual(host_assessment.share_limit(), 2)
        sc.update({'discovery_concurrency': 4, 'assess_share_percent': 10}, SimpleNamespace(username='root', pk=None, is_authenticated=True, is_superuser=True))
        self.assertEqual(host_assessment.share_limit(), 1)
        sc.update({'assess_share_percent': 100}, SimpleNamespace(username='root', pk=None, is_authenticated=True, is_superuser=True))
        self.assertIsNone(host_assessment.share_limit())

    def test_an_assessment_waits_only_while_a_scan_waits_and_the_share_is_held(self):
        self.assessments(6)
        self.assertFalse(host_assessment.over_share())  # six hold the share, but no scan waits: the whole pool is theirs
        self.scan()
        self.assertTrue(host_assessment.over_share())
        HostAssessment.objects.filter(status='running').first().delete()
        self.assertFalse(host_assessment.over_share())  # five are under the limit of six

    def test_a_batch_of_hosts_holds_one_slot_not_one_each(self):
        sc.update({'assess_batch': 8}, SimpleNamespace(username='root', pk=None, is_authenticated=True, is_superuser=True))
        self.assessments(16)  # two batches
        self.scan()
        self.assertEqual(host_assessment.slots_held(), 2)
        self.assertFalse(host_assessment.over_share())

    def test_the_task_looks_again_later_instead_of_starting_and_keeps_its_row_and_task_id(self):
        from cveFeed import tasks
        self.assessments(6)
        self.scan()
        job = HostAssessment.objects.create(project=self.project, domain=self.domain, host='waits.share.example.com', status='queued', source='topup')
        with mock.patch.object(host_assessment, 'execute') as execute, mock.patch.object(tasks.assess_host, 'apply_async') as again:
            out = tasks.assess_host.apply(args=[job.pk], task_id='abc').get()
        execute.assert_not_called()
        again.assert_called_once()
        self.assertEqual((again.call_args.kwargs['task_id'], again.call_args.kwargs['countdown'], again.call_args.kwargs['priority']),
                         ('abc', host_assessment.SHARE_DEFER_SECONDS, host_assessment.ASSESS_PRIORITY))
        self.assertEqual(out['status'], 'deferred')
        job.refresh_from_db()
        self.assertEqual(job.status, 'queued')

    def test_the_gate_never_stops_work_when_it_cannot_decide(self):
        with mock.patch.object(host_assessment, 'share_limit', side_effect=RuntimeError('down')):
            self.assertFalse(host_assessment.over_share())


class ClaimOutageTests(SentinelBase):
    """AM-5: tasks that expire unclaimed while the slots are free, or while the limiter refuses claims, are a claim outage, not Sentinel capacity trouble."""

    def holding(self, count):
        """``count`` tasks the live Sentinels hold now, so their slots are in use (``busy`` of the base class holds them with no Sentinel, which this signal does not count)."""
        agents = list(Agent.objects.filter(kind='scanner'))
        SentinelTask.objects.bulk_create([SentinelTask(project=self.proj, kind='nmap', target={}, status='running', agent=agents[i % len(agents)], claimed_at=timezone.now())
                                          for i in range(count)])

    def test_unclaimed_expiries_with_every_slot_idle_are_not_counted_as_waits_that_ran_locally(self):
        self.live()
        self.tasks(70, 'expired', WAIT, ago=timedelta(minutes=3))
        sample = signals.sentinels(timezone.now().timestamp())
        self.assertEqual((sample['claims_outage'], sample['fallbacks'], sample['unclaimed']), (True, 0, 70))
        samples = [merge(BASE, {'t': NOW - 600, 'sentinel': sample}), merge(BASE, {'t': NOW, 'sentinel': sample})]
        for setting in (policy.Setting('assess_batch', 'batch', 'b', 4, 32, 4, 'more', 16, 8), policy.Setting('stage_parallel', 'stage', 's', 2, 16, 1, 'more', 6, 4),
                        policy.Setting('sentinel_refresh_gap_hours', 'refresh_gap', 'r', 2, 24, 1, 'gap', 3, 6)):
            self.assertIsNone(policy.trouble(setting, samples), setting.key)  # no back-off of Sentinel work for a claim outage
            self.assertNotEqual(decide(setting, setting.high if setting.sense == 'more' else setting.low, setting.default, samples)['phase'], 'back_off')

    def test_the_same_expiries_with_the_slots_busy_still_count_as_capacity_trouble(self):
        self.live()
        self.holding(8)
        self.tasks(70, 'expired', WAIT, ago=timedelta(minutes=3))
        sample = signals.sentinels(timezone.now().timestamp())
        self.assertEqual((sample['claims_outage'], sample['fallbacks']), (False, 70))
        batch = policy.Setting('assess_batch', 'batch', 'b', 4, 32, 4, 'more', 16, 8)
        self.assertIn('timed out', policy.trouble(batch, [merge(BASE, {'t': NOW, 'sentinel': sample})]))

    def test_refusals_by_the_servers_limiter_are_an_outage_whatever_the_slots(self):
        self.live()
        self.holding(8)
        self.tasks(5, 'expired', WAIT, ago=timedelta(minutes=3))
        with mock.patch('agentapi.maintainer_signals.claim_refusals', return_value={'this_hour': 150, 'previous_hour': 20}):
            sample = signals.sentinels(timezone.now().timestamp())
        self.assertEqual((sample['claims_outage'], sample['fallbacks']), (True, 0))


class KindPauseTests(SentinelBase):
    def setUp(self):
        super().setUp()
        self.live(count=3)
        self.agents = [Agent.objects.get(name=f'sentinel-{i}') for i in (1, 2, 3)]

    def test_a_pause_is_a_deny_with_an_expiry_that_ends_by_itself(self):
        now = timezone.now()
        until = sentinel_policy.pause(self.agents[0], 'nmap', 2, 'failed three times', now=now)
        self.assertEqual(until, now + timedelta(hours=2))
        agent = Agent.objects.get(pk=self.agents[0].pk)
        got = sentinel_policy.resolve(agent)['nmap']
        self.assertEqual((got['mode'], got['source'], got['until']), ('deny', 'pause', until.isoformat()))
        self.assertIn('nmap', sentinel_policy.denied(agent))
        self.assertEqual(sentinel_policy.resolve(Agent.objects.get(pk=self.agents[1].pk))['nmap']['source'], 'default')  # only this Sentinel
        with mock.patch.object(sentinel_policy.timezone, 'now', return_value=until + timedelta(seconds=1)):
            self.assertEqual(sentinel_policy.resolve(agent)['nmap']['mode'], 'allow')  # nothing to clean up, nothing to forget
            self.assertEqual(sentinel_policy.active_pauses(agent), {})

    def test_the_range_is_one_to_six_hours_at_most_two_kinds_and_never_the_last_sentinel_of_a_kind(self):
        now = timezone.now()
        self.assertEqual(sentinel_policy.pause(self.agents[0], 'nmap', 99, 'x', now=now), now + timedelta(hours=6))
        self.assertEqual(sentinel_policy.pause(self.agents[0], 'hygiene_check', 0, 'x', now=now), now + timedelta(hours=1))
        with self.assertRaises(sentinel_policy.PauseRefused) as caught:
            sentinel_policy.pause(self.agents[1], 'waf', 2, 'x', now=now)
        self.assertIn('at most 2', str(caught.exception))
        sentinel_policy.pause(self.agents[1], 'nmap', 2, 'x', now=now)  # the same kind on a second Sentinel is not a third kind
        with self.assertRaises(sentinel_policy.PauseRefused) as caught:
            sentinel_policy.pause(self.agents[2], 'nmap', 2, 'x', now=now)  # it would be the last Sentinel that can run it
        self.assertIn('last one', str(caught.exception))
        self.assertTrue(sentinel_policy.lift(Agent.objects.get(pk=self.agents[1].pk), 'nmap'))
        with self.assertRaises(sentinel_policy.PauseRefused):
            sentinel_policy.pause(self.agents[0], 'not_a_kind', 2, 'x')

    def test_a_kind_that_fails_every_time_on_one_sentinel_is_paused_there_and_recorded(self):
        self.tasks(3, 'failed', 'boom', kind='nmap', ago=timedelta(minutes=20), agent='sentinel-1')
        self.tasks(5, 'done', kind='nmap', ago=timedelta(minutes=20), agent='sentinel-2')
        self.tasks(3, 'failed', 'boom', kind='hygiene_check', ago=timedelta(minutes=20), agent='sentinel-1')
        self.tasks(1, 'done', kind='hygiene_check', ago=timedelta(minutes=20), agent='sentinel-1')  # it finished one: not "every time"
        made = autotune.pause_failing_kinds('auto', timezone.now())
        self.assertEqual([(m['sentinel'], m['kind'], m['hours']) for m in made], [('sentinel-1', 'nmap', 2)])
        d = TuningDecision.objects.get(setting='sentinel_pause:nmap')
        self.assertEqual((d.action, d.phase, d.applied, d.new_value, d.source), ('pause', 'pause', True, 2, 'controller'))
        self.assertEqual(d.signals['sentinel'], 'sentinel-1')
        self.assertFalse(autotune.list_decisions('sentinel_pause:nmap')['results'][0]['can_revert'])
        self.assertTrue(__import__('dashboard.models', fromlist=['AuditLog']).AuditLog.objects.filter(action='autotune.pause').exists())
        self.assertEqual(autotune.pause_failing_kinds('auto', timezone.now()), [])  # already paused: not again
        self.assertEqual(autotune.pause_failing_kinds('suggest', timezone.now()), [])

    def test_after_the_pause_ends_the_old_failures_do_not_pause_it_again_but_three_new_ones_do_for_longer(self):
        self.tasks(3, 'failed', 'boom', kind='nmap', ago=timedelta(minutes=20), agent='sentinel-1')
        start = timezone.now()
        autotune.pause_failing_kinds('auto', start)
        later = start + timedelta(hours=2, minutes=5)
        self.assertEqual(autotune.pause_failing_kinds('auto', later), [])  # the same three failures
        SentinelTask.objects.bulk_create([SentinelTask(project=self.proj, kind='nmap', target={}, status='failed', error='boom', finished_at=later - timedelta(minutes=1),
                                                       agent=self.agents[0]) for _ in range(3)])
        made = autotune.pause_failing_kinds('auto', later)
        self.assertEqual([m['hours'] for m in made], [4])
