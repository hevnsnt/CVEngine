"""Why a kind has nowhere to go, said truthfully (``sentinel_broker.explain_none``): a live, enabled Sentinel that has the kind and simply has no free slot is
``busy`` (back-pressure, never "does not have it"); ``never`` is only for a kind no covered Sentinel lists, and then names what the live ones do offer. Work that
only waited for a slot is shown as ``waiting`` (amber), never as a failed line or a failure count, and one plain sentence says when everything is saturated."""
from datetime import timedelta
from unittest import mock

from django.utils import timezone

from agentapi import sentinel_broker as sb
from agentapi import sentinel_dispatch as dispatch
from agentapi.models import Agent, SentinelTask
from cveFeed import activity, reviewer
from cveFeed.models import AgentActivity
from reNgine import resources
from tests.test_reviewer import Fixture
from tests.test_sentinel_capability_policy import PolicyBase


class ExplainNoneTests(PolicyBase):
    def hold(self, agent, n, kind='nmap'):
        for _ in range(n):
            SentinelTask.objects.create(project=self.project, kind=kind, target={'addresses': ['192.0.2.10']}, ips=['192.0.2.10'], agent=agent, status='running')

    def test_a_live_enabled_sentinel_with_the_kind_and_no_free_slot_is_busy_not_never(self):
        a = self.external('johnny', caps=('bbot_discovery', 'dns_resolve'), max_concurrent=2)
        self.hold(a, 2)
        answer = sb.explain_none(self.project, 'bbot_discovery')
        self.assertEqual(answer['reason'], 'busy')
        self.assertTrue(answer['waiting'])
        self.assertNotIn('does not have', answer['message'])
        self.assertNotIn('no Sentinel that covers', answer['message'])
        self.assertIn('every Sentinel that can run', answer['message'])
        self.assertIn('johnny 2 of 2', answer['message'])  # an administrator's reading names the load
        self.assertIn('this waits its turn and is asked again', answer['message'])

    def test_the_public_sentence_names_no_sentinel(self):
        a = self.external('johnny-secret-name', caps=('bbot_discovery',), max_concurrent=1)
        self.hold(a, 1)
        answer = sb.explain_none(self.project, 'bbot_discovery')
        self.assertNotIn('johnny-secret-name', answer['public'])
        self.assertIn('is busy right now; this waits its turn', answer['public'])

    def test_a_per_kind_cap_reached_is_busy(self):
        a = self.external('johnny', caps=('bbot_discovery', 'nmap'), max_concurrent=5)
        self.manage(a, {'kinds': {'bbot_discovery': {'mode': 'allow', 'max_concurrent': 1}}})
        self.hold(a, 1, kind='bbot_discovery')
        answer = sb.explain_none(self.project, 'bbot_discovery')
        self.assertEqual((answer['reason'], answer['waiting']), ('busy', True))

    def test_a_task_that_expired_in_the_queue_with_a_free_live_sentinel_is_still_not_never(self):
        a = self.external('johnny', caps=('bbot_discovery',), max_concurrent=5)  # slots free, nothing held: the kind is there, the answer is not "does not have it"
        answer = sb.explain_none(self.project, 'bbot_discovery')
        self.assertEqual(answer['reason'], 'busy')
        self.assertNotEqual(answer['reason'], 'never')

    def test_never_only_when_no_covered_sentinel_lists_the_kind_and_it_names_what_is_offered(self):
        self.external('johnny', caps=('nmap', 'dns_resolve'))
        answer = sb.explain_none(self.project, 'bbot_discovery')
        self.assertEqual((answer['reason'], answer['waiting']), ('never', False))
        self.assertIn('no Sentinel that covers this lists', answer['message'])
        self.assertIn('they offer', answer['message'])
        self.assertIn('nmap', answer['message'])

    def test_the_hard_reasons_come_before_busy(self):
        busy = self.external('busy-one', caps=('bbot_discovery',), max_concurrent=1)
        self.hold(busy, 1, kind='bbot_discovery')
        off = self.external('off-one', caps=('bbot_discovery',))
        Agent.objects.filter(pk=off.pk).update(last_seen=timezone.now() - timedelta(hours=1))
        answer = sb.explain_none(self.project, 'bbot_discovery')
        self.assertEqual(answer['reason'], 'offline')
        self.assertLess(sb.NONE_REASONS.index('offline'), sb.NONE_REASONS.index('busy'))
        self.assertLess(sb.NONE_REASONS.index('busy'), sb.NONE_REASONS.index('never'))

    def test_work_that_only_the_builtin_scanner_may_take_is_not_said_to_be_missing_on_a_sentinel_that_has_the_kind(self):
        self.external('johnny', caps=('bbot_discovery',))
        answer = sb.explain_none(self.project, 'bbot_discovery', builtin_only=True)
        self.assertEqual((answer['reason'], answer['waiting']), ('builtin', False))
        self.assertIn('only the built-in scanner', answer['message'])
        self.assertNotIn('no Sentinel that covers', answer['message'])


class WaitingIsNotFailureTests(PolicyBase):
    def test_a_busy_none_raises_a_waiting_scanner_unavailable_without_names(self):
        a = self.external('johnny-secret-name', caps=('nmap',), max_concurrent=1)
        SentinelTask.objects.create(project=self.project, kind='nmap', target={}, agent=a, status='running')
        with mock.patch.object(sb, 'capacity_state', return_value={'state': 'none', **sb.explain_none(self.project, 'nmap')}):
            with self.assertRaises(resources.ScannerUnavailable) as raised:
                dispatch._no_scanner('nmap', self.project)
        self.assertTrue(raised.exception.waiting)
        self.assertNotIn('johnny-secret-name', str(raised.exception))

    def test_a_missing_scanner_is_not_waiting(self):
        with self.assertRaises(resources.ScannerUnavailable) as raised:
            dispatch._no_scanner('nmap', self.project)
        self.assertFalse(raised.exception.waiting)

    def test_a_settled_waiting_line_is_one_line_with_a_count_per_scan(self):
        first = activity.log('run_check', 'x', project=self.project, status='running', scan_id=7)
        activity.settle_waiting(first, 'nmap work for example.test is waiting for a free Sentinel slot', scan_id=7)
        second = activity.log('run_check', 'y', project=self.project, status='running', scan_id=7)
        activity.settle_waiting(second, 'nmap work for example.test is waiting for a free Sentinel slot', scan_id=7)
        rows = AgentActivity.objects.filter(status='waiting')
        self.assertEqual((rows.count(), rows.get().repeat), (1, 2))
        other = activity.log('run_check', 'z', project=self.project, status='running', scan_id=8)
        activity.settle_waiting(other, 'nmap work for example.test is waiting for a free Sentinel slot', scan_id=8)
        self.assertEqual(AgentActivity.objects.filter(status='waiting').count(), 2)  # another scan keeps its own line
        self.assertFalse(AgentActivity.objects.filter(status='failed').exists())


class BacklogTests(PolicyBase):
    def test_no_note_while_a_slot_is_free_or_the_queue_is_short(self):
        a = self.external('johnny', caps=('nmap',), max_concurrent=1)
        for _ in range(sb.BACKLOG_MIN):
            SentinelTask.objects.create(project=self.project, kind='nmap', target={}, status='queued')
        self.assertIsNone(sb.backlog())  # a slot is free
        SentinelTask.objects.create(project=self.project, kind='nmap', target={}, agent=a, status='running')
        self.assertIsNotNone(sb.backlog())
        SentinelTask.objects.filter(status='queued').delete()
        self.assertIsNone(sb.backlog())  # saturated, but nothing waits

    def test_the_note_is_one_plain_sentence_with_the_numbers_and_no_name(self):
        a = self.external('johnny-secret-name', caps=('nmap',), max_concurrent=1)
        SentinelTask.objects.create(project=self.project, kind='nmap', target={}, agent=a, status='running')
        for _ in range(1300):
            SentinelTask.objects.create(project=self.project, kind='nmap', target={}, status='queued')
        note = sb.backlog()
        self.assertEqual(note['message'], 'Your Sentinels are all busy: 1,300 checks are waiting. They are working through them.')
        self.assertNotIn('johnny', note['message'])
        self.assertEqual((note['queued'], note['slots']), (1300, 1))


class DiscoveryLineTests(PolicyBase):
    """``run_discovery`` keeps the scan's record (waiting for a scanner, still due) but the activity line says what happened."""

    def make_scan(self):
        from cveFeed import discovery
        from dashboard.models import Org  # noqa: F401
        from scanEngine.models import EngineType
        from targetApp.models import Domain
        EngineType.objects.get_or_create(engine_name='e', defaults={'yaml_configuration': 'x', 'default_engine': True})
        domain = Domain.objects.filter(project=self.project).first() or Domain.objects.create(name='example.test', project=self.project, insert_date=timezone.now())
        with mock.patch('cveFeed.tasks.run_bbot_discovery.delay'):
            return discovery.start_discovery(domain)

    def run_with(self, error):
        from cveFeed import discovery
        scan = self.make_scan()
        with mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False), mock.patch('reNgine.tasks.geo_localize.delay'), \
                mock.patch('cveFeed.tasks.correlate_cves.delay'), mock.patch('agentapi.sentinel_stream.dispatch_stream', side_effect=error):
            out = discovery.run_discovery(scan.id)
        return out, AgentActivity.objects.filter(kind='discovery', message__contains='Discovery of ').order_by('-id')

    def test_a_discovery_that_only_waited_for_a_slot_is_a_waiting_line_not_a_failed_one(self):
        out, lines = self.run_with(resources.ScannerUnavailable('bbot_discovery', 'every Sentinel that can run bbot discovery is busy right now', waiting=True))
        self.assertIn('waiting for a scanner', out['error'])  # the scan record is unchanged: the target stays due and is queued again
        line = lines.get()
        self.assertEqual(line.status, 'waiting')
        self.assertIn('is waiting for a free Sentinel', line.message)
        self.assertNotIn('failed', line.message)
        self.assertFalse(AgentActivity.objects.filter(status='failed').exists())

    def test_a_missing_scanner_and_a_real_failure_stay_red(self):
        for error in (resources.ScannerUnavailable('bbot_discovery', 'bbot discovery is not enabled on any live Sentinel (off on johnny)'), RuntimeError('boom')):
            with self.subTest(error=type(error).__name__):
                AgentActivity.objects.all().delete()
                out, lines = self.run_with(error)
                self.assertEqual(lines.get().status, 'failed')
                self.assertIn('failed:', lines.get().message)


class ReviewerCountsTests(Fixture):
    def check(self, code):
        return {c['code']: c for c in reviewer.ops_checks()}.get(code)

    def test_waiting_lines_are_not_a_scan_error_and_failed_ones_still_are(self):
        for n in range(30):
            AgentActivity.objects.create(kind='discovery', message=f'Discovery of h{n}.example.test is waiting for a free Sentinel', status='waiting', project=self.proj)
        self.assertEqual(self.check('scan_errors')['state'], 'ok')
        for n in range(30):
            AgentActivity.objects.create(kind='discovery', message=f'Discovery of f{n}.example.test failed: boom', status='failed', project=self.proj)
        self.assertEqual(self.check('scan_errors')['state'], 'problem')
