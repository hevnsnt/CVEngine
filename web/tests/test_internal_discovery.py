"""Finding the live hosts of a declared internal range: a Sentinel inside the network sweeps it and each answer becomes a target."""
from datetime import timedelta
from unittest import mock

from django.utils import timezone

from agentapi import sentinel_broker as sb
from agentapi.models import SentinelTask
from cveFeed import internal_discovery as idisc
from cveFeed.models import InternalRange
from targetApp.models import Domain
from tests.test_agentapi import call
from tests.test_internal_scan import Base


def answering(*hosts_by_chunk):
    """A dispatch that answers each ``discover`` call, in order, with the given IPs; ``None`` stands for no Sentinel answering."""
    queue, calls = list(hosts_by_chunk), []

    def dispatch(project, kind, target, **kwargs):
        calls.append((kind, target, kwargs))
        ips = queue.pop(0)
        return None if ips is None else {'hosts': [{'ip': ip, 'hostnames': []} for ip in ips]}
    dispatch.calls = calls
    return dispatch


class ChunkTests(Base):
    def test_a_range_is_swept_in_24s_and_ipv6_is_not_swept(self):
        self.assertEqual([str(n) for n in idisc.chunks('10.20.0.0/23')[0]], ['10.20.0.0/24', '10.20.1.0/24'])
        self.assertEqual(idisc.chunks('10.20.0.0/23')[1], 2)
        self.assertEqual([str(n) for n in idisc.chunks('10.20.0.64/26')[0]], ['10.20.0.64/26'])
        self.assertEqual(idisc.chunks('fd00::/112'), ([], 0))
        self.assertEqual([str(n) for n in idisc.chunks('10.20.0.0/22', start=1, limit=2)[0]], ['10.20.1.0/24', '10.20.2.0/24'])


class DiscoverTests(Base):
    def setUp(self):
        super().setUp()
        self.range = InternalRange.objects.get(project=self.pa, cidr='10.20.0.0/24')
        Domain.objects.all().delete()

    def run_with(self, dispatch):
        with mock.patch('cveFeed.internal_scan.sweep') as sweep:
            out = idisc.discover_range(self.range.pk, dispatch=dispatch)
        return out, sweep

    def test_answering_hosts_become_targets_and_are_not_discovered_from_here(self):
        dispatch = answering(['10.20.0.5', '10.20.0.9'])
        with mock.patch('agentapi.services._start_discoveries') as discover:
            out, sweep = self.run_with(dispatch)
            discover.assert_not_called()
        self.assertEqual((out['found'], out['created'], out['failed']), (2, 2, 0))
        self.assertEqual(sorted(Domain.objects.filter(project=self.pa).values_list('name', flat=True)), ['10.20.0.5', '10.20.0.9'])
        kind, target, kwargs = dispatch.calls[0]
        self.assertEqual((kind, target), ('discover', {'cidr': '10.20.0.0/24'}))
        self.assertTrue(kwargs['internal'])
        sweep.assert_called_once()  # the new targets are scanned without waiting for the next daily sweep
        self.range.refresh_from_db()
        self.assertIsNotNone(self.range.last_discovery_at)
        self.assertEqual((self.range.last_discovery_hosts, self.range.last_discovery_error), (2, ''))

    def test_an_address_outside_the_chunk_the_network_or_junk_is_dropped(self):
        out, _ = self.run_with(answering(['10.99.0.5', '10.20.0.0', '10.20.0.255', 'not-an-ip', '8.8.8.8', '10.20.0.7', '10.20.0.7']))
        self.assertEqual(out['found'], 1)
        self.assertEqual(list(Domain.objects.filter(project=self.pa).values_list('name', flat=True)), ['10.20.0.7'])

    def test_a_host_already_a_target_is_not_added_again_and_nothing_new_scans_nothing(self):
        Domain.objects.create(name='10.20.0.5', project=self.pa, insert_date=timezone.now())
        out, sweep = self.run_with(answering(['10.20.0.5']))
        self.assertEqual((out['found'], out['created']), (1, 0))
        self.assertEqual(Domain.objects.filter(project=self.pa).count(), 1)
        sweep.assert_not_called()

    def test_no_sentinel_answering_is_an_error_not_an_empty_network(self):
        out, sweep = self.run_with(answering(None))
        self.assertEqual((out['failed'], out['found'], out['created']), (1, 0, 0))
        self.range.refresh_from_db()
        self.assertIsNone(self.range.last_discovery_at)  # not swept: it is retried, never read as a clean network
        self.assertIn('no Sentinel inside the network answered', self.range.last_discovery_error)
        sweep.assert_not_called()

    def test_a_large_range_resumes_where_the_last_run_stopped(self):
        self.range.cidr = '10.20.0.0/22'
        self.range.save()
        with mock.patch.dict('os.environ', {'CVENGINE_INTERNAL_DISCOVERY_CHUNKS': '2'}):
            first, _ = self.run_with(answering(['10.20.0.5'], []))
            self.range.refresh_from_db()
            self.assertEqual((self.range.discovery_cursor, self.range.last_discovery_at), (2, None))
            second, _ = self.run_with(answering(['10.20.2.5'], []))
        self.range.refresh_from_db()
        self.assertEqual((first['chunks'], second['chunks']), (2, 2))
        self.assertEqual(self.range.discovery_cursor, 0)
        self.assertIsNotNone(self.range.last_discovery_at)
        self.assertEqual(sorted(Domain.objects.values_list('name', flat=True)), ['10.20.0.5', '10.20.2.5'])

    def test_a_failed_chunk_keeps_the_cursor_so_it_is_retried(self):
        self.range.cidr = '10.20.0.0/23'
        self.range.save()
        out, _ = self.run_with(answering(['10.20.0.5'], None))
        self.assertEqual((out['failed'], out['found']), (1, 1))
        self.range.refresh_from_db()
        self.assertEqual((self.range.discovery_cursor, self.range.last_discovery_at), (0, None))

    def test_an_ipv6_range_is_reported_not_swept(self):
        self.range.cidr = 'fd00::/112'
        self.range.save()
        dispatch = answering()
        out, _ = self.run_with(dispatch)
        self.assertIn('IPv6', out['error'])
        self.assertEqual(dispatch.calls, [])


class DueTests(Base):
    def test_a_range_is_due_only_with_a_live_internal_discover_sentinel_and_not_swept_inside_the_cadence(self):
        row = InternalRange.objects.get(project=self.pa, cidr='10.20.0.0/24')
        self.assertEqual(idisc.due_ranges(), [])  # no Sentinel
        self.sentinel('outside', ['discover'])
        self.assertEqual(idisc.due_ranges(), [])  # one outside the network cannot reach it
        self.sentinel('no-discover', ['nmap', 'network:internal'])
        self.assertEqual(idisc.due_ranges(), [])
        self.sentinel('inside', ['discover', 'network:internal'])
        self.assertEqual(idisc.due_ranges(), [row])
        InternalRange.objects.filter(pk=row.pk).update(last_discovery_at=timezone.now() - timedelta(days=2))
        self.assertEqual(idisc.due_ranges(), [])
        InternalRange.objects.filter(pk=row.pk).update(last_discovery_at=timezone.now() - timedelta(days=8))
        self.assertEqual(idisc.due_ranges(), [row])

    def test_sweep_queues_each_due_range(self):
        self.sentinel('inside', ['discover', 'network:internal'])
        with mock.patch('cveFeed.tasks.run_internal_discovery') as task, mock.patch('cveFeed.scan_control.pause_requested', return_value=False):
            self.assertEqual(idisc.sweep(), {'queued': 1})
            task.delay.assert_called_once()
        with mock.patch('cveFeed.tasks.run_internal_discovery') as task, mock.patch('cveFeed.scan_control.pause_requested', return_value=True):
            self.assertEqual(idisc.sweep()['queued'], 0)
            task.delay.assert_not_called()


class ResultAndRestTests(Base):
    def test_a_discover_report_is_cleaned(self):
        body = {'outcome': 'done', 'hosts': [{'ip': '10.20.0.5', 'hostnames': ['a.corp', 7, '']}, {'ip': '10.20.0.5'}, {'ip': 3}, 'x',
                                             {'ip': '10.20.0.6', 'extra': 'dropped'}]}
        out = sb.clean_result('discover', body)
        self.assertEqual(out['hosts'], [{'ip': '10.20.0.5', 'hostnames': ['a.corp']}, {'ip': '10.20.0.6', 'hostnames': []}])
        with self.assertRaises(sb.ApiError):
            sb.clean_result('discover', {'outcome': 'done', 'hosts': [{'ip': f'10.0.{i // 250}.{i % 250}'} for i in range(sb.MAX_DISCOVER_HOSTS + 1)]})

    def test_only_a_network_internal_sentinel_can_take_a_discover_task(self):
        from agentapi.models import Agent
        task = SentinelTask.objects.create(project=self.pa, kind='discover', target={'cidr': '10.20.0.0/24'}, ips=['10.20.0.0'])
        outside = sb.effective(Agent.objects.get(pk=self.sentinel('outside', ['discover'])))
        inside = sb.effective(Agent.objects.get(pk=self.sentinel('inside', ['discover', 'network:internal'])))
        self.assertEqual(outside.refusal(task), ('capability', 'network:internal'))
        self.assertIsNone(inside.refusal(task))

    def test_scan_now_queues_for_admins_with_a_sentinel_and_explains_a_refusal(self):
        row = InternalRange.objects.get(project=self.pa)
        url = f'/api/v1/projects/ir-a/internal-ranges/{row.pk}/discover'
        with mock.patch('cveFeed.tasks.run_internal_discovery') as task:
            status, out = call(self.t_admin(), 'POST', url)
            self.assertEqual(status, 409)
            self.assertIn('network:internal', out['error'])
            task.delay.assert_not_called()
            self.sentinel('inside', ['discover', 'network:internal'])
            status, out = call(self.t_admin(), 'POST', url)
            self.assertEqual((status, out), (202, {'queued': '10.20.0.0/24'}))
            task.delay.assert_called_once_with(row.pk)

    def t_admin(self):
        from agentapi.auth import create_token
        return create_token(self.admin, 'disc-admin')[1]

    def test_scan_now_is_for_administrators_of_that_project_only(self):
        from agentapi.auth import create_token
        row = InternalRange.objects.get(project=self.pa)
        url = f'/api/v1/projects/ir-a/internal-ranges/{row.pk}/discover'
        self.assertEqual(call(create_token(self.member, 'disc-member')[1], 'POST', url)[0], 403)
        self.assertEqual(call(create_token(self.other, 'disc-other')[1], 'POST', url)[0], 404)
        self.assertEqual(call(self.t_admin(), 'POST', f'/api/v1/projects/ir-a/internal-ranges/999999/discover')[0], 404)

    def test_the_range_listing_says_when_it_was_last_swept(self):
        row = InternalRange.objects.get(project=self.pa)
        InternalRange.objects.filter(pk=row.pk).update(last_discovery_at=timezone.now(), last_discovery_hosts=12, last_discovery_error='')
        out = call(self.t_admin(), 'GET', '/api/v1/projects/ir-a/internal-ranges')[1]['results'][0]
        self.assertEqual(out['last_discovery_hosts'], 12)
        self.assertTrue(out['last_discovery_at'])


class StatsTests(Base):
    def test_the_stats_networks_say_when_each_range_was_last_swept_and_what_stopped_it(self):
        from cveFeed import internal_view
        row = InternalRange.objects.get(project=self.pa)
        InternalRange.objects.filter(pk=row.pk).update(last_discovery_at=timezone.now(), last_discovery_hosts=9, last_discovery_error='no Sentinel answered')
        network = internal_view.summary()['networks'][0]
        self.assertEqual((network['last_discovery_hosts'], network['last_discovery_error']), (9, 'no Sentinel answered'))
        self.assertTrue(network['last_discovery_at'])

    def test_a_discover_task_has_its_own_completion_ceiling(self):
        from agentapi import sentinel_dispatch
        self.assertEqual(sentinel_dispatch._dispatch_timeout('discover'), 1200)
