import os
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import changes, discovery, ledger, nuclei_scan, retest
from cveFeed.models import AssetChange, CVEEntry, CVEMatch, DeferredRetest, HostState, ServiceRun
from dashboard.models import ProjectMembership
from startScan.models import ScanActivity, ScanHistory, Subdomain
from tests.test_agentapi import call
from tests.test_changes import ChangeFixture
from tests.test_perf_hostpipeline import _stages

HOST = {'ip': '203.0.113.5', 'ports': [(443, 'https', 'nginx', '1.18.0')], 'techs': ['nginx']}


class RetestFixture(ChangeFixture):
	def setUp(self):
		super().setUp()
		self.delay = mock.patch('cveFeed.tasks.retest_hosts.delay').start()
		mock.patch('reNgine.tasks.geo_localize.delay').start()
		mock.patch('cveFeed.tasks.run_hygiene_task.delay').start()
		self.addCleanup(mock.patch.stopall)

	def change(self, scan, host, kind, before=None, after=None):
		return AssetChange.objects.create(project=self.project, domain=self.domain, scan=scan, host=host, kind=kind, before=before, after=after)


class HostsToRetestTests(RetestFixture, TestCase):
	def setUp(self):
		super().setUp()
		self.scan_ = self.scan({'a.ct.test': HOST})

	def hosts(self):
		return retest.hosts_to_retest(self.scan_)

	def test_a_version_bump_counts_and_a_product_only_change_does_not(self):
		self.change(self.scan_, 'a.ct.test', 'service_changed', {'port': '443/tcp', 'product': 'nginx', 'version': '1.18.0'},
			{'port': '443/tcp', 'product': 'nginx', 'version': '1.20.1'})
		self.change(self.scan_, 'b.ct.test', 'service_changed', {'port': '22/tcp', 'product': 'OpenSSH', 'version': '8.0'},
			{'port': '22/tcp', 'product': 'openssh-server', 'version': '8.0'})
		self.assertEqual(self.hosts(), ['a.ct.test'])

	def test_an_auth_change_counts_only_when_a_route_became_open(self):
		self.change(self.scan_, 'a.ct.test', 'auth_changed', {'auth_state': 'login', 'url': 'u'}, {'auth_state': 'open', 'url': 'u'})
		self.change(self.scan_, 'b.ct.test', 'auth_changed', {'auth_state': 'open', 'url': 'u'}, {'auth_state': 'login', 'url': 'u'})
		self.change(self.scan_, 'c.ct.test', 'auth_changed', {'auth_state': 'open', 'url': 'u'}, {'auth_state': 'open', 'url': 'u'})
		self.assertEqual(self.hosts(), ['a.ct.test'])

	def test_other_kinds_that_grow_exposure_count_and_closures_do_not(self):
		for host, kind in (('a.ct.test', 'host_new'), ('b.ct.test', 'port_opened'), ('c.ct.test', 'tech_added'), ('d.ct.test', 'zombie_host'),
				('e.ct.test', 'host_returned'), ('f.ct.test', 'port_closed'), ('g.ct.test', 'host_retired'), ('h.ct.test', 'cert_changed')):
			self.change(self.scan_, host, kind)
		self.assertEqual(sorted(self.hosts()), ['a.ct.test', 'b.ct.test', 'c.ct.test', 'd.ct.test', 'e.ct.test'])

	def test_changes_of_other_scans_are_ignored_and_hosts_are_deduplicated(self):
		other = self.scan({'z.ct.test': HOST})
		self.change(other, 'z.ct.test', 'host_new')
		self.change(self.scan_, 'a.ct.test', 'host_new')
		self.change(self.scan_, 'a.ct.test', 'port_opened')
		self.assertEqual(self.hosts(), ['a.ct.test'])

	def test_the_cap_keeps_the_highest_scores(self):
		for i, score in enumerate((10, 90, 50, 70, 30)):
			name = f'h{i}.ct.test'
			Subdomain.objects.create(name=name, target_domain=self.domain, scan_history=self.scan_, score=score)
			self.change(self.scan_, name, 'host_new')
		with mock.patch.dict(os.environ, {'CVENGINE_RETEST_MAX_HOSTS': '3'}):
			self.assertEqual(self.hosts(), ['h1.ct.test', 'h3.ct.test', 'h2.ct.test'])
		self.assertEqual(len(self.hosts()), 5)  # the default cap is 25

	def test_hosts_re_tested_inside_the_window_are_left_out(self):
		self.change(self.scan_, 'a.ct.test', 'host_new')
		self.change(self.scan_, 'b.ct.test', 'host_new')
		ledger.record(retest.RETEST_SERVICE, ['a.ct.test'], self.project)
		self.assertEqual(self.hosts(), ['b.ct.test'])


class QueueTests(RetestFixture, TestCase):
	def test_immediate_worker_consumption_does_not_get_requeued_by_publisher(self):
		scan = self.scan({'a.ct.test': HOST})
		self.change(scan, 'a.ct.test', 'host_new')
		def consume(_domain_id, _names, _scan_id, ids):
			self.assertEqual(list(DeferredRetest.objects.filter(pk__in=ids).values_list('status', flat=True)), ['dispatching'])
			DeferredRetest.objects.filter(pk__in=ids).update(status='done')
		self.delay.side_effect = consume
		self.assertEqual(retest.queue_retests(scan)['queued'], 1)
		self.assertEqual(DeferredRetest.objects.get().status, 'done')

	def test_capped_overflow_is_durable_and_drained_by_later_sweep(self):
		scan = self.scan({f'h{i}.ct.test': HOST for i in range(4)})
		for i in range(4):
			self.change(scan, f'h{i}.ct.test', 'host_new')
		with mock.patch.dict(os.environ, {'CVENGINE_RETEST_MAX_HOSTS': '2'}):
			self.assertEqual(retest.queue_retests(scan)['queued'], 2)
			self.assertEqual(DeferredRetest.objects.filter(status='pending').count(), 2)
			self.assertEqual(retest.dispatch_deferred_retests()['queued'], 2)
		self.assertEqual(DeferredRetest.objects.filter(status='queued').count(), 4)

	def test_new_evidence_on_same_host_queues_again_inside_legacy_ttl(self):
		first = self.scan({'a.ct.test': HOST})
		self.change(first, 'a.ct.test', 'service_changed', {'version': '1'}, {'version': '2'})
		self.assertEqual(retest.queue_retests(first)['queued'], 1)
		DeferredRetest.objects.update(status='done')
		second = self.scan({'a.ct.test': HOST})
		self.change(second, 'a.ct.test', 'service_changed', {'version': '2'}, {'version': '3'})
		self.assertEqual(retest.queue_retests(second)['queued'], 1)
		self.assertEqual(DeferredRetest.objects.filter(host='a.ct.test').count(), 2)

	def test_broker_failure_leaves_pending_row_for_retry(self):
		scan = self.scan({'a.ct.test': HOST})
		self.change(scan, 'a.ct.test', 'host_new')
		self.delay.side_effect = RuntimeError('broker down')
		self.assertEqual(retest.queue_retests(scan)['queued'], 0)
		self.assertEqual(DeferredRetest.objects.get().status, 'pending')
		self.assertFalse(ServiceRun.objects.filter(service='retest', status='done').exists())

	def test_expired_queued_claim_is_recovered_with_backoff(self):
		from datetime import timedelta
		scan = self.scan({'a.ct.test': HOST})
		self.change(scan, 'a.ct.test', 'host_new')
		self.assertEqual(retest.queue_retests(scan)['queued'], 1)
		DeferredRetest.objects.update(updated_at=timezone.now() - timedelta(hours=4))
		self.assertEqual(retest.dispatch_deferred_retests()['queued'], 0)
		row = DeferredRetest.objects.get()
		self.assertEqual(row.status, 'pending')
		self.assertGreater(row.next_attempt_at, timezone.now())
		DeferredRetest.objects.update(next_attempt_at=timezone.now() - timedelta(seconds=1))
		self.assertEqual(retest.dispatch_deferred_retests()['queued'], 1)

	def test_a_baseline_scan_queues_nothing(self):
		out = changes.record_scan_changes(self.baseline().id)
		self.assertTrue(out['baseline'])
		self.delay.assert_not_called()

	def test_a_full_scan_with_changes_queues_once_and_records_the_ledger_first(self):
		changes.record_scan_changes(self.baseline().id)
		second = self.scan({'a.ct.test': {**HOST, 'ports': [(443, 'https', 'nginx', '1.20.1')]},
			'b.ct.test': {'ip': '203.0.113.6', 'ports': [(22, 'ssh', 'OpenSSH', '8.0')]}, 'c.ct.test': {'ip': '203.0.113.7', 'ports': []}})
		changes.record_scan_changes(second.id, resolver=lambda names: {(n, 'x') for n in names})
		self.assertEqual(self.delay.call_args.args[:3], (self.domain.id, ['c.ct.test', 'a.ct.test'], second.id))
		self.assertEqual(len(self.delay.call_args.args[3]), 2)
		self.assertEqual(sorted(ServiceRun.objects.filter(service='retest', status='queued').values_list('asset', flat=True)),
			['a.ct.test', 'c.ct.test'])
		self.assertTrue(ServiceRun.objects.filter(service='retest').first().scan_id == second.id)
		from cveFeed.models import AgentActivity
		self.assertTrue(AgentActivity.objects.filter(kind='changes', message__startswith='Re-testing 2 changed host(s) of ct.test: c.ct.test, a.ct.test').exists())
		self.assertEqual(retest.queue_retests(second), {'queued': 0, 'reason': 'nothing changed'})  # the ledger stops a second queue
		self.assertEqual(self.delay.call_count, 1)

	def test_a_host_pipeline_scan_never_queues_a_retest(self):
		partial = self.scan({'a.ct.test': HOST}, tasks=[discovery.HOST_PIPELINE_TASK])
		self.change(partial, 'a.ct.test', 'host_new')
		self.assertEqual(retest.queue_retests(partial), {'queued': 0, 'reason': 'partial scan'})
		again = self.scan({'a.ct.test': HOST}, tasks=[discovery.HOST_PIPELINE_TASK, retest.RETEST_TASK])
		self.change(again, 'a.ct.test', 'host_new')
		self.assertEqual(retest.queue_retests(again)['queued'], 0)
		self.delay.assert_not_called()

	def test_a_failure_to_queue_never_fails_the_diff(self):
		changes.record_scan_changes(self.baseline().id)
		second = self.scan({'a.ct.test': HOST, 'c.ct.test': {'ip': '203.0.113.7', 'ports': []}})
		self.delay.side_effect = RuntimeError('broker down')
		out = changes.record_scan_changes(second.id, resolver=lambda names: {(n, 'x') for n in names})
		self.assertEqual(out['changes'], 1)


class EndToEndTests(RetestFixture, TestCase):
	def test_a_retest_run_is_marked_forces_the_cve_checks_and_never_queues_another(self):
		HostState.objects.create(project=self.project, domain=self.domain, host='known.ct.test', state={})  # not a baseline run
		_, kwargs = _stages()
		with mock.patch('cveFeed.nuclei_scan.run_cve_checks', wraps=nuclei_scan.run_cve_checks) as checks:
			out = discovery.run_host_pipeline(self.domain.id, ['www.ct.test'], retest=True, source_scan_id=7, **kwargs)
		scan = ScanHistory.objects.get(pk=out['scan_id'])
		self.assertEqual(scan.tasks, [discovery.HOST_PIPELINE_TASK, discovery.RETEST_TASK])
		self.assertEqual(checks.call_args.kwargs['force'], True)
		self.assertTrue(AssetChange.objects.filter(scan=scan, kind='host_new').exists())  # it did diff...
		self.delay.assert_not_called()  # ...and did not queue another
		from cveFeed.models import AgentActivity
		self.assertTrue(AgentActivity.objects.filter(message__startswith='Re-testing 1 changed host of ct.test (www.ct.test) after scan #7').exists())

	def test_a_plain_host_pipeline_does_not_force(self):
		_, kwargs = _stages()
		with mock.patch('cveFeed.nuclei_scan.run_cve_checks', wraps=nuclei_scan.run_cve_checks) as checks:
			out = discovery.run_host_pipeline(self.domain.id, ['www.ct.test'], **kwargs)
		self.assertEqual(checks.call_args.kwargs['force'], False)
		self.assertEqual(ScanHistory.objects.get(pk=out['scan_id']).tasks, [discovery.HOST_PIPELINE_TASK])

	def test_the_stop_flag_is_honoured_in_a_retest(self):
		_, kwargs = _stages()
		calls = iter([False, True])
		with mock.patch.object(discovery, 'stopped', side_effect=lambda scan_id: next(calls, True)):
			out = discovery.run_host_pipeline(self.domain.id, ['www.ct.test'], retest=True, **kwargs)
		self.assertEqual(out['status'], 'aborted')

	def test_run_cve_checks_ignores_a_fresh_ledger_row_only_when_forced(self):
		scan = self.scan({'www.ct.test': HOST})
		sub = Subdomain.objects.get(scan_history=scan)
		cve = CVEEntry.objects.create(cve_id='CVE-2099-9', kev=True, cvss=9.8, title='t', published_at=timezone.now())
		CVEMatch.objects.create(cve_entry=cve, subdomain=sub, confidence=0.9)
		ledger.record(nuclei_scan.cve_service('CVE-2099-9'), ['www.ct.test'], self.project)
		runner = mock.Mock(return_value={'results': []})
		nuclei_scan.run_cve_checks(scan, [sub], None, cve_runner=runner)
		runner.assert_not_called()  # tested yesterday: left out
		out = nuclei_scan.run_cve_checks(scan, [sub], None, cve_runner=runner, force=True)
		runner.assert_called_once()
		self.assertEqual((out['hosts'], out['not_tested']), (0, 1))  # no result is not successful coverage

	def test_the_scans_api_says_which_runs_are_retests(self):
		_, kwargs = _stages()
		discovery.run_host_pipeline(self.domain.id, ['www.ct.test'], retest=True, **kwargs)
		discovery.run_host_pipeline(self.domain.id, ['api.ct.test'], **kwargs)
		user = User.objects.create_user('retester', password='x')
		ProjectMembership.objects.create(user=user, project=self.project, role='user')
		_, token = create_token(user, 't')
		status, data = call(token, 'GET', '/api/v1/projects/pc/scans')
		self.assertEqual(status, 200)
		self.assertEqual(sorted(s['kind'] for s in data['results']), ['hosts', 'retest'])
