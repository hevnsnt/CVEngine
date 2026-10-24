import datetime
import json
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import activity, changes, discovery
from cveFeed import hygiene as hy
from cveFeed.models import AgentActivity, AssetChange, HostState
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanActivity, ScanHistory, Subdomain, Technology
from targetApp.models import Domain
from tests.test_agentapi import call, rpc
from tests.test_hygiene import cert
from tests.test_perf_hostpipeline import _stages


def state(ports=None, techs=(), ip='203.0.113.5'):
	"""A snapshot with one IP; ports is {"443/tcp": (service, product, version)}."""
	return {'ips': {ip: {'ports': {k: {'service': v[0], 'product': v[1], 'version': v[2]} for k, v in (ports or {}).items()}}},
		'techs': sorted(techs)}


class DiffTests(SimpleTestCase):
	def kinds(self, before, after):
		return [(k, ip, port) for k, ip, port, _, _ in changes.diff_states(before, after)]

	def test_port_opened_and_closed(self):
		before = state({'443/tcp': ('https', 'nginx', '1.18.0')})
		after = state({'443/tcp': ('https', 'nginx', '1.18.0'), '8443/tcp': ('https', '', '')})
		self.assertEqual(self.kinds(before, after), [('port_opened', '203.0.113.5', 8443)])
		self.assertEqual(self.kinds(after, before), [('port_closed', '203.0.113.5', 8443)])

	def test_a_new_ip_opens_all_its_ports_and_a_lost_ip_closes_them(self):
		before = state({'443/tcp': ('https', '', '')})
		after = {'ips': {**before['ips'], '203.0.113.9': {'ports': {'22/tcp': {'service': 'ssh', 'product': '', 'version': ''},
			'80/tcp': {'service': 'http', 'product': '', 'version': ''}}}}, 'techs': []}
		self.assertEqual(self.kinds(before, after), [('port_opened', '203.0.113.9', 22), ('port_opened', '203.0.113.9', 80)])
		self.assertEqual(self.kinds(after, before), [('port_closed', '203.0.113.9', 22), ('port_closed', '203.0.113.9', 80)])

	def test_version_change_is_a_service_change_but_a_product_appearing_is_not(self):
		old = state({'443/tcp': ('https', 'nginx', '1.18.0')})
		new = state({'443/tcp': ('https', 'nginx', '1.20.1')})
		(kind, ip, port, was, now), = changes.diff_states(old, new)
		self.assertEqual((kind, port, was['version'], now['version']), ('service_changed', 443, '1.18.0', '1.20.1'))
		self.assertEqual(changes.diff_states(state({'443/tcp': ('https', '', '')}), new), [])  # nmap enrichment, not a change

	def test_technologies_added_and_removed(self):
		out = changes.diff_states(state(techs=['nginx', 'php']), state(techs=['nginx', 'wordpress']))
		self.assertEqual([(k, a or b) for k, _, _, b, a in out], [('tech_added', 'wordpress'), ('tech_removed', 'php')])

	def test_identical_states_have_no_changes_and_the_fingerprint_ignores_key_order(self):
		a = state({'443/tcp': ('https', 'nginx', '1')}, ['x'])
		self.assertEqual(changes.diff_states(a, json.loads(json.dumps(a))), [])
		self.assertEqual(changes.fingerprint({'a': 1, 'b': 2}), changes.fingerprint({'b': 2, 'a': 1}))
		self.assertNotEqual(changes.fingerprint({'a': 1}), changes.fingerprint({'a': 2}))


class ChangeFixture:
	def setUp(self):
		org = Org.objects.create(name='C', slug='c')
		self.project = Project.objects.create(name='P', slug='pc', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='ct.test', project=self.project, insert_date=timezone.now())
		self.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.ips = {}
		patcher = mock.patch('cveFeed.tasks.retest_hosts.delay')  # a diff may queue a re-test: never to a real broker
		self.retests = patcher.start()
		self.addCleanup(patcher.stop)

	def scan(self, hosts, tasks=None, status=2):
		"""A scan whose hosts are {name: {'ip': ..., 'ports': [(number, service, product, version)], 'techs': [...]}}.
		IP and Port rows are shared across scans and rewritten in place, as the real pipeline does."""
		scan = ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, start_scan_date=timezone.now(), scan_status=status,
			tasks=tasks or [], results_dir='x')
		for name, spec in hosts.items():
			sub = Subdomain.objects.create(name=name, target_domain=self.domain, scan_history=scan)
			ip = self.ips.get(spec['ip'])
			if ip is None:
				ip = self.ips[spec['ip']] = IpAddress.objects.create(address=spec['ip'])
			sub.ip_addresses.add(ip)
			for number, service, product, version in spec.get('ports', []):
				port = ip.ports.filter(number=number).first()
				if port is None:
					port = Port.objects.create(number=number)
					ip.ports.add(port)
				port.service_name, port.product, port.version, port.state = service, product, version, 'open'
				port.save()
			for tech in spec.get('techs', []):
				sub.technologies.add(Technology.objects.get_or_create(name=tech)[0])
		return scan

	def baseline(self):
		return self.scan({'a.ct.test': {'ip': '203.0.113.5', 'ports': [(443, 'https', 'nginx', '1.18.0')], 'techs': ['nginx']},
			'b.ct.test': {'ip': '203.0.113.6', 'ports': [(22, 'ssh', 'OpenSSH', '8.0')]}})


class RecordTests(ChangeFixture, TestCase):
	def test_the_first_scan_is_a_baseline_with_no_changes(self):
		scan = self.baseline()
		out = changes.record_scan_changes(scan.id)
		self.assertTrue(out['baseline'])
		self.assertEqual(AssetChange.objects.count(), 0)
		self.assertEqual(set(HostState.objects.values_list('host', flat=True)), {'a.ct.test', 'b.ct.test'})
		row = HostState.objects.get(host='a.ct.test')
		self.assertEqual(row.state['ips']['203.0.113.5']['ports']['443/tcp']['version'], '1.18.0')
		self.assertEqual(row.fingerprint, changes.fingerprint(row.state))
		self.assertTrue(AgentActivity.objects.filter(kind='changes', message__startswith='Baseline recorded for ct.test: 2 hosts').exists())

	def test_a_second_scan_records_exactly_what_changed(self):
		changes.record_scan_changes(self.baseline().id)
		second = self.scan({
			'a.ct.test': {'ip': '203.0.113.5', 'ports': [(443, 'https', 'nginx', '1.20.1'), (8443, 'https', '', '')], 'techs': ['nginx', 'php']},
			'b.ct.test': {'ip': '203.0.113.6', 'ports': [(22, 'ssh', 'OpenSSH', '8.0')]},
			'c.ct.test': {'ip': '203.0.113.7', 'ports': [(80, 'http', '', '')]}})
		out = changes.record_scan_changes(second.id, resolver=lambda names: {(n, '203.0.113.9') for n in names})
		got = sorted(AssetChange.objects.values_list('kind', 'host', 'port'), key=str)
		self.assertEqual(got, sorted([('host_new', 'c.ct.test', None), ('port_opened', 'a.ct.test', 8443),
			('service_changed', 'a.ct.test', 443), ('tech_added', 'a.ct.test', None)], key=str))
		self.assertEqual(out['changes'], 4)
		self.assertEqual(AssetChange.objects.get(kind='service_changed').after['version'], '1.20.1')
		self.assertEqual(AssetChange.objects.get(kind='port_opened').scan_id, second.id)
		self.assertEqual(HostState.objects.get(host='a.ct.test').state['ips']['203.0.113.5']['ports']['443/tcp']['version'], '1.20.1')
		self.assertTrue(HostState.objects.filter(host='c.ct.test').exists())
		self.assertTrue(AgentActivity.objects.filter(kind='changes', message__startswith='Changes for ct.test').exists())
		# the same scan state again: nothing new
		third = self.scan({'a.ct.test': {'ip': '203.0.113.5', 'ports': [(443, 'https', 'nginx', '1.20.1'), (8443, 'https', '', '')], 'techs': ['nginx', 'php']}})
		self.assertEqual(changes.record_scan_changes(third.id, resolver=lambda names: {(n, 'x') for n in names})['changes'], 0)

	def test_a_missing_host_that_no_longer_resolves_is_retired_and_one_that_still_resolves_is_not(self):
		changes.record_scan_changes(self.baseline().id)
		second = self.scan({'a.ct.test': {'ip': '203.0.113.5', 'ports': [(443, 'https', 'nginx', '1.18.0')], 'techs': ['nginx']}})
		asked = []

		def resolver(names):
			asked.append(list(names))
			return set()
		out = changes.record_scan_changes(second.id, resolver=resolver)
		self.assertEqual(asked, [['b.ct.test']])
		self.assertEqual(out['retired'], 1)
		self.assertEqual(AssetChange.objects.get(kind='host_retired').host, 'b.ct.test')
		self.assertIsNotNone(HostState.objects.get(host='b.ct.test').retired_at)
		self.assertIsNone(HostState.objects.get(host='a.ct.test').retired_at)

	def test_a_missing_host_that_still_resolves_stays(self):
		changes.record_scan_changes(self.baseline().id)
		second = self.scan({'a.ct.test': {'ip': '203.0.113.5', 'ports': [(443, 'https', 'nginx', '1.18.0')], 'techs': ['nginx']}})
		changes.record_scan_changes(second.id, resolver=lambda names: {(n, '203.0.113.6') for n in names})
		self.assertFalse(AssetChange.objects.filter(kind='host_retired').exists())
		self.assertIsNone(HostState.objects.get(host='b.ct.test').retired_at)

	def test_a_host_pipeline_scan_never_retires(self):
		changes.record_scan_changes(self.baseline().id)
		partial = self.scan({'a.ct.test': {'ip': '203.0.113.5', 'ports': [(443, 'https', 'nginx', '1.18.0')], 'techs': ['nginx']}},
			tasks=[discovery.HOST_PIPELINE_TASK])
		resolver = mock.Mock(return_value=set())
		out = changes.record_scan_changes(partial.id, resolver=resolver)
		resolver.assert_not_called()
		self.assertEqual(out['retired'], 0)
		self.assertFalse(AssetChange.objects.filter(kind='host_retired').exists())

	def test_a_retired_host_seen_again_returns(self):
		changes.record_scan_changes(self.baseline().id)
		second = self.scan({'a.ct.test': {'ip': '203.0.113.5', 'ports': [(443, 'https', 'nginx', '1.18.0')], 'techs': ['nginx']}})
		changes.record_scan_changes(second.id, resolver=lambda names: set())
		third = self.scan({'b.ct.test': {'ip': '203.0.113.6', 'ports': [(22, 'ssh', 'OpenSSH', '8.0')]},
			'a.ct.test': {'ip': '203.0.113.5', 'ports': [(443, 'https', 'nginx', '1.18.0')], 'techs': ['nginx']}})
		changes.record_scan_changes(third.id, resolver=lambda names: {(n, 'x') for n in names})
		self.assertEqual(AssetChange.objects.filter(kind='host_returned').count(), 1)
		self.assertIsNone(HostState.objects.get(host='b.ct.test').retired_at)

	def test_changes_are_capped_per_scan_and_flagged(self):
		changes.record_scan_changes(self.baseline().id)
		hosts = {f'n{i}.ct.test': {'ip': '203.0.113.20', 'ports': []} for i in range(12)}
		second = self.scan(hosts)
		with mock.patch.object(changes, 'MAX_CHANGES_PER_SCAN', 5):
			out = changes.record_scan_changes(second.id, resolver=lambda names: {(n, 'x') for n in names})
		self.assertTrue(out['truncated'])
		self.assertEqual(AssetChange.objects.count(), 5)


class StageTests(ChangeFixture, TestCase):
	def setUp(self):
		super().setUp()
		mock.patch('reNgine.tasks.geo_localize.delay').start()
		self.hygiene = mock.patch('cveFeed.tasks.run_hygiene_task.delay').start()
		self.addCleanup(mock.patch.stopall)

	def test_the_stage_is_recorded_and_a_second_run_reports_changes(self):
		_, kwargs = _stages()
		out = discovery.run_host_pipeline(self.domain.id, ['www.ct.test'], **kwargs)
		self.assertTrue(out['asset_changes']['baseline'])
		self.assertEqual(ScanActivity.objects.get(scan_of_id=out['scan_id'], name='asset_changes').status, discovery.SUCCESS)

	def test_a_failing_diff_is_recorded_without_failing_the_scan(self):
		_, kwargs = _stages()
		with mock.patch('cveFeed.changes.record_scan_changes', side_effect=RuntimeError('boom')):
			out = discovery.run_host_pipeline(self.domain.id, ['www.ct.test'], **kwargs)
		scan = ScanHistory.objects.get(pk=out['scan_id'])
		self.assertEqual((scan.scan_status, scan.error_message), (discovery.SUCCESS, 'Failed stages: asset_changes'))
		self.assertEqual(out['failed_stages'], ['asset_changes'])
		self.assertEqual(ScanActivity.objects.get(scan_of_id=out['scan_id'], name='asset_changes').status, discovery.FAILED)


class TriageStageTests(ChangeFixture, TestCase):
	"""The triage stage sits after the targeted nuclei pass and before the change log."""

	def setUp(self):
		super().setUp()
		mock.patch('reNgine.tasks.geo_localize.delay').start()
		mock.patch('cveFeed.tasks.run_hygiene_task.delay').start()
		self.addCleanup(mock.patch.stopall)

	def test_the_stage_comes_after_targeted_nuclei_and_before_the_change_log(self):
		_, kwargs = _stages()
		out = discovery.run_host_pipeline(self.domain.id, ['www.ct.test'], **kwargs)
		names = list(ScanActivity.objects.filter(scan_of_id=out['scan_id']).order_by('id').values_list('name', flat=True))
		self.assertEqual(names[-3:], ['nuclei_targeted_scan', 'triage', 'asset_changes'])
		self.assertEqual(ScanActivity.objects.get(scan_of_id=out['scan_id'], name='triage').status, discovery.SUCCESS)
		self.assertIn('triage', out)

	def test_a_triage_that_raises_marks_its_stage_failed_and_the_scan_records_it(self):
		_, kwargs = _stages()
		with mock.patch('cveFeed.triage.run_for_scan', side_effect=RuntimeError('boom')):
			out = discovery.run_host_pipeline(self.domain.id, ['www.ct.test'], **kwargs)
		scan = ScanHistory.objects.get(pk=out['scan_id'])
		self.assertEqual((scan.scan_status, scan.error_message), (discovery.SUCCESS, 'Failed stages: triage'))
		self.assertEqual(ScanActivity.objects.get(scan_of_id=out['scan_id'], name='triage').status, discovery.FAILED)
		self.assertEqual(ScanActivity.objects.get(scan_of_id=out['scan_id'], name='asset_changes').status, discovery.SUCCESS)

	def test_a_stop_before_the_stage_ends_the_pipeline_without_triage(self):
		_, kwargs = _stages()
		calls = []

		def stopped(scan_id):
			calls.append(1)
			return ScanActivity.objects.filter(scan_of_id=scan_id, name='nuclei_targeted_scan', status=discovery.SUCCESS).exists()
		with mock.patch.object(discovery, 'stopped', side_effect=stopped), mock.patch('cveFeed.triage.run_for_scan') as stage:
			out = discovery.run_host_pipeline(self.domain.id, ['www.ct.test'], **kwargs)
		self.assertEqual(out['status'], 'aborted')
		stage.assert_not_called()

	def test_validation_is_queued_per_project_for_what_the_scan_produced(self):
		from cveFeed.models import CVEEntry, CVEMatch
		from startScan.models import Subdomain
		_, kwargs = _stages()
		cve = CVEEntry.objects.create(cve_id='CVE-2099-9', published_at=timezone.now(),
									  affected=[{'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}])
		from cveFeed import triage as triage_module
		real_stage = triage_module.run_for_scan

		def seeded(scan_id, provider=False):
			sub = Subdomain.objects.filter(scan_history_id=scan_id).first()
			CVEMatch.objects.create(cve_entry=cve, subdomain=sub, matched_product='nginx', matched_version='1.18.0',
									version_in_range=True, source='port', evidence={'ip': '203.0.113.7', 'port': 80})
			return real_stage(scan_id, provider)
		with mock.patch('cveFeed.triage.run_for_scan', side_effect=seeded), mock.patch('cveFeed.tasks.validate_findings.delay') as delay:
			out = discovery.run_host_pipeline(self.domain.id, ['www.ct.test'], **kwargs)
		self.assertEqual(ScanActivity.objects.get(scan_of_id=out['scan_id'], name='triage').status, discovery.SUCCESS)
		self.assertEqual(delay.call_count, 1)
		project_id, ids, scan_id = delay.call_args[0]
		self.assertEqual((project_id, scan_id), (self.domain.project_id, out['scan_id']))


class CertChangeTests(TestCase):
	def setUp(self):
		self.project = Project.objects.create(name='H', slug='hc', insert_date=timezone.now(), org=Org.objects.create(name='H', slug='hh'))
		self.domain = Domain.objects.create(name='example.test', project=self.project, insert_date=timezone.now())
		Subdomain.objects.create(name='www.example.test', target_domain=self.domain)

	def run_with(self, issuer):
		def probe(host, port):
			if host != 'www.example.test':
				return None
			return {**cert(host=host, port=port, sans=[host], subject=host), 'issuer': issuer}
		return hy.run_hygiene(self.domain.id, probe=probe, emailer=lambda n: ([], False), mx=lambda n, t: False)

	def test_a_changed_certificate_is_one_change_and_the_first_sight_is_none(self):
		self.assertEqual(self.run_with('CN=Old CA')['cert_changes'], 0)
		self.assertFalse(AssetChange.objects.exists())
		self.assertEqual(self.run_with('CN=Old CA')['cert_changes'], 0)
		self.assertEqual(self.run_with('CN=New CA')['cert_changes'], 1)
		c = AssetChange.objects.get()
		self.assertEqual((c.kind, c.host, c.port, c.before['issuer'], c.after['issuer']), ('cert_changed', 'www.example.test', 443, 'CN=Old CA', 'CN=New CA'))


class ApiTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		org1, org2 = Org.objects.create(name='One', slug='co1'), Org.objects.create(name='Two', slug='co2')
		cls.pa = Project.objects.create(name='A', slug='proj-a', insert_date=now, org=org1)
		cls.pb = Project.objects.create(name='B', slug='proj-b', insert_date=now, org=org2)
		cls.da = Domain.objects.create(name='a.example', project=cls.pa, insert_date=now)
		cls.db = Domain.objects.create(name='b.example', project=cls.pb, insert_date=now)
		alice, bob = User.objects.create_user('calice', password='x'), User.objects.create_user('cbob', password='x')
		ProjectMembership.objects.create(user=alice, project=cls.pa, role='user')
		ProjectMembership.objects.create(user=bob, project=cls.pb, role='user')
		_, cls.t_alice = create_token(alice, 'a')
		_, cls.t_bob = create_token(bob, 'b')
		AssetChange.objects.create(project=cls.pa, domain=cls.da, host='www.a.example', kind='port_opened', ip='203.0.113.5', port=8443,
			after={'port': '8443/tcp', 'product': '', 'version': ''})
		AssetChange.objects.create(project=cls.pa, domain=cls.da, host='old.a.example', kind='host_retired',
			detected_at=now - datetime.timedelta(days=30))
		AssetChange.objects.create(project=cls.pb, domain=cls.db, host='www.b.example', kind='host_new')

	def test_changes_are_project_scoped_and_default_to_the_last_seven_days(self):
		status, data = call(self.t_alice, 'GET', '/api/v1/projects/proj-a/changes?since=7d')
		self.assertEqual(status, 200)
		self.assertEqual([c['host'] for c in data['results']], ['www.a.example'])
		self.assertEqual(data['results'][0]['target'], 'a.example')
		self.assertEqual(call(self.t_alice, 'GET', '/api/v1/projects/proj-a/changes')[1]['count'], 1)
		self.assertEqual(call(self.t_alice, 'GET', '/api/v1/projects/proj-a/changes?since=60d')[1]['count'], 2)

	def test_filters_and_validation(self):
		status, data = call(self.t_alice, 'GET', '/api/v1/projects/proj-a/changes?since=60d&kind=host_retired')
		self.assertEqual([c['host'] for c in data['results']], ['old.a.example'])
		self.assertEqual(call(self.t_alice, 'GET', '/api/v1/projects/proj-a/changes?kind=bogus')[0], 400)
		self.assertEqual(call(self.t_alice, 'GET', '/api/v1/projects/proj-a/changes?since=garbage')[0], 400)
		self.assertEqual(call(self.t_alice, 'GET', '/api/v1/projects/proj-a/changes?since=2020-01-01T00:00:00Z')[1]['count'], 2)
		self.assertEqual(call(self.t_alice, 'GET', '/api/v1/projects/proj-a/changes?host=WWW')[1]['count'], 1)

	def test_another_project_is_not_visible(self):
		self.assertEqual(call(self.t_bob, 'GET', '/api/v1/projects/proj-a/changes')[0], 404)
		self.assertEqual(call(self.t_bob, 'GET', '/api/v1/projects/proj-b/changes')[1]['results'][0]['host'], 'www.b.example')

	def test_mcp_tool(self):
		status, data = rpc(self.t_alice, 'tools/call', {'name': 'list_changes', 'arguments': {'project': 'proj-a', 'since': '24h'}})
		self.assertEqual(status, 200)
		self.assertFalse(data['result']['isError'])
		self.assertEqual(json.loads(data['result']['content'][0]['text'])['count'], 1)

	def test_prune_deletes_only_old_rows(self):
		from cveFeed.tasks import prune_asset_changes
		AssetChange.objects.filter(host='old.a.example').update(detected_at=timezone.now() - datetime.timedelta(days=91))
		self.assertEqual(prune_asset_changes()['deleted'], 1)
		self.assertEqual(set(AssetChange.objects.values_list('host', flat=True)), {'www.a.example', 'www.b.example'})
		with mock.patch.dict('os.environ', {'CVENGINE_CHANGES_RETENTION_DAYS': '0'}):  # clamped to one day: fresh rows stay
			self.assertEqual(prune_asset_changes()['deleted'], 0)
