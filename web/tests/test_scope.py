"""Scope: a tenant on a shared provider domain (acme.jfrog.com) is scanned as that host, never as the provider's apex."""
import importlib
from unittest import mock

from django.apps import apps as django_apps
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import discovery, ctmonitor, tasks
from dashboard.models import Org, Project
from reNgine import bbot as bbot_lib
from reNgine import resources
from scanEngine.models import EngineType
from startScan.models import ScanHistory
from targetApp.models import Domain
from targetApp.shared_domains import SHARED_DOMAINS, effective_apex, is_provider_domain, is_shared_apex

MARKER = 'Added for the weekly deep discovery of its subdomains'


class EffectiveApexTests(SimpleTestCase):
	def test_a_tenant_on_a_shared_domain_is_host_scoped(self):
		self.assertEqual(effective_apex('acme.jfrog.com'), ('acme.jfrog.com', True))
		self.assertEqual(effective_apex('acme.atlassian.net'), ('acme.atlassian.net', True))
		self.assertEqual(effective_apex('Acme.GitHub.io.'), ('acme.github.io', True))

	def test_a_deep_tenant_name_and_regional_s3_hosts_are_host_scoped(self):
		self.assertEqual(effective_apex('a.b.acme.jfrog.com'), ('a.b.acme.jfrog.com', True))
		self.assertEqual(effective_apex('bucket.s3.us-east-1.amazonaws.com'), ('bucket.s3.us-east-1.amazonaws.com', True))
		self.assertEqual(effective_apex('x.blob.core.windows.net'), ('x.blob.core.windows.net', True))

	def test_an_owned_subdomain_promotes_to_its_apex(self):
		self.assertEqual(effective_apex('hr.clouds.acme-example.ai'), ('acme-example.ai', False))
		self.assertEqual(effective_apex('www.example.co.uk'), ('example.co.uk', False))

	def test_an_owned_apex_is_its_own_scope_and_promotable(self):
		self.assertEqual(effective_apex('acme-example.ai'), ('acme-example.ai', False))

	def test_a_shared_apex_added_directly_is_host_scoped_and_never_promoted(self):
		self.assertEqual(effective_apex('jfrog.com'), ('jfrog.com', True))
		self.assertTrue(is_provider_domain('jfrog.com'))
		self.assertFalse(is_provider_domain('acme.jfrog.com'))

	def test_ips_and_junk_have_no_scope(self):
		for value in ('203.0.113.5', '10.0.0.0/24', '1.1.1.1-9', 'com', '', None, 'not a domain'):
			self.assertEqual(effective_apex(value), (None, False), value)

	def test_the_list_holds_the_providers_that_motivated_it(self):
		for name in ('jfrog.com', 'atlassian.net', 'herokuapp.com', 'github.io', 'cloudfront.net', 'azurewebsites.net', 'okta.com'):
			self.assertIn(name, SHARED_DOMAINS)
			self.assertTrue(is_shared_apex(name))
		self.assertFalse(is_shared_apex('acme-example.ai'))


class IsHostScopedTests(SimpleTestCase):
	def test_scope_mode_overrides_the_list(self):
		self.assertTrue(Domain(name='acme.jfrog.com').is_host_scoped())
		self.assertFalse(Domain(name='acme.jfrog.com', scope_mode='parent').is_host_scoped())
		self.assertTrue(Domain(name='hr.acme-example.ai', scope_mode='host').is_host_scoped())
		self.assertFalse(Domain(name='hr.acme-example.ai').is_host_scoped())
		self.assertFalse(Domain(name='203.0.113.5').is_host_scoped())


def _clear_claim():
	client = getattr(resources.get_store(), 'r', None)
	if client is not None:
		client.delete('cvengine:sweep:deep-apex')


class ApexSweepScopeTests(TestCase):
	def setUp(self):
		_clear_claim()
		self.addCleanup(_clear_claim)
		org = Org.objects.create(name='S', slug='scp')
		self.p1 = Project.objects.create(name='P1', slug='scp1', insert_date=timezone.now(), org=org)
		EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		patch = mock.patch('cveFeed.tasks.run_bbot_discovery.delay')
		patch.start()
		self.addCleanup(patch.stop)

	def _domain(self, name, **kw):
		return Domain.objects.create(name=name, project=self.p1, insert_date=timezone.now(), **kw)

	def _queued(self):
		return {s.domain.name for s in ScanHistory.objects.filter(scan_status=discovery.QUEUED)}

	def test_a_tenant_on_a_shared_domain_never_creates_or_scans_the_provider_apex(self):
		self._domain('acme.jfrog.com')
		self._domain('acme.atlassian.net')
		out = tasks.deep_scan_apexes()
		self.assertEqual(out['queued'], 0)
		self.assertFalse(Domain.objects.filter(name__in=['jfrog.com', 'atlassian.net']).exists())
		self.assertEqual(self._queued(), set())

	def test_an_owned_subdomain_still_promotes_its_apex(self):
		self._domain('hr.clouds.acme-example.ai')
		tasks.deep_scan_apexes()
		self.assertTrue(Domain.objects.filter(name='acme-example.ai').exists())
		self.assertEqual(self._queued(), {'acme-example.ai'})

	def test_a_shared_domain_added_directly_is_not_swept(self):
		self._domain('jfrog.com', description='mine')
		tasks.deep_scan_apexes()
		self.assertEqual(self._queued(), set())

	def test_host_mode_stops_promotion_of_an_owned_name(self):
		self._domain('hr.acme-example.ai', scope_mode='host')
		tasks.deep_scan_apexes()
		self.assertFalse(Domain.objects.filter(name='acme-example.ai').exists())
		self.assertEqual(self._queued(), set())

	def test_parent_mode_forces_promotion_even_on_the_shared_list(self):
		self._domain('acme.jfrog.com', scope_mode='parent')
		tasks.deep_scan_apexes()
		self.assertEqual(self._queued(), {'jfrog.com'})
		self.assertTrue(Domain.objects.filter(name='jfrog.com').exists())

	def test_an_apex_owned_by_another_project_is_still_skipped(self):
		other = Project.objects.create(name='P2', slug='scp2', insert_date=timezone.now(), org=self.p1.org)
		Domain.objects.create(name='acme-example.ai', project=other, insert_date=timezone.now())
		self._domain('hr.acme-example.ai')
		out = tasks.deep_scan_apexes()
		self.assertEqual(out['skipped'], 1)
		self.assertEqual(Domain.objects.filter(name='acme-example.ai').count(), 1)


class StrictScopeTests(TestCase):
	def test_the_command_carries_strict_scope_only_when_asked(self):
		self.assertIn('--strict-scope', bbot_lib.build_command(['acme.jfrog.com'], strict_scope=True))
		self.assertNotIn('--strict-scope', bbot_lib.build_command(['acme-example.ai']))

	def test_discovery_of_a_host_scoped_target_runs_bbot_strict(self):
		org = Org.objects.create(name='S2', slug='scp3')
		project = Project.objects.create(name='P3', slug='scp3', insert_date=timezone.now(), org=org)
		engine = EngineType.objects.create(engine_name='e2', yaml_configuration='x', default_engine=True)
		seen = {}

		def stream(targets, **kwargs):
			seen[targets[0]] = kwargs.get('strict_scope')
			return iter([])
		for name in ('acme.jfrog.com', 'acme-example.ai'):
			domain = Domain.objects.create(name=name, project=project, insert_date=timezone.now())
			scan = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=timezone.now(),
				scan_status=discovery.QUEUED, results_dir='/tmp')
			with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.correlate_cves.delay'):
				discovery.run_discovery(scan.id, stream=stream)
		self.assertEqual(seen, {'acme.jfrog.com': True, 'acme-example.ai': False})


class CertificateTransparencyScopeTests(TestCase):
	def test_a_bare_provider_domain_is_never_queried(self):
		with mock.patch.object(ctmonitor.requests, 'get') as get:
			self.assertEqual(ctmonitor.fetch_ct_names('jfrog.com'), set())
		get.assert_not_called()

	def test_a_tenant_host_is_queried_for_its_own_tree(self):
		resp = mock.Mock(status_code=200)
		resp.json.return_value = [{'name_value': 'acme.jfrog.com\nother.jfrog.com\napi.acme.jfrog.com'}]
		with mock.patch.object(ctmonitor.requests, 'get', return_value=resp) as get, \
				mock.patch.object(ctmonitor, 'reserve_slot', return_value=0), mock.patch.object(ctmonitor.time, 'sleep'):
			names = ctmonitor.fetch_ct_names('acme.jfrog.com')
		self.assertEqual(get.call_args.kwargs['params']['q'], '%.acme.jfrog.com')
		self.assertEqual(names, {'acme.jfrog.com', 'api.acme.jfrog.com'})

	def test_the_sweep_leaves_provider_domains_out(self):
		org = Org.objects.create(name='S4', slug='scp4')
		project = Project.objects.create(name='P4', slug='scp4', insert_date=timezone.now(), org=org)
		for name in ('jfrog.com', 'acme.jfrog.com', 'acme-example.ai'):
			Domain.objects.create(name=name, project=project, insert_date=timezone.now())
		client = getattr(resources.get_store(), 'r', None)
		if client is not None:
			client.delete('cvengine:sweep:ct-watch')
		self.addCleanup(lambda: client.delete('cvengine:sweep:ct-watch') if client is not None else None)
		queued = []
		with mock.patch('cveFeed.tasks.watch_certificate_transparency.apply_async', side_effect=lambda args, countdown: queued.append(args[0])):
			tasks.watch_certificates_all()
		names = set(Domain.objects.filter(id__in=queued).values_list('name', flat=True))
		self.assertEqual(names, {'acme.jfrog.com', 'acme-example.ai'})


class DataMigrationTests(TestCase):
	def setUp(self):
		org = Org.objects.create(name='S5', slug='scp5')
		self.project = Project.objects.create(name='P5', slug='scp5', insert_date=timezone.now(), org=org)
		self.migration = importlib.import_module('targetApp.migrations.0003_remove_shared_provider_apexes')

	def _domain(self, name, description=None):
		return Domain.objects.create(name=name, project=self.project, insert_date=timezone.now(), description=description)

	def test_removes_the_auto_created_apex_and_host_scopes_a_user_added_one(self):
		self._domain('jfrog.com', MARKER)
		self._domain('atlassian.net', MARKER)
		self._domain('github.io', 'my pages')
		self._domain('herokuapp.com')  # empty description: user added
		self._domain('acme.jfrog.com')
		self._domain('acme-example.ai', MARKER)  # not a shared domain: the sweep's apex of an owned name stays
		self.migration.remove_shared_apexes(django_apps, mock.Mock())
		names = set(Domain.objects.values_list('name', flat=True))
		self.assertEqual(names, {'github.io', 'herokuapp.com', 'acme.jfrog.com', 'acme-example.ai'})
		self.assertEqual(Domain.objects.get(name='github.io').scope_mode, 'host')
		self.assertEqual(Domain.objects.get(name='herokuapp.com').scope_mode, 'host')
		self.assertEqual(Domain.objects.get(name='acme-example.ai').scope_mode, 'auto')
		self.assertEqual(Domain.objects.get(name='acme.jfrog.com').scope_mode, 'auto')

	def test_the_deletion_cascades_to_the_scans_of_the_removed_domain(self):
		engine = EngineType.objects.create(engine_name='e5', yaml_configuration='x', default_engine=True)
		domain = self._domain('jfrog.com', MARKER)
		ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=timezone.now(), scan_status=2, results_dir='/tmp')
		self.migration.remove_shared_apexes(django_apps, mock.Mock())
		self.assertFalse(ScanHistory.objects.exists())

	def test_reverse_is_a_noop_and_it_is_idempotent(self):
		self._domain('jfrog.com', MARKER)
		self.migration.remove_shared_apexes(django_apps, mock.Mock())
		self.migration.remove_shared_apexes(django_apps, mock.Mock())
		self.assertEqual(Domain.objects.count(), 0)
		reverse = self.migration.Migration.operations[0].reverse_code
		self.assertIsNotNone(reverse)
		reverse(django_apps, mock.Mock())
