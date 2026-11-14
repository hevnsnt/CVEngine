from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import db_exposure as dbx
from cveFeed.models import HostExclusion
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain


class FakePort:
	def __init__(self, service_name='', product=''):
		self.service_name, self.product = service_name, product


class CheckerForTests(SimpleTestCase):
	def test_matches_by_service_name_or_product_case_insensitively(self):
		self.assertEqual(dbx.checker_for(FakePort(service_name='redis'))[0], 'Redis')
		self.assertEqual(dbx.checker_for(FakePort(product='Memcached 1.6'))[0], 'Memcached')
		self.assertEqual(dbx.checker_for(FakePort(service_name='postgresql'))[0], 'PostgreSQL')
		self.assertEqual(dbx.checker_for(FakePort(product='Elasticsearch REST API'))[0], 'Elasticsearch')
		self.assertEqual(dbx.checker_for(FakePort(service_name='http', product='CouchDB httpd'))[0], 'CouchDB')
		self.assertEqual(dbx.checker_for(FakePort(service_name='mysql'))[0], 'MySQL')
		self.assertEqual(dbx.checker_for(FakePort(product='MariaDB 10.11'))[0], 'MySQL')
		self.assertEqual(dbx.checker_for(FakePort(service_name='mongodb'))[0], 'MongoDB')
		self.assertEqual(dbx.checker_for(FakePort(product='MongoDB 7.0.4'))[0], 'MongoDB')

	def test_unmatched_service_returns_none(self):
		self.assertEqual(dbx.checker_for(FakePort(service_name='https', product='nginx')), (None, None))
		self.assertEqual(dbx.checker_for(FakePort()), (None, None))


class RunDbExposureChecksTests(TestCase):
	def setUp(self):
		org = Org.objects.create(name='D', slug='d-dbx')
		self.project = Project.objects.create(name='P', slug='p-dbx', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='example.test', project=self.project, insert_date=timezone.now())
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x')
		self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=timezone.now())

	def _host(self, name, service_name):
		sub = Subdomain.objects.create(scan_history=self.scan, name=name)
		ip = IpAddress.objects.create(address=f'203.0.113.{Subdomain.objects.count()}')
		port = Port.objects.create(number=6379, service_name=service_name)
		ip.ports.add(port)
		sub.ip_addresses.add(ip)
		return sub, ip, port

	def test_no_matching_ports_means_nothing_checked(self):
		self._host('www.example.test', 'https')
		self.assertEqual(dbx.run_db_exposure_checks(self.scan.id), {'checked': 0, 'exposed': 0})

	def test_retained_excluded_host_is_not_probed(self):
		sub, _, _ = self._host('redis.example.test', 'redis')
		# Organization exclusions can leave records in projects the author cannot
		# write to. Keep this record to model that supported state.
		HostExclusion.objects.create(org=self.project.org, host=sub.name)
		probe = mock.Mock(return_value=True)
		result = dbx.run_db_exposure_checks(self.scan.id, checks={'redis': ('Redis', probe)})
		self.assertEqual(result, {'checked': 0, 'exposed': 0})
		probe.assert_not_called()
		self.assertTrue(Subdomain.objects.filter(pk=sub.pk).exists())
		self.assertFalse(Vulnerability.objects.exists())

	def test_allowed_sibling_on_same_ip_is_probed_without_excluded_findings(self):
		excluded, ip, port = self._host('excluded.example.test', 'redis')
		allowed = Subdomain.objects.create(scan_history=self.scan, name='allowed.example.test')
		allowed.ip_addresses.add(ip)
		HostExclusion.objects.create(org=self.project.org, host=excluded.name)
		probe = mock.Mock(return_value=True)
		result = dbx.run_db_exposure_checks(self.scan.id, checks={'redis': ('Redis', probe)})
		self.assertEqual(result, {'checked': 1, 'exposed': 1})
		probe.assert_called_once_with(ip.address, port.number)
		self.assertEqual(list(Vulnerability.objects.values_list('subdomain_id', flat=True)), [allowed.pk])

	def test_exclusion_added_after_planning_is_checked_before_dispatch(self):
		sub, _, _ = self._host('redis.example.test', 'redis')
		probe = mock.Mock(return_value=True)
		def exclude_at_activity(*args, **kwargs):
			HostExclusion.objects.create(org=self.project.org, host=sub.name)
			return None
		with mock.patch('cveFeed.activity.log', side_effect=exclude_at_activity), \
				mock.patch('cveFeed.activity.settle'):
			result = dbx.run_db_exposure_checks(self.scan.id, checks={'redis': ('Redis', probe)})
		self.assertEqual(result, {'checked': 0, 'exposed': 0})
		probe.assert_not_called()

	def test_exclusion_during_probe_prevents_new_finding(self):
		sub, _, _ = self._host('redis.example.test', 'redis')
		def exclude_during_probe(host, port):
			HostExclusion.objects.create(org=self.project.org, host=sub.name)
			return True
		result = dbx.run_db_exposure_checks(self.scan.id, checks={'redis': ('Redis', exclude_during_probe)})
		self.assertEqual(result, {'checked': 1, 'exposed': 0})
		self.assertFalse(Vulnerability.objects.exists())

	def test_exclusion_lookup_failure_prevents_dispatch(self):
		self._host('redis.example.test', 'redis')
		probe = mock.Mock(return_value=True)
		with mock.patch('cveFeed.models.HostExclusion.objects.filter', side_effect=RuntimeError('lookup unavailable')):
			with self.assertRaisesMessage(RuntimeError, 'lookup unavailable'):
				dbx.run_db_exposure_checks(self.scan.id, checks={'redis': ('Redis', probe)})
		probe.assert_not_called()

	def test_exclusion_lookup_failure_after_probe_prevents_finding(self):
		self._host('redis.example.test', 'redis')
		probe = mock.Mock(return_value=True)
		with mock.patch.object(dbx, '_excluded_names', side_effect=[frozenset(), frozenset(), RuntimeError('lookup unavailable')]):
			with self.assertRaisesMessage(RuntimeError, 'lookup unavailable'):
				dbx.run_db_exposure_checks(self.scan.id, checks={'redis': ('Redis', probe)})
		probe.assert_called_once()
		self.assertFalse(Vulnerability.objects.exists())

	def test_open_service_creates_a_critical_vulnerability(self):
		sub, ip, port = self._host('redis.example.test', 'redis')
		result = dbx.run_db_exposure_checks(self.scan.id, checks={'redis': ('Redis', lambda h, p: True)})
		self.assertEqual(result, {'checked': 1, 'exposed': 1})
		vuln = Vulnerability.objects.get(scan_history=self.scan)
		self.assertEqual((vuln.name, vuln.severity, vuln.subdomain_id, vuln.source), ('Unauthenticated Redis exposure', 4, sub.id, 'db_exposure'))

	def test_closed_service_creates_nothing(self):
		self._host('redis.example.test', 'redis')
		result = dbx.run_db_exposure_checks(self.scan.id, checks={'redis': ('Redis', lambda h, p: False)})
		self.assertEqual(result, {'checked': 1, 'exposed': 0})
		self.assertEqual(Vulnerability.objects.count(), 0)

	def test_rerun_does_not_duplicate_findings(self):
		self._host('redis.example.test', 'redis')
		checks = {'redis': ('Redis', lambda h, p: True)}
		dbx.run_db_exposure_checks(self.scan.id, checks=checks)
		dbx.run_db_exposure_checks(self.scan.id, checks=checks)
		self.assertEqual(Vulnerability.objects.filter(scan_history=self.scan).count(), 1)

	def test_a_crashing_checker_is_skipped_not_fatal(self):
		self._host('redis.example.test', 'redis')

		def boom(h, p):
			raise RuntimeError('socket exploded')
		result = dbx.run_db_exposure_checks(self.scan.id, checks={'redis': ('Redis', boom)})
		self.assertEqual(result, {'checked': 1, 'exposed': 0})
		self.assertEqual(Vulnerability.objects.count(), 0)

	def test_none_from_a_checker_missing_its_library_is_treated_as_not_open(self):
		self._host('redis.example.test', 'redis')
		result = dbx.run_db_exposure_checks(self.scan.id, checks={'redis': ('Redis', lambda h, p: None)})
		self.assertEqual(result, {'checked': 1, 'exposed': 0})
