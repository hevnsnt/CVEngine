import socket
import threading
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


class CheckMemcachedTests(SimpleTestCase):
	def _serve(self, reply):
		srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		srv.bind(('127.0.0.1', 0))
		srv.listen(1)
		port = srv.getsockname()[1]

		def run():
			conn, _ = srv.accept()
			conn.recv(64)
			conn.sendall(reply)
			conn.close()
			srv.close()
		threading.Thread(target=run, daemon=True).start()
		return port

	def test_version_reply_means_open(self):
		port = self._serve(b'VERSION 1.6.21\r\n')
		self.assertTrue(dbx.check_memcached('127.0.0.1', port))

	def test_unexpected_reply_means_not_open(self):
		port = self._serve(b'ERROR\r\n')
		self.assertFalse(dbx.check_memcached('127.0.0.1', port))

	def test_nothing_listening_means_not_open(self):
		self.assertFalse(dbx.check_memcached('127.0.0.1', 1))  # port 1 refuses on loopback


class CheckRedisTests(SimpleTestCase):
	def test_ping_success_means_open(self):
		fake_redis = mock.Mock()
		fake_redis.Redis.return_value.ping.return_value = True
		fake_redis.AuthenticationError = Exception
		fake_redis.ResponseError = type('ResponseError', (Exception,), {})
		with mock.patch.dict('sys.modules', {'redis': fake_redis}):
			self.assertTrue(dbx.check_redis('h', 6379))

	def test_noauth_response_error_means_not_open(self):
		fake_redis = mock.Mock()

		class ResponseError(Exception):
			pass
		fake_redis.AuthenticationError = type('AuthenticationError', (Exception,), {})
		fake_redis.ResponseError = ResponseError
		fake_redis.Redis.return_value.ping.side_effect = ResponseError('NOAUTH Authentication required.')
		with mock.patch.dict('sys.modules', {'redis': fake_redis}):
			self.assertFalse(dbx.check_redis('h', 6379))

	def test_authentication_error_means_not_open(self):
		fake_redis = mock.Mock()
		auth_err = type('AuthenticationError', (Exception,), {})
		fake_redis.AuthenticationError = auth_err
		fake_redis.ResponseError = type('ResponseError', (Exception,), {})
		fake_redis.Redis.return_value.ping.side_effect = auth_err('bad auth')
		with mock.patch.dict('sys.modules', {'redis': fake_redis}):
			self.assertFalse(dbx.check_redis('h', 6379))


class CheckPostgresTests(SimpleTestCase):
	def test_successful_connect_with_no_password_means_open(self):
		fake_psycopg2 = mock.Mock()
		fake_psycopg2.connect.return_value = mock.Mock()
		with mock.patch.dict('sys.modules', {'psycopg2': fake_psycopg2}):
			self.assertTrue(dbx.check_postgres('h', 5432))
			fake_psycopg2.connect.assert_called_once_with(
				host='h', port=5432, dbname='postgres', user='postgres', password='', connect_timeout=dbx.CONNECT_TIMEOUT)

	def test_connect_failure_means_not_open(self):
		fake_psycopg2 = mock.Mock()
		fake_psycopg2.connect.side_effect = Exception('password authentication failed')
		with mock.patch.dict('sys.modules', {'psycopg2': fake_psycopg2}):
			self.assertFalse(dbx.check_postgres('h', 5432))


class CheckMysqlTests(SimpleTestCase):
	def test_successful_connect_as_root_with_no_password_means_open(self):
		fake_pymysql = mock.Mock()
		fake_conn = mock.Mock()
		fake_conn.get_server_info.return_value = '8.0.35'
		fake_pymysql.connect.return_value = fake_conn
		with mock.patch.dict('sys.modules', {'pymysql': fake_pymysql}):
			self.assertTrue(dbx.check_mysql('h', 3306))
			fake_pymysql.connect.assert_called_once_with(
				host='h', port=3306, user='root', password='', connect_timeout=dbx.CONNECT_TIMEOUT,
				read_timeout=dbx.CONNECT_TIMEOUT, write_timeout=dbx.CONNECT_TIMEOUT)
			fake_conn.close.assert_called_once()

	def test_access_denied_means_not_open(self):
		fake_pymysql = mock.Mock()
		fake_pymysql.connect.side_effect = Exception("(1045, \"Access denied for user 'root'@'h' (using password: NO)\")")
		with mock.patch.dict('sys.modules', {'pymysql': fake_pymysql}):
			self.assertFalse(dbx.check_mysql('h', 3306))

	def test_missing_library_means_unknown(self):
		with mock.patch.dict('sys.modules', {'pymysql': None}):
			self.assertIsNone(dbx.check_mysql('h', 3306))


class CheckMongodbTests(SimpleTestCase):
	def test_listdatabases_success_means_open(self):
		fake_pymongo = mock.Mock()
		fake_client = mock.Mock()
		fake_client.admin.command.return_value = {'databases': [{'name': 'admin'}, {'name': 'secrets'}]}
		fake_pymongo.MongoClient.return_value = fake_client
		with mock.patch.dict('sys.modules', {'pymongo': fake_pymongo}):
			self.assertTrue(dbx.check_mongodb('h', 27017))
			fake_client.admin.command.assert_called_once_with('listDatabases', 1, nameOnly=True)
			fake_client.close.assert_called_once()
		self.assertIn('2 database name(s)', dbx.EVIDENCE.get(('h', 27017), ''))

	def test_unauthorized_means_not_open(self):
		fake_pymongo = mock.Mock()
		fake_client = mock.Mock()
		fake_client.admin.command.side_effect = Exception('not authorized on admin to execute command')
		fake_pymongo.MongoClient.return_value = fake_client
		with mock.patch.dict('sys.modules', {'pymongo': fake_pymongo}):
			self.assertFalse(dbx.check_mongodb('h', 27017))

	def test_missing_library_means_unknown(self):
		with mock.patch.dict('sys.modules', {'pymongo': None}):
			self.assertIsNone(dbx.check_mongodb('h', 27017))


class CheckHttpBackedServicesTests(SimpleTestCase):
	def test_elasticsearch_open_root_endpoint(self):
		resp = mock.Mock(status_code=200, content=b'{"cluster_name": "x"}')
		resp.json.return_value = {'cluster_name': 'x'}
		with mock.patch('requests.get', return_value=resp):
			self.assertTrue(dbx.check_elasticsearch('h', 9200))

	def test_elasticsearch_401_means_not_open(self):
		resp = mock.Mock(status_code=401, content=b'')
		with mock.patch('requests.get', return_value=resp):
			self.assertFalse(dbx.check_elasticsearch('h', 9200))

	def test_couchdb_admin_party_all_dbs_listable(self):
		resp = mock.Mock(status_code=200)
		resp.json.return_value = ['_users', 'secrets']
		with mock.patch('requests.get', return_value=resp):
			self.assertTrue(dbx.check_couchdb('h', 5984))

	def test_couchdb_401_means_not_open(self):
		resp = mock.Mock(status_code=401)
		with mock.patch('requests.get', return_value=resp):
			self.assertFalse(dbx.check_couchdb('h', 5984))

	def test_network_errors_mean_not_open_not_a_crash(self):
		with mock.patch('requests.get', side_effect=OSError('refused')):
			self.assertFalse(dbx.check_elasticsearch('h', 9200))
			self.assertFalse(dbx.check_couchdb('h', 5984))


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
