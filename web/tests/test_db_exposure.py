import socket
import threading
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import db_exposure as dbx
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
