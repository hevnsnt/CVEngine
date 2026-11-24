"""A discovery batch reads what it needs once per batch and writes only the columns that change: no whole-row save of a host or an address
that nothing changed (such a save puts back what another writer stored meanwhile), one technology lookup per name, the hosts an earlier
streaming batch stored and their addresses and ports read together, and the HTTP answers saved on the port as ``http`` alone."""
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from dashboard.models import Org, Project
from cvengine import discovery_events as bbot_lib
from cvengine.tasks import persist_bbot_result, save_ip_address, save_subdomain
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain
from targetApp.models import Domain


def _writes(queries, table):
	return [q['sql'] for q in queries.captured_queries if q['sql'].startswith(f'UPDATE "{table}"')]


def _reads(queries):
	return sum(1 for q in queries.captured_queries if q['sql'].lstrip().upper().startswith('SELECT'))


class Base(TestCase):
	def setUp(self):
		org = Org.objects.create(name='Ingest', slug='ingest')
		self.project = Project.objects.create(name='P', slug='p-ingest', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='ing.test', project=self.project, insert_date=timezone.now())
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, scan_status=1, start_scan_date=timezone.now())
		self.ctx = {'scan_history_id': self.scan.id, 'domain_id': self.domain.id}

	def names(self, prefix, count):
		return [f'{prefix}{i}.ing.test' for i in range(count)]

	def hosts_batch(self, names, first):
		"""New hosts, two addresses and three ports each."""
		resolutions = set()
		for i, name in enumerate(names):
			resolutions |= {(name, f'198.51.100.{first + i}'), (name, f'203.0.113.{first + i}')}
		return bbot_lib.BbotResult(subdomains=set(names), resolutions=resolutions, ports={(n, p) for n in names for p in (80, 443, 8080)})

	def later_batch(self, names):
		"""What a later streaming batch says about hosts an earlier one stored: technologies and the root HTTP answer on 443."""
		http = [{'host': n, 'url': f'https://{n}/', 'port': 443, 'status': 200, 'title': 'Welcome', 'webserver': 'nginx',
				 'content_type': 'text/html', 'location': ''} for n in names]
		return bbot_lib.BbotResult(technologies={(n, t) for n in names for t in ('nginx', 'PHP')}, http=http)


class BatchQueryCountTests(Base):
	def test_reads_of_a_later_batch_do_not_grow_with_its_hosts(self):
		small, large = self.names('s', 5), self.names('l', 20)
		persist_bbot_result(self.hosts_batch(small, 10), ctx=self.ctx)
		persist_bbot_result(self.hosts_batch(large, 50), ctx=self.ctx)
		persist_bbot_result(self.hosts_batch(['warm.ing.test'], 90), ctx=self.ctx)
		persist_bbot_result(self.later_batch(['warm.ing.test']), ctx=self.ctx)  # the Technology rows exist before either run is measured

		def run(names):
			with CaptureQueriesContext(connection) as first:
				persist_bbot_result(self.later_batch(names), ctx=self.ctx)
			with CaptureQueriesContext(connection) as again:  # the same answers again: nothing changed, nothing is rewritten
				persist_bbot_result(self.later_batch(names), ctx=self.ctx)
			return first, again
		small_first, small_again = run(small)
		large_first, large_again = run(large)
		self.assertEqual(_reads(small_first), _reads(large_first))  # hosts, addresses, ports and technologies read once per batch
		self.assertEqual(len(small_again), len(large_again))
		for queries in (small_again, large_again):
			self.assertEqual(_writes(queries, 'startScan_subdomain'), [])
			self.assertEqual(_writes(queries, 'startScan_port'), [])
		# the first answer wrote each host's fields and the http of its 443 row (on the host's first address), those columns only, in one
		# statement per table for the whole batch
		subdomain_writes = _writes(large_first, 'startScan_subdomain')
		self.assertEqual(len(subdomain_writes), 1)
		self.assertTrue(all('"score"' not in sql and '"is_important"' not in sql for sql in subdomain_writes))
		port_writes = _writes(large_first, 'startScan_port')
		self.assertEqual(len(port_writes), 1)
		self.assertTrue(all('"banner"' not in sql and '"service_name"' not in sql for sql in port_writes))
		for name in large:
			sub = Subdomain.objects.get(scan_history=self.scan, name=name)
			self.assertEqual((sub.http_status, sub.page_title, sub.webserver), (200, 'Welcome', 'nginx'))
			self.assertEqual(sub.technologies.count(), 2)
			self.assertEqual([p.http['status'] for ip in sub.ip_addresses.all() for p in ip.ports.filter(number=443)], [200])

	def test_new_hosts_and_their_addresses_are_never_rewritten_after_insert(self):
		names = self.names('n', 6)
		with CaptureQueriesContext(connection) as queries:
			persist_bbot_result(self.hosts_batch(names, 100), ctx=self.ctx)
		self.assertEqual(_writes(queries, 'startScan_subdomain'), [])
		self.assertEqual(_writes(queries, 'startScan_ipaddress'), [])
		for sub in Subdomain.objects.filter(scan_history=self.scan):
			self.assertIsNotNone(sub.discovered_date)
			self.assertEqual(sub.ip_addresses.count(), 2)
			self.assertEqual(sorted(sub.ip_addresses.order_by('id').first().ports.values_list('number', flat=True)), [80, 443, 8080])


class NoLostUpdateTests(Base):
	def test_linking_an_address_keeps_what_another_writer_stored_on_the_host(self):
		sub = Subdomain.objects.create(name='x.ing.test', target_domain=self.domain, scan_history=self.scan)
		stale = Subdomain.objects.get(pk=sub.pk)  # what agentapi.dns_crosscheck.release holds while the ingest writes the same row
		Subdomain.objects.filter(pk=sub.pk).update(http_status=200, page_title='Live', webserver='nginx', is_important=True, score=40)
		with CaptureQueriesContext(connection) as queries:
			ip, created = save_ip_address('198.51.100.200', subdomain=stale)
		self.assertTrue(created)
		self.assertEqual(_writes(queries, 'startScan_subdomain'), [])
		self.assertEqual(_writes(queries, 'startScan_ipaddress'), [])
		sub.refresh_from_db()
		self.assertEqual((sub.http_status, sub.page_title, sub.webserver, sub.is_important, sub.score), (200, 'Live', 'nginx', True, 40))
		self.assertEqual(list(sub.ip_addresses.all()), [ip])

	def test_an_extra_attribute_writes_its_own_column_only_when_it_changes(self):
		sub = Subdomain.objects.create(name='y.ing.test', target_domain=self.domain, scan_history=self.scan)
		ip, _ = save_ip_address('198.51.100.201', subdomain=sub)
		IpAddress.objects.filter(pk=ip.pk).update(os_guess='Linux 5.x')
		with CaptureQueriesContext(connection) as queries:
			save_ip_address('198.51.100.201', subdomain=sub, reverse_pointer='y.example')
		writes = _writes(queries, 'startScan_ipaddress')
		self.assertEqual(len(writes), 1)
		self.assertNotIn('"os_guess"', writes[0])
		ip.refresh_from_db()
		self.assertEqual((ip.reverse_pointer, ip.os_guess), ('y.example', 'Linux 5.x'))
		with CaptureQueriesContext(connection) as queries:
			save_ip_address('198.51.100.201', subdomain=sub, reverse_pointer='y.example')
		self.assertEqual(_writes(queries, 'startScan_ipaddress'), [])

	def test_a_new_host_is_inserted_with_its_discovery_time(self):
		with CaptureQueriesContext(connection) as queries:
			sub, created = save_subdomain('z.ing.test', ctx=self.ctx)
		self.assertTrue(created)
		self.assertIsNotNone(sub.discovered_date)
		self.assertEqual(_writes(queries, 'startScan_subdomain'), [])
		self.assertEqual(Subdomain.objects.get(pk=sub.pk).discovered_date, sub.discovered_date)
		self.assertEqual(save_subdomain('z.ing.test', ctx=self.ctx), (sub, False))


class HttpRecordTests(Base):
	def setUp(self):
		super().setUp()
		self.sub = Subdomain.objects.create(name='www.ing.test', target_domain=self.domain, scan_history=self.scan)
		self.other = Subdomain.objects.create(name='alt.ing.test', target_domain=self.domain, scan_history=self.scan)
		self.ip = IpAddress.objects.create(address='198.51.100.210')
		self.sub.ip_addresses.add(self.ip)
		self.other.ip_addresses.add(self.ip)  # two names of one address

	def rec(self, host, path, status, title):
		return {'host': host, 'url': f'https://{host}{path}', 'port': 8443, 'status': status, 'title': title, 'webserver': 'nginx',
				'content_type': '', 'location': ''}

	def test_a_port_an_earlier_record_added_is_the_one_later_records_use(self):
		records = [self.rec('www.ing.test', '/admin', 403, 'Denied'), self.rec('www.ing.test', '/', 200, 'Welcome'),
				   self.rec('alt.ing.test', '/login', 401, 'Login')]
		persist_bbot_result(bbot_lib.BbotResult(http=records), ctx=self.ctx)
		port = self.ip.ports.get(number=8443)  # one row, not one per record or per name
		self.assertEqual((port.http['status'], port.http['title']), (200, 'Welcome'))  # the root answer wins; a deeper one does not overwrite it
		self.assertEqual((port.source, port.service_name), ('bbot', 'https'))
		self.assertIsNotNone(port.last_seen)

	def test_the_answer_leaves_the_rest_of_the_port_alone(self):
		port = Port.objects.create(number=8443, product='nginx', version='1.25.0', banner='HTTP/1.1 200 OK', source='nmap')
		self.ip.ports.add(port)
		persist_bbot_result(bbot_lib.BbotResult(http=[self.rec('www.ing.test', '/', 200, 'Welcome')]), ctx=self.ctx)
		port.refresh_from_db()
		self.assertEqual((port.product, port.version, port.banner, port.source), ('nginx', '1.25.0', 'HTTP/1.1 200 OK', 'nmap'))
		self.assertEqual(port.http['title'], 'Welcome')
