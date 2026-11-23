"""The batched discovery ingest (``reNgine.tasks.persist_bbot_result``) stores exactly what the one-row-at-a-time ingest stored: the same hosts,
addresses, links, ports (filled, dated, sourced), technologies, Shodan readings, URLs, HTTP fields, findings and labels, for new hosts and for hosts an
earlier streaming batch stored, excluded and internal ones refused alike. Both run on the same database state, rolled back in between, and every
table they write is compared by its natural keys. The number of statements a batch takes no longer grows with its hosts."""
from django.db import connection, transaction
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from cveFeed.models import HostExclusion, HostLabel, ProbeObservation
from dashboard.models import Org, Project
from reNgine import discovery_events as bbot_lib
from reNgine.tasks import persist_bbot_result
from scanEngine.models import EngineType
from startScan.models import EndPoint, IpAddress, Port, ScanHistory, SubScan, Subdomain, SubdomainTechnology, Vulnerability
from targetApp.models import Domain
from tests.legacy_bbot_ingest import legacy_persist_bbot_result

CPE = 'cpe:/a:openbsd:openssh:8.9p1'
CPE2 = 'cpe:/a:nginx:nginx:1.18.0'


def _http(host, path, port, status, title):
	return {'host': host, 'url': f'https://{host}{path}', 'port': port, 'status': status, 'title': title, 'webserver': 'nginx',
			'content_type': 'text/html', 'location': ''}


def _finding(host, name, informational=False):
	return {'module': 'badsecrets', 'name': name, 'severity': 2, 'host': host, 'url': f'https://{host}/', 'description': f'{name} found on {host}',
			'informational': informational, 'port': 443}


class Fixture(TestCase):
	def setUp(self):
		self.org = Org.objects.create(name='Equiv', slug='equiv')
		self.project = Project.objects.create(name='P', slug='p-equiv', insert_date=timezone.now(), org=self.org)
		self.domain = Domain.objects.create(name='eq.test', project=self.project, insert_date=timezone.now())
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, scan_status=1, start_scan_date=timezone.now())
		HostExclusion.objects.create(org=self.org, host='banned.eq.test')
		# what an earlier streaming batch stored: a host with an address, a port nmap named (and one it left unnamed), and a host the batch names again (a second row of one name in one scan is refused by the unique key since startScan 0031)
		self.old = Subdomain.objects.create(name='old.eq.test', scan_history=self.scan, target_domain=self.domain, discovered_date=timezone.now())
		ip = IpAddress.objects.create(address='198.51.100.9', org=self.org)
		self.old.ip_addresses.add(ip)
		ip.ports.add(Port.objects.create(number=22, service_name='ssh-custom', description='', source='nmap'))
		ip.ports.add(Port.objects.create(number=443, service_name='', description='', source=''))
		Subdomain.objects.create(name='twin.eq.test', scan_history=self.scan, target_domain=self.domain)
		self.subscan = SubScan.objects.create(scan_history=self.scan, subdomain=self.old, start_scan_date=timezone.now(), status=1)
		self.ctx = {'scan_history_id': self.scan.id, 'domain_id': self.domain.id, 'subscan_id': self.subscan.id}

	def batches(self):
		first = bbot_lib.BbotResult(
			subdomains={'eq.test', 'a.eq.test', 'b.eq.test', 'twin.eq.test', 'banned.eq.test', 'not-under.other.test', 'bad_name!', '203.0.113.50'},
			resolutions={('a.eq.test', '198.51.100.1'), ('a.eq.test', '198.51.100.2'), ('b.eq.test', '198.51.100.2'), ('b.eq.test', '10.0.0.5'),
						 ('twin.eq.test', '198.51.100.3'), ('banned.eq.test', '198.51.100.4'), ('203.0.113.50', '203.0.113.50'),
						 ('a.eq.test', '127.0.0.1')},
			ports={('a.eq.test', 80), ('a.eq.test', 443), ('b.eq.test', 443), ('b.eq.test', 61234), ('twin.eq.test', 8080), ('banned.eq.test', 80),
				   ('203.0.113.50', 22), ('203.0.113.51', 8443), ('10.0.0.9', 80), ('old.eq.test', 22), ('old.eq.test', 443), ('old.eq.test', 25),
				   ('gone.eq.test', 80)},
			technologies={('a.eq.test', 'nginx/1.18.0'), ('a.eq.test', 'PHP'), ('b.eq.test', 'nginx'), ('a.eq.test', CPE), ('a.eq.test', CPE2),
						  ('old.eq.test', 'Caddy'), ('old.eq.test', CPE), ('banned.eq.test', 'nginx')},
			urls={('https://a.eq.test/', 200), ('https://a.eq.test/login', 401), ('https://old.eq.test/', 301), ('https://b.eq.test/x', 0)},
			findings=[_finding('a.eq.test', 'Leaked key'), _finding('old.eq.test', 'Old leak'), _finding('banned.eq.test', 'Never'),
					  _finding('a.eq.test', 'WAF Detection', informational=True)],
			http=[_http('a.eq.test', '/admin', 443, 403, 'Denied'), _http('a.eq.test', '/', 443, 200, 'Welcome'), _http('b.eq.test', '/', 8443, 200, 'B'),
				  _http('old.eq.test', '/', 443, 200, 'Old'), _http('old.eq.test', '/deep', 9443, 500, 'Err'), _http('twin.eq.test', '/x', 0, 404, 'Nope')])
		second = bbot_lib.BbotResult(
			subdomains={'c.eq.test'}, resolutions={('c.eq.test', '198.51.100.1')},
			ports={('a.eq.test', 443), ('a.eq.test', 8080), ('c.eq.test', 443), ('b.eq.test', 61234)},
			technologies={('a.eq.test', 'nginx/1.18.0'), ('c.eq.test', CPE)},
			urls={('https://a.eq.test/', 200), ('https://c.eq.test/', 200)},
			findings=[_finding('a.eq.test', 'Leaked key'), _finding('c.eq.test', 'C leak')],
			http=[_http('a.eq.test', '/', 443, 200, 'Welcome again'), _http('c.eq.test', '/', 443, 200, 'C'), _http('a.eq.test', '/', 8080, 200, 'Alt')])
		return [first, second]

	def snapshot(self):
		subs = Subdomain.objects.filter(target_domain=self.domain)
		ports = [(link.ipaddress.address, link.port.number, link.port.protocol, link.port.service_name, link.port.description, link.port.source,
				  link.port.last_seen is not None, link.port.http, link.port.product)
				 for link in IpAddress.ports.through.objects.select_related('ipaddress', 'port')]
		readings = []
		for row in ProbeObservation.objects.filter(project=self.project):
			evidence = {k: v for k, v in (row.evidence or {}).items() if k != 'reported_at'}
			readings.append((row.host, row.probe, row.port, row.kind, row.product, row.version, row.outcome, sorted(evidence.items(), key=str)))
		return {
			'hosts': sorted((s.name, s.scan_history_id, s.http_url or '', s.http_status, s.page_title or '', s.webserver or '', s.discovered_date is not None,
							 sorted(s.subdomain_subscan_ids.values_list('pk', flat=True))) for s in subs),
			'host_count': subs.count(),
			'addresses': sorted((ip.address, ip.org_id, ip.is_private) for ip in IpAddress.objects.all()),
			'address_links': sorted(Subdomain.ip_addresses.through.objects.filter(subdomain__in=subs).values_list('subdomain__name', 'ipaddress__address')),
			'ports': sorted(ports, key=str),
			'port_count': Port.objects.count(),
			'technologies': sorted(SubdomainTechnology.objects.filter(subdomain__in=subs).values_list('subdomain__name', 'technology__name', 'source')),
			'readings': sorted(readings, key=str),
			'endpoints': sorted(EndPoint.objects.filter(scan_history=self.scan).values_list('http_url', 'subdomain__name', 'http_status', 'source')),
			'findings': sorted(Vulnerability.objects.filter(scan_history=self.scan).values_list('name', 'subdomain__name', 'http_url', 'severity', 'source',
																							 'template_id', 'open_status'), key=str),
			'labels': sorted(HostLabel.objects.filter(project=self.project).values_list('host', 'label')),
		}

	def run_with(self, persist):
		sid = transaction.savepoint()
		try:
			for batch in self.batches():
				persist(batch, ctx=dict(self.ctx))
			return self.snapshot()
		finally:
			transaction.savepoint_rollback(sid)


class EquivalenceTests(Fixture):
	def test_the_batched_ingest_stores_what_the_per_row_ingest_stored(self):
		before = self.run_with(legacy_persist_bbot_result)
		after = self.run_with(persist_bbot_result)
		for key in before:
			self.assertEqual(after[key], before[key], key)
		# the fixture reaches every path: kept, refused and excluded names, internal addresses, address hosts, earlier-batch hosts, filled ports
		hosts = {row[0] for row in after['hosts']}
		self.assertTrue({'a.eq.test', 'b.eq.test', 'c.eq.test', 'eq.test', 'twin.eq.test', 'old.eq.test'} <= hosts)
		self.assertFalse({'banned.eq.test', 'not-under.other.test', 'bad_name!', '203.0.113.50'} & hosts)
		self.assertNotIn('10.0.0.5', {a for a, *_ in after['addresses']})
		self.assertIn(('198.51.100.9', 22, 'tcp', 'ssh-custom', '', 'nmap', True, {}, ''), after['ports'])  # a scanner's name and source stay
		self.assertTrue(any(p[:2] == ('203.0.113.51', 8443) for p in after['ports']))  # an address host takes its port on its own address
		self.assertTrue(after['readings'])
		self.assertEqual(sum(1 for f in after['findings'] if f[0] == 'Leaked key'), 1)

	def test_a_batch_run_twice_stores_what_the_per_row_ingest_stored(self):
		def twice(persist):
			def run(batch, ctx):
				persist(batch, ctx=ctx)
				persist(batch, ctx=dict(ctx))
			return run
		self.assertEqual(self.run_with(twice(persist_bbot_result)), self.run_with(twice(legacy_persist_bbot_result)))


class StatementCountTests(Fixture):
	def batch(self, prefix, count, first):
		names = [f'{prefix}{i}.eq.test' for i in range(count)]
		return bbot_lib.BbotResult(
			subdomains=set(names), resolutions={(n, f'198.51.{first}.{i + 1}') for i, n in enumerate(names)} | {(n, f'203.0.{first}.{i + 1}') for i, n in enumerate(names)},
			ports={(n, p) for n in names for p in (80, 443, 8443)}, technologies={(n, t) for n in names for t in ('nginx', 'PHP', CPE)},
			urls={(f'https://{n}/', 200) for n in names}, http=[_http(n, '/', 443, 200, 'Hi') for n in names])

	def test_statements_of_a_batch_do_not_grow_with_its_hosts(self):
		persist_bbot_result(self.batch('warm', 1, 90), ctx=dict(self.ctx))  # the Technology rows exist before either run is measured

		def statements(prefix, count, first):
			with CaptureQueriesContext(connection) as queries:
				persist_bbot_result(self.batch(prefix, count, first), ctx=dict(self.ctx))
			return [q['sql'] for q in queries.captured_queries if 'probeobservation' not in q['sql'].lower()]  # Shodan readings are stored per host
		small, large = statements('s', 3, 10), statements('l', 30, 20)
		self.assertEqual(len(small), len(large), '\n'.join(large))
		self.assertEqual(Subdomain.objects.filter(name__startswith='l', scan_history=self.scan).count(), 30)
		self.assertEqual(Port.objects.filter(ports__ip_addresses__name__startswith='l').distinct().count(), 90)
