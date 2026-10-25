from urllib.parse import urlencode

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed.models import RouteAuth
from dashboard.models import Org, Project, ProjectMembership
from startScan.models import IpAddress, Port, Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call

NOW = timezone.now()


class SearchEvidenceTests(TestCase):
	"""``php`` and ``tech:php`` find a host wherever CVEngine saw PHP: the Server header, a PHPSESSID cookie, a route fingerprint, a
	service banner or NSE output. Evidence of a closed port, a retired route or another project's route does not count."""

	@classmethod
	def setUpTestData(cls):
		org = Org.objects.create(name='Widgets', slug='widgets')
		cls.pa = Project.objects.create(name='A', slug='ev-a', insert_date=NOW, org=org)
		cls.pb = Project.objects.create(name='B', slug='ev-b', insert_date=NOW, org=org)
		cls.da = Domain.objects.create(name='acme.example', project=cls.pa, insert_date=NOW)
		cls.db = Domain.objects.create(name='other.example', project=cls.pb, insert_date=NOW)
		user = User.objects.create_user('ev-user', password='x')
		ProjectMembership.objects.create(user=user, project=cls.pa, role='user')
		_, cls.token = create_token(user, 'ev')

		def host(name, domain=cls.da, **fields):
			return Subdomain.objects.create(name=name, target_domain=domain, **fields)

		def route(sub, project=cls.pa, domain=cls.da, **evidence):
			retired = evidence.pop('retired', None)
			return RouteAuth.objects.create(project=project, domain=domain, host=sub.name, url=f'https://{sub.name}/', path='/',
											auth_state='open', evidence=evidence, retired_at=retired)

		def port(sub, ip, number, **fields):
			addr = IpAddress.objects.get_or_create(address=ip)[0]
			sub.ip_addresses.add(addr)
			addr.ports.add(Port.objects.create(number=number, **fields))

		host('header.acme.example', webserver='nginx/1.18 PHP/8.1')
		cookie = host('cookie.acme.example')
		route(cookie, cookies=['PHPSESSID'], markers=[], server='nginx')
		finger = host('finger.acme.example')
		route(finger, fingerprints=[{'name': 'PHP:8.2.30', 'source': 'header:x-powered-by'}], fingerprint_names=['PHP:8.2.30'], markers=[])
		ftp = host('ftp.acme.example')
		port(ftp, '192.0.2.21', 21, service_name='ftp', banner='220 ProFTPD Server ready', extra={'scripts': {'ftp-anon': 'Anonymous FTP login allowed'}, 'script_text': 'Anonymous FTP login allowed'})
		dead = host('closed.acme.example')
		port(dead, '192.0.2.22', 80, service_name='http', state='closed', banner='X-Powered-By: PHP/5.6')
		retired = host('retired.acme.example')
		route(retired, cookies=['PHPSESSID'], retired=NOW)
		iso = host('iso.acme.example')
		other = host('iso.acme.example', domain=cls.db)
		route(other, project=cls.pb, domain=cls.db, cookies=['PHPSESSID'])
		host('plain.acme.example')
		assert iso.pk != other.pk

	def names(self, q):
		status, data = call(self.token, 'GET', '/api/v1/projects/ev-a/search?' + urlencode({'q': q}))
		self.assertEqual(status, 200, data)
		return sorted(h['host'] for h in data['results'])

	def why(self, q):
		status, data = call(self.token, 'GET', '/api/v1/projects/ev-a/search?' + urlencode({'q': q}))
		self.assertEqual(status, 200, data)
		return {h['host']: h['matched'] for h in data['results']}

	def test_php_is_found_in_a_header_a_cookie_and_a_fingerprint(self):
		expected = ['cookie.acme.example', 'finger.acme.example', 'header.acme.example']
		self.assertEqual(self.names('php'), expected)
		self.assertEqual(self.names('tech:php'), expected)

	def test_each_result_says_where_php_was_seen(self):
		why = self.why('tech:php')
		self.assertEqual(why['header.acme.example'], ['web server nginx/1.18 PHP/8.1'])
		self.assertEqual(why['cookie.acme.example'], ['cookie PHPSESSID'])
		self.assertEqual(why['finger.acme.example'], ['PHP:8.2.30 (header:x-powered-by)'])

	def test_a_closed_port_a_retired_route_and_another_projects_route_do_not_count(self):
		hosts = self.names('php')
		for name in ('closed.acme.example', 'retired.acme.example', 'iso.acme.example', 'plain.acme.example'):
			self.assertNotIn(name, hosts)

	def test_banner_search_reads_banners_and_nse_output_on_open_ports(self):
		self.assertEqual(self.names('banner:proftpd'), ['ftp.acme.example'])
		self.assertEqual(self.names('banner:"anonymous ftp"'), ['ftp.acme.example'])
		self.assertEqual(self.names('banner:php'), [])  # the only PHP banner is on a closed port
		self.assertEqual(self.why('banner:proftpd')['ftp.acme.example'], ['port 21 ftp (banner)'])
		self.assertEqual(self.why('banner:anonymous')['ftp.acme.example'], ['port 21 ftp (ftp-anon)'])

	def test_a_bare_word_finds_banners_too_and_negation_works(self):
		self.assertEqual(self.names('proftpd'), ['ftp.acme.example'])
		self.assertEqual(self.names('tech:php -nginx'), ['finger.acme.example'])  # the header and cookie hosts both say nginx

	def test_json_key_names_are_not_searchable_text(self):
		# the evidence rows hold keys called markers, source, fingerprints and cookies: searching for them must not match every row
		for word in ('markers', 'source', 'fingerprints', 'fingerprint_names', 'cookies', 'scripts', 'script_text', 'ftp-anon'):
			self.assertEqual(self.names(word), [], word)
