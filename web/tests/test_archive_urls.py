import json
from unittest import mock
from urllib.parse import urlencode

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import archive_urls
from cveFeed.models import HostArchive, ServiceRun
from dashboard.models import Org, Project, ProjectMembership
from startScan.models import Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call

NOW = timezone.now()


class FakeResponse:
	def __init__(self, urls, status=200):
		self.status, self.body = status, json.dumps([['original']] + [[u] for u in urls]).encode()

	def raise_for_status(self):
		if self.status >= 400:
			raise RuntimeError(f'HTTP {self.status}')

	def iter_content(self, size):
		yield self.body

	def close(self):
		pass


class ClassifyTests(SimpleTestCase):
	def test_extensions_and_paths_name_the_technology(self):
		urls = ['https://www.acme.example/index.php?id=3', 'http://www.acme.example/blog/wp-content/themes/x/style.css',
				'https://www.acme.example/login.aspx', 'https://www.acme.example/about.html']
		out = archive_urls.classify(urls, 'acme.example', {'www.acme.example'})
		tech = out['www.acme.example']['technologies']
		self.assertEqual(set(tech), {'PHP', 'WordPress', 'ASP.NET'})
		self.assertEqual(out['www.acme.example']['url_count'], 4)
		self.assertEqual(tech['PHP']['sample'], ['/index.php'])

	def test_unknown_hosts_and_other_domains_are_ignored(self):
		urls = ['https://old.acme.example/a.php', 'https://evil.example/a.php', 'https://acme.example.evil.example/a.php']
		self.assertEqual(archive_urls.classify(urls, 'acme.example', {'www.acme.example'}), {})

	def test_fetch_drops_the_header_row_and_bad_status(self):
		self.assertEqual(archive_urls.fetch_urls('acme.example', get=lambda *a, **k: FakeResponse(['http://a/x.php'])), ['http://a/x.php'])
		with self.assertRaises(RuntimeError):
			archive_urls.fetch_urls('acme.example', get=lambda *a, **k: FakeResponse([], status=503))


class ArchiveLookupTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		org = Org.objects.create(name='Widgets', slug='widgets')
		cls.project = Project.objects.create(name='A', slug='arc-a', insert_date=NOW, org=org)
		cls.domain = Domain.objects.create(name='acme.example', project=cls.project, insert_date=NOW)
		Subdomain.objects.create(name='www.acme.example', target_domain=cls.domain)
		Subdomain.objects.create(name='plain.acme.example', target_domain=cls.domain)
		user = User.objects.create_user('arc-user', password='x')
		ProjectMembership.objects.create(user=user, project=cls.project, role='user')
		_, cls.token = create_token(user, 'arc')

	def run_lookup(self, urls=('https://www.acme.example/index.php', 'https://www.acme.example/wp-login.php'), **kwargs):
		return archive_urls.run_for_domain(self.domain.id, get=lambda *a, **k: FakeResponse(urls), **kwargs)

	def test_stores_historical_evidence_for_known_hosts_only(self):
		out = self.run_lookup(urls=('https://www.acme.example/index.php', 'https://gone.acme.example/x.php'))
		self.assertEqual(out['stored'], 1)
		row = HostArchive.objects.get()
		self.assertEqual((row.host, row.tech_text, row.url_count), ('www.acme.example', 'php', 1))

	def test_runs_once_a_week_per_target(self):
		self.run_lookup()
		self.assertEqual(self.run_lookup(), {'skipped': 'checked recently'})
		self.assertEqual(ServiceRun.objects.filter(service='archive-urls').count(), 1)
		self.assertIn('stored', self.run_lookup(force=True))

	def test_a_failing_archive_changes_nothing(self):
		def broken(*a, **k):
			raise OSError('archive.org unreachable')
		out = archive_urls.run_for_domain(self.domain.id, get=broken)
		self.assertIn('error', out)
		self.assertFalse(HostArchive.objects.exists())
		self.assertFalse(ServiceRun.objects.filter(service='archive-urls').exists())  # so the next run tries again

	def test_can_be_switched_off(self):
		with mock.patch.dict('os.environ', {'CVENGINE_ARCHIVE_LOOKUP': '0'}):
			self.assertEqual(self.run_lookup(), {'skipped': 'disabled'})

	def test_search_finds_php_history_and_says_it_is_historical(self):
		self.run_lookup()
		status, data = call(self.token, 'GET', '/api/v1/projects/arc-a/search?' + urlencode({'q': 'php'}))
		self.assertEqual(status, 200, data)
		self.assertEqual([h['host'] for h in data['results']], ['www.acme.example'])
		self.assertTrue(any(m.startswith('seen in web archive: PHP') for m in data['results'][0]['matched']), data)
		status, data = call(self.token, 'GET', '/api/v1/projects/arc-a/search?' + urlencode({'q': 'wordpress'}))
		self.assertEqual([h['host'] for h in data['results']], ['www.acme.example'])
