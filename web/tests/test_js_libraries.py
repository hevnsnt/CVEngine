import unittest

from django.test import TestCase

from cveFeed import fingerprint, route_auth
from cveFeed.models import RouteAuth
from startScan.models import Subdomain
from tests.test_route_auth import RouteFixture, probe

PAGE = """<html><head>
<script src="/assets/jquery-3.4.1.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/vue/3.3.4/vue.global.js"></script>
<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
<script src="/static/app.js"></script>
<script src="https://other.example/x.js"></script>
</head><body ng-version="15.2.9"></body></html>"""


class LibraryDetectionTests(unittest.TestCase):
	def test_script_names_are_hints_and_a_query_string_is_never_a_version(self):
		every, _ = fingerprint.script_sources(PAGE, 'https://www.rt.test/')
		found = fingerprint.from_script_urls(every)
		self.assertEqual([n for n, _src in found], ['jQuery:3.4.1', 'Vue.js:3.3.4', 'jQuery'])  # ?ver=3.7.1 is the asset's cache-buster
		self.assertEqual({src for _n, src in found}, {'script:filename'})

	def test_only_same_host_scripts_are_read(self):
		every, local = fingerprint.script_sources(PAGE, 'https://www.rt.test/')
		self.assertEqual(local, ['https://www.rt.test/assets/jquery-3.4.1.min.js', 'https://www.rt.test/wp-includes/js/jquery/jquery.min.js?ver=3.7.1',
							   'https://www.rt.test/static/app.js'])
		self.assertIn('https://other.example/x.js', every)

	def test_a_script_banner_names_the_library(self):
		self.assertEqual(fingerprint.from_script_body('/*! jQuery v3.5.1 | (c) JS Foundation */ var a')[0][0], 'jQuery:3.5.1')
		self.assertEqual(fingerprint.from_script_body('/*! Bootstrap v4.6.0 (https://getbootstrap.com/) */')[0][0], 'Bootstrap:4.6.0')
		self.assertEqual(fingerprint.from_script_body('/** @license React v17.0.2 */')[0][0], 'React:17.0.2')
		self.assertEqual(fingerprint.from_script_body('var nothing = 1;'), [])
		self.assertEqual(fingerprint.from_script_body('x' * 5000 + '/*! jQuery v3.5.1 */'), [])  # only the head of a script counts

	def test_angular_and_categories(self):
		names = [f['name'] for f in fingerprint.from_response(body=PAGE, content_type='text/html', scripts=['/a/jquery-1.12.4.js'])]
		self.assertIn('Angular:15.2.9', names)
		self.assertIn('jQuery:1.12.4', names)
		self.assertEqual(fingerprint.categorize('jQuery:3.4.1'), 'javascript library')

	def test_extend_prefers_a_versioned_name_and_stays_capped(self):
		out = fingerprint.extend([{'name': 'jQuery', 'source': 'x'}], [('jQuery:3.4.1', 'script:banner')])
		self.assertEqual([f['name'] for f in out], ['jQuery:3.4.1'])
		many = fingerprint.extend([], [(f'Lib{i}', 's') for i in range(50)])
		self.assertEqual(len(many), fingerprint.MAX_FINGERPRINTS)


class ScriptReadingTests(RouteFixture, TestCase):
	def setUp(self):
		super().setUp()
		self.scan_obj = self.scan()

	def run_check(self, scripts):
		def fake(url):
			if url.endswith('/'):
				return probe(url=url, body=PAGE)
			if '.js' in url:
				fetched.append(url)
			return probe(url=url, content_type='application/javascript', body=scripts.get(url.rsplit('/', 1)[-1].split('?')[0], ''))
		fetched = []
		route_auth.run_route_auth(self.scan_obj.id, probe=fake)
		return fetched

	def test_script_banners_join_the_hosts_fingerprints_and_technologies(self):
		fetched = self.run_check({'jquery-3.4.1.min.js': '/*! jQuery v3.4.1 | MIT */', 'app.js': '/*! Bootstrap v3.3.7 */'})
		# the three same-host scripts and the library on a public CDN; never the script of another site
		self.assertEqual(len(fetched), 4)
		self.assertNotIn('https://other.example/x.js', fetched)
		root = RouteAuth.objects.get(path='/')
		self.assertNotIn('local_scripts', root.evidence)
		self.assertNotIn('page_scripts', root.evidence)
		self.assertIn('jQuery:3.4.1', root.evidence['fingerprint_names'])
		self.assertIn('Bootstrap:3.3.7', root.evidence['fingerprint_names'])
		self.assertIn('Vue.js:3.3.4', root.evidence['fingerprint_names'])  # its file states nothing here: the CDN path is the hint
		self.assertEqual(root.evidence['libraries']['vue']['version_source'], 'filename')
		route_auth.link_technologies(self.scan_obj, {root.url: {'evidence': root.evidence}})
		sub = Subdomain.objects.get(scan_history=self.scan_obj)
		self.assertIn('Bootstrap:3.3.7', [t.name for t in sub.technologies.all()])

	def test_an_unreadable_script_does_not_stop_the_check(self):
		def fake(url):
			if url.endswith('/'):
				return probe(url=url, body=PAGE)
			raise OSError('reset')
		route_auth.run_route_auth(self.scan_obj.id, probe=fake)
		root = RouteAuth.objects.get(path='/')
		self.assertIn('jQuery:3.4.1', root.evidence['fingerprint_names'])  # from the script name alone
