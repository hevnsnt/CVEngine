import unittest

from django.test import TestCase

from cvengine_scanner import fingerprint

from cveFeed import js_libraries, route_auth
from cveFeed.models import RouteAuth
from startScan.models import Subdomain
from tests import route_scanner
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
		every, _ = js_libraries.script_sources(PAGE, 'https://www.rt.test/')
		found = js_libraries.from_script_urls(every)
		self.assertEqual([n for n, _src in found], ['jQuery:3.4.1', 'Vue.js:3.3.4', 'jQuery'])  # ?ver=3.7.1 is the asset's cache-buster
		self.assertEqual({src for _n, src in found}, {'script:filename'})

	def test_only_same_host_scripts_are_read(self):
		every, local = js_libraries.script_sources(PAGE, 'https://www.rt.test/')
		self.assertEqual(local, ['https://www.rt.test/assets/jquery-3.4.1.min.js', 'https://www.rt.test/wp-includes/js/jquery/jquery.min.js?ver=3.7.1',
							   'https://www.rt.test/static/app.js'])
		self.assertIn('https://other.example/x.js', every)

	def test_a_script_banner_names_the_library(self):
		self.assertEqual(js_libraries.from_script_body('/*! jQuery v3.5.1 | (c) JS Foundation */ var a')[0][0], 'jQuery:3.5.1')
		self.assertEqual(js_libraries.from_script_body('/*! Bootstrap v4.6.0 (https://getbootstrap.com/) */')[0][0], 'Bootstrap:4.6.0')
		self.assertEqual(js_libraries.from_script_body('/** @license React v17.0.2 */')[0][0], 'React:17.0.2')
		self.assertEqual(js_libraries.from_script_body('var nothing = 1;'), [])
		self.assertEqual(js_libraries.from_script_body('x' * 5000 + '/*! jQuery v3.5.1 */'), [])  # only the head of a script counts

	def test_angular_and_categories(self):
		names = [f['name'] for f in fingerprint.from_response(body=PAGE, content_type='text/html', from_scripts=js_libraries.script_fingerprints(['/a/jquery-1.12.4.js']))]
		self.assertIn('Angular:15.2.9', names)
		self.assertIn('jQuery:1.12.4', names)
		self.assertEqual(fingerprint.categorize('jQuery:3.4.1'), 'javascript library')

	def test_extend_prefers_a_versioned_name_and_stays_capped(self):
		out = fingerprint.extend([{'name': 'jQuery', 'source': 'x'}], [('jQuery:3.4.1', 'script:banner')])
		self.assertEqual([f['name'] for f in out], ['jQuery:3.4.1'])
		many = fingerprint.extend([], [(f'Lib{i}', 's') for i in range(50)])
		self.assertEqual(len(many), fingerprint.MAX_FINGERPRINTS)


class ScriptReadingTests(RouteFixture, TestCase):
	"""The scanner reads the scripts a front page loads (cvengine_scanner/tests/probes/test_routes.py: a script of the front page is read and its library
	recorded, a script outside the policy is not read); the server stores what it reports with the route and joins it to the host's technologies."""

	def setUp(self):
		super().setUp()
		self.scan_obj = self.scan()

	def test_what_the_scanner_read_in_the_scripts_is_stored_with_the_route_and_joins_the_hosts_technologies(self):
		names = ['jQuery:3.4.1', 'Bootstrap:3.3.7', 'Vue.js:3.3.4']

		def front_page_only(url):
			return probe(url=url, body=PAGE) if url.rstrip('/') == 'https://www.rt.test' else probe(url=url, status=404)

		def serve(task):
			out = route_scanner.result(task, front_page_only)
			for row in out['routes']:
				if row['id'] == 'https://www.rt.test/':  # the scanner read the scripts: their banners and the CDN path are in what it reports
					row['evidence'].update({'fingerprints': [{'name': n, 'source': 'script:banner'} for n in names], 'fingerprint_names': names,
											'script_urls': ['https://www.rt.test/assets/jquery-3.4.1.min.js']})
			return out
		self.scanner().responders['route_probe'] = serve
		route_auth.run_route_auth(self.scan_obj.id)
		root = RouteAuth.objects.get(path='/')
		self.assertNotIn('local_scripts', root.evidence)
		self.assertNotIn('page_scripts', root.evidence)
		self.assertEqual(root.evidence['fingerprint_names'], names)
		route_auth.link_technologies(self.scan_obj, {root.url: {'evidence': root.evidence}})
		sub = Subdomain.objects.get(scan_history=self.scan_obj)
		self.assertIn('Bootstrap:3.3.7', [t.name for t in sub.technologies.all()])
