import gzip
import time

from django.test import SimpleTestCase, TestCase

from cveFeed import fingerprint, hygiene, intel, mailfail, route_auth


class BodyRegexTests(SimpleTestCase):
	def timed(self, fn):
		started = time.monotonic()
		result = fn()
		self.assertLess(time.monotonic() - started, 1.5)
		return result

	def test_pathological_pages_are_read_in_linear_time(self):
		for tag in ('<meta ', '<script ', '<input ', '<meta name="generator" '):
			body = tag * (64 * 1024 // len(tag))
			self.timed(lambda: fingerprint.from_response(body=body, content_type='text/html'))
			self.timed(lambda: fingerprint.script_srcs(body))
			self.timed(lambda: route_auth.PASSWORD_INPUT_RE.search(body))
			self.timed(lambda: route_auth.META_REFRESH_RE.search(body))

	def test_real_markup_still_matches(self):
		html = '<html><head><meta name="generator" content="WordPress 6.4.2"><script src="/js/jquery-3.6.0.min.js"></script></head></html>'
		self.assertEqual(fingerprint.generator_content(html), 'WordPress 6.4.2')
		self.assertEqual(fingerprint.generator_content('<meta content="Drupal 10" name="generator">'), 'Drupal 10')
		self.assertEqual(fingerprint.script_srcs(html), ['/js/jquery-3.6.0.min.js'])
		self.assertTrue(route_auth.PASSWORD_INPUT_RE.search('<form><input class="x" type="password" name="p">'))
		match = route_auth.META_REFRESH_RE.search('<meta http-equiv="refresh" content="0; url=/login">')
		self.assertEqual(match.group(1), '/login')


class SpfBudgetTests(SimpleTestCase):
	def test_a_wide_include_tree_stops_at_the_query_budget(self):
		asked = []

		def fetch(domain):
			asked.append(domain)
			return ['v=spf1 ' + ' '.join(f'include:n{i}.{domain}' for i in range(40)) + ' -all']

		count = hygiene.count_spf_lookups('evil.example', fetch)
		self.assertLessEqual(len(asked), hygiene.SPF_MAX_QUERIES)
		self.assertGreater(count, hygiene.SPF_LOOKUP_LIMIT)

	def test_mailfail_takes_a_bounded_list_of_domains(self):
		record = ['v=spf1 ' + ' '.join(f'include:n{i}.example' for i in range(500)) + ' -all']
		self.assertEqual(len(mailfail.spf_referenced_domains(record)), mailfail.SPF_MAX_DOMAINS)


class FeedDecompressionTests(SimpleTestCase):
	def test_epss_still_parses(self):
		raw = gzip.compress(b'#model\ncve,epss,percentile\nCVE-2024-0001,0.5,0.9\n')
		self.assertEqual(intel.parse_epss(raw), {'CVE-2024-0001': [0.5, 0.9]})

	def test_an_expanding_file_is_refused(self):
		bomb = gzip.compress(b'0' * (3 * 1024 * 1024))
		with self.assertRaises(intel.SourceError):
			intel._gunzip(bomb, 1024 * 1024)


class RunCommandRedactionTests(TestCase):
	def test_a_redacted_secret_is_not_logged_or_stored_but_the_command_still_runs(self):
		from startScan.models import Command

		from reNgine.tasks import run_command
		with self.assertLogs('reNgine.tasks', level='INFO') as logs:
			code, output = run_command('echo -a key-abc-123456', redact=('key-abc-123456',))
		self.assertEqual(code, 0)
		self.assertIn('key-abc-123456', output)  # the process really received it
		stored = Command.objects.latest('id').command
		self.assertEqual(stored, 'echo -a ***')
		self.assertNotIn('key-abc-123456', '\n'.join(logs.output))
