import io
import json
import os
import tempfile
from unittest import mock

from django.test import SimpleTestCase

from cveFeed import shot_worker


class FakePage:
	"""What Capturer touches of a Playwright page, with the answers a test sets. No browser is launched."""

	def __init__(self, goto=None, url='https://www.example.test/', title='Example', status=200, write=b'\x89PNG fake picture bytes', events=None):
		self._goto, self.url, self._title, self.status, self.write = goto, url, title, status, write
		self.handlers, self.routes, self.closed, self.screenshots, self.waits = {}, [], False, [], []
		self.events = events if events is not None else []

	def on(self, name, handler):
		self.handlers[name] = handler

	def route(self, pattern, handler):
		self.routes.append((pattern, handler))

	def goto(self, url, wait_until=None, timeout=None):
		self.events.append(('goto', url, wait_until, timeout))
		if isinstance(self._goto, Exception):
			raise self._goto
		return mock.Mock(status=self.status)

	def wait_for_load_state(self, state, timeout=None):
		self.waits.append((state, timeout))

	def wait_for_timeout(self, ms):
		self.waits.append(('settle', ms))

	def title(self):
		return self._title

	def screenshot(self, path=None, **options):
		self.screenshots.append((path, options))
		if self.write is not None:
			with open(path, 'wb') as handle:
				handle.write(self.write)

	def close(self):
		self.closed = True


class FakeContext:
	def __init__(self, page, options):
		self.page, self.options, self.closed = page, options, False

	def new_page(self):
		return self.page

	def close(self):
		self.closed = True


class FakeBrowser:
	def __init__(self, pages):
		self.pages, self.contexts, self.version = list(pages), [], '156.0.0.0'

	def new_context(self, **options):
		context = FakeContext(self.pages.pop(0), options)
		self.contexts.append(context)
		return context


PROXY = {'server': 'http://127.0.0.1:4555', 'password': 'secret'}


def capture(page, key='7', **settings):
	browser = FakeBrowser([page])
	directory = tempfile.mkdtemp()
	out = os.path.join(directory, f'{key}.png')
	result = shot_worker.Capturer(browser, {'proxy': PROXY, **settings}).capture({'key': key, 'url': 'https://www.example.test/', 'out': out})
	return result, browser, out


class CapturerTests(SimpleTestCase):
	def test_it_will_not_be_built_without_a_vetting_proxy(self):
		for proxy in (None, {}, {'server': 'http://127.0.0.1:1'}, {'password': 'x'}):
			with self.assertRaises(ValueError):
				shot_worker.Capturer(FakeBrowser([]), {'proxy': proxy})

	def test_a_page_is_captured_in_a_fresh_locked_down_context_through_the_proxy(self):
		page = FakePage(title='  Sign   in  ', status=403)
		result, browser, out = capture(page)
		self.assertEqual((result['outcome'], result['status'], result['title'], result['final_url']), ('ok', 403, 'Sign in', 'https://www.example.test/'))
		self.assertEqual(result['path'], out)
		self.assertGreater(os.path.getsize(out), 0)
		options = browser.contexts[0].options
		self.assertEqual(options['proxy'], {'server': PROXY['server'], 'username': '7', 'password': 'secret', 'bypass': '<-loopback>'})  # loopback is judged too, and the page is named
		self.assertTrue(options['ignore_https_errors'])
		self.assertFalse(options['accept_downloads'])
		self.assertEqual((options['service_workers'], options['permissions'], options['viewport']), ('block', [], {'width': 1280, 'height': 800}))
		self.assertTrue(page.closed and browser.contexts[0].closed)
		self.assertEqual(page.screenshots[0][1]['full_page'], False)
		self.assertIn('dialog', page.handlers)
		self.assertIn('popup', page.handlers)

	def test_each_page_gets_its_own_context_and_its_own_proxy_user(self):
		browser = FakeBrowser([FakePage(), FakePage()])
		capturer = shot_worker.Capturer(browser, {'proxy': PROXY})
		directory = tempfile.mkdtemp()
		for key in ('1', '2'):
			capturer.capture({'key': key, 'url': 'https://a.example.test/', 'out': os.path.join(directory, key + '.png')})
		self.assertEqual([c.options['proxy']['username'] for c in browser.contexts], ['1', '2'])
		self.assertEqual(len(browser.contexts), 2)

	def test_the_user_agent_and_timeouts_come_from_the_settings(self):
		page = FakePage()
		_result, browser, _out = capture(page, user_agent='UA/1', nav_timeout_ms=9000, total_seconds=12)
		self.assertEqual(browser.contexts[0].options['user_agent'], 'UA/1')
		self.assertLessEqual(page.events[0][3], 9000)
		self.assertEqual(page.events[0][2], 'domcontentloaded')

	def test_what_a_failed_navigation_raised_becomes_an_outcome_and_a_reason(self):
		for message, outcome in (('Page.goto: Timeout 15000ms exceeded.', 'timeout'), ('Page.goto: net::ERR_CONNECTION_REFUSED at x', 'unreachable'),
								 ('Page.goto: net::ERR_NAME_NOT_RESOLVED at x', 'unreachable'), ('Page.goto: net::ERR_SSL_PROTOCOL_ERROR at x', 'tls_error'),
								 ('Page.goto: net::ERR_TUNNEL_CONNECTION_FAILED at x', 'unreachable'), ('Page.goto: Download is starting', 'error'),
								 ('Page.goto: net::ERR_TOO_MANY_REDIRECTS at x', 'error'), ('Page.goto: something odd\nwith a second line', 'error')):
			page = FakePage(goto=Exception(message))
			result, browser, _out = capture(page)
			self.assertEqual(result['outcome'], outcome, message)
			self.assertTrue(result['reason'], message)
			self.assertNotIn('\n', result['reason'])
			self.assertTrue(page.closed and browser.contexts[0].closed, 'the context is closed whatever happened')
			self.assertEqual(result['path'], '')

	def test_a_browser_error_page_is_not_a_screenshot_of_the_site(self):
		result, _browser, _out = capture(FakePage(url='chrome-error://chromewebdata/'))
		self.assertEqual(result['outcome'], 'unreachable')
		self.assertEqual(result['path'], '')

	def test_an_empty_picture_is_an_error_not_a_capture(self):
		result, _browser, _out = capture(FakePage(write=b''))
		self.assertEqual(result['outcome'], 'error')

	def test_a_context_that_cannot_be_made_ends_that_page_only(self):
		browser = FakeBrowser([])
		browser.new_context = mock.Mock(side_effect=Exception('Target closed'))
		result = shot_worker.Capturer(browser, {'proxy': PROXY}).capture({'key': '1', 'url': 'https://a.example.test/', 'out': '/nonexistent/x.png'})
		self.assertEqual(result['outcome'], 'error')

	def test_waits_that_time_out_are_not_failures(self):
		page = FakePage()
		page.wait_for_load_state = mock.Mock(side_effect=Exception('Timeout'))
		result, _browser, _out = capture(page)
		self.assertEqual(result['outcome'], 'ok')  # a page that never goes idle is photographed as it is

	def test_dialogs_are_dismissed_and_popups_closed(self):
		page = FakePage()
		capture(page)
		dialog, popup = mock.Mock(), mock.Mock()
		page.handlers['dialog'](dialog)
		page.handlers['popup'](popup)
		dialog.dismiss.assert_called_once()
		popup.close.assert_called_once()

	def test_only_web_urls_leave_the_browser(self):
		page = FakePage()
		capture(page)
		handler = page.routes[0][1]
		for url, passes in (('https://a.example.test/x', True), ('http://a.example.test/', True), ('data:text/plain,hi', True), ('blob:https://a/1', True),
							('file:///etc/passwd', False), ('ftp://a.example.test/', False), ('chrome://settings', False), ('javascript:alert(1)', False)):
			route = mock.Mock()
			route.request.url = url
			handler(route)
			self.assertEqual(route.continue_.called, passes, url)
			self.assertEqual(route.abort.called, not passes, url)


class ProtocolTests(SimpleTestCase):
	def run_main(self, job):
		stdout = io.StringIO()
		code = shot_worker.main(stdin=io.StringIO(json.dumps(job) + '\n'), stdout=stdout)
		return code, [json.loads(line) for line in stdout.getvalue().splitlines()]

	def test_a_job_without_a_proxy_is_refused_before_any_browser_starts(self):
		with mock.patch.dict('sys.modules', {'playwright': None, 'playwright.sync_api': None}):
			code, lines = self.run_main({'targets': [{'key': '1', 'url': 'https://a/', 'out': '/tmp/x'}]})
		self.assertEqual(code, 2)
		self.assertEqual(lines[0]['op'], 'fatal')
		self.assertIn('vetting proxy', lines[0]['reason'])

	def test_a_missing_playwright_is_reported_not_raised(self):
		with mock.patch.dict('sys.modules', {'playwright': None, 'playwright.sync_api': None}):
			code, lines = self.run_main({'targets': [], 'proxy': PROXY})
		self.assertEqual((code, lines[0]['op']), (2, 'fatal'))
		self.assertIn('Playwright is not installed', lines[0]['reason'])


class ClassifyTests(SimpleTestCase):
	def test_every_outcome_has_plain_words(self):
		for message in ('Timeout 1ms exceeded', 'net::ERR_CERT_AUTHORITY_INVALID', 'net::ERR_EMPTY_RESPONSE', 'net::ERR_ADDRESS_UNREACHABLE', 'Target page, context or browser has been closed', '', None):
			outcome, reason = shot_worker.classify_error(message)
			self.assertIn(outcome, ('timeout', 'unreachable', 'tls_error', 'error'))
			self.assertTrue(reason)
