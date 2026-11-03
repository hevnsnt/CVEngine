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


def proc(cmdline, nspid=('10',), userns='user:[1]', filters=1):
	return {'pid': 0, 'cmdline': cmdline, 'nspid': list(nspid), 'userns': userns, 'filters': filters}


OWN = proc('python3 shot_worker.py')
BROWSER = proc('/opt/pw-browsers/chrome-headless-shell --headless --remote-debugging-pipe')
RENDERER = proc('/opt/pw-browsers/chrome-headless-shell --type=renderer', nspid=('40', '4', '1'), userns='user:[2]', filters=2)


class SandboxTests(SimpleTestCase):
	"""Chromium's sandbox: what counts as engaged, and a browser without it is never used (the real processes are checked by the image test in CI)."""

	def test_only_a_renderer_in_its_own_user_and_pid_namespace_under_its_own_seccomp_filter_counts(self):
		self.assertEqual(shot_worker.judge_sandbox([BROWSER, RENDERER], OWN), '')
		self.assertIn('--no-sandbox', shot_worker.judge_sandbox([proc(BROWSER['cmdline'] + ' --no-sandbox'), RENDERER], OWN))
		self.assertIn('no renderer', shot_worker.judge_sandbox([BROWSER], OWN))
		self.assertIn('PID namespace', shot_worker.judge_sandbox([BROWSER, {**RENDERER, 'nspid': ['40']}], OWN))
		self.assertIn('user namespace', shot_worker.judge_sandbox([BROWSER, {**RENDERER, 'userns': OWN['userns']}], OWN))
		self.assertIn('seccomp', shot_worker.judge_sandbox([BROWSER, {**RENDERER, 'filters': 1}], OWN))

	def launcher(self, launched=None, error=None):
		browser = mock.Mock(version='156.0.0.0')

		def launch(**kwargs):
			if error:
				raise error
			(launched if launched is not None else []).append(kwargs)
			return browser
		return mock.Mock(chromium=mock.Mock(launch=launch)), browser

	def test_the_browser_is_launched_with_its_sandbox_and_checked_before_it_is_used(self):
		launched = []
		playwright, browser = self.launcher(launched)
		self.assertIs(shot_worker.launch(playwright, verify=lambda b: ''), browser)
		self.assertIs(launched[0]['chromium_sandbox'], True)
		with self.assertRaisesRegex(shot_worker.SandboxError, 'did not engage: the renderer shares'):
			shot_worker.launch(playwright, verify=lambda b: 'the renderer shares the user namespace of the browser')
		browser.close.assert_called()  # a browser without its sandbox is closed, never handed back
		with self.assertRaisesRegex(shot_worker.SandboxError, 'could not run'):
			shot_worker.launch(playwright, verify=mock.Mock(side_effect=RuntimeError('boom')))
		shot_worker.launch(playwright, sandbox=False, verify=mock.Mock(side_effect=AssertionError('not checked')))
		self.assertIs(launched[-1]['chromium_sandbox'], False)  # CVENGINE_SCREENSHOT_SANDBOX=0

	def test_a_sandbox_that_cannot_start_is_told_in_plain_words(self):
		for message, words in (('[FATAL:zygote_host_impl_linux.cc(128)] No usable sandbox! If you are running on Ubuntu', 'user namespaces'),
							   ('Running as root without --no-sandbox is not supported. See https://crbug.com/638180.', 'as root')):
			playwright, _ = self.launcher(error=RuntimeError('BrowserType.launch: Target page, context or browser has been closed\n' + message))
			with self.assertRaisesRegex(shot_worker.SandboxError, words):
				shot_worker.launch(playwright)
		playwright, _ = self.launcher(error=RuntimeError('Executable does not exist'))
		with self.assertRaisesRegex(RuntimeError, 'Executable'):
			shot_worker.launch(playwright)  # any other failure is not called a sandbox problem

	def test_the_batch_child_loads_nothing_when_the_sandbox_fails_and_says_so(self):
		fake = mock.Mock()
		fake.sync_playwright.return_value.__enter__ = mock.Mock(return_value=mock.Mock())
		fake.sync_playwright.return_value.__exit__ = mock.Mock(return_value=False)
		with mock.patch.dict('sys.modules', {'playwright': mock.Mock(), 'playwright.sync_api': fake}), \
				mock.patch.object(shot_worker, 'launch', side_effect=shot_worker.SandboxError(shot_worker.NO_USERNS)) as launch, \
				mock.patch.object(shot_worker, 'Capturer') as capturer:
			stdout = io.StringIO()
			code = shot_worker.main(stdin=io.StringIO(json.dumps({'targets': [{'key': '1', 'url': 'https://a/', 'out': '/tmp/x'}], 'proxy': PROXY}) + '\n'), stdout=stdout)
		lines = [json.loads(line) for line in stdout.getvalue().splitlines()]
		self.assertEqual((code, lines[0]['op']), (4, 'fatal'))
		self.assertTrue(lines[0]['reason'].startswith(shot_worker.SANDBOX_PREFIX + "Chromium's sandbox could not start"))
		self.assertIs(launch.call_args.kwargs['sandbox'], True)  # on unless the parent says otherwise
		capturer.assert_not_called()


class ClassifyTests(SimpleTestCase):
	def test_every_outcome_has_plain_words(self):
		for message in ('Timeout 1ms exceeded', 'net::ERR_CERT_AUTHORITY_INVALID', 'net::ERR_EMPTY_RESPONSE', 'net::ERR_ADDRESS_UNREACHABLE', 'Target page, context or browser has been closed', '', None):
			outcome, reason = shot_worker.classify_error(message)
			self.assertIn(outcome, ('timeout', 'unreachable', 'tls_error', 'error'))
			self.assertTrue(reason)
