"""The certificate transparency watch's second source: Cert Spotter answers when crt.sh cannot, under its own pacing, hourly budget
and circuit; with the fallback off everything is as before. Every request is mocked: no test reaches crt.sh or Cert Spotter."""
import json
import os
from unittest import mock

import requests
from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from cveFeed import ctmonitor
from cveFeed.models import AgentActivity, DiscoveryEvent, HostExclusion
from dashboard.models import Org, Project, SystemTimings
from startScan.models import Subdomain
from targetApp.models import Domain

_KEYS = [f'cvengine:ct:circuit:{s}:{k}' for s in (ctmonitor.CRTSH, ctmonitor.CERTSPOTTER) for k in ('open', 'fails')] + \
	[ctmonitor._BUSY_KEY + s for s in (ctmonitor.CRTSH, ctmonitor.CERTSPOTTER)]


def reset_ct_state():
	"""Pacing, in-flight counts, circuits, busy marks and the hourly budget of both sources, so no test inherits another's."""
	for pacing in ctmonitor._PACING.values():
		pacing['local']['next'] = 0.0
		pacing['flight_local']['n'] = 0
	client = ctmonitor._redis()
	if client is not None:
		client.delete(*[p['slot'] for p in ctmonitor._PACING.values()], *[p['flight'] for p in ctmonitor._PACING.values()])
	import time
	hour = int(time.time() // 3600)
	cache.delete_many(_KEYS + [f'cvengine:certspotter:hour:{h}' for h in (hour - 1, hour, hour + 1)])


def reply(status=200, body=None, headers=None):
	r = mock.Mock()
	r.status_code, r.headers = status, headers or {}
	r.iter_content.side_effect = lambda size: iter([json.dumps(body if body is not None else []).encode()])
	if status >= 400:
		r.raise_for_status.side_effect = requests.HTTPError(f'{status}')
	else:
		r.raise_for_status.side_effect = None
	return r


def issuance(*names):
	return {'id': '1', 'dns_names': list(names), 'not_before': '2026-01-01T00:00:00Z'}


class Router:
	"""``requests.get`` stand-in: answers crt.sh and Cert Spotter from their own lists and records every call by source."""

	def __init__(self, crtsh=(), certspotter=()):
		self.replies = {ctmonitor.CRTSH: list(crtsh), ctmonitor.CERTSPOTTER: list(certspotter)}
		self.calls = {ctmonitor.CRTSH: [], ctmonitor.CERTSPOTTER: []}

	def __call__(self, url, params=None, timeout=None, stream=None):
		source = ctmonitor.CERTSPOTTER if url == ctmonitor.CERTSPOTTER_URL else ctmonitor.CRTSH
		assert url in (ctmonitor.CRT_SH_URL, ctmonitor.CERTSPOTTER_URL), url  # nothing ever goes to the target
		self.calls[source].append(params)
		queue = self.replies[source]
		answer = queue.pop(0) if len(queue) > 1 else queue[0]
		if isinstance(answer, Exception):
			raise answer
		return answer


class FallbackTestCase(TestCase):
	def setUp(self):
		reset_ct_state()
		self.addCleanup(reset_ct_state)
		for name, value in (('MIN_GAP', (0, 0)), ('CERTSPOTTER_GAP', (0, 0))):
			patcher = mock.patch.object(ctmonitor, name, value)
			patcher.start()
			self.addCleanup(patcher.stop)
		pipeline = mock.patch('cveFeed.tasks.host_pipeline.delay')
		pipeline.start()
		self.addCleanup(pipeline.stop)
		sleeper = mock.patch.object(ctmonitor.time, 'sleep')  # the real lookup sleeps out its slot: not in a test
		sleeper.start()
		self.addCleanup(sleeper.stop)
		real_push = ctmonitor.push_back
		# crt.sh's back-off between its attempts is recorded elsewhere (test_ctmonitor); here it would push its next attempt past the inline wait
		pusher = mock.patch.object(ctmonitor, 'push_back', side_effect=lambda seconds, now=None, source=ctmonitor.CRTSH:
		                           None if source == ctmonitor.CRTSH else real_push(seconds, source=source))
		pusher.start()
		self.addCleanup(pusher.stop)
		os.environ.pop('CVENGINE_CT_FALLBACK', None)
		self.addCleanup(os.environ.pop, 'CVENGINE_CT_FALLBACK', None)
		now = timezone.now()
		self.org = Org.objects.create(name='F', slug='ctf')
		self.project = Project.objects.create(name='F', slug='ctf-p', insert_date=now, org=self.org)
		self.domain = Domain.objects.create(name='fallback.test', project=self.project, insert_date=now)
		Subdomain.objects.create(target_domain=self.domain, name='fallback.test')

	def run_with(self, router):
		with mock.patch.object(ctmonitor.requests, 'get', side_effect=router):
			return ctmonitor.run_ct_watch(self.domain.id)

	def names(self):
		return set(Subdomain.objects.filter(target_domain=self.domain).values_list('name', flat=True))


class FallbackTests(FallbackTestCase):
	def test_crt_sh_down_and_cert_spotter_up_adds_the_hosts_with_the_source_recorded(self):
		HostExclusion.objects.create(org=self.org, host='excluded.fallback.test')
		router = Router(crtsh=[reply(502)], certspotter=[reply(200, [
			issuance('*.fallback.test', 'www.fallback.test', 'excluded.fallback.test'),
			issuance('api.fallback.test', 'fallback.test.evil.net', 'other.example', 'FALLBACK.TEST'),
		])])
		out = self.run_with(router)
		self.assertEqual(out, {'checked': 4, 'new': 2, 'source': 'certspotter'})  # fallback.test, www, api and the excluded one were in the reply
		self.assertEqual(self.names(), {'fallback.test', 'www.fallback.test', 'api.fallback.test'})  # outside the tree and excluded: dropped
		self.assertEqual(len(router.calls[ctmonitor.CRTSH]), ctmonitor.MAX_ATTEMPTS)  # crt.sh got its polite attempts first
		self.assertEqual(router.calls[ctmonitor.CERTSPOTTER], [{'domain': 'fallback.test', 'include_subdomains': 'true', 'expand': 'dns_names'}])
		events = DiscoveryEvent.objects.filter(domain=self.domain)
		self.assertEqual(set(events.values_list('module', flat=True)), {'ct-monitor:certspotter'})
		self.assertEqual(set(events.values_list('label', flat=True)), {'www.fallback.test', 'api.fallback.test'})
		line = AgentActivity.objects.get(kind='discovery', message__icontains='Certificate transparency').message
		self.assertIn('found by certspotter', line)

	def test_crt_sh_answering_never_calls_cert_spotter_and_keeps_its_events_as_today(self):
		router = Router(crtsh=[reply(200, [{'name_value': 'mail.fallback.test'}])], certspotter=[AssertionError('not asked')])
		self.assertEqual(self.run_with(router), {'checked': 1, 'new': 1})
		self.assertEqual(router.calls[ctmonitor.CERTSPOTTER], [])
		event = DiscoveryEvent.objects.get(host='mail.fallback.test')
		self.assertEqual((event.module, event.label, event.type, event.scan_id), ('ct-monitor', 'mail.fallback.test', 'DNS_NAME', None))

	def test_both_down_is_a_failure_as_before(self):
		router = Router(crtsh=[reply(502)], certspotter=[reply(503)])
		self.assertEqual(self.run_with(router), {'checked': 0, 'new': 0, 'failed': True})
		self.assertEqual(len(router.calls[ctmonitor.CERTSPOTTER]), ctmonitor.CERTSPOTTER_ATTEMPTS)
		self.assertEqual(self.names(), {'fallback.test'})

	def test_the_kill_switch_keeps_todays_behaviour(self):
		os.environ['CVENGINE_CT_FALLBACK'] = 'off'
		router = Router(crtsh=[reply(502)], certspotter=[AssertionError('not asked')])
		self.assertEqual(self.run_with(router), {'checked': 0, 'new': 0, 'failed': True})
		self.assertEqual(router.calls[ctmonitor.CERTSPOTTER], [])
		self.assertFalse(ctmonitor.fallback_enabled())

	def test_the_setting_off_keeps_todays_behaviour(self):
		t = SystemTimings.current()
		t.ct_fallback_source = False
		t.save()
		router = Router(crtsh=[reply(502)], certspotter=[AssertionError('not asked')])
		self.assertEqual(self.run_with(router), {'checked': 0, 'new': 0, 'failed': True})
		self.assertEqual(router.calls[ctmonitor.CERTSPOTTER], [])

	def test_the_setting_is_on_by_default(self):
		self.assertTrue(SystemTimings.current().ct_fallback_source)
		self.assertTrue(ctmonitor.fallback_enabled())

	def test_a_rate_limited_cert_spotter_is_not_retried_and_is_left_alone_for_the_hour(self):
		router = Router(crtsh=[reply(502)], certspotter=[reply(429, headers={'Retry-After': '3000'})])
		self.assertTrue(self.run_with(router)['failed'])
		self.assertEqual(len(router.calls[ctmonitor.CERTSPOTTER]), 1)
		with self.assertRaises(ctmonitor.CtBusy):  # every worker now waits it out: no request is made
			ctmonitor._fetch_certspotter('fallback.test', sleep=lambda s: None)
		self.assertEqual(len(router.calls[ctmonitor.CERTSPOTTER]), 1)

	def test_the_hourly_budget_is_shared_and_never_exceeded(self):
		router = Router(certspotter=[reply(200, [issuance('a.fallback.test')])])
		with mock.patch.object(ctmonitor.requests, 'get', side_effect=router), mock.patch.object(ctmonitor, 'CERTSPOTTER_PER_HOUR', 2):
			for _ in range(2):
				self.assertEqual(ctmonitor._fetch_certspotter('fallback.test', sleep=lambda s: None), {'a.fallback.test'})
			with self.assertRaises(ctmonitor.CtBusy) as busy:
				ctmonitor._fetch_certspotter('fallback.test', sleep=lambda s: None)
		self.assertEqual(busy.exception.source, 'certspotter')
		self.assertEqual(len(router.calls[ctmonitor.CERTSPOTTER]), 2)

	def test_a_remaining_count_of_zero_spends_the_budget(self):
		router = Router(certspotter=[reply(200, [], headers={'X-RateLimit-Remaining': '0'})])
		with mock.patch.object(ctmonitor.requests, 'get', side_effect=router):
			self.assertEqual(ctmonitor._fetch_certspotter('fallback.test', sleep=lambda s: None), set())
			with self.assertRaises(ctmonitor.CtBusy):
				ctmonitor._fetch_certspotter('fallback.test', sleep=lambda s: None)

	def test_cert_spotter_waiting_on_crt_sh_failure_is_a_failure_not_a_busy_loop(self):
		ctmonitor.push_back(500, source=ctmonitor.CERTSPOTTER)
		router = Router(crtsh=[reply(502)], certspotter=[AssertionError('not asked')])
		self.assertTrue(self.run_with(router)['failed'])
		self.assertEqual(router.calls[ctmonitor.CERTSPOTTER], [])

	def test_a_provider_domain_is_never_sent_to_cert_spotter(self):
		with mock.patch.object(ctmonitor.requests, 'get') as get:
			self.assertEqual(ctmonitor._fetch_certspotter('jfrog.com', sleep=lambda s: None), set())
		get.assert_not_called()

	def test_an_oversized_cert_spotter_reply_is_refused(self):
		big = mock.Mock(status_code=200, headers={})
		big.iter_content.side_effect = lambda size: iter([b'[' + b' ' * 40] * 3)
		with mock.patch.object(ctmonitor.requests, 'get', return_value=big), mock.patch.object(ctmonitor, 'MAX_BYTES', 100):
			self.assertIsNone(ctmonitor._fetch_certspotter('fallback.test', sleep=lambda s: None))
		big.close.assert_called()


class CircuitTests(FallbackTestCase):
	def test_a_source_that_fails_in_a_row_is_skipped_for_a_while_then_asked_again(self):
		router = Router(crtsh=[reply(502)], certspotter=[reply(200, [issuance('x.fallback.test')])])
		with mock.patch.object(ctmonitor.requests, 'get', side_effect=router):
			for _ in range(ctmonitor.CIRCUIT_FAILURES):
				ctmonitor.lookup('fallback.test', sleep=lambda s: None)
			self.assertTrue(ctmonitor.circuit_open(ctmonitor.CRTSH))
			asked = len(router.calls[ctmonitor.CRTSH])
			self.assertEqual(ctmonitor.lookup('fallback.test', sleep=lambda s: None), ({'x.fallback.test'}, 'certspotter'))
			self.assertEqual(len(router.calls[ctmonitor.CRTSH]), asked)  # skipped: not asked while its circuit is open
			cache.delete(f'cvengine:ct:circuit:{ctmonitor.CRTSH}:open')  # the few minutes passed
			router.replies[ctmonitor.CRTSH] = [reply(200, [{'name_value': 'y.fallback.test'}])]
			self.assertEqual(ctmonitor.lookup('fallback.test', sleep=lambda s: None), ({'y.fallback.test'}, 'crt.sh'))

	def test_with_the_fallback_off_an_open_circuit_does_not_skip_crt_sh(self):
		os.environ['CVENGINE_CT_FALLBACK'] = '0'
		cache.set(f'cvengine:ct:circuit:{ctmonitor.CRTSH}:open', 1, 600)
		router = Router(crtsh=[reply(200, [{'name_value': 'z.fallback.test'}])])
		with mock.patch.object(ctmonitor.requests, 'get', side_effect=router):
			self.assertEqual(ctmonitor.lookup('fallback.test', sleep=lambda s: None), ({'z.fallback.test'}, 'crt.sh'))

	def test_crt_sh_busy_for_long_asks_the_fallback_instead_of_waiting_more(self):
		cache.set(ctmonitor._BUSY_KEY + ctmonitor.CRTSH, 1.0, 3600)  # busy since long ago, no success since
		router = Router(certspotter=[reply(200, [issuance('b.fallback.test')])])
		with mock.patch.object(ctmonitor, '_fetch', side_effect=ctmonitor.CtBusy(200)), \
				mock.patch.object(ctmonitor.requests, 'get', side_effect=router):
			self.assertEqual(ctmonitor.lookup('fallback.test', sleep=lambda s: None), ({'b.fallback.test'}, 'certspotter'))

	def test_crt_sh_busy_for_a_moment_is_waited_for_as_today(self):
		router = Router(certspotter=[AssertionError('not asked')])
		with mock.patch.object(ctmonitor, '_fetch', side_effect=ctmonitor.CtBusy(200)), \
				mock.patch.object(ctmonitor.requests, 'get', side_effect=router):
			with self.assertRaises(ctmonitor.CtBusy):
				ctmonitor.lookup('fallback.test', sleep=lambda s: None)
		self.assertEqual(router.calls[ctmonitor.CERTSPOTTER], [])

	def test_crt_sh_busy_and_the_fallback_failing_stays_a_wait_not_a_failure(self):
		cache.set(ctmonitor._BUSY_KEY + ctmonitor.CRTSH, 1.0, 3600)
		router = Router(certspotter=[reply(503)])
		with mock.patch.object(ctmonitor, '_fetch', side_effect=ctmonitor.CtBusy(200)), \
				mock.patch.object(ctmonitor.requests, 'get', side_effect=router):
			with self.assertRaises(ctmonitor.CtBusy) as busy:
				ctmonitor.lookup('fallback.test', sleep=lambda s: None)
		self.assertEqual(busy.exception.source, 'crt.sh')


class OtherSitesTests(FallbackTestCase):
	def test_names_either_source_found_are_asked_at_each_web_address(self):
		from cveFeed import vhost_scan
		for module, host in (('ct-monitor', 'one.fallback.test'), ('ct-monitor:certspotter', 'two.fallback.test')):
			DiscoveryEvent.objects.create(scan=None, domain=self.domain, type='DNS_NAME', label=host, host=host, parent_host='fallback.test', module=module)
		names = vhost_scan.known_names(self.project.id)
		self.assertIn('one.fallback.test', names)
		self.assertIn('two.fallback.test', names)


class ParseCertSpotterTests(TestCase):
	def test_reads_the_dns_names_of_the_domains_own_tree_only(self):
		got = ctmonitor.parse_certspotter([issuance('*.ex.test', 'www.ex.test', 'ex.test.attacker.net'), {'dns_names': None}, 'junk',
		                                   issuance('Deep.API.ex.test.', 'not a name')], 'ex.test')
		self.assertEqual(got, {'ex.test', 'www.ex.test', 'deep.api.ex.test'})
		self.assertEqual(ctmonitor.parse_certspotter({'error': 'x'}, 'ex.test'), set())


class TimingsSwitchTests(TestCase):
	def setUp(self):
		self.root = User.objects.create_superuser('ctroot', password='x')

	def test_an_app_admin_turns_the_fallback_off_and_on(self):
		from tests.test_admin import api
		from tests.test_tenancy import client_for
		c = client_for(self.root)
		status, data = api(c, 'GET', 'timings')
		self.assertEqual((status, data['ct_fallback_source']), (200, True))
		self.assertEqual(api(c, 'PUT', 'timings', {'ct_fallback_source': 'nope'})[0], 400)
		status, data = api(c, 'PUT', 'timings', {'ct_fallback_source': False})
		self.assertEqual((status, data['ct_fallback_source']), (200, False))
		self.assertFalse(SystemTimings.current().ct_fallback_source)
		self.assertEqual(SystemTimings.current().ct_watch_minutes, 20)  # untouched
		with mock.patch.dict(os.environ, {'CVENGINE_CT_FALLBACK': '0'}):
			api(c, 'PUT', 'timings', {'ct_fallback_source': True})
			self.assertTrue(api(c, 'GET', 'timings')[1]['ct_fallback_forced_off'])
