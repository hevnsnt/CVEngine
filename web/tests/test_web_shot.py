import io
import os
import shutil
import sys
import tempfile
import textwrap
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import web_shot
from cveFeed.models import HostExclusion, HostScreenshot, HostState, InternalRange
from dashboard.models import Org, Project, ProjectMembership
from startScan.models import IpAddress, Port, Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call
from tests.test_route_auth import RouteFixture
from tests.test_service_intel import RDP_ENC, RDP_NLA_ONLY

from PIL import Image


def png(width=60, height=40, flat=False, noise=0):
	"""PNG bytes of a picture with something in it (or one flat color). ``noise`` makes it different from every other number: a few dots up to 1000,
	random pixels everywhere above that (which a PNG cannot compress, for the size-cap tests)."""
	import random
	image = Image.new('RGB', (width, height), (30, 60, 120))
	if not flat:
		for x in range(width):
			image.putpixel((x, height // 2), (250, 250, 250))
		rng = random.Random(noise)
		if noise > 1000:
			image = Image.frombytes('RGB', (width, height), rng.randbytes(width * height * 3))
		else:
			for _ in range(noise):
				image.putpixel((rng.randrange(width), rng.randrange(height)), (rng.randrange(256), rng.randrange(256), rng.randrange(256)))
	buf = io.BytesIO()
	image.save(buf, 'PNG')
	return buf.getvalue()


class ShotFixture(RouteFixture):
	"""A project with a target, a media directory of its own, and the browser reported as installed (no browser is ever launched here)."""

	def setUp(self):
		super().setUp()
		self.media = tempfile.mkdtemp()
		self.addCleanup(shutil.rmtree, self.media, ignore_errors=True)
		override = override_settings(MEDIA_ROOT=self.media)
		override.enable()
		self.addCleanup(override.disable)
		mock.patch.object(web_shot, 'browser_installed', return_value=True).start()
		self.kicked = mock.patch('cveFeed.tasks.drain_screenshots.apply_async').start()
		cache.clear()

	def host(self, name='www.rt.test', ports=((443, 'https'), (80, 'http')), address='203.0.113.5', **fields):
		scan = self.scan(names=(name,), ports=ports, ip=address)
		sub = Subdomain.objects.get(scan_history=scan, name=name)
		if fields:
			Subdomain.objects.filter(pk=sub.pk).update(**fields)
		return self.fresh(sub)

	def fresh(self, sub):
		return Subdomain.objects.filter(pk=sub.pk).select_related('target_domain').prefetch_related('ip_addresses__ports').get()

	def rows(self, **filters):
		return {(r.scheme, r.port): r for r in HostScreenshot.objects.filter(project=self.project, **filters)}

	def make_row(self, host='www.rt.test', scheme='https', port=443, **fields):
		fields.setdefault('outcome', 'queued')
		fields.setdefault('domain', self.domain)
		return HostScreenshot.objects.create(project=self.project, host=host, scheme=scheme, port=port, **fields)

	def plant(self, rel, data=None):
		full = os.path.join(self.media, rel)
		os.makedirs(os.path.dirname(full), exist_ok=True)
		with open(full, 'wb') as handle:
			handle.write(data if data is not None else png())
		return full


# ------------------------------------------------------------------------------------------------ choosing the pages

class TargetSelectionTests(ShotFixture, TestCase):
	def test_every_open_http_port_is_a_page_https_first_then_80_then_the_rest(self):
		sub = self.host(ports=((22, 'ssh'), (8080, 'http-proxy'), (80, 'http'), (8443, 'https-alt'), (443, 'https'), (3389, 'ms-wbt-server')))
		self.assertEqual(web_shot.web_targets(sub), [('https', 443), ('http', 80), ('http', 8080), ('https', 8443)])

	def test_a_tls_web_service_nmap_calls_http_is_asked_over_https(self):
		sub = self.host(ports=((80, 'http'),))
		port = Port.objects.create(number=10443, service_name='http', state='open', extra={'tunnel': 'ssl'})
		sub.ip_addresses.first().ports.add(port)
		self.assertIn(('https', 10443), web_shot.web_targets(self.fresh(sub)))

	def test_a_known_web_port_counts_even_when_the_service_was_not_identified(self):
		sub = self.host(ports=((8888, 'unknown'),))
		self.assertEqual(web_shot.web_targets(sub), [('http', 8888)])

	def test_closed_filtered_and_udp_ports_are_not_pages(self):
		sub = self.host(ports=((443, 'https'),))
		ip = sub.ip_addresses.first()
		ip.ports.add(Port.objects.create(number=8080, service_name='http', state='closed'), Port.objects.create(number=8000, service_name='http', state='filtered'),
					 Port.objects.create(number=8081, service_name='http', state='open', protocol='udp'))
		self.assertEqual(web_shot.web_targets(self.fresh(sub)), [('https', 443)])

	def test_the_page_the_hosts_own_url_names_is_included(self):
		sub = self.host(ports=(), http_url='https://www.rt.test:9999/login')
		self.assertEqual(web_shot.web_targets(sub), [('https', 9999)])

	def test_a_host_nothing_is_known_about_has_no_pages_unless_a_person_asks(self):
		sub = self.host(ports=((22, 'ssh'),))
		self.assertEqual(web_shot.web_targets(sub), [])
		self.assertEqual(web_shot.web_targets(sub, manual=True), [('https', 443), ('http', 80)])

	def test_a_host_behind_a_cdn_is_photographed_on_80_and_443_only(self):
		sub = self.host(ports=((443, 'https'), (80, 'http'), (8080, 'http-proxy'), (8443, 'https-alt'), (2082, 'http'), (2083, 'https')))
		IpAddress.objects.filter(address='203.0.113.5').update(is_cdn=True)
		self.assertEqual(web_shot.web_targets(self.fresh(sub)), [('https', 443), ('http', 80)])
		IpAddress.objects.filter(address='203.0.113.5').update(is_cdn=False)
		Subdomain.objects.filter(pk=sub.pk).update(is_cdn=True)
		self.assertEqual(web_shot.web_targets(self.fresh(sub)), [('https', 443), ('http', 80)])

	def test_a_host_with_many_web_ports_is_capped(self):
		sub = self.host(ports=tuple((8000 + i, 'http') for i in range(12)))
		self.assertEqual(len(web_shot.web_targets(sub)), web_shot.MAX_PORTS_PER_HOST)

	def test_urls_name_the_host_not_the_address_and_leave_default_ports_out(self):
		self.assertEqual(web_shot.url_for('www.rt.test', 'https', 443), 'https://www.rt.test/')
		self.assertEqual(web_shot.url_for('www.rt.test', 'http', 80), 'http://www.rt.test/')
		self.assertEqual(web_shot.url_for('www.rt.test', 'https', 8443), 'https://www.rt.test:8443/')
		self.assertEqual(web_shot.url_for('2001:db8::1', 'http', 8080), 'http://[2001:db8::1]:8080/')


class RdpOutcomeTests(ShotFixture, TestCase):
	def sub_with(self, script):
		sub = self.host(ports=())
		extra = {'scripts': {'rdp-enum-encryption': script}} if script is not None else {}
		sub.ip_addresses.first().ports.add(Port.objects.create(number=3389, service_name='ms-wbt-server', state='open', extra=extra))
		return self.fresh(sub)

	def test_a_server_that_insists_on_nla_is_an_outcome_not_nothing(self):
		out = web_shot.rdp_outcomes(self.sub_with(RDP_NLA_ONLY))
		self.assertEqual([port for port, _ in out], [3389])
		self.assertIn('Network Level Authentication', out[0][1])

	def test_a_server_that_accepts_a_connection_without_nla_is_left_to_the_rdp_capture(self):
		self.assertEqual(web_shot.rdp_outcomes(self.sub_with(RDP_ENC)), [])

	def test_a_server_nothing_was_learned_about_is_not_called_nla(self):
		self.assertEqual(web_shot.rdp_outcomes(self.sub_with(None)), [])

	def test_queueing_records_the_nla_outcome_on_its_own_row(self):
		sub = self.sub_with(RDP_NLA_ONLY)
		web_shot.queue_for_subs([sub], self.project.pk)
		row = HostScreenshot.objects.get(project=self.project, scheme='rdp', port=3389)
		self.assertEqual(row.outcome, 'nla_required')
		self.assertIn('sign-in', row.reason)


# ------------------------------------------------------------------------------------------------ queueing

class QueueTests(ShotFixture, TestCase):
	def test_planning_writes_a_queued_row_per_page_and_never_captures(self):
		sub = self.host()
		out = web_shot.queue_for_subs([sub], self.project.pk)
		self.assertEqual((out['queued'], out['hosts']), (2, 1))
		rows = self.rows()
		self.assertEqual(set(rows), {('https', 443), ('http', 80)})
		self.assertTrue(all(r.outcome == 'queued' and r.queued_at and not r.image_path and not r.by_person for r in rows.values()))
		self.assertEqual(rows[('https', 443)].domain_id, self.domain.pk)
		self.assertEqual(HostScreenshot.objects.get(scheme='https').host, 'www.rt.test')

	def test_planning_twice_is_idempotent(self):
		sub = self.host()
		web_shot.queue_for_subs([sub], self.project.pk)
		again = web_shot.queue_for_subs([sub], self.project.pk)
		self.assertEqual((again['queued'], again['kept']), (0, 2))
		self.assertEqual(HostScreenshot.objects.count(), 2)

	def test_a_capture_inside_its_window_is_kept_and_an_old_one_is_asked_again(self):
		sub = self.host(ports=((443, 'https'),))
		now = timezone.now()
		row = self.make_row(outcome='ok', captured_at=now - timedelta(hours=10), image_path='x.png')
		self.assertEqual(web_shot.queue_for_subs([sub], self.project.pk)['kept'], 1)
		HostScreenshot.objects.filter(pk=row.pk).update(captured_at=now - web_shot.ttl() - timedelta(hours=1))
		out = web_shot.queue_for_subs([sub], self.project.pk)
		self.assertEqual(out['queued'], 1)
		row.refresh_from_db()
		self.assertEqual((row.outcome, row.image_path), ('queued', 'x.png'))  # the old picture stays until the new one arrives

	def test_force_asks_again_inside_the_window(self):
		sub = self.host(ports=((443, 'https'),))
		self.make_row(outcome='ok', captured_at=timezone.now(), image_path='x.png')
		self.assertEqual(web_shot.queue_for_subs([sub], self.project.pk, force=True)['queued'], 1)

	def test_a_failed_page_is_not_retried_inside_the_retry_window(self):
		sub = self.host(ports=((443, 'https'),))
		row = self.make_row(outcome='timeout', attempted_at=timezone.now() - timedelta(hours=2))
		self.assertEqual(web_shot.queue_for_subs([sub], self.project.pk)['kept'], 1)
		HostScreenshot.objects.filter(pk=row.pk).update(attempted_at=timezone.now() - web_shot.retry_after() - timedelta(hours=1))
		self.assertEqual(web_shot.queue_for_subs([sub], self.project.pk)['queued'], 1)

	def test_a_person_asking_marks_the_row_even_when_it_was_already_queued(self):
		sub = self.host(ports=((443, 'https'),))
		web_shot.queue_for_subs([sub], self.project.pk)
		web_shot.queue_for_subs([sub], self.project.pk, by_person=True)
		self.assertTrue(HostScreenshot.objects.get().by_person)

	def test_one_scan_queues_at_most_the_cap_and_the_backfill_takes_the_rest(self):
		subs = [self.host(name=f'h{i}.rt.test', address=f'203.0.113.{10 + i}', ports=((443, 'https'),)) for i in range(5)]
		with mock.patch.dict(os.environ, {'CVENGINE_SCREENSHOT_MAX_PER_SCAN': '3'}):
			out = web_shot.queue_for_subs(subs, self.project.pk)
		self.assertEqual(out['queued'], 3)
		self.assertEqual(HostScreenshot.objects.count(), 3)

	def test_an_excluded_host_gets_no_row(self):
		sub = self.host()
		HostExclusion.objects.create(org=self.project.org, host='www.rt.test')
		web_shot.queue_for_subs([sub], self.project.pk)
		self.assertEqual(HostScreenshot.objects.count(), 0)

	def test_an_archived_host_gets_no_row(self):
		sub = self.host()
		HostState.objects.create(project=self.project, domain=self.domain, host='www.rt.test', archived_at=timezone.now())
		web_shot.queue_for_subs([sub], self.project.pk)
		self.assertEqual(HostScreenshot.objects.count(), 0)

	def test_a_bug_bounty_host_the_program_holds_back_says_so_on_its_row(self):
		sub = self.host(ports=((443, 'https'),))

		def refusal(gate, project_id, host=None, *, unattended=True, derived=False):
			return 'the bug bounty engagement has not confirmed automated testing' if unattended else ''
		with mock.patch('cveFeed.bounty_gate.Gate.refusal', refusal):
			out = web_shot.queue_for_subs([sub], self.project.pk)
			self.assertEqual((out['queued'], out['blocked']), (0, 1))
			row = HostScreenshot.objects.get()
			self.assertEqual(row.outcome, 'blocked')
			self.assertIn('Not captured: the bug bounty engagement has not confirmed automated testing', row.reason)
			by_person = web_shot.queue_for_subs([sub], self.project.pk, by_person=True, force=True)  # a person asked: only the host scope applies
		self.assertEqual(by_person['queued'], 1)
		self.assertEqual(HostScreenshot.objects.get().outcome, 'queued')

	def test_an_address_inside_a_declared_internal_network_is_blocked_with_the_reason(self):
		InternalRange.objects.create(project=self.project, cidr='10.1.2.0/24')
		sub = self.host(name='10.1.2.3', ports=((80, 'http'),), address='10.1.2.3')
		web_shot.queue_for_subs([sub], self.project.pk)
		row = HostScreenshot.objects.get()
		self.assertEqual(row.outcome, 'blocked')
		self.assertIn('only a Sentinel', row.reason)

	def test_a_port_that_stopped_being_a_web_page_loses_its_failed_row_and_keeps_a_picture(self):
		sub = self.host(ports=((443, 'https'),))
		self.make_row(scheme='http', port=8080, outcome='unreachable', reason='refused', attempted_at=timezone.now() - timedelta(days=3))
		self.make_row(scheme='http', port=8000, outcome='ok', image_path='old.png', captured_at=timezone.now() - timedelta(days=9),
					  attempted_at=timezone.now() - timedelta(days=9))
		web_shot.queue_for_subs([sub], self.project.pk)
		self.assertEqual(set(self.rows()), {('https', 443), ('http', 8000)})
		self.assertGreater(self.rows()[('http', 8000)].attempted_at, timezone.now() - timedelta(minutes=5))  # looked at, so the backfill moves on

	def test_a_scan_queues_the_pages_of_every_host_it_found_and_asks_for_one_drain(self):
		scan = self.scan(names=('a.rt.test', 'b.rt.test'), ports=((443, 'https'),))
		out = web_shot.queue_for_scan(scan.id, by_person=True)
		self.assertEqual(out['queued'], 2)
		self.assertEqual({r.host for r in HostScreenshot.objects.all()}, {'a.rt.test', 'b.rt.test'})
		self.assertTrue(HostScreenshot.objects.filter(by_person=True).count() == 2)
		self.kicked.assert_called_once()
		web_shot.queue_for_scan(scan.id)
		self.assertEqual(self.kicked.call_count, 1)  # nothing new was queued: no second message

	def test_a_switched_off_server_queues_nothing(self):
		scan = self.scan()
		with mock.patch.dict(os.environ, {'CVENGINE_SCREENSHOTS': '0'}):
			self.assertEqual(web_shot.queue_for_scan(scan.id)['queued'], 0)
			self.assertFalse(web_shot.has_work_for_scan(scan))
		self.assertEqual(HostScreenshot.objects.count(), 0)

	def test_a_scan_with_no_web_service_has_no_work_and_no_browser_means_no_stage(self):
		self.assertTrue(web_shot.has_work_for_scan(self.scan()))
		self.assertFalse(web_shot.has_work_for_scan(self.scan(names=('db.rt.test',), ports=((5432, 'postgresql'),), ip='203.0.113.9')))
		with mock.patch.object(web_shot, 'browser_installed', return_value=False):
			self.assertFalse(web_shot.has_work_for_scan(self.scan(names=('x.rt.test',), ip='203.0.113.7')))

	def test_the_button_queues_every_page_whatever_the_window_says(self):
		sub = self.host(ports=((443, 'https'),))
		self.make_row(outcome='ok', captured_at=timezone.now(), image_path='x.png')
		out = web_shot.queue_host(self.project, sub)
		self.assertEqual(out['queued'], 1)
		self.assertTrue(HostScreenshot.objects.get().by_person)
		self.kicked.assert_called_once()

	def test_a_broker_problem_when_asking_for_the_drain_is_not_an_error(self):
		self.assertTrue(web_shot.kick())
		self.kicked.side_effect = OSError('broker down')
		with self.assertLogs('cveFeed.web_shot', 'WARNING'):
			self.assertFalse(web_shot.kick())


class DiscoveryStageTests(ShotFixture, TestCase):
	"""The stage sits after nmap in ``_run_stages``, so full scans, host assessments, Rescan host, certificate transparency hosts and retests all get it."""

	def run_stages(self, scan, **kwargs):
		from cveFeed import discovery
		with mock.patch('cveFeed.discovery.stopped', return_value=False):
			return discovery._run_stages(scan.id, {'scan_id': scan.id, 'status': discovery.SUCCESS}, hygiene=False,
										 nmap_runner=lambda targets, flags, timeout: '<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>',
										 db_exposure_checks={}, provider=None, light_stream=lambda path, **k: iter([]), targeted_stream=lambda path, **k: iter([]),
										 route_probe=lambda url: {'url': url, 'status': 200, 'body': '', 'title': ''}, **kwargs)

	def test_a_scan_with_web_pages_queues_them_in_its_own_stage_after_nmap(self):
		from startScan.models import ScanActivity
		scan = self.scan(ports=((443, 'https'), (80, 'http')))
		out = self.run_stages(scan)
		names = list(ScanActivity.objects.filter(scan_of=scan).order_by('id').values_list('name', flat=True))
		self.assertEqual(names[:3], ['nmap_scan', 'web_screenshot', 'db_exposure_scan'])
		self.assertEqual(out['web_screenshot']['queued'], 2)
		self.assertEqual(ScanActivity.objects.get(scan_of=scan, name='web_screenshot').status, 2)
		self.assertEqual(HostScreenshot.objects.count(), 2)

	def test_a_retest_and_a_forced_run_ask_again_and_a_persons_run_is_marked(self):
		calls = []
		scan = self.scan()
		self.run_stages(scan, retest=True, screenshot_queuer=lambda scan_id, by_person, force: calls.append((by_person, force)) or {'queued': 0})
		self.run_stages(scan, by_person=True, screenshot_queuer=lambda scan_id, by_person, force: calls.append((by_person, force)) or {'queued': 0})
		self.assertEqual(calls, [(False, True), (True, False)])

	def test_a_failing_stage_is_recorded_and_never_takes_the_scan_down(self):
		from startScan.models import ScanActivity
		scan = self.scan()

		def boom(scan_id, by_person, force):
			raise RuntimeError('broker down')
		out = self.run_stages(scan, screenshot_queuer=boom)
		self.assertEqual(out['web_screenshot']['error'], 'broker down')
		self.assertEqual(ScanActivity.objects.get(scan_of=scan, name='web_screenshot').status, 0)
		self.assertIn('triage', list(ScanActivity.objects.filter(scan_of=scan).values_list('name', flat=True)))  # the later stages still ran

	def test_no_browser_or_no_web_page_means_no_stage_row(self):
		from startScan.models import ScanActivity
		with mock.patch.object(web_shot, 'browser_installed', return_value=False):
			self.run_stages(self.scan())
		self.run_stages(self.scan(names=('db.rt.test',), ports=((5432, 'postgresql'),), ip='203.0.113.9'))
		self.assertFalse(ScanActivity.objects.filter(name='web_screenshot').exists())


# ------------------------------------------------------------------------------------------------ the guards, per connection

class GuardTests(ShotFixture, TestCase):
	def guard(self, resolver=None, primary='www.rt.test', unattended=True, excluded=None):
		calls = []

		def resolve(host, port):
			calls.append((host, port))
			return resolver(host, port) if resolver else ((2, ('203.0.113.5', port)),)
		guard = web_shot.Guard(self.project.pk, primary, unattended, excluded=excluded, resolver=resolve)
		return guard, calls

	def test_the_pages_own_host_is_let_through_with_the_vetted_address(self):
		guard, _ = self.guard()
		target, reason = guard.admit('www.rt.test', 443)
		self.assertEqual((target, reason), ((((2, ('203.0.113.5', 443)),), self.project.pk), ''))  # the project is the authority for its own tailnet address only
		other, _ = guard.admit('cdn.thirdparty.test', 443)
		self.assertIsNone(other[1])

	def test_a_host_that_resolves_to_an_internal_address_is_refused_on_every_hop_and_for_a_sub_resource(self):
		def internal(host, port):
			if host == 'evil.example.test':
				raise ValueError('probe destination is prohibited')
			return ((2, ('203.0.113.5', port)),)
		guard, _ = self.guard(internal)
		target, reason = guard.admit('evil.example.test', 80)
		self.assertIsNone(target)
		self.assertIn('internal or reserved address', reason)
		self.assertEqual(guard.denied, [('evil.example.test', reason)])

	def test_a_redirect_to_a_literal_internal_address_is_refused_by_the_real_address_rules(self):
		guard = web_shot.Guard(self.project.pk, 'www.rt.test', True, excluded=frozenset())  # the real resolver: a literal address is judged as itself
		for address in ('127.0.0.1', '169.254.169.254', '10.0.0.5', '192.168.1.1', '[::1]'):
			target, reason = guard.admit(address.strip('[]'), 80)
			self.assertIsNone(target, address)
			self.assertIn('internal or reserved', reason, address)

	def test_a_name_that_does_not_resolve_is_refused_with_a_reason(self):
		def gone(host, port):
			raise OSError('Name or service not known')
		guard, _ = self.guard(gone)
		target, reason = guard.admit('nothing.example.test', 443)
		self.assertIsNone(target)
		self.assertIn('could not be resolved', reason)

	def test_an_excluded_host_is_refused_wherever_the_browser_meets_it(self):
		HostExclusion.objects.create(org=self.project.org, host='excluded.rt.test')
		guard, calls = self.guard()
		target, reason = guard.admit('excluded.rt.test', 443)
		self.assertIsNone(target)
		self.assertIn('excluded for this organization', reason)
		self.assertEqual(calls, [])  # refused before any name lookup

	def test_an_unreadable_exclusion_list_stops_the_request(self):
		guard, _ = self.guard()
		with mock.patch('cveFeed.exclusions.excluded_names', side_effect=RuntimeError('db')):
			target, reason = guard.admit('www.rt.test', 443)
		self.assertIsNone(target)
		self.assertIn('exclusion list could not be read', reason)

	def test_the_bug_bounty_scope_holds_back_every_host_but_the_pages_own(self):
		seen = []

		def refusal(gate, project_id, host=None, *, unattended=True, derived=False):
			seen.append((host, unattended))
			return 'the program\'s scope does not name it'
		guard, _ = self.guard(unattended=True)
		with mock.patch('cveFeed.bounty_gate.Gate.refusal', refusal):
			self.assertIsNotNone(guard.admit('www.rt.test', 443)[0])  # the page itself was admitted when it was queued
			target, reason = guard.admit('sso.thirdparty.test', 443)
		self.assertIsNone(target)
		self.assertIn('cannot be visited: the program\'s scope does not name it', reason)
		self.assertEqual(seen, [('sso.thirdparty.test', True)])

	def test_a_person_asking_does_not_need_the_project_confirmation(self):
		seen = []

		def refusal(gate, project_id, host=None, *, unattended=True, derived=False):
			seen.append(unattended)
			return ''
		guard, _ = self.guard(unattended=False)
		with mock.patch('cveFeed.bounty_gate.Gate.refusal', refusal):
			guard.admit('cdn.thirdparty.test', 443)
		self.assertEqual(seen, [False])

	def test_a_verdict_is_remembered_for_the_page(self):
		guard, calls = self.guard()
		guard.admit('cdn.thirdparty.test', 443)
		guard.admit('CDN.thirdparty.test.', 443)
		self.assertEqual(len(calls), 1)

	def test_a_page_that_never_loaded_says_which_host_stopped_it(self):
		guard, _ = self.guard(lambda host, port: (_ for _ in ()).throw(ValueError('x')) if host != 'www.rt.test' else ((2, ('203.0.113.5', port)),))
		self.assertEqual(guard.blocked_reason(), '')
		guard.admit('hop.thirdparty.test', 80)
		self.assertTrue(guard.blocked_reason().startswith('Redirects to hop.thirdparty.test, which is not visited:'))
		other, _ = self.guard(lambda host, port: (_ for _ in ()).throw(ValueError('x')))
		other.admit('www.rt.test', 443)
		self.assertTrue(other.blocked_reason().startswith('www.rt.test resolves to an internal or reserved address'))

	def test_the_connection_is_made_to_the_vetted_address_through_the_pinned_transport(self):
		with mock.patch('cveFeed.pinned_transport.open_socket', return_value='socket') as opened:
			self.assertEqual(web_shot.connect((((2, ('203.0.113.5', 443)),), 7), 'www.rt.test', 443, 9), 'socket')
		opened.assert_called_once_with(((2, ('203.0.113.5', 443)),), 9, project=7, host='www.rt.test')


# ------------------------------------------------------------------------------------------------ capturing

class FakeProxy:
	"""Stands in for the vetting proxy: records the guard hook the batch gave it, binds nothing."""
	instances = []

	def __init__(self, admit, connect, secret):
		self.admit, self.connect, self.secret = admit, connect, secret
		self.server = 'http://127.0.0.1:1'
		FakeProxy.instances.append(self)

	def __enter__(self):
		return self

	def __exit__(self, *exc):
		return False


def runner_for(plan, seen=None):
	"""A browser child that plays ``plan`` (``{host: result fields}``, picture bytes in ``'png'``) instead of launching Chromium."""
	def run(job, on_result, wall, label='', workdir=None):
		if seen is not None:
			seen.append((job, wall, label, workdir))
		for target in job['targets']:
			host = target['url'].split('://', 1)[1].split('/', 1)[0].split(':')[0]
			step = dict(plan.get(host, {'outcome': 'ok'}))
			if callable(step.get('before')):
				step.pop('before')(FakeProxy.instances[-1], target['key'])
			data = step.pop('png', None)
			outcome = step.setdefault('outcome', 'ok')
			if outcome == 'ok':
				with open(target['out'], 'wb') as handle:
					handle.write(data if data is not None else png())
				step.setdefault('final_url', target['url'])
				step.setdefault('status', 200)
				step.setdefault('title', 'Title')
			on_result({'key': target['key'], 'reason': '', **step})
		return plan.get('__failure__', {}).get('reason', '')
	return run


class CaptureTests(ShotFixture, TestCase):
	def setUp(self):
		super().setUp()
		self.sub = self.host(ports=((443, 'https'),))
		FakeProxy.instances = []

	def queue(self, **kw):
		web_shot.queue_for_subs([self.sub], self.project.pk, **kw)
		return HostScreenshot.objects.get(host='www.rt.test', scheme='https', port=443)

	def drain(self, plan=None, **kw):
		with mock.patch('cveFeed.web_shot._resolve', return_value='203.0.113.5'):
			return web_shot.drain(runner=runner_for(plan or {}, kw.pop('seen', None)), proxy_factory=FakeProxy, **kw)

	def test_a_good_page_is_stored_with_everything_the_host_page_needs(self):
		row = self.queue()
		seen = []
		out = self.drain({'www.rt.test': {'title': 'Welcome', 'final_url': 'https://www.rt.test/home', 'status': 200}}, seen=seen)
		self.assertEqual((out['captured'], out['failed'], out['blocked']), (1, 0, 0))
		row.refresh_from_db()
		self.assertEqual((row.outcome, row.reason, row.http_status, row.title, row.final_url), ('ok', '', 200, 'Welcome', 'https://www.rt.test/home'))
		self.assertTrue(row.captured_at and row.attempted_at and not row.queued_at)
		self.assertRegex(row.image_path, rf'^screenshots/{self.project.pk}/www\.rt\.test/https-443-\d+\.png$')
		self.assertTrue(os.path.isfile(os.path.join(self.media, row.image_path)))
		self.assertTrue(os.path.isfile(os.path.join(self.media, row.thumb_path)))
		self.assertRegex(row.image_hash, r'^[0-9a-f]{16}$')
		self.assertEqual(row.image_bytes, os.path.getsize(os.path.join(self.media, row.image_path)))
		job, wall, label, workdir = seen[0]
		self.assertEqual(job['targets'][0]['url'], 'https://www.rt.test/')
		self.assertEqual(job['proxy']['server'], FakeProxy.instances[0].server)
		self.assertEqual(job['proxy']['password'], FakeProxy.instances[0].secret)
		self.assertFalse(os.path.exists(workdir), 'the private working directory is removed')

	def test_the_browser_is_given_nothing_of_the_workers_secrets(self):
		with mock.patch.dict(os.environ, {'POSTGRES_PASSWORD': 'hunter2', 'CELERY_BROKER': 'redis://secret', 'PATH': '/usr/bin'}):
			env = web_shot._child_env('/tmp/w')
		self.assertNotIn('POSTGRES_PASSWORD', env)
		self.assertNotIn('CELERY_BROKER', env)
		self.assertEqual((env['HOME'], env['TMPDIR']), ('/tmp/w', '/tmp/w'))

	def test_a_page_that_redirects_to_another_host_says_so(self):
		row = self.queue()
		self.drain({'www.rt.test': {'final_url': 'https://mybluegrace.example/'}})
		row.refresh_from_db()
		self.assertEqual(row.outcome, 'ok')
		self.assertEqual(row.reason, 'Redirects to https://mybluegrace.example/ (another host).')

	def test_an_error_page_is_still_a_picture_with_its_status_as_the_reason(self):
		row = self.queue()
		self.drain({'www.rt.test': {'status': 403}})
		row.refresh_from_db()
		self.assertEqual((row.outcome, row.http_status, row.reason), ('ok', 403, 'The server answered HTTP 403.'))

	def test_a_page_that_rendered_blank_is_recorded_as_blank_and_stores_no_picture(self):
		row = self.queue()
		self.drain({'www.rt.test': {'png': png(flat=True)}})
		row.refresh_from_db()
		self.assertEqual((row.outcome, row.image_path), ('blank', ''))
		self.assertEqual(os.listdir(self.media), [])

	def test_a_failure_says_why_and_keeps_the_earlier_picture(self):
		row = self.queue()
		self.drain()
		first = HostScreenshot.objects.get().image_path
		captured = HostScreenshot.objects.get().captured_at
		HostScreenshot.objects.update(outcome='queued')
		self.drain({'www.rt.test': {'outcome': 'timeout', 'reason': 'The page did not load within the time allowed.'}})
		row.refresh_from_db()
		self.assertEqual((row.outcome, row.reason, row.image_path, row.captured_at), ('timeout', 'The page did not load within the time allowed.', first, captured))
		self.assertGreater(row.attempted_at, captured)

	def test_only_the_current_and_the_previous_picture_are_kept(self):
		row = self.queue()
		paths = []
		for i in range(3):
			self.drain({'www.rt.test': {'png': png(noise=50 * (i + 1))}})
			row.refresh_from_db()
			paths.append(row.image_path)
			HostScreenshot.objects.update(outcome='queued')
			import time
			time.sleep(0.003)  # file names carry the millisecond
		self.assertEqual(len(set(paths)), 3)
		row.refresh_from_db()
		self.assertEqual(row.previous_image_path, paths[1])
		self.assertTrue(os.path.isfile(os.path.join(self.media, paths[2])) or os.path.isfile(os.path.join(self.media, row.image_path)))
		self.assertTrue(os.path.isfile(os.path.join(self.media, paths[1])))
		self.assertFalse(os.path.exists(os.path.join(self.media, paths[0])), 'older than the previous capture: deleted')

	def test_a_picture_over_the_size_cap_is_stored_as_a_smaller_jpeg(self):
		row = self.queue()
		big = png(width=400, height=300, noise=120000)
		with mock.patch.object(web_shot, 'max_bytes', return_value=60 * 1024):
			self.drain({'www.rt.test': {'png': big}})
		row.refresh_from_db()
		self.assertEqual(row.outcome, 'ok')
		self.assertTrue(row.image_path.endswith('.jpg'))
		self.assertLessEqual(row.image_bytes, 60 * 1024)
		self.assertLess(row.image_bytes, len(big))

	def test_a_picture_that_cannot_be_shrunk_under_the_cap_is_refused(self):
		row = self.queue()
		with mock.patch.object(web_shot, 'max_bytes', return_value=64 * 1024):
			self.drain({'www.rt.test': {'png': png(width=500, height=400, noise=200000)}})
		row.refresh_from_db()
		self.assertEqual((row.outcome, row.image_path), ('error', ''))
		self.assertIn('larger than the size allowed', row.reason)

	def test_a_project_over_its_storage_cap_stops_storing_and_says_so(self):
		other = self.make_row(host='other.rt.test', outcome='ok', image_path='screenshots/x.png', image_bytes=600, previous_image_path='screenshots/p.png')
		self.plant('screenshots/p.png')
		row = self.queue()
		with mock.patch.object(web_shot, 'project_cap_bytes', return_value=500):
			self.drain()
		row.refresh_from_db()
		self.assertEqual(row.outcome, 'error')
		self.assertIn('storage', row.reason)
		other.refresh_from_db()
		self.assertEqual(other.previous_image_path, '')  # the comparison copies are given up first
		self.assertFalse(os.path.exists(os.path.join(self.media, 'screenshots/p.png')))

	def test_a_page_a_guard_stopped_is_blocked_with_the_reason_not_unreachable(self):
		row = self.queue()

		def meets_an_internal_host(proxy, key):
			proxy.admit(key, 'www.rt.test', 443)
			proxy.admit(key, 'hop.internal.test', 80)
		with mock.patch('cveFeed.pinned_transport.resolve', side_effect=lambda host, port, project=None: (_ for _ in ()).throw(ValueError('prohibited')) if host == 'hop.internal.test' else ((2, ('203.0.113.5', port)),)):
			self.drain({'www.rt.test': {'outcome': 'unreachable', 'reason': 'The connection was closed without an answer.', 'before': meets_an_internal_host}})
		row.refresh_from_db()
		self.assertEqual(row.outcome, 'blocked')
		self.assertTrue(row.reason.startswith('Redirects to hop.internal.test, which is not visited:'), row.reason)

	def test_a_sub_resource_a_guard_dropped_does_not_stop_the_page(self):
		self.queue()

		def drops_an_asset(proxy, key):
			proxy.admit(key, 'cdn.internal.test', 443)
		with mock.patch('cveFeed.pinned_transport.resolve', side_effect=lambda host, port, project=None: (_ for _ in ()).throw(ValueError('x')) if host.startswith('cdn') else ((2, ('203.0.113.5', port)),)):
			out = self.drain({'www.rt.test': {'before': drops_an_asset}})
		self.assertEqual(out['captured'], 1)
		self.assertEqual(out['dropped_requests'], 1)

	def test_the_proxy_asks_the_guard_of_the_page_it_belongs_to(self):
		self.queue()
		answers = {}

		def asks(proxy, key):
			answers['own'] = proxy.admit(key, 'www.rt.test', 443)[1]
			answers['unknown'] = proxy.admit('999', 'www.rt.test', 443)
		with mock.patch('cveFeed.pinned_transport.resolve', return_value=((2, ('203.0.113.5', 443)),)):
			self.drain({'www.rt.test': {'before': asks}})
		self.assertEqual(answers['own'], '')
		self.assertEqual(answers['unknown'], (None, 'unknown page'))

	def test_a_browser_that_could_not_run_marks_the_rows_and_is_remembered_until_it_works(self):
		row = self.queue()
		out = self.drain({'__failure__': {'reason': 'The browser stopped.'}, 'www.rt.test': {'outcome': 'ok'}})
		self.assertEqual(out['error'], 'The browser stopped.')
		self.assertEqual(cache.get('screenshots:last_browser_error')['error'], 'The browser stopped.')
		runner = lambda job, on_result, wall, label='', workdir=None: 'Playwright is not installed.'  # noqa: E731
		row.refresh_from_db()
		HostScreenshot.objects.update(outcome='queued')
		with mock.patch('cveFeed.web_shot._resolve', return_value='203.0.113.5'):
			web_shot.drain(runner=runner, proxy_factory=FakeProxy)
		row.refresh_from_db()
		self.assertEqual(row.outcome, 'unavailable')
		self.assertIn('Playwright is not installed.', row.reason)
		HostScreenshot.objects.update(outcome='queued')
		self.drain()
		self.assertIsNone(cache.get('screenshots:last_browser_error'))

	def test_a_stopped_or_memory_starved_run_leaves_the_pages_queued(self):
		from reNgine import resources
		row = self.queue()

		def stopped(job, on_result, wall, label='', workdir=None):
			raise resources.ScanAborted('paused')
		with mock.patch('cveFeed.web_shot._resolve', return_value='203.0.113.5'):
			out = web_shot.drain(runner=stopped, proxy_factory=FakeProxy)
		row.refresh_from_db()
		self.assertEqual(row.outcome, 'queued')
		self.assertEqual(out['stopped'], 'ScanAborted')

	def test_a_page_that_gives_nothing_back_is_not_retried_in_a_tight_loop(self):
		self.queue()
		calls = []

		def silent(job, on_result, wall, label='', workdir=None):
			calls.append(1)
			return ''
		with mock.patch('cveFeed.web_shot._resolve', return_value='203.0.113.5'):
			web_shot.drain(runner=silent, proxy_factory=FakeProxy)
		self.assertEqual(len(calls), 1)


class PrecheckTests(ShotFixture, TestCase):
	"""Every queued page is judged again where it is used: what was true when it was queued may not be now."""

	def setUp(self):
		super().setUp()
		self.sub = self.host(ports=((443, 'https'),))
		FakeProxy.instances = []

	def drain(self, resolve='203.0.113.5', by_person=False):
		self.row = self.make_row(by_person=by_person)
		resolver = resolve if callable(resolve) else mock.Mock(return_value=resolve)
		with mock.patch('cveFeed.web_shot._resolve', resolver):
			return web_shot.drain(runner=runner_for({}), proxy_factory=FakeProxy)

	def test_a_host_that_left_the_inventory_is_forgotten_not_photographed(self):
		Subdomain.objects.all().delete()
		out = self.drain()
		self.assertEqual((out['captured'], out['dropped']), (0, 1))
		self.assertEqual(HostScreenshot.objects.count(), 0)

	def test_a_host_excluded_since_it_was_queued_is_forgotten(self):
		HostExclusion.objects.create(org=self.project.org, host='www.rt.test')
		self.drain()
		self.assertEqual(HostScreenshot.objects.count(), 0)

	def test_an_archived_host_is_blocked(self):
		HostState.objects.create(project=self.project, domain=self.domain, host='www.rt.test', archived_at=timezone.now())
		self.drain()
		self.assertEqual((self.row.__class__.objects.get().outcome, self.row.__class__.objects.get().reason), ('blocked', 'Not captured: the host is archived.'))

	def test_the_bug_bounty_confirmation_holds_back_an_unattended_page_but_not_a_persons(self):
		def refusal(gate, project_id, host=None, *, unattended=True, derived=False):
			return 'the bug bounty engagement has not confirmed automated testing' if unattended else ''
		with mock.patch('cveFeed.bounty_gate.Gate.refusal', refusal):
			self.drain(by_person=False)
			self.assertEqual(HostScreenshot.objects.get().outcome, 'blocked')
			HostScreenshot.objects.all().delete()
			self.drain(by_person=True)
		self.assertEqual(HostScreenshot.objects.get().outcome, 'ok')

	def test_a_name_that_now_resolves_to_an_internal_address_is_blocked(self):
		def internal(host, port, project_id):
			raise ValueError('probe destination is prohibited')
		self.drain(internal)
		row = HostScreenshot.objects.get()
		self.assertEqual(row.outcome, 'blocked')
		self.assertIn('internal or reserved address', row.reason)

	def test_a_name_that_does_not_resolve_is_unreachable_with_the_reason(self):
		def gone(host, port, project_id):
			raise OSError('Name or service not known')
		self.drain(gone)
		row = HostScreenshot.objects.get()
		self.assertEqual(row.outcome, 'unreachable')
		self.assertIn('could not be resolved', row.reason)


class DrainTests(ShotFixture, TestCase):
	def setUp(self):
		super().setUp()
		FakeProxy.instances = []
		self.sub = self.host(ports=((443, 'https'),))

	def test_nothing_runs_while_scanning_is_paused_and_the_pages_stay_queued(self):
		self.make_row()
		with mock.patch('reNgine.resources.global_pause_requested', return_value=True):
			out = web_shot.drain(runner=runner_for({}), proxy_factory=FakeProxy)
		self.assertEqual(out['skipped'], 'scanning is paused')
		self.assertEqual(HostScreenshot.objects.get().outcome, 'queued')

	def test_a_second_drain_while_one_runs_returns_at_once(self):
		self.make_row()
		from contextlib import contextmanager

		@contextmanager
		def taken(key, owner, ttl):
			yield 'drain-other'
		with mock.patch('reNgine.resources.redis_claim', taken):
			out = web_shot.drain(runner=runner_for({}), proxy_factory=FakeProxy)
		self.assertEqual(out['skipped'], 'another drain is running')
		self.assertEqual(HostScreenshot.objects.get().outcome, 'queued')

	def test_without_the_browser_the_pages_wait_and_the_reason_is_given(self):
		self.make_row()
		with mock.patch.object(web_shot, 'browser_installed', return_value=False):
			out = web_shot.drain(runner=runner_for({}), proxy_factory=FakeProxy)
		self.assertIn('Chromium is not installed', out['skipped'])
		self.assertEqual(HostScreenshot.objects.get().outcome, 'queued')

	def test_a_persons_request_goes_first_and_the_oldest_next(self):
		old = self.make_row(host='old.rt.test', queued_at=timezone.now() - timedelta(hours=3))
		new = self.make_row(host='new.rt.test', queued_at=timezone.now())
		person = self.make_row(host='person.rt.test', queued_at=timezone.now(), by_person=True)
		for host in ('old.rt.test', 'new.rt.test', 'person.rt.test'):
			Subdomain.objects.create(name=host, target_domain=self.domain, scan_history=self.sub.scan_history)
		self.assertEqual([r.host for r in web_shot.queued_rows(10)], ['person.rt.test', 'old.rt.test', 'new.rt.test'])
		self.assertEqual(len(web_shot.queued_rows(2)), 2)
		self.assertTrue(old and new and person)

	def test_a_long_queue_is_taken_a_batch_at_a_time_until_it_is_empty(self):
		for i in range(5):
			name = f'h{i}.rt.test'
			Subdomain.objects.create(name=name, target_domain=self.domain, scan_history=self.sub.scan_history)
			self.make_row(host=name)
		batches = []

		def run(job, on_result, wall, label='', workdir=None):
			batches.append(len(job['targets']))
			return runner_for({})(job, on_result, wall, label, workdir)
		with mock.patch('cveFeed.web_shot._resolve', return_value='203.0.113.5'):
			out = web_shot.drain(runner=run, proxy_factory=FakeProxy, batch=2)
		self.assertEqual(batches, [2, 2, 1])
		self.assertEqual(out['captured'], 5)
		self.assertFalse(HostScreenshot.objects.filter(outcome='queued').exists())

	def test_a_drain_that_runs_out_of_time_asks_for_another_instead_of_holding_the_worker(self):
		self.make_row()
		ticks = iter([0, 10_000])
		out = web_shot.drain(runner=runner_for({}), proxy_factory=FakeProxy, budget_seconds=5, now_fn=lambda: next(ticks))
		self.assertTrue(out['continued'])
		self.kicked.assert_called_once()
		self.assertEqual(self.kicked.call_args.kwargs['countdown'], 5)

	def test_a_page_queued_while_a_drain_was_finishing_gets_another_drain(self):
		row = self.make_row()
		looks = iter([[row], [], [row]])  # the loop's two looks, then the last look after the drain has done its work

		def process(rows, runner=None, resolve=None, summary=None, proxy_factory=None):
			summary['captured'] += 1
			return summary
		with mock.patch.object(web_shot, 'queued_rows', side_effect=lambda limit: next(looks)), mock.patch.object(web_shot, 'process', process):
			out = web_shot.drain(runner=runner_for({}), proxy_factory=FakeProxy)
		self.assertEqual(out['captured'], 1)
		self.kicked.assert_called_once()
		self.assertEqual(self.kicked.call_args.kwargs['countdown'], 5)

	def test_the_activity_feed_gets_one_line(self):
		from cveFeed.models import AgentActivity
		self.make_row()
		with mock.patch('cveFeed.web_shot._resolve', return_value='203.0.113.5'):
			web_shot.drain(runner=runner_for({}), proxy_factory=FakeProxy)
		self.assertTrue(AgentActivity.objects.filter(message='Screenshots: 1 captured, 0 not captured, 0 blocked').exists())


class RunChildTests(SimpleTestCase):
	"""The real child-process plumbing, over a stand-in script (no browser)."""

	def run_script(self, script, wall=20, on_result=None):
		results = []
		workdir = tempfile.mkdtemp()
		self.addCleanup(shutil.rmtree, workdir, ignore_errors=True)
		with mock.patch.object(web_shot, '_unprivileged', return_value=None):
			failure = web_shot.run_child({'targets': [{'key': '1'}], 'proxy': {'server': 's', 'password': 'p'}}, on_result or results.append, wall,
										 argv=[sys.executable, '-c', textwrap.dedent(script)], heavy=False, workdir=workdir)
		return failure, results

	def test_results_are_handed_over_as_they_arrive_and_done_ends_it(self):
		failure, results = self.run_script("""
			import json, sys
			job = json.loads(sys.stdin.readline())
			print(json.dumps({'op': 'result', 'key': '1', 'outcome': 'ok', 'seen_proxy': job['proxy']['server']}), flush=True)
			print('not json at all', flush=True)
			print(json.dumps({'op': 'done'}), flush=True)""")
		self.assertEqual(failure, '')
		self.assertEqual(results[0]['seen_proxy'], 's')

	def test_a_fatal_message_is_returned_as_the_reason(self):
		failure, _ = self.run_script("""
			import json
			print(json.dumps({'op': 'fatal', 'reason': 'Executable does not exist'}), flush=True)""")
		self.assertEqual(failure, 'Executable does not exist')

	def test_a_child_that_dies_before_finishing_is_reported_with_its_status(self):
		failure, _ = self.run_script("import sys; sys.exit(3)")
		self.assertIn('status 3', failure)

	def test_a_child_that_hangs_is_killed_at_the_wall_clock_limit(self):
		import time
		started = time.monotonic()
		failure, _ = self.run_script("import time; time.sleep(60)", wall=1)
		self.assertLess(time.monotonic() - started, 15)
		self.assertTrue(failure)

	def test_the_child_runs_in_its_own_session_with_the_workdir_as_home(self):
		failure, results = self.run_script("""
			import json, os
			print(json.dumps({'op': 'result', 'key': '1', 'home': os.environ.get('HOME'), 'tmp': os.environ.get('TMPDIR'), 'db': os.environ.get('POSTGRES_PASSWORD'),
			                  'sid_is_leader': os.getsid(0) == os.getpid()}), flush=True)
			print(json.dumps({'op': 'done'}), flush=True)""")
		self.assertEqual(failure, '')
		self.assertTrue(results[0]['home'].startswith(tempfile.gettempdir()))
		self.assertEqual(results[0]['home'], results[0]['tmp'])
		self.assertIsNone(results[0]['db'])
		self.assertTrue(results[0]['sid_is_leader'])

	def test_the_browser_runs_as_an_unprivileged_account_when_the_worker_is_root(self):
		with mock.patch('os.geteuid', return_value=0), mock.patch('pwd.getpwnam', return_value=mock.Mock(pw_uid=65534, pw_gid=65534)):
			self.assertEqual(web_shot._unprivileged(), (65534, 65534))
			with mock.patch.dict(os.environ, {'CVENGINE_SCREENSHOT_USER': '-'}):
				self.assertIsNone(web_shot._unprivileged())
		with mock.patch('os.geteuid', return_value=1000):
			self.assertIsNone(web_shot._unprivileged())
		with mock.patch('os.geteuid', return_value=0), mock.patch('pwd.getpwnam', side_effect=KeyError('nobody')):
			with self.assertLogs('cveFeed.web_shot', 'WARNING'):
				self.assertIsNone(web_shot._unprivileged())


# ------------------------------------------------------------------------------------------------ the hourly backfill

class BackfillTests(ShotFixture, TestCase):
	def project_with_hosts(self, slug, count, ports=((443, 'https'),), start=10):
		org = Org.objects.create(name=slug, slug=slug)
		project = Project.objects.create(name=slug, slug=slug, insert_date=timezone.now(), org=org)
		domain = Domain.objects.create(name=f'{slug}.test', project=project, insert_date=timezone.now())
		from startScan.models import ScanHistory
		scan = ScanHistory.objects.create(domain=domain, scan_type=self.engine, start_scan_date=timezone.now(), scan_status=2, tasks=[], results_dir='x')
		for i in range(count):
			sub = Subdomain.objects.create(name=f'h{i}.{slug}.test', target_domain=domain, scan_history=scan)
			ip, _ = IpAddress.objects.get_or_create(address=f'198.51.{start}.{i + 1}')
			sub.ip_addresses.add(ip)
			for number, service in ports:
				ip.ports.add(Port.objects.create(number=number, service_name=service, state='open'))
		return project

	def hosts_queued(self, project):
		return sorted(HostScreenshot.objects.filter(project=project).values_list('host', flat=True))

	def test_hosts_with_a_web_port_and_no_picture_are_queued_newest_first_up_to_the_project_cap(self):
		project = self.project_with_hosts('bf-a', 5)
		out = web_shot.backfill(per_project=3, total=50)
		self.assertEqual(out['queued'], 3)
		self.assertEqual(len(self.hosts_queued(project)), 3)

	def test_the_overall_cap_holds_across_projects(self):
		self.project_with_hosts('bf-a', 4, start=10)
		self.project_with_hosts('bf-b', 4, start=11)
		out = web_shot.backfill(per_project=3, total=5)
		self.assertEqual(out['queued'], 5)
		self.assertEqual(HostScreenshot.objects.count(), 5)

	def test_the_next_run_starts_after_the_project_the_last_one_ended_on(self):
		first = self.project_with_hosts('bf-a', 3, start=10)
		second = self.project_with_hosts('bf-b', 3, start=11)
		web_shot.backfill(per_project=3, total=3)  # only room for one project's worth
		self.assertEqual((len(self.hosts_queued(first)), len(self.hosts_queued(second))), (3, 0))
		web_shot.backfill(per_project=3, total=3)
		self.assertEqual(len(self.hosts_queued(second)), 3)  # the other project is not starved by the first

	def test_hosts_with_no_web_evidence_or_a_row_already_are_left_alone(self):
		project = self.project_with_hosts('bf-a', 2, ports=((22, 'ssh'),))
		self.assertEqual(web_shot.backfill()['queued'], 0)
		project2 = self.project_with_hosts('bf-b', 2, start=11)
		self.make_row(host='h0.bf-b.test', outcome='ok', captured_at=timezone.now(), image_path='x.png', domain=Domain.objects.get(project=project2))
		HostScreenshot.objects.filter(host='h0.bf-b.test').update(project=project2)
		web_shot.backfill()
		self.assertEqual(self.hosts_queued(project2), ['h0.bf-b.test', 'h1.bf-b.test'])
		self.assertEqual(HostScreenshot.objects.get(host='h0.bf-b.test').outcome, 'ok')
		self.assertEqual(self.hosts_queued(project), [])

	def test_a_picture_older_than_its_window_is_asked_for_again_after_the_hosts_that_have_none(self):
		project = self.project_with_hosts('bf-a', 2)
		stale = HostScreenshot.objects.create(project=project, domain=Domain.objects.get(project=project), host='h0.bf-a.test', scheme='https', port=443, outcome='ok',
											  captured_at=timezone.now() - timedelta(days=10), attempted_at=timezone.now() - timedelta(days=10), image_path='old.png')
		out = web_shot.backfill()
		stale.refresh_from_db()
		self.assertEqual(stale.outcome, 'queued')
		self.assertEqual(out['queued'], 2)

	def test_a_paused_instance_a_missing_browser_and_a_blocked_project_queue_nothing(self):
		project = self.project_with_hosts('bf-a', 2)
		with mock.patch('cveFeed.scan_control.pause_requested', return_value=True):
			self.assertEqual(web_shot.backfill()['skipped'], 'scanning is paused')
		with mock.patch.object(web_shot, 'browser_installed', return_value=False):
			self.assertIn('Chromium is not installed', web_shot.backfill()['skipped'])
		with mock.patch('cveFeed.conductor.bounty_blocked_projects', return_value={project.pk}):
			out = web_shot.backfill()
		self.assertEqual((out['queued'], HostScreenshot.objects.filter(project=project).count()), (0, 0))

	def test_an_archived_host_is_not_backfilled(self):
		project = self.project_with_hosts('bf-a', 2)
		HostState.objects.create(project=project, domain=Domain.objects.get(project=project), host='h0.bf-a.test', archived_at=timezone.now())
		web_shot.backfill()
		self.assertEqual(self.hosts_queued(project), ['h1.bf-a.test'])

	def test_the_sweep_queues_then_drains_and_only_one_runs_at_a_time(self):
		self.project_with_hosts('bf-a', 1)
		with mock.patch('cveFeed.web_shot._resolve', return_value='198.51.10.1'), mock.patch('cveFeed.ledger.sweep_claim', return_value=True):
			out = web_shot.sweep(runner=runner_for({}))
		self.assertEqual((out['backfill']['queued'], out['drain']['captured']), (1, 1))
		with mock.patch('cveFeed.ledger.sweep_claim', return_value=False):
			self.assertEqual(web_shot.sweep(), {'skipped': 'another sweep is running'})

	def test_the_env_knobs_are_read_and_bad_values_fall_back(self):
		with mock.patch.dict(os.environ, {'CVENGINE_SCREENSHOT_BACKFILL_PER_PROJECT': '7', 'CVENGINE_SCREENSHOT_BACKFILL_MAX': 'many', 'CVENGINE_SCREENSHOT_TTL_HOURS': '5'}):
			self.assertEqual(web_shot.backfill_caps(), (7, web_shot.DEFAULT_BACKFILL_TOTAL))
			self.assertEqual(web_shot.ttl(), timedelta(hours=5))


# ------------------------------------------------------------------------------------------------ reading: the host page, the picture, the API

class ReadFixture(ShotFixture):
	def setUp(self):
		super().setUp()
		self.user = User.objects.create_user('shot-reader', password='x')
		ProjectMembership.objects.create(user=self.user, project=self.project, role='user')
		_, self.token = create_token(self.user, 'shots')

	def record(self, sub=None):
		status, data = call(self.token, 'GET', '/api/v1/projects/pr/hosts')
		self.assertEqual(status, 200, data)
		rows = [r for r in data['results'] if sub is None or r['id'] == sub.id]
		return rows[0]

	def get_picture(self, sub, query='', user=None):
		from tests.test_tenancy import client_for
		return client_for(user or self.user).get(f'/cve/pr/hosts/{sub.id}/screenshot/{query}')

	def body(self, response):
		return b''.join(response.streaming_content)


class ServingTests(ReadFixture, TestCase):
	def setUp(self):
		super().setUp()
		self.sub = self.host(ports=((443, 'https'), (80, 'http')))

	def shot(self, scheme='https', port=443, color_noise=10, **fields):
		rel = f'screenshots/{self.project.pk}/www.rt.test/{scheme}-{port}-1.png'
		data = png(noise=color_noise)
		self.plant(rel, data)
		fields.setdefault('outcome', 'ok')
		fields.setdefault('captured_at', timezone.now())
		return self.make_row(scheme=scheme, port=port, image_path=rel, image_hash=f'{port:016x}', **fields), data

	def test_the_browsers_picture_is_served_to_a_member_and_the_best_page_comes_first(self):
		_, https = self.shot('https', 443)
		self.shot('http', 80, color_noise=300)
		response = self.get_picture(self.sub)
		self.assertEqual((response.status_code, response['Content-Type']), (200, 'image/png'))
		self.assertEqual(self.body(response), https)

	def test_a_page_can_be_asked_for_by_scheme_and_port_and_a_missing_one_is_404(self):
		self.shot('https', 443)
		_, other = self.shot('http', 80, color_noise=300)
		self.assertEqual(self.body(self.get_picture(self.sub, '?scheme=http&port=80')), other)
		self.assertEqual(self.get_picture(self.sub, '?scheme=http&port=8080').status_code, 404)
		self.assertEqual(self.get_picture(self.sub, '?scheme=https&port=abc').status_code, 400)
		self.assertEqual(self.get_picture(self.sub, '?size=huge').status_code, 400)

	def test_a_page_with_no_picture_is_not_served_as_one(self):
		self.make_row(outcome='timeout')
		self.assertEqual(self.get_picture(self.sub).status_code, 404)
		self.assertEqual(self.get_picture(self.sub, '?scheme=https&port=443').status_code, 404)

	def test_the_thumbnail_is_the_stored_one_and_is_made_when_it_is_missing(self):
		from cveFeed import shots
		row, _ = self.shot('https', 443)
		full = os.path.join(self.media, row.image_path)
		thumb = shots.thumbnail_path(full)
		HostScreenshot.objects.filter(pk=row.pk).update(thumb_path=os.path.relpath(thumb, self.media))
		response = self.get_picture(self.sub, '?size=thumb')
		self.assertEqual((response.status_code, response['Content-Type']), (200, 'image/jpeg'))
		os.remove(thumb)
		HostScreenshot.objects.filter(pk=row.pk).update(thumb_path='')
		self.assertEqual(self.get_picture(self.sub, '?size=thumb').status_code, 200)

	def test_the_capture_before_the_current_one_can_be_compared(self):
		row, _ = self.shot('https', 443)
		self.assertEqual(self.get_picture(self.sub, '?scheme=https&port=443&previous=1').status_code, 404)
		before = f'screenshots/{self.project.pk}/www.rt.test/https-443-0.png'
		self.plant(before, png(noise=500))
		HostScreenshot.objects.filter(pk=row.pk).update(previous_image_path=before)
		self.assertEqual(self.body(self.get_picture(self.sub, '?scheme=https&port=443&previous=1')), png(noise=500))

	def test_another_organizations_host_is_a_404(self):
		stranger = User.objects.create_user('stranger', password='x')
		org = Org.objects.create(name='X', slug='x-org')
		Project.objects.create(name='X', slug='x-proj', insert_date=timezone.now(), org=org)
		self.shot()
		self.assertEqual(self.get_picture(self.sub, user=stranger).status_code, 404)

	def test_a_stored_path_that_leaves_the_media_root_or_is_missing_is_a_404_not_a_crash(self):
		row, _ = self.shot()
		HostScreenshot.objects.filter(pk=row.pk).update(image_path='../../../etc/passwd')
		self.assertEqual(self.get_picture(self.sub).status_code, 404)
		HostScreenshot.objects.filter(pk=row.pk).update(image_path='screenshots/gone.png')
		self.assertEqual(self.get_picture(self.sub).status_code, 404)

	def test_the_discovery_screenshot_is_the_fallback_and_the_newest_same_name_row_that_has_one_wins(self):
		"""A rescan writes a newer row with no screenshot; it used to hide the older row's."""
		old_rel = 'rt.test_1/screenshots/old.png'
		self.plant(old_rel, png(noise=77))
		older = self.host(name='www.rt.test', ports=((443, 'https'),), address='203.0.113.5')
		Subdomain.objects.filter(pk=older.pk).update(screenshot_path=old_rel)
		newer = self.host(name='www.rt.test', ports=((443, 'https'),), address='203.0.113.5')  # the rescan: a newer row, no screenshot_path
		HostScreenshot.objects.all().delete()
		self.assertEqual(self.body(self.get_picture(newer)), png(noise=77))
		self.assertEqual(self.get_picture(newer, '?row=1').status_code, 404)  # the change history asks for the row's own file only
		self.assertEqual(self.body(self.get_picture(older, '?row=1')), png(noise=77))

	def test_the_browsers_picture_wins_over_a_discovery_one(self):
		rel = 'rt.test_1/screenshots/old.png'
		self.plant(rel, png(noise=77))
		Subdomain.objects.filter(pk=self.sub.pk).update(screenshot_path=rel)
		_, mine = self.shot()
		self.assertEqual(self.body(self.get_picture(self.sub)), mine)
		self.assertEqual(self.body(self.get_picture(self.sub, '?row=1')), png(noise=77))


class HostRecordTests(ReadFixture, TestCase):
	def setUp(self):
		super().setUp()
		self.sub = self.host(ports=((443, 'https'), (80, 'http')))

	def shot_row(self, **fields):
		fields.setdefault('outcome', 'ok')
		fields.setdefault('captured_at', timezone.now())
		rel = f'screenshots/{self.project.pk}/www.rt.test/x-{fields.get("port", 443)}.png'
		self.plant(rel)
		return self.make_row(image_path=rel, image_hash=f'{fields.get("port", 443):016x}', **fields)

	def test_a_host_with_a_browser_picture_says_so_with_alt_text_and_a_per_page_list(self):
		self.shot_row(title='Welcome', http_status=200, final_url='https://www.rt.test/home', image_bytes=1234)
		record = self.record()
		self.assertTrue(record['screenshot'])
		self.assertEqual((record['screenshot_note'], record['screenshot_source']), ('', 'browser'))
		self.assertRegex(record['screenshot_alt'], r'^Screenshot of https://www\.rt\.test:443 \(https://www\.rt\.test/home\), captured \d{4}-\d\d-\d\d$')
		self.assertGreater(record['screenshot_version'], 0)
		page = record['screenshots'][0]
		self.assertEqual((page['scheme'], page['port'], page['title'], page['http_status'], page['outcome']), ('https', 443, 'Welcome', 200, 'ok'))
		self.assertTrue(page['has_image'])
		self.assertNotIn('image_path', page)  # no file path ever leaves the server
		self.assertNotIn('screenshots/', str(record['screenshots']))

	def test_a_host_with_no_picture_says_what_happened_not_none_yet(self):
		self.make_row(outcome='timeout', reason='The page did not load within the time allowed.', attempted_at=timezone.now())
		self.make_row(scheme='http', port=80, outcome='unreachable', reason='The connection was refused.', attempted_at=timezone.now())
		record = self.record()
		self.assertFalse(record['screenshot'])
		self.assertIn('https://www.rt.test:443: The page did not load within the time allowed.', record['screenshot_note'])
		self.assertIn('http://www.rt.test:80: The connection was refused.', record['screenshot_note'])
		self.assertNotIn('None yet', record['screenshot_note'])

	def test_a_page_waiting_for_the_worker_says_so(self):
		self.make_row()
		self.assertIn('Waiting for the screenshot worker: https://www.rt.test:443', self.record()['screenshot_note'])

	def test_a_host_that_answers_on_the_web_but_was_never_photographed_says_when_it_will_be(self):
		note = self.record()['screenshot_note']
		self.assertIn('waiting for the next screenshot pass', note)
		self.assertIn('Take screenshot', note)

	def test_a_host_with_nothing_on_the_web_says_there_is_nothing_to_capture(self):
		self.host(name='db.rt.test', ports=((5432, 'postgresql'),), address='203.0.113.9')
		note = [r for r in call(self.token, 'GET', '/api/v1/projects/pr/hosts')[1]['results'] if r['host'] == 'db.rt.test'][0]['screenshot_note']
		self.assertEqual(note, 'None: no web page has answered on this host, so there is nothing to capture.')

	def test_a_server_without_the_browser_says_that(self):
		with mock.patch.object(web_shot, 'browser_installed', return_value=False):
			self.assertIn('Chromium is not installed on this server', self.record()['screenshot_note'])

	def test_a_discovery_screenshot_is_shown_and_a_later_failed_attempt_is_noted(self):
		Subdomain.objects.filter(pk=self.sub.pk).update(screenshot_path='rt.test_1/screenshots/old.png')
		self.make_row(outcome='tls_error', reason='The TLS handshake failed.', attempted_at=timezone.now())
		record = self.record()
		self.assertTrue(record['screenshot'])
		self.assertEqual(record['screenshot_source'], 'discovery')
		self.assertIn('An older screenshot from discovery is shown. The latest capture attempt: https://www.rt.test:443: The TLS handshake failed.', record['screenshot_note'])

	def test_a_rescan_row_with_no_screenshot_still_shows_the_older_rows_one(self):
		Subdomain.objects.filter(pk=self.sub.pk).update(screenshot_path='rt.test_1/screenshots/old.png')
		self.host(name='www.rt.test', ports=((443, 'https'), (80, 'http')))  # the newer row a rescan writes
		record = self.record()
		self.assertTrue(record['screenshot'])
		self.assertEqual(record['screenshot_note'], '')

	def test_two_pages_with_the_same_picture_are_listed_once_as_a_picture(self):
		first = self.shot_row(port=443)
		HostScreenshot.objects.filter(pk=first.pk).update(image_hash='abcd' * 4)
		second = self.shot_row(port=80, scheme='http')
		HostScreenshot.objects.filter(pk=second.pk).update(image_hash='abcd' * 4)
		self.assertEqual(len(web_shot.pictures(list(HostScreenshot.objects.all()))), 1)

	def test_an_rdp_port_that_needs_nla_carries_the_outcome_instead_of_nothing(self):
		sub = self.host(name='win.rt.test', ports=(), address='203.0.113.77')
		sub.ip_addresses.first().ports.add(Port.objects.create(number=3389, service_name='ms-wbt-server', state='open', extra={'scripts': {'rdp-enum-encryption': RDP_NLA_ONLY}}))
		web_shot.queue_for_subs([self.fresh(sub)], self.project.pk)
		record = self.record(sub)
		port = next(p for p in record['ips'][0]['ports'] if p['number'] == 3389)
		self.assertEqual(port['rdp_screenshot']['outcome'], 'nla_required')
		self.assertIsNone(port['rdp_screenshot']['url'])
		self.assertIn('Network Level Authentication', port['rdp_screenshot']['reason'])
		self.assertFalse(record['screenshot'])


class ApiTests(ReadFixture, TestCase):
	def setUp(self):
		super().setUp()
		self.sub = self.host(ports=((443, 'https'),))
		self.path = f'/api/v1/projects/pr/hosts/{self.sub.id}/screenshot'

	def user_token(self, name, role, read_only=False, project=None):
		user = User.objects.create_user(name, password='x')
		ProjectMembership.objects.create(user=user, project=project or self.project, role=role)
		return create_token(user, name, read_only=read_only)[1]

	def test_take_screenshot_queues_the_pages_for_a_person_and_answers_202(self):
		status, data = call(self.token, 'POST', self.path, {})
		self.assertEqual(status, 202, data)
		self.assertEqual((data['status'], data['queued'], data['pages']), ('queued', 1, ['https://www.rt.test:443']))
		row = HostScreenshot.objects.get()
		self.assertEqual((row.outcome, row.by_person, row.host), ('queued', True, 'www.rt.test'))
		self.kicked.assert_called_once()

	def test_a_second_press_while_it_waits_is_not_a_second_row(self):
		call(self.token, 'POST', self.path, {})
		status, data = call(self.token, 'POST', self.path, {})
		self.assertEqual((status, data['status']), (202, 'queued'))
		self.assertEqual(HostScreenshot.objects.count(), 1)

	def test_the_audit_role_and_a_read_only_token_cannot_press_it_but_can_read(self):
		for token in (self.user_token('shot-auditor', 'audit'), self.user_token('shot-ro', 'user', read_only=True)):
			self.assertEqual(call(token, 'POST', self.path, {})[0], 403)
			self.assertEqual(call(token, 'GET', self.path + 's')[0], 200)
		self.assertEqual(HostScreenshot.objects.count(), 0)

	def test_no_token_and_a_stranger_get_nothing(self):
		self.assertEqual(call(None, 'POST', self.path, {})[0], 401)
		other = Project.objects.create(name='Other', slug='other-shot', insert_date=timezone.now(), org=Org.objects.create(name='O', slug='o-shot'))
		stranger = self.user_token('shot-stranger', 'user', project=other)
		self.assertEqual(call(stranger, 'POST', self.path, {})[0], 404)
		self.assertEqual(call(stranger, 'GET', self.path + 's')[0], 404)
		self.assertEqual(HostScreenshot.objects.count(), 0)

	def test_the_all_projects_view_never_writes(self):
		status, data = call(self.token, 'POST', f'/api/v1/projects/_all/hosts/{self.sub.id}/screenshot', {})
		self.assertEqual((status, data['error']), (400, 'pick a project to make changes'))
		self.assertEqual(call(self.token, 'GET', f'/api/v1/projects/_all/hosts/{self.sub.id}/screenshots')[0], 400)

	def test_an_unknown_host_and_another_projects_host_are_404(self):
		self.assertEqual(call(self.token, 'POST', '/api/v1/projects/pr/hosts/999999/screenshot', {})[0], 404)
		other_project = Project.objects.create(name='P2', slug='p2-shot', insert_date=timezone.now(), org=self.project.org)
		domain = Domain.objects.create(name='p2.test', project=other_project, insert_date=timezone.now())
		foreign = Subdomain.objects.create(name='www.p2.test', target_domain=domain, scan_history=self.sub.scan_history)
		self.assertEqual(call(self.token, 'POST', f'/api/v1/projects/pr/hosts/{foreign.id}/screenshot', {})[0], 404)

	def test_an_excluded_an_archived_or_internal_host_is_refused_with_the_reason(self):
		HostState.objects.create(project=self.project, domain=self.domain, host='www.rt.test', archived_at=timezone.now())
		status, data = call(self.token, 'POST', self.path, {})
		self.assertEqual(status, 409)
		self.assertIn('archived', data['error'])
		HostState.objects.all().delete()
		HostExclusion.objects.create(org=self.project.org, host='www.rt.test')
		self.assertEqual(call(self.token, 'POST', self.path, {})[0], 409)
		self.assertEqual(HostScreenshot.objects.count(), 0)

	def test_the_bug_bounty_scope_still_applies_to_a_person(self):
		with mock.patch('cveFeed.bounty_gate.Gate.refusal', return_value='the program\'s scope does not name it'):
			status, data = call(self.token, 'POST', self.path, {})
		self.assertEqual(status, 409)
		self.assertIn('scope does not name it', data['error'])

	def test_a_server_without_the_browser_answers_503_with_why(self):
		with mock.patch.object(web_shot, 'browser_installed', return_value=False):
			status, data = call(self.token, 'POST', self.path, {})
		self.assertEqual(status, 503)
		self.assertIn('Chromium is not installed', data['error'])

	def test_a_host_with_no_known_web_port_is_tried_on_443_and_80_when_a_person_asks(self):
		sub = self.host(name='quiet.rt.test', ports=((22, 'ssh'),), address='203.0.113.50')
		status, data = call(self.token, 'POST', f'/api/v1/projects/pr/hosts/{sub.id}/screenshot', {})
		self.assertEqual((status, data['queued']), (202, 2))

	def test_the_status_lists_every_page_with_its_outcome_and_what_waits(self):
		self.make_row(outcome='timeout', reason='The page did not load within the time allowed.', attempted_at=timezone.now())
		self.make_row(scheme='http', port=80)
		status, data = call(self.token, 'GET', self.path + 's')
		self.assertEqual(status, 200)
		self.assertEqual((data['host'], data['queued'], data['available']), ('www.rt.test', 1, True))
		self.assertEqual({(p['scheme'], p['outcome']) for p in data['screenshots']}, {('https', 'timeout'), ('http', 'queued')})
		self.assertIn('did not load', data['note'] + str(data['screenshots']))

	def test_the_mcp_tools_exist_and_the_write_one_is_a_write(self):
		from agentapi import mcp
		tools = {name: write for name, _desc, _schema, _fn, write in mcp.TOOLS}
		self.assertTrue(tools['screenshot_host'])
		self.assertFalse(tools['get_host_screenshots'])


# ------------------------------------------------------------------------------------------------ counts, housekeeping, wiring

class StatusTests(ReadFixture, TestCase):
	def test_the_counts_say_how_many_hosts_have_a_picture_what_waits_and_the_last_error(self):
		self.host(name='a.rt.test', ports=((443, 'https'),), address='203.0.113.21')
		self.host(name='b.rt.test', ports=((443, 'https'),), address='203.0.113.22')
		self.host(name='c.rt.test', ports=((22, 'ssh'),), address='203.0.113.23')
		self.make_row(host='a.rt.test', outcome='ok', image_path='x.png')
		self.make_row(host='a.rt.test', scheme='http', port=80, outcome='ok', image_path='y.png')
		self.make_row(host='b.rt.test', outcome='timeout', reason='The page did not load within the time allowed.', attempted_at=timezone.now())
		self.make_row(host='b.rt.test', scheme='http', port=80, outcome='queued')
		self.make_row(host='b.rt.test', scheme='http', port=8080, outcome='blocked', reason='Not captured: x')
		self.make_row(host='b.rt.test', scheme='rdp', port=3389, outcome='nla_required', reason='NLA')
		counts = web_shot.status_counts([self.project.pk])
		self.assertEqual((counts['hosts_with_web'], counts['hosts_with_screenshot']), (2, 1))
		self.assertEqual((counts['queued'], counts['failed'], counts['blocked'], counts['nla_required']), (1, 1, 1, 1))
		self.assertEqual(counts['pages']['ok'], 2)
		self.assertEqual(counts['last_error']['page'], 'https://b.rt.test:443')
		self.assertEqual(counts['last_error']['outcome'], 'timeout')
		self.assertTrue(counts['available'])
		self.assertIsNone(counts['unavailable_reason'])

	def test_the_system_status_carries_them_per_project_and_the_browser_for_admins(self):
		from agentapi import system_status
		self.make_row(outcome='ok', image_path='x.png')
		row = system_status._project_row(self.project)
		self.assertEqual(row['screenshots']['hosts_with_screenshot'], 1)
		problems, notes = [], []
		cache.set('screenshots:last_browser_error', {'at': '2026-11-01T00:00:00+00:00', 'error': 'The browser stopped.'}, 60)
		out = system_status._screenshots(problems, notes)
		self.assertEqual((out['enabled'], out['chromium_installed'], out['queued']), (True, True, 0))
		self.assertTrue(any('screenshots: the browser last failed to run' in p and 'The browser stopped.' in p for p in problems))
		problems, notes = [], []
		cache.delete('screenshots:last_browser_error')
		with mock.patch.object(web_shot, 'browser_installed', return_value=False):
			system_status._screenshots(problems, notes)
		self.assertEqual(problems, [])
		self.assertTrue(any('Chromium is not installed' in n for n in notes))  # a note, not a problem: the rest of the image runs fine

	def test_the_queue_and_the_browser_are_in_the_status_listings(self):
		from agentapi import system_status
		self.assertIn('screenshot_queue', system_status.QUEUES)
		self.assertEqual(system_status._chromium_version(), web_shot.pinned_browser()['version'])
		with mock.patch.object(web_shot, 'browser_installed', return_value=False):
			self.assertIsNone(system_status._chromium_version())


class HousekeepingTests(ReadFixture, TestCase):
	def test_deleting_a_host_removes_its_rows_and_its_picture_files(self):
		sub = self.host()
		row = self.make_row(outcome='ok', image_path=f'screenshots/{self.project.pk}/www.rt.test/https-443-1.png',
							thumb_path=f'screenshots/{self.project.pk}/www.rt.test/https-443-1.png.thumb-320.jpg',
							previous_image_path=f'screenshots/{self.project.pk}/www.rt.test/https-443-0.png')
		for rel in (row.image_path, row.thumb_path, row.previous_image_path):
			self.plant(rel)
		self.make_row(host='other.rt.test', outcome='ok', image_path=f'screenshots/{self.project.pk}/other.rt.test/https-443-1.png')
		self.plant(f'screenshots/{self.project.pk}/other.rt.test/https-443-1.png')
		admin = User.objects.create_superuser('shot-admin', 'a@x.test', 'x')
		_, token = create_token(admin, 'admin')
		with mock.patch('reNgine.common_func.SCAN_RESULTS_ROOT', self.media):  # the media root of this test is where the files were planted
			status, data = call(token, 'POST', '/api/v1/projects/pr/hosts/www.rt.test/delete', {})
		self.assertEqual(status, 200, data)
		self.assertEqual(data['web_screenshots'], 1)
		self.assertEqual(list(HostScreenshot.objects.values_list('host', flat=True)), ['other.rt.test'])
		self.assertFalse(os.path.exists(os.path.join(self.media, f'screenshots/{self.project.pk}/www.rt.test')))
		self.assertTrue(os.path.isfile(os.path.join(self.media, f'screenshots/{self.project.pk}/other.rt.test/https-443-1.png')))
		self.assertTrue(sub)

	def test_moving_a_target_to_another_project_takes_its_captures_along(self):
		from agentapi import target_move
		self.make_row(outcome='ok', image_path='x.png')
		destination = Project.objects.create(name='Dest', slug='dest-shot', insert_date=timezone.now(), org=self.project.org)
		with mock.patch('cveFeed.exclusions.is_excluded', return_value=False):
			target_move.repoint(self.project, destination, [self.domain], {'www.rt.test'})
		self.assertEqual(HostScreenshot.objects.get().project_id, destination.pk)

	def test_the_model_is_one_row_per_page_and_is_tenancy_scoped(self):
		from django.db import IntegrityError, transaction
		from tenancy.scope import SCOPES
		self.make_row()
		with self.assertRaises(IntegrityError), transaction.atomic():
			self.make_row()
		self.make_row(scheme='http', port=80)
		self.assertEqual(SCOPES['cveFeed.HostScreenshot'], 'project_id')

	def test_the_files_are_only_ever_removed_from_the_screenshots_directory(self):
		keep = self.plant('other_dir/keep.png')
		inside = self.plant('screenshots/1/h/a.png')
		web_shot.remove_files('other_dir/keep.png', 'screenshots/1/h/a.png', '../etc/hosts', '')
		self.assertTrue(os.path.isfile(keep))
		self.assertFalse(os.path.exists(inside))


class WiringTests(TestCase):
	def test_the_tasks_have_a_queue_of_their_own_which_the_classic_worker_consumes(self):
		from cveFeed import tasks
		from reNgine import time_limits
		from tests.test_entrypoint import worker_commands
		self.assertEqual(tasks.drain_screenshots.queue, 'screenshot_queue')
		self.assertEqual(tasks.screenshot_backfill.queue, 'screenshot_queue')
		commands = worker_commands()
		self.assertLessEqual(len(commands), 4)  # still the four workers: no fifth process
		owners = [c for c in commands if 'screenshot_queue' in c]
		self.assertEqual(len(owners), 1)
		self.assertIn('-n classic_worker', owners[0])
		self.assertIsNotNone(time_limits.limits_for('screenshot_queue'))

	def test_the_hourly_backfill_is_scheduled_on_its_queue(self):
		from django_celery_beat.models import PeriodicTask
		task = PeriodicTask.objects.get(name='cvengine-screenshot-backfill')
		self.assertEqual((task.task, task.queue, task.enabled, task.crontab.minute, task.crontab.hour), ('screenshot_backfill', 'screenshot_queue', True, '41', '*'))

	def test_the_browser_is_a_memory_gated_heavy_job_that_runs_one_at_a_time(self):
		from reNgine import resources
		self.assertIn('screenshot', resources.BASE_COSTS_MB)
		self.assertEqual(resources.MAX_CONCURRENT['screenshot'], 1)
		self.assertEqual(web_shot.HEAVY_KIND, 'screenshot')

	def test_paused_scanning_defers_the_screenshot_tasks(self):
		from cveFeed import scan_control, tasks
		self.assertNotIn('drain_screenshots', scan_control.PAUSE_EXEMPT_TASKS)
		self.assertNotIn('screenshot_backfill', scan_control.PAUSE_EXEMPT_TASKS)
		self.assertTrue(tasks.drain_screenshots.name and tasks.screenshot_backfill.name)

	def test_the_chromium_pin_in_the_dockerfile_is_the_build_the_pinned_playwright_drives(self):
		"""A Playwright bump that moves the browser fails here until the Dockerfile's pin (which the image build also checks against a real launch) is read and updated."""
		import re
		from pathlib import Path
		root = Path(__file__).resolve().parents[2]
		dockerfile = (root / 'web' / 'Dockerfile').read_text()
		pin = re.search(r'(?m)^ARG PLAYWRIGHT_CHROMIUM_VERSION=(\S+)$', dockerfile).group(1)
		self.assertEqual(pin, web_shot.pinned_browser()['version'])
		self.assertIn('playwright install --with-deps --only-shell chromium', dockerfile)
		self.assertIn('runuser -u nobody', dockerfile)  # the build launches it as the account the worker runs it as
		self.assertRegex((root / 'web' / 'requirements.txt').read_text(), r'(?m)^playwright==\d+\.\d+\.\d+$')

	def test_the_browser_is_in_the_bill_of_materials_and_the_tool_version_check(self):
		import importlib.util
		from pathlib import Path
		root = Path(__file__).resolve().parents[2]
		for name in ('generate_sbom', 'check_tool_versions'):
			spec = importlib.util.spec_from_file_location(name, root / 'scripts' / f'{name}.py')
			module = importlib.util.module_from_spec(spec)
			spec.loader.exec_module(module)
			if name == 'generate_sbom':
				components = {c['name']: c for c in module.build()['components']}
				chromium = components['chromium (Playwright headless shell)']
				self.assertEqual(chromium['version'], web_shot.pinned_browser()['version'])
				self.assertRegex(components['playwright']['version'], r'^\d+\.\d+\.\d+$')
			else:
				rows = {r['tool']: r for r in module.collect(lambda url, as_json=True: {})}
				self.assertRegex(rows['playwright (screenshot browser; its Chromium build is pinned by it)']['pinned'], r'^\d+\.\d+\.\d+$')

	def test_the_browser_install_is_looked_up_from_the_pinned_playwright(self):
		pinned = web_shot.pinned_browser()
		self.assertRegex(pinned['revision'], r'^\d+$')
		self.assertRegex(pinned['version'], r'^\d+\.\d+\.\d+\.\d+$')
		with tempfile.TemporaryDirectory() as root, mock.patch.dict(os.environ, {'PLAYWRIGHT_BROWSERS_PATH': root}):
			self.assertFalse(web_shot.browser_installed())
			os.makedirs(os.path.join(root, f'chromium_headless_shell-{pinned["revision"]}'))
			self.assertFalse(web_shot.browser_installed())  # the installer's completion marker is what counts
			open(os.path.join(root, f'chromium_headless_shell-{pinned["revision"]}', 'INSTALLATION_COMPLETE'), 'w').close()
			self.assertTrue(web_shot.browser_installed())
		self.assertIn('Chromium is not installed', web_shot.unavailable_reason() if not web_shot.browser_installed() else 'Chromium is not installed')
