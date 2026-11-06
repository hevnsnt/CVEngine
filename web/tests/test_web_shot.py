import base64
import io
import os
import shutil
import tempfile
import time
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from agentapi.auth import create_token
from agentapi.models import SentinelTask
from cveFeed import web_shot
from cveFeed.models import HostExclusion, HostScreenshot, HostState, InternalRange
from dashboard.models import Org, Project, ProjectMembership
from startScan.models import IpAddress, Port, Subdomain
from targetApp.models import Domain
from tests.fake_scanner import FakeScanner, LocalFallback, assert_ran_nowhere_locally
from tests.test_agentapi import call
from tests.test_route_auth import RouteFixture
from tests.test_service_intel import RDP_ENC, RDP_NLA_ONLY

from PIL import Image
from tests.port_stage_stub import port_double


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


def shot_result(task, plan=None, sandbox=None, **extra):
	"""What a Sentinel answers for a ``web_screenshot`` task: one page per page of the task, as ``plan`` says by host (``{host: {outcome, reason, final_url,
	status, title, image}}``; a page not in the plan is photographed with a picture of its own)."""
	from urllib.parse import urlsplit
	plan = plan or {}
	pages = []
	for page in task['target']['pages']:
		spec = dict(plan.get(urlsplit(page['url']).hostname, {}))
		outcome = spec.pop('outcome', 'ok')
		item = {'id': page['id'], 'outcome': outcome, 'reason': spec.pop('reason', ''), 'final_url': spec.pop('final_url', page['url'] if outcome == 'ok' else ''),
				'status': spec.pop('status', 200 if outcome == 'ok' else None), 'title': spec.pop('title', '')}
		if outcome == 'ok':
			item['image'] = base64.b64encode(spec.pop('image', None) or png(noise=int(page['id']) % 900 + 1)).decode()
		pages.append(item)
	return {'outcome': 'done', 'sandbox': sandbox or {'engaged': True, 'reason': '', 'version': '156.0.8078.4'}, 'pages': pages,
			'touched': [], 'refused': [], 'dropped_requests': 0, **extra}


class Scanner:
	"""A fake Sentinel that takes ``web_screenshot`` (and nothing else), answering through ``shot_result``; ``tasks`` are the targets it was handed."""

	def __init__(self, plan=None, wait='60', **kw):
		self.tasks, self.plan, self.wait, self.kw = [], plan, wait, kw

	def respond(self, task):
		self.tasks.append(task['target'])
		return shot_result(task, self.plan, **self.kw)

	def mode(self, mode):
		self.fake.set_mode(mode)

	def __enter__(self):
		# the fake serves one task per poll of the virtual clock, so the claim budget (one second by default) is widened for a drain of several tasks
		self.env = mock.patch.dict(os.environ, {'CVENGINE_SENTINEL_CLAIM_TIMEOUT': self.wait, 'CVENGINE_SENTINEL_DISPATCH_TIMEOUT': self.wait})
		self.env.start()
		self.fake = FakeScanner(kinds=['web_screenshot'], responders={'web_screenshot': self.respond})
		self.local = LocalFallback('none')
		self.local.__enter__()
		self.fake.__enter__()
		return self

	def __exit__(self, *exc):
		self.fake.__exit__(*exc)
		self.local.__exit__(*exc)
		self.env.stop()


class ShotFixture(RouteFixture):
	"""A project with a target and a media directory of its own. No browser is ever launched here: the pictures come from a fake Sentinel."""

	def setUp(self):
		super().setUp()
		self.media = tempfile.mkdtemp()
		self.addCleanup(shutil.rmtree, self.media, ignore_errors=True)
		override = override_settings(MEDIA_ROOT=self.media)
		override.enable()
		self.addCleanup(override.disable)
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

	def test_a_scan_with_no_web_service_has_no_work_and_switched_off_means_no_stage(self):
		self.assertTrue(web_shot.has_work_for_scan(self.scan()))
		self.assertFalse(web_shot.has_work_for_scan(self.scan(names=('db.rt.test',), ports=((5432, 'postgresql'),), ip='203.0.113.9')))
		with mock.patch.dict(os.environ, {'CVENGINE_SCREENSHOTS': '0'}):
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
										 port_stage_run=port_double(),
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

	def test_switched_off_or_no_web_page_means_no_stage_row(self):
		from startScan.models import ScanActivity
		with mock.patch.dict(os.environ, {'CVENGINE_SCREENSHOTS': '0'}):
			self.run_stages(self.scan())
		self.run_stages(self.scan(names=('db.rt.test',), ports=((5432, 'postgresql'),), ip='203.0.113.9'))
		self.assertFalse(ScanActivity.objects.filter(name='web_screenshot').exists())


# ------------------------------------------------------------------------------------------------ the guards, per connection

# ------------------------------------------------------------------------------------------------ capturing

# ------------------------------------------------------------------------------------------------ the hourly backfill

class BackfillTests(ShotFixture, TestCase):
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

	def test_a_paused_instance_screenshots_switched_off_and_a_blocked_project_queue_nothing(self):
		project = self.project_with_hosts('bf-a', 2)
		with mock.patch('cveFeed.scan_control.pause_requested', return_value=True):
			self.assertEqual(web_shot.backfill()['skipped'], 'scanning is paused')
		with mock.patch.dict(os.environ, {'CVENGINE_SCREENSHOTS': '0'}):
			self.assertIn('switched off', web_shot.backfill()['skipped'])
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
		with Scanner(), mock.patch('cveFeed.ledger.sweep_claim', return_value=True):
			out = web_shot.sweep()
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
		self.assertNotIn('No screenshot yet', record['screenshot_note'])

	def test_a_page_waiting_for_the_worker_says_so(self):
		self.make_row()
		self.assertIn('Waiting for a scanner to take the screenshot (the pages stay queued until one can): https://www.rt.test:443', self.record()['screenshot_note'])

	def test_a_host_that_answers_on_the_web_but_was_never_photographed_says_when_it_will_be(self):
		note = self.record()['screenshot_note']
		self.assertIn('waiting for the next screenshot pass', note)
		self.assertIn('Take screenshot', note)

	def test_a_host_with_nothing_on_the_web_says_there_is_nothing_to_capture(self):
		self.host(name='db.rt.test', ports=((5432, 'postgresql'),), address='203.0.113.9')
		note = [r for r in call(self.token, 'GET', '/api/v1/projects/pr/hosts')[1]['results'] if r['host'] == 'db.rt.test'][0]['screenshot_note']
		self.assertEqual(note, 'No screenshot: no web port (such as 80 or 443) is recorded open on this host, so there is no page to capture.')

	def test_a_server_with_screenshots_switched_off_says_that(self):
		with mock.patch.dict(os.environ, {'CVENGINE_SCREENSHOTS': '0'}):
			self.assertIn('switched off on this server', self.record()['screenshot_note'])

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

	def test_a_server_with_screenshots_switched_off_answers_503_with_why(self):
		with mock.patch.dict(os.environ, {'CVENGINE_SCREENSHOTS': '0'}):
			status, data = call(self.token, 'POST', self.path, {})
		self.assertEqual(status, 503)
		self.assertIn('switched off', data['error'])

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

	def test_the_system_status_carries_them_per_project_and_the_last_sandbox_proof_for_admins(self):
		from agentapi import system_status
		self.make_row(outcome='ok', image_path='x.png')
		row = system_status._project_row(self.project)
		self.assertEqual(row['screenshots']['hosts_with_screenshot'], 1)
		problems, notes = [], []
		out = system_status._screenshots(problems, notes)
		self.assertEqual((out['enabled'], out['queued'], out['sandbox']['state']), (True, 0, 'unchecked'))
		self.assertNotIn('chromium_installed', out)  # no browser runs on this server
		self.assertEqual((problems, notes), ([], []))
		with self.assertLogs('cveFeed.web_shot', 'ERROR'):
			web_shot.record_sandbox(False, 'the renderer shares the user namespace of the browser')
		problems, notes = [], []
		system_status._screenshots(problems, notes)
		self.assertTrue(any('screenshots: the renderer shares the user namespace' in p for p in problems))
		web_shot.record_sandbox(True, version='156.0.8078.4')
		self.assertEqual(web_shot.sandbox_status()['state'], 'engaged')
		with mock.patch.dict(os.environ, {'CVENGINE_SCREENSHOTS': '0'}):
			problems, notes = [], []
			system_status._screenshots(problems, notes)
		self.assertTrue(any('switched off' in n for n in notes))  # a note, not a problem

	def test_the_queue_is_in_the_status_listings_and_no_browser_version_is(self):
		from agentapi import system_status
		self.assertIn('screenshot_queue', system_status.QUEUES)
		self.assertFalse(hasattr(system_status, '_chromium_version'))


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

	def test_paused_scanning_defers_the_screenshot_tasks(self):
		from cveFeed import scan_control, tasks
		self.assertNotIn('drain_screenshots', scan_control.PAUSE_EXEMPT_TASKS)
		self.assertNotIn('screenshot_backfill', scan_control.PAUSE_EXEMPT_TASKS)
		self.assertTrue(tasks.drain_screenshots.name and tasks.screenshot_backfill.name)

	def test_the_server_image_carries_no_browser_and_no_capture_code(self):
		from pathlib import Path
		root = Path(__file__).resolve().parents[2]
		self.assertNotRegex((root / 'web' / 'requirements.txt').read_text().lower(), r'(?m)^playwright')
		dockerfile = (root / 'web' / 'Dockerfile').read_text()
		self.assertNotIn('playwright', dockerfile.lower())
		self.assertNotIn('PLAYWRIGHT_CHROMIUM_VERSION', dockerfile)
		for name in ('shot_worker.py', 'shot_proxy.py', 'management/commands/check_screenshot_sandbox.py'):
			self.assertFalse((root / 'web' / 'cveFeed' / name).exists(), name)
		self.assertNotIn('check_screenshot_sandbox', (root / 'web' / 'celery-entrypoint.sh').read_text())
		for name in ('run_child', 'Guard', 'launch', 'check_sandbox', 'pinned_browser', 'browser_installed', 'stack_blocklist', 'read_picture'):
			self.assertFalse(hasattr(web_shot, name), name)

	def test_the_browser_is_not_in_the_bill_of_materials_or_the_tool_version_check(self):
		import importlib.util
		from pathlib import Path
		root = Path(__file__).resolve().parents[2]
		for name in ('generate_sbom', 'check_tool_versions'):
			spec = importlib.util.spec_from_file_location(name, root / 'scripts' / f'{name}.py')
			module = importlib.util.module_from_spec(spec)
			spec.loader.exec_module(module)
			if name == 'generate_sbom':
				names = {c['name'] for c in module.build()['components']}
				self.assertFalse([n for n in names if 'chromium' in n.lower() or n == 'playwright'])
			else:
				self.assertFalse([r for r in module.collect(lambda url, as_json=True: {}) if 'playwright' in r['tool'] or 'chromium' in r['tool']])

	def test_web_screenshot_never_runs_on_this_server(self):
		from agentapi import sentinel_dispatch
		self.assertIn('web_screenshot', sentinel_dispatch.NEVER_LOCAL)
		self.assertIn('web_screenshot', SentinelTask.KINDS)
		with mock.patch.dict(os.environ, {'CVENGINE_LOCAL_FALLBACK': 'all'}):
			self.assertFalse(sentinel_dispatch.fallback_allowed('web_screenshot'))


# ------------------------------------------------------------------------------------------------ review round: hardening

class PictureFileTests(ShotFixture, TestCase):
	def test_the_stored_picture_is_a_new_file_of_our_own_and_never_overwrites(self):
		target = os.path.join(self.media, 'screenshots', '1', 'h', 'a.png')
		web_shot.write_new(target, b'x')
		self.assertEqual(oct(os.stat(target).st_mode & 0o777), '0o644')
		with self.assertRaises(FileExistsError):
			web_shot.write_new(target, b'y')
		os.remove(target)
		os.symlink('/etc/hostname', target)
		with self.assertRaises(OSError):
			web_shot.write_new(target, b'z')

	def test_two_hosts_that_differ_only_in_replaced_characters_have_their_own_directories(self):
		self.assertNotEqual(web_shot.safe_name('a*b.example.test'), web_shot.safe_name('a_b.example.test'))
		self.assertNotEqual(web_shot.safe_name('x' * 80 + '1.example'), web_shot.safe_name('x' * 80 + '2.example'))
		self.assertEqual(web_shot.safe_name('WWW.Example.test'), web_shot.safe_name('www.example.test'))
		self.assertRegex(web_shot.safe_name('www.example.test'), r'^www\.example\.test-[0-9a-f]{8}$')


class OrphanFileTests(ShotFixture, TestCase):
	def test_a_row_deleted_by_a_cascade_takes_its_files_and_empty_directories_with_it(self):
		rel = f'screenshots/{self.project.pk}/www.rt.test-abcd1234/https-443-1.png'
		previous = f'screenshots/{self.project.pk}/www.rt.test-abcd1234/https-443-0.png'
		self.plant(rel)
		self.plant(previous)
		self.plant(rel + web_shot.THUMB_SUFFIX)
		self.make_row(outcome='ok', image_path=rel, previous_image_path=previous)
		self.domain.delete()  # the project's target goes, and its rows with it
		self.assertEqual(HostScreenshot.objects.count(), 0)
		self.assertFalse(os.path.exists(os.path.join(self.media, 'screenshots', str(self.project.pk))))

	def test_a_queued_row_whose_host_is_gone_loses_its_picture_files_too(self):
		sub = self.host(ports=((443, 'https'),))
		rel = f'screenshots/{self.project.pk}/www.rt.test-abcd1234/https-443-1.png'
		self.plant(rel)
		self.make_row(outcome='queued', image_path=rel)
		Subdomain.objects.filter(pk=sub.pk).delete()
		web_shot.drain()  # the page is judged first: no scanner is needed to forget it
		self.assertFalse(os.path.exists(os.path.join(self.media, rel)))

	def test_the_sweep_removes_old_files_no_row_names_and_keeps_the_rest(self):
		kept = f'screenshots/{self.project.pk}/h-1/a.png'
		old_orphan = f'screenshots/{self.project.pk}/h-2/b.png'
		new_orphan = f'screenshots/{self.project.pk}/h-2/c.png'
		for rel in (kept, old_orphan, new_orphan):
			self.plant(rel)
		self.make_row(outcome='ok', image_path=kept)
		long_ago = time.time() - 3 * 86400
		os.utime(os.path.join(self.media, kept), (long_ago, long_ago))
		os.utime(os.path.join(self.media, old_orphan), (long_ago, long_ago))
		self.assertEqual(web_shot.sweep_orphans(), 1)
		self.assertTrue(os.path.exists(os.path.join(self.media, kept)))
		self.assertFalse(os.path.exists(os.path.join(self.media, old_orphan)))
		self.assertTrue(os.path.exists(os.path.join(self.media, new_orphan)))  # a young file may be one being written

	def test_the_storage_a_project_uses_counts_the_comparison_copies(self):
		self.make_row(outcome='ok', image_path='a', image_bytes=100, previous_image_path='b', previous_image_bytes=40)
		self.assertEqual(web_shot.project_bytes(self.project.pk), 140)

	def test_the_weekly_maintenance_runs_the_sweep(self):
		import inspect

		from cveFeed import tasks
		self.assertIn('sweep_orphans', inspect.getsource(tasks.weekly_maintenance))


class ByPersonTests(ShotFixture, TestCase):
	def test_a_persons_request_is_used_up_by_the_capture_and_not_carried_into_a_later_unattended_one(self):
		sub = self.host(ports=((443, 'https'),))
		web_shot.queue_for_subs([sub], self.project.pk, by_person=True)
		self.assertTrue(HostScreenshot.objects.get().by_person)
		with Scanner():
			web_shot.drain()
		self.assertFalse(HostScreenshot.objects.get().by_person)
		HostScreenshot.objects.update(outcome='timeout', by_person=True, attempted_at=timezone.now() - timedelta(days=3))  # e.g. left over from an interrupted run
		web_shot.queue_for_subs([sub], self.project.pk)  # the backfill or a scan asks again
		self.assertEqual(HostScreenshot.objects.get().outcome, 'queued')
		self.assertFalse(HostScreenshot.objects.get().by_person)


class BackfillStarvationTests(ShotFixture, TestCase):
	def test_an_excluded_subtree_does_not_starve_the_hosts_behind_it(self):
		from startScan.models import ScanHistory
		scan = ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, start_scan_date=timezone.now(), scan_status=2, tasks=[], results_dir='x')
		ip, _ = IpAddress.objects.get_or_create(address='198.51.100.77')
		ip.ports.add(Port.objects.create(number=443, service_name='https', state='open'))
		for i in range(30):  # newest ids first: the excluded names crowd the top of the list
			sub = Subdomain.objects.create(name=f'ok{i}.rt.test', target_domain=self.domain, scan_history=scan)
			sub.ip_addresses.add(ip)
		for i in range(30):
			sub = Subdomain.objects.create(name=f'bad{i}.skip.rt.test', target_domain=self.domain, scan_history=scan)
			sub.ip_addresses.add(ip)
		HostExclusion.objects.create(org=self.project.org, host='skip.rt.test', include_subdomains=True)
		out = web_shot.backfill(per_project=5, total=50)
		self.assertEqual(out['queued'], 5)
		self.assertFalse(HostScreenshot.objects.filter(host__contains='skip').exists())

	def test_a_cdn_host_whose_only_web_port_is_an_edge_port_gets_a_marker_row_so_it_is_not_planned_every_hour(self):
		sub = self.host(ports=((8443, 'https-alt'),))
		IpAddress.objects.filter(address='203.0.113.5').update(is_cdn=True)
		web_shot.queue_for_subs([self.fresh(sub)], self.project.pk)
		row = HostScreenshot.objects.get()
		self.assertEqual((row.outcome, row.port), ('blocked', 8443))
		self.assertIn('behind a CDN', row.reason)


# ------------------------------------------------------------------------------------------------ the drain: pages go to a Sentinel and the pictures come back

class SentinelCaptureTests(ShotFixture, TestCase):
	def setUp(self):
		super().setUp()
		self.sub = self.host(ports=((443, 'https'),))

	def queue(self, **kw):
		web_shot.queue_for_subs([self.sub], self.project.pk, **kw)
		return HostScreenshot.objects.get(host='www.rt.test', scheme='https', port=443)

	def test_a_good_page_is_stored_with_everything_the_host_page_needs(self):
		row = self.queue()
		with Scanner({'www.rt.test': {'title': 'Welcome', 'final_url': 'https://www.rt.test/home', 'status': 200}}) as scanner:
			out = web_shot.drain()
		self.assertEqual((out['captured'], out['failed'], out['blocked']), (1, 0, 0))
		row.refresh_from_db()
		self.assertEqual((row.outcome, row.reason, row.http_status, row.title, row.final_url), ('ok', '', 200, 'Welcome', 'https://www.rt.test/home'))
		self.assertTrue(row.captured_at and row.attempted_at and not row.queued_at)
		self.assertRegex(row.image_path, rf'^screenshots/{self.project.pk}/www\.rt\.test-[0-9a-f]{{8}}/https-443-\d+\.png$')
		self.assertTrue(os.path.isfile(os.path.join(self.media, row.image_path)))
		self.assertTrue(os.path.isfile(os.path.join(self.media, row.thumb_path)))
		self.assertRegex(row.image_hash, r'^[0-9a-f]{16}$')
		self.assertEqual(row.image_bytes, os.path.getsize(os.path.join(self.media, row.image_path)))
		self.assertEqual(len(scanner.tasks), 1)

	def test_the_task_names_the_page_by_the_rows_own_id_and_carries_the_policy_and_the_limits(self):
		row = self.queue()
		HostExclusion.objects.create(org=self.project.org, host='skip.rt.test', include_subdomains=True)
		HostExclusion.objects.create(org=self.project.org, host='one.rt.test')
		with Scanner() as scanner:
			web_shot.drain()
		target = scanner.tasks[0]
		self.assertEqual(target['pages'], [{'id': str(row.pk), 'url': 'https://www.rt.test/'}])
		self.assertEqual(target['scope']['hosts'], ['www.rt.test'])
		self.assertTrue(set(target['scope']['excluded']) >= {'skip.rt.test', 'one.rt.test'})
		self.assertEqual(target['scope']['excluded_trees'], ['skip.rt.test'])
		self.assertEqual((target['scope']['private'], target['scope']['domains']), (False, []))
		self.assertTrue(target['open_web'])  # no bug bounty program: a page's own fonts and scripts may load
		self.assertEqual((target['timeout_seconds'], target['max_bytes']), (20, web_shot.DEFAULT_MAX_BYTES))
		from agentapi import sentinel_contract
		from jsonschema import Draft202012Validator
		doc = sentinel_contract.load()
		Draft202012Validator({'$ref': '#/$defs/targets/web_screenshot', '$defs': doc['$defs']}).validate(target)

	def test_a_bug_bounty_project_may_only_load_the_listed_hosts(self):
		from cveFeed.models import BountyEngagement, BountyProgram
		program = BountyProgram.objects.create(platform='hackerone', handle='acme', name='Acme')
		BountyEngagement.objects.create(project=self.project, program=program, status='active')
		with Scanner() as scanner, mock.patch('cveFeed.bounty_gate.Gate.refusal', return_value=''):
			self.queue(by_person=True)
			web_shot.drain()
		self.assertFalse(scanner.tasks[0]['open_web'])

	def test_an_exclusion_list_too_long_for_the_policy_closes_the_open_web(self):
		from cveFeed import probe_scope
		HostExclusion.objects.bulk_create([HostExclusion(org=self.project.org, host=f'x{i}.rt.test') for i in range(probe_scope.MAX_EXCLUDED + 1)])
		policy, open_web = probe_scope.for_screenshots(self.project.pk, ['www.rt.test'])
		self.assertFalse(open_web)
		self.assertEqual(len(policy['excluded']), probe_scope.MAX_EXCLUDED)

	def test_no_pages_of_two_projects_ever_share_a_task(self):
		other = self.project_with_hosts('two', 1)
		self.queue()
		web_shot.queue_for_subs(list(Subdomain.objects.filter(target_domain__project=other)), other.pk)
		with Scanner() as scanner:
			web_shot.drain()
		self.assertEqual(sorted(len(t['pages']) for t in scanner.tasks), [1, 1])
		self.assertEqual({p['url'].split('/')[2] for t in scanner.tasks for p in t['pages']}, {'www.rt.test', 'h0.two.test'})

	def test_a_long_queue_goes_in_tasks_of_at_most_six_pages(self):
		for i in range(14):
			name = f'h{i}.rt.test'
			Subdomain.objects.create(name=name, target_domain=self.domain, scan_history=self.sub.scan_history)
			self.make_row(host=name)
		with Scanner() as scanner:
			out = web_shot.drain()
		self.assertEqual(sorted(len(t['pages']) for t in scanner.tasks), [2, 6, 6])
		self.assertEqual(out['captured'], 14)
		self.assertFalse(HostScreenshot.objects.filter(outcome='queued').exists())

	def test_a_page_that_redirects_to_another_host_says_so(self):
		row = self.queue()
		with Scanner({'www.rt.test': {'final_url': 'https://acme-site.example/'}}):
			web_shot.drain()
		row.refresh_from_db()
		self.assertEqual(row.outcome, 'ok')
		self.assertEqual(row.reason, 'Redirects to https://acme-site.example/ (another host).')

	def test_an_error_page_is_still_a_picture_with_its_status_as_the_reason(self):
		row = self.queue()
		with Scanner({'www.rt.test': {'status': 403}}):
			web_shot.drain()
		row.refresh_from_db()
		self.assertEqual((row.outcome, row.http_status, row.reason), ('ok', 403, 'The server answered HTTP 403.'))

	def test_what_the_scanner_could_not_photograph_keeps_its_reason_and_the_old_picture(self):
		row = self.queue()
		with Scanner() as scanner:
			web_shot.drain()
			row.refresh_from_db()
			old = row.image_path
			for outcome, counted in (('timeout', 'failed'), ('blocked', 'blocked'), ('too_big', 'failed')):
				HostScreenshot.objects.filter(pk=row.pk).update(outcome='queued')
				scanner.plan = {'www.rt.test': {'outcome': outcome, 'reason': f'it was {outcome}'}}
				out = web_shot.drain()
				row.refresh_from_db()
				self.assertEqual((row.outcome, row.reason, row.image_path, out[counted]), (outcome, f'it was {outcome}', old, 1), outcome)

	def test_a_flat_color_picture_is_a_blank_page_whatever_the_scanner_says(self):
		row = self.queue()
		with Scanner({'www.rt.test': {'image': png(flat=True)}}):
			out = web_shot.drain()
		row.refresh_from_db()
		self.assertEqual((row.outcome, row.image_path, out['failed']), ('blank', '', 1))

	def test_a_picture_that_is_not_a_png_is_never_stored(self):
		row = self.queue()
		with Scanner({'www.rt.test': {'image': b'<html>not an image</html>' + b'x' * 60}}):
			web_shot.drain()
		row.refresh_from_db()
		self.assertEqual((row.outcome, row.image_path), ('error', ''))
		self.assertIn('not a usable PNG', row.reason)
		self.assertEqual(os.listdir(self.media), [])

	def test_a_page_the_scanner_did_not_report_is_unavailable_never_a_state_and_the_rest_are_kept(self):
		other = self.make_row(host='b.rt.test')
		Subdomain.objects.create(name='b.rt.test', target_domain=self.domain, scan_history=self.sub.scan_history)
		row = self.queue()

		def respond(task):
			result = shot_result(task)
			result['pages'] = [p for p in result['pages'] if p['id'] != str(other.pk)]
			return result
		fake = FakeScanner(kinds=['web_screenshot'], responders={'web_screenshot': respond})
		with LocalFallback('none'), fake:
			out = web_shot.drain()
		other.refresh_from_db()
		row.refresh_from_db()
		self.assertEqual((row.outcome, other.outcome, out['captured'], out['failed']), ('ok', 'unavailable', 1, 1))
		self.assertIn('reported nothing', other.reason)

	def test_an_id_the_task_did_not_name_is_dropped_and_names_are_never_used(self):
		row = self.queue()

		def respond(task):
			result = shot_result(task)
			evil = dict(result['pages'][0], id='999999', image=result['pages'][0]['image'])
			result['pages'].append(evil)
			result['pages'][0]['title'] = '../../etc/passwd'
			result['pages'][0]['final_url'] = '../../x'
			return result
		with LocalFallback('none'), FakeScanner(kinds=['web_screenshot'], responders={'web_screenshot': respond}):
			web_shot.drain()
		row.refresh_from_db()
		self.assertEqual(row.outcome, 'ok')
		self.assertEqual(HostScreenshot.objects.count(), 1)
		self.assertTrue(row.image_path.startswith(f'screenshots/{self.project.pk}/www.rt.test-'))
		self.assertEqual(sum(len(files) for _d, _s, files in os.walk(self.media)) , 2)  # the picture and its thumbnail

	def test_a_sandbox_that_did_not_engage_opens_nothing_and_every_page_says_why(self):
		from agentapi import system_status
		from cveFeed.models import AgentActivity
		row = self.queue()
		reason = "Chromium's sandbox could not start: this container may not create the user namespaces it needs."
		with Scanner(sandbox={'engaged': False, 'reason': reason, 'version': ''}) as scanner, self.assertLogs('cveFeed.web_shot', 'ERROR'):
			def respond(task):
				return {'outcome': 'done', 'sandbox': {'engaged': False, 'reason': reason}, 'pages': [], 'touched': [], 'refused': []}
			scanner.fake.responders['web_screenshot'] = respond
			out = web_shot.drain()
		row.refresh_from_db()
		self.assertEqual((row.outcome, out['failed']), ('unavailable', 1))
		self.assertIn('sandbox did not engage', row.reason)
		self.assertIn('user namespaces', row.reason)
		self.assertEqual(web_shot.sandbox_status()['state'], 'failed')
		problems, notes = [], []
		system_status._screenshots(problems, notes)
		self.assertTrue(any('user namespaces' in p for p in problems))
		self.assertEqual(AgentActivity.objects.filter(message__startswith='Screenshots are off').count(), 1)

	def test_a_proof_of_the_sandbox_in_the_result_is_recorded(self):
		self.queue()
		with Scanner():
			web_shot.drain()
		self.assertEqual(web_shot.sandbox_status()['state'], 'engaged')
		self.assertEqual(web_shot.sandbox_status()['chromium_version'], '156.0.8078.4')

	def test_a_result_that_says_nothing_of_the_sandbox_is_refused_by_the_server(self):
		from agentapi.services import ApiError
		from agentapi import sentinel_broker
		with self.assertRaises(ApiError):
			sentinel_broker.clean_result('web_screenshot', {'outcome': 'done', 'pages': []})


class NoScannerTests(ShotFixture, TestCase):
	"""``web_screenshot`` has no local path at all: with no scanner able to take it nothing is recorded and the pages stay queued."""

	def setUp(self):
		super().setUp()
		self.sub = self.host(ports=((443, 'https'),))
		self.row = self.make_row()
		assert_ran_nowhere_locally(self, 'web_screenshot')

	def test_no_scanner_at_all_leaves_the_page_queued(self):
		with LocalFallback('none'):
			out = web_shot.drain()
		self.assertIn('no scanner could take this work (web_screenshot)', out['skipped'])
		self.assertEqual(out['captured'], 0)
		self.row.refresh_from_db()
		self.assertEqual((self.row.outcome, self.row.attempted_at, self.row.reason), ('queued', None, ''))
		self.kicked.assert_not_called()  # a page that cannot be taken is not kicked in a loop

	def test_local_fallback_all_does_not_bring_a_local_run_back(self):
		with LocalFallback('all'):
			out = web_shot.drain()
		self.assertIn('no scanner could take', out['skipped'])
		self.row.refresh_from_db()
		self.assertEqual(self.row.outcome, 'queued')

	def test_an_offline_scanner_leaves_the_page_queued_and_a_live_one_takes_it_later(self):
		with Scanner() as scanner:
			scanner.mode('offline')
			out = web_shot.drain()
			self.assertIn('no scanner could take', out['skipped'])
			self.row.refresh_from_db()
			self.assertEqual(self.row.outcome, 'queued')
			scanner.mode('ok')
			out = web_shot.drain()
		self.row.refresh_from_db()
		self.assertEqual((self.row.outcome, out['captured']), ('ok', 1))

	def test_a_scanner_that_fails_or_never_answers_leaves_the_page_queued(self):
		with Scanner(wait='1') as scanner:
			for mode in ('fail', 'timeout', 'idle'):
				scanner.mode(mode)
				out = web_shot.drain()
				self.row.refresh_from_db()
				self.assertEqual(self.row.outcome, 'queued', mode)
				self.assertIn('no scanner could take', out['skipped'], mode)

	def test_the_waiting_state_is_what_a_page_that_nothing_can_take_shows(self):
		web_shot.queue_for_subs([self.fresh(self.sub)], self.project.pk, by_person=True, force=True)
		with LocalFallback('none'):
			web_shot.drain()
		rows = list(HostScreenshot.objects.all())
		self.assertEqual({r.outcome for r in rows}, {'queued'})
		self.assertIn('Waiting for a scanner', web_shot.note_for(rows, has_web_evidence=True))

	def test_a_project_without_a_scanner_does_not_hold_up_one_that_has_one(self):
		other = self.project_with_hosts('two', 1)
		web_shot.queue_for_subs(list(Subdomain.objects.filter(target_domain__project=other)), other.pk)
		from agentapi import sentinel_dispatch
		from reNgine.resources import ScannerUnavailable
		original = sentinel_dispatch.scanner_or_local

		def gate(project, kind):
			if project.pk == self.project.pk:
				raise ScannerUnavailable(kind, 'no scanner for this project')
			return original(project, kind)
		with Scanner(), mock.patch.object(sentinel_dispatch, 'scanner_or_local', gate):
			out = web_shot.drain()
		self.assertEqual(out['captured'], 1)
		self.assertEqual(out['waiting'], [self.project.pk])
		self.assertEqual(HostScreenshot.objects.get(host='h0.two.test').outcome, 'ok')
		self.assertEqual(HostScreenshot.objects.get(pk=self.row.pk).outcome, 'queued')


class PrecheckTests(ShotFixture, TestCase):
	"""Every queued page is judged again where it is used: what was true when it was queued may not be now."""

	def setUp(self):
		super().setUp()
		self.sub = self.host(ports=((443, 'https'),))
		self.scanner = Scanner().__enter__()
		self.addCleanup(self.scanner.__exit__, None, None, None)

	def drain(self, by_person=False):
		self.row = self.make_row(by_person=by_person)
		self.scanner.tasks.clear()
		out = web_shot.drain()
		self.tasks = list(self.scanner.tasks)
		return out

	def test_a_host_that_left_the_inventory_is_forgotten_not_photographed(self):
		Subdomain.objects.all().delete()
		out = self.drain()
		self.assertEqual((out['captured'], out['dropped']), (0, 1))
		self.assertEqual(HostScreenshot.objects.count(), 0)
		self.assertEqual(self.tasks, [])

	def test_a_host_excluded_since_it_was_queued_is_forgotten(self):
		HostExclusion.objects.create(org=self.project.org, host='www.rt.test')
		self.drain()
		self.assertEqual(HostScreenshot.objects.count(), 0)
		self.assertEqual(self.tasks, [])

	def test_an_archived_host_is_blocked(self):
		HostState.objects.create(project=self.project, domain=self.domain, host='www.rt.test', archived_at=timezone.now())
		self.drain()
		row = HostScreenshot.objects.get()
		self.assertEqual((row.outcome, row.reason), ('blocked', 'Not captured: the host is archived.'))
		self.assertEqual(self.tasks, [])

	def test_the_bug_bounty_confirmation_holds_back_an_unattended_page_but_not_a_persons(self):
		def refusal(gate, project_id, host=None, *, unattended=True, derived=False):
			return 'the bug bounty engagement has not confirmed automated testing' if unattended else ''
		with mock.patch('cveFeed.bounty_gate.Gate.refusal', refusal):
			self.drain(by_person=False)
			self.assertEqual(HostScreenshot.objects.get().outcome, 'blocked')
			self.assertEqual(self.tasks, [])
			HostScreenshot.objects.all().delete()
			self.drain(by_person=True)
		self.assertEqual(HostScreenshot.objects.get().outcome, 'ok')

	def test_a_target_made_manual_only_while_the_page_waited_is_blocked_for_the_schedule(self):
		Domain.objects.filter(pk=self.domain.pk).update(discovery_mode=Domain.DISCOVERY_MANUAL)
		self.drain(by_person=False)
		row = HostScreenshot.objects.get()
		self.assertEqual((row.outcome, row.reason), ('blocked', 'Not captured: the target is set to manual only.'))


class DrainTests(ShotFixture, TestCase):
	def setUp(self):
		super().setUp()
		self.sub = self.host(ports=((443, 'https'),))

	def test_nothing_runs_while_scanning_is_paused_and_the_pages_stay_queued(self):
		self.make_row()
		with Scanner() as scanner, mock.patch('reNgine.resources.global_pause_requested', return_value=True):
			out = web_shot.drain()
		self.assertEqual(out['skipped'], 'scanning is paused')
		self.assertEqual(scanner.tasks, [])
		self.assertEqual(HostScreenshot.objects.get().outcome, 'queued')

	def test_a_second_drain_while_one_runs_returns_at_once(self):
		self.make_row()
		from contextlib import contextmanager

		@contextmanager
		def taken(key, owner, ttl):
			yield 'drain-other'
		with Scanner() as scanner, mock.patch('reNgine.resources.redis_claim', taken):
			out = web_shot.drain()
		self.assertEqual(out['skipped'], 'another drain is running')
		self.assertEqual(scanner.tasks, [])
		self.assertEqual(HostScreenshot.objects.get().outcome, 'queued')

	def test_switched_off_the_pages_wait_and_the_reason_is_given(self):
		self.make_row()
		with mock.patch.dict(os.environ, {'CVENGINE_SCREENSHOTS': '0'}):
			out = web_shot.drain()
		self.assertIn('switched off', out['skipped'])
		self.assertEqual(HostScreenshot.objects.get().outcome, 'queued')

	def test_a_persons_request_goes_first_and_the_oldest_next(self):
		self.make_row(host='old.rt.test', queued_at=timezone.now() - timedelta(hours=3))
		self.make_row(host='new.rt.test', queued_at=timezone.now())
		self.make_row(host='person.rt.test', queued_at=timezone.now(), by_person=True)
		self.assertEqual([r.host for r in web_shot.queued_rows(10)], ['person.rt.test', 'old.rt.test', 'new.rt.test'])
		self.assertEqual(len(web_shot.queued_rows(2)), 2)
		self.assertEqual([r.host for r in web_shot.queued_rows(10, exclude_projects=[self.project.pk])], [])

	def test_a_long_queue_is_taken_a_batch_at_a_time_until_it_is_empty(self):
		for i in range(5):
			name = f'h{i}.rt.test'
			Subdomain.objects.create(name=name, target_domain=self.domain, scan_history=self.sub.scan_history)
			self.make_row(host=name)
		with Scanner() as scanner:
			out = web_shot.drain(batch=2)
		self.assertEqual(sorted(len(t['pages']) for t in scanner.tasks), [1, 2, 2])
		self.assertEqual(out['captured'], 5)
		self.assertFalse(HostScreenshot.objects.filter(outcome='queued').exists())

	def test_a_drain_that_runs_out_of_time_asks_for_another_instead_of_holding_the_worker(self):
		self.make_row()
		ticks = iter([0, 10_000])
		out = web_shot.drain(budget_seconds=5, now_fn=lambda: next(ticks))
		self.assertTrue(out['continued'])
		self.kicked.assert_called_once()
		self.assertEqual(self.kicked.call_args.kwargs['countdown'], 5)

	def test_a_page_queued_while_a_drain_was_finishing_gets_another_drain(self):
		row = self.make_row()
		looks = iter([[row], [], [row]])  # the loop's two looks, then the last look after the drain has done its work

		def process(rows, summary=None):
			summary['captured'] += 1
			return summary
		with mock.patch.object(web_shot, 'queued_rows', side_effect=lambda limit, exclude=(): next(looks)), mock.patch.object(web_shot, 'process', process):
			out = web_shot.drain()
		self.assertEqual(out['captured'], 1)
		self.kicked.assert_called_once()
		self.assertEqual(self.kicked.call_args.kwargs['countdown'], 5)

	def test_the_activity_feed_gets_one_line(self):
		from cveFeed.models import AgentActivity
		self.make_row()
		with Scanner():
			web_shot.drain()
		self.assertTrue(AgentActivity.objects.filter(message='Screenshots: 1 captured, 0 not captured, 0 blocked').exists())


# ------------------------------------------------------------------------------------------------ what the server keeps of a result

class ResultCleaningTests(SimpleTestCase):
	def png_b64(self, **kw):
		return base64.b64encode(png(**kw)).decode()

	def clean(self, pages, **extra):
		from agentapi import sentinel_broker
		return sentinel_broker.clean_result('web_screenshot', {'outcome': 'done', 'sandbox': {'engaged': True}, 'pages': pages, **extra})

	def test_a_good_result_passes_through_and_matches_the_contract(self):
		import json
		from pathlib import Path
		from agentapi import sentinel_contract
		from jsonschema import Draft202012Validator
		good = json.loads((Path(__file__).parent / 'fixtures' / 'sentinel_results' / 'web_screenshot.json').read_text())
		Draft202012Validator(sentinel_contract.result_schema('web_screenshot')).validate(good)
		out = self.clean(good['pages'], touched=good['touched'], refused=good['refused'], dropped_requests=1)
		self.assertEqual([p['outcome'] for p in out['pages']], ['ok', 'unreachable'])
		self.assertEqual(out['pages'][0]['image'], good['pages'][0]['image'])
		self.assertEqual((out['touched'], out['refused'], out['dropped_requests']), (good['touched'], good['refused'], 1))

	def test_a_picture_is_checked_before_anything_opens_it(self):
		import struct
		import zlib
		good = png()
		header = struct.pack('>II', 100_000, 100_000) + good[24:29]
		bomb = good[:16] + header + struct.pack('>I', zlib.crc32(b'IHDR' + header) & 0xFFFFFFFF) + good[33:]  # a good checksum, and sides of ten billion pixels
		bad_crc = good[:29] + b'\0\0\0\0' + good[33:]
		for name, data in (('bomb', bomb), ('crc', bad_crc), ('text', b'hello' * 20), ('truncated', good[:-12]), ('empty', b''), ('signature only', good[:8])):
			with self.subTest(name):
				page = {'id': '1', 'outcome': 'ok', 'image': base64.b64encode(data).decode()}
				out = self.clean([page])['pages'][0]
				self.assertEqual(out['outcome'], 'error')
				self.assertNotIn('image', out)
		self.assertEqual(self.clean([{'id': '1', 'outcome': 'ok', 'image': 'not base64!!'}])['pages'][0]['outcome'], 'error')
		self.assertEqual(self.clean([{'id': '1', 'outcome': 'ok'}])['pages'][0]['outcome'], 'error')  # ok with no picture is not ok

	def test_a_picture_over_the_cap_is_refused_and_an_image_on_a_failed_page_is_dropped(self):
		from agentapi import web_screenshot_results as results
		huge = base64.b64encode(png(width=40, height=40) + b'\0' * (results.MAX_IMAGE_BYTES + 1)).decode()
		self.assertEqual(self.clean([{'id': '1', 'outcome': 'ok', 'image': huge}])['pages'][0]['outcome'], 'error')
		failed = self.clean([{'id': '1', 'outcome': 'timeout', 'image': self.png_b64()}])['pages'][0]
		self.assertNotIn('image', failed)

	def test_the_task_can_ask_for_a_smaller_picture_than_the_contract_allows(self):
		from agentapi import web_screenshot_results as results
		big = png(width=300, height=300, noise=5000)
		page = {'id': '1', 'outcome': 'ok', 'image': base64.b64encode(big).decode()}

		class Task:
			target = {'pages': [{'id': '1', 'url': 'https://a.example/'}], 'max_bytes': 1000}
		self.assertGreater(len(big), 1000)
		out = results.bind(self.clean([page]), Task())['pages'][0]
		self.assertEqual((out['outcome'], out['reason']), ('error', results.TOO_BIG))

	def test_strings_are_clipped_and_odd_values_are_dropped(self):
		page = {'id': '1', 'outcome': 'timeout', 'reason': 'x' * 900, 'final_url': 'y' * 5000, 'title': 't' * 900, 'status': True}
		out = self.clean([page, {'id': '', 'outcome': 'ok'}, {'id': '2', 'outcome': 'nonsense'}, 'text', {'outcome': 'ok'}])['pages']
		self.assertEqual(len(out), 1)
		self.assertEqual((len(out[0]['reason']), len(out[0]['final_url']), len(out[0]['title']), out[0]['status']), (300, 2000, 300, None))

	def test_too_many_pages_is_not_a_result(self):
		from agentapi.services import ApiError
		with self.assertRaises(ApiError):
			self.clean([{'id': str(i), 'outcome': 'timeout'} for i in range(7)])

	def test_a_browser_that_was_not_proven_sandboxed_has_no_pages(self):
		from agentapi import sentinel_broker
		out = sentinel_broker.clean_result('web_screenshot', {'outcome': 'done', 'sandbox': {'engaged': False, 'reason': 'no'},
														  'pages': [{'id': '1', 'outcome': 'ok', 'image': self.png_b64()}]})
		self.assertEqual((out['sandbox']['engaged'], out['pages']), (False, []))

	def test_the_bounds_are_the_contracts(self):
		from agentapi import sentinel_contract
		from agentapi import web_screenshot_results as results
		from cveFeed import probe_scope
		doc = sentinel_contract.load()['$defs']
		page = doc['results']['web_screenshot']['allOf'][1]['properties']['pages']
		self.assertEqual(page['maxItems'], results.MAX_PAGES)
		self.assertEqual(doc['targets']['web_screenshot']['properties']['pages']['maxItems'], web_shot.MAX_PAGES_PER_TASK)
		self.assertEqual(page['items']['properties']['image']['maxLength'], (results.MAX_IMAGE_BYTES + 2) // 3 * 4)
		self.assertEqual(doc['targets']['web_screenshot']['properties']['max_bytes']['maximum'], results.MAX_IMAGE_BYTES)
		self.assertEqual(sorted(page['items']['properties']['outcome']['enum']), sorted(results.OUTCOMES))
		scope = doc['probe_scope']['properties']
		self.assertEqual((scope['excluded']['maxItems'], scope['excluded_trees']['maxItems']), (probe_scope.MAX_EXCLUDED, probe_scope.MAX_EXCLUDED_TREES))
		self.assertEqual(web_shot.MAX_PAGES_PER_TASK * results.MAX_IMAGE_BYTES * 4 // 3 + 4096 < 24 * 1024 * 1024, True)  # six pictures fit the 24 MiB a result body may be
