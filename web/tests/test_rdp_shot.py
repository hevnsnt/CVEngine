import io
import shutil
import tempfile
from unittest import mock

from django.test import SimpleTestCase, TestCase

from cveFeed import rdp_shot
from cveFeed.models import HostExclusion, RdpScreenshot, ServiceRun
from startScan.models import Port, Subdomain, Vulnerability
from tests.fake_scanner import FakeScanner, LocalFallback, assert_ran_nowhere_locally, fixture
from tests.test_route_auth import RouteFixture
from tests.test_service_intel import RDP_ENC, RDP_NLA_ONLY
from tests.port_stage_stub import port_double

try:
	from PIL import Image
	HAVE_PIL = True
except ImportError:
	HAVE_PIL = False


def png_bytes(color):
	buf = io.BytesIO()
	Image.new('RGB', (40, 30), color=color).save(buf, 'PNG')
	return buf.getvalue()


class VisionReplyTests(SimpleTestCase):
	def test_a_signed_in_screen_names_the_account(self):
		parsed = rdp_shot._parse_vision_reply('{"signed_in": true, "username": "ACME\\\\jsmith", "description": "Locked desktop for jsmith"}')
		self.assertEqual(parsed, {'logged_in_user': 'ACME\\jsmith', 'summary': 'Locked desktop for jsmith'})

	def test_signed_in_false_never_reports_a_username_even_if_given_one(self):
		parsed = rdp_shot._parse_vision_reply('{"signed_in": false, "username": "should be ignored", "description": "A login prompt"}')
		self.assertEqual(parsed['logged_in_user'], '')
		self.assertEqual(parsed['summary'], 'A login prompt')

	def test_prose_around_the_json_is_tolerated(self):
		parsed = rdp_shot._parse_vision_reply('Here it is: {"signed_in": false, "description": "blank"} thanks')
		self.assertIsNotNone(parsed)

	def test_unusable_replies_are_none(self):
		for bad in ('', 'no json here', '{not json}', '[]', '"a string"'):
			self.assertIsNone(rdp_shot._parse_vision_reply(bad))


class MeaningfulImageTests(SimpleTestCase):
	def test_a_flat_color_is_not_meaningful(self):
		if not HAVE_PIL:
			self.skipTest('Pillow not installed')
		self.assertFalse(rdp_shot.is_meaningful(png_bytes('black')))

	def test_a_varied_image_is_meaningful(self):
		if not HAVE_PIL:
			self.skipTest('Pillow not installed')
		buf = io.BytesIO()
		img = Image.new('RGB', (40, 30), color='black')
		for x in range(20):
			img.putpixel((x, 15), (255, 255, 255))
		img.save(buf, 'PNG')
		self.assertTrue(rdp_shot.is_meaningful(buf.getvalue()))

	def test_garbage_bytes_are_not_meaningful(self):
		self.assertFalse(rdp_shot.is_meaningful(b'not an image'))
		self.assertFalse(rdp_shot.is_meaningful(b''))


class CandidatesTests(RouteFixture, TestCase):
	def test_only_a_confirmed_nla_free_rdp_port_is_a_candidate(self):
		scan = self.scan(names=('win.rt.test',), ports=())
		sub = Subdomain.objects.get(scan_history=scan)
		ip = sub.ip_addresses.get()
		ip.ports.add(Port.objects.create(number=3389, state='open', service_name='ms-wbt-server',
										  extra={'scripts': {'rdp-enum-encryption': RDP_ENC}}))
		self.assertEqual(rdp_shot.rdp_candidates(scan), [(sub, ip.address, 3389)])

	def test_a_server_that_insists_on_nla_is_not_a_candidate(self):
		scan = self.scan(names=('win.rt.test',), ports=())
		sub = Subdomain.objects.get(scan_history=scan)
		ip = sub.ip_addresses.get()
		ip.ports.add(Port.objects.create(number=3389, state='open', service_name='ms-wbt-server',
										  extra={'scripts': {'rdp-enum-encryption': RDP_NLA_ONLY}}))
		self.assertEqual(rdp_shot.rdp_candidates(scan), [])

	def test_a_non_rdp_port_is_never_a_candidate_even_with_matching_script_text(self):
		scan = self.scan(names=('win.rt.test',), ports=())
		sub = Subdomain.objects.get(scan_history=scan)
		ip = sub.ip_addresses.get()
		ip.ports.add(Port.objects.create(number=8080, state='open', service_name='http',
										  extra={'scripts': {'rdp-enum-encryption': RDP_ENC}}))
		self.assertEqual(rdp_shot.rdp_candidates(scan), [])


class RunForScanTests(RouteFixture, TestCase):
	"""The capture runs on a Sentinel (a fake one here) and nowhere else; this side validates, stores and reads it."""

	def setUp(self):
		super().setUp()
		self.media_root = tempfile.mkdtemp()
		self.addCleanup(shutil.rmtree, self.media_root, ignore_errors=True)
		override = self.settings(MEDIA_ROOT=self.media_root)
		override.enable()
		self.addCleanup(override.disable)
		LocalFallback('none').apply(self)
		assert_ran_nowhere_locally(self, 'rdp_shot')
		self.scan_obj = self.scan(names=('win.rt.test',), ports=())
		self.sub = Subdomain.objects.get(scan_history=self.scan_obj)
		self.ip = self.sub.ip_addresses.get()
		self.ip.ports.add(Port.objects.create(number=3389, state='open', service_name='ms-wbt-server',
											   extra={'scripts': {'rdp-enum-encryption': RDP_ENC}}))

	def reader(self, png):
		return {'logged_in_user': 'ACME\\jsmith', 'summary': 'Locked screen for jsmith'}

	def go(self, fake=None, **kw):
		kw.setdefault('reader', self.reader)
		if fake is not None:
			return rdp_shot.run_for_scan(self.scan_obj.id, **kw)
		with FakeScanner(kinds=['rdp_shot']) as fake:
			self.served = fake.served
			return rdp_shot.run_for_scan(self.scan_obj.id, **kw)

	def test_a_real_capture_is_stored_and_read(self):
		out = self.go()
		self.assertEqual([entry['target'] for entry in self.served], [{'address': self.ip.address, 'port': 3389}])
		self.assertEqual((out['attempted'], out['captured'], out['read']), (1, 1, 1))
		shot = RdpScreenshot.objects.get(project=self.project, host='win.rt.test', port=3389)
		self.assertEqual((shot.address, shot.logged_in_user, shot.ai_summary), (self.ip.address, 'ACME\\jsmith', 'Locked screen for jsmith'))
		self.assertTrue(shot.image_path)
		vuln = Vulnerability.objects.get(name='RDP login screen shows a signed-in account')
		self.assertIn('ACME\\jsmith', vuln.description)
		self.assertEqual(vuln.severity, 0)
		self.assertTrue(ServiceRun.objects.filter(service='rdp-shot', asset=f'{self.ip.address}:3389').exists())

	def test_the_reading_is_asked_of_the_reviewer_container_with_the_image(self):
		import base64
		import json
		from tests import ai_queue

		class Vision:
			name, model = 'anthropic', 'vision-model'

			def complete(self, system, user):
				return json.dumps({'signed_in': True, 'username': 'ACME\\jsmith', 'description': 'Locked screen for jsmith'})
		ai_queue.configure()
		out = self.go(reader=None)
		self.assertEqual((out['captured'], out['read']), (1, 1))  # queued
		shot = RdpScreenshot.objects.get(project=self.project, host='win.rt.test', port=3389)
		self.assertEqual(shot.logged_in_user, '')  # not read yet
		from cveFeed import ai_jobs
		taken = ai_jobs.next_jobs(1)[0]
		self.assertEqual((taken['kind'], taken['image']['media_type'], base64.b64decode(taken['image']['data'])), ('rdp_screenshot', 'image/png', base64.b64decode(fixture('rdp_shot')['image'])))
		ai_jobs.submit(taken['id'], ai_queue.answer(taken, Vision()))
		ai_jobs.apply(taken['id'])
		shot.refresh_from_db()
		self.assertEqual((shot.logged_in_user, shot.ai_summary, shot.ai_error), ('ACME\\jsmith', 'Locked screen for jsmith', ''))
		self.assertTrue(Vulnerability.objects.filter(name='RDP login screen shows a signed-in account').exists())

	def test_a_blank_capture_is_not_stored(self):
		with mock.patch('cveFeed.rdp_shot.is_meaningful', return_value=False):
			out = self.go()
		self.assertEqual((out['attempted'], out['captured']), (1, 0))
		self.assertFalse(RdpScreenshot.objects.exists())
		self.assertEqual(ServiceRun.objects.get(service='rdp-shot').status, 'failed')

	def test_no_frame_at_all_is_recorded_as_a_failed_try_and_nothing_is_stored(self):
		with FakeScanner(kinds=['rdp_shot'], responders={'rdp_shot': fixture('rdp_shot', painted=False, image='')}) as fake:
			out = rdp_shot.run_for_scan(self.scan_obj.id, reader=self.reader)
		self.assertEqual(len(fake.served), 1)
		self.assertEqual((out['attempted'], out['captured']), (1, 0))
		self.assertFalse(RdpScreenshot.objects.exists())

	def test_a_scanner_that_fails_leaves_the_server_due_and_records_nothing(self):
		with FakeScanner(kinds=['rdp_shot'], mode='fail') as fake:
			out = rdp_shot.run_for_scan(self.scan_obj.id, reader=self.reader)
		self.assertEqual(len(fake.served), 1)
		self.assertEqual((out['attempted'], out['captured']), (0, 0))
		self.assertIn('no scanner could take this work (rdp_shot)', out['skipped'])
		self.assertFalse(ServiceRun.objects.filter(service='rdp-shot').exists())
		self.assertFalse(RdpScreenshot.objects.exists())

	def test_with_the_scanner_offline_it_waits_whatever_the_fallback_variable_says(self):
		with FakeScanner(kinds=['rdp_shot'], mode='offline') as fake:
			for fallback in ('none', 'all', 'rdp_shot'):  # the kind has no local path at all
				with self.subTest(fallback=fallback), LocalFallback(fallback):
					out = rdp_shot.run_for_scan(self.scan_obj.id, reader=self.reader)
					self.assertIn('no scanner could take this work (rdp_shot)', out['skipped'])
		self.assertEqual(fake.served, [])
		self.assertFalse(RdpScreenshot.objects.exists())
		self.assertFalse(ServiceRun.objects.filter(service='rdp-shot').exists())

	def test_a_screen_with_nobody_signed_in_is_stored_without_a_finding(self):
		out = self.go(reader=lambda png: {'logged_in_user': '', 'summary': 'Just a login prompt'})
		self.assertEqual(out['captured'], 1)
		self.assertTrue(RdpScreenshot.objects.filter(port=3389).exists())
		self.assertFalse(Vulnerability.objects.filter(name='RDP login screen shows a signed-in account').exists())

	def test_an_ai_read_error_still_stores_the_screenshot(self):
		out = self.go(reader=lambda png: {'error': 'No AI model is configured'})
		self.assertEqual((out['captured'], out['read']), (1, 0))
		self.assertEqual(RdpScreenshot.objects.get(port=3389).ai_error, 'No AI model is configured')

	def test_runs_once_per_window_then_only_on_force(self):
		with FakeScanner(kinds=['rdp_shot']) as fake:
			rdp_shot.run_for_scan(self.scan_obj.id, reader=self.reader)
			again = rdp_shot.run_for_scan(self.scan_obj.id, reader=self.reader)
			self.assertEqual((again['attempted'], again['reused']), (0, 1))
			rdp_shot.run_for_scan(self.scan_obj.id, reader=self.reader, force=True)
		self.assertEqual(len(fake.served), 2)

	def test_disabled_by_the_environment_variable(self):
		with mock.patch.dict('os.environ', {'CVENGINE_RDP_SHOT': '0'}), FakeScanner(kinds=['rdp_shot']) as fake:
			out = rdp_shot.run_for_scan(self.scan_obj.id, reader=self.reader)
		self.assertEqual(out, {'attempted': 0, 'skipped': 'disabled'})
		self.assertEqual(fake.served, [])

	def test_an_excluded_host_is_never_a_candidate_or_connected_to(self):
		self.assertEqual(len(rdp_shot.rdp_candidates(self.scan_obj)), 1)
		HostExclusion.objects.create(org=self.scan_obj.domain.project.org, host='win.rt.test')
		self.assertEqual(rdp_shot.rdp_candidates(self.scan_obj), [])  # S04-11
		with FakeScanner(kinds=['rdp_shot']) as fake, mock.patch.object(rdp_shot, 'rdp_candidates', return_value=[(self.sub, self.ip.address, 3389)]):
			out = rdp_shot.run_for_scan(self.scan_obj.id, reader=lambda png: {})
		self.assertEqual((fake.served, out['captured']), ([], 0))  # excluded after the list was made: no task is even created

	def test_no_candidates_is_a_no_op(self):
		other = self.scan(names=('plain.rt.test',), ports=((443, 'https'),), ip='203.0.113.99')
		with FakeScanner(kinds=['rdp_shot']) as fake:
			out = rdp_shot.run_for_scan(other.id, reader=self.reader)
		self.assertEqual((out, fake.served), ({'attempted': 0}, []))

	def test_bounded_per_scan(self):
		for i in range(3):
			sub = Subdomain.objects.create(name=f'win{i}.rt.test', target_domain=self.domain, scan_history=self.scan_obj)
			ip = __import__('startScan.models', fromlist=['IpAddress']).IpAddress.objects.create(address=f'203.0.113.{10 + i}')
			sub.ip_addresses.add(ip)
			ip.ports.add(Port.objects.create(number=3389, state='open', service_name='ms-wbt-server',
											  extra={'scripts': {'rdp-enum-encryption': RDP_ENC}}))
		with mock.patch('cveFeed.rdp_shot.max_hosts', return_value=2):
			out = self.go()
		self.assertEqual(out['attempted'], 2)


class PipelineWiringTests(RouteFixture, TestCase):
	def setUp(self):
		super().setUp()
		self.media_root = tempfile.mkdtemp()
		self.addCleanup(shutil.rmtree, self.media_root, ignore_errors=True)
		override = self.settings(MEDIA_ROOT=self.media_root)
		override.enable()
		self.addCleanup(override.disable)
		LocalFallback('none').apply(self)

	def stages(self, scan, **kw):
		from cveFeed import discovery
		return discovery._run_stages(scan.id, {'scan_id': scan.id, 'status': discovery.SUCCESS}, hygiene=False,
									 port_stage_run=port_double(), db_exposure_checks={}, provider=None,
									 light_stream=lambda path, **k: iter([]), targeted_stream=lambda path, **k: iter([]),
									 route_probe=lambda url: {'url': url, 'status': 200, 'body': '', 'title': ''}, **kw)

	def test_the_pipeline_runs_the_stage_only_when_a_candidate_exists(self):
		from cveFeed import discovery
		scan = self.scan(names=('win.rt.test',), ports=())
		sub = Subdomain.objects.get(scan_history=scan)
		ip = sub.ip_addresses.get()
		ip.ports.add(Port.objects.create(number=3389, state='open', service_name='ms-wbt-server',
										  extra={'scripts': {'rdp-enum-encryption': RDP_ENC}}))
		with mock.patch('cveFeed.discovery.stopped', return_value=False), FakeScanner(kinds=['rdp_shot']) as fake:
			self.stages(scan, rdp_reader=lambda png: {'logged_in_user': '', 'summary': ''})
		self.assertEqual([entry['target'] for entry in fake.served], [{'address': ip.address, 'port': 3389}])
		from startScan.models import ScanActivity
		self.assertTrue(ScanActivity.objects.filter(scan_of=scan, name='rdp_screenshot').exists())

	def test_a_scan_with_no_rdp_candidate_never_starts_the_stage(self):
		from startScan.models import ScanActivity
		scan = self.scan(names=('plain.rt.test',), ports=((443, 'https'),))
		with mock.patch('cveFeed.discovery.stopped', return_value=False):
			self.stages(scan)
		self.assertFalse(ScanActivity.objects.filter(scan_of=scan, name='rdp_screenshot').exists())

	def test_with_no_scanner_the_stage_waits_and_nothing_is_captured_here(self):
		scan = self.scan(names=('win.rt.test',), ports=())
		ip = Subdomain.objects.get(scan_history=scan).ip_addresses.get()
		ip.ports.add(Port.objects.create(number=3389, state='open', service_name='ms-wbt-server',
										  extra={'scripts': {'rdp-enum-encryption': RDP_ENC}}))
		assert_ran_nowhere_locally(self, 'rdp_shot')
		with mock.patch('cveFeed.discovery.stopped', return_value=False):
			self.stages(scan)
		self.assertFalse(RdpScreenshot.objects.exists())
		self.assertFalse(ServiceRun.objects.filter(service='rdp-shot').exists())  # still due


class HostRecordTests(RouteFixture, TestCase):
	def test_the_host_record_carries_the_rdp_screenshot(self):
		from agentapi.auth import create_token
		from django.contrib.auth.models import User
		from dashboard.models import ProjectMembership
		from tests.test_agentapi import call
		from cveFeed.models import RdpScreenshot
		scan = self.scan(names=('win.rt.test',), ports=())
		sub = Subdomain.objects.get(scan_history=scan)
		ip = sub.ip_addresses.get()
		ip.ports.add(Port.objects.create(number=3389, state='open', service_name='ms-wbt-server'))
		RdpScreenshot.objects.create(project=self.project, domain=self.domain, host='win.rt.test', address=ip.address,
									 port=3389, image_path='win.rt.test_1/rdp/x.png', logged_in_user='ACME\\jsmith',
									 ai_summary='Locked screen for jsmith')
		user = User.objects.create_user('rdp-record-user', password='x')
		ProjectMembership.objects.create(user=user, project=self.project, role='user')
		_, token = create_token(user, 'rdp-rec')
		status, data = call(token, 'GET', '/api/v1/projects/pr/hosts')
		self.assertEqual(status, 200, data)
		port_row = next(p for p in data['results'][0]['ips'][0]['ports'] if p['number'] == 3389)
		self.assertEqual(port_row['rdp_screenshot']['logged_in_user'], 'ACME\\jsmith')
		self.assertEqual(port_row['rdp_screenshot']['summary'], 'Locked screen for jsmith')
		self.assertEqual(port_row['rdp_screenshot']['url'], f'/cve/pr/hosts/{sub.id}/rdp-screenshot/3389/')

	def test_a_port_with_no_capture_carries_none(self):
		from agentapi.auth import create_token
		from django.contrib.auth.models import User
		from dashboard.models import ProjectMembership
		from tests.test_agentapi import call
		scan = self.scan(names=('plain.rt.test',), ports=((3389, 'ms-wbt-server'),))
		user = User.objects.create_user('rdp-record-user2', password='x')
		ProjectMembership.objects.create(user=user, project=self.project, role='user')
		_, token = create_token(user, 'rdp-rec2')
		status, data = call(token, 'GET', '/api/v1/projects/pr/hosts')
		self.assertEqual(status, 200, data)
		port_row = data['results'][0]['ips'][0]['ports'][0]
		self.assertIsNone(port_row['rdp_screenshot'])
