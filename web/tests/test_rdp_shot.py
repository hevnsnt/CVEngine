import io
import shutil
import tempfile
from unittest import mock

from django.test import SimpleTestCase, TestCase

from cveFeed import rdp_shot
from cveFeed.models import RdpScreenshot, ServiceRun
from startScan.models import Port, Subdomain, Vulnerability
from tests.test_route_auth import RouteFixture
from tests.test_service_intel import RDP_ENC, RDP_NLA_ONLY

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
	def setUp(self):
		super().setUp()
		self.media_root = tempfile.mkdtemp()
		self.addCleanup(shutil.rmtree, self.media_root, ignore_errors=True)
		override = self.settings(MEDIA_ROOT=self.media_root)
		override.enable()
		self.addCleanup(override.disable)
		self.scan_obj = self.scan(names=('win.rt.test',), ports=())
		self.sub = Subdomain.objects.get(scan_history=self.scan_obj)
		self.ip = self.sub.ip_addresses.get()
		self.ip.ports.add(Port.objects.create(number=3389, state='open', service_name='ms-wbt-server',
											   extra={'scripts': {'rdp-enum-encryption': RDP_ENC}}))
		self.calls = []

	def capturer(self, host, port):
		self.calls.append((host, port))
		return self.png

	def reader(self, png):
		return {'logged_in_user': 'ACME\\jsmith', 'summary': 'Locked screen for jsmith'}

	def go(self, **kw):
		with mock.patch('cveFeed.rdp_shot.available', return_value=True):
			return rdp_shot.run_for_scan(self.scan_obj.id, capturer=self.capturer, reader=self.reader, **kw)

	def test_a_real_capture_is_stored_and_read(self):
		self.png = b'\x89PNG\r\nreal-enough-content-0123456789'
		with mock.patch('cveFeed.rdp_shot.is_meaningful', return_value=True):
			out = self.go()
		self.assertEqual(self.calls, [(self.ip.address, 3389)])
		self.assertEqual((out['attempted'], out['captured'], out['read']), (1, 1, 1))
		shot = RdpScreenshot.objects.get(project=self.project, host='win.rt.test', port=3389)
		self.assertEqual((shot.address, shot.logged_in_user, shot.ai_summary), (self.ip.address, 'ACME\\jsmith', 'Locked screen for jsmith'))
		self.assertTrue(shot.image_path)
		vuln = Vulnerability.objects.get(name='RDP login screen shows a signed-in account')
		self.assertIn('ACME\\jsmith', vuln.description)
		self.assertEqual(vuln.severity, 0)
		self.assertTrue(ServiceRun.objects.filter(service='rdp-shot', asset=f'{self.ip.address}:3389').exists())

	def test_a_blank_capture_is_not_stored(self):
		self.png = b'blank'
		with mock.patch('cveFeed.rdp_shot.is_meaningful', return_value=False):
			out = self.go()
		self.assertEqual((out['attempted'], out['captured']), (1, 0))
		self.assertFalse(RdpScreenshot.objects.exists())
		self.assertEqual(ServiceRun.objects.get(service='rdp-shot').status, 'failed')

	def test_no_frame_at_all_is_not_a_failure(self):
		self.calls = []

		def capturer(host, port):
			self.calls.append((host, port))
			return None
		out = None
		with mock.patch('cveFeed.rdp_shot.available', return_value=True):
			out = rdp_shot.run_for_scan(self.scan_obj.id, capturer=capturer, reader=self.reader)
		self.assertEqual((out['attempted'], out['captured']), (1, 0))
		self.assertFalse(RdpScreenshot.objects.exists())

	def test_a_capture_exception_does_not_stop_the_scan_or_raise(self):
		def boom(host, port):
			raise ConnectionError('refused')
		with mock.patch('cveFeed.rdp_shot.available', return_value=True):
			out = rdp_shot.run_for_scan(self.scan_obj.id, capturer=boom, reader=self.reader)
		self.assertEqual((out['attempted'], out['captured']), (1, 0))
		self.assertEqual(ServiceRun.objects.get(service='rdp-shot').status, 'failed')

	def test_a_screen_with_nobody_signed_in_is_stored_without_a_finding(self):
		self.png = b'\x89PNG\r\nreal-enough-content-0123456789'

		def reader(png):
			return {'logged_in_user': '', 'summary': 'Just a login prompt'}
		with mock.patch('cveFeed.rdp_shot.is_meaningful', return_value=True):
			with mock.patch('cveFeed.rdp_shot.available', return_value=True):
				rdp_shot.run_for_scan(self.scan_obj.id, capturer=self.capturer, reader=reader)
		self.assertTrue(RdpScreenshot.objects.filter(port=3389).exists())
		self.assertFalse(Vulnerability.objects.filter(name='RDP login screen shows a signed-in account').exists())

	def test_an_ai_read_error_still_stores_the_screenshot(self):
		self.png = b'\x89PNG\r\nreal-enough-content-0123456789'

		def reader(png):
			return {'error': 'No AI model is configured'}
		with mock.patch('cveFeed.rdp_shot.is_meaningful', return_value=True):
			with mock.patch('cveFeed.rdp_shot.available', return_value=True):
				out = rdp_shot.run_for_scan(self.scan_obj.id, capturer=self.capturer, reader=reader)
		self.assertEqual((out['captured'], out['read']), (1, 0))
		shot = RdpScreenshot.objects.get(port=3389)
		self.assertEqual(shot.ai_error, 'No AI model is configured')

	def test_runs_once_per_window_then_only_on_force(self):
		self.png = b'\x89PNG\r\nreal-enough-content-0123456789'
		with mock.patch('cveFeed.rdp_shot.is_meaningful', return_value=True):
			self.go()
			again = self.go()
			self.assertEqual(again['attempted'], 0)
			self.assertEqual(again['reused'], 1)
			self.go(force=True)
		self.assertEqual(len(self.calls), 2)

	def test_disabled_by_the_environment_variable(self):
		with mock.patch.dict('os.environ', {'CVENGINE_RDP_SHOT': '0'}):
			out = rdp_shot.run_for_scan(self.scan_obj.id, capturer=self.capturer, reader=self.reader)
		self.assertEqual(out, {'attempted': 0, 'skipped': 'disabled'})
		self.assertEqual(self.calls, [])

	def test_skipped_without_aardwolf_installed(self):
		# no capturer override here: the availability gate only applies to the real default capturer
		with mock.patch('cveFeed.rdp_shot.available', return_value=False):
			out = rdp_shot.run_for_scan(self.scan_obj.id)
		self.assertEqual(out, {'attempted': 0, 'skipped': 'aardwolf is not installed'})

	def test_an_injected_capturer_is_used_even_without_aardwolf_installed(self):
		self.png = b'\x89PNG\r\nreal-enough-content-0123456789'
		with mock.patch('cveFeed.rdp_shot.available', return_value=False), mock.patch('cveFeed.rdp_shot.is_meaningful', return_value=True):
			out = rdp_shot.run_for_scan(self.scan_obj.id, capturer=self.capturer, reader=self.reader)
		self.assertEqual(out['captured'], 1)

	def test_no_candidates_is_a_no_op(self):
		other = self.scan(names=('plain.rt.test',), ports=((443, 'https'),), ip='203.0.113.99')
		with mock.patch('cveFeed.rdp_shot.available', return_value=True):
			out = rdp_shot.run_for_scan(other.id, capturer=self.capturer, reader=self.reader)
		self.assertEqual(out, {'attempted': 0})

	def test_bounded_per_scan(self):
		for i in range(3):
			sub = Subdomain.objects.create(name=f'win{i}.rt.test', target_domain=self.domain, scan_history=self.scan_obj)
			ip = __import__('startScan.models', fromlist=['IpAddress']).IpAddress.objects.create(address=f'203.0.113.{10 + i}')
			sub.ip_addresses.add(ip)
			ip.ports.add(Port.objects.create(number=3389, state='open', service_name='ms-wbt-server',
											  extra={'scripts': {'rdp-enum-encryption': RDP_ENC}}))
		self.png = b'\x89PNG\r\nreal-enough-content-0123456789'
		with mock.patch('cveFeed.rdp_shot.max_hosts', return_value=2):
			with mock.patch('cveFeed.rdp_shot.is_meaningful', return_value=True):
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

	def test_the_pipeline_runs_the_stage_only_when_a_candidate_exists(self):
		from cveFeed import discovery
		scan = self.scan(names=('win.rt.test',), ports=())
		sub = Subdomain.objects.get(scan_history=scan)
		ip = sub.ip_addresses.get()
		ip.ports.add(Port.objects.create(number=3389, state='open', service_name='ms-wbt-server',
										  extra={'scripts': {'rdp-enum-encryption': RDP_ENC}}))
		calls = []

		def capturer(host, port):
			calls.append((host, port))
			return b'\x89PNG\r\nreal-enough-content-0123456789'
		with mock.patch('cveFeed.rdp_shot.is_meaningful', return_value=True), mock.patch('cveFeed.discovery.stopped', return_value=False):
			discovery._run_stages(scan.id, {'scan_id': scan.id, 'status': discovery.SUCCESS}, hygiene=False,
								  nmap_runner=lambda targets, flags, timeout: '', db_exposure_checks={}, provider=None,
								  light_stream=lambda path, **k: iter([]), targeted_stream=lambda path, **k: iter([]),
								  route_probe=lambda url: {'url': url, 'status': 200, 'body': '', 'title': ''},
								  rdp_capturer=capturer, rdp_reader=lambda png: {'logged_in_user': '', 'summary': ''})
		self.assertEqual(calls, [(ip.address, 3389)])
		from startScan.models import ScanActivity
		self.assertTrue(ScanActivity.objects.filter(scan_of=scan, name='rdp_screenshot').exists())

	def test_a_scan_with_no_rdp_candidate_never_starts_the_stage(self):
		from cveFeed import discovery
		from startScan.models import ScanActivity
		scan = self.scan(names=('plain.rt.test',), ports=((443, 'https'),))
		with mock.patch('cveFeed.discovery.stopped', return_value=False):
			discovery._run_stages(scan.id, {'scan_id': scan.id, 'status': discovery.SUCCESS}, hygiene=False,
								  nmap_runner=lambda targets, flags, timeout: '', db_exposure_checks={}, provider=None,
								  light_stream=lambda path, **k: iter([]), targeted_stream=lambda path, **k: iter([]),
								  route_probe=lambda url: {'url': url, 'status': 200, 'body': '', 'title': ''})
		self.assertFalse(ScanActivity.objects.filter(scan_of=scan, name='rdp_screenshot').exists())


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
