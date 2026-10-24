from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import correlation, notify
from cveFeed.models import CVEEntry, CVEMatch
from cveFeed.tasks import auto_fire_new_cves
from dashboard.models import AIProviderSettings, Org, Project
from scanEngine.models import EngineType, Notification
from startScan.models import IpAddress, Port, ScanHistory, Subdomain
from targetApp.models import Domain

SENDERS = ('send_discord_message', 'send_slack_message', 'send_lark_message', 'send_telegram_message')
NGINX = [{'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}]
NO_RANGE = [{'product': 'nginx'}]  # names the product, no version bound: the AI may clear it


class FeedAnnouncementTests(TestCase):
	"""Verdict 1: the feed sync's fire notification fires, after the AI, with or without auto-fire."""

	def setUp(self):
		correlation._INDEX_CACHE.update(key=None, value=None)
		org = Org.objects.create(name='N', slug='n')
		project = Project.objects.create(name='P', slug='pn', insert_date=timezone.now(), org=org)
		domain = Domain.objects.create(name='feed.test', project=project, insert_date=timezone.now())
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.scan = ScanHistory.objects.create(domain=domain, scan_type=engine, scan_status=2, start_scan_date=timezone.now())
		sub = Subdomain.objects.create(name='www.feed.test', target_domain=domain, scan_history=self.scan)  # hosts always have a scan
		ip = IpAddress.objects.create(address='198.51.100.60')
		sub.ip_addresses.add(ip)
		ip.ports.add(Port.objects.create(number=80, product='nginx', version='1.18.0'))
		self.sent = []
		for name in SENDERS:
			patcher = mock.patch(f'reNgine.common_func.{name}', side_effect=lambda text, n=name: self.sent.append((n, text)))
			patcher.start()
			self.addCleanup(patcher.stop)
		Notification.objects.create(send_to_slack=True, slack_hook_url='https://hooks.invalid/x')

	def cve(self, affected=NGINX, cve_id='CVE-2099-60'):
		return CVEEntry.objects.create(cve_id=cve_id, kev=True, cvss=9.8, published_at=timezone.now(), affected=affected)

	def slack(self):
		return [t for n, t in self.sent if n == 'send_slack_message']

	def test_a_feed_match_on_a_scanned_host_is_announced_even_with_auto_fire_off(self):
		cve = self.cve()
		out = auto_fire_new_cves([cve.pk])
		self.assertEqual(out['skipped'], 'auto-fire disabled')
		self.assertEqual(len(self.slack()), 1)
		self.assertIn('1 new fire-tier CVE match on 1 host', self.slack()[0])
		self.assertTrue(CVEMatch.objects.get().scan_history_id)  # the case the old scan=None filter could never see

	def test_with_auto_fire_off_only_the_new_cves_are_announced_not_the_backlog(self):
		self.cve(cve_id='CVE-2099-61')  # an older hot CVE nobody fired
		fresh = self.cve(cve_id='CVE-2099-62')
		auto_fire_new_cves([fresh.pk])
		self.assertEqual(CVEMatch.objects.count(), 1)
		self.assertEqual(CVEMatch.objects.get().cve_entry_id, fresh.pk)
		self.assertEqual(auto_fire_new_cves(), {'skipped': 'auto-fire disabled'})  # nothing new: no walk, no message
		self.assertEqual(len(self.slack()), 1)

	def test_a_rerun_does_not_announce_the_same_matches_again(self):
		cve = self.cve()
		auto_fire_new_cves([cve.pk])
		auto_fire_new_cves([cve.pk])
		self.assertEqual(len(self.slack()), 1)

	def test_a_match_the_ai_calls_a_false_positive_stays_open_but_is_not_announced(self):
		# the version is in range, so the AI cannot close the match on its own; it does keep it from paging anyone
		AIProviderSettings.objects.create(auto_fire=True, enabled=True)
		cve = self.cve()
		provider = mock.Mock(model='m')
		provider.name = 'test'
		provider.complete.return_value = '{"classification": "likely_false_positive", "reason": "banner says patched"}'
		with mock.patch('reNgine.ai_settings.get_configured_provider', return_value=provider), \
				mock.patch('cveFeed.tasks.template_test_for_cve.delay'):
			out = auto_fire_new_cves([cve.pk])
		self.assertEqual(out, {'fired': 1})  # still tested: a template hit is evidence, and is announced on its own
		self.assertEqual(CVEMatch.objects.get().ai_verdict, 'uncertain')
		self.assertEqual(self.slack(), [])

	def test_a_match_without_version_evidence_is_not_announced(self):
		cve = self.cve(NO_RANGE)
		auto_fire_new_cves([cve.pk])
		self.assertEqual(CVEMatch.objects.get().version_in_range, None)
		self.assertEqual(self.slack(), [])

	def test_the_message_is_sent_after_the_confirmation_not_before(self):
		AIProviderSettings.objects.create(auto_fire=True, enabled=True)
		cve = self.cve()
		order = []
		with mock.patch('cveFeed.autofire.fire_for_cve', side_effect=lambda *a, **k: order.append('fire')), \
				mock.patch.object(notify, 'fire_matches', side_effect=lambda *a, **k: order.append('notify')):
			auto_fire_new_cves([cve.pk])
		self.assertEqual(order, ['fire', 'notify'])

	def test_a_patched_match_is_not_announced(self):
		cve = self.cve()
		auto_fire_new_cves([cve.pk])
		self.sent.clear()
		CVEMatch.objects.update(distro_status='patched', created_at=timezone.now())
		self.assertFalse(notify.fire_matches(timezone.now() - timedelta(minutes=1)))
		self.assertEqual(self.slack(), [])

	def test_a_scan_scoped_call_still_filters_on_its_scan(self):
		cve = self.cve()
		auto_fire_new_cves([cve.pk])
		self.sent.clear()
		other = ScanHistory.objects.create(domain=self.scan.domain, scan_type=self.scan.scan_type, scan_status=1, start_scan_date=timezone.now())
		self.assertFalse(notify.fire_matches(timezone.now() - timedelta(minutes=5), other))
		self.assertTrue(notify.fire_matches(timezone.now() - timedelta(minutes=5), self.scan))

	def test_the_sync_hands_its_new_cves_to_the_task(self):
		from cveFeed import tasks
		client = mock.Mock()
		client.iter_entries.return_value = iter([{'id': 'CVE-2099-63'}])
		client.get_entry.return_value = {'id': 'CVE-2099-63'}
		entry = mock.Mock(threat_tier='fire', pk=77)
		with mock.patch('cveFeed.tasks.CVENowClient', return_value=client), mock.patch('cveFeed.tasks.CVEEntry.from_api', return_value=(entry, True)), \
				mock.patch('cveFeed.tasks.auto_fire_new_cves.delay') as delay:
			tasks.sync_cve_now_feed()
		delay.assert_called_once_with([77])
