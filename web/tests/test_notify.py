"""Pipeline notifications (cveFeed.notify): bounded, batched, non-fatal, and never a real network call."""
import logging
from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import discovery, notify
from cveFeed.models import CVEEntry, CVEMatch
from dashboard.models import Org, Project
from scanEngine.models import EngineType, Notification
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain
from tests.test_discovery import EVENTS

SENDERS = ('send_discord_message', 'send_slack_message', 'send_lark_message', 'send_telegram_message')


class NotifyTests(TestCase):
	def setUp(self):
		org = Org.objects.create(name='N', slug='n')
		self.project = Project.objects.create(name='P', slug='pn', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='example.test', project=self.project, insert_date=timezone.now())
		self.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		# every network path is patched: a sender that slipped through would be a test failure, not a request
		self.sent = []
		self.patches = [mock.patch(f'reNgine.common_func.{name}', side_effect=lambda text, n=name: self.sent.append((n, text)))
		                for name in SENDERS]
		self.patches += [mock.patch('requests.post', side_effect=AssertionError('network')),
		                 mock.patch('requests.get', side_effect=AssertionError('network'))]
		for p in self.patches:
			p.start()
			self.addCleanup(p.stop)
		self.since = timezone.now() - timedelta(minutes=1)

	def enable(self, **flags):
		Notification.objects.all().delete()
		return Notification.objects.create(send_to_slack=True, slack_hook_url='https://hooks.invalid/x', **flags)

	def scan(self):
		return ScanHistory.objects.create(domain=self.domain, scan_type=self.engine, start_scan_date=self.since, scan_status=1)

	def matches(self, scan, count, **cve):
		fields = dict(cve_id='CVE-2099-1', kev=True, cvss=9.8, published_at=timezone.now())
		fields.update(cve)
		entry = CVEEntry.objects.create(**fields)
		for i in range(count):
			sub = Subdomain.objects.create(scan_history=scan, target_domain=self.domain, name=f'h{i}_x.example.test')
			CVEMatch.objects.create(cve_entry=entry, subdomain=sub, scan_history=scan, confidence=0.9, version_in_range=True)
		return entry

	def test_send_says_whether_any_channel_took_the_message(self):
		self.enable(send_interesting_notif=True, send_vuln_notif=False)
		self.assertIs(notify._send('x', 'send_interesting_notif'), True)
		self.assertFalse(notify._send('x', 'send_vuln_notif'))  # this kind of event is switched off: nothing was tried
		with mock.patch.object(notify, 'CHANNEL_SENDERS', {'slack': 'send_slack_message'}), \
				mock.patch('reNgine.common_func.send_slack_message', side_effect=RuntimeError('down')):
			self.assertIsNone(notify._send('x', 'send_interesting_notif'))  # tried, and every channel failed

	def test_a_failing_only_channel_is_a_failure_even_though_the_other_senders_are_silent(self):
		# the real channel table: the three switched-off senders return silently and must not count as delivered
		self.enable(send_interesting_notif=True)
		with mock.patch('reNgine.common_func.send_slack_message', side_effect=RuntimeError('down')):
			self.assertIsNone(notify._send('x', 'send_interesting_notif'))
		self.assertIs(notify._send('x', 'send_interesting_notif'), True)
		# switched on but with no address: nothing can be tried
		Notification.objects.all().delete()
		Notification.objects.create(send_to_slack=True, slack_hook_url='', send_interesting_notif=True)
		self.assertIs(notify._send('x', 'send_interesting_notif'), False)

	# --- settings gate ---------------------------------------------------------------------
	def test_nothing_is_sent_without_settings_or_with_everything_off(self):
		scan = self.scan()
		self.matches(scan, 2)
		self.assertFalse(notify.fire_matches(self.since, scan))  # no Notification row at all
		Notification.objects.create()  # a row, but no channel on
		self.assertFalse(notify.fire_matches(self.since, scan))
		self.enable(send_vuln_notif=False)
		self.assertFalse(notify.fire_matches(self.since, scan))
		self.assertEqual(self.sent, [])

	# --- new fire-tier matches --------------------------------------------------------------
	def test_many_new_fire_matches_make_one_message_that_names_a_few(self):
		scan = self.scan()
		self.matches(scan, 12)
		self.matches(scan, 1, cve_id='CVE-2099-2', kev=False, cvss=2.0)  # ice: not mentioned
		self.enable()
		self.assertTrue(notify.fire_matches(self.since, scan))
		slack = [t for n, t in self.sent if n == 'send_slack_message']
		self.assertEqual(len(slack), 1)  # one message for twelve hosts
		self.assertIn('12 new fire-tier CVE matches on 12 hosts', slack[0])
		self.assertIn('CVE-2099-1', slack[0])
		self.assertIn('and 7 more', slack[0])  # five are named
		self.assertNotIn('CVE-2099-2', slack[0])
		self.assertLess(len(slack[0]), 900)

	def test_old_out_of_range_or_not_affected_matches_do_not_notify(self):
		scan = self.scan()
		entry = self.matches(scan, 1)
		CVEMatch.objects.update(created_at=self.since - timedelta(days=1))  # not new
		sub = Subdomain.objects.create(scan_history=scan, target_domain=self.domain, name='a.example.test')
		CVEMatch.objects.create(cve_entry=entry, subdomain=sub, scan_history=scan, version_in_range=False)
		sub = Subdomain.objects.create(scan_history=scan, target_domain=self.domain, name='b.example.test')
		CVEMatch.objects.create(cve_entry=entry, subdomain=sub, scan_history=scan, ai_verdict='not_affected')
		self.enable()
		self.assertFalse(notify.fire_matches(self.since, scan))
		self.assertEqual(self.sent, [])

	def test_a_page_needs_evidence_that_the_vulnerability_exists(self):
		scan = self.scan()
		entry = CVEEntry.objects.create(cve_id='CVE-2099-7', kev=True, cvss=9.8, published_at=timezone.now())
		def match(name, **fields):
			sub = Subdomain.objects.create(scan_history=scan, target_domain=self.domain, name=name)
			return CVEMatch.objects.create(cve_entry=entry, subdomain=sub, scan_history=scan, confidence=0.9, **fields)
		match('no-version.example.test')  # the product is named but no version supports it
		match('ai-doubt.example.test', version_in_range=True, ai_verdict='uncertain')  # the AI called it a likely false positive
		self.enable()
		self.assertFalse(notify.fire_matches(self.since, scan))
		self.assertEqual(self.sent, [])
		match('proven.example.test', ai_verdict='uncertain', template_result='vulnerable')  # a template hit proves it
		match('distro.example.test', distro_status='vulnerable')
		match('version.example.test', version_in_range=True, ai_verdict='affected')
		self.assertTrue(notify.fire_matches(self.since, scan))
		text = [t for n, t in self.sent if n == 'send_slack_message'][0]
		self.assertIn('3 new fire-tier CVE matches on 3 hosts', text)
		for name in ('proven', 'distro', 'version'):
			self.assertIn(name, text)
		for name in ('no-version', 'ai-doubt'):
			self.assertNotIn(name, text)

	def test_a_feed_sync_reports_the_matches_of_its_own_cves_whatever_scan_row_they_sit_on(self):
		scan = self.scan()
		entry = self.matches(scan, 1)  # a match on a scan's host row, made by the same feed correlation
		other = CVEEntry.objects.create(cve_id='CVE-2099-2', kev=True, cvss=9.8, published_at=timezone.now())
		sub = Subdomain.objects.create(scan_history=scan, target_domain=self.domain, name='sync.example.test')
		CVEMatch.objects.create(cve_entry=other, subdomain=sub, scan_history=None, version_in_range=True)
		self.enable()
		self.assertTrue(notify.fire_matches(self.since, cve_ids=[other.pk]))  # the other CVE's match is not this sync's
		texts = [t for n, t in self.sent if n == 'send_slack_message']
		self.assertEqual(len(texts), 1)
		self.assertIn('1 new fire-tier CVE match on 1 host:', texts[0])
		self.assertNotIn('h0_x', texts[0])
		self.assertTrue(entry.pk)

	def test_untrusted_names_cannot_add_markup_or_mentions(self):
		scan = self.scan()
		entry = CVEEntry.objects.create(cve_id='CVE-2099-1', kev=True, published_at=timezone.now())
		sub = Subdomain.objects.create(scan_history=scan, target_domain=self.domain, name='a<!channel>*[x](http://e).example.test')
		CVEMatch.objects.create(cve_entry=entry, subdomain=sub, scan_history=scan, version_in_range=True)
		self.enable()
		notify.fire_matches(self.since, scan)
		text = self.sent[0][1]
		for bad in ('<', '>', '*', '[', '(', '!'):
			self.assertNotIn(bad, text.split(': ', 1)[1])

	# --- confirmed template-test hits --------------------------------------------------------
	def test_confirmed_hits_are_one_message_for_all_hosts(self):
		self.enable()
		scan = self.scan()
		hits = [('CVE-2099-1', f'h{i}.example.test') for i in range(40)] + [('CVE-2099-3', 'x.example.test')]
		self.assertTrue(notify.template_hits(hits, scan))
		slack = [t for n, t in self.sent if n == 'send_slack_message']
		self.assertEqual(len(slack), 1)
		self.assertIn('confirmed 41 vulnerable hosts across 2 CVEs in `example.test`', slack[0])
		self.assertIn('and 36 more', slack[0])
		self.assertFalse(notify.template_hits([], scan))

	def test_the_per_cve_task_sends_once_for_its_hosts_and_nothing_when_none_are_vulnerable(self):
		from cveFeed.tasks import template_test_for_cve
		self.enable()
		entry = CVEEntry.objects.create(cve_id='CVE-2099-5', kev=True, published_at=timezone.now())
		no_ai = mock.patch('reNgine.ai_settings.get_configured_provider', side_effect=RuntimeError('none'))
		results = [{'host': f'h{i}.example.test', 'vulnerable': True} for i in range(6)] + [{'host': 'ok.example.test', 'vulnerable': False}]
		with mock.patch('cveFeed.templategen.run_cve_tests', return_value={'source': 'installed', 'results': results}), no_ai:
			template_test_for_cve(entry.pk, [r['host'] for r in results])
		self.assertEqual(len([1 for n, _ in self.sent if n == 'send_slack_message']), 1)
		self.sent.clear()
		clean = [{'host': 'a.example.test', 'vulnerable': False}]
		with mock.patch('cveFeed.templategen.run_cve_tests', return_value={'source': 'installed', 'results': clean}), no_ai:
			template_test_for_cve(entry.pk, ['a.example.test'])
		self.assertEqual(self.sent, [])

	# --- discovery finished ------------------------------------------------------------------
	def test_scan_finished_is_a_one_line_summary(self):
		self.enable()
		scan = self.scan()
		Subdomain.objects.create(scan_history=scan, target_domain=self.domain, name='www.example.test')
		self.assertTrue(notify.scan_finished(scan, {'correlation': {'matches': 3}, 'nuclei_targeted': {'findings': 2},
		                                            'db_exposure': {'exposed': 1}}))
		slack = [t for n, t in self.sent if n == 'send_slack_message']
		self.assertEqual(len(slack), 1)
		self.assertNotIn('\n', slack[0])
		self.assertIn('discovery of `example.test` finished (scan #%d): 1 host, 3 CVE matches, 2 nuclei findings, 1 exposed database' % scan.id,
		              slack[0])

	def test_scan_status_switch_controls_the_summary_only(self):
		self.enable(send_scan_status_notif=False)
		self.assertFalse(notify.scan_finished(self.scan(), {}))
		self.assertEqual(self.sent, [])

	def test_a_full_pipeline_sends_one_summary_and_no_fire_message_when_there_is_nothing_fire(self):
		self.enable()
		with mock.patch('cveFeed.tasks.run_bbot_discovery.delay'):
			scan = discovery.start_discovery(self.domain)
		with mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.run_hygiene_task.delay'):
			discovery.run_pipeline(scan.id, stream=lambda *a, **k: iter(EVENTS), light_stream=lambda path, **k: iter([]),
			                       targeted_stream=lambda path, **k: iter([]), nmap_runner=lambda *a, **k: '<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>',
			                       db_exposure_checks={}, provider=None)
		slack = [t for n, t in self.sent if n == 'send_slack_message']
		self.assertEqual(len(slack), 1)
		self.assertIn('finished (scan #%d): 2 hosts' % scan.id, slack[0])

	# --- failure handling --------------------------------------------------------------------
	def test_a_failing_channel_is_logged_without_its_text_and_does_not_stop_the_others_or_the_caller(self):
		self.enable(send_to_discord=True, discord_hook_url='https://hooks.invalid/d', send_to_lark=True, lark_hook_url='https://hooks.invalid/l',
		            send_to_telegram=True, telegram_bot_token='123:T', telegram_bot_chat_id='1')
		secret = 'https://api.telegram.org/bot123:SECRET/sendMessage'
		with mock.patch('reNgine.common_func.send_discord_message', side_effect=RuntimeError(secret)):
			with self.assertLogs('cveFeed.notify', level=logging.WARNING) as logs:
				self.assertTrue(notify.scan_finished(self.scan(), {}))
		self.assertEqual([n for n, _ in self.sent], ['send_slack_message', 'send_lark_message', 'send_telegram_message'])  # the rest still ran
		self.assertNotIn('SECRET', '\n'.join(logs.output))

	def test_a_broken_settings_lookup_is_swallowed(self):
		with mock.patch('cveFeed.notify._settings', side_effect=RuntimeError('db down')):
			self.assertFalse(notify.scan_finished(self.scan(), {}))
			self.assertFalse(notify.fire_matches(self.since))


class SenderHelperTests(TestCase):
	"""The reNgine helpers behind the messages: bounded in time, and silent for a channel that is off."""

	def test_slack_and_lark_posts_have_a_timeout_and_off_channels_send_nothing(self):
		from reNgine import common_func
		with mock.patch('requests.post') as post, mock.patch('requests.get') as get:
			common_func.send_slack_message('x')
			common_func.send_lark_message('x')
			common_func.send_telegram_message('x')
			self.assertEqual((post.call_count, get.call_count), (0, 0))  # no Notification row
			Notification.objects.create(send_to_slack=True, slack_hook_url='https://hooks.invalid/s',
			                            send_to_lark=True, lark_hook_url='https://hooks.invalid/l')
			common_func.send_slack_message('x')
			common_func.send_lark_message('x')
			common_func.send_telegram_message('x')  # off
			self.assertEqual(post.call_count, 2)
			self.assertTrue(all(call.kwargs.get('timeout') for call in post.call_args_list))
			self.assertEqual(get.call_count, 0)
