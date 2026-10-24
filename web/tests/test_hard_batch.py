import os
from unittest import mock

from django.core.cache import cache
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import hit_batch, notify, tasks
from cveFeed.models import CVEEntry
from dashboard.models import AIProviderSettings, Org, Project
from scanEngine.models import Notification
from startScan.models import IpAddress, Port, Subdomain
from targetApp.models import Domain

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


class BatchTests(SimpleTestCase):
	"""Verdict 10: one message per auto-fire run."""

	def setUp(self):
		cache.clear()
		self.sent = []

	def send(self, hits):
		self.sent.append(list(hits))
		return True

	def test_the_last_test_to_finish_sends_one_message_with_every_hit(self):
		batch = hit_batch.start()
		for _ in range(3):
			hit_batch.join(batch)
		hit_batch.record(batch, [('CVE-1', 'a.t')])
		self.assertFalse(hit_batch.leave(batch, self.send))  # test 1 done, the run and two tests still hold places
		hit_batch.record(batch, [('CVE-2', 'b.t'), ('CVE-2', 'c.t')])
		self.assertFalse(hit_batch.leave(batch, self.send))
		hit_batch.record(batch, [])  # a test with no hits adds nothing
		hit_batch.leave(batch, self.send)
		self.assertEqual(self.sent, [])
		self.assertTrue(hit_batch.leave(batch, self.send))  # the run's own place is the last
		self.assertEqual(self.sent, [[('CVE-1', 'a.t'), ('CVE-2', 'b.t'), ('CVE-2', 'c.t')]])

	def test_a_fast_test_cannot_send_before_the_run_has_queued_everything(self):
		batch = hit_batch.start()
		hit_batch.join(batch)
		hit_batch.record(batch, [('CVE-1', 'a.t')])
		self.assertFalse(hit_batch.leave(batch, self.send))  # the first test finished while the run is still dispatching
		hit_batch.join(batch)
		hit_batch.leave(batch, self.send)
		self.assertEqual(self.sent, [])
		hit_batch.leave(batch, self.send)
		self.assertEqual(len(self.sent), 1)

	def test_no_hits_means_no_message_and_the_state_is_removed(self):
		batch = hit_batch.start()
		self.assertFalse(hit_batch.leave(batch, self.send))
		self.assertEqual(self.sent, [])
		self.assertIsNone(cache.get(f'cvengine:hits:{batch}:pending'))

	def test_an_expired_batch_is_ignored(self):
		self.assertFalse(hit_batch.leave('no-such-batch', self.send))

	def test_a_failing_sender_never_raises(self):
		batch = hit_batch.start()
		hit_batch.record(batch, [('CVE-1', 'a.t')])
		def boom(hits):
			raise RuntimeError('channel down')
		self.assertFalse(hit_batch.leave(batch, boom))

	def test_the_hits_kept_are_bounded(self):
		batch = hit_batch.start()
		hit_batch.record(batch, [(f'CVE-{i}', 'h') for i in range(hit_batch.MAX_HITS + 50)])
		hit_batch.leave(batch, self.send)
		self.assertEqual(len(self.sent[0]), hit_batch.MAX_HITS)


class RunTests(TestCase):
	def setUp(self):
		cache.clear()
		org = Org.objects.create(name='N', slug='n')
		project = Project.objects.create(name='P', slug='pn', insert_date=timezone.now(), org=org)
		domain = Domain.objects.create(name='batch.test', project=project, insert_date=timezone.now())
		ip = IpAddress.objects.create(address='198.51.100.70')
		ip.ports.add(Port.objects.create(number=80, product='nginx', version='1.18.0'))
		self.cves = []
		for n in range(3):
			sub = Subdomain.objects.create(name=f'h{n}.batch.test', target_domain=domain)
			sub.ip_addresses.add(ip)
			self.cves.append(CVEEntry.objects.create(cve_id=f'CVE-2099-7{n}', kev=True, cvss=9.8, published_at=timezone.now(),
				affected=[{'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}]))
		AIProviderSettings.objects.create(auto_fire=True)
		Notification.objects.create(send_to_slack=True, slack_hook_url='https://hooks.invalid/x')
		self.messages = []
		patcher = mock.patch('reNgine.common_func.send_slack_message', side_effect=lambda text: self.messages.append(text))
		patcher.start()
		self.addCleanup(patcher.stop)
		for name in ('send_discord_message', 'send_lark_message', 'send_telegram_message'):
			p = mock.patch(f'reNgine.common_func.{name}')
			p.start()
			self.addCleanup(p.stop)

	def run_batch(self, vulnerable_by_cve):
		"""Run the auto-fire task with the template tests executed inline (as Celery would, one by one)."""
		def fake_delay(cve_pk, hosts, project_id=None, batch=None):
			cve = CVEEntry.objects.get(pk=cve_pk)
			outcome = {'source': 'existing', 'results': [{'host': h, 'vulnerable': h in vulnerable_by_cve.get(cve.cve_id, ())} for h in hosts]}
			with mock.patch('cveFeed.templategen.run_cve_tests', return_value=outcome), \
					mock.patch('reNgine.ai_settings.get_configured_provider', return_value=None):
				tasks.template_test_for_cve(cve_pk, hosts, project_id, batch)
		with mock.patch('cveFeed.tasks.template_test_for_cve.delay', side_effect=fake_delay):
			return tasks.auto_fire_new_cves([c.pk for c in self.cves])

	def test_three_cves_with_hits_make_one_message(self):
		self.run_batch({c.cve_id: ('h0.batch.test', 'h1.batch.test') for c in self.cves})
		hit_messages = [m for m in self.messages if 'template test confirmed' in m]
		self.assertEqual(len(hit_messages), 1)
		self.assertIn('6 vulnerable hosts across 3 CVEs', hit_messages[0])

	def test_no_hits_no_template_message(self):
		self.run_batch({})
		self.assertEqual([m for m in self.messages if 'template test confirmed' in m], [])

	def test_a_test_that_crashes_still_lets_the_others_report(self):
		calls = []

		def fake_delay(cve_pk, hosts, project_id=None, batch=None):
			calls.append(cve_pk)
			if len(calls) == 1:
				with mock.patch('cveFeed.templategen.run_cve_tests', side_effect=RuntimeError('nuclei crashed')), \
						mock.patch('reNgine.ai_settings.get_configured_provider', return_value=None):
					with self.assertRaises(RuntimeError):
						tasks.template_test_for_cve(cve_pk, hosts, project_id, batch)
				return
			outcome = {'source': 'existing', 'results': [{'host': h, 'vulnerable': True} for h in hosts]}
			with mock.patch('cveFeed.templategen.run_cve_tests', return_value=outcome), \
					mock.patch('reNgine.ai_settings.get_configured_provider', return_value=None):
				tasks.template_test_for_cve(cve_pk, hosts, project_id, batch)
		with mock.patch('cveFeed.tasks.template_test_for_cve.delay', side_effect=fake_delay):
			tasks.auto_fire_new_cves([c.pk for c in self.cves])
		self.assertEqual(len([m for m in self.messages if 'template test confirmed' in m]), 1)

	def test_a_test_started_on_its_own_announces_itself(self):
		cve = self.cves[0]
		outcome = {'source': 'existing', 'results': [{'host': 'h0.batch.test', 'vulnerable': True}]}
		with mock.patch('cveFeed.templategen.run_cve_tests', return_value=outcome), mock.patch('reNgine.ai_settings.get_configured_provider', return_value=None):
			tasks.template_test_for_cve(cve.pk, ['h0.batch.test'])
		self.assertEqual(len([m for m in self.messages if 'template test confirmed' in m]), 1)

	def test_a_queue_failure_gives_back_the_place_it_took_and_the_run_gives_back_its_own(self):
		attempts = []

		def flaky(cve_pk, hosts, project_id=None, batch=None):
			attempts.append(cve_pk)
			if len(attempts) == 1:
				raise RuntimeError('broker down')
		with mock.patch('cveFeed.tasks.template_test_for_cve.delay', side_effect=flaky), \
				mock.patch('cveFeed.autofire.fire_for_cve', side_effect=lambda cve, **kw: kw['test_dispatcher'](cve.pk, ['h0.batch.test'], None)), \
				mock.patch.object(hit_batch, 'join', wraps=hit_batch.join) as join, mock.patch.object(hit_batch, 'leave', wraps=hit_batch.leave) as leave:
			with self.assertRaises(RuntimeError):
				tasks.auto_fire_new_cves([c.pk for c in self.cves])
		self.assertEqual(join.call_count, 1)
		self.assertEqual(leave.call_count, 2)  # the failed queue's place, and the run's own


class HelpTextTests(SimpleTestCase):
	def test_the_notification_settings_explain_the_shared_channel_and_the_batching(self):
		text = open(os.path.join(REPO, 'static', 'cve', 'settings.js')).read()
		self.assertIn('shared by the whole instance', text)
		self.assertIn('one message per auto-fire run', text)
