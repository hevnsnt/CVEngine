"""The "AI and your data" page (/cve/ai/, cveFeed/ai_disclosure.py) and the leaks it found on the way: every AI stage is described, the page
says which jobs are on, and what a model is sent no longer carries a person's login, a secret in the reviewer's own packets, or the host's
name inside an earlier check's summary."""
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase

from cveFeed import ai_disclosure, host_context, reviewer, threat
from cveFeed.models import ReviewerSettings, Triage
from cveFeed.threat import SMOKE
from dashboard.models import AIProviderSettings
from cvengine.ai_prompts import STAGES
from tests import test_heat_override, test_reviewer
from tests.test_tenancy import client_for

TOKEN = 'ghp_' + 'a1B2c3D4e5' * 4  # a GitHub token shape the secret masking knows


class CatalogueTests(SimpleTestCase):
	def test_every_ai_stage_is_described_or_retired(self):
		# a new AI job must say what it sends before it ships: add it to ai_disclosure.JOBS (or RETIRED once nothing calls it)
		missing = set(STAGES) - ai_disclosure.stage_ids() - ai_disclosure.RETIRED
		self.assertEqual(missing, set(), f'AI stages with no entry on the AI and your data page: {sorted(missing)}')
		self.assertEqual(ai_disclosure.stage_ids() - set(STAGES), set(), 'the page describes a stage cvengine.ai_prompts does not name')

	def test_every_job_says_what_it_sends_never_sends_and_how_to_stop_it(self):
		for job in ai_disclosure.JOBS:
			for key in ('title', 'purpose', 'when', 'changes', 'switch'):
				self.assertTrue(job[key].strip(), f'{job["id"]}: {key} is empty')
			self.assertTrue(job['sends'] and job['never'], f'{job["id"]}: says nothing about what it sends')
			self.assertIn(job['group'], {g for g, _t, _i in ai_disclosure.GROUPS})


class PageTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		cls.reader = User.objects.create_user('ai-reader', password='x')
		cls.admin = User.objects.create_superuser('ai-admin', password='x')

	def setUp(self):
		from django.core.cache import cache
		cache.delete(ai_disclosure.COUNTS_CACHE_KEY)  # the counts are cached for ten minutes: no test sees another's
		self.addCleanup(cache.delete, ai_disclosure.COUNTS_CACHE_KEY)

	def get(self, user):
		return client_for(user).get('/cve/ai/')

	def test_any_signed_in_person_can_read_it_and_it_names_every_job(self):
		r = self.get(self.reader)
		self.assertEqual(r.status_code, 200)
		html = r.content.decode()
		self.assertIn('<h1>AI and your data</h1>', html)
		for job in ai_disclosure.JOBS:
			self.assertIn(f'id="job-{job["id"]}"', html)
		for anchor in ('id="mcp"', 'id="host-context"', 'id="still-sent"', 'id="stop"'):
			self.assertIn(anchor, html)
		self.assertNotIn('calls in 30 days', html)  # the calls are an App Admin's figures

	def test_with_no_provider_it_says_nothing_is_sent_and_every_job_is_off(self):
		html = self.get(self.reader).content.decode()
		self.assertIn('nothing is sent to any AI model', html)
		self.assertIn(f'0 of {len(ai_disclosure.JOBS)} AI jobs are on', html)

	def test_a_hosted_provider_is_named_with_its_host_and_the_default_off_jobs_stay_off(self):
		AIProviderSettings.objects.create(provider='anthropic', api_key='sk-test-key', enabled=True)
		live = ai_disclosure.state()
		self.assertEqual((live['kind'], live['provider'], live['host']), ('hosted', 'Anthropic', 'api.anthropic.com'))
		self.assertTrue(live['jobs']['finding_triage'][0])
		for off in ('host_review', 'finding_review', 'operations_check', 'template_validation'):  # they ship off: an administrator turns them on
			self.assertEqual(live['jobs'][off], (False, 'off in Settings'), off)
		html = self.get(self.reader).content.decode()
		self.assertIn('<b>Anthropic</b>, a hosted service', html)

	def test_the_reviewer_switch_turns_its_jobs_on_and_the_container_switch_turns_everything_off(self):
		AIProviderSettings.objects.create(provider='anthropic', api_key='sk-test-key', enabled=True)
		ReviewerSettings.objects.create(enabled=True, host_review_enabled=True)
		self.assertTrue(ai_disclosure.state()['jobs']['host_review'][0])
		with mock.patch.dict('os.environ', {'CVENGINE_REVIEWER': '0'}):
			jobs = ai_disclosure.state()['jobs']
		self.assertEqual(jobs['finding_triage'], (False, 'the AI reviewer container is off'))
		self.assertTrue(jobs['connection_test'][0])  # the Settings test is made by the web container itself

	def test_a_self_hosted_server_address_is_shown_to_app_admins_only(self):
		AIProviderSettings.objects.create(provider='ollama', base_url='http://10.0.0.5:11434', model='llama', enabled=True)
		self.assertIn('<code>10.0.0.5</code>', self.get(self.admin).content.decode())
		html = self.get(self.reader).content.decode()
		self.assertIn('server your administrator runs', html)
		self.assertNotIn('10.0.0.5', html)

	def test_app_admins_see_the_calls_of_each_job(self):
		self.assertIn('calls in 30 days', self.get(self.admin).content.decode())

	def test_a_database_that_cannot_count_the_calls_does_not_make_the_page_a_500(self):
		from django.db import OperationalError
		with mock.patch.object(ai_disclosure, '_count_calls', side_effect=OperationalError('canceling statement due to statement timeout')):
			r = self.get(self.admin)
		self.assertEqual(r.status_code, 200)
		html = r.content.decode()
		self.assertIn('id="job-finding_triage"', html)  # everything the page says about what is sent is still there
		self.assertNotIn('calls in 30 days', html)
		self.assertIn('call counts could not be read', html)

	def test_the_thirty_day_counts_are_kept_for_ten_minutes_and_a_failure_is_not_kept(self):
		from django.core.cache import cache
		from django.db import OperationalError
		cache.delete(ai_disclosure.COUNTS_CACHE_KEY)
		with mock.patch.object(ai_disclosure, '_count_calls', side_effect=OperationalError('timeout')) as failing:
			self.assertIsNone(ai_disclosure._counts())
			self.assertIsNone(ai_disclosure._counts())
		self.assertEqual(failing.call_count, 2)  # a failure is tried again on the next view
		with mock.patch.object(ai_disclosure, '_count_calls', return_value={'finding_triage': 7}) as ok:
			self.assertEqual(ai_disclosure._counts(), {'finding_triage': 7})
			self.assertEqual(ai_disclosure._counts(), {'finding_triage': 7})
		self.assertEqual(ok.call_count, 1)  # the second view came from the cache
		cache.delete(ai_disclosure.COUNTS_CACHE_KEY)

	def test_the_account_menu_and_the_api_keys_page_link_to_it(self):
		self.assertIn('href="/cve/ai/"', client_for(self.reader).get('/cve/about/').content.decode())
		self.assertIn('/cve/ai/#mcp', client_for(self.admin).get('/cve/agents/').content.decode())


class HeatReasonWithoutPersonTests(test_heat_override.Fixture):
	def test_a_model_is_told_a_person_set_the_heat_never_who(self):
		self.override(self.smoke, SMOKE, 'only the login page is reachable')
		match = self.load(self.smoke)
		self.assertEqual(threat.heat_reason(match), 'set to smoke by heat-alice: only the login page is reachable')  # people still see who
		heat, reason = reviewer._heat('cve_match', match)
		self.assertEqual(reason, 'set to smoke by a person: only the login page is reachable')
		self.assertNotIn('heat-alice', reason)


class ReviewerPacketMaskingTests(test_reviewer.Fixture):
	def test_the_finding_review_packet_masks_secrets_like_every_queued_job(self):
		row = Triage.objects.get(match=self.match)
		Triage.objects.filter(pk=row.pk).update(reason=f'The page printed {TOKEN} in its footer')
		packet = reviewer.build_packet(Triage.objects.get(pk=row.pk), 'k1')
		self.assertNotIn(TOKEN, str(packet))
		self.assertIn('ghp_', str(packet))  # the masked shape stays readable

	def test_the_operations_snapshot_masks_secrets_in_error_text(self):
		check = {'code': 'sentinel_failures', 'state': 'bad', 'title': 'Tasks fail', 'description': '',
				 'facts': {'latest_error': f'401 from https://api.example.com with Authorization: Bearer {TOKEN}'}}
		with mock.patch.object(reviewer, 'ops_checks', return_value=[check]), mock.patch.object(reviewer, '_watchdog_events', return_value=[]):
			snap = reviewer.snapshot(_scan_only=True)
		self.assertNotIn(TOKEN, str(snap))


class EarlierCheckSummaryTests(SimpleTestCase):
	def test_the_host_name_in_an_earlier_check_summary_is_replaced(self):
		names = host_context._names_of(SimpleNamespace(name='app.example.com', target_domain=SimpleNamespace(name='example.com'), cname=''))
		row = SimpleNamespace(validation_steps=[{'kind': 'library_read', 'result': 'reaffirmed',
												 'summary': 'Fetched https://app.example.com/static/jquery.js: the banner states jQuery v1.2'}])
		steps = host_context._steps(1, 'app.example.com', rows=[row], names=names)
		self.assertNotIn('example.com', steps[0]['summary'])
		self.assertIn('[host]', steps[0]['summary'])
