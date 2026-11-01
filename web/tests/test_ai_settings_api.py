"""Settings, AI model: the settings that say how a request is made (timeouts, reply limit, context window, structured output, reasoning,
keep-alive) through the API behind the page: what is stored, what is refused, that an empty value clears one, that it reaches the provider,
that the secret handling and the superuser-only rule are unchanged, and what the audit log keeps."""
import json
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase

from dashboard.models import AIProviderSettings, AuditLog, Org, OrgMembership
from reNgine import ai_providers as ai
from reNgine.ai_profiles import AIRuntime
from tests.test_settings import send
from tests.test_tenancy import client_for

ENV_NAMES = ('CVENGINE_AI_TIMEOUT', 'CVENGINE_AI_CONNECT_TIMEOUT', 'CVENGINE_AI_MAX_TOKENS', 'CVENGINE_AI_STRUCTURED', 'CVENGINE_AI_REASONING',
	'CVENGINE_OLLAMA_NUM_CTX')
FIELDS = ('request_timeout', 'connect_timeout', 'max_tokens', 'context_tokens', 'structured_mode', 'reasoning', 'keep_alive')


class AiRequestSettingsApiTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		cls.root = User.objects.create_superuser('airoot', 'a@x.io', 'x')
		cls.admin = User.objects.create_user('aiadmin', password='x')
		org = Org.objects.create(name='Ai', slug='ai-org')
		OrgMembership.objects.create(user=cls.admin, org=org, role='admin')

	def setUp(self):
		self.c = client_for(self.root)
		patcher = mock.patch.dict('os.environ', {name: '' for name in ENV_NAMES})
		patcher.start()
		self.addCleanup(patcher.stop)

	def put(self, **body):
		return send(self.c, 'PUT', 'ai', body)

	# --- what is reported ---

	def test_a_fresh_install_reports_every_setting_empty_and_follows_the_defaults(self):
		status, data = send(self.c, 'GET', 'ai')
		self.assertEqual(status, 200)
		for name in ('request_timeout', 'connect_timeout', 'max_tokens', 'context_tokens'):
			self.assertIsNone(data[name], name)
		for name in ('structured_mode', 'reasoning', 'keep_alive'):
			self.assertEqual(data[name], '', name)
		self.assertEqual(data['env'], {})
		self.assertEqual({k: v['source'] for k, v in data['effective'].items() if k in ('request_timeout', 'max_tokens')},
			{'request_timeout': 'default', 'max_tokens': 'default'})
		self.assertEqual(data['effective']['request_timeout']['value'], 120)
		self.assertEqual(data['effective']['max_tokens']['value'], 2048)

	def test_the_page_is_told_the_ranges_the_choices_and_what_applies_where(self):
		data = send(self.c, 'GET', 'ai')[1]
		self.assertEqual(data['limits']['request_timeout'], {'min': 10, 'max': 3600, 'unit': 'seconds'})
		self.assertEqual(data['limits']['connect_timeout']['max'], 300)
		self.assertEqual((data['limits']['max_tokens']['min'], data['limits']['max_tokens']['max']), (64, 32768))
		self.assertEqual((data['limits']['context_tokens']['min'], data['limits']['context_tokens']['max']), (512, 1048576))
		self.assertEqual(data['choices']['structured_mode'], ['auto', 'all', 'off'])
		self.assertEqual(data['choices']['reasoning'], ['default', 'off', 'low', 'medium', 'high', 'max'])
		self.assertEqual(data['applies_to'], {'context_tokens': ['ollama'], 'keep_alive': ['ollama']})
		self.assertEqual(set(data['provider_defaults']), set(data['providers']))
		self.assertEqual(data['provider_defaults']['lmstudio']['request_timeout'], 300)
		self.assertIsNone(data['provider_defaults']['openai']['max_tokens'])

	def test_the_environment_in_force_is_listed_and_the_effective_value_follows_it(self):
		with mock.patch.dict('os.environ', {'CVENGINE_AI_TIMEOUT': '400', 'CVENGINE_AI_REASONING': 'low', 'CVENGINE_OLLAMA_NUM_CTX': 'big'}):
			data = send(self.c, 'GET', 'ai')[1]
			self.assertEqual(data['env'], {'request_timeout': '400', 'reasoning': 'low', 'context_tokens': 'big'})  # as written: the page shows it
			self.assertEqual((data['effective']['request_timeout']['value'], data['effective']['request_timeout']['source']), (400, 'env'))
			self.assertIsNone(data['effective']['context_tokens']['value'])  # not a number: ignored, as the provider does
			self.put(request_timeout=900)
			data = send(self.c, 'GET', 'ai')[1]
			self.assertEqual((data['effective']['request_timeout']['value'], data['effective']['request_timeout']['source']), (900, 'setting'))
			self.assertEqual(data['env']['request_timeout'], '400')  # the environment is still reported: the page can say what a cleared field falls back to

	# --- what is stored ---

	def test_every_setting_round_trips(self):
		status, data = self.put(request_timeout=600, connect_timeout=30, max_tokens=4096, context_tokens=16384, structured_mode='off',
			reasoning='low', keep_alive='30m')
		self.assertEqual(status, 200)
		self.assertEqual({k: data[k] for k in FIELDS}, {'request_timeout': 600, 'connect_timeout': 30, 'max_tokens': 4096,
			'context_tokens': 16384, 'structured_mode': 'off', 'reasoning': 'low', 'keep_alive': '30m'})
		row = AIProviderSettings.objects.get()
		self.assertEqual({k: getattr(row, k) for k in FIELDS}, {k: data[k] for k in FIELDS})
		self.assertEqual({k: send(self.c, 'GET', 'ai')[1][k] for k in FIELDS}, {k: data[k] for k in FIELDS})

	def test_numbers_may_arrive_as_text_as_a_form_sends_them(self):
		data = self.put(request_timeout=' 600 ', max_tokens='4096')[1]
		self.assertEqual((data['request_timeout'], data['max_tokens']), (600, 4096))

	def test_an_update_without_the_setting_leaves_it_alone(self):
		self.put(request_timeout=600, structured_mode='all', keep_alive='1h')
		data = self.put(model='m')[1]
		self.assertEqual((data['request_timeout'], data['structured_mode'], data['keep_alive']), (600, 'all', '1h'))

	def test_an_empty_value_clears_a_setting(self):
		self.put(request_timeout=600, connect_timeout=30, max_tokens=4096, context_tokens=2048, structured_mode='all', reasoning='high', keep_alive='5m')
		for empty in ('', None):
			self.put(request_timeout=600, structured_mode='all', reasoning='high', keep_alive='5m')
			data = self.put(request_timeout=empty, connect_timeout=empty, max_tokens=empty, context_tokens=empty, structured_mode=empty,
				reasoning=empty, keep_alive=empty)[1]
			self.assertEqual({k: data[k] for k in FIELDS}, {'request_timeout': None, 'connect_timeout': None, 'max_tokens': None,
				'context_tokens': None, 'structured_mode': '', 'reasoning': '', 'keep_alive': ''}, repr(empty))
			self.assertEqual(AIProviderSettings.objects.get().request_timeout, None)

	def test_values_are_normalised(self):
		data = self.put(structured_mode=' ALL ', reasoning='High', keep_alive=' 30M ')[1]
		self.assertEqual((data['structured_mode'], data['reasoning'], data['keep_alive']), ('all', 'high', '30m'))

	# --- what is refused ---

	def test_a_number_outside_its_range_or_not_a_whole_number_is_refused_and_nothing_is_stored(self):
		self.put(request_timeout=600)
		for body in ({'request_timeout': 9}, {'request_timeout': 3601}, {'request_timeout': 'soon'}, {'request_timeout': 1.5}, {'request_timeout': '1e3'},
				{'request_timeout': True}, {'request_timeout': [600]}, {'request_timeout': -10}, {'request_timeout': '60 0'},
				{'connect_timeout': 0}, {'connect_timeout': 301}, {'max_tokens': 63}, {'max_tokens': 32769}, {'max_tokens': '-1'},
				{'context_tokens': 511}, {'context_tokens': 1048577}, {'context_tokens': {}}, {'request_timeout': '9' * 40}):
			status, data = self.put(model='changed', **body)
			self.assertEqual(status, 400, body)
			self.assertIn(next(iter(body)), data['error'], body)
		row = AIProviderSettings.objects.get()
		self.assertEqual((row.request_timeout, row.model), (600, ''))  # one bad value stores none of the request

	def test_the_edges_of_every_range_are_accepted(self):
		for name, low, high in (('request_timeout', 10, 3600), ('connect_timeout', 1, 300), ('max_tokens', 64, 32768), ('context_tokens', 512, 1048576)):
			for value in (low, high):
				self.assertEqual(self.put(**{name: value})[1][name], value, (name, value))

	def test_a_word_that_is_not_a_choice_is_refused(self):
		for body in ({'structured_mode': 'sometimes'}, {'structured_mode': 5}, {'reasoning': 'loud'}, {'reasoning': 'xhigh'}, {'reasoning': ['low']},
				{'keep_alive': 'forever'}, {'keep_alive': '1d'}, {'keep_alive': '5m; x'}, {'keep_alive': 30}, {'keep_alive': '-2'}):
			status, data = self.put(**body)
			self.assertEqual(status, 400, body)
			self.assertIn(next(iter(body)), data['error'])
		row = AIProviderSettings.objects.first()
		self.assertTrue(row is None or (row.structured_mode, row.reasoning, row.keep_alive) == ('', '', ''))

	def test_default_is_a_reasoning_choice_and_the_others_are_the_levels(self):
		for level in ('default', 'off', 'low', 'medium', 'high', 'max'):
			self.assertEqual(self.put(reasoning=level)[1]['reasoning'], level)

	# --- who may, and what is kept ---

	def test_only_a_superuser_reads_or_changes_them(self):
		other = client_for(self.admin)
		self.assertEqual(send(other, 'PUT', 'ai', {'request_timeout': 600})[0], 403)
		self.assertEqual(send(other, 'GET', 'ai')[0], 403)
		self.assertIsNone(AIProviderSettings.objects.first())

	def test_the_secret_is_still_write_only_and_the_new_fields_leak_none(self):
		status, data = self.put(provider='openai', api_key='sk-very-secret-key', base_url='https://llm.example.com/v1', request_timeout=600)
		self.assertEqual(status, 200)
		blob = json.dumps(send(self.c, 'GET', 'ai')[1]) + json.dumps(data)
		self.assertNotIn('sk-very-secret-key', blob)
		self.assertTrue(data['has_key'])
		self.assertEqual(self.put(request_timeout=700)[1]['has_key'], True)  # a change of a setting keeps the stored key
		self.assertEqual(AIProviderSettings.objects.get().api_key, 'sk-very-secret-key')

	def test_a_new_address_still_drops_the_stored_key_whatever_else_is_set(self):
		self.put(provider='openai', api_key='sk-keep-me', base_url='https://llm.example.com/v1')
		data = self.put(base_url='https://other.example.net/v1', request_timeout=600, max_tokens=1000)[1]
		self.assertFalse(data['has_key'])
		self.assertEqual(data['request_timeout'], 600)

	def test_a_metadata_address_is_still_refused_with_the_new_fields_present(self):
		self.assertEqual(self.put(base_url='http://169.254.169.254/v1', request_timeout=600)[0], 400)
		self.assertIsNone(AIProviderSettings.objects.first())

	# --- the audit log ---

	def test_a_change_is_audited_by_name_with_the_new_value_and_never_a_key_or_address(self):
		self.put(provider='openai', api_key='sk-audit-secret', base_url='https://user:pw@llm.example.com/v1', request_timeout=600, reasoning='low')
		entry = AuditLog.objects.filter(action='ai.settings').latest('id')
		self.assertEqual(entry.actor_name, 'airoot')
		self.assertEqual(sorted(entry.detail['changed']), ['api_key', 'base_url', 'provider', 'reasoning', 'request_timeout'])
		self.assertEqual((entry.detail['request_timeout'], entry.detail['reasoning']), (600, 'low'))
		blob = json.dumps(entry.detail) + entry.target
		for secret in ('sk-audit-secret', 'user:pw', 'llm.example.com'):
			self.assertNotIn(secret, blob)

	def test_a_save_that_changes_nothing_is_not_audited(self):
		self.put(request_timeout=600)
		before = AuditLog.objects.filter(action='ai.settings').count()
		self.put(request_timeout=600)
		self.put(enabled=False)
		self.assertEqual(AuditLog.objects.filter(action='ai.settings').count(), before)
		self.put(request_timeout=None)
		self.assertEqual(AuditLog.objects.filter(action='ai.settings').count(), before + 1)

	# --- they reach the request ---

	def test_the_configured_provider_carries_the_settings(self):
		from reNgine.ai_settings import get_configured_provider
		self.put(provider='ollama', base_url='http://h:11434', model='qwen3:8b', enabled=True, request_timeout=600, max_tokens=3000,
			context_tokens=8192, keep_alive='20m', reasoning='off', structured_mode='off', connect_timeout=25)
		provider = get_configured_provider()
		self.assertEqual(provider.runtime, AIRuntime(request_timeout=600, connect_timeout=25, max_tokens=3000, context_tokens=8192,
			structured_mode='off', reasoning='off', keep_alive='20m'))
		with mock.patch('requests.post', return_value=mock.Mock(json=lambda: {'message': {'content': 'ok'}})) as post:
			provider.complete('s', 'u')
		kwargs = post.call_args[1]
		self.assertEqual(kwargs['timeout'], (25, 600))
		self.assertEqual(kwargs['json']['options'], {'num_predict': 3000, 'num_ctx': 8192})
		self.assertEqual((kwargs['json']['keep_alive'], kwargs['json']['think']), ('20m', False))

	def test_an_install_that_sets_nothing_builds_the_provider_it_always_did(self):
		from reNgine.ai_settings import get_configured_provider
		AIProviderSettings.objects.create(provider='anthropic', api_key='k', enabled=True)
		self.assertEqual(get_configured_provider().runtime, AIRuntime())

	def test_a_row_edited_by_hand_with_a_bad_value_still_sends_a_valid_request(self):
		from reNgine.ai_settings import get_configured_provider
		AIProviderSettings.objects.create(provider='anthropic', api_key='k', enabled=True, request_timeout=1, max_tokens=5, structured_mode='x', reasoning='y', keep_alive='z')
		self.assertEqual(get_configured_provider().runtime, AIRuntime())

	# --- the connection test ---

	def test_the_connection_test_uses_the_saved_settings(self):
		self.put(provider='anthropic', api_key='k', model='claude-x', request_timeout=777, connect_timeout=7, max_tokens=999)
		with mock.patch('requests.post', return_value=mock.Mock(json=lambda: {'content': [{'type': 'text', 'text': 'ok'}], 'stop_reason': 'end_turn'})) as post:
			status, data = send(self.c, 'POST', 'ai/test')
		self.assertEqual((status, data['ok']), (200, True))
		self.assertEqual(post.call_args[1]['timeout'], (7, 777))
		self.assertEqual(post.call_args[1]['json']['max_tokens'], 999)
		self.assertIsNotNone(AIProviderSettings.objects.get().verified_at)

	def fail_with(self, exc):
		self.put(provider='anthropic', api_key='sk-test-key', model='claude-x')
		with mock.patch('requests.post', side_effect=exc):
			return send(self.c, 'POST', 'ai/test')

	def test_a_failed_test_says_what_to_change(self):
		import requests

		def http_error(status):
			response = mock.Mock(status_code=status, text='{"error": "nope"}')
			response.raise_for_status.side_effect = requests.HTTPError(response=response)
			return mock.Mock(return_value=response)
		cases = (
			(requests.Timeout(), 'longer "Request timeout"'), (requests.ConnectionError('boom'), 'could not be reached'),
		)
		for exc, hint in cases:
			status, data = self.fail_with(exc)
			self.assertEqual(status, 400)
			self.assertIn(hint, data['error'])
			self.assertTrue(data['error'].startswith('connection failed: '), data['error'])
			self.assertNotIn('sk-test-key', data['error'])
		for code, hint in ((401, 'refused the key'), (429, 'rate limiting'), (500, 'answered with an error')):
			self.put(provider='anthropic', api_key='sk-test-key', model='claude-x')
			with mock.patch('requests.post', http_error(code)):
				status, data = send(self.c, 'POST', 'ai/test')
			self.assertEqual(status, 400)
			self.assertIn(hint, data['error'], code)
			self.assertNotIn('nope', data['error'])  # what the provider said is never repeated
		self.assertIsNone(AIProviderSettings.objects.get().verified_at)

	def test_the_timeout_hint_names_the_seconds_in_force(self):
		import requests
		self.put(provider='anthropic', api_key='k', model='claude-x', request_timeout=45)
		with mock.patch('requests.post', side_effect=requests.Timeout()):
			data = send(self.c, 'POST', 'ai/test')[1]
		self.assertIn('No answer in 45 seconds', data['error'])

	def test_a_cut_off_or_empty_reply_points_at_the_reply_limit(self):
		self.put(provider='anthropic', api_key='k', model='claude-x')
		for reply, hint in (({'content': [{'type': 'text', 'text': 'x'}], 'stop_reason': 'max_tokens'}, 'Reply limit'),
				({'content': [], 'stop_reason': 'end_turn'}, 'Reply limit')):
			with mock.patch('requests.post', return_value=mock.Mock(json=lambda r=reply: r)):
				status, data = send(self.c, 'POST', 'ai/test')
			self.assertEqual(status, 400)
			self.assertIn(hint, data['error'])

	def test_a_missing_key_has_no_invented_hint(self):
		self.put(provider='anthropic', model='claude-x')
		status, data = send(self.c, 'POST', 'ai/test')
		self.assertEqual((status, data['error']), (400, 'connection failed: anthropic requires an API key'))

	def test_every_hint_is_a_sentence_for_a_category_the_provider_layer_raises(self):
		from cveFeed.settings_api import AI_ERROR_HINTS
		raised = {'provider_auth', 'provider_rate_limit', 'provider_timeout', 'provider_network', 'provider_http', 'provider_json', 'provider_shape',
			'output_truncated', 'empty_response'}
		self.assertEqual(set(AI_ERROR_HINTS), raised)
		self.assertEqual(ai.AIProviderError('x', category='provider_timeout').category, 'provider_timeout')
