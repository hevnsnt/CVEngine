"""The provider capability profile (reNgine/ai_profiles.py): the request each provider sends is byte for byte what it was before the table
existed, the opt-in reasoning controls send exactly their own fields and only when asked, and a key is never guessed onto a vendor."""
import json
import unittest
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase

from reNgine import ai_profiles as profiles
from reNgine import ai_providers as ai

OPENAI_OK = {'choices': [{'message': {'content': 'ok'}, 'finish_reason': 'stop'}]}
ANTHROPIC_OK = {'content': [{'type': 'text', 'text': 'ok'}], 'stop_reason': 'end_turn'}
OLLAMA_OK = {'message': {'content': 'ok'}, 'done': True}
PNG = b'\x89PNG\r\n\x1a\nfake'
SCHEMA = {'type': 'object', 'properties': {'x': {'type': 'string'}}}
MESSAGES = [{'role': 'system', 'content': 's'}, {'role': 'user', 'content': 'u'}]
OPENROUTER_HEADERS = {'Authorization': 'Bearer k', 'HTTP-Referer': 'https://github.com/hevnsnt/CVEngine', 'X-Title': 'CVEngine'}
TRIAGE = {'temperature': 0, 'seed': ai.TRIAGE_SEED, 'schema': SCHEMA, 'max_tokens': 400}  # what ai._ask_triage asks for


class Reply:
	def __init__(self, data):
		self._data = data

	def raise_for_status(self):
		pass

	def json(self):
		return self._data


def provider(name, model='m', base=None):
	keyed = name in ('anthropic', 'openai', 'openrouter')
	return ai.get_provider(name, model=model, api_key='k' if keyed else None, base_url=base)


BASES = {'ollama': 'http://h:11434', 'vllm': 'http://h:8000/v1', 'lmstudio': 'http://h:1234/v1'}
REPLIES = {'anthropic': ANTHROPIC_OK, 'openai': OPENAI_OK, 'openrouter': OPENAI_OK, 'ollama': OLLAMA_OK, 'vllm': OPENAI_OK, 'lmstudio': OPENAI_OK}


def sent(name, call='complete', env=None, options=None, model='m', base=None):
	"""(url, headers, json body) of the one request ``call`` makes, with ``env`` set and the stage's ``options`` asked for."""
	with mock.patch.dict('os.environ', env or {}, clear=False), mock.patch('requests.post', return_value=Reply(REPLIES[name])) as post:
		p = provider(name, model=model, base=base or BASES.get(name))
		with ai.request_options(**(options or {})):
			if call == 'vision':
				p.complete_vision('s', 'u', PNG)
			else:
				p.complete('s', 'u')
	args, kwargs = post.call_args
	return args[0], kwargs['headers'], kwargs['json']


def clean_env():
	return mock.patch.dict('os.environ', {k: '' for k in ('CVENGINE_AI_REASONING', 'CVENGINE_AI_MAX_TOKENS', 'CVENGINE_AI_STRUCTURED',
		'CVENGINE_OLLAMA_NUM_CTX')})


class RequestBodyTests(unittest.TestCase):
	"""Captured before the profile table was wired in: each provider's request for a plain call, a triage call (temperature, seed, schema and
	the stage's reply limit pinned) and an image call, and the settings that change them. These must not move."""

	def setUp(self):
		patcher = clean_env()
		patcher.start()
		self.addCleanup(patcher.stop)

	def test_anthropic(self):
		url, headers, body = sent('anthropic')
		self.assertEqual(url, 'https://api.anthropic.com/v1/messages')
		self.assertEqual(headers, {'x-api-key': 'k', 'anthropic-version': '2023-06-01'})
		self.assertEqual(body, {'model': 'm', 'max_tokens': 2048, 'system': 's', 'messages': [{'role': 'user', 'content': 'u'}]})
		self.assertEqual(sent('anthropic', options=TRIAGE)[2], body)  # no temperature, seed or schema, and the stage's limit is not used
		self.assertEqual(sent('anthropic', env={'CVENGINE_AI_MAX_TOKENS': '900'})[2]['max_tokens'], 900)
		self.assertEqual(sent('anthropic', options={'token_factor': 2})[2]['max_tokens'], 4096)
		_, _, vision = sent('anthropic', call='vision')
		self.assertEqual(vision['messages'][0]['content'][0], {'type': 'image', 'source': {'type': 'base64', 'media_type': 'image/png',
			'data': 'iVBORw0KGgpmYWtl'}})
		self.assertEqual(set(vision), {'model', 'max_tokens', 'system', 'messages'})

	def test_anthropic_with_a_base_url(self):
		url, _, body = sent('anthropic', base='https://gw.example.test/v1/messages')
		self.assertEqual(url, 'https://gw.example.test/v1/messages')
		self.assertEqual(body['max_tokens'], 2048)

	def test_openai(self):
		url, headers, body = sent('openai')
		self.assertEqual(url, 'https://api.openai.com/v1/chat/completions')
		self.assertEqual(headers, {'Authorization': 'Bearer k'})
		self.assertEqual(body, {'model': 'm', 'messages': MESSAGES})
		self.assertEqual(sent('openai', options=TRIAGE)[2], body)  # a hosted provider is sent no temperature, seed, schema or limit
		self.assertEqual(sent('openai', env={'CVENGINE_AI_MAX_TOKENS': '900'})[2], {**body, 'max_completion_tokens': 900})
		self.assertEqual(sent('openai', env={'CVENGINE_AI_MAX_TOKENS': '900'}, base='https://proxy.example.test/v1')[2], {**body, 'max_tokens': 900})
		self.assertEqual(sent('openai', env={'CVENGINE_AI_STRUCTURED': 'all'}, options=TRIAGE)[2], {**body, 'response_format': {
			'type': 'json_schema', 'json_schema': {'name': 'triage', 'strict': True, 'schema': SCHEMA}}})
		_, _, vision = sent('openai', call='vision')
		self.assertEqual(set(vision), {'model', 'messages'})

	def test_openrouter(self):
		url, headers, body = sent('openrouter')
		self.assertEqual(url, 'https://openrouter.ai/api/v1/chat/completions')
		self.assertEqual(headers, OPENROUTER_HEADERS)
		self.assertEqual(body, {'model': 'm', 'messages': MESSAGES})
		self.assertEqual(sent('openrouter', options=TRIAGE)[2], body)
		self.assertEqual(sent('openrouter', env={'CVENGINE_AI_MAX_TOKENS': '900'})[2], {**body, 'max_tokens': 900})
		self.assertEqual(sent('openrouter', env={'CVENGINE_AI_STRUCTURED': 'all'}, options=TRIAGE)[2], {**body, 'provider': {'require_parameters': True},
			'response_format': {'type': 'json_schema', 'json_schema': {'name': 'triage', 'strict': True, 'schema': SCHEMA}}})

	def test_ollama(self):
		url, headers, body = sent('ollama')
		self.assertEqual(url, 'http://h:11434/api/chat')
		self.assertEqual(headers, {})
		self.assertEqual(body, {'model': 'm', 'stream': False, 'messages': MESSAGES, 'options': {'num_predict': 2048}})
		self.assertEqual(sent('ollama', options=TRIAGE)[2], {**body, 'options': {'num_predict': 400, 'temperature': 0, 'seed': ai.TRIAGE_SEED}, 'format': SCHEMA})
		self.assertEqual(sent('ollama', env={'CVENGINE_AI_MAX_TOKENS': '900', 'CVENGINE_OLLAMA_NUM_CTX': '8192'})[2]['options'], {'num_predict': 900, 'num_ctx': 8192})
		_, _, vision = sent('ollama', call='vision')
		self.assertEqual(vision['messages'][1], {'role': 'user', 'content': 'u', 'images': ['iVBORw0KGgpmYWtl']})
		self.assertEqual(vision['options'], {'num_predict': 2048})

	def test_vllm_and_lmstudio(self):
		for name, base in (('vllm', 'http://h:8000/v1'), ('lmstudio', 'http://h:1234/v1')):
			url, headers, body = sent(name)
			self.assertEqual((url, headers), (f'{base}/chat/completions', {}), name)
			self.assertEqual(body, {'model': 'm', 'messages': MESSAGES, 'max_tokens': 2048}, name)
			self.assertEqual(sent(name, options=TRIAGE)[2], {'model': 'm', 'messages': MESSAGES, 'max_tokens': 400, 'temperature': 0, 'seed': ai.TRIAGE_SEED,
				'response_format': {'type': 'json_schema', 'json_schema': {'name': 'triage', 'strict': True, 'schema': SCHEMA}}}, name)
			self.assertEqual(sent(name, env={'CVENGINE_AI_MAX_TOKENS': '900'})[2]['max_tokens'], 900, name)
			self.assertEqual(sent(name, call='vision')[2]['max_tokens'], 2048, name)

	def test_a_set_reasoning_variable_that_means_nothing_changes_no_request(self):
		for name in REPLIES:
			plain = sent(name)
			for value in ('', 'bogus', 'OFF-ish'):
				self.assertEqual(sent(name, env={'CVENGINE_AI_REASONING': value}), plain, (name, value))


class ProfileTableTests(SimpleTestCase):
	def test_the_provider_lists_derive_from_the_table_and_are_what_they_were(self):
		from dashboard.models import AIProviderSettings
		ids = ['anthropic', 'openai', 'openrouter', 'ollama', 'vllm', 'lmstudio']  # the stored ids: no provider is added by the table
		self.assertEqual(list(profiles.PROFILES), ids)
		self.assertEqual(list(ai.PROVIDERS), ids)
		self.assertEqual([p for p, _ in AIProviderSettings.PROVIDER_CHOICES], ids)
		self.assertEqual(AIProviderSettings.PROVIDER_CHOICES, [('anthropic', 'Anthropic'), ('openai', 'OpenAI'), ('openrouter', 'OpenRouter'),
			('ollama', 'Ollama'), ('vllm', 'vLLM'), ('lmstudio', 'LM Studio')])
		self.assertEqual(list(ai.DEFAULT_MODELS), ids)
		self.assertEqual(ai.DEFAULT_MODELS, {'anthropic': 'claude-haiku-5-5', 'openai': 'gpt-5.4-nano', 'openrouter': '', 'ollama': '', 'vllm': '', 'lmstudio': ''})
		self.assertEqual(ai.SELECTABLE, ('openrouter', 'ollama', 'vllm', 'lmstudio'))
		self.assertEqual(ai.KEYLESS, ('ollama', 'vllm', 'lmstudio'))
		self.assertEqual(ai.SERVER_URL_PROVIDERS, ('ollama', 'vllm', 'lmstudio'))
		self.assertEqual(ai.LOCAL_PORT, {'ollama': 11434, 'vllm': 8000, 'lmstudio': 1234})
		self.assertEqual((ai.MAX_TOKENS, ai.TRIAGE_TOKEN_CAP), (2048, 400))
		self.assertEqual((ai.ANTHROPIC_URL, ai.OPENAI_URL, ai.OPENROUTER_BASE), ('https://api.anthropic.com/v1/messages',
			'https://api.openai.com/v1/chat/completions', 'https://openrouter.ai/api/v1'))

	def test_every_class_names_its_profile_and_the_facts_agree_with_its_behaviour(self):
		for name, cls in ai.PROVIDERS.items():
			profile = profiles.PROFILES[name]
			self.assertEqual(cls.name, profile.id)
			self.assertIn(profile.transport, profiles.TRANSPORTS)
			self.assertIn(profile.reasoning_detect('anything'), profiles.MECHANISMS)
			if profile.transport == 'openai_chat':  # the name of the limit field follows the address: OpenAI's own host takes max_completion_tokens
				self.assertIsInstance(provider(name, base=BASES.get(name)), ai.OpenAIProvider)
				address = profile.default_base or BASES[name]
				self.assertEqual(provider(name, base=address)._limit_name(), profile.token_param, name)
		self.assertEqual(profiles.PROFILES['ollama'].token_param, 'num_predict')

	def test_a_profile_is_frozen_and_the_module_needs_no_django(self):
		import dataclasses
		with self.assertRaises(dataclasses.FrozenInstanceError):
			profiles.PROFILES['openai'].label = 'x'
		source = open(profiles.__file__).read()
		for word in ('django', 'requests', 'celery'):
			self.assertNotRegex(source, rf'^\s*(?:from|import) {word}', word)


class MechanismTests(unittest.TestCase):
	def test_the_mechanism_of_a_model(self):
		table = {
			('openai', 'gpt-5.4-nano'): 'effort', ('openai', 'gpt-5'): 'effort', ('openai', 'o3'): 'effort', ('openai', 'o4-mini'): 'effort',
			('openai', 'o3-mini'): 'effort', ('openai', 'o1'): 'effort', ('openai', 'openai/gpt-5-mini'): 'effort',
			('openai', 'gpt-4o'): 'none', ('openai', 'gpt-4.1'): 'none', ('openai', 'o1-mini'): 'none', ('openai', 'o1-preview'): 'none',
			('openai', 'gpt-5-chat-latest'): 'none', ('openai', 'deepseek-reasoner'): 'none', ('openai', ''): 'none',
			('anthropic', 'claude-haiku-5-5'): 'adaptive', ('anthropic', 'claude-sonnet-5-5'): 'adaptive', ('anthropic', 'claude-opus-5-5'): 'adaptive',
			('anthropic', 'claude-opus-5'): 'adaptive', ('anthropic', 'claude-sonnet-5'): 'adaptive', ('anthropic', 'claude-fable-5-1'): 'adaptive',
			('anthropic', 'claude-fable-5'): 'adaptive', ('anthropic', 'claude-opus-4-8'): 'adaptive', ('anthropic', 'claude-opus-4-6'): 'adaptive',
			('anthropic', 'claude-sonnet-4-6'): 'adaptive', ('anthropic', 'anthropic.claude-opus-5-5'): 'adaptive',
			('anthropic', 'claude-haiku-4-5'): 'budget', ('anthropic', 'claude-haiku-4-5-20251001'): 'budget',
			('anthropic', 'claude-sonnet-4-5-20250929'): 'budget', ('anthropic', 'claude-sonnet-4-20250514'): 'budget',
			('anthropic', 'claude-opus-4-1-20250805'): 'budget', ('anthropic', 'claude-3-7-sonnet-latest'): 'budget',
			('anthropic', 'claude-3-5-haiku-20241022'): 'none', ('anthropic', 'claude-3-opus-20240229'): 'none', ('anthropic', 'my-gateway-model'): 'none',
			('openrouter', 'deepseek/deepseek-r1'): 'none',
			('ollama', 'qwen3:8b'): 'toggle', ('ollama', 'deepseek-r1:7b'): 'toggle', ('ollama', 'gpt-oss:20b'): 'toggle', ('vllm', 'Qwen/Qwen3-32B'): 'toggle',
			('lmstudio', 'magistral-small'): 'toggle', ('ollama', 'llama3.1:8b'): 'none', ('vllm', 'meta/llama-3'): 'none', ('lmstudio', 'qwen2.5-7b'): 'none',
			('nope', 'x'): 'none',
		}
		for (provider_id, model), expected in table.items():
			self.assertEqual(profiles.reasoning_mechanism(provider_id, model), expected, (provider_id, model))

	def test_claude_version(self):
		self.assertEqual(profiles.claude_version('claude-sonnet-4-20250514'), ('sonnet', 4, 0))
		self.assertEqual(profiles.claude_version('claude-opus-4-1-20250805'), ('opus', 4, 1))
		self.assertEqual(profiles.claude_version('us.anthropic.claude-haiku-4-5-20251001-v1:0'), ('haiku', 4, 5))
		self.assertEqual(profiles.claude_version('claude-3-5-sonnet-20241022'), ('sonnet', 3, 5))
		self.assertEqual(profiles.claude_version('claude-opus-5'), ('opus', 5, 0))
		self.assertIsNone(profiles.claude_version('gpt-5'))


class ReasoningRequestTests(unittest.TestCase):
	"""CVENGINE_AI_REASONING is opt in: unset sends nothing, set adds exactly the field the provider's mechanism names."""
	FORBIDDEN_FOR_ANTHROPIC = ('temperature', 'top_p', 'top_k')

	def setUp(self):
		ai._REASONING_NOTED.clear()
		patcher = clean_env()
		patcher.start()
		self.addCleanup(patcher.stop)

	def reasoning(self, name, level, model='m', **kwargs):
		env = {'CVENGINE_AI_REASONING': level, **kwargs.pop('env', {})}
		return sent(name, env=env, model=model, **kwargs)

	def extra(self, name, level, model='m', **kwargs):
		"""The fields the setting added to the request, as against the same request without it."""
		_, _, body = self.reasoning(name, level, model, **kwargs)
		_, _, plain = sent(name, call=kwargs.get('call', 'complete'), model=model, env=kwargs.get('env'), options=kwargs.get('options'), base=kwargs.get('base'))
		self.assertEqual({k: v for k, v in body.items() if k in plain and body[k] != plain[k]}, {}, 'nothing else changes')
		return {k: v for k, v in body.items() if k not in plain}

	def test_openai_gets_reasoning_effort_only_for_a_model_that_has_it(self):
		self.assertEqual(self.extra('openai', 'low', 'gpt-5.4-nano'), {'reasoning_effort': 'low'})
		self.assertEqual(self.extra('openai', 'medium', 'o3-mini'), {'reasoning_effort': 'medium'})
		self.assertEqual(self.extra('openai', 'high', 'gpt-5'), {'reasoning_effort': 'high'})
		self.assertEqual(self.extra('openai', 'max', 'gpt-5'), {'reasoning_effort': 'high'})  # `xhigh` is not sent (UNVERIFIED which model takes it)
		self.assertEqual(self.extra('openai', 'high', 'gpt-5', call='vision'), {'reasoning_effort': 'high'})
		for model in ('gpt-4o', 'o1-mini', 'gpt-5-chat-latest', 'deepseek-reasoner'):
			self.assertEqual(self.extra('openai', 'high', model), {}, model)
		self.assertEqual(self.extra('openai', 'off', 'gpt-5.4-nano'), {})  # cannot be switched off from here: nothing is sent, and it is logged

	def test_openai_behind_a_proxy_still_follows_the_model_name(self):
		self.assertEqual(self.extra('openai', 'low', 'o3', base='https://proxy.example.test/v1'), {'reasoning_effort': 'low'})
		self.assertEqual(self.extra('openai', 'low', 'llama-3', base='https://proxy.example.test/v1'), {})

	def test_an_adaptive_claude_model_gets_adaptive_thinking_and_an_effort(self):
		for model in ('claude-haiku-5-5', 'claude-sonnet-5-5', 'claude-opus-5-5', 'claude-fable-5-1', 'claude-opus-4-8', 'claude-sonnet-4-6'):
			for level in ('low', 'medium', 'high', 'max'):
				fields = self.extra('anthropic', level, model)
				self.assertEqual(fields, {'thinking': {'type': 'adaptive'}, 'output_config': {'effort': level}}, (model, level))
			_, _, body = self.reasoning('anthropic', 'high', model)
			self.assertEqual(body['max_tokens'], 2048)  # the reply limit is not touched
			for key in self.FORBIDDEN_FOR_ANTHROPIC + ('budget_tokens',):
				self.assertNotIn(key, body)
				self.assertNotIn(key, body['thinking'])
		self.assertEqual(self.extra('anthropic', 'low', 'claude-opus-5-5', call='vision'), {'thinking': {'type': 'adaptive'}, 'output_config': {'effort': 'low'}})

	def test_off_is_sent_only_where_it_is_valid(self):
		self.assertEqual(self.extra('anthropic', 'off', 'claude-haiku-5-5'), {'thinking': {'type': 'disabled'}})
		self.assertEqual(self.extra('anthropic', 'off', 'claude-sonnet-5'), {'thinking': {'type': 'disabled'}})
		self.assertEqual(self.extra('anthropic', 'off', 'claude-opus-5'), {'thinking': {'type': 'disabled'}})
		for model in ('claude-opus-5-5', 'claude-sonnet-5-5', 'claude-fable-5-1', 'claude-fable-5', 'claude-opus-4-8', 'claude-sonnet-4-6',
					  'claude-haiku-4-5', 'claude-3-5-haiku-20241022', 'my-gateway-model'):
			self.assertEqual(self.extra('anthropic', 'off', model), {}, model)  # cannot be disabled, does not think unless asked, or unknown

	def test_a_budget_era_claude_model_gets_a_budget_below_the_reply_limit(self):
		for model in ('claude-haiku-4-5', 'claude-sonnet-4-5-20250929', 'claude-opus-4-1-20250805', 'claude-3-7-sonnet-latest'):
			for limit, level, want in ((None, 'low', 1024), (None, 'max', 1024), ('8000', 'medium', 4096), ('8000', 'max', 6976), ('32768', 'max', 16384),
									   ('2100', 'high', 1076)):
				env = {'CVENGINE_AI_MAX_TOKENS': limit} if limit else {}
				_, _, body = self.reasoning('anthropic', level, model, env=env)
				self.assertEqual(body['thinking'], {'type': 'enabled', 'budget_tokens': want}, (model, limit, level))
				self.assertGreaterEqual(want, 1024)
				self.assertLess(want, body['max_tokens'])
				self.assertNotIn('output_config', body)
				for key in self.FORBIDDEN_FOR_ANTHROPIC:
					self.assertNotIn(key, body)
		# a limit with no room for a 1024 budget and an answer: the setting is ignored, not sent invalid
		self.assertEqual(self.extra('anthropic', 'high', 'claude-haiku-4-5', env={'CVENGINE_AI_MAX_TOKENS': '2000'}), {})
		self.assertEqual(self.extra('anthropic', 'high', 'claude-3-5-haiku-20241022'), {})

	def test_ollama_gets_a_top_level_think_for_a_model_with_the_switch(self):
		self.assertEqual(self.extra('ollama', 'off', 'qwen3:8b'), {'think': False})
		self.assertEqual(self.extra('ollama', 'low', 'deepseek-r1:7b'), {'think': True})
		self.assertEqual(self.extra('ollama', 'max', 'qwen3:8b'), {'think': True})
		self.assertEqual(self.extra('ollama', 'medium', 'gpt-oss:20b'), {'think': 'medium'})  # UNVERIFIED: gpt-oss takes a level, not a boolean
		self.assertEqual(self.extra('ollama', 'off', 'gpt-oss:20b'), {})
		self.assertEqual(self.extra('ollama', 'high', 'llama3.1:8b'), {})
		_, _, body = self.reasoning('ollama', 'off', 'qwen3:8b')
		self.assertNotIn('think', body['options'])
		self.assertEqual(self.extra('ollama', 'off', 'qwen3:8b', call='vision'), {'think': False})
		_, _, with_options = self.reasoning('ollama', 'off', 'qwen3:8b', options=TRIAGE)
		self.assertEqual((with_options['think'], with_options['options']['temperature'], with_options['format']), (False, 0, SCHEMA))

	def test_other_servers_are_told_nothing(self):
		for name in ('vllm', 'lmstudio', 'openrouter'):
			for level in ('off', 'high'):
				self.assertEqual(self.extra(name, level, 'qwen3-32b'), {}, (name, level))

	def test_nothing_is_sent_unless_the_variable_is_set_and_valid(self):
		for name in REPLIES:
			plain = sent(name, model='gpt-5' if name == 'openai' else 'claude-haiku-5-5' if name == 'anthropic' else 'qwen3:8b')
			for value in (None, '', '  ', 'medium-ish', 'on', 'true', 'xhigh'):
				got = sent(name, model='gpt-5' if name == 'openai' else 'claude-haiku-5-5' if name == 'anthropic' else 'qwen3:8b',
						   env={'CVENGINE_AI_REASONING': value} if value is not None else {})
				self.assertEqual(got, plain, (name, value))
		self.assertEqual(ai.reasoning_level(), None)

	def test_the_level_is_case_and_space_insensitive(self):
		with mock.patch.dict('os.environ', {'CVENGINE_AI_REASONING': ' High '}):
			self.assertEqual(ai.reasoning_level(), 'high')

	def test_an_ignored_setting_is_logged_once_per_provider_and_model(self):
		with mock.patch.dict('os.environ', {'CVENGINE_AI_REASONING': 'high'}):
			with self.assertLogs('reNgine.ai_providers', level='WARNING') as logs:
				for _ in range(3):
					sent('openai', model='gpt-4o', env={'CVENGINE_AI_REASONING': 'high'})
				sent('openai', model='gpt-4.1', env={'CVENGINE_AI_REASONING': 'high'})
				sent('vllm', model='qwen3-32b', env={'CVENGINE_AI_REASONING': 'high'})
		self.assertEqual(len(logs.records), 3)
		self.assertIn('CVENGINE_AI_REASONING=high is ignored for openai gpt-4o', logs.output[0])
		self.assertIn('server', logs.output[2])

	def test_the_plan_is_pure_and_names_why_it_sent_nothing(self):
		self.assertEqual(profiles.reasoning_plan('openai', 'gpt-5', None), ({}, ''))
		self.assertEqual(profiles.reasoning_plan('openai', 'gpt-5', 'bogus'), ({}, ''))
		fields, why = profiles.reasoning_plan('anthropic', 'claude-haiku-4-5', 'high', 1500)
		self.assertEqual(fields, {})
		self.assertIn('CVENGINE_AI_MAX_TOKENS', why)
		self.assertEqual(profiles.reasoning_plan('nope', 'x', 'high')[0], {})


class DetectKeyTests(unittest.TestCase):
	def test_only_an_unambiguous_prefix_names_a_provider(self):
		self.assertEqual(ai.detect_provider('sk-ant-api03-' + 'x' * 30), 'anthropic')
		self.assertEqual(ai.detect_provider('sk-or-v1-' + 'x' * 30), 'openrouter')
		self.assertEqual(ai.detect_provider('  sk-proj-' + 'x' * 30), 'openai')
		for key in ('sk-' + 'x' * 48, 'sk-svcacct-' + 'x' * 40, 'sk-admin-' + 'x' * 40, 'AIzaSy' + 'x' * 33, 'sk-short', '', None, 'nope'):
			self.assertIsNone(ai.detect_provider(key), key)

	def test_a_bare_sk_key_is_ambiguous_and_nothing_else_is(self):
		self.assertTrue(ai.ambiguous_key('sk-' + 'x' * 48))
		self.assertTrue(ai.ambiguous_key('sk-svcacct-' + 'x' * 40))
		for key in ('sk-ant-' + 'x' * 30, 'sk-or-' + 'x' * 30, 'sk-proj-' + 'x' * 30, 'AIzaSy' + 'x' * 33, '', None, 'abc'):
			self.assertFalse(ai.ambiguous_key(key), key)


class OnboardingKeyTests(TestCase):
	"""A pasted key goes only where the person chose or its prefix names: a bare sk- key makes no request at all."""
	BARE = 'sk-' + 'a1b2' * 12

	@classmethod
	def setUpTestData(cls):
		cls.root = User.objects.create_superuser('onb-root', 'onb@example.test', 'x')

	def setUp(self):
		from tests.test_tenancy import client_for
		self.c = client_for(self.root)

	def save(self, body):
		return self.c.post('/cve/api/setup/save', json.dumps(body), content_type='application/json')

	def test_detect_says_when_a_key_is_ambiguous(self):
		def detect(key):
			return self.c.post('/cve/api/setup/detect', json.dumps({'key': key}), content_type='application/json').json()
		self.assertEqual(detect(self.BARE), {'provider': None, 'ambiguous': True})
		self.assertEqual(detect('sk-ant-' + 'x' * 30), {'provider': 'anthropic', 'ambiguous': False})
		self.assertEqual(detect('AIzaSy' + 'x' * 33), {'provider': None, 'ambiguous': False})

	def test_a_bare_sk_key_does_not_produce_a_request_to_openai_or_anywhere(self):
		from dashboard.models import AIProviderSettings
		with mock.patch('requests.post') as post, mock.patch('requests.get') as get, mock.patch('requests.Session.request') as session:
			response = self.save({'key': self.BARE})
			self.assertEqual(response.status_code, 400)
			self.assertIn('Pick the provider', response.json()['error'])
			# a connected provider is not a reason to try a new, unrecognised key on it either
			AIProviderSettings.objects.create(provider='anthropic', api_key='sk-ant-old' + 'x' * 20, enabled=True)
			self.assertEqual(self.save({'key': self.BARE}).status_code, 400)
			AIProviderSettings.objects.update(provider='openai')
			self.assertEqual(self.save({'key': self.BARE, 'model': ''}).status_code, 400)
		for call in (post, get, session):
			call.assert_not_called()
		self.assertNotIn(self.BARE, [row.api_key for row in AIProviderSettings.objects.all()])

	def test_a_bare_key_with_the_provider_picked_goes_to_that_provider_only(self):
		with mock.patch('requests.post', return_value=Reply(OPENAI_OK)) as post:
			response = self.save({'key': self.BARE, 'provider': 'openai', 'model': 'gpt-5.4-nano'})
		self.assertEqual(response.status_code, 200, response.content)
		self.assertEqual([c.args[0] for c in post.call_args_list], ['https://api.openai.com/v1/chat/completions'])

	def test_a_prefix_that_names_the_vendor_is_still_enough(self):
		with mock.patch('requests.post', return_value=Reply(ANTHROPIC_OK)) as post:
			response = self.save({'key': 'sk-ant-api03-' + 'x' * 30, 'model': 'claude-haiku-5-5'})
		self.assertEqual(response.status_code, 200, response.content)
		self.assertEqual([c.args[0] for c in post.call_args_list], ['https://api.anthropic.com/v1/messages'])

	def test_no_key_re_checks_the_connected_provider(self):
		from dashboard.models import AIProviderSettings
		AIProviderSettings.objects.create(provider='anthropic', model='claude-haiku-5-5', api_key='stored-key', enabled=True)
		with mock.patch('requests.post', return_value=Reply(ANTHROPIC_OK)) as post:
			self.assertEqual(self.save({'key': ''}).status_code, 200)
		self.assertEqual(post.call_args.kwargs['headers']['x-api-key'], 'stored-key')


class AnthropicBaseUrlTests(unittest.TestCase):
	def setUp(self):
		patcher = clean_env()
		patcher.start()
		self.addCleanup(patcher.stop)

	def test_a_bare_address_or_one_ending_in_v1_is_the_server_and_any_other_path_is_used_as_written(self):
		for base, url in (('https://gw.example.test', 'https://gw.example.test/v1/messages'), ('https://gw.example.test/', 'https://gw.example.test/v1/messages'),
						  ('https://gw.example.test/v1', 'https://gw.example.test/v1/messages'), ('https://gw.example.test/v1/', 'https://gw.example.test/v1/messages'),
						  ('https://gw.example.test/v1/messages', 'https://gw.example.test/v1/messages'),
						  ('https://gw.example.test/anthropic/v1/messages', 'https://gw.example.test/anthropic/v1/messages'),
						  ('https://gw.example.test:4000/proxy/messages', 'https://gw.example.test:4000/proxy/messages'), (None, ai.ANTHROPIC_URL), ('', ai.ANTHROPIC_URL)):
			self.assertEqual(sent('anthropic', base=base)[0] if base else sent('anthropic')[0], url, base)

	def test_the_model_list_comes_from_the_same_server(self):
		for base, url in (('https://gw.example.test', 'https://gw.example.test/v1/models?limit=1000'), ('https://gw.example.test/v1', 'https://gw.example.test/v1/models?limit=1000'),
						  ('https://gw.example.test/v1/messages', 'https://gw.example.test/v1/models?limit=1000'), (None, 'https://api.anthropic.com/v1/models?limit=1000')):
			with mock.patch('requests.get', return_value=Reply({'data': []})) as get:
				provider('anthropic', base=base).list_models()
			self.assertEqual(get.call_args.args[0], url, base)


class SameServiceTests(unittest.TestCase):
	def test_a_change_of_host_is_a_new_service(self):
		same = profiles.same_service
		self.assertTrue(same('openai', '', 'openai', ''))
		self.assertTrue(same('openai', '', 'openai', 'https://api.openai.com/v1'))  # the vendor's own address, written out
		self.assertTrue(same('openai', 'HTTPS://API.OpenAI.com/v1/', 'openai', ''))
		self.assertTrue(same('anthropic', '', 'anthropic', 'https://api.anthropic.com'))
		self.assertTrue(same('anthropic', '', 'anthropic', 'https://api.anthropic.com:443/v1/messages'))
		self.assertTrue(same('vllm', 'http://h:8000/v1', 'vllm', ' http://h:8000/v1/ '))
		self.assertFalse(same('openai', '', 'anthropic', ''))
		self.assertFalse(same('openai', '', 'openai', 'https://evil.example.net/v1'))
		self.assertFalse(same('openai', 'https://evil.example.net/v1', 'openai', ''))
		self.assertFalse(same('openai', '', 'openai', 'https://api.openai.com.evil.example.net/v1'))
		self.assertFalse(same('openai', '', 'openai', 'https://api.openai.com@evil.example.net/v1'))
		self.assertFalse(same('anthropic', '', 'anthropic', 'https://gw.example.test'))
		self.assertFalse(same('vllm', 'http://h:8000/v1', 'vllm', 'http://h:8001/v1'))  # another port is another server
		self.assertFalse(same('vllm', 'http://h:8000/v1', 'vllm', 'https://h:8000/v1'))
		self.assertFalse(same('vllm', 'http://h:8000/v1', 'vllm', 'http://h2:8000/v1'))
		self.assertFalse(same('openai', 'https://gw.example.test/a', 'openai', 'https://gw.example.test/b'))  # one host may front several services
		self.assertFalse(same('ollama', 'http://h:11434', 'ollama', ''))  # a self-hosted server has no vendor address to fall back to


if __name__ == '__main__':
	unittest.main()
