"""The AI settings an operator can change on the Settings page (timeouts, reply limit, context window, structured output, reasoning,
keep-alive): what each one does to the request of each provider, that the page wins over the environment and the environment over the
provider's default, that an empty or out-of-range value follows the next layer, and that an install that sets none sends what it always did."""
import unittest
from types import SimpleNamespace
from unittest import mock

from reNgine import ai_providers as ai
from reNgine import ai_profiles as profiles
from reNgine.ai_profiles import AIRuntime

OPENAI_OK = {'choices': [{'message': {'content': 'ok'}, 'finish_reason': 'stop'}]}
ANTHROPIC_OK = {'content': [{'type': 'text', 'text': 'ok'}], 'stop_reason': 'end_turn'}
OLLAMA_OK = {'message': {'content': 'ok'}}
REPLIES = {'anthropic': ANTHROPIC_OK, 'openai': OPENAI_OK, 'openrouter': OPENAI_OK, 'ollama': OLLAMA_OK, 'vllm': OPENAI_OK, 'lmstudio': OPENAI_OK}
BASES = {'ollama': 'http://h:11434', 'vllm': 'http://h:8000/v1', 'lmstudio': 'http://h:1234/v1'}
ENV_NAMES = ('CVENGINE_AI_TIMEOUT', 'CVENGINE_AI_CONNECT_TIMEOUT', 'CVENGINE_AI_MAX_TOKENS', 'CVENGINE_AI_STRUCTURED', 'CVENGINE_AI_REASONING',
	'CVENGINE_OLLAMA_NUM_CTX')


class Reply:
	def __init__(self, data):
		self._data = data

	def raise_for_status(self):
		pass

	def json(self):
		return self._data


def row(**values):
	"""What a settings row holds (the columns the runtime reads), everything else empty."""
	return SimpleNamespace(**{'request_timeout': None, 'connect_timeout': None, 'max_tokens': None, 'context_tokens': None,
		'structured_mode': '', 'reasoning': '', 'keep_alive': '', **values})


def send(name, runtime=None, env=None, model='m', options=None, triage=False):
	"""(timeout, json body) of the request a provider makes with ``runtime`` and the environment ``env`` (every AI variable cleared first)."""
	environment = {**{k: '' for k in ENV_NAMES}, **(env or {})}
	with mock.patch.dict('os.environ', environment), mock.patch('requests.post', return_value=Reply(REPLIES[name])) as post:
		p = ai.get_provider(name, model=model, api_key='k' if name in ('anthropic', 'openai', 'openrouter') else None,
			base_url=BASES.get(name), runtime=runtime)
		with ai.request_options(**(options or {})):
			p.complete('s', 'u')
	return post.call_args[1]['timeout'], post.call_args[1]['json']


def limit(body):
	return body.get('max_tokens') or body.get('max_completion_tokens') or (body.get('options') or {}).get('num_predict')


class RuntimeValuesTests(unittest.TestCase):
	def test_an_empty_row_is_an_empty_runtime(self):
		self.assertEqual(AIRuntime.from_row(row()), AIRuntime())
		self.assertEqual(AIRuntime.from_row(SimpleNamespace()), AIRuntime())  # an object without the columns (an old row) reads the same

	def test_every_value_is_read_back_and_a_bad_one_is_dropped(self):
		good = AIRuntime.from_row(row(request_timeout=600, connect_timeout=30, max_tokens=4096, context_tokens=16384, structured_mode='off',
			reasoning='low', keep_alive='30m'))
		self.assertEqual((good.request_timeout, good.connect_timeout, good.max_tokens, good.context_tokens, good.structured_mode, good.reasoning,
			good.keep_alive), (600, 30, 4096, 16384, 'off', 'low', '30m'))
		bad = AIRuntime.from_row(row(request_timeout=5, connect_timeout=301, max_tokens=63, context_tokens=511, structured_mode='sometimes',
			reasoning='loud', keep_alive='soon; rm'))
		self.assertEqual(bad, AIRuntime())  # a row edited by hand cannot send what a provider would refuse
		self.assertEqual(AIRuntime.from_row(row(max_tokens=32769)), AIRuntime())
		self.assertEqual(AIRuntime.from_row(row(request_timeout=True)), AIRuntime())

	def test_every_documented_range_is_inclusive(self):
		for name, (low, high, _env, _unit) in profiles.NUMBER_SETTINGS.items():
			self.assertEqual(profiles.clean_number(name, low), low)
			self.assertEqual(profiles.clean_number(name, str(high)), high)
			self.assertIsNone(profiles.clean_number(name, low - 1))
			self.assertIsNone(profiles.clean_number(name, high + 1))
			self.assertIsNone(profiles.clean_number(name, ''))
			self.assertIsNone(profiles.clean_number(name, 'x'))

	def test_keep_alive_accepts_what_ollama_does(self):
		for value in ('5m', '1h', '90s', '0', '-1', '24h'):
			self.assertTrue(profiles.KEEP_ALIVE_PATTERN.match(value), value)
		for value in ('', 'forever', '-2', '1d', '5 m', '5m\n{"x":1}', '123456s'):
			self.assertFalse(profiles.KEEP_ALIVE_PATTERN.match(value), repr(value))

	def test_a_setting_applies_to_the_providers_that_send_it(self):
		self.assertEqual([p for p in profiles.PROFILES if profiles.setting_applies('context_tokens', p)], ['ollama'])
		self.assertEqual([p for p in profiles.PROFILES if profiles.setting_applies('keep_alive', p)], ['ollama'])
		for name in ('request_timeout', 'connect_timeout', 'max_tokens', 'structured_mode', 'reasoning'):
			self.assertTrue(all(profiles.setting_applies(name, p) for p in profiles.PROFILES), name)


class NothingSetTests(unittest.TestCase):
	def test_a_provider_with_no_runtime_sends_what_it_always_did(self):
		for name in REPLIES:
			self.assertEqual(send(name), send(name, runtime=AIRuntime()), name)
			self.assertEqual(send(name), send(name, runtime=AIRuntime.from_row(row())), name)
		self.assertEqual(send('anthropic')[0], (10, 120))
		self.assertEqual(limit(send('anthropic')[1]), 2048)
		self.assertIsNone(limit(send('openai')[1]))
		self.assertEqual(send('lmstudio')[0], (10, 300))
		self.assertEqual(send('ollama')[1]['options'], {'num_predict': 2048})
		self.assertNotIn('keep_alive', send('ollama')[1])


class TimeoutSettingTests(unittest.TestCase):
	def test_the_request_timeout_is_the_page_then_the_environment_then_the_provider(self):
		for name in REPLIES:
			default = ai.PROVIDERS[name].timeout
			self.assertEqual(send(name)[0], (10, default), name)
			self.assertEqual(send(name, env={'CVENGINE_AI_TIMEOUT': '200'})[0], (10, 200), name)
			self.assertEqual(send(name, AIRuntime(request_timeout=900), env={'CVENGINE_AI_TIMEOUT': '200'})[0], (10, 900), name)
			self.assertEqual(send(name, AIRuntime(request_timeout=900))[0], (10, 900), name)

	def test_the_connect_timeout_is_the_page_then_the_environment_then_ten_seconds(self):
		for name in ('anthropic', 'vllm'):
			default = ai.PROVIDERS[name].timeout
			self.assertEqual(send(name, env={'CVENGINE_AI_CONNECT_TIMEOUT': '40'})[0], (40, default))
			self.assertEqual(send(name, AIRuntime(connect_timeout=5), env={'CVENGINE_AI_CONNECT_TIMEOUT': '40'})[0], (5, default))
			self.assertEqual(send(name, AIRuntime(connect_timeout=5, request_timeout=70))[0], (5, 70))

	def test_a_value_outside_its_range_follows_the_next_layer(self):
		self.assertEqual(send('vllm', AIRuntime(request_timeout=3), env={'CVENGINE_AI_TIMEOUT': '200'})[0], (10, 200))
		self.assertEqual(send('vllm', AIRuntime(connect_timeout=999))[0], (10, 120))

	def test_the_model_list_is_not_given_the_answer_timeout(self):
		with mock.patch('requests.get', return_value=Reply({'data': []})) as get:
			ai.get_provider('vllm', base_url='http://h:8000/v1', runtime=AIRuntime(request_timeout=900)).list_models()
		self.assertEqual(get.call_args[1]['timeout'], 30)


class ReplyLimitSettingTests(unittest.TestCase):
	def test_the_limit_reaches_every_provider_under_the_name_it_uses(self):
		runtime = AIRuntime(max_tokens=4096)
		self.assertEqual(send('anthropic', runtime)[1]['max_tokens'], 4096)
		self.assertEqual(send('openrouter', runtime)[1]['max_tokens'], 4096)
		self.assertEqual(send('vllm', runtime)[1]['max_tokens'], 4096)
		self.assertEqual(send('lmstudio', runtime)[1]['max_tokens'], 4096)
		self.assertEqual(send('ollama', runtime)[1]['options']['num_predict'], 4096)
		self.assertEqual(send('openai', runtime)[1]['max_completion_tokens'], 4096)  # OpenAI's own address names it that

	def test_the_page_wins_over_the_environment_which_wins_over_the_default(self):
		self.assertEqual(limit(send('anthropic', AIRuntime(max_tokens=3000), env={'CVENGINE_AI_MAX_TOKENS': '5000'})[1]), 3000)
		self.assertEqual(limit(send('anthropic', env={'CVENGINE_AI_MAX_TOKENS': '5000'})[1]), 5000)
		self.assertEqual(limit(send('anthropic')[1]), 2048)
		self.assertEqual(limit(send('openai', env={'CVENGINE_AI_MAX_TOKENS': '5000'})[1]), 5000)

	def test_it_replaces_a_stage_limit_as_the_environment_always_did(self):
		triage = {'max_tokens': 400}
		self.assertEqual(limit(send('vllm', options=triage)[1]), 400)
		self.assertEqual(limit(send('vllm', AIRuntime(max_tokens=1500), options=triage)[1]), 1500)

	def test_a_retry_after_a_cut_off_reply_asks_for_more_than_the_setting(self):
		self.assertEqual(limit(send('vllm', AIRuntime(max_tokens=1000), options={'token_factor': 2})[1]), 2000)

	def test_a_value_out_of_range_is_not_sent(self):
		self.assertEqual(limit(send('anthropic', AIRuntime(max_tokens=10))[1]), 2048)
		self.assertIsNone(limit(send('openai', AIRuntime(max_tokens=99999))[1]))


class ContextSettingTests(unittest.TestCase):
	def test_ollama_is_asked_for_the_window_the_page_names(self):
		self.assertEqual(send('ollama', AIRuntime(context_tokens=16384))[1]['options'], {'num_predict': 2048, 'num_ctx': 16384})
		self.assertEqual(send('ollama', AIRuntime(context_tokens=16384), env={'CVENGINE_OLLAMA_NUM_CTX': '8192'})[1]['options']['num_ctx'], 16384)
		self.assertEqual(send('ollama', env={'CVENGINE_OLLAMA_NUM_CTX': '8192'})[1]['options']['num_ctx'], 8192)

	def test_no_other_provider_is_sent_it(self):
		for name in ('anthropic', 'openai', 'openrouter', 'vllm', 'lmstudio'):
			self.assertEqual(send(name, AIRuntime(context_tokens=16384)), send(name), name)

	def test_a_prompt_that_nearly_fills_the_page_s_window_is_reported(self):
		with mock.patch('requests.post', return_value=Reply({'message': {'content': 'ok'}, 'prompt_eval_count': 4000})), \
				mock.patch.object(ai.logger, 'disabled', False), self.assertLogs('reNgine.ai_providers', level='WARNING') as logs:
			ai.get_provider('ollama', model='m', base_url='http://h:11434', runtime=AIRuntime(context_tokens=4096)).complete('s', 'u')
		self.assertIn('4000 prompt tokens of a 4096 token context window', logs.output[0])


class KeepAliveSettingTests(unittest.TestCase):
	def test_ollama_is_told_how_long_to_keep_the_model(self):
		for value in ('30m', '0', '-1', '1h'):
			self.assertEqual(send('ollama', AIRuntime(keep_alive=value))[1]['keep_alive'], value)

	def test_it_is_a_top_level_field_and_leaves_the_options_alone(self):
		body = send('ollama', AIRuntime(keep_alive='30m', max_tokens=900))[1]
		self.assertEqual(body['options'], {'num_predict': 900})
		self.assertEqual(body['keep_alive'], '30m')

	def test_the_vision_request_carries_it_too(self):
		with mock.patch('requests.post', return_value=Reply(OLLAMA_OK)) as post:
			ai.get_provider('ollama', model='m', base_url='http://h:11434', runtime=AIRuntime(keep_alive='10m')).complete_vision('s', 'u', b'\x89PNG')
		self.assertEqual(post.call_args[1]['json']['keep_alive'], '10m')

	def test_no_other_provider_is_sent_it(self):
		for name in ('anthropic', 'openai', 'openrouter', 'vllm', 'lmstudio'):
			self.assertEqual(send(name, AIRuntime(keep_alive='30m')), send(name), name)


class StructuredSettingTests(unittest.TestCase):
	def setUp(self):
		ai._STRUCTURED.clear()
		self.addCleanup(ai._STRUCTURED.clear)

	def asked(self, name, runtime=None, env=None):
		reply = Reply(REPLIES[name] if name != 'ollama' else {'message': {'content': TRIAGE_OK}})
		if name in ('openai', 'openrouter', 'vllm', 'lmstudio'):
			reply = Reply({'choices': [{'message': {'content': TRIAGE_OK}, 'finish_reason': 'stop'}]})
		elif name == 'anthropic':
			reply = Reply({'content': [{'type': 'text', 'text': TRIAGE_OK}], 'stop_reason': 'end_turn'})
		with mock.patch.dict('os.environ', {**{k: '' for k in ENV_NAMES}, **(env or {})}), mock.patch('requests.post', return_value=reply) as post:
			p = ai.get_provider(name, model='m', api_key='k' if name in ('anthropic', 'openai', 'openrouter') else None, base_url=BASES.get(name), runtime=runtime)
			ai.triage_finding(p, 'cve_match', {'product': 'nginx'})
		return post.call_args[1]['json']

	def test_a_self_hosted_server_is_sent_a_schema_unless_the_page_turns_it_off(self):
		self.assertEqual(self.asked('vllm')['response_format']['type'], 'json_schema')
		self.assertNotIn('response_format', self.asked('vllm', AIRuntime(structured_mode='off')))
		self.assertNotIn('response_format', self.asked('vllm', AIRuntime(structured_mode='off'), env={'CVENGINE_AI_STRUCTURED': 'all'}))
		self.assertIn('format', self.asked('ollama'))
		self.assertNotIn('format', self.asked('ollama', AIRuntime(structured_mode='off')))

	def test_a_hosted_provider_is_sent_one_only_when_the_page_says_all(self):
		for name in ('openai', 'openrouter'):
			self.assertNotIn('response_format', self.asked(name), name)
			self.assertEqual(self.asked(name, AIRuntime(structured_mode='all'))['response_format']['type'], 'json_schema', name)
			self.assertNotIn('response_format', self.asked(name, AIRuntime(structured_mode='auto'), env={'CVENGINE_AI_STRUCTURED': 'all'}), name)  # the page wins
			self.assertEqual(self.asked(name, env={'CVENGINE_AI_STRUCTURED': 'all'})['response_format']['type'], 'json_schema', name)

	def test_anthropic_is_never_sent_a_schema(self):
		body = self.asked('anthropic', AIRuntime(structured_mode='all'))
		self.assertEqual(set(body), set(self.asked('anthropic')))  # the prompt carries a random nonce: compare the fields
		self.assertEqual(set(body), {'model', 'max_tokens', 'system', 'messages'})


class ReasoningSettingTests(unittest.TestCase):
	def setUp(self):
		ai._REASONING_NOTED.clear()

	def test_the_page_sets_the_level_the_way_the_provider_takes_it(self):
		self.assertEqual(send('openai', AIRuntime(reasoning='low'), model='gpt-5.4-nano')[1]['reasoning_effort'], 'low')
		self.assertEqual(send('anthropic', AIRuntime(reasoning='high'), model='claude-sonnet-4-6')[1]['output_config'], {'effort': 'high'})
		self.assertIs(send('ollama', AIRuntime(reasoning='off'), model='qwen3:8b')[1]['think'], False)

	def test_the_page_wins_over_the_environment(self):
		env = {'CVENGINE_AI_REASONING': 'high'}
		self.assertEqual(send('openai', env=env, model='gpt-5')[1]['reasoning_effort'], 'high')
		self.assertEqual(send('openai', AIRuntime(reasoning='low'), env=env, model='gpt-5')[1]['reasoning_effort'], 'low')

	def test_default_sends_nothing_even_when_the_environment_asks(self):
		env = {'CVENGINE_AI_REASONING': 'high'}
		self.assertNotIn('reasoning_effort', send('openai', AIRuntime(reasoning='default'), env=env, model='gpt-5')[1])
		self.assertEqual(send('openai', AIRuntime(reasoning='default'), env=env, model='gpt-5'), send('openai', model='gpt-5'))

	def test_a_model_without_the_control_is_left_alone_and_the_log_names_the_setting(self):
		with mock.patch.object(ai.logger, 'disabled', False), self.assertLogs('reNgine.ai_providers', level='WARNING') as logs:
			self.assertEqual(send('openai', AIRuntime(reasoning='low'), model='gpt-4o'), send('openai', model='gpt-4o'))
		self.assertIn('the reasoning setting (low) is ignored for openai gpt-4o', logs.output[0])

	def test_the_budget_of_an_older_claude_model_follows_the_page_s_reply_limit(self):
		body = send('anthropic', AIRuntime(reasoning='low', max_tokens=4096), model='claude-sonnet-4-5')[1]
		self.assertEqual(body['thinking'], {'type': 'enabled', 'budget_tokens': 1024})
		self.assertEqual(body['max_tokens'], 4096)


TRIAGE_OK = ('{"classification": "needs_validation", "reason": "r", "impact": "i", "severity_adjust": 0, "severity_reason": "", '
	'"remediation": "p", "validation_steps": []}')


class EffectiveSettingsTests(unittest.TestCase):
	def effective(self, name='anthropic', runtime=None, env=None, model='m'):
		with mock.patch.dict('os.environ', {**{k: '' for k in ENV_NAMES}, **(env or {})}):
			return ai.effective_settings(name, model, runtime)

	def test_each_value_says_where_it_comes_from(self):
		out = self.effective(runtime=AIRuntime(request_timeout=900, max_tokens=4000), env={'CVENGINE_AI_MAX_TOKENS': '3000', 'CVENGINE_AI_CONNECT_TIMEOUT': '20'})
		self.assertEqual((out['request_timeout']['value'], out['request_timeout']['source']), (900, 'setting'))
		self.assertEqual((out['max_tokens']['value'], out['max_tokens']['source']), (4000, 'setting'))
		self.assertEqual((out['connect_timeout']['value'], out['connect_timeout']['source']), (20, 'env'))

	def test_the_defaults_are_the_providers(self):
		out = self.effective('anthropic')
		self.assertEqual((out['request_timeout']['value'], out['connect_timeout']['value'], out['max_tokens']['value']), (120, 10, 2048))
		self.assertEqual({v['source'] for k, v in out.items() if k in ('request_timeout', 'connect_timeout', 'max_tokens')}, {'default'})
		self.assertEqual(self.effective('lmstudio')['request_timeout']['value'], 300)
		self.assertIsNone(self.effective('openai')['max_tokens']['value'])  # none is sent
		self.assertIn('400 for a finding triage', self.effective('vllm')['max_tokens']['note'])
		self.assertEqual(self.effective('vllm', runtime=AIRuntime(max_tokens=900))['max_tokens']['note'], '')

	def test_only_ollama_has_a_context_window_and_keep_alive(self):
		for name in profiles.PROFILES:
			out = self.effective(name, AIRuntime(context_tokens=4096, keep_alive='5m'))
			self.assertEqual((out['context_tokens']['applies'], out['keep_alive']['applies']), (name == 'ollama',) * 2, name)

	def test_structured_output_says_whether_a_schema_goes_out(self):
		self.assertIn('is sent', self.effective('vllm')['structured_mode']['note'])
		self.assertIn('no schema', self.effective('openai')['structured_mode']['note'])
		self.assertIn('is sent', self.effective('openai', AIRuntime(structured_mode='all'))['structured_mode']['note'])
		self.assertIn('no schema', self.effective('vllm', AIRuntime(structured_mode='off'))['structured_mode']['note'])
		self.assertIn('no schema', self.effective('anthropic', AIRuntime(structured_mode='all'))['structured_mode']['note'])
		self.assertEqual(self.effective('ollama', env={'CVENGINE_AI_STRUCTURED': 'off'})['structured_mode']['source'], 'env')

	def test_reasoning_says_whether_this_model_takes_it(self):
		self.assertIsNone(self.effective('openai')['reasoning']['value'])
		out = self.effective('openai', AIRuntime(reasoning='low'), model='gpt-4o')['reasoning']
		self.assertEqual((out['value'], out['source']), ('low', 'setting'))
		self.assertIn('no reasoning control', out['note'])
		self.assertEqual(self.effective('openai', AIRuntime(reasoning='low'), model='gpt-5')['reasoning']['note'], 'applied to this model')
		self.assertIsNone(self.effective('openai', AIRuntime(reasoning='default'), env={'CVENGINE_AI_REASONING': 'high'})['reasoning']['value'])
		self.assertEqual(self.effective('openai', env={'CVENGINE_AI_REASONING': 'high'}, model='gpt-5')['reasoning']['source'], 'env')

	# the provider_defaults table is what the page's hints read
	def test_the_defaults_table_matches_what_a_request_gets(self):
		for name in profiles.PROFILES:
			d = ai.provider_defaults(name)
			self.assertEqual(d['request_timeout'], send(name)[0][1], name)
			self.assertEqual(d['max_tokens'], limit(send(name)[1]), name)
			self.assertEqual(d['triage_max_tokens'], 400 if name in ('ollama', 'vllm', 'lmstudio') else None, name)


if __name__ == '__main__':
	unittest.main()
