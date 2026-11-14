"""The pipeline's request layer (cvengine_reviewer.llm.complete): the requests the server made itself before 1.4, made from the container.

Run in the reviewer image by CI (.github/workflows/build-pr.yml, job reviewer-image), or locally: ``PYTHONPATH=reviewer python3 -m unittest
discover -s reviewer/tests``. Standard library only; no request leaves the machine (``_http`` is replaced, or a local server answers)."""
import base64
import http.server
import json
import threading
import time
import unittest
from unittest import mock

from cvengine_reviewer import llm

SCHEMA = {'type': 'object', 'additionalProperties': False, 'required': ['classification'],
          'properties': {'classification': {'type': 'string', 'enum': ['likely', 'needs_validation']}}}
TRIAGE = {'temperature': 0, 'seed': 20260101, 'max_tokens': 400, 'retry_truncated': True, 'schema_name': 'triage'}
BASES = {'ollama': 'http://192.0.2.10:11434', 'vllm': 'http://192.0.2.10:8000/v1', 'lmstudio': 'http://192.0.2.10:1234/v1'}
KEYED = ('anthropic', 'openai', 'openrouter')


def block(name, model='m', base=None, **runtime):
    return {'provider': name, 'model': model, 'api_key': 'k' if name in KEYED else '',
            'base_url': BASES.get(name, '') if base is None else base, 'runtime': runtime}


def answer(name, text='{"classification": "likely"}', **extra):
    if name == 'anthropic':
        return {'content': [{'type': 'text', 'text': text}], 'stop_reason': 'end_turn', 'model': 'claude-x',
                'usage': {'input_tokens': 11, 'output_tokens': 7, 'cache_read_input_tokens': 3}, **extra}
    if name == 'ollama':
        return {'message': {'content': text}, 'prompt_eval_count': 11, 'eval_count': 7, **extra}
    return {'choices': [{'message': {'content': text}, 'finish_reason': extra.pop('finish_reason', 'stop')}],
            'usage': {'prompt_tokens': 11, 'completion_tokens': 7}, **extra}


class Recorder:
    """Stands in for ``llm._http``: records each request and answers from a list (an exception in it is raised)."""

    def __init__(self, *replies):
        self.replies, self.requests = list(replies), []

    def __call__(self, name, url, headers, body, timeout, connect_timeout, limit):
        self.requests.append({'url': url, 'headers': headers, 'body': body, 'timeout': timeout, 'connect': connect_timeout})
        reply = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        if isinstance(reply, Exception):
            raise reply
        return reply


def ask(name, *replies, schema=None, options=None, image=None, **kw):
    recorder = Recorder(*(replies or (answer(name),)))
    with mock.patch.object(llm, '_http', recorder):
        result = llm.complete(block(name, **kw), 'system', 'user', schema, options, image)
    return result, recorder.requests


def refused(status, body):
    return llm.ModelError('refused', 'provider_http' if status != 401 else 'provider_auth', http_status=status, hint=body.lower())


class RequestShapeTests(unittest.TestCase):
    def setUp(self):
        llm._STRUCTURED.clear()
        llm._RESOLVED.clear()

    def test_the_default_anthropic_request_is_the_one_the_server_made(self):
        (text, calls, model), sent = ask('anthropic')
        self.assertEqual(sent[0]['url'], 'https://api.anthropic.com/v1/messages')
        self.assertEqual(sent[0]['headers'], {'x-api-key': 'k', 'anthropic-version': '2023-06-01'})
        self.assertEqual(json.dumps(sent[0]['body']),
                         json.dumps({'model': 'm', 'max_tokens': 2048, 'system': 'system', 'messages': [{'role': 'user', 'content': 'user'}]}))
        self.assertEqual((sent[0]['timeout'], sent[0]['connect']), (120, 10))
        self.assertEqual((text, model), ('{"classification": "likely"}', 'm'))
        self.assertEqual((calls[0]['status'], calls[0]['input_tokens'], calls[0]['cache_read_tokens'], calls[0]['actual_model']),
                         ('succeeded', 11, 3, 'claude-x'))

    def test_an_anthropic_base_url_is_read_as_the_server_did(self):
        for base, url in (('https://gw.example.com', 'https://gw.example.com/v1/messages'), ('https://gw.example.com/v1/', 'https://gw.example.com/v1/messages'),
                          ('https://gw.example.com/proxy/messages', 'https://gw.example.com/proxy/messages')):
            self.assertEqual(ask('anthropic', base=base)[1][0]['url'], url, base)

    def test_anthropic_is_never_sent_a_schema_and_keeps_2048_for_a_triage(self):
        body = ask('anthropic', schema=SCHEMA, options=TRIAGE)[1][0]['body']
        self.assertEqual(body['max_tokens'], 2048)
        for key in ('temperature', 'seed', 'output_config', 'response_format'):
            self.assertNotIn(key, body)

    def test_a_triage_on_a_self_hosted_server_is_pinned_capped_and_shaped(self):
        for name in ('vllm', 'lmstudio'):
            body = ask(name, schema=SCHEMA, options=TRIAGE)[1][0]['body']
            self.assertEqual((body['max_tokens'], body['temperature'], body['seed']), (400, 0, 20260101), name)
            self.assertEqual(body['response_format'], {'type': 'json_schema', 'json_schema': {'name': 'triage', 'strict': True, 'schema': SCHEMA}})
        body = ask('ollama', schema=SCHEMA, options=TRIAGE)[1][0]['body']
        self.assertEqual(body['options'], {'num_predict': 400, 'temperature': 0, 'seed': 20260101})
        self.assertEqual((body['format'], body['stream']), (SCHEMA, False))
        self.assertEqual(ask('vllm')[1][0]['body']['max_tokens'], 2048)  # outside a stage with its own limit

    def test_a_hosted_provider_keeps_its_behaviour(self):
        for name in ('openai', 'openrouter'):
            body = ask(name, schema=SCHEMA, options=TRIAGE)[1][0]['body']
            for key in ('max_tokens', 'max_completion_tokens', 'temperature', 'seed', 'response_format'):
                self.assertNotIn(key, body, name)
        self.assertEqual(ask('openrouter')[1][0]['headers']['X-Title'], 'CVEngine')
        body = ask('openrouter', schema=SCHEMA, options=TRIAGE, structured_mode='all')[1][0]['body']
        self.assertEqual((body['response_format']['type'], body['provider']), ('json_schema', {'require_parameters': True}))

    def test_the_limit_goes_under_the_name_the_address_takes(self):
        self.assertEqual(ask('openai', max_tokens=900)[1][0]['body']['max_completion_tokens'], 900)
        proxy = ask('openai', base='https://llm-proxy.example.com/v1', max_tokens=900, schema=SCHEMA, options=TRIAGE)[1][0]['body']
        self.assertEqual(proxy['max_tokens'], 900)
        self.assertNotIn('temperature', proxy)  # a proxy set up as "openai" is not a self-hosted server
        self.assertEqual(ask('vllm', max_tokens=1500, options=TRIAGE)[1][0]['body']['max_tokens'], 1500)  # the setting wins over the stage

    def test_the_settings_shape_the_request(self):
        sent = ask('vllm', request_timeout=600, connect_timeout=45)[1][0]
        self.assertEqual((sent['timeout'], sent['connect']), (600, 45))
        self.assertEqual(ask('lmstudio')[1][0]['timeout'], 300)  # LM Studio may load a model first
        self.assertEqual(ask('vllm', request_timeout=2)[1][0]['timeout'], 120)  # out of range: the default
        body = ask('ollama', context_tokens=8192, keep_alive='-1')[1][0]['body']
        self.assertEqual((body['options'], body['keep_alive']), ({'num_predict': 2048, 'num_ctx': 8192}, -1))
        self.assertEqual(ask('ollama', keep_alive='30m')[1][0]['body']['keep_alive'], '30m')
        self.assertNotIn('response_format', ask('vllm', schema=SCHEMA, structured_mode='off')[1][0]['body'])
        body = ask('anthropic', model='claude-sonnet-4-6', reasoning='low')[1][0]['body']
        self.assertEqual((body['thinking'], body['output_config']), ({'type': 'adaptive'}, {'effort': 'low'}))


class OwnJobsPinTests(unittest.TestCase):
    """The reviewer's own jobs (``llm.call``): the same packet gives the same answer on a self-hosted model (AR-5)."""

    def sent(self, name, **provider):
        replies = {'ollama': {'message': {'content': '{}'}}, 'openai': {'choices': [{'message': {'content': '{}'}, 'finish_reason': 'stop'}]}}
        seen = []

        def post(url, headers, body, timeout):
            seen.append(body)
            return replies.get(name, replies['openai'])
        with mock.patch.object(llm, '_post', post):
            llm.call({'provider': name, 'model': 'm', 'base_url': BASES.get(name, ''), **provider}, 's', 'u', SCHEMA, 300)
        return seen[0]

    def test_a_self_hosted_server_gets_temperature_zero_and_the_fixed_seed(self):
        for name in ('vllm', 'lmstudio'):
            body = self.sent(name)
            self.assertEqual((body['temperature'], body['seed']), (0, 20260101), name)
        self.assertEqual(self.sent('ollama')['options'], {'num_predict': 300, 'temperature': 0, 'seed': 20260101})

    def test_a_hosted_provider_is_sent_neither(self):
        for name in ('openai', 'openrouter'):
            body = self.sent(name, api_key='k')
            self.assertNotIn('temperature', body, name)
            self.assertNotIn('seed', body, name)
        self.assertEqual(llm.pinned('anthropic'), {})
        self.assertEqual(llm.pinned('nothing-known'), {})


class StructuredLadderTests(unittest.TestCase):
    def setUp(self):
        llm._STRUCTURED.clear()

    def test_a_server_that_refuses_the_schema_is_asked_in_json_mode_then_plainly_and_remembers(self):
        refuse = refused(400, '{"error": "unsupported response_format: json_schema"}')
        _, sent = ask('lmstudio', refuse, refuse, answer('lmstudio'), schema=SCHEMA, options=TRIAGE)
        self.assertEqual([r['body'].get('response_format', {}).get('type') for r in sent], ['json_schema', 'json_object', None])
        _, again = ask('lmstudio', schema=SCHEMA, options=TRIAGE)
        self.assertNotIn('response_format', again[0]['body'])

    def test_an_error_that_has_nothing_to_do_with_the_schema_is_not_retried_without_it(self):
        for status, body in ((401, 'bad key'), (429, 'slow down'), (500, 'boom'), (400, 'context length exceeded')):
            with self.assertRaises(llm.ModelError) as raised:
                ask('vllm', refused(status, body), answer('vllm'), schema=SCHEMA, options=TRIAGE)
            self.assertEqual(len(raised.exception.calls), 1, status)
            llm._STRUCTURED.clear()

    def test_an_empty_answer_under_a_schema_is_asked_again_without_it(self):
        _, sent = ask('vllm', answer('vllm', text=''), answer('vllm'), schema=SCHEMA, options=TRIAGE)
        self.assertEqual([r['body'].get('response_format', {}).get('type') for r in sent], ['json_schema', 'json_object'])

    def test_ollama_steps_down_to_plain_json_then_nothing(self):
        refuse = refused(400, '{"error":"invalid format"}')
        _, sent = ask('ollama', refuse, refuse, answer('ollama'), schema=SCHEMA, options=TRIAGE)
        self.assertEqual([r['body'].get('format') for r in sent], [SCHEMA, 'json', None])


class TruncationTests(unittest.TestCase):
    CUT = {'choices': [{'message': {'content': '{"classif'}, 'finish_reason': 'length'}]}

    def test_a_cut_off_reply_is_asked_again_once_with_twice_the_limit(self):
        (_, calls, _), sent = ask('vllm', self.CUT, answer('vllm'), options=TRIAGE)
        self.assertEqual([r['body']['max_tokens'] for r in sent], [400, 800])
        self.assertEqual([c['status'] for c in calls], ['failed', 'succeeded'])
        self.assertEqual(calls[0]['category'], 'output_truncated')

    def test_the_ceiling_and_a_provider_sent_no_limit_are_not_asked_twice(self):
        with self.assertRaises(llm.ModelError) as raised:
            ask('vllm', self.CUT, max_tokens=32768, options=TRIAGE)
        self.assertEqual((raised.exception.category, len(raised.exception.calls)), ('output_truncated', 1))
        with self.assertRaises(llm.ModelError) as raised:
            ask('openai', self.CUT, options=TRIAGE)
        self.assertEqual(len(raised.exception.calls), 1)
        _, sent = ask('vllm', self.CUT, answer('vllm'), max_tokens=20000, options=TRIAGE)
        self.assertEqual([r['body']['max_tokens'] for r in sent], [20000, 32768])

    def test_a_stage_that_opts_out_is_not_retried(self):
        with self.assertRaises(llm.ModelError):
            ask('vllm', self.CUT, answer('vllm'), options={'max_tokens': 400, 'retry_truncated': False})

    def test_every_stage_is_retried_unless_it_opts_out(self):
        (_, calls, _), sent = ask('vllm', self.CUT, answer('vllm'), options={'max_tokens': 400})
        self.assertEqual([r['body']['max_tokens'] for r in sent], [400, 800])

    def test_empty_and_cut_off_replies_have_their_own_categories(self):
        for name, data, category in (('openai', answer('openai', text=' '), 'empty_response'), ('ollama', {'message': {'content': '{'}, 'done_reason': 'length'}, 'output_truncated'),
                                     ('anthropic', {'content': [], 'stop_reason': 'max_tokens'}, 'output_truncated'), ('vllm', {'nope': 1}, 'provider_shape')):
            with self.assertRaises(llm.ModelError) as raised:
                ask(name, data)
            self.assertEqual(raised.exception.category, category, name)


class VisionTests(unittest.TestCase):
    IMAGE = {'media_type': 'image/png', 'data': base64.b64encode(b'\x89PNG').decode()}

    def test_each_transport_carries_the_image_its_own_way(self):
        content = ask('anthropic', image=self.IMAGE)[1][0]['body']['messages'][0]['content']
        self.assertEqual((content[0]['type'], content[0]['source']['data'], content[1]), ('image', self.IMAGE['data'], {'type': 'text', 'text': 'user'}))
        content = ask('lmstudio', image=self.IMAGE)[1][0]['body']['messages'][1]['content']
        self.assertEqual(content[1]['image_url']['url'], 'data:image/png;base64,' + self.IMAGE['data'])
        message = ask('ollama', image=self.IMAGE)[1][0]['body']['messages'][1]
        self.assertEqual(message['images'], [self.IMAGE['data']])


class ModelChoiceTests(unittest.TestCase):
    def setUp(self):
        llm._RESOLVED.clear()

    def test_anthropic_and_openai_pick_the_newest_cheapest_listed_or_fall_back(self):
        listing = {'data': [{'id': 'claude-opus-9', 'created_at': '2026-01-01T00:00:00Z'}, {'id': 'claude-haiku-9', 'created_at': '2026-02-01T00:00:00Z'}]}
        (_, _, model), sent = ask('anthropic', listing, answer('anthropic'), model='')
        self.assertEqual((model, sent[1]['body']['model']), ('claude-haiku-9', 'claude-haiku-9'))
        llm._RESOLVED.clear()
        (_, _, model), _ = ask('openai', llm.ModelError('x', 'provider_http', http_status=500), answer('openai'), model='')
        self.assertEqual(model, 'gpt-5.4-nano')

    def test_a_self_hosted_server_needs_a_choice_unless_it_serves_one(self):
        (_, _, model), _ = ask('vllm', {'data': [{'id': 'qwen'}]}, answer('vllm'), model='')
        self.assertEqual(model, 'qwen')
        with self.assertRaises(llm.ModelError) as raised:
            ask('vllm', {'data': [{'id': 'a'}, {'id': 'b'}]}, model='')
        self.assertEqual((raised.exception.category, len(raised.exception.calls)), ('provider_error', 1))

    def test_a_block_that_cannot_make_a_request_is_refused_before_any(self):
        for bad in ({'provider': 'nope'}, {'provider': 'anthropic', 'api_key': ''}, {'provider': 'vllm', 'base_url': ''},
                    {'provider': 'vllm', 'base_url': 'file:///etc/passwd'}):
            with mock.patch.object(llm, '_http') as http, self.assertRaises(llm.ModelError):
                llm.complete(bad, 's', 'u')
            http.assert_not_called()


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.server.seen.append((self.path, dict(self.headers), body))
        status, payload = self.server.plan.pop(0)
        if status == 'sleep':
            time.sleep(2)
            status, payload = 200, b'{}'
        self.send_response(status)
        self.end_headers()
        self.wfile.write(payload if isinstance(payload, bytes) else json.dumps(payload).encode())


class HttpTests(unittest.TestCase):
    """``_http`` against a server on this machine: what goes out, and how each failure is named."""

    def setUp(self):
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
        self.server.seen, self.server.plan = [], []
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = f'http://127.0.0.1:{self.server.server_address[1]}/v1/chat/completions'

    def post(self, timeout=5):
        with mock.patch.dict('os.environ', {'NO_PROXY': '127.0.0.1', 'no_proxy': '127.0.0.1'}):
            return llm._http('vllm', self.url, {'Authorization': 'Bearer k'}, {'model': 'm'}, timeout, 5, 1000)

    def test_a_json_answer_is_read_and_the_request_carries_the_key_as_a_header_only(self):
        self.server.plan = [(200, {'ok': 1})]
        self.assertEqual(self.post(), {'ok': 1})
        path, headers, body = self.server.seen[0]
        self.assertEqual((path, headers['Authorization'], body), ('/v1/chat/completions', 'Bearer k', {'model': 'm'}))

    def test_each_failure_has_its_category(self):
        self.server.plan = [(401, b'bad key'), (429, b'slow'), (400, b'{"error": "unsupported response_format"}'), (200, b'not json'),
                            (200, b'x' * 2000), ('sleep', None)]
        for category in ('provider_auth', 'provider_rate_limit', 'provider_http', 'provider_json', 'provider_shape'):
            with self.assertRaises(llm.ModelError) as raised:
                self.post()
            self.assertEqual(raised.exception.category, category)
            self.assertNotIn('Bearer', str(raised.exception))
        self.assertEqual(raised.exception.category, 'provider_shape')
        with self.assertRaises(llm.ModelError) as raised:
            self.post(timeout=0.5)
        self.assertEqual(raised.exception.category, 'provider_timeout')

    def test_a_refusal_keeps_the_start_of_its_body_for_the_structured_ladder(self):
        self.server.plan = [(400, b'{"error": "Unsupported response_format"}')]
        with self.assertRaises(llm.ModelError) as raised:
            self.post()
        self.assertEqual((raised.exception.http_status, raised.exception.hint), (400, '{"error": "unsupported response_format"}'))
        self.assertTrue(llm._refused_structure(raised.exception))

    def test_a_server_that_is_not_there_is_a_network_failure(self):
        self.server.shutdown()
        self.server.server_close()
        with self.assertRaises(llm.ModelError) as raised:
            self.post()
        self.assertEqual(raised.exception.category, 'provider_network')


if __name__ == '__main__':
    unittest.main()
