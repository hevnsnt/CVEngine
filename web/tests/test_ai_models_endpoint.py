"""Settings, AI model: the list of models behind the drop-downs (POST /cve/api/settings/ai/models). The saved key is used when none is typed and is
never returned or logged, the address checks are those of saving, the list is cached for a few minutes (a failure for a few seconds) under a
key that holds no secret, it is capped, a failure is told in plain words, and the reviewer's two models still save through the reviewer API."""
import logging
import socket
from unittest import mock

import requests
from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase

from cveFeed import settings_api
from cveFeed.models import ReviewerSettings
from dashboard.models import AIProviderSettings, Org, OrgMembership
from tests.test_settings import send
from tests.test_tenancy import client_for

SAVED_KEY = 'sk-test-saved-key-0001'
TYPED_KEY = 'sk-test-typed-key-0002'


class Reply:
    def __init__(self, data=None, status=200, bad_json=False):
        self._data, self.status_code, self._bad = data, status, bad_json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f'{self.status_code} for url: https://hidden.example.com/v1/models', response=self)

    def json(self):
        if self._bad:
            raise ValueError('not json')
        return self._data


def openai_list(*ids):
    return Reply({'data': [{'id': i, 'created': 1_700_000_000 + n} for n, i in enumerate(ids)]})


class ModelsEndpointTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.root = User.objects.create_superuser('mroot', 'm@x.io', 'x')
        cls.admin = User.objects.create_user('madmin', password='x')
        org = Org.objects.create(name='M', slug='m-org')
        OrgMembership.objects.create(user=cls.admin, org=org, role='admin')

    def setUp(self):
        cache.clear()
        self.c = client_for(self.root)
        lookup = mock.patch('socket.getaddrinfo', side_effect=socket.gaierror)  # the address check resolves the host: no test touches the network
        lookup.start()
        self.addCleanup(lookup.stop)
        self.addCleanup(cache.clear)

    def models(self, **body):
        return send(self.c, 'POST', 'ai/models', body)

    def save_connection(self, provider='openai', base_url='', key=SAVED_KEY):
        AIProviderSettings.objects.all().delete()
        AIProviderSettings.objects.create(provider=provider, base_url=base_url, api_key=key)

    # --- the key ---

    def test_the_saved_key_is_used_when_the_page_sends_none(self):
        self.save_connection()
        with mock.patch('requests.get', return_value=openai_list('gpt-a', 'gpt-b')) as get:
            status, data = self.models(provider='openai')
        self.assertEqual(status, 200)
        self.assertEqual(get.call_args.kwargs['headers'], {'Authorization': f'Bearer {SAVED_KEY}'})
        self.assertEqual([m['id'] for m in data['models']], ['gpt-b', 'gpt-a'])  # newest first, as the provider reports it

    def test_a_typed_key_wins_over_the_saved_one(self):
        self.save_connection()
        with mock.patch('requests.get', return_value=openai_list('gpt-a')) as get:
            self.models(provider='openai', api_key=TYPED_KEY)
        self.assertEqual(get.call_args.kwargs['headers'], {'Authorization': f'Bearer {TYPED_KEY}'})

    def test_the_saved_key_goes_only_to_the_provider_and_address_it_was_saved_for(self):
        self.save_connection(provider='openai', base_url='https://gw.example.com/v1')
        with mock.patch('reNgine.ai_providers.get_provider') as get_provider:
            get_provider.return_value.list_models.return_value = []
            self.models(provider='anthropic')
            self.assertIsNone(get_provider.call_args.kwargs['api_key'])
            self.models(provider='openai', base_url='https://other.example.com/v1')
            self.assertIsNone(get_provider.call_args.kwargs['api_key'])
            self.models(provider='openai')  # the saved address
            self.assertEqual(get_provider.call_args.kwargs['api_key'], SAVED_KEY)

    def test_without_a_key_for_the_address_the_reason_is_said_in_words(self):
        self.save_connection(provider='openai', base_url='https://gw.example.com/v1')
        with mock.patch('requests.get') as get:
            status, data = self.models(provider='openai', base_url='https://other.example.com/v1')
        self.assertEqual(status, 400)
        self.assertIn('no API key for this address', data['error'])
        get.assert_not_called()

    def test_no_answer_holds_the_key_not_the_saved_one_and_not_the_typed_one(self):
        self.save_connection()
        with mock.patch('requests.get', return_value=openai_list('gpt-a')):
            r = self.c.post('/cve/api/settings/ai/models', '{"provider": "openai", "api_key": "%s"}' % TYPED_KEY, content_type='application/json')
            plain = self.c.post('/cve/api/settings/ai/models', '{"provider": "openai"}', content_type='application/json')
        for response in (r, plain):
            self.assertNotIn(SAVED_KEY, response.content.decode())
            self.assertNotIn(TYPED_KEY, response.content.decode())
        got = send(self.c, 'GET', 'ai')[1]
        self.assertNotIn('api_key', got)
        self.assertTrue(got['has_key'])
        self.assertNotIn(SAVED_KEY, str(got))

    def test_a_failure_logs_and_says_nothing_with_the_key_or_the_address(self):
        self.save_connection(base_url='https://hidden.example.com/v1')
        records = []

        class Catch(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())
        handler = Catch(level=logging.DEBUG)
        root = logging.getLogger()
        before = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        self.addCleanup(lambda: (root.removeHandler(handler), root.setLevel(before)))
        for failure in (requests.ConnectionError(f'refused for {SAVED_KEY} at https://hidden.example.com'), Reply(status=401)):
            cache.clear()
            kwargs = {'side_effect': failure} if isinstance(failure, Exception) else {'return_value': failure}
            with mock.patch('requests.get', **kwargs):
                status, data = self.models(provider='openai', api_key=TYPED_KEY)
            self.assertEqual(status, 400)
            self.assertNotIn(SAVED_KEY, str(data))
            self.assertNotIn(TYPED_KEY, str(data))
            self.assertNotIn('hidden.example.com', str(data))
        self.assertFalse([m for m in records if SAVED_KEY in m or TYPED_KEY in m], records)

    # --- the address ---

    def test_a_metadata_address_is_refused_before_anything_is_asked_or_cached(self):
        self.save_connection()
        with mock.patch('requests.get', return_value=openai_list('x')) as get:
            for url in ('http://169.254.169.254/latest', 'http://2852039166/', 'http://metadata.google.internal/', 'http://[fe80::1]/v1'):
                for _ in range(2):  # a second ask is not served from a cache of the first
                    self.assertEqual(self.models(provider='openai', base_url=url)[0], 400, url)
            with mock.patch('socket.getaddrinfo', return_value=[(2, 1, 6, '', ('169.254.169.254', 0))]):
                self.assertEqual(self.models(provider='openai', base_url='http://169.254.169.254.nip.example.test/')[0], 400)
        get.assert_not_called()

    def test_a_refused_address_stays_refused_after_a_good_one_was_cached(self):
        self.save_connection()
        with mock.patch('requests.get', return_value=openai_list('x')):
            status, data = self.models(provider='openai', api_key=TYPED_KEY, base_url='https://gw.example.com/v1')
            self.assertEqual(status, 200, data)
            self.assertEqual(self.models(provider='openai', base_url='http://169.254.169.254/v1')[0], 400)

    def test_an_address_must_be_http_and_a_provider_must_be_known_and_your_own_server_needs_one(self):
        with mock.patch('requests.get') as get:
            self.assertEqual(self.models(provider='openai', base_url='ftp://gw.example.com')[0], 400)
            self.assertEqual(self.models(provider='nonesuch')[0], 400)
            status, data = self.models(provider='ollama')
            self.assertEqual(status, 400)
            self.assertIn('address', data['error'])
        get.assert_not_called()

    # --- the cache ---

    def test_a_second_ask_is_answered_from_the_cache_and_refresh_asks_again(self):
        self.save_connection()
        with mock.patch('requests.get', return_value=openai_list('gpt-a')) as get:
            first = self.models(provider='openai')
            second = self.models(provider='openai')
            self.assertEqual(get.call_count, 1)
            self.assertEqual(first, second)
            self.models(provider='openai', refresh=True)
            self.assertEqual(get.call_count, 2)

    def test_the_cache_is_per_provider_address_and_key(self):
        self.save_connection()
        with mock.patch('requests.get', return_value=openai_list('gpt-a')) as get:
            self.models(provider='openai')
            self.models(provider='openai', api_key=TYPED_KEY)  # another key: another list
            self.models(provider='openai', api_key=TYPED_KEY, base_url='https://gw.example.com/v1')
            self.models(provider='openrouter', api_key=TYPED_KEY)
            self.assertEqual(get.call_count, 4)
            self.models(provider='openai', api_key=TYPED_KEY)
            self.assertEqual(get.call_count, 4)

    def test_the_cache_holds_a_hash_of_the_key_never_the_key(self):
        self.save_connection()
        stored = []
        real = cache.set

        def spy(key, value, *args, **kwargs):
            stored.append((key, value))
            return real(key, value, *args, **kwargs)
        with mock.patch('requests.get', return_value=openai_list('gpt-a')), mock.patch('django.core.cache.cache.set', side_effect=spy):
            self.models(provider='openai')
            self.models(provider='openai', api_key=TYPED_KEY)
        self.assertEqual(len(stored), 2)
        for key, value in stored:
            self.assertTrue(key.startswith('cve:ai-models:'))
            self.assertNotIn(SAVED_KEY, key + str(value))
            self.assertNotIn(TYPED_KEY, key + str(value))
        self.assertNotEqual(stored[0][0], stored[1][0])

    def test_the_lifetimes_are_minutes_for_a_list_and_seconds_for_a_failure(self):
        self.assertEqual(settings_api.MODELS_CACHE_SECONDS, 300)
        self.assertLessEqual(settings_api.MODELS_FAIL_SECONDS, 60)
        self.assertLess(settings_api.MODELS_FAIL_SECONDS, settings_api.MODELS_CACHE_SECONDS)
        self.save_connection()
        ttls = []
        with mock.patch('django.core.cache.cache.set', side_effect=lambda k, v, ttl=None, *a, **kw: ttls.append(ttl)), \
                mock.patch('requests.get', side_effect=[openai_list('a'), requests.ConnectionError('x')]):
            self.models(provider='openai')
            self.models(provider='openai', refresh=True)
        self.assertEqual(ttls, [settings_api.MODELS_CACHE_SECONDS, settings_api.MODELS_FAIL_SECONDS])

    def test_a_failure_is_remembered_briefly_so_a_down_server_is_not_hammered(self):
        self.save_connection()
        with mock.patch('requests.get', side_effect=requests.ConnectionError('refused')) as get:
            first = self.models(provider='openai')
            second = self.models(provider='openai')
            self.assertEqual(get.call_count, 1)
            self.assertEqual(first, second)
            self.assertEqual(first[0], 400)
            self.models(provider='openai', refresh=True)  # the person asked again: ask the server again
            self.assertEqual(get.call_count, 2)
        with mock.patch('requests.get', return_value=openai_list('back')):  # and a good answer after the failure expires is not blocked
            self.assertEqual(self.models(provider='openai', refresh=True)[0], 200)

    def test_a_cache_that_is_down_is_a_miss_not_an_error(self):
        self.save_connection()
        with mock.patch('django.core.cache.cache.get', side_effect=ConnectionError('redis')), \
                mock.patch('django.core.cache.cache.set', side_effect=ConnectionError('redis')), \
                mock.patch('requests.get', return_value=openai_list('gpt-a')):
            self.assertEqual(self.models(provider='openai')[0], 200)

    # --- the list itself ---

    def test_the_list_is_capped_deduplicated_and_cleaned(self):
        self.save_connection()
        ids = [f'model-{n}' for n in range(settings_api.MODELS_MAX + 100)]
        reply = Reply({'data': [{'id': i, 'created': n} for n, i in enumerate(ids)] + [{'id': 'model-3'}, {'id': 'x' * 500}, {'id': ''}, {'nope': 1}, {'id': 7}]})
        with mock.patch('requests.get', return_value=reply):
            status, data = self.models(provider='openai')
        self.assertEqual(status, 200, data)
        self.assertEqual(len(data['models']), settings_api.MODELS_MAX)
        got = [m['id'] for m in data['models']]
        self.assertEqual(len(set(got)), len(got))
        self.assertTrue(all(isinstance(i, str) and 0 < len(i) <= settings_api.MODELS_ID_MAX for i in got))

    def test_a_price_is_a_number_per_million_input_tokens_or_none_and_a_model_is_recommended(self):
        self.save_connection(provider='openrouter')
        reply = Reply({'data': [{'id': 'v/big', 'created': 3, 'pricing': {'prompt': '0.000003'}}, {'id': 'v/mini', 'created': 2, 'pricing': {'prompt': '0.0000008'}},
                                {'id': 'v/odd', 'created': 1, 'pricing': {'prompt': 'free'}}]})
        with mock.patch('requests.get', return_value=reply):
            data = self.models(provider='openrouter')[1]
        prices = {m['id']: m['price'] for m in data['models']}
        self.assertAlmostEqual(prices['v/big'], 3.0)
        self.assertAlmostEqual(prices['v/mini'], 0.8)
        self.assertIsNone(prices['v/odd'])
        self.assertEqual(data['recommended'], '')  # OpenRouter needs a pick: nothing is recommended for it

    def test_anthropic_lists_models_and_recommends_the_newest_cheapest(self):
        self.save_connection(provider='anthropic')
        reply = Reply({'data': [{'id': 'claude-sonnet-5-5', 'created_at': '2026-02-01T00:00:00Z'}, {'id': 'claude-haiku-5-5', 'created_at': '2026-03-01T00:00:00Z'},
                                {'id': 'claude-haiku-4-5', 'created_at': '2025-10-01T00:00:00Z'}]})
        with mock.patch('requests.get', return_value=reply) as get:
            data = self.models(provider='anthropic')[1]
        self.assertEqual(get.call_args.kwargs['headers'].get('x-api-key'), SAVED_KEY)
        self.assertEqual(data['recommended'], 'claude-haiku-5-5')
        self.assertEqual(len(data['models']), 3)

    def test_a_failure_is_told_in_plain_words_by_kind_and_never_in_the_provider_s_own(self):
        self.save_connection()
        cases = [
            (Reply(status=401), 'key was refused'), (Reply(status=403), 'key was refused'), (Reply(status=429), 'rate limiting'),
            (Reply(status=500), 'error'), (Reply(bad_json=True), 'not with a list of models'),
            (requests.ConnectionError('refused'), 'nothing answered'), (requests.ReadTimeout('slow'), 'in time'), (requests.ConnectTimeout('slow'), 'connection'),
        ]
        for failure, words in cases:
            cache.clear()
            kwargs = {'side_effect': failure} if isinstance(failure, Exception) else {'return_value': failure}
            with mock.patch('requests.get', **kwargs):
                status, data = self.models(provider='openai')
            self.assertEqual(status, 400, words)
            self.assertIn(words, data['error'], (words, data))
            self.assertNotIn('hidden.example.com', data['error'])

    def test_an_answer_that_is_not_a_list_of_models_is_a_plain_failure_not_a_server_error(self):
        self.save_connection()
        with mock.patch('requests.get', return_value=Reply(['not', 'a', 'dict'])):
            status, data = self.models(provider='openai')
        self.assertEqual(status, 400)
        self.assertIn('not with a list of models', data['error'])

    # --- who may ask ---

    def test_only_a_superuser_may_ask(self):
        with mock.patch('requests.get') as get:
            self.assertEqual(send(client_for(self.admin), 'POST', 'ai/models', {'provider': 'openai'})[0], 403)
            from django.test import Client
            self.assertIn(send(Client(), 'POST', 'ai/models', {'provider': 'openai'})[0], (302, 403))  # signed out: the login redirect or a refusal, never a list
        get.assert_not_called()

    def test_the_answer_to_the_page_says_which_providers_need_an_address(self):
        data = send(self.c, 'GET', 'ai')[1]
        self.assertEqual(sorted(data['needs_url']), ['lmstudio', 'ollama', 'vllm'])


class ReviewerModelsStillSaveThroughTheReviewerApiTests(TestCase):
    """The reviewer's two model boxes moved into the table on the AI page; the reviewer API they save through is unchanged."""

    @classmethod
    def setUpTestData(cls):
        cls.root = User.objects.create_superuser('rroot', 'r@x.io', 'x')

    def setUp(self):
        self.c = client_for(self.root)
        AIProviderSettings.objects.create(provider='openai', model='gpt-default', api_key='k', enabled=True)

    def test_the_page_saves_only_the_models_and_the_other_reviewer_settings_stay(self):
        send(self.c, 'PUT', 'reviewer', {'enabled': True, 'auto_close': True, 'review_daily_max': 77, 'ops_hours': [5, 17]})
        status, data = send(self.c, 'PUT', 'reviewer', {'review_model': 'gpt-big', 'ops_model': ''})
        self.assertEqual(status, 200)
        self.assertEqual((data['review_model'], data['ops_model']), ('gpt-big', ''))
        self.assertEqual((data['enabled'], data['auto_close'], data['review_daily_max'], data['ops_hours']), (True, True, 77, [5, 17]))
        self.assertEqual(data['models_in_force'], {'review': 'gpt-big', 'ops': 'gpt-default'})  # empty follows the default model on another provider
        row = ReviewerSettings.objects.get()
        self.assertEqual((row.review_model, row.ops_model), ('gpt-big', ''))

    def test_a_model_the_provider_did_not_list_is_kept_as_typed_and_a_bad_name_is_refused(self):
        self.assertEqual(send(self.c, 'PUT', 'reviewer', {'review_model': 'org/my-tuned:7b@q4'})[1]['review_model'], 'org/my-tuned:7b@q4')
        self.assertEqual(send(self.c, 'PUT', 'reviewer', {'ops_model': 'bad name; rm'})[0], 400)

    def test_on_anthropic_an_empty_model_is_the_built_in_one_which_the_page_says_so(self):
        AIProviderSettings.objects.all().update(provider='anthropic')
        data = send(self.c, 'GET', 'reviewer')[1]
        self.assertEqual(data['default_models'], {'review': 'claude-sonnet-5-5', 'ops': 'claude-haiku-5-5'})
        self.assertEqual(data['models_in_force'], {'review': 'claude-sonnet-5-5', 'ops': 'claude-haiku-5-5'})
