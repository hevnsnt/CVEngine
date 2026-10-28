"""Provider attempt ledger, cost coverage, and protected usage settings."""
import json
from datetime import date
from unittest import mock
import requests

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from cveFeed.ai_usage import snapshot
from cveFeed.models import AIUsage
from dashboard.models import AIProviderSettings, Project
from reNgine import ai_providers as ai
from tests.test_tenancy import client_for


class FakeResp:
    def __init__(self, body):
        self.body = body

    def raise_for_status(self):
        return None

    def json(self):
        return self.body


class UsageTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.root = User.objects.create_superuser('usage-root', 'usage@example.test', 'x')
        cls.viewer = User.objects.create_user('usage-viewer', password='x')

    def setUp(self):
        self.client = client_for(self.root)
        # Standalone provider unittest cases share the keepdb database and can log
        # attempts outside Django's per-TestCase rollback.
        AIUsage.objects.all().delete()
        AIProviderSettings.objects.create(provider='anthropic', model='claude-test', api_key='secret-marker', enabled=True)

    def test_anthropic_success_and_error_attempts_without_secrets(self):
        body = {'model': 'claude-test-actual', 'content': [{'type': 'text', 'text': 'ok'}],
                'usage': {'input_tokens': 110, 'output_tokens': 20, 'cache_read_input_tokens': 10}}
        provider = ai.get_provider('anthropic', api_key='secret-marker', model='claude-test')
        with mock.patch('requests.post', return_value=FakeResp(body)):
            with ai.usage_stage('finding_triage'):
                self.assertEqual(provider.complete('private prompt', 'private target'), 'ok')
        with mock.patch('requests.post', return_value=FakeResp({'model': 'claude-test-actual', 'content': []})):
            with self.assertRaises(ai.AIProviderError):
                provider.complete('private prompt', 'private target')
        rows = list(AIUsage.objects.order_by('id'))
        self.assertEqual([r.status for r in rows], ['succeeded', 'failed'])
        self.assertEqual((rows[0].actual_model, rows[0].stage, rows[0].input_tokens, rows[0].cache_read_tokens),
                         ('claude-test-actual', 'finding_triage', 110, 10))
        self.assertEqual(rows[1].error_category, 'empty_response')
        self.assertNotIn('secret-marker', json.dumps(snapshot(), default=str))
        self.assertNotIn('private prompt', json.dumps(snapshot(), default=str))
        self.assertNotIn('private target', json.dumps(snapshot(), default=str))

    def test_network_failure_is_counted_and_malformed_reply_is_not_exposed(self):
        provider = ai.get_provider('openai', api_key='secret-marker', model='test-model')
        with mock.patch('requests.post', side_effect=requests.ConnectionError('secret-marker private target')):
            with self.assertRaises(ai.AIProviderError):
                provider.complete('system', 'private target')
        with mock.patch('requests.post', return_value=FakeResp({'private': 'private target'})):
            with self.assertRaises(ai.AIProviderError) as failure:
                provider.complete('system', 'private target')
        self.assertEqual(failure.exception.category, 'provider_shape')
        self.assertNotIn('private target', str(failure.exception))
        rows = list(AIUsage.objects.order_by('id'))
        self.assertEqual([row.error_category for row in rows], ['provider_network', 'provider_shape'])
        self.assertNotIn('secret-marker', json.dumps(snapshot(), default=str))

    def test_verification_is_not_inferred_from_an_old_or_different_connection(self):
        cfg = AIProviderSettings.objects.get()
        AIUsage.objects.create(provider='anthropic', model='claude-test', status='succeeded',
                               input_tokens=1, output_tokens=1)
        self.assertEqual(snapshot()['health'], 'responding')
        self.assertIsNone(snapshot()['verified_at'])
        cfg.verified_at = timezone.now()
        cfg.verified_provider, cfg.verified_model = cfg.provider, cfg.model
        cfg.save()
        self.assertEqual(snapshot()['health'], 'responding')
        cfg.model = 'other-model'
        cfg.save()
        self.assertEqual(snapshot()['health'], 'no_recent_activity')

    def test_unknown_price_then_exact_model_cost_and_partial_usage(self):
        AIUsage.objects.create(provider='anthropic', model='claude-test', actual_model='claude-actual',
                               status='succeeded', input_tokens=1000000, output_tokens=1000000)
        self.assertEqual(snapshot()['unknown_cost_attempts'], 1)
        self.assertIsNone(snapshot()['known_estimated_usd'])
        self.assertEqual(snapshot()['observed_model'], 'claude-actual')
        url = '/cve/api/settings/ai/usage/rate'
        rate = {'provider': 'anthropic', 'model': 'claude-actual', 'input_per_million_usd': '2',
                'output_per_million_usd': '4', 'source_url': 'https://example.test/pricing', 'as_of': date.today().isoformat()}
        response = self.client.put(url, json.dumps(rate), content_type='application/json')
        self.assertEqual(response.status_code, 200, response.content)
        result = snapshot()
        self.assertEqual((result['known_estimated_usd'], result['unknown_cost_attempts']), ('6.000000', 0))
        AIUsage.objects.create(provider='anthropic', model='claude-test', actual_model='claude-actual',
                               status='failed', error_category='provider_timeout')
        result = snapshot()
        self.assertEqual((result['attempts'], result['errors'], result['unknown_cost_attempts'], result['priced_attempts']), (2, 1, 1, 1))
        self.assertEqual(result['known_estimated_usd'], '6.000000')
        AIUsage.objects.create(provider='anthropic', model='claude-test', actual_model='different-model',
                               status='succeeded', input_tokens=5, output_tokens=5)
        self.assertEqual(snapshot()['unknown_cost_attempts'], 2)

    def test_rate_validation_and_access(self):
        path = '/cve/api/settings/ai/usage'
        self.assertEqual(client_for(self.viewer).get(path).status_code, 403)
        self.assertEqual(self.client.get(path + '?days=365').status_code, 400)
        self.assertEqual(self.client.get(path).status_code, 200)
        rate_path = path + '/rate'
        bad = {'provider': 'anthropic', 'model': 'claude-test', 'input_per_million_usd': 'NaN',
               'output_per_million_usd': '1', 'source_url': 'https://example.test/pricing', 'as_of': date.today().isoformat()}
        self.assertEqual(self.client.put(rate_path, json.dumps(bad), content_type='application/json').status_code, 400)
        bad['input_per_million_usd'] = '1'
        bad['source_url'] = 'http://example.test/pricing'
        self.assertEqual(self.client.put(rate_path, json.dumps(bad), content_type='application/json').status_code, 400)
        self.assertEqual(client_for(self.viewer).put(rate_path, json.dumps(bad), content_type='application/json').status_code, 403)

    def test_connected_menu_and_verification_change(self):
        Project.objects.create(name='Sample Project', slug='sample-project', insert_date=timezone.now())
        response = self.client.get('/cve/setup/')
        self.assertContains(response, 'AI Model Usage')
        self.assertContains(response, 'id="ai-usage"')
        self.assertContains(response, '/cve/settings/#keys')
        cfg = AIProviderSettings.objects.get()
        cfg.verified_at, cfg.verified_provider, cfg.verified_model = timezone.now(), cfg.provider, cfg.model
        cfg.save()
        response = self.client.put('/cve/api/settings/ai', json.dumps({'model': 'claude-other'}), content_type='application/json')
        self.assertEqual(response.status_code, 200)
        cfg.refresh_from_db()
        self.assertIsNone(cfg.verified_at)
        cfg.enabled = False
        cfg.save()
        self.assertContains(self.client.get('/cve/setup/'), 'Connect AI model')

    def test_connected_model_change_reuses_only_the_same_provider_key(self):
        with mock.patch.object(ai.AnthropicProvider, 'complete', return_value='ok') as complete:
            response = self.client.post('/cve/api/setup/save', json.dumps({'provider': 'anthropic',
                'model': 'claude-new', 'key': ''}), content_type='application/json')
        self.assertEqual(response.status_code, 200, response.content)
        complete.assert_called_once()
        cfg = AIProviderSettings.objects.get()
        self.assertEqual((cfg.api_key, cfg.model, cfg.verified_model),
                         ('secret-marker', 'claude-new', 'claude-new'))
        with mock.patch.object(ai.OpenAIProvider, 'complete') as other:
            response = self.client.post('/cve/api/setup/save', json.dumps({'provider': 'openai',
                'model': 'openai-new', 'key': ''}), content_type='application/json')
        self.assertEqual(response.status_code, 400)
        other.assert_not_called()
