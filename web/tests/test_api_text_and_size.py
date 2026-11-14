"""Free text sent to the API is cleaned once at the door, and an oversized JSON body is refused (review 2 F3 and F6)."""
import json
from unittest import mock

from django.http import JsonResponse
from django.test import RequestFactory, SimpleTestCase

from agentapi import mcp, rest
from reNgine import input_guard


class CleanedAtTheDoorTests(SimpleTestCase):
    def test_a_rest_body_loses_nul_bytes_and_lone_surrogates(self):
        request = RequestFactory().post('/api/v1/x', data=json.dumps({'text': 'a\u0000b\ud800c', 'nested': {'k\u0000': ['x\ud800']}}), content_type='application/json')
        data = rest._body(request)
        self.assertEqual(data['text'], 'ab\ufffdc')
        self.assertEqual(data['nested'], {'k': ['x\ufffd']})
        data['text'].encode('utf-8')  # the encoder that raised before

    def test_an_mcp_tool_receives_cleaned_arguments(self):
        seen = {}

        def handler(ctx, args):
            seen.update(args)
            return {}
        tool = ('probe', 'x', {'type': 'object', 'properties': {'text': {'type': 'string'}}}, handler, False)
        with mock.patch.dict(mcp.BY_NAME, {'probe': tool}):
            mcp.call_tool(object(), 'probe', {'text': 'a\u0000b\ud800'})
        self.assertEqual(seen['text'], 'ab\ufffd')


class OversizeTests(SimpleTestCase):
    def middleware(self, request):
        return input_guard.InputGuardMiddleware(lambda r: JsonResponse({'ok': True}))(request)

    def post(self, path, size, content_type='application/json'):
        request = RequestFactory().post(path, data='{}', content_type=content_type)
        request.META['CONTENT_LENGTH'] = str(size)
        return request

    def test_a_json_body_over_the_limit_sent_to_the_api_or_the_mcp_is_refused(self):
        for path in ('/api/v1/projects/p/targets', '/mcp/'):
            response = self.middleware(self.post(path, input_guard.MAX_BODY + 1))
            self.assertEqual(response.status_code, 413, path)

    def test_a_body_at_the_limit_other_content_and_the_machine_routes_pass(self):
        self.assertEqual(self.middleware(self.post('/api/v1/projects/p/targets', input_guard.MAX_BODY)).status_code, 200)
        self.assertEqual(self.middleware(self.post('/api/v1/projects/p/targets', input_guard.MAX_BODY + 1, 'text/plain')).status_code, 200)
        self.assertEqual(self.middleware(self.post('/cve/settings/data', input_guard.MAX_BODY + 1)).status_code, 200)  # not an API path
