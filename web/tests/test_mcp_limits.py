"""Small fixtures for aggregate MCP bounds; no scanner or provider calls."""
import json
from unittest import mock

from django.test import RequestFactory, SimpleTestCase

from agentapi import mcp


class McpLimitsTests(SimpleTestCase):
    def request(self, payload):
        request = RequestFactory().post('/mcp/', json.dumps(payload), content_type='application/json')
        request.user = object()
        return request

    def test_oversized_body_is_rejected_before_read_or_dispatch(self):
        request = self.request({'jsonrpc': '2.0', 'id': 1, 'method': 'ping'})
        request.META['CONTENT_LENGTH'] = str(mcp.MAX_BODY_BYTES + 1)
        with mock.patch.object(request, 'read', side_effect=AssertionError('body was read')), \
                mock.patch.object(mcp, 'handle_message') as dispatch:
            response = mcp.endpoint(request)
        self.assertEqual(response.status_code, 413)
        dispatch.assert_not_called()

    def test_actual_body_size_is_checked_even_with_missing_length(self):
        request = self.request({})
        request.META.pop('CONTENT_LENGTH', None)
        request._body = b' ' * (mcp.MAX_BODY_BYTES + 1)
        with mock.patch.object(mcp, 'handle_message') as dispatch:
            response = mcp.endpoint(request)
        self.assertEqual(response.status_code, 413)
        dispatch.assert_not_called()

    def test_oversized_batch_is_rejected_before_any_write_dispatch(self):
        message = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                   'params': {'name': 'start_scan', 'arguments': {'project': 'dummy', 'target_id': 1}}}
        with mock.patch.object(mcp, 'handle_message') as dispatch:
            response = mcp.endpoint(self.request([message] * (mcp.MAX_BATCH_ITEMS + 1)))
        self.assertEqual(response.status_code, 413)
        dispatch.assert_not_called()

    def test_maximum_catalog_batch_fits_response_budget(self):
        messages = [{'jsonrpc': '2.0', 'id': i, 'method': 'tools/list'} for i in range(mcp.MAX_BATCH_ITEMS)]
        response = mcp.endpoint(self.request(messages))
        self.assertEqual(response.status_code, 200)
        self.assertLessEqual(len(response.content), mcp.MAX_RESPONSE_BYTES)
        results = json.loads(response.content)
        self.assertEqual(len(results), mcp.MAX_BATCH_ITEMS)
        self.assertTrue(all('tools' in result['result'] for result in results))

    def test_notifications_have_no_response_in_single_or_batch_requests(self):
        notification = {'jsonrpc': '2.0', 'method': 'notifications/initialized'}
        for payload in (notification, [notification] * mcp.MAX_BATCH_ITEMS):
            response = mcp.endpoint(self.request(payload))
            self.assertEqual((response.status_code, response.content), (202, b''))
        response = mcp.endpoint(self.request([notification, {'jsonrpc': '2.0', 'id': 7, 'method': 'ping'}]))
        self.assertEqual(json.loads(response.content), [{'jsonrpc': '2.0', 'id': 7, 'result': {}}])

    def test_oversized_results_become_bounded_errors_without_redispatch(self):
        payload = [{'jsonrpc': '2.0', 'id': i, 'method': 'ping'} for i in range(2)]
        responses = [{'jsonrpc': '2.0', 'id': i, 'result': 'x' * 3000} for i in range(2)]
        with mock.patch.object(mcp, 'MAX_RESPONSE_BYTES', 4096), \
                mock.patch.object(mcp, 'handle_message', side_effect=responses) as dispatch:
            response = mcp.endpoint(self.request(payload))
        self.assertEqual(dispatch.call_count, 2)
        self.assertLessEqual(len(response.content), 4096)
        results = json.loads(response.content)
        self.assertEqual([r['id'] for r in results], [0, 1])
        self.assertTrue(all(r['error']['code'] == -32001 for r in results))
        self.assertTrue(all('may have completed' in r['error']['message'] for r in results))

    def test_giant_id_does_not_amplify_response_limit_error(self):
        response = {'jsonrpc': '2.0', 'id': 'x' * 2000, 'result': {}}
        result = json.loads(mcp._bounded_result(response, 1024))
        self.assertIsNone(result['id'])
        self.assertEqual(result['error']['code'], -32001)

    def test_bounded_encoder_preserves_unicode_json(self):
        original = {'description': 'Caf\u00e9 \u2603'}
        self.assertEqual(json.loads(mcp._encode_bounded(original, 100)), original)
        self.assertIsNone(mcp._encode_bounded(original, 2))

    def test_malformed_message_does_not_abort_valid_batch_sibling(self):
        messages = [{'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': ['bad']},
                    {'jsonrpc': '2.0', 'id': 2, 'method': 'ping'}]
        results = json.loads(mcp.endpoint(self.request(messages)).content)
        self.assertEqual(results[0]['error']['code'], -32602)
        self.assertEqual(results[1]['result'], {})

    def test_invalid_tool_arguments_do_not_dispatch(self):
        with mock.patch.object(mcp, 'call_tool') as dispatch:
            response = mcp.endpoint(self.request({'jsonrpc': '2.0', 'id': 1,
                'method': 'tools/call', 'params': {'name': [], 'arguments': []}}))
        self.assertEqual(json.loads(response.content)['error']['code'], -32602)
        dispatch.assert_not_called()

    def test_invalid_unicode_and_excessive_nesting_return_parse_error(self):
        for body in (b'\xff', b'[' * 2000 + b']' * 2000):
            request = self.request({})
            request._body = body
            response = mcp.endpoint(request)
            self.assertEqual(json.loads(response.content)['error']['code'], -32700)

    def test_empty_batch_is_invalid_request(self):
        response = mcp.endpoint(self.request([]))
        self.assertEqual(json.loads(response.content)['error']['code'], -32600)
