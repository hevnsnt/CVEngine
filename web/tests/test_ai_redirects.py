"""AI provider requests do not follow a redirect to an address the server will not call (a typed URL passes the address check, its Location
header did not). A local 302 server stands in for a hostile or misconfigured gateway; nothing leaves this machine."""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

from django.test import SimpleTestCase

from reNgine import ai_providers as ai

SEEN = []


def serve(location=None, body=b'{"data": [{"id": "gpt-x", "created": 1}]}'):
    class Handler(BaseHTTPRequestHandler):
        def _go(self):
            SEEN.append((self.command, self.path, self.headers.get('Authorization')))
            if location:
                self.send_response(302)
                self.send_header('Location', location)
                self.send_header('Content-Length', '0')
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        do_GET = do_POST = _go

        def log_message(self, *args):
            pass

    server = HTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class RedirectGuardTests(SimpleTestCase):
    def setUp(self):
        SEEN.clear()

    def start(self, **kw):
        server = serve(**kw)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f'http://127.0.0.1:{server.server_port}'

    def provider(self, base):
        return ai.OpenAIProvider(model='gpt-x', api_key='sk-test-key', base_url=base)

    def test_redirect_to_the_metadata_address_is_not_followed(self):
        base = self.start(location='http://169.254.169.254/latest/meta-data/')
        with self.assertRaises(ai.AIProviderError) as ctx:
            self.provider(base).list_models()
        self.assertEqual(ctx.exception.category, 'provider_redirect')
        self.assertIn('redirected to an address this server will not call', str(ctx.exception))
        self.assertEqual(len(SEEN), 1)  # only the typed address was asked

    def test_redirect_to_a_private_address_is_not_followed(self):
        for target in ('http://10.0.0.5:8080/v1/models', 'http://192.168.1.9/x', 'http://[::1]:9/x'):
            base = self.start(location=target)
            with self.assertRaises(ai.AIProviderError, msg=target) as ctx:
                self.provider(base).list_models()
            self.assertEqual(ctx.exception.category, 'provider_redirect')

    def test_unparseable_or_non_http_targets_are_refused(self):
        for target in ('file:///etc/passwd', 'http://[bad/', 'http://host:notaport/x', 'gopher://x/'):
            base = self.start(location=target)
            with self.assertRaises(ai.AIProviderError, msg=target) as ctx:
                self.provider(base).list_models()
            self.assertEqual(ctx.exception.category, 'provider_redirect', target)

    def test_chat_post_is_guarded_too(self):
        base = self.start(location='http://169.254.169.254/latest/')
        with self.assertRaises(ai.AIProviderError) as ctx:
            self.provider(base)._post(f'{base}/chat/completions', {'Authorization': 'Bearer k'}, {'a': 1})
        self.assertEqual(ctx.exception.category, 'provider_redirect')
        self.assertEqual(len(SEEN), 1)

    def test_a_loop_stops_after_three_hops(self):
        base = self.start()
        with mock.patch('requests.get') as get:
            get.return_value = mock.Mock(status_code=302, headers={'Location': base + '/again'})
            with self.assertRaises(ai.AIProviderError) as ctx:
                ai.guarded_request('get', base + '/models')
        self.assertEqual(ctx.exception.category, 'provider_redirect')
        self.assertEqual(get.call_count, ai.MAX_REDIRECTS + 1)

    def test_a_gateway_that_answers_directly_still_works(self):
        base = self.start()
        models = self.provider(base).list_models()
        self.assertEqual([m['id'] for m in models], ['gpt-x'])
        self.assertEqual(SEEN[0][2], 'Bearer sk-test-key')

    def test_a_same_host_redirect_is_followed(self):
        base = self.start()
        with mock.patch('requests.get') as get:
            get.side_effect = [mock.Mock(status_code=301, headers={'Location': '/v1/models'}),
                               mock.Mock(status_code=200, headers={})]
            resp = ai.guarded_request('get', base + '/models', headers={'Authorization': 'Bearer k'})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(get.call_args.args[0], base + '/v1/models')
        self.assertEqual(get.call_args.kwargs['headers'], {'Authorization': 'Bearer k'})
        self.assertIs(get.call_args.kwargs['allow_redirects'], False)

    def test_a_cross_host_public_redirect_drops_the_key(self):
        with mock.patch('requests.get') as get, mock.patch('socket.getaddrinfo', return_value=[(2, 1, 6, '', ('93.184.216.34', 0))]):
            get.side_effect = [mock.Mock(status_code=302, headers={'Location': 'https://cdn.example.com/models'}),
                               mock.Mock(status_code=200, headers={})]
            ai.guarded_request('get', 'https://api.example.com/models', headers={'Authorization': 'Bearer k'})
        self.assertEqual(get.call_args.kwargs['headers'], {})
