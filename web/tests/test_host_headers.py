from django.conf import settings
from django.test import TestCase, override_settings


class HostHeaderTests(TestCase):
    def test_default_site_host_is_bounded(self):
        self.assertNotIn('*', settings.ALLOWED_HOSTS)
        self.assertIn('localhost', settings.ALLOWED_HOSTS)
        self.assertIn('127.0.0.1', settings.ALLOWED_HOSTS)

    @override_settings(ALLOWED_HOSTS=['scanner.example.test', 'localhost', '127.0.0.1'])
    def test_unexpected_host_is_rejected_before_page_render(self):
        self.assertEqual(self.client.get('/login/', HTTP_HOST='scanner.example.test').status_code, 200)
        self.assertEqual(self.client.get('/login/', HTTP_HOST='unexpected.example.test').status_code, 400)

    def test_production_session_cookies_are_secure(self):
        if not settings.DEBUG:
            self.assertTrue(settings.SESSION_COOKIE_SECURE)
            self.assertTrue(settings.CSRF_COOKIE_SECURE)

    @override_settings(SECURE_HSTS_SECONDS=3600)
    def test_short_hsts_only_on_secure_proxy_requests(self):
        secure = self.client.get('/login/', HTTP_X_FORWARDED_PROTO='https')
        self.assertEqual(secure.status_code, 200)
        self.assertEqual(secure.headers.get('Strict-Transport-Security'), 'max-age=3600')
        self.assertNotIn('includeSubDomains', secure.headers['Strict-Transport-Security'])
        plain = self.client.get('/login/')
        self.assertEqual(plain.status_code, 200)
        self.assertNotIn('Strict-Transport-Security', plain.headers)


class ComposeServiceHostTests(TestCase):
    """The built-in scanner and the AI reviewer reach the server as http://web:8000; ``web`` is a trusted host only while one of them is on."""

    def allowed_hosts(self, **env):
        import json
        import os
        import subprocess
        import sys
        environ = {k: v for k, v in os.environ.items() if k not in ('CVENGINE_REVIEWER', 'CVENGINE_BUILTIN_SCANNER')}
        environ.update(env)
        out = subprocess.run([sys.executable, '-c', 'import json, django; django.setup(); from django.conf import settings; '
                              'print(json.dumps(settings.ALLOWED_HOSTS))'],
                             env=environ, cwd=settings.BASE_DIR, capture_output=True, text=True, timeout=120, check=True)
        return json.loads(out.stdout.strip().splitlines()[-1])

    def test_web_is_trusted_while_the_reviewer_is_on_which_is_the_default(self):
        self.assertIn('web', self.allowed_hosts())

    def test_web_is_not_trusted_when_the_reviewer_and_the_scanner_are_off(self):
        self.assertNotIn('web', self.allowed_hosts(CVENGINE_REVIEWER='0'))

    def test_web_is_trusted_for_the_built_in_scanner_alone(self):
        self.assertIn('web', self.allowed_hosts(CVENGINE_REVIEWER='0', CVENGINE_BUILTIN_SCANNER='1'))
