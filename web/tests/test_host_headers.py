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
