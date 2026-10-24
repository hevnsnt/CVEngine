"""The retired CMS tool must never execute a URL from a request."""
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase

from tests.test_tenancy import client_for


class LegacyCMSSecurityTests(TestCase):
    def test_arbitrary_url_does_not_reach_shell_or_network(self):
        admin = User.objects.create_superuser('cms-security-admin', 'cms-security@example.test', 'x')
        client = client_for(admin)
        with mock.patch('api.views.run_command') as command, mock.patch('os.system') as shell:
            response = client.get('/api/tools/cms_detector/', {'url': 'https://outside.example/'})
        self.assertEqual(response.status_code, 410, response.content)
        self.assertIn('project-scoped scan', response.json()['message'])
        command.assert_not_called()
        shell.assert_not_called()

    def test_legacy_helper_cannot_be_invoked_directly(self):
        from reNgine.common_func import get_cms_details
        with mock.patch('os.system') as shell:
            with self.assertRaises(RuntimeError):
                get_cms_details('https://outside.example/;touch /tmp/unsafe')
        shell.assert_not_called()
