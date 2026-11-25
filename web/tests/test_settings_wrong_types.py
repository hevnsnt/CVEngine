"""Settings and administration writes with a value of the wrong JSON type answer 400, not 500 (N3b fuzz run).

A list or an object where text was expected (an AI provider, an email security mode, a membership scope or role), a value that is not an
object for an API key entry, and a HackerOne credential with characters HTTP basic auth cannot carry each raised TypeError,
AttributeError or UnicodeEncodeError inside the handler.
"""
import json
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase

from cveFeed import bounty_submit
from tests.test_tenancy import client_for

WRONG = ([], ['x'], {}, {'a': 1})


class WrongTypeTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		cls.boss = User.objects.create_superuser('wt-boss', 'wt@example.com', 'x')

	def setUp(self):
		self.client = client_for(self.boss)
		self.client.raise_request_exception = False

	def _send(self, method, url, body):
		r = getattr(self.client, method)(url, json.dumps(body), content_type='application/json')
		return r.status_code, r.content.decode()

	def test_settings_with_a_list_or_object_for_text_are_a_400(self):
		cases = [('put', '/cve/api/settings/ai', 'provider'), ('post', '/cve/api/settings/ai/models', 'provider'),
		         ('put', '/cve/api/settings/email', 'security')]
		for method, url, key in cases:
			for bad in WRONG:
				with self.subTest(url=url, key=key, value=bad):
					status, text = self._send(method, url, {key: bad})
					self.assertEqual(status, 400, text)

	def test_an_api_key_entry_that_is_not_an_object_is_a_400(self):
		for bad in ('x', 1, True, 1.5, [1]):
			with self.subTest(value=bad):
				status, text = self._send('put', '/cve/api/settings/keys', {'chaos': bad})
				self.assertEqual(status, 400, text)
		status, text = self._send('put', '/cve/api/settings/keys', {'chaos': {'key': 'abc'}})
		self.assertEqual(status, 200, text)

	def test_a_membership_scope_or_role_that_is_not_text_is_a_400(self):
		for key in ('scope', 'role'):
			for bad in WRONG:
				with self.subTest(key=key, value=bad):
					body = {'username': 'wt-new', 'email': 'wt-new@example.com', 'scope': 'org', 'role': 'user', key: bad}
					status, text = self._send('post', '/cve/api/admin/users', body)
					self.assertEqual(status, 400, text)
		self.assertFalse(User.objects.filter(username='wt-new').exists())


class HackerOneCredentialTests(SimpleTestCase):
	def test_a_credential_that_is_not_ascii_is_refused_before_anything_is_sent(self):
		never = mock.Mock(side_effect=AssertionError('nothing may be sent'))
		for username, token in (('me', '\u202eabc'), ('me', '\uff45\uff58'), ('m\u00e9\u2603', 'tok')):
			with self.subTest(username=username, token=token):
				out = bounty_submit.verify_hackerone(username, token, get=never)
				self.assertIs(out['verified'], False)
				with self.assertRaises(bounty_submit.SubmitError) as caught:
					bounty_submit.submit_hackerone({}, username, token, post=never)
				self.assertIn('Nothing was sent', caught.exception.message)
		never.assert_not_called()

	def test_an_ascii_credential_is_still_checked(self):
		get = mock.Mock(return_value=mock.Mock(status_code=200))
		self.assertIs(bounty_submit.verify_hackerone('me', 'tok', get=get)['verified'], True)
		get.assert_called_once()
