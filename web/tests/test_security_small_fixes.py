"""Three small hardening fixes from the r3 security review (S6, S7, S10). Each test here failed on develop before its fix.

S6: the Django cache signs what it pickles, so a value written straight into Redis is never unpickled.
S7: every response that sets no policy of its own also carries a report-only script policy that allows this site and the import map.
S10: a session ends after 12 hours without a request, and each request starts the 12 hours again."""
import base64
import datetime
import hashlib
import pickle
import re

from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.sessions.models import Session
from django.core.cache import cache
from django.test import Client, TestCase
from django.utils import timezone

from cvengine.hashed_sessions import db_key

RAN = []


def _record(what):
	RAN.append(what)
	return what


class Planted:
	"""What someone with write access to Redis would store: unpickling it calls _record."""

	def __reduce__(self):
		return (_record, ('code ran',))


def _raw_client():
	return cache._cache.get_client(None, write=True)


class SignedCacheTests(TestCase):
	"""S6: Redis write access must not be code execution in web, celery or beat."""

	def setUp(self):
		cache.clear()
		RAN.clear()

	def test_a_plain_pickle_planted_in_redis_is_never_unpickled(self):
		_raw_client().set(cache.make_key('planted'), pickle.dumps(Planted()))
		self.assertIsNone(cache.get('planted'))
		self.assertEqual(cache.get_many(['planted']), {'planted': None})
		self.assertEqual(RAN, [])  # on develop the read ran the planted call and returned 'code ran'

	def test_a_signed_value_that_was_altered_is_ignored(self):
		cache.set('kept', {'a': 1})
		key = cache.make_key('kept')
		stored = _raw_client().get(key)
		_raw_client().set(key, stored[:-1] + bytes([stored[-1] ^ 1]))
		self.assertIsNone(cache.get('kept'))

	def test_values_read_back_as_written(self):
		now = timezone.now()
		for value in ({'ids': [1, 2], 'at': now}, 'text', ['a', ('b', 2)], {1, 2}, 2.5, True, b'raw', None):
			cache.set('v', value)
			self.assertEqual(cache.get('v', 'missing'), value)
		cache.set_many({'m1': 'one', 'm2': {'two': 2}})
		self.assertEqual(cache.get_many(['m1', 'm2']), {'m1': 'one', 'm2': {'two': 2}})

	def test_stored_values_are_signed_and_ints_stay_plain_for_incr(self):
		cache.set('obj', {'a': 1})
		self.assertTrue(_raw_client().get(cache.make_key('obj')).startswith(b'cvs1'))
		cache.set('n', 5)
		self.assertEqual(_raw_client().get(cache.make_key('n')), b'5')  # what incr, decr and the raw TTL reads rely on
		self.assertEqual(cache.incr('n'), 6)
		self.assertEqual(cache.get('n'), 6)

	def test_a_different_secret_reads_nothing(self):
		cache.set('s', 'value')
		with self.settings(SECRET_KEY='another-installation-' + 'x' * 40):
			self.assertIsNone(cache.get('s'))

	def test_the_cache_is_configured_with_the_signed_serializer(self):
		conf = settings.CACHES['default']
		self.assertEqual(conf['OPTIONS']['serializer'], 'cvengine.cache_serializer.SignedRedisSerializer')
		self.assertEqual(conf['VERSION'], 2)  # apart from the unsigned values of earlier releases


class ScriptPolicyReportOnlyTests(TestCase):
	"""S7: the enforced policy had no script-src; a report-only one shows what an enforced one would block."""

	def setUp(self):
		cache.clear()

	def test_a_page_carries_the_report_only_script_policy_with_the_import_map_hash(self):
		from cveFeed.templatetags.assets import importmap
		response = Client().get('/login/')
		policy = response['Content-Security-Policy-Report-Only']
		self.assertIn("script-src 'self' 'sha256-", policy)
		self.assertIn("style-src 'self' 'unsafe-inline'", policy)
		for directive in ("base-uri 'self'", "object-src 'none'", "frame-ancestors 'none'", "form-action 'self'"):
			self.assertIn(directive, policy)
		body = re.fullmatch(r'<script type="importmap">(.*)</script>', importmap(), re.S).group(1)  # the exact text the pages inline
		digest = base64.b64encode(hashlib.sha256(body.encode('utf-8')).digest()).decode('ascii')
		self.assertIn(f"'sha256-{digest}'", policy)

	def test_the_enforced_policy_is_unchanged(self):
		response = Client().get('/login/')
		self.assertEqual(response['Content-Security-Policy'], "base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'")

	def test_a_response_with_its_own_policy_gets_no_report_only_header(self):
		from cvengine.middleware import ContentSecurityPolicyMiddleware
		from django.http import HttpRequest, HttpResponse

		def own(request):
			response = HttpResponse('x')
			response['Content-Security-Policy'] = "default-src 'none'; sandbox"
			return response
		response = ContentSecurityPolicyMiddleware(own)(HttpRequest())
		self.assertEqual(response['Content-Security-Policy'], "default-src 'none'; sandbox")
		self.assertNotIn('Content-Security-Policy-Report-Only', response)


class SessionIdleTimeoutTests(TestCase):
	"""S10: sessions lasted 14 days from sign-in with no idle timeout."""

	def setUp(self):
		cache.clear()
		self.user = User.objects.create_user('idle', password='right-pw-1')

	def session_row(self, client):
		return Session.objects.get(session_key=db_key(client.session.session_key))

	def test_a_sign_in_lasts_twelve_hours(self):
		client = Client()
		response = client.post('/login/', {'username': 'idle', 'password': 'right-pw-1'})
		self.assertEqual(response.cookies[settings.SESSION_COOKIE_NAME]['max-age'], 12 * 60 * 60)
		left = self.session_row(client).expire_date - timezone.now()
		self.assertTrue(datetime.timedelta(hours=11, minutes=59) < left <= datetime.timedelta(hours=12), left)

	def test_each_request_starts_the_twelve_hours_again(self):
		client = Client()
		client.force_login(self.user)
		Session.objects.filter(session_key=db_key(client.session.session_key)).update(expire_date=timezone.now() + datetime.timedelta(hours=1))
		response = client.get('/cve/api/alive')  # any answer but a 500 saves the session (this user has no project, so it is a 403)
		left = self.session_row(client).expire_date - timezone.now()
		self.assertGreater(left, datetime.timedelta(hours=11, minutes=59))  # on develop it stayed at the hour it had left
		self.assertEqual(response.cookies[settings.SESSION_COOKIE_NAME]['max-age'], 12 * 60 * 60)

	def test_a_session_idle_past_its_age_is_signed_out(self):
		client = Client()
		client.force_login(self.user)
		Session.objects.filter(session_key=db_key(client.session.session_key)).update(expire_date=timezone.now() - datetime.timedelta(seconds=1))
		response = client.get('/cve/')
		self.assertEqual(response.status_code, 302)
		self.assertIn('/login/', response['Location'])
