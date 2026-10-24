import datetime
import json
import logging

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import sensitive as sv
from cveFeed.models import AgentActivity, AssetChange, RouteAuth, ServiceRun
from dashboard.models import ProjectMembership
from startScan.models import Subdomain
from tests.test_agentapi import call
from tests.test_route_auth import RouteFixture

# built from pieces so no source line looks like a real credential
AWS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE'
GITHUB = 'ghp' + '_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'
SLACK = 'xoxb' + '-' + '123456789012-abcdefghij'
STRIPE = 'sk' + '_live_' + 'a1B2c3D4e5F6g7H8i9J0k1L2'
GOOGLE = 'AIza' + 'SyA1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q'
JWT = 'eyJhbGciOiJIUzI1NiJ9' + '.' + 'eyJzdWIiOiIxMjM0NTY3ODkwIn0' + '.' + 'dBjftJeZ4CVPmB92K27uhbUJU1p1r'
PEM = '-----BEGIN RSA ' + 'PRIVATE KEY-----'
EMAIL = 'johndoe@acme-corp.io'
PHONE = '+44 20 7946 0958'
CARD = '4111 1111 1111 1111'


class PatternTests(SimpleTestCase):
	def types(self, text):
		return set(sv.scan_text(text))

	def test_each_credential_pattern_matches_and_near_misses_do_not(self):
		for name, value in (('aws_key', AWS_KEY), ('github_token', GITHUB), ('slack_token', SLACK), ('stripe_key', STRIPE),
				('google_key', GOOGLE), ('jwt', JWT), ('private_key', PEM)):
			self.assertEqual(self.types(f'x {value} y'), {name}, name)
		self.assertEqual(self.types('AKIA' + 'SHORT'), set())
		self.assertEqual(self.types('ghp' + '_tooshort'), set())
		self.assertEqual(self.types('-----BEGIN ' + 'CERTIFICATE-----'), set())

	def test_email_phone_and_internal_identifiers(self):
		self.assertEqual(self.types(f'contact {EMAIL}'), {'email'})
		self.assertEqual(self.types(f'call {PHONE}'), {'phone'})
		self.assertEqual(self.types('db at 10.20.30.40 and 192.168.1.5'), {'internal_ip'})
		self.assertEqual(self.types('host build01.corp and db.internal'), {'internal_host'})
		self.assertEqual(self.types('public 8.8.8.8 and 10.999.1.1'), set())

	def test_noise_is_dropped(self):
		self.assertEqual(self.types('noreply@example.com support@sentry.io logo@2x.png'), set())

	def test_a_card_needs_luhn_and_a_card_iin_and_a_timestamp_is_not_one(self):
		self.assertEqual(self.types(f'pay {CARD}'), {'card'})
		self.assertNotIn('card', self.types('pay 4111 1111 1111 1112'))  # Luhn fails
		self.assertEqual(self.types('ts 1700000000000'), set())  # 13 digits, wrong IIN
		self.assertEqual(self.types('5555555555554444'), {'card'})
		self.assertTrue(sv.luhn_ok('4111111111111111') and not sv.luhn_ok('4111111111111112'))

	def test_a_phone_is_not_a_card_and_all_one_digit_numbers_are_ignored(self):
		self.assertNotIn('phone', self.types(f'pay {CARD}'))
		self.assertEqual(self.types('call 000-000-0000'), set())

	def test_a_jwt_is_not_counted_as_an_email_and_a_credential_is_not_counted_twice(self):
		found = sv.scan_text(f'token {JWT} and {AWS_KEY}')
		self.assertEqual(set(found), {'jwt', 'aws_key'})
		found = sv.scan_text(f'key=ab{AWS_KEY}@cd.io')
		self.assertNotIn('aws_key', found.get('email', {}))

	def test_values_are_deduplicated_and_capped(self):
		found = sv.scan_text(' '.join([EMAIL] * 5))
		self.assertEqual(found['email']['count'], 1)
		many = ' '.join(f'user{i}@acme-corp.io' for i in range(80))
		self.assertEqual(sv.scan_text(many)['email']['count'], sv.MAX_PER_TYPE)

	def test_mask_never_exposes_more_than_four_characters_and_handles_short_values(self):
		self.assertEqual(sv.mask(AWS_KEY), 'AK********LE')
		self.assertEqual(sv.mask('abcdefghij'), 'ab******ij')
		for value in ('', 'a', 'abc', 'abcd', 'abcde', 'x' * 100, GITHUB, JWT, PEM):
			out = sv.mask(value)
			shown = sum(1 for a, b in zip(out, value) if a == b != '*')
			self.assertLessEqual(len([c for c in out if c != '*']), 4, value)
			self.assertLessEqual(len(out), 12, value)
		self.assertEqual(sv.mask('abc'), '***')
		self.assertEqual(sv.mask(EMAIL), 'jo**@****.io')
		self.assertNotIn('johndoe', sv.mask(EMAIL))

	def test_scan_text_returns_only_counts_and_masked_samples(self):
		found = sv.scan_text(f'{EMAIL} {AWS_KEY}')
		self.assertEqual(found['aws_key'], {'count': 1, 'sample': 'AWS access key, 20 chars (AKIA...)'})
		self.assertNotIn(AWS_KEY, json.dumps(found))
		self.assertNotIn('johndoe', json.dumps(found))

	def test_score_tiers(self):
		self.assertEqual(sv.sensitive_score({}), 0)
		self.assertEqual(sv.sensitive_score({'aws_key': {'count': 1}}), 25)
		self.assertEqual(sv.sensitive_score({'email': {'count': 5}}), 15)
		self.assertEqual(sv.sensitive_score({'phone': {'count': 3}}), 15)
		self.assertEqual(sv.sensitive_score({'card': {'count': 1}}), 15)
		self.assertEqual(sv.sensitive_score({'email': {'count': 2}}), 5)
		self.assertEqual(sv.sensitive_score({'internal_ip': {'count': 1}}), 5)
		self.assertEqual(sv.sensitive_score({'email': {'count': 9}, 'jwt': {'count': 1}}), 25)

	def test_only_text_like_content_is_scanned(self):
		for ok in ('text/html', 'text/plain; charset=utf-8', 'application/json', 'application/javascript', 'application/vnd.api+json',
				'application/atom+xml', 'APPLICATION/JSON'):
			self.assertTrue(sv.is_text(ok), ok)
		for bad in ('image/png', 'font/woff2', 'application/pdf', 'application/octet-stream', '', None):
			self.assertFalse(sv.is_text(bad), bad)


class ListHandler(logging.Handler):
	def __init__(self):
		super().__init__(logging.DEBUG)
		self.lines = []

	def emit(self, record):
		self.lines.append(record.getMessage())


class RunnerTests(RouteFixture, TestCase):
	def setUp(self):
		super().setUp()
		self.logs = ListHandler()
		logging.getLogger().addHandler(self.logs)
		self.old_level = logging.getLogger().level
		logging.getLogger().setLevel(logging.DEBUG)
		self.addCleanup(logging.getLogger().removeHandler, self.logs)
		self.addCleanup(logging.getLogger().setLevel, self.old_level)

	def everything_stored(self):
		return json.dumps({'routes': list(RouteAuth.objects.values()), 'activity': list(AgentActivity.objects.values()),
			'changes': list(AssetChange.objects.values()), 'ledger': list(ServiceRun.objects.values())}, default=str) + ' '.join(self.logs.lines)

	def test_a_known_secret_is_counted_and_masked_and_never_stored_returned_or_logged(self):
		body = f'{{"aws_access_key": "{AWS_KEY}", "owner": "{EMAIL}"}}'
		self.answers = {'/api': {'status': 200, 'content_type': 'application/json', 'body': body}}
		self.run_it(self.scan())
		row = RouteAuth.objects.get(path='/api')
		self.assertEqual(row.sensitive['aws_key'], {'count': 1, 'sample': 'AWS access key, 20 chars (AKIA...)'})
		self.assertEqual(row.sensitive['email'], {'count': 1, 'sample': 'jo**@****.io'})
		self.assertEqual((row.sensitive_score, row.content_type), (25, 'application/json'))
		self.assertEqual(RouteAuth.objects.get(path='/admin').sensitive, {})
		stored = self.everything_stored()
		self.assertNotIn(AWS_KEY, stored)
		self.assertNotIn('johndoe', stored)
		self.assertNotIn('aws_access_key', stored)  # the body itself is not stored either
		self.assertTrue(AgentActivity.objects.filter(message__contains='1 routes serve sensitive data').exists())

	def test_the_api_never_returns_a_raw_value(self):
		body = f'key {AWS_KEY} mail {EMAIL}'
		self.answers = {'/api': {'status': 200, 'content_type': 'text/html', 'body': body}}
		self.run_it(self.scan())
		user = User.objects.create_user('sens', password='x')
		ProjectMembership.objects.create(user=user, project=self.project, role='user')
		_, token = create_token(user, 't')
		for path in ('routes?sensitive=1', 'routes', 'changes', 'search?q=sensitive:credentials'):
			status, data = call(token, 'GET', f'/api/v1/projects/pr/{path}')
			self.assertEqual(status, 200, path)
			text = json.dumps(data)
			self.assertNotIn(AWS_KEY, text)
			self.assertNotIn('johndoe', text)
		_, data = call(token, 'GET', '/api/v1/projects/pr/routes?sensitive=1')
		self.assertEqual([r['path'] for r in data['results']], ['/api'])
		self.assertEqual(data['results'][0]['sensitive_score'], 25)
		self.assertEqual(data['results'][0]['sensitive']['aws_key']['sample'], 'AWS access key, 20 chars (AKIA...)')

	def test_a_binary_response_is_never_scanned(self):
		self.answers = {'/api': {'status': 200, 'content_type': 'image/png', 'body': AWS_KEY}}
		self.run_it(self.scan())
		self.assertEqual(RouteAuth.objects.get(path='/api').sensitive, {})

	def test_sensitive_found_is_emitted_only_when_a_new_type_appears_on_a_later_run(self):
		self.answers = {'/api': {'status': 200, 'content_type': 'application/json', 'body': f'mail {EMAIL}'}}
		self.run_it(self.scan())
		self.assertFalse(AssetChange.objects.filter(kind='sensitive_found').exists())  # first sight is not a change
		ServiceRun.objects.update(finished_at=timezone.now() - datetime.timedelta(days=8))
		self.run_it(self.scan())
		self.assertFalse(AssetChange.objects.filter(kind='sensitive_found').exists())  # same types
		ServiceRun.objects.update(finished_at=timezone.now() - datetime.timedelta(days=8))
		self.answers = {'/api': {'status': 200, 'content_type': 'application/json', 'body': f'mail {EMAIL} key {AWS_KEY}'}}
		self.run_it(self.scan())
		change = AssetChange.objects.get(kind='sensitive_found')
		self.assertEqual(change.before, {'types': ['email']})
		self.assertEqual(change.after['types'], ['aws_key', 'email'])
		self.assertEqual(change.after['counts'], {'aws_key': 1, 'email': 1})
		self.assertNotIn('sample', json.dumps(change.after))
		self.assertNotIn(AWS_KEY, self.everything_stored())

	def test_host_search_by_sensitive_group(self):
		self.answers = {'/api': {'status': 200, 'content_type': 'application/json', 'body': f'key {AWS_KEY}'},
			'/login': {'status': 200, 'content_type': 'text/html', 'body': 'a 10.1.2.3 b'}}
		self.run_it(self.scan())
		Subdomain.objects.filter(name='www.rt.test').update(target_domain=self.domain)
		user = User.objects.create_user('sens2', password='x')
		ProjectMembership.objects.create(user=user, project=self.project, role='user')
		_, token = create_token(user, 't')
		hosts = lambda q: [h['host'] for h in call(token, 'GET', f'/api/v1/projects/pr/search?q={q}')[1]['results']]  # noqa: E731
		self.assertEqual(hosts('sensitive:credentials'), ['www.rt.test'])
		self.assertEqual(hosts('sensitive:internal'), ['www.rt.test'])
		self.assertEqual(hosts('sensitive:pii'), [])
		self.assertEqual(hosts('sensitive:any'), ['www.rt.test'])
		self.assertEqual(call(token, 'GET', '/api/v1/projects/pr/search?q=sensitive:bogus')[0], 400)
		_, data = call(token, 'GET', '/api/v1/projects/pr/search?q=sensitive:credentials')
		self.assertIn('sensitive credentials', data['results'][0]['matched'])
