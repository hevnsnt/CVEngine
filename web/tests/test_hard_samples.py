import json

from django.test import SimpleTestCase

from cveFeed import sensitive as sv
from tests.test_sensitive import AWS_KEY, CARD, EMAIL, GITHUB, GOOGLE, JWT, PEM, PHONE, SLACK, STRIPE


class CredentialSampleTests(SimpleTestCase):
	"""Verdict 5: a credential sample proves the type, never shows a character of the secret."""

	def test_each_credential_type_shows_label_length_and_public_prefix_only(self):
		self.assertEqual(sv.sample(AWS_KEY, 'aws_key'), 'AWS access key, 20 chars (AKIA...)')
		self.assertEqual(sv.sample(GITHUB, 'github_token'), 'GitHub token, 40 chars (ghp_...)')
		self.assertEqual(sv.sample(SLACK, 'slack_token'), f'Slack token, {len(SLACK)} chars (xoxb-...)')
		self.assertEqual(sv.sample(STRIPE, 'stripe_key'), f'Stripe live key, {len(STRIPE)} chars (sk_live_...)')
		self.assertEqual(sv.sample(GOOGLE, 'google_key'), f'Google API key, {len(GOOGLE)} chars (AIza...)')
		self.assertEqual(sv.sample(JWT, 'jwt'), f'JWT, {len(JWT)} chars (eyJ...)')

	def test_no_secret_character_survives_in_any_credential_sample(self):
		for name, value in (('aws_key', AWS_KEY), ('github_token', GITHUB), ('slack_token', SLACK), ('stripe_key', STRIPE),
				('google_key', GOOGLE), ('jwt', JWT)):
			out = sv.sample(value, name)
			prefix = sv.CREDENTIAL_PREFIX[name].match(value).group(0)
			secret = value[len(prefix):]
			for window in range(0, len(secret) - 2):
				if secret[window:window + 3] != prefix[:3]:  # the format prefix may legitimately repeat inside a secret
					self.assertNotIn(secret[window:window + 3], out, (name, window))

	def test_a_jwt_sample_has_no_dotted_segment(self):
		out = sv.sample(JWT, 'jwt')
		self.assertNotIn('.', out.replace('...', ''))
		for part in JWT.split('.'):
			self.assertNotIn(part[5:], out)

	def test_a_private_key_shows_only_its_pem_header(self):
		self.assertEqual(sv.sample(PEM, 'private_key'), f'private key, PEM header {PEM}')

	def test_email_and_phone_keep_the_current_mask(self):
		self.assertEqual(sv.sample(EMAIL, 'email'), 'jo**@****.io')
		self.assertEqual(sv.sample(PHONE, 'phone'), sv.mask(PHONE))
		self.assertEqual(sv.sample(CARD, 'card'), sv.mask(CARD))

	def test_scan_text_uses_the_credential_form_and_returns_no_raw_value(self):
		found = sv.scan_text(f'{EMAIL} {AWS_KEY} {GITHUB} {PEM}')
		self.assertEqual(found['aws_key']['sample'], 'AWS access key, 20 chars (AKIA...)')
		self.assertEqual(found['email']['sample'], 'jo**@****.io')
		blob = json.dumps(found)
		for secret in (AWS_KEY, GITHUB, 'IOSFODNN7', 'johndoe'):
			self.assertNotIn(secret, blob)

	def test_a_value_with_no_known_prefix_still_shows_nothing_of_itself(self):
		self.assertEqual(sv.sample('abcdefghij', 'github_token'), 'GitHub token, 10 chars')
