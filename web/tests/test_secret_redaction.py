"""Secret masking for AI prompts and replies (cveFeed.secret_redaction): a test vector for every pattern, the known-secret mask, the
nuclei template rules, idempotence and the cost of long adversarial strings."""
import time
import unittest

from cveFeed import secret_redaction as sr

# The vectors are fake. Where a literal one looks enough like a real credential to trip GitHub's push protection, it is written in pieces.
KEY = 'AIzaSyD' + '1234567890abcdefghijklmnopqrstuv'  # 39 characters

# (kind, text containing the secret, the secret as it must no longer appear)
VECTORS = [
    ('google_api_key', 'key=' + KEY + '&x=1', KEY),
    ('google_oauth_secret', 'client GOCSPX-' + 'a1B2c3D4' * 4, 'GOCSPX-' + 'a1B2c3D4' * 4),
    ('aws_access_key_id', 'id AKIAIOSFODNN7EXAMPLE here', 'AKIAIOSFODNN7EXAMPLE'),
    ('aws_access_key_id', 'id ASIAIOSFODNN7EXAMPLE here', 'ASIAIOSFODNN7EXAMPLE'),
    ('aws_secret_access_key', 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'),
    ('github_token', 'ghp_' + 'aB3' * 12, 'ghp_' + 'aB3' * 12),
    ('github_token', 'gho_' + 'x9' * 18, 'gho_' + 'x9' * 18),
    ('github_token', 'ghu_' + 'x9' * 18, 'ghu_' + 'x9' * 18),
    ('github_token', 'ghs_' + 'x9' * 18, 'ghs_' + 'x9' * 18),
    ('github_token', 'ghr_' + 'x9' * 18, 'ghr_' + 'x9' * 18),
    ('github_token', 'github_pat_11ABCDEFG0' + 'abcdef0123456789' * 3, 'github_pat_11ABCDEFG0' + 'abcdef0123456789' * 3),
    ('gitlab_token', 'glpat-' + 'AbCdEfGhIj1234567890', 'glpat-' + 'AbCdEfGhIj1234567890'),
    ('slack_token', 'xoxb-1234567890-abcdefghijkl', 'xoxb-1234567890-abcdefghijkl'),
    ('slack_token', 'xoxp-1234567890-abcdefghijkl', 'xoxp-1234567890-abcdefghijkl'),
    ('slack_webhook', 'POST https://hooks.slack' + '.com/services/T0000000A/B0000000B/abcdefghijklmnopqrstuvwx', 'abcdefghijklmnopqrstuvwx'),
    ('discord_webhook', 'https://discord.com/api/webhooks/123456789012345678/' + 'aB-_' * 10, 'aB-_' * 10),
    ('stripe_key', 'sk_live_' + 'a1B2c3D4' * 3, 'sk_live_' + 'a1B2c3D4' * 3),
    ('stripe_key', 'rk_live_' + 'a1B2c3D4' * 3, 'rk_live_' + 'a1B2c3D4' * 3),
    ('stripe_key', 'pk_live_' + 'a1B2c3D4' * 3, 'pk_live_' + 'a1B2c3D4' * 3),
    ('anthropic_key', 'sk-ant-api03-' + 'aB1_-' * 10, 'sk-ant-api03-' + 'aB1_-' * 10),
    ('openai_key', 'sk-' + 'aB1' * 16, 'sk-' + 'aB1' * 16),
    ('openai_key', 'sk-proj-' + 'aB1_' * 12, 'sk-proj-' + 'aB1_' * 12),
    ('sendgrid_key', 'SG.' + 'aB1' * 8 + '.' + 'cD2' * 14, 'SG.' + 'aB1' * 8 + '.' + 'cD2' * 14),
    ('mailgun_key', 'key' + '-0123456789abcdef' + '0123456789abcdef', 'key' + '-0123456789abcdef' + '0123456789abcdef'),
    ('twilio_sid_or_key', 'A' + 'C0123456789abcdef' + '0123456789abcdef', 'A' + 'C0123456789abcdef' + '0123456789abcdef'),
    ('twilio_sid_or_key', 'S' + 'K0123456789abcdef' + '0123456789abcdef', 'S' + 'K0123456789abcdef' + '0123456789abcdef'),
    ('npm_token', 'npm_' + 'aB1' * 12, 'npm_' + 'aB1' * 12),
    ('pypi_token', 'pypi-' + 'AgEIcHlwaS5vcmc' + 'aB1_' * 14, 'pypi-' + 'AgEIcHlwaS5vcmc' + 'aB1_' * 14),
    ('azure_storage_key', 'DefaultEndpointsProtocol=https;AccountKey=' + 'aB1+/' * 10 + '==;', 'aB1+/' * 10),
    ('jwt', 'token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk ok',
     'eyJzdWIiOiIxMjM0NTY3ODkwIn0'),
    ('private_key', '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA' + 'a' * 60 + '\n' + 'b' * 60 + '\n-----END RSA PRIVATE KEY-----', 'a' * 60),
    ('private_key', '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC' + 'c' * 60 + '\n-----END PRIVATE KEY-----', 'c' * 60),
    ('private_key', '{"key":"-----BEGIN EC PRIVATE KEY-----\\nMHcCAQEE' + 'd' * 60 + '\\n-----END EC PRIVATE KEY-----\\n"}', 'd' * 60),
    ('private_key', 'cut short -----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC' + 'e' * 60, 'e' * 60),
    ('url_password', 'postgres://admin:hunter2pass@db.example.test:5432/app', 'hunter2pass'),
    ('url_password', 'mongodb+srv://user:p4ss%21word@cluster0.example.test/db', 'p4ss%21word'),
    ('url_password', 'https://user:s3cret@example.test/path', 's3cret'),
    ('bearer_token', 'Authorization: Bearer abcDEF1234567890abcdef.xyz-123', 'abcDEF1234567890abcdef.xyz-123'),
    ('auth_header', 'Authorization: Basic dXNlcjpwYXNzd29yZA==', 'dXNlcjpwYXNzd29yZA=='),
    ('secret', 'Known Secret Found. Secret Type: [Django] Secret: [s3cr3t-signing-value] Product Type: [cookie]', 's3cr3t-signing-value'),
    ('secret', 'Possible Secret Found. Raw result: [AbCd1234efGh] RawV2 result: [AbCd1234efGh+user]', 'AbCd1234efGh'),
    ('secret_product', 'Product: [' + 'Zm9vYmFy' * 8 + '] Detecting Module: [x]', 'Zm9vYmFy' * 8),
]

# Text that looks a little like a secret and must stay as it is.
HARMLESS = [
    'nginx 1.18.0 is vulnerable to CVE-2021-23017',
    'Bearer token-based authentication is used by the API',
    'the key is exposed on the sk-learn page',
    'task-1234567890123456789012345 and risk-assessment-of-the-key',
    'https://example.test:8443/path?x=1',
    'postgres://db.example.test:5432/app',
    'password: required',
    'AKIA is the prefix of an AWS access key id',
    'eyJ is how a JWT starts',
    'Secret Type: [Django] and Product: [nginx]',
    '',
]


class RedactTextTests(unittest.TestCase):
    def test_every_pattern_masks_its_secret_and_names_its_kind(self):
        for kind, text, secret in VECTORS:
            with self.subTest(kind=kind, text=text[:50]):
                out = sr.redact_text(text)
                self.assertNotIn(secret, out)
                self.assertIn(f', {kind}, fp:', out)
                self.assertIn('[redacted ', out)

    def test_harmless_text_is_untouched(self):
        for text in HARMLESS:
            with self.subTest(text=text):
                self.assertEqual(sr.redact_text(text), text)

    def test_masking_is_idempotent(self):
        for kind, text, _ in VECTORS:
            with self.subTest(kind=kind):
                once = sr.redact_text(text)
                self.assertEqual(sr.redact_text(once), once)

    def test_the_mask_keeps_prefix_length_and_a_stable_fingerprint(self):
        out = sr.redact_text('found ' + KEY + ' on the page')
        self.assertTrue(out.startswith('found AIza\u2026[redacted 39 chars, google_api_key, fp:'))
        self.assertEqual(out, sr.redact_text('found ' + KEY + ' on the page'))  # the same secret, the same mask
        other = sr.redact_text('found ' + KEY[:-1] + 'X on the page')
        self.assertNotEqual(out, other)
        self.assertEqual(sr.fingerprint(KEY), sr.fingerprint(KEY))
        self.assertRegex(sr.fingerprint(KEY), r'^[0-9a-f]{8}$')

    def test_url_credentials_keep_the_rest_of_the_address(self):
        out = sr.redact_text('postgres://admin:hunter2pass@db.example.test:5432/app')
        self.assertTrue(out.startswith('postgres://admin:'))
        self.assertTrue(out.endswith('@db.example.test:5432/app'))

    def test_several_secrets_in_one_text(self):
        out = sr.redact_text(f'a {KEY} b AKIAIOSFODNN7EXAMPLE c ghp_{"aB3" * 12} d')
        self.assertEqual(out.count('[redacted '), 3)
        for secret in (KEY, 'AKIAIOSFODNN7EXAMPLE', 'ghp_' + 'aB3' * 12):
            self.assertNotIn(secret, out)

    def test_not_a_string_is_returned_as_it_is(self):
        for value in (None, 5, ['AKIAIOSFODNN7EXAMPLE'], {'a': KEY}):
            self.assertIs(sr.redact_text(value), value)

    def test_the_fingerprint_depends_on_the_server_key(self):
        before = sr.fingerprint('same-secret')
        saved = list(sr._KEY_CACHE)
        try:
            sr._KEY_CACHE[:] = [b'another-key']
            self.assertNotEqual(sr.fingerprint('same-secret'), before)
        finally:
            sr._KEY_CACHE[:] = saved


class AdversarialInputTests(unittest.TestCase):
    """Long hostile strings must cost about as much as a long ordinary one: every repeat is bounded and every pattern starts at a token
    boundary or a literal anchor."""
    CASES = {
        'begin-markers': '-----BEGIN PRIVATE KEY-----' * 20000,
        'begin-then-base64': '-----BEGIN PRIVATE KEY-----' + 'a' * 300000,
        'begin-then-spaces': '-----BEGIN PRIVATE KEY-----' + ' ' * 300000,
        'pem-lines-no-end': '-----BEGIN PRIVATE KEY-----\n' + ('a' * 64 + '\n') * 8000,
        'jwt-starts': 'eyJ' * 100000,
        'jwt-dots': ('eyJ' + 'a' * 100 + '.') * 5000,
        'url-schemes': 'a://' * 100000,
        'url-colons': 'a://b:' * 60000,
        'url-long-user': 'https://' + 'u' * 300000,
        'bearer-words': 'Bearer ' * 50000,
        'bearer-long': 'Bearer ' + 'a' * 300000,
        'auth-headers': 'Authorization: Basic ' * 20000,
        'prefixes': 'AIza' * 100000 + 'sk-' * 100000 + 'SG.' * 100000 + 'AKIA' * 100000,
        'long-token-runs': 'sk-' + 'a' * 300000,
        'brackets': 'Secret: [' * 50000,
        'bracket-long': 'Secret: [' + 'a' * 300000,
        'product': 'Product: [' * 50000,
        'webhooks': 'https://hooks.slack.com/services/' * 10000,
        'account-keys': 'AccountKey=' * 30000,
        'aws-secret-assign': 'aws_secret_access_key=' * 20000,
        'many-matches': ('AIza' + 'a' * 35 + ' ') * 20000,
    }

    def test_each_case_is_fast(self):
        for name, text in self.CASES.items():
            with self.subTest(name=name):
                started = time.monotonic()
                sr.redact_text(text)
                self.assertLess(time.monotonic() - started, 5.0, f'{name} took too long')


class MaskSecretTests(unittest.TestCase):
    def test_a_known_shape_keeps_its_public_prefix(self):
        out = sr.mask_secret(KEY, 'google-api-key')
        self.assertTrue(out.startswith('AIza\u2026[redacted 39 chars, google_api_key, fp:'))
        self.assertNotIn(KEY[4:], out)

    def test_an_unknown_shape_takes_the_hint_and_has_no_prefix(self):
        out = sr.mask_secret('hunter2-hunter2-hunter2', 'Weird-Template')
        self.assertTrue(out.startswith('\u2026[redacted 23 chars, weird_template, fp:'))
        self.assertNotIn('hunter2', out)
        self.assertIn(', secret, fp:', sr.mask_secret('hunter2-hunter2-hunter2'))

    def test_empty_stays_empty(self):
        self.assertEqual((sr.mask_secret(''), sr.mask_secret(None), sr.mask_secret('  ')), ('', '', ''))

    def test_a_value_that_only_contains_a_secret_is_masked_whole(self):
        out = sr.mask_secret('prefix text ' + KEY)
        self.assertNotIn('prefix text', out)
        self.assertIn('redacted 51 chars', out)


class ExtractedResultsTests(unittest.TestCase):
    def test_secret_templates_by_tag_and_by_id(self):
        self.assertEqual(sr.secret_template('google-api-key', ['exposure', 'token', 'google']), 'strong')
        self.assertEqual(sr.secret_template('x', ['Token']), 'strong')
        self.assertEqual(sr.secret_template('aws-access-key-value'), 'strong')
        self.assertEqual(sr.secret_template('git-config', ['exposure', 'git']), 'weak')
        self.assertEqual(sr.secret_template('apache-version', ['tech']), '')
        self.assertEqual(sr.secret_template('', None), '')

    def test_a_strong_template_masks_every_value(self):
        out = sr.mask_extracted([KEY, 'short'], 'google-api-key', ['token'])
        self.assertEqual(len(out), 2)
        self.assertTrue(out[0].startswith('AIza\u2026[redacted 39 chars, google_api_key'))
        self.assertIn('redacted 5 chars', out[1])

    def test_a_weak_template_masks_only_what_looks_like_a_secret(self):
        out = sr.mask_extracted(['nginx/1.18', 'two words here', 'Zm9vYmFyYmF6cXV4'], 'some-leak', ['exposure'])
        self.assertEqual(out[:2], ['nginx/1.18', 'two words here'])
        self.assertIn('[redacted 16 chars', out[2])

    def test_a_template_nobody_tagged_still_gets_the_generic_pass(self):
        out = sr.mask_extracted(['v1.2', 'AKIAIOSFODNN7EXAMPLE'], 'plain-template', ['panel'])
        self.assertEqual(out[0], 'v1.2')
        self.assertNotIn('AKIAIOSFODNN7EXAMPLE', out[1])

    def test_no_values(self):
        self.assertEqual(sr.mask_extracted(None, 'x'), [])
        self.assertEqual(sr.mask_extracted([None], 'x', ['token']), [''])
