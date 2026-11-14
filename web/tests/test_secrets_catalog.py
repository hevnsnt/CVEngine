"""The secrets catalog (cveFeed.secrets_catalog): mapping, masking, normalisation and the severity table of docs/SECRETS-PLAN.md section 8. Pure."""
import base64
import json
from pathlib import Path

from django.test import SimpleTestCase

from cveFeed import secrets_catalog as catalog

RULE_IDS = Path(__file__).with_name('fixtures') / 'kingfisher_rule_ids.txt'  # every rule ID of the pinned Kingfisher 2.18.1 rule bundle


def jwt(claims):
    part = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=')
    return f'eyJhbGciOiJIUzI1NiJ9.{part}.c2lnbmF0dXJlLXNpZ25hdHVyZQ'


class MappingTests(SimpleTestCase):
    def test_the_case_that_started_it_is_a_browser_key_from_every_detector(self):
        for rule in ('betterleaks.gcp-api-key', 'nuclei:google-api-key', 'route:google_key'):
            kind = catalog.classify(rule, 'AIzaSyA1B2C3D4E5F6G7H8I9J0KLMNOPQRSTUVw')
            self.assertEqual((kind.provider, kind.kind, kind.klass), ('Google', 'google-api-key', 'P'), rule)

    def test_the_value_decides_between_kinds_of_one_provider(self):
        self.assertEqual(catalog.classify('betterleaks.stripe-access-token', 'pk_live_' + 'p' * 16).klass, 'P')
        self.assertEqual(catalog.classify('betterleaks.stripe-access-token', 'sk_live_' + 's' * 16).klass, 'S')
        self.assertEqual(catalog.classify('betterleaks.mapbox-api-token', 'pk.eyJ1Ijoi').klass, 'P')
        self.assertEqual(catalog.classify('betterleaks.mapbox-api-token', 'sk.eyJ1Ijoi').klass, 'S')

    def test_an_aws_key_id_alone_is_an_identifier_and_the_secret_half_a_server_secret(self):
        self.assertEqual(catalog.classify('betterleaks.aws-access-token').kind, 'aws-access-key-id')
        self.assertEqual(catalog.classify('betterleaks.aws-access-token').klass, 'I')
        self.assertEqual(catalog.classify('betterleaks.aws-secret-access-key').kind, 'aws-access-key-pair')
        self.assertEqual(catalog.classify('betterleaks.aws-secret-access-key').klass, 'S')

    def test_a_pem_private_key_is_a_server_secret_whatever_found_it(self):
        self.assertEqual(catalog.classify('betterleaks.private-key').kind, 'private-key')
        self.assertEqual(catalog.classify('custom.something', '-----BEGIN RSA PRIVATE KEY-----\nMIIE').kind, 'private-key')

    def test_an_unknown_rule_is_uncatalogued_server_secret_medium_never_a_crash(self):
        kind = catalog.classify('betterleaks.datadog-api-key')
        self.assertEqual((kind.provider, kind.klass, kind.catalogued), ('Datadog', 'S', False))
        self.assertEqual(catalog.severity(kind)[0], catalog.MEDIUM)
        self.assertIn('uncatalogued', catalog.severity(kind)[1])
        for odd in ('', None, '???', 'x' * 500):
            self.assertFalse(catalog.classify(odd).catalogued)

    def test_every_rule_of_the_pinned_bundle_maps_without_a_crash(self):
        """docs/SECRETS-PLAN.md 8.1: a rule is known or uncatalogued, never an error. The uncatalogued ones are listed as a warning only."""
        ids = RULE_IDS.read_text().split()
        self.assertGreater(len(ids), 400)
        uncatalogued = []
        for rule_id in ids:
            self.assertTrue(catalog.rule_id_ok(rule_id), rule_id)
            kind = catalog.classify(rule_id)
            self.assertIn(kind.klass, catalog.CLASSES, rule_id)
            catalog.severity(kind)
            if not kind.catalogued:
                uncatalogued.append(rule_id)
        self.assertLess(len(uncatalogued), len(ids))  # a warning list, not a failure: it only must not be everything


class MaskTests(SimpleTestCase):
    def test_never_more_than_the_prefix_and_four_characters(self):
        self.assertEqual(catalog.mask('AIzaSyA1B2C3D4E5F6G7H8I9J0KLMNOPQRSTUVw'), 'AIza…TUVw')
        self.assertEqual(catalog.mask('AKIAIOSFODNN7EXAMPLE'), 'AKIA…MPLE')
        self.assertEqual(catalog.mask('ghp_' + 'a' * 32 + 'WXYZ'), 'ghp_…WXYZ')
        self.assertEqual(catalog.mask('"sk_live_' + 'q' * 20 + 'uvwx"'), 'sk_live_…uvwx')  # built at run time: no key-shaped literal

    def test_a_short_value_shows_nothing_of_its_own(self):
        self.assertEqual(catalog.mask('abcdefghij'), '…')
        self.assertEqual(catalog.mask('xoxb-12345'), 'xoxb-…')  # the format prefix every Slack bot token carries, nothing of its own

    def test_a_pem_shows_its_header_only(self):
        pem = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----'
        self.assertEqual(catalog.mask(pem), 'PEM OPENSSH PRIVATE KEY')
        self.assertNotIn('b3Bl', catalog.mask(pem))

    def test_a_url_credential_keeps_the_scheme_only(self):
        masked = catalog.mask('postgres://admin:s3cretpassw0rd@db.example.com:5432/app')
        self.assertTrue(masked.startswith('postgres://…'))
        self.assertNotIn('s3cret', masked)

    def test_normalisation_strips_whitespace_and_quotes(self):
        self.assertEqual(catalog.normalise('  "AKIAIOSFODNN7EXAMPLE" '), 'AKIAIOSFODNN7EXAMPLE')
        self.assertEqual(catalog.normalise("'`x`'"), 'x')


class SeverityTests(SimpleTestCase):
    def sev(self, rule, value='', status='unverified', meta=None, facts=None):
        return catalog.severity(catalog.classify(rule, value), status, meta, facts, now=1_800_000_000)[0]

    def test_the_table(self):
        google = 'betterleaks.gcp-api-key'
        self.assertEqual(self.sev(google), catalog.INFO)
        self.assertEqual(self.sev(google, status='live'), catalog.LOW)
        self.assertEqual(self.sev(google, status='live', meta={'gemini_access': True}), catalog.MEDIUM)
        self.assertEqual(self.sev(google, status='live', meta={'gemini_access': True, 'restriction': 'http_referrer'}), catalog.LOW)
        self.assertEqual(self.sev(google, status='inactive'), catalog.INFO)
        github = 'betterleaks.github-pat'
        self.assertEqual(self.sev(github), catalog.HIGH)
        self.assertEqual(self.sev(github, status='live'), catalog.CRITICAL)
        self.assertEqual(self.sev(github, status='inactive'), catalog.LOW)
        self.assertEqual(self.sev('betterleaks.aws-access-token'), catalog.LOW)
        self.assertEqual(self.sev('betterleaks.slack-webhook-url'), catalog.MEDIUM)

    def test_a_jwt_is_medium_until_its_exp_claim_has_passed(self):
        self.assertEqual(self.sev('betterleaks.jwt', facts={'exp': 1_900_000_000}), catalog.MEDIUM)
        self.assertEqual(self.sev('betterleaks.jwt', facts={'exp': 1_700_000_000}), catalog.LOW)
        self.assertEqual(self.sev('betterleaks.jwt'), catalog.MEDIUM)
        self.assertEqual(catalog.jwt_expiry(jwt({'exp': 1_700_000_000, 'sub': 'x'})), 1_700_000_000)
        self.assertIsNone(catalog.jwt_expiry('eyJ.not-base64!.x'))
        self.assertIsNone(catalog.jwt_expiry('AKIAIOSFODNN7EXAMPLE'))

    def test_a_persons_decision_is_kept_and_quiet_statuses_do_not_count(self):
        for status in ('public_by_design', 'accepted', 'false_positive', 'revoked'):
            self.assertEqual(catalog.status_after_validation(status, 'verified_active'), status)
            self.assertFalse(catalog.counts(status))
        self.assertEqual(catalog.status_after_validation('unverified', 'verified_active'), 'live')
        self.assertEqual(catalog.status_after_validation('live', 'verified_inactive'), 'inactive')
        self.assertEqual(catalog.status_after_validation('unverified', 'not_attempted'), 'unverified')
        self.assertTrue(catalog.counts('live'))
