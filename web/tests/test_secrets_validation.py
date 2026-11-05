"""The third lock of secret validation (docs/SECRETS-PLAN.md 5.2): only reviewed validators run, and only while each one is the text a person
reviewed. The hashes in ``cveFeed/data/secrets_validation_allowlist.json`` are recomputed here from the pinned, attested Kingfisher rule bundle,
which CI downloads and verifies (``.github/workflows/build-pr.yml``) and names in ``CVENGINE_KINGFISHER_RULES``."""
import os
import re
from pathlib import Path

from django.test import SimpleTestCase

from cveFeed import secrets_catalog, secrets_validation


def rules_dir():
    path = os.environ.get('CVENGINE_KINGFISHER_RULES', '')
    return Path(path) if path else None


class AllowListShapeTests(SimpleTestCase):
    def test_the_list_is_identity_only_and_pinned(self):
        data = secrets_validation.allowlist()
        self.assertRegex(data['rule_bundle_sha256'], r'^[0-9a-f]{64}$')
        self.assertRegex(data['kingfisher_version'], r'^\d+\.\d+\.\d+$')
        self.assertEqual(set(data['rules']), set(data['reviewed']), 'every rule on the list says what its validator calls')
        for rule_id, digest in data['rules'].items():
            self.assertTrue(secrets_catalog.rule_id_ok(rule_id), rule_id)
            self.assertRegex(digest, r'^[0-9a-f]{64}$', rule_id)
            self.assertTrue(secrets_catalog.classify(rule_id).catalogued, rule_id)
        self.assertLessEqual(len(secrets_validation.rule_ids()), 20)  # the contract's validate_rules bound

    def test_the_block_reader(self):
        text = ('- name: A\n  id: betterleaks.a\n  pattern: x\n  validation:\n    type: Http\n    content:\n      url: https://example.com/\n'
                '- name: B\n  id: betterleaks.b\n  pattern: y\n')
        self.assertEqual(secrets_validation.validator_block(text, 'betterleaks.a'),
                         '  validation:\n    type: Http\n    content:\n      url: https://example.com/\n')
        self.assertEqual(secrets_validation.validator_block(text, 'betterleaks.b'), '')
        self.assertIsNone(secrets_validation.validator_block(text, 'betterleaks.c'))


class PinnedBundleTests(SimpleTestCase):
    def setUp(self):
        self.dir = rules_dir()
        if self.dir is None:
            if os.environ.get('CI'):
                self.fail('CVENGINE_KINGFISHER_RULES is not set: the CI step that downloads the pinned rule bundle did not run')
            self.skipTest('the pinned Kingfisher rule bundle is downloaded by CI (CVENGINE_KINGFISHER_RULES)')
        self.text = ''.join(p.read_text() for p in sorted(self.dir.glob('*.yml')))

    def test_every_allow_listed_validator_is_the_one_that_was_reviewed(self):
        """A changed validator leaves the list until a person reads it again: update the hash only after reviewing the new block."""
        for rule_id, digest in secrets_validation.allowlist()['rules'].items():
            self.assertEqual(secrets_validation.validator_hash(self.text, rule_id), digest,
                             f'{rule_id}: its validator changed in the pinned bundle; review it before allowing it again')

    def test_the_reviewed_validators_only_read(self):
        """No write method, and no POST except Slack's identity endpoint (the rule for the list)."""
        for rule_id in secrets_validation.allowlist()['rules']:
            block = secrets_validation.validator_block(self.text, rule_id)
            source = block.split('expression:')[0]
            self.assertFalse(re.search(r'http\.(put|patch|delete)\b', source), rule_id)
            for url in re.findall(r'http\.post\("([^"]+)"', source):
                self.assertEqual(url, 'https://slack.com/api/auth.test', rule_id)

    def test_the_helpers_have_no_validator_of_their_own(self):
        for rule_id in secrets_validation.allowlist().get('helpers') or ():
            self.assertEqual(secrets_validation.validator_block(self.text, rule_id), '', rule_id)

    def test_every_bundle_rule_maps_and_the_vendored_id_list_is_current(self):
        ids = sorted(set(re.findall(r'^  id: (\S+)$', self.text, re.M)))
        vendored = (Path(__file__).with_name('fixtures') / 'kingfisher_rule_ids.txt').read_text().split()
        self.assertEqual(ids, sorted(vendored), 'refresh tests/fixtures/kingfisher_rule_ids.txt from the pinned bundle')
