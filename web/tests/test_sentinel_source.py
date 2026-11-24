"""Which Sentinel commit the contract was read from (About and Sentinels pages), and the build wiring that installs exactly the pinned commit."""
import json
from importlib import metadata
from pathlib import Path
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase

from agentapi import sentinel_contract, sentinel_source
from tests.test_tenancy import client_for

ROOT = Path(__file__).resolve().parents[2]
SHA = 'd' * 40


def fake_distribution(direct_url):
    dist = mock.Mock()
    dist.read_text.return_value = direct_url
    return dist


class LibraryTests(TestCase):
    def test_the_commit_is_read_from_what_pip_recorded(self):
        raw = json.dumps({'url': 'https://github.com/hevnsnt/cvENGINE-sentinel', 'vcs_info': {'vcs': 'git', 'commit_id': SHA, 'requested_revision': 'main'}})
        with mock.patch.object(metadata, 'distribution', return_value=fake_distribution(raw)):
            found = sentinel_source.library()
            line = sentinel_source.contract_line()
        self.assertEqual((found['commit'], found['short'], found['ref']), (SHA, SHA[:12], 'main'))
        self.assertEqual(line, f'Result contract version {sentinel_contract.version()}, read from Sentinel {SHA[:12]}')

    def test_an_install_that_did_not_come_from_git_says_so_and_never_guesses(self):
        for raw in (None, '', 'not json', json.dumps({'url': 'file:///x'}), json.dumps({'vcs_info': {'commit_id': 'zzz'}}), json.dumps([1])):
            with mock.patch.object(metadata, 'distribution', return_value=fake_distribution(raw)):
                self.assertIsNone(sentinel_source.library()['commit'], raw)
                self.assertIn('its commit is not recorded in this install', sentinel_source.contract_line())
        with mock.patch.object(metadata, 'distribution', side_effect=metadata.PackageNotFoundError('cvengine-scanner')):
            self.assertIsNone(sentinel_source.library()['commit'])

    def test_both_pages_say_it(self):
        user = User.objects.create_user('source-reader', password='x', is_superuser=True)
        raw = json.dumps({'url': 'u', 'vcs_info': {'commit_id': SHA, 'requested_revision': 'main'}})
        with mock.patch.object(metadata, 'distribution', return_value=fake_distribution(raw)):
            for path in ('/cve/about/', '/cve/sentinels/'):
                html = client_for(user).get(path).content.decode()
                self.assertIn(f'read from Sentinel {SHA[:12]}', html, path)


class BuildWiringTests(TestCase):
    """The image installs EXACTLY the Sentinel commit web/requirements.txt pins (security review S5): no branch is resolved at build time, and the
    built-in scanner's image is pinned by digest to the image published from the same commit (scanner.lock.json)."""

    def test_the_pin_stays_a_full_commit_in_requirements(self):
        text = (ROOT / 'web' / 'requirements.txt').read_text()
        self.assertRegex(text, r'(?m)^cvengine-scanner @ git\+https://github\.com/hevnsnt/cvENGINE-sentinel@[0-9a-f]{40}')

    def test_the_dockerfile_installs_the_pin_and_resolves_nothing(self):
        text = (ROOT / 'web' / 'Dockerfile').read_text()
        for gone in ('SENTINEL_REF', 'SENTINEL_SHA', 'SENTINEL_REPO', 'git ls-remote', 'refs/heads', 'cvengine-scanner @ git+'):
            self.assertNotIn(gone, text)
        self.assertIn('pip install --no-cache-dir -r /tmp/requirements.txt', text)
        self.assertIn('direct_url.json', text)  # the build still prints the commit it holds

    def test_no_build_path_passes_a_sentinel_ref_any_more(self):
        self.assertFalse((ROOT / 'scripts' / 'sentinel-ref.sh').exists())
        for name in ('docker-compose.yml', 'docker-compose.dev.yml', 'Makefile', 'scripts/update.sh', 'scripts/apply-update.sh', 'scripts/update-deploy.sh',
                     '.env.example', 'install.sh'):
            text = (ROOT / name).read_text()
            for gone in ('sentinel-ref.sh', 'SENTINEL_REF', 'SENTINEL_SHA', 'SENTINEL_BUILD_ENV'):
                self.assertNotIn(gone, text, name)

    def test_the_library_and_the_scanner_image_come_from_one_commit(self):
        lock = json.loads((ROOT / 'scanner.lock.json').read_text())
        requirements = (ROOT / 'web' / 'requirements.txt').read_text()
        self.assertIn(f'cvENGINE-sentinel@{lock["floor"]["commit"]}', requirements)
        self.assertRegex(lock['floor']['digest'], r'^sha256:[0-9a-f]{64}$')
        compose = (ROOT / 'docker-compose.yml').read_text()
        self.assertIn(f'{lock["image"]}@{lock["floor"]["digest"]}}}}}', compose)
        self.assertNotIn('cvengine-sentinel:main', compose)

    def test_ci_still_reads_a_full_commit_where_it_always_did(self):
        workflow = (ROOT / '.github' / 'workflows' / 'build-pr.yml').read_text()
        self.assertIn(r"cvENGINE-sentinel@\([0-9a-f]\{40\}\)", workflow)
        self.assertRegex(workflow, r'scanner_lock\.py check --remote')  # the pinned commit is on the Sentinel main branch and its image is the pinned digest
