"""Which Sentinel commit the contract was read from (About and Sentinels pages), and the build wiring that installs the newest Sentinel main."""
import json
import re
import subprocess
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
    """The image installs the newest Sentinel main over the floor that requirements.txt pins; CI keeps the floor."""

    def test_the_floor_stays_a_full_commit_in_requirements(self):
        text = (ROOT / 'web' / 'requirements.txt').read_text()
        self.assertRegex(text, r'(?m)^cvengine-scanner @ git\+https://github\.com/hevnsnt/cvENGINE-sentinel@[0-9a-f]{40}')

    def test_the_dockerfile_resolves_a_ref_to_a_commit_and_records_it(self):
        text = (ROOT / 'web' / 'Dockerfile').read_text()
        self.assertIn('ARG SENTINEL_REF=main', text)
        self.assertIn('ARG SENTINEL_SHA=', text)
        self.assertRegex(text, r'cvengine-scanner @ git\+\$\{SENTINEL_REPO\}@\$\{sha\}')
        self.assertIn('direct_url.json', text)
        self.assertIn('com.cvengine.sentinel.sha', text)
        self.assertLess(text.index('pip install --no-cache-dir -r /tmp/requirements.txt'), text.index('ARG SENTINEL_REF=main'))  # the newest goes over the floor, not under it

    def test_every_build_passes_the_arguments_and_every_build_path_resolves_the_commit_first(self):
        compose = (ROOT / 'docker-compose.yml').read_text()
        self.assertEqual(compose.count('SENTINEL_REF: "${SENTINEL_REF:-main}"'), 2)  # web and celery: the two builds of ./web
        self.assertEqual(compose.count('SENTINEL_SHA: "${SENTINEL_SHA:-}"'), 2)
        for script in ('scripts/update.sh', 'scripts/apply-update.sh', 'scripts/update-deploy.sh'):
            text = (ROOT / script).read_text()
            self.assertLess(text.index('scripts/sentinel-ref.sh'), text.index('build web celery celery-beat'), script)
        makefile = (ROOT / 'Makefile').read_text()
        self.assertEqual(makefile.count('${SENTINEL_BUILD_ENV}'), 2)  # make up and make build

    def test_the_ref_script_takes_a_full_sha_as_it_is_and_refuses_what_is_not_a_ref(self):
        run = lambda ref: subprocess.run(['bash', str(ROOT / 'scripts' / 'sentinel-ref.sh')], capture_output=True, text=True, env={'PATH': '/usr/bin:/bin', 'SENTINEL_REF': ref}, timeout=30)
        self.assertEqual(run(SHA).stdout.strip(), SHA)
        for bad in ('main; rm -rf /', '--upload-pack=x', '$(id)', 'a b'):
            out = run(bad)
            self.assertEqual((out.returncode, out.stdout.strip()), (0, ''), bad)  # nothing is printed: the Dockerfile then resolves SENTINEL_REF itself, and fails on a ref that is not one

    def test_ci_still_reads_a_full_commit_where_it_always_did(self):
        workflow = (ROOT / '.github' / 'workflows' / 'build-pr.yml').read_text()
        self.assertIn(r"cvENGINE-sentinel@\([0-9a-f]\{40\}\)", workflow)
        self.assertRegex(workflow, r'scanner_lock\.py check --remote')  # the floor is on the Sentinel main branch
