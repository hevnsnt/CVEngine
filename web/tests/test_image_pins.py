"""scripts/image_pins.py: every stock image the repository builds on or runs is pinned by digest, and the one way to move a pin is a pull request
that ran ``bump`` (security review S5). The registry is never asked here: a fake resolver stands in for it."""
import importlib.util
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts' / 'image_pins.py'
A, B = 'sha256:' + 'a' * 64, 'sha256:' + 'b' * 64


def load():
    spec = importlib.util.spec_from_file_location('image_pins', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pins = load()


class RepositoryPinTests(unittest.TestCase):
    """The files as they are in the repository."""

    def test_every_stock_image_is_pinned_by_digest(self):
        refs = pins.references()
        self.assertEqual(pins.check(refs), [])
        found = {(r['file'], r['image']) for r in refs}
        for expected in (('web/Dockerfile', 'ubuntu'), ('web/Dockerfile', 'ghcr.io/astral-sh/uv'), ('reviewer/Dockerfile', 'python'), ('certs/Dockerfile', 'alpine'),
                         ('docker-compose.yml', 'postgres'), ('docker-compose.yml', 'redis'), ('docker-compose.yml', 'nginx'),
                         ('docker-compose.dev.yml', 'postgres'), ('docker-compose.dev.yml', 'redis')):
            self.assertIn(expected, found)
        self.assertTrue(all(r['digest'] for r in refs))

    def test_the_command_line_check_passes(self):
        self.assertEqual(pins.main(['check']), 0)

    def test_no_compose_file_or_dockerfile_names_a_stock_image_by_tag_alone(self):
        # the same rule, read without the script's own parser: any image: or FROM line naming a stock image carries @sha256
        for name in pins.FILES:
            for line in (ROOT / name).read_text().splitlines():
                stripped = line.strip()
                if stripped.startswith(('image:', 'FROM ')) and any(f'{image}:' in stripped for image in ('ubuntu', 'astral-sh/uv', 'alpine', 'postgres', 'redis', 'nginx')):
                    self.assertIn('@sha256:', stripped, f'{name}: {stripped}')

    def test_the_web_image_stages_share_one_ubuntu_pin(self):
        ubuntu = {r['digest'] for r in pins.references() if r['image'] == 'ubuntu'}
        self.assertEqual(len(ubuntu), 1)


class ParserTests(unittest.TestCase):
    def tree(self, files):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        for name, text in files.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text)
        return root

    def test_tags_alone_and_two_digests_for_one_tag_are_reported(self):
        root = self.tree({'web/Dockerfile': f'FROM ubuntu:26.04 AS python\nFROM ubuntu:26.04@{A}\nFROM python AS x\n',
                          'docker-compose.yml': f'services:\n  r:\n    image: "redis:alpine@{A}"\n  d:\n    image: redis:alpine@{B}\n'
                                                '  w:\n    image: cvengine/web:latest\n  s:\n    image: "${X:-ghcr.io/x/y:main}"\n'})
        refs = pins.references(root)
        self.assertEqual([(r['file'], r['line'], r['image'], r['digest']) for r in refs],
                         [('web/Dockerfile', 1, 'ubuntu', None), ('web/Dockerfile', 2, 'ubuntu', A),
                          ('docker-compose.yml', 3, 'redis', A), ('docker-compose.yml', 5, 'redis', B)])
        problems = pins.check(refs)
        self.assertTrue(any('web/Dockerfile:1: ubuntu:26.04 is a tag alone' in p for p in problems), problems)
        self.assertTrue(any('docker-compose.yml:5: redis:alpine is pinned to' in p and 'docker-compose.yml:3' in p for p in problems), problems)
        self.assertEqual(pins.check([]), ['no stock image reference found: the pinned files moved or their syntax changed'])

    def test_rewrite_touches_only_the_named_references_and_keeps_the_line(self):
        text = f'FROM ubuntu:26.04 AS python\nFROM ghcr.io/astral-sh/uv:0.13.9@{A} AS uv\nRUN echo ubuntu:26.04\n'
        out, count = pins.rewrite(text, 'Dockerfile', {('ubuntu', '26.04'): B})
        self.assertEqual(count, 1)
        self.assertEqual(out, f'FROM ubuntu:26.04@{B} AS python\nFROM ghcr.io/astral-sh/uv:0.13.9@{A} AS uv\nRUN echo ubuntu:26.04\n')
        compose = f'    image: "nginx:alpine@{A}"  # the proxy\n    image: nginx:alpine\n'
        out, count = pins.rewrite(compose, 'compose', {('nginx', 'alpine'): B})
        self.assertEqual((out, count), (f'    image: "nginx:alpine@{B}"  # the proxy\n    image: nginx:alpine@{B}\n', 2))
        self.assertEqual(pins.rewrite(out, 'compose', {('nginx', 'alpine'): B}), (out, 0), 'a second bump to the same digest changes nothing')

    def test_bump_resolves_each_tag_once_and_writes_every_file(self):
        root = self.tree({'web/Dockerfile': 'FROM ubuntu:26.04 AS python\nFROM ubuntu:26.04\n',
                          'docker-compose.yml': f'    image: "redis:alpine@{A}"\n',
                          'docker-compose.dev.yml': '    image: "redis:alpine"\n'})
        asked = []
        lines = pins.bump((), root, resolver=lambda image, tag: asked.append((image, tag)) or B)
        self.assertEqual(sorted(asked), [('redis', 'alpine'), ('ubuntu', '26.04')])
        self.assertEqual((root / 'web/Dockerfile').read_text(), f'FROM ubuntu:26.04@{B} AS python\nFROM ubuntu:26.04@{B}\n')
        self.assertEqual((root / 'docker-compose.dev.yml').read_text(), f'    image: "redis:alpine@{B}"\n')
        self.assertIn(f'redis:alpine -> {B}', lines)
        self.assertEqual(pins.check(pins.references(root)), [])

    def test_bump_of_one_image_leaves_the_others_and_dry_run_writes_nothing(self):
        root = self.tree({'docker-compose.yml': '    image: redis:alpine\n    image: nginx:alpine\n'})
        pins.bump(['nginx'], root, resolver=lambda image, tag: B, dry_run=True)
        self.assertEqual((root / 'docker-compose.yml').read_text(), '    image: redis:alpine\n    image: nginx:alpine\n')
        pins.bump(['nginx'], root, resolver=lambda image, tag: B)
        self.assertEqual((root / 'docker-compose.yml').read_text(), f'    image: redis:alpine\n    image: nginx:alpine@{B}\n')
        with self.assertRaises(pins.PinError):
            pins.bump(['mysql'], root, resolver=lambda image, tag: B)

    def test_behind_lists_only_pins_whose_tag_moved(self):
        refs = [{'file': 'f', 'line': 1, 'image': 'redis', 'tag': 'alpine', 'digest': A},
                {'file': 'g', 'line': 2, 'image': 'redis', 'tag': 'alpine', 'digest': A},
                {'file': 'f', 'line': 3, 'image': 'nginx', 'tag': 'alpine', 'digest': B}]
        asked = []
        late = pins.behind(refs, resolver=lambda image, tag: asked.append(image) or B)
        self.assertEqual([r['line'] for r, _ in late], [1, 2])
        self.assertEqual(asked, ['redis', 'nginx'], 'one question per image:tag')

    def test_the_remote_check_reports_and_fails_only_when_asked_to(self):
        root = self.tree({'docker-compose.yml': f'    image: redis:alpine@{A}\n'})
        with mock.patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(pins.main(['check', '--remote'], root, resolver=lambda image, tag: B), 0)
        self.assertIn('python3 scripts/image_pins.py bump redis', out.getvalue())
        with mock.patch('sys.stdout', new_callable=io.StringIO):
            self.assertEqual(pins.main(['check', '--remote', '--fail-if-behind'], root, resolver=lambda image, tag: B), 1)
            self.assertEqual(pins.main(['check', '--remote', '--fail-if-behind'], root, resolver=lambda image, tag: A), 0)
        with mock.patch('sys.stderr', new_callable=io.StringIO):
            self.assertEqual(pins.main(['check', '--bogus'], root), 2)
            self.assertEqual(pins.main([], root), 2)


class RegistryTests(unittest.TestCase):
    def test_registry_names(self):
        self.assertEqual(pins.registry('nginx')[:2], ('registry-1.docker.io', 'library/nginx'))
        self.assertIn('scope=repository:library/nginx:pull', pins.registry('nginx')[2])
        self.assertEqual(pins.registry('ghcr.io/astral-sh/uv')[:2], ('ghcr.io', 'astral-sh/uv'))
        self.assertEqual(pins.registry('ghcr.io/astral-sh/uv')[2], 'https://ghcr.io/token?scope=repository:astral-sh/uv:pull')
        self.assertEqual(pins.registry('someone/tool')[:2], ('registry-1.docker.io', 'someone/tool'))

    def test_resolve_asks_for_a_token_then_heads_the_manifest_with_the_index_types(self):
        seen = []

        class Reply(io.BytesIO):
            def __init__(self, body=b'', headers=None):
                super().__init__(body)
                self.headers = headers or {}

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def opener(request, timeout=30):
            seen.append(request)
            if 'token' in request.full_url:
                return Reply(json.dumps({'token': 'T'}).encode())
            return Reply(headers={'Docker-Content-Digest': A})

        self.assertEqual(pins.resolve('redis', 'alpine', opener=opener), A)
        token, head = seen
        self.assertEqual(head.full_url, 'https://registry-1.docker.io/v2/library/redis/manifests/alpine')
        self.assertEqual(head.get_method(), 'HEAD')
        self.assertEqual(head.get_header('Authorization'), 'Bearer T')
        self.assertIn('application/vnd.oci.image.index.v1+json', head.get_header('Accept'))

        def no_digest(request, timeout=30):
            return Reply(json.dumps({'token': 'T'}).encode()) if 'token' in request.full_url else Reply(headers={})
        with self.assertRaises(pins.PinError):
            pins.resolve('redis', 'alpine', opener=no_digest)


class BumpFlowTests(unittest.TestCase):
    """How a pin moves: documented, and the weekly tool check reports a moved tag."""

    def test_the_docs_say_how_to_bump(self):
        text = (ROOT / 'docs' / 'UPDATES.md').read_text()
        self.assertIn('python3 scripts/image_pins.py bump', text)
        self.assertIn('python3 scripts/scanner_lock.py bump', text)

    def test_ci_checks_the_pins_and_the_weekly_job_reports_moved_tags(self):
        build = (ROOT / '.github' / 'workflows' / 'build-pr.yml').read_text()
        self.assertIn('python3 scripts/image_pins.py check', build)
        weekly = (ROOT / '.github' / 'workflows' / 'tool-releases.yml').read_text()
        self.assertIn('python3 scripts/image_pins.py check --remote', weekly)
