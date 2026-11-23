"""The application image runs a Python without the incremental cyclic garbage collector.

CPython 3.14.0 to 3.14.4 shipped an incremental collector that 3.14.5 reverted to the generational one of 3.13 (python.org, Python 3.14.5 release
notes). Under the gevent pool of the celery workers it crashed the process with "Fatal Python error: Segmentation fault" inside the collector, and
Ubuntu 26.04 ships 3.14.4, so web/Dockerfile installs a pinned CPython instead of the distribution's. CI runs the tests on another Python, so these
checks read the Dockerfile itself.
"""
import re
from pathlib import Path

from django.test import SimpleTestCase

WEB = Path(__file__).resolve().parent.parent
DOCKERFILE = WEB / 'Dockerfile'


def incremental_gc(version):
    """True for a CPython release that has the incremental collector (3.14.0 to 3.14.4, and the 3.14 pre-releases)."""
    match = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)((?:a|b|rc)\d+)?', version)
    if not match:
        raise ValueError(f'not a full CPython version: {version}')
    major, minor, micro = (int(match.group(n)) for n in (1, 2, 3))
    return (major, minor) == (3, 14) and micro <= 4


class ImagePythonTests(SimpleTestCase):
    def setUp(self):
        self.text = DOCKERFILE.read_text(encoding='utf-8')

    def test_the_pinned_python_is_not_a_release_with_the_incremental_collector(self):
        match = re.search(r'(?m)^ARG PYTHON_VERSION=(\S+)$', self.text)
        self.assertIsNotNone(match, 'web/Dockerfile pins no PYTHON_VERSION')
        self.assertFalse(incremental_gc(match.group(1)), f'web/Dockerfile pins Python {match.group(1)}, a release with the incremental collector')

    def test_the_image_installs_no_distribution_python(self):
        # Ubuntu 26.04's python3 is 3.14.4: the venv and every `python3` the entrypoints run must be the pinned one
        installs = ' '.join(re.findall(r'apt-get install\s+([^&|;)\n]*(?:\\\n[^&|;)\n]*)*)', self.text))
        self.assertNotRegex(installs, r'\bpython3(?:\.\d+)?(?:-(?:dev|venv|pip))?\b')
        self.assertIn('/opt/python/bin/python3 -m venv /opt/venv', self.text)

    def test_the_build_refuses_a_bad_interpreter(self):
        self.assertGreaterEqual(self.text.count('(3, 14) and v[2] <= 4'), 2)  # the python stage and the venv both check what they got

    def test_the_version_rule(self):
        for bad in ('3.14.0', '3.14.4', '3.14.0rc3'):
            self.assertTrue(incremental_gc(bad), bad)
        for good in ('3.14.5', '3.14.10', '3.13.9', '3.12.12', '3.15.0'):
            self.assertFalse(incremental_gc(good), good)
