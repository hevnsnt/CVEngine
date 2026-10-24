"""Run the reviewed HTTP fixture gate with a real, pinned Nuclei binary.

This intentionally uses a generic local marker. It never approves a CVE draft
or scans an external host; CVE-specific positive fixtures remain maintainer work.
"""
import os
import sys
import tempfile
from pathlib import Path

import django

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'reNgine.settings')
django.setup()

from cveFeed import template_fixtures, templategen  # noqa: E402


DETECTOR = '''id: cvengine-local-fixture-check
info:
  name: Local fixture discriminator
  author: cvengine-test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/probe"
    matchers:
      - type: word
        words:
          - "cvengine-positive-marker-2099"
'''
RESPONSES = {
    'positive': {'status': 200, 'body': 'cvengine-positive-marker-2099', 'headers': {}},
    'negative': {'status': 200, 'body': 'ordinary response', 'headers': {}},
}


def main():
    binary = os.environ.get('CVENGINE_NUCLEI_SMOKE_BIN', '')
    if not binary or not Path(binary).is_file():
        raise SystemExit('CVENGINE_NUCLEI_SMOKE_BIN must name the verified Nuclei binary')
    templategen.NUCLEI_BIN = binary
    if templategen.static_check(DETECTOR) != (True, '') or not template_fixtures.supported_template(DETECTOR):
        raise SystemExit('the local detector does not pass the static fixture policy')
    with tempfile.TemporaryDirectory(prefix='cvengine-nuclei-smoke-') as directory:
        candidate = Path(directory) / 'local-fixture.yaml'
        candidate.write_text(DETECTOR)
        valid, detail = templategen.validate_with_nuclei(str(candidate))
        if not valid:
            raise SystemExit(f'Nuclei syntax validation failed: {detail[-300:]}')
        verified, detail = template_fixtures.verify(str(candidate), DETECTOR, RESPONSES)
        if not verified:
            raise SystemExit(f'positive/negative loopback fixture failed: {detail}')
    print('Nuclei syntax and positive/negative loopback detector smoke passed')


if __name__ == '__main__':
    main()
