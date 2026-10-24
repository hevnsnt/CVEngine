"""Bounded local positive/negative checks for independently reviewed HTTP fixtures.

The model cannot write these fixtures. A maintainer adds a CVE-specific JSON file
under reviewed_fixtures with provenance in a code-reviewed change. The fixture
can test a response detector; it cannot prove a real remote host is vulnerable.
"""
import hashlib
import http.server
import json
import re
import subprocess
import threading
from pathlib import Path
from urllib.parse import urlsplit

import yaml

ROOT = Path(__file__).with_name('reviewed_fixtures')
MAX_FILE = 20_000
MAX_BODY = 4_096
ALLOWED_METHODS = {'GET', 'HEAD', 'OPTIONS'}
ALLOWED_MATCHERS = {'word', 'regex', 'status'}
PATH = re.compile(r'^\{\{BaseURL\}\}/[A-Za-z0-9_./?=&%+-]*$')


def load(cve_id):
    """Return (fixture, provenance, reason); absent or unsafe fixtures never authorize execution."""
    if not re.fullmatch(r'CVE-\d{4}-\d{4,}', str(cve_id or ''), re.I):
        return None, '', 'unsupported CVE identifier for reviewed fixture'
    path = ROOT / (cve_id.upper() + '.json')
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None, '', 'no independently reviewed positive fixture for this CVE'
    except OSError:
        return None, '', 'reviewed fixture could not be read'
    if len(raw) > MAX_FILE:
        return None, '', 'reviewed fixture is too large'
    try:
        fixture = json.loads(raw)
    except (ValueError, UnicodeError):
        return None, '', 'reviewed fixture is malformed JSON'
    if not isinstance(fixture, dict) or set(fixture) != {'cve_id', 'source_url', 'reviewed_by', 'positive', 'negative'}:
        return None, '', 'reviewed fixture schema is incomplete'
    try:
        source = urlsplit(str(fixture['source_url']))
    except ValueError:
        return None, '', 'reviewed fixture provenance URL is invalid'
    if (fixture['cve_id'] != cve_id.upper() or source.scheme != 'https' or not source.hostname or
            source.username or source.password or not isinstance(fixture['reviewed_by'], str) or
            not fixture['reviewed_by'].strip() or len(fixture['reviewed_by']) > 80):
        return None, '', 'reviewed fixture provenance is invalid'
    for key in ('positive', 'negative'):
        response = fixture[key]
        if not isinstance(response, dict) or set(response) != {'status', 'body', 'headers'}:
            return None, '', f'{key} response schema is invalid'
        if (type(response['status']) is not int or response['status'] not in (200, 401, 403, 404) or
                not isinstance(response['body'], str) or len(response['body'].encode()) > MAX_BODY or
                not isinstance(response['headers'], dict) or len(response['headers']) > 12):
            return None, '', f'{key} response is outside fixture limits'
        if any(not isinstance(k, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{0,63}', k) or
               k.lower() in {'location', 'refresh'} or not isinstance(v, str) or
               len(v) > 256 or '\r' in v or '\n' in v
               for k, v in response['headers'].items()):
            return None, '', f'{key} headers are invalid'
    if fixture['positive'] == fixture['negative']:
        return None, '', 'positive and negative fixture responses are identical'
    digest = hashlib.sha256(raw).hexdigest()[:16]
    provenance = f'reviewed fixture {path.name} sha256:{digest} source:{fixture["source_url"]}'[:300]
    return fixture, provenance, ''


def supported_template(yaml_text):
    """Only one read-only HTTP response detector is supported by this fixture harness."""
    try:
        doc = yaml.safe_load(yaml_text)
    except yaml.YAMLError:
        return False
    if not isinstance(doc, dict) or set(doc) - {'id', 'info', 'http'}:
        return False
    blocks = doc.get('http')
    if not isinstance(blocks, list) or len(blocks) != 1 or not isinstance(blocks[0], dict):
        return False
    block = blocks[0]
    matchers = block.get('matchers')
    return bool(set(block) <= {'method', 'path', 'matchers', 'matchers-condition'} and
                isinstance(block.get('method', 'GET'), str) and
                block.get('method', 'GET').upper() in ALLOWED_METHODS and
                isinstance(block.get('path'), list) and len(block['path']) == 1 and
                isinstance(block['path'][0], str) and PATH.fullmatch(block['path'][0]) and
                block.get('matchers-condition', 'or') in {'and', 'or'} and
                isinstance(matchers, list) and matchers and
                all(isinstance(m, dict) and m.get('type') in ALLOWED_MATCHERS and
                    not m.get('negative') for m in matchers))


def _case(path, response, expected_path):
    from cveFeed import templategen

    class FixtureHandler(http.server.BaseHTTPRequestHandler):
        def handle_response(self):
            if self.path != expected_path:
                self.send_error(404)
                return
            self.send_response(response['status'])
            for name, value in response['headers'].items():
                self.send_header(name, value)
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(response['body'].encode())

        do_GET = handle_response
        do_HEAD = handle_response
        do_OPTIONS = handle_response

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), FixtureHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = templategen._run([templategen.NUCLEI_BIN, '-t', path, '-u',
            f'http://127.0.0.1:{server.server_port}', '-jsonl', '-silent', '-duc', '-ni',
            '-rl', '2', '-timeout', '2', '-retries', '0'], 30)
        if result.returncode != 0:
            return None, 'local Nuclei fixture execution failed'
        hits = []
        for line in result.stdout.splitlines():
            if line.strip():
                try:
                    hits.append(templategen.is_hit(json.loads(line)))
                except (ValueError, TypeError):
                    return None, 'local Nuclei fixture output was malformed'
        return any(hits), ''
    except (OSError, subprocess.TimeoutExpired):
        return None, 'local Nuclei fixture test was unavailable or timed out'
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def verify(path, yaml_text, fixture):
    """Require a positive hit and a negative miss from separate loopback responses."""
    if not supported_template(yaml_text):
        return False, 'functional fixture unsupported for this template type'
    expected_path = yaml.safe_load(yaml_text)['http'][0]['path'][0].removeprefix('{{BaseURL}}')
    positive, error = _case(path, fixture['positive'], expected_path)
    if error:
        return False, error
    if not positive:
        return False, 'positive reviewed fixture did not match'
    negative, error = _case(path, fixture['negative'], expected_path)
    if error:
        return False, error
    if negative:
        return False, 'negative reviewed fixture matched (false positive)'
    return True, 'reviewed positive and negative HTTP fixtures passed; live-host affectedness remains unknown'
