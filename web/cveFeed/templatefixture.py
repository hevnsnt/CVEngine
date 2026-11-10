"""Offline matcher evaluation of an AI-written template against a fixture response.

The positive and the not-affected controls of the automatic template lifecycle (``cveFeed.templatevalidate``). Pure Python, no I/O, no
tool run: it reads the template's matchers (word, regex, status, binary, size) and says whether they would match a response given as
data. It is not the scanner: the Sentinel's syntax check and benign loopback check stay the authority on syntax and on a silent
negative, and a matcher this module cannot evaluate (a ``dsl`` expression, xpath, json, an unresolved variable in a word) raises
``Unsupported`` so the draft is rejected with that reason instead of being trusted blind.

A fixture is ``{"status": 200, "headers": {"Server": "x"}, "body": "..."}``.
"""
import re

from cveFeed.safeyaml import load_template

MAX_BODY = 20000
MAX_HEADERS = 30
HTTP_BLOCKS = ('http', 'requests')
BYTE_BLOCKS = ('network', 'tcp')

# What no vulnerable host is needed for: a plain page that says nothing about any product. A template that matches it matches everything.
BENIGN = {'status': 200, 'headers': {'Content-Type': 'text/html; charset=utf-8', 'Server': 'benign-fixture'},
          'body': '<!doctype html><html><head><title>Welcome</title></head><body><h1>It works</h1><p>Nothing to see here.</p></body></html>'}
NOT_FOUND = {'status': 404, 'headers': {'Content-Type': 'text/html'}, 'body': '<html><body><h1>404 Not Found</h1></body></html>'}


class Unsupported(Exception):
    """The template uses a matcher this evaluator cannot decide offline."""


REGEX_SECONDS = 2.0  # a matcher pattern gets this long on a fixture body, then it is given up on

_REGEX_CHILD = (
    "import json, re, sys\n"
    "data = json.load(sys.stdin)\n"
    "try:\n"
    "    out = ['ok', re.search(data['pattern'], data['text'], re.DOTALL) is not None]\n"
    "except re.error as exc:\n"
    "    out = ['error', str(exc)]\n"
    "sys.stdout.write(json.dumps(out))\n"
)


def _regex_found(pattern, text):
    """Whether ``pattern`` matches ``text`` (DOTALL), with a time limit. A model wrote the pattern and public CVE text it read may have steered it: Python's
    backtracking engine can take hours on ``(a+)+$`` against twenty thousand characters, and that would hold a worker and its database connection. The
    scanner's own engine reads the same pattern in linear time, so a pattern that is too slow here is only slow in this check. It runs in a separate
    interpreter that is killed at the limit (a thread cannot be interrupted, and a Celery child may not start a ``multiprocessing`` process) and is reported
    as a matcher this check cannot evaluate (review 2 F5). The pattern and text go in on standard input, never on a command line."""
    import json
    import subprocess
    import sys

    try:
        done = subprocess.run([sys.executable, '-I', '-c', _REGEX_CHILD], input=json.dumps({'pattern': pattern, 'text': text}), capture_output=True,
                              text=True, timeout=REGEX_SECONDS, check=False)
    except subprocess.TimeoutExpired:
        raise Unsupported(f'regex {pattern[:60]!r} took longer than {REGEX_SECONDS:g} s on the fixture and cannot be evaluated offline')
    except OSError as exc:
        raise Unsupported(f'regex {pattern[:60]!r} cannot be evaluated offline ({type(exc).__name__})')
    try:
        kind, value = json.loads(done.stdout)
    except ValueError:
        raise Unsupported(f'regex {pattern[:60]!r} cannot be evaluated offline (the check ended without an answer)')
    if kind == 'error':
        raise Unsupported(f'regex {pattern[:60]!r} cannot be evaluated offline ({value})')
    return value


def clean_fixture(value):
    """A bounded, well-formed fixture from a model's JSON object, or None when it is not one."""
    if not isinstance(value, dict):
        return None
    status = value.get('status', 200)
    body = value.get('body', '')
    headers = value.get('headers') or {}
    if isinstance(status, str) and status.strip().isdigit():
        status = int(status)
    if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
        return None
    if not isinstance(body, str) or not isinstance(headers, dict):
        return None
    clean = {}
    for key, val in list(headers.items())[:MAX_HEADERS]:
        if isinstance(key, str) and isinstance(val, (str, int)) and re.fullmatch(r'[A-Za-z0-9-]{1,60}', key):
            clean[key] = str(val)[:500]
    return {'status': status, 'headers': clean, 'body': body[:MAX_BODY]}


def _parts(fixture):
    headers = ''.join(f'{k}: {v}\r\n' for k, v in fixture['headers'].items())
    header_text = f"HTTP/1.1 {fixture['status']}\r\n{headers}"
    content_type = next((v for k, v in fixture['headers'].items() if k.lower() == 'content-type'), '')
    return {'body': fixture['body'], 'header': header_text, 'all': header_text + '\r\n' + fixture['body'],
            'response': header_text + '\r\n' + fixture['body'], 'raw': header_text + '\r\n' + fixture['body'],
            'data': fixture['body'], 'content_type': content_type, '': fixture['body']}


def _one(matcher, fixture, parts):
    kind = str(matcher.get('type', '')).lower()
    part = str(matcher.get('part', '') or '').lower()
    if part and part not in parts and part not in ('status_code',):
        raise Unsupported(f'matcher part {part!r} cannot be evaluated offline')
    text = parts.get(part, parts['body'])
    condition = str(matcher.get('condition', 'or')).lower()
    if kind == 'status':
        wanted = matcher.get('status') or []
        hit = fixture['status'] in [int(s) for s in wanted if str(s).lstrip('-').isdigit()]
    elif kind == 'word':
        words = [str(w) for w in (matcher.get('words') or [])]
        if not words:
            raise Unsupported('a word matcher without words')
        if any('{{' in w for w in words):
            raise Unsupported('a word matcher with a variable cannot be evaluated offline')
        fold = matcher.get('case-insensitive') is True
        hay = text.lower() if fold else text
        found = [(w.lower() if fold else w) in hay for w in words]
        hit = all(found) if condition == 'and' else any(found)
    elif kind == 'regex':
        patterns = [str(p) for p in (matcher.get('regex') or [])]
        if not patterns:
            raise Unsupported('a regex matcher without patterns')
        found = []
        for pattern in patterns:
            found.append(_regex_found(pattern, text))
        hit = all(found) if condition == 'and' else any(found)
    elif kind == 'binary':
        found = []
        for hexed in matcher.get('binary') or []:
            try:
                needle = bytes.fromhex(str(hexed)).decode('latin-1')
            except ValueError:
                raise Unsupported('a binary matcher that is not hexadecimal')
            found.append(needle in text.encode('utf-8', 'replace').decode('latin-1'))
        if not found:
            raise Unsupported('a binary matcher without values')
        hit = all(found) if condition == 'and' else any(found)
    elif kind == 'size':
        hit = len(text.encode('utf-8', 'replace')) in [int(s) for s in (matcher.get('size') or []) if str(s).isdigit()]
    else:
        raise Unsupported(f'a {kind or "typeless"} matcher cannot be evaluated offline')
    return (not hit) if matcher.get('negative') is True else hit


def matches(yaml_text, fixture):
    """Whether the template's matchers match ``fixture``: True when any request block does. Raises ``Unsupported`` for a template it
    cannot evaluate (no http or network block, a dsl matcher, ...)."""
    doc = load_template(yaml_text)
    if not isinstance(doc, dict):
        raise Unsupported('the template is not a mapping')
    parts = _parts(fixture)
    blocks = [b for proto in HTTP_BLOCKS + BYTE_BLOCKS for b in (doc.get(proto) or []) if isinstance(b, dict)]
    if not blocks:
        raise Unsupported('only http and network checks can be tested against a fixture')
    for block in blocks:
        results = [_one(m, fixture, parts) for m in (block.get('matchers') or []) if isinstance(m, dict) and not m.get('internal')]
        if not results:
            raise Unsupported('a request block without matchers')
        if (all(results) if str(block.get('matchers-condition', 'or')).lower() == 'and' else any(results)):
            return True
    return False
