#!/usr/bin/env python3
"""The built-in scanner image this release runs, and the known-good floor it was tested with: scanner.lock.json, and the commands the scripts, the
Makefile and CI read it with.

  python3 scripts/scanner_lock.py ref                    the image reference compose runs by default (image:tag, the moving tag)
  python3 scripts/scanner_lock.py floor                  the Sentinel commit the release was tested with (40 characters)
  python3 scripts/scanner_lock.py contract-floor         the lowest result-contract version a built-in scanner may check in with
  python3 scripts/scanner_lock.py accepts N [SERVER_VERSION SERVER_MIN]
                                                         exit 0 when a scanner that declares contract N is acceptable (N is not below the floor and
                                                         not below what the server still speaks); says why on stderr when not
  python3 scripts/scanner_lock.py digest                 the floor image's digest (provenance), exit 1 when none is recorded
  python3 scripts/scanner_lock.py source                 the git build context of the from-source fallback (repository#floor commit)
  python3 scripts/scanner_lock.py local                  the local tag a from-source build is given
  python3 scripts/scanner_lock.py check [--remote]       exit 1 when an invariant is broken (below); --remote also asks GitHub
  python3 scripts/scanner_lock.py raise-floor --commit C --contract N [--digest sha256:...]
                                                         move the floor up to a newer tested commit (never needed for the scanner to update)

The built-in scanner FOLLOWS the newest published Sentinel: docker-compose.yml runs ``image:tag`` (the lock's ``tag``, ``main``: the newest build of the
Sentinel repository's main branch, which only receives code after its checks pass), and the update scripts pull it again at every update and on a
schedule (scripts/scanner.sh). Nothing is pinned by digest any more, so no person has to approve a new image for a fresh install to get a fix.

The lock is the KNOWN-GOOD FLOOR instead: ``floor.commit`` is a Sentinel commit this release was tested with, ``floor.contract_version`` the result
contract that commit speaks (the update routine keeps a new image only when it checks in at or above it), and ``floor.digest`` (optional) the image
that commit was published as, kept for provenance. ``make scanner-build`` builds the floor commit from source, the offline fallback.

``check`` proves, offline: the file is well formed; docker-compose.yml's default scanner image is the moving ``image:tag`` this file names (and not a
digest, so the default can never go stale); and the floor's contract version is not above the one the server reads (the installed library's, which
``agentapi.sentinel_contract`` reads: a floor above it would mean the release insists on a scanner newer than its own server understands).
``--remote`` adds: the floor commit exists on the Sentinel repository's main branch (it is the tip of it or behind it).

The operator who wants to hold a version sets CVENGINE_SCANNER_IMAGE in .env to a digest or tag; the update scripts then never pull over it.
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / 'scanner.lock.json'
COMPOSE = ROOT / 'docker-compose.yml'
LOCAL_IMAGE = 'cvengine-sentinel-local'
DIGEST = re.compile(r'^sha256:[0-9a-f]{64}$')
VERSION = re.compile(r'^[0-9a-f]{12}$')
COMMIT = re.compile(r'^[0-9a-f]{40}$')
IMAGE = re.compile(r'^[a-z0-9.-]+(:[0-9]{1,5})?(/[a-z0-9._-]+)+$')  # a registry may name a port (a local registry for a rehearsal)
TAG = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$')
DEFAULT = re.compile(r'(\$\{CVENGINE_SCANNER_IMAGE:-\$\{CVENGINE_SCANNER_ROLLBACK_IMAGE:-)([^}]*)(\}\})')
MOVING_TAG = 'main'  # what the Sentinel repository's publish workflow re-points at every build of its main branch


class LockError(ValueError):
    pass


def load(path=LOCK):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    validate(data)
    return data


def validate(data):
    if not isinstance(data, dict) or not IMAGE.match(str(data.get('image') or '')):
        raise LockError('scanner.lock.json: "image" must be a registry image name')
    if not TAG.match(str(data.get('tag') or '')):
        raise LockError('scanner.lock.json: "tag" must be an image tag (the moving tag the scanner follows), never a digest')
    floor = data.get('floor') if isinstance(data.get('floor'), dict) else {}
    if not COMMIT.match(str(floor.get('commit') or '')):
        raise LockError('scanner.lock.json: "floor.commit" must be a full 40-character Sentinel commit')
    if not VERSION.match(str(floor.get('version') or '')) or not floor['commit'].startswith(floor['version']):
        raise LockError('scanner.lock.json: "floor.version" must be the first 12 characters of floor.commit')
    contract = floor.get('contract_version')
    if isinstance(contract, bool) or not isinstance(contract, int) or contract < 1:
        raise LockError('scanner.lock.json: "floor.contract_version" must be a whole number of at least 1')
    if floor.get('digest') is not None and not DIGEST.match(str(floor['digest'])):
        raise LockError('scanner.lock.json: "floor.digest" must be sha256:<64 hex> or null')
    source = data.get('source') if isinstance(data.get('source'), dict) else {}
    if not str(source.get('repository') or '').startswith('https://'):
        raise LockError('scanner.lock.json: "source.repository" must be an https repository')


def ref(data):
    return f'{data["image"]}:{data["tag"]}'


def floor_commit(data):
    return data['floor']['commit']


def contract_floor(data):
    return data['floor']['contract_version']


def local_tag(data):
    return f'{LOCAL_IMAGE}:{data["floor"]["version"]}'


def source(data):
    return f'{data["source"]["repository"]}#{data["floor"]["commit"]}'


def compose_default(text):
    found = DEFAULT.search(text)
    return found.group(2) if found else None


def server_contract():
    """``(version, min_supported)`` the server reads, from the installed scanner library (what ``agentapi.sentinel_contract`` reads), or None where
    the library is not installed (a bare checkout: the Django tests assert this against the real thing)."""
    try:
        from cvengine_scanner import contract
    except ImportError:
        return None
    return contract.version(), contract.min_supported()


def accepts(data, declared, server_version=None, server_min=None):
    """``(ok, why)``: whether a scanner that declares result-contract version ``declared`` may be kept as the built-in scanner. The floor is this
    release's tested minimum; ``server_min`` (what the server still speaks) is the server's own refusal line. A version ABOVE the server's is fine:
    a newer scanner is offered the kinds this server knows."""
    if isinstance(declared, bool) or not isinstance(declared, int) or declared < 1:
        return False, f'it declared no usable contract version ({declared!r})'
    floor = contract_floor(data)
    if declared < floor:
        return False, f'its contract version {declared} is below the floor {floor} this release was tested with'
    if server_min is not None and declared < server_min:
        return False, f'its contract version {declared} is older than the {server_min} this server still speaks'
    return True, ''


def remote_check(data):
    """The floor commit is the tip of, or behind, the Sentinel repository's main branch: ``(ok, why)``."""
    repo = re.sub(r'^https://github\.com/|\.git$', '', data['source']['repository'])
    url = f'https://api.github.com/repos/{repo}/compare/{floor_commit(data)}...main'
    headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'cvengine-scanner-lock'}
    token = os.environ.get('GITHUB_TOKEN') or os.environ.get('GH_TOKEN')
    if token:  # CI has one; it only lifts the anonymous rate limit
        headers['Authorization'] = f'Bearer {token}'
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            status = json.load(response).get('status')
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False, f'floor commit {floor_commit(data)[:12]} is not in {repo}'
        raise
    if status in ('ahead', 'identical'):  # main is ahead of the floor, or is the floor
        return True, ''
    return False, f'floor commit {floor_commit(data)[:12]} is not on the main branch of {repo} (compare says {status})'


def check(data, compose_text, remote=False, server=None):
    """Every broken invariant, as sentences (an empty list is a pass)."""
    problems = []
    found = compose_default(compose_text)
    if found is None:
        problems.append('docker-compose.yml has no scanner image default')
    elif found != ref(data):
        problems.append(f'docker-compose.yml runs {found!r} by default, not the moving tag {ref(data)!r} scanner.lock.json names')
    if found and '@' in found:
        problems.append('the compose default must follow a tag, not a digest (an operator holds a digest in .env)')
    if data['tag'] != MOVING_TAG:
        problems.append(f'the tag is {data["tag"]!r}: the Sentinel publish workflow moves {MOVING_TAG!r} at every build of its main branch')
    pair = server if server is not None else server_contract()
    if pair is not None and contract_floor(data) > pair[0]:
        problems.append(f'floor.contract_version {contract_floor(data)} is above the contract version {pair[0]} this server reads')
    if remote:
        ok, why = remote_check(data)
        if not ok:
            problems.append(why)
    return problems


def raise_floor(data, commit, contract, digest=None):
    if contract < contract_floor(data):
        raise LockError(f'the floor only moves up: contract {contract} is below {contract_floor(data)}')
    out = {**data, 'floor': {'commit': commit, 'version': commit[:12], 'contract_version': contract, 'digest': digest}}
    validate(out)
    return out


def main(argv):
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    command, rest = argv[0], argv[1:]
    try:
        data = load()
        if command == 'ref':
            print(ref(data))
        elif command == 'floor':
            print(floor_commit(data))
        elif command == 'contract-floor':
            print(contract_floor(data))
        elif command == 'digest':
            if not data['floor'].get('digest'):
                return 1
            print(data['floor']['digest'])
        elif command == 'source':
            print(source(data))
        elif command == 'local':
            print(local_tag(data))
        elif command == 'accepts':
            if len(rest) not in (1, 3) or not all(re.fullmatch(r'-?\d+', r) for r in rest):
                print('usage: scanner_lock.py accepts N [SERVER_VERSION SERVER_MIN]', file=sys.stderr)
                return 2
            numbers = [int(r) for r in rest]
            ok, why = accepts(data, numbers[0], *(numbers[1:3] if len(numbers) == 3 else ()))
            if not ok:
                print(why, file=sys.stderr)
                return 1
        elif command == 'check':
            problems = check(data, COMPOSE.read_text(encoding='utf-8'), remote='--remote' in rest)
            for line in problems:
                print(line, file=sys.stderr)
            return 1 if problems else 0
        elif command == 'raise-floor':
            opts = dict(zip(rest[::2], rest[1::2]))
            if len(rest) % 2 or set(opts) - {'--commit', '--contract', '--digest'} or not {'--commit', '--contract'} <= set(opts) or not opts['--contract'].isdigit():
                print('usage: scanner_lock.py raise-floor --commit C --contract N [--digest sha256:...]', file=sys.stderr)
                return 2
            new = raise_floor(data, opts['--commit'], int(opts['--contract']), opts.get('--digest'))
            LOCK.write_text(json.dumps(new, indent=2) + '\n', encoding='utf-8')
            print(floor_commit(new))
        else:
            print(__doc__, file=sys.stderr)
            return 2
    except (OSError, ValueError) as exc:
        print(f'scanner_lock.py: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
