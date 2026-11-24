#!/usr/bin/env python3
"""The built-in scanner image this release runs, pinned by digest, and the Sentinel commit it and the server's scanner library come from: scanner.lock.json,
and the commands the scripts, the Makefile and CI read it with.

  python3 scripts/scanner_lock.py ref                    the image reference compose runs by default (image@sha256:..., the pin)
  python3 scripts/scanner_lock.py floor                  the Sentinel commit of the pin (40 characters; web/requirements.txt installs the same one)
  python3 scripts/scanner_lock.py contract-floor         the lowest result-contract version a built-in scanner may check in with
  python3 scripts/scanner_lock.py accepts N [SERVER_VERSION SERVER_MIN]
                                                         exit 0 when a scanner that declares contract N is acceptable (N is not below the floor and
                                                         not below what the server still speaks); says why on stderr when not
  python3 scripts/scanner_lock.py digest                 the pinned image's digest
  python3 scripts/scanner_lock.py source                 the git build context of the from-source fallback (repository#commit)
  python3 scripts/scanner_lock.py local                  the local tag a from-source build is given
  python3 scripts/scanner_lock.py check [--remote]       exit 1 when an invariant is broken (below); --remote also asks GitHub and the registry
  python3 scripts/scanner_lock.py bump [--commit C] [--contract N]
                                                         move the pin to commit C (default: the tip of the Sentinel's main branch): looks up the
                                                         digest of the image published from it (tag sha-<12>), and writes it here, in
                                                         docker-compose.yml and in web/requirements.txt, for a pull request
  python3 scripts/scanner_lock.py raise-floor --commit C --contract N --digest sha256:...
                                                         the same with every value given (offline); the contract only moves up

The built-in scanner runs EXACTLY the image this file pins (``image@floor.digest``, the multi-platform index the Sentinel's publish workflow pushed
for ``floor.commit``), and the server image installs the Sentinel library at the same commit (web/requirements.txt). Nothing on a host follows a
moving tag: an update pulls the pinned digest of the commit it installs, so a new Sentinel reaches a server only through a pull request here that
ran ``bump`` (docs/UPDATES.md, "Pinned images"). ``tag`` is the branch tag a bump reads the newest commit of (``main``), never what a host runs.
``floor.contract_version`` is the result contract that commit speaks: the update routine keeps a scanner only when it checks in at or above it.
``make scanner-build`` builds the pinned commit from source, the offline fallback.

``check`` proves, offline: the file is well formed; docker-compose.yml's default scanner image is exactly ``image@floor.digest``; web/requirements.txt
installs the library from ``floor.commit``; and the contract version is not above the one the server reads (the installed library's, which
``agentapi.sentinel_contract`` reads). ``--remote`` adds: the commit is on the Sentinel repository's main branch, and the registry's ``sha-<12>`` tag
names the pinned digest.

The operator who wants another image sets CVENGINE_SCANNER_IMAGE in .env to a digest or tag; the update scripts then never pull over it.
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
REQUIREMENTS = ROOT / 'web' / 'requirements.txt'
LIBRARY = re.compile(r'(?m)^(cvengine-scanner @ git\+https://github\.com/hevnsnt/cvENGINE-sentinel@)([0-9a-f]{40})')
LOCAL_IMAGE = 'cvengine-sentinel-local'
DIGEST = re.compile(r'^sha256:[0-9a-f]{64}$')
VERSION = re.compile(r'^[0-9a-f]{12}$')
COMMIT = re.compile(r'^[0-9a-f]{40}$')
IMAGE = re.compile(r'^[a-z0-9.-]+(:[0-9]{1,5})?(/[a-z0-9._-]+)+$')  # a registry may name a port (a local registry for a rehearsal)
TAG = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$')
DEFAULT = re.compile(r'(\$\{CVENGINE_SCANNER_IMAGE:-\$\{CVENGINE_SCANNER_ROLLBACK_IMAGE:-)([^}]*)(\}\})')
MOVING_TAG = 'main'  # the branch a bump reads; the Sentinel repository's publish workflow also tags every build sha-<first 12 of the commit>


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
        raise LockError('scanner.lock.json: "tag" must be a tag (the branch tag a bump reads), never a digest')
    floor = data.get('floor') if isinstance(data.get('floor'), dict) else {}
    if not COMMIT.match(str(floor.get('commit') or '')):
        raise LockError('scanner.lock.json: "floor.commit" must be a full 40-character Sentinel commit')
    if not VERSION.match(str(floor.get('version') or '')) or not floor['commit'].startswith(floor['version']):
        raise LockError('scanner.lock.json: "floor.version" must be the first 12 characters of floor.commit')
    contract = floor.get('contract_version')
    if isinstance(contract, bool) or not isinstance(contract, int) or contract < 1:
        raise LockError('scanner.lock.json: "floor.contract_version" must be a whole number of at least 1')
    if not DIGEST.match(str(floor.get('digest') or '')):
        raise LockError('scanner.lock.json: "floor.digest" must be sha256:<64 hex>: the image the scanner runs is pinned by digest')
    source = data.get('source') if isinstance(data.get('source'), dict) else {}
    if not str(source.get('repository') or '').startswith('https://'):
        raise LockError('scanner.lock.json: "source.repository" must be an https repository')


def ref(data):
    return f'{data["image"]}@{data["floor"]["digest"]}'


def published_tag(data, commit=None):
    """The tag the Sentinel's publish workflow gave the image of ``commit`` (default: the pinned one)."""
    return f'sha-{(commit or floor_commit(data))[:12]}'


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


def library_commit(text):
    """The Sentinel commit web/requirements.txt installs the server's library from, or None."""
    found = LIBRARY.search(text)
    return found.group(2) if found else None


def remote_check(data):
    """The pinned commit is the tip of, or behind, the Sentinel repository's main branch: ``(ok, why)``."""
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


def check(data, compose_text, remote=False, server=None, requirements_text=None, resolver=None):
    """Every broken invariant, as sentences (an empty list is a pass)."""
    problems = []
    found = compose_default(compose_text)
    if found is None:
        problems.append('docker-compose.yml has no scanner image default')
    elif found != ref(data):
        problems.append(f'docker-compose.yml runs {found!r} by default, not the pinned image {ref(data)!r} scanner.lock.json names')
    if found and '@sha256:' not in found:
        problems.append('the compose default must be pinned by digest, never a moving tag (python3 scripts/scanner_lock.py bump)')
    if data['tag'] != MOVING_TAG:
        problems.append(f'the tag is {data["tag"]!r}: a bump reads the newest commit of {MOVING_TAG!r}')
    if requirements_text is not None:
        library = library_commit(requirements_text)
        if library != floor_commit(data):
            problems.append(f'web/requirements.txt installs the Sentinel library from {library!r}, not the pinned commit {floor_commit(data)!r}: '
                            'the scanner image and the server library move together (python3 scripts/scanner_lock.py bump)')
    pair = server if server is not None else server_contract()
    if pair is not None and contract_floor(data) > pair[0]:
        problems.append(f'floor.contract_version {contract_floor(data)} is above the contract version {pair[0]} this server reads')
    if remote:
        ok, why = remote_check(data)
        if not ok:
            problems.append(why)
        published = (resolver or _resolver())(data['image'], published_tag(data))
        if published != data['floor']['digest']:
            problems.append(f'{data["image"]}:{published_tag(data)} names {published}, not the pinned {data["floor"]["digest"]}')
    return problems


def _resolver():
    """scripts/image_pins.py's registry lookup (the digest a tag names now, nothing pulled)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location('image_pins', Path(__file__).resolve().parent / 'image_pins.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.resolve


def raise_floor(data, commit, contract, digest):
    if contract < contract_floor(data):
        raise LockError(f'the floor only moves up: contract {contract} is below {contract_floor(data)}')
    out = {**data, 'floor': {'commit': commit, 'version': commit[:12], 'contract_version': contract, 'digest': digest}}
    validate(out)
    return out


def write_pin(new, root=ROOT):
    """Write the pin ``new`` to scanner.lock.json, the compose default and web/requirements.txt (one pull request moves all three)."""
    root = Path(root)
    compose = (root / 'docker-compose.yml').read_text(encoding='utf-8')
    if compose_default(compose) is None:
        raise LockError('docker-compose.yml has no scanner image default')
    compose = DEFAULT.sub(lambda m: m.group(1) + ref(new) + m.group(3), compose, count=1)
    requirements = (root / 'web' / 'requirements.txt').read_text(encoding='utf-8')
    if library_commit(requirements) is None:
        raise LockError('web/requirements.txt does not install cvengine-scanner from a Sentinel commit')
    requirements = LIBRARY.sub(lambda m: m.group(1) + floor_commit(new), requirements, count=1)
    (root / 'scanner.lock.json').write_text(json.dumps(new, indent=2) + '\n', encoding='utf-8')
    (root / 'docker-compose.yml').write_text(compose, encoding='utf-8')
    (root / 'web' / 'requirements.txt').write_text(requirements, encoding='utf-8')


def tip_commit(data):
    """The newest commit of the Sentinel repository's main branch (``git ls-remote``)."""
    import subprocess
    out = subprocess.run(['git', 'ls-remote', data['source']['repository'], f'refs/heads/{MOVING_TAG}'], capture_output=True, text=True, timeout=60)
    sha = out.stdout.split()[0] if out.returncode == 0 and out.stdout.split() else ''
    if not COMMIT.match(sha):
        raise LockError(f'could not read the tip of {MOVING_TAG} of {data["source"]["repository"]}')
    return sha


def bump(data, commit=None, contract=None, resolver=None, root=ROOT):
    """Pin ``commit`` (default: the tip of main): its published image's digest, the same commit for the library. Returns the new lock."""
    commit = commit or tip_commit(data)
    if not COMMIT.match(commit):
        raise LockError('--commit must be a full 40-character Sentinel commit')
    digest = (resolver or _resolver())(data['image'], published_tag(data, commit))
    new = raise_floor(data, commit, contract_floor(data) if contract is None else contract, digest)
    write_pin(new, root)
    return new


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
            problems = check(data, COMPOSE.read_text(encoding='utf-8'), remote='--remote' in rest, requirements_text=REQUIREMENTS.read_text(encoding='utf-8'))
            for line in problems:
                print(line, file=sys.stderr)
            return 1 if problems else 0
        elif command == 'raise-floor':
            opts = dict(zip(rest[::2], rest[1::2]))
            if len(rest) % 2 or set(opts) - {'--commit', '--contract', '--digest'} or not {'--commit', '--contract', '--digest'} <= set(opts) \
                    or not opts['--contract'].isdigit():
                print('usage: scanner_lock.py raise-floor --commit C --contract N --digest sha256:...', file=sys.stderr)
                return 2
            new = raise_floor(data, opts['--commit'], int(opts['--contract']), opts['--digest'])
            write_pin(new, LOCK.parent)
            print(ref(new))
        elif command == 'bump':
            opts = dict(zip(rest[::2], rest[1::2]))
            if len(rest) % 2 or set(opts) - {'--commit', '--contract'} or not opts.get('--contract', '1').isdigit():
                print('usage: scanner_lock.py bump [--commit C] [--contract N]', file=sys.stderr)
                return 2
            new = bump(data, opts.get('--commit'), int(opts['--contract']) if '--contract' in opts else None, root=LOCK.parent)
            print(f'{floor_commit(new)} {ref(new)}')
            print('Now read the Sentinel pins again for the About page (web/cveFeed/software.py, SENTINEL_PINS_COMMIT) and run the tests.')
        else:
            print(__doc__, file=sys.stderr)
            return 2
    except (OSError, ValueError, urllib.error.URLError) as exc:
        print(f'scanner_lock.py: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
