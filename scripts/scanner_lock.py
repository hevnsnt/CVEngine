#!/usr/bin/env python3
"""The built-in scanner image this release runs: scanner.lock.json, and the commands the scripts and the Makefile read it with.

  python3 scripts/scanner_lock.py ref                    the image reference compose runs (image@digest, or the local source build)
  python3 scripts/scanner_lock.py source                 the git build context of the from-source fallback (repository#commit)
  python3 scripts/scanner_lock.py local                  the local tag a from-source build is given
  python3 scripts/scanner_lock.py published              exit 0 when the lock pins a published digest
  python3 scripts/scanner_lock.py pin --digest sha256:... --version V [--commit C]
                                                         pin a published image (the digest the Sentinel repository's publish workflow prints)
  python3 scripts/scanner_lock.py check                  exit 1 when docker-compose.yml's default differs from the lock

The lock pins the cvENGINE Sentinel image (hevnsnt/cvENGINE-sentinel) by DIGEST, never by tag: a tag can move, a digest cannot, so a release
always runs the scanner it was tested with. ``version`` is the Sentinel commit the image reports (12 characters) and ``source`` the commit it was
built from, for `make scanner-build`, which builds the same scanner from source. While ``digest`` is null (no published image yet) compose runs the
local source build, tagged ``cvengine-sentinel-local:<version>``, and the update scripts build it when it is missing.

docker-compose.yml repeats the reference as the default of its scanner image (``${CVENGINE_SCANNER_IMAGE:-${CVENGINE_SCANNER_ROLLBACK_IMAGE:-REF}}``)
so a plain `docker compose up` runs the pinned image too; ``pin`` rewrites both and ``check`` (a test runs it) keeps them equal.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / 'scanner.lock.json'
COMPOSE = ROOT / 'docker-compose.yml'
LOCAL_IMAGE = 'cvengine-sentinel-local'
DIGEST = re.compile(r'^sha256:[0-9a-f]{64}$')
VERSION = re.compile(r'^[0-9a-f]{12}$')
COMMIT = re.compile(r'^[0-9a-f]{40}$')
IMAGE = re.compile(r'^[a-z0-9.-]+(/[a-z0-9._-]+)+$')
DEFAULT = re.compile(r'(\$\{CVENGINE_SCANNER_IMAGE:-\$\{CVENGINE_SCANNER_ROLLBACK_IMAGE:-)([^}]*)(\}\})')


class LockError(ValueError):
    pass


def load(path=LOCK):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    validate(data)
    return data


def validate(data):
    if not isinstance(data, dict) or not IMAGE.match(str(data.get('image') or '')):
        raise LockError('scanner.lock.json: "image" must be a registry image name')
    if data.get('digest') is not None and not DIGEST.match(str(data['digest'])):
        raise LockError('scanner.lock.json: "digest" must be sha256:<64 hex> or null')
    if not VERSION.match(str(data.get('version') or '')):
        raise LockError('scanner.lock.json: "version" must be the 12-character Sentinel commit')
    source = data.get('source') if isinstance(data.get('source'), dict) else {}
    if not str(source.get('repository') or '').startswith('https://') or not COMMIT.match(str(source.get('commit') or '')):
        raise LockError('scanner.lock.json: "source" must name an https repository and a full commit')
    if not source['commit'].startswith(data['version']):
        raise LockError('scanner.lock.json: "version" must be the start of the source commit')


def local_tag(data):
    return f'{LOCAL_IMAGE}:{data["version"]}'


def ref(data):
    return f'{data["image"]}@{data["digest"]}' if data.get('digest') else local_tag(data)


def source(data):
    return f'{data["source"]["repository"]}#{data["source"]["commit"]}'


def compose_default(text):
    found = DEFAULT.search(text)
    return found.group(2) if found else None


def pin(data, digest, version, commit=None):
    out = {**data, 'digest': digest, 'version': version}
    if commit:
        out['source'] = {**data['source'], 'commit': commit}
    elif not data['source']['commit'].startswith(version):
        raise LockError('a new version needs --commit (the full Sentinel commit it was built from)')
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
        elif command == 'source':
            print(source(data))
        elif command == 'local':
            print(local_tag(data))
        elif command == 'published':
            return 0 if data.get('digest') else 1
        elif command == 'check':
            found = compose_default(COMPOSE.read_text(encoding='utf-8'))
            if found != ref(data):
                print(f'docker-compose.yml runs {found!r} by default but scanner.lock.json pins {ref(data)!r}; run scripts/scanner_lock.py pin',
                      file=sys.stderr)
                return 1
        elif command == 'pin':
            opts = dict(zip(rest[::2], rest[1::2]))
            if len(rest) % 2 or set(opts) - {'--digest', '--version', '--commit'} or not {'--digest', '--version'} <= set(opts):
                print('usage: scanner_lock.py pin --digest sha256:... --version V [--commit C]', file=sys.stderr)
                return 2
            new = pin(data, opts['--digest'], opts['--version'], opts.get('--commit'))
            text = COMPOSE.read_text(encoding='utf-8')
            if compose_default(text) is None:
                raise LockError('docker-compose.yml has no scanner image default to rewrite')
            LOCK.write_text(json.dumps(new, indent=2) + '\n', encoding='utf-8')
            COMPOSE.write_text(DEFAULT.sub(lambda m: m.group(1) + ref(new) + m.group(3), text, count=1), encoding='utf-8')
            print(ref(new))
        else:
            print(__doc__, file=sys.stderr)
            return 2
    except (OSError, ValueError) as exc:
        print(f'scanner_lock.py: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
