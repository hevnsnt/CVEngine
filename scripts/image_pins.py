#!/usr/bin/env python3
"""The stock images this repository builds on and runs, pinned by digest: what they are, a check, and the one way to move them (a pull request).

  python3 scripts/image_pins.py list                     every pinned reference: file, line, image, tag, digest
  python3 scripts/image_pins.py check                    exit 1 when a stock image is referenced by tag alone, or one image:tag carries two
                                                         different digests in two places (offline)
  python3 scripts/image_pins.py check --remote [--fail-if-behind]
                                                         also asks each registry which digest the tag names today and lists the pins that
                                                         are behind it (a report; it fails only with --fail-if-behind)
  python3 scripts/image_pins.py bump [IMAGE ...] [--dry-run]
                                                         rewrite the pins of IMAGE (all when none is named, for example `nginx` or
                                                         `ghcr.io/astral-sh/uv`) to the digest their tag names today, in every file

A pin is written ``image:tag@sha256:<64 hex>``: Docker uses the digest and ignores the tag, which stays for the reader and for the next bump. The
digest is the one of the multi-platform index, so amd64 and arm64 hosts pull the same pinned release. What is pinned here:

  * the ``FROM`` lines of web/Dockerfile and reviewer/Dockerfile (ubuntu, the uv build stage, the reviewer's python base);
  * the ``image:`` lines of docker-compose.yml and docker-compose.dev.yml for the stock services (postgres, redis, nginx).

The built-in scanner's image is pinned the same way, but in scanner.lock.json, together with the Sentinel library commit web/requirements.txt installs
(scripts/scanner_lock.py; ``scanner_lock.py bump`` moves both). The Tailscale sidecar keeps its version tag (TAILSCALE_IMAGE, checked by
scripts/check_tool_versions.py). Nothing on a host ever resolves a tag: an update pulls exactly the digests of the commit it installs, so a new
nginx, Redis, PostgreSQL, Ubuntu or uv release reaches a server only through a reviewed pull request that ran this script (docs/UPDATES.md,
"Pinned images").
"""
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = ('web/Dockerfile', 'reviewer/Dockerfile', 'docker-compose.yml', 'docker-compose.dev.yml')
# A stock image of a public registry: optional registry host, a path, a tag, then optionally the digest. Our own images (cvengine/web:latest,
# cvengine-reviewer-local) and references built from variables (the scanner, Tailscale) are not stock images and are never matched.
STOCK = ('ubuntu', 'ghcr.io/astral-sh/uv', 'python', 'postgres', 'redis', 'nginx')
REF = re.compile(r'(?P<image>(?:[a-z0-9.-]+(?::[0-9]+)?/)?[a-z0-9._-]+(?:/[a-z0-9._-]+)*):(?P<tag>[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})'
                 r'(?:@(?P<digest>sha256:[0-9a-f]{64}))?')
LINE = {
    'Dockerfile': re.compile(r'^(?P<lead>FROM\s+(?:--platform=\S+\s+)?)(?P<ref>\S+)'),
    'compose': re.compile(r'^(?P<lead>\s*image:\s*"?)(?P<ref>[^"\s#]+)'),
}
DIGEST = re.compile(r'^sha256:[0-9a-f]{64}$')
ACCEPT = ', '.join(('application/vnd.oci.image.index.v1+json', 'application/vnd.docker.distribution.manifest.list.v2+json',
                    'application/vnd.oci.image.manifest.v1+json', 'application/vnd.docker.distribution.manifest.v2+json'))


class PinError(ValueError):
    pass


def _kind(name):
    return 'Dockerfile' if name.endswith('Dockerfile') else 'compose'


def references(root=ROOT, files=FILES):
    """Every stock image reference in the pinned files: dicts of file, line (1-based), image, tag, digest (None when the tag stands alone)."""
    found = []
    for name in files:
        path = Path(root) / name
        if not path.is_file():
            continue
        for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            match = LINE[_kind(name)].match(line)
            if not match:
                continue
            ref = REF.fullmatch(match.group('ref'))
            if not ref or ref.group('image') not in STOCK:
                continue
            found.append({'file': name, 'line': number, 'image': ref.group('image'), 'tag': ref.group('tag'), 'digest': ref.group('digest')})
    return found


def check(refs):
    """Every broken rule, as sentences (an empty list is a pass)."""
    problems = []
    seen = {}
    for ref in refs:
        where = f'{ref["file"]}:{ref["line"]}'
        name = f'{ref["image"]}:{ref["tag"]}'
        if not ref['digest']:
            problems.append(f'{where}: {name} is a tag alone; pin it by digest (python3 scripts/image_pins.py bump {ref["image"]})')
            continue
        other = seen.setdefault(name, (ref['digest'], where))
        if other[0] != ref['digest']:
            problems.append(f'{where}: {name} is pinned to {ref["digest"][:19]}, but {other[1]} pins it to {other[0][:19]}')
    if not refs:
        problems.append('no stock image reference found: the pinned files moved or their syntax changed')
    return problems


def registry(image):
    """``(registry host, repository path, token URL)`` of an image name: Docker Hub (``library/`` for the official images) or a named registry."""
    first, _, rest = image.partition('/')
    if rest and ('.' in first or ':' in first):
        return first, rest, f'https://{first}/token?scope=repository:{rest}:pull'
    path = image if rest else f'library/{image}'
    return 'registry-1.docker.io', path, f'https://auth.docker.io/token?service=registry.docker.io&scope=repository:{path}:pull'


def _open(request, timeout=30):
    return urllib.request.urlopen(request, timeout=timeout)


def resolve(image, tag, opener=_open):
    """The digest the registry serves for ``image:tag`` now (the multi-platform index when there is one), without pulling anything."""
    host, path, token_url = registry(image)
    with opener(urllib.request.Request(token_url, headers={'User-Agent': 'cvengine-image-pins'})) as response:
        token = json.load(response).get('token') or ''
    request = urllib.request.Request(f'https://{host}/v2/{path}/manifests/{tag}', method='HEAD',
                                     headers={'Accept': ACCEPT, 'Authorization': f'Bearer {token}', 'User-Agent': 'cvengine-image-pins'})
    with opener(request) as response:
        digest = (response.headers.get('Docker-Content-Digest') or '').strip()
    if not DIGEST.match(digest):
        raise PinError(f'{image}:{tag}: the registry answered no digest')
    return digest


def rewrite(text, kind, wanted):
    """``text`` with every stock reference whose ``(image, tag)`` is in ``wanted`` pinned to ``wanted[(image, tag)]``; returns (text, count)."""
    pattern = LINE[kind]
    out, changed = [], 0
    for line in text.splitlines(keepends=True):
        match = pattern.match(line)
        ref = REF.fullmatch(match.group('ref')) if match else None
        key = (ref.group('image'), ref.group('tag')) if ref else None
        if key in wanted and ref.group('digest') != wanted[key]:
            start, end = match.span('ref')
            line = line[:start] + f'{key[0]}:{key[1]}@{wanted[key]}' + line[end:]
            changed += 1
        out.append(line)
    return ''.join(out), changed


def bump(names=(), root=ROOT, resolver=resolve, dry_run=False):
    """Pin every reference of the named images (all stock images when ``names`` is empty) to today's digest of its tag. Returns lines to print."""
    refs = references(root)
    unknown = set(names) - {r['image'] for r in refs}
    if unknown:
        raise PinError('not a pinned image here: ' + ', '.join(sorted(unknown)))
    keys = sorted({(r['image'], r['tag']) for r in refs if not names or r['image'] in names})
    wanted = {key: resolver(*key) for key in keys}
    lines = []
    for name in FILES:
        path = Path(root) / name
        if not path.is_file():
            continue
        text, count = rewrite(path.read_text(encoding='utf-8'), _kind(name), wanted)
        if count:
            lines.append(f'{name}: {count} pin{"s" if count != 1 else ""} moved')
            if not dry_run:
                path.write_text(text, encoding='utf-8')
    for (image, tag), digest in wanted.items():
        lines.append(f'{image}:{tag} -> {digest}')
    return lines


def behind(refs, resolver=resolve):
    """``[(ref, today's digest)]`` for every pin whose tag now names another digest (one registry question per image:tag)."""
    today = {}
    out = []
    for ref in refs:
        key = (ref['image'], ref['tag'])
        if key not in today:
            today[key] = resolver(*key)
        if ref['digest'] and ref['digest'] != today[key]:
            out.append((ref, today[key]))
    return out


def main(argv, root=ROOT, resolver=resolve):
    if not argv or argv[0] not in ('list', 'check', 'bump'):
        print(__doc__, file=sys.stderr)
        return 2
    command, rest = argv[0], argv[1:]
    try:
        if command == 'list':
            for ref in references(root):
                print(f'{ref["file"]}:{ref["line"]}\t{ref["image"]}:{ref["tag"]}\t{ref["digest"] or "(tag only)"}')
            return 0
        if command == 'check':
            unknown = set(rest) - {'--remote', '--fail-if-behind'}
            if unknown:
                print(__doc__, file=sys.stderr)
                return 2
            refs = references(root)
            problems = check(refs)
            for line in problems:
                print(line, file=sys.stderr)
            if problems:
                return 1
            if '--remote' in rest:
                late = behind(refs, resolver)
                for ref, digest in late:
                    print(f'{ref["file"]}:{ref["line"]}: {ref["image"]}:{ref["tag"]} is pinned to {ref["digest"][:19]}; the tag now names {digest[:19]} '
                          f'(python3 scripts/image_pins.py bump {ref["image"]})')
                if late and '--fail-if-behind' in rest:
                    return 1
            return 0
        dry = '--dry-run' in rest
        names = [a for a in rest if a != '--dry-run']
        if any(a.startswith('-') for a in names):
            print(__doc__, file=sys.stderr)
            return 2
        for line in bump(names, root, resolver, dry):
            print(line)
        return 0
    except (OSError, ValueError, urllib.error.URLError) as exc:
        print(f'image_pins.py: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
