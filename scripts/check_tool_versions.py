#!/usr/bin/env python3
"""Report which pinned scanner tools are behind their newest release.

  python3 scripts/check_tool_versions.py [--json] [--fail-if-behind]

Every tool the images are built from is pinned (web/Dockerfile, web/requirements.txt, docker-compose.yml and the nuclei version the CI smoke
test downloads). This compares each pin with the newest release: nmap, WPScan, nuclei (the image and the CI smoke test), naabu, bbot, tzdata,
wafw00f, the Go toolchain and, when the Tailscale profile is present, its sidecar image. Nuclei's templates are not pinned: they refresh at runtime.
Exit status is 0 whatever the answer, or 1 with --fail-if-behind when any tool is behind, a pin cannot be found in its file or a newest
version cannot be read (the gate fails closed: a renamed pin or an unreachable site must not pass a release; the weekly report, which
runs without the flag, shows such a row as "?" and never calls it behind). The weekly workflow (.github/workflows/tool-releases.yml) turns "behind" into an issue; the release workflows use --fail-if-behind."""
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def version_key(text):
    return tuple(int(part) for part in re.findall(r'\d+', text))


def pinned(path, pattern):
    match = re.search(pattern, (ROOT / path).read_text(encoding='utf-8'))
    return match.group(1) if match else None


def fetch(url, as_json=True):
    request = urllib.request.Request(url, headers={'User-Agent': 'cvengine-tool-check', 'Accept': 'application/json, text/html'})
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - fixed https URLs below
        body = response.read(2_000_000).decode('utf-8', 'replace')
    return json.loads(body) if as_json else body


def latest_nmap(html):
    versions = re.findall(r'nmap-(\d+\.\d+(?:\.\d+)?)\.tar\.bz2', html)
    return max(versions, key=version_key) if versions else None


def latest_wpscan(data):
    return str(data.get('version') or '') or None


def latest_go_module(data):
    """proxy.golang.org/<module>/@latest answers {"Version": "v3.11.1"}: the newest release that is not a pre-release."""
    return str(data.get('Version') or '').lstrip('v') or None


def latest_pypi(data):
    return str((data.get('info') or {}).get('version') or '') or None


def latest_go_toolchain(data):
    """go.dev/dl/?mode=json lists releases newest first: [{"version": "go1.27.3", "stable": true}, ...]."""
    for release in data if isinstance(data, list) else []:
        if release.get('stable'):
            return str(release.get('version') or '').removeprefix('go') or None
    return None


def latest_docker_tag(data):
    """The newest vX.Y.Z tag of a Docker Hub repository (the moving tags such as stable and latest are ignored)."""
    names = [t.get('name', '') for t in (data.get('results') or [])] if isinstance(data, dict) else []
    versions = [n.lstrip('v') for n in names if re.fullmatch(r'v\d+\.\d+\.\d+', n)]
    return max(versions, key=version_key) if versions else None


def compare(name, have, latest):
    behind = bool(have and latest and version_key(have) < version_key(latest))
    return {'tool': name, 'pinned': have, 'latest': latest, 'behind': behind}


def safely(get, url, as_json=True):
    """The answer, or None when the site cannot be reached: one unreachable site must not hide the others."""
    try:
        return get(url, as_json)
    except Exception:  # noqa: BLE001 - network, HTTP and JSON errors all mean "unknown"
        return None


GO_PROXY = 'https://proxy.golang.org/{}/@latest'
# (label, file, regex for the pinned version, where the newest version is read from, how to read it, optional: omit when the pin is absent)
TOOLS = [
    ('nmap', 'web/Dockerfile', r'ARG NMAPVERSION=([0-9.]+)', 'https://nmap.org/dist/', latest_nmap, False, False),
    ('wpscan', 'web/Dockerfile', r'ARG WPSCAN_VERSION=([0-9.]+)', 'https://rubygems.org/api/v1/gems/wpscan.json', latest_wpscan, True, False),
    ('nuclei', 'web/Dockerfile', r'ARG NUCLEI_VERSION=([0-9.]+)', GO_PROXY.format('github.com/projectdiscovery/nuclei/v3'),
     latest_go_module, True, False),
    ('nuclei (CI smoke test)', '.github/workflows/build-pr.yml', r'nuclei_([0-9.]+)_linux_amd64',
     GO_PROXY.format('github.com/projectdiscovery/nuclei/v3'), latest_go_module, True, False),
    ('naabu', 'web/Dockerfile', r'ARG NAABU_VERSION=([0-9.]+)', GO_PROXY.format('github.com/projectdiscovery/naabu/v2'),
     latest_go_module, True, False),
    ('bbot', 'web/Dockerfile', r'ARG BBOT_VERSION=([0-9.]+)', 'https://pypi.org/pypi/bbot/json', latest_pypi, True, False),
    ('tzdata (bbot)', 'web/Dockerfile', r'ARG TZDATA_VERSION=([0-9.]+)', 'https://pypi.org/pypi/tzdata/json', latest_pypi, True, False),
    ('wafw00f', 'web/requirements.txt', r'(?m)^wafw00f==([0-9.]+)', 'https://pypi.org/pypi/wafw00f/json', latest_pypi, True, False),
    ('go (toolchain)', 'web/Dockerfile', r'ARG GOVERSION=([0-9.]+)', 'https://go.dev/dl/?mode=json', latest_go_toolchain, True, False),
    ('tailscale (sidecar image)', 'docker-compose.yml', r'tailscale/tailscale:v([0-9.]+)',
     'https://hub.docker.com/v2/repositories/tailscale/tailscale/tags/?page_size=50&ordering=last_updated', latest_docker_tag, True, True),
]


def collect(get=fetch):
    rows, cache = [], {}
    for label, path, pattern, url, read, as_json, optional in TOOLS:
        have = pinned(path, pattern)
        if have is None and optional:
            continue  # the tool is not in this checkout (the Tailscale profile on a branch without it)
        if url not in cache:
            cache[url] = safely(get, url, as_json)
        answer = cache[url]
        rows.append(compare(label, have, read(answer) if answer else None))
    return rows


def report(rows):
    lines = ['| Tool | Pinned | Latest |', '| --- | --- | --- |']
    lines += [f"| {r['tool']} | {r['pinned'] or '?'} | {r['latest'] or '?'}{' (newer)' if r['behind'] else ''} |" for r in rows]
    return '\n'.join(lines)


def main():
    result = collect()
    print(json.dumps(result) if '--json' in sys.argv else report(result))
    if '--fail-if-behind' in sys.argv and any(r['behind'] or r['pinned'] is None or r['latest'] is None for r in result):
        sys.exit(1)


if __name__ == '__main__':
    main()
