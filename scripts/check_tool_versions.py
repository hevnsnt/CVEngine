#!/usr/bin/env python3
"""Report which scanner tools the repository pins are behind their newest release.

  python3 scripts/check_tool_versions.py [--json]

Checks the nmap and WPScan versions in web/Dockerfile and the nuclei version the CI smoke test downloads in
.github/workflows/build-pr.yml (the image itself installs nuclei at its latest on every build, and its templates refresh every six hours).
Exit status is 0 whatever the answer; the weekly workflow (.github/workflows/tool-releases.yml) turns "behind" into an issue."""
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


def latest_nuclei(data):
    return str(data.get('tag_name') or '').lstrip('v') or None


def compare(name, have, latest):
    behind = bool(have and latest and version_key(have) < version_key(latest))
    return {'tool': name, 'pinned': have, 'latest': latest, 'behind': behind}


def safely(get, url, as_json=True):
    """The answer, or None when the site cannot be reached: one unreachable site must not hide the others."""
    try:
        return get(url, as_json)
    except Exception:  # noqa: BLE001 - network, HTTP and JSON errors all mean "unknown"
        return None


def collect(get=fetch):
    html = safely(get, 'https://nmap.org/dist/', False)
    wpscan = safely(get, 'https://rubygems.org/api/v1/gems/wpscan.json')
    nuclei = safely(get, 'https://api.github.com/repos/projectdiscovery/nuclei/releases/latest')
    rows = [
        compare('nmap', pinned('web/Dockerfile', r'ARG NMAPVERSION=([0-9.]+)'), latest_nmap(html) if html else None),
        compare('wpscan', pinned('web/Dockerfile', r'ARG WPSCAN_VERSION=([0-9.]+)'), latest_wpscan(wpscan) if wpscan else None),
        compare('nuclei (CI smoke test)', pinned('.github/workflows/build-pr.yml', r'nuclei_([0-9.]+)_linux_amd64'),
                latest_nuclei(nuclei) if nuclei else None),
    ]
    return rows


def report(rows):
    lines = ['| Tool | Pinned | Latest |', '| --- | --- | --- |']
    lines += [f"| {r['tool']} | {r['pinned'] or '?'} | {r['latest'] or '?'}{' (newer)' if r['behind'] else ''} |" for r in rows]
    return '\n'.join(lines)


if __name__ == '__main__':
    result = collect()
    print(json.dumps(result) if '--json' in sys.argv else report(result))
