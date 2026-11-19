#!/usr/bin/env python3
"""Refresh the vendored Rapid7 Recog fingerprint databases in web/cveFeed/data/recog/ from one pinned upstream commit.

Recog (https://github.com/rapid7/recog, BSD-2-Clause) maps banners to product, version and CPE. cvENGINE runs its XML databases on the server,
over the banners it already stored (cveFeed.recog). Only the databases cveFeed.recog.DATABASES reads are kept, with Recog's LICENSE; no Ruby
code. Run by hand when you want a newer Recog (it needs the network: each file is downloaded from raw.githubusercontent.com at that commit), review the diff, run the
Recog tests (web/tests/test_recog.py: every loaded fingerprint must match its own examples), and commit the output:

    python3 scripts/update_recog.py <full commit sha> [<commit date>]   # pin a new commit
    python3 scripts/update_recog.py                                     # fetch the commit already pinned in manifest.json again

It writes the XML files, LICENSE and COPYING, manifest.json (the commit, its date and the SHA-256 of every file, which the tests check) and README.md.
"""
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / 'web' / 'cveFeed' / 'data' / 'recog'
REPO = 'rapid7/recog'
# the databases cveFeed.recog reads (keep in step with cveFeed.recog.DATABASES)
FILES = ('http_servers.xml', 'http_cookies.xml', 'ssh_banners.xml', 'smtp_banners.xml', 'ftp_banners.xml', 'snmp_sysdescr.xml',
         'telnet_banners.xml', 'pop_banners.xml', 'imap_banners.xml', 'mysql_banners.xml', 'ntp_banners.xml')
README = """# Rapid7 Recog fingerprints (vendored data)

The XML fingerprint databases of [Rapid7 Recog](https://github.com/{repo}), pinned to commit
[`{commit}`](https://github.com/{repo}/tree/{commit}) ({date}). Recog is under the BSD 2-Clause license: `LICENSE` and `COPYING` in this
folder are Recog's own (Copyright (c) 2014-2015, Rapid7).

Only the databases `cveFeed.recog` reads are kept, unchanged, with no Ruby code: {files}.
`manifest.json` records the commit and the SHA-256 of every file; the tests check both, and check that every fingerprint cvENGINE loads
matches Recog's own `<example>` entries.

Refresh with `python3 scripts/update_recog.py <commit>` (it downloads that commit's files from GitHub), review the diff, run
`python3 manage.py test tests.test_recog` and commit. Nothing reads the network at run time or in CI.
"""


def fetch(commit, path):
    url = f'https://raw.githubusercontent.com/{REPO}/{commit}/{path}'
    req = urllib.request.Request(url, headers={'User-Agent': 'recog-data-refresh'})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def commit_date(commit):
    req = urllib.request.Request(f'https://api.github.com/repos/{REPO}/commits/{commit}',
                                 headers={'User-Agent': 'recog-data-refresh', 'Accept': 'application/vnd.github+json'})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())['commit']['committer']['date']
    except Exception:  # noqa: BLE001 - the date is informational
        return ''


def main(argv):
    manifest_path = DEST / 'manifest.json'
    pinned = json.loads(manifest_path.read_text())['commit'] if manifest_path.exists() else ''
    commit = (argv[1] if len(argv) > 1 else pinned).strip().lower()
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise SystemExit('give the full 40-character commit sha to pin')
    found = {name: fetch(commit, name) for name in ('LICENSE', 'COPYING')}
    for name in FILES:
        found[name] = fetch(commit, f'xml/{name}')
    DEST.mkdir(parents=True, exist_ok=True)
    for name, data in found.items():
        (DEST / name).write_bytes(data)
    date = (argv[2] if len(argv) > 2 else '') or commit_date(commit) or (
        json.loads(manifest_path.read_text()).get('date', '') if pinned == commit else '')
    manifest = {'source': f'https://github.com/{REPO}', 'commit': commit, 'date': date, 'license': 'BSD-2-Clause',
                'files': {name: hashlib.sha256(found[name]).hexdigest() for name in sorted(found)}}
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
    (DEST / 'README.md').write_text(README.format(repo=REPO, commit=commit, date=date or 'date unknown',
                                                  files=', '.join(f'`{n}`' for n in FILES)))
    print(f'pinned {REPO}@{commit}: {len(FILES)} databases')


if __name__ == '__main__':
    main(sys.argv)
