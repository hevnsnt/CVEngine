"""Which Sentinel commit this server's scanner library (and so the result contract it reads) comes from.

The image installs ``cvengine-scanner`` from the Sentinel repository at build time: ``web/requirements.txt`` names the known-good floor commit that CI and a
plain ``pip install`` use, and the Dockerfile's ``SENTINEL_REF`` build argument (default ``main``, resolved to a commit sha when the image is built) installs the
newest build over it. pip records the commit it installed in the package's ``direct_url.json`` whichever way it was installed, so this reads the answer from
the install itself: no label or file that could disagree with what is really there. The About page and the Sentinels page say ``contract read from Sentinel <sha>``.
"""
import json
import re
from importlib import metadata

SHA = re.compile(r'^[0-9a-f]{40}$')


def library():
    """``{commit, short, url, ref}`` of the installed library: ``commit`` (40 hex) is ``None`` when it was not installed from git (a checkout on the path)."""
    out = {'commit': None, 'short': None, 'url': None, 'ref': None}
    try:
        raw = metadata.distribution('cvengine-scanner').read_text('direct_url.json')
        info = json.loads(raw) if raw else {}
    except (metadata.PackageNotFoundError, ValueError, OSError):
        return out
    vcs = info.get('vcs_info') if isinstance(info, dict) else None
    commit = str((vcs or {}).get('commit_id') or '').lower()
    if SHA.match(commit):
        out.update(commit=commit, short=commit[:12], url=str(info.get('url') or '')[:200], ref=str((vcs or {}).get('requested_revision') or '')[:100] or None)
    return out


def contract_line():
    """The sentence the pages show."""
    from agentapi import sentinel_contract
    found = library()
    version = sentinel_contract.version()
    if found['commit']:
        return f'Result contract version {version}, read from Sentinel {found["short"]}'
    return f'Result contract version {version}, read from the installed Sentinel library (its commit is not recorded in this install)'


def status():
    found = library()
    return {**found, 'text': contract_line()}
