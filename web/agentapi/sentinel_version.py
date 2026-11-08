"""Whether each Sentinel runs the current version of the Sentinel client.

A Sentinel reports its build in its heartbeat (``info.version``: the git commit its image was built from, 12 characters, or what its updater
wrote). cvENGINE asks GitHub, a few times a day and never while a person waits, for the head of the Sentinel repository's branch and for how
far behind each reported version is, and keeps the answer in the cache. Rows and pages read that answer only: nothing here makes a request
while a list is being built, so a slow or unreachable GitHub costs a page nothing and shows as ``unknown``.

``state(agent)`` is ``{status, version, latest, behind_by, ...}`` with ``status`` one of ``current``, ``behind`` or ``unknown`` (no version
reported, the latest not checked yet, the check switched off or failing, or no verdict for exactly this installed commit). ``behind`` means the newest
build the server saw is a descendant of the one the Sentinel runs; a build equal to or ahead of the cached head is ``current``, never ``behind``.
"""
import logging
import os
import re

import requests
from django.core.cache import cache

from cveFeed import updater

logger = logging.getLogger(__name__)

DEFAULT_REPO = 'hevnsnt/cvENGINE-sentinel'
DEFAULT_BRANCH = 'main'
LATEST_PREFIX = 'sentinel-version:latest'
VERDICT_PREFIX = 'sentinel-version:verdict'
ASKED_KEY = 'sentinel-version:asked'
TTL = 24 * 3600  # the answer outlives a missed refresh; ``checked_at`` says how old it is
ASK_EVERY = 300  # a page that finds nothing cached asks for a refresh at most this often (seconds)
HEX_RE = re.compile(r'^[0-9a-f]{7,40}$')
MAX_VERSIONS = 20  # distinct reported versions compared per refresh


def enabled():
    return os.environ.get('CVENGINE_SENTINEL_VERSION_CHECK', '').strip().lower() not in ('0', 'off', 'false', 'no')


def repo():
    value = os.environ.get('CVENGINE_SENTINEL_REPO', '').strip()
    return value if updater.valid_repo(value) else DEFAULT_REPO


def branch():
    value = os.environ.get('CVENGINE_SENTINEL_BRANCH', '').strip()
    return value if updater.valid_branch(value) else DEFAULT_BRANCH


def latest_key(repo_name=None, branch_name=None):
    """The remote head is cached per repository and branch: a changed setting never reads another branch's head."""
    return f'{LATEST_PREFIX}:{repo_name or repo()}:{branch_name or branch()}'


def verdict_key(version, repo_name=None, branch_name=None):
    """A verdict (how far the newest build is ahead of one installed commit) is cached per installed commit AND remote branch, so a Sentinel that moved
    to another commit can never read the verdict that was made for the one it ran before."""
    return f'{VERDICT_PREFIX}:{repo_name or repo()}:{branch_name or branch()}:{str(version or "").strip().lower()}'


def forget(version):
    """Drop the cached verdict of one installed commit (a Sentinel stopped running it)."""
    if version:
        cache.delete(verdict_key(version))


def version_changed(old, new):
    """A Sentinel reported another version: the verdict of the commit it left is dropped at once. The verdict for the commit it runs now is made by the
    background refresh, which ``state`` asks for (rate limited) while the cached head is older than ``version_since``; nothing is claimed meanwhile."""
    if old and old != new:
        forget(str(old).strip().lower())


def _parse(value):
    from django.utils.dateparse import parse_datetime
    try:
        return parse_datetime(value) if isinstance(value, str) else None
    except ValueError:
        return None


def _token():
    """A token for a private Sentinel repository: ``CVENGINE_SENTINEL_REPO_TOKEN``, else the one the update check of cvENGINE itself uses (the
    same GitHub account usually owns both). A token that cannot see the repository only makes the check say so."""
    explicit = os.environ.get('CVENGINE_SENTINEL_REPO_TOKEN', '').strip()
    if explicit:
        return explicit
    try:
        from cveFeed.models import UpdateSettings
        return UpdateSettings.current().token or ''
    except Exception:  # noqa: BLE001 - no token is a normal answer
        return ''


def reported_versions():
    """The distinct versions the non-revoked Sentinels reported (hex commits only, newest registered first)."""
    from agentapi.models import Agent
    seen = []
    for info in Agent.objects.filter(kind='scanner').exclude(status='revoked').order_by('-id').values_list('info', flat=True)[:200]:
        version = str((info or {}).get('version') or '').strip().lower()
        if HEX_RE.match(version) and version not in seen:
            seen.append(version)
    return seen[:MAX_VERSIONS]


def _verdict(compared):
    """Commits the newest build is ahead of the installed commit, from one compare answer: 0 when the installed commit is the head, behind it or equal, a
    count only when the head is a descendant of it, and None (not known) when the compare failed, GitHub never saw the commit or the two diverged."""
    if compared.get('compare_error') or not compared.get('reference_known', True):
        return None
    if compared.get('compare_status') == 'diverged':
        return None
    return compared.get('behind_by')


def refresh(get=requests.get, now=None):
    """Ask GitHub for the head of the Sentinel branch and how far behind it each reported version is; store the answer. A failure keeps the last
    known head and records the reason. Returns the stored answer."""
    from django.utils import timezone
    now = now or timezone.now()
    key = latest_key()
    previous = cache.get(key) or {}
    if not enabled():
        return previous
    try:
        found = updater.fetch_latest(repo(), branch(), _token(), installed='', get=get)
    except updater.UpdateError as exc:
        out = {**previous, 'error': str(exc)[:300], 'checked_at': now.isoformat()}
        cache.set(key, out, TTL)
        return out
    for version in reported_versions():
        if found['sha'].startswith(version):
            behind = 0
        else:
            try:
                behind = _verdict(updater.fetch_latest(repo(), branch(), _token(), installed=version, get=get))
            except updater.UpdateError:
                behind = None
        cache.set(verdict_key(version), {'head': found['sha'], 'behind_by': behind, 'checked_at': now.isoformat()}, TTL)
    out = {'sha': found['sha'], 'message': found['message'], 'url': found['url'], 'date': found['date'], 'error': '', 'checked_at': now.isoformat(),
           'repo': repo(), 'branch': branch()}
    cache.set(key, out, TTL)
    return out


def _version_since(agent):
    return _parse((agent.info or {}).get('version_since'))


def _ask_for_refresh():
    """Nothing cached yet: queue one refresh (at most every ``ASK_EVERY`` seconds), never run it here."""
    if not cache.add(ASKED_KEY, 1, ASK_EVERY):
        return
    try:
        from cveFeed.tasks import refresh_sentinel_version
        refresh_sentinel_version.apply_async(queue='cve_feed_queue', expires=600)
    except Exception:  # noqa: BLE001 - the twice-daily schedule still runs; this is only the first-view shortcut
        logger.info('could not queue the Sentinel version check')


def state(agent, settings_value=None):
    """The version of ``agent`` against the latest Sentinel client. Reads the cache only."""
    version = str(((agent.info or {}).get('version')) or '').strip().lower()
    out = {'status': 'unknown', 'version': version or None, 'latest': None, 'latest_message': None, 'latest_url': None, 'latest_date': None,
           'behind_by': None, 'checked_at': None, 'repo': repo(), 'detail': ''}
    if not enabled():
        out['detail'] = 'the version check is switched off (CVENGINE_SENTINEL_VERSION_CHECK)'
        return out
    latest = cache.get(latest_key())
    if latest is None:
        _ask_for_refresh()
        out['detail'] = 'the latest version has not been checked yet'
        return out
    out.update(latest=(latest.get('sha') or '')[:12] or None, latest_message=latest.get('message') or None, latest_url=latest.get('url') or None,
               latest_date=latest.get('date') or None, checked_at=latest.get('checked_at'))
    if not latest.get('sha'):
        out['detail'] = latest.get('error') or 'the latest version could not be read'
        return out
    if not version:
        out['detail'] = 'unknown (built without the updater): this Sentinel reports no version, so it cannot be compared'
        return out
    if not HEX_RE.match(version):
        out['detail'] = 'this Sentinel reports a version that is not a commit, so it cannot be compared'
        return out
    # the remote head is older than the last time this Sentinel changed version: the build it runs may be newer than that head, so look again (in the
    # background, rate limited), and say nothing about it until the answer is in
    checked, since = _parse(latest.get('checked_at')), _version_since(agent)
    stale = bool(since and (checked is None or checked < since))
    if latest['sha'].startswith(version):
        out.update(status='current', behind_by=0, detail='this is the latest version')
        return out
    verdict = cache.get(verdict_key(version))
    if stale or not verdict or verdict.get('head') != latest['sha']:
        _ask_for_refresh()
        out['detail'] = 'whether this build is behind is being checked again' if stale or verdict else 'this build has not been compared with the latest yet'
        return out
    behind = verdict.get('behind_by')
    if behind == 0:  # at or past the head of the branch (a build from a branch that is ahead)
        out.update(status='current', behind_by=0, detail='this is the latest version, or newer')
        return out
    if not isinstance(behind, int) or behind < 0:  # the compare failed, GitHub never saw this commit or the branches diverged: nothing is claimed
        out['detail'] = 'could not tell whether this build is behind the latest'
        return out
    out.update(status='behind', behind_by=behind)
    out['detail'] = f'{behind} commit{"s" if behind != 1 else ""} behind the latest ({out["latest"]})' + ('' if settings_value is None else f'; self-update is {settings_value}')
    if error := latest.get('error'):
        out['detail'] += f' (the last check failed: {error})'
    return out
