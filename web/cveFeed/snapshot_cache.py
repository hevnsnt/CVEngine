"""Short-lived snapshots of the live screen's expensive answers, shared by every web worker and every viewer of the same scope.

The Live page polls a handful of endpoints every few seconds; two of them (the headline counts and the discovery counts) walk the whole
inventory. They used to be cached in a dict of each gunicorn worker, per user, so W workers x U users recomputed them every ten seconds, and a
busy moment piled those recomputations on top of each other until the proxy answered 502. They now live in the Django cache (Redis), where:

* the key is the caller's **scope** (a hash of the project ids the request runs under, see ``scope_hash``), never the user: two members of one
  project share one entry, and two different scopes can never read each other's;
* the work is **single flight**: when an entry is missing or too old, one request takes a short lock and computes, the others serve the stale
  copy (kept three times as long as it is fresh) or, with none, wait a moment for the winner's answer;
* a Redis outage never breaks a view: every cache call is guarded and the answer is computed directly, as it was before the cache existed;
* ``bump_stats_revision`` (a finding was closed) makes every entry stale at once through the revision stored in each entry.

Stage 1 of the live-screen plan (a periodic refresher that keeps these warm) builds on ``snapshot`` and ``scope_hash``.
"""
import hashlib
import json
import logging
import time

from django.core.cache import cache

logger = logging.getLogger(__name__)

REVISION_KEY = 'cvengine:stats:revision'
STALE_FACTOR = 3  # a snapshot is kept this many times as long as it is fresh, to serve while one request refreshes it
LOCK_SECONDS = 20  # a winner that dies leaves the lock this long at most
WAIT_SECONDS = 2.0  # a request with nothing to serve waits this long for the winner before computing for itself
WAIT_STEP = 0.05


def _now():
    return time.time()


def scope_hash(*params):
    """Who may share a snapshot: a hash of the effective allowed project ids of the running request, plus ``params`` (the selected project and
    organization, which already narrowed that set but are kept in the key for clarity). Call it inside ``project_scoped``.

    A caller with no restriction (an App Admin) hashes *every* project id, so creating a project changes the key, and carries an ``all`` marker
    so it never shares with a member who happens to see every project: unrestricted callers also see rows no project owns."""
    from dashboard.models import Project
    from tenancy import scope
    allowed = scope.current_allowed()
    if allowed is None:
        ids, marker = sorted(Project.objects.values_list('id', flat=True)), 'all'
    else:
        ids, marker = sorted(allowed), 'ids'
    raw = json.dumps([marker, ids, [str(p) for p in params]], separators=(',', ':'))
    return hashlib.sha1(raw.encode()).hexdigest()[:20]


def revision():
    try:
        return cache.get(REVISION_KEY) or ''
    except Exception:  # noqa: BLE001 - a cache outage is no reason to fail a request
        return ''


def bump_revision():
    """Every snapshot is stale from now on (they are refreshed by the next request). Without Redis nothing is cached, so nothing can be stale."""
    from django.utils import timezone
    try:
        cache.set(REVISION_KEY, timezone.now().isoformat(), timeout=None)
    except Exception:  # noqa: BLE001
        logger.warning('could not bump the stats revision: the cache is not answering')


def token_of(payload):
    """A short stable token of a JSON-able payload: the ETag of a snapshot is computed once, when it is built."""
    return hashlib.sha1(json.dumps(payload, sort_keys=True, default=str, separators=(',', ':')).encode()).hexdigest()[:20]


def snapshot(name, scope, compute, fresh, etag_of=None):
    """``{'payload', 'etag', 'at', 'rev'}`` for ``name`` under ``scope`` (a ``scope_hash``): the cached one while it is younger than ``fresh``
    seconds and of the current revision, else a new one from ``compute()``, built by one request at a time (see the module docstring).
    ``etag_of(payload)`` (default: a token of the whole payload) is run once, when the snapshot is built, so a poll that finds nothing new
    never hashes anything: use it to leave out what moves every second (a clock) without meaning anything."""
    key = f'cve:snap:{name}:{scope}'
    lock = f'{key}:lock'

    def build(rev):
        payload = compute()
        return {'payload': payload, 'etag': (etag_of or token_of)(payload), 'at': _now(), 'rev': rev}

    try:
        entry, rev = cache.get(key), revision()
        if entry is not None and (not isinstance(entry, dict) or 'payload' not in entry):
            entry = None
    except Exception:  # noqa: BLE001
        return build('')
    if entry is not None and entry['rev'] == rev and _now() - entry['at'] < fresh:
        return entry
    try:
        won = cache.add(lock, 1, LOCK_SECONDS)
    except Exception:  # noqa: BLE001
        return build(rev)
    if not won:
        if entry is not None:
            return entry  # somebody is refreshing it: serve what there is
        deadline = time.monotonic() + WAIT_SECONDS
        while time.monotonic() < deadline:  # nothing to serve (a cold key): give the winner a moment to finish
            time.sleep(WAIT_STEP)
            try:
                entry = cache.get(key)
            except Exception:  # noqa: BLE001
                break
            if isinstance(entry, dict) and 'payload' in entry:
                return entry
        return build(rev)
    try:
        entry = build(rev)
        try:
            cache.set(key, entry, int(fresh * STALE_FACTOR) or 1)
        except Exception:  # noqa: BLE001
            logger.warning('could not store the %s snapshot: the cache is not answering', name)
        return entry
    finally:
        try:
            cache.delete(lock)
        except Exception:  # noqa: BLE001
            pass


def matches(request, etag):
    """Whether the request's ``If-None-Match`` names ``etag`` (quoted, weak, bare, in a list, or ``*``)."""
    sent = request.META.get('HTTP_IF_NONE_MATCH', '')
    if not sent:
        return False
    if sent.strip() == '*':
        return True
    return etag in {part.strip().removeprefix('W/').strip('"') for part in sent.split(',')}


def respond(request, etag, build):
    """The answer, or ``304`` with no body when the client already holds this ``etag``. ``build()`` returns the JSON-able payload and runs
    only when the client does not: put the work a 304 must not cost inside it. Always ``private, no-cache``: a browser or proxy may keep the
    copy but must ask before reusing it, which is what makes the conditional request work (``no-store`` would forbid it)."""
    from django.http import HttpResponseNotModified, JsonResponse
    if matches(request, etag):
        response = HttpResponseNotModified()
    else:
        response = JsonResponse(build())
    response['ETag'] = f'"{etag}"'
    response['Cache-Control'] = 'private, no-cache'
    return response


def respond_payload(request, payload, etag=None):
    """``respond`` for an answer that is already built (a cheap one, or one the caller needed anyway): the ETag is a token of the payload
    unless ``etag`` is given. The saving is the body on the wire and the redraw in the browser, not the work behind the payload."""
    return respond(request, etag or token_of(payload), lambda: payload)
