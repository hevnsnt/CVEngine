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

Stage 1 adds a **refresher** (``cveFeed.live_refresh``, a celery beat task on a queue of its own): every request for a scope registers it as *hot*
for a minute (``mark_hot``: the scope's key, the project ids it runs under and the parameters it was asked with), and the refresher recomputes
the snapshots of the hot scopes before they go stale, so while it is alive (``refresher_alive``: it leaves a heartbeat every run) a request
serves what the refresher stored and computes only when the cache is cold, the revision moved, or the refresher has stopped. A scope nobody
asks for stops being refreshed within a minute. What the refresher stores sits under the same key a request would have written, and it is
computed under exactly the project ids that key was hashed from, so a scope can never be served another scope's numbers. Hits, stale answers,
misses and refreshes are counted per hour in the cache (``metrics``), for ``get_system_status``.
"""
import hashlib
import json
import logging
import time

from django.core.cache import cache

from reNgine import livecache_config

logger = logging.getLogger(__name__)

REVISION_KEY = 'cvengine:stats:revision'
STALE_FACTOR = 3  # a snapshot is kept this many times as long as it is fresh, to serve while one request refreshes it
LOCK_SECONDS = 20  # a winner that dies leaves the lock this long at most
WAIT_SECONDS = 2.0  # a request with nothing to serve waits this long for the winner before computing for itself
WAIT_STEP = 0.05

HOT_KEY = 'cve:snap:hot'  # {'<name>:<scope>': recipe}: the scopes asked for lately, and how to recompute each
HOT_LOCK = 'cve:snap:hot:lock'
MAX_HOT = 500  # a larger fleet of scopes is not registered (they are computed by the requests, as before)
MAX_HOT_PER_USER = 24  # one user's share of them (a screen asks for about four snapshots per scope): the first registered keep their place, later ones are not registered
BEAT_KEY = 'cve:snap:refresher'  # the refresher's heartbeat: {'at', 'interval', ...}
METRIC_TTL = 3 * 3600
# a request: served fresh / served stale / computed / waited for a winner; the refresher: refreshed a snapshot, skipped a run (a stressed worker), overran its budget
OUTCOMES = ('hit', 'stale', 'miss', 'waited', 'refreshed', 'skipped', 'overran')
NAMES = ('stats', 'discovery-counts', 'graph-version', 'graph-live', 'refresher')

_hot_seen = {}  # (name, scope) -> when this process last registered it: a poll does not write to the cache each time


def _now():
    return time.time()


def _clock():
    """Wall time for the bookkeeping around the snapshots (hot scopes, the heartbeat, the counters); ``_now`` stays the clock of the entries."""
    return time.time()


def count(name, outcome, n=1):
    """Add to this hour's counter of ``outcome`` for the snapshot ``name`` (shared by every worker; a cache that does not answer counts nothing)."""
    key = f'cve:snap:m:{int(_clock() // 3600)}:{name}:{outcome}'
    try:
        try:
            cache.incr(key, n)  # one round trip for every count but the first of an hour
        except ValueError:
            if not cache.add(key, n, METRIC_TTL):
                cache.incr(key, n)
    except Exception:  # noqa: BLE001 - a counter is never worth a failed poll
        pass


def metrics():
    """``{'this_hour': {...}, 'previous_hour': {...}}``, each ``{'hit', 'stale', 'miss', 'waited', 'refreshed', 'served_from_cache_percent', 'by_snapshot'}``
    summed over every worker (``this_hour`` is the clock hour in progress, so it counts from its start)."""
    bucket = int(_clock() // 3600)
    out = {}
    for label, hour in (('this_hour', bucket), ('previous_hour', bucket - 1)):
        keys = {(n, o): f'cve:snap:m:{hour}:{n}:{o}' for n in NAMES for o in OUTCOMES}
        try:
            got = cache.get_many(list(keys.values()))
        except Exception:  # noqa: BLE001
            got = {}
        totals = dict.fromkeys(OUTCOMES, 0)
        by_name = {}
        for (name, outcome), key in keys.items():
            n = int(got.get(key) or 0)
            totals[outcome] += n
            if n:
                by_name.setdefault(name, {})[outcome] = n
        served = totals['hit'] + totals['stale']
        asked = served + totals['miss'] + totals['waited']
        out[label] = {**totals, 'served_from_cache_percent': round(100 * served / asked, 1) if asked else None, 'by_snapshot': by_name}
    return out


def mark_hot(name, scope, hot):
    """Register ``scope`` as asked for just now, for the refresher: ``hot`` is ``{'params': the scope_hash parameters, 'args': what the compute
    function needs, 'check': optional, returns False for a scope that names nothing the caller may see}``. Run inside ``project_scoped`` (the project
    ids the request runs under are what the refresher computes under, and what ``scope`` was hashed from). At most one cache write, and one run of
    ``check``, per scope, process and third of the hot window; a registration that loses the race to another worker's is made by the next poll.
    A scope is not registered when ``check`` refuses it, when the registry is full (``MAX_HOT``) or when the caller already holds
    ``MAX_HOT_PER_USER`` of them, so one member cannot fill the registry (or the refresher's time) with scopes of their own making."""
    if not livecache_config.refresh_enabled():
        return
    key, hot_seconds, now = (name, scope), livecache_config.hot_seconds(), _clock()
    if now - _hot_seen.get(key, 0.0) < hot_seconds / 3:
        return
    if len(_hot_seen) > 2000:
        _hot_seen.clear()
    _hot_seen[key] = now  # also when refused below: a refused scope is not asked about again at every poll
    check = hot.get('check')
    try:
        if check is not None and not check():
            return
    except Exception:  # noqa: BLE001
        return
    from tenancy import scope as tenancy_scope
    allowed, user = tenancy_scope.current_allowed(), getattr(tenancy_scope.current_user(), 'pk', None)
    try:
        if not cache.add(HOT_LOCK, 1, 5):
            _hot_seen.pop(key, None)  # another worker is writing the index: ask again at the next poll
            return
        try:
            index = {k: v for k, v in (cache.get(HOT_KEY) or {}).items() if v['seen'] + hot_seconds > now}
            ident = f'{name}:{scope}'
            if ident in index or (len(index) < MAX_HOT and sum(1 for v in index.values() if v.get('user') == user) < MAX_HOT_PER_USER):
                index[ident] = {'name': name, 'scope': scope, 'allowed': None if allowed is None else sorted(allowed), 'user': user,
                                'params': [str(p) for p in hot.get('params', ())], 'args': dict(hot.get('args') or {}), 'seen': now}
                cache.set(HOT_KEY, index, hot_seconds * 5)
        finally:
            cache.delete(HOT_LOCK)
    except Exception:  # noqa: BLE001
        _hot_seen.pop(key, None)


def hot_recipes():
    """The scopes asked for within the hot window: what the refresher recomputes."""
    now, hot_seconds = _clock(), livecache_config.hot_seconds()
    try:
        index = cache.get(HOT_KEY) or {}
    except Exception:  # noqa: BLE001
        return []
    return [v for v in index.values() if v['seen'] + hot_seconds > now]


def reset_hot():
    """Forget every hot scope, the refresher's heartbeat and what this process registered (tests, and a factory reset)."""
    _hot_seen.clear()
    try:
        cache.delete_many([HOT_KEY, HOT_LOCK, BEAT_KEY])
    except Exception:  # noqa: BLE001
        pass


def beat(info):
    """The refresher's heartbeat: ``info`` plus when it was written and the interval it runs at."""
    interval = livecache_config.refresh_seconds()
    try:
        cache.set(BEAT_KEY, {**info, 'at': _clock(), 'interval': interval}, max(120, interval * 20))
    except Exception:  # noqa: BLE001
        pass


def last_beat():
    try:
        return cache.get(BEAT_KEY) or None
    except Exception:  # noqa: BLE001
        return None


def refresher_alive():
    """Whether the refresher has run lately enough that a request may leave a hot snapshot to it: a heartbeat younger than four intervals."""
    if not livecache_config.refresh_enabled():
        return False
    last = last_beat()
    return bool(last) and _clock() - last['at'] <= max(15, 4 * last.get('interval', 5))


def keep_seconds(fresh):
    """How long a snapshot is kept: three times its freshness, and at least three refresher intervals, so a refresher that runs every 5 s never
    finds a 2 s snapshot already gone."""
    return max(int(fresh * STALE_FACTOR) or 1, livecache_config.refresh_seconds() * 3)


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


def _build(compute, etag_of, rev, by='request'):
    payload = compute()
    return {'payload': payload, 'etag': (etag_of or token_of)(payload), 'at': _now(), 'rev': rev, 'by': by}


def snapshot(name, scope, compute, fresh, etag_of=None, hot=None):
    """``{'payload', 'etag', 'at', 'rev'}`` for ``name`` under ``scope`` (a ``scope_hash``): the cached one while it is younger than ``fresh``
    seconds and of the current revision, else a new one from ``compute()``, built by one request at a time (see the module docstring).
    ``etag_of(payload)`` (default: a token of the whole payload) is run once, when the snapshot is built, so a poll that finds nothing new
    never hashes anything: use it to leave out what moves every second (a clock) without meaning anything.

    ``hot`` (``{'params': ..., 'args': ...}``, see ``mark_hot``) registers the scope with the refresher. An entry the refresher stored is served
    even past ``fresh`` (for up to ``keep_seconds``) while the refresher is alive: it is on its way to a new one."""
    key = f'cve:snap:{name}:{scope}'
    lock = f'{key}:lock'
    if hot is not None:
        mark_hot(name, scope, hot)

    try:
        entry, rev = cache.get(key), revision()
        if entry is not None and (not isinstance(entry, dict) or 'payload' not in entry):
            entry = None
    except Exception:  # noqa: BLE001
        return _build(compute, etag_of, '')
    if entry is not None and entry['rev'] == rev:
        age = _now() - entry['at']
        if age < fresh:
            count(name, 'hit')
            return entry
        if entry.get('by') == 'refresher' and age < keep_seconds(fresh) and refresher_alive():
            count(name, 'stale')  # the refresher keeps this scope warm: the next one is on its way
            return entry
    try:
        won = cache.add(lock, 1, LOCK_SECONDS)
    except Exception:  # noqa: BLE001
        return _build(compute, etag_of, rev)
    if not won:
        if entry is not None:
            count(name, 'stale')
            return entry  # somebody is refreshing it: serve what there is
        deadline = time.monotonic() + WAIT_SECONDS
        while time.monotonic() < deadline:  # nothing to serve (a cold key): give the winner a moment to finish
            time.sleep(WAIT_STEP)
            try:
                entry = cache.get(key)
            except Exception:  # noqa: BLE001
                break
            if isinstance(entry, dict) and 'payload' in entry:
                count(name, 'waited')
                return entry
        count(name, 'miss')
        return _build(compute, etag_of, rev)
    try:
        try:  # another request may have stored the entry and let go of the lock between the read above and winning the lock here: serve it
            stored = cache.get(key)
            if (isinstance(stored, dict) and 'payload' in stored and stored.get('rev') == rev
                    and (entry is None or stored.get('at') != entry.get('at'))):  # one that was not there when the key was read
                count(name, 'waited')
                return stored
        except Exception:  # noqa: BLE001 - an unreadable cache is built from, as everywhere else here
            pass
        count(name, 'miss')
        entry = _build(compute, etag_of, rev)
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


def refresh(name, scope, compute, fresh, etag_of=None, due_age=None):
    """What the refresher does for one hot scope: ``(status, entry, previous)`` (``previous`` is the snapshot it replaced, or None). ``'fresh'`` when the stored snapshot is of the current revision and younger
    than ``due_age`` (default ``fresh``), ``'busy'`` when a request or another refresher holds the lock, else ``'refreshed'`` with the new
    snapshot, stored under the key a request would have written (``by: 'refresher'``, so requests know to leave it to us). Raises what
    ``compute`` raises (the lock is released first)."""
    key = f'cve:snap:{name}:{scope}'
    lock = f'{key}:lock'
    due = fresh if due_age is None else due_age
    entry, rev = cache.get(key), revision()
    previous = entry if isinstance(entry, dict) and 'payload' in entry else None
    if previous is not None and previous['rev'] == rev and _now() - previous['at'] < due:
        return 'fresh', previous, previous
    if not cache.add(lock, 1, LOCK_SECONDS):
        return 'busy', previous, previous
    try:
        entry = _build(compute, etag_of, rev, by='refresher')
        cache.set(key, entry, keep_seconds(fresh))
        count(name, 'refreshed')
        return 'refreshed', entry, previous
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
