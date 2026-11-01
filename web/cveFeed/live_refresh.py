"""The live screen's refresher (stage 1 of the live-screen caching plan): keeps the snapshots of the scopes people are looking at warm.

Celery beat dispatches ``refresh_live_snapshots`` every ``CVENGINE_LIVE_REFRESH_SECONDS`` (5) to ``live_cache_queue``, a queue of its own
consumed by the celery container's classic worker (never by the discovery, feed or validation workers, whose slots scan work holds for hours). Each run recomputes the snapshots (``cveFeed.snapshot_cache``) of the scopes registered as hot, that is asked for
within the last ``CVENGINE_LIVE_HOT_SECONDS`` (60), and only those: a scope nobody opens is never computed in advance. While it runs it leaves a
heartbeat, and a request that finds a snapshot this task stored serves it without computing, even a little past its freshness window.

Tenancy: a recipe carries the project ids the request ran under, and the key it was stored under is a hash of those ids and the request's
parameters. The refresher runs the computation inside that very scope (``tenancy.scope``, no user) and recomputes the hash first; a recipe whose
hash no longer comes out the same (a project was created under an App Admin's all-projects view) is dropped, so a payload is never stored under
a key whose scope did not compute it. Access that is removed from a user never needs this module: the user's next request hashes a different
set of ids and reads another key.

The refresher runs on a worker that also runs other work (the classic one: gevent, with a database driver that does not yield), so every query of
a run holds that worker's other tasks for its duration. It is therefore deliberately small: a run has a time budget of at most three seconds and
at most half an interval, takes the scopes oldest first (so every hot scope is served over a few runs), yields to the worker's other tasks
between scopes, leaves a scope that is not due alone, skips the whole run when the queues the worker consumes hold a large backlog (or when the
previous run overran), and counts every skip and overrun (``skipped``, ``overran``: ``get_system_status``). If the classic worker looks starved,
``CVENGINE_LIVE_REFRESH=0`` is the first thing to flip.

``CVENGINE_LIVE_REFRESH=0`` is the kill switch (no scope is registered, the task returns at once and requests compute as before stage 1).
"""
import logging
import time
import uuid

from django.core.cache import cache

from cveFeed import snapshot_cache
from reNgine import livecache_config
from tenancy import scope as tenancy_scope

logger = logging.getLogger(__name__)

MAX_BUDGET_SECONDS = 3.0  # a run never holds the worker longer than this between two yields to its other tasks, nor longer than half an interval
BACKLOG_SKIP = 100  # messages waiting in the queues the classic worker consumes, above which a run is skipped
OWN_BACKLOG_SKIP = 3  # refreshes already waiting for a slot: the worker is behind, adding to it helps nobody
CLASSIC_QUEUES = ('send_notif_queue', 'send_task_notif_queue', 'geo_localize_queue', 'run_command_queue', 'api_queue', 'wpscan_queue', 'testssl_queue',
                  'bucketscan_queue', 'vhost_queue', 'udp_queue', 'openvas_queue', 'supplier_queue', 'ctwatch_queue')
RUN_LOCK = 'cve:snap:refresher:lock'


def computers():
    """``name -> (compute(args), fresh seconds, etag_of, after)`` for each snapshot a scope can be hot for. Resolved on every call, from the
    views' own functions (a test that patches one is honoured); ``after(recipe, entry, previous)`` runs after a refresh."""
    from cveFeed import graph_live, views
    return {
        'stats': (lambda a: views.stats_payload(), views.STATS_CACHE_SECONDS, None, None),
        'discovery-counts': (lambda a: views.discovery_counts(), views.STATS_CACHE_SECONDS, None, None),
        'graph-version': (lambda a: views.graph_version(a.get('domain_id'), a.get('scan_id')), views.GRAPH_VERSION_SECONDS, None, _prebuild_graph),
        'graph-live': (lambda a: graph_live.live(a.get('project'), a.get('domain_id')), views.GRAPH_LIVE_SECONDS, views._graph_live_token, None),
    }


def _prebuild_graph(recipe, entry, previous):
    """A graph whose version moved is built here, once, so the viewers' ``?v=`` polls that find it changed are served from the cache instead of
    each walking the inventory (a request that finds the payload missing still builds it, as before). Kept as long as a payload a request builds
    (``GRAPH_CACHE_SECONDS``): a deleted host must not stay on the graph longer than that. Nothing is built for a version that did not move."""
    from cveFeed import views
    if previous is not None and previous['payload'] == entry['payload']:
        return
    key = views.graph_cache_key(recipe['scope'], entry['payload'])
    if cache.get(key) is None:
        args = recipe['args']
        cache.set(key, {**views.graph_payload(args.get('domain_id'), args.get('scan_id')), 'version': entry['payload']}, views.GRAPH_CACHE_SECONDS)


def budget_seconds(interval=None):
    interval = livecache_config.refresh_seconds() if interval is None else interval
    return min(MAX_BUDGET_SECONDS, interval / 2)


def backlog():
    """``(own, classic)``: refreshes waiting for a slot, and messages waiting in the other queues the classic worker consumes. ``(0, 0)`` when the
    broker cannot be asked (a refresh is then not held back for want of an answer)."""
    try:
        from reNgine.celery import app
        with app.connection_for_read() as connection:
            client = connection.default_channel.client
            return client.llen('live_cache_queue'), sum(client.llen(q) for q in CLASSIC_QUEUES)
    except Exception:  # noqa: BLE001
        return 0, 0


def _yield():
    """Let the worker's other greenlets run (gevent pool); a plain no-op elsewhere."""
    try:
        import gevent
        gevent.sleep(0)
    except ImportError:
        time.sleep(0)


def _owns(token):
    try:
        return cache.get(RUN_LOCK) == token
    except Exception:  # noqa: BLE001
        return False


def refresh_hot_scopes(budget=None):
    """One run: refresh what is due among the hot scopes, oldest first, within ``budget`` seconds (default ``budget_seconds()``). Returns a summary."""
    if not livecache_config.refresh_enabled():
        return {'enabled': False}
    interval = livecache_config.refresh_seconds()
    budget = budget_seconds(interval) if budget is None else budget
    token = uuid.uuid4().hex
    try:
        if not cache.add(RUN_LOCK, token, 30):
            return {'enabled': True, 'skipped': 'another run is in progress'}
    except Exception:  # noqa: BLE001 - without the cache there is nothing to refresh
        return {'enabled': True, 'skipped': 'the cache is not answering'}
    started = time.monotonic()
    ran = False
    summary = {'enabled': True, 'hot': 0, 'refreshed': 0, 'fresh': 0, 'busy': 0, 'dropped': 0, 'errors': 0, 'out_of_time': 0, 'idle': 0}
    try:
        last = snapshot_cache.last_beat() or {}
        own, classic = backlog()
        reason = ('the previous run overran its budget' if last.get('overran') else
                  f'{own} refreshes are waiting for a slot' if own >= OWN_BACKLOG_SKIP else
                  f'{classic} messages are waiting in the classic worker\'s queues' if classic >= BACKLOG_SKIP else '')
        if reason:
            snapshot_cache.count('refresher', 'skipped')
            snapshot_cache.beat({'state': 'skipped', 'skipped': reason, 'overran': False})  # the next run is not held back for this one
            return {**summary, 'skipped': reason}
        ran = True
        snapshot_cache.beat({'state': 'running'})
        known = computers()
        recipes = snapshot_cache.hot_recipes()
        summary['hot'] = len(recipes)
        keys = {f"cve:snap:{r['name']}:{r['scope']}": r for r in recipes}
        try:
            stored = cache.get_many(list(keys))
        except Exception:  # noqa: BLE001
            stored = {}
        now, active = snapshot_cache._clock(), livecache_config.hot_seconds() / 3 + 3 * interval

        def age_of(key):  # a missing or older snapshot goes first: what a run leaves undone it does first next time
            entry = stored.get(key)
            return float('inf') if not isinstance(entry, dict) or 'at' not in entry else snapshot_cache._now() - entry['at']
        for key in sorted(keys, key=age_of, reverse=True):
            rec = keys[key]
            if time.monotonic() - started > budget:
                summary['out_of_time'] += 1
                continue
            if not _owns(token):  # our lock ran out and another run took over: leave the rest to it
                summary['skipped'] = 'the run lock was lost'
                break
            spec = known.get(rec['name'])
            if spec is None:
                summary['dropped'] += 1
                continue
            compute, fresh, etag_of, after = spec
            if fresh < interval and now - rec['seen'] > active:
                summary['idle'] += 1  # a snapshot that is stale within one interval is worth refreshing only for a scope still being watched
                continue
            allowed = rec['allowed']
            tokens = tenancy_scope.set_scope(None if allowed is None else set(allowed), None)
            try:
                if snapshot_cache.scope_hash(*rec['params']) != rec['scope']:
                    summary['dropped'] += 1  # the scope's projects changed since the request: that key is no one's now
                    continue
                status, entry, previous = snapshot_cache.refresh(rec['name'], rec['scope'], lambda: compute(rec['args']), fresh, etag_of,
                                                                 due_age=max(0, fresh - interval))
                summary[status] += 1
                if after and status == 'refreshed':
                    after(rec, entry, previous)
            except Exception:  # noqa: BLE001 - one scope's failure never stops the others
                summary['errors'] += 1
                logger.exception('live snapshot refresh of %s failed', rec['name'])
            finally:
                tenancy_scope.reset_scope(tokens)
            _yield()
    finally:
        summary['seconds'] = round(time.monotonic() - started, 3)
        if ran:
            overran = summary['seconds'] > 2 * budget  # the budget is checked between scopes: one slow query can overshoot it
            if overran:
                snapshot_cache.count('refresher', 'overran')
            snapshot_cache.beat({'state': 'idle', 'overran': overran, **{k: summary[k] for k in ('hot', 'refreshed', 'errors', 'seconds')}})
        try:
            if _owns(token):  # a lock another run took over is not ours to delete
                cache.delete(RUN_LOCK)
        except Exception:  # noqa: BLE001
            pass
    return summary
