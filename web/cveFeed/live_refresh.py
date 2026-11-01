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

``CVENGINE_LIVE_REFRESH=0`` is the kill switch (no scope is registered, the task returns at once and requests compute as before stage 1).
"""
import logging
import time

from django.core.cache import cache

from cveFeed import snapshot_cache
from reNgine import livecache_config
from tenancy import scope as tenancy_scope

logger = logging.getLogger(__name__)

GRAPH_KEEP_SECONDS = 600  # a graph payload the refresher builds is kept this long: its key names the version, so an unchanged graph needs no rebuild


def computers():
    """``name -> (compute(args), fresh seconds, etag_of, after)`` for each snapshot a scope can be hot for. Resolved on every call, from the
    views' own functions (a test that patches one is honoured); ``after(recipe, entry)`` runs after a refresh."""
    from cveFeed import graph_live, views
    return {
        'stats': (lambda a: views.stats_payload(), views.STATS_CACHE_SECONDS, None, None),
        'discovery-counts': (lambda a: views.discovery_counts(), views.STATS_CACHE_SECONDS, None, None),
        'graph-version': (lambda a: views.graph_version(a.get('domain_id'), a.get('scan_id')), views.GRAPH_VERSION_SECONDS, None, _prebuild_graph),
        'graph-live': (lambda a: graph_live.live(a.get('project'), a.get('domain_id')), views.GRAPH_LIVE_SECONDS, views._graph_live_token, None),
    }


def _prebuild_graph(recipe, entry):
    """A graph whose version moved is built here, once, so the viewers' ``?v=`` polls that find it changed are served from the cache instead of
    each walking the inventory (a request that finds the payload missing still builds it, as before)."""
    from cveFeed import views
    key = views.graph_cache_key(recipe['scope'], entry['payload'])
    if cache.get(key) is None:
        args = recipe['args']
        cache.set(key, {**views.graph_payload(args.get('domain_id'), args.get('scan_id')), 'version': entry['payload']}, GRAPH_KEEP_SECONDS)


def refresh_hot_scopes(budget=None):
    """One run: refresh what is due among the hot scopes, oldest first, within ``budget`` seconds (default: three intervals). Returns a summary."""
    if not livecache_config.refresh_enabled():
        return {'enabled': False}
    interval = livecache_config.refresh_seconds()
    budget = interval * 3 if budget is None else budget
    run_lock = 'cve:snap:refresher:lock'
    try:
        if not cache.add(run_lock, 1, max(30, interval * 6)):
            return {'enabled': True, 'skipped': 'another run is in progress'}
    except Exception:  # noqa: BLE001 - without the cache there is nothing to refresh
        return {'enabled': True, 'skipped': 'the cache is not answering'}
    started = time.monotonic()
    summary = {'enabled': True, 'hot': 0, 'refreshed': 0, 'fresh': 0, 'busy': 0, 'dropped': 0, 'errors': 0, 'out_of_time': 0}
    try:
        snapshot_cache.beat({'state': 'running'})
        known = computers()
        recipes = snapshot_cache.hot_recipes()
        summary['hot'] = len(recipes)
        keys = {f"cve:snap:{r['name']}:{r['scope']}": r for r in recipes}
        try:
            stored = cache.get_many(list(keys))
        except Exception:  # noqa: BLE001
            stored = {}

        def age_of(key):  # a missing or older snapshot goes first
            entry = stored.get(key)
            return float('inf') if not isinstance(entry, dict) or 'at' not in entry else snapshot_cache._now() - entry['at']
        for key in sorted(keys, key=age_of, reverse=True):
            rec = keys[key]
            if time.monotonic() - started > budget:
                summary['out_of_time'] += 1
                continue
            spec = known.get(rec['name'])
            if spec is None:
                summary['dropped'] += 1
                continue
            compute, fresh, etag_of, after = spec
            allowed = rec['allowed']
            tokens = tenancy_scope.set_scope(None if allowed is None else set(allowed), None)
            try:
                if snapshot_cache.scope_hash(*rec['params']) != rec['scope']:
                    summary['dropped'] += 1  # the scope's projects changed since the request: that key is no one's now
                    continue
                status, entry = snapshot_cache.refresh(rec['name'], rec['scope'], lambda: compute(rec['args']), fresh, etag_of,
                                                       due_age=max(0, fresh - interval))
                summary[status] += 1
                if after and entry is not None and status in ('refreshed', 'fresh'):
                    after(rec, entry)
            except Exception:  # noqa: BLE001 - one scope's failure never stops the others
                summary['errors'] += 1
                logger.exception('live snapshot refresh of %s failed', rec['name'])
            finally:
                tenancy_scope.reset_scope(tokens)
    finally:
        summary['seconds'] = round(time.monotonic() - started, 3)
        snapshot_cache.beat({'state': 'idle', **{k: summary[k] for k in ('hot', 'refreshed', 'errors', 'seconds')}})
        try:
            cache.delete(run_lock)
        except Exception:  # noqa: BLE001
            pass
    return summary
