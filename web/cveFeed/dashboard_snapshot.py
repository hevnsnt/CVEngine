"""One precomputed snapshot per project: every number and the attack-surface map of the dashboard.

The dashboard used to ask four endpoints (headline counts, the map, the ticker's counts, the host search for the "Hosts scanned" tile) that each walked
the whole inventory of the caller's scope, in the request, behind a cache keyed by the scope (a hash of every project id the caller sees) and fresh for
5 to 15 seconds. On a 15-project instance with an open dashboard that meant the same few-second to tens-of-seconds computation, over everything,
again and again, by whichever request or refresher run found the key stale; any change bumped the revision and made all of it cold at once.

Now the unit of work is a project, and the request never computes:

* ``compute_project(pid)`` builds the snapshot of one project (headline counts, the ticker's counts, the coverage counts the search facets give, the
  graph) under that project's own scope, and ``refresh_project`` stores it under ``cve:dash:p:<id>``: a key of the project, never of a user or a request.
* A request reads the snapshots of the projects it may see (``collect``) and sums them (``merge_stats``, ``merge_graph``): the all-projects view is
  the sum of the per-project numbers, which is exact because a host, a finding and a match belong to one project. It answers at once with what
  is stored, however old, and says how old (``as_of``). Entries that do not exist yet make the answer ``partial`` and are scheduled.
* Refreshing is background work only. ``refresh_dashboard_snapshots`` (celery beat, every minute) refreshes the projects whose snapshot is older than
  ``REFRESH_AFTER``; ``mark_dirty`` (a Sentinel result landed, or a finding changed) asks for one soon, at most one queued refresh per project per
  ``DEBOUNCE`` seconds however many results arrive; a request that finds a snapshot older than ``REFRESH_AFTER`` asks for the same debounced refresh and
  does not wait for it. A poll never refreshes anything by itself.
* One refresh of one project is bounded by that project's size (600 hosts, not 3,000), takes a lock so two never run at once, and a failure keeps
  the previous snapshot.

Unrestricted callers (an App Admin with no project filter) are summed over every project that exists; rows that belong to no project are not part of
the dashboard's numbers.
"""
import hashlib
import logging
import threading
import time

from django.core.cache import cache

logger = logging.getLogger(__name__)

KEY = 'cve:dash:p:%s'
LOCK = 'cve:dash:lock:%s'
QUEUED = 'cve:dash:queued:%s'
DIRTY = 'cve:dash:dirty:%s'
VERSION = 1  # bump when the shape of a snapshot changes: older entries are then ignored and rebuilt
KEEP_SECONDS = 7 * 24 * 3600  # an entry is kept this long without a refresh: a stale answer beats a dash
STALE_AFTER = 120  # older than this and the page says "as of N minutes ago"
REFRESH_AFTER = 90  # the beat task and the requests ask for a refresh when the snapshot is older than this
DEBOUNCE = 15  # at most one queued refresh per project per this many seconds
LOCK_SECONDS = 600
BEAT_BUDGET = 50  # one beat run stops starting new refreshes after this many seconds (the next run, a minute later, continues)

# the parts of stats_payload that are per project and add up; everything else in it is either global (the CVE catalogue) or live (read fresh per request)
SUM_KEYS = ('targets', 'certs_expiring', 'certs_total', 'hygiene_open', 'hosts', 'hosts_live', 'matches', 'match_groups', 'scanner_findings', 'exposed_hosts')
GLOBAL_KEYS = ('tiers', 'cves', 'autofire_runs', 'templates')
LIVE_KEYS = ('scans_running', 'scans_queued', 'scans_background_running')
HYGIENE_CHECKS = 50


def _now():
    return time.time()


def key_of(pid):
    return KEY % pid


# --- building ----------------------------------------------------------------

def coverage_of(project):
    """The facets of an empty host search over this project (heat per host, the hosts with no address to scan): what the Hosts scanned tile reads."""
    from agentapi import services
    qs = services._internal_filter(services.search_host_rows(project, []), {})
    heat, by_id, truncated = services._heat_facets(project, qs)
    return {'heat': heat, 'truncated': bool(truncated), 'unscannable': services._unscannable_facet(qs, by_id)}


def compute_project(pid):
    """The snapshot payload of one project, computed under that project's scope (what a member of just that project would be shown). The host walk
    (``counts.host_reps``) is the expensive read and is run once for the whole build (``counts.walk_memo``)."""
    from cveFeed import counts, views
    from dashboard.models import Project
    from tenancy import scope as tenancy_scope
    tokens = tenancy_scope.set_scope({pid}, None)
    started = time.monotonic()
    try:
        project = Project.objects.filter(pk=pid).first()
        if project is None:
            return None
        with counts.walk_memo():
            stats = views.stats_payload()
            for k in LIVE_KEYS:
                stats.pop(k, None)
            stats['hygiene_checks'] = counts.hygiene_top_checks(HYGIENE_CHECKS)
            stats_seconds = time.monotonic() - started
            live, ips, ports = views.discovery_sets()
            discovery = {'hosts': len(live), 'ips': len(ips), 'ports': len(ports), 'ip_ids': sorted(ips), 'port_ids': sorted(ports)}
            return {'v': VERSION, 'project': {'id': pid, 'slug': project.slug}, 'stats': stats, 'discovery': discovery,
                    'coverage': coverage_of(project), 'graph': views.graph_payload(), 'stats_seconds': round(stats_seconds, 3),
                    'seconds': round(time.monotonic() - started, 3)}
    finally:
        tenancy_scope.reset_scope(tokens)


def refresh_project(pid, force=True):
    """Compute and store one project's snapshot. ``'refreshed'``, ``'busy'`` (another refresh holds the lock) or ``'gone'``. A failure keeps the
    previous snapshot and is logged."""
    lock = LOCK % pid
    try:
        if not cache.add(lock, 1, LOCK_SECONDS):
            return 'busy'
    except Exception:  # noqa: BLE001 - no cache, nothing to store into
        return 'busy'
    try:
        started = _now()
        payload = compute_project(pid)
        if payload is None:
            cache.delete(key_of(pid))
            return 'gone'
        cache.set(key_of(pid), {'payload': payload, 'at': _now(), 'started': started}, KEEP_SECONDS)
        return 'refreshed'
    except Exception:  # noqa: BLE001
        logger.exception('dashboard snapshot of project %s failed; the previous one stays', pid)
        return 'failed'
    finally:
        try:
            cache.delete(lock)
        except Exception:  # noqa: BLE001
            pass


# --- asking for refreshes (never in the request's own time) ------------------

def _enqueue(pid, countdown):
    try:
        from cveFeed.tasks import refresh_dashboard_snapshot
        refresh_dashboard_snapshot.apply_async(args=[pid], countdown=countdown, queue='live_cache_queue', expires=max(300, countdown * 10))
        return True
    except Exception:  # noqa: BLE001 - no broker: refreshed by the next beat run, or by a thread below
        return False


def schedule(pid, countdown=DEBOUNCE):
    """Ask for a refresh of one project soon: at most one queued per project per ``DEBOUNCE`` seconds. Returns whether one was queued by this call."""
    try:
        if not cache.add(QUEUED % pid, 1, DEBOUNCE):
            return False
    except Exception:  # noqa: BLE001
        return False
    if _enqueue(pid, countdown):
        return True
    threading.Thread(target=refresh_project, args=(pid,), daemon=True, name=f'dash-refresh-{pid}').start()  # no broker: do it beside the request
    return True


def mark_dirty(project_ids=None):
    """Something changed in these projects (a Sentinel result landed, a finding was closed): their snapshots are refreshed soon, once per ``DEBOUNCE``
    however many results arrive. ``None``: every project."""
    from reNgine import livecache_config
    if not livecache_config.dashboard_snapshots_enabled():
        return
    try:
        if project_ids is None:
            if not cache.add('cve:dash:bump', 1, 2):
                return  # a burst of changes (one call per row) is one mark: the refresh is queued DEBOUNCE seconds out and computes after all of them
            from dashboard.models import Project
            project_ids = list(Project.objects.values_list('id', flat=True))
        for pid in project_ids:
            if pid is None:
                continue
            cache.set(DIRTY % pid, _now(), KEEP_SECONDS)
            schedule(pid)
    except Exception:  # noqa: BLE001 - a dirty mark is never worth a failed ingestion
        logger.warning('could not mark the dashboard snapshots dirty', exc_info=True)


# --- reading -----------------------------------------------------------------

def read(ids):
    """``{id: entry or None}`` for these projects (one cache round trip)."""
    ids = list(ids)
    try:
        got = cache.get_many([key_of(i) for i in ids])
    except Exception:  # noqa: BLE001
        got = {}
    out = {}
    for i in ids:
        entry = got.get(key_of(i))
        ok = isinstance(entry, dict) and isinstance(entry.get('payload'), dict) and entry['payload'].get('v') == VERSION
        out[i] = entry if ok else None
    return out


def visible_ids():
    """The ids of the projects the running request may see (the tenancy-scoped manager)."""
    from dashboard.models import Project
    return sorted(Project.objects.values_list('id', flat=True))


def visible_ids_all():
    """Every project id that exists, whoever asks (a test, a management command)."""
    from dashboard.models import Project
    from tenancy import scope as tenancy_scope
    tokens = tenancy_scope.set_scope(None, None)
    try:
        return sorted(Project.objects.values_list('id', flat=True))
    finally:
        tenancy_scope.reset_scope(tokens)


def collect(ids=None, ask=True):
    """``(entries, meta)``: the stored snapshots of ``ids`` (default: every project the request may see) and how complete and how old they are.
    ``meta``: ``as_of`` (epoch seconds of the oldest snapshot), ``age`` (seconds), ``stale`` (older than ``STALE_AFTER``), ``partial`` (some project
    has none yet), ``missing`` (how many), ``projects``. Projects with no snapshot, or one older than ``REFRESH_AFTER``, are scheduled (debounced)
    when ``ask``: this never waits for them."""
    ids = visible_ids() if ids is None else list(ids)
    entries = read(ids)
    now = _now()
    missing = [i for i, e in entries.items() if e is None]
    have = [e for e in entries.values() if e is not None]
    oldest = min((e['at'] for e in have), default=None)
    if ask:
        for i, e in entries.items():
            if e is None or now - e['at'] > REFRESH_AFTER:
                schedule(i, countdown=0 if e is None else DEBOUNCE)
    age = None if oldest is None else max(0, int(now - oldest))
    return have, {'as_of': oldest, 'age': age, 'stale': age is not None and age > STALE_AFTER, 'partial': bool(missing), 'missing': len(missing),
                  'projects': len(ids)}


# --- summing -----------------------------------------------------------------

def _plus(a, b):
    return (a or 0) + (b or 0)


def merge_stats(entries):
    """The headline payload of the sum of these project snapshots: the same keys ``stats_payload`` returns (minus the live scan counts, which the caller
    adds fresh)."""
    parts = [e['payload']['stats'] for e in entries]
    out = {k: 0 for k in SUM_KEYS}
    any_part = parts[0] if parts else {}
    for k in GLOBAL_KEYS:
        out[k] = any_part.get(k, {'fire': 0, 'smoke': 0, 'ice': 0} if k == 'tiers' else 0)
    checks, groups_truncated = {}, False
    for s in parts:
        for k in SUM_KEYS:
            out[k] = _plus(out[k], s.get(k))
        groups_truncated = groups_truncated or bool(s.get('match_groups_truncated'))
        for c in s.get('hygiene_checks') or []:
            row = checks.setdefault(c['check'], {'check': c['check'], 'worst': c['worst'], 'n': 0})
            row['n'] += c['n']
            if _SEV_RANK.get(c['worst'], 0) > _SEV_RANK.get(row['worst'], 0):
                row['worst'] = c['worst']
    out['match_groups_truncated'] = groups_truncated
    out['hygiene_top'] = sorted(checks.values(), key=lambda r: (-_SEV_RANK.get(r['worst'], 0), -r['n'], r['check']))[:3]
    oldest = max((s for s in parts if s.get('oldest_open_days') is not None), key=lambda s: s['oldest_open_days'], default=None)
    for k in ('oldest_open_days', 'oldest_open_kind', 'oldest_open_id', 'oldest_open_what'):
        out[k] = oldest.get(k) if oldest else None
    out['internal'] = _merge_internal([s.get('internal') or {} for s in parts])
    return out


_SEV_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}


def _merge_internal(parts):
    have = [p for p in parts if p.get('has')]
    if not have:
        return {'has': False, 'networks': [], 'hosts': 0, 'hosts_live': 0, 'findings': 0, 'matches': 0, 'last_scan_at': None, 'sentinels_online': 0}
    return {'has': True, 'networks': [n for p in have for n in p.get('networks') or []],
            **{k: sum(p.get(k) or 0 for p in have) for k in ('hosts', 'hosts_live', 'findings', 'matches', 'sentinels_online')},
            'last_scan_at': max((p['last_scan_at'] for p in have if p.get('last_scan_at')), default=None)}


def merge_discovery(entries):
    """The ticker's counts of the sum: live hosts add up (a host belongs to one project), addresses and ports are unions of the projects' id sets, so an
    address two projects of one organization share is counted once, as a single walk over everything counts it."""
    ips, ports, hosts = set(), set(), 0
    for e in entries:
        d = e['payload'].get('discovery') or {}
        hosts += d.get('hosts', 0)
        ips.update(d.get('ip_ids') or ())
        ports.update(d.get('port_ids') or ())
    return {'hosts': hosts, 'ips': len(ips), 'ports': len(ports)}


def merge_coverage(entries):
    """``{'heat', 'unscannable', 'truncated'}`` summed: what ``facets`` of a host search over these projects would say."""
    heat, truncated = {}, False
    un = {'count': 0, 'private': 0, 'no_dns': 0, 'unknown': 0}
    for e in entries:
        c = e['payload'].get('coverage') or {}
        for k, v in (c.get('heat') or {}).items():
            heat[k] = heat.get(k, 0) + v
        truncated = truncated or bool(c.get('truncated'))
        for k in un:
            un[k] += (c.get('unscannable') or {}).get(k, 0)
    return {'heat': heat, 'truncated': truncated, 'unscannable': un}


def graph_version(entries):
    """A token that moves exactly when one of the summed snapshots was replaced."""
    raw = ','.join(f"{e['payload']['project']['id']}@{e['at']:.3f}" for e in sorted(entries, key=lambda e: e['payload']['project']['id']))
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


def merge_graph(entries, cap):
    """The map of the sum: the riskiest hosts of every project first, each with the nodes it brings (its target, addresses, CVEs), until ``cap`` nodes are
    drawn, which is the cut a single walk over everything makes (``graph_payload`` stops adding nodes at the same ``cap``)."""
    hosts, nodes_by_id, projects, per_project, edges, cut = [], {}, {}, {}, [], False
    for e in entries:
        g = e['payload'].get('graph') or {}
        projects.update(g.get('projects') or {})
        h = g.get('hosts') or {}
        per_project.update(h.get('projects') or {})
        cut = cut or h.get('drawn', 0) < h.get('total', 0)
        for n in g.get('nodes') or []:
            nodes_by_id.setdefault(n['id'], n)
            if n['kind'] == 'subdomain':
                hosts.append(n)
        edges.extend(g.get('edges') or [])
    brings = {}
    for x in edges:
        for a, b in ((x['from'], x['to']), (x['to'], x['from'])):
            if a.startswith('sub:'):
                brings.setdefault(a, set()).add(b)
    hosts.sort(key=lambda n: (-(n.get('score') if n.get('score') is not None else -1), n['label'], n['id']))
    drawn, kept = set(), []
    for n in hosts:
        need = {n['id']} | {b for b in brings.get(n['id'], ()) if not b.startswith('sub:')}
        if len(drawn | need) > cap:
            cut = True
            break
        drawn |= need
        kept.append(n)
    kept_ids = {n['id'] for n in kept}
    seen, out_edges = set(), []
    for x in sorted(edges, key=lambda x: (x['from'], x['to'])):
        t = (x['from'], x['to'])
        if t not in seen and x['from'] in drawn and x['to'] in drawn:
            seen.add(t)
            out_edges.append(x)
    nodes = [nodes_by_id[i] for i in sorted(drawn, key=lambda i: (i not in kept_ids, i)) if i in nodes_by_id]
    n_drawn = len(kept)
    total = n_drawn if not cut else max(sum(per_project.values()), n_drawn)
    return {'nodes': nodes, 'edges': out_edges, 'hosts': {'drawn': n_drawn, 'total': total, 'projects': per_project if cut else {}}, 'projects': projects}


def refresh_due(budget=BEAT_BUDGET):
    """What the beat task does: refresh, oldest first, every project that has no snapshot, is marked dirty or whose snapshot is older than
    ``REFRESH_AFTER``, until ``budget`` seconds are used. Returns a summary."""
    from dashboard.models import Project
    started = time.monotonic()
    ids = list(Project.objects.values_list('id', flat=True))  # a celery task has no scope: every project
    entries = read(ids)
    now = _now()
    try:
        dirty = cache.get_many([DIRTY % i for i in ids])
    except Exception:  # noqa: BLE001
        dirty = {}

    def due(i):
        e = entries[i]
        return e is None or now - e['at'] > REFRESH_AFTER or (DIRTY % i in dirty and dirty[DIRTY % i] > e['started'])
    order = sorted((i for i in ids if due(i)), key=lambda i: entries[i]['at'] if entries[i] else 0)
    summary = {'projects': len(ids), 'due': len(order), 'refreshed': 0, 'busy': 0, 'failed': 0, 'gone': 0, 'left': 0}
    for n, i in enumerate(order):
        if time.monotonic() - started > budget:
            summary['left'] = len(order) - n
            break
        summary[refresh_project(i)] += 1
    summary['seconds'] = round(time.monotonic() - started, 2)
    return summary


def refresh_all(budget=None):
    """Compute every project's snapshot now, in this process, in order: what ``manage.py refresh_dashboard_snapshots`` does after an upgrade or a cache
    flush, and what tests call to have numbers to read. Returns ``{project id: outcome}``."""
    from dashboard.models import Project
    return {pid: refresh_project(pid) for pid in Project.objects.values_list('id', flat=True)}
