"""One measurement for the auto-tuner (cveFeed.autotune), taken every run (ten minutes): numbers only, never a host name, an address, a finding
or any text from a scanned host, so the same dictionary can be shown on the page, stored with a decision and summarised for the AI advisor.

Every probe is wrapped: one that fails leaves its numbers out (None), and a rule that needs a number it does not have never raises the setting
(``cveFeed.autotune_policy``). What is read:

* memory: per scanning container, the share of memory free (the lowest over the interval, from the 30 second history ``reNgine.resources``
  keeps), the memory budget, memory kills (by scanner kind), how often each scanner kind had a run waiting for its turn and the most that ran
  at once, and what one run of each kind costs (the learned peak with its margin, or the estimate);
* the database: client connections in use and ``max_connections``;
* the CPU: the one-minute load per core;
* the discovery worker: whether it answers (the 30 second tick's record), its ceiling, the tasks it runs now and the messages waiting;
* Sentinels: live ones, their slots and the slots in use, queued work and its age, and the waits that timed out and ran locally instead;
* assessments: queued and running, and the age of the oldest queued one;
* the work conductor: whether its last round was held back by its depth while targets were due, or had nothing to do;
* scanner failures that point at load (a timeout, out of memory, a kill) by scanner kind;
* whether scanning is paused and whether an update is being applied;
* the facts the targets are sized from (``cveFeed.autotune_policy.size_for``): the CPU cores this container may use (its cgroup quota, else the
  machine's count), the scanning container's total memory, the hosts and targets in the inventory, and the share of free disk.
"""
import json
import logging
import os
import time

logger = logging.getLogger(__name__)

INTERVAL_SECONDS = 600


def _probe(name, fn, default=None):
    try:
        return fn()
    except Exception:  # noqa: BLE001 - one measurement that cannot be taken never stops the others
        logger.debug('auto-tune: %s could not be measured', name, exc_info=False)
        return default


def memory(now, interval=INTERVAL_SECONDS):
    from reNgine import resources
    out = {'reported': False, 'free_frac': None, 'budget_mb': None, 'kills': 0, 'kills_by_kind': {}, 'waiting': {}, 'running': {}, 'cost_mb': {}}
    store = resources.get_store()
    if not isinstance(store, resources.RedisStore):
        return out
    since = now - interval
    free, budgets, totals, counted = [], [], [], 0
    waits, running = {}, {}
    for key in store.r.scan_iter(match='cvengine:heavy:*:state'):
        try:
            state = json.loads(store.r.get(key) or '{}')
        except ValueError:
            continue
        if now - float(state.get('t', 0)) > 180:
            continue  # a container that stopped reporting
        namespace = key[:-len(':state')]
        other = resources.RedisStore(store.r, namespace)
        mem = state.get('memory') or {}
        if mem.get('total_mb'):
            free.append(mem.get('available_mb', 0) / mem['total_mb'])
            totals.append(int(mem['total_mb']))
        if state.get('budget_mb'):
            budgets.append(int(state['budget_mb']))
        for event in other.events():
            if float(event.get('t', 0)) >= since:
                out['kills'] += 1
                kind = str(event.get('kind') or '')
                out['kills_by_kind'][kind] = out['kills_by_kind'].get(kind, 0) + 1
        for kind in resources.BASE_COSTS_MB:
            cost = resources.effective_cost(kind, other)
            out['cost_mb'][kind] = max(out['cost_mb'].get(kind, 0), cost)
    for item in resources.adaptive_history(since):
        mem = item.get('memory') or {}
        if mem.get('total_mb'):
            free.append(mem.get('available_mb', 0) / mem['total_mb'])
        counted += 1
        for kind, n in (item.get('waiting_by_kind') or {}).items():
            if n:
                waits[kind] = waits.get(kind, 0) + 1
        for kind, n in (item.get('running_by_kind') or {}).items():
            running[kind] = max(running.get(kind, 0), int(n or 0))
    if free and budgets:
        out.update(reported=True, free_frac=round(max(0.0, min(1.0, min(free))), 3), budget_mb=min(budgets), total_mb=min(totals) if totals else None)
    out['waiting'] = {kind: round(n / counted, 2) for kind, n in waits.items()} if counted else {}
    out['running'] = running
    return out


def database():
    from django.db import connection
    with connection.cursor() as cursor:
        cursor.execute("SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'client backend'")
        used = int(cursor.fetchone()[0])
        cursor.execute('SHOW max_connections')
        top = int(cursor.fetchone()[0])
    return {'used': used, 'max': top}


def cores():
    """The CPU cores this container may use: its cgroup v2 quota (``cpu.max``) when one is set, else the machine's count."""
    count = os.cpu_count() or 1
    try:
        with open('/sys/fs/cgroup/cpu.max') as f:
            quota, period = f.read().split()[:2]
        if quota != 'max':
            count = min(count, max(1, int(int(quota) / int(period))))
    except (OSError, ValueError):
        pass
    return count


def size():
    """How big the instance is and how much disk is left: {'hosts', 'targets', 'disk_free_percent'}."""
    import shutil

    from django.conf import settings

    from cveFeed.models import HostState
    from targetApp.models import Domain
    out = {'hosts': HostState.objects.count(), 'targets': Domain.objects.exclude(project=None).count(), 'disk_free_percent': None}
    path = getattr(settings, 'RENGINE_RESULTS', None)
    path = path if path and os.path.isdir(path) else getattr(settings, 'RENGINE_HOME', '/')
    usage = shutil.disk_usage(path)
    if usage.total:
        out['disk_free_percent'] = round(usage.free * 100 / usage.total, 1)
    return out


def load():
    per_core = os.getloadavg()[0] / (os.cpu_count() or 1)
    return round(per_core, 2)


def discovery(now):
    from cveFeed import scan_concurrency
    running = scan_concurrency.running_discovery()
    workers = running.get('workers') or {}
    replying = bool(workers) and running.get('age_seconds') is not None and running['age_seconds'] <= scan_concurrency.RUNNING_STALE_SECONDS
    out = {'replying': replying, 'ceiling': running.get('value'), 'active': None, 'queued': None}
    out['queued'] = _probe('discovery queue', _discovery_queue)
    if replying:
        out['active'] = _probe('discovery tasks', lambda: _discovery_active(list(workers)))
    return out


def _discovery_queue():
    from agentapi.system_status import PRIORITY_SUFFIXES, _broker_client
    client = _broker_client()
    return sum(client.llen('discovery_queue' + suffix) for suffix in PRIORITY_SUFFIXES)


def _discovery_active(names):
    from reNgine.celery import app
    active = app.control.inspect(timeout=1.5, destination=names).active() or {}
    if not active:
        return None
    return sum(len(tasks or []) for name, tasks in active.items() if name in names)


def sentinels(now, interval=INTERVAL_SECONDS):
    from datetime import timedelta

    from django.utils import timezone

    from agentapi.agent_broker import LIVE_WINDOW
    from agentapi.models import Agent, SentinelTask
    at = timezone.now()
    live = list(Agent.objects.filter(kind='scanner', status='active', last_seen__gte=at - LIVE_WINDOW))
    slots = sum(min(a.max_concurrent, (a.limits or {}).get('max_concurrent') or a.max_concurrent) for a in live)
    in_use = SentinelTask.objects.filter(agent__in=live, status__in=('claimed', 'running')).count() if live else 0
    queued = SentinelTask.objects.filter(status='queued')
    oldest = queued.order_by('created_at').values_list('created_at', flat=True).first()
    since = at - timedelta(seconds=interval)
    expired = SentinelTask.objects.filter(status='expired', finished_at__gte=since)
    return {'live': len(live), 'slots': slots, 'in_use': in_use, 'queued': queued.count(),
            'oldest_queued_s': int((at - oldest).total_seconds()) if oldest else None,
            'timeouts': expired.filter(error__icontains='timed out').count(),
            'fallbacks': expired.filter(error__icontains='in time').count()}


def assessments():
    from django.utils import timezone

    from cveFeed.models import HostAssessment
    at = timezone.now()
    queued = HostAssessment.objects.filter(status='queued')
    oldest = queued.order_by('created_at').values_list('created_at', flat=True).first()
    return {'queued': queued.count(), 'running': HostAssessment.objects.filter(status='running').count(),
            'oldest_s': int((at - oldest).total_seconds()) if oldest else None}


def conductor_state():
    from cveFeed import conductor
    last = conductor.last_round() or {}
    depth = conductor.wanted_depth()
    if not depth:
        return {'depth': 0, 'active': None, 'state': 'off'}
    skipped = last.get('skipped')
    if skipped == 'paused':
        state = 'paused'
    elif skipped == 'nothing is due':
        state = 'idle'
    elif last.get('active') is not None and last['active'] >= depth:
        state = 'saturated' if conductor.next_targets(1) else 'full'  # held back by its depth with a target due, or simply busy
    elif last:
        state = 'filling'
    else:
        state = 'unknown'
    return {'depth': depth, 'active': last.get('active'), 'state': state}


def capacity_failures(now, interval=INTERVAL_SECONDS):
    from datetime import timedelta

    from django.db.models import Count
    from django.utils import timezone

    from cveFeed.performance_review import CAPACITY_PATTERN, STAGE_KINDS
    from startScan.models import ScanActivity
    since = timezone.now() - timedelta(seconds=interval)
    out = {}
    rows = (ScanActivity.objects.filter(time__gte=since, status=0, name__in=STAGE_KINDS, error_message__iregex=CAPACITY_PATTERN)
            .values('name').annotate(n=Count('id')))
    for row in rows:
        kind = STAGE_KINDS[row['name']]
        out[kind] = out.get(kind, 0) + row['n']
    return out


def paused():
    from cveFeed.scan_control import pause_requested
    return bool(pause_requested(fail_closed=True))


def updating():
    from cveFeed import updater
    return updater.read_phase().get('phase') in ('draining', 'applying')


def collect(now=None, boot=''):
    """One measurement (a plain dictionary of numbers). ``now`` in seconds since the epoch."""
    now = now or time.time()
    return {
        't': now, 'boot': boot,
        'paused': _probe('pause', paused, True), 'updating': _probe('update', updating, False),
        'memory': _probe('memory', lambda: memory(now), {'reported': False}),
        'db': _probe('database', database, {}),
        'load': _probe('load', load),
        'cores': _probe('cores', cores),
        'size': _probe('size', size, {}),
        'discovery': _probe('discovery', lambda: discovery(now), {'replying': None}),
        'sentinel': _probe('sentinels', lambda: sentinels(now), {}),
        'assess': _probe('assessments', assessments, {}),
        'conductor': _probe('conductor', conductor_state, {}),
        'failures': _probe('failures', lambda: capacity_failures(now), {}),
    }


def summarise(samples):
    """The window's measurements in a few numbers each, for the page, the API and the AI advisor."""
    if not samples:
        return {'measurements': 0}

    def nums(*path):
        out = []
        for s in samples:
            value = s
            for name in path:
                value = value.get(name) if isinstance(value, dict) else None
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                out.append(value)
        return out

    def span(*path, digits=2):
        values = nums(*path)
        return {'min': round(min(values), digits), 'max': round(max(values), digits), 'mean': round(sum(values) / len(values), digits)} if values else None

    db = [s['db']['used'] / s['db']['max'] for s in samples if (s.get('db') or {}).get('max') and (s['db'].get('used') is not None)]
    kinds = sorted({k for s in samples for k in ((s.get('memory') or {}).get('waiting') or {})} |
                   {k for s in samples for k in ((s.get('memory') or {}).get('running') or {})})
    last = samples[-1]
    return {
        'measurements': len(samples), 'minutes': int((samples[-1]['t'] - samples[0]['t']) // 60),
        'memory_free_share': span('memory', 'free_frac'), 'memory_budget_mb': (last.get('memory') or {}).get('budget_mb'),
        'memory_kills': sum(nums('memory', 'kills')),
        'database_connection_share': {'max': round(max(db), 2), 'mean': round(sum(db) / len(db), 2)} if db else None,
        'cpu_load_per_core': span('load'),
        'discovery': {'ceiling': (last.get('discovery') or {}).get('ceiling'), 'busy': span('discovery', 'active', digits=1),
                      'queued': span('discovery', 'queued', digits=1),
                      'not_answering': sum(1 for s in samples if (s.get('discovery') or {}).get('replying') is False)},
        'sentinel': {'live': (last.get('sentinel') or {}).get('live'), 'slots': (last.get('sentinel') or {}).get('slots'),
                     'slots_in_use': span('sentinel', 'in_use', digits=1), 'queued': span('sentinel', 'queued', digits=1),
                     'timeouts': sum(nums('sentinel', 'timeouts')), 'ran_locally': sum(nums('sentinel', 'fallbacks'))},
        'assessments': {'queued': span('assess', 'queued', digits=1), 'oldest_queued_minutes': (max(nums('assess', 'oldest_s')) // 60) if nums('assess', 'oldest_s') else None},
        'conductor': {state: sum(1 for s in samples if (s.get('conductor') or {}).get('state') == state)
                      for state in ('saturated', 'full', 'filling', 'idle', 'off', 'paused')},
        'scanners': {kind: {'waiting_share': round(sum(nums('memory', 'waiting', kind)) / len(samples), 2),
                            'most_running': max(nums('memory', 'running', kind), default=0),
                            'mb_per_run': (last.get('memory') or {}).get('cost_mb', {}).get(kind),
                            'capacity_failures': sum(nums('failures', kind))} for kind in kinds},
        'paused_measurements': sum(1 for s in samples if s.get('paused') or s.get('updating')),
    }
