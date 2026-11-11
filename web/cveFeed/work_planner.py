"""The work planner: keeps the Sentinels busy with checks that are due, without waiting for a whole target to be rescanned.

Why it exists. A Sentinel task has no life of its own: a Celery job creates it, waits for it and files the result (``agentapi.sentinel_dispatch``). Every
such job came from a scan stage, a host assessment or a sweep. ``secrets_scan`` and ``ssh_probe`` (1.4) were only ever stages of a full scan, so a host
scanned before 1.4 got neither until its whole target was scanned again, and with idle Sentinel slots and an empty queue nothing created work.
``cveFeed.check_coverage`` knows which checks are due per host but is accounting only. This module turns "due" into Sentinel work.

What it is. A deterministic planner with no AI, no model call and nothing that waits on one. Two beat tasks (``cveFeed.tasks``):

* ``work_planner_census`` (every 5 minutes): which checks are due, per project, from ``check_coverage`` (the exact rules: not applicable, excluded, archived,
  CDN or shared edge, internal, the ledger window). One pass over the current inventory, about 2 s and 3,000 queries for 3,000 hosts, so it is its own task and
  the answer (the due units, each with its sort key) is kept in the cache. The tick never runs it.
* ``work_planner_tick`` (every minute, and again 3 s after a planned batch ends): measures the Sentinels (``sentinel_broker.planner_capacity``: live Sentinels,
  free slots per kind, queued and held tasks), and when slots are idle and the queue is shallow, queues batches of due units. A batch is one Sentinel task
  (``ssh_probe``: at most 25 endpoints, ``secrets_scan``: at most 25 hosts) run by ``work_planner_batch`` through the same entry points the scan stages use
  (``ssh_scan.run_for_hosts``, ``secrets_scan.run_for_hosts``), so the scope policy, the do-not-scan guard (``sentinel_dispatch._refuse``), the bug bounty
  gate, the ledger window, claims and storage all apply unchanged. No scan is created.

How much. The queue is kept at ``planner_queue_factor`` (2) times the idle slots of each kind, never more than ``planner_max_queue_per_sentinel`` (10)
tasks waiting per live Sentinel, at most ``planner_batches_per_run`` (12) batches per run. Planner tasks carry priority 0 (``sentinel_broker.PLANNER_PRIORITY``):
a Sentinel takes validation (3), smoke (2) and every scan stage (1) first, and the host assessment feed does not count them as queued first-pass work. Slots a
task of another kind is already waiting for are not idle. A kind that failed three batches in a row is left alone for 10 minutes, a unit of a failed or
refused batch for 30 minutes and 6 hours, and the Sentinel's own "paused after repeated failures" (``failing_kinds``) and its contract gate
(``sentinel_contract.can_run``) are in ``SentinelEff.caps``, so a Sentinel that cannot run a kind is no capacity for it.

Who first. Projects are served round-robin across organizations and then projects (one batch per turn, the position kept between runs), so a project with a
thousand targets cannot take the queue. Inside a project the order is: exposed hosts (an open port on an address a scanner may reach), more open ports first,
web hosts that answered for secrets, then never run before oldest run, then name.

What it never does. It plans nothing for a host the coverage rules call not applicable (excluded, archived, internal, out of scope), a manual-only target, a
bug bounty project that has not confirmed automated testing, a project no live Sentinel covers, an address on the organization's do-not-scan list, or while
scanning is paused or the instance switch is off (``planner_enabled``, Settings, Work planner). It never makes a Sentinel kind or changes the contract.

Secrets. ``secrets_scan.plan`` reads the route check's rows, so only web hosts that already have them are planned; a due web host without them is counted as
waiting for the route check (the route check stays a scan stage, see docs/PIPELINE.md).
"""
import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta

from django.db.models import prefetch_related_objects
from django.core.cache import cache
from django.utils import timezone

logger = logging.getLogger(__name__)

CENSUS_KEY = 'cvengine:planner:census'
LAST_KEY = 'cvengine:planner:last'
LOCK_KEY = 'cvengine:planner:lock'
CURSOR_KEY = 'cvengine:planner:cursor'
SKIP_KEY = 'cvengine:planner:skip:{kind}:{project}:{unit}'
CENSUS_TTL = 20 * 60  # three beats and a little: a census that stops being refreshed is not read for ever
LOCK_SECONDS = 120
TICK_SECONDS = 60
PAGE = 200  # hosts per ``check_coverage.load`` call: the page size its own listings use
MAX_UNITS_PER_PROJECT_KIND = 3000
FAIL_STREAK = 3
FAIL_COOLDOWN = timedelta(minutes=10)
UNIT_FAILED_FOR = 30 * 60  # seconds a unit of a failed batch is left alone
UNIT_REFUSED_FOR = 6 * 3600  # seconds a unit a guard refused is left alone
QUEUED_LOST_AFTER = timedelta(minutes=30)
RUNNING_LOST_AFTER = timedelta(hours=2)
KEEP_FINISHED = timedelta(days=7)
SLACK = 3  # candidates read from the ledger per wanted unit: some are fresh since the census, some are in flight
PLANNER_QUEUE = 'planner_queue'


class Spec:
    """One check the planner keeps alive: the Sentinel task kind, the ``check_coverage`` check it serves, and how its units read in a sentence."""

    def __init__(self, kind, check_id, service, noun, per_task):
        self.kind, self.check_id, self.service, self.noun, self.per_task = kind, check_id, service, noun, per_task

    def phrase(self, n):
        return f'{n:,} {self.noun}{"" if n == 1 else "s"}'


def specs():
    """The planner-enabled kinds, in the order they take turns."""
    from cveFeed import secrets_scan, ssh_scan
    return {'ssh_probe': Spec('ssh_probe', 'ssh-inspection', ssh_scan.SERVICE, 'SSH check', ssh_scan.MAX_TARGETS_PER_TASK),
            'secrets_scan': Spec('secrets_scan', 'secrets-scan', secrets_scan.SERVICE, 'secret check', secrets_scan.MAX_HOSTS)}


# Every Sentinel task kind is planner-enabled (``specs``) or listed here with the reason and the ``check_coverage`` check it belongs to, if any
# (tests.test_work_planner holds the two lists to the contract's kinds: a new kind fails there until it is placed in one of them).
NOT_PLANNED = {
    'nmap': ('nmap', 'a stage of the host pipeline and of the background sweeps; the host assessment feed (coverage_topup) queues first passes'),
    'naabu': ('naabu', 'a stage of the host pipeline; the host assessment feed queues first passes'),
    'nmap_full': ('full-ports', 'its own paced background sweep (cveFeed.fullscan), one address at a time'),
    'nmap_udp': ('udp', 'its own paced background sweep (cveFeed.udp_scan)'),
    'nmap_verify': (None, 'a follow-up of a finding, not a recurring check'),
    'nuclei_light': ('nuclei-tech', 'a stage of the host pipeline; the host assessment feed re-checks the stalest hosts'),
    'nuclei_targeted': ('nuclei', 'a stage of the host pipeline; the host assessment feed re-checks the stalest hosts'),
    'nuclei_deep': ('nuclei-deep', 'its own paced weekly sweep (weekly_deep_nuclei)'),
    'nuclei_validate': (None, 'a validation of a finding, queued by validation'),
    'testssl': ('tls-audit', 'its own daily sweep (testssl_sweep)'),
    'wpscan': ('wpscan', 'a stage of the host pipeline, and its own quick pass for the sites the stage missed'),
    'wpscan_thorough': ('wpscan-thorough', 'its own sweep, one site per project at a time (hours per site)'),
    'openvas': ('openvas', 'its own sweep, an optional add-on that runs one GVM task at a time'),
    'discover': (None, 'internal range discovery, queued by the internal discovery sweep'),
    'bbot_discovery': ('discovery', 'target discovery, queued by the work conductor'),
    'waf': ('waf', 'a stage of the host pipeline'),
    'http_probe': ('version-probes', 'a stage of the host pipeline: it needs the products the port stage saw'),
    'dns_resolve': (None, 'name lookups of discovery and the retire check, not a per-host check'),
    'node2shell': ('node2shell', 'a stage of the host pipeline, for hosts already fingerprinted as Node.js'),
    'rdp_shot': ('rdp-screenshot', 'a stage of the host pipeline'),
    'db_probe': ('db-exposure', 'a stage of the host pipeline'),
    'path_probe': (None, 'a validation re-test, queued by validation'),
    'alive_check': (None, 'the retire check of a vanished name'),
    'bucket_check': (None, 'its own daily sweep (bucket_sweep)'),
    'vhost_probe': ('vhost', 'its own slow polite sweep (vhost_sweep)'),
    'subdir_probe': ('subapps', 'its own slow polite sweep (subdir_apps_sweep)'),
    'supplier_check': (None, 'its own daily sweep (supplier_sweep)'),
    'hygiene_check': ('email-auth', 'its own daily sweep (run_hygiene_all)'),
    'dangling_dns_check': (None, 'a follow-up of a baddns finding'),
    'route_probe': ('web-routes', 'a stage of the host pipeline; the planner needs its rows as a prerequisite of secrets_scan and waits for them (a follow-up)'),
    'route_probe_signed': ('routes-signed-in', 'built-in scanner only, needs a stored sign-in: never queued by a planner'),
    'page_read': (None, 'a validation re-test, queued by validation'),
    'identity_check': (None, 'name and certificate reads of discovery, not a per-host check'),
    'web_screenshot': (None, 'its own drain and hourly backfill (drain_screenshots)'),
}


# ----------------------------------------------------------------------------- settings

def _tunable(key, default):
    from cveFeed import tunables
    try:
        return int(tunables.value(key, default))
    except Exception:  # noqa: BLE001 - the saved copy is a cache: the default decides
        return default


def enabled():
    return _tunable('planner_enabled', 1) != 0


def queue_factor():
    return max(1, _tunable('planner_queue_factor', 2))


def max_queue_per_sentinel():
    return max(1, _tunable('planner_max_queue_per_sentinel', 10))


def batches_per_run():
    return max(1, _tunable('planner_batches_per_run', 12))


# ----------------------------------------------------------------------------- the census: what is due

def _sort_key(h, entry, web=False):
    """Ascending, exposed first: ``[0 if an address a scanner may reach has an open port else 1, minus the open ports, 0 if a web host answered (secrets) else 1,
    seconds since the epoch of the last run (0 when it never ran)]``."""
    ports = {(a.address, p.number) for a in h.scannable() for p in a.ports if p.protocol in ('', 'tcp')}
    last = entry.get('last_run')
    stamp = 0
    if last:
        try:
            stamp = int(datetime.fromisoformat(last).timestamp())
        except ValueError:
            stamp = 0
    return [0 if ports else 1, -len(ports), (0 if h.http_up else 1) if web else 0, stamp]


def _pages(hosts):
    """``hosts`` (a Subdomain queryset) in id order, ``PAGE`` rows at a time: the ids are read once (the current-inventory filter, a dear predicate, runs one time
    and not once per page, and a list of ids is small), each page of rows is then read by its ids, through the same filter again (cheap for 200 ids): a host deleted, or no longer current, since the ids were
    read is not checked, and is not counted as the copy of its name that the other copies are then dropped for. Yields lists of rows."""
    ids = list(hosts.order_by('id').values_list('pk', flat=True))
    for start in range(0, len(ids), PAGE):
        yield list(hosts.filter(pk__in=ids[start:start + PAGE]).select_related('target_domain').order_by('id'))


def build_census(now=None):
    """The due checks of every project, from ``check_coverage``: ``{'at', 'projects': {id: {'slug', 'org', 'blocked', 'kinds': {kind: {'applicable', 'due',
    'awaiting', 'units': [{'u', 'd', 's', 'h'?}]}}}}}``. Read-only. ``u`` is the unit (``address:port`` or a host name), ``d`` its target, ``s`` its sort key and ``h``
    the host names of an SSH endpoint."""
    from cveFeed import check_coverage as cc
    from cveFeed import exclusions
    from cveFeed.conductor import bounty_blocked_projects
    from cveFeed.correlation import latest_scan_q
    from cveFeed.internal_scan import TASK_TAG as INTERNAL_PIPELINE_TASK
    from cveFeed.models import RouteAuth
    from dashboard.models import Project
    from startScan.models import Subdomain
    from targetApp.models import Domain
    now = now or timezone.now()
    want = specs()
    blocked = bounty_blocked_projects()
    out = {'at': now.isoformat(), 'projects': {}}
    for project in Project.objects.order_by('pk'):
        entry = out['projects'][str(project.pk)] = {'slug': project.slug, 'org': project.org_id, 'blocked': project.pk in blocked,
                                                    'kinds': {k: {'applicable': 0, 'due': 0, 'awaiting': 0, 'units': []} for k in want}}
        if entry['blocked']:
            continue
        banned = exclusions.excluded_names(project.pk)  # names, the networks of the do-not-scan list and the names that resolve into them
        if banned.unreadable:  # fail closed: nothing is planned for the project until the list can be read
            entry['blocked'], entry['note'] = True, 'the do-not-scan list could not be read'
            continue
        routed = set(RouteAuth.objects.filter(project_id=project.pk, retired_at__isnull=True).values_list('host', flat=True).distinct())
        hosts = (Subdomain.objects.filter(latest_scan_q(), target_domain__project=project).exclude(scan_history__tasks__contains=[INTERNAL_PIPELINE_TASK])
                 .exclude(target_domain__discovery_mode=Domain.DISCOVERY_MANUAL))

        def check_page(page):  # its own scope: what a page read (evidence, addresses, ports) is let go of when it returns, before the next page is read
            ev = cc.load([(s, [], project.pk) for s in page])
            for sub in page:
                h = ev.facts[sub.id]
                h.excluded = exclusions.normalize(h.name) in banned
                result = cc.coverage(h, ev, rich=True)
                by_id = {c['id']: c for c in result['checks']}
                for kind, spec in want.items():
                    check = by_id.get(spec.check_id)
                    if check is None or check['state'] == 'not_applicable':
                        continue
                    bucket = entry['kinds'][kind]
                    if kind == 'ssh_probe':
                        due = [u['unit'] for u in check.get('units', []) if u['state'] == 'due']
                        bucket['applicable'] += len(check.get('units', []))
                        for unit in due:
                            bucket['due'] += 1
                            if len(bucket['units']) < MAX_UNITS_PER_PROJECT_KIND:
                                bucket['units'].append({'u': unit, 'd': sub.target_domain_id, 's': _sort_key(h, check), 'h': [h.name]})
                    else:
                        bucket['applicable'] += 1
                        if check['state'] != 'due':
                            continue
                        bucket['due'] += 1
                        if h.name not in routed:
                            bucket['awaiting'] += 1  # the route check has not read this host yet: secrets_scan.plan would leave it out
                        elif len(bucket['units']) < MAX_UNITS_PER_PROJECT_KIND:
                            bucket['units'].append({'u': h.name, 'd': sub.target_domain_id, 's': _sort_key(h, check, web=True)})

        seen = set()
        for rows in _pages(hosts):
            page = [s for s in rows if s.name.lower() not in seen]
            seen.update(s.name.lower() for s in page)
            # a page of hosts and what they carry (addresses, ports, technologies) is read, checked and let go before the next: the census used to hold every host
            # of the project with all its ports in one list, so its memory grew with hosts x ports (the 1.3 GB census of the port-flood incident)
            prefetch_related_objects(page, 'ip_addresses__ports', 'technologies')
            check_page(page)
        _merge_endpoints(entry['kinds'].get('ssh_probe'))
    return out


def _merge_endpoints(bucket):
    """One SSH endpoint is one unit however many host names answer at it: the names are listed together, the best sort key kept."""
    if not bucket:
        return
    merged = {}
    for unit in bucket['units']:
        have = merged.get(unit['u'])
        if have is None:
            merged[unit['u']] = unit
        else:
            have['h'] = sorted(set(have['h']) | set(unit['h']))
            have['s'] = min(have['s'], unit['s'])
    bucket['units'] = list(merged.values())
    bucket['due'] = len(merged) if len(bucket['units']) < MAX_UNITS_PER_PROJECT_KIND else bucket['due']


def census(now=None, store=True):
    """Build the census and keep it in the cache (``CENSUS_TTL``). Returns it."""
    now = now or timezone.now()
    data = build_census(now)
    if store:
        try:
            cache.set(CENSUS_KEY, json.dumps(data), CENSUS_TTL)
        except Exception:  # noqa: BLE001 - without the cache the tick waits for the next census
            logger.warning('work planner: the census could not be kept', exc_info=True)
    return data


def cached_census():
    try:
        raw = cache.get(CENSUS_KEY)
        return json.loads(raw) if raw else None
    except Exception:  # noqa: BLE001
        return None


# ----------------------------------------------------------------------------- the tick

def _memo_skip(kind, project_id, unit, seconds):
    try:
        cache.set(SKIP_KEY.format(kind=kind, project=project_id, unit=unit), 1, seconds)
    except Exception:  # noqa: BLE001 - without the cache a refused unit is asked again next run, and refused again
        pass


def _skipped(kind, project_id, units):
    keys = {SKIP_KEY.format(kind=kind, project=project_id, unit=u['u']): u['u'] for u in units}
    try:
        got = cache.get_many(list(keys))
    except Exception:  # noqa: BLE001
        return set()
    return {keys[k] for k in got}


def _in_flight(kind):
    """``{project id: {unit}}`` the planner has queued or is running, and the units of a Sentinel task of the kind that a scan stage holds now."""
    from agentapi.models import SentinelTask
    from cveFeed.models import PlannerBatch
    held = defaultdict(set)
    pending = defaultdict(int)
    for project_id, units, status in PlannerBatch.objects.filter(kind=kind, status__in=('queued', 'running')).values_list('project_id', 'units', 'status'):
        held[project_id].update(u['u'] for u in units or [])
        pending[project_id] += status == 'queued'
    for project_id, target in SentinelTask.objects.filter(kind=kind, status__in=('queued', 'claimed', 'running')).values_list('project_id', 'target'):
        if not isinstance(target, dict):
            continue
        if kind == 'ssh_probe':
            held[project_id].update(f"{t.get('address')}:{t.get('port')}" for t in target.get('targets') or [] if isinstance(t, dict))
        else:
            held[project_id].update(str(t.get('host') or '') for t in target.get('hosts') or [] if isinstance(t, dict))
    return held, sum(pending.values())


def _backing_off(kind, now):
    """True while the last ``FAIL_STREAK`` finished batches of ``kind`` all failed and the newest ended less than ``FAIL_COOLDOWN`` ago."""
    from cveFeed.models import PlannerBatch
    rows = list(PlannerBatch.objects.filter(kind=kind, status__in=('done', 'failed'), finished_at__isnull=False).order_by('-finished_at').values_list('status', 'finished_at')[:FAIL_STREAK])
    return len(rows) == FAIL_STREAK and all(s == 'failed' for s, _ in rows) and now - rows[0][1] < FAIL_COOLDOWN


def _reap(now):
    """Batches whose job never ended (a worker lost) are failed so they stop counting as in flight; old finished rows are pruned."""
    from cveFeed.models import PlannerBatch
    lost = (PlannerBatch.objects.filter(status='queued', created_at__lt=now - QUEUED_LOST_AFTER).update(status='failed', finished_at=now, detail='the batch was never started')
            + PlannerBatch.objects.filter(status='running', started_at__lt=now - RUNNING_LOST_AFTER).update(status='failed', finished_at=now, detail='the batch never ended'))
    stale = list(PlannerBatch.objects.filter(finished_at__lt=now - KEEP_FINISHED).values_list('pk', flat=True)[:1000])
    if stale:
        PlannerBatch.objects.filter(pk__in=stale).delete()
    return lost


def _rotation(project_ids):
    """Projects in the order of this turn: organizations round-robin, then projects inside each, starting after the position the last run ended on."""
    try:
        last = int(cache.get(CURSOR_KEY) or 0)
    except (TypeError, ValueError):
        last = 0
    ordered = sorted(project_ids)
    return [p for p in ordered if p > last] + [p for p in ordered if p <= last]


def _interleave(census_projects, kind):
    """Projects with units of ``kind``, ordered so that one organization's projects do not follow each other while another organization waits: the
    organizations take turns (starting after the one served last), and inside an organization the projects do (``_rotation``)."""
    by_org = defaultdict(list)
    for pid in _rotation([int(p) for p, e in census_projects.items() if e['kinds'].get(kind, {}).get('units')]):
        by_org[census_projects[str(pid)]['org']].append(pid)
    order = sorted(by_org, key=lambda o: (o is None, o or 0))
    try:
        last = int(cache.get(CURSOR_KEY) or 0)
    except (TypeError, ValueError):
        last = 0
    served = census_projects.get(str(last), {}).get('org') if last else None
    if last and order:
        after = [o for o in order if (o is None, o or 0) > (served is None, served or 0)]
        order = after + [o for o in order if o not in after]
    queues = [by_org[o] for o in order]
    out = []
    while any(queues):
        for q in queues:
            if q:
                out.append(q.pop(0))
    return out


def _next_batch(spec, project, entry, ready, fresh_cache):
    """The next batch of one project for ``spec``: the best-sorted ready unit's target, up to ``per_task`` of its units. ``ready`` is that project's list of
    ready units (sorted, shrinking). Returns ``(domain_id, units)`` or None."""
    if not ready:
        return None
    domain = ready[0]['d']
    chosen = [u for u in ready if u['d'] == domain][:spec.per_task]
    taken = {id(u) for u in chosen}
    ready[:] = [u for u in ready if id(u) not in taken]
    return domain, chosen


def tick(now=None):
    """The one clean entry point (the outer watchdog calls it as its action when Sentinels sit idle). Does what the beat task ``work_planner_tick`` does,
    and builds the census first when none is cached (the beat leaves that to its own five-minute task; a caller that asked for work wants it now).
    Returns the summary dict: ``state`` (``queued``, ``busy``, ``nothing_due``, ``paused``, ``off``, ``no_sentinel``, ``backing_off``, ``nothing_queued``,
    ``running``), ``queued`` (``{kind: units}``), ``batches``, ``due``, ``awaiting``, ``reasons``, ``live``. Never raises for an ordinary gate."""
    now = now or timezone.now()
    if enabled() and cached_census() is None:
        try:
            census(now)
        except Exception:  # noqa: BLE001 - run() then reports 'warming' and the census task is asked for
            logger.warning('work planner: the census could not be built for a tick', exc_info=True)
    return run(now)


def run(now=None, kick=False):
    """One tick: measure capacity, and queue due batches where slots are idle. Returns the summary (also kept for the Scanners page). Never raises for an
    ordinary gate (off, paused, no Sentinel, nothing due, busy); a project that cannot be planned is skipped and named in ``reasons``."""
    now = now or timezone.now()
    try:
        added = cache.add(LOCK_KEY, 1, LOCK_SECONDS)
    except Exception:  # noqa: BLE001 - without the cache an overlap is possible: every step below is idempotent (units in flight are never planned twice)
        added = True
    if not added:
        return {'state': 'running', 'at': now.isoformat(), 'note': 'another run is going'}
    try:
        summary = _run(now)
    finally:
        try:
            cache.delete(LOCK_KEY)
        except Exception:  # noqa: BLE001
            pass
    summary['kick'] = bool(kick)
    try:
        cache.set(LAST_KEY, json.dumps(summary), 24 * 3600)
    except Exception:  # noqa: BLE001
        pass
    return summary


def _run(now):
    from agentapi import sentinel_broker
    from cveFeed import activity
    from cveFeed.conductor import bounty_blocked_projects
    from cveFeed.scan_control import pause_requested
    from dashboard.models import Project
    summary = {'at': now.isoformat(), 'state': 'nothing_due', 'queued': {}, 'batches': 0, 'due': {}, 'awaiting': {}, 'reasons': {}}
    want = specs()
    if not enabled():
        summary['state'] = 'off'
        return summary
    if pause_requested(fail_closed=True):
        summary['state'] = 'paused'
        return summary
    _reap(now)
    with sentinel_broker.memoised_rights():
        cap = sentinel_broker.planner_capacity(list(want), now)
        data = cached_census()
        summary['live'] = cap['live']
        if not cap['live']:
            summary['state'] = 'no_sentinel'
            return summary
        if data is None:
            from cveFeed.tasks import work_planner_census
            try:
                work_planner_census.apply_async(queue='cve_feed_queue', expires=300)
            except Exception:  # noqa: BLE001 - the next tick asks again
                logger.warning('work planner: the census could not be queued', exc_info=True)
            summary['state'] = 'warming'
            return summary
        summary['census_at'] = data['at']
        blocked = bounty_blocked_projects()
        factor, per_sentinel, per_run = queue_factor(), max_queue_per_sentinel(), batches_per_run()
        pending_all = {k: _in_flight(k) for k in want}
        pending_total = sum(p for _h, p in pending_all.values())
        room = max(0, per_sentinel * cap['live'] - cap['queued_total'] - pending_total)
        projects = {p.pk: p for p in Project.objects.select_related('org').filter(pk__in=[int(i) for i in data['projects']])}
        plan = []  # (spec, project, domain id, units)
        cursor = {}
        wanted = {}
        for kind, spec in want.items():
            k = cap['kinds'][kind]
            summary['due'][kind] = sum(e['kinds'][kind]['due'] for e in data['projects'].values())
            summary['awaiting'][kind] = sum(e['kinds'][kind]['awaiting'] for e in data['projects'].values())
            if not summary['due'][kind] - summary['awaiting'][kind]:
                summary['reasons'][kind] = 'nothing due'
                continue
            if not k['sentinels']:
                summary['reasons'][kind] = 'no live Sentinel can take it'
                continue
            if _backing_off(kind, now):
                summary['reasons'][kind] = f'backing off: the last {FAIL_STREAK} batches failed'
                continue
            idle = max(0, min(k['free'], cap['free_total']) - (cap['queued_total'] - cap['queued'].get(kind, 0)))
            if not idle:
                summary['reasons'][kind] = _busy_reason(k, cap, kind)
                continue
            have = cap['queued'].get(kind, 0) + pending_all[kind][1]
            wanted[kind] = max(0, factor * idle - have)
            if not wanted[kind]:
                summary['reasons'][kind] = 'the queue is already deep enough'
        deficits = dict(wanted)
        ready = {}  # kind -> {project id: sorted ready units}
        order = {}
        for kind in deficits:
            order[kind] = _interleave(data['projects'], kind)
            ready[kind] = {}
        budget = min(per_run, room)
        reach = {}
        while budget > 0 and any(deficits.get(k, 0) > 0 and order[k] for k in deficits):
            for kind in [k for k in want if deficits.get(k, 0) > 0 and order.get(k)]:
                if budget <= 0:
                    break
                spec = want[kind]
                pid = order[kind].pop(0)
                entry = data['projects'][str(pid)]
                project = projects.get(pid)
                if project is None or pid in blocked:
                    continue
                if (pid, kind) not in reach:
                    reach[(pid, kind)] = sentinel_broker.capacity_state(project, kind)['state'] != 'none'
                if not reach[(pid, kind)]:
                    summary['reasons'].setdefault(f'project:{entry["slug"]}', 'no live Sentinel covers it')
                    continue
                if pid not in ready[kind]:
                    ready[kind][pid] = _ready_units(spec, project, entry, pending_all[kind][0].get(pid, set()), spec.per_task * max(1, deficits[kind]) * SLACK, summary)
                batch = _next_batch(spec, project, entry, ready[kind][pid], None)
                if batch is None:
                    continue
                if ready[kind][pid]:
                    order[kind].append(pid)  # more of its units are ready: it takes its next turn after the others
                plan.append((spec, project, batch[0], batch[1]))
                cursor[kind] = pid
                deficits[kind] -= 1
                budget -= 1
        made = _enqueue(plan, now)
        for spec, units in made.items():
            summary['queued'][spec] = units
        summary['batches'] = sum(1 for _ in plan) if plan else 0
        if cursor:
            try:
                cache.set(CURSOR_KEY, max(cursor.values()), None)
            except Exception:  # noqa: BLE001
                pass
    if summary['queued']:
        summary['state'] = 'queued'
        text = ' and '.join(want[k].phrase(n) for k, n in summary['queued'].items())
        more = [f'{want[k].phrase(max(0, summary["due"][k] - summary["awaiting"][k] - summary["queued"].get(k, 0)))} still due' for k in want if summary['due'].get(k)]
        activity.log('run_check', f'Work planner queued {text} for the Sentinels ({summary["batches"]} batches' + (f'; {"; ".join(more)}' if more else '') + ')',
                     batches=summary['batches'], queued=summary['queued'], due=summary['due'])
    elif any(r.startswith(BUSY_PREFIX) for r in summary['reasons'].values()) or any('deep enough' in r for r in summary['reasons'].values()):
        summary['state'] = 'busy'
    elif any(r.startswith('backing off') for r in summary['reasons'].values()):
        summary['state'] = 'backing_off'
    elif sum(max(0, summary['due'][k] - summary['awaiting'][k]) for k in want) == 0:
        summary['state'] = 'nothing_due'
    else:
        summary['state'] = 'nothing_queued'
    return summary


def _ready_units(spec, project, entry, in_flight, limit, summary):
    """The units of ``project`` the planner may queue now, best first, at most ``limit``: the census's units that are not in flight, not left alone after a failure
    or a refusal, still not fresh in the ledger (the census is up to five minutes old) and not on the organization's do-not-scan list."""
    from cveFeed import exclusions, ledger
    units = sorted(entry['kinds'][spec.kind]['units'], key=lambda u: (u['s'], u['u']))
    units = [u for u in units if u['u'] not in in_flight]
    skipped = _skipped(spec.kind, project.pk, units[:limit * 2])
    units = [u for u in units if u['u'] not in skipped][:limit]
    if not units:
        return []
    fresh = ledger.fresh(spec.service, [u['u'] for u in units], project.pk)
    units = [u for u in units if ledger._norm(u['u']) not in fresh]
    if spec.kind == 'ssh_probe' and units:
        try:
            refused = exclusions.address_refusals(project.pk, [u['u'].rsplit(':', 1)[0] for u in units])
        except Exception:  # noqa: BLE001 - an authorization list that cannot be read: nothing is planned for the project this run
            summary['reasons'][f'project:{entry["slug"]}'] = 'the do-not-scan list could not be read'
            return []
        units = [u for u in units if u['u'].rsplit(':', 1)[0] not in refused]
    return units


def _enqueue(plan, now):
    """Store each planned batch and hand it to a worker. Returns ``{kind: units queued}``. A batch that cannot be handed over is failed on the spot."""
    from cveFeed.models import PlannerBatch
    from cveFeed.tasks import work_planner_batch
    made = defaultdict(int)
    for spec, project, domain_id, units in plan:
        batch = PlannerBatch.objects.create(project=project, domain_id=domain_id, kind=spec.kind, units=[{k: v for k, v in u.items() if k != 's'} for u in units])
        try:
            work_planner_batch.apply_async(args=[batch.pk], queue=PLANNER_QUEUE, expires=3600)
        except Exception as exc:  # noqa: BLE001 - the broker is down: the units stay due, the next run tries again
            PlannerBatch.objects.filter(pk=batch.pk).update(status='failed', finished_at=now, detail=f'could not be queued: {str(exc)[:200]}')
            continue
        made[spec.kind] += len(units)
    return dict(made)


# ----------------------------------------------------------------------------- one batch

def execute_batch(batch_id, dispatch=None):
    """Run one stored batch: the same entry the scan stage uses for the kind, with the batch's units. Idempotent (a batch that is not ``queued`` is left
    alone). Every gate is read again here, at run time: the switch, scanning paused, the bug bounty gate, and (inside the entry) exclusions, scope, the
    ledger and the do-not-scan guard. A batch a guard stops is ``skipped`` and its units are left alone for hours; one that fails, for 30 minutes."""
    from cveFeed.bounty_gate import Gate
    from cveFeed.models import PlannerBatch
    from cveFeed.scan_control import pause_requested
    from reNgine.resources import AddressExcluded, ScannerUnavailable
    now = timezone.now()
    if not PlannerBatch.objects.filter(pk=batch_id, status='queued').update(status='running', started_at=now):
        return {'status': 'ignored'}
    batch = PlannerBatch.objects.select_related('project__org', 'domain').get(pk=batch_id)
    units = [u['u'] for u in batch.units or []]
    outcome, detail = 'done', ''
    try:
        if not enabled():
            outcome, detail = 'skipped', 'the work planner was switched off'
        elif pause_requested(fail_closed=True):
            outcome, detail = 'skipped', 'scanning is paused'
        elif Gate().project_blocked(batch.project_id):
            outcome, detail = 'skipped', 'the bug bounty engagement has not confirmed automated testing'
        elif batch.kind == 'ssh_probe':
            from cveFeed import ssh_scan
            keys = [(u.rsplit(':', 1)[0], int(u.rsplit(':', 1)[1])) for u in units]
            names = sorted({h for u in batch.units or [] for h in u.get('h') or []})
            result = ssh_scan.run_for_hosts(batch.project, names, keys=keys, dispatch=dispatch, priority=_priority())
            detail = f"{result['inspected']} of {result['endpoints']} endpoints inspected, {result['findings']} compromised host keys"
        elif batch.kind == 'secrets_scan':
            from cveFeed import secrets_scan
            result = secrets_scan.run_for_hosts(batch.project, batch.domain, units, dispatch=dispatch, priority=_priority())
            detail = f"{result['hosts']} hosts read, {result['secrets']} secrets"
        else:
            outcome, detail = 'skipped', f'{batch.kind} is not a planner kind'
    except AddressExcluded as exc:
        outcome, detail = 'skipped', str(exc)[:280]
    except ScannerUnavailable as exc:
        outcome, detail = 'failed', str(exc)[:280]
    except Exception as exc:  # noqa: BLE001 - one batch never stops the planner; the units are left alone for a while
        logger.exception('work planner batch %s failed', batch_id)
        outcome, detail = 'failed', f'{type(exc).__name__}: {str(exc)[:240]}'
    PlannerBatch.objects.filter(pk=batch_id).update(status=outcome, detail=detail[:300], finished_at=timezone.now())
    if outcome in ('failed', 'skipped'):
        for unit in units:
            _memo_skip(batch.kind, batch.project_id, unit, UNIT_REFUSED_FOR if outcome == 'skipped' else UNIT_FAILED_FOR)
    return {'status': outcome, 'detail': detail}


def _priority():
    from agentapi import sentinel_broker
    return sentinel_broker.PLANNER_PRIORITY


def kick():
    """Ask for a tick in a few seconds (a batch just ended: its slot is free), unless one is already going. Never raises."""
    try:
        from cveFeed.tasks import work_planner_tick
        work_planner_tick.apply_async(kwargs={'kick': True}, countdown=3, queue='cve_feed_queue', expires=60)
    except Exception:  # noqa: BLE001 - the next beat runs one
        pass


# ----------------------------------------------------------------------------- what the Scanners page says

def _last():
    try:
        raw = cache.get(LAST_KEY)
        return json.loads(raw) if raw else None
    except Exception:  # noqa: BLE001
        return None


def overview(allowed=None, now=None):
    """The planner's state for the Scanners page: ``{'enabled', 'state', 'line', 'next_run_seconds', 'kinds': [...], 'batches': {...}}``. ``allowed`` is the set
    of project ids the viewer may read (None: all); the due counts are summed over those only."""
    from cveFeed.models import PlannerBatch
    now = now or timezone.now()
    want = specs()
    last = _last() or {}
    data = cached_census() or {'projects': {}}
    rows = {k: {'kind': k, 'label': s.noun + 's', 'noun': s.noun, 'applicable': 0, 'due': 0, 'awaiting': 0, 'in_flight': 0, 'blocked': 0}
            for k, s in want.items()}
    for pid, entry in data['projects'].items():
        if allowed is not None and int(pid) not in allowed:
            continue
        for kind, bucket in entry['kinds'].items():
            if kind not in rows:
                continue
            if entry.get('blocked'):
                rows[kind]['blocked'] += 1
                continue
            for key in ('applicable', 'due', 'awaiting'):
                rows[kind][key] += bucket[key]
    flight = PlannerBatch.objects.filter(status__in=('queued', 'running'))
    if allowed is not None:
        flight = flight.filter(project_id__in=allowed)
    counts = defaultdict(int)
    for kind, units in flight.values_list('kind', 'units'):
        counts[kind] += len(units or [])
    for kind, row in rows.items():
        row['in_flight'] = counts.get(kind, 0)
        row['ready'] = max(0, row['due'] - row['awaiting'])
    at = last.get('at')
    next_in = None
    if at:
        try:
            next_in = max(0, TICK_SECONDS - int((now - datetime.fromisoformat(at)).total_seconds()))
        except ValueError:
            next_in = None
    on = enabled()
    return {'enabled': on, 'state': last.get('state') or ('off' if not on else 'waiting'), 'line': describe(last, rows, on, next_in, want, scoped=allowed is not None), 'next_run_seconds': next_in,
            'last_run': at, 'census_at': data.get('at'), 'kinds': list(rows.values()), 'batches_in_flight': flight.count()}


BUSY_PREFIX = 'no free slot: '


def _busy_reason(k, cap, kind):
    """Why a kind with work due got no slot, in numbers. "All Sentinel slots busy" was said whenever this kind's share came to zero, including when 6 of 10
    slots were free: the Sentinels that can run the kind may all be full, the kind may have a cap of its own, or other kinds' waiting tasks may already
    claim every free slot. Each is a different thing for a person to do something about."""
    free_total = cap['free_total']
    others = cap['queued_total'] - cap['queued'].get(kind, 0)
    if free_total <= 0:
        return f'{BUSY_PREFIX}all {sum(a["slots"] for a in cap["agents"])} Sentinel slots busy'
    if k['free'] <= 0:
        who = f'{k["sentinels"]} Sentinel(s) that can run it' if k['sentinels'] else 'the Sentinels that can run it'
        return f'{BUSY_PREFIX}the {who} have no free slot ({k["slots"]} slot(s) for this kind, all held, or capped for it); {free_total} slot(s) are free on Sentinels that cannot take it'
    return f'{BUSY_PREFIX}{others} task(s) of other kinds already wait for the {min(k["free"], free_total)} free slot(s) of Sentinels that can run it'


def describe(last, rows, on, next_in, want=None, scoped=False):
    """The one plain sentence about the planner (``Planner: ...``). ``scoped`` is a viewer who sees some projects: the last run's ``queued`` counts are the
    whole instance's (every tenant's), so the sentence is built from the viewer's own rows (what is in flight for them) and never says what was queued
    elsewhere (review 2 F7)."""
    want = want or specs()
    state = (last or {}).get('state')
    if not on:
        return 'Planner: off (Settings, Work planner). Sentinels only get work from scans.'
    tail = f', next run in {next_in} s' if next_in is not None else ''
    queued = ({k: r['in_flight'] for k, r in rows.items() if r['in_flight']} if scoped else (last or {}).get('queued', {}))
    still = [f'{want[k].phrase(max(0, r["ready"] - (r["in_flight"] if scoped else (last or {}).get("queued", {}).get(k, 0))))} still due' for k, r in rows.items() if k in want and r['ready']]
    still_text = f', {"; ".join(still)}' if still else ''
    if state == 'queued':
        done = ' and '.join(want[k].phrase(n) for k, n in queued.items() if k in want)
        if not done:  # a viewer none of whose projects had work in this round
            return f'Planner: running, nothing of yours was queued in the last round{still_text}{tail}'
        return f'Planner: queued {done}{still_text}{tail}'
    if state == 'paused':
        return 'Planner: waiting, scanning is paused' + tail
    if state == 'no_sentinel':
        return 'Planner: waiting, no Sentinel is checking in' + tail
    if state == 'warming':
        return 'Planner: counting what is due, first answer within a few minutes' + tail
    if state == 'busy':
        return 'Planner: waiting, all Sentinel slots busy' + still_text + tail
    if state == 'backing_off':
        return 'Planner: backing off after repeated failures' + still_text + tail
    if state in ('nothing_due', None) and not any(r['ready'] for r in rows.values()):
        waiting = [f'{want[k].phrase(r["awaiting"])} wait for a route check' for k, r in rows.items() if k in want and r['awaiting']]
        return 'Planner: nothing due' + (f' ({"; ".join(waiting)})' if waiting else '') + tail
    return 'Planner: nothing queued this run' + still_text + tail
