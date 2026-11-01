"""Fast, deterministic top-up of host-assessment coverage, independent of the three-hour AI review.

cveFeed.assessment_review's three-hour review offers the model at most one due host per project per
three-hour window (AssessmentReviewDecision allows one decision per project per window, and the model
may or may not even pick the offered action over triage/validate/discover). That is far too slow for a
project that just picked up dozens of new subdomains from one discovery run: at one host every three
hours, an 80-host backlog would take ten days to drain.

This module runs on a short interval (see the migration that schedules ``top_up_host_assessments``,
every TOPUP_INTERVAL_MINUTES) and queues host assessments directly, with no model call and no per-project
decision throttle: for every project with free host-assessment capacity, it enqueues the next due hosts
from the same population cveFeed.assessment_review.host_coverage_due() looks at (missing core stage
coverage, no recent attempt, not excluded, not archived), up to that project's free capacity.

Interval and cap choice (see also docs/PIPELINE.md): a backlog the size of today's (roughly 80 hosts in
one project) needs to drain within hours, not days. A host assessment's own pipeline (nmap, the light
nuclei pass, CVE correlation, the targeted nuclei pass) typically finishes well inside this sweep's
interval, so throughput is bounded by the per-project queue slot (5) refilling as each assessment
finishes, not by how often this sweep runs. Every TOPUP_INTERVAL_MINUTES (5) is frequent enough that a
freed slot is refilled within minutes rather than sitting idle until the next three-hour review, while
staying far below the per-minute cadence of cveFeed.conductor's own work_conductor sweep. At the
project's cap of 5 concurrent assessments, draining an 80-host backlog takes roughly 80 / 5 = 16 rounds;
even at a generous 20 minutes per host assessment that is about 16 * 20 = 320 minutes, call it half a day
in the worst case, and considerably less in practice since most hosts resolve or fail fast. PROJECT_LIMIT
and MAX_ENQUEUED_PER_RUN bound a single run's cost: today's 8 projects and ~342 hosts are examined in a
few cheap, indexed queries per run (one active-count query per project, and the due-hosts query only for
a project that actually has free capacity), never a project's full host list when it has no free slot.

This module also holds backlog_exists(), the instance-wide gate cveFeed.fullscan and cveFeed.udp_scan check
before picking their next deep-scan target: first-pass coverage everywhere outranks any one address's full
port sweep or UDP exposure check. It reuses host_coverage_due() rather than a second query.
"""
import logging
from datetime import timedelta

from django.utils import timezone

logger = logging.getLogger(__name__)

PROJECT_LIMIT = 100          # projects examined per run; today's installations have under ten
MAX_ENQUEUED_PER_RUN = 20    # mirrors host_assessment's base global cap (it grows with the Sentinels' slots, see host_assessment.caps)
MAX_PER_RUN_BASE = MAX_ENQUEUED_PER_RUN
PER_PROJECT_LIMIT = 5        # mirrors host_assessment's per-project active cap


def top_up(now=None, only_sentinel_projects=False):
    """One sweep: enqueue due host assessments for every project with free capacity, bounded by the caps above (``host_assessment.caps``: they
    grow with the live Sentinels' slots, so a Sentinel keeps twice its capacity queued behind what it runs). Hosts with no scannable address are
    resolved again first (``unresolved_archive.recheck``, DNS only) and are not counted as work.

    ``only_sentinel_projects`` is the once-a-minute feed (``feed_sentinels``): only projects a live Sentinel covers.

    Returns a small summary dict; never raises for an ordinary gate (paused, bounty-blocked, at capacity) or for one
    project's enqueue failure, so one bad project never stops the rest of the sweep.
    """
    from agentapi import sentinel_broker
    with sentinel_broker.memoised_rights():  # the Sentinels' rights and slots are worked out once for the whole sweep, not once per project and per call
        return _top_up(now, only_sentinel_projects)


CURSOR_KEY = 'cvengine:topup:cursor'  # the last project a sweep looked at: the next sweep carries on after it


def _projects(blocked):
    """The projects one sweep looks at: at most ``PROJECT_LIMIT``, starting after the one the last sweep ended on and wrapping round, so with more
    projects than that every one gets its turn, instead of the first hundred by id being the only ones ever topped up."""
    from django.core.cache import cache
    from dashboard.models import Project
    try:
        cursor = int(cache.get(CURSOR_KEY) or 0)
    except (TypeError, ValueError, OSError):
        cursor = 0
    base = Project.objects.exclude(pk__in=blocked).order_by('pk')
    rows = list(base.filter(pk__gt=cursor)[:PROJECT_LIMIT])
    if len(rows) < PROJECT_LIMIT:
        rows += list(base.filter(pk__lte=cursor)[:PROJECT_LIMIT - len(rows)])
    return rows


def _remember_cursor(pk):
    from django.core.cache import cache
    try:
        cache.set(CURSOR_KEY, pk, None)
    except Exception:  # noqa: BLE001 - without the cache every sweep starts at the first project, as before
        pass


def _top_up(now, only_sentinel_projects):
    from cveFeed.assessment_review import host_coverage_due
    from cveFeed.conductor import bounty_blocked_projects
    from cveFeed.host_assessment import active_slots, batch_size_for, batches, caps, enqueue_batch
    from cveFeed.scan_control import pause_requested
    from cveFeed import unresolved_archive
    from startScan.models import Subdomain

    now = now or timezone.now()
    result = {'projects_checked': 0, 'hosts_queued': 0, 'batches_queued': 0, 'skipped': None}
    if pause_requested(fail_closed=True):
        result['skipped'] = 'paused'
        return result
    try:
        result['rechecked'] = unresolved_archive.recheck(now)
    except Exception:  # noqa: BLE001 - a DNS problem must never stop the feed
        logger.exception('coverage top-up: could not re-resolve hosts with no address')
    global_cap, _project_cap = caps()
    global_active = active_slots()  # the caps are in pipeline runs (worker slots): a batch of hosts is one, however many hosts it carries
    if global_active >= global_cap:
        result['skipped'] = 'global capacity'
        return result
    blocked = bounty_blocked_projects()
    budget = min(global_cap - global_active, MAX_PER_RUN_BASE + (global_cap - 20))  # runs this sweep may start
    from agentapi import sentinel_broker
    last = None
    for project in _projects(blocked):
        if budget <= 0:
            break
        last = project.pk
        if only_sentinel_projects and not sentinel_broker.project_slots(project):
            continue
        result['projects_checked'] += 1
        free = min(caps(project)[1] - active_slots(project), budget)  # runs this project may start
        if free <= 0:
            continue
        size = batch_size_for(project)
        _, due_ids = host_coverage_due(project, now, limit=free * size, need_count=False)  # up to ``size`` hosts for each run
        if not due_ids:
            continue
        subs = {s.pk: s for s in Subdomain.objects.filter(pk__in=due_ids).select_related('target_domain')}
        for group in batches([subs[i] for i in due_ids if i in subs], size):  # hosts of one target are one run: the Sentinel gets many targets per task
            if budget <= 0 or free <= 0:
                break
            try:
                jobs, skipped = enqueue_batch(project, group, source='topup')
            except (ValueError, RuntimeError) as exc:
                logger.info('coverage top-up could not queue hosts %s of project %s: %s', [g.pk for g in group], project.pk, exc)
                continue
            for sub, why in skipped:
                logger.info('coverage top-up could not queue host %s of project %s: %s', sub.pk, project.pk, why)
            if jobs:
                result['hosts_queued'] += len(jobs)
                result['batches_queued'] += 1
                budget -= 1
                free -= 1
    if last is not None:
        _remember_cursor(last)
    if result['hosts_queued']:
        from cveFeed import activity
        runs = f" in {result['batches_queued']} run{'s' if result['batches_queued'] != 1 else ''}" if result['batches_queued'] != result['hosts_queued'] else ''
        activity.log('discovery', f"Coverage top-up queued {result['hosts_queued']} host assessment"
                     f"{'s' if result['hosts_queued'] != 1 else ''}{runs} across {result['projects_checked']} project"
                     f"{'s' if result['projects_checked'] != 1 else ''}", status='done',
                     hosts_queued=result['hosts_queued'])
    return result


REFRESH_GAP_DEFAULT_HOURS = 6  # a host is not assessed again by the refresh until this long after its last assessment started
REFRESH_PER_RUN = 20           # most assessments one refresh pass queues across all projects


def refresh_gap():
    """How long a host rests between refresh assessments (what an App Admin saved on Settings, configMaxxing, else
    ``CVENGINE_SENTINEL_REFRESH_GAP_HOURS``, default 6; ``0`` turns the refresh off). Read on every pass (``cveFeed.tunables``)."""
    from cveFeed import tunables
    hours = float(tunables.value('sentinel_refresh_gap_hours', REFRESH_GAP_DEFAULT_HOURS))
    return None if hours <= 0 else timedelta(hours=hours)


def stalest_hosts(project, now, limit, gap):
    """Up to ``limit`` ``Subdomain`` rows of ``project``'s current inventory whose last host assessment started longest ago (never assessed first),
    leaving out a host assessed inside ``gap``. One row per host name. This is for hosts that already have their first-pass coverage: the ones that
    miss it are ``host_coverage_due``'s."""
    from django.db.models import F, OuterRef, Q, Subquery
    from django.db.models.functions import Lower
    from cveFeed.correlation import latest_scan_q
    from cveFeed.models import HostAssessment
    from startScan.models import Subdomain

    last = HostAssessment._base_manager.filter(project=project, host=OuterRef('lowered')).order_by('-created_at').values('created_at')[:1]
    rows = (Subdomain.objects.filter(latest_scan_q(), target_domain__project=project).select_related('target_domain')
            .annotate(lowered=Lower('name')).annotate(last_assessed=Subquery(last))
            .filter(Q(last_assessed__isnull=True) | Q(last_assessed__lt=now - gap))
            .order_by(F('last_assessed').asc(nulls_first=True), 'id')[:limit * 4])
    seen, out = set(), []
    for row in rows:
        if row.lowered in seen:
            continue
        seen.add(row.lowered)
        out.append(row)
        if len(out) >= limit:
            break
    return out


def refresh_for_sentinels(now=None):
    """Keep the Sentinels busy when no host is missing first-pass coverage. Every host assessment sends its stages to a Sentinel first, so a
    Sentinel works only while assessments are in flight, and once every host has its first pass nothing creates one: it would sit idle. For each
    project a live Sentinel covers, this fills the project's Sentinel-scaled assessment cap (``host_assessment.caps``) with the hosts assessed
    longest ago, none inside ``refresh_gap()``. The stages go to a Sentinel and fall back to this server only when it cannot take them. The usual
    gates apply in ``host_assessment.enqueue`` (exclusions, archived hosts, bug bounty scope and its confirmation, internal hosts). Returns a
    summary; never raises for one project."""
    from agentapi import sentinel_broker
    from cveFeed.conductor import bounty_blocked_projects
    from cveFeed.host_assessment import active_slots, batch_size_for, batches, caps, enqueue_batch
    from cveFeed.scan_control import pause_requested

    now = now or timezone.now()
    gap = refresh_gap()
    out = {'refreshed': 0, 'skipped': None}
    if gap is None:
        out['skipped'] = 'refresh is off'
        return out
    if pause_requested(fail_closed=True):
        out['skipped'] = 'paused'
        return out
    global_cap, _ = caps()
    budget = min(global_cap - active_slots(), REFRESH_PER_RUN)  # pipeline runs, as in the top-up
    if budget <= 0:
        out['skipped'] = 'global capacity'
        return out
    for project in _projects(bounty_blocked_projects()):
        if budget <= 0:
            break
        if not sentinel_broker.project_slots(project):
            continue
        free = min(caps(project)[1] - active_slots(project), budget)
        if free <= 0:
            continue
        size = batch_size_for(project)
        cand = stalest_hosts(project, now, free * size, gap)
        for group in batches(cand, size):
            if budget <= 0 or free <= 0:
                break
            try:
                jobs, skipped = enqueue_batch(project, group, source='refresh')
            except (ValueError, RuntimeError) as exc:
                logger.info('refresh could not queue hosts %s of project %s: %s', [g.pk for g in group], project.pk, exc)
                continue
            for sub, why in skipped:
                logger.info('refresh could not queue host %s of project %s: %s', sub.pk, project.pk, why)
            if jobs:
                out['refreshed'] += len(jobs)
                budget -= 1
                free -= 1
    if out['refreshed']:
        from cveFeed import activity
        activity.log('discovery', f"Refresh queued {out['refreshed']} host assessment{'s' if out['refreshed'] != 1 else ''} so the Sentinels keep working",
                     status='done', hosts_queued=out['refreshed'])
    return out


def feed_sentinels(now=None):
    """Once a minute, keep the Sentinels working: first the hosts missing a first pass (``top_up`` over the projects they cover, with the
    Sentinel-scaled caps), then, with the pool still short of those caps, the stalest hosts again (``refresh_for_sentinels``). A Sentinel that
    works through its tasks has the next ones already waiting, and one that has run out of new hosts is given old ones to re-check, instead of
    idling. Does nothing without a live Sentinel."""
    from agentapi import sentinel_broker
    with sentinel_broker.memoised_rights():  # top_up joins this block, so the rights built for the slot count are the ones it reuses
        slots = sentinel_broker.total_slots()
        if not slots:
            return {'skipped': 'no live Sentinel'}
        waiting = sentinel_broker.waiting_tasks()
        wanted = 2 * slots
        if waiting >= wanted:
            return {'skipped': 'queue is deep enough', 'slots': slots, 'waiting': waiting}
        out = {**top_up(now, only_sentinel_projects=True), 'slots': slots, 'waiting': waiting, 'wanted': wanted}
        out['refresh'] = refresh_for_sentinels(now)
        return out


# ----------------------------------------------------------------------------- deep-scan coverage gate

GATE_PROJECT_LIMIT = 200  # projects walked per gate call before giving up and letting deep scans proceed; a cheap
                          # LIMIT-1-per-project check (no DISTINCT aggregate), so this affords a wider cap than
                          # PROJECT_LIMIT above


def backlog_exists(now=None):
    """True when any project, not bounty-blocked, still has a host missing core first-pass coverage: nmap_scan,
    nuclei_light_scan, cve_correlation, nuclei_targeted_scan (the same population host_coverage_due() looks at).

    cveFeed.fullscan and cveFeed.udp_scan check this before picking their next target, and skip the run while it
    is True: first-pass coverage everywhere outranks any one address's 65,535-port sweep or UDP exposure check.

    Deliberately a cheap existence check, not a count: each project is asked for at most one due host id (a single
    ``LIMIT 1`` query, ``need_count=False``, no DISTINCT aggregate), and the loop returns on the first project that
    has one. The only case that walks every project is the common, healthy one where nothing is due anywhere, and
    even that walk is bounded by GATE_PROJECT_LIMIT, so this never becomes an unbounded table scan.

    A bounty-blocked project's hosts never count: that backlog is intentionally deferred, not incomplete, and must
    not gate deep scanning forever (see cveFeed.conductor.bounty_blocked_projects). Nor does anything count while
    scanning is paused instance-wide: nothing, including this gate's own caller, is eligible to work on anything
    right now, so this returns False rather than making the full-port and UDP sweeps' own retry wait forever on a
    backlog that cannot currently shrink; both sweeps have their own pause gates and act on neither result while
    paused.
    """
    from cveFeed.assessment_review import host_coverage_due
    from cveFeed.conductor import bounty_blocked_projects
    from cveFeed.scan_control import pause_requested
    from dashboard.models import Project

    now = now or timezone.now()
    if pause_requested(fail_closed=True):
        return False
    blocked = bounty_blocked_projects()
    for project in Project.objects.exclude(pk__in=blocked).order_by('pk')[:GATE_PROJECT_LIMIT]:
        _, due_ids = host_coverage_due(project, now, limit=1, need_count=False)
        if due_ids:
            return True
    return False


def log_deferral(label, now=None):
    """Log one deferral line for a deep-scan sweep the gate just blocked, at most once every 30 minutes per
    ``label`` (cveFeed.ledger.sweep_claim), so a sweep that fires every few minutes does not fill the activity feed
    with the same note. ``label`` names the sweep in the message, e.g. "Full-port scan" or "UDP scan"."""
    from cveFeed import activity, ledger
    key = 'coverage-gate-note-' + label.lower().replace(' ', '-')
    if not ledger.sweep_claim(key, 30 * 60):
        return
    hosts, projects = backlog_summary(now)
    activity.log('run_check', f'{label} deferred: {hosts} host{"s" if hosts != 1 else ""} across {projects} '
                 f'project{"s" if projects != 1 else ""} still need a first pass')


def backlog_summary(now=None, limit=GATE_PROJECT_LIMIT):
    """How big the current gate-blocking backlog is: (hosts, projects). Only for the deferral log line, never on
    the hot gate-check path (backlog_exists already proved there is at least one due host before this runs), and
    the caller rate-limits how often it is actually computed (see cveFeed.ledger.sweep_claim)."""
    from cveFeed.assessment_review import host_coverage_due
    from cveFeed.conductor import bounty_blocked_projects
    from dashboard.models import Project

    now = now or timezone.now()
    blocked = bounty_blocked_projects()
    hosts, projects_with_backlog = 0, 0
    for project in Project.objects.exclude(pk__in=blocked).order_by('pk')[:limit]:
        count, _ = host_coverage_due(project, now, limit=1)
        if count:
            hosts += count
            projects_with_backlog += 1
    return hosts, projects_with_backlog
