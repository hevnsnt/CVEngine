"""The work conductor: a watchdog that makes sure there is always a queue of work and that it is the most important work.

Scans used to start only when someone asked or when a daily/weekly sweep ran, so for most of the day nothing was running even with a
thousand hosts to look after. Every minute this keeps the discovery pipeline fed: it counts the scans that are running or queued and,
below the wanted depth (``CVENGINE_WORK_DEPTH``, default 3; 0 turns the conductor off), starts discovery of the targets that have gone
longest without one. Never scanned first, then the stalest, at most one per project per round so no project starves the rest, and
never a project whose bug bounty engagement has not confirmed automated testing, never a target scanned within ``CVENGINE_WORK_MIN_GAP_HOURS`` (default 2), one that already has a scan queued or running, one an
organization excluded, or anything while scanning is paused (including the pause an update holds).

Everything else that keeps the instance busy (validation of fire and smoke matches, re-tests of changed hosts, the paced full port scan
and deep nuclei, triage, the AI review every three hours) has its own schedule; this is the part that guarantees the discovery queue
never runs dry. Each dispatch is logged in the target's project activity, and the last round is kept for ``status()``.
"""
import logging
import os
from datetime import timedelta

logger = logging.getLogger(__name__)

DEFAULT_DEPTH = 3
DEFAULT_MIN_GAP_HOURS = 2
ROUND_KEY = 'cvengine:conductor:last'


def _env_int(name, default):
    try:
        return max(0, int(os.environ.get(name, default)))
    except ValueError:
        return default


def wanted_depth():
    return _env_int('CVENGINE_WORK_DEPTH', DEFAULT_DEPTH)


def min_gap():
    return timedelta(hours=_env_int('CVENGINE_WORK_MIN_GAP_HOURS', DEFAULT_MIN_GAP_HOURS))


def active_scans():
    """Discovery scans going or waiting: queued ones, and running ones that started inside the running window (an older one is stalled
    and the reaper deals with it). A host-pipeline run is not a discovery scan."""
    from cveFeed.counts import queued_scans, running_scans
    from cveFeed.discovery import HOST_PIPELINE_TASK
    return (running_scans() | queued_scans()).exclude(tasks__contains=[HOST_PIPELINE_TASK])


def bounty_blocked_projects():
    """Projects the conductor never scans on its own: a bug bounty engagement is scanned automatically only when its owner confirmed
    the program's policy allows it (policy acknowledged and automated testing allowed), the engagement is still being worked and the
    program's scope is the one that was acknowledged. Any other engagement, paused or finished ones included, keeps its whole project
    out until a person acknowledges the changed scope again: scanning a program's assets without that confirmation can break its rules.
    ``cveFeed.bounty_gate.Gate`` is how a sweep asks, and also asks per host whether the program's scope names it."""
    from django.db.models import F, Q

    from cveFeed.models import BountyEngagement
    confirmed = Q(automated_ok=True, policy_ack_at__isnull=False, status__in=('watching', 'active'), ack_content_hash=F('program__content_hash'))
    return set(BountyEngagement.objects.exclude(confirmed).values_list('project_id', flat=True))


def next_targets(limit, now=None):
    """The targets to scan next, most overdue first: never scanned, then longest since the last scan. At most one per project, none
    with a scan going, none scanned inside the minimum gap, none excluded."""
    from django.db.models import F, OuterRef, Subquery
    from django.utils import timezone

    from cveFeed.exclusions import excluded_names
    from startScan.models import ScanHistory
    from targetApp.models import Domain
    now = now or timezone.now()
    busy = set(active_scans().values_list('domain_id', flat=True))
    from cveFeed.bounty_gate import Gate
    gate = Gate()
    blocked_projects = gate.blocked
    cutoff = now - min_gap()
    from cveFeed.discovery import HOST_PIPELINE_TASK
    # A host-only retest does not refresh discovery of the entire domain.
    newest = (ScanHistory.objects.filter(domain_id=OuterRef('pk'))
              .exclude(tasks__contains=[HOST_PIPELINE_TASK])
              .order_by('-start_scan_date').values('start_scan_date')[:1])
    rows = (Domain.objects.exclude(project=None).annotate(last_scan=Subquery(newest))
            .order_by(F('last_scan').asc(nulls_first=True), 'id').values_list('id', 'project_id', 'name', 'last_scan'))
    from targetApp.target_types import internal_networks, sentinel_only_target
    chosen, projects, banned, internal = [], set(), {}, {}
    for domain_id, project_id, name, last_scan in rows.iterator(chunk_size=500):
        if len(chosen) >= limit:
            break
        if domain_id in busy or project_id in projects or project_id in blocked_projects or (last_scan and last_scan >= cutoff):
            continue
        if project_id not in banned:
            banned[project_id] = excluded_names(project_id)
        if name.lower().rstrip('.') in banned[project_id] or gate.refusal(project_id, name):  # a bug bounty program's scope does not name it
            continue
        if project_id not in internal:
            internal[project_id] = internal_networks(project_id)
        if internal[project_id] and sentinel_only_target(name, project_id, internal[project_id]):
            continue  # inside a declared internal network: a Sentinel scans it, this server never queues discovery for it
        projects.add(project_id)
        chosen.append(domain_id)
    return chosen


def keep_work_queued():
    """One round: top the discovery queue up to the wanted depth. Returns what happened, for the task result and ``status()``."""
    from django.utils import timezone

    from cveFeed.scan_control import pause_requested
    depth = wanted_depth()
    result = {'at': timezone.now().isoformat(), 'depth': depth, 'started': 0}
    if not depth:
        result['skipped'] = 'off'
    elif pause_requested():
        result['skipped'] = 'paused'
    else:
        from cveFeed import ledger
        if not ledger.sweep_claim('conductor', 50):
            result['skipped'] = 'another round is running'
        else:
            current = active_scans().count()
            result['active'] = current
            if current < depth:
                from cveFeed.discovery import start_discoveries
                from targetApp.models import Domain
                ids = next_targets(depth - current)
                if ids:
                    domains = list(Domain.objects.filter(pk__in=ids))
                    domains.sort(key=lambda d: ids.index(d.id))
                    try:
                        result['started'] = len(start_discoveries(domains, 'standard'))
                    except Exception:  # noqa: BLE001 - a failed round must not stop the next one
                        logger.exception('work conductor: could not queue discovery')
                        result['error'] = 'could not queue discovery'
                else:
                    result['skipped'] = 'nothing is due'
    _remember(result)
    return result


def _remember(result):
    try:
        import json

        from reNgine import resources
        client = getattr(resources.get_store(), 'r', None)
        if client is not None:
            client.set(ROUND_KEY, json.dumps(result), ex=24 * 3600)
    except Exception:  # noqa: BLE001
        pass


def last_round():
    try:
        import json

        from reNgine import resources
        client = getattr(resources.get_store(), 'r', None)
        raw = client.get(ROUND_KEY) if client is not None else None
        return json.loads(raw) if raw else None
    except Exception:  # noqa: BLE001
        return None


def status():
    """What the conductor sees, for the system status: the wanted depth, scans running and queued, and its last round."""
    from cveFeed.counts import queued_scans, running_scans
    return {'wanted_depth': wanted_depth(), 'running': running_scans().count(), 'queued': queued_scans().count(), 'last_round': last_round()}
