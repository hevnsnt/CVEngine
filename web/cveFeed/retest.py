"""Re-test on change: a host that just changed is tested again now, not at the next scheduled scan.

When a scan's changes are recorded, the hosts whose exposure grew (a new or returned host, a port opened, a version changed, a
technology added, a route that became open, a zombie) go through the host pipeline once more, with the CVE checks forced: a
version bump must be tested even if that CVE was checked for the host yesterday. At most RETEST_MAX_HOSTS hosts per source scan,
equal evidence coalesces for 24 hours (new evidence can run sooner), and a re-test never triggers another because it is a partial scan.
"""
import logging
import os
import hashlib
import json
from collections import defaultdict
from datetime import timedelta

from django.db import models, transaction
from django.utils import timezone

logger = logging.getLogger(__name__)

RETEST_TASK = 'retest'  # marker in ScanHistory.tasks next to HOST_PIPELINE_TASK
RETEST_SERVICE = 'retest'  # equal evidence coalesces for CVENGINE_TTL_RETEST hours
DEFAULT_MAX_HOSTS = 25
MAX_CHANGE_ROWS = 2000  # change rows read per scan
TRIGGER_KINDS = ('host_new', 'host_returned', 'port_opened', 'service_changed', 'tech_added', 'tech_version_changed', 'auth_changed',
                 'zombie_host')


def max_hosts():
    """Hosts re-tested per source scan (CVENGINE_RETEST_MAX_HOSTS)."""
    try:
        return max(1, int(os.environ.get('CVENGINE_RETEST_MAX_HOSTS', DEFAULT_MAX_HOSTS)))
    except ValueError:
        return DEFAULT_MAX_HOSTS


def _worth_it(row):
    """Whether one change row is a reason to test again."""
    before, after = row['before'] or {}, row['after'] or {}
    if row['kind'] == 'service_changed':
        return isinstance(after, dict) and after.get('version') != before.get('version')
    if row['kind'] == 'auth_changed':
        return after.get('auth_state') == 'open' and before.get('auth_state') != 'open'
    return True


def hosts_to_retest(scan):
    """The host names of ``scan`` to test again, highest score first, at most max_hosts(): those with a change that matters
    (a service change counts only when the version differs, an auth change only when a route became open), minus hosts
    already re-tested inside the ledger window."""
    from cveFeed import ledger
    from cveFeed.scoring import row_preference, usable_rows
    from cveFeed.models import AssetChange
    from startScan.models import Subdomain
    project = scan.domain.project_id
    rows = AssetChange.objects.filter(scan=scan, kind__in=TRIGGER_KINDS).values('host', 'kind', 'before', 'after')[:MAX_CHANGE_ROWS]
    names = list(dict.fromkeys(r['host'] for r in rows if _worth_it(r)))
    if not names:
        return []
    recent = ledger.fresh(RETEST_SERVICE, names, project)
    names = [n for n in names if n.lower() not in recent]
    score = {}
    for start in range(0, len(names), 500):
        # the score of the source scan's row, else of the newest finished scan's: a failed or queued scan's partial row (score 0)
        # must not push a fire host to the back of the queue
        rows = usable_rows(Subdomain.objects.filter(target_domain__project_id=project, name__in=names[start:start + 500])) \
            .order_by('name', *row_preference(scan.id)).distinct('name')
        for name, best in rows.values_list('name', 'score'):
            score[name] = best or 0
    names.sort(key=lambda n: (-score.get(n, 0), n))  # hottest first, then by name
    return names[:max_hosts()]


def _changed_evidence(scan):
    """Group all relevant change rows; equal evidence coalesces across scans."""
    from cveFeed.models import AssetChange
    by_host = defaultdict(list)
    rows = AssetChange.objects.filter(scan=scan, kind__in=TRIGGER_KINDS).values('host', 'kind', 'before', 'after')
    for row in rows.iterator(chunk_size=500):
        if _worth_it(row):
            by_host[row['host'].lower()].append([row['kind'], row['before'], row['after']])
    return {host: hashlib.sha1(json.dumps(sorted(items, key=lambda x: json.dumps(x, sort_keys=True, default=str)),
                                        sort_keys=True, default=str).encode()).hexdigest()
            for host, items in by_host.items()}


def _next_project(due):
    """The project to serve next: of those with due re-tests, the one whose re-tests were dispatched longest ago (never first),
    so one tenant's large discovery cannot hold every other project's re-tests behind its batches."""
    from django.db.models import Max

    from cveFeed.models import DeferredRetest
    projects = sorted(set(due.values_list('project_id', flat=True)))
    if not projects:
        return None
    served = dict(DeferredRetest.objects.filter(project_id__in=projects).exclude(status='pending')
                  .values('project_id').annotate(at=Max('updated_at')).values_list('project_id', 'at'))
    return min(projects, key=lambda p: (p in served, served.get(p) or timezone.now(), p))


def dispatch_deferred_retests(limit=None):
    """Send one bounded batch: the least recently served project's due re-tests of one scan, hottest hosts first. Broker
    rejection leaves rows pending."""
    from django.db.models import OuterRef, Subquery, Value
    from django.db.models.functions import Coalesce

    from cveFeed.models import DeferredRetest, HostState
    from cveFeed.tasks import retest_hosts
    from cveFeed import ledger
    now = timezone.now()
    with transaction.atomic():
        # A publisher crash is retried quickly; a running scan gets its full bounded execution window.
        DeferredRetest.objects.filter(status='dispatching', updated_at__lt=now - timedelta(minutes=5)).update(
            status='pending', next_attempt_at=now, updated_at=now)
        DeferredRetest.objects.filter(status__in=['queued', 'running'], updated_at__lt=now - timedelta(hours=3)).update(
            status='pending', next_attempt_at=now + timedelta(minutes=5), updated_at=now)
        due = DeferredRetest.objects.filter(status='pending', next_attempt_at__lte=now)
        project = _next_project(due)
        if project is None:
            return {'queued': 0}
        # within the project, the hottest changed hosts go first (HostState.score), oldest first at equal heat
        heat = Coalesce(Subquery(HostState.objects.filter(project_id=OuterRef('project_id'), host=OuterRef('host'))
                                 .values('score')[:1]), Value(0))
        chosen = list(due.select_for_update(skip_locked=True).filter(project_id=project).annotate(heat=heat)
                      .order_by('-heat', 'created_at', 'id')[:1])
        if not chosen:
            return {'queued': 0}
        first = chosen[0]
        batch = list(due.select_for_update(skip_locked=True).filter(domain_id=first.domain_id, scan_id=first.scan_id)
                     .annotate(heat=heat).order_by('-heat', 'created_at', 'id')[:min(limit or max_hosts(), max_hosts())])
        ids, names = [r.id for r in batch], [r.host for r in batch]
        # Commit this claim before publishing: a fast worker must be able to see it.
        DeferredRetest.objects.filter(pk__in=ids).update(status='dispatching', attempts=models.F('attempts') + 1,
                                                        updated_at=now)
    ledger.record(RETEST_SERVICE, names, first.project_id, first.scan_id, 'queued')
    try:
        retest_hosts.delay(first.domain_id, names, first.scan_id, ids)
    except Exception:
        logger.exception('retest broker rejected %s hosts', len(names))
        DeferredRetest.objects.filter(pk__in=ids, status='dispatching').update(
            status='pending', next_attempt_at=timezone.now() + timedelta(minutes=5), updated_at=timezone.now())
        ledger.record(RETEST_SERVICE, names, first.project_id, first.scan_id, 'failed')
        return {'queued': 0, 'error': 'broker unavailable'}
    DeferredRetest.objects.filter(pk__in=ids, status='dispatching').update(status='queued', updated_at=timezone.now())
    return {'queued': len(names), 'hosts': names}


def queue_retests(scan):
    """Queue one re-test of the hosts that changed in ``scan``. Guards, in order: a partial scan (a new-hosts pipeline, and a
    re-test itself) never queues one, which is what stops a loop; a scan with nothing to re-test queues nothing. Active work
    and recent terminal episodes coalesce equal evidence; a later recurrence gets a new row and its own retry budget."""
    from cveFeed import activity, discovery, ledger
    from cveFeed.models import DeferredRetest
    from dashboard.models import Project
    if discovery.HOST_PIPELINE_TASK in (scan.tasks or []) or RETEST_TASK in (scan.tasks or []):
        return {'queued': 0, 'reason': 'partial scan'}
    evidence = _changed_evidence(scan)
    if not evidence:
        return {'queued': 0, 'reason': 'nothing changed'}
    domain, project = scan.domain, scan.domain.project_id
    with transaction.atomic():
        # Serialize producers even when no episode exists yet. A fast worker may finish between two producers;
        # the second must see that terminal episode before deciding whether it is time for another one.
        Project.objects.select_for_update().get(pk=project)
        prior_rows = DeferredRetest.objects.filter(project_id=project, host__in=evidence)
        known_hosts = set(prior_rows.values_list('host', flat=True).distinct())
        cutoff = min(timezone.now() - timedelta(seconds=ledger.ttl(RETEST_SERVICE)), scan.start_scan_date)
        prior = set(prior_rows.filter(
            models.Q(status__in=['pending', 'dispatching', 'queued', 'running']) |
            models.Q(updated_at__gte=cutoff) | models.Q(scan=scan)
        ).values_list('host', 'signature'))
        # Keep legacy coverage and source-scan replay protection. A delayed scan that began before the last
        # episode finished is still part of that episode, even if its callback arrives after the TTL.
        legacy_fresh = ledger.fresh(RETEST_SERVICE, evidence, project)
        to_add = [DeferredRetest(project_id=project, domain=domain, scan=scan, host=host, signature=sig)
                  for host, sig in evidence.items()
                  if (host, sig) not in prior and not (host in legacy_fresh and host not in known_hosts)]
        DeferredRetest.objects.bulk_create(to_add, ignore_conflicts=True)
    dispatched = dispatch_deferred_retests()
    if dispatched['queued']:
        names = dispatched['hosts']
        activity.log('changes', f'Re-testing {len(names)} changed host(s) of {domain.name}: {", ".join(names[:3])}'
                     f'{", ..." if len(names) > 3 else ""}', project=project, scan_id=scan.id)
    return dispatched if dispatched['queued'] or dispatched.get('error') else {
        'queued': 0, 'reason': 'nothing changed' if not to_add else 'deferred'}
