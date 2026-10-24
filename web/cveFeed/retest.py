"""Re-test on change: a host that just changed is tested again now, not at the next scheduled scan.

When a scan's changes are recorded, the hosts whose exposure grew (a new or returned host, a port opened, a version changed, a
technology added, a route that became open, a zombie) go through the host pipeline once more, with the CVE checks forced: a
version bump must be tested even if that CVE was checked for the host yesterday. At most RETEST_MAX_HOSTS hosts per source scan,
one re-test per host per 24 hours, and a re-test never triggers another (it is a partial scan, which is the loop breaker).
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
RETEST_SERVICE = 'retest'  # ledger: one re-test per host per 24 hours (CVENGINE_TTL_RETEST)
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


def dispatch_deferred_retests(limit=None):
    """Send one bounded oldest-first batch. Broker rejection leaves rows pending."""
    from cveFeed.models import DeferredRetest
    from cveFeed.tasks import retest_hosts
    from cveFeed import ledger
    now = timezone.now()
    with transaction.atomic():
        # A publisher crash is retried quickly; a running scan gets its full bounded execution window.
        DeferredRetest.objects.filter(status='dispatching', updated_at__lt=now - timedelta(minutes=5)).update(
            status='pending', next_attempt_at=now, updated_at=now)
        DeferredRetest.objects.filter(status__in=['queued', 'running'], updated_at__lt=now - timedelta(hours=3)).update(
            status='pending', next_attempt_at=now + timedelta(minutes=5), updated_at=now)
        chosen = list(DeferredRetest.objects.select_for_update(skip_locked=True).filter(
            status='pending', next_attempt_at__lte=now).order_by('created_at', 'id')[:1])
        if not chosen:
            return {'queued': 0}
        first = chosen[0]
        batch = list(DeferredRetest.objects.select_for_update(skip_locked=True).filter(
            status='pending', next_attempt_at__lte=now, domain_id=first.domain_id, scan_id=first.scan_id)
                     .order_by('created_at', 'id')[:min(limit or max_hosts(), max_hosts())])
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
    re-test itself) never queues one, which is what stops a loop; a scan with nothing to re-test queues nothing. The ledger is
    recorded only after broker acceptance, so a failed enqueue cannot suppress a later retry."""
    from cveFeed import activity, discovery, ledger
    from cveFeed.models import DeferredRetest
    if discovery.HOST_PIPELINE_TASK in (scan.tasks or []) or RETEST_TASK in (scan.tasks or []):
        return {'queued': 0, 'reason': 'partial scan'}
    evidence = _changed_evidence(scan)
    if not evidence:
        return {'queued': 0, 'reason': 'nothing changed'}
    domain, project = scan.domain, scan.domain.project_id
    prior = set(DeferredRetest.objects.filter(project_id=project, host__in=evidence).values_list('host', 'signature'))
    # Preserve the legacy TTL for rows from before the durable queue existed.
    legacy_fresh = ledger.fresh(RETEST_SERVICE, evidence, project)
    known_hosts = {h for h, _ in prior}
    to_add = [DeferredRetest(project_id=project, domain=domain, scan=scan, host=host, signature=sig)
              for host, sig in evidence.items() if (host, sig) not in prior and not (host in legacy_fresh and host not in known_hosts)]
    DeferredRetest.objects.bulk_create(to_add, ignore_conflicts=True)
    dispatched = dispatch_deferred_retests()
    if dispatched['queued']:
        names = dispatched['hosts']
        activity.log('changes', f'Re-testing {len(names)} changed host(s) of {domain.name}: {", ".join(names[:3])}'
                     f'{", ..." if len(names) > 3 else ""}', project=project, scan_id=scan.id)
    return dispatched if dispatched['queued'] or dispatched.get('error') else {
        'queued': 0, 'reason': 'nothing changed' if not to_add else 'deferred'}
