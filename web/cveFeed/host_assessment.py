"""Scoped, deduplicated assessments of individual inventoried hosts.

Every host has its own ``HostAssessment`` row (status, history, the Live page, the API), but the feed does not run one pipeline per host: hosts of one
target that are due together are carried through one pipeline run (``enqueue_batch`` / ``execute_batch``), so each Sentinel stage is handed many
targets at once instead of one tiny task per host that the pipeline then waits for. ``CVENGINE_ASSESS_BATCH`` sets how many (default 8, 1 to 64;
1 is one pipeline per host, as before)."""
import logging
import os
import uuid

from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone
from datetime import timedelta

from cveFeed.models import HostAssessment

logger = logging.getLogger(__name__)
ACTIVE = ('queued', 'running')


def serialize(job):
    from startScan.models import ScanActivity

    stages = []
    if job.scan_id:
        stages = list(ScanActivity.objects.filter(scan_of_id=job.scan_id).order_by('id').values(
            'name', 'title', 'status', 'error_message', 'time'))
        for stage in stages:
            stage['time'] = stage['time'].isoformat() if stage['time'] else None
    return {'id': job.id, 'host': job.host, 'status': job.status, 'source': job.source,
            'scan_id': job.scan_id, 'stages': stages, 'result': job.result, 'error': job.error,
            'created_at': job.created_at.isoformat(),
            'started_at': job.started_at.isoformat() if job.started_at else None,
            'finished_at': job.finished_at.isoformat() if job.finished_at else None}


ORPHAN_AFTER_MINUTES = 10  # a queued row older than this whose Celery task no longer exists does not count toward the caps


def active_count(project=None):
    """Host assessments occupying a slot: queued or running, not counting a row that has waited ``ORPHAN_AFTER_MINUTES`` for a task that
    no longer exists in any queue or worker (a restart took it; cveFeed.reaper queues such a row again, but until then it would
    hold a slot nothing will ever free). The broker is never asked from here (that takes seconds, and this runs on web requests and every minute):
    the answer is the last one the reaper's own probe stored (``broker_recovery.live_snapshot``), and it is only held against a row that already
    existed when it was taken. With no recent answer every active row counts."""
    rows = HostAssessment._base_manager.filter(status__in=ACTIVE)
    if project is not None:
        rows = rows.filter(project=project)
    total = rows.count()
    old = list(rows.filter(status='queued', created_at__lt=timezone.now() - timedelta(minutes=ORPHAN_AFTER_MINUTES))
               .values_list('celery_id', 'created_at')[:100])
    if not old:
        return total
    from cveFeed import broker_recovery
    snapshot = broker_recovery.live_snapshot()
    if snapshot is None:
        return total
    live, taken_at = snapshot
    return total - sum(1 for task_id, created in old if created < taken_at and (not task_id or task_id not in live))


BATCH_ENV = 'CVENGINE_ASSESS_BATCH'
DEFAULT_BATCH, MAX_BATCH = 8, 64  # 64 is what one dispatched nmap/naabu task takes (agentapi.sentinel_broker.MAX_ADDRESSES)


def batch_size():
    """Most hosts of one target carried through one assessment pipeline run (``CVENGINE_ASSESS_BATCH``, default 8, held to 1..64; 1 runs
    every host on its own, exactly as before batching). An unreadable value is the default. A value saved on Settings, configMaxxing wins over
    the environment (see ``cveFeed.scan_concurrency``); when it cannot be read, the environment decides."""
    try:
        from cveFeed import scan_concurrency
        got = scan_concurrency.resolve('assess_batch')
        if got['source'] == 'admin':
            return got['value']
    except Exception:  # noqa: BLE001 - the saved copy is a cache: without it the environment decides
        logger.debug('assessment batch: the saved size could not be read', exc_info=False)
    try:
        wanted = int(str(os.environ.get(BATCH_ENV, '')).strip())
    except ValueError:
        wanted = DEFAULT_BATCH
    return max(1, min(MAX_BATCH, wanted))


def batch_size_for(project):
    """``batch_size()``, except 1 where batching would do harm:

    * a project a host-narrowed Sentinel covers (``agentapi.sentinel_broker.host_narrowed``): a task naming many hosts can be claimed by a Sentinel
      that only some of them are in the scope of, so those hosts keep one pipeline run, and one task, each;
    * a project no live Sentinel covers (``project_slots`` is 0): the work runs on this server, where nmap and nuclei are held to a few at once
      (``heavy_job``), so a big batch only multiplies the wall time of one run and what a kill at the time limit takes with it."""
    size = batch_size()
    if size > 1:
        try:
            from agentapi import sentinel_broker
            if not sentinel_broker.project_slots(project) or sentinel_broker.host_narrowed(project):
                return 1
        except Exception:  # noqa: BLE001 - when it cannot be told, the safe answer is no batching
            logger.exception('could not tell how project %s is covered by Sentinels', project.pk)
            return 1
    return size


def _live_rows(project=None):
    """``[(celery_id, ...)]`` of the active rows that count: ``active_count``'s rule, row by row (a queued row older than ``ORPHAN_AFTER_MINUTES``
    that the reaper's last broker snapshot says has no task is left out)."""
    rows = HostAssessment._base_manager.filter(status__in=ACTIVE)
    if project is not None:
        rows = rows.filter(project=project)
    rows = list(rows.values_list('celery_id', 'status', 'created_at'))
    cutoff = timezone.now() - timedelta(minutes=ORPHAN_AFTER_MINUTES)
    if any(status == 'queued' and created < cutoff for _, status, created in rows):
        from cveFeed import broker_recovery
        snapshot = broker_recovery.live_snapshot()
        if snapshot is not None:
            live, taken_at = snapshot
            rows = [r for r in rows if not (r[1] == 'queued' and r[2] < cutoff and r[2] < taken_at and (not r[0] or r[0] not in live))]
    return rows


def active_slots(project=None):
    """Pipeline runs occupying a worker slot: the rows of a batch count once, since a batch is one Celery task, one worker slot and one stream of
    Sentinel tasks however many hosts it carries (its rows share a Celery task id); a row with no task id yet is a run of its own. Counted from the
    rows that count (``_live_rows``, so an orphaned batch holds no slot), never as ``active_count`` less something. The caps below are in these
    slots; the hosts in flight are bounded by them times the batch size, and ``active_count`` still counts every host."""
    if batch_size() <= 1:  # no batches are made: one row, one run, exactly as before (a batch still queued from before is counted by host: the safe side)
        return active_count(project)
    rows = _live_rows(project)
    return len({celery_id for celery_id, _, _ in rows if celery_id}) + sum(1 for celery_id, _, _ in rows if not celery_id)


def batches(subs, size=None):
    """``subs`` (``Subdomain`` rows, in order) grouped into lists of at most ``size`` hosts that may share one pipeline run: the same target of the
    same project (the stages, the Sentinels' rights and the gates are the target's), never a host-scoped target or an address typed as a host
    (those have their own address rules: ``is_scannable_ip`` is asked per project for them), which each run alone."""
    from targetApp.target_types import classify_target, IP
    size = batch_size() if size is None else size
    groups, order = {}, []
    for sub in subs:
        domain = sub.target_domain
        alone = size <= 1 or domain.is_host_scoped() or classify_target(sub.name) == IP
        key = ('alone', sub.pk) if alone else (domain.project_id, domain.pk)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(sub)
    out = []
    for key in order:
        rows = groups[key]
        out.extend(rows[i:i + size] for i in range(0, len(rows), max(1, size)))
    return out


BASE_GLOBAL_CAP, BASE_PROJECT_CAP = 20, 5
SENTINEL_QUEUE_FACTOR = 3  # assessments in flight per Sentinel slot: the slots working, plus twice as many waiting behind them


def caps(project=None):
    """``(global cap, per-project cap)`` of host assessments in flight. 20 and 5 on their own; with live Sentinels the work is mostly theirs to do
    (an assessment waits on one for most of its stages), so more may be in flight: ``SENTINEL_QUEUE_FACTOR`` times the slots, so a Sentinel always has
    twice its capacity queued behind what it is running, instead of idling between the few assessments a small cap lets through."""
    try:
        from agentapi import sentinel_broker
        total = sentinel_broker.total_slots()
        mine = sentinel_broker.project_slots(project) if project is not None else 0
    except Exception:  # noqa: BLE001 - the base caps are always safe
        return BASE_GLOBAL_CAP, BASE_PROJECT_CAP
    return (max(BASE_GLOBAL_CAP, BASE_GLOBAL_CAP + SENTINEL_QUEUE_FACTOR * total),
            max(BASE_PROJECT_CAP, SENTINEL_QUEUE_FACTOR * mine))


def _admit(project, sub, unattended=True):
    """``(target domain, host name)`` for a stored host owned by this project that may be assessed, else ``ValueError``."""
    from cveFeed.exclusions import is_excluded
    from cveFeed.models import HostState
    from targetApp.models import Domain
    from targetApp.target_types import sentinel_only_target

    domain = sub.target_domain
    host = sub.name.lower().rstrip('.')
    if not domain or domain.project_id != project.pk or not (host == domain.name.lower() or
            (not domain.is_host_scoped() and host.endswith('.' + domain.name.lower()))):
        raise ValueError('host is outside its stored target scope')
    if sentinel_only_target(host, project.pk):
        raise ValueError('internal hosts are assessed by an internal Sentinel scan')
    if unattended and domain.discovery_mode == Domain.DISCOVERY_MANUAL:  # "just add them, do not scan yet": only a person's request assesses its hosts
        from cveFeed.manual_only import other_holder
        domain = other_holder(project.pk, host)  # unless a target that is not manual only holds the host too: then it is that target's
        if domain is None:
            raise ValueError('the target is set to manual only; assess its hosts yourself, or pick a discovery mode for it')
    if is_excluded(project.pk, host):
        raise ValueError('host is excluded')
    from cveFeed.bounty_gate import Gate
    why = Gate().refusal(project.pk, host, unattended=unattended)  # no person behind it: a bug bounty project must have confirmed automated testing; any caller: the host must be in scope
    if why:
        raise ValueError(f'host is not scanned: {why}')
    if HostState.objects.filter(project=project, host=host, archived_at__isnull=False).exists():
        raise ValueError('host is archived; restore it before scanning')
    return domain, host


def _require_capacity(project):
    """``RuntimeError`` when the queue is at capacity. The global caps count every project: _base_manager is not narrowed to the caller's projects
    by the tenancy scope, which inside a request would make "20 at once across the installation" mean 20 per user. They are counted in worker
    slots (``active_slots``: a batch is one)."""
    from startScan.models import ScanHistory
    active_scans = ScanHistory._base_manager.filter(Q(scan_status=-1) | Q(scan_status=1,
                                                                          start_scan_date__gte=timezone.now() - timedelta(hours=11)))
    global_cap, project_cap = caps(project)
    if active_slots() >= global_cap or active_slots(project) >= project_cap or active_scans.count() >= max(20, global_cap):
        raise RuntimeError('host assessment queue is at capacity; retry later')


def enqueue(project, sub, *, source='manual', user=None):
    """Accept only a stored host owned by this project; a model cannot supply a new target."""
    domain, host = _admit(project, sub, unattended=user is None)
    existing = HostAssessment.objects.filter(project=project, host=host, status__in=ACTIVE).order_by('id').first()
    if existing:
        return existing, False
    _require_capacity(project)
    try:
        with transaction.atomic():
            job = HostAssessment.objects.create(project=project, domain=domain, host=host, source=source, requested_by=user)
    except IntegrityError:
        return HostAssessment.objects.get(project=project, host=host, status__in=ACTIVE), False
    from cveFeed.tasks import assess_host
    try:
        task = assess_host.apply_async(args=[job.pk], queue='discovery_queue')
        HostAssessment.objects.filter(pk=job.pk, status='queued').update(celery_id=task.id)
        from cveFeed import activity
        activity.log('discovery', f'Host assessment #{job.pk} queued for {host}', project=project.pk, status='queued')
    except Exception as exc:
        logger.exception('could not enqueue host assessment %s', job.pk)
        HostAssessment.objects.filter(pk=job.pk).update(status='failed', finished_at=timezone.now(),
                                                         error=f'broker enqueue failed: {type(exc).__name__}')
        job.refresh_from_db()
        return job, True
    job.refresh_from_db()
    return job, True


def enqueue_batch(project, subs, *, source='topup'):
    """Queue ``subs`` (hosts of one target of ``project``, from ``batches``) as ONE pipeline run with a row per host. Returns ``(jobs, skipped)``:
    the rows queued, and ``[(sub, reason)]`` for each host that was not (a gate refused it, or it already has an active assessment). Every host
    passes the same gates as ``enqueue`` (scope, internal ranges, exclusions, bug bounty confirmation and scope, archive, no second active row); a
    host refused is left out and the others go on. ``RuntimeError`` when the queue is at capacity. A single host is exactly ``enqueue``."""
    subs = list(subs)
    if len(subs) == 1:
        try:
            job, created = enqueue(project, subs[0], source=source)
        except ValueError as exc:
            return [], [(subs[0], str(exc))]
        if created and job.status == 'queued':
            return [job], []
        return [], [(subs[0], 'already queued' if not created else job.error or job.status)]
    admitted, skipped, domain = [], [], None
    for sub in subs:
        try:
            sub_domain, host = _admit(project, sub)
        except ValueError as exc:
            skipped.append((sub, str(exc)))
            continue
        if domain is not None and sub_domain.pk != domain.pk:
            skipped.append((sub, 'a batch holds the hosts of one target'))
            continue
        if HostAssessment.objects.filter(project=project, host=host, status__in=ACTIVE).exists():
            skipped.append((sub, 'already queued'))
            continue
        domain = sub_domain
        admitted.append((sub, host))
    if not admitted:
        return [], skipped
    _require_capacity(project)
    created = []  # (sub, row)
    for sub, host in admitted:
        try:
            with transaction.atomic():
                created.append((sub, HostAssessment.objects.create(project=project, domain=domain, host=host, source=source)))
        except IntegrityError:  # a second sweep queued it between the check and now
            skipped.append((sub, 'already queued'))
    jobs = [job for _, job in created]
    if not jobs:
        return [], skipped
    task_id = str(uuid.uuid4())  # the rows share it: a batch is one Celery task (the reaper and ``active_slots`` read the group from it)
    ids = [job.pk for job in jobs]
    HostAssessment.objects.filter(pk__in=ids).update(celery_id=task_id)
    from cveFeed import activity
    from cveFeed.tasks import assess_hosts
    try:
        assess_hosts.apply_async(args=[ids], task_id=task_id, queue='discovery_queue')
    except Exception as exc:
        logger.exception('could not enqueue host assessment batch %s', ids)
        HostAssessment.objects.filter(pk__in=ids).update(status='failed', finished_at=timezone.now(),
                                                         error=f'broker enqueue failed: {type(exc).__name__}')
        return [], skipped + [(sub, f'broker enqueue failed: {type(exc).__name__}') for sub, _ in created]
    names = [job.host for job in jobs]
    activity.log('discovery', f'Host assessments #{ids[0]} to #{ids[-1]} queued as one run for {len(ids)} host{"s" if len(ids) != 1 else ""} of '
                 f'{domain.name} ({", ".join(names[:3])}{", ..." if len(names) > 3 else ""})', project=project.pk, status='queued')
    return list(HostAssessment.objects.filter(pk__in=ids).order_by('pk')), skipped


def _unassessable(job):
    """Whether the host may no longer be assessed now: it is gone from the inventory, internal, excluded, archived, outside its target, or
    scanning is paused, or the program's scope or confirmation changed while it queued (re-read here: that is the point of use)."""
    from cveFeed.bounty_gate import Gate
    from cveFeed.exclusions import is_excluded
    from cveFeed.models import HostState
    from cveFeed.scan_control import pause_requested
    from startScan.models import Subdomain
    from targetApp.models import Domain
    from targetApp.target_types import sentinel_only_target

    current = Subdomain.objects.filter(target_domain=job.domain, name=job.host).exists()
    return bool(not current or sentinel_only_target(job.host, job.project_id) or is_excluded(job.project_id, job.host) or
                (job.requested_by_id is None and job.domain.discovery_mode == Domain.DISCOVERY_MANUAL) or
                HostState.objects.filter(project_id=job.project_id, host=job.host, archived_at__isnull=False).exists() or
                (job.domain.is_host_scoped() and job.host != job.domain.name.lower()) or pause_requested() or
                Gate().refusal(job.project_id, job.host, unattended=job.requested_by_id is None))


BATCH_STOPPED = 'Stopped with the run it was part of: another host of that run was stopped by a person'  # see agentapi.services.stop_host_assessment


REFUSED = {'status': 'inconclusive', 'error': 'host is absent, excluded, outside scope, or scanning is paused'}


def _finish(job, result):
    """Store one host's outcome: its status, its streak of attempts with no scannable address, and the activity line."""
    from cveFeed import activity
    from cveFeed.unresolved_archive import record_attempt
    state = result.get('status')
    # a stage that failed leaves the assessment incomplete even though the scan (and the inventory it found) stands
    status = (('failed' if result.get('failed_stages') else 'completed') if state == 2 else 'stopped' if state == 'aborted' else
              'inconclusive' if state in ('empty', 'inconclusive') else 'failed')
    record_attempt(job.project, job.domain, job.host, result)
    HostAssessment.objects.filter(pk=job.pk, status='running').update(
        status=status, result=result, error=str(result.get('error') or '')[:300], finished_at=timezone.now())
    activity.log('discovery', f'Host assessment #{job.pk} {status} for {job.host}' +
                 (f': {str(result.get("error"))[:160]}' if result.get('error') else ''),
                 project=job.project_id, status='failed' if status == 'failed' else 'done', scan_id=result.get('scan_id'))
    return status


def _diagnosed(job, result):
    """A failed run reports the exception text of whatever stopped it; every other state carries the pipeline's own explanation
    ("Failed stages: nmap_scan", "stopped", why it was inconclusive), which stays."""
    from cveFeed import activity
    from cveFeed.discovery import FAILED
    if result.get('error') and result.get('status') == FAILED:
        return {**result, 'error': activity.diagnostic(f'Host assessment #{job.pk}', result['error'])}
    return result


def _failed(job, exc):
    from cveFeed import activity
    return {'status': 'failed', 'error': activity.diagnostic(f'Host assessment #{job.pk}', f'{type(exc).__name__}: {exc}', type(exc).__name__)}


def execute(job_id, celery_id=None):
    from cveFeed.discovery import run_host_pipeline

    now = timezone.now()
    if not HostAssessment.objects.filter(pk=job_id, status='queued').update(status='running', started_at=now):
        return {'status': 'stopped_or_already_started'}
    job = HostAssessment.objects.select_related('domain', 'project').get(pk=job_id)
    from cveFeed import activity
    activity.log('discovery', f'Host assessment #{job.pk} started for {job.host}', project=job.project_id, status='running')
    try:
        if _unassessable(job):
            result = dict(REFUSED)
        else:
            result = _diagnosed(job, run_host_pipeline(job.domain_id, [job.host], celery_id=celery_id, retest=True,
                                                       force=True, hygiene=True, assessment_id=job_id,
                                                       by_person=job.requested_by_id is not None))
    except Exception as exc:
        logger.exception('host assessment %s failed', job_id)
        result = _failed(job, exc)
    _finish(job, result)
    return result


def execute_batch(job_ids, celery_id=None):
    """Run the queued assessments ``job_ids`` (hosts of one target, from ``enqueue_batch``) as one pipeline run, then settle each host on its own.

    A row stopped while it waited is skipped. Each host is checked again at the point of use (``_unassessable``) and one that no longer passes is
    ``inconclusive`` alone; the others go on. The pipeline names the hosts that did not reach the stages (no answer from DNS, no scannable
    address, dropped by a gate): each gets its own outcome and the rest the run's. A stage that failed is every host's, as the scan is shared,
    and a run that is stopped (the scan, or a pause) stops them all. Returns ``{'hosts': n, 'statuses': {status: count}}``."""
    from cveFeed import activity
    from cveFeed.discovery import run_host_pipeline

    claimed = []
    for pk in dict.fromkeys(job_ids):
        if HostAssessment.objects.filter(pk=pk, status='queued').update(status='running', started_at=timezone.now()):
            claimed.append(pk)
    if not claimed:
        return {'status': 'stopped_or_already_started'}
    jobs = list(HostAssessment.objects.select_related('domain', 'project').filter(pk__in=claimed).order_by('pk'))
    groups = {}
    for job in jobs:  # enqueue_batch makes one target; a row that is not is still never run with another target's
        groups.setdefault((job.domain_id, job.requested_by_id), []).append(job)
    statuses = {}
    for (domain_id, requested_by), group in groups.items():
        activity.log('discovery', f'Host assessments #{group[0].pk} to #{group[-1].pk} started as one run for {len(group)} host'
                     f'{"s" if len(group) != 1 else ""} of {group[0].domain.name}', project=group[0].project_id, status='running')
        try:
            eligible = []
            for job in group:
                if _unassessable(job):
                    status = _finish(job, dict(REFUSED))
                    statuses[status] = statuses.get(status, 0) + 1
                else:
                    eligible.append(job)
            if not eligible:
                continue
            outcome = run_host_pipeline(domain_id, [job.host for job in eligible], celery_id=celery_id, retest=True, force=True, hygiene=True,
                                        assessment_ids=[job.pk for job in eligible], by_person=requested_by is not None)
            own = outcome.pop('per_host', {}) if isinstance(outcome, dict) else {}
            for job in eligible:
                if job.host in own:
                    result = own[job.host]
                else:  # the host went through the stages: the run's result, with this host's own count of what resolved
                    result = {**outcome, 'batch_hosts': len(eligible), **({'resolved': 1} if 'resolved' in outcome else {})}
                status = _finish(job, _diagnosed(job, result))
                statuses[status] = statuses.get(status, 0) + 1
        except Exception as exc:
            logger.exception('host assessment batch %s failed', [job.pk for job in group])
            for job in group:
                if HostAssessment.objects.filter(pk=job.pk, status='running').exists():
                    status = _finish(job, _failed(job, exc))
                    statuses[status] = statuses.get(status, 0) + 1
    return {'hosts': len(jobs), 'statuses': statuses}
