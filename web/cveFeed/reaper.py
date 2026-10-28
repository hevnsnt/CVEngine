"""Expire host-assessment, validation, scan and activity-feed jobs that will never finish.

A worker killed mid-task (restart, out-of-memory, a lost broker message) leaves its job "queued" or "running" for good: it holds the
host's or finding's only active slot and counts toward the per-project and global caps, so one bad restart can stop a project's
assessments or automatic validation, or leave an AI activity row showing "running" in the feed forever even though the scan or
check it described has long since finished. Every 15 minutes (tasks.reap_stuck_jobs) a job past its age limit is marked failed
with the reason. A finishing worker only ever updates a row still "running", so a late result is dropped, never mixed in. A
failed validation job is due again at once (next_attempt_at) while it has attempts left, so the sweep can queue it afresh. While
scanning is paused, queued jobs are waiting on purpose and are left alone; only running ones are expired.

A ``ScanHistory`` row and a running ``HostAssessment`` are not in the hours-based table above: a scan is not a capacity-limited slot
the way a validation or assessment job is, so it never used to be expired at all, and scripts/apply-update.sh's drain wait
(``running_scans``) counts any ``scan_status=1`` row with no age limit of its own - a scan orphaned by a worker restart (its Celery
task gone, nothing left to ever finish it) would otherwise block every later update indefinitely, as happened on a live install (a
worker restart at the scan's start left it "running" with a dead task; the next update waited over five hours for it). Rather than
wait for an hours-scale timeout, ``expire_orphaned_running`` asks the broker directly (the same check ``redispatch_queued_assessments``
already uses) whether a still-running scan's or assessment's Celery task exists anywhere, and closes it out within one reaper tick
once it is both past a short grace period and provably dead - the row is never closed just because the broker could not be asked."""
import os
from datetime import timedelta

from django.db.models import CharField, F, Value
from django.db.models.functions import Concat, Left
from django.utils import timezone

# (model, state, age setting, default hours, the timestamp the age is measured from)
LIMITS = (
    ('HostAssessment', 'queued', 'CVENGINE_ASSESSMENT_QUEUED_HOURS', 12, 'created_at'),
    ('HostAssessment', 'running', 'CVENGINE_ASSESSMENT_RUNNING_HOURS', 6, 'started_at'),
    ('OnDemandValidation', 'queued', 'CVENGINE_VALIDATION_QUEUED_HOURS', 6, 'created_at'),
    ('OnDemandValidation', 'running', 'CVENGINE_VALIDATION_RUNNING_HOURS', 2, 'started_at'),
    ('AutomaticValidation', 'queued', 'CVENGINE_VALIDATION_QUEUED_HOURS', 6, 'created_at'),
    ('AutomaticValidation', 'running', 'CVENGINE_VALIDATION_RUNNING_HOURS', 2, 'started_at'),
    # matches discovery.RUNNING_WINDOW_SECONDS: the same age a scan itself is considered a restart casualty at
    ('AgentActivity', 'running', 'CVENGINE_ACTIVITY_RUNNING_HOURS', 11, 'created_at'),
)
VALIDATION_MODELS = ('OnDemandValidation', 'AutomaticValidation')
NO_ERROR_FIELD = ('AgentActivity',)  # has no `error` column; the reason is appended to its own `message` instead


def _hours(name, default):
    try:
        return max(1, int(os.environ.get(name, '')))
    except ValueError:
        return default


REDISPATCH_AFTER_MINUTES = 30  # a queued assessment nobody started in this long is asked for again
REDISPATCH_EVERY_HOURS = 2  # and no more often than this, so a long but healthy queue does not fill with copies


def redispatch_queued_assessments(now=None):
    """Queue the host assessments still waiting after ``REDISPATCH_AFTER_MINUTES`` once more. A queued row whose worker message was lost
    (a broker or worker restart that returned nothing, see cveFeed.broker_recovery) would otherwise count toward the capacity limit until
    the reaper expires it hours later. A second message is harmless: ``host_assessment.execute`` moves a row from queued to running once,
    and a message for a row that already moved does nothing. A row whose task the broker or a worker still holds is left alone when that can
    be told (``broker_recovery.live_task_ids``). Returns how many were queued again."""
    from django.db.models import Q

    from cveFeed import ledger
    from cveFeed.models import HostAssessment
    from cveFeed.scan_control import pause_requested
    from cveFeed.tasks import assess_host
    from reNgine import resources
    if pause_requested():  # waiting on purpose
        return 0
    from cveFeed import broker_recovery
    now = now or timezone.now()
    client = getattr(resources.get_store(), 'r', None)
    live = broker_recovery.live_task_ids()  # None when it cannot be told: then only the age and the rate limit decide
    queued = 0
    for job in HostAssessment._base_manager.filter(Q(status='queued'), created_at__lt=now - timedelta(minutes=REDISPATCH_AFTER_MINUTES)
                                                    ).order_by('id')[:50]:
        if live is not None and job.celery_id and job.celery_id in live:  # still in a queue or a worker: it is only waiting its turn
            continue
        key = f'cvengine:assess:redispatch:{job.pk}'
        try:
            if client is None or not client.set(key, ledger._owner(), nx=True, ex=REDISPATCH_EVERY_HOURS * 3600):
                continue
        except Exception:  # noqa: BLE001 - no Redis, no way to rate-limit: leave it to the reaper
            continue
        task = assess_host.apply_async(args=[job.pk], queue='discovery_queue')
        HostAssessment._base_manager.filter(pk=job.pk, status='queued').update(celery_id=task.id)
        queued += 1
    return queued


STALE_RUNNING_GRACE_SECONDS = 120  # a scan or assessment this young may not have its celery id recorded yet: never judged by the broker alone


def expire_orphaned_running(now=None, live=None):
    """Close a ``ScanHistory`` or ``HostAssessment`` row stuck "running" because the worker that held it was killed (a worker or
    update restart) before it could finish or requeue it: closed as soon as the broker can say its Celery task exists nowhere (not
    queued, held unacknowledged, reserved, active or scheduled), rather than waiting for the hours-scale ``LIMITS`` above. ``live``
    (``broker_recovery.live_task_ids()``, injectable for tests) is None when that cannot be told - no Redis broker, a queue too
    long to read, no worker answered - and then nothing here is closed; the hours-based expiry above is the fallback. Returns
    ``{'<Model>': n}``."""
    now = now or timezone.now()
    if live is None:
        from cveFeed import broker_recovery
        live = broker_recovery.live_task_ids()
    if live is None:
        return {}
    cutoff = now - timedelta(seconds=STALE_RUNNING_GRACE_SECONDS)
    counts = {}
    from startScan.models import ScanHistory
    message = 'expired: the worker running this scan is gone (a restart or update) and no Celery task for it remains'
    dead = [s.pk for s in ScanHistory.objects.filter(scan_status=1, start_scan_date__lt=cutoff).only('pk', 'celery_ids')
            if not set(s.celery_ids) & live]
    if dead:
        n = ScanHistory.objects.filter(pk__in=dead, scan_status=1).update(scan_status=0, stop_scan_date=now, error_message=message[:290])
        if n:
            counts['ScanHistory'] = n
    from cveFeed.models import HostAssessment
    dead_ha = [a.pk for a in HostAssessment._base_manager.filter(status='running', started_at__lt=cutoff).only('pk', 'celery_id')
               if not a.celery_id or a.celery_id not in live]
    if dead_ha:
        n = HostAssessment._base_manager.filter(pk__in=dead_ha, status='running').update(status='failed', finished_at=now, error=message)
        if n:
            counts['HostAssessment'] = n
    return counts


def reap(now=None):
    """Expire the stuck jobs. Returns {'<Model>:<state>': n} for the ones expired."""
    from django.apps import apps
    from django.db.models import Q

    from cveFeed.scan_control import pause_requested
    now = now or timezone.now()
    paused = pause_requested()
    counts = {}
    for name, state, setting, default, field in LIMITS:
        if state == 'queued' and paused:
            continue
        hours = _hours(setting, default)
        cutoff = now - timedelta(hours=hours)
        model = apps.get_model('cveFeed', name)
        # a running row with no start time (written by an older worker) ages from its creation
        old = Q(**{f'{field}__lt': cutoff})
        if field == 'started_at':
            old |= Q(started_at__isnull=True, created_at__lt=cutoff)
        reason = (f'expired: still queued after {hours} hours; the worker or broker probably lost it' if state == 'queued' else
                  f'expired: no result after {hours} hours running; the worker was probably restarted')
        fields = {'status': 'failed', 'finished_at': now}
        if name in NO_ERROR_FIELD:
            # message is a CharField(500); Left() keeps a long existing message from overflowing the column on concat
            tagged = Concat(F('message'), Value(f' ({reason})'), output_field=CharField())
            fields['message'] = Left(tagged, 500)
        else:
            fields['error'] = reason
        stuck = model.objects.filter(old, status=state)
        if name in VALIDATION_MODELS:
            # due again at once while attempts remain; a job that keeps killing its worker stops at MAX_ATTEMPTS like any failure
            from cveFeed.hot_validation import MAX_ATTEMPTS
            n = stuck.filter(attempts__lt=MAX_ATTEMPTS).update(**fields, next_attempt_at=now)
            n += stuck.update(**fields, next_attempt_at=None)
        else:
            n = stuck.update(**fields)
        if n:
            counts[f'{name}:{state}'] = n
    return counts
