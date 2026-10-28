"""Durable operator pause for scanner dispatch and active scanner processes."""
import fcntl
import os
import time
from contextlib import contextmanager

from celery import Task
from django.conf import settings
from django_celery_beat.schedulers import DatabaseScheduler


# Work that never touches a customer target and costs no AI budget keeps running during a pause: the CVE feed, distribution
# fixes, bug bounty catalogue and threat intelligence, the update check and template download, notifications, pruning and
# other bookkeeping. Everything else (discovery, scanners, validation, AI triage and reviews, certificate watching) waits.
PAUSE_EXEMPT_TASKS = frozenset({
    'sync_cve_now_feed', 'backfill_cve_now_feed', 'sync_distro_fixes', 'sync_bounty_catalogue', 'sync_threat_intel',
    'check_for_updates', 'refresh_sentinel_version', 'feed_sentinels', 'update_nuclei_templates', 'prune_asset_changes', 'report_resources', 'rescore_all_hosts',
    'reconcile_invalid_correlations', 'weekly_maintenance', 'reap_stuck_jobs', 'send_notif',
    'send_task_notif', 'snapshot_daily_stats', 'bootstrap_first_run', 'evaluate_saved_searches',
})


def pause_requested(fail_closed=True):
    """Whether scanning is paused. When the control database cannot be read, a gate that is about to start work treats that as
    paused (``fail_closed``); a watchdog deciding whether to kill work already running passes False, so a database blip never
    kills a healthy scanner."""
    from cveFeed.models import ScanControl

    try:
        return ScanControl.objects.filter(pk=1, paused=True).exists()
    except Exception:
        return fail_closed


def defer_if_paused(task):
    if task.name in PAUSE_EXEMPT_TASKS:
        return
    if pause_requested():
        # Celery retains the original queue and arguments when retrying. In particular,
        # an early-ack worker cannot silently consume a queued scan during a pause.
        raise task.retry(countdown=60, max_retries=None)


class PauseAwareTask(Task):
    def __call__(self, *args, **kwargs):
        defer_if_paused(self)
        return super().__call__(*args, **kwargs)


BEAT_HEARTBEAT_KEY = 'cvengine:beat:heartbeat'
_beat = {'at': 0.0}


def beat_heartbeat():
    """Epoch seconds of beat's last tick, or None when it never wrote one (cannot be told, or Redis is down). Lets a status page tell a
    beat that is not running from a schedule whose last_run_at is merely flushed to the database only every few minutes."""
    try:
        from reNgine import resources
        value = resources.get_store().r.get(BEAT_HEARTBEAT_KEY)
        return float(value) if value else None
    except Exception:  # noqa: BLE001
        return None


class PauseAwareScheduler(DatabaseScheduler):
    def tick(self, *args, **kwargs):
        wait = super().tick(*args, **kwargs)
        now = time.time()
        if now - _beat['at'] >= 15:  # a tick can come every few seconds; the heartbeat needs no more than this
            _beat['at'] = now
            try:
                from reNgine import resources
                resources.get_store().r.set(BEAT_HEARTBEAT_KEY, f'{now:.0f}', ex=3600)
            except Exception:  # noqa: BLE001 - bookkeeping must never stop the scheduler
                pass
        return wait

    def is_due(self, entry):
        if getattr(entry, 'task', '') not in PAUSE_EXEMPT_TASKS and pause_requested():
            return False, 5
        return super().is_due(entry)


@contextmanager
def updater_idle():
    """Serialize a UI resume with both host updater scripts' shared lock."""
    path = os.path.join(settings.RENGINE_HOME, '.update-lock')
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    locked = False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except BlockingIOError as exc:
            raise RuntimeError('An update is running; scanning cannot resume until it finishes') from exc
        yield
    finally:
        if locked:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def request_drain_pause(reason='An update is being applied'):
    """Pause new scan dispatch for an approved update to drain into (cveFeed.updater), without touching work already
    running: unlike the operator "Pause all scanning" action, this never calls abort_running_scans. A no-op, safely
    skipped, if scanning is already paused for any reason (an operator's own pause already stops new dispatch, and
    must never be silently reinterpreted as ours to release later). Serialized against a manual resume via the same
    lock updater_idle uses, so the two can never race each other into an inconsistent state."""
    from django.db import transaction

    from cveFeed.models import ScanControl
    with updater_idle(), transaction.atomic():
        row = ScanControl.objects.select_for_update().get_or_create(pk=1)[0]
        if not row.paused:
            from django.utils import timezone as tz
            row.paused, row.paused_by_update, row.reason, row.actor, row.changed_at, row.last_error = \
                True, True, reason[:200], '', tz.now(), ''
            row.save(update_fields=['paused', 'paused_by_update', 'reason', 'actor', 'changed_at', 'last_error'])


def release_update_pause():
    """Undo request_drain_pause once the update it was waiting for has finished, but only a pause this module set:
    an operator's own pause (paused_by_update False) is never cleared here, exactly like request_drain_pause never
    claims one that already exists."""
    from django.db import transaction

    from cveFeed.models import ScanControl
    with updater_idle(), transaction.atomic():
        row = ScanControl.objects.select_for_update().get_or_create(pk=1)[0]
        if row.paused and row.paused_by_update:
            from django.utils import timezone as tz
            row.paused, row.paused_by_update, row.reason, row.actor, row.changed_at = False, False, '', '', tz.now()
            row.save(update_fields=['paused', 'paused_by_update', 'reason', 'actor', 'changed_at'])


def abort_running_scans(actor):
    """Stop running scan records cooperatively, without revoking a worker process."""
    from django.utils import timezone
    from reNgine import resources
    from startScan.models import ScanHistory, ScanActivity

    now = timezone.now()
    ids = list(ScanHistory._base_manager.filter(scan_status=1).values_list('id', flat=True))
    for scan_id in ids:
        changed = ScanHistory._base_manager.filter(pk=scan_id, scan_status=1).update(
            scan_status=3, stop_scan_date=now, aborted_by=actor, error_message='Stopped by global scanning pause')
        if changed:
            ScanActivity.objects.filter(scan_of_id=scan_id, status__in=(-1, 1)).update(
                status=3, time=now, error_message='Stopped by global scanning pause')
            resources.request_abort(scan_id)
    return len(ids)
