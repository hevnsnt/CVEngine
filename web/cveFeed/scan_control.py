"""Durable operator pause for scanner dispatch and active scanner processes."""
import fcntl
import os
from contextlib import contextmanager

from celery import Task
from django.conf import settings
from django_celery_beat.schedulers import DatabaseScheduler


def pause_requested():
    """Fail closed when the control database is unavailable to a scanner."""
    from cveFeed.models import ScanControl

    try:
        return ScanControl.objects.filter(pk=1, paused=True).exists()
    except Exception:
        return True


def defer_if_paused(task):
    if pause_requested():
        # Celery retains the original queue and arguments when retrying. In particular,
        # an early-ack worker cannot silently consume a queued scan during a pause.
        raise task.retry(countdown=60, max_retries=None)


class PauseAwareTask(Task):
    def __call__(self, *args, **kwargs):
        defer_if_paused(self)
        return super().__call__(*args, **kwargs)


class PauseAwareScheduler(DatabaseScheduler):
    def is_due(self, entry):
        if pause_requested():
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
