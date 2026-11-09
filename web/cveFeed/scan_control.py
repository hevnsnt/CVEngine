"""Durable operator pause for scanner dispatch and active scanner processes."""
import fcntl
import os
import time
from contextlib import contextmanager
from datetime import timedelta

from celery import Task
from django.conf import settings
from django_celery_beat.schedulers import DatabaseScheduler


# Work that never touches a customer target and costs no AI budget keeps running during a pause: the CVE feed, distribution
# fixes, bug bounty catalogue and threat intelligence, the update check and template download, notifications, pruning and
# other bookkeeping. Everything else (discovery, scanners, validation, AI triage and reviews, certificate watching) waits.
PAUSE_EXEMPT_TASKS = frozenset({
    'sync_cve_now_feed', 'backfill_cve_now_feed', 'sync_distro_fixes', 'sync_bounty_catalogue', 'sync_threat_intel',
    'check_for_updates', 'refresh_sentinel_version', 'feed_sentinels', 'ensure_builtin_scanner', 'ensure_reviewer_token', 'reviewer_ops_checks', 'update_nuclei_templates', 'prune_asset_changes', 'prune_scan_history', 'report_resources', 'apply_scan_concurrency', 'autotune', 'rescore_all_hosts',
    'reconcile_invalid_correlations', 'weekly_maintenance', 'reap_stuck_jobs', 'send_notif',
    'send_task_notif', 'snapshot_daily_stats', 'bootstrap_first_run', 'evaluate_saved_searches',
    'refresh_live_snapshots',  # the Live screen's cache keeps answering while scanning is paused: people watch a pause too
    # The OpenVAS step is exempt so that a pause can reach a GVM task that is already running: while scanning is paused it only stops
    # that task (``openvas_scan.tick``), and never starts or dispatches one.
    'openvas_sweep',
    # A stage that waits on Sentinels without its worker (agentapi.stage_runs) is work already in flight, as a stage blocked in its worker was: its
    # callback finishes it during a pause (an update's drain waits for it), and its drive and tick are what let a pause reach its fanned-out tasks.
    'stage_run_resume', 'stage_run_drive', 'stage_runs_tick',
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


def operator_pause_requested():
    """Whether an App Admin pressed Pause all scanning: a watchdog that stops work already running asks this, so an update's drain pause
    (which lets running work finish) never stops it, and an unreadable control database never kills a healthy scanner."""
    from cveFeed.models import ScanControl

    try:
        return ScanControl.objects.filter(pk=1, paused=True, paused_by_update=False).exists()
    except Exception:
        return False


def defer_if_paused(task):
    if task.name in PAUSE_EXEMPT_TASKS:
        return
    if pause_requested():
        # Celery retains the original queue and arguments when retrying. In particular,
        # an early-ack worker cannot silently consume a queued scan during a pause.
        raise task.retry(countdown=60, max_retries=None)


class PauseAwareTask(Task):
    def __call__(self, *args, **kwargs):
        # Only a task a worker is running can be retried later. A plain function call (a scan stage, a management command, an API
        # view) has no queued message to defer: ``retry`` would raise ``celery.exceptions.Retry`` into the caller, so it runs in-line.
        # Whatever started it was already held by the pause (a scan is aborted, the beat entry is not due).
        if not getattr(self.request, 'called_directly', True):
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


GRACE_ENV = 'CVENGINE_UPDATE_GRACE_SECONDS'
DEFAULT_GRACE_SECONDS = 600  # how long after an update the broker keeps what the outage left open: Sentinels reconnect within a minute, the rest is margin
OPEN_WINDOW_MAX = timedelta(hours=6)  # a window nobody closed (an update that failed and was never resumed) stops holding leases after this: never for ever
UPDATE_LEASE = timedelta(minutes=30)  # the lease a held task is given when an update starts, so a Sentinel's task is not judged lost minutes into the outage


def grace_seconds():
    try:
        return max(0, min(86400, int(os.environ.get(GRACE_ENV, DEFAULT_GRACE_SECONDS))))
    except ValueError:
        return DEFAULT_GRACE_SECONDS


def update_window():
    """``(started, ended, grace_until)`` of the last update (``ScanControl``), each a datetime or None; all None when it cannot be read or no
    update ran. A caller that only wants to know whether leases are to be kept asks ``in_update_grace``."""
    from cveFeed.models import ScanControl

    try:
        row = ScanControl.objects.filter(pk=1).values_list('update_started_at', 'update_ended_at', 'update_grace_until').first()
    except Exception:  # noqa: BLE001 - a control row that cannot be read never judges a lease
        return None, None, None
    return row or (None, None, None)


def in_update_grace(now=None):
    """Whether the broker is to keep Sentinel leases and tasks alive because an update is running (its window is open and not older than
    ``OPEN_WINDOW_MAX``), or ended less than ``grace_seconds`` ago. While true nothing is expired for a missing heartbeat or an unlisted task:
    the Sentinels were talking to a server that was down, not gone."""
    from django.utils import timezone as tz
    now = now or tz.now()
    started, ended, grace = update_window()
    if started is None:
        return False
    if ended is None or ended < started:
        return now - started < OPEN_WINDOW_MAX
    return grace is not None and now < grace


def update_hold():
    """Whether an update's drain pause is on right now: nothing new is handed to a Sentinel, no stage starts (the rest of the queue waits)."""
    from cveFeed.models import ScanControl

    try:
        return ScanControl.objects.filter(pk=1, paused=True, paused_by_update=True).exists()
    except Exception:  # noqa: BLE001
        return False


def outage_overlap(since, now=None):
    """Seconds of the last update's window (started to ended, or to now while it is open) that fall between ``since`` (epoch seconds) and now:
    what a budget counted in wall-clock time must not charge to a Sentinel's task, since nothing could be heard then."""
    from django.utils import timezone as tz
    now = now or tz.now()
    started, ended, _grace = update_window()
    if started is None or since is None:
        return 0.0
    end = ended if ended is not None and ended >= started else min(now, started + OPEN_WINDOW_MAX)
    low = max(started.timestamp(), float(since))
    high = min(end.timestamp(), now.timestamp())
    return max(0.0, high - low)


def request_drain_pause(reason='An update is being applied'):
    """Pause new scan dispatch for an approved update (cveFeed.updater), without touching work already running: unlike the operator "Pause all
    scanning" action, this never calls abort_running_scans. An update does not wait for scans that run on Sentinels: it opens the update window
    (``update_started_at``: until it ends the broker keeps every Sentinel lease, ``in_update_grace``) and gives the tasks the Sentinels hold a
    longer lease, so what they finish during the outage is still theirs to report when the server is back. A no-op, safely skipped, for the pause
    itself if scanning is already paused for any reason (an operator's own pause already stops new dispatch, and must never be silently
    reinterpreted as ours to release later). Serialized against a manual resume via the same lock updater_idle uses, so the two can never race each
    other into an inconsistent state."""
    from django.db import transaction
    from django.utils import timezone as tz

    from cveFeed.models import ScanControl
    with updater_idle(), transaction.atomic():
        row = ScanControl.objects.select_for_update().get_or_create(pk=1)[0]
        now = tz.now()
        fields = []
        if row.update_started_at is None or row.update_ended_at is not None or now - row.update_started_at >= OPEN_WINDOW_MAX:  # the host asks again at every poll: one window
            row.update_started_at, row.update_ended_at, row.update_grace_until = now, None, None
            fields = ['update_started_at', 'update_ended_at', 'update_grace_until']
        if not row.paused:
            row.paused, row.paused_by_update, row.reason, row.actor, row.changed_at, row.last_error = \
                True, True, reason[:200], '', now, ''
            fields += ['paused', 'paused_by_update', 'reason', 'actor', 'changed_at', 'last_error']
        row.save(update_fields=fields)
    hold_sentinel_leases()


def hold_sentinel_leases(now=None):
    """Give every Sentinel task that is claimed or running a lease of ``UPDATE_LEASE`` from now (never a shorter one than it has)."""
    from django.utils import timezone as tz
    try:
        from agentapi.models import SentinelTask
        now = now or tz.now()
        return SentinelTask._base_manager.filter(status__in=('claimed', 'running'), lease_expires_at__lt=now + UPDATE_LEASE).update(
            lease_expires_at=now + UPDATE_LEASE)
    except Exception:  # noqa: BLE001 - the window is what holds the leases; this is a margin
        return 0


def close_update_window(row, now):
    """End the update window on ``row`` (a locked ScanControl): the grace after it starts now. Returns the fields to save (none when no window is open)."""
    if row.update_started_at is not None and row.update_ended_at is None:
        row.update_ended_at, row.update_grace_until = now, now + timedelta(seconds=grace_seconds())
        return ['update_ended_at', 'update_grace_until']
    return []


def release_update_pause():
    """Undo request_drain_pause once the update it was waiting for has finished, but only a pause this module set:
    an operator's own pause (paused_by_update False) is never cleared here, exactly like request_drain_pause never
    claims one that already exists. Closes the update window and starts the grace after it."""
    from django.db import transaction
    from django.utils import timezone as tz

    from cveFeed.models import ScanControl
    with updater_idle(), transaction.atomic():
        row = ScanControl.objects.select_for_update().get_or_create(pk=1)[0]
        now = tz.now()
        fields = close_update_window(row, now)
        if row.paused and row.paused_by_update:
            row.paused, row.paused_by_update, row.reason, row.actor, row.changed_at = False, False, '', '', now
            fields += ['paused', 'paused_by_update', 'reason', 'actor', 'changed_at']
        if fields:
            row.save(update_fields=fields)


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
