"""The AI activity feed: one place every automated step reports what it is doing.

``log`` records a finished fact; ``step`` records a running step and settles it
as done or failed with its duration. Logging never raises: telemetry must not
break the work it describes.
"""
import contextlib
import logging

from django.utils import timezone

logger = logging.getLogger(__name__)
REPEAT_WINDOW = 600  # seconds: the same line again within this long counts as a repeat of the newest one, not a new entry


def _project_id(project):
    return getattr(project, 'pk', project)


def diagnostic(what, raw, kind=''):
    """A failure line safe to store and show to project members: what failed, the exception type, and a diagnostic id. The raw
    text (an exception message can carry paths, addresses or provider replies) goes to the worker log under that id only."""
    import hashlib
    raw = str(raw or '')
    stamp = hashlib.sha256(f'{what}:{raw}:{timezone.now().isoformat()}'.encode()).hexdigest()[:12]
    logger.warning('%s failed (diagnostic %s): %s', what, stamp, raw[:2000])
    return f'{what} failed{f" ({kind})" if kind else ""}; diagnostic {stamp} is in the worker log'


def discard(entry):
    """Drop an entry that turned out to be nothing worth showing (a "running" line whose step found nothing to report)."""
    if entry is None:
        return
    try:
        entry.delete()
    except Exception:  # noqa: BLE001
        logger.warning('could not discard AI activity', exc_info=True)


def _repeat_of(kind, message, project_id, scan_id, status):
    """The newest entry of this project (and scan) when it says exactly this and is recent enough to be the same line again."""
    from datetime import timedelta
    from cveFeed.models import AgentActivity
    if status == 'running':
        return None  # a running step is settled later by its own row
    newest = AgentActivity.objects.filter(project_id=project_id).order_by('-id').first()
    if newest and newest.kind == kind and newest.message == message and newest.status == status \
            and (newest.detail or {}).get('scan_id') == scan_id \
            and newest.created_at >= timezone.now() - timedelta(seconds=REPEAT_WINDOW):
        return newest
    return None


def log(kind, message, project=None, cve_id='', status='done', **detail):
    """Record one activity entry and return it (None if it could not be written). The same line again, right after itself and
    within ten minutes, does not add a row: the newest one gets a fresh timestamp and its ``repeat`` count goes up."""
    try:
        from django.db.models import F
        from cveFeed.models import AgentActivity
        message = message[:500]
        same = _repeat_of(kind, message, _project_id(project), detail.get('scan_id'), status)
        if same is not None:
            AgentActivity.objects.filter(pk=same.pk).update(repeat=F('repeat') + 1, created_at=timezone.now(), finished_at=timezone.now())
            same.refresh_from_db()
            return same
        entry = AgentActivity.objects.create(
            kind=kind, message=message, status=status, project_id=_project_id(project),
            cve_id=cve_id or '', detail=detail,
            finished_at=None if status == 'running' else timezone.now())
        return entry
    except Exception:  # noqa: BLE001
        logger.warning('could not record AI activity %r', message, exc_info=True)
        return None


def settle(entry, status='done', message=None, **detail):
    if entry is None:
        return
    try:
        if message:
            entry.message = message[:500]
        entry.status = status
        entry.detail = {**(entry.detail or {}), **detail}
        entry.finished_at = timezone.now()
        entry.save(update_fields=['message', 'status', 'detail', 'finished_at'])
    except Exception:  # noqa: BLE001
        logger.warning('could not settle AI activity', exc_info=True)


@contextlib.contextmanager
def step(kind, message, project=None, cve_id='', **detail):
    """Show ``message`` as running, then done (or failed if the block raises). Yields a handle whose
    ``.done_message`` / ``.detail`` the block may set to describe the outcome."""
    class Handle:
        done_message = None
        extra = {}
    handle = Handle()
    handle.extra = {}
    entry = log(kind, message, project=project, cve_id=cve_id, status='running', **detail)
    try:
        yield handle
    except Exception as exc:
        settle(entry, 'failed', message=f'{message}: {exc}'[:500])
        raise
    settle(entry, 'done', message=handle.done_message, **handle.extra)
