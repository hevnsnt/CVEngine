"""Weekly log maintenance: archive the old rows of the log tables to a tar.gz, then delete them, and drop finished agent tasks and
expired PDF reports.

The AI activity feed (AgentActivity), the AI call leases (TriageCall) and the AI usage ledger (AIUsage) grow with every scan and
every model call, and nothing else removes them. Once a week the rows older than each table's retention are written, one JSON
object per line, into ``cvengine-logs-<time>.tar.gz`` under the archive directory, and are deleted only after that file is
complete on disk. Archives older than CVENGINE_LOG_ARCHIVE_DAYS are removed. The default directory is on the scan-results
volume, in a dot-folder no project media path can name, so only a superuser can download it through the media view.

The same run prunes operational tables that had no other delete path (``prune_operational``): ended StageRuns, old input guard strikes and
bans that are over, expired login sessions and old finished host assessments, in bounded id batches and without an archive.
"""
import datetime
import json
import logging
import os
import tarfile
import tempfile

from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

# table: (retention setting, default days, the timestamp a row ages by)
RETENTION = {
    'AgentActivity': ('CVENGINE_ACTIVITY_RETENTION_DAYS', 30, 'created_at'),
    'TriageCall': ('CVENGINE_TRIAGE_CALL_RETENTION_DAYS', 90, 'started_at'),
    'AIUsage': ('CVENGINE_AI_USAGE_RETENTION_DAYS', 400, 'started_at'),  # a year of cost history for the AI usage page
    'McpCall': ('CVENGINE_MCP_LOG_RETENTION_DAYS', 90, 'at'),  # the MCP page's History of tool calls
}
# The routine audit rows of the Sentinel queue: one claim, accept and completion per task, and one expiry per task that ended on its own, nearly all of
# the audit log on an instance with Sentinels (about 10,000 rows a day, a million rows in a few weeks at 3000 targets). They are archived and deleted
# with the log tables once older than this. This is an allow-list: only these actions are ever deleted, and every other audit action (logins, who
# changed what, role and token changes, agent suspends and deletes, expiry sweeps, cancels, late and adopted results, secret reads) is kept. A
# person's decision that expires tasks (suspending, deleting or unregistering an agent) has its own row (agent.status, agent.delete, agent.unregister).
ROUTINE_AUDIT_ACTIONS = ('sentinel.task.claim', 'sentinel.task.accept', 'sentinel.task.complete', 'sentinel.task.expire')
ROUTINE_AUDIT_RETENTION = ('CVENGINE_SENTINEL_AUDIT_RETENTION_DAYS', 14)
ARCHIVE_PREFIX = 'cvengine-logs-'
DELETE_CHUNK = 5000


def _days(name, default):
    try:
        return max(1, int(os.environ.get(name, '')))
    except ValueError:
        return default


def archive_dir():
    return os.environ.get('CVENGINE_LOG_ARCHIVE_DIR') or os.path.join(settings.MEDIA_ROOT, '.log-archives')


def _export(tar, name, rows):
    """Write ``rows`` (dicts) as ``<name>.jsonl`` into ``tar``; returns how many."""
    count = 0
    with tempfile.NamedTemporaryFile('w', suffix='.jsonl', encoding='utf-8', delete=False) as out:
        try:
            for row in rows:
                out.write(json.dumps(row, default=str, sort_keys=True) + '\n')
                count += 1
            out.flush()
            out.close()
            if count:
                tar.add(out.name, arcname=f'{name}.jsonl')
        finally:
            os.unlink(out.name)
    return count


def _delete(qs):
    deleted = 0
    while True:
        ids = list(qs.values_list('id', flat=True)[:DELETE_CHUNK])
        if not ids:
            return deleted
        deleted += qs.model.objects.filter(id__in=ids).delete()[0]


def _routine_audit(now):
    """The routine Sentinel task audit rows older than ``CVENGINE_SENTINEL_AUDIT_RETENTION_DAYS`` (``ROUTINE_AUDIT_ACTIONS``), in id order, or None
    when there are none. Bounded by the newest routine id older than the cutoff, so rows written while this runs wait for next week. Every read is a
    range of ``auditlog_action_id_idx`` (action, id), one action at a time."""
    from django.db.models import Max

    from dashboard.models import AuditLog
    setting, default = ROUTINE_AUDIT_RETENTION
    cutoff = now - datetime.timedelta(days=_days(setting, default))
    tops = [AuditLog.objects.filter(action=action, created_at__lt=cutoff).order_by().aggregate(top=Max('id'))['top'] for action in ROUTINE_AUDIT_ACTIONS]
    tops = [top for top in tops if top is not None]
    if not tops:
        return None
    return AuditLog.objects.filter(id__lte=max(tops), created_at__lt=cutoff, action__in=ROUTINE_AUDIT_ACTIONS).order_by('id')


def _delete_routine_audit(qs):
    """Delete ``qs`` (``_routine_audit``) in batches of ``DELETE_CHUNK``, one action at a time, keyset on id: each batch reads the next ids of
    one action after the last batch, so no batch scans the rows an earlier batch kept or deleted, and no statement deletes more than a batch."""
    deleted = 0
    for action in ROUTINE_AUDIT_ACTIONS:
        last = 0
        while True:
            ids = list(qs.filter(action=action, id__gt=last).order_by('id').values_list('id', flat=True)[:DELETE_CHUNK])
            if not ids:
                break
            deleted += qs.model.objects.filter(id__in=ids).delete()[0]
            last = ids[-1]
    return deleted


def keyset_delete(qs, chunk=None, keep=frozenset()):
    """Delete the rows of ``qs`` in primary key order, at most ``chunk`` (default DELETE_CHUNK) ids per statement, each page read after the
    last id seen, so a long backlog is never scanned again from the start. Ids in ``keep`` are skipped. Returns how many rows of ``qs.model``
    were deleted."""
    chunk = chunk or DELETE_CHUNK
    model = qs.model
    deleted, last = 0, None
    while True:
        page = qs if last is None else qs.filter(pk__gt=last)
        ids = list(page.order_by('pk').values_list('pk', flat=True)[:chunk])
        if not ids:
            return deleted
        doomed = [pk for pk in ids if pk not in keep]
        if doomed:
            deleted += model._base_manager.filter(pk__in=doomed).delete()[1].get(model._meta.label, 0)
        last = ids[-1]


# Operational tables that had no delete path: (retention setting, default days). Nothing is archived for them: they are engine bookkeeping, and
# the audit log keeps what a person did (bans, disabled accounts).
OPERATIONAL_RETENTION = {
    'StageRun': ('CVENGINE_STAGE_RUN_RETENTION_DAYS', 30),
    'AbuseStrike': ('CVENGINE_ABUSE_RETENTION_DAYS', 90),
    'HostAssessment': ('CVENGINE_HOST_ASSESSMENT_RETENTION_DAYS', 90),
}


def _cutoff(name, now):
    setting, default = OPERATIONAL_RETENTION[name]
    return now - datetime.timedelta(days=_days(setting, default))


def prune_stage_runs(now):
    """Ended StageRuns past the retention. A run tied to a scan also goes with the scan; a sweep's run (no scan) had no other way out."""
    from agentapi import stage_runs
    setting, default = OPERATIONAL_RETENTION['StageRun']
    return stage_runs.prune(now, days=_days(setting, default))


def prune_abuse(now):
    """Input guard strikes and bans that can no longer do anything. A strike counts only inside ``input_guard.WINDOW`` (15 minutes), so one older
    than the retention is history only. A ban goes when it is over: an address ban whose ``expires_at`` passed more than the retention ago, or a
    ban an admin lifted that was made more than the retention ago. A ban with no expiry that is not lifted (a disabled account, a manual block)
    is kept for as long as it is in force."""
    from django.db.models import Q

    from dashboard.models import AbuseBan, AbuseStrike
    cutoff = _cutoff('AbuseStrike', now)
    return (keyset_delete(AbuseStrike.objects.filter(created_at__lt=cutoff)),
            keyset_delete(AbuseBan.objects.filter(Q(expires_at__lt=cutoff) | Q(lifted=True, created_at__lt=cutoff))))


def prune_sessions(now):
    """Expired login sessions (what ``manage.py clearsessions`` does, in bounded batches). The session store never reads a row past its
    ``expire_date`` (``reNgine.hashed_sessions``), so it is dead weight."""
    from django.contrib.sessions.models import Session
    return keyset_delete(Session.objects.filter(expire_date__lt=now))


def prune_host_assessments(now):
    """Finished host assessments past the retention, except the ones something still reads: the newest of each host in its project (the top-up
    orders hosts by their latest assessment, ``coverage_topup.stalest_hosts``, and ``latest_host_assessment`` shows it) and the ones a HostState
    names as the check behind its archive decision (``archive_assessment``). A queued or running one is never touched."""
    from django.db.models import Max, Q

    from cveFeed.host_assessment import ACTIVE
    from cveFeed.models import HostAssessment, HostState
    cutoff = _cutoff('HostAssessment', now)
    rows = HostAssessment._base_manager
    old = (rows.exclude(status__in=ACTIVE)
           .filter(Q(finished_at__lt=cutoff) | Q(finished_at__isnull=True, created_at__lt=cutoff)))
    if not old.exists():
        return 0
    # read once, as two grouped scans, rather than a correlated subquery per row (no index leads on the host)
    keep = set(rows.order_by().values('project_id', 'host').annotate(top=Max('id')).values_list('top', flat=True))
    keep.update(HostState._base_manager.filter(archive_assessment__isnull=False).values_list('archive_assessment_id', flat=True))
    return keyset_delete(old, keep=keep)


def prune_operational(now):
    """Prune the operational tables (``OPERATIONAL_RETENTION`` and expired sessions). One table failing is logged and does not stop the others
    or the rest of the maintenance; it is tried again next week. Returns {table: rows deleted} for the tables that ran."""
    out = {}
    steps = (('StageRun', prune_stage_runs), ('Abuse', prune_abuse), ('Session', prune_sessions), ('HostAssessment', prune_host_assessments))
    for name, step in steps:
        try:
            result = step(now)
        except Exception:  # noqa: BLE001 - housekeeping only
            logger.exception('pruning %s failed', name)
            continue
        if name == 'Abuse':
            out['AbuseStrike'], out['AbuseBan'] = result
        else:
            out[name] = result
    return out


def prune_archives(directory, now):
    keep = datetime.timedelta(days=_days('CVENGINE_LOG_ARCHIVE_DAYS', 365))
    removed = 0
    for name in os.listdir(directory):
        path = os.path.join(directory, name)
        if name.startswith(ARCHIVE_PREFIX) and name.endswith('.tar.gz') and os.path.isfile(path) \
                and now - datetime.datetime.fromtimestamp(os.path.getmtime(path), tz=datetime.timezone.utc) > keep:
            os.unlink(path)
            removed += 1
    return removed


def run(now=None):
    """Archive and delete the expired log rows. Returns {'archive': path or '', 'archived': {table: n}, 'deleted': {table: n},
    'archives_removed': n}. Nothing is deleted unless its archive was written completely."""
    from django.apps import apps
    from django.db.models import Max
    now = now or timezone.now()
    directory = archive_dir()
    os.makedirs(directory, mode=0o700, exist_ok=True)
    path = os.path.join(directory, f'{ARCHIVE_PREFIX}{now:%Y%m%dT%H%M%SZ}.tar.gz')
    partial = path + '.partial'
    plan, archived = {}, {}
    try:
        with tarfile.open(partial, 'w:gz') as tar:
            for name, (setting, default, field) in RETENTION.items():
                model = apps.get_model('cveFeed', name)
                qs = model.objects.filter(**{f'{field}__lt': now - datetime.timedelta(days=_days(setting, default))})
                top = qs.aggregate(top=Max('id'))['top']
                if top is None:
                    continue
                qs = qs.filter(id__lte=top)  # rows that age past the cutoff while this runs wait for next week, unarchived and kept
                plan[name] = qs
                archived[name] = _export(tar, name, qs.order_by('id').values().iterator(chunk_size=2000))
            routine = _routine_audit(now)
            if routine is not None:
                plan['AuditLog'] = routine
                archived['AuditLog'] = _export(tar, 'AuditLog', routine.values().iterator(chunk_size=2000))
    except BaseException:
        if os.path.exists(partial):
            os.unlink(partial)
        raise
    if any(archived.values()):
        os.replace(partial, path)
        os.chmod(path, 0o600)
    else:
        os.unlink(partial)
        path = ''
    deleted = {name: (_delete_routine_audit if name == 'AuditLog' else _delete)(qs) for name, qs in plan.items()}
    from agentapi import agent_broker
    from agentapi import sentinel_broker
    from cveFeed import report_export
    return {'archive': path, 'archived': archived, 'deleted': deleted, 'archives_removed': prune_archives(directory, now),
            'agent_tasks_deleted': agent_broker.prune_tasks(now), 'sentinel_tasks_deleted': sentinel_broker.prune_tasks(now),
            'sentinel_enrollments_deleted': sentinel_broker.prune_enrollments(now),
            'reports_removed': report_export.prune_expired(now), 'pruned': prune_operational(now)}
