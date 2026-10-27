"""Weekly log maintenance: archive the old rows of the log tables to a tar.gz, then delete them, and drop finished agent tasks.

The AI activity feed (AgentActivity), the AI call leases (TriageCall) and the AI usage ledger (AIUsage) grow with every scan and
every model call, and nothing else removes them. Once a week the rows older than each table's retention are written, one JSON
object per line, into ``cvengine-logs-<time>.tar.gz`` under the archive directory, and are deleted only after that file is
complete on disk. Archives older than CVENGINE_LOG_ARCHIVE_DAYS are removed. The default directory is on the scan-results
volume, in a dot-folder no project media path can name, so only a superuser can download it through the media view.
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
}
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
    deleted = {name: _delete(qs) for name, qs in plan.items()}
    from agentapi import agent_broker
    return {'archive': path, 'archived': archived, 'deleted': deleted, 'archives_removed': prune_archives(directory, now),
            'agent_tasks_deleted': agent_broker.prune_tasks(now)}
