"""Expire host-assessment, validation and activity-feed jobs that will never finish.

A worker killed mid-task (restart, out-of-memory, a lost broker message) leaves its job "queued" or "running" for good: it holds the
host's or finding's only active slot and counts toward the per-project and global caps, so one bad restart can stop a project's
assessments or automatic validation, or leave an AI activity row showing "running" in the feed forever even though the scan or
check it described has long since finished. Every 15 minutes (tasks.reap_stuck_jobs) a job past its age limit is marked failed
with the reason. A finishing worker only ever updates a row still "running", so a late result is dropped, never mixed in. A
failed validation job is due again at once (next_attempt_at) while it has attempts left, so the sweep can queue it afresh. While
scanning is paused, queued jobs are waiting on purpose and are left alone; only running ones are expired.
"""
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
