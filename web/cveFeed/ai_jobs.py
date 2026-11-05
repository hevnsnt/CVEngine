"""The pipeline's model calls, made by the AI reviewer container (docs/AI-REVIEWER.md): the server makes none itself.

A stage that needs a model's answer (triage, ...) queues an ``AIJob`` instead of calling a provider, and carries on. The container takes
jobs over ``/api/v1/reviewer/jobs/next`` (``next_jobs``), calls the model and posts the answer to ``/api/v1/reviewer/jobs/<id>/result``
(``submit``). A Celery task then continues the stage where it left off (``apply``): the answer is checked with the stage's own validator
and applied exactly as the stage applied it when it called the model itself, or the stage's one retry is queued, or the failure is handled
as a provider error was. The budgets, caps and ceilings stay with each stage: a stage reserves its budget when it queues a job, and a
stage may refuse to hand a job out on a day whose budget is spent (``admit``). A finished job keeps its counts only: its question and its
answer are dropped.

What a job carries (``packet``) is the stage's fixed system prompt and its parts in order: text cvENGINE wrote itself, and data that came
from a scanned host, a scanner or a feed, which the container puts between nonce markers (its ``guard.fence``). Every string is masked for
secrets before it is stored (``cveFeed.secret_redaction``), as every prompt was before 1.4, and so is the answer, unless the stage needs it
literal (a scanner template it drafted).

With no AI provider configured the stages do not queue anything (they behave as they always did without AI). With a provider but no
reviewer to serve the queue (``CVENGINE_REVIEWER=0``, the container down, scanning paused) jobs wait, and ``waiting`` says so for the UI.
A job never answered within ``TTL`` expires and its stage is told, so the work is asked again by the stage's own sweep.
"""
import hashlib
import json
import logging
import re
import secrets
from datetime import timedelta
from importlib import import_module

from django.db import IntegrityError, transaction
from django.utils import timezone

logger = logging.getLogger(__name__)

LEASE_MIN = 900                  # seconds a container holds a job at least
LEASE_MAX = 3 * 3600
MAX_LEASES = 3                   # a job handed out this often without an answer has failed (a container that dies on it)
TTL = timedelta(days=7)          # a job not answered in this long expires; its stage asks again
KEEP = timedelta(days=30)        # finished jobs are kept this long, for the counts
APPLY_GRACE = timedelta(minutes=2)
APPLY_STUCK = timedelta(minutes=30)
REPLY_MAX = 200_000              # characters of one answer
IMAGE_MAX = 6_000_000            # base64 characters of the one image a job may carry (the RDP reading)
PACKET_MAX = 1_000_000           # bytes of a job's packet without its image
BATCH_BYTES = 6_000_000          # bytes of jobs handed out in one answer
BATCH_MAX = 20
WINDOW = 200                     # queued jobs looked at per hand-out (some may wait for tomorrow's budget)
WAITING_AFTER = timedelta(minutes=15)  # a queued job older than this means the queue is not being served
MEDIA_TYPES = ('image/png', 'image/jpeg', 'image/webp', 'image/gif')
MODEL_NAME = re.compile(r'^[A-Za-z0-9._:/@+\-]{0,200}$')
# What a failure may be called: the categories of the container's request layer (cvengine_reviewer.llm), which are the server's own from
# before 1.4, and two of the queue's.
CATEGORIES = frozenset(('provider_error', 'provider_auth', 'provider_rate_limit', 'provider_http', 'provider_connect_timeout',
                        'provider_timeout', 'provider_network', 'provider_json', 'provider_shape', 'output_truncated', 'empty_response',
                        'unsupported', 'unexpected_error', 'malformed_job', 'lease_expired'))

# kind -> the module that continues it. Each defines ``job_answer(job, text)`` (returns None, or a ``Retry``) and ``job_failure(job,
# category, detail)``; optionally ``job_admit(job)`` (False keeps it queued, 'drop' expires it) and ``job_expired(job)``.
HANDLERS = {
    'triage': 'cveFeed.triage',
    'local_checks': 'cveFeed.triage',
}


class Retry:
    """What ``job_answer`` returns to ask once more: a new stage name and parts (the original question and why the answer was refused)."""

    def __init__(self, stage, parts):
        self.stage, self.parts = stage, parts


class JobError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def text(value):
    """A part cvENGINE wrote itself."""
    return {'text': str(value)}


def fence(label, data):
    """A part that came from a scanned host, a scanner or a feed: fenced by the container."""
    return {'fence': re.sub(r'[^A-Z_]', '', str(label).upper())[:30] or 'DATA', 'data': data}


def _handler(kind):
    return import_module(HANDLERS[kind])


# ------------------------------------------------------------------------------------------------------------------------- state

def provider_row():
    """The configured AI provider, or None when AI is off or its settings cannot make a request (no key where one is needed, no server
    address for a self-hosted one): the stages then behave as they always did without AI."""
    from dashboard.models import AIProviderSettings
    from reNgine.ai_profiles import PROFILES
    row = AIProviderSettings.objects.filter(enabled=True).first()
    profile = PROFILES.get(getattr(row, 'provider', None))
    if row is None or profile is None:
        return None
    if profile.needs_key and not (row.api_key or '').strip():
        return None
    url = (row.base_url or '').strip()
    if (profile.needs_url and not url) or (url and not re.match(r'^https?://', url, re.I)):
        return None
    return row


def ai_on():
    return provider_row() is not None


def serving(row=None):
    """``(True, '')`` when the reviewer container may take jobs now, else ``(False, why)``."""
    from cveFeed import reviewer
    row = row if row is not None else provider_row()
    if not reviewer.env_enabled():
        return False, 'the AI reviewer container is turned off (CVENGINE_REVIEWER=0)'
    if row is None:
        return False, 'no AI provider is configured'
    if reviewer.paused():
        return False, 'scanning is paused'
    return True, ''


def runtime_block(row):
    """The operator's request settings as one request needs them, every layer resolved here (the Settings page, then the CVENGINE_AI_*
    variables of this server's .env, then nothing: the container falls back to the provider's own default)."""
    from reNgine.ai_profiles import AIRuntime
    from reNgine.ai_providers import _layered, reasoning_level, structured_mode
    runtime = AIRuntime.from_row(row)
    out = {name: _layered(name, runtime)[0] for name in ('request_timeout', 'connect_timeout', 'max_tokens', 'context_tokens')}
    out.update(structured_mode=structured_mode(runtime), reasoning=reasoning_level(runtime), keep_alive=runtime.keep_alive or '')
    return out


def provider_block(row):
    """The job block of the reviewer's configuration: the provider, its address and key, the model chosen (empty: the container picks the
    provider's default as the server used to), and the request settings."""
    from reNgine.ai_providers import reachable_url
    return {'provider': row.provider, 'base_url': reachable_url(row.base_url) if row.base_url else '', 'api_key': row.api_key or '',
            'model': row.model or '', 'runtime': runtime_block(row)}


def lease_seconds(row=None):
    row = row if row is not None else provider_row()
    timeout = (runtime_block(row)['request_timeout'] if row is not None else None) or 300
    return max(LEASE_MIN, min(LEASE_MAX, 3 * int(timeout) + 120))


# ----------------------------------------------------------------------------------------------------------------------- queueing

def _redact(value, depth=0):
    from cveFeed.secret_redaction import redact_text
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict) and depth < 12:
        return {k: _redact(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)) and depth < 12:
        return [_redact(v, depth + 1) for v in value]
    return value


def _clean_parts(parts):
    out = []
    for part in parts:
        if 'fence' in part:
            out.append({'fence': part['fence'], 'data': _redact(json.loads(json.dumps(part.get('data'), default=str)))})
        else:
            out.append({'text': _redact(str(part.get('text') or ''))})
    if not out or len(out) > 20:
        raise ValueError('a job has from 1 to 20 parts')
    return out


def enqueue(kind, stage, *, system, parts, schema=None, options=None, image=None, context=None, project=None, dedupe='', priority=5):
    """Queue one model call. Returns the job, or the open job already queued for the same ``(kind, dedupe)``."""
    from cveFeed.models import AIJob
    if kind not in HANDLERS:
        raise ValueError(f'unknown AI job kind {kind!r}')
    packet = {'system': str(system), 'parts': _clean_parts(parts), 'schema': schema, 'options': dict(options or {})}
    if len(json.dumps(packet, default=str)) > PACKET_MAX:
        raise ValueError('the job is too large')
    if image is not None:
        if image.get('media_type') not in MEDIA_TYPES or not isinstance(image.get('data'), str) or not 0 < len(image['data']) <= IMAGE_MAX:
            raise ValueError('the image is not one a job may carry')
        packet['image'] = {'media_type': image['media_type'], 'data': image['data']}
    project_id = getattr(project, 'pk', project)
    try:
        with transaction.atomic():
            return AIJob.objects.create(kind=kind, stage=str(stage)[:40], project_id=project_id, dedupe=str(dedupe)[:80], priority=priority,
                                        packet=packet, context=json.loads(json.dumps(context or {}, default=str)))
    except IntegrityError:
        found = AIJob.objects.filter(kind=kind, dedupe=str(dedupe)[:80], status__in=AIJob.OPEN).first()
        if found is None:
            raise
        return found


def _for_container(job):
    out = {'id': job.pk, 'kind': job.kind, 'stage': job.stage, 'attempt': job.attempt, 'lease': job.lease,
           'system': job.packet.get('system') or '', 'parts': job.packet.get('parts') or [], 'schema': job.packet.get('schema'),
           'options': job.packet.get('options') or {}}
    if job.packet.get('image'):
        out['image'] = job.packet['image']
    return out


def _admit(job):
    hook = getattr(_handler(job.kind), 'job_admit', None)
    if hook is None:
        return True
    try:
        answer = hook(job)
    except Exception:  # noqa: BLE001 - a stage that cannot decide keeps its job queued
        logger.exception('AI job %s: the admission check failed', job.pk)
        return False
    return 'drop' if answer == 'drop' else bool(answer)


def _expire(job, now, category='expired'):
    from cveFeed.models import AIJob
    if not AIJob.objects.filter(pk=job.pk, status='queued').update(status='expired', finished_at=now, error_category=category):
        return False
    hook = getattr(_handler(job.kind), 'job_expired', None)
    if hook is not None:
        try:
            hook(job)
        except Exception:  # noqa: BLE001
            logger.exception('AI job %s: its stage could not be told it expired', job.pk)
    return True


def next_jobs(limit=8, now=None):
    """Up to ``limit`` jobs for the container, each leased to it for a while with a fresh lease token, oldest of the most urgent first.
    Nothing while the queue may not be served (``serving``)."""
    from cveFeed.models import AIJob
    row = provider_row()
    if not serving(row)[0]:
        return []
    now = now or timezone.now()
    release_expired(now)
    limit = max(1, min(int(limit or 1), BATCH_MAX))
    seconds = lease_seconds(row)
    out, size = [], 0
    with transaction.atomic():
        for job in AIJob.objects.select_for_update(skip_locked=True).filter(status='queued').order_by('priority', 'created_at', 'id')[:WINDOW]:
            if len(out) >= limit or size > BATCH_BYTES:
                break
            admitted = _admit(job) if job.attempt == 1 else True
            if admitted == 'drop':
                _expire(job, now, 'dropped')
                continue
            if not admitted:
                continue
            job.status, job.lease, job.lease_until, job.leases = 'leased', secrets.token_hex(12), now + timedelta(seconds=seconds), job.leases + 1
            job.save(update_fields=['status', 'lease', 'lease_until', 'leases', 'updated_at'])
            packet = _for_container(job)
            size += len(json.dumps(packet, default=str))
            out.append(packet)
    return out


def release_expired(now=None):
    """Leases that ran out go back to the queue; a job handed out MAX_LEASES times without an answer fails."""
    from cveFeed.models import AIJob
    now = now or timezone.now()
    stale = list(AIJob.objects.filter(status='leased', lease_until__lt=now).values_list('pk', 'leases'))
    for pk, leases in stale:
        if leases >= MAX_LEASES:
            if AIJob.objects.filter(pk=pk, status='leased').update(status='answered', result={'error': 'lease_expired'}, lease='',
                                                                   error_category='lease_expired', answered_at=now):
                _schedule(pk)
        else:
            AIJob.objects.filter(pk=pk, status='leased', lease_until__lt=now).update(status='queued', lease='', lease_until=None)
    return len(stale)


# ------------------------------------------------------------------------------------------------------------------------- answers

def _count(value, high=10_000_000):
    if isinstance(value, bool):
        return None
    try:
        value = int(value)
    except (TypeError, ValueError):
        return None
    return value if 0 <= value <= high else None


def _record_calls(job, provider, calls, now):
    """One AIUsage row per call the container made for the job (at most eight): counts and outcome only, never text."""
    from cveFeed.models import AIUsage
    rows = []
    for call in calls[:8] if isinstance(calls, list) else []:
        if not isinstance(call, dict):
            continue
        status = 'succeeded' if call.get('status') == 'succeeded' else 'failed'
        category = call.get('category') if call.get('category') in CATEGORIES else ('' if status == 'succeeded' else 'unexpected_error')
        model = str(call.get('model') or job.model or '')
        actual = str(call.get('actual_model') or '')
        duration = _count(call.get('duration_ms'), 24 * 3600 * 1000)
        rows.append(AIUsage(provider=provider, model=model[:200] if MODEL_NAME.match(model) else '', actual_model=actual[:200] if MODEL_NAME.match(actual) else '',
                            stage=job.stage, status=status, error_category=category, started_at=now - timedelta(milliseconds=duration or 0),
                            input_tokens=_count(call.get('input_tokens')), output_tokens=_count(call.get('output_tokens')),
                            cache_read_tokens=_count(call.get('cache_read_tokens')), cache_write_tokens=_count(call.get('cache_write_tokens')),
                            duration_ms=duration))
    AIUsage.objects.bulk_create(rows)
    return rows


def submit(job_id, body, now=None):
    """Take the container's answer for one job: ``{lease, text | error, provider, model, calls: [...], http_status?, stop_reason?}``.
    Refused (JobError) for an unknown job (404), a lease that is not the job's current one (409) or a malformed body (400). Returns
    ``{accepted: true}``; the stage continues in a Celery task."""
    from cveFeed.models import AIJob
    from reNgine.ai_profiles import PROFILES
    if not isinstance(body, dict):
        raise JobError('body must be a JSON object')
    has_text, error = isinstance(body.get('text'), str), body.get('error')
    if has_text == (error is not None):
        raise JobError('send either text or error')
    if has_text and len(body['text']) > REPLY_MAX:
        raise JobError('the answer is too long')
    if error is not None and error not in CATEGORIES:
        raise JobError('error must be one of the known categories')
    provider = body.get('provider') if body.get('provider') in PROFILES else ''
    model = str(body.get('model') or '')
    model = model if MODEL_NAME.match(model) else ''
    now = now or timezone.now()
    with transaction.atomic():
        job = AIJob.objects.select_for_update().filter(pk=job_id).first()
        if job is None:
            raise JobError('not found', 404)
        lease = body.get('lease')
        if job.status != 'leased' or not job.lease or not isinstance(lease, str) or not secrets.compare_digest(lease, job.lease):
            raise JobError('this job is no longer leased to you', 409)
        rows = _record_calls(job, provider, body.get('calls'), now)
        if has_text:
            job.result = {'text': body['text']}
        else:
            job.result = {'error': error, **({'http_status': body['http_status']} if _count(body.get('http_status'), 999) else {}),
                          **({'stop_reason': str(body['stop_reason'])[:40]} if isinstance(body.get('stop_reason'), str) else {})}
            job.error_category = error
        job.status, job.lease, job.lease_until, job.answered_at = 'answered', '', None, now
        job.provider, job.model = provider, model
        job.input_tokens = job.input_tokens + sum(r.input_tokens or 0 for r in rows)
        job.output_tokens = job.output_tokens + sum(r.output_tokens or 0 for r in rows)
        job.save()
        pk = job.pk
        transaction.on_commit(lambda: _schedule(pk))
    return {'accepted': True}


def _schedule(pk):
    try:
        from cveFeed.tasks import apply_ai_job
        apply_ai_job.apply_async(args=[pk])
    except Exception:  # noqa: BLE001 - the housekeeping pass applies an answer whose task was lost
        logger.warning('AI job %s: could not queue its continuation; the housekeeping pass will apply it', pk, exc_info=True)


def apply(job_id):
    """Continue the stage of one answered job: its ``job_answer`` (or ``job_failure``) runs once, outside any long transaction. A Retry
    queues the job again with its new parts; otherwise the raw answer is dropped and the job is finished."""
    from cveFeed.models import AIJob
    now = timezone.now()
    if not AIJob.objects.filter(pk=job_id, status='answered').update(status='applying', updated_at=now):
        return None
    job = AIJob.objects.get(pk=job_id)
    module = _handler(job.kind)
    outcome, status = None, 'applied'
    try:
        if 'text' in job.result:
            from cveFeed.secret_redaction import redact_text
            answer = job.result['text']
            if (job.packet.get('options') or {}).get('redact_reply', True):  # a stage whose answer must stay literal (a template) opts out
                answer = redact_text(answer)
            outcome = module.job_answer(job, answer)
        else:
            status = 'failed'
            module.job_failure(job, job.result.get('error') or 'unexpected_error', job.result)
    except Exception:  # noqa: BLE001 - a continuation that breaks fails its job, never the worker
        logger.exception('AI job %s (%s): could not apply the answer', job.pk, job.kind)
        status, job.error_category = 'failed', 'apply_error'
    if isinstance(outcome, Retry):
        job.packet = {**job.packet, 'parts': _clean_parts(outcome.parts)}
        job.status, job.stage, job.attempt, job.result, job.leases = 'queued', str(outcome.stage)[:40], job.attempt + 1, {}, 0
        job.save(update_fields=['packet', 'status', 'stage', 'attempt', 'result', 'leases', 'updated_at'])
        return 'retry'
    job.status, job.result, job.packet, job.finished_at = status, {}, {}, timezone.now()  # the question (and any reply in it) goes too
    job.save(update_fields=['status', 'result', 'packet', 'finished_at', 'error_category', 'updated_at'])
    return status


def housekeeping(now=None):
    """Every few minutes: leases that ran out go back to the queue, answers whose Celery task was lost are applied, a continuation that
    died is failed, jobs never answered within TTL expire (their stage is told), and finished jobs past KEEP are deleted."""
    from cveFeed.models import AIJob
    now = now or timezone.now()
    out = {'released': release_expired(now), 'applied': 0, 'stuck': 0, 'expired': 0}
    for pk in AIJob.objects.filter(status='answered', answered_at__lt=now - APPLY_GRACE).values_list('pk', flat=True)[:200]:
        apply(pk)
        out['applied'] += 1
    out['stuck'] = AIJob.objects.filter(status='applying', updated_at__lt=now - APPLY_STUCK).update(
        status='failed', error_category='apply_lost', result={}, finished_at=now)
    for job in AIJob.objects.filter(status='queued', created_at__lt=now - TTL)[:500]:
        out['expired'] += _expire(job, now)
    AIJob.objects.filter(status__in=('applied', 'failed', 'expired'), finished_at__lt=now - KEEP).delete()
    return out


def waiting(now=None):
    """For the UI: ``{queued, oldest_minutes, serving, why, waiting_for_reviewer}``. ``waiting_for_reviewer`` is true when AI work is
    queued and the reviewer container is not taking it: turned off, never called in, or the oldest job has waited past WAITING_AFTER."""
    from cveFeed.models import AIJob
    now = now or timezone.now()
    queued = AIJob.objects.filter(status='queued')
    count = queued.count()
    oldest = queued.order_by('created_at').values_list('created_at', flat=True).first()
    ok, why = serving()
    minutes = int((now - oldest).total_seconds() // 60) if oldest else 0
    if ok and count:
        from agentapi import builtin_reviewer
        status = builtin_reviewer.status()
        if not status.get('token'):
            ok, why = False, 'the server has not handed the reviewer container its token yet'
        elif oldest and now - oldest > WAITING_AFTER:
            ok, why = False, f"the reviewer container has not taken work for {minutes} minutes (last call: {status.get('last_seen') or 'never'})"
    return {'queued': count, 'oldest_minutes': minutes, 'serving': ok, 'why': why, 'waiting_for_reviewer': bool(count and not ok)}


def waiting_message(state=None):
    """One plain sentence for a page, or '' when nothing waits."""
    state = state or waiting()
    if not state['waiting_for_reviewer']:
        return ''
    return (f"AI is waiting for the reviewer container: {state['queued']} AI job(s) queued, the oldest for {state['oldest_minutes']} "
            f"minute(s), because {state['why']}.")


def digest(text_value):
    """A short digest of an answer, for a diagnostic that must not hold its text."""
    return hashlib.sha256(str(text_value).encode()).hexdigest()[:12]
