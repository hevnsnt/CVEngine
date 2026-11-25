"""Bounded AI choice among checks that the deterministic validation policy already permits.

The model receives evidence and names of approved checks, never a shell command or an
arbitrary target. Its response can only select those checks or request a draft template.

The question is an AI job (``cveFeed.ai_jobs``, kind ``validation_plan``): the AI reviewer container asks the model, this server never
does. A validation request whose plan is not known yet waits for it (``tasks.validate_match_on_demand`` parks the request and the
answer, or the job's failure, sends it on: ``job_answer``, ``job_failure``, ``job_expired``). It never waits for ever: with the reviewer
not taking work, after ``PLAN_WAIT`` without an answer, past the budget or when the job fails, the request goes on with the deterministic
plan (``fallback``). The answer is kept on the job (its ``context``), so a request that asks again, or another request for the same
evidence, reads it there.
"""
import hashlib
import json
import logging
from datetime import timedelta

from django.db import connection, transaction
from django.utils import timezone

from cveFeed import templategen
from cveFeed.models import TriageCall
from cvengine import ai_prompts
from cvengine.ai_providers import clean_text

logger = logging.getLogger(__name__)

PLAN_WAIT = timedelta(minutes=10)    # a request waits this long for its plan, then goes on with the deterministic one
ANSWER_REUSE = timedelta(hours=24)  # a plan answered for the same evidence this recently is used again, not asked again
NUDGE_EVERY = timedelta(minutes=5)

SYSTEM = ai_prompts.compose('validation_plan', "First read host_metadata: every technology with "
          "its version and where it was seen, the ports with product, version, extra info and banners, the front page headers, any CDN, "
          "WAF or hosting edge, certificates, the operating system guess, earlier probe and check results and the host's other CVE "
          "matches. Then say which missing fact decides the question: the product's version, which look-alike product it is (nginx, "
          "ingress-nginx and nginx-ui are different software), whether an edge hides the origin, or local state that no network check "
          "can read. Choose only checks that can establish that fact. Kind fact_probe is a catalogue of read-only version and identity "
          "probes the application runs itself; prefer it whenever a version or identity is missing. Kind script_read reads a JavaScript "
          "library's version again from the script files the page loads (the file's own banner, which copy runs): it is the check for "
          "a client-side library, where nmap and a HEAD see nothing, and a version it reads is not proof the page is exploitable. "
          "A check being safe and available "
          "does not make it relevant. Generic HTTP banners and nmap service versions cannot verify local kernel, driver, NIC, KVM or "
          "hardware prerequisites: say they need the host inventory reporter. Behind a CDN or WAF the Server header, X-Powered-By and "
          "error pages describe the edge, so origin software and versions cannot be known from here; a tag such as cloudflare names "
          "the edge, not an application: say so instead of assuming. If none can establish a relevant fact, return an empty "
          "check_kinds list and explain the missing evidence. "
          "Reply with one JSON object only: "
          '{"check_kinds":["nuclei_template"],"generate_template":false,"reason":"..."}. '
          "check_kinds may contain only listed kinds. Choose generate_template only if no safe installed CVE "
          "template exists and a specific non-destructive detector can plausibly be written from the CVE facts. "
          "Never propose commands, URLs, hosts, credentials, or an exploit payload. An empty plan is allowed "
          "when evidence is insufficient. A version or a generic server banner alone does not prove vulnerability, and a banner "
          "that states no version proves nothing either way.")
MAX_REASON = 700


def parse_plan(reply, checks, can_generate):
    """Reject out-of-schema choices. A model cannot expand the deterministic check set."""
    from cvengine.ai_providers import extract_json
    obj = extract_json(reply, ('check_kinds', 'generate_template', 'reason'))
    if obj is None or set(obj) != {'check_kinds', 'generate_template', 'reason'}:
        return None
    kinds, generate, reason = obj['check_kinds'], obj['generate_template'], obj['reason']
    allowed = {c['kind'] for c in checks}
    if not isinstance(kinds, list) or len(kinds) > len(allowed) or len(set(map(str, kinds))) != len(kinds):
        return None
    if any(not isinstance(k, str) or k not in allowed for k in kinds):
        return None
    if not isinstance(generate, bool) or (generate and (not can_generate or 'nuclei_template' in allowed)):
        return None
    if not isinstance(reason, str) or not reason.strip():
        return None
    return {'check_kinds': kinds, 'generate_template': generate, 'reason': clean_text(reason, MAX_REASON),
            'source': 'ai'}


def daily_limits():
    """(all projects, one project) planning requests a day, from the AI settings; 0 stops AI planning."""
    from dashboard.models import AIProviderSettings
    cfg = AIProviderSettings.objects.first()
    return (cfg.plan_daily_total, cfg.plan_daily_per_project) if cfg else (200, 20)


def _reserve(project_id, signature):
    """One in-flight plan per signature; billable attempts per day are capped per project and in total (Settings > AI model)."""
    with transaction.atomic():
        if connection.vendor == 'postgresql':
            with connection.cursor() as cursor:
                cursor.execute('SELECT pg_advisory_xact_lock(%s)', [21860074])
        now = timezone.now()
        TriageCall.objects.filter(kind='validation_plan', status='running', expires_at__lte=now).update(
            status='expired', finished_at=now)
        if TriageCall.objects.filter(kind='validation_plan', signature=signature, status='running').exists():
            return None, 'another planning request is running for this evidence'
        since = now.replace(hour=0, minute=0, second=0, microsecond=0)
        today = TriageCall.objects.filter(kind='validation_plan', started_at__gte=since)
        total, per_project = daily_limits()
        if today.count() >= total or today.filter(project_id=project_id).count() >= per_project:
            return None, 'AI planning daily budget reached (raise it in Settings > AI model)'
        # held while the question waits for the reviewer container; the job's answer, failure or expiry closes it
        from cveFeed import ai_jobs
        return TriageCall.objects.create(kind='validation_plan', project_id=project_id, signature=signature,
                                         expires_at=now + ai_jobs.TTL), ''


PLAN_SCHEMA = {'type': 'object', 'additionalProperties': False, 'required': ['check_kinds', 'generate_template', 'reason'],
               'properties': {'check_kinds': {'type': 'array', 'items': {'type': 'string'}}, 'generate_template': {'type': 'boolean'},
                              'reason': {'type': 'string'}}}


def _fallback(checks, probe_kinds):
    # An exact CVE template is relevant by construction; generic banners are not. A probe finds the fact itself.
    return {'check_kinds': (['nuclei_template'] if any(c['kind'] == 'nuclei_template' for c in checks) else []) + probe_kinds,
            'generate_template': False,
            'reason': 'No usable AI plan. Only a vetted CVE-specific template can run without an AI relevance decision.',
            'source': 'policy_fallback'}


def _with_probes(decision, probe_kinds):
    missing = [kind for kind in probe_kinds if kind not in decision['check_kinds']]
    if missing:
        decision = {**decision, 'check_kinds': decision['check_kinds'] + missing}  # an empty or narrow plan never ends a request while a probe can still find the fact
        decision['reason'] = clean_text(decision['reason'] + (' (Version and identity probes still run to establish the missing fact.)'
                                                              if 'fact_probe' in missing else
                                                              ' (The script read still runs: it reads the library version from the page.)'), MAX_REASON)
    return decision


def _signature(project_id, row, observations):
    observation_digest = hashlib.sha256(json.dumps(observations or [], sort_keys=True, default=str).encode()).hexdigest()[:12]
    return hashlib.sha256(f'validation-plan-v2:{project_id}:{row.signature}:{observation_digest}'.encode()).hexdigest()[:40]


def _dedupe(signature):
    return f'plan:{signature}'


def _settled(job):
    """Whether a plan job has its outcome: it left an answer or a failure on itself (``_finish``, while it is still being applied), or it ended."""
    from cveFeed.models import AIJob
    ctx = job.context or {}
    return 'plan' in ctx or 'failed' in ctx or job.status not in AIJob.OPEN


def _answered(job, checks, can_generate, probe_kinds):
    """What a finished plan job left for a request (``job.context``): ``(decision, None)`` for an answer, ``(None, why)`` when it gave none."""
    ctx = job.context or {}
    if isinstance(ctx.get('plan'), dict):
        decision = ctx['plan']
        allowed = {c['kind'] for c in checks}
        kinds = [k for k in decision.get('check_kinds') or [] if k in allowed]  # the request's own approved checks bound it once more
        generate = bool(decision.get('generate_template')) and can_generate and 'nuclei_template' not in allowed
        return _with_probes({'check_kinds': kinds, 'generate_template': generate, 'reason': decision.get('reason') or '', 'source': 'ai'},
                            probe_kinds), None
    return None, ctx.get('failed') or ('the AI plan job ended without an answer' if job.status != 'applied' else 'AI returned an invalid plan')


def plan(project_id, row, cve, subject, checks, template, provider=None, observations=None, host=None, waiting=None):
    """Return ``(decision, ai)``: ``ai`` is whether AI planning is on (``ai_jobs.ai_on``). Failure cannot authorize generic checks by default.
    ``host`` is the host's metadata (cveFeed.host_context.host_context), given to the model as untrusted data. Version and identity probes need
    no relevance decision: they are the way to learn the missing fact, so they are always part of the plan when the planner offers them.

    The decision's ``source`` is ``ai``, ``policy_fallback``, or ``pending``: the question is queued for the AI reviewer container (``job``
    names it) and the caller waits for it (``tasks.validate_match_on_demand`` parks the request). ``waiting`` is what the caller parked on
    before (``{'job': id, 'since': iso}``): its answer is read from that job, and a job that has not answered within ``PLAN_WAIT``, or a
    reviewer that is not taking work, ends the wait with the deterministic plan. ``provider`` is not used (the container asks the model); it
    is accepted so that older callers keep working."""
    from cveFeed import ai_jobs
    from cveFeed.models import AIJob
    can_generate = not template[0]
    # the version and identity probes, and the script read of a client-side library: the deterministic way to learn the missing fact
    probe_kinds = [kind for kind in ('fact_probe', 'script_read') if any(c['kind'] == kind for c in checks)]
    fallback = _fallback(checks, probe_kinds)
    if not ai_jobs.ai_on():
        return {**fallback, 'reason': 'No AI provider is configured; version and identity probes and a vetted CVE template run, other generic '
                                      'checks have no CVE-specific relevance decision.'}, False
    now = timezone.now()
    if waiting and waiting.get('job'):
        job = AIJob.objects.filter(pk=waiting['job']).first()
        if job is not None and _settled(job):
            decision, why = _answered(job, checks, can_generate, probe_kinds)
            if decision:
                return decision, True
            return {**fallback, 'reason': f'{why}; generic external checks deferred.'}, True
        since = _parse_time(waiting.get('since')) or now
        serving, why = ai_jobs.serving()
        if job is None or not serving or now - since >= PLAN_WAIT:
            why = (why if not serving else f'the AI plan did not arrive within {int(PLAN_WAIT.total_seconds() // 60)} minutes' if job is not None
                   else 'the AI plan job is gone')
            return {**fallback, 'reason': f'{why}; generic external checks deferred.'}, True
        return {**fallback, 'source': 'pending', 'job': job.pk, 'reason': 'waiting for the AI reviewer container to choose the checks'}, True
    signature = _signature(project_id, row, observations)
    done = (AIJob.objects.filter(kind='validation_plan', dedupe=_dedupe(signature), status='applied', finished_at__gte=now - ANSWER_REUSE)
            .order_by('-id').first())
    if done is not None and isinstance((done.context or {}).get('plan'), dict):
        return _answered(done, checks, can_generate, probe_kinds)[0], True
    open_job = AIJob.objects.filter(kind='validation_plan', dedupe=_dedupe(signature), status__in=AIJob.OPEN).order_by('-id').first()
    if open_job is not None:  # another request for the same evidence asked already: wait for the same answer
        return {**fallback, 'source': 'pending', 'job': open_job.pk, 'reason': 'waiting for the AI reviewer container to choose the checks'}, True
    serving, why = ai_jobs.serving()
    if not serving:  # nobody would answer: the request does not wait for a queue nobody serves
        return {**fallback, 'reason': f'AI planning is not available now ({why}); generic external checks deferred.'}, True
    claim, why = _reserve(project_id, signature)
    if claim is None:
        return {**fallback, 'reason': why + '; generic external checks deferred.'}, True
    try:
        from cveFeed import detection
        context = {'cve': {**templategen.cve_info_for(cve), 'guidance': detection.prompt_guidance(cve)},
                   'asset_evidence': {k: subject.get(k) for k in ('source', 'product', 'matched_version', 'range', 'port')},
                   'approved_checks': [{'kind': c['kind'], 'label': c['label']} for c in checks],
                   'host_metadata': host,
                   'completed_observations': (observations or [])[:6],
                   'safe_template': bool(template[0]), 'template_unavailable_reason': template[1] if not template[0] else ''}
        # templategen's prompt cleaner treats CVE feed text as hostile input. The hostname and IP are excluded.
        safe = templategen._clean_value(context, 500)
        job = ai_jobs.enqueue('validation_plan', 'validation_plan', system=SYSTEM,
                              parts=[ai_jobs.text('Choose the checks for this CVE match:'), ai_jobs.fence('VALIDATION_CONTEXT', safe)],
                              schema=PLAN_SCHEMA, options={'temperature': 0, 'schema_name': 'validation_plan'},
                              context={'claim': claim.pk, 'checks': [c['kind'] for c in checks], 'can_generate': can_generate},
                              project=project_id, dedupe=_dedupe(signature), priority=2)
    except Exception:
        logger.warning('validation plan: the AI planning question could not be queued (claim %s)', claim.pk, exc_info=True)
        TriageCall.objects.filter(pk=claim.pk, status='running').update(status='failed', finished_at=timezone.now())
        return {**fallback, 'reason': 'AI planning could not be queued; generic external checks deferred.'}, True
    return {**fallback, 'source': 'pending', 'job': job.pk, 'reason': 'waiting for the AI reviewer container to choose the checks'}, True


def _parse_time(value):
    from django.utils.dateparse import parse_datetime
    try:
        return parse_datetime(value) if value else None
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------------------------- the answers (cveFeed.ai_jobs)

def _claim_of(job):
    return TriageCall.objects.filter(pk=(job.context or {}).get('claim')).first()


def _finish(job, status, **context):
    """Close the job's budget claim and keep what it left (``plan`` or ``failed``) on the job, then send on the requests parked on it."""
    from cveFeed.models import AIJob
    TriageCall.objects.filter(pk=(job.context or {}).get('claim'), status='running').update(status=status, finished_at=timezone.now())
    AIJob.objects.filter(pk=job.pk).update(context={**(job.context or {}), **context})
    job.context = {**(job.context or {}), **context}
    resume_parked(job.pk)


def job_answer(job, text):
    from cveFeed import ai_jobs
    from cvengine.ai_providers import repair_parts
    ctx = job.context or {}
    checks = [{'kind': k} for k in ctx.get('checks') or []]
    decision = parse_plan(text, checks, bool(ctx.get('can_generate')))
    if decision is None and job.attempt == 1:
        # sent back to the model once, with why it was rejected; the second answer is the one that counts (and is a billed request)
        claim = _claim_of(job)
        if claim is not None:
            TriageCall.objects.create(kind='validation_plan', signature=claim.signature, project_id=claim.project_id, status='repair',
                                      expires_at=timezone.now(), finished_at=timezone.now())
        return ai_jobs.Retry('validation_plan', repair_parts(job.packet.get('parts') or [], text,
                                                             'the reply is not the plan object, or it names a check that was not listed'))
    if decision is None:
        _finish(job, 'failed', failed='AI returned an invalid plan')
    else:
        _finish(job, 'succeeded', plan={k: decision[k] for k in ('check_kinds', 'generate_template', 'reason')})
    return None


def job_failure(job, category, detail):
    _finish(job, 'failed', failed=f'AI planning failed ({category})')


def job_expired(job):
    _finish(job, 'expired', failed='the AI plan was never answered')


def job_admit(job):
    """A plan whose claim was given up (no request waits for it any more) is not asked."""
    claim = _claim_of(job)
    return True if claim is not None and claim.status == 'running' else 'drop'


# --------------------------------------------------------------------------------------------- the requests that wait

def parked(job_id=None):
    """The validation requests parked on a plan job (``job_id``), or on any (None)."""
    from cveFeed.models import OnDemandValidation
    rows = OnDemandValidation.objects.filter(status='queued', result__has_key='waiting')
    return rows.filter(result__waiting__job=job_id) if job_id is not None else rows


def resume_parked(job_id):
    """Send on the requests parked on ``job_id``: they read its answer (or its failure) and continue."""
    for pk, priority in parked(job_id).values_list('pk', 'priority'):
        _dispatch(pk, priority)


def _dispatch(pk, priority=3):
    from cveFeed.tasks import validate_match_on_demand
    try:
        validate_match_on_demand.apply_async(args=[pk], priority=priority)
    except Exception:  # noqa: BLE001 - the nudge (``nudge_parked``) sends it on later
        logger.warning('validation request %s: could not be sent on after its plan', pk, exc_info=True)


def park(request_id, decision, progress=None, round_number=1):
    """Put a running request back in the queue to wait for its plan (``decision['job']``). ``progress`` is what the request already did (its
    first round of checks), kept for when it continues. False when the request was no longer running. A job that ended meanwhile sends the
    request on at once."""
    from cveFeed.models import AIJob, OnDemandValidation
    row = OnDemandValidation.objects.filter(pk=request_id, status='running').first()
    if row is None:
        return False
    result = {**(row.result or {}), 'waiting': {'job': decision['job'], 'since': timezone.now().isoformat(), 'round': round_number},
              'progress': progress or {}, 'check_state': 'not_run', 'ai_state': 'not_run',
              'next_action': 'waiting for the AI reviewer container to choose the checks'}
    if not OnDemandValidation.objects.filter(pk=request_id, status='running').update(status='queued', result=result, started_at=None):
        return False
    job = AIJob.objects.filter(pk=decision['job']).first()
    if job is None or _settled(job):  # it ended while the request was being parked: nobody else sends it on
        _dispatch(request_id, row.priority)
    return True


def nudge_parked(now=None):
    """From the AI job housekeeping: a request parked longer than ``PLAN_WAIT`` is sent on (it goes on with the deterministic plan), and so is
    one whose job ended without sending it (a lost message). Each at most once per ``NUDGE_EVERY``."""
    from django.core.cache import cache
    from cveFeed.models import AIJob
    now = now or timezone.now()
    sent = 0
    for row in parked()[:200]:
        waiting = (row.result or {}).get('waiting') or {}
        since = _parse_time(waiting.get('since')) or now
        job = AIJob.objects.filter(pk=waiting.get('job')).first()
        ended = job is None or _settled(job)
        if (ended or now - since >= PLAN_WAIT) and cache.add(f'cvengine:plan-nudge:{row.pk}', 1, timeout=int(NUDGE_EVERY.total_seconds())):
            _dispatch(row.pk, row.priority)
            sent += 1
    return sent


def generate_candidate(project_id, cve, provider):
    """Create at most one bounded draft attempt for a CVE; never install or run it on the requested host. ``provider`` is whether AI is on
    (``plan``'s second value)."""
    if not provider:
        return {'status': 'unavailable', 'reason': 'AI provider is not configured'}
    signature = hashlib.sha256(f'validation-template-v1:{project_id}:{cve.cve_id}'.encode()).hexdigest()[:40]
    claim, why = _reserve(project_id, signature)
    if claim is None:
        return {'status': 'deferred', 'reason': why}
    try:
        try:
            job = templategen.generate_template(cve, project=project_id, candidate_only=True)
        except templategen.TemplateBudgetExceeded as exc:  # no AI question was queued, so the planning budget is not charged
            TriageCall.objects.filter(pk=claim.pk).delete()
            return {'status': 'deferred', 'reason': str(exc)}
        TriageCall.objects.filter(pk=claim.pk, status='running').update(status='succeeded', finished_at=timezone.now())
        return {'status': 'queued', 'job': job.pk,
                'reason': 'the AI reviewer container writes the draft; it is validated when it lands and is never run on this host',
                'provenance': 'AI-authored draft; static, syntax and benign control gates; automatic fixture test and second-pass review follow'}
    except Exception:
        logger.warning('validation plan: template generation for %s could not be queued (claim %s)', cve.cve_id, claim.pk, exc_info=True)
        TriageCall.objects.filter(pk=claim.pk, status='running').update(status='failed', finished_at=timezone.now())
        return {'status': 'failed', 'reason': 'template generation could not be queued'}
