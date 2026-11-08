"""The server's half of the AI reviewer (docs/AI-REVIEWER.md).

The reviewer itself runs in its own container (``reviewer/``): no source, no database, no Redis, a read-only filesystem. It reaches this
server only through ``/api/v1/reviewer/*`` with a token of scope ``reviewer`` (agentapi.reviewer_api). Everything that decides anything is
here, on this side:

* **Finding review.** ``next_packets`` hands out sanitised review packets: findings that are open and not yet reviewed in their current
  state, keyed by ``review_key`` (the finding's evidence key and its host's state fingerprint). ``apply_verdict`` takes one verdict back.
  It closes a finding as a false positive only through ``close_gate``: no hard evidence, nobody worked it, no instructions aimed at an AI
  in its evidence, and the state the verdict was given on is still the current one. Anything else is recorded as the reviewer's
  opinion and changes nothing.
* **Operations checks.** ``ops_checks`` computes the checks from ``system_status`` and the database, every half hour, with or without an
  AI (``run_ops_checks`` raises and resolves ``AdminAlert`` rows). The operations job adds its diagnosis (``apply_ops_report``) and may ask
  for an action. An action runs only if the current checks offer it, and no more often than its own interval.

Every word the model writes is data: it is cleaned, stripped of markup and links, refused if it repeats a marker planted in the
evidence, and only ever rendered as text.
"""
import hashlib
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone as dt_timezone

from django.core.cache import cache
from django.db.models import Q
from django.utils import timezone

logger = logging.getLogger(__name__)

VERDICTS = ('false_positive', 'true_open', 'true_in_progress', 'true_fixed', 'true_accepted_risk', 'uncertain')
CONFIDENCES = ('low', 'medium', 'high')
REASON_CODES = (
    'version_not_affected',     # the version shown is outside the affected range, or the fix is backported
    'product_mismatch',         # the product on the host is not the product the advisory names
    'evidence_is_claim',        # the finding rests on text the host serves about itself (a comment, a banner, a file name), not on behaviour
    'check_not_applicable',     # the check does not apply to this kind of host (a mail check on a host that sends no mail, ...)
    'generic_match',            # a catch-all page, a soft 404 or a generic matcher answered, not the flaw
    'duplicate',                # the same issue is already reported on this host
    'stale_evidence',           # what the finding rests on is no longer on the host
    'decoy',                    # the evidence looks planted for automated scanners
    'confirmed_by_evidence',    # cvENGINE's own evidence shows the flaw
    'plausible_exposure',       # nothing rules it out: a real exposure until shown otherwise
    'remediated',               # the evidence shows it fixed
    'other',
)
NOTE_MAX = 1200
LEASE_SECONDS = 900
PACKET_LIMIT = 25
WINDOW = 400  # candidates read per request to find the ones not yet reviewed in their current state
DEFAULT_OPS_HOURS = (3, 9, 15, 21)
DEFAULT_MODELS = {'review': 'claude-sonnet-5-5', 'ops': 'claude-haiku-5-5'}
KIND_ORDER = {'cve_match': 0, 'nuclei': 1, 'db_exposure': 2, 'bbot': 3, 'hygiene': 4}
AUDIT_KIND = {'cve_match': 'match', 'nuclei': 'vulnerability', 'db_exposure': 'vulnerability', 'bbot': 'vulnerability', 'hygiene': 'hygiene'}
CLOSE_PREFIX = 'Closed automatically: the AI reviewer'
CRITICAL = 4


def env_enabled():
    return os.environ.get('CVENGINE_REVIEWER', '1').strip().lower() not in ('0', 'false', 'no', 'off')


def settings_row():
    from cveFeed.models import ReviewerSettings
    return ReviewerSettings.current()


def provider_row():
    from dashboard.models import AIProviderSettings
    return AIProviderSettings.objects.filter(enabled=True).first()


def paused():
    from cveFeed.scan_control import pause_requested
    return pause_requested()


def enabled(row=None, provider=None):
    """Whether the reviewer works now: switched on in .env and in Settings, with an AI provider configured, and scanning not paused (a
    pause stops every paid AI call, like the rest of the AI work)."""
    row = row or settings_row()
    provider = provider if provider is not None else provider_row()
    return bool(env_enabled() and row.enabled and provider and not paused())


def model_for(job, row, provider):
    """The model a job uses: the one named for it, else the default for Anthropic, else the provider's own."""
    named = (row.review_model if job == 'review' else row.ops_model).strip()
    if named:
        return named
    if provider.provider == 'anthropic':
        return DEFAULT_MODELS[job]
    return provider.model or ''


def ops_hours(row):
    hours = [h for h in (row.ops_hours or []) if isinstance(h, int) and 0 <= h <= 23]
    return sorted(set(hours)) or list(DEFAULT_OPS_HOURS)


def ops_due(row, now=None):
    """Whether the operations job should run now: a scheduled UTC hour has passed since it last reported."""
    now = now or timezone.now()
    last = row.last_ops_at
    for days_back in (0, 1):
        day = (now - timedelta(days=days_back)).date()
        for hour in sorted(ops_hours(row), reverse=True):
            slot = datetime(day.year, day.month, day.day, hour, tzinfo=dt_timezone.utc)
            if slot <= now:
                return last is None or last < slot
    return False


def reviews_today(now=None):
    from cveFeed.models import FindingReview
    now = now or timezone.now()
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return FindingReview.objects.filter(created_at__gte=start).count()


JOB_WORKERS = 4  # pipeline jobs the container runs side by side


def config(now=None):
    """What the reviewer container needs to work: whether it may review and run the pipeline's AI jobs, the provider and key, the model
    of each job, the request settings, its limits. The pipeline's jobs (cveFeed.ai_jobs) are served whenever an AI provider is configured,
    whatever the review setting says; the finding review and the operations check need it on too."""
    from cveFeed import ai_jobs
    from reNgine.ai_providers import reachable_url
    row, provider = settings_row(), provider_row()
    on = enabled(row, provider)
    jobs_on, jobs_why = ai_jobs.serving()
    out = {'enabled': on, 'auto_close': row.auto_close, 'review_daily_max': row.review_daily_max,
           'reviews_left_today': max(0, row.review_daily_max - reviews_today(now)), 'ops_due': bool(on and ops_due(row, now)),
           'packet_limit': PACKET_LIMIT, 'note_max': NOTE_MAX, 'verdicts': list(VERDICTS), 'confidences': list(CONFIDENCES),
           'reason_codes': list(REASON_CODES), 'jobs_enabled': jobs_on, 'job_workers': JOB_WORKERS}
    if jobs_on:
        out['jobs'] = ai_jobs.provider_block(ai_jobs.provider_row())
    else:
        out['jobs_why'] = jobs_why
    if not on:
        out['why'] = ('turned off in .env (CVENGINE_REVIEWER=0)' if not env_enabled() else
                      'turned off in Settings' if not row.enabled else 'no AI provider is configured' if not provider else
                      'scanning is paused')
        return out
    base = {'provider': provider.provider, 'base_url': reachable_url(provider.base_url) if provider.base_url else '',
            'api_key': provider.api_key or '', 'timeout': int(getattr(provider, 'request_timeout', 0) or 120)}
    out['review'] = {**base, 'model': model_for('review', row, provider)}
    out['ops'] = {**base, 'model': model_for('ops', row, provider)}
    return out


# --------------------------------------------------------------------------------------------------------------- finding review

def open_q():
    """Triage rows of findings that are still open: a CVE match not ruled out, a scanner finding still reported, a hygiene finding still
    failing, each with a remediation status of open or in progress. Web routes have no remediation workflow and are left out."""
    working = ('open', 'in_progress')
    return ((Q(match__isnull=False) & Q(match__remediation_status__in=working) & ~Q(match__ai_verdict='not_affected'))
            | (Q(vulnerability__isnull=False) & Q(vulnerability__open_status=True) & Q(vulnerability__remediation_status__in=working))
            | (Q(hygiene__isnull=False) & Q(hygiene__status='open') & Q(hygiene__remediation_status__in=working)))


def _fingerprints(pairs):
    from cveFeed.models import HostState
    if not pairs:
        return {}
    q = Q()
    for project_id, host in pairs:
        q |= Q(project_id=project_id, host=host)
    return {(r['project_id'], r['host']): r['fingerprint'] for r in HostState.objects.filter(q).values('project_id', 'host', 'fingerprint')}


def review_key(triage, fingerprint):
    basis = f'{triage.kind}|{triage.evidence_key or triage.signature}|{fingerprint or ""}'
    return hashlib.sha1(basis.encode()).hexdigest()


def _last_keys(triage_ids):
    from cveFeed.models import FindingReview
    out = {}
    for row in FindingReview.objects.filter(triage_id__in=triage_ids).order_by('triage_id', '-created_at').values('triage_id', 'review_key'):
        out.setdefault(row['triage_id'], row['review_key'])
    return out


def due(limit=PACKET_LIMIT, now=None):
    """Up to ``limit`` ``(triage, review_key)`` pairs to review now: open findings whose current key has no review, CVE matches first."""
    from cveFeed.models import Triage
    rows = list(Triage.objects.filter(open_q()).exclude(kind='route_auth')
                .order_by('-last_seen', '-id').only('id', 'kind', 'project_id', 'host', 'evidence_key', 'signature')[:WINDOW * 5])
    rows.sort(key=lambda t: KIND_ORDER.get(t.kind, 9))  # stable: newest first within a kind
    fingerprints = _fingerprints({(t.project_id, t.host) for t in rows[:WINDOW]})
    last = _last_keys([t.pk for t in rows[:WINDOW]])
    picked = []
    for triage in rows[:WINDOW]:
        key = review_key(triage, fingerprints.get((triage.project_id, triage.host), ''))
        if last.get(triage.pk) == key:
            continue
        if not cache.add(f'cvengine:reviewer:lease:{triage.pk}', key, LEASE_SECONDS):
            continue  # handed out within the last 15 minutes
        picked.append((triage.pk, key))
        if len(picked) >= limit:
            break
    return picked


def _raw_evidence(triage, finding):
    """What the scanner stored about the host for this finding, for the injection scan (never sent to the model)."""
    out = [triage.validation_evidence]
    if triage.kind == 'cve_match':
        out.append(finding.evidence)
    elif triage.kind == 'hygiene':
        out += [finding.evidence, finding.detail]
    else:
        out += [getattr(finding, 'response', None), getattr(finding, 'extracted_results', None), getattr(finding, 'matcher_name', None)]
    return out


def worked_by_person(kind, finding):
    """Whether a person has worked this finding: a status other than open, an assignee, a comment, a status change or heat set by hand,
    or (for a CVE match) a manual validation request. Such a finding is never closed automatically: a person's work wins."""
    from cveFeed.models import FindingAuditEvent, FindingComment, OnDemandValidation
    audit_kind = AUDIT_KIND.get(kind, kind)
    if finding.remediation_status != 'open' or getattr(finding, 'assignee_id', None):
        return True
    if FindingComment.objects.filter(finding_kind=audit_kind, finding_id=finding.pk).exists():
        return True
    if FindingAuditEvent.objects.filter(finding_kind=audit_kind, finding_id=finding.pk, actor__isnull=False).exists():
        return True
    triage = getattr(finding, 'triage', None)
    if triage is not None and triage.heat_override:
        return True
    return kind == 'cve_match' and OnDemandValidation.objects.filter(match=finding, source='manual').exists()


def proof(kind, triage, finding):
    """Why this finding cannot be a false positive in cvENGINE's own eyes, or '': hard evidence about this host."""
    from cveFeed import match_policy
    if triage.validation_status == 'hit':
        return "one of cvENGINE's own read-only checks reproduced it"
    if kind == 'cve_match':
        if match_policy.has_hard_evidence(finding.source, finding.evidence or {}, finding.template_result or '', finding.distro_status or '',
                                          triage.validation_status):
            return 'it has hard evidence (a template hit, the distribution tracker, runZero or the host itself)'
        return ''
    if kind == 'db_exposure' and (finding.response or '').strip():
        return 'the database service answered without credentials'
    return ''


def close_gate(kind, triage, finding, injection):
    """``(outcome if not closable, reason)``: ``('', '')`` when the server may close this finding as a false positive."""
    reason = proof(kind, triage, finding)
    if reason:
        return 'disputed', reason
    if worked_by_person(kind, finding):
        return 'held', 'a person has worked this finding'
    if injection:
        return 'held', 'its evidence carries text aimed at AI agents (' + ', '.join(injection) + ')'
    if kind in ('nuclei', 'db_exposure', 'bbot') and (finding.severity or 0) >= CRITICAL:
        return 'held', 'a critical scanner finding is closed by a person'
    return '', ''


def _heat(kind, finding):
    from cveFeed import threat
    try:
        if kind == 'cve_match':
            heat = threat.match_heat(finding)
            return heat, threat.heat_reason(finding, heat)
        if kind in ('nuclei', 'db_exposure', 'bbot'):
            heat = threat.finding_heat(finding)
            return heat, threat.finding_heat_reason(finding, heat)
    except Exception:  # noqa: BLE001 - the heat is context for the model; a failure to read it never blocks the review
        logger.warning('reviewer: could not read the heat of %s %s', kind, finding.pk, exc_info=True)
    return '', ''


def _load(triage_id):
    from cveFeed.models import Triage
    return (Triage.objects.select_related('match', 'match__cve_entry', 'match__subdomain', 'match__subdomain__target_domain', 'vulnerability',
                                          'vulnerability__subdomain', 'vulnerability__target_domain', 'hygiene', 'hygiene__domain')
            .filter(pk=triage_id).first())


def build_packet(triage, key):
    """The review packet of one finding: what cvENGINE computed itself (``trusted``), what the scanned host said, sanitised (``untrusted``),
    and whether the server could close it at all."""
    from cveFeed import injection_guard
    from cveFeed import triage as triage_lib
    finding = triage.finding
    d = triage_lib.describe(finding)
    kind = triage.kind
    injection = injection_guard.families(_raw_evidence(triage, finding), d.get('payload'), d.get('host_context'))
    blocked, why = close_gate(kind, triage, finding, injection)
    heat, heat_reason = _heat(kind, finding)
    steps = [{'check': str(s.get('label') or s.get('kind') or '')[:80], 'result': str(s.get('result') or '')[:40]}
             for s in (triage.validation_steps or [])[:10] if isinstance(s, dict)]
    return {
        'ref': f't{triage.pk}', 'review_key': key, 'kind': kind,
        'trusted': {
            'heat': heat, 'heat_reason': str(heat_reason or '')[:300],
            'severity': triage_lib.SEVERITY_NAMES.get(d.get('severity'), 'unknown'),
            'hard_evidence': [str(x)[:200] for x in (triage.hard_evidence or [])][:8],
            'earlier_classification': triage.classification or '',
            'validation_status': triage.validation_status, 'validation_checks': steps,
            'first_seen': triage.first_seen.date().isoformat() if triage.first_seen else '',
            'last_seen': triage.last_seen.date().isoformat() if triage.last_seen else '',
            'status': finding.remediation_status,
            'server_may_close': not blocked, 'server_will_not_close_because': why,
            'instructions_aimed_at_ai_found_in_evidence': injection,
        },
        'untrusted': {
            'facts': d.get('payload'), 'host_context': d.get('host_context'),
            'earlier_triage_reason_written_by_a_model': triage_lib.strip_instructions((triage.reason or '')[:800]),
        },
    }


def next_packets(limit=PACKET_LIMIT, now=None):
    """Up to ``limit`` review packets (fewer once today's cap is reached)."""
    row = settings_row()
    if not enabled(row):
        return []
    limit = max(0, min(int(limit or PACKET_LIMIT), PACKET_LIMIT, row.review_daily_max - reviews_today(now)))
    packets = []
    for triage_id, key in due(limit, now) if limit else []:
        triage = _load(triage_id)
        if triage is None or triage.finding is None:
            continue
        try:
            packets.append(build_packet(triage, key))
        except Exception:  # noqa: BLE001 - one finding that cannot be described must not stop the batch
            logger.warning('reviewer: could not build the packet of triage %s', triage_id, exc_info=True)
            cache.delete(f'cvengine:reviewer:lease:{triage_id}')
    return packets


_MARKUP = re.compile(r'[<>]')
_LINK = re.compile(r'\b(?:https?|ftp|file|javascript|data):\S*|\bwww\.\S+', re.I)


class VerdictError(ValueError):
    """A verdict that is not accepted (the API answers 400 or 409)."""

    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def clean_note(text):
    """A model's note as stored: cleaned like a person's closure note, no markup characters, no links, at most NOTE_MAX characters."""
    from cveFeed import closure
    text = closure.clip_note(text if isinstance(text, str) else '', NOTE_MAX) or ''
    text = _LINK.sub('[link removed]', _MARKUP.sub('', text))
    return re.sub(r'[ \t]+', ' ', text).strip()[:NOTE_MAX]


def _parse_verdict(body):
    if not isinstance(body, dict):
        raise VerdictError('body must be a JSON object')
    verdict, confidence = body.get('verdict'), body.get('confidence')
    reason_code = body.get('reason_code') or 'other'
    if verdict not in VERDICTS:
        raise VerdictError('verdict must be one of ' + ', '.join(VERDICTS))
    if confidence not in CONFIDENCES:
        raise VerdictError('confidence must be one of ' + ', '.join(CONFIDENCES))
    if reason_code not in REASON_CODES:
        raise VerdictError('reason_code must be one of ' + ', '.join(REASON_CODES))
    key = body.get('review_key')
    if not isinstance(key, str) or not re.fullmatch(r'[0-9a-f]{40}', key):
        raise VerdictError('review_key must be the key of the packet')

    def count(name):
        try:
            return max(0, min(int((body.get('usage') or {}).get(name) or 0), 10_000_000))
        except (TypeError, ValueError):
            return 0
    return {'verdict': verdict, 'confidence': confidence, 'reason_code': reason_code, 'review_key': key,
            'note': body.get('note'), 'model': str(body.get('model') or '')[:100],
            'input_tokens': count('input_tokens'), 'output_tokens': count('output_tokens')}


def apply_verdict(ref, body, now=None):
    """Take one verdict for the finding ``ref`` (``t<triage id>``). Returns ``{outcome, reason, review_id}``. Raises VerdictError for a
    malformed verdict, an unknown finding (404), or a verdict on a state that is no longer current (409: the finding changed, was closed, or
    was already reviewed in this state)."""
    from django.db import transaction
    from cveFeed import activity, closure, injection_guard
    from cveFeed import triage as triage_lib
    from cveFeed.models import FindingAuditEvent, FindingReview, Triage
    parsed = _parse_verdict(body)
    match = re.fullmatch(r't(\d{1,12})', str(ref or ''))
    if not match:
        raise VerdictError('not found', 404)
    triage = _load(int(match.group(1)))
    if triage is None or triage.finding is None or triage.kind not in KIND_ORDER:
        raise VerdictError('not found', 404)
    if not Triage.objects.filter(open_q(), pk=triage.pk).exists():
        raise VerdictError('the finding is no longer open', 409)
    fingerprint = _fingerprints({(triage.project_id, triage.host)}).get((triage.project_id, triage.host), '')
    key = review_key(triage, fingerprint)
    if parsed['review_key'] != key:
        raise VerdictError('the finding or its host changed since the packet was built', 409)
    if FindingReview.objects.filter(triage=triage, review_key=key).exists():
        raise VerdictError('this state of the finding was already reviewed', 409)
    finding = triage.finding
    d = triage_lib.describe(finding)
    raw = _raw_evidence(triage, finding)
    injection = injection_guard.families(raw, d.get('payload'), d.get('host_context'))
    note = clean_note(parsed['note'])
    if injection_guard.repeats_marker(note, injection_guard.planted_markers(raw, d.get('payload'), d.get('host_context'))):
        injection = sorted(set(injection) | {'echo_marker'})
        note = 'The reviewer\'s note repeated an identifier planted in the evidence and was discarded.'
        parsed['verdict'], parsed['confidence'] = 'uncertain', 'low'
    outcome, held = 'recorded', ''
    if parsed['verdict'] == 'false_positive':
        blocked, held = close_gate(triage.kind, triage, finding, injection)
        if blocked:
            outcome = blocked
        elif parsed['confidence'] != 'high':
            outcome, held = 'held', f"the reviewer's confidence is {parsed['confidence']}, not high"
        elif not settings_row().auto_close:
            outcome, held = 'held', 'closing false positives is turned off in Settings'
        else:
            outcome = 'closed'
    model = parsed['model']
    now = now or timezone.now()
    with transaction.atomic():
        review = FindingReview.objects.create(
            triage=triage, project_id=triage.project_id, review_key=key, verdict=parsed['verdict'], confidence=parsed['confidence'],
            reason_code=parsed['reason_code'], note=note, model=model, outcome=outcome, held_reason=held[:200], injection=injection,
            input_tokens=parsed['input_tokens'], output_tokens=parsed['output_tokens'])
        if outcome == 'closed':
            text = f"{CLOSE_PREFIX} ({model or 'model not reported'}) found this is a false positive. {note}".strip()
            text = closure.clip_note(text)
            before = finding.remediation_status
            finding.remediation_status, finding.remediation_updated_at, finding.remediation_by = 'false_positive', now, None
            finding.remediation_note = text
            finding.save(update_fields=['remediation_status', 'remediation_updated_at', 'remediation_by', 'remediation_note'])
            FindingAuditEvent.objects.create(project_id=triage.project_id, finding_kind=AUDIT_KIND[triage.kind], finding_id=finding.pk,
                                             event='status', actor=None, before={'status': before},
                                             after={'status': 'false_positive', 'note': text, 'by': 'ai_reviewer', 'review_id': review.pk})
    cache.delete(f'cvengine:reviewer:lease:{triage.pk}')
    if outcome == 'closed':
        from agentapi import services
        host = services._host_of(finding)
        if host:
            services._rescore_hosts([host])
        activity.log('remediation', f'AI reviewer closed {triage.kind} finding #{finding.pk} on {triage.host or "?"} as a false positive',
                     project=triage.project, finding_kind=AUDIT_KIND[triage.kind], finding_id=finding.pk, before='open',
                     after='false_positive', note=note[:500], review_id=review.pk)
    elif outcome == 'disputed':
        activity.log('remediation', f'AI reviewer disputes {triage.kind} finding #{finding.pk} on {triage.host or "?"} (kept open: {held})',
                     project=triage.project, finding_kind=AUDIT_KIND[triage.kind], finding_id=finding.pk, review_id=review.pk)
    return {'outcome': outcome, 'reason': held, 'review_id': review.pk}


def review_summary(triage_id):
    """The newest review of a finding, for its page and the API: ``{verdict, confidence, reason_code, note, model, outcome, held_reason,
    at}`` or None."""
    from cveFeed.models import FindingReview
    row = FindingReview.objects.filter(triage_id=triage_id).order_by('-created_at').first()
    if row is None:
        return None
    return {'verdict': row.verdict, 'confidence': row.confidence, 'reason_code': row.reason_code, 'note': row.note, 'model': row.model,
            'outcome': row.outcome, 'held_reason': row.held_reason, 'at': row.created_at.isoformat()}


# --------------------------------------------------------------------------------------------------------------- operations

ACTIONS = {'feed_sentinels': timedelta(minutes=15), 'refresh_nuclei_templates': timedelta(hours=1)}
ACTIVITY_ERROR_PROBLEM = 20     # failed activity lines of one kind in six hours
SENTINEL_FAILED_PROBLEM = 5     # failed or expired Sentinel tasks of one Sentinel and kind in six hours
DRAFT_WAIT = timedelta(days=3)


def _admin():
    from django.contrib.auth.models import User
    return User.objects.filter(is_superuser=True, is_active=True).order_by('id').first()


def installed_templates_version():
    """The nuclei-templates release installed on this server, from nuclei's own config file, or ''."""
    root = os.environ.get('NUCLEI_CONFIG_DIR', '/root/.config/nuclei')
    try:
        with open(os.path.join(root, '.templates-config.json'), encoding='utf-8') as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return ''
    return str(data.get('nuclei-templates-version') or '')[:40] if isinstance(data, dict) else ''


def _check(code, state, title, detail, facts=None, actions=(), severity=None):
    return {'code': code, 'state': state, 'severity': severity or ('critical' if state == 'problem' else 'warning' if state == 'warning' else 'info'),
            'title': title, 'detail': detail, 'facts': facts or {}, 'actions': list(actions)}


def ops_checks(now=None, templates_release=None):
    """The operations checks (docs/AI-REVIEWER.md), from ``system_status`` and the database. ``templates_release`` is the newest
    nuclei-templates release the reviewer container read from GitHub, ``{tag, published_at}``, when it has one."""
    from agentapi.models import SentinelTask
    from agentapi.services import Ctx
    from agentapi.system_status import system_status
    from cveFeed.models import AgentActivity, AIUsage, GeneratedTemplate
    from django.db.models import Count
    now = now or timezone.now()
    admin = _admin()
    status = system_status(Ctx(user=admin)) if admin else {'problems': [], 'system': None}
    system = status.get('system') or {}
    sentinels = system.get('sentinels') or {}
    checks = []

    # Sentinels idle while there is work
    live = int(sentinels.get('live') or 0)
    from cveFeed import coverage_topup
    done_2h = SentinelTask.objects.filter(status='done', finished_at__gte=now - timedelta(hours=2)).count() if live else 0
    queued = sum((sentinels.get('queue') or {}).values()) if live else 0
    backlog = coverage_topup.backlog_exists(now) if live else False
    if live and not done_2h and not queued:
        checks.append(_check('sentinels_idle', 'problem' if backlog else 'warning', 'Sentinels are idle',
                             f'{live} live Sentinel(s) finished no task in the last two hours and none is queued'
                             + (', while hosts still need their first scan.' if backlog else '.'),
                             {'live': live, 'done_2h': done_2h, 'queued': queued, 'backlog': backlog}, actions=('feed_sentinels',)))
    else:
        checks.append(_check('sentinels_idle', 'ok', 'Sentinels are busy', '', {'live': live, 'done_2h': done_2h, 'queued': queued}))

    # nuclei templates
    templates = ((system.get('tools') or {}).get('nuclei_templates')) or {}
    refresh = templates.get('last_refresh') or {}
    installed = installed_templates_version()
    newer = ''
    if isinstance(templates_release, dict) and re.fullmatch(r'v?\d+(?:\.\d+){1,3}', str(templates_release.get('tag') or '')):
        tag = str(templates_release['tag'])
        if installed and tag.lstrip('v') != installed.lstrip('v'):
            newer = tag
    hours = None
    try:
        hours = (now - datetime.fromisoformat(refresh['at'])).total_seconds() / 3600 if refresh.get('at') else None
    except (TypeError, ValueError):
        hours = None
    failed = bool(refresh) and not refresh.get('ok')
    if failed or newer or (hours is not None and hours > 24):
        detail = []
        if failed:
            detail.append(f"The last refresh failed: {str(refresh.get('result') or 'no detail')[:200]}.")
        if hours is not None and hours > 24:
            detail.append(f'No successful refresh for {int(hours)} hours.')
        if newer:
            detail.append(f'nuclei-templates {newer} is out; this server has {installed}.')
        checks.append(_check('nuclei_templates', 'problem' if failed else 'warning', 'nuclei templates are out of date', ' '.join(detail),
                             {'installed': installed, 'latest': newer or installed, 'hours_since_refresh': round(hours or 0, 1), 'failed': failed},
                             actions=('refresh_nuclei_templates',)))
    else:
        checks.append(_check('nuclei_templates', 'ok', 'nuclei templates are current', '', {'installed': installed}))

    # Sentinel task failures, by Sentinel and kind
    six = now - timedelta(hours=6)
    from agentapi import sentinel_broker
    not_waiting = ~sentinel_broker.waiting_q()  # a task that expired waiting for a free slot is back-pressure, counted below, not a failure
    groups = list(SentinelTask.objects.filter(not_waiting, status__in=('failed', 'expired'), finished_at__gte=six)
                  .values('agent__name', 'kind').annotate(n=Count('id')).order_by('-n')[:10])
    bad = [g for g in groups if g['n'] >= SENTINEL_FAILED_PROBLEM]
    if bad:
        samples = {}
        for g in bad[:5]:
            err = (SentinelTask.objects.filter(not_waiting, status__in=('failed', 'expired'), finished_at__gte=six, agent__name=g['agent__name'], kind=g['kind'])
                   .exclude(error='').order_by('-finished_at').values_list('error', flat=True).first())
            samples[f"{g['agent__name']}/{g['kind']}"] = str(err or '')[:200]
        checks.append(_check('sentinel_errors', 'problem', 'Sentinel tasks are failing',
                             '; '.join(f"{g['agent__name'] or 'a Sentinel'}: {g['n']} {g['kind']} task(s) failed or stopped reporting" for g in bad) + '.',
                             {'groups': [{'sentinel': g['agent__name'], 'kind': g['kind'], 'failed': g['n']} for g in bad], 'last_errors': samples}))
    else:
        checks.append(_check('sentinel_errors', 'ok', 'Sentinel tasks succeed', '', {}))
    # tasks that expired only because every Sentinel slot was busy: the targets stay due and are asked again, so a note, never a failure
    held = list(SentinelTask.objects.filter(sentinel_broker.waiting_q(), finished_at__gte=six).values('kind').annotate(n=Count('id')).order_by('-n')[:10])
    waited = sum(r['n'] for r in held)
    if waited >= SENTINEL_FAILED_PROBLEM:
        checks.append(_check('sentinel_waiting', 'warning', 'Sentinel tasks are waiting for a free slot',
                             f"{waited} task(s) waited for a Sentinel slot in the last six hours ({', '.join(str(r['n']) + ' ' + r['kind'] for r in held[:5])}); "
                             'their targets stay due and are asked again. The Sentinels are busy: add one, or give the one you have more slots.',
                             {'waited': waited, 'by_kind': {r['kind']: r['n'] for r in held}}, severity='info'))

    # failed activity lines, by kind
    failed_kinds = list(AgentActivity.objects.filter(status='failed', created_at__gte=six).values('kind').annotate(n=Count('id')).order_by('-n')[:10])
    heavy = [f for f in failed_kinds if f['n'] >= ACTIVITY_ERROR_PROBLEM]
    if heavy:
        samples = {f['kind']: AgentActivity.objects.filter(status='failed', created_at__gte=six, kind=f['kind'])
                   .order_by('-created_at').values_list('message', flat=True).first() for f in heavy[:5]}
        checks.append(_check('scan_errors', 'problem', 'Scans and tasks are failing',
                             '; '.join(f"{f['n']} failed {f['kind']} line(s)" for f in heavy) + ' in the last six hours.',
                             {'kinds': {f['kind']: f['n'] for f in heavy}, 'last_messages': {k: str(v or '')[:200] for k, v in samples.items()}}))
    else:
        checks.append(_check('scan_errors', 'ok', 'Scans and tasks succeed', '', {}))

    # what system_status itself reports
    problems = [str(p)[:300] for p in (status.get('problems') or [])][:20]
    checks.append(_check('system', 'problem' if problems else 'ok', 'cvENGINE reports problems' if problems else 'cvENGINE reports no problems',
                         '\n'.join(problems), {'problems': problems}))

    # AI-written templates waiting for a person
    drafts = GeneratedTemplate.objects.filter(status=GeneratedTemplate.STATUS_DRAFT, created_at__lte=now - DRAFT_WAIT).count()
    checks.append(_check('generated_templates', 'warning' if drafts else 'ok', 'AI-written nuclei templates wait for review',
                         f'{drafts} draft template(s) have waited more than three days for a person to review them.' if drafts else '',
                         {'waiting': drafts}, severity='info'))

    # AI calls failing
    ai_failed = list(AIUsage.objects.filter(status='failed', started_at__gte=now - timedelta(days=1))
                     .values('error_category').annotate(n=Count('id')).order_by('-n')[:8])
    total = sum(r['n'] for r in ai_failed)
    checks.append(_check('ai_errors', 'warning' if total >= 10 else 'ok', 'AI calls are failing',
                         ', '.join(f"{r['n']} {r['error_category'] or 'unknown'}" for r in ai_failed) + ' in the last 24 hours.' if total >= 10 else '',
                         {'by_category': {r['error_category'] or 'unknown': r['n'] for r in ai_failed}}))
    return checks


def _digest(check):
    keep = {k: v for k, v in (check.get('facts') or {}).items() if k not in ('last_errors', 'last_messages', 'hours_since_refresh', 'done_2h')}
    return hashlib.sha1(json.dumps([check['code'], check['state'], keep], sort_keys=True, default=str).encode()).hexdigest()


def sync_alerts(checks, now=None):
    """Open, refresh or resolve one ``AdminAlert`` per check code: a check that is not ``ok`` keeps its alert open (with the newest facts),
    an ``ok`` one resolves it. Returns ``{opened, resolved}``."""
    from cveFeed.models import AdminAlert
    now = now or timezone.now()
    opened = resolved = 0
    for check in checks:
        alert = AdminAlert.objects.filter(code=check['code'], resolved_at__isnull=True).first()
        if check['state'] == 'ok':
            if alert:
                alert.resolved_at = now
                alert.save(update_fields=['resolved_at'])
                resolved += 1
            continue
        digest = _digest(check)
        if alert is None:
            AdminAlert.objects.create(code=check['code'], severity=check['severity'], title=check['title'][:200], detail=check['detail'][:4000],
                                      facts=check['facts'], digest=digest, first_seen=now, last_seen=now)
            opened += 1
        else:
            alert.severity, alert.title, alert.detail, alert.facts, alert.digest, alert.last_seen = (
                check['severity'], check['title'][:200], check['detail'][:4000], check['facts'], digest, now)
            alert.save(update_fields=['severity', 'title', 'detail', 'facts', 'digest', 'last_seen'])
    return {'opened': opened, 'resolved': resolved}


def run_ops_checks(now=None):
    """The half-hourly deterministic pass: compute the checks and bring the alerts up to date (no AI involved)."""
    checks = ops_checks(now)
    return sync_alerts(checks, now)


def snapshot(now=None, templates_release=None):
    checks = ops_checks(now, templates_release)
    return {'at': (now or timezone.now()).isoformat(), 'checks': checks,
            'actions': {name: f'at most once every {int(gap.total_seconds() // 60)} minutes' for name, gap in ACTIONS.items()}}


def _run_action(name):
    from cveFeed import tasks
    if name == 'feed_sentinels':
        tasks.feed_sentinels.apply_async()
    elif name == 'refresh_nuclei_templates':
        tasks.update_nuclei_templates.apply_async()


# The reviewer container's own two jobs call the model themselves, so it tells the server about each call (this route) and the usage page
# names them: a refused review is then a number, not a log line in the container. Counts and outcome only, never text.
USAGE_STAGES = ('finding_review', 'operations_check')
_USAGE_CATEGORIES = {'auth': 'provider_auth', 'rate_limit': 'provider_rate_limit', 'http': 'provider_http', 'network': 'provider_network',
                     'shape': 'provider_shape', 'truncated': 'output_truncated', 'refused': 'refused', 'model': 'provider_error'}


def record_usage(body, now=None):
    """Take one call report from the container: ``{stage, provider, model, status, category, stop_reason, input_tokens, output_tokens,
    duration_ms}``. One AIUsage row. Raises VerdictError for a stage that is not one of the container's own two jobs."""
    import re
    from cveFeed import ai_jobs
    from cveFeed.models import AIUsage
    if not isinstance(body, dict) or body.get('stage') not in USAGE_STAGES:
        raise VerdictError('stage must be one of ' + ', '.join(USAGE_STAGES))
    status = 'succeeded' if body.get('status') == 'succeeded' else 'failed'
    category = '' if status == 'succeeded' else str(body.get('category') or '')
    category = _USAGE_CATEGORIES.get(category, category)
    if status == 'failed' and category not in ai_jobs.CATEGORIES:
        category = 'unexpected_error'
    model = str(body.get('model') or '')
    stop = str(body.get('stop_reason') or '')

    def count(name, ceiling=10_000_000):
        try:
            value = int(body.get(name))
        except (TypeError, ValueError):
            return None
        return value if 0 <= value <= ceiling else None
    now = now or timezone.now()
    AIUsage.objects.create(
        provider=re.sub(r'[^a-z0-9_-]', '', str(body.get('provider') or '').lower())[:32], model=model[:200] if ai_jobs.MODEL_NAME.match(model) else '',
        stage=body['stage'], status=status, error_category=category, stop_reason=stop[:24] if re.fullmatch(r'[a-z_]{1,24}', stop) else '',
        input_tokens=count('input_tokens'), output_tokens=count('output_tokens'), duration_ms=count('duration_ms', 24 * 3600 * 1000), started_at=now)
    return {'recorded': True}


def apply_ops_report(body, now=None):
    """Take the operations job's report: ``{alerts: [{code, severity, diagnosis}], actions: [names], model, templates_release}``. The
    checks are computed again here; a diagnosis is kept only for a check that is not ``ok``, and an action runs only when that check offers
    it now and its interval has passed. Returns ``{alerts_updated, actions_run, actions_refused}``."""
    from cveFeed import activity
    from cveFeed.models import AdminAlert
    if not isinstance(body, dict):
        raise VerdictError('body must be a JSON object')
    now = now or timezone.now()
    release = body.get('templates_release') if isinstance(body.get('templates_release'), dict) else None
    checks = ops_checks(now, release)
    sync_alerts(checks, now)
    by_code = {c['code']: c for c in checks}
    model = str(body.get('model') or '')[:100]
    updated = 0
    for item in (body.get('alerts') or [])[:20] if isinstance(body.get('alerts'), list) else []:
        if not isinstance(item, dict):
            continue
        check = by_code.get(item.get('code'))
        if not check or check['state'] == 'ok':
            continue
        alert = AdminAlert.objects.filter(code=check['code'], resolved_at__isnull=True).first()
        if alert is None:
            continue
        alert.ai_detail, alert.ai_model = clean_note(item.get('diagnosis'))[:NOTE_MAX], model
        if item.get('severity') in ('info', 'warning', 'critical') and check['state'] != 'problem':
            alert.severity = item['severity'] if item['severity'] != 'critical' else 'warning'  # only a problem the server sees is critical
        alert.save(update_fields=['ai_detail', 'ai_model', 'severity'])
        updated += 1
    ran, refused = [], []
    offered = {a for c in checks if c['state'] != 'ok' for a in c['actions']}
    for name in (body.get('actions') or [])[:5] if isinstance(body.get('actions'), list) else []:
        if name not in ACTIONS or name not in offered:
            refused.append(str(name)[:40])
            continue
        if not cache.add(f'cvengine:reviewer:action:{name}', 1, int(ACTIONS[name].total_seconds())):
            refused.append(name)
            continue
        _run_action(name)
        ran.append(name)
        activity.log('run_check', f'AI reviewer started {name.replace("_", " ")}', action=name)
    row = settings_row()
    row.last_ops_at = now
    row.save(update_fields=['last_ops_at', 'updated_at'])
    return {'alerts_updated': updated, 'actions_run': ran, 'actions_refused': refused}


def open_alerts(user=None):
    """The open alerts an App Admin sees: not resolved, and not dismissed unless the problem changed since."""
    from cveFeed.models import AdminAlert
    rows = AdminAlert.objects.filter(resolved_at__isnull=True).order_by('-last_seen')[:20]
    out = []
    for a in rows:
        if a.dismissed_at and a.dismissed_digest == a.digest:
            continue
        out.append({'id': a.pk, 'code': a.code, 'severity': a.severity, 'title': a.title, 'detail': a.detail, 'ai_detail': a.ai_detail,
                    'ai_model': a.ai_model, 'first_seen': a.first_seen.isoformat(), 'last_seen': a.last_seen.isoformat()})
    return out


def dismiss_alert(alert_id, user, now=None):
    from cveFeed.models import AdminAlert
    alert = AdminAlert.objects.filter(pk=alert_id, resolved_at__isnull=True).first()
    if alert is None:
        return False
    alert.dismissed_at, alert.dismissed_by, alert.dismissed_digest = now or timezone.now(), user, alert.digest
    alert.save(update_fields=['dismissed_at', 'dismissed_by', 'dismissed_digest'])
    return True
