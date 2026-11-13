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
import secrets
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone as dt_timezone

from django.core.cache import cache
from django.db.models import Q
from django.utils import timezone

from cveFeed import maintainer_checks

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
WINDOW = 400  # candidates read per page while looking for the ones not yet reviewed in their current state (the pages go on until the limit is found or none are left)
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
    """The AI provider the reviewer may use: the pipeline's own (``ai_jobs.provider_row``), so a row with no key or no server address is none."""
    from cveFeed import ai_jobs
    return ai_jobs.provider_row()


def _any_provider():
    from dashboard.models import AIProviderSettings
    return AIProviderSettings.objects.filter(enabled=True).exists()


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


def _ops_tried_since(since):
    """Whether the container reported a call of the operations job at or after ``since`` (any outcome; a cut-off it then retried inside the
    same attempt is not a try of its own). ``record_usage`` keeps them in the database, so this holds across a container restart."""
    from cveFeed.models import AIUsage
    return AIUsage.objects.filter(stage='operations_check', started_at__gte=since).exclude(error_category='truncated_retried').exists()


def ops_due(row, now=None):
    """Whether the operations job should run now: a scheduled UTC hour has passed since it last reported."""
    now = now or timezone.now()
    last = row.last_ops_at
    if _ops_tried_since(now - OPS_RETRY_WAIT):
        return False  # a try in the last hour, whatever came of it (and whether or not the container restarted since): once an hour, a paid call
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


REFUSED = 'refused'  # FindingReview.outcome of a review the model did not answer (refused, empty, cut off, unusable): no verdict
REFUSED_WAIT = timedelta(hours=24)  # how long such a finding waits before it is asked again, when its host does not change meanwhile
OPS_RETRY_WAIT = timedelta(hours=1)  # a failed operations job runs again after this at the earliest


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
                      'turned off in Settings' if not row.enabled else ('no AI provider is configured' if not _any_provider() else 'the AI provider has no key or server address') if not provider else
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


def _reviewed(triages, fingerprints):
    """``{(project id, host, review key): [(outcome, created_at), ...]}`` of the reviews that already hold the current key of each of these
    findings. Looked up by the key, not by the Triage row: a rescan makes a new row for the same finding (same kind, evidence key and host
    state, so the same key), and that copy is not asked about again."""
    from cveFeed.models import FindingReview
    keys = {review_key(t, fingerprints.get((t.project_id, t.host), '')) for t in triages}
    out = {}
    for row in (FindingReview.objects.filter(review_key__in=keys).order_by('-created_at', '-id')
                .values('review_key', 'outcome', 'created_at', 'triage__project_id', 'triage__host')):
        out.setdefault((row['triage__project_id'], row['triage__host'], row['review_key']), []).append((row['outcome'], row['created_at']))
    return out


def due(limit=PACKET_LIMIT, now=None):
    """Up to ``limit`` ``(triage, review_key)`` pairs to review now: open findings whose current key has no review, CVE matches first.
    Each project with open findings gets an equal share of the batch (what one has too little of goes to the others), so a large project
    cannot take the whole of the daily cap while another has work."""
    from cveFeed.models import Triage
    projects = sorted(Triage.objects.filter(open_q()).exclude(kind='route_auth').order_by().values_list('project_id', flat=True).distinct())
    now = now or timezone.now()
    picked, active = [], list(projects)
    while active and len(picked) < limit:
        share = max(1, -(-(limit - len(picked)) // len(active)))
        full = []
        for project_id in active:
            got = _due_in(project_id, min(share, limit - len(picked)), now)
            picked += got
            if len(got) >= share:
                full.append(project_id)  # it may have more
            if len(picked) >= limit:
                break
        active = full
    return picked


def _due_in(project_id, limit, now):
    """``due`` for one project. The open findings are read in pages of WINDOW in that order until ``limit`` are found or none are left, so a
    finding is reached however many reviewed ones come before it."""
    from django.db.models import Case, IntegerField, Value, When
    from cveFeed.models import Triage
    rank = Case(*[When(kind=k, then=Value(v)) for k, v in KIND_ORDER.items()], default=Value(9), output_field=IntegerField())
    qs = (Triage.objects.filter(open_q(), project_id=project_id).exclude(kind='route_auth').annotate(kind_rank=rank).order_by('kind_rank', '-last_seen', '-id')
          .only('id', 'kind', 'project_id', 'host', 'evidence_key', 'signature'))
    picked = []
    offset = 0
    while len(picked) < limit:
        rows = list(qs[offset:offset + WINDOW])
        if not rows:
            break
        offset += WINDOW
        fingerprints = _fingerprints({(t.project_id, t.host) for t in rows})
        seen_all = _reviewed(rows, fingerprints)
        for triage in rows:
            key = review_key(triage, fingerprints.get((triage.project_id, triage.host), ''))
            seen = seen_all.get((triage.project_id, triage.host, key), [])
            if seen and not (all(outcome == REFUSED for outcome, _ in seen) and now - seen[0][1] >= REFUSED_WAIT):
                continue  # reviewed in this state; a refused or empty review is asked again only after a day (or when the host changes)
            if not cache.add(f'cvengine:reviewer:lease:{triage.pk}', key, LEASE_SECONDS):
                continue  # handed out within the last 15 minutes
            picked.append((triage.pk, key))
            if len(picked) >= limit:
                break
    return picked


def _raw_evidence(triage, finding):
    """What the scanner stored about the host for this finding, for the injection scan (never sent to the model)."""
    out = [triage.validation_evidence, triage.hard_evidence,  # the wording of a hard-evidence line and of a check label can quote the host or a template
           [step.get('label') for step in (triage.validation_steps or []) if isinstance(step, dict)]]
    if triage.kind == 'cve_match':
        out.append(finding.evidence)
    elif triage.kind == 'hygiene':
        out += [finding.evidence, finding.detail]
    else:
        out += [getattr(finding, 'response', None), getattr(finding, 'extracted_results', None), getattr(finding, 'matcher_name', None)]
    return out


def _copies(kind, finding):
    """The ids of the earlier copies of this finding (a rescan makes a new row for the same finding and carries its status over, but not the
    comments and audit events kept by the old row's id): the rows of the same project, host, kind and evidence key, and, for a CVE match, the
    ones its triage was carried from (``Triage.carried_from``). Empty when it has no triage row."""
    from cveFeed.models import Triage
    triage = getattr(finding, 'triage', None)
    if triage is None:
        return []
    column = {'cve_match': 'match_id', 'hygiene': 'hygiene_id'}.get(kind, 'vulnerability_id')
    ids = set()
    if triage.evidence_key:
        ids |= set(Triage.objects.filter(project_id=triage.project_id, host=triage.host, kind=kind, evidence_key=triage.evidence_key)
                   .exclude(**{column: None}).values_list(column, flat=True)[:50])
    seen, match_id = set(), triage.carried_from if kind == 'cve_match' else None
    for _ in range(6):
        if not match_id or match_id in seen:
            break
        seen.add(match_id)
        ids.add(match_id)
        match_id = Triage.objects.filter(match_id=match_id).values_list('carried_from', flat=True).first()
    ids.discard(finding.pk)
    return sorted(ids)


def worked_by_person(kind, finding):
    """Whether a person has worked this finding: a status other than open, an assignee, a remediation date or owner, a comment, a status
    change or heat set by hand, or (for a CVE match) a manual validation request, on this copy of it or on an earlier copy a rescan replaced
    (``_copies``). Such a finding is never closed automatically: a person's work wins."""
    from cveFeed.models import FindingAuditEvent, FindingComment, OnDemandValidation
    audit_kind = AUDIT_KIND.get(kind, kind)
    if finding.remediation_status != 'open' or getattr(finding, 'assignee_id', None) or getattr(finding, 'remediation_by_id', None):
        return True
    ids = [finding.pk] + _copies(kind, finding)
    if FindingComment.objects.filter(finding_kind=audit_kind, finding_id__in=ids).exists():
        return True
    if FindingAuditEvent.objects.filter(finding_kind=audit_kind, finding_id__in=ids, actor__isnull=False).exists():
        return True
    triage = getattr(finding, 'triage', None)
    if triage is not None and triage.heat_override:
        return True
    return kind == 'cve_match' and OnDemandValidation.objects.filter(match_id__in=ids, source='manual').exists()


def proof(kind, triage, finding):
    """Why this finding cannot be a false positive in cvENGINE's own eyes, or '': hard evidence about this host."""
    from cveFeed import match_policy
    if triage.retest_state == 'still_reproduces':
        return 'a retest after it was marked fixed reproduced it again'  # reopened by a check that ran: no verdict of the model undoes that
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


def floor_hold(kind, facts):
    """Why the triage's own floor (``triage.hard_evidence``) keeps this finding from being closed by a model, or ''. The rule is the
    triage's, "a model may clear a finding only when the evidence sets no floor", and it is read from there, not copied: a scanner finding
    with any floor (a template matcher that fired, a CVE template, a medium or higher rating) and a CVE match with any floor (a version
    inside the affected range, unless the triage itself finds concrete grounds in ``closure_basis`` or a patched distribution release; an
    advisory with no version bound) are for a person or a published range, never for the model. A database exposure is held the same way (its floor is set
    whether or not the service answered). Hygiene findings are judged by ``proof`` and the reviewer's own rules."""
    from cveFeed import triage as triage_lib
    floor, found = triage_lib.hard_evidence(kind, facts or {})
    if floor and kind in ('nuclei', 'cve_match', 'db_exposure'):
        return '; '.join(found)
    return ''


def close_gate(kind, triage, finding, injection, facts=None):
    """``(outcome if not closable, reason)``: ``('', '')`` when the server may close this finding as a false positive. ``facts`` is the
    finding's ``triage.describe`` facts (what the floors read)."""
    reason = proof(kind, triage, finding)
    if reason:
        return 'disputed', reason
    reason = floor_hold(kind, facts)
    if reason:
        return 'held', 'hard evidence: ' + reason
    if worked_by_person(kind, finding):
        return 'held', 'a person has worked this finding'
    if injection:
        return 'held', 'its evidence carries text aimed at AI agents (' + ', '.join(injection) + ')'
    if kind in ('nuclei', 'db_exposure', 'bbot') and (finding.severity or 0) >= CRITICAL:
        return 'held', 'a critical scanner finding is closed by a person'
    return '', ''


PRIOR_CAP = 50  # the most hosts a prior counts (it is shown as a number to the model and to a person)
OTHER_HOSTS_SAID_REAL = 'of the same evidence on other hosts said it is real'  # the end of the held reason of ``other_hosts_hold`` (the ranking and the page match on it)


def same_evidence_prior(triage):
    """``(hosts that said real, hosts that said false positive)``: how the AI reviewer judged the same question on OTHER hosts of the same project.
    The same question is the finding's kind and its ``evidence_key`` (the asset evidence of ``triage.evidence_key_for``: the CVE or check, the
    product and version, the matcher; never the host, and not the review key either, which also carries the host's state). Counted over the
    project only (never across projects or organizations: what one tenant's hosts said is not another tenant's business), from reviews that
    count: not refused, no planted text in the evidence, a real verdict or a false positive. One host counts once. Zero for both when the
    finding has no evidence key. One indexed query (``triage_proj_kind_evkey_idx``)."""
    from django.db.models import Count
    from cveFeed.models import FindingReview
    if not triage.evidence_key:
        return 0, 0
    rows = (FindingReview.objects.filter(project_id=triage.project_id, triage__project_id=triage.project_id, triage__kind=triage.kind,
                                         triage__evidence_key=triage.evidence_key, injection=[])
            .exclude(triage__host=triage.host).exclude(outcome=REFUSED)
            .aggregate(real=Count('triage__host', distinct=True, filter=Q(verdict__startswith='true_')),
                       fp=Count('triage__host', distinct=True, filter=Q(verdict='false_positive'))))
    return min(rows['real'] or 0, PRIOR_CAP), min(rows['fp'] or 0, PRIOR_CAP)


def prior_line(real, false_positive):
    """The prior as one line of cvENGINE's own words (numbers only, no host names), or '' when no other host was judged."""
    if not real and not false_positive:
        return ''
    return (f'the same evidence was judged real on {real} other host{"" if real == 1 else "s"}, '
            f'false positive on {false_positive} (earlier reviews, for consistency; judge this finding on its own evidence)')


def other_hosts_hold(real):
    """The held reason when earlier reviews of the same evidence on other hosts said it is real, or ''."""
    return f'{real} earlier review{"" if real == 1 else "s"} {OTHER_HOSTS_SAID_REAL}' if real else ''


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
    blocked, why = close_gate(kind, triage, finding, injection, d.get('facts'))
    heat, heat_reason = _heat(kind, finding)
    prior = prior_line(*same_evidence_prior(triage))  # cvENGINE's own count of earlier verdicts: numbers, no host names, nothing the host wrote
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
            **({'same_evidence_on_other_hosts': prior} if prior else {}),
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


DIAGNOSIS_MIN_WORDS = 3  # a diagnosis says what is wrong and what to do: fewer than three words is not one


def clean_note(text):
    """A model's note as stored: cleaned like a person's closure note, no markup characters, no links, at most NOTE_MAX characters."""
    from cveFeed import closure
    text = closure.clip_note(text if isinstance(text, str) else '', NOTE_MAX) or ''
    text = _LINK.sub('[link removed]', _MARKUP.sub('', text))
    return re.sub(r'[ \t]+', ' ', text).strip()[:NOTE_MAX]


def usable_note(text, min_words=2):
    """``clean_note(text)`` when it is a real note (``min_words`` words or more and not filler, ``cveFeed.filler``), else the empty string: the interface
    shows the reviewer's line only when there is something in it."""
    from cveFeed.filler import is_placeholder
    note = clean_note(text)
    return note if len(note.split()) >= min_words and not is_placeholder(note) else ''


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


def _lock(triage):
    """Lock the row of the finding and of its triage until the surrounding transaction ends, and return the triage read again under the lock
    (with its finding): what a person saved a moment ago is in it. Call inside ``transaction.atomic``."""
    from cveFeed.models import Triage
    finding = triage.finding
    if finding is not None:
        type(finding).objects.select_for_update().filter(pk=finding.pk).first()
    Triage.objects.select_for_update().filter(pk=triage.pk).first()
    return _load(triage.pk)


def apply_verdict(ref, body, now=None):
    """Take one verdict for the finding ``ref`` (``t<triage id>``). Returns ``{outcome, reason, review_id}``. Raises VerdictError for a
    malformed verdict, an unknown finding (404), or a verdict on a state that is no longer current (409: the finding changed, was closed, or
    was already reviewed in this state)."""
    parsed = _parse_verdict(body)
    match = re.fullmatch(r't(\d{1,12})', str(ref or ''))
    if not match:
        raise VerdictError('not found', 404)
    triage = _load(int(match.group(1)))
    if triage is None or triage.finding is None or triage.kind not in KIND_ORDER:
        raise VerdictError('not found', 404)
    fingerprint = _fingerprints({(triage.project_id, triage.host)}).get((triage.project_id, triage.host), '')
    key = review_key(triage, fingerprint)
    if parsed['review_key'] != key:
        raise VerdictError('the finding or its host changed since the packet was built', 409)
    return apply_finding_verdict(triage, parsed, key, now=now)


HOST_DECIDES = 'the host review does not close findings by itself: a person decides'  # held reason: a host review's false positive while ReviewerSettings.host_review_auto_close is off
CONTRADICTS = 'contradicts the earlier verdict on this state'  # held reason: a host review would close what an earlier review called real


def apply_finding_verdict(triage, parsed, key, host_review=None, extra_injection=(), extra_markers=(), now=None):
    """The shared core of ``apply_verdict``: apply the parsed verdict ``parsed`` (``_parse_verdict``'s shape) for ``triage``, whose current
    ``review_key`` is ``key``, under the row lock and through ``close_gate``. The finding review calls it with a verdict of the container; the
    host review (``cveFeed.host_review``) calls it once per finding with ``host_review`` set (the row is linked to the ``HostReview``). Then a
    person's work, hard evidence and planted instructions hold a closure exactly as they do for a single finding. ``extra_injection`` is the
    families of AI-directed text found elsewhere in the host's evidence (the host's banners and pages): they hold the closure too, and
    ``extra_markers`` are identifiers planted there, which a note must not repeat. A host review is not "the same state reviewed once": a newer
    review of a state that has one is allowed (the newest row is the current one). Raises VerdictError like ``apply_verdict``."""
    from django.db import transaction
    from cveFeed import activity, closure, injection_guard
    from cveFeed import triage as triage_lib
    from cveFeed.models import FindingAuditEvent, FindingReview, Triage
    model = parsed['model']
    now = now or timezone.now()
    with transaction.atomic():
        # The finding's row is locked for the rest of the verdict: a person's change (status, assignee, comment) that is being saved now
        # either finished before this read, so the gate below sees it and holds the closure, or waits until this verdict is done. A verdict
        # can never overwrite a change made between the check and the save.
        triage = _lock(triage)
        if triage is None or triage.finding is None:
            raise VerdictError('not found', 404)
        if not Triage.objects.filter(open_q(), pk=triage.pk).exists():
            raise VerdictError('the finding is no longer open', 409)
        if host_review is None and FindingReview.objects.filter(triage=triage, review_key=key).exclude(outcome=REFUSED).exists():
            raise VerdictError('this state of the finding was already reviewed', 409)
        finding = triage.finding
        d = triage_lib.describe(finding)
        raw = _raw_evidence(triage, finding)
        injection = sorted(set(injection_guard.families(raw, d.get('payload'), d.get('host_context'))) | set(extra_injection))
        note = usable_note(parsed['note'], min_words=2)  # filler ("Placeholder") is no reason: the verdict stands, with no note
        if injection_guard.repeats_marker(note, injection_guard.planted_markers(raw, d.get('payload'), d.get('host_context')) | set(extra_markers)):
            injection = sorted(set(injection) | {'echo_marker'})
            note = 'The reviewer\'s note repeated an identifier planted in the evidence and was discarded.'
            parsed['verdict'], parsed['confidence'] = 'uncertain', 'low'
        outcome, held = 'recorded', ''
        if parsed['verdict'] == 'false_positive':
            blocked, held = close_gate(triage.kind, triage, finding, injection, d.get('facts'))
            if blocked:
                outcome = blocked
            elif parsed['confidence'] != 'high':
                outcome, held = 'held', f"the reviewer's confidence is {parsed['confidence']}, not high"
            elif not settings_row().auto_close:
                outcome, held = 'held', 'closing false positives is turned off in Settings'
            else:
                outcome = 'closed'
        if outcome == 'closed' and host_review is not None:
            # a host review is a newer look at a state that may already have a verdict (the finding reviewer's, an earlier host review's, a person's
            # "Review now"): it may not undo a real verdict on the same evidence, so asking again is never another roll at closing the finding
            # ANY earlier real verdict on this evidence holds it, not only the newest: an opinion recorded in between must not hide it
            if FindingReview.objects.filter(triage=triage, review_key=key, verdict__startswith='true_').exclude(outcome=REFUSED).exclude(host_review=host_review).exists():
                outcome, held = 'held', CONTRADICTS
        if outcome == 'closed':
            # the same question asked of another host of this project came out real: a closure that would make two hosts with the same evidence
            # disagree waits for a person (real always stands: the other direction changes nothing)
            real, _ = same_evidence_prior(triage)
            if real:
                outcome, held = 'held', other_hosts_hold(real)
        if outcome == 'closed' and host_review is not None and not settings_row().host_review_auto_close:
            # persuasion cannot be fully detected: in 1.4.0 a host review's false positive is a recorded opinion, and a person closes it (one click on the host card),
            # unless an administrator switched this on
            outcome, held = 'held', HOST_DECIDES
        review = FindingReview.objects.create(
            triage=triage, project_id=triage.project_id, review_key=key, verdict=parsed['verdict'], confidence=parsed['confidence'],
            reason_code=parsed['reason_code'], note=note, model=model, outcome=outcome, held_reason=held[:200], injection=injection,
            input_tokens=parsed['input_tokens'], output_tokens=parsed['output_tokens'], host_review=host_review)
        if outcome == 'closed':
            text = f"{CLOSE_PREFIX} ({model or 'model not reported'}) found this is a false positive. {note}".strip()
            text = closure.clip_note(text)
            before = finding.remediation_status
            finding.remediation_status, finding.remediation_updated_at, finding.remediation_by = 'false_positive', now, None
            finding.remediation_note = text
            finding.save(update_fields=['remediation_status', 'remediation_updated_at', 'remediation_by', 'remediation_note'])
            FindingAuditEvent.objects.create(project_id=triage.project_id, finding_kind=AUDIT_KIND[triage.kind], finding_id=finding.pk,
                                             event='status', actor=None, before={'status': before},
                                             after={'status': 'false_positive', 'note': text, 'by': 'ai_reviewer', 'review_id': review.pk,
                                                    **({'host_review_id': host_review.pk} if host_review is not None else {})})
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
    return {'outcome': outcome, 'reason': held, 'review_id': review.pk, 'echo_marker': 'echo_marker' in injection}


def record_refusal(ref, body, now=None):
    """Take the container's report that the model gave no usable answer for the finding ``ref`` (``{review_key, category, model}``): it
    refused, answered with nothing, was cut off twice or answered outside the schema. One ``FindingReview`` row with outcome ``refused`` and
    no verdict is kept, so the call counts against the daily cap and ``due`` leaves the finding alone until its host changes or a day passes.
    Idempotent per finding and state: a second report for the same state inside 24 hours returns the first one's answer and adds no
    row; a state that has a real verdict takes no refusal (409); no more rows than the daily cap are kept (429). Raises VerdictError like
    ``apply_verdict`` (404 unknown finding, 409 a state that is no longer current)."""
    from django.db import transaction
    from cveFeed.models import FindingReview, Triage
    if not isinstance(body, dict):
        raise VerdictError('body must be a JSON object')
    key = body.get('review_key')
    if not isinstance(key, str) or not re.fullmatch(r'[0-9a-f]{40}', key):
        raise VerdictError('review_key must be the key of the packet')
    match = re.fullmatch(r't(\d{1,12})', str(ref or ''))
    triage = _load(int(match.group(1))) if match else None
    if triage is None or triage.finding is None or triage.kind not in KIND_ORDER:
        raise VerdictError('not found', 404)
    category = re.sub(r'[^a-z_]', '', str(body.get('category') or '').lower())[:40] or 'no_answer'
    now = now or timezone.now()
    with transaction.atomic():
        triage = _lock(triage)  # two reports of the same finding at once take turns: the second one finds the first one's row
        if triage is None or triage.finding is None:
            raise VerdictError('not found', 404)
        if not Triage.objects.filter(open_q(), pk=triage.pk).exists():
            raise VerdictError('the finding is no longer open', 409)
        fingerprint = _fingerprints({(triage.project_id, triage.host)}).get((triage.project_id, triage.host), '')
        if key != review_key(triage, fingerprint):
            raise VerdictError('the finding or its host changed since the packet was built', 409)
        rows = list(FindingReview.objects.filter(triage=triage, review_key=key).order_by('-created_at', '-id'))
        if any(row.outcome != REFUSED for row in rows):
            raise VerdictError('this state of the finding was already reviewed', 409)  # a real verdict stands: no refusal after it
        if rows and now - rows[0].created_at < REFUSED_WAIT:
            return {'outcome': REFUSED, 'reason': rows[0].held_reason, 'review_id': rows[0].pk}  # the same report again: the same answer, no new row
        if reviews_today(now) >= settings_row().review_daily_max:
            raise VerdictError('the daily limit of reviews is used up', 429)
        review = FindingReview.objects.create(triage=triage, project_id=triage.project_id, review_key=key, verdict='', confidence='low',
                                              outcome=REFUSED, held_reason=category, model=str(body.get('model') or '')[:100])
    cache.delete(f'cvengine:reviewer:lease:{triage.pk}')
    return {'outcome': REFUSED, 'reason': category, 'review_id': review.pk}


VERDICT_WORDS = {
    'false_positive': 'The AI reviewer thinks this is a false positive.',
    'true_open': 'The AI reviewer thinks this is real and still open.',
    'true_in_progress': 'The AI reviewer thinks this is real and is being worked on.',
    'true_fixed': 'The AI reviewer thinks this is real but already fixed.',
    'true_accepted_risk': 'The AI reviewer thinks this is real and the risk is accepted.',
    'uncertain': 'The AI reviewer could not decide.',
}
REAL_VERDICTS = tuple(v for v in VERDICTS if v.startswith('true_'))


def outcome_words(outcome, held_reason=''):
    """What the server did with a verdict, as a sentence for a person (``FindingReview.outcome``)."""
    if outcome == 'closed':
        return 'cvENGINE closed this finding as a false positive because the verdict was high confidence and nothing stood against it.'
    if outcome == 'disputed':
        return ('The finding was kept open because cvENGINE has hard evidence that it is real' + (f' ({held_reason})' if held_reason else '')
                + '. A person should look at it.')
    if outcome == 'held':
        if held_reason == 'a person has worked this finding':
            return 'The finding was kept open because a person has already worked on it. The AI reviewer does not overrule a person.'
        return f"The finding was kept open: {held_reason or 'the verdict did not meet the rules for closing'}. A person should look at it."
    return 'The opinion is recorded; nothing was changed on the finding.'


def _summary_of(row):
    """The plain form of one FindingReview row. ``disputed`` is true when the reviewer called the finding a false positive and the server did
    not close it: the cases a person should look at. Every text field is stored already cleaned (``clean_note``) and is shown as text."""
    return {'verdict': row.verdict, 'confidence': row.confidence, 'reason_code': row.reason_code, 'note': row.note, 'model': row.model,
            'outcome': row.outcome, 'held_reason': row.held_reason, 'at': row.created_at.isoformat(),
            'verdict_text': VERDICT_WORDS.get(row.verdict, row.verdict), 'outcome_text': outcome_words(row.outcome, row.held_reason),
            'disputed': row.verdict == 'false_positive' and row.outcome != 'closed', 'says_real': row.verdict in REAL_VERDICTS}


def review_summaries(triage_ids):
    """``{triage id: summary}`` of the newest review of each of these findings (one query), for the list and the detail."""
    from cveFeed.models import FindingReview
    out = {}
    ids = [i for i in triage_ids if i]
    if not ids:
        return out
    # newest first per finding; Postgres keeps the first row of each triage_id (DISTINCT ON), so the history is not loaded
    for row in (FindingReview.objects.filter(triage_id__in=ids).exclude(outcome=REFUSED).order_by('triage_id', '-created_at', '-id')
                .distinct('triage_id')):
        out[row.triage_id] = _summary_of(row)
    return out


def review_summary(triage_id):
    """The newest review of a finding, for its page and the API (``_summary_of``), or None."""
    return review_summaries([triage_id]).get(triage_id)


def newest_review_q(prefix=''):
    """The newest review's verdict, outcome, confidence and held reason of a finding as subquery annotations, ``review_verdict``,
    ``review_outcome``, ``review_confidence`` and ``review_held`` (``prefix`` reaches the Triage row's id from the finding: ``triage__``)."""
    from django.db.models import CharField, IntegerField, JSONField, OuterRef, Subquery
    from cveFeed.models import FindingReview
    newest = FindingReview.objects.filter(triage_id=OuterRef(prefix + 'id')).exclude(outcome=REFUSED).order_by('-created_at', '-id')
    return {'review_host': Subquery(newest.values('host_review_id')[:1], output_field=IntegerField()),
            'review_verdict': Subquery(newest.values('verdict')[:1], output_field=CharField()),
            'review_outcome': Subquery(newest.values('outcome')[:1], output_field=CharField()),
            'review_confidence': Subquery(newest.values('confidence')[:1], output_field=CharField()),
            'review_held': Subquery(newest.values('held_reason')[:1], output_field=CharField()),
            'review_injection': Subquery(newest.values('injection')[:1], output_field=JSONField())}


def newest_review_row_q(prefix=''):
    """The newest review of a finding as one subquery annotation, ``review_row`` (a JSON object of the fields ``_summary_of`` shows) and
    ``review_at``, so a list reads each row's review in the query that reads the row, with no extra round trip (``summary_from_row``)."""
    from django.db.models import DateTimeField, JSONField, OuterRef, Subquery
    from django.db.models.functions import JSONObject
    from cveFeed.models import FindingReview
    newest = FindingReview.objects.filter(triage_id=OuterRef(prefix + 'id')).exclude(outcome=REFUSED).order_by('-created_at', '-id')
    fields = ('verdict', 'confidence', 'reason_code', 'note', 'model', 'outcome', 'held_reason')
    return {'review_row': Subquery(newest.annotate(j=JSONObject(**{f: f for f in fields})).values('j')[:1], output_field=JSONField()),
            'review_at': Subquery(newest.values('created_at')[:1], output_field=DateTimeField())}


def summary_from_row(obj):
    """``_summary_of`` of the review annotated on ``obj`` by ``newest_review_row_q``; None when it has none."""
    from types import SimpleNamespace
    data, at = getattr(obj, 'review_row', None), getattr(obj, 'review_at', None)
    return _summary_of(SimpleNamespace(**data, created_at=at)) if data and at else None


# --------------------------------------------------------------------------------------------------------------- operations

ACTIONS = {'feed_sentinels': timedelta(minutes=15), 'refresh_nuclei_templates': timedelta(hours=1)}
ACTIVITY_ERROR_PROBLEM = 20     # failed activity lines of one kind in six hours
SENTINEL_FAILED_PROBLEM = 5     # failed or expired Sentinel tasks of one Sentinel and kind in six hours
SENTINEL_ERROR_SHARE = 0.05     # ...the overall rule: that many in a group and this share of all the tasks that finished (or no Sentinel is live, or none completed) is an alert
RESTART_GRACE = timedelta(minutes=15)  # a task a Sentinel had claimed before its own finished update restart, and that stopped reporting up to this long after it, is the restart's doing
WAIT_SATURATED_SHARE = 0.10     # this share of the tasks that finished or waited having waited for a slot is saturation, trend or not
GROUP_FAILED_SHARE = 0.5        # a Sentinel and kind whose failed share of their own finished tasks is this high, with SENTINEL_FAILED_PROBLEM failures, is an alert whatever the rest of the fleet does


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


# Every code ops_checks can return, in the order it computes them. The snapshot sends it to the reviewer container, which builds the model's answer
# format from it; tests/test_ai_prompts.py holds it equal to the codes written in ops_checks and to the container's fallback copy.
OPS_CODES = ('sentinels_idle', 'workers_down', 'nuclei_templates', 'sentinel_errors', 'sentinel_waiting', 'sentinels_offline', 'scan_errors', 'system',
             'generated_templates', 'ai_errors', 'memory', 'queue_starvation', 'sentinel_claims_refused')


def _check(code, state, title, detail, facts=None, actions=(), severity=None):
    """One check. ``state`` is ok, warning or problem, or ``unknown``: the numbers it needs could not be read, so there is no verdict."""
    return {'code': code, 'state': state, 'severity': severity or ('critical' if state == 'problem' else 'warning' if state == 'warning' else 'info'),
            'title': title, 'detail': detail, 'facts': facts or {}, 'actions': list(actions)}


def _who():
    """The id of the Sentinel behind a task: its agent, or, for a task that expired (the broker clears the agent then), the one that held it."""
    from agentapi.sentinel_broker import EXPIRED_AGENT
    from django.db.models import IntegerField
    from django.db.models.fields.json import KeyTextTransform
    from django.db.models.functions import Cast, Coalesce
    return Coalesce('agent_id', Cast(KeyTextTransform(EXPIRED_AGENT, 'result'), IntegerField()))


def _restart_q(since):
    """A ``Q`` for the expired tasks a Sentinel's own update restart cut off: tasks of that Sentinel, claimed before the moment its updater reported
    (``info.update.at``, only when ``info.update.status`` is ``done``), that stopped reporting from that moment to ``RESTART_GRACE`` after it. Needs the
    ``who`` annotation (``_who``). ``None`` when there was none. Nothing else opens a window: not another Sentinel's update, not a failed one, not the
    server's clean-up line (it is about the server's own workers, and the Sentinel tasks are not touched by it), and never a task that stopped
    reporting before the restart."""
    from agentapi.models import Agent
    q = None
    for pk, info in Agent.objects.filter(kind='scanner').values_list('pk', 'info')[:200]:
        update = (info or {}).get('update') if isinstance(info, dict) else None
        if not isinstance(update, dict) or update.get('status') != 'done':
            continue
        try:
            moment = datetime.fromisoformat(str(update.get('at'))) if update.get('at') else None
        except ValueError:
            moment = None
        if moment is None:
            continue
        moment = moment if moment.tzinfo else moment.replace(tzinfo=dt_timezone.utc)
        if moment < since - RESTART_GRACE:
            continue
        part = Q(who=pk, claimed_at__lt=moment, finished_at__gte=moment, finished_at__lte=moment + RESTART_GRACE)
        q = part if q is None else q | part
    return None if q is None else Q(status='expired') & q


def _starvation_inputs(now, paused, live):
    """What ``maintainer_checks.queue_starvation`` needs besides the signals, counted here: the host assessments running and queued, the scans queued, and per
    Sentinel task kind the oldest queued task, what that kind normally waits (the median over its last 200 claimed tasks of the day) and the other kinds the
    Sentinels claimed lately. A count that cannot be made is ``None``: no verdict, never a zero."""
    from agentapi.models import SentinelTask
    from cveFeed.models import HostAssessment
    from django.db.models import Count, Min
    from startScan.models import ScanHistory
    out = {'paused': paused, 'scans_queued': None, 'assessments_running': None, 'assessments_queued': None, 'sentinel_kinds': None}
    try:
        by = {r['status']: r['n'] for r in HostAssessment.objects.filter(status__in=('queued', 'running')).values('status').annotate(n=Count('id'))}
        out.update(assessments_running=by.get('running', 0), assessments_queued=by.get('queued', 0), scans_queued=ScanHistory.objects.filter(scan_status=-1).count())
    except Exception:  # noqa: BLE001 - one unreadable source gives no verdict, it does not stop the other checks
        logger.debug('queue starvation: could not count scans and assessments', exc_info=True)
    try:
        kinds = []
        if live:
            recent = SentinelTask.objects.filter(claimed_at__gte=now - timedelta(minutes=maintainer_checks.SENTINEL_BUSY_MINUTES)).values_list('kind', flat=True).distinct()
            claimed_lately = set(recent)
            for row in SentinelTask.objects.filter(status='queued').values('kind').annotate(n=Count('id'), oldest=Min('created_at'))[:30]:
                waits = sorted((c - k).total_seconds() for k, c in SentinelTask.objects.filter(kind=row['kind'], claimed_at__isnull=False, created_at__gte=now - timedelta(days=1))
                               .order_by('-id').values_list('created_at', 'claimed_at')[:200])
                kinds.append({'kind': row['kind'], 'queued': row['n'], 'oldest_age_seconds': int(max(0, (now - row['oldest']).total_seconds())),
                              'typical_wait_seconds': int(waits[len(waits) // 2]) if waits else None, 'busy_with': sorted(claimed_lately - {row['kind']})})
        out['sentinel_kinds'] = kinds
    except Exception:  # noqa: BLE001
        logger.debug('queue starvation: could not read the Sentinel queue', exc_info=True)
    return out


def ops_checks(now=None, templates_release=None, _out=None):
    """The operations checks (docs/AI-REVIEWER.md), from ``system_status`` and the database. ``templates_release`` is the newest
    nuclei-templates release the reviewer container read from GitHub, ``{tag, published_at}``, when it has one."""
    from agentapi.models import SentinelTask
    from agentapi.services import Ctx
    from agentapi.system_status import system_status
    from cveFeed.models import AgentActivity, AIUsage
    from django.db.models import Count, Q
    now = now or timezone.now()
    admin = _admin()
    status = system_status(Ctx(user=admin)) if admin else {'problems': [], 'system': None}
    system = status.get('system') or {}
    if _out is not None:
        _out['status'] = status
    sentinels = system.get('sentinels') or {}
    signals = ((system.get('signals') or {}).get('signals')) if isinstance(system.get('signals'), dict) else None
    signals = signals if isinstance(signals, dict) else {}
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

    # the Celery lanes: all four must answer. A container can look up while lanes are gone (the 1.4.0 update incident: three of four stopped, nothing
    # consumed the CVE feed, validation or classic queues, and no notice said so), and the Sentinels page alone says nothing about them.
    workers = system.get('workers') or {}
    lanes = [row for row in (workers.get('consumers') or []) if isinstance(row, dict)]
    gone = [row['worker'] for row in lanes if row.get('consuming') is not True]
    if workers.get('state') in ('degraded', 'unknown') or (lanes and gone and workers.get('state') != 'responding'):
        names = ', '.join(gone) if gone and len(gone) < len(lanes) else 'every worker lane' if lanes else 'the workers'
        checks.append(_check('workers_down', 'problem', 'Background workers are down',
                             f'{names} did not answer, probe after probe, so the queues they consume are not being worked: '
                             'scans, the CVE feed and validation are stalled. Run `docker compose restart celery` on the server; '
                             'the Update screen and the container health say the same.',
                             {'state': workers.get('state'), 'lanes_down': gone, 'note': str(workers.get('note') or '')[:300]}))
    else:
        checks.append(_check('workers_down', 'ok', 'Background workers answer', '', {'state': workers.get('state')}))

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

    # Sentinel task failures, by Sentinel and kind, judged against how much work was done and whether the Sentinels are live
    six = now - timedelta(hours=6)
    from agentapi import sentinel_broker
    from agentapi.models import Agent
    from cveFeed import fleet as fleet_lib
    fleet = fleet_lib.fleet_facts(now)
    not_waiting = ~sentinel_broker.waiting_q() & ~Q(error='cancelled by a person')  # a task that expired waiting for a free slot is back-pressure, counted below, and one a person cancelled is no failure
    who = _who()
    ended = SentinelTask.objects.annotate(who=who).filter(not_waiting, status__in=('failed', 'expired'), finished_at__gte=six)
    restart_q = _restart_q(six)
    restart_cut = ended.filter(restart_q).count() if restart_q is not None else 0
    counted = ended.exclude(restart_q) if restart_q is not None else ended
    done_rows = SentinelTask.objects.filter(status='done', finished_at__gte=six)
    completed = done_rows.count()
    done_by = {(r['agent_id'], r['kind']): r['n'] for r in done_rows.values('agent_id', 'kind').annotate(n=Count('id'))}
    names = dict(Agent.objects.filter(kind='scanner').values_list('pk', 'name'))
    groups = []
    for g in counted.values('who', 'kind').annotate(n=Count('id')).order_by('-n')[:60]:
        g['done'] = done_by.get((g['who'], g['kind']), 0)
        g['name'] = names.get(g['who']) or 'a Sentinel'
        g['share'] = g['n'] / (g['n'] + g['done'])
        groups.append(g)
    failed_total = counted.count()
    share = failed_total / (failed_total + completed) if failed_total + completed else 1.0
    # each Sentinel and kind is judged on its own numbers: a kind that fails every time, or a Sentinel whose tasks all stop reporting, is an alert at any
    # volume of work beside it. The fleet-wide share only decides for the groups with several failures when nothing group-wise says so (an install with no
    # live Sentinel, or nothing completed, or 5 percent of everything that finished)
    # (a task whose Sentinel is not known, an old row or a dispatch that timed out before any claim, has no numbers of its own: only the overall rule judges it)
    own = [g for g in groups if g['who'] is not None and ((g['n'] >= SENTINEL_FAILED_PROBLEM and g['share'] >= GROUP_FAILED_SHARE) or not g['done'])]
    several = [g for g in groups if g['n'] >= SENTINEL_FAILED_PROBLEM]
    overall = bool(several) and (not fleet['live_sentinels'] or not completed or share >= SENTINEL_ERROR_SHARE)
    bad = sorted({id(g): g for g in own + (several if overall else [])}.values(), key=lambda g: -g['n'])[:10]
    if bad:
        samples = {}
        for g in bad[:5]:
            err = (counted.filter(who=g['who'], kind=g['kind']).exclude(error='').order_by('-finished_at').values_list('error', flat=True).first())
            samples[f"{g['name']}/{g['kind']}"] = str(err or '')[:200]
        checks.append(_check('sentinel_errors', 'problem', 'Sentinel tasks are failing',
                             '; '.join(f"{g['name']}: {g['n']} {g['kind']} task(s) failed or stopped reporting"
                                       + (f", {g['done']} completed" if g['done'] else ', none completed') for g in bad)
                             + f". In the last six hours {failed_total} of {failed_total + completed} finished tasks failed or stopped reporting ({share * 100:.1f}%), "
                               f"{completed} completed, with {fleet_lib.sentinels_text(fleet['live_sentinels'])}"
                             + (f'; {restart_cut} that stopped reporting around an update restart are not counted' if restart_cut else '') + '.',
                             {'groups': [{'sentinel': g['name'], 'kind': g['kind'], 'failed': g['n'], 'completed': g['done']} for g in bad], 'last_errors': samples,
                              'failed': failed_total, 'completed': completed, 'live_sentinels': fleet['live_sentinels'], 'restart_cut': restart_cut,
                              'builtin_scanner': fleet['builtin_scanner']}))
    else:
        checks.append(_check('sentinel_errors', 'ok', 'Sentinel tasks succeed', '', {}))
    # tasks that expired only because every Sentinel slot was busy: the targets stay due and are asked again, so a note, never a failure
    held_rows = SentinelTask.objects.filter(sentinel_broker.waiting_q(), finished_at__gte=six)
    held = list(held_rows.values('kind').annotate(n=Count('id')).order_by('-n')[:10])
    waited = sum(r['n'] for r in held)
    if waited >= SENTINEL_FAILED_PROBLEM:
        recent = held_rows.filter(finished_at__gte=now - timedelta(hours=3)).count()
        earlier = waited - recent
        queued_now = SentinelTask.objects.filter(status='queued').count()
        growing = recent > earlier * 1.25
        slots = fleet['slots']
        # falling behind: no Sentinel is live to do the work, or the waits are growing and the queue already holds more than every slot is busy with
        behind = not fleet['live_sentinels'] or (growing and queued_now >= max(slots, 1))
        where = (f"The install has {slots} slot{'s' if slots != 1 else ''} across {fleet_lib.sentinels_text(fleet['live_sentinels'])}; "
                 f'{completed} completed in the same six hours and {queued_now} are queued now.')
        share_waited = waited / (waited + completed)
        saturated = bool(slots) and (share_waited >= WAIT_SATURATED_SHARE or queued_now >= 3 * slots)  # whatever the trend: a good part of the work finds no free slot
        # tasks that expired unclaimed while the slots are free are not a shortage of capacity: the Sentinels are not claiming (a limiter that refused every claim
        # for an hour read as "add a Sentinel" here). Say that, and why when the numbers say, and give no capacity advice.
        queue_counts = sentinels.get('queue') or {}
        slots_in_use = (queue_counts.get('claimed') or 0) + (queue_counts.get('running') or 0) if fleet['live_sentinels'] else None
        claimed_2h = SentinelTask.objects.filter(claimed_at__gte=now - timedelta(hours=2)).count() if fleet['live_sentinels'] else None
        refusals = signals.get('claim_refusals')
        refused_2h = sum((r.get('this_hour') or 0) + (r.get('previous_hour') or 0) for r in (refusals.get('by') or []) if isinstance(r, dict) and r.get('action') == 'claim') \
            if isinstance(refusals, dict) and refusals.get('state') == 'known' else 0
        not_claiming, why = (maintainer_checks.not_claiming(slots, slots_in_use, claimed_2h, refused_2h) if fleet['live_sentinels'] and (refused_2h or waited / (waited + completed) >= WAIT_SATURATED_SHARE)
                             else (False, ''))  # a few tasks that expired unclaimed beside plenty that completed are noise, not an outage
        if not fleet['live_sentinels']:
            advice = 'No Sentinel is live, so none of this work is being done: bring a Sentinel online on the Sentinels page.'
        elif not_claiming:
            advice = (f'The Sentinels are not claiming work: {slots_in_use} of {slots} slots are in use while tasks expire unclaimed, so this is not a shortage of capacity '
                      f'and adding Sentinels or slots will not help. {why}').strip()
        elif behind:
            advice = (f'Work is falling behind: waits grew from {earlier} in the earlier three hours to {recent} in the latest three, and the queue holds '
                      f'{queued_now} against {slots} slots. Add a Sentinel, or give the ones you have more slots.')
        elif saturated:
            advice = (f'The Sentinels are at capacity: {waited} of {waited + completed} tasks ({share_waited * 100:.0f}%) found no free slot in six hours '
                      f'({earlier} then {recent}, so it is not getting worse). Nothing is broken; raise the slot count of a Sentinel or bring another online '
                      'if you want this work done sooner.')
        elif growing:
            advice = f'Waits grew ({earlier} then {recent}) but only {queued_now} are queued against {slots} slots, so work is not falling behind.'
        else:
            advice = f'The backlog is not growing ({earlier} waits in the earlier three hours, {recent} in the latest three): the Sentinels are keeping up and no action is needed.'
        facts = {'waited': waited, 'by_kind': {r['kind']: r['n'] for r in held}, 'slots': slots, 'completed': completed, 'queued_now': queued_now,
                 'waited_earlier': earlier, 'waited_recent': recent, 'growing': growing, 'falling_behind': behind, 'saturated': saturated,
                 'live_sentinels': fleet['live_sentinels'], 'not_claiming': not_claiming, 'slots_in_use': slots_in_use, 'claimed_2h': claimed_2h, 'refused_2h': refused_2h}
        # with no Sentinel live nothing is being done at all: that is a problem (a warning, not a note); with Sentinels live it is back-pressure, a note
        checks.append(_check('sentinel_waiting', 'warning' if fleet['live_sentinels'] else 'problem',
                             'Sentinels are not claiming work' if not_claiming else 'Sentinel tasks are waiting for a free slot',
                             f"{waited} task(s) waited for a Sentinel slot in the last six hours ({', '.join(str(r['n']) + ' ' + r['kind'] for r in held[:5])}); "
                             f'their targets stay due and are asked again. {where} {advice}', facts,
                             severity='info' if fleet['live_sentinels'] and not not_claiming else 'warning'))

    # the maintainer's checks (cveFeed/maintainer_checks.py): what the signals say about memory, starved queues and refused claims. A part that could not be read is
    # no verdict ('unknown'): it neither raises an alert nor resolves one.
    work = _starvation_inputs(now, bool((system.get('work') or {}).get('paused')), fleet['live_sentinels'])
    checks.append(_check('memory', **maintainer_checks.memory(signals)))
    checks.append(_check('queue_starvation', **maintainer_checks.queue_starvation(signals, work)))
    checks.append(_check('sentinel_claims_refused', **maintainer_checks.claim_refusals(signals)))

    # a Sentinel that was registered and approved, was heard from this week, and now none is live: nothing runs, whether or not tasks wait
    if not fleet['live_sentinels']:
        gone = list(Agent.objects.filter(kind='scanner', status='active', token__revoked=False, last_seen__gte=now - timedelta(days=7))
                    .order_by('name').values_list('name', flat=True)[:10])
        if gone:
            checks.append(_check('sentinels_offline', 'problem', 'No Sentinel is live',
                                 f"No Sentinel has been heard from lately, so no scan work is being done. Registered and approved, but silent: {', '.join(gone)}. "
                                 'Check that the Sentinel is running and can reach this server (the Sentinels page shows when each was last seen).',
                                 {'silent': gone}, severity='warning'))
        else:
            checks.append(_check('sentinels_offline', 'ok', 'Sentinels are heard from', '', {}))
    else:
        checks.append(_check('sentinels_offline', 'ok', 'Sentinels are heard from', '', {}))

    # failed activity lines, by kind
    failed_kinds = list(AgentActivity.objects.filter(status='failed', created_at__gte=six).values('kind').annotate(n=Count('id')).order_by('-n')[:10])
    heavy = [f for f in failed_kinds if f['n'] >= ACTIVITY_ERROR_PROBLEM]
    if heavy:
        samples = {f['kind']: AgentActivity.objects.filter(status='failed', created_at__gte=six, kind=f['kind'])
                   .order_by('-created_at').values_list('message', flat=True).first() for f in heavy[:5]}
        checks.append(_check('scan_errors', 'problem', 'Scans and tasks are failing',
                             '; '.join(f"{f['n']} failed {f['kind']} line(s)" for f in heavy) + ' in the last six hours. '
                             + ' '.join(f"Latest {k}: {str(v or 'no message')[:160]}" for k, v in list(samples.items())[:3]),
                             {'kinds': {f['kind']: f['n'] for f in heavy}, 'last_messages': {k: str(v or '')[:200] for k, v in samples.items()}}))
    else:
        checks.append(_check('scan_errors', 'ok', 'Scans and tasks succeed', '', {}))

    # what system_status itself reports
    problems = [str(p)[:300] for p in (status.get('problems') or [])][:20]
    checks.append(_check('system', 'problem' if problems else 'ok', 'cvENGINE reports problems' if problems else 'cvENGINE reports no problems',
                         '\n'.join(problems), {'problems': problems}))

    # AI-written templates are validated by the system (cveFeed.templatevalidate), never by a person: only a real problem it cannot fix itself is reported
    from cveFeed import templatevalidate
    stuck = templatevalidate.problem(now)
    checks.append(_check('generated_templates', 'warning' if stuck else 'ok',
                         stuck['title'] if stuck else 'AI-written nuclei templates are validated automatically',
                         stuck['detail'] if stuck else '', stuck['facts'] if stuck else {}))

    # AI calls failing, by stage and category. A reply that was cut off and then answered by the automatic retry is recorded as
    # ``truncated_retried`` and is not a failure: only a cut-off that survived the retry counts here, and the stage is named.
    since = now - timedelta(days=1)
    ai_failed = list(AIUsage.objects.filter(status='failed', started_at__gte=since).exclude(error_category='truncated_retried')
                     .values('stage', 'error_category').annotate(n=Count('id')).order_by('-n')[:12])
    total = sum(r['n'] for r in ai_failed)
    recovered = AIUsage.objects.filter(status='failed', started_at__gte=since, error_category='truncated_retried').count()
    by_stage = {}
    for r in ai_failed:
        by_stage.setdefault(r['stage'] or 'unspecified', {})[r['error_category'] or 'unknown'] = r['n']
    by_category = {}
    for r in ai_failed:
        by_category[r['error_category'] or 'unknown'] = by_category.get(r['error_category'] or 'unknown', 0) + r['n']
    detail = ''
    if total >= 10:
        detail = ', '.join(f"{r['n']} {r['error_category'] or 'unknown'} in {r['stage'] or 'unspecified'}" for r in ai_failed) + ' in the last 24 hours.'
        if 'output_truncated' in by_category:
            detail += (' output_truncated: the reply was cut off even after the automatic retry with twice the room (up to 32768 tokens), so the model '
                       'is spending the room on thinking. Next step: lower Reasoning for this model (Settings, AI model), or choose a model that '
                       'thinks less; the stage is named above.')
        if recovered:
            detail += f' {recovered} other cut-off repl{"y was" if recovered == 1 else "ies were"} answered by the automatic retry and are not counted.'
    checks.append(_check('ai_errors', 'warning' if total >= 10 else 'ok', 'AI calls are failing', detail,
                         {'by_category': by_category, 'by_stage': by_stage, 'cut_off_answered_by_retry': recovered, 'automatic_retry': True}))
    return checks


def _meaning(value):
    """What a fact says apart from how big it is: names, switches and states stay, a count is only "there is one". A dismissed alert comes back
    when the problem changes (another Sentinel or kind, a state turning true), not because one more task waited or failed."""
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        return '#'
    if isinstance(value, dict):
        return {str(k): _meaning(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return sorted((_meaning(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True, default=str))
    return str(value)


def _digest(check):
    keep = {k: _meaning(v) for k, v in (check.get('facts') or {}).items() if k not in ('last_errors', 'last_messages', 'hours_since_refresh', 'done_2h', 'completed', 'queued_now', 'live_sentinels', 'slots',
                                                                                    'restart_cut', 'waited_earlier', 'waited_recent', 'growing')}
    return hashlib.sha1(json.dumps([check['code'], check['state'], keep], sort_keys=True, default=str).encode()).hexdigest()


def sync_alerts(checks, now=None):
    """Open, refresh or resolve one ``AdminAlert`` per check code: a check that is not ``ok`` keeps its alert open (with the newest facts),
    an ``ok`` one resolves it. Returns ``{opened, resolved}``."""
    from cveFeed.models import AdminAlert
    now = now or timezone.now()
    opened = resolved = 0
    for check in checks:
        if check['state'] == 'unknown':
            continue  # no verdict: an open alert is neither refreshed nor resolved (it ages, and is shown as not re-checked: ``open_alerts``)
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


def _watchdog_events(limit=10):
    """What the outer watchdog (cveFeed.watchdog) did lately, for the operations diagnosis to explain in words. Never raises; no rule depends on it."""
    try:
        from cveFeed.models import WatchdogEvent
        return [{'at': e.at.isoformat(), 'rule': e.rule, 'level': e.level, 'action': e.action, 'result': e.result[:300]}
                for e in WatchdogEvent.objects.exclude(level='info')[:limit]]
    except Exception:  # noqa: BLE001
        return []


def snapshot(now=None, templates_release=None, _scan_only=False):
    """What the reviewer container's operations job is given: the checks that have a verdict, the measurements behind them and auto-tuning's last decisions."""
    out = {}
    checks = ops_checks(now, templates_release, _out=out)
    from cveFeed import fleet
    system = (out.get('status') or {}).get('system') or {}
    signals = (system.get('signals') or {}).get('signals') if isinstance(system.get('signals'), dict) else None
    tuning = system.get('autotune') if isinstance(system.get('autotune'), dict) and 'error' not in system['autotune'] else None
    snap = {'at': (now or timezone.now()).isoformat(), 'checks': [c for c in checks if c['state'] != 'unknown'], 'codes': list(OPS_CODES), 'watchdog': _watchdog_events(),
            'fleet': fleet.fleet_facts(now), 'actions': {name: f'at most once every {int(gap.total_seconds() // 60)} minutes' for name, gap in ACTIONS.items()}}
    if isinstance(signals, dict) or tuning:
        snap.update(maintainer_checks.brief(signals, tuning))
    if _scan_only:  # the report-time rescan: the same keys, built again now, nothing stored and no offer
        return snap
    snap.update(_tuning_offer(snap, now))
    snap['snapshot_id'] = secrets.token_hex(12)
    try:  # what the scan found is stored under the snapshot's id: the report that answers this snapshot carries the id back, and one without a stored result is held
        cache.set(OPS_SNAPSHOT_KEY + snap['snapshot_id'], snapshot_flags(snap), OPS_SNAPSHOT_SECONDS)
    except Exception:  # noqa: BLE001 - no stored result: the proposals of its report are held (fail closed)
        logger.warning('operations snapshot: the scan result could not be stored', exc_info=True)
    return snap


OPS_SNAPSHOT_KEY = 'cvengine:reviewer:ops-snapshot:'
OPS_SNAPSHOT_SECONDS = 6 * 3600  # how long the scan of a snapshot is kept for the report that answers it (a model call takes minutes); later, the report's proposals are held


FLAG_WORDS = {'ai_directive': 'instructions to an AI', 'workflow_order': 'orders to an AI agent', 'echo_marker': 'a request to repeat a marker',
              'impossible_task': 'an impossible task for an AI', 'false_lead': 'a planted lead', 'scan_failed': 'the scan could not be made'}


def flag_words(families):
    return ', '.join(FLAG_WORDS.get(f, f.replace('_', ' ')) for f in families)


def snapshot_flags(snap):
    """The families of text aimed at an AI (``injection_guard.families``) in the strings of this snapshot a Sentinel, a scanner, an agent, a person or an
    earlier model could have written: the checks (titles, descriptions and facts quote Sentinel names, error text, task failures and host names), the
    signals (a Sentinel's name among the refused claims) and the tuning block (who pinned what, and the reasons of earlier decisions, an agent's and the AI's
    own among them). All of it is already inside fenced blocks for the model; the scan decides whether its tuning proposals may be applied."""
    from cveFeed import injection_guard
    return sorted(injection_guard.families({k: v for k, v in snap.items() if k in ('checks', 'signals', 'tuning', 'fleet', 'watchdog')}))


def _tuning_offer(snap, now):
    """What the health-check AI may propose now (``autotune.ai_offer``), added to the snapshot as ``tuning.proposals`` and ``tuning_settings`` (the keys the
    answer's ``tuning`` may name), and the scan of the snapshot's text remembered for the report that answers it. Never raises."""
    try:
        from cveFeed import autotune
        offer = autotune.ai_offer(now)
        by = autotune.by_key()
        proposals = {'allowed': not offer['gate'], 'why_not': offer['gate'] or None, 'left_today': offer['left_today'], 'at_most_per_report': autotune.MAX_AI_PROPOSALS,
                     'offered': [{'setting': k, 'label': o['label'], 'value': o['value'], 'lowest': o['range'][0], 'highest': o['range'][1],
                                  'higher_number_means': o['higher'], 'a_raise_stops': str(o['raise_stops'])[:120]} for k, o in offer['offered'].items()],
                     'not_offered': [{'setting': k, 'label': by[k].label if k in by else k, 'why': str(why)[:120]} for k, why in list(offer['not_offered'].items())[:20]]}
        tuning = dict(snap.get('tuning') or {})
        tuning['proposals'] = proposals
        out = {'tuning': tuning, 'tuning_settings': list(offer['offered'])}
        while len(json.dumps(out['tuning'], default=str)) > 9000 and out['tuning']['proposals']['not_offered']:
            out['tuning']['proposals']['not_offered'].pop()
        return out
    except Exception:  # noqa: BLE001 - the checks and diagnoses do not depend on it
        logger.warning('operations snapshot: the tuning offer could not be built', exc_info=True)
        return {}


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
    cache_read_tokens, cache_write_tokens, duration_ms}``. One AIUsage row. Raises VerdictError for a stage that is not one of the container's own two jobs."""
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
        input_tokens=count('input_tokens'), output_tokens=count('output_tokens'), cache_read_tokens=count('cache_read_tokens'),
        cache_write_tokens=count('cache_write_tokens'), duration_ms=count('duration_ms', 24 * 3600 * 1000), started_at=now)
    return {'recorded': True}


SEVERITY_RANK = {'info': 0, 'warning': 1, 'critical': 2}


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
    from cveFeed import fleet
    facts = fleet.fleet_facts(now)
    by_code = {c['code']: c for c in checks}
    model = str(body.get('model') or '')[:100]
    updated = 0
    for item in (body.get('alerts') or [])[:20] if isinstance(body.get('alerts'), list) else []:
        if not isinstance(item, dict):
            continue
        check = by_code.get(item.get('code'))
        if not check or check['state'] in ('ok', 'unknown'):
            continue
        alert = AdminAlert.objects.filter(code=check['code'], resolved_at__isnull=True).first()
        if alert is None:
            continue
        alert.ai_detail = usable_note(item.get('diagnosis'), min_words=DIAGNOSIS_MIN_WORDS)[:NOTE_MAX]  # nothing, not filler, when the model gave no real diagnosis
        if alert.ai_detail and fleet.contradicts_fleet(alert.ai_detail, facts):  # a sentence says no Sentinel is online while one is, or to start a built-in one this install does not have: the facts win, the rest stays
            alert.ai_detail = usable_note(fleet.without_contradictions(alert.ai_detail, facts), min_words=DIAGNOSIS_MIN_WORDS)[:NOTE_MAX]
        alert.ai_model = model if alert.ai_detail else ''
        if item.get('severity') in ('info', 'warning', 'critical') and check['state'] != 'problem':
            wanted = item['severity'] if item['severity'] != 'critical' else 'warning'  # only a problem the server sees is critical
            if SEVERITY_RANK[wanted] > SEVERITY_RANK.get(alert.severity, 0):  # the model may raise a note to a warning, never quiet what the server's own check says
                alert.severity = wanted
        alert.save(update_fields=['ai_detail', 'ai_model', 'severity'])
        updated += 1
    ran, refused = [], []
    offered = {a for c in checks if c['state'] not in ('ok', 'unknown') for a in c['actions']}
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
    out = {'alerts_updated': updated, 'actions_run': ran, 'actions_refused': refused}
    if body.get('tuning'):
        out['tuning'] = apply_ops_tuning(body.get('tuning'), checks, now, body.get('snapshot_id'), release)
    return out


def apply_ops_tuning(proposals, checks, now, snapshot_id=None, release=None):
    """The health-check AI's ``tuning`` proposals (at most two are read): judged against what may be proposed NOW (``autotune.ai_offer``, not the snapshot's
    older numbers) and applied through the engine as ``source='ai'``. Held, recorded and not applied, when anything the AI read was flagged as text aimed at an
    AI (the snapshot's own scan, remembered for this report, or the checks as they are now), or when the proposal's own reason is. Returns one result per
    proposal, ``{setting, status (applied, suggested, refused, held), text}``: the reply the container logs."""
    from cveFeed import autotune, injection_guard
    if not isinstance(proposals, list):
        return [{'setting': '', 'status': 'refused', 'text': 'tuning must be a list of proposals'}]
    from cveFeed.models import AdminAlert
    open_codes = set(AdminAlert.objects.filter(resolved_at__isnull=True).values_list('code', flat=True))
    proposals = [{**p, 'alert': p.get('alert') if p.get('alert') in open_codes and p.get('alert') in OPS_CODES else None} if isinstance(p, dict) else p for p in proposals]  # only the code of an alert that is open now
    offer = autotune.ai_offer(now)
    if offer['gate']:
        return autotune.ai_apply(proposals, offer, now)  # every proposal answered "ignored: <why>"
    stored = None
    if isinstance(snapshot_id, str) and re.fullmatch(r'[0-9a-f]{24}', snapshot_id):
        try:
            stored = cache.get(OPS_SNAPSHOT_KEY + snapshot_id)
        except Exception:  # noqa: BLE001
            stored = None
    if not isinstance(stored, list):  # an id the server did not make, none, or one that expired or was lost: fail closed
        return autotune.ai_hold_all(proposals, 'the report does not answer a snapshot this server made (or its scan result is gone), so nothing was applied', now)
    try:  # the same keys as the snapshot's own scan, built again now
        fresh = snapshot_flags(snapshot(now, release, _scan_only=True))
    except Exception:  # noqa: BLE001 - a scan that cannot be made holds the proposals
        fresh = ['scan_failed']
    flagged = sorted(set(stored) | set(fresh))
    if flagged:
        return autotune.ai_hold_all(proposals, 'text aimed at an AI may be in what it read (' + flag_words(flagged) + '), so nothing was applied', now)
    clean, held = [], []
    for item in proposals[:autotune.MAX_AI_PROPOSALS]:
        if isinstance(item, dict) and injection_guard.families(item.get('reason') or ''):
            held.append(item)
        else:
            clean.append(item)
    results = autotune.ai_hold_all(held, 'its reason reads as text aimed at an AI', now) if held else []
    return results + autotune.ai_apply(clean + list(proposals[autotune.MAX_AI_PROPOSALS:]), offer, now)


ALERT_STALE_AFTER = timedelta(hours=1)  # the checks run every 30 minutes (the watchdog tick, or the beat task): an alert not refreshed for this long was not re-checked


def answering_decision(alert):
    """The id of the newest auto-tuning decision made while this alert was open that answered it (its ``signals['alerts']`` holds the alert's code,
    ``autotune.open_alert_codes``), or None: the alert strip links to that decision's line in Settings, configMaxxing, Auto-tuning."""
    from cveFeed import autotune
    if alert.code not in OPS_CODES:
        return None
    from cveFeed.models import TuningDecision
    return TuningDecision.objects.filter(created_at__gte=alert.first_seen, signals__alerts__contains=[alert.code]).order_by('-created_at', '-pk').values_list('pk', flat=True).first()


def open_alerts(user=None):
    """The open alerts an App Admin sees: not resolved, and not dismissed unless the problem changed since."""
    from cveFeed.models import AdminAlert
    rows = list(AdminAlert.objects.filter(resolved_at__isnull=True).order_by('-last_seen')[:20])
    from cveFeed import fleet
    facts = fleet.fleet_facts() if any(a.ai_detail for a in rows) else {}
    out = []
    now = timezone.now()
    for a in rows:
        if a.dismissed_at and a.dismissed_digest == a.digest:
            continue
        ai_detail = usable_note(a.ai_detail, min_words=DIAGNOSIS_MIN_WORDS)  # a row stored before filler was refused is not shown either
        if ai_detail and fleet.contradicts_fleet(ai_detail, facts):  # advice stored before this guard keeps only the sentences the facts do not contradict
            ai_detail = usable_note(fleet.without_contradictions(ai_detail, facts), min_words=DIAGNOSIS_MIN_WORDS)
        detail, age = a.detail, now - a.last_seen
        stale = a.code in OPS_CODES and age > ALERT_STALE_AFTER  # the check that keeps it current has not run lately: its numbers are old, say so
        if stale:
            detail = f'Not re-checked for {maintainer_checks.span(age.total_seconds())}, so this may no longer be true. {detail}'
        out.append({'id': a.pk, 'code': a.code, 'severity': a.severity, 'title': a.title, 'detail': detail, 'ai_detail': ai_detail, 'stale': stale,
                    'age_minutes': int(age.total_seconds() // 60), 'ai_model': a.ai_model if ai_detail else '', 'first_seen': a.first_seen.isoformat(), 'last_seen': a.last_seen.isoformat(),
                    'decision_id': answering_decision(a)})
    return out


def dismiss_alert(alert_id, user, now=None):
    from cveFeed.models import AdminAlert
    alert = AdminAlert.objects.filter(pk=alert_id, resolved_at__isnull=True).first()
    if alert is None:
        return False
    alert.dismissed_at, alert.dismissed_by, alert.dismissed_digest = now or timezone.now(), user, alert.digest
    alert.save(update_fields=['dismissed_at', 'dismissed_by', 'dismissed_digest'])
    return True
