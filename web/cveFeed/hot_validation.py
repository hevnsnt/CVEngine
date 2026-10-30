"""Bounded, durable validation dispatch: every CVE match, and the Fire/Smoke scanner findings.

The sweep only selects findings already in an owned inventory. The worker rechecks scope and
evidence before any check runs. Broker priority 0 (Fire) precedes 3 (manual), 6 (Smoke) and
9 (Ice, every other CVE match) on the reserved validation worker; a duplicate delivery after
promotion is harmless. A CVE match of any confidence is queued by itself, hottest first; the
per-sweep, per-project and per-day caps bound the work, and Ice only uses what Fire and Smoke leave.
"""
import os
from datetime import timedelta

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from cveFeed import activity, match_policy, triage
from cveFeed.correlation import latest_scan_q
from cveFeed.models import AutomaticValidation, HotValidationCursor, OnDemandValidation, Triage
from cveFeed.threat import FIRE, ICE, SMOKE, classify_threat_tier, match_temperature

PAGE = 100
MAX_ENQUEUE = 20
PROJECT_ACTIVE_CAP = 10
PROJECT_ICE_CAP = 5  # Ice stops here, so a project's cold matches cannot fill the slots a Fire or Smoke finding needs
PRIORITY = {FIRE: 0, SMOKE: 6, ICE: 9}  # Redis steps: 0 Fire, 3 manual, 6 Smoke, 9 Ice
HOST_REPORTED = 'host'  # CVEMatch.source of a match the host reported itself (cveFeed.inventory_match): no outside check can see what it rests on
MAX_ATTEMPTS = 7  # failed tries of the same evidence before it is left alone (a changed signature starts again)


def validate_all_matches():
    """Whether every CVE match is validated automatically, not only the Fire and Smoke ones. On unless
    CVENGINE_AUTO_VALIDATE_ALL_MATCHES is 0, false, no or off."""
    return os.environ.get('CVENGINE_AUTO_VALIDATE_ALL_MATCHES', '1').strip().lower() not in ('0', 'false', 'no', 'off')


def retry_after(attempts, capped_only=False):
    """When a failed validation of the same evidence may be queued again. Stopped only by the per-day caps: once the caps reset,
    without spending an attempt. Otherwise an exponential backoff (5 min, doubling, at most 6 h), and None once MAX_ATTEMPTS
    tries are spent, which marks the evidence exhausted."""
    from cveFeed.validation import next_cap_reset
    if capped_only:
        return next_cap_reset()
    if attempts >= MAX_ATTEMPTS:
        return None
    return timezone.now() + timedelta(minutes=min(360, 5 * 2 ** max(0, attempts - 1)))


def next_attempt_number(previous, signature, signature_of):
    """The attempt number of a new job for this evidence: 1 for new evidence, the same number after a cap deferral, else one more."""
    if not previous or signature_of(previous) != signature:
        return 1
    if (previous.result or {}).get('deferred_by_cap'):
        return previous.attempts or 1
    return min((previous.attempts or 1) + 1, MAX_ATTEMPTS)


def tier_for(row):
    """The canonical asset finding tier, or None when this finding is no longer current/open."""
    if row.kind == 'cve_match' and row.match_id:
        match = row.match
        if match.ai_verdict == 'not_affected' or match.distro_status == 'patched' or not match.subdomain_id:
            return None
        cve = match.cve_entry
        return match_temperature(classify_threat_tier(cve.kev, cve.epss_reached, cve.exploit_db, cve.cvss),
                                 cve.cvss, match.ai_verdict, match.distro_status, match_policy.version_unknown(match))
    if row.vulnerability_id:
        vuln = row.vulnerability
        if not vuln.open_status:
            return None
        return FIRE if vuln.severity >= 3 else SMOKE if vuln.severity == 2 else None
    if row.hygiene_id:
        finding = row.hygiene
        if finding.status != 'open':
            return None
        return FIRE if finding.severity >= 3 else SMOKE if finding.severity == 2 else None
    if row.route_id and row.route.auth_state == 'open':
        return SMOKE if triage.describe_route(row.route)['severity'] >= 2 else None
    return None


def manual_eligible(row):
    """A manual request may review a lower-tier finding, but never a closed or detached one."""
    if row.match_id:
        return False  # CVE matches use the per-match on-demand request.
    if row.vulnerability_id:
        return bool(row.vulnerability.open_status and row.vulnerability.target_domain_id and
                    row.vulnerability.target_domain.project_id == row.project_id)
    if row.hygiene_id:
        return bool(row.hygiene.status == 'open' and row.hygiene.domain.project_id == row.project_id)
    if row.route_id:
        return bool(row.route.auth_state == 'open' and row.route.project_id == row.project_id)
    return False


def _candidate_rows(lane):
    cve_fire = (Q(match__cve_entry__kev=True) | Q(match__cve_entry__exploit_db=True)
                | Q(match__cve_entry__cvss__gte=9)
                | (Q(match__cve_entry__epss_reached=True) & Q(match__cve_entry__cvss__gte=7))
                | (Q(match__ai_verdict='affected') & Q(match__cve_entry__cvss__gte=7)))
    cve_hot = cve_fire | Q(match__cve_entry__cvss__gte=7) | Q(match__cve_entry__epss_reached=True)
    unknown = match_policy.version_unknown_q('match__')  # waits for a person or a published range: never validated automatically
    if lane == ICE:
        # every other current CVE match, whatever its confidence or score (an unscored CVE too); one the AI ruled out or the distro
        # patched is not a finding to validate
        cold = (Q(match__isnull=False) & ~cve_hot & ~unknown & ~Q(match__ai_verdict='not_affected') & ~Q(match__distro_status='patched')
                & ~Q(match__source=HOST_REPORTED) & latest_scan_q('match__subdomain__'))
        return Triage.objects.filter(cold).select_related('match__cve_entry', 'match__subdomain__target_domain').order_by('pk')
    severity = 3 if lane == FIRE else 2
    candidate = ((cve_fire if lane == FIRE else cve_hot) & Q(match__isnull=False) & ~unknown & ~Q(match__source=HOST_REPORTED)
                 & latest_scan_q('match__subdomain__'))
    candidate |= Q(vulnerability__open_status=True, vulnerability__severity__gte=severity)
    candidate |= Q(hygiene__status='open', hygiene__severity__gte=severity)
    if lane == SMOKE:
        candidate |= Q(route__auth_state='open') & (Q(route__sensitive_score__gt=0)
                      | Q(route__path__iregex=triage.ADMIN_PATH.pattern))
    return Triage.objects.filter(candidate).select_related(
        'match__cve_entry', 'match__subdomain__target_domain', 'vulnerability__subdomain',
        'vulnerability__target_domain', 'route__domain', 'hygiene__domain').order_by('pk')


def _active_count(project_id):
    return (OnDemandValidation.objects.filter(project_id=project_id, status__in=('queued', 'running')).count()
            + AutomaticValidation.objects.filter(project_id=project_id, status__in=('queued', 'running')).count())


def _recently_handled(job, signature, now):
    if not job or getattr(job, 'evidence_signature', getattr(job, 'signature', '')) != signature:
        return False
    return _job_current(job, now)


def _job_current(job, now):
    """Whether ``job``, taken to be about the same evidence, still stands for the finding: running, backing off after a failure,
    exhausted, skipped for a lasting reason, or finished inside the window (a day when the AI could not answer, else seven)."""
    if job.status in ('queued', 'running'):
        return True
    when = job.finished_at or job.created_at
    if job.status == 'failed':
        if getattr(job, 'attempts', 0) >= MAX_ATTEMPTS and not job.next_attempt_at:
            return True  # exhausted this evidence; a changed signature may be queued
        return ((job.next_attempt_at > now) if job.next_attempt_at else when > now - timedelta(minutes=5)) \
            if hasattr(job, 'next_attempt_at') else when > now - timedelta(minutes=5)
    if job.status == 'skipped':
        # Evidence changes get a new signature. Closure can be reversed without a
        # signature change, so a reopened eligible finding is allowed a new job.
        reason = (job.result or {}).get('reason')
        if reason in ('no_longer_eligible', 'historical'):
            return False  # a replaced match's job says nothing about the match that replaced it
        if reason == 'out_of_scope':
            return when > now - timedelta(minutes=30)
        return True
    result = job.result or {}
    interval = timedelta(days=1) if result.get('ai_state') in ('unavailable', 'deferred', 'failed') else timedelta(days=7)
    return when > now - interval


CARRY_HOPS = 6  # a finding rescanned over and over: how many earlier matches of it are followed for a job


def _carried_job(row):
    """The newest validation job of an earlier match of this finding: a rescan makes a new match row, and with it a finding with no job of
    its own, so its history (a validation that failed for good, one that is backing off, one that finished a day ago) was lost and the
    work was queued again at attempt 1, every rescan (issue 206). The link is ``Triage.carried_from``, set when the row took its record
    from the one before it, and is followed back while the older matches have no job themselves."""
    seen, match_id = set(), row.carried_from
    for _ in range(CARRY_HOPS):
        if not match_id or match_id in seen:
            return None
        seen.add(match_id)
        job = OnDemandValidation.objects.filter(match_id=match_id).order_by('-id').first()
        if job:
            return job
        match_id = Triage.objects.filter(match_id=match_id).values_list('carried_from', flat=True).first()
    return None


def _inherited_fresh(row, now):
    """A rescan's new match row carries the validation its predecessor finished (cveFeed.triage._twins) but has no job of its own: a
    result younger than the usual window is as good as a job of its own. Without this every rescan queued every match again."""
    if row.validation_status not in ('hit', 'clean', 'observed', 'no_check') or not row.validated_at:
        return False
    return row.validated_at > now - timedelta(days=7)


def enqueue(row, lane):
    """Idempotent dispatch of this persisted finding. No target argument reaches the broker."""
    from cveFeed.tasks import automatic_validate_finding, validate_match_on_demand

    priority = PRIORITY[lane]
    cap = PROJECT_ICE_CAP if lane == ICE else PROJECT_ACTIVE_CAP
    now = timezone.now()
    with transaction.atomic():
        row = Triage.objects.select_for_update(of=('self',)).select_related(
            'match__cve_entry', 'match__subdomain__target_domain', 'vulnerability', 'route', 'hygiene').get(pk=row.pk)
        if tier_for(row) != lane or (lane == ICE and not row.match_id):
            return 'stale'
        if row.match_id:
            previous = OnDemandValidation.objects.filter(match_id=row.match_id).order_by('-id').first()
            carried = _carried_job(row) if previous is None else None
            if previous and previous.status in ('queued', 'running'):
                if previous.status == 'queued' and previous.priority > priority:
                    previous.priority = priority
                    previous.save(update_fields=['priority'])
                    job, task, promoted = previous, validate_match_on_demand, True
                else:
                    return 'inflight'
            elif _recently_handled(previous, row.signature, now):
                return 'fresh'
            elif carried is not None and carried.status not in ('queued', 'running') and _job_current(carried, now):
                return 'fresh'  # the finding's earlier match was handled, and that stands for this one (its evidence is the same)
            elif previous is None and carried is None and _inherited_fresh(row, now):
                return 'fresh'
            else:
                if _active_count(row.project_id) >= cap:
                    return 'project_cap'
                if carried is not None:
                    # the attempt count and the backoff carry on from the earlier match's job: its evidence is this one's by construction
                    attempts = next_attempt_number(carried, row.signature, lambda j: row.signature)
                else:
                    attempts = next_attempt_number(previous, row.signature, lambda j: j.evidence_signature)
                job = OnDemandValidation.objects.create(match_id=row.match_id, project_id=row.project_id,
                    evidence_signature=row.signature, priority=priority, attempts=attempts)
                task, promoted = validate_match_on_demand, False
        else:
            previous = AutomaticValidation.objects.filter(triage=row).order_by('-id').first()
            if previous and previous.status in ('queued', 'running'):
                if previous.status == 'queued' and previous.priority > priority:
                    previous.priority = priority
                    previous.save(update_fields=['priority'])
                    job, task, promoted = previous, automatic_validate_finding, True
                else:
                    return 'inflight'
            elif _recently_handled(previous, row.signature, now):
                return 'fresh'
            else:
                if _active_count(row.project_id) >= cap:
                    return 'project_cap'
                job = AutomaticValidation.objects.create(triage=row, project_id=row.project_id,
                    signature=row.signature, priority=priority,
                    attempts=next_attempt_number(previous, row.signature, lambda j: j.signature))
                task, promoted = automatic_validate_finding, False
    try:
        task.apply_async(args=[job.pk], priority=priority)
    except Exception:
        if not promoted:
            type(job).objects.filter(pk=job.pk, status='queued').update(
                status='failed', error='validation broker rejected the request', finished_at=timezone.now())
        activity.log('validate', f'{lane.title()} validation could not be queued for finding #{row.pk}',
                     project=row.project_id, status='failed', finding_id=row.pk, job_id=job.pk, stage='enqueue')
        return 'failed'
    activity.log('validate', f'{lane.title()} validation {"promoted" if promoted else "queued"} for finding #{row.pk}',
                 project=row.project_id, finding_id=row.pk, job_id=job.pk, priority=priority, queue='validation_priority_queue')
    return 'promoted' if promoted else 'queued'


def _backfill_projects(limit=2):
    """Advance project pages so old findings with no Triage row become eligible without a global burst."""
    from dashboard.models import Project

    with transaction.atomic():
        cursor, _ = HotValidationCursor.objects.select_for_update().get_or_create(lane='projects')
        ids = list(Project.objects.filter(pk__gt=cursor.last_pk).order_by('pk').values_list('pk', flat=True)[:limit])
        if not ids:
            cursor.last_pk = 0
            ids = list(Project.objects.order_by('pk').values_list('pk', flat=True)[:limit])
        if ids:
            cursor.last_pk = ids[-1]
        cursor.save(update_fields=['last_pk', 'updated_at'])
    for project_id in ids:
        triage.backfill(project_id, limit=25)
    return len(ids)


def sweep(page=PAGE, max_jobs=MAX_ENQUEUE):
    page = max(1, min(int(page), PAGE))
    max_jobs = max(1, min(int(max_jobs), MAX_ENQUEUE))
    stats = {'projects': _backfill_projects(), 'fire': 0, 'smoke': 0, 'ice': 0, 'promoted': 0,
             'fresh': 0, 'inflight': 0, 'project_cap': 0, 'failed': 0}
    for lane in (FIRE, SMOKE, ICE) if validate_all_matches() else (FIRE, SMOKE):
        cursor, _ = HotValidationCursor.objects.get_or_create(lane=lane)
        base = _candidate_rows(lane)
        rows = list(base.filter(pk__gt=cursor.last_pk)[:page])
        if not rows:
            cursor.last_pk = 0
            rows = list(base[:page])
        for row in rows:
            if stats[FIRE] + stats[SMOKE] + stats[ICE] >= max_jobs:
                break  # next sweep starts with the first deferred row
            result = enqueue(row, lane)
            if result in stats:
                stats[result] += 1
            elif result == 'queued':
                stats[lane] += 1
            HotValidationCursor.objects.filter(lane=lane).update(last_pk=row.pk, updated_at=timezone.now())
    return stats
