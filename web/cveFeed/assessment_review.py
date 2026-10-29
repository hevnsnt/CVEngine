"""Checkpointed, scoped three-hour review of assessment coverage.

The model sees only counts and persisted identifiers. It may choose one of three existing,
policy-checked queue actions for each project (triage, validate, discover); it cannot supply a
host, command or scope. Topping up host-assessment coverage is deterministic, not a model judgment call, so it is handled
by cveFeed.coverage_topup on its own short interval instead of being offered here; ``dispatch``'s
``assess_host`` branch stays in place (it is still policy-checked, still no model-supplied target)
only so a caller can ask for it directly, but ``project_facts`` never offers it to the model.
"""
import json
import logging
import re
from datetime import timedelta

from django.db import transaction
from django.db.models import Count, Max, Q
from django.utils import timezone

from cveFeed import activity
from cveFeed.models import AssessmentReview, AssessmentReviewDecision

logger = logging.getLogger(__name__)
PAGE = 10
MAX_MODEL_CALLS = 100
MAX_QUEUED_ACTIONS = 20
LEASE = timedelta(minutes=10)
PERIOD = timedelta(hours=3)
# Beat fires every PERIOD but the task starts after queue latency, so two runs can be a little less than PERIOD apart; without
# slack the second is "not due" and the review waits a whole extra cycle.
DUE_SLACK = timedelta(minutes=20)
SYSTEM = (
    'You review assessment coverage for one authorized project. The JSON input contains only stored counts and IDs. '
    'Choose at most one action from the offered actions. An offered action is a candidate, not proof it is needed. '
    'Prefer no action when evidence is fresh, the queue is busy, or an external check cannot answer the finding. '
    'Never invent a target, command, credential, new scope or scan mode. Reply with exactly one JSON object: '
    '{"action":"none","reason":"short evidence-based reason"}.')

HOST_STAGES = ('nmap_scan', 'nuclei_light_scan', 'cve_correlation', 'nuclei_targeted_scan')


def host_coverage_due(project, at, limit=1, need_count=True):
    """Count every distinct current-inventory name missing a successful core stage; return up to ``limit`` due stored host
    ids, ordered by id so every caller (the three-hour review, cveFeed.coverage_topup) walks the same deterministic
    queue.

    A recent attempt or active scan is deferred, not falsely counted as covered. This query
    evaluates the full project population in the database, including scanless CT hosts.

    ``need_count`` is on by default for the three-hour review's evidence, but a caller that only asks "is there
    at least one" (cveFeed.coverage_topup's top-up and its full-port/UDP sweep gate) passes ``need_count=False`` to
    skip the DISTINCT aggregate below: with it off, this is a single bounded ``LIMIT`` query.
    """
    from django.db.models import Exists, OuterRef
    from cveFeed.correlation import latest_scan_q
    from cveFeed.models import HostAssessment, HostExclusion, HostState
    from cveFeed.unresolved_archive import COUNTS_FOR
    from startScan.models import ScanActivity, Subdomain

    completed = Subdomain.objects.filter(target_domain__project=project, name=OuterRef('name'),
                                         scan_history__scan_status=2)
    for index, stage in enumerate(HOST_STAGES):
        check = ScanActivity.objects.filter(scan_of_id=OuterRef('scan_history_id'), name=stage, status=2)
        key = f'stage_{index}'
        completed = completed.annotate(**{key: Exists(check)}).filter(**{key: True})
    attempts = HostAssessment.objects.filter(project=project, host=OuterRef('name'),
                                             created_at__gte=at - timedelta(hours=24))
    active = Subdomain.objects.filter(target_domain__project=project, name=OuterRef('name'),
                                      scan_history__scan_status__in=(-1, 1))
    excluded = HostExclusion.objects.filter(org_id=project.org_id, host=OuterRef('name'))
    archived = HostState.objects.filter(project=project, host=OuterRef('name'), archived_at__isnull=False)
    # A host that has no scannable address (a dangling name, or one that points inside a private network) was tried and has nothing to scan: it is
    # not a first-pass backlog. Counting it kept the full-port and UDP sweeps waiting, and the project's few assessment slots busy, for ever.
    # unresolved_archive.recheck resolves it again every few hours and puts it back here the moment it has an address.
    no_address = HostState.objects.filter(project=project, host=OuterRef('name'), unresolved_checks__gte=1,
                                          unresolved_last_at__gte=at - COUNTS_FOR)
    # the current inventory only (one row per host, from the latest scan), not every scan's copy of every name: with a long history the
    # six correlated checks below ran once per host per scan, every minute for every project
    rows = (Subdomain.objects.filter(latest_scan_q()).filter(target_domain__project=project)
            .annotate(covered=Exists(completed), recent_attempt=Exists(attempts), active_scan=Exists(active),
                      excluded_name=Exists(excluded), archived_name=Exists(archived), no_address=Exists(no_address))
            .filter(covered=False, recent_attempt=False, active_scan=False, excluded_name=False, archived_name=False, no_address=False))
    due_ids = list(rows.order_by('id').values_list('id', flat=True)[:limit]) if limit else []
    count = (rows.order_by().values('name').distinct().count()) if need_count else None
    return count, due_ids


def host_coverage_gap(project, at):
    """Single-id view of host_coverage_due: the three-hour review offers at most one due host per project per call."""
    count, due_ids = host_coverage_due(project, at, limit=1)
    return count, (due_ids[0] if due_ids else None)


def parse_decision(reply, offered):
    text = str(reply or '').strip()
    if text.startswith('```'):
        text = text.removeprefix('```json').removeprefix('```').removesuffix('```').strip()
    try:
        value = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(value, dict) or set(value) != {'action', 'reason'}:
        return None
    if value['action'] not in set(offered) | {'none'} or not isinstance(value['reason'], str) or not value['reason'].strip():
        return None
    from reNgine.ai_providers import clean_text
    return {'action': value['action'], 'reason': clean_text(value['reason'], 300)}


def project_facts(project_id, start, end):
    """Aggregate complete project populations; no first-page sample is represented as full coverage."""
    from cveFeed.models import AgentActivity, CVEMatch, HostState, Triage
    from cveFeed.inactive_archive import candidates as inactive_candidates
    from dashboard.models import Project
    from startScan.models import ScanHistory, Subdomain
    from targetApp.models import Domain
    from cveFeed.validation import due_ids

    project = Project.objects.get(pk=project_id)
    triage_rows = Triage.objects.filter(project_id=project_id)
    findings = triage_rows.aggregate(
        total=Count('id'), pending=Count('id', filter=Q(status__in=('pending', 'error', 'not_triaged'))),
        unvalidated=Count('id', filter=Q(validation_status__in=('none', 'pending', 'failed'))))
    scans = ScanHistory.objects.filter(domain__project_id=project_id).aggregate(
        total=Count('id'), active=Count('id', filter=Q(scan_status__in=(-1, 1))),
        failed_recent=Count('id', filter=Q(scan_status=0, start_scan_date__gte=start)))
    recent = AgentActivity.objects.filter(project_id=project_id, created_at__gte=start, created_at__lt=end).aggregate(
        total=Count('id'), errors=Count('id', filter=Q(status='failed')))
    from django.db.models import OuterRef, Subquery
    latest_success = ScanHistory.objects.filter(domain_id=OuterRef('pk'), scan_status=2).order_by('-stop_scan_date', '-id')
    due = (Domain.objects.filter(project_id=project_id)
           .annotate(last_success=Subquery(latest_success.values('stop_scan_date')[:1]))
           .filter(Q(last_success__isnull=True) | Q(last_success__lt=end - timedelta(days=7)))
           .order_by('last_success', 'id').values_list('id', flat=True).first())
    due_validation = due_ids(project_id, limit=1)
    due_hosts, due_host_id = host_coverage_gap(project, end)
    top_findings = list(triage_rows.filter(status__in=('pending', 'error', 'not_triaged'))
                        .order_by('id').values('id', 'kind', 'status', 'validation_status')[:5])
    facts = {'project_id': project_id, 'targets': Domain.objects.filter(project_id=project_id).count(),
             'hosts': Subdomain.objects.filter(target_domain__project_id=project_id).values('name').distinct().count(),
             'matched_cves': CVEMatch.objects.filter(subdomain__target_domain__project_id=project_id).count(),
             'matched_cves_updated_in_window': CVEMatch.objects.filter(subdomain__target_domain__project_id=project_id,
                                                                        cve_entry__synced_at__gte=start).count(),
             'findings': findings, 'top_pending_findings': top_findings, 'scans': scans, 'recent_activity': recent,
             'recent_scan_results': {'failed': scans['failed_recent']},
             'due_discovery_target_id': due, 'due_validation': bool(due_validation),
             'hosts_missing_core_coverage': due_hosts, 'due_host_id': due_host_id,
             'retired_unarchived_hosts': HostState.objects.filter(project=project, retired_at__isnull=False,
                                                                  archived_at__isnull=True).count(),
             'retired_hosts_due_observation': inactive_candidates(end).filter(project=project).count(),
             'last_scan_at': ScanHistory.objects.filter(domain__project_id=project_id).aggregate(Max('start_scan_date'))['start_scan_date__max']}
    offered = []
    if findings['pending']:
        offered.append('triage')
    if due_validation:
        offered.append('validate')
    if due is not None and scans['active'] == 0:
        offered.append('discover')
    # due_host_id stays in facts for evidence and for cveFeed.dispatch's own direct 'assess_host' entry point, but
    # it is deliberately left out of `offered`: cveFeed.coverage_topup drains this backlog on its own short
    # interval, without a model call, so the three-hour review no longer competes with it for a host assessment.
    return project, facts, offered


def model_decision(facts, offered):
    from reNgine.ai_settings import get_configured_provider
    from reNgine.ai_providers import usage_stage
    provider = get_configured_provider()
    if provider is None:
        return None, 'AI provider unavailable'
    payload = {**facts, 'last_scan_at': facts['last_scan_at'].isoformat() if facts['last_scan_at'] else None,
               'offered_actions': offered}
    with usage_stage('assessment_review'):
        reply = provider.complete(SYSTEM, json.dumps(payload, separators=(',', ':'), sort_keys=True))
    decision = parse_decision(reply, offered)
    return decision, '' if decision else 'invalid model action'


def dispatch(project, facts, action):
    """Revalidate the target and queue caps at the point of use. No model-supplied target is accepted."""
    from cveFeed.scan_control import pause_requested
    if pause_requested():
        return 'deferred', None, 'scanning is paused'
    from startScan.models import ScanHistory
    if action == 'discover' and ScanHistory.objects.filter(scan_status__in=(-1, 1)).count() >= 20:
        return 'deferred', None, 'global scan queue is busy'
    if action == 'triage':
        from cveFeed.tasks import triage_pending
        from cveFeed.models import Triage
        if not Triage.objects.filter(project=project, status__in=('pending', 'error', 'not_triaged')).exists():
            return 'stale', None, 'no triage is currently due'
        task = triage_pending.apply_async(args=[project.pk], queue='cve_feed_queue')
        return 'queued', None, f'triage task {task.id}'
    if action == 'validate':
        from cveFeed.tasks import validate_findings
        from cveFeed.validation import due_ids
        ids = due_ids(project.pk, limit=20)
        if not ids:
            return 'stale', None, 'no validation is currently due'
        task = validate_findings.apply_async(args=[project.pk, ids], queue='cve_feed_queue')
        return 'queued', None, f'validation task {task.id}'
    if action == 'discover':
        from cveFeed.discovery import running_discovery, start_discovery
        from cveFeed.exclusions import is_excluded
        from targetApp.models import Domain
        target = Domain.objects.filter(pk=facts['due_discovery_target_id'], project=project).first()
        if not target or is_excluded(project.pk, target.name) or running_discovery(target):
            return 'stale', None, 'target is excluded, absent or already scanning'
        scan = start_discovery(target)
        return 'queued', scan.pk, f'discovery scan #{scan.pk}'
    if action == 'assess_host':
        from cveFeed.host_assessment import enqueue
        from startScan.models import Subdomain
        sub = Subdomain.objects.filter(pk=facts.get('due_host_id'), target_domain__project=project) \
            .select_related('target_domain').first()
        if not sub:
            return 'stale', None, 'due inventory host is no longer present'
        try:
            job, created = enqueue(project, sub, source='review')
        except ValueError:
            return 'stale', None, 'host left scope or was excluded'
        except RuntimeError:
            return 'deferred', None, 'host assessment queue is at capacity'
        return ('queued' if created and job.status == 'queued' else 'deferred' if job.status == 'failed' else 'stale',
                job.pk, f'host assessment #{job.pk} is {job.status}')
    return 'no_action', None, 'no action selected'


def _claim(review_id=None):
    from dashboard.models import Project
    now = timezone.now()
    with transaction.atomic():
        if review_id:
            review = AssessmentReview.objects.select_for_update().filter(pk=review_id).first()
        else:
            review = AssessmentReview.objects.select_for_update().filter(status__in=('queued', 'running', 'partial')).order_by('-id').first()
            if review and (review.model_calls >= MAX_MODEL_CALLS or
                           (review.status == 'partial' and not Project.objects.filter(pk__gt=review.cursor_project_id).exists())):
                # A later three-hour window starts after this cursor, so large installations
                # rotate through the full population without unbounded provider spending.
                review = None
            if review is None:
                last = AssessmentReview.objects.order_by('-id').first()
                if last and last.period_end > now - PERIOD + DUE_SLACK:
                    return None, 'not due'
                # windows are contiguous: this one starts where the last ended (unless that was more than two periods ago)
                start = last.period_end if last and last.period_end > now - 2 * PERIOD else now - PERIOD
                review = AssessmentReview.objects.create(period_start=start, period_end=now,
                    total_projects=Project.objects.count(),
                    cursor_project_id=last.cursor_project_id if last and last.model_calls >= MAX_MODEL_CALLS else 0)
        if review is None or review.status in ('completed', 'failed'):
            return None, 'finished'
        if review.lease_until and review.lease_until > now:
            return None, 'running elsewhere'
        review.status, review.started_at, review.lease_until = 'running', review.started_at or now, now + LEASE
        review.save(update_fields=['status', 'started_at', 'lease_until', 'updated_at'])
        return review, ''


def run_page(review_id=None):
    """Process one bounded page and checkpoint it. A continuation covers later projects."""
    from dashboard.models import Project
    from cveFeed.tasks import assessment_review_task
    review, reason = _claim(review_id)
    if not review:
        return {'skipped': reason}
    progress = activity.log('inventory', f'Three-hour assessment review #{review.pk}: checking project coverage', status='running', review_id=review.pk)
    try:
        if not review.performance:
            from cveFeed.performance_review import review as review_performance
            review.performance = review_performance(now=review.period_end)
            review.save(update_fields=['performance', 'updated_at'])
        ids = list(Project.objects.filter(pk__gt=review.cursor_project_id).order_by('pk').values_list('pk', flat=True)[:PAGE])
        for project_id in ids:
            if review.model_calls >= MAX_MODEL_CALLS:
                break
            if AssessmentReviewDecision.objects.filter(review=review, project_id=project_id).exists():
                review.cursor_project_id = project_id
                review.save(update_fields=['cursor_project_id', 'updated_at'])
                continue
            status, action, reason, job_id, facts = 'no_action', 'none', '', None, {}
            try:
                project, facts, offered = project_facts(project_id, review.period_start, review.period_end)
                if not offered:
                    reason = 'Inventory, findings and recent activity have no due supported action'
                elif review.queued_actions >= MAX_QUEUED_ACTIONS:
                    status, reason = 'deferred', 'review action cap reached; pending work retained for a later cycle'
                else:
                    review.model_calls += 1
                    decision, error = model_decision(facts, offered)
                    if decision is None:
                        status, reason = 'deferred', error
                    else:
                        action, reason = decision['action'], decision['reason']
                        if action != 'none':
                            status, job_id, gate = dispatch(project, facts, action)
                            reason = f'{reason} · {gate}'[:300]
                AssessmentReviewDecision.objects.create(review=review, project=project, action=action, status=status,
                    reason=reason[:300], job_id=job_id,
                    evidence={'targets': facts.get('targets'), 'hosts': facts.get('hosts'),
                              'hosts_missing_core_coverage': facts.get('hosts_missing_core_coverage'),
                              'retired_unarchived_hosts': facts.get('retired_unarchived_hosts'),
                              'retired_hosts_due_observation': facts.get('retired_hosts_due_observation'),
                              'matched_cves': facts.get('matched_cves'), 'findings': facts.get('findings'),
                              'scans': facts.get('scans'), 'recent_activity': facts.get('recent_activity')})
                if status == 'queued':
                    review.queued_actions += 1
                    activity.log('inventory', f'Three-hour review #{review.pk}: {action} queued for project #{project_id}',
                                 project=project_id, review_id=review.pk, job_id=job_id, reason=reason[:300])
                elif status == 'deferred':
                    review.error_count += 1
                review.reviewed_projects += 1
            except Exception as exc:
                category = re.sub(r'[^a-zA-Z0-9_]', '', str(getattr(exc, 'category', '') or type(exc).__name__))[:40]
                logger.error('assessment review %s project %s failed (%s)', review.pk, project_id, category)
                review.error_count += 1
                AssessmentReviewDecision.objects.get_or_create(review=review, project_id=project_id,
                    defaults={'action': 'none', 'status': 'failed', 'reason': f'{category}: review failed; see server diagnostics'})
            review.cursor_project_id = project_id
            review.save(update_fields=['cursor_project_id', 'queued_actions', 'reviewed_projects', 'model_calls', 'error_count', 'updated_at'])
        more = Project.objects.filter(pk__gt=review.cursor_project_id).exists()
        review.lease_until = None
        if more and review.model_calls < MAX_MODEL_CALLS:
            review.save(update_fields=['lease_until', 'updated_at'])
            try:
                assessment_review_task.apply_async(args=[review.pk], countdown=1, queue='cve_feed_queue')
            except Exception:
                review.status, review.error = 'partial', 'continuation enqueue failed; scheduled retry will resume'
                review.save(update_fields=['status', 'error', 'updated_at'])
            activity.settle(progress, 'done', f'Three-hour review #{review.pk}: {review.reviewed_projects}/{review.total_projects} projects reviewed; continuing')
            return {'review_id': review.pk, 'status': review.status, 'reviewed': review.reviewed_projects}
        review.status = 'partial' if more or review.error_count else 'completed'
        if more and review.model_calls >= MAX_MODEL_CALLS:
            review.error = 'AI review call budget reached; next three-hour cycle resumes after the current cursor'
        review.finished_at = timezone.now() if not more else None
        review.save(update_fields=['status', 'error', 'finished_at', 'lease_until', 'updated_at'])
        activity.settle(progress, 'done' if review.status == 'completed' else 'failed',
            f'Three-hour review #{review.pk}: {review.reviewed_projects}/{review.total_projects} projects reviewed, '
            f'{review.queued_actions} actions queued, {review.error_count} deferred or failed', review_id=review.pk)
        return {'review_id': review.pk, 'status': review.status, 'reviewed': review.reviewed_projects,
                'actions': review.queued_actions, 'deferred_or_failed': review.error_count}
    except Exception as exc:
        logger.error('assessment review %s failed (%s)', review.pk, type(exc).__name__)
        review.status, review.error, review.lease_until = 'partial', f'{type(exc).__name__}: review interrupted', None
        review.save(update_fields=['status', 'error', 'lease_until', 'updated_at'])
        activity.settle(progress, 'failed', f'Three-hour review #{review.pk} interrupted; scheduled retry will resume')
        return {'review_id': review.pk, 'status': 'partial', 'error': review.error}
