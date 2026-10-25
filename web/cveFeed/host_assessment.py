"""Scoped, deduplicated assessments of individual inventoried hosts."""
import logging

from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone
from datetime import timedelta

from cveFeed.models import HostAssessment

logger = logging.getLogger(__name__)
ACTIVE = ('queued', 'running')


def serialize(job):
    from startScan.models import ScanActivity

    stages = []
    if job.scan_id:
        stages = list(ScanActivity.objects.filter(scan_of_id=job.scan_id).order_by('id').values(
            'name', 'title', 'status', 'error_message', 'time'))
        for stage in stages:
            stage['time'] = stage['time'].isoformat() if stage['time'] else None
    return {'id': job.id, 'host': job.host, 'status': job.status, 'source': job.source,
            'scan_id': job.scan_id, 'stages': stages, 'result': job.result, 'error': job.error,
            'created_at': job.created_at.isoformat(),
            'started_at': job.started_at.isoformat() if job.started_at else None,
            'finished_at': job.finished_at.isoformat() if job.finished_at else None}


def enqueue(project, sub, *, source='manual', user=None):
    """Accept only a stored host owned by this project; a model cannot supply a new target."""
    from cveFeed.exclusions import is_excluded
    from cveFeed.models import HostState
    from startScan.models import ScanHistory

    domain = sub.target_domain
    host = sub.name.lower().rstrip('.')
    if not domain or domain.project_id != project.pk or not (host == domain.name.lower() or
            (not domain.is_host_scoped() and host.endswith('.' + domain.name.lower()))):
        raise ValueError('host is outside its stored target scope')
    if is_excluded(project.pk, host):
        raise ValueError('host is excluded')
    if HostState.objects.filter(project=project, host=host, archived_at__isnull=False).exists():
        raise ValueError('host is archived; restore it before scanning')
    existing = HostAssessment.objects.filter(project=project, host=host, status__in=ACTIVE).order_by('id').first()
    if existing:
        return existing, False
    active_scans = ScanHistory.objects.filter(Q(scan_status=-1) | Q(scan_status=1,
                                                                    start_scan_date__gte=timezone.now() - timedelta(hours=11)))
    if HostAssessment.objects.filter(status__in=ACTIVE).count() >= 20 or \
            HostAssessment.objects.filter(project=project, status__in=ACTIVE).count() >= 5 or \
            active_scans.count() >= 20:
        raise RuntimeError('host assessment queue is at capacity; retry later')
    try:
        with transaction.atomic():
            job = HostAssessment.objects.create(project=project, domain=domain, host=host, source=source, requested_by=user)
    except IntegrityError:
        return HostAssessment.objects.get(project=project, host=host, status__in=ACTIVE), False
    from cveFeed.tasks import assess_host
    try:
        task = assess_host.apply_async(args=[job.pk], queue='discovery_queue')
        HostAssessment.objects.filter(pk=job.pk, status='queued').update(celery_id=task.id)
        from cveFeed import activity
        activity.log('discovery', f'Host assessment #{job.pk} queued for {host}', project=project.pk, status='queued')
    except Exception as exc:
        logger.exception('could not enqueue host assessment %s', job.pk)
        HostAssessment.objects.filter(pk=job.pk).update(status='failed', finished_at=timezone.now(),
                                                         error=f'broker enqueue failed: {type(exc).__name__}')
        job.refresh_from_db()
        return job, True
    job.refresh_from_db()
    return job, True


def execute(job_id, celery_id=None):
    from cveFeed.discovery import FAILED, run_host_pipeline
    from cveFeed.exclusions import is_excluded
    from cveFeed.models import HostState
    from cveFeed.scan_control import pause_requested
    from startScan.models import Subdomain

    now = timezone.now()
    if not HostAssessment.objects.filter(pk=job_id, status='queued').update(status='running', started_at=now):
        return {'status': 'stopped_or_already_started'}
    job = HostAssessment.objects.select_related('domain', 'project').get(pk=job_id)
    from cveFeed import activity
    activity.log('discovery', f'Host assessment #{job.pk} started for {job.host}', project=job.project_id, status='running')
    try:
        current = Subdomain.objects.filter(target_domain=job.domain, name=job.host).exists()
        if not current or is_excluded(job.project_id, job.host) or \
                HostState.objects.filter(project_id=job.project_id, host=job.host, archived_at__isnull=False).exists() or \
                (job.domain.is_host_scoped() and job.host != job.domain.name.lower()) or pause_requested():
            result = {'status': 'inconclusive', 'error': 'host is absent, excluded, outside scope, or scanning is paused'}
        else:
            result = run_host_pipeline(job.domain_id, [job.host], celery_id=celery_id, retest=True,
                                       force=True, hygiene=True, assessment_id=job_id)
            # a failed run reports the exception text of whatever stopped it; every other state carries the pipeline's own
            # explanation ("Failed stages: nmap_scan", "stopped", why it was inconclusive), which stays
            if result.get('error') and result.get('status') == FAILED:
                result = {**result, 'error': activity.diagnostic(f'Host assessment #{job.pk}', result['error'])}
    except Exception as exc:
        logger.exception('host assessment %s failed', job_id)
        result = {'status': 'failed', 'error': activity.diagnostic(f'Host assessment #{job.pk}', f'{type(exc).__name__}: {exc}',
                                                                    type(exc).__name__)}
    state = result.get('status')
    # a stage that failed leaves the assessment incomplete even though the scan (and the inventory it found) stands
    status = (('failed' if result.get('failed_stages') else 'completed') if state == 2 else 'stopped' if state == 'aborted' else
              'inconclusive' if state in ('empty', 'inconclusive') else 'failed')
    HostAssessment.objects.filter(pk=job_id, status='running').update(
        status=status, result=result, error=str(result.get('error') or '')[:300], finished_at=timezone.now())
    activity.log('discovery', f'Host assessment #{job.pk} {status} for {job.host}' +
                 (f': {str(result.get("error"))[:160]}' if result.get('error') else ''),
                 project=job.project_id, status='failed' if status == 'failed' else 'done', scan_id=result.get('scan_id'))
    return result
