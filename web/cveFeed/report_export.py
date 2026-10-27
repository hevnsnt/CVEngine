"""One-click PDF reports: queue a report, poll it, download it, and clean up.

A report is built in a celery task (``generate_report`` on ``cve_feed_queue``) from ``cveFeed.report_data``, rendered by
``cveFeed.report_pdf`` in a child process, and written under the report directory with a random file name. A ``ReportExport`` row
says who asked, for what, how it went and when the file expires (24 hours). The only way to read the file is ``download``, an
authenticated view of the user who asked, which checks the project role again. Expired files are removed on access and in the weekly
maintenance (``cveFeed.maintenance``).

Permissions follow the project roles: any role that can read the project (audit included) can export it, and the report holds only
that project's rows. The task checks the role again when it runs, so a user who lost access in the meantime gets nothing. A report is
a read, so a read-only token may ask for one. Nothing here contacts a host, so the scan safety gates (exclusions, scannable_hosts,
pause) do not apply; a host removed or excluded is simply not in the inventory the report reads.
"""
import logging
import os
import re
import secrets
from datetime import timedelta

from django.conf import settings
from django.db.models import Q
from django.http import FileResponse
from django.utils import timezone

from agentapi.services import ALL_PROJECTS, ApiError, Ctx, get_one_project, get_project

logger = logging.getLogger(__name__)

TTL_HOURS_DEFAULT, TTL_HOURS_CEILING = 24, 168
ACTIVE_PER_USER_DEFAULT = 3
PER_HOUR_DEFAULT = 20
ACTIVE_TOTAL_DEFAULT = 8
STUCK_AFTER = timedelta(hours=2)  # a queued or running report this old lost its worker
FILE_RE = re.compile(r'^[0-9a-f]{48}\.pdf$')
ACTIVE = ('queued', 'running')


def _env_int(name, default, ceiling=10 ** 6):
    try:
        return min(ceiling, max(1, int(os.environ.get(name, ''))))
    except ValueError:
        return default


def ttl():
    return timedelta(hours=_env_int('CVENGINE_REPORT_TTL_HOURS', TTL_HOURS_DEFAULT, TTL_HOURS_CEILING))


def report_dir():
    """The directory the PDFs are written to: a dot-folder of the scan results volume, which no media path can name."""
    return os.environ.get('CVENGINE_REPORT_DIR') or os.path.join(settings.MEDIA_ROOT, '.reports')


def _path(filename):
    if not FILE_RE.match(filename or ''):
        return None
    root = os.path.realpath(report_dir())
    path = os.path.realpath(os.path.join(root, filename))
    return path if os.path.dirname(path) == root else None


def _remove_file(job):
    path = _path(job.filename)
    if path:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        except OSError:
            logger.warning('could not remove report file of export %s', job.pk, exc_info=True)


# --- requesting ----------------------------------------------------------------------------------------------------------------

def enqueue(ctx, slug, host=None, include_closed=False):
    """Queue a report of the project (or of one host of it) for the caller. Returns ``(job, created)``: asking again for the same
    report while one is queued or running gives that one back."""
    from agentapi.host_manage import clean_host
    from cveFeed.models import ReportExport
    from tenancy import audit
    if slug == ALL_PROJECTS:  # the all-projects view has no single project to report on
        raise ApiError(400, 'pick a project to make changes')
    project, _ = get_project(ctx, slug)  # any role that reads the project; 404 for one the caller cannot see
    if include_closed not in (True, False):
        raise ApiError(400, 'include_closed must be true or false')
    host = clean_host(host) if host not in (None, '') else ''
    if host:
        from agentapi import services as svc
        from cveFeed.correlation import latest_scan_q
        from startScan.models import Subdomain
        if not svc._scoped(Subdomain.objects.all(), project, 'target_domain__project').filter(latest_scan_q()).filter(name__iexact=host).exists():
            raise ApiError(404, 'host not found')
    now = timezone.now()
    _expire_stuck(now)
    twin = ReportExport.objects.filter(project=project, requested_by=ctx.user, host=host, include_closed=bool(include_closed),
                                       status__in=ACTIVE).first()
    if twin:
        return twin, False
    # the caps count rows across every user: _base_manager is not narrowed to the caller's projects by the tenancy scope
    mine = ReportExport._base_manager.filter(requested_by=ctx.user)
    if mine.filter(status__in=ACTIVE).count() >= _env_int('CVENGINE_REPORT_ACTIVE_PER_USER', ACTIVE_PER_USER_DEFAULT, 50) or \
            mine.filter(created_at__gte=now - timedelta(hours=1)).count() >= _env_int('CVENGINE_REPORT_PER_HOUR', PER_HOUR_DEFAULT, 1000) or \
            ReportExport._base_manager.filter(status__in=ACTIVE).count() >= _env_int('CVENGINE_REPORT_ACTIVE_TOTAL', ACTIVE_TOTAL_DEFAULT, 200):
        raise ApiError(429, 'too many reports are being made; wait for one to finish and try again')
    job = ReportExport.objects.create(token=secrets.token_urlsafe(32), project=project, requested_by=ctx.user, host=host,
                                      include_closed=bool(include_closed), expires_at=now + ttl())
    audit.record(ctx.user, 'report.export', project.slug, org=project.org_id, host=host, include_closed=bool(include_closed))
    from cveFeed.tasks import generate_report
    try:
        task = generate_report.apply_async(args=[job.pk], queue='cve_feed_queue')
        ReportExport.objects.filter(pk=job.pk, status='queued').update(celery_id=task.id)
    except Exception as exc:  # noqa: BLE001 - the broker is down: the row says so instead of waiting forever
        logger.exception('could not queue report %s', job.pk)
        ReportExport.objects.filter(pk=job.pk).update(status='failed', finished_at=timezone.now(), error=f'could not be queued ({type(exc).__name__})')
    job.refresh_from_db()
    return job, True


def _expire_stuck(now):
    """A report whose worker died would otherwise stay "running" for ever: fail the ones older than STUCK_AFTER."""
    from cveFeed.models import ReportExport
    ReportExport._base_manager.filter(status__in=ACTIVE, created_at__lt=now - STUCK_AFTER).update(
        status='failed', finished_at=now, error='the report was not finished (the worker stopped); ask for it again')


# --- reading -------------------------------------------------------------------------------------------------------------------

def serialize(job, now=None):
    now = now or timezone.now()
    ready = job.status == 'done' and job.expires_at > now
    base = f'/api/v1/projects/{job.project.slug}/reports/{job.token}'
    return {'id': job.token, 'status': 'expired' if job.status == 'done' and not ready else job.status, 'project': job.project.slug,
            'host': job.host or None, 'include_closed': job.include_closed, 'created': job.created_at.isoformat(),
            'finished': job.finished_at.isoformat() if job.finished_at else None, 'expires': job.expires_at.isoformat(),
            'size_bytes': job.size_bytes if ready else None, 'summary': job.summary if ready else {}, 'error': job.error,
            'status_url': base, 'download_url': f'{base}/download' if ready else None}


def _mine(ctx, slug, token):
    """The caller's own report of this project, or 404 (the same answer for another user's, another project's and a missing one)."""
    from cveFeed.models import ReportExport
    project, _ = get_one_project(ctx, slug)
    job = ReportExport.objects.select_related('project').filter(token=str(token)[:64], project=project, requested_by=ctx.user).first()
    if job is None:
        raise ApiError(404, 'report not found')
    return job


def status(ctx, slug, token):
    now = timezone.now()
    _expire_stuck(now)
    job = _mine(ctx, slug, token)
    if job.status == 'done' and job.expires_at <= now:
        _remove_file(job)
        job.filename = ''
        job.save(update_fields=['filename'])
    return serialize(job, now)


def download(ctx, slug, token):
    """The PDF as an attachment for the user who asked, while it has not expired."""
    now = timezone.now()
    job = _mine(ctx, slug, token)
    if job.status != 'done':
        raise ApiError(409, 'the report is not ready' if job.status in ACTIVE else 'the report could not be made; ask for it again')
    path = _path(job.filename)
    if job.expires_at <= now or not path or not os.path.isfile(path):
        _remove_file(job)
        raise ApiError(410, 'the report has expired; ask for it again')
    stem = re.sub(r'[^A-Za-z0-9._-]+', '-', f'cvengine-report-{job.project.slug}-{job.host or "project"}')[:100].strip('-')
    response = FileResponse(open(path, 'rb'), content_type='application/pdf', as_attachment=True,
                            filename=f'{stem}-{job.created_at:%Y%m%d}.pdf')
    response['Cache-Control'] = 'private, no-store'
    response['X-Content-Type-Options'] = 'nosniff'
    return response


# --- the task ------------------------------------------------------------------------------------------------------------------

def _fail(job, message):
    from cveFeed.models import ReportExport
    ReportExport.objects.filter(pk=job.pk).update(status='failed', finished_at=timezone.now(), error=message[:200])
    return {'status': 'failed', 'error': message}


def execute(job_id, celery_id=None):
    """Make one queued report. Runs in a worker, as the user who asked: the role is checked again, the report is read for that
    project only, and the PDF is written to a random file name that becomes visible only when it is complete."""
    from cveFeed import report_data, report_pdf
    from cveFeed.models import ReportExport
    now = timezone.now()
    claimed = ReportExport._base_manager.filter(pk=job_id, status='queued').update(status='running', started_at=now, celery_id=celery_id or '')
    if not claimed:
        return {'status': 'skipped', 'error': 'the report is not queued'}
    try:  # every report made also clears the ones that expired, so a busy instance does not wait for the weekly maintenance
        prune_expired(now)
    except Exception:  # noqa: BLE001 - housekeeping must never stop a report
        logger.warning('could not remove expired reports', exc_info=True)
    job = ReportExport._base_manager.select_related('project__org', 'requested_by').get(pk=job_id)
    user = job.requested_by
    if not user.is_active:
        return _fail(job, 'the account that asked for this report is disabled')
    try:
        get_project(Ctx(user=user), job.project.slug)
    except ApiError:
        return _fail(job, 'you no longer have access to this project')
    directory = report_dir()
    os.makedirs(directory, mode=0o700, exist_ok=True)
    filename = secrets.token_hex(24) + '.pdf'
    final = os.path.join(directory, filename)
    partial = final + '.partial'
    try:
        data = report_data.collect(job.project, host=job.host or None, include_closed=job.include_closed, now=now)
        report_pdf.render_pdf(report_pdf.build_html(data), partial)
        os.chmod(partial, 0o600)
        os.replace(partial, final)
    except LookupError:
        return _fail(job, 'the host is no longer in the inventory')
    except report_pdf.RenderError as exc:
        return _fail(job, str(exc))
    except Exception:  # noqa: BLE001 - the reason stays in the log; the row gets a short message
        logger.exception('report %s failed', job.pk)
        _remove_partial(partial)
        return _fail(job, 'the report could not be generated; see the worker log')
    summary = {'hosts': len(data['hosts']), 'findings': len(data['findings']), 'findings_total': data['summary']['findings'],
               'hygiene': data['caps']['hygiene_shown'], 'omitted': {k: data['caps'][k] for k in ('hosts_omitted', 'findings_omitted', 'hygiene_omitted')}}
    finished = timezone.now()
    ReportExport.objects.filter(pk=job.pk).update(status='done', filename=filename, size_bytes=os.path.getsize(final), summary=summary,
                                                  finished_at=finished, expires_at=finished + ttl())
    return {'status': 'done', 'size_bytes': os.path.getsize(final), **summary}


def _remove_partial(path):
    try:
        os.unlink(path)
    except OSError:
        pass


# --- cleanup -------------------------------------------------------------------------------------------------------------------

def prune_expired(now=None):
    """Delete expired reports (the file, then the row) and the files no row owns that are older than the lifetime (a worker that died
    between writing a PDF and recording it). Returns how many reports and stray files were removed."""
    from cveFeed.models import ReportExport
    now = now or timezone.now()
    removed = 0
    for job in ReportExport._base_manager.filter(Q(expires_at__lt=now) | Q(status='failed', finished_at__lt=now - ttl())):
        _remove_file(job)
        job.delete()
        removed += 1
    stray = 0
    directory = report_dir()
    if os.path.isdir(directory):
        known = set(ReportExport._base_manager.exclude(filename='').values_list('filename', flat=True))
        cutoff = now.timestamp() - ttl().total_seconds()
        for name in os.listdir(directory):
            path = os.path.join(directory, name)
            if (FILE_RE.match(name) and name not in known or name.endswith('.partial')) and os.path.isfile(path) and os.path.getmtime(path) < cutoff:
                os.unlink(path)
                stray += 1
    return {'reports': removed, 'stray_files': stray}
