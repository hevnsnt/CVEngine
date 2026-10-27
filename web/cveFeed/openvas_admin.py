"""Settings > OpenVAS: the App Admin's switch for the optional Greenbone add-on, its GMP login, the per-project opt-in and the connection state.

Superuser only, like the rest of /cve/api/settings (the dispatcher enforces it, and so does the tenancy middleware). Switching the add-on on is
the act that allows any scan by the sidecar at all, an instance-wide decision, so it is not delegated to project or organization roles, and the
add-on is deliberately not part of the agent REST API or MCP. The GMP password is write-only: a response says whether it is set, never what
it is, and a blank field on update keeps the stored value. The Test connection runs in a worker (the web container has no sidecar socket)
and reads the saved login; no credential is put in a task message.
"""
import re

from cveFeed.tailscale_api import clean_text

MAX_HOSTS = 200
_HOST_RE = re.compile(r'^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9._:-]*[A-Za-z0-9])?$')


def _error(status, message):
    from cveFeed.settings_api import SettingsError
    return SettingsError(status, message)


def link_dict(link):
    """One project's opt-in as the settings page sees it."""
    from cveFeed.models import OpenvasRun
    last = OpenvasRun.objects.filter(project=link.project).order_by('-id').first()
    return {
        'project': {'id': link.project_id, 'name': link.project.name, 'slug': link.project.slug}, 'enabled': link.enabled, 'hosts': list(link.hosts or []),
        'last_run': ({'status': last.status, 'gvm_status': last.gvm_status, 'progress': last.progress, 'error': last.error, 'summary': last.summary,
                      'started_at': last.started_at.isoformat(), 'finished_at': last.finished_at.isoformat() if last.finished_at else None}
                     if last else None),
    }


def openvas_get(request):
    from cveFeed import openvas_scan
    from cveFeed.models import OpenvasProject, OpenvasRun, OpenvasSettings
    from dashboard.models import Project
    row = OpenvasSettings.current()
    links = OpenvasProject.objects.select_related('project').order_by('project__name')
    linked = {link.project_id for link in links}
    return {
        'enabled': row.enabled, 'username': row.gmp_username, 'password_set': bool(row.gmp_password), 'transport': openvas_scan.transport(),
        'state': row.state or {}, 'running': OpenvasRun.objects.filter(status='running').exists(),
        'floor': {'min_available_mb': openvas_scan.min_available_mb(), 'max_hosts_per_task': openvas_scan.max_hosts(), 'max_hours': openvas_scan.max_hours(),
                  'confirmed_qod': openvas_scan.CONFIRMED_QOD, 'excluded_families': list(openvas_scan.EXCLUDED_FAMILIES)},
        'links': [link_dict(link) for link in links],
        'projects': [{'id': p.id, 'name': p.name, 'slug': p.slug, 'org': p.org.name if p.org else ''}
                     for p in Project.objects.select_related('org').order_by('name') if p.id not in linked],
    }


def set_schedule(enabled):
    """Turn the sweep's beat entry on or off together with the switch, so an install that never enables the add-on has nothing scheduled."""
    from django_celery_beat.models import IntervalSchedule, PeriodicTask
    from cveFeed.openvas_scan import BEAT_NAME, QUEUE
    interval, _ = IntervalSchedule.objects.get_or_create(every=15, period='minutes')
    task, _ = PeriodicTask.objects.get_or_create(name=BEAT_NAME, defaults={'task': 'openvas_sweep', 'interval': interval, 'enabled': False, 'queue': QUEUE})
    if task.enabled != enabled:
        task.enabled = enabled
        task.save()  # save, not update: the beat scheduler learns of a change through the model's signal


def openvas_put(request):
    from cveFeed.admin_api import audit
    from cveFeed.models import OpenvasSettings
    from cveFeed.settings_api import _body
    data = _body(request)
    row = OpenvasSettings.current()
    was = row.enabled
    if 'gmp_username' in data:
        row.gmp_username = clean_text(data['gmp_username'], 64)
    password = data.get('gmp_password')
    if isinstance(password, str) and password.strip():
        if len(password) > 200:
            raise _error(400, 'gmp_password is too long')
        row.gmp_password = password.strip()
    if data.get('clear_credentials'):
        row.gmp_username, row.gmp_password = '', ''
    if 'enabled' in data:
        row.enabled = bool(data['enabled'])
    if row.enabled and not (row.gmp_username and row.gmp_password):
        raise _error(400, 'save the GMP login first (`make openvas-user` creates and saves one); the add-on cannot be switched on without it')
    row.updated_by = request.user
    row.save()
    set_schedule(row.enabled)
    audit(request.user, 'openvas.enable' if row.enabled and not was else 'openvas.disable' if was and not row.enabled else 'openvas.update',
          'openvas', enabled=row.enabled, credentials=bool(row.gmp_username and row.gmp_password))
    return openvas_get(request)


def _project(project_id):
    from dashboard.models import Project
    project = Project.objects.filter(pk=project_id).first() if str(project_id).isdigit() else None
    if project is None:
        raise _error(404, 'project not found')
    return project


def _hosts(data, project, current):
    """The cleaned host list: ``current`` when the key is absent. Each entry must be a host the project already has (a name or address the
    scans found or a person added: OpenVAS never scans something the project does not own) and must pass the same gate as every other
    scanner (not excluded, not archived, not resolving to a prohibited range)."""
    if 'hosts' not in data:
        return current
    value = data['hosts']
    if isinstance(value, str):
        value = re.split(r'[\s,]+', value)
    if not isinstance(value, list):
        raise _error(400, 'hosts must be a list')
    out = []
    for item in value:
        item = clean_text(item, 253).lower()
        if not item:
            continue
        if not _HOST_RE.match(item):
            raise _error(400, f'{item!r} is not a host name or address')
        if item not in out:
            out.append(item)
    if len(out) > MAX_HOSTS:
        raise _error(400, f'at most {MAX_HOSTS} hosts per project')
    if out:
        from startScan.models import Subdomain
        from targetApp.models import Domain
        known = set(Subdomain.objects.filter(target_domain__project=project, name__in=out).values_list('name', flat=True))
        known |= {n.lower() for n in Domain.objects.filter(project=project).values_list('name', flat=True)}
        stranger = [h for h in out if h not in {k.lower() for k in known}]
        if stranger:
            raise _error(400, f'not a host of this project: {", ".join(stranger[:5])}')
        from targetApp.target_types import scannable_hosts
        allowed = set(scannable_hosts(out, project=project.id))
        refused = [h for h in out if h not in allowed]
        if refused:
            raise _error(400, f'refused (excluded, archived, or an address or name a scanner may not be pointed at): {", ".join(refused[:5])}')
    return out


def project_put(request, project_id):
    from cveFeed.admin_api import audit
    from cveFeed.models import OpenvasProject
    from cveFeed.settings_api import _body
    data = _body(request)
    project = _project(project_id)
    link = OpenvasProject.objects.filter(project=project).first() or OpenvasProject(project=project)
    link.hosts = _hosts(data, project, link.hosts or [])
    if 'enabled' in data:
        link.enabled = bool(data['enabled'])
    link.updated_by = request.user
    link.save()
    audit(request.user, 'openvas.project.update', project.slug, org=project.org_id, project=project.slug, enabled=link.enabled, hosts=len(link.hosts))
    return link_dict(link)


def project_delete(request, project_id):
    from cveFeed.admin_api import audit
    from cveFeed.models import OpenvasProject
    project = _project(project_id)
    link = OpenvasProject.objects.filter(project=project).first()
    if link is None:
        raise _error(404, 'that project has not opted in')
    link.delete()
    audit(request.user, 'openvas.project.remove', project.slug, org=project.org_id, project=project.slug)
    return {'deleted': True}


def openvas_test(request):
    """Ask a worker to connect, authenticate and read the feed state, and say what it found. Never raises for a down sidecar: that is the answer."""
    from cveFeed.models import OpenvasSettings
    from cveFeed.tasks import openvas_check
    row = OpenvasSettings.current()
    if not (row.gmp_username and row.gmp_password):
        return {'connected': False, 'error': 'no GMP login is saved yet', 'feed': None, 'guard': None, 'gmp_version': ''}
    try:
        return openvas_check.delay().get(timeout=40)
    except Exception:  # noqa: BLE001 - no worker answered in time: say so, never fail the page
        return {'connected': False, 'error': 'no worker answered; is the celery container running?', 'feed': None, 'guard': None, 'gmp_version': ''}
