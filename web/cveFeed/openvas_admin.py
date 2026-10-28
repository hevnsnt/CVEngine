"""Settings > OpenVAS: the App Admin's switch for the optional Greenbone add-on, its GMP login, the per-project opt-in and the connection state.

Superuser only, like the rest of /cve/api/settings (the dispatcher enforces it, and so does the tenancy middleware). Switching the add-on on is
the act that allows any scan by the sidecar at all, an instance-wide decision, so it is not delegated to project or organization roles, and the
add-on is deliberately not part of the agent REST API or MCP. The GMP password is write-only: a response says whether it is set, never what
it is, and a blank field on update keeps the stored value. The Test connection runs in a worker (the web container has no sidecar socket)
and reads the saved login; no credential is put in a task message.
"""
import json
import logging
import os
import re
import time

from django.conf import settings

from cveFeed.tailscale_api import clean_text

logger = logging.getLogger(__name__)

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


# ----------------------------------------------------------------------------- the simple page: switch it on, choose what it looks at
# App Admins and Org Admins use these (the ``/cve/api/admin`` routes). The instance-wide engine is switched on by the first choice anybody
# makes, and only an App Admin switches it off. Nothing is typed: the GMP login is made by the worker (``openvas_scan.ensure_login``) and
# the containers are started by the host's watcher (``scripts/openvas-sync.sh``), which the web container asks through a flag file.

WANTED = '.openvas-wanted'  # written here: "on" or "off"
APPLIED = '.openvas-applied'  # written by scripts/openvas-sync.sh: {"want": "on", "ok": true, "error": "", "at": 1700000000}


def _path(name):
    return os.path.join(settings.BASE_DIR, name)


def request_containers(on):
    """Ask the host's watcher to start (or stop) the Greenbone containers: the web container has no Docker access on purpose. Returns whether the
    request could be written."""
    tmp = _path(WANTED + '.tmp')
    try:
        with open(tmp, 'w') as f:
            f.write('on\n' if on else 'off\n')
        os.replace(tmp, _path(WANTED))
        return True
    except OSError:
        logger.warning('could not write %s', WANTED)
        return False


def host_report():
    """What the host's watcher did with the last request: ``{want, ok, error, at}``, or ``None`` when it has not answered."""
    try:
        with open(_path(APPLIED)) as f:
            data = json.loads(f.read(2000))
        return {'want': 'on' if data.get('want') == 'on' else 'off', 'ok': bool(data.get('ok')), 'error': clean_text(data.get('error') or '', 200),
                'at': float(data.get('at') or 0)}
    except (OSError, ValueError, TypeError, AttributeError):
        return None


def engine_status(row):
    """One plain answer for the page: ``{state, headline, detail}``. ``state`` is off, starting, loading, ready or problem."""
    from cveFeed import updater
    if not row.enabled:
        return {'state': 'off', 'headline': 'Off', 'detail': 'Choose what to scan below and it switches on by itself.'}
    seen = row.state or {}
    if seen.get('connected'):
        feed = seen.get('feed') or {}
        guard = seen.get('guard') or {}
        if not feed.get('ready'):
            return {'state': 'loading', 'headline': 'Getting ready',
                    'detail': 'Downloading the vulnerability tests. The first time takes from several minutes to a few hours; scans start by themselves when it ends. ' + clean_text(feed.get('reason') or '', 160)}
        if guard and not guard.get('ok'):
            return {'state': 'ready', 'headline': 'Ready, waiting for memory', 'detail': clean_text(guard.get('reason') or '', 200)}
        return {'state': 'ready', 'headline': 'Ready', 'detail': 'Hosts are scanned a few at a time, each once a week.'}
    report = host_report()
    if report and report['want'] == 'on' and not report['ok']:
        return {'state': 'problem', 'headline': 'The scanner could not be started', 'detail': report['error'] or 'The host could not start the containers. See web/.openvas-log on the host.'}
    error = seen.get('error') or ''
    if 'default login' in error or 'refused' in error:
        return {'state': 'problem', 'headline': 'The scanner login needs help', 'detail': error}
    if not updater.host_updater()['alive'] and not (report and report['want'] == 'on' and report['ok']):
        return {'state': 'problem', 'headline': 'Nothing on the host can start it',
                'detail': 'Run "make openvas-up" on the host once, or install the updater (scripts/install-updater.sh) so this page can start it for you.'}
    return {'state': 'starting', 'headline': 'Starting', 'detail': 'Starting the scanner containers. This takes a minute or two.'}


def _last_run(project_id):
    from cveFeed.models import OpenvasRun
    last = OpenvasRun.objects.filter(project_id=project_id).order_by('-id').first()
    if not last:
        return None
    return {'status': last.status, 'progress': last.progress, 'error': last.error, 'finished_at': last.finished_at.isoformat() if last.finished_at else None}


def admin_get(request, actor):
    """What this person may aim OpenVAS at (their organizations and those organizations' projects, or everything for an App Admin) and how
    the scanner is doing."""
    from cveFeed.models import OpenvasOrg, OpenvasProject, OpenvasSettings
    from dashboard.models import Org, Project
    from tenancy import roles
    row = OpenvasSettings.current()
    managed = roles.managed_org_ids(actor)
    org_on = dict(OpenvasOrg.objects.filter(org_id__in=managed).values_list('org_id', 'enabled'))
    links = {l.project_id: l for l in OpenvasProject.objects.filter(project__org_id__in=managed).select_related('project')}
    groups = []
    for org in Org.objects.filter(pk__in=managed).order_by('name'):
        projects = [{'id': p.id, 'name': p.name, 'enabled': bool(links.get(p.id) and links[p.id].enabled), 'last_run': _last_run(p.id)}
                    for p in Project.objects.filter(org_id=org.pk).order_by('name')]
        groups.append({'id': org.pk, 'name': org.name, 'enabled': bool(org_on.get(org.pk)), 'projects': projects})
    return {'engine': {'enabled': row.enabled, 'can_switch_off': actor.is_superuser, **engine_status(row)}, 'orgs': groups,
            'who': 'app_admin' if actor.is_superuser else 'org_admin'}


def _engine(request, actor, on):
    """Switch the whole add-on on or off: the sweep's beat entry, the containers (through the host's watcher) and, on, a first check that makes
    the login."""
    from cveFeed.admin_api import audit
    from cveFeed.models import OpenvasSettings
    row = OpenvasSettings.current()
    if row.enabled == on:
        if on and not (row.state or {}).get('connected'):
            request_containers(True)  # asking again is how a person retries after a failed start
        return
    row.enabled = on
    row.updated_by = actor
    row.save()
    set_schedule(on)
    request_containers(on)
    audit(actor, 'openvas.enable' if on else 'openvas.disable', 'openvas', enabled=on)
    if on:
        try:
            from cveFeed.tasks import openvas_check
            openvas_check.delay()
        except Exception:  # noqa: BLE001 - no broker right now: the sweep makes the login at its next step
            logger.info('could not queue the first OpenVAS check')


def _flags(value, what):
    from cveFeed.admin_api import AdminError
    if not isinstance(value, dict):
        raise AdminError(400, f'{what} must be an object of id: true or false')
    out = {}
    for key, flag in value.items():
        if not str(key).isdigit() or not isinstance(flag, bool):
            raise AdminError(400, f'{what} must map ids to true or false')
        out[int(key)] = flag
    return out


def admin_put(request, actor):
    """Apply a choice: ``{"orgs": {"3": true}, "projects": {"7": false}, "enabled": false}``. Only organizations (and their projects) the person
    administers can be chosen; only an App Admin may send ``enabled`` (to switch the add-on off for everyone)."""
    from cveFeed.admin_api import AdminError, _body, audit
    from cveFeed.models import OpenvasOrg, OpenvasProject
    from dashboard.models import Org, Project
    from tenancy import roles
    data = _body(request)
    managed = roles.managed_org_ids(actor)
    orgs = _flags(data.get('orgs', {}), 'orgs')
    projects = _flags(data.get('projects', {}), 'projects')
    if 'enabled' in data and not actor.is_superuser:
        raise AdminError(403, 'only an App Admin switches OpenVAS off for everyone')
    if any(i not in managed for i in orgs):
        raise AdminError(403, 'you do not administer one of those organizations')
    found = {p.pk: p for p in Project.objects.filter(pk__in=projects)}
    if len(found) != len(projects):
        raise AdminError(404, 'project not found')
    if any(p.org_id not in managed for p in found.values()):
        raise AdminError(403, 'you do not administer the organization of one of those projects')
    for org in Org.objects.filter(pk__in=orgs):
        link = OpenvasOrg.objects.filter(org=org).first() or OpenvasOrg(org=org)
        link.enabled, link.updated_by = orgs[org.pk], actor
        link.save()
        audit(actor, 'openvas.org.update', org.slug, org=org.pk, enabled=link.enabled)
    for pid, flag in projects.items():
        project = found[pid]
        link = OpenvasProject.objects.filter(project=project).first() or OpenvasProject(project=project)
        link.enabled, link.updated_by = flag, actor
        link.save()
        audit(actor, 'openvas.project.update', project.slug, org=project.org_id, project=project.slug, enabled=link.enabled)
    if 'enabled' in data:
        _engine(request, actor, bool(data['enabled']))
    elif any(orgs.values()) or any(projects.values()):
        _engine(request, actor, True)
    return admin_get(request, actor)


def admin_check(request, actor):
    """Look at the scanner now (the page asks while it is starting): makes the login when there is none and reads the feed. A worker does it, since
    only a worker has gvmd's socket."""
    from cveFeed.models import OpenvasSettings
    row = OpenvasSettings.current()
    if row.enabled:
        report = host_report()
        if report and report['want'] == 'on' and not report['ok']:
            request_containers(True)  # "Try again" after a failed start
        from cveFeed.tasks import openvas_check
        try:
            openvas_check.delay().get(timeout=40)
        except Exception:  # noqa: BLE001 - no worker answered in time: the status says what is known
            logger.info('the OpenVAS check did not answer in time')
    return admin_get(request, actor)
