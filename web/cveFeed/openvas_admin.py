"""Settings > OpenVAS: the App Admin's switch for the optional OpenVAS add-on and the per-project opt-in.

Superuser only, like the rest of /cve/api/settings (the dispatcher enforces it, and so does the tenancy middleware). Switching the add-on on is
an instance-wide decision, so it is not delegated to project or organization roles, and the add-on is deliberately not part of the agent REST API
or MCP. This server runs no OpenVAS engine and holds no GMP login: a Sentinel's own gvmd containers scan, and this page only says which Sentinels
can (``sentinel_readiness``) and what the last run did.
"""
import logging
import re

from cveFeed.tailscale_api import clean_text

logger = logging.getLogger(__name__)

MAX_HOSTS = 200
_HOST_RE = re.compile(r'^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9._:-]*[A-Za-z0-9])?$')


def _error(status, message):
    from cveFeed.settings_api import SettingsError
    return SettingsError(status, message)


def apply_choice(link, flag):
    """A person's tick or untick of one project. Ticked: the project's own opt-in, or just back under its organization's when that covers it.
    Unticked while the organization covers the project: an explicit exclusion, which wins over the organization (the page showed the project as
    scanned, and the person said no); otherwise simply off."""
    from cveFeed.models import OpenvasOrg
    covered = OpenvasOrg.objects.filter(org_id=link.project.org_id, enabled=True).exists()
    if flag:
        link.excluded = False
        link.enabled = link.enabled or not covered
    else:
        link.enabled, link.excluded = False, covered


def effective(link, org_enabled):
    """Whether the sweep scans this project: its own opt-in, or its organization's unless the project was excluded (as ``openvas_scan.sweep_links``)."""
    return bool(link and link.enabled) or (org_enabled and not (link and link.excluded))


def link_dict(link):
    """One project's opt-in as the settings page sees it."""
    from cveFeed.models import OpenvasRun
    last = OpenvasRun.objects.filter(project=link.project).order_by('-id').first()
    return {
        'project': {'id': link.project_id, 'name': link.project.name, 'slug': link.project.slug}, 'enabled': link.enabled, 'excluded': link.excluded, 'hosts': list(link.hosts or []), 'forced_hosts': list(link.forced_hosts or []),
        'last_run': ({'status': last.status, 'gvm_status': last.gvm_status, 'progress': last.progress, 'error': last.error, 'summary': last.summary,
                      'started_at': last.started_at.isoformat(), 'finished_at': last.finished_at.isoformat() if last.finished_at else None}
                     if last else None),
    }


def sentinel_readiness():
    """Each Sentinel that can run OpenVAS, or that should be able to: ``{id, name, live, internal, declares, ready, reason}``. ``declares`` is the
    ``openvas`` capability (a Sentinel declares it only while its own GVM stack can scan); ``reason`` is what its GVM stack says when it is not
    ready (still syncing its feeds, no scan configuration, no login), or why this Sentinel does not scan (a light profile, a disabled kind)."""
    from agentapi.models import Agent
    from agentapi.sentinel_broker import INTERNAL_CAPABILITY, SentinelEff, effective_capabilities
    from django.utils import timezone
    now = timezone.now()
    out = []
    for agent in Agent.objects.filter(kind='scanner').exclude(status='revoked').order_by('name', 'id')[:100]:
        eff = SentinelEff(agent, now)
        reported = (agent.info or {}).get('openvas') or {}
        declares = 'openvas' in (eff.caps if not eff.problem else agent.capabilities or [])
        if eff.problem:
            reason = eff.problem
        elif agent.status != 'active':
            reason = f'the Sentinel is {agent.status}'
        elif declares:
            reason = ''
        else:
            reason = reported.get('reason') or ('its profile is light, or OpenVAS is turned off on it' if not reported else 'not ready')
        out.append({'id': agent.pk, 'name': agent.name, 'live': bool(eff.live), 'internal': INTERNAL_CAPABILITY in effective_capabilities(agent),
                    'declares': declares, 'ready': bool(eff.live and declares and agent.status == 'active'), 'reason': clean_text(reason, 200)})
    return out


def latest_run():
    """The newest OpenVAS run of any project, for the Settings page."""
    from cveFeed.models import OpenvasRun
    last = OpenvasRun.objects.order_by('-id').first()
    return ({'status': last.status, 'progress': last.progress, 'error': last.error, 'summary': last.summary, 'hosts': sorted(last.hosts.values()),
             'via': 'sentinel' if last.sentinel_task_id else 'local', 'started_at': last.started_at.isoformat(),
             'finished_at': last.finished_at.isoformat() if last.finished_at else None} if last else None)


def openvas_get(request):
    from cveFeed import openvas_scan
    from cveFeed.models import OpenvasProject, OpenvasRun, OpenvasSettings
    from dashboard.models import Project
    row = OpenvasSettings.current()
    links = OpenvasProject.objects.select_related('project').order_by('project__name')
    linked = {link.project_id for link in links}
    return {
        'enabled': row.enabled, 'sentinel_only': True,  # always: the server runs no engine of its own
        'sentinels': sentinel_readiness(), 'last_run': latest_run(),
        'running': OpenvasRun.objects.filter(status='running').exists(),
        'floor': {'max_hosts_per_task': openvas_scan.max_hosts(), 'max_hours': openvas_scan.max_hours(),
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
    if 'enabled' in data:
        row.enabled = bool(data['enabled'])
    row.updated_by = request.user
    row.save()
    set_schedule(row.enabled)
    audit(request.user, 'openvas.enable' if row.enabled and not was else 'openvas.disable' if was and not row.enabled else 'openvas.update',
          'openvas', enabled=row.enabled)
    return openvas_get(request)


def _project(project_id):
    from dashboard.models import Project
    project = Project.objects.filter(pk=project_id).first() if str(project_id).isdigit() else None
    if project is None:
        raise _error(404, 'project not found')
    return project


def _hosts(data, project, current, key='hosts'):
    """The cleaned host list: ``current`` when the key is absent. Each entry must be a host the project already has (a name or address the
    scans found or a person added: OpenVAS never scans something the project does not own) and must pass the same gate as every other
    scanner (not excluded, not archived, not resolving to a prohibited range)."""
    if key not in data:
        return current
    value = data[key]
    if isinstance(value, str):
        value = re.split(r'[\s,]+', value)
    if not isinstance(value, list):
        raise _error(400, f'{key} must be a list')
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
    link.forced_hosts = [h for h in _hosts(data, project, link.forced_hosts or [], 'forced_hosts')]
    if 'enabled' in data:
        apply_choice(link, bool(data['enabled']))
    link.updated_by = request.user
    link.save()
    audit(request.user, 'openvas.project.update', project.slug, org=project.org_id, project=project.slug, enabled=link.enabled, hosts=len(link.hosts),
          forced=len(link.forced_hosts))
    return link_dict(link)


def project_queue(request, project_id):
    """What the sweep would do with each candidate host of one project right now, and why (``openvas_scan.explain``): Fire or Smoke hosts and the
    listed ones, in scan order, then the ones that are not due with the reason."""
    from cveFeed import openvas_scan
    from cveFeed.models import OpenvasProject
    project = _project(project_id)
    link = OpenvasProject.objects.filter(project=project).first() or OpenvasProject(project=project)
    return {'project': project.slug, 'enabled': link.enabled, 'hosts_per_task': openvas_scan.max_hosts(), 'budget_hours_per_host': openvas_scan.max_hours(),
            'candidates': openvas_scan.explain(link)[:200]}


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
    """The state of OpenVAS as this server can know it: which Sentinels can run it (their own gvmd containers say so in their heartbeat). The server
    holds no connection to an engine, so there is nothing to connect to."""
    return {'connected': any(s['ready'] for s in sentinel_readiness()), 'sentinels': sentinel_readiness(), 'error': '', 'feed': None, 'guard': None,
            'gmp_version': ''}


# ----------------------------------------------------------------------------- the simple page: switch it on, choose what it looks at
# App Admins and Org Admins use these (the ``/cve/api/admin`` routes). The instance-wide engine is switched on and off by an App Admin only;
# once it is on, Org Admins choose their organizations and projects. Nothing is typed: the GMP login is made by the worker (``openvas_scan.ensure_login``) and
# the containers are started by the host's watcher (``scripts/openvas-sync.sh``), which the web container asks through a flag file.

def engine_status(row):
    """One plain answer for the page: ``{state, headline, detail, fix}``. ``state`` is off or ready (ready: the work goes to a Sentinel; with none
    eligible a due host stays due)."""
    if not row.enabled:
        return {'state': 'off', 'headline': 'Off', 'detail': '', 'fix': None}
    return {'state': 'ready', 'headline': 'Sentinel only', 'fix': None,
            'detail': 'This server never runs OpenVAS itself. A due host with no eligible Sentinel stays due until one is.'}


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
        covered = bool(org_on.get(org.pk))
        # ``enabled`` is what the sweep does (the project's own opt-in, or its organization's unless excluded); ``via_org`` says which.
        projects = [{'id': p.id, 'name': p.name, 'enabled': effective(links.get(p.id), covered), 'via_org': covered and not (links.get(p.id) and links[p.id].enabled)
                     and not (links.get(p.id) and links[p.id].excluded), 'excluded': bool(links.get(p.id) and links[p.id].excluded), 'last_run': _last_run(p.id)}
                    for p in Project.objects.filter(org_id=org.pk).order_by('name')]
        groups.append({'id': org.pk, 'name': org.name, 'enabled': covered, 'projects': projects})
    return {'engine': {'enabled': row.enabled, 'sentinel_only': True, 'can_switch': actor.is_superuser, **engine_status(row)},
            'orgs': groups, 'who': 'app_admin' if actor.is_superuser else 'org_admin'}


def _engine(request, actor, on):
    """Switch the whole add-on on or off: the sweep's beat entry. The scanning itself is a Sentinel's."""
    from cveFeed.admin_api import audit
    from cveFeed.models import OpenvasSettings
    row = OpenvasSettings.current()
    if row.enabled == on:
        return
    row.enabled = on
    row.updated_by = actor
    row.save()
    set_schedule(on)
    audit(actor, 'openvas.enable' if on else 'openvas.disable', 'openvas', enabled=on)


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
    """Apply a choice: ``{"orgs": {"3": true}, "projects": {"7": false}, "enabled": true}``. Only organizations (and their projects) the person
    administers can be chosen, and only once the add-on is on; only an App Admin may send ``enabled`` (switch it on or off for everyone)."""
    from cveFeed.admin_api import AdminError, _body, audit
    from cveFeed.models import OpenvasOrg, OpenvasProject
    from dashboard.models import Org, Project
    from tenancy import roles
    data = _body(request)
    managed = roles.managed_org_ids(actor)
    orgs = _flags(data.get('orgs', {}), 'orgs')
    projects = _flags(data.get('projects', {}), 'projects')
    if ('enabled' in data or 'sentinel_only' in data) and not actor.is_superuser:
        raise AdminError(403, 'only an App Admin switches OpenVAS on or off')
    from cveFeed.models import OpenvasSettings
    if not OpenvasSettings.current().enabled and not data.get('enabled') and (any(orgs.values()) or any(projects.values())):
        raise AdminError(409, 'an App Admin has to switch OpenVAS on first')
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
        apply_choice(link, flag)
        link.updated_by = actor
        link.save()
        audit(actor, 'openvas.project.update', project.slug, org=project.org_id, project=project.slug, enabled=link.enabled, excluded=link.excluded)
    if 'sentinel_only' in data:
        # Applied before _engine() below: a single request that both switches the engine on and sets sentinel_only
        # must never ask the host to start the local containers, which it would if _engine() read the old value.
        from cveFeed.admin_api import audit
        row = OpenvasSettings.current()
        row.sentinel_only, row.updated_by = bool(data['sentinel_only']), actor
        row.save()
        audit(actor, 'openvas.update', 'openvas', sentinel_only=row.sentinel_only)
    if 'enabled' in data:
        _engine(request, actor, bool(data['enabled']))
    return admin_get(request, actor)


def admin_check(request, actor):
    """The page's "look at the scanner now": this server holds no engine to look at, so it answers with the current state."""
    return admin_get(request, actor)
