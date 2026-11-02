"""First-run wizard API (/cve/api/welcome/): organization, project, AI key, first target, optional search-engine keys.

Superusers only. A fresh install already has an untouched "Default" org (the tenancy migration creates
it), so the wizard renames that in place instead of leaving a stray "Default" behind.
"""
import json

from django.http import JsonResponse
from django.utils import timezone
from django.utils.text import slugify

from dashboard.models import AIProviderSettings, Org, OrgMembership, Project, UserProfile
from targetApp.models import Domain
from tenancy import roles


class WelcomeError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status, self.message = status, message


def _body(request):
    try:
        data = json.loads(request.body or b'{}')
    except json.JSONDecodeError:
        raise WelcomeError(400, 'body must be valid JSON')
    return data if isinstance(data, dict) else {}


def _unique_slug(model, name, fallback, exclude_pk=None):
    base = slugify(name)[:50] or fallback
    slug, n = base, 2
    while model.objects.filter(slug=slug).exclude(pk=exclude_pk).exists():
        slug, n = f'{base}-{n}', n + 1
    return slug


def _untouched_default_org():
    """The migration-created org, if nothing has been built in it yet."""
    org = Org.objects.filter(slug='default').first()
    if org and not Domain.objects.filter(project__org=org).exists() and org.name == 'Default':
        return org
    return None


def _wizard_org(user):
    """The organization every wizard step works in: the newest one (not "Default") this superuser administers, else the newest
    named one, else the starter. One rule for the state, the project step and the org step, so they cannot pick different ones."""
    mine = Org.objects.filter(memberships__user=user, memberships__role='admin').exclude(name='Default').order_by('-id').first()
    return mine or Org.objects.exclude(name='Default').order_by('-id').first() or Org.objects.order_by('id').first()


def needs_welcome(user):
    """Superusers who have not finished the wizard (or have no project at all)."""
    if not user.is_superuser:
        return False
    profile = UserProfile.objects.filter(user=user).first()
    return not (profile and profile.onboarded) or not Project.objects.exists()


def state(request):
    org = _wizard_org(request.user)
    project = Project.objects.order_by('id').first()
    cfg = AIProviderSettings.objects.first()
    return {
        'org': {'name': org.name, 'slug': org.slug, 'named': org.name != 'Default'} if org else None,
        'project': {'name': project.name, 'slug': project.slug, 'named': project.name != 'Default'} if project else None,
        'ai_ready': bool(cfg and cfg.enabled and (cfg.api_key or (cfg.provider in ('ollama', 'vllm', 'lmstudio') and cfg.base_url))),
        'targets': Domain.objects.count(),
        'onboarded': bool(UserProfile.objects.filter(user=request.user, onboarded=True).exists()),
    }


def save_org(request):
    name = str(_body(request).get('name', '')).strip()[:100]
    if len(name) < 2:
        raise WelcomeError(400, 'Give your organization a name (2 or more characters).')
    org = _untouched_default_org() or Org.objects.filter(name=name).first()
    if org is None:
        # the step sent again with another name renames the organization the wizard made, while nothing is built in it
        own = _wizard_org(request.user)
        if own and own.name != 'Default' and OrgMembership.objects.filter(user=request.user, org=own, role='admin').exists() \
                and not Domain.objects.filter(project__org=own).exists():
            org = own
    org = org or Org()
    org.name = name
    if not org.pk:
        org.slug = _unique_slug(Org, name, 'org')
    org.save()
    OrgMembership.objects.get_or_create(user=request.user, org=org, defaults={'role': 'admin'})
    return state(request)


def save_project(request):
    data = _body(request)
    name = str(data.get('name', '')).strip()[:100]
    if len(name) < 2:
        raise WelcomeError(400, 'Give your project a name (2 or more characters).')
    if roles.is_reserved_project(name):
        raise WelcomeError(400, f'"{roles.ALL_PROJECTS}" is reserved for the all-projects view; choose another name.')
    org = _wizard_org(request.user)
    project = Project.objects.filter(org=org, name='Default').first() \
        if not Domain.objects.exists() else None  # rename the untouched starter project
    project = project or Project.objects.filter(org=org, name=name).first()
    if project is None:
        project = Project(insert_date=timezone.now(), org=org)
    project.name = name
    if not project.pk or (project.slug == 'default' and not Domain.objects.filter(project=project).exists()):
        project.slug = _unique_slug(Project, name, 'project', exclude_pk=project.pk)
    project.save()
    return state(request)


def add_first_target(request):
    from agentapi import services
    from cveFeed import discovery
    data = _body(request)
    if not data.get('authorized'):
        raise WelcomeError(400, 'Confirm you are authorized to test this target.')
    slug = data.get('project') or (Project.objects.order_by('id').values_list('slug', flat=True).first())
    ctx = services.Ctx(user=request.user)
    try:
        result = services.add_target(ctx, slug, str(data.get('value', '')))
    except services.ApiError as exc:
        raise WelcomeError(exc.status, exc.message)
    domains = result['created']
    names = [d['name'] for d in domains]
    scan_id = None
    if data.get('start', True):
        # A target that already exists (the page was reloaded, or the first attempt failed after saving it) starts discovery
        # too: starting is safe to repeat, since one that is already queued or running is returned instead of a second.
        again = [] if domains else list(Domain._base_manager.filter(name__in=result['already_exists'], project__slug=slug).order_by('id'))
        starting = list(Domain.objects.filter(id__in=[d['id'] for d in domains]).order_by('id')) or again
        if starting:
            try:
                scans = discovery.start_in_stored_modes(starting)  # a target that already exists keeps the mode it was given; a manual only one is not scanned
                scan_id = scans[0].id if scans else None
            except RuntimeError:  # no scan engine yet (a fresh install is still setting itself up)
                raise WelcomeError(503, 'The scanner is still starting up. Your target is saved; try again in a few seconds.')
    return {'created': names, 'already_exists': result['already_exists'], 'scan_id': scan_id, 'project': slug}


# Services the wizard offers: the keys that most improve passive discovery, in the order shown. The rest are in Settings.
WIZARD_KEY_SERVICES = ('shodan', 'virustotal', 'securitytrails')


def save_keys(request):
    """Save the optional keys from the wizard's last step. Values are written and never echoed back; a blank one is ignored."""
    from agentapi import services
    data = _body(request)
    keys = data.get('keys') if isinstance(data.get('keys'), dict) else {}
    slug = data.get('project') or Project.objects.order_by('id').values_list('slug', flat=True).first()
    ctx = services.Ctx(user=request.user)
    saved = []
    for service in WIZARD_KEY_SERVICES:
        value = str(keys.get(service) or '').strip()
        if not value:
            continue
        try:
            services.set_api_credential(ctx, slug, service, {'api_key': value})
        except services.ApiError as exc:
            raise WelcomeError(exc.status, exc.message)
        saved.append(service)
    return {'saved': saved}


def finish(request):
    profile, _ = UserProfile.objects.get_or_create(user=request.user)
    profile.onboarded = True
    profile.save(update_fields=['onboarded'])
    return state(request)


ROUTES = {
    ('GET', 'state'): state, ('POST', 'org'): save_org, ('POST', 'project'): save_project,
    ('POST', 'target'): add_first_target, ('POST', 'keys'): save_keys, ('POST', 'finish'): finish,
}


def dispatch(request, path):
    if not (request.user.is_authenticated and request.user.is_superuser):
        return JsonResponse({'error': 'superuser only'}, status=403)
    handler = ROUTES.get((request.method, path.strip('/')))
    if not handler:
        return JsonResponse({'error': 'not found'}, status=404)
    try:
        return JsonResponse(handler(request))
    except WelcomeError as exc:
        return JsonResponse({'error': exc.message}, status=exc.status)
