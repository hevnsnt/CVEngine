"""First-run wizard API (/cve/api/welcome/): organization, project, AI key, first target.

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


def needs_welcome(user):
    """Superusers who have not finished the wizard (or have no project at all)."""
    if not user.is_superuser:
        return False
    profile = UserProfile.objects.filter(user=user).first()
    return not (profile and profile.onboarded) or not Project.objects.exists()


def state(request):
    org = Org.objects.exclude(name='Default').order_by('id').first() or Org.objects.order_by('id').first()
    project = Project.objects.order_by('id').first()
    cfg = AIProviderSettings.objects.first()
    return {
        'org': {'name': org.name, 'slug': org.slug, 'named': org.name != 'Default'} if org else None,
        'project': {'name': project.name, 'slug': project.slug, 'named': project.name != 'Default'} if project else None,
        'ai_ready': bool(cfg and cfg.enabled and (cfg.api_key or (cfg.provider in ('ollama', 'vllm') and cfg.base_url))),
        'targets': Domain.objects.count(),
        'onboarded': bool(UserProfile.objects.filter(user=request.user, onboarded=True).exists()),
    }


def save_org(request):
    name = str(_body(request).get('name', '')).strip()[:100]
    if len(name) < 2:
        raise WelcomeError(400, 'Give your organization a name (2 or more characters).')
    org = _untouched_default_org() or Org.objects.filter(name=name).first() or Org()
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
    org = Org.objects.exclude(name='Default').order_by('-id').first() or Org.objects.order_by('id').first()
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
    scan_id = None
    if domains and data.get('start', True):
        scan = discovery.start_discovery(Domain.objects.get(id=domains[0]['id']))
        scan_id = scan.id
    return {'created': [d['name'] for d in domains], 'already_exists': result['already_exists'], 'scan_id': scan_id,
            'project': slug}


def finish(request):
    profile, _ = UserProfile.objects.get_or_create(user=request.user)
    profile.onboarded = True
    profile.save(update_fields=['onboarded'])
    return state(request)


ROUTES = {
    ('GET', 'state'): state, ('POST', 'org'): save_org, ('POST', 'project'): save_project,
    ('POST', 'target'): add_first_target, ('POST', 'finish'): finish,
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
