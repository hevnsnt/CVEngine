"""Tenancy middleware: publish the user's project scope, enforce roles per project."""
import re

from django.http import HttpResponseForbidden, HttpResponseNotFound, JsonResponse
from django.shortcuts import render
from django.shortcuts import redirect
from django.urls import reverse

from tenancy import roles, scope

PROJECT_PARAMS = ('slug', 'project_slug', 'project')


class TenancyMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, 'user', None)
        if not (user and user.is_authenticated):
            return self.get_response(request)
        tokens = scope.set_scope(roles.allowed_project_ids(user), user)
        try:
            return self.get_response(request)
        finally:
            scope.reset_scope(tokens)

    def process_view(self, request, view_func, view_args, view_kwargs):
        user = request.user
        if user.is_authenticated and not getattr(request, 'api_token', None):
            blocked = self._temporary_password(request, user)
            if blocked:
                return blocked
        if not user.is_authenticated or roles.ALWAYS_OPEN.match(request.path):
            return None
        redirect_response = self._require_mfa(request, user)
        if redirect_response:
            return redirect_response
        slug = view_kwargs.get('slug') or next(
            (request.GET.get(p) for p in PROJECT_PARAMS if request.GET.get(p)), None)
        role = self._role_for(user, slug)
        profile = getattr(user, 'tenancy_profile', None)
        reason = roles.check_access(
            role, request.method, request.path,
            bugbounty_enabled=bool(profile and profile.bugbounty_enabled), is_superuser=user.is_superuser)
        if reason:
            if reason == 'no access to this project' and slug:
                # same answer whether the project is missing or off limits (no existence leak); the standalone
                # 404 page needs no project, so browsers get the themed one
                if request.path.startswith(('/api/', '/cve/api/')):
                    return JsonResponse({'error': 'not found'}, status=404)
                return render(request, '404.html', status=404)
            if request.path.startswith(('/api/', '/cve/api/')):
                return JsonResponse({'error': reason}, status=403)
            return render(request, 'error.html', {'code': 403, 'title': 'Not allowed', 'message': reason}, status=403)
        request.project_role = role
        return None

    EXEMPT_FROM_PASSWORD_CHANGE = re.compile(r'^/(logout|mfa|staticfiles|cve/account|cve/api/account)(/|$)')

    def _temporary_password(self, request, user):
        """An account whose password an administrator set must choose its own before doing anything else."""
        profile = getattr(user, 'tenancy_profile', None)
        if not (profile and profile.must_change_password) or self.EXEMPT_FROM_PASSWORD_CHANGE.match(request.path):
            return None
        if request.path.startswith(('/api/', '/cve/api/')):
            return JsonResponse({'error': 'choose your own password first (My account)'}, status=403)
        return redirect('cve_account')

    @staticmethod
    def _role_for(user, slug):
        from dashboard.models import Project
        if not slug or slug == roles.ALL_PROJECTS:  # the all-projects view is read-only; every project in it is scoped by the data layer
            return roles.user_best_role(user)
        project = Project.objects.filter(slug=slug).first()  # scoped: None if not allowed
        return roles.effective_role(user, project) if project else None

    @staticmethod
    def must_enrol_mfa(user):
        """True when the user belongs to an organization that requires MFA and has not enrolled."""
        profile = getattr(user, 'tenancy_profile', None)
        if profile and profile.mfa_enabled:
            return False
        return roles.requires_mfa(user)

    @classmethod
    def _require_mfa(cls, request, user):
        return redirect(reverse('cve_account') + '#security') if cls.must_enrol_mfa(user) else None


class RetireClassicUiMiddleware:
    """The reNgine screens are gone. Their addresses forward to the matching CVEngine page; anything that
    would have changed data through them is refused. Downloads (exports, reports), /api/ and /admin/ stay."""

    KEEP = re.compile(r'^/(cve/|api/|mcp/|mfa/|login/|logout/|staticfiles/|admin/|swagger|favicon)|/export/|/create_report')
    MAP = [
        (re.compile(r'^/scan/(?P<slug>[-\w]+)/detail/(?P<id>\d+)'), '/cve/{slug}/scans/{id}/'),
        (re.compile(r'^/scan/(?P<slug>[-\w]+)/(history|scheduled)'), '/cve/{slug}/scans/'),
        (re.compile(r'^/scan/(?P<slug>[-\w]+)/(detail/vuln|detail/all)'), '/cve/{slug}/vulns/'),
        (re.compile(r'^/scan/(?P<slug>[-\w]+)/all/subdomains'), '/cve/{slug}/hosts/'),
        (re.compile(r'^/target/(?P<slug>[-\w]+)/'), '/cve/{slug}/targets/'),
        (re.compile(r'^/(?P<slug>[-\w]+)/profile'), '/cve/account/'),
        (re.compile(r'^/(?P<slug>[-\w]+)/admin_interface'), '/cve/admin/'),
        (re.compile(r'^/scanEngine/'), '/cve/settings/'),
    ]
    CLASSIC = re.compile(r'^/(target|scan|scanEngine|recon_note)/|^/[-\w]+/(dashboard|profile|admin_interface|search|projects|bountyhub)(/|$)|^/404/?$|^/delete/')

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path
        if request.user.is_authenticated and self.CLASSIC.search(path) and not self.KEEP.search(path):
            if request.method != 'GET':
                return JsonResponse({'error': 'the classic interface was retired; use /cve/'}, status=410)
            for pattern, target in self.MAP:
                m = pattern.match(path)
                if m:
                    return redirect(target.format(**m.groupdict()))
            return redirect('cve_dashboard')
        return self.get_response(request)
