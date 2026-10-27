"""Bearer-token authentication for agents (REST /api/v1/ and MCP /mcp/)."""
import hashlib
import re
import secrets
from datetime import timedelta

from django.http import JsonResponse
from django.utils import timezone

TOKEN_PREFIX = 'cve_'
AGENT_PATHS = ('/api/v1/', '/mcp/')
MFA_REQUIRED_MESSAGE = ('your organization requires multi-factor authentication: set up MFA '
                        'in the web app (My account, /cve/account/) before using the API')
LAST_USED_RESOLUTION = timedelta(minutes=1)
SCOPE_FULL, SCOPE_INVENTORY = 'full', 'inventory'
TOKEN_SCOPES = (SCOPE_FULL, SCOPE_INVENTORY)
INVENTORY_PATH = re.compile(r'^/api/v1/projects/(?P<slug>[-\w]+)/inventory/?$')
DENIED_MESSAGE = 'this token is not allowed to do that (an inventory token can only post inventory reports to its own project)'


def hash_token(raw):
    return hashlib.sha256(raw.encode()).hexdigest()


def create_token(user, name, read_only=False, expires_at=None, scope=SCOPE_FULL, project=None):
    """Return (ApiToken, raw secret). The secret is shown once and never stored. An ``inventory`` token belongs to one project and can
    only post that project's host inventory reports (see ``request_allowed``)."""
    from dashboard.models import ApiToken
    if scope not in TOKEN_SCOPES:
        raise ValueError(f'unknown token scope {scope!r}')
    raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
    token = ApiToken.objects.create(
        user=user, name=name[:100], key_hash=hash_token(raw), prefix=raw[:8],
        read_only=read_only, expires_at=expires_at, scope=scope, project=project)
    return token, raw


def authenticate(raw):
    """Return the ApiToken for a raw bearer value, or None if unknown/revoked/expired/inactive."""
    from dashboard.models import ApiToken
    if not raw.startswith(TOKEN_PREFIX):
        return None
    token = ApiToken.objects.select_related('user', 'project').filter(key_hash=hash_token(raw), revoked=False).first()
    if not token or not token.user.is_active:
        return None
    if token.expires_at and token.expires_at <= timezone.now():
        return None
    return token


def request_allowed(token, request):
    """Whether ``token`` may make this request. Only a ``full`` token may make any; an ``inventory`` token may only POST its own
    project's inventory reports; a token of any other scope (a value this code does not know) may make none, so a scope that is
    misspelt or added later is closed, never open. Enforced before any route or MCP tool runs, so no handler can forget it."""
    if token.scope == SCOPE_FULL:
        return True
    if token.scope != SCOPE_INVENTORY:
        return False
    match = INVENTORY_PATH.match(request.path)
    return bool(request.method == 'POST' and match and token.project_id and match.group('slug') == token.project.slug)


def bearer_from(request):
    header = request.META.get('HTTP_AUTHORIZATION', '')
    return header[7:].strip() if header[:7].lower() == 'bearer ' else None


class AgentTokenMiddleware:
    """Authenticate agent requests from a bearer token, before login-required and tenancy run.

    Agent paths never fall through to the HTML login redirect: no valid credential is a 401 JSON.
    Token requests are CSRF exempt (no cookies involved).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.path.startswith(AGENT_PATHS):
            return self.get_response(request)
        raw = bearer_from(request)
        if raw:
            token = authenticate(raw)
            if not token:
                return JsonResponse({'error': 'invalid, expired or revoked token'}, status=401)
            if not request_allowed(token, request):
                return JsonResponse({'error': DENIED_MESSAGE}, status=403)
            request.user = token.user
            request.api_token = token
            request._dont_enforce_csrf_checks = True
            now = timezone.now()
            if not token.last_used_at or now - token.last_used_at > LAST_USED_RESOLUTION:
                type(token).objects.filter(pk=token.pk).update(last_used_at=now)
        elif not request.user.is_authenticated:
            return JsonResponse({'error': 'authentication required (Authorization: Bearer <token>)'}, status=401)
        # /api/v1/ and /mcp/ are exempt from the tenancy MFA redirect, so enforce the same rule here, for
        # sessions and for tokens owned by a user who still has to enrol (tokens work again once they do)
        from tenancy.middleware import TenancyMiddleware
        if TenancyMiddleware.must_enrol_mfa(request.user):
            return JsonResponse({'error': MFA_REQUIRED_MESSAGE}, status=403)
        return self.get_response(request)
