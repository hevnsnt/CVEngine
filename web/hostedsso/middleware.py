"""Per-request binding of an SSO-born session to the edge, and the step-up (recent sign-in) rule.

No-op unless CVENGINE_HOSTED and CVENGINE_SSO are on. A session that came from an SSO exchange carries ``sso_sub`` and ``sso_sid``; each request must
bring the same values in ``X-CVL-SSO-Sub`` / ``X-CVL-SSO-Sid`` and nginx's ``X-CVL-Edge-Verified: 1``, else the session is flushed. The binding
only narrows access: a session that never came from SSO (local sign-in, API tokens) is not touched."""
import functools
import logging
import re
import time
from urllib.parse import quote

from django.conf import settings
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.utils.crypto import constant_time_compare

from hostedsso.common import SSO_START, edge_verified, safe_next, sso_active, stepup_url

logger = logging.getLogger(__name__)

API_PREFIXES = ('/api/', '/cve/api/', '/mcp/')

# What needs a sign-in no older than CVENGINE_SSO_STEPUP_AGE for a session that came from SSO: (method pattern, path pattern). Matching happens here, in
# one place, so no view is edited. Reads stay open; creating or changing credentials, people, roles, provider settings, exports and deleting do not.
_WRITE = r'POST|PUT|PATCH|DELETE'
STEP_UP_RULES = [(re.compile(m), re.compile(p)) for m, p in [
    (_WRITE, r'^/cve/api/admin/(users|memberships)(/|$)'),                    # users, roles and their credentials
    (_WRITE, r'^/cve/api/admin/orgs/\d+/api-keys(/|$)'),                      # third-party service keys of an organization
    (r'DELETE', r'^/cve/api/admin/(projects|orgs)/\d+/?$'),                   # project / organization delete
    (r'POST|PUT', r'^/api/v1/tokens/?$'),                                      # API tokens
    (r'DELETE', r'^/api/v1/tokens/\d+/?$'),
    (r'GET|POST', r'^/api/v1/(projects/[-\w]+/|orgs/[-\w]+/)?sentinels/enroll/?$'),  # Sentinel / fleet enrollment secrets
    (r'PUT|POST', r'^/cve/api/settings/(ai|keys|email|reviewer)(/test|/models)?/?$'),  # AI provider, API keys, mail credentials
    (r'PUT|POST|DELETE', r'^/cve/api/settings/tailscale(/|$)'),
    (r'GET', r'/export/'),                                   # data exports
    (r'GET', r'^/cve/api/settings/(cve_seed/download/|egress/connections\.csv)'),
]]


def sso_session(request):
    session = getattr(request, 'session', None)
    return bool(session is not None and session.get('sso_sub'))


def has_recent_auth(request, max_age=None):
    """True when the session did not come from SSO (nothing to step up), or its ``auth_time`` is within ``max_age`` seconds
    (default CVENGINE_SSO_STEPUP_AGE). Always True when SSO is off."""
    if not sso_active() or not sso_session(request):
        return True
    limit = settings.CVENGINE_SSO_STEPUP_AGE if max_age is None else max_age
    auth_time = request.session.get('sso_auth_time')
    return type(auth_time) is int and 0 <= time.time() - auth_time <= limit


def require_recent_auth(request, max_age=None):
    """None when the request may go on, else the refusal response (403, with the address to sign in again)."""
    if has_recent_auth(request, max_age):
        return None
    reauth = stepup_url(request, request.get_full_path() if request.method == 'GET' else None)
    if request.path.startswith(API_PREFIXES):
        return JsonResponse({'error': 'recent_auth_required', 'message': 'confirm your sign-in again to do this', 'reauth_url': reauth}, status=403)
    return render(request, 'error.html', {'code': 403, 'title': 'Confirm your sign-in',
                                          'message': 'This action needs a recent sign-in. Sign in again through cvengine.live, then retry.'}, status=403)


def recent_auth_required(view=None, *, max_age=None):
    """View decorator form of ``require_recent_auth`` (usable bare or with ``max_age``)."""
    def decorate(func):
        @functools.wraps(func)
        def wrapper(request, *args, **kwargs):
            refused = require_recent_auth(request, max_age)
            return refused if refused is not None else func(request, *args, **kwargs)
        return wrapper
    return decorate(view) if callable(view) else decorate


def _needs_step_up(request):
    return any(m.fullmatch(request.method) and p.search(request.path) for m, p in STEP_UP_RULES)


class SsoBindingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if sso_active() and sso_session(request):
            refused = self._bind(request) or self._step_up(request)
            if refused is not None:
                return refused
        return self.get_response(request)

    @staticmethod
    def _bind(request):
        session = request.session
        trusted = edge_verified(request)
        sub, sid = request.META.get('HTTP_X_CVL_SSO_SUB', ''), request.META.get('HTTP_X_CVL_SSO_SID', '')
        if (trusted and sub and sid and constant_time_compare(sub, str(session.get('sso_sub', '')))
                and constant_time_compare(sid, str(session.get('sso_sid', '')))):
            return None
        logger.warning('sso: session flushed (binding %s)', 'mismatch' if trusted and sub and sid else 'headers missing or untrusted')
        session.flush()
        if request.path.startswith(API_PREFIXES) or request.method not in ('GET', 'HEAD'):
            return JsonResponse({'error': 'sign in again'}, status=401)
        return HttpResponseRedirect(SSO_START + '?next=' + quote(safe_next(request, request.get_full_path()), safe=''))

    @staticmethod
    def _step_up(request):
        return require_recent_auth(request) if _needs_step_up(request) else None
