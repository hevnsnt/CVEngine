"""Small shared checks for the single sign-on views, middleware and login gating."""
import re
from urllib.parse import urlencode

from django.conf import settings
from django.shortcuts import resolve_url
from django.utils.http import url_has_allowed_host_and_scheme

SSO_START = '/_cvl/sso'
NEXT_RE = re.compile(r'^/(?![/\\])[^\s]{0,2047}$')  # the interface contract's rule for ``next``


def sso_active():
    """SSO is on only on a hosted server whose environment asks for it."""
    return bool(getattr(settings, 'CVENGINE_HOSTED', False) and getattr(settings, 'CVENGINE_SSO', False))


def enforcing():
    return bool(sso_active() and getattr(settings, 'CVENGINE_SSO_ENFORCE', False))


def edge_verified(request):
    """True only when the proxy checked the edge secret itself (it overwrites this header, so a client cannot set it)."""
    return request.META.get('HTTP_X_CVL_EDGE_VERIFIED') == '1'


def safe_next(request, candidate):
    """``candidate`` when it is a same-site path the contract allows, else the default landing page."""
    if (isinstance(candidate, str) and NEXT_RE.match(candidate)
            and url_has_allowed_host_and_scheme(candidate, allowed_hosts={request.get_host()}, require_https=request.is_secure())):
        return candidate
    return resolve_url(settings.LOGIN_REDIRECT_URL)


def sso_url(request, candidate=None):
    return SSO_START + '?' + urlencode({'next': safe_next(request, candidate)})
