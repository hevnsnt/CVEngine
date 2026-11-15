"""Local sign-in gating (CVENGINE_SSO_ENFORCE). Off unless hosted, SSO and enforcement are all on; then the password form and the Django admin
login are refused and the visitor is sent to the edge's SSO start, except inside a break-glass window set by the provisioner."""
import logging
import time

from django.conf import settings
from django.http import HttpResponseRedirect

from hostedsso.common import edge_verified, enforcing, sso_url

logger = logging.getLogger(__name__)

BREAKGLASS_MAX_SECONDS = 3600


def breakglass_active(now=None):
    """True while CVENGINE_SSO_BREAKGLASS_UNTIL is in the future and no more than an hour ahead of now (a later value is a mistake or a
    forgotten window, and counts as closed)."""
    until = getattr(settings, 'CVENGINE_SSO_BREAKGLASS_UNTIL', 0)
    if type(until) is not int or until <= 0:
        return False
    now = time.time() if now is None else now
    return now < until <= now + BREAKGLASS_MAX_SECONDS


def local_login_allowed(request):
    """True when local sign-in may proceed: not enforcing (the stock case), or a break-glass window is open and the request came through the edge."""
    if not enforcing():
        return True
    return breakglass_active() and edge_verified(request)


def refuse_local_login(request, candidate_next=None):
    """None when local sign-in may proceed, else the 302 to the edge's SSO start (with a validated ``next``)."""
    if local_login_allowed(request):
        return None
    return HttpResponseRedirect(sso_url(request, candidate_next if candidate_next is not None else request.GET.get('next') or request.POST.get('next')))


def breakglass_in_use(request):
    """True when this request is proceeding only because of the break-glass window."""
    return enforcing() and local_login_allowed(request)


def audit_breakglass(request, action, user=None, **detail):
    """One audit row and one log line for every break-glass step (attempt, success, refusal). Never raises."""
    from reNgine.client_ip import client_ip
    ip = client_ip(request) or ''
    logger.warning('sso break-glass: %s (user=%s ip=%s)', action, getattr(user, 'username', '-'), ip)
    try:
        from tenancy import audit
        if user is not None:
            audit.record_for_user(user, action, user, ip=ip, **detail)
        else:
            audit.record(None, action, str(detail.pop('attempted', ''))[:150], ip=ip, **detail)
    except Exception:  # noqa: BLE001
        logger.warning('sso break-glass: the audit row could not be written', exc_info=True)
