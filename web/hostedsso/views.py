"""The two server-to-server endpoints of single sign-on, called by the edge only: the one-time assertion exchange and the back-channel logout.

Both answer 404 unless SSO is on, nginx vouched for the edge secret (``X-CVL-Edge-Verified: 1``) and the call carries ``X-CVL-SSO-Exchange: 1``, 405 to anything but POST, and never say which check failed."""
import json
import logging
import time
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import login
from django.contrib.sessions.models import Session
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import IntegrityError, transaction
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from hostedsso.common import edge_verified, exchange_header_ok, sso_active
from hostedsso.models import SsoIdentity, SsoJti
from hostedsso.verify import ASSERTION, LOGOUT, SsoError, verify
from reNgine.client_ip import client_ip
from tenancy import audit, throttle

logger = logging.getLogger(__name__)

MAX_BODY = 8192
JTI_KEEP = timedelta(minutes=10)
FAIL_LIMIT = 20  # refusals per client address per window
FAIL_WINDOW = 600


def _ip(request):
    return client_ip(request) or 'unknown'


def _throttle_key(request):
    return f'sso_fail:{_ip(request)}'


def _gate(request):
    """None to carry on, else the response for a request that must not be served."""
    if not sso_active() or not edge_verified(request) or not exchange_header_ok(request):
        return HttpResponse(status=404)
    if request.method != 'POST':
        response = HttpResponse(status=405)
        response['Allow'] = 'POST'
        return response
    if throttle.exceeded(_throttle_key(request), FAIL_LIMIT):
        return JsonResponse({'error': 'too_many_attempts'}, status=429)
    return None


def _refuse(request, status, error):
    throttle.count(_throttle_key(request), FAIL_WINDOW)
    response = JsonResponse({'error': error}, status=status)
    response['Cache-Control'] = 'no-store'
    return response


def _body_field(request, name):
    """The string member ``name`` of the JSON body, or None."""
    if len(request.body) > MAX_BODY:
        return None
    try:
        data = json.loads(request.body.decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        return None
    value = data.get(name) if isinstance(data, dict) else None
    return value if isinstance(value, str) and value else None


@csrf_exempt
def exchange(request):
    blocked = _gate(request)
    if blocked:
        return blocked
    assertion = _body_field(request, 'assertion')
    if assertion is None:
        return JsonResponse({'error': 'bad_request'}, status=400)
    try:
        claims = verify(assertion, ASSERTION)
    except SsoError:
        return _refuse(request, 401, 'invalid_assertion')
    now = timezone.now()
    try:
        with transaction.atomic():
            SsoJti.objects.filter(expires_at__lt=now).delete()  # rows past their ten minutes
            SsoJti.objects.create(jti=claims['jti'], expires_at=now + JTI_KEEP)
    except IntegrityError:
        logger.warning('sso: assertion refused (replayed jti)')
        return _refuse(request, 401, 'invalid_assertion')
    subject = str(claims['sub'])
    identity = SsoIdentity.objects.select_related('user').filter(issuer=claims['iss'], subject=subject).first()
    if identity is None:
        audit.record(None, 'sso.not_linked', f'sub:{subject}', ip=_ip(request))
        return _refuse(request, 403, 'not_linked')
    user = identity.user
    if not user.is_active:
        audit.record_for_user(user, 'sso.refused_inactive', user, ip=_ip(request))
        return _refuse(request, 403, 'not_linked')
    _sign_in(request, identity, claims)
    response = HttpResponse(status=204)
    response['Cache-Control'] = 'no-store'
    return response


def _sign_in(request, identity, claims):
    user = identity.user
    request.session.flush()  # whatever came with the request is not kept: the session key is new
    login(request, user, backend=settings.AUTHENTICATION_BACKENDS[0])
    seconds = min(claims['sexp'] - int(time.time()), settings.CVENGINE_SSO_MAX_AUTH_AGE)
    request.session['sso_sub'] = str(claims['sub'])
    request.session['sso_sid'] = claims['sid']
    request.session['sso_auth_time'] = claims['auth_time']
    request.session['sso_amr'] = list(claims['amr'])
    request.session.set_expiry(max(seconds, 1))
    _note_email(identity, claims['email'], request)
    identity.last_login_at = timezone.now()
    identity.save(update_fields=['last_login_at', 'email_seen'])
    audit.record_for_user(user, 'sso.login', user, ip=_ip(request), amr=list(claims['amr']))


def _note_email(identity, email, request):
    """The site's email for this person becomes the account's email at the next sign-in; a change is audited (old and new)."""
    email = email.strip()
    try:
        validate_email(email)
    except ValidationError:
        return
    user = identity.user
    if identity.email_seen != email:
        identity.email_seen = email
    if (user.email or '').lower() != email.lower():
        old = user.email
        user.email = email
        user.save(update_fields=['email'])
        audit.record_for_user(user, 'sso.email_changed', user, old=old, new=email, ip=_ip(request))


@csrf_exempt
def backchannel_logout(request):
    blocked = _gate(request)
    if blocked:
        return blocked
    token = _body_field(request, 'logout_token')
    if token is None:
        return JsonResponse({'error': 'bad_request'}, status=400)
    try:
        claims = verify(token, LOGOUT)
    except SsoError:
        return _refuse(request, 401, 'invalid_token')
    deleted = end_sessions(sid=claims.get('sid'), sub=str(claims['sub']) if 'sub' in claims else None)
    audit.record(None, 'sso.backchannel_logout', f"sid:{claims.get('sid', '-')} sub:{claims.get('sub', '-')}"[:300], sessions=deleted, ip=_ip(request))
    return HttpResponse(status=204)  # the same answer whether or not anything matched: repeating a logout is harmless


def end_sessions(sid=None, sub=None):
    """Delete every SSO-born session that matches the given family hash and/or subject. Sessions are stored by a keyed hash of their cookie
    (reNgine.hashed_sessions), so the rows are decoded and matched, then deleted by primary key."""
    from reNgine.hashed_sessions import SessionStore
    decoder = SessionStore()
    doomed = []
    for row in Session.objects.filter(expire_date__gt=timezone.now()).only('pk', 'session_data').iterator(chunk_size=500):
        try:
            data = decoder.decode(row.session_data)
        except Exception:  # noqa: BLE001
            continue
        if not data.get('sso_sub'):
            continue
        if (sid is None or data.get('sso_sid') == sid) and (sub is None or data.get('sso_sub') == sub):
            doomed.append(row.pk)
    if doomed:
        Session.objects.filter(pk__in=doomed).delete()
    return len(doomed)


# The edge calls these with no session; they authenticate by the signed token themselves (login_required_middleware reads this flag).
exchange.login_required = False
backchannel_logout.login_required = False
