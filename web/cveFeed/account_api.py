"""The signed-in user's own account: profile, password, two-step sign-in, and a plain account of what they can reach."""
import json
import re

from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.db import transaction

from dashboard.models import ApiToken, OrgMembership, ProjectMembership, UserProfile
from tenancy import audit, mfa, roles, throttle
from tenancy.views import SETUP_SECRET_KEY, check_second_factor, clear_failures, fail, locked, profile_of

PASSWORD_MAX_FAILURES = 5
PASSWORD_LOCK_SECONDS = 600


class AccountError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status, self.message = status, message


def _body(request):
    try:
        data = json.loads(request.body or b'{}')
    except json.JSONDecodeError:
        raise AccountError(400, 'body must be valid JSON')
    return data if isinstance(data, dict) else {}


def account_payload(user):
    profile = UserProfile.objects.filter(user=user).first()
    orgs = [{'scope': 'Organization', 'name': m.org.name, 'role': roles.ROLE_LABELS.get(('org', m.role), m.role), 'mfa_required': m.org.require_mfa}
            for m in OrgMembership.objects.filter(user=user).select_related('org')]
    projects = [{'scope': 'Project', 'name': m.project.name, 'role': roles.ROLE_LABELS.get(('project', m.role), m.role)}
                for m in ProjectMembership.objects.filter(user=user).select_related('project')]
    access = [{'scope': 'Everything', 'name': 'This CVEngine instance', 'role': 'App Admin'}] if user.is_superuser else orgs + projects
    return {
        'username': user.username, 'first_name': user.first_name, 'last_name': user.last_name,
        'name': user.get_full_name() or user.username, 'email': user.email,
        'role': 'App Admin' if user.is_superuser else (access[0]['role'] if access else 'No access yet'),
        'access': access, 'is_admin': roles.is_admin_anywhere(user),
        'mfa_enabled': bool(profile and profile.mfa_enabled), 'mfa_required': roles.requires_mfa(user),
        'bugbounty_enabled': user.is_superuser or bool(profile and profile.bugbounty_enabled),
        'must_change_password': bool(profile and profile.must_change_password),
        'tokens': ApiToken.objects.filter(user=user, revoked=False).count(),
        'last_login': user.last_login.isoformat() if user.last_login else None, 'date_joined': user.date_joined.isoformat(),
    }


def get_account(request):
    return account_payload(request.user)


def update_profile(request):
    data, user = _body(request), request.user
    email = str(data.get('email', user.email)).strip()[:254]
    if email and not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email):
        raise AccountError(400, 'that does not look like an email address')
    user.first_name = str(data.get('first_name', user.first_name)).strip()[:150]
    user.last_name = str(data.get('last_name', user.last_name)).strip()[:150]
    user.email = email
    user.save(update_fields=['first_name', 'last_name', 'email'])
    return account_payload(user)


def change_password(request):
    data, user = _body(request), request.user
    key = f'pw-change-fail:{user.pk}'
    if throttle.exceeded(key, PASSWORD_MAX_FAILURES):
        raise AccountError(429, 'too many wrong passwords; try again in a few minutes')
    if not user.check_password(str(data.get('current', ''))):
        throttle.count(key, PASSWORD_LOCK_SECONDS)
        raise AccountError(400, 'your current password is not correct')
    throttle.clear(key)
    new = str(data.get('new', ''))
    if new == data.get('current'):
        raise AccountError(400, 'choose a different password')
    try:
        validate_password(new, user)
    except ValidationError as exc:
        raise AccountError(400, ' '.join(exc.messages))
    user.set_password(new)
    user.save()
    update_session_auth_hash(request, user)  # keep this session signed in
    # Like an administrator reset, a password change cuts off bearer tokens: otherwise a token minted
    # from a stolen session would outlive the very password change meant to end the compromise.
    ApiToken.objects.filter(user=user, revoked=False).update(revoked=True)
    profile, _ = UserProfile.objects.get_or_create(user=user)
    profile.must_change_password = False
    profile.save(update_fields=['must_change_password'])
    audit.record_for_user(user, 'account.password_change', user)
    return account_payload(user)


def mfa_start(request):
    """Begin enrolment: a fresh secret kept in the session until a code from the authenticator app confirms it."""
    if profile_of(request.user).mfa_enabled:
        raise AccountError(400, 'two-step sign-in is already on')
    secret = request.session[SETUP_SECRET_KEY] = mfa.new_secret()
    return {'secret': secret, 'uri': mfa.otpauth_uri(secret, request.user.username)}


@transaction.atomic
def mfa_enable(request):
    data, user = _body(request), request.user
    initial = profile_of(user)
    profile = UserProfile.objects.select_for_update().get(pk=initial.pk)
    if profile.mfa_enabled:
        raise AccountError(400, 'two-step sign-in is already on')
    secret = request.session.get(SETUP_SECRET_KEY)
    if not secret:
        raise AccountError(400, 'start setup again: the setup key expired')
    step = mfa.verify(secret, str(data.get('code', '')))
    if not step:
        raise AccountError(400, 'that code is not valid. Check the time on your phone and try again.')
    plain, hashes = mfa.new_recovery_codes()
    profile.mfa_secret, profile.mfa_enabled = secret, True
    profile.recovery_codes, profile.mfa_last_step = hashes, step
    profile.save(update_fields=['mfa_secret', 'mfa_enabled', 'recovery_codes', 'mfa_last_step'])
    request.session.pop(SETUP_SECRET_KEY, None)
    audit.record_for_user(user, 'account.mfa_enable', user)
    return {**account_payload(user), 'recovery_codes': plain}


@transaction.atomic
def mfa_disable(request):
    data, user = _body(request), request.user
    initial = profile_of(user)
    profile = UserProfile.objects.select_for_update().get(pk=initial.pk)
    if not profile.mfa_enabled:
        raise AccountError(400, 'two-step sign-in is already off')
    if roles.requires_mfa(user):
        raise AccountError(400, 'your organization requires two-step sign-in')
    if locked(user):
        raise AccountError(429, 'too many attempts. Try again in a few minutes.')
    if not check_second_factor(profile, str(data.get('code', ''))):
        fail(user)
        raise AccountError(400, 'that code is not valid')
    clear_failures(user)
    profile.mfa_enabled, profile.mfa_secret, profile.recovery_codes = False, '', []
    profile.save(update_fields=['mfa_enabled', 'mfa_secret', 'recovery_codes'])
    audit.record_for_user(user, 'account.mfa_disable', user)
    return account_payload(user)


ROUTES = {('GET', 'me'): get_account, ('PATCH', 'profile'): update_profile, ('POST', 'password'): change_password,
          ('POST', 'mfa/start'): mfa_start, ('POST', 'mfa/enable'): mfa_enable, ('POST', 'mfa/disable'): mfa_disable}


def dispatch(request, path):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'sign in first'}, status=401)
    handler = ROUTES.get((request.method, path.strip('/')))
    if not handler:
        return JsonResponse({'error': 'not found'}, status=404)
    try:
        return JsonResponse(handler(request))
    except AccountError as exc:
        return JsonResponse({'error': exc.message}, status=exc.status)
