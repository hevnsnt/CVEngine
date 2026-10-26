"""MFA views: the two-step login. Enrolling and turning it off live on My account (cveFeed/account_api.py)."""
import hashlib
import math
import time
from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.views import LoginView, LogoutView
from django.core.cache import cache
from django.db import transaction
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.crypto import constant_time_compare, salted_hmac
from django.utils.http import url_has_allowed_host_and_scheme

from reNgine.client_ip import client_ip
from tenancy import mfa, throttle

PENDING_KEY = 'mfa_pending'
SETUP_SECRET_KEY = 'mfa_setup_secret'
PENDING_TTL = 300
MAX_FAILURES = 5
LOCKOUT_SECONDS = 300
# password step: failed attempts per window, per (address, name), per address and per name. The pair limit is tight; the name
# limit is loose so one stranger cannot lock the real owner out, and the address limit stops spraying many names from one place.
LOGIN_LIMITS = (('pair', 5), ('ip', 30), ('user', 50))


def profile_of(user):
    from dashboard.models import UserProfile
    return UserProfile.objects.get_or_create(user=user)[0]


def locked(user):
    return cache.get(f'mfa_fail:{user.pk}', 0) >= MAX_FAILURES


def fail(user):
    """Count one failed second factor. The counter lives in the shared Redis cache and is incremented atomically, so concurrent
    attempts (several web workers, several threads) cannot undercount; the lockout window starts at the first failure."""
    throttle.count(f'mfa_fail:{user.pk}', LOCKOUT_SECONDS)


def clear_failures(user):
    cache.delete(f'mfa_fail:{user.pk}')


@transaction.atomic
def check_second_factor(profile, code):
    """Consume one factor under a row lock, never trusting a caller's stale profile."""
    from dashboard.models import UserProfile
    current = UserProfile.objects.select_for_update().filter(pk=profile.pk).first()
    if not current or not current.mfa_enabled or not current.mfa_secret:
        return False
    step = mfa.verify(current.mfa_secret, code, last_used_step=current.mfa_last_step)
    if step:
        current.mfa_last_step = step
        current.save(update_fields=['mfa_last_step'])
        return True
    remaining = mfa.consume_recovery_code(current.recovery_codes, code or '')
    if remaining is not None:
        current.recovery_codes = remaining
        current.save(update_fields=['recovery_codes'])
        return True
    return False


def _factor_state(profile):
    """Bind a pending login to this enrollment without copying its secret to the session."""
    return salted_hmac('tenancy.pending-mfa', f'{profile.pk}:{profile.mfa_secret}').hexdigest()



def _valid_pending(pending):
    if not isinstance(pending, dict):
        return False
    ts = pending.get('ts')
    return (type(ts) in (int, float) and math.isfinite(ts)
            and 0 <= time.time() - ts <= PENDING_TTL
            and type(pending.get('user')) is int
            and pending.get('backend') in settings.AUTHENTICATION_BACKENDS
            and all(isinstance(pending.get(k), str) and pending[k]
                    for k in ('auth_hash', 'factor_state', 'next')))



class SignOutView(LogoutView):
    """Django 5 only signs out on POST. A GET (an old link or bookmark) asks first instead of failing."""
    http_method_names = ['get', 'post', 'options']

    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        return render(request, 'tenancy/signout_confirm.html')


def _login_keys(request, username):
    name = hashlib.sha256((username or '').strip().lower()[:150].encode()).hexdigest()[:32]
    ip = client_ip(request) or 'unknown'
    return {'pair': f'login_fail:pair:{ip}:{name}', 'ip': f'login_fail:ip:{ip}', 'user': f'login_fail:user:{name}'}


def login_throttled(request, username):
    keys = _login_keys(request, username)
    return any(throttle.exceeded(keys[kind], limit) for kind, limit in LOGIN_LIMITS)


class MFALoginView(LoginView):
    """Password step; users with MFA are not logged in until /mfa/verify/ succeeds. Wrong passwords are counted and, past a limit,
    refused before the password is even checked, so the login form cannot be used to guess passwords."""

    def post(self, request, *args, **kwargs):
        if login_throttled(request, request.POST.get('username')):
            form = self.get_form()
            form.is_valid()
            form.errors.pop('__all__', None)
            form.add_error(None, 'Too many failed sign-in attempts. Try again in a few minutes.')
            response = self.render_to_response(self.get_context_data(form=form))
            response.status_code = 429
            return response
        return super().post(request, *args, **kwargs)

    def form_invalid(self, form):
        keys = _login_keys(self.request, self.request.POST.get('username'))
        for key in keys.values():
            throttle.count(key, LOCKOUT_SECONDS)
        return super().form_invalid(form)

    def form_valid(self, form):
        user = form.get_user()
        cache.delete(_login_keys(self.request, self.request.POST.get('username'))['pair'])
        profile = getattr(user, 'tenancy_profile', None)
        self.request.session.pop(PENDING_KEY, None)
        if not (profile and profile.mfa_enabled):
            return super().form_valid(form)
        self.request.session[PENDING_KEY] = {
            'user': user.pk, 'backend': user.backend, 'next': self.get_success_url(), 'ts': time.time(),
            'auth_hash': user.get_session_auth_hash(), 'factor_state': _factor_state(profile)}
        return redirect('mfa_verify')


def admin_login_redirect(request):
    """Django's own /admin/login/ signs a staff user in with the password alone, which would skip the second step MFALoginView
    enforces at /login/. It is never served: a signed-out visitor is sent to /login/ (keeping a safe ``next``), a signed-in staff
    user on to the admin, and anyone else to the app, so the redirect cannot loop with the admin's own permission check."""
    target = request.GET.get('next', '')
    user = request.user
    if user.is_authenticated and not (user.is_active and user.is_staff):
        return redirect(settings.LOGIN_REDIRECT_URL)
    if url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
        if user.is_authenticated:
            return redirect(target)
        return redirect(reverse('login') + '?' + urlencode({'next': target}))
    if user.is_authenticated:
        return redirect(reverse('admin:index'))
    return redirect(reverse('login'))


def verify_view(request):
    from dashboard.models import UserProfile
    pending = request.session.get(PENDING_KEY)
    if not _valid_pending(pending):
        request.session.pop(PENDING_KEY, None)
        return redirect('login')
    error = ''
    # Lock user before profile so a concurrent password change cannot occur between
    # checking the first-factor proof and issuing a session with the current hash.
    with transaction.atomic():
        user = User.objects.select_for_update().filter(pk=pending['user'], is_active=True).first()
        profile = UserProfile.objects.select_for_update().filter(user=user).first() if user else None
        if (not user or not profile or not profile.mfa_enabled or not profile.mfa_secret
                or not constant_time_compare(pending['auth_hash'], user.get_session_auth_hash())
                or not constant_time_compare(pending['factor_state'], _factor_state(profile))):
            request.session.pop(PENDING_KEY, None)
            return redirect('login')
        if request.method == 'POST':
            if locked(user):
                error = 'Too many attempts. Try again in a few minutes.'
            elif check_second_factor(profile, request.POST.get('code')):
                request.session.pop(PENDING_KEY, None)
                clear_failures(user)
                login(request, user, backend=pending['backend'])
                target = pending['next']
                ok = url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()})
                return redirect(target if ok else '/')
            else:
                fail(user)
                error = 'That code is not valid.'
    return render(request, 'tenancy/mfa_verify.html', {'error': error})


@login_required
def setup_view(request):
    """Old address of the enrolment page: two-step sign-in is now managed on My account."""
    return redirect(reverse('cve_account') + '#security')


@login_required
def disable_view(request):
    return redirect(reverse('cve_account') + '#security')
