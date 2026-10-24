"""MFA views: the two-step login. Enrolling and turning it off live on My account (cveFeed/account_api.py)."""
import math
import time

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

from tenancy import mfa

PENDING_KEY = 'mfa_pending'
SETUP_SECRET_KEY = 'mfa_setup_secret'
PENDING_TTL = 300
MAX_FAILURES = 5
LOCKOUT_SECONDS = 300


def profile_of(user):
    from dashboard.models import UserProfile
    return UserProfile.objects.get_or_create(user=user)[0]


def locked(user):
    return cache.get(f'mfa_fail:{user.pk}', 0) >= MAX_FAILURES


def fail(user):
    """Count one failed second factor. The counter lives in the shared Redis cache and is incremented atomically, so concurrent
    attempts (several web workers, several threads) cannot undercount; the lockout window starts at the first failure."""
    key = f'mfa_fail:{user.pk}'
    cache.add(key, 0, LOCKOUT_SECONDS)  # only when absent: sets the window, never extends it
    try:
        cache.incr(key)
    except ValueError:  # the key expired between the add and the incr
        cache.set(key, 1, LOCKOUT_SECONDS)


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


class MFALoginView(LoginView):
    """Password step; users with MFA are not logged in until /mfa/verify/ succeeds."""

    def form_valid(self, form):
        user = form.get_user()
        profile = getattr(user, 'tenancy_profile', None)
        self.request.session.pop(PENDING_KEY, None)
        if not (profile and profile.mfa_enabled):
            return super().form_valid(form)
        self.request.session[PENDING_KEY] = {
            'user': user.pk, 'backend': user.backend, 'next': self.get_success_url(), 'ts': time.time(),
            'auth_hash': user.get_session_auth_hash(), 'factor_state': _factor_state(profile)}
        return redirect('mfa_verify')


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
