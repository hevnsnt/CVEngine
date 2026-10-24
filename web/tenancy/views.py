"""MFA views: the two-step login. Enrolling and turning it off live on My account (cveFeed/account_api.py)."""
import time

from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.views import LoginView, LogoutView
from django.core.cache import cache
from django.shortcuts import redirect, render
from django.urls import reverse
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


def check_second_factor(profile, code):
    """Accept a TOTP code (no replay) or a single-use recovery code. Returns True on success."""
    step = mfa.verify(profile.mfa_secret, code, last_used_step=profile.mfa_last_step)
    if step:
        profile.mfa_last_step = step
        profile.save(update_fields=['mfa_last_step'])
        return True
    remaining = mfa.consume_recovery_code(profile.recovery_codes, code or '')
    if remaining is not None:
        profile.recovery_codes = remaining
        profile.save(update_fields=['recovery_codes'])
        return True
    return False


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
        if not (profile and profile.mfa_enabled):
            return super().form_valid(form)
        self.request.session[PENDING_KEY] = {
            'user': user.pk, 'backend': user.backend, 'next': self.get_success_url(), 'ts': time.time()}
        return redirect('mfa_verify')


def verify_view(request):
    pending = request.session.get(PENDING_KEY)
    if not pending or time.time() - pending['ts'] > PENDING_TTL:
        request.session.pop(PENDING_KEY, None)
        return redirect('login')
    user = User.objects.get(pk=pending['user'])
    error = ''
    if request.method == 'POST':
        if locked(user):
            error = 'Too many attempts. Try again in a few minutes.'
        elif check_second_factor(profile_of(user), request.POST.get('code')):
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
