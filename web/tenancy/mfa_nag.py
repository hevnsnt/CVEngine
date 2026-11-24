"""The reminder that asks an administrator without two-step sign-in to turn it on.

An administrator (an App Admin, which is a superuser, or an Org Admin) whose account has no two-step sign-in sees a banner on every page
of the app shell until they turn it on. The banner links to the MFA setup address (``mfa_setup``, which opens My account at its
security section). It never blocks anything and enforces nothing: an organization that requires MFA already does that
(``TenancyMiddleware._require_mfa``). "Remind me later" hides it for the rest of the current session only; the next sign-in starts a
new session and shows it again.

Cost: the banner reads the user's profile row, which the tenancy middleware has already read for this request
(``TenancyMiddleware._temporary_password``), and whether the user is an administrator, which the page shell already computes. So it
adds no query to a page in practice and one at most.
"""
from django.db.models import Q
from django.urls import reverse

SNOOZE_KEY = 'mfa_nag_snoozed'
# The page where two-step sign-in is set up (My account) shows no reminder about it; the sign-in pages do not use the shell at all.
EXEMPT_PAGES = frozenset({'account'})


def mfa_enabled(user):
    profile = getattr(user, 'tenancy_profile', None)  # cached on the request's user once read; a missing profile counts as no MFA
    return bool(profile and profile.mfa_enabled)


def snoozed(request):
    session = getattr(request, 'session', None)
    return bool(session is not None and session.get(SNOOZE_KEY))


def for_request(request, is_admin, active=''):
    """The banner's context for this page, or None when it is not shown. ``is_admin`` is ``roles.is_admin_anywhere(user)``, which
    the shell has already computed."""
    user = getattr(request, 'user', None)
    if not (user is not None and user.is_authenticated and is_admin) or active in EXEMPT_PAGES:
        return None
    if getattr(request, 'api_token', None) or snoozed(request) or mfa_enabled(user):
        return None
    return {'setup_url': reverse('mfa_setup'), 'snooze_url': reverse('mfa_nag_snooze'), 'next': request.get_full_path()}


def admins_without_mfa(actor):
    """Names (only) of the active administrators ``actor`` administers who have no two-step sign-in, sorted. An App Admin sees every
    App Admin and every Org Admin; an Org Admin sees the Org Admins of the organizations they administer, never another tenant's."""
    from django.contrib.auth.models import User

    from tenancy import roles
    if actor.is_superuser:
        admins = Q(is_superuser=True) | Q(org_memberships__role=roles.ADMIN)
    else:
        managed = roles.managed_org_ids(actor)
        if not managed:
            return []
        admins = Q(org_memberships__role=roles.ADMIN, org_memberships__org_id__in=managed)
    rows = (User.objects.filter(admins, is_active=True).exclude(tenancy_profile__mfa_enabled=True).distinct()
            .order_by('username').values_list('username', 'first_name', 'last_name'))
    return [f'{first} {last}'.strip() or username for username, first, last in rows]
