"""The link in an onboarding email: it names one account, works until it expires, and stops working the moment that account's
password changes (the first time the person sets one, or when an administrator resets it), so it can be used once.

Nothing is stored. The token is signed with the site's secret key and carries the account and a fingerprint of the credentials it
was issued against; the account's current credentials must still match that fingerprint when the link is opened.
"""
import os

from django.contrib.auth.models import User
from django.core import signing
from django.utils.crypto import constant_time_compare, salted_hmac

SALT = 'cvengine.invite'
DEFAULT_DAYS = 7
MAX_DAYS = 30


def valid_days():
    """How many days a link works: ``CVENGINE_INVITE_DAYS`` (default 7), kept between 1 and 30."""
    try:
        days = int(os.environ.get('CVENGINE_INVITE_DAYS', DEFAULT_DAYS))
    except ValueError:
        days = DEFAULT_DAYS
    return max(1, min(MAX_DAYS, days))


def _fingerprint(user):
    return salted_hmac(SALT, f'{user.pk}:{user.password}:{user.last_login or ""}').hexdigest()[:24]


def make_token(user):
    return signing.dumps({'u': user.pk, 'f': _fingerprint(user)}, salt=SALT, compress=False)


def read_token(token, user=None):
    """The active account a token was issued for, or None when it is malformed, expired, for another state of the account or for
    an account that is gone or disabled. ``user`` is the row already locked by the caller (re-checked inside its transaction)."""
    try:
        data = signing.loads(str(token)[:500], salt=SALT, max_age=valid_days() * 86400)
        pk, fingerprint = data['u'], data['f']
    except (signing.BadSignature, KeyError, TypeError):
        return None
    if type(pk) is not int or not isinstance(fingerprint, str):
        return None
    user = user if user is not None and user.pk == pk else User.objects.filter(pk=pk).first()
    if not user or not user.is_active or not constant_time_compare(fingerprint, _fingerprint(user)):
        return None
    return user
