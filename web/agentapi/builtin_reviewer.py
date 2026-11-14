"""The AI reviewer container's token: minted here, handed over on a volume only the server and the reviewer share (docs/AI-REVIEWER.md).

``ensure()`` keeps one live token of scope ``reviewer`` and writes it to ``<bootstrap dir>/token`` (mode 0600, owned by the reviewer's user),
where the reviewer container reads it through a read-only mount. The token can call ``/api/v1/reviewer/*`` and nothing else
(``agentapi.auth.request_allowed``), never ``/mcp/``. It belongs to the oldest App Admin who can act (active, not owing a two-step sign-in
set-up), expires after 30 days, and is replaced a week before that, or at once when it was revoked, expired or its owner can no longer act.
Each replacement revokes the token it replaces and is written to the audit log. ``CVENGINE_REVIEWER=0`` revokes it and removes the file.
"""
import logging
import os
from datetime import timedelta

from django.utils import timezone

logger = logging.getLogger(__name__)

NAME = 'cvENGINE AI reviewer'
TTL = timedelta(days=30)
RENEW_BELOW = timedelta(days=7)


def bootstrap_dir():
    return os.environ.get('CVENGINE_REVIEWER_BOOTSTRAP_DIR', '/var/lib/cvengine-reviewer').strip() or '/var/lib/cvengine-reviewer'


def reviewer_uid():
    try:
        return int(os.environ.get('CVENGINE_REVIEWER_UID', '10002'))
    except ValueError:
        return 10002


def token_path():
    return os.path.join(bootstrap_dir(), 'token')


def _write(raw):
    path = token_path()
    folder = os.path.dirname(path)
    os.makedirs(folder, mode=0o750, exist_ok=True)
    try:  # the reviewer must be able to enter the folder too (it is mounted read-only there)
        os.chown(folder, reviewer_uid(), reviewer_uid())
    except OSError:
        pass
    tmp = f'{path}.{os.getpid()}.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as handle:
        handle.write(raw)
    try:  # the reviewer runs as an unprivileged user that must be able to read it; where this process is not root there is nothing to hand over
        os.chown(tmp, reviewer_uid(), reviewer_uid())
    except OSError:
        pass
    os.replace(tmp, path)


def _remove():
    try:
        os.remove(token_path())
    except FileNotFoundError:
        pass


def _current():
    from dashboard.models import ApiToken
    return ApiToken.objects.select_related('user').filter(scope='reviewer', revoked=False).order_by('-id').first()


def _can_act(user):
    from tenancy.middleware import TenancyMiddleware
    return bool(user.is_active and user.is_superuser) and not TenancyMiddleware.must_enrol_mfa(user)


def _owner():
    from django.contrib.auth.models import User
    for user in User.objects.filter(is_superuser=True, is_active=True).order_by('id')[:20]:
        if _can_act(user):
            return user
    return None


def ensure(now=None):
    """Bring the reviewer's token up to date. Returns ``{'state': disabled | no_admin | current | written}``."""
    from agentapi.auth import SCOPE_REVIEWER, create_token
    from cveFeed import reviewer
    from dashboard.models import ApiToken
    from tenancy import audit
    now = now or timezone.now()
    if not reviewer.env_enabled():
        revoked = ApiToken.objects.filter(scope=SCOPE_REVIEWER, revoked=False).update(revoked=True)
        _remove()
        return {'state': 'disabled', 'revoked': revoked}
    token = _current()
    if (token is not None and _can_act(token.user) and token.expires_at and token.expires_at - now > RENEW_BELOW
            and os.path.exists(token_path())):
        return {'state': 'current', 'expires_at': token.expires_at.isoformat()}
    owner = _owner()
    if owner is None:
        return {'state': 'no_admin'}
    new, raw = create_token(owner, NAME, expires_at=now + TTL, scope=SCOPE_REVIEWER)
    _write(raw)
    ApiToken.objects.filter(scope=SCOPE_REVIEWER, revoked=False).exclude(pk=new.pk).update(revoked=True)
    audit.record(owner, 'reviewer.token', 'token for the AI reviewer container', token_id=new.pk)
    logger.info('AI reviewer: token %s written, valid until %s', new.prefix, new.expires_at.isoformat())
    return {'state': 'written', 'expires_at': new.expires_at.isoformat()}


def status(now=None):
    """For a status page: whether the reviewer is on, and when it last called the server."""
    from cveFeed import reviewer
    token = _current()
    out = {'enabled': reviewer.env_enabled(), 'token': bool(token)}
    if token is not None:
        out['last_seen'] = token.last_used_at.isoformat() if token.last_used_at else None
        out['expires_at'] = token.expires_at.isoformat() if token.expires_at else None
    return out
