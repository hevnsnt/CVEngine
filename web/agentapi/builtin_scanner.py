"""The install's own scanner ("CVEngine Scanner"): the server's half of enrolling it with nobody typing a secret.

When ``CVENGINE_BUILTIN_SCANNER`` is on, ``ensure()`` keeps one instance-wide enrollment ready for the scanner container and hands it over as a
provisioning blob (the same base64 JSON a person pastes into ``CVENGINE_SENTINEL_BLOB``) in a file on a volume only the server and the scanner
share. The scanner redeems it with the ordinary bootstrap call, the file is removed the moment it was redeemed, and a scanner that is later lost
(its token revoked or expired, its Agent deleted) gets a fresh blob on the next run. Nothing here widens a Sentinel's rights: it is the same
instance-scope enrollment an App Admin can generate by hand, owned by the oldest App Admin, written to the audit log, single use.
"""
import logging
import os
from datetime import timedelta

from django.utils import timezone

logger = logging.getLogger(__name__)

NAME = 'CVEngine Scanner'
BLOB_TTL = timedelta(hours=24)  # a person's enrollment lives 30 minutes; this one waits for a container that may still be starting
RENEW_BELOW = timedelta(hours=2)  # an unredeemed blob this close to expiry is replaced, so a slow start never meets an expired one


def enabled():
    return os.environ.get('CVENGINE_BUILTIN_SCANNER', '').strip().lower() in ('1', 'true', 'yes', 'on')


def bootstrap_dir():
    return os.environ.get('CVENGINE_SCANNER_BOOTSTRAP_DIR', '/var/lib/cvengine-scanner').strip() or '/var/lib/cvengine-scanner'


def scanner_uid():
    try:
        return int(os.environ.get('CVENGINE_SCANNER_UID', '10001'))
    except ValueError:
        return 10001


def blob_path():
    return os.path.join(bootstrap_dir(), 'blob')


def server_url():
    """Where the scanner container reaches the server: the compose service, not the public name (``CVENGINE_SCANNER_SERVER_URL`` to override)."""
    return os.environ.get('CVENGINE_SCANNER_SERVER_URL', '').strip() or 'http://web:8000'


def builtin_agent():
    """The Sentinel the built-in enrollment created, newest first, or ``None``."""
    return _agent_from_enrollment()


def _agent_from_enrollment():
    from agentapi.models import SentinelEnrollment
    row = SentinelEnrollment.objects.filter(builtin=True, used_by_agent__isnull=False).exclude(used_by_agent__status='revoked') \
        .select_related('used_by_agent', 'used_by_agent__token').order_by('-id').first()
    return row.used_by_agent if row else None


def _alive(agent, now):
    """Whether the built-in Sentinel can still be heard from: its token is not revoked and has not expired."""
    token = agent.token
    return not token.revoked and (token.expires_at is None or token.expires_at > now)


def _write_blob(text):
    path = blob_path()
    os.makedirs(os.path.dirname(path), mode=0o750, exist_ok=True)
    tmp = f'{path}.{os.getpid()}.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as handle:
        handle.write(text)
    try:  # the scanner container runs as an unprivileged user that must be able to read it; where this process is not root there is nothing to hand over
        os.chown(tmp, scanner_uid(), scanner_uid())
    except OSError:
        pass
    os.replace(tmp, path)


def _remove_blob():
    try:
        os.remove(blob_path())
        return True
    except FileNotFoundError:
        return False


def _admin():
    from django.contrib.auth.models import User
    return User.objects.filter(is_superuser=True, is_active=True).order_by('id').first()


def ensure(now=None):
    """Bring the built-in scanner's enrollment up to date and say where it stands: ``disabled``, ``no_admin`` (no App Admin yet to own it),
    ``enrolled`` (a live built-in Sentinel exists; any leftover blob is removed), ``waiting`` (a blob is ready and still good) or
    ``blob_written`` (a new one was written this run)."""
    from agentapi import sentinel_broker as broker
    from agentapi.models import SentinelEnrollment
    from tenancy import audit
    if not enabled():
        return {'state': 'disabled'}
    now = now or timezone.now()
    agent = builtin_agent()
    if agent is not None and _alive(agent, now):
        _remove_blob()
        return {'state': 'enrolled', 'agent_id': agent.pk}
    ready = SentinelEnrollment.objects.filter(builtin=True, used_at__isnull=True, expires_at__gt=now + RENEW_BELOW).order_by('-id').first()
    if ready is not None and os.path.exists(blob_path()):
        return {'state': 'waiting', 'expires_at': ready.expires_at.isoformat()}
    admin = _admin()
    if admin is None:
        return {'state': 'no_admin'}
    SentinelEnrollment.objects.filter(builtin=True, used_at__isnull=True).delete()  # an unredeemed older secret is never left valid beside the new one
    raw = broker.ENROLLMENT_PREFIX + broker.secrets.token_urlsafe(32)
    expires_at = now + BLOB_TTL
    row = SentinelEnrollment.objects.create(token_hash=broker._hash_enrollment(raw), prefix=raw[:10], created_by=admin, expires_at=expires_at,
                                            network='external', builtin=True)
    payload = {'enrollment_token': raw, 'server_url': server_url(), 'expires_at': expires_at.isoformat(), 'scope': 'instance'}
    _write_blob(broker.encode_enrollment_blob(payload))
    audit.record(admin, 'sentinel.enroll.generate', 'instance enrollment for the built-in scanner', enrollment_id=row.pk)
    logger.info('built-in scanner: enrollment %s ready until %s', row.prefix, expires_at.isoformat())
    return {'state': 'blob_written', 'expires_at': expires_at.isoformat()}


def status(now=None):
    """What a status page shows: whether the built-in scanner is switched on, enrolled and heard from."""
    now = now or timezone.now()
    if not enabled():
        return {'enabled': False}
    agent = builtin_agent()
    if agent is None:
        return {'enabled': True, 'enrolled': False}
    live = bool(agent.last_seen and now - agent.last_seen <= timedelta(minutes=3))
    return {'enabled': True, 'enrolled': True, 'agent_id': agent.pk, 'name': agent.name, 'live': live, 'last_seen': agent.last_seen.isoformat() if agent.last_seen else None}
