"""The install's own scanner ("CVEngine Scanner"): the server's half of enrolling it with nobody typing a secret.

The scanner is on by default (``CVENGINE_BUILTIN_SCANNER`` unset); ``0`` turns it off. While it is on, ``ensure()`` keeps one instance-wide enrollment ready for the scanner container and hands it over as a
provisioning blob (the same base64 JSON a person pastes into ``CVENGINE_SENTINEL_BLOB``) in a file on a volume only the server and the scanner
share. The scanner redeems it with the ordinary bootstrap call, the file is removed the moment it was redeemed, and a scanner that is later lost
(its token revoked or expired, its Agent deleted) gets a fresh blob on the next run. Nothing here widens a Sentinel's rights: it is the same
instance-scope enrollment an App Admin can generate by hand, owned by the oldest App Admin, written to the audit log, single use. Turned off, the
next run revokes the scanner's token and removes any blob, so the container idles (``CVENGINE_REVIEWER=0`` does the same for the AI reviewer).
"""
import logging
import os
import stat
from datetime import timedelta

from django.utils import timezone
from cvengine.usage_stamps import durable_commit

logger = logging.getLogger(__name__)

NAME = 'CVEngine Scanner'
BLOB_TTL = timedelta(hours=24)  # like a person's enrollment, this one waits for a container that may still be starting
RENEW_BELOW = timedelta(hours=2)  # an unredeemed blob this close to expiry is replaced, so a slow start never meets an expired one


OFF = ('0', 'false', 'no', 'off')


def enabled():
    """On unless ``CVENGINE_BUILTIN_SCANNER`` is ``0`` (or ``false``, ``no``, ``off``): every install runs the built-in scanner by default."""
    return os.environ.get('CVENGINE_BUILTIN_SCANNER', '1').strip().lower() not in OFF


def bootstrap_dir():
    return os.environ.get('CVENGINE_SCANNER_BOOTSTRAP_DIR', '/var/lib/cvengine-scanner').strip() or '/var/lib/cvengine-scanner'


BLOB_MODE = 0o640  # the writer and the group the scanner is given, never anyone else


class BlobPermissionError(OSError):
    """The blob could not be made mode 0640 with the scanner's group, so none was left behind (it is never written readable by others)."""


def blob_gid():
    """The group the scanner container reads the blob with: the application's group, 10002, which docker-compose.yml gives the scanner service with
    ``group_add`` (``CVENGINE_APP_GID``, as for the ownership service)."""
    try:
        return int(os.environ.get('CVENGINE_APP_GID', '10002'))
    except ValueError:
        return 10002


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
    """Whether the built-in Sentinel can still be heard from: its token is not revoked and has not expired, and the user it belongs to can still act
    (an Agent whose user was disabled, or has to set up two-step sign-in first, is set aside by ``agent_broker.Eff._problem``, so a scanner owned by
    such a user is as good as lost and gets a new enrollment under a user who can). A suspended or pending scanner is left alone: that is an
    administrator's decision, not a loss."""
    from tenancy.middleware import TenancyMiddleware
    token = agent.token
    if token.revoked or (token.expires_at is not None and token.expires_at <= now):
        return False
    user = token.user
    return bool(user.is_active) and not TenancyMiddleware.must_enrol_mfa(user)


def _write_blob(text):
    path = blob_path()
    os.makedirs(os.path.dirname(path), mode=0o750, exist_ok=True)
    tmp = f'{path}.{os.getpid()}.tmp'
    gid = blob_gid()
    # Created 0600, then given the scanner's group and opened to it (0640): the scanner runs as its own account with group 10002 added
    # (docker-compose.yml, group_add), and the folder is 10002's with mode 2751 (web/ownership.sh). The writer is uid 10002 with no capability, so
    # it can set its own group on its own file but never give the file away. When the file cannot be made 0640 with that group it is removed and
    # the run fails: the secret is never left readable by others.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, 'w') as handle:
            handle.write(text)
            handle.flush()
            try:
                os.fchown(handle.fileno(), -1, gid)
                os.fchmod(handle.fileno(), BLOB_MODE)
            except OSError as exc:
                raise BlobPermissionError(f'cannot give the built-in scanner blob group {gid} and mode 0640: {exc}') from exc
            st = os.fstat(handle.fileno())
            if stat.S_IMODE(st.st_mode) != BLOB_MODE or st.st_gid != gid:
                raise BlobPermissionError(f'the built-in scanner blob came out mode {oct(stat.S_IMODE(st.st_mode))} group {st.st_gid}, '
                                          f'not 0640 group {gid}')
        os.replace(tmp, path)
    except BaseException as exc:
        try:
            os.remove(tmp)
        except FileNotFoundError:
            pass
        if isinstance(exc, BlobPermissionError):
            logger.error('built-in scanner: no enrollment written, %s. The writer must own the file and be in group %s (or be root); '
                         '`docker compose run --rm ownership` sets up the folder (docs/BUILTIN-SCANNER.md)', exc, gid)
        raise


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
    ``blob_written`` (a new one was written this run). Raises ``BlobPermissionError`` (and logs why) when the blob cannot be made mode 0640 with the
    scanner's group: nothing is written then, and the enrollment made for it is deleted."""
    from agentapi import sentinel_broker as broker
    from agentapi.models import SentinelEnrollment
    from tenancy import audit
    if not enabled():
        return _turn_off()
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
    try:
        _write_blob(broker.encode_enrollment_blob(payload))
    except BlobPermissionError:
        row.delete()  # its secret was never handed over; the next run tries again with a new one
        raise
    audit.record(admin, 'sentinel.enroll.generate', 'instance enrollment for the built-in scanner', enrollment_id=row.pk)
    logger.info('built-in scanner: enrollment %s ready until %s', row.prefix, expires_at.isoformat())
    return {'state': 'blob_written', 'expires_at': expires_at.isoformat()}


def _turn_off():
    """Switched off: no enrollment stays valid, no blob stays on the volume, and the built-in scanner's token is revoked (its tasks are released),
    so a container that keeps running takes no work. ``revoked`` is how many tokens this run revoked."""
    from agentapi.agent_broker import release_agent_tasks
    from agentapi.models import Agent, SentinelEnrollment
    from dashboard.models import ApiToken
    from tenancy import audit
    SentinelEnrollment.objects.filter(builtin=True, used_at__isnull=True).delete()
    _remove_blob()
    revoked = 0
    for row in SentinelEnrollment.objects.filter(builtin=True, used_by_agent__isnull=False).select_related('used_by_agent__token__user'):
        agent = row.used_by_agent
        if agent.token.revoked:
            continue
        release_agent_tasks(agent, 'the built-in scanner was turned off (CVENGINE_BUILTIN_SCANNER=0)')
        with durable_commit():  # a revocation a crash could undo would let the token in again
            revoked += ApiToken.objects.filter(pk=agent.token_id, revoked=False).update(revoked=True)
        Agent.objects.filter(pk=agent.pk).exclude(status='revoked').update(status='revoked', status_changed_at=timezone.now(),
                                                                          status_note='the built-in scanner was turned off (CVENGINE_BUILTIN_SCANNER=0)')
        audit.record_for_user(None, 'agent.revoke', agent.token.user, target=agent.name, agent_id=agent.pk, kind=agent.kind,
                              reason='CVENGINE_BUILTIN_SCANNER=0')
        logger.info('built-in scanner turned off: revoked the token of %s (agent %s)', agent.name, agent.pk)
    return {'state': 'disabled', 'revoked': revoked}


def status(now=None):
    """What a status page shows: whether the built-in scanner is switched on, enrolled and heard from."""
    now = now or timezone.now()
    if not enabled():
        return {'enabled': False}
    agent = builtin_agent()
    if agent is None:
        return {'enabled': True, 'enrolled': False}
    live = bool(agent.last_seen and now - agent.last_seen <= timedelta(minutes=3))
    out = {'enabled': True, 'enrolled': True, 'agent_id': agent.pk, 'name': agent.name, 'live': live, 'last_seen': agent.last_seen.isoformat() if agent.last_seen else None}
    out.update(release(agent))
    return out


def release(agent):
    """What the running built-in scanner is: its build (``version``, the Sentinel commit), the contract it speaks and whether this server accepts it, whether it is
    the newest build of the Sentinel's main branch the server saw (``newest``: True, False, or None while that is not known: the check is cached, never made here),
    and ``version_since`` (when it last changed). The scanner follows the newest published image, so ``newest`` False is a scanner that has not been updated yet."""
    from agentapi import sentinel_contract, sentinel_version
    info = agent.info or {}
    found = sentinel_version.state(agent)
    return {'version': info.get('version'), 'contract_version': info.get('contract_version'), 'contract_state': sentinel_contract.state(info.get('contract_version')),
            'contract_note': sentinel_contract.note(info.get('contract_version')),
            'newest': {'current': True, 'behind': False}.get(found['status']), 'newest_version': found['latest'], 'behind_by': found['behind_by'], 'newest_checked_at': found['checked_at'],
            'version_since': info.get('version_since')}
