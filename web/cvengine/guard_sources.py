"""The addresses the input guard must never ban silently: the owner's own and a live Sentinel's.

An App Admin's browser and a Sentinel at the same site share one public address. When that Sentinel's scan reaches this server (or anything at the
address sends probes the guard reads as attacks), a 24 hour ban of the address locks the App Admin out of the web interface and stops the Sentinel,
with nothing on screen saying why. So the guard asks ``protected(ip)`` before it bans: an address that in the last ``WINDOW`` was the source of a
signed-in App Admin session, or of a live Sentinel's authenticated call, is not banned. Its strikes are still stored, and an App Admin alert names
the address, the path and the reason (``cvengine.input_guard``).

What is kept: one cache entry per (kind, address) for ``WINDOW``, written at most once per ``REFRESH`` per address (``note``). Only addresses and the
name of who used them: never a session key or a token. A cache that cannot be read protects nothing (the ban goes ahead as before), because an
address the guard cannot vouch for must not escape a ban.
"""
import logging
from datetime import timedelta

from django.utils import timezone

logger = logging.getLogger(__name__)

WINDOW = timedelta(hours=24)
REFRESH = 600  # seconds: one address of one kind is written again at most this often
KINDS = {'admin': 'a signed-in App Admin session', 'sentinel': 'a live Sentinel'}
_PREFIX = 'guard-source'
SENTINEL_PATH = '/api/v1/sentinel'  # a token's call here is a Sentinel's (an older one may hold a full token); whether it is live is asked at ban time


def _key(kind, ip):
    return f'{_PREFIX}:{kind}:{ip}'


def note(kind, ip, who, token_id=None):
    """Remember that ``ip`` was used by ``who`` (an App Admin's user name, a Sentinel token's name) of ``kind`` just now. Never raises, never queries."""
    if kind not in KINDS or not ip:
        return
    try:
        from django.core.cache import cache
        if cache.add(f'{_key(kind, ip)}:fresh', 1, REFRESH):
            cache.set(_key(kind, ip), {'who': str(who or '')[:150], 'token_id': token_id, 'at': timezone.now().isoformat()}, int(WINDOW.total_seconds()))
    except Exception:  # noqa: BLE001 - a cache that is down: nothing is remembered, and the guard bans as it always did
        logger.debug('guard sources: could not note %s', kind, exc_info=True)


def note_request(request):
    """Note the address of a signed-in App Admin's browser session, or of a Sentinel's authenticated call. Never raises. Any other request costs
    nothing here, and none costs a query (whether the Sentinel is live is asked only when a ban is about to be made, ``protected``)."""
    try:
        token = getattr(request, 'api_token', None)
        user = getattr(request, 'user', None)
        if token is not None:
            if (getattr(token, 'scope', '') == 'sentinel' or str(getattr(request, 'path', '')).startswith(SENTINEL_PATH)) and not getattr(token, 'revoked', False):
                from cvengine.client_ip import client_ip
                note('sentinel', client_ip(request), getattr(token, 'name', ''), token_id=getattr(token, 'pk', None))
            return
        if user is not None and getattr(user, 'is_authenticated', False) and getattr(user, 'is_superuser', False):
            from cvengine.client_ip import client_ip
            note('admin', client_ip(request), user.get_username())
    except Exception:  # noqa: BLE001
        logger.debug('guard sources: could not read the request', exc_info=True)


def _live_sentinel(token_id):
    """The name of the active Sentinel behind the token, or None: a pending, suspended or revoked one does not protect its address."""
    from agentapi.models import Agent
    agent = Agent._base_manager.filter(token_id=token_id, token__revoked=False, status='active').only('name').first() if token_id else None
    return agent.name if agent is not None else None


def protected(ip):
    """``[(kind, who), ...]`` for each way ``ip`` was used in the last ``WINDOW`` that keeps it from a silent ban, else ``[]``."""
    if not ip:
        return []
    try:
        from django.core.cache import cache
        found = cache.get_many([_key(kind, ip) for kind in KINDS])
        out = []
        for kind in KINDS:
            row = found.get(_key(kind, ip))
            if not isinstance(row, dict):
                continue
            if kind == 'sentinel':
                name = _live_sentinel(row.get('token_id'))
                if name is None:
                    continue
                out.append((kind, name))
            else:
                out.append((kind, row.get('who', '')))
        return out
    except Exception:  # noqa: BLE001 - unreadable: nothing is protected, the ban goes ahead
        logger.warning('guard sources: could not read the protected addresses', exc_info=True)
        return []


def forget(ip=None):
    """Drop what is kept (tests)."""
    from django.core.cache import cache
    if ip:
        cache.delete_many([k for kind in KINDS for k in (_key(kind, ip), f'{_key(kind, ip)}:fresh')])
