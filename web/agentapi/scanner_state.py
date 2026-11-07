"""The derived, read-only "scanner offline" signal of the move to Sentinels (docs/SCANNER-ARCHITECTURE.md).

No kind runs on this server (``sentinel_dispatch.NEVER_LOCAL``; ``CVENGINE_LOCAL_FALLBACK`` is ignored since 1.4). When no Sentinel is live that can run a kind,
a stage that needs it raises ``resources.ScannerUnavailable`` and leaves the target due: nothing fails, nothing is scanned locally, and the work resumes by
itself when a scanner is back. This module only *reads* that situation so it can be shown and so the sweeps that run on their own schedules stop
dispatching, raising, catching and logging every tick for nothing. It is **not** a pause: it writes nothing (``ScanControl`` is never touched), stops
nothing that is running and exempts no work from the real pause; it is recomputed from the Sentinels' own heartbeats, so it clears by itself.

``waiting_kinds()`` is the kinds for which no live, active Sentinel declares the capability right now (anywhere on the instance: a Sentinel scoped to
another project still counts, so the signal says "surely nothing can take this", never a guess). ``state()`` adds ``never_seen``: of those, the kinds
for which no Sentinel that could run them has ever registered (any status), and ``disabled`` (present only when not empty): the waiting kinds that a live
Sentinel has and its capability policy (an administrator's, an instance default, or its own machine) turns off, with no other active Sentinel that has them
offline. Those are not "offline": the scanner is there and told not to take the work, so the interface says so and the fix is a setting, not a reconnect.
Until the built-in scanner has enrolled for the first time nothing is reported (a fresh install's scanner is expected within seconds; its stages wait all
the same). The answer is kept in the Django cache for ``CACHE_SECONDS`` so a beat tick or a polling page costs one cache read.
"""
import logging

from django.utils import timezone

logger = logging.getLogger(__name__)

CACHE_SECONDS = 15
CACHE_KEY = 'cvengine:scanner-state:'
INTERNAL_ONLY = ('discover',)  # internal ranges are Sentinel-only by design and have no stage that waits: never reported as waiting
NO_STAGE = ()  # contract kinds no server stage dispatches yet: nothing waits for them, so a Sentinel without them is not "offline" (empty since 1.4: every kind has a stage)


def _empty():
    return {'offline': False, 'kinds': [], 'never_seen': []}


def _compute(now):
    """The uncached answer: a few queries (the live Sentinels' rights, and one read of every Sentinel's declared capabilities)."""
    from agentapi import sentinel_broker
    from agentapi.models import Agent, SentinelTask
    off = [k for k in SentinelTask.KINDS if k not in NO_STAGE and k not in INTERNAL_ONLY]  # every kind waits for a scanner: none runs here
    if not off:
        return _empty()
    offered, denied, live_pks = set(), set(), set()
    for eff in sentinel_broker._live_scanners(now):
        offered |= eff.caps if eff.builtin else eff.caps - set(sentinel_broker.BUILTIN_KINDS)  # only the built-in scanner takes those
        live_pks.add(eff.agent.pk)
        # a kind it has (declared, or turned off on its machine) and its policy turns off
        denied |= {k for k in eff.denied if k in (eff.agent.capabilities or []) or eff.policy[k]['machine']}
    kinds = [k for k in off if k not in offered]
    if not kinds:
        return _empty()
    # Registered at any time, in any status (a revoked or suspended one still proves a scanner was set up): the declared capabilities, and when
    # the last of them was heard from, which is when the work started waiting. ``away`` are the kinds an active Sentinel has while it is not heard from.
    declared = {k: None for k in kinds}
    ever, away = set(), set()
    for pk, capabilities, last_seen, status in Agent.objects.filter(kind='scanner').values_list('pk', 'capabilities', 'last_seen', 'status'):
        for kind in set(capabilities or []) & set(kinds):
            ever.add(kind)
            if status == 'active' and pk not in live_pks:
                away.add(kind)
            if last_seen and (declared[kind] is None or last_seen > declared[kind]):
                declared[kind] = last_seen
    heard = [t for k, t in declared.items() if t is not None]
    out = {'offline': True, 'kinds': kinds, 'never_seen': [k for k in kinds if k not in ever]}
    disabled = [k for k in kinds if k in denied and k not in away]
    if disabled:
        out['disabled'] = disabled
    if heard:
        out['since'] = max(heard).isoformat()
    return out


def tailscale_enabled():
    """Whether this install runs the ``tailscale`` compose profile: it is in ``COMPOSE_PROFILES`` (``.env`` reaches every container) or the sidecar has
    published a node status file (``cveFeed.tailscale_local``, fresh or not: the install is set up for it)."""
    import os
    profiles = os.environ.get('COMPOSE_PROFILES', '').replace(' ', ',').lower().split(',')
    if 'tailscale' in profiles:
        return True
    from cveFeed import tailscale_local
    return tailscale_local.available()


def state(now=None):
    """``{'offline': bool, 'kinds': [...], 'never_seen': [...], 'since'?: iso}``. ``kinds`` are the waiting kinds (see ``waiting_kinds``), ``never_seen`` the
    ones among them no Sentinel capable of them ever registered for, ``since`` when a scanner that could run one of them was last heard from (absent
    when none ever was). Cached for ``CACHE_SECONDS`` unless ``now`` is given (a caller that names a time wants that time's answer)."""
    from django.core.cache import cache

    from agentapi import sentinel_dispatch
    if not sentinel_dispatch.builtin_scanner_enrolled():
        return _empty()  # no scanner has enrolled yet (a fresh install, or the built-in scanner is off): nothing is reported and nothing is read
    if now is not None:
        return _compute(now)
    key = CACHE_KEY + 'default'
    try:
        cached = cache.get(key)
    except Exception:  # noqa: BLE001 - a cache that is down only means asking again
        cached = None
    if isinstance(cached, dict):
        return cached
    out = _compute(timezone.now())
    try:
        cache.set(key, out, CACHE_SECONDS)
    except Exception:  # noqa: BLE001
        logger.debug('scanner state could not be cached', exc_info=True)
    return out


def waiting_kinds(now=None):
    """The kinds that no live, active Sentinel can run right now: work of these kinds waits (it stays due, nothing is marked failed) until a scanner
    reconnects. Empty until the built-in scanner has enrolled."""
    return list(state(now)['kinds'])


def disabled_kinds(now=None):
    """The waiting kinds that are turned off, not offline: a live Sentinel has each and its capability policy denies it (``state()['disabled']``)."""
    return list(state(now).get('disabled', []))


def offline_kinds(now=None):
    """The waiting kinds that really are waiting for a scanner to come back: not turned off, and not a kind no scanner ever registered for (the second
    sentence of ``messages``)."""
    snapshot = state(now)
    skip = set(snapshot.get('disabled', [])) | set(snapshot.get('never_seen', []))
    return [k for k in snapshot['kinds'] if k not in skip]


def is_waiting(kind, now=None):
    return kind in state(now)['kinds']


def skip_note(kind, now=None):
    """The ``skipped`` text for a sweep of ``kind`` that should not start because it is waiting for a scanner, or None when it may go on. A kind that is turned
    off on every Sentinel that has it says so: that is a setting, not a scanner that is offline."""
    try:
        snapshot = state(now)
        if kind not in snapshot['kinds']:
            return None
        turned_off = kind in snapshot.get('disabled', [])
    except Exception:  # noqa: BLE001 - a reading that fails must never stop a sweep: it goes on as it did before this existed
        logger.warning('scanner state could not be read', exc_info=True)
        return None
    if turned_off:
        return f'{_words([kind])} is turned off on every Sentinel that has it; the targets stay due'
    return f'no scanner is online for {kind}; the targets stay due'


def _join(kinds):
    return ', '.join(kinds)


def _words(kinds):
    """``kinds`` as an administrator reads them (``OpenVAS``, ``internal discovery``), for the sentence about a setting."""
    from agentapi import sentinel_policy
    return ', '.join(sentinel_policy.label(k) for k in kinds)


def messages(snapshot=None):
    """The sentences the interface and the status show, ``{'offline': str|None, 'never_seen': str|None}``, and ``'disabled'`` when a kind is turned off. The
    first names the kinds that are waiting for a scanner that was set up before (it reconnects and the work resumes); the second the kinds no scanner was ever
    registered for; the third the kinds a live Sentinel has and the capability policy turns off on every Sentinel that has it (a setting to change, not a scanner
    to bring back)."""
    snapshot = state() if snapshot is None else snapshot
    never = [k for k in snapshot.get('never_seen', [])]
    disabled = [k for k in snapshot.get('disabled', []) if k not in never]
    waiting = [k for k in snapshot.get('kinds', []) if k not in never and k not in disabled]
    out = {
        'offline': (f'Scanner offline: {_join(waiting)} work is waiting. Nothing has failed; it resumes automatically when a scanner reconnects.'
                    if waiting else None),
        'never_seen': (f'No scanner has ever registered for {_join(never)}, and this server runs none of them: '
                       'nothing of that kind will run until one does.' if never else None),
    }
    if disabled:
        out['disabled'] = (f'{_words(disabled)} {"is" if len(disabled) == 1 else "are"} turned off on every Sentinel that has '
                           f'{"it" if len(disabled) == 1 else "them"}. Nothing has failed; the work stays due until one is turned back on (Sentinels page, Settings).')
    return out


def status(admin=True, snapshot=None):
    """The ``scanner`` block of the system status and the stats poll: the state plus the wording. The ``never_seen`` part describes a server setup, so it is
    for an App Admin (``admin``); anyone else sees the waiting kinds and the first sentence only."""
    snapshot = dict(state() if snapshot is None else snapshot)
    text = messages(snapshot)
    if not admin:
        snapshot['kinds'] = [k for k in snapshot['kinds'] if k not in snapshot['never_seen']]
        snapshot['disabled'] = [k for k in snapshot.get('disabled', []) if k in snapshot['kinds']]
        if not snapshot['disabled']:
            snapshot.pop('disabled', None)
        snapshot['never_seen'] = []
        snapshot['offline'] = bool(snapshot['kinds'])
        text['never_seen'] = None
    snapshot['messages'] = [t for t in (text['offline'], text.get('disabled'), text['never_seen']) if t]
    snapshot['message'] = text['offline']
    snapshot['disabled_message'] = text.get('disabled')
    snapshot['never_seen_message'] = text['never_seen']
    return snapshot
