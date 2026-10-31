"""The derived, read-only "scanner offline" signal of the move to one scanner (docs/SCANNER-ARCHITECTURE.md, ``CVENGINE_LOCAL_FALLBACK``).

When a kind may not run on this server (``sentinel_dispatch.local_fallback_kinds``) and no Sentinel is live that can run it, a stage that needs it raises
``resources.ScannerUnavailable`` and leaves the target due: nothing fails, nothing is scanned locally, and the work resumes by itself when a scanner is
back. This module only *reads* that situation so it can be shown and so the sweeps that run on their own schedules stop dispatching, raising, catching and
logging every tick for nothing. It is **not** a pause: it writes nothing (``ScanControl`` is never touched), stops nothing that is running and exempts
no work from the real pause; it is recomputed from the Sentinels' own heartbeats, so it clears by itself.

``waiting_kinds()`` is the kinds that may not run here and for which no live, active Sentinel declares the capability right now (anywhere on the
instance: a Sentinel scoped to another project still counts, so the signal says "surely nothing can take this", never a guess). ``state()`` adds
``never_seen``: of those, the kinds for which no Sentinel that could run them has ever registered (any status), which is the foot-gun of
``CVENGINE_LOCAL_FALLBACK=none`` on an instance with no scanner at all, and ``disabled`` (present only when not empty): the waiting kinds that a live Sentinel has
and its capability policy (an administrator's, an instance default, or its own machine) turns off, with no other active Sentinel that has them offline. Those are
not "offline": the scanner is there and told not to take the work, so the interface says so and the fix is a setting, not a reconnect. The answer is kept in the Django cache for ``CACHE_SECONDS`` so a beat tick or
a polling page costs one cache read; with the variable unset every kind may run here, the answer is empty and no query is made at all.
"""
import logging

from django.utils import timezone

logger = logging.getLogger(__name__)

CACHE_SECONDS = 15
CACHE_KEY = 'cvengine:scanner-state:'  # followed by the raw value of CVENGINE_LOCAL_FALLBACK, so a changed setting is never answered from the old one
INTERNAL_ONLY = ('discover',)  # internal ranges are Sentinel-only by design: never part of a vantage-point warning
NO_STAGE = ('waf',)  # contract kinds no server stage dispatches yet: nothing waits for them, so a Sentinel without them is not "offline" (drop when one does)


def _empty():
    return {'offline': False, 'kinds': [], 'never_seen': []}


def _compute(now):
    """The uncached answer: a few queries (the live Sentinels' rights, and one read of every Sentinel's declared capabilities)."""
    from agentapi import sentinel_broker, sentinel_dispatch
    from agentapi.models import Agent, SentinelTask
    allowed = sentinel_dispatch.local_fallback_kinds()
    off = [k for k in SentinelTask.KINDS if k not in allowed and k not in NO_STAGE]
    if not off:
        return _empty()
    offered, denied, live_pks = set(), set(), set()
    for eff in sentinel_broker._live_scanners(now):
        offered |= eff.caps
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


def _uses_proxy(kind, tools):
    """Whether a run of ``kind`` takes the egress proxy: its tool (the kind's name, or the part before the first underscore) is one of
    ``egress_proxy.TOOLS``. A kind that runs on raw sockets never did, so the proxy is no part of its vantage point."""
    return kind in tools or kind.split('_')[0] in tools


def _tailscale_enabled():
    """Whether this install runs the ``tailscale`` compose profile: it is in ``COMPOSE_PROFILES`` (``.env`` reaches every container) or the sidecar has
    published a node status file (``cveFeed.tailscale_local``, fresh or not: the install is set up for it)."""
    import os
    profiles = os.environ.get('COMPOSE_PROFILES', '').replace(' ', ',').lower().split(',')
    if 'tailscale' in profiles:
        return True
    from cveFeed import tailscale_local
    return tailscale_local.available()


def vantage_warnings():
    """Sentences (one per cause, empty for none) warning that ``CVENGINE_LOCAL_FALLBACK`` moves kinds to the built-in scanner container, which has
    none of this server's vantage point: its egress proxy (Settings > Proxy, only for the kinds whose tools take one), the Tailscale network namespace
    that the ``tailscale`` sidecar shares with celery, or ``CVENGINE_ALLOW_PRIVATE_TARGETS``. Those scans would start from the scanner's network
    without anything failing, so an administrator is told. It is a warning, never a refusal, derived and never stored (``ScanControl`` is untouched).
    Internal ranges are Sentinel-only already and are not a cause. With the variable unset no kind moves and nothing is read."""
    from agentapi import sentinel_dispatch
    from agentapi.models import SentinelTask
    allowed = sentinel_dispatch.local_fallback_kinds()
    off = [k for k in SentinelTask.KINDS if k not in allowed and k not in NO_STAGE and k not in INTERNAL_ONLY]
    if not off:
        return []

    def probe(check):
        try:
            return bool(check())
        except Exception:  # noqa: BLE001 - a reading that fails is no reason to warn, nor to break the status
            logger.debug('vantage check could not be read', exc_info=True)
            return False

    def sentence(kinds, what):
        return (f"CVENGINE_LOCAL_FALLBACK moves {_join(kinds)} to the built-in scanner, which does not use {what}; "
                "those scans will start from the scanner's network instead.")

    from cveFeed import egress_proxy
    from targetApp import target_types
    out = []
    proxied = [k for k in off if _uses_proxy(k, egress_proxy.TOOLS)]
    if proxied and probe(egress_proxy.configured):
        out.append(sentence(proxied, "this server's egress proxy"))
    if probe(_tailscale_enabled):
        out.append(sentence(off, 'the Tailscale network'))
    if probe(target_types.private_targets_allowed):
        out.append(sentence(off, 'the private-target setting (CVENGINE_ALLOW_PRIVATE_TARGETS)'))
    return out


def state(now=None):
    """``{'offline': bool, 'kinds': [...], 'never_seen': [...], 'since'?: iso}``. ``kinds`` are the waiting kinds (see ``waiting_kinds``), ``never_seen`` the
    ones among them no Sentinel capable of them ever registered for, ``since`` when a scanner that could run one of them was last heard from (absent
    when none ever was). Cached for ``CACHE_SECONDS`` unless ``now`` is given (a caller that names a time wants that time's answer)."""
    import os

    from django.core.cache import cache

    from agentapi import sentinel_dispatch
    raw = os.environ.get(sentinel_dispatch.LOCAL_FALLBACK_ENV, '').strip().lower()
    if raw in ('', 'all', '*'):
        return _empty()  # every kind may still run here: nothing can be waiting, and nothing is read
    if now is not None:
        return _compute(now)
    key = CACHE_KEY + raw
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
    """The kinds that may not run on this server and that no live, active Sentinel can run right now: work of these kinds waits (it stays due, nothing is
    marked failed) until a scanner reconnects. Empty when ``CVENGINE_LOCAL_FALLBACK`` is unset."""
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
        'never_seen': (f'CVENGINE_LOCAL_FALLBACK stops {_join(never)} from running on this server but no scanner has ever registered for them: '
                       'nothing of that kind will run until one does.' if never else None),
    }
    if disabled:
        out['disabled'] = (f'{_words(disabled)} {"is" if len(disabled) == 1 else "are"} turned off on every Sentinel that has '
                           f'{"it" if len(disabled) == 1 else "them"}. Nothing has failed; the work stays due until one is turned back on (Sentinels page, Settings).')
    return out


def unknown_message(unknown):
    """The sentence for names in ``CVENGINE_LOCAL_FALLBACK`` that are no kind, or None when there are none."""
    if not unknown:
        return None
    return f'CVENGINE_LOCAL_FALLBACK names kinds that do not exist: {_join(unknown)}; check the spelling.'


def status(admin=True, snapshot=None):
    """The ``scanner`` block of the system status and the stats poll: the state plus the wording. The ``never_seen`` part and ``unknown_kinds`` (names in
    ``CVENGINE_LOCAL_FALLBACK`` that are no kind) and ``vantage`` (``vantage_warnings``) describe a server setting, so they are for an App Admin (``admin``);
    anyone else sees the waiting kinds and the first sentence only."""
    from agentapi import sentinel_dispatch
    snapshot = dict(state() if snapshot is None else snapshot)
    text = messages(snapshot)
    unknown = sentinel_dispatch.unknown_fallback_kinds()
    if not admin:
        snapshot['kinds'] = [k for k in snapshot['kinds'] if k not in snapshot['never_seen']]
        snapshot['disabled'] = [k for k in snapshot.get('disabled', []) if k in snapshot['kinds']]
        if not snapshot['disabled']:
            snapshot.pop('disabled', None)
        snapshot['never_seen'] = []
        snapshot['offline'] = bool(snapshot['kinds'])
        text['never_seen'] = None
        unknown = []
    snapshot['unknown_kinds'] = unknown
    snapshot['vantage'] = vantage_warnings() if admin else []  # a server setting, so for an App Admin; not in ``messages`` (the page strip)
    snapshot['messages'] = [t for t in (text['offline'], text.get('disabled'), text['never_seen']) if t]
    snapshot['message'] = text['offline']
    snapshot['disabled_message'] = text.get('disabled')
    snapshot['never_seen_message'] = text['never_seen']
    snapshot['unknown_kinds_message'] = unknown_message(unknown)
    return snapshot
