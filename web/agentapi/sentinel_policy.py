"""The capability policy of a Sentinel: which of the kinds it declares an administrator lets it take, prefers, or caps.

A Sentinel *declares* what it can do (the tools it found, ``gvm_ready``, its machine's own ``CVENGINE_SENTINEL_DISABLE``). An administrator then chooses,
per Sentinel and per kind, what cvENGINE may hand it. This holds for the install's own scanner (the built-in one) exactly as for an external Sentinel,
so "OpenVAS runs on the Remote Sentinel and not on the built-in one" is a setting, not a deployment.

Where it is stored (no new table). ``Agent.managed_settings['kinds']`` is ``{'value': {kind: {'mode': ..., 'max_concurrent': ...}}, 'at', 'by'}``, the same
envelope every managed setting has, so last-write-wins and the audit trail are the ones ``agentapi.sentinel_settings`` already gives. The instance
defaults are ``SentinelDefaults.builtin_kinds`` and ``external_kinds`` in the same shape, without an envelope.

``mode`` is ``allow`` (offered: the default for a declared kind), ``deny`` (never offered; this is what ``disabled_kinds`` always meant) or ``prefer`` (offered,
and work is held back from the others for a moment while a preferring Sentinel has room, ``sentinel_broker.PREFER_DEFER_SECONDS``). ``max_concurrent`` caps
how many tasks of that kind the Sentinel holds at once, inside its own ``max_concurrent``.

Resolution, per Sentinel and kind: the machine's veto (``disabled_kinds`` it reported; the server cannot lift it) > the Sentinel's own policy > the
instance default of its class (built-in or external) > allow. A policy is taken whole from one level (a Sentinel's ``prefer`` with no cap does not pick up
a default's cap). The old ``disabled_kinds`` setting keeps working both ways: stored values still read as ``deny``, and the wire reply to a Sentinel still
carries ``disabled_kinds``, now derived from this policy, so a client that predates it keeps honouring it.
"""
import threading
from contextlib import contextmanager

from agentapi import agent_broker as broker
from agentapi.models import SentinelDefaults, SentinelTask
from agentapi.services import ApiError

MODES = ('allow', 'deny', 'prefer')
SHIPPED_BUILTIN = {'openvas': {'mode': 'deny', 'max_concurrent': None}}  # the built-in scanner does not run OpenVAS until an administrator says so
# The words an administrator reads, for the messages the server writes (the interface has the same list).
# A kind is named by its own name with the underscores read as spaces, except where an administrator knows it by another word.
LABELS = {'openvas': 'OpenVAS', 'discover': 'internal discovery', 'waf': 'WAF detection'}
SOURCES = ('agent', 'instance default', 'machine', 'contract', 'cool-off', 'default')


def label(kind):
    return LABELS.get(kind) or str(kind).replace('_', ' ')


def _entry(mode, cap=None):
    return {'mode': mode, 'max_concurrent': cap}


def clean_kinds(value, what='kinds', allow_null_entries=True):
    """The policy map in ``value`` validated: ``{kind: {mode, max_concurrent}}``, or ``ApiError``. Known kinds only, ``mode`` one of ``MODES``,
    ``max_concurrent`` ``null`` or a whole number from 1 to ``MAX_CONCURRENT_CAP``. With ``allow_null_entries`` a ``null`` entry is kept (it removes the
    kind's own policy); the entry of a kind must carry its ``mode``, so a change always says what it means."""
    if not isinstance(value, dict) or not value:
        raise ApiError(400, f'{what} must be an object {{kind: {{"mode": "allow"|"deny"|"prefer", "max_concurrent": 1-{broker.MAX_CONCURRENT_CAP}|null}}}} '
                            f'for at least one of {", ".join(SentinelTask.KINDS)}')
    out = {}
    for kind, entry in value.items():
        if not isinstance(kind, str) or kind not in SentinelTask.KINDS:
            raise ApiError(400, f'{what}: {str(kind)[:40]!r} is not a task kind; kinds are {", ".join(SentinelTask.KINDS)}')
        if entry is None and allow_null_entries:
            out[kind] = None
            continue
        if not isinstance(entry, dict) or set(entry) - {'mode', 'max_concurrent'}:
            raise ApiError(400, f'{what}.{kind} must be an object with mode and max_concurrent')
        mode = entry.get('mode')
        if mode not in MODES:
            raise ApiError(400, f'{what}.{kind}.mode must be one of {", ".join(MODES)}')
        cap = entry.get('max_concurrent')
        if cap is not None and (isinstance(cap, bool) or not isinstance(cap, int) or not 1 <= cap <= broker.MAX_CONCURRENT_CAP):
            raise ApiError(400, f'{what}.{kind}.max_concurrent must be null or a whole number from 1 to {broker.MAX_CONCURRENT_CAP}')
        out[kind] = _entry(mode, cap)
    return out


def normalise(stored):
    """Whatever is stored read tolerantly into ``{kind: {mode, max_concurrent}}`` (an entry that is no longer valid is ignored, never an error)."""
    out = {}
    if not isinstance(stored, dict):
        return out
    for kind, entry in stored.items():
        if kind in SentinelTask.KINDS and isinstance(entry, dict) and entry.get('mode') in MODES:
            cap = entry.get('max_concurrent')
            out[kind] = _entry(entry['mode'], cap if isinstance(cap, int) and not isinstance(cap, bool) and cap >= 1 else None)
    return out


# --- what is stored on a Sentinel ---------------------------------------------------------------------------------------------------------

def machine_denied(agent):
    """The kinds the Sentinel's own machine turned off (``CVENGINE_SENTINEL_DISABLE`` / its reported ``disabled_kinds``). A veto: no setting here lifts it."""
    value = ((agent.reported_settings or {}).get('disabled_kinds') or {}).get('value')
    return {k for k in value if isinstance(k, str) and k in SentinelTask.KINDS} if isinstance(value, list) else set()


def managed_envelope(agent):
    """``({kind: entry}, at, by)``: the administrator's policy for this Sentinel. The ``disabled_kinds`` an administrator set before policies existed read as ``deny``;
    a ``kinds`` entry for the same kind wins. ``at`` and ``by`` are those of the latest of the two settings."""
    managed = agent.managed_settings or {}
    out, stamps = {}, []
    legacy = managed.get('disabled_kinds') or {}
    if isinstance(legacy.get('value'), list):
        for kind in legacy['value']:
            if kind in SentinelTask.KINDS:
                out[kind] = _entry('deny')
        stamps.append(legacy)
    stored = managed.get('kinds') or {}
    out.update(normalise(stored.get('value')))
    if stored:
        stamps.append(stored)
    stamp = max(stamps, key=lambda s: s.get('at') or '') if stamps else {}
    return out, stamp.get('at'), stamp.get('by')


def managed_kinds(agent):
    return managed_envelope(agent)[0]


# --- the instance defaults ----------------------------------------------------------------------------------------------------------------

_local = threading.local()


@contextmanager
def shared_lookups():
    """Within this block the instance defaults and the built-in scanner's id are read once and reused, so building the rights of many Sentinels in a row
    (a page of cards, a sweep) costs two queries, not two per Sentinel. Meant for one short call in one thread; nested uses share the outer one."""
    if getattr(_local, 'cache', None) is not None:
        yield
        return
    _local.cache = {}
    try:
        yield
    finally:
        _local.cache = None


def defaults():
    """``{'builtin': {kind: entry}, 'external': {kind: entry}, 'builtin_shipped': bool, 'by': str, 'at': iso|None}`` from the one defaults row (one query, or
    none inside ``shared_lookups``)."""
    memo = getattr(_local, 'cache', None)
    if memo is not None and 'defaults' in memo:
        return memo['defaults']
    row = SentinelDefaults.current()
    shipped = row.builtin_kinds is None
    out = {'builtin': normalise(SHIPPED_BUILTIN if shipped else row.builtin_kinds), 'external': normalise(row.external_kinds),
           'builtin_shipped': shipped, 'by': row.changed_by or '', 'at': row.changed_at.isoformat() if row.changed_at else None}
    if memo is not None:
        memo['defaults'] = out
    return out


def builtin_pk():
    from agentapi import sentinel_broker
    memo = getattr(_local, 'cache', None)
    if memo is not None:
        if 'builtin-pk' not in memo:
            memo['builtin-pk'] = sentinel_broker.builtin_pk()
        return memo['builtin-pk']
    return sentinel_broker.builtin_pk()


def is_builtin(agent):
    pk = builtin_pk()
    return pk is not None and pk == agent.pk


# --- resolution --------------------------------------------------------------------------------------------------------------------------

def resolve(agent, builtin=None):
    """``{kind: {'mode', 'cap', 'source', 'by', 'at', 'machine'}}`` for every kind. ``source`` says which level decided the mode: ``machine`` (a veto, mode
    ``deny``), ``agent`` (this Sentinel's own policy), ``instance default`` or ``default`` (nothing set: ``allow``). ``builtin`` is whether the Sentinel is
    the install's own scanner (looked up when not given)."""
    builtin = is_builtin(agent) if builtin is None else builtin
    veto = machine_denied(agent)
    own, own_at, own_by = managed_envelope(agent)
    shared = defaults()
    default = shared['builtin' if builtin else 'external']
    out = {}
    for kind in SentinelTask.KINDS:
        if kind in veto:
            out[kind] = {'mode': 'deny', 'cap': None, 'source': 'machine', 'by': None, 'at': ((agent.reported_settings or {}).get('disabled_kinds') or {}).get('at'),
                         'machine': True}
        elif kind in own:
            out[kind] = {'mode': own[kind]['mode'], 'cap': own[kind]['max_concurrent'], 'source': 'agent', 'by': own_by, 'at': own_at, 'machine': False}
        elif kind in default:
            out[kind] = {'mode': default[kind]['mode'], 'cap': default[kind]['max_concurrent'], 'source': 'instance default',
                         'by': shared['by'] or None, 'at': shared['at'], 'machine': False}
        else:
            out[kind] = {'mode': 'allow', 'cap': None, 'source': 'default', 'by': None, 'at': None, 'machine': False}
    return out


def denied(agent, builtin=None, policy=None):
    """The kinds this Sentinel must not be offered, whether or not it declares them: the machine's veto and every ``deny`` of the policy."""
    policy = resolve(agent, builtin) if policy is None else policy
    return {kind for kind, p in policy.items() if p['mode'] == 'deny'}


def wire_disabled_kinds(agent, builtin=None):
    """The ``disabled_kinds`` a Sentinel is told (sorted): every denied kind. The wire format stays what it always was, so an older client honours it."""
    return sorted(denied(agent, builtin))


def prefers(agent, kind, builtin=None):
    """Whether this Sentinel's policy ``prefer``s ``kind`` (cheap: stored JSON and the defaults only)."""
    return resolve(agent, builtin)[kind]['mode'] == 'prefer'


# --- changing a Sentinel's policy ---------------------------------------------------------------------------------------------------------

def refuse_unavailable(agent, change):
    """``ApiError`` (409) when ``change`` (the cleaned ``{kind: entry|None}``) allows or prefers a kind the Sentinel cannot run: one it did not declare (its
    tool is missing or off) or one its machine turned off. Only what a Sentinel actually declares can be enabled; ``deny``, a cap-less removal and a change
    that keeps a kind off are always fine."""
    veto = machine_denied(agent)
    declared = set(agent.capabilities or [])
    for kind, entry in change.items():
        if entry is None or entry['mode'] == 'deny':
            continue
        if kind in veto:
            raise ApiError(409, f'{label(kind)} is turned off on the Sentinel\'s machine (CVENGINE_SENTINEL_DISABLE); cvENGINE cannot turn it back on, change it on the machine')
        if kind not in declared:
            raise ApiError(409, f'{label(kind)} is not available on this Sentinel (its tool is missing or off on the machine), so it cannot be allowed here')


def apply_change(current, change):
    """``current`` (``{kind: entry}``) with ``change`` (``{kind: entry|None}``, or ``None`` for clear everything) applied: a new dict."""
    if change is None:
        return {}
    out = dict(current)
    for kind, entry in change.items():
        if entry is None:
            out.pop(kind, None)
        else:
            out[kind] = entry
    return out


def apply_disabled_kinds(current, disabled):
    """``current`` with the older ``disabled_kinds`` list applied: each kind of the list is ``deny``; a kind that was denied and is not in the list is
    allowed again (its cap kept), so the old setting means what it always did. ``None`` is an empty list."""
    disabled = set(disabled or [])
    out = dict(current)
    for kind in SentinelTask.KINDS:
        entry = out.get(kind)
        if kind in disabled:
            out[kind] = _entry('deny', (entry or {}).get('max_concurrent'))
        elif entry and entry['mode'] == 'deny':
            if entry['max_concurrent'] is None:
                del out[kind]
            else:
                out[kind] = _entry('allow', entry['max_concurrent'])
    return out
