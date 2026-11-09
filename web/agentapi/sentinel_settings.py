"""A Sentinel's settings, managed from cvENGINE or set where it runs: the most recent change wins.

A Sentinel is configured on its own machine (its environment), and an administrator can also change the same settings from cvENGINE
after it checked in, so nothing has to be touched on the machine. Both sides keep a value and the time it last changed (this server's
clock, so the two can be compared): ``Agent.reported_settings`` is what the Sentinel's own configuration says, ``Agent.managed_settings``
what an administrator set. The effective value of each setting is the one changed last; a Sentinel that restarts with an unchanged
configuration does not override a later edit made here, and an edit made on the machine after the last dashboard edit wins.

Network access is an exception: only enrollment or an administrator grants internal access. Clearing an administrator's network setting
restores the grant recorded at enrollment, or external if no matching enrollment exists. A local external setting can still limit that grant.

The Sentinel reports only its *local* values, never the effective ones it applied (it would otherwise look like a new local change every
time), and applies the effective ones the server sends back in its registration and heartbeat replies. Settings are plain data the Sentinel
validates; nothing in them is a command. What a Sentinel may do for a project is still decided by its scope and an administrator's approval
and limits (``agent_broker``): a setting only changes how this Sentinel presents itself and how much it runs.
"""
import hashlib
import json
from datetime import datetime

from django.utils import timezone

from agentapi import agent_broker as broker
from agentapi import agent_scope as scope_lib
from agentapi import sentinel_policy as policy_lib
from agentapi.models import Agent, SentinelDefaults, SentinelEnrollment, SentinelTask
from agentapi.services import ApiError
from tenancy import audit

SETTINGS = ('name', 'network', 'profile', 'disabled_kinds', 'kinds', 'max_concurrent', 'self_update', 'discovery_keys')
# ``kinds`` and ``discovery_keys`` are set from cvENGINE only. ``discovery_keys`` is a boolean: false is this Sentinel's opt-out from being sent the project's discovery API
# keys (the instance setting ``sentinel_bbot_keys`` is the other switch); absent or true means it follows the instance setting. Never sent to a Sentinel.
MANAGED_ONLY = ('kinds', 'discovery_keys')  # set from cvENGINE only: a Sentinel never reports a policy (it can only turn a kind off, with ``disabled_kinds``)
SELF_UPDATE = ('off', 'manual', 'automatic')
# What an administrator is told to run on the Sentinel's machine when its host updater is missing: fixed text, never something a Sentinel reported.
INSTALL_COMMAND = 'cd <the Sentinel checkout> && sudo ./scripts/install-updater.sh'


def clean_settings(raw, managed=True):
    """The settings in ``raw`` (any subset of ``SETTINGS``) validated, or ``ApiError``. ``None`` as a value is kept so a caller can clear one. ``managed`` is
    False for what a Sentinel reports about itself, which cannot carry ``MANAGED_ONLY`` settings."""
    from agentapi import sentinel_broker as sb
    allowed = SETTINGS if managed else tuple(k for k in SETTINGS if k not in MANAGED_ONLY)
    if not isinstance(raw, dict) or not raw:
        raise ApiError(400, f'send settings as an object with any of {", ".join(allowed)}')
    unknown = sorted(set(raw) - set(allowed))
    if unknown:
        raise ApiError(400, f'unknown setting {unknown[0]!r}; settings are {", ".join(allowed)}')
    out = {}
    for key, value in raw.items():
        if value is None:
            out[key] = None
        elif key == 'name':
            try:
                out[key] = scope_lib.clean_name(value)
            except scope_lib.ScopeError as exc:
                raise ApiError(400, str(exc))
        elif key == 'network':
            if value not in sb.NETWORKS:
                raise ApiError(400, f'network must be one of {", ".join(sb.NETWORKS)}')
            out[key] = value
        elif key == 'profile':
            if value not in sb.PROFILES:
                raise ApiError(400, f'profile must be one of {", ".join(sb.PROFILES)}')
            out[key] = value
        elif key == 'self_update':
            if value not in SELF_UPDATE:
                raise ApiError(400, f'self_update must be one of {", ".join(SELF_UPDATE)}')
            out[key] = value
        elif key == 'disabled_kinds':
            if not isinstance(value, list) or len(value) > len(SentinelTask.KINDS) or not all(isinstance(k, str) and k in SentinelTask.KINDS for k in value):
                raise ApiError(400, f'disabled_kinds must be a list drawn from {", ".join(SentinelTask.KINDS)}')
            out[key] = sorted(set(value))
        elif key == 'kinds':
            out[key] = policy_lib.clean_kinds(value)
        elif key == 'discovery_keys':
            if not isinstance(value, bool):
                raise ApiError(400, 'discovery_keys must be true or false (false: this Sentinel is never sent a project\'s discovery API keys)')
            out[key] = value
        elif key == 'max_concurrent':
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= broker.MAX_CONCURRENT_CAP:
                raise ApiError(400, f'max_concurrent must be a whole number from 1 to {broker.MAX_CONCURRENT_CAP}')
            out[key] = value
    return out


def discovery_keys_opt_out(agent):
    """Whether an administrator turned off sending discovery API keys to this one Sentinel (Sentinel settings)."""
    return ((agent.managed_settings or {}).get('discovery_keys') or {}).get('value') is False


def _when(entry):
    try:
        return datetime.fromisoformat(entry['at'])
    except (KeyError, TypeError, ValueError):
        return None


def detail(agent):
    """Setting values and sources. Network reports its usable value, server grant and the machine's local limit."""
    out = {}
    managed, reported = agent.managed_settings or {}, agent.reported_settings or {}
    for key in SETTINGS:
        if key in ('disabled_kinds', 'kinds'):
            continue  # below: the capability policy, with the older disabled_kinds derived from it
        m, r = managed.get(key), reported.get(key)
        if m is None and r is None:
            continue
        pick = 'sentinel' if m is None else 'server' if r is None else ('sentinel' if (_when(r) and _when(m) and _when(r) > _when(m)) else 'server')
        entry = m if pick == 'server' else r
        out[key] = {'value': entry['value'], 'source': pick, 'at': entry.get('at'), 'by': entry.get('by') if pick == 'server' else None}
    _kinds_detail(agent, out)
    if agent.kind == 'scanner':
        managed_network = managed.get('network')
        reported_network = reported.get('network')
        machine_value = (reported_network or {}).get('value')
        grant = 'internal' if agent.network == 'internal' else 'external'
        limited_by_machine = grant == 'internal' and machine_value == 'external'
        source_entry = reported_network if limited_by_machine else managed_network
        network = {'value': effective_network(agent), 'source': 'sentinel' if limited_by_machine else 'server',
                   'at': (source_entry or {}).get('at'), 'by': None if limited_by_machine else (managed_network or {}).get('by'),
                   'server_grant': grant, 'machine_value': machine_value, 'managed': managed_network is not None,
                   'grant_at': (managed_network or {}).get('at'), 'grant_by': (managed_network or {}).get('by')}
        if limited_by_machine:
            network['limited_by_machine'] = True
        if grant == 'external' and machine_value == 'internal':
            network['limited_by_server'] = True
        out['network'] = network
    _limits(agent, out)
    return out


def _kinds_detail(agent, out):
    """``kinds`` (the administrator's capability policy for this Sentinel) and ``disabled_kinds`` (the kinds it refuses on this Sentinel's own account: the
    machine's and the administrator's denials; the instance defaults are not in it) into ``out``. ``disabled_kinds`` is the older name of the same
    thing and is kept so a reader of it keeps working."""
    reported = (agent.reported_settings or {}).get('disabled_kinds')
    own, at, by = policy_lib.managed_envelope(agent)
    if own or at:
        out['kinds'] = {'value': own, 'source': 'server', 'at': at, 'by': by}
    if not own and not at and reported is None:
        return
    managed_value = sorted(k for k, e in own.items() if e['mode'] == 'deny')
    machine = sorted(policy_lib.machine_denied(agent))
    m = {'at': at, 'by': by} if at else None
    pick = 'sentinel' if m is None else 'server' if reported is None else ('sentinel' if (_when(reported) and _when(m) and _when(reported) > _when(m)) else 'server')
    entry = m if pick == 'server' else reported
    out['disabled_kinds'] = {'value': sorted(set(managed_value) | set(machine)), 'source': pick, 'at': (entry or {}).get('at'),
                             'by': (entry or {}).get('by') if pick == 'server' else None}


RANK = {'off': 0, 'manual': 1, 'automatic': 2}


def effective_network(agent):
    """``internal`` only when the server says the Sentinel is inside a private network (``Agent.network``) AND the machine's own setting does not
    say otherwise: a Sentinel's local configuration is a limit, so it can lower itself to external but never raise itself to internal."""
    if agent.network != 'internal':
        return 'external'
    return 'external' if ((agent.reported_settings or {}).get('network') or {}).get('value') == 'external' else 'internal'


def disabled_kinds(agent, builtin=None):
    """The task kinds this Sentinel must not be offered: those its own machine disabled and every kind an administrator, or the instance default for its
    class, denies (``sentinel_policy``; all of them limit it)."""
    return policy_lib.denied(agent, builtin)


def _limits(agent, entries):
    """Mark a local self-update setting that caps what cvENGINE can ask for."""
    reported = agent.reported_settings or {}
    local = (reported.get('self_update') or {}).get('value')
    if local in RANK:
        managed = ((agent.managed_settings or {}).get('self_update') or {}).get('value')
        wanted = managed if managed in RANK else instance_self_update()
        if RANK[local] < RANK.get(wanted, 0):
            entry = entries.setdefault('self_update', {'value': wanted, 'source': 'server', 'at': None, 'by': None})
            entry.update(limited_by_machine=True, machine_value=local, wanted=wanted)


def instance_self_update():
    """The instance-wide default for Sentinels' self-update: the administrators' choice (``SentinelDefaults.self_update``), else ``automatic`` while
    "Keep Sentinels on the newest version" is on (the default) and ``manual`` once an administrator turned it off. A Sentinel with a value of its own,
    and a machine's own ceiling (``CVENGINE_SENTINEL_UPDATE``), still win over this."""
    row = SentinelDefaults.current()
    if row.self_update in SELF_UPDATE:
        return row.self_update
    return 'automatic' if row.keep_newest else 'manual'


def keep_newest():
    """Whether the instance keeps Sentinels on the newest version (Settings, Sentinels). On unless an administrator turned it off."""
    return bool(SentinelDefaults.current().keep_newest)


def explicit(agent):
    """``{setting: value}`` for settings either side set, without the instance default. Network uses its authorized effective value."""
    has_network = 'network' in (agent.managed_settings or {}) or 'network' in (agent.reported_settings or {})
    return {key: entry['value'] for key, entry in detail(agent).items() if (key != 'network' or has_network) and key not in MANAGED_ONLY}


def effective(agent, kinds=True):
    """``{setting: value}``: what this Sentinel should run with now. ``self_update`` always has a value: its own, else the instance default. ``kinds``
    leaves out the lookups of the capability policy (the instance defaults and whether this is the built-in scanner: two queries) for a caller that only
    wants another setting, such as a page of agents."""
    out = explicit(agent)
    out.setdefault('self_update', instance_self_update())
    if agent.kind == 'scanner':
        out['network'] = effective_network(agent)
        if kinds:
            denied = policy_lib.wire_disabled_kinds(agent)  # the wire format of the capability policy is still the one list a client already honours
            if denied or 'disabled_kinds' in out:
                out['disabled_kinds'] = denied
    return out


def revision(values):
    """A short fingerprint of effective settings, so a client can tell cheaply that something changed."""
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()[:12]


def record_reported(agent, raw, now=None):
    """Store the Sentinel's own settings. Only a value that differs from the last one it reported moves its time forward, so a restart with an
    unchanged configuration never overrides an administrator's later edit. Returns the settings that changed."""
    now = now or timezone.now()
    values = clean_settings({k: v for k, v in (raw or {}).items() if v is not None}, managed=False) if raw else {}
    reported, changed = dict(agent.reported_settings or {}), []
    for key, value in values.items():
        if (reported.get(key) or {}).get('value') != value:
            reported[key] = {'value': value, 'at': now.isoformat()}
            changed.append(key)
    if changed:
        agent.reported_settings = reported
        Agent.objects.filter(pk=agent.pk).update(reported_settings=reported)
    return changed


def set_managed(agent, raw, actor, now=None):
    """An administrator's change from cvENGINE. Clearing network restores its enrollment grant, never the Sentinel's claim."""
    from agentapi import sentinel_broker as sb
    now = now or timezone.now()
    values = clean_settings(raw)
    if 'kinds' in values and 'disabled_kinds' in values:
        raise ApiError(400, 'send kinds (the capability policy) or disabled_kinds (the older list of denied kinds), not both')
    managed, before = dict(agent.managed_settings or {}), explicit(agent)
    kinds_before = policy_lib.managed_kinds(agent)
    kinds_after = kinds_before
    if 'kinds' in values or 'disabled_kinds' in values:
        if 'kinds' in values:
            change = values.pop('kinds')
            if change is not None:
                policy_lib.refuse_unavailable(agent, change)  # only what the Sentinel declares can be enabled; refused before anything is stored
            kinds_after = policy_lib.apply_change(kinds_before, change)
        else:
            kinds_after = policy_lib.apply_disabled_kinds(kinds_before, values.pop('disabled_kinds'))
        if kinds_after != kinds_before:  # the older disabled_kinds is folded into the policy, which is its one home from now on
            managed.pop('disabled_kinds', None)
            if kinds_after:
                managed['kinds'] = {'value': kinds_after, 'at': now.isoformat(), 'by': actor.username}
            else:
                managed.pop('kinds', None)
    network_before = agent.network
    if 'network' in values:  # the Sentinel cannot grant itself access to private networks
        if values['network'] is None:
            enrolled = SentinelEnrollment.objects.filter(used_by_agent=agent, token_id=agent.token_id).values_list('network', flat=True).first()
            agent.network = enrolled if enrolled in sb.NETWORKS else 'external'
        else:
            agent.network = values['network']
    for key, value in values.items():
        if value is None:
            managed.pop(key, None)
        elif (managed.get(key) or {}).get('value') != value:
            managed[key] = {'value': value, 'at': now.isoformat(), 'by': actor.username}
    agent.managed_settings = managed
    updates = {'managed_settings': managed}
    if 'network' in values:
        updates['network'] = agent.network
    Agent.objects.filter(pk=agent.pk).update(**updates)
    grant_change = {'network_grant_before': network_before, 'network_grant_after': agent.network} if 'network' in values else {}
    if kinds_after != kinds_before:
        grant_change.update(kinds_before=kinds_before, kinds_after=kinds_after)  # who changed what in the capability policy: the map before and after
    if 'discovery_keys' in values:
        grant_change['discovery_keys_after'] = 'follows the instance setting' if values['discovery_keys'] is None else ('send' if values['discovery_keys'] else 'never send')
    audit.record_for_user(actor, 'agent.settings', agent.token.user, target=agent.name, agent_id=agent.pk,
                          before=before, after=explicit(agent), **grant_change)
    return effective(agent)


def reply(agent):
    """What a Sentinel is told about its settings: the effective values and their fingerprint. The built-in scanner is also told ``vantage``
    (``builtin_vantage``): this server's egress proxy and the private networks its own scans may reach, so it scans from where the server did. Derived
    at every reply and stored nowhere, sent to the built-in scanner alone (its token and its enrollment make it that, never what it reports)."""
    values = effective(agent)
    from agentapi import sentinel_broker
    if agent.kind == 'scanner' and sentinel_broker.is_builtin(agent):
        vantage = builtin_vantage()
        if vantage:
            values['vantage'] = vantage
    return {'values': values, 'rev': revision(values)}


TAILNET_RANGES = ('100.64.0.0/10', 'fd7a:115c:a1e0::/48')  # Tailscale's addresses: the CGNAT range and its unique local IPv6 prefix
PRIVATE_RANGES = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', 'fc00::/7')


def builtin_vantage():
    """Where this server's own scans leave from, for the built-in scanner (the managed settings channel of risk 6, docs/SCANNER-ARCHITECTURE.md):

    - ``proxies``, ``bypass`` and ``proxy_private``: Settings > Proxy when it is on (``cveFeed.egress_proxy``), the destinations that never go through
      it (``CVENGINE_PROXY_BYPASS`` and ``NO_PROXY`` as this server reads them) and whether private addresses go through it too
      (``CVENGINE_PROXY_PRIVATE``). The URLs can carry a login: this goes to the built-in scanner only, over the compose network, and is never stored
      or logged.
    - ``private_ranges``: the private networks it may scan although it is not internal, as this server's own scans may: all of private space with
      ``CVENGINE_ALLOW_PRIVATE_TARGETS``, the tailnet when the Tailscale sidecar is on (the scanner shares celery's network namespace, where the
      sidecar's route lives). The server still decides which addresses are in scope; this only lifts the scanner's own floor to match.

    Empty when none of these is set."""
    import os

    from agentapi import scanner_state
    from cveFeed import egress_proxy
    from targetApp import target_types
    out = {}
    specs = egress_proxy.configured()
    if specs:
        out['proxies'] = [spec.url for spec in specs]
        out['bypass'] = [e for var in ('CVENGINE_PROXY_BYPASS', 'NO_PROXY', 'no_proxy') for e in
                         (item.strip().lower() for item in os.environ.get(var, '').split(',')) if e]
        out['proxy_private'] = not egress_proxy.private_bypass()
    if target_types.private_targets_allowed():
        out['private_ranges'] = list(PRIVATE_RANGES)
    elif scanner_state.tailscale_enabled():
        out['private_ranges'] = list(TAILNET_RANGES)
    return out


# --- the Sentinel's own version and its host-side updater ---------------------------------------------------------------------------------

UPDATE_STATUSES = ('idle', 'waiting', 'draining', 'updating', 'done', 'failed')
# What a built-in scanner image can do beyond its kinds (``info.features``; the Sentinel client's ``config.BUILTIN_FEATURES``): ``secret_read``, the
# single-use read of a stored credential for a signed-in pass, and ``vantage``, the egress proxy and private ranges of the settings reply. A name this
# server does not know is dropped. ``info.builtin`` is what the image says it is; whether a Sentinel IS the built-in scanner is decided by its
# enrollment (``builtin_scanner.builtin_agent``), never by this.
# ``bbot_keys`` (any Sentinel: the Sentinel client's ``config.EXTERNAL_FEATURES``): it reads a bbot discovery task's API keys through the same single-use read, keeps
# them in a private file for the run and masks them. A Sentinel that does not say so (every older client) is never sent them; the field is optional.
FEATURES = ('secret_read', 'vantage', 'bbot_keys')


def clean_info(raw):
    """What a Sentinel reports about itself, validated: its client ``version``, the ``contract_version`` it speaks (cvengine_scanner/contract/sentinel_contract.json), its updater's ``update`` state, whether its own GVM stack can scan (``openvas``), for the built-in scanner image ``builtin`` and its ``features``, and ``waiting`` (kinds held back for memory, tasks still stopping: ``clean_waiting``). Anything else is dropped."""
    if not isinstance(raw, dict):
        raise ApiError(400, 'info must be an object')
    out = {}
    if raw.get('version') is not None:
        version = raw['version']
        if not isinstance(version, str) or len(version) > 64 or not all(c.isalnum() or c in '.-_+' for c in version):
            raise ApiError(400, 'version must be at most 64 letters, digits and . - _ +')
        out['version'] = version
    contract = raw.get('contract_version')
    if contract is not None:
        if isinstance(contract, bool) or not isinstance(contract, int) or not 1 <= contract <= 1000:
            raise ApiError(400, 'contract_version must be a whole number from 1 to 1000')
        out['contract_version'] = contract
    update = raw.get('update')
    if update is not None:
        if not isinstance(update, dict) or update.get('status') not in UPDATE_STATUSES:
            raise ApiError(400, f'update.status must be one of {", ".join(UPDATE_STATUSES)}')
        clean = {'status': update['status']}
        for key, limit in (('phase', 60), ('detail', 300), ('from', 64), ('to', 64), ('at', 40)):
            value = update.get(key)
            if value is not None:
                if not isinstance(value, str):
                    raise ApiError(400, f'update.{key} must be text')
                clean[key] = ''.join(c for c in value if c.isprintable())[:limit]
        out['update'] = clean
    updater = raw.get('updater')
    if updater is not None:
        if not isinstance(updater, dict) or not isinstance(updater.get('installed'), bool) or not isinstance(updater.get('running', False), bool):
            raise ApiError(400, 'updater must be {installed: bool, running: bool, last_run, last_result, detail}')
        clean = {'installed': updater['installed'], 'running': bool(updater.get('running')) and updater['installed']}
        for key, limit in (('last_run', 40), ('last_result', 40), ('detail', 300)):
            value = updater.get(key)
            if value is not None:
                if not isinstance(value, str):
                    raise ApiError(400, f'updater.{key} must be text')
                clean[key] = ''.join(c for c in value if c.isprintable())[:limit]
        out['updater'] = clean
    builtin = raw.get('builtin')
    if builtin is not None:
        if not isinstance(builtin, bool):
            raise ApiError(400, 'builtin must be true or false')
        out['builtin'] = builtin
    features = raw.get('features')
    if features is not None:
        if not isinstance(features, list) or len(features) > 20 or not all(isinstance(f, str) for f in features):
            raise ApiError(400, 'features must be a list of names')
        out['features'] = sorted({f for f in features if f in FEATURES})
    gvm = raw.get('openvas')
    if gvm is not None:
        if not isinstance(gvm, dict) or not isinstance(gvm.get('ready'), bool):
            raise ApiError(400, 'openvas must be {ready: bool, reason: text}')
        reason = gvm.get('reason')
        if reason is not None and not isinstance(reason, str):
            raise ApiError(400, 'openvas.reason must be text')
        out['openvas'] = {'ready': gvm['ready'], 'reason': ''.join(c for c in (reason or '') if c.isprintable())[:200]}
    waiting = raw.get('waiting')
    if waiting is not None:
        out['waiting'] = clean_waiting(waiting)
    return out


def _count(value, high=10 ** 7):
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= high else 0


def clean_waiting(raw):
    """``info.waiting``: the heavy kinds a Sentinel holds back for lack of memory (``{kind, need_mb, free_mb, budget_mb, seconds, held_by: [{task, kind, mb,
    seconds}]}``) and the tasks it was told to stop that are still stopping (``{kind, task, seconds, stopping: true}``), so the Sentinels page can say why a kind
    is not being taken. At most six entries and three holders each, text clipped, numbers whole; an empty list says nothing waits now."""
    if not isinstance(raw, list) or len(raw) > 20:
        raise ApiError(400, 'waiting must be a list of at most 20 entries')
    out = []
    for item in raw[:6]:
        if not isinstance(item, dict) or not isinstance(item.get('kind'), str):
            raise ApiError(400, 'each waiting entry must be an object with a kind')
        row = {'kind': ''.join(c for c in item['kind'] if c.isprintable())[:40], 'seconds': _count(item.get('seconds'), 10 ** 9)}
        if item.get('stopping') is True:
            row.update(stopping=True, task=_count(item.get('task'), 2 ** 62))
        else:
            row.update(need_mb=_count(item.get('need_mb')), free_mb=_count(item.get('free_mb')), budget_mb=_count(item.get('budget_mb')), held_by=[])
            for holder in (item.get('held_by') if isinstance(item.get('held_by'), list) else [])[:3]:
                if isinstance(holder, dict) and isinstance(holder.get('kind'), str):
                    row['held_by'].append({'task': _count(holder.get('task'), 2 ** 62), 'kind': ''.join(c for c in holder['kind'] if c.isprintable())[:40],
                                           'mb': _count(holder.get('mb')), 'seconds': _count(holder.get('seconds'), 10 ** 9)})
        out.append(row)
    return out


def record_info(agent, raw, now=None):
    """Store what the Sentinel reports. An administrator's pending "update now" is answered, and so cleared, by a different version or a failed attempt."""
    info = clean_info(raw)
    if not info:
        return False
    merged = {**(agent.info or {}), **info}
    # when the Sentinel last changed the version it runs (or first reported one): "last updated" on the Sentinels page. Only the server writes it.
    if 'version' in info and (agent.info or {}).get('version') != info['version']:
        from django.utils import timezone
        merged['version_since'] = (now or timezone.now()).isoformat()
        from agentapi import sentinel_version
        sentinel_version.version_changed((agent.info or {}).get('version'), info['version'])  # the old verdict goes at once; the new one is made in the background
    fields = {'info': merged}
    version_changed = 'version' in info and (agent.info or {}).get('version') not in (None, info['version'])
    failed = (info.get('update') or {}).get('status') == 'failed'
    if agent.update_requested_at and (version_changed or failed):
        fields['update_requested_at'] = None
    for key, value in fields.items():
        setattr(agent, key, value)
    Agent.objects.filter(pk=agent.pk).update(**fields)
    return True


def update_reply(agent):
    """What a Sentinel's updater is told: ``setting`` (``off``, ``manual`` or ``automatic``, this Sentinel's effective self-update setting) and
    whether an administrator asked it to update now. ``mode`` is the same answer in the older vocabulary (``auto`` or ``manual``) for a client that
    predates ``setting``. Nothing changes a Sentinel's code unless ``setting`` is ``automatic``, or ``manual`` and ``requested``; ``off`` never."""
    setting = effective(agent, kinds=False)['self_update']
    out = {'setting': setting, 'mode': 'auto' if setting == 'automatic' else 'manual',
           'requested': bool(agent.update_requested_at) and setting != 'off'}
    if out['requested']:
        # optional fields: the commit cvENGINE wants this Sentinel on and why ('newest': the instance keeps Sentinels on the newest version, 'admin': Update now).
        # A client that does not know them ignores them; the contract version is unchanged. Only ever a build the Sentinel is behind (never a downgrade).
        from agentapi import sentinel_autoupdate
        held = sentinel_autoupdate.stored(agent)
        if held.get('status') == 'requested' and held.get('target'):
            out['target'], out['reason'] = held['target'], 'admin' if held.get('reason') == 'admin' else 'newest'
    return out


def updater_state(agent):
    """What cvENGINE knows about the Sentinel's host-side updater: ``{state, last_run, last_result, detail, install_command, warning}``. ``state`` is
    ``running`` (installed and has run recently), ``stopped`` (installed, not running), ``not_installed``, or ``unknown`` (a client that does
    not say). ``warning`` is set when self-update is meant to happen (manual or automatic) and no updater is running, so a Sentinel that can never
    update itself is visible instead of silently never updating."""
    reported = (agent.info or {}).get('updater')
    if reported is None:
        state = 'unknown'
    elif not reported.get('installed'):
        state = 'not_installed'
    else:
        state = 'running' if reported.get('running') else 'stopped'
    setting = effective(agent, kinds=False)['self_update']
    warning = None
    if state in ('not_installed', 'stopped') and setting != 'off':
        warning = (f'self-update is {setting.capitalize()} here but the updater is {"not installed" if state == "not_installed" else "not running"} '
                   f'on the Sentinel\'s machine, so it will not update itself: run {INSTALL_COMMAND} there')
    return {'state': state, 'last_run': (reported or {}).get('last_run'), 'last_result': (reported or {}).get('last_result'),
            'detail': (reported or {}).get('detail'), 'install_command': INSTALL_COMMAND if state in ('not_installed', 'stopped') else None,
            'warning': warning}


def request_update(agent, actor, now=None):
    """An administrator's "update now" for one Sentinel: its updater proceeds whatever the mode says, still draining running tasks first. Refused
    while self-update is Off for it."""
    if effective(agent, kinds=False)['self_update'] == 'off':
        raise ApiError(409, 'self-update is Off for this Sentinel: set it to Manual or Automatic first')
    now = now or timezone.now()
    agent.update_requested_at = now
    Agent.objects.filter(pk=agent.pk).update(update_requested_at=now)
    from agentapi import sentinel_autoupdate
    target = sentinel_autoupdate.admin_pressed(agent, now)  # clears a flag and the rate limit; names the newest commit when this Sentinel is behind
    audit.record_for_user(actor, 'agent.update_requested', agent.token.user, target=agent.name, agent_id=agent.pk,
                          version=(agent.info or {}).get('version'), update_to=target)


DEFAULT_KEYS = ('self_update', 'keep_newest', 'builtin_kinds', 'external_kinds')


def get_defaults():
    """The instance-wide Sentinel defaults: ``{self_update, effective_self_update, follows_instance, builtin_kinds, builtin_kinds_is_shipped, external_kinds,
    changed_by, changed_at}``. ``builtin_kinds`` and ``external_kinds`` are the capability policy a Sentinel gets for a kind it has no policy of its own for
    (``{kind: {mode, max_concurrent}}``): the first for the install's own scanner (OpenVAS denied until an administrator changes it, which
    ``builtin_kinds_is_shipped`` says), the second for every other Sentinel (empty: every declared kind is allowed)."""
    row = SentinelDefaults.current()
    kinds = policy_lib.defaults()
    return {'self_update': row.self_update or None, 'keep_newest': bool(row.keep_newest), 'effective_self_update': instance_self_update(), 'follows_instance': not row.self_update,
            'builtin_kinds': kinds['builtin'], 'builtin_kinds_is_shipped': kinds['builtin_shipped'], 'external_kinds': kinds['external'],
            'changed_by': row.changed_by or None, 'changed_at': row.changed_at.isoformat() if row.changed_at else None}


def set_defaults(actor, body):
    """App Admin only: any of ``{self_update: off|manual|automatic|null, builtin_kinds: {kind: {mode, max_concurrent}}|null, external_kinds: {...}|null}``.
    ``self_update`` ``null`` goes back to following ``keep_newest`` (a boolean, on by default: Sentinels are Automatic and cvENGINE asks them to update to the newest build). ``builtin_kinds`` / ``external_kinds`` replace the whole map
    (``{}``: no defaults); ``null`` for ``builtin_kinds`` restores the shipped default (OpenVAS denied on the built-in scanner), for ``external_kinds`` it is
    the same as ``{}``. They apply to every Sentinel of the class with no policy of its own for a kind."""
    if not actor.is_superuser:
        raise ApiError(403, 'the Sentinel defaults are changed by an App Admin')
    if not isinstance(body, dict) or not body or set(body) - set(DEFAULT_KEYS):
        raise ApiError(400, f'send any of {", ".join(DEFAULT_KEYS)}: {{"self_update": "off" | "manual" | "automatic" | null, "keep_newest": true | false, '
                            '"builtin_kinds": {kind: {"mode", "max_concurrent"}} | null, "external_kinds": {kind: {"mode", "max_concurrent"}} | null}')
    value = body.get('self_update')
    if 'keep_newest' in body and not isinstance(body['keep_newest'], bool):
        raise ApiError(400, 'keep_newest must be true or false')
    if 'self_update' in body and value is not None and value not in SELF_UPDATE:
        raise ApiError(400, f'self_update must be one of {", ".join(SELF_UPDATE)}, or null')
    cleaned = {}
    for key in ('builtin_kinds', 'external_kinds'):
        if key in body:
            if body[key] is None:
                cleaned[key] = None
            elif body[key] == {}:
                cleaned[key] = {}
            else:
                cleaned[key] = policy_lib.clean_kinds(body[key], what=key, allow_null_entries=False)
    before = get_defaults()
    row = SentinelDefaults.current()
    if 'self_update' in body:
        row.self_update = value or ''
    if 'keep_newest' in body:
        row.keep_newest = body['keep_newest']
    if 'builtin_kinds' in cleaned:
        row.builtin_kinds = cleaned['builtin_kinds']  # None: the shipped default again
    if 'external_kinds' in cleaned:
        row.external_kinds = cleaned['external_kinds'] or {}
    row.changed_by, row.changed_at = actor.username, timezone.now()
    row.save()
    after = get_defaults()
    extra = {key: {'before': before[key], 'after': after[key]} for key in ('builtin_kinds', 'external_kinds') if key in body}
    if 'keep_newest' in body:
        extra['keep_newest'] = {'before': before['keep_newest'], 'after': after['keep_newest']}
    audit.record(actor, 'sentinel.defaults', 'sentinel defaults', before=before['self_update'], after=after['self_update'], **extra)
    return after
