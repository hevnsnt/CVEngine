"""A Sentinel's settings, managed from cvENGINE or set where it runs: the most recent change wins.

A Sentinel is configured on its own machine (its environment), and an administrator can also change the same settings from cvENGINE
after it checked in, so nothing has to be touched on the machine. Both sides keep a value and the time it last changed (this server's
clock, so the two can be compared): ``Agent.reported_settings`` is what the Sentinel's own configuration says, ``Agent.managed_settings``
what an administrator set. The effective value of each setting is the one changed last; a Sentinel that restarts with an unchanged
configuration does not override a later edit made here, and an edit made on the machine after the last dashboard edit wins.

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
from agentapi.models import Agent, SentinelDefaults, SentinelTask
from agentapi.services import ApiError
from tenancy import audit

SETTINGS = ('name', 'network', 'profile', 'disabled_kinds', 'max_concurrent', 'self_update')
SELF_UPDATE = ('off', 'manual', 'automatic')
# What an administrator is told to run on the Sentinel's machine when its host updater is missing: fixed text, never something a Sentinel reported.
INSTALL_COMMAND = 'cd <the Sentinel checkout> && sudo ./scripts/install-updater.sh'


def clean_settings(raw):
    """The settings in ``raw`` (any subset of ``SETTINGS``) validated, or ``ApiError``. ``None`` as a value is kept so a caller can clear one."""
    from agentapi import sentinel_broker as sb
    if not isinstance(raw, dict) or not raw:
        raise ApiError(400, f'send settings as an object with any of {", ".join(SETTINGS)}')
    unknown = sorted(set(raw) - set(SETTINGS))
    if unknown:
        raise ApiError(400, f'unknown setting {unknown[0]!r}; settings are {", ".join(SETTINGS)}')
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
        elif key == 'max_concurrent':
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= broker.MAX_CONCURRENT_CAP:
                raise ApiError(400, f'max_concurrent must be a whole number from 1 to {broker.MAX_CONCURRENT_CAP}')
            out[key] = value
    return out


def _when(entry):
    try:
        return datetime.fromisoformat(entry['at'])
    except (KeyError, TypeError, ValueError):
        return None


def detail(agent):
    """``{setting: {value, source, at, by}}`` for every setting either side has a value for. ``source`` is ``server`` (set from cvENGINE) or
    ``sentinel`` (its own configuration); a tie goes to the server, because an administrator's explicit edit is the more deliberate act."""
    out = {}
    managed, reported = agent.managed_settings or {}, agent.reported_settings or {}
    for key in SETTINGS:
        m, r = managed.get(key), reported.get(key)
        if m is None and r is None:
            continue
        pick = 'sentinel' if m is None else 'server' if r is None else ('sentinel' if (_when(r) and _when(m) and _when(r) > _when(m)) else 'server')
        entry = m if pick == 'server' else r
        out[key] = {'value': entry['value'], 'source': pick, 'at': entry.get('at'), 'by': entry.get('by') if pick == 'server' else None}
    return out


def instance_self_update():
    """The instance-wide default for Sentinels' self-update: the administrators' choice (``SentinelDefaults``), else the instance's own update
    choice (Automatic updates mean ``automatic``, anything else ``manual``)."""
    from cveFeed import updater
    chosen = SentinelDefaults.current().self_update
    if chosen in SELF_UPDATE:
        return chosen
    return 'automatic' if updater.read_mode() == 'auto' else 'manual'


def explicit(agent):
    """``{setting: value}`` for the settings someone actually set (the Sentinel's own configuration or an administrator), without the instance default."""
    return {key: entry['value'] for key, entry in detail(agent).items()}


def effective(agent):
    """``{setting: value}``: what this Sentinel should run with now. ``self_update`` always has a value: its own, else the instance default."""
    out = explicit(agent)
    out.setdefault('self_update', instance_self_update())
    return out


def revision(values):
    """A short fingerprint of effective settings, so a client can tell cheaply that something changed."""
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()[:12]


def record_reported(agent, raw, now=None):
    """Store the Sentinel's own settings. Only a value that differs from the last one it reported moves its time forward, so a restart with an
    unchanged configuration never overrides an administrator's later edit. Returns the settings that changed."""
    now = now or timezone.now()
    values = clean_settings({k: v for k, v in (raw or {}).items() if v is not None}) if raw else {}
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
    """An administrator's change from cvENGINE. A value of ``null`` clears the server's value for that setting, so the Sentinel's own applies."""
    now = now or timezone.now()
    values = clean_settings(raw)
    managed, before = dict(agent.managed_settings or {}), explicit(agent)
    for key, value in values.items():
        if value is None:
            managed.pop(key, None)
        elif (managed.get(key) or {}).get('value') != value:
            managed[key] = {'value': value, 'at': now.isoformat(), 'by': actor.username}
    agent.managed_settings = managed
    Agent.objects.filter(pk=agent.pk).update(managed_settings=managed)
    audit.record_for_user(actor, 'agent.settings', agent.token.user, target=agent.name, agent_id=agent.pk, before=before, after=explicit(agent))
    return effective(agent)


def reply(agent):
    """What a Sentinel is told about its settings: the effective values and their fingerprint."""
    values = effective(agent)
    return {'values': values, 'rev': revision(values)}


# --- the Sentinel's own version and its host-side updater ---------------------------------------------------------------------------------

UPDATE_STATUSES = ('idle', 'waiting', 'draining', 'updating', 'done', 'failed')


def clean_info(raw):
    """What a Sentinel reports about itself, validated: its client ``version``, its updater's ``update`` state and whether its own GVM stack can scan (``openvas``). Anything else is dropped."""
    if not isinstance(raw, dict):
        raise ApiError(400, 'info must be an object')
    out = {}
    if raw.get('version') is not None:
        version = raw['version']
        if not isinstance(version, str) or len(version) > 64 or not all(c.isalnum() or c in '.-_+' for c in version):
            raise ApiError(400, 'version must be at most 64 letters, digits and . - _ +')
        out['version'] = version
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
    gvm = raw.get('openvas')
    if gvm is not None:
        if not isinstance(gvm, dict) or not isinstance(gvm.get('ready'), bool):
            raise ApiError(400, 'openvas must be {ready: bool, reason: text}')
        reason = gvm.get('reason')
        if reason is not None and not isinstance(reason, str):
            raise ApiError(400, 'openvas.reason must be text')
        out['openvas'] = {'ready': gvm['ready'], 'reason': ''.join(c for c in (reason or '') if c.isprintable())[:200]}
    return out


def record_info(agent, raw, now=None):
    """Store what the Sentinel reports. An administrator's pending "update now" is answered, and so cleared, by a different version or a failed attempt."""
    info = clean_info(raw)
    if not info:
        return False
    merged = {**(agent.info or {}), **info}
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
    setting = effective(agent)['self_update']
    return {'setting': setting, 'mode': 'auto' if setting == 'automatic' else 'manual',
            'requested': bool(agent.update_requested_at) and setting != 'off'}


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
    setting = effective(agent)['self_update']
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
    if effective(agent)['self_update'] == 'off':
        raise ApiError(409, 'self-update is Off for this Sentinel: set it to Manual or Automatic first')
    now = now or timezone.now()
    agent.update_requested_at = now
    Agent.objects.filter(pk=agent.pk).update(update_requested_at=now)
    audit.record_for_user(actor, 'agent.update_requested', agent.token.user, target=agent.name, agent_id=agent.pk,
                          version=(agent.info or {}).get('version'))


def get_defaults():
    """The instance-wide Sentinel defaults: ``{self_update, effective_self_update, follows_instance, changed_by, changed_at}``."""
    row = SentinelDefaults.current()
    return {'self_update': row.self_update or None, 'effective_self_update': instance_self_update(), 'follows_instance': not row.self_update,
            'changed_by': row.changed_by or None, 'changed_at': row.changed_at.isoformat() if row.changed_at else None}


def set_defaults(actor, body):
    """App Admin only: ``{self_update: off|manual|automatic|null}`` (``null`` goes back to following the instance's own Automatic or Manual
    update choice). Applies to every Sentinel with no value of its own for that setting."""
    if not actor.is_superuser:
        raise ApiError(403, 'the Sentinel defaults are changed by an App Admin')
    if not isinstance(body, dict) or set(body) != {'self_update'}:
        raise ApiError(400, 'send {"self_update": "off" | "manual" | "automatic" | null}')
    value = body['self_update']
    if value is not None and value not in SELF_UPDATE:
        raise ApiError(400, f'self_update must be one of {", ".join(SELF_UPDATE)}, or null')
    before = get_defaults()
    row = SentinelDefaults.current()
    row.self_update, row.changed_by, row.changed_at = value or '', actor.username, timezone.now()
    row.save()
    audit.record(actor, 'sentinel.defaults', 'sentinel defaults', before=before['self_update'], after=value)
    return get_defaults()
