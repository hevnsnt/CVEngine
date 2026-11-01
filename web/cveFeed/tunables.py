"""Tunables: the numeric knobs an operator wants to turn without editing ``.env`` and restarting, chosen on Settings, configMaxxing.

One registry (``TUNABLES``): adding a tunable is one ``Tunable(...)`` line here and a call to ``value(key)`` where the code used to read the
environment variable. Nothing else changes: the storage (one row, ``TunableSettings``), the validation, the audit entries, the settings API and
the cards on the page are all driven by the registry. A new *group* (a card) is one ``Group`` line here and one ``registerTunableGroup`` line in
``static/cve/tunables-card.js`` (a test keeps the two lists equal).

Precedence, one rule for every tunable: the value an App Admin saved here, else the environment variable (as it always was), else the built-in
default. The saved value is a row in the database (the truth). The processes that read a tunable (web, celery workers) use a copy that is
published to Redis on every save and again every 30 seconds (``reconcile``, from the ``report_resources`` tick, so a flushed Redis heals), and
cache it in memory for ``CACHE_SECONDS``: a save takes effect everywhere within seconds, with no restart, and a read never waits on the
database. If Redis cannot be read, the last copy the process saw is kept (none yet means the environment or the default, exactly as before this
page existed).

``applies`` says when a tunable takes effect: ``live`` (read on every use) or ``restart`` (read once when a process starts; the page then says
so). Every tunable registered today is live.

These are instance-level settings: one value for the whole installation, never per project or organization. A per-project daily cap is the same
number for every project. Only an App Admin (superuser) can read or change them.
"""
import json
import logging
import os
import threading
import time
from collections import namedtuple

from reNgine import resources

logger = logging.getLogger(__name__)

VALUES_KEY = 'cvengine:tunables:values'  # the published copy of TunableSettings.values
CACHE_SECONDS = resources.SAVED_CACHE_SECONDS
LIVE, RESTART = 'live', 'restart'

Group = namedtuple('Group', 'id title intro')
# key: stable id (also the API and database key). env: the environment variable that existed before the page. default/low/high: whole numbers;
# the environment is clamped up to ``low`` as every reader always did, but never capped at ``high``. ``unit`` is a few words shown beside the
# box. ``env_float``: the environment may hold a fraction (hours), which is passed through as it always was.
Tunable = namedtuple('Tunable', 'key label help group env default low high unit applies env_float', defaults=(LIVE, False))

GROUPS = [
    Group('ai_spend', 'AI spend',
          'Every triage question, validation check and template draft is a call to your AI provider, which costs money with a paid key. '
          'Lower numbers spend less and leave more work waiting for the next day; higher numbers clear a backlog faster. A day starts at midnight (server time). '
          'The AI model tab holds the provider, the model and the planning and CVE guidance budgets.'),
    Group('throughput', 'Scan pacing',
          'How eagerly scans are started and how widely one scan spreads across your Sentinels. More at once finishes sooner but puts more load on '
          'your Sentinels and more traffic on your targets. How many things this server scans at once is under Scan concurrency.'),
]

TUNABLES = [
    Tunable('triage_max_per_run', 'Triage questions per run',
            'Most AI triage questions one run asks. One question serves every finding with the same evidence; a repair call and a local-check suggestion count too. '
            'What is over the cap waits for the next run.',
            'ai_spend', 'CVENGINE_TRIAGE_MAX_PER_RUN', 100, 1, 1000, 'questions'),
    Tunable('triage_max_per_project_day', 'Triage questions per project per day',
            'Most AI triage questions asked for one project in a day, so one busy project cannot use the whole day\'s budget. The same number applies to every project.',
            'ai_spend', 'CVENGINE_TRIAGE_MAX_PER_PROJECT_DAY', 500, 1, 10000, 'questions'),
    Tunable('triage_max_per_day', 'Triage questions per day',
            'Most AI triage questions asked in a day across all projects: the ceiling on triage spend. Failed and abandoned attempts count, because the provider bills them.',
            'ai_spend', 'CVENGINE_TRIAGE_MAX_PER_DAY', 2000, 1, 50000, 'questions'),
    Tunable('validate_max_per_run', 'Validation checks per task',
            'Most validation checks one validation task runs. Each check can use up to three AI calls.',
            'ai_spend', 'CVENGINE_VALIDATE_MAX_PER_RUN', 50, 1, 500, 'checks'),
    Tunable('validate_max_per_project_day', 'Validation checks per project per day',
            'Most validation checks run for one project in a day. The same number applies to every project.',
            'ai_spend', 'CVENGINE_VALIDATE_MAX_PER_PROJECT_DAY', 300, 1, 5000, 'checks'),
    Tunable('validate_max_per_day', 'Validation checks per day',
            'Most validation checks run in a day across all projects: the ceiling on validation spend. Failed checks count.',
            'ai_spend', 'CVENGINE_VALIDATE_MAX_PER_DAY', 1500, 1, 20000, 'checks'),
    Tunable('validate_min_gap_hours', 'Hours between validations of the same finding',
            'The least time between two automatic validations of the same host, CVE, product and version whose evidence did not change (a rescan makes a new '
            'match of the same finding each time). New evidence is validated at once. 0 turns the gap off.',
            'ai_spend', 'CVENGINE_VALIDATE_MIN_GAP_HOURS', 12, 0, 720, 'hours', LIVE, True),
    Tunable('template_gen_max_per_day', 'AI template drafts per day',
            'Most Nuclei templates the AI may draft in a day across all projects. Every attempt counts, whatever its outcome.',
            'ai_spend', 'CVENGINE_TEMPLATE_GEN_MAX_PER_DAY', 10, 1, 200, 'drafts'),
    Tunable('stage_parallel', 'Chunks of one scan stage at once',
            'The most chunk tasks ONE scan stage keeps in flight across Sentinel slots at once (the nmap and naabu chunks of up to 64 addresses, the nuclei chunks). '
            '1 sends them one after another. The window is also limited by the Sentinel slots that are free, so raising this does nothing without free slots.',
            'throughput', 'CVENGINE_STAGE_PARALLEL', 4, 1, 16, 'chunks'),
    Tunable('work_min_gap_hours', 'Hours before a target is scanned again by the conductor',
            'The work conductor never starts a discovery scan of a target scanned inside this many hours. Lower rescans sooner and costs more scanning. '
            'How many scans it keeps running is under Scan concurrency.',
            'throughput', 'CVENGINE_WORK_MIN_GAP_HOURS', 2, 0, 168, 'hours'),
    Tunable('sentinel_refresh_gap_hours', 'Hours before a host is assessed again by the refresh',
            'When no host is missing its first pass, a live Sentinel is kept busy by assessing the hosts assessed longest ago again, none sooner than this many hours '
            'after its last assessment. 0 turns the refresh off.',
            'throughput', 'CVENGINE_SENTINEL_REFRESH_GAP_HOURS', 6, 0, 720, 'hours', LIVE, True),
    Tunable('bulk_discover_now', 'Targets scanned at once when many are added',
            'How many of the targets one add (a paste of many names, the API or a tool) queues for discovery at once. The rest are created and left to the work '
            'conductor, one per project per minute, so one paste cannot push every other project\'s scans back.',
            'throughput', 'CVENGINE_BULK_DISCOVER_NOW', 50, 1, 500, 'targets'),
]
BY_KEY = {t.key: t for t in TUNABLES}
GROUP_BY_ID = {g.id: g for g in GROUPS}
assert len(BY_KEY) == len(TUNABLES) and all(t.group in GROUP_BY_ID for t in TUNABLES), 'a tunable is duplicated or names no group'
APPLIES_TEXT = {LIVE: 'Applies within a few seconds, with no restart', RESTART: 'Applies after the next restart'}


# --- resolving a value ------------------------------------------------------------------------------------------------

def env_value(tunable, environ=None):
    """The number the environment gives, or None when it is unset or not a number. Clamped up to the tunable's minimum (as every reader always
    did), never capped: the environment was never range-checked, and an operator who sets it knows."""
    raw = (environ if environ is not None else os.environ).get(tunable.env)
    if raw is None or not str(raw).strip():
        return None
    try:
        number = float(str(raw).strip())
        if number != number or number in (float('inf'), float('-inf')):
            return None
        number = number if tunable.env_float else int(number)
    except (ValueError, OverflowError):
        return None
    return max(tunable.low, number)


def _valid_saved(tunable, saved):
    return isinstance(saved, int) and not isinstance(saved, bool) and tunable.low <= saved <= tunable.high


def resolve(key, stored=None):
    """{'value', 'source'} for one key: ``admin`` (saved on the page), ``environment`` or ``default``. ``stored`` is the saved mapping; by default
    the cached copy the processes use."""
    tunable = BY_KEY[key]
    values = stored_values() if stored is None else stored
    saved = values.get(key)
    if _valid_saved(tunable, saved):
        return {'value': saved, 'source': 'admin'}
    env = env_value(tunable)
    if env is not None:
        return {'value': env, 'source': 'environment'}
    return {'value': tunable.default, 'source': 'default'}


def value(key, default=None):
    """The number in effect for a tunable now: what the code that used to read the environment variable calls. ``default`` is the module's own
    constant, used when neither a saved value nor the environment gives one (a test, or a deployment, that patches the constant keeps working; a
    test pins that it equals the registry's default). Never raises: when the saved copy cannot be read, the environment decides, then the default."""
    try:
        got = resolve(key)
    except Exception:  # noqa: BLE001 - a cache that cannot be read must never stop a scan or an AI budget check
        logger.debug('tunable %s: the saved copy could not be read', key, exc_info=False)
        got = resolve(key, {})
    return default if default is not None and got['source'] == 'default' else got['value']


# --- the published copy -----------------------------------------------------------------------------------------------

_cache = {'at': None, 'values': {}}
_lock = threading.Lock()


def invalidate():
    """Forget this process's cached copy (a save does this at once; other processes catch up within CACHE_SECONDS)."""
    with _lock:
        _cache.update(at=None)


def stored_values(now_fn=time.monotonic):
    """What an App Admin saved, as the processes see it: the Redis copy, cached CACHE_SECONDS. On a Redis outage the last copy this process saw
    is kept; with none, nothing is saved as far as this process knows and the environment or the default applies, as before this page."""
    now = now_fn()
    with _lock:
        if _cache['at'] is not None and now - _cache['at'] < CACHE_SECONDS:
            return _cache['values']
    try:
        client = resources.redis_client()
        raw = client.get(VALUES_KEY) if client is not None else None
        values = json.loads(raw).get('values', {}) if raw else {}
        values = values if isinstance(values, dict) else {}
    except Exception:  # noqa: BLE001
        logger.debug('saved tunables could not be read', exc_info=False)
        with _lock:
            _cache['at'] = now  # no retry on every call during an outage
            return _cache['values']
    with _lock:
        _cache.update(at=now, values=values)
    return values


def publish(values):
    """Put the saved values where the processes read them. Returns whether Redis took them (the 30 second tick tries again if not)."""
    try:
        client = resources.redis_client()
        if client is None:
            return False
        client.set(VALUES_KEY, json.dumps({'values': values, 't': time.time()}))
        return True
    except Exception:  # noqa: BLE001
        logger.warning('tunables: could not publish the saved values to Redis; processes pick them up on the next 30 second check')
        return False
    finally:
        invalidate()


def saved_row():
    from cveFeed.models import TunableSettings
    return TunableSettings.current()


def saved_values():
    """The saved values straight from the database (the truth), keeping only what names a known tunable."""
    return {k: v for k, v in (saved_row().values or {}).items() if k in BY_KEY and isinstance(v, int) and not isinstance(v, bool)}


def reconcile():
    """The 30 second tick (``report_resources``): republish the saved values, so a flushed Redis heals. Never raises."""
    try:
        return publish(saved_values())
    except Exception:  # noqa: BLE001
        logger.debug('tunables: reconcile could not read the saved values', exc_info=False)
        return False


# --- validation and saving --------------------------------------------------------------------------------------------

def clean(key, raw):
    """A whole number inside the tunable's range, or None (reset to default). Raises ValueError with a sentence for the page."""
    import re
    tunable = BY_KEY.get(key)
    if tunable is None:
        raise ValueError(f'unknown setting {key}')
    if raw is None:
        return None
    if isinstance(raw, str) and re.fullmatch(r'\s*\d+\s*', raw):
        raw = int(raw)
    if isinstance(raw, float) and raw.is_integer():
        raw = int(raw)
    if isinstance(raw, bool) or not isinstance(raw, int) or not tunable.low <= raw <= tunable.high:
        raise ValueError(f'{tunable.label} must be a whole number from {tunable.low} to {tunable.high}')
    return raw


def _need_admin(user):
    if not (getattr(user, 'is_authenticated', False) and getattr(user, 'is_superuser', False)):
        raise PermissionError('only an App Admin may change these settings')


def update(values, user):
    """Save a partial change: ``{key: whole number}`` sets, ``{key: None}`` resets that key to its default. Everything is validated first;
    nothing is saved if one value is wrong. Each change is audited. Only a superuser may call it. Returns the keys changed."""
    from django.db import transaction
    from django.utils import timezone

    from cveFeed.admin_api import audit
    from cveFeed.models import TunableSettings
    _need_admin(user)
    if not isinstance(values, dict):
        raise ValueError('values must be an object of setting: number')
    cleaned = {key: clean(key, raw) for key, raw in values.items()}
    changed = []
    with transaction.atomic():
        row = TunableSettings.objects.select_for_update().get(pk=TunableSettings.current().pk)
        stored, meta = dict(row.values or {}), dict(row.meta or {})
        for key, new in cleaned.items():
            before = resolve(key, stored)
            env = BY_KEY[key].env
            if new is None:
                if key in stored:
                    stored.pop(key)
                    meta.pop(key, None)
                    changed.append(key)
                    audit(user, 'tunable.reset', key, env=env, before=before['value'], before_source=before['source'], after=resolve(key, stored)['value'])
            elif stored.get(key) != new:
                stored[key] = new
                meta[key] = {'by': user.username, 'at': timezone.now().isoformat()}
                changed.append(key)
                audit(user, 'tunable.set', key, env=env, before=before['value'], before_source=before['source'], after=new)
        if changed:
            row.values, row.meta, row.updated_by = stored, meta, user
            row.save()
    if changed:
        publish(stored)
    return changed


def reset_group(user, group_id):
    """Every tunable of one group back to its default (part of the configMaxxing "reset all"). Audited per key and as one entry. Returns the
    keys that were set."""
    from cveFeed.admin_api import audit
    _need_admin(user)
    keys = [t.key for t in TUNABLES if t.group == group_id]
    cleared = update({key: None for key in keys}, user)
    audit(user, 'config_maxxing.tunables_reset_all', group_id, cleared=sorted(cleared))
    return sorted(cleared)


# --- what the page shows -------------------------------------------------------------------------------------------------

def snapshot():
    """Everything the cards show, from the database (the truth) and the environment. The same shape as the Scan concurrency card's fields, so
    the page draws them with the same code."""
    row = saved_row()
    stored = {k: v for k, v in (row.values or {}).items() if k in BY_KEY}
    fields = []
    for t in TUNABLES:
        got = resolve(t.key, stored)
        meta = (row.meta or {}).get(t.key) or {}
        admin = got['source'] == 'admin'
        fields.append({'key': t.key, 'label': t.label, 'help': t.help, 'group': t.group, 'default': t.default, 'min': t.low, 'max': t.high,
                       'unit': t.unit, 'value': got['value'], 'source': got['source'], 'env_name': t.env, 'env_value': env_value(t),
                       'saved': stored.get(t.key) if admin else None, 'set_by': meta.get('by') if admin else None,
                       'set_at': meta.get('at') if admin else None, 'applies': t.applies, 'applies_text': APPLIES_TEXT[t.applies]})
    return {'fields': fields, 'groups': [{'id': g.id, 'title': g.title, 'intro': g.intro} for g in GROUPS], 'cache_seconds': CACHE_SECONDS}
