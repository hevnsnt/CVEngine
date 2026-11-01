"""Tunables: the numeric knobs an operator wants to turn without editing ``.env`` and restarting, chosen on Settings, configMaxxing.

One registry (``TUNABLES``): adding a tunable is one ``Tunable(...)`` line here and a call to ``value(key)`` where the code used to read the
environment variable. Nothing else changes: the storage (one row, ``TunableSettings``), the validation, the audit entries, the settings API and
the cards on the page are all driven by the registry. A new *group* (a card) is one ``Group`` line here and one ``registerTunableGroup`` line in
``static/cve/tunables-card.js`` (a test keeps the two lists equal).

Precedence, one rule for every tunable: the value an App Admin saved here (it pins the tunable), else the number the auto-tuner chose (mode
Auto, only for a tunable with ``auto_tunable=True``; ``cveFeed.autotune``), else the environment variable (as it always was), else the built-in
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
# ``caution``: ``cap`` (a number that limits paid calls or work per run or day: the page warns, softly, about a value far below or far above the default),
# ``rescan`` (0 means continuous rescans) or ``None``. ``window``: when a cap counts from again (``run``, ``utc_day``, ``rolling_day``). ``note``: a
# sentence that replaces the standard "applies" text where a tunable is read less often than on every use.
# ``auto_tunable`` must be stated (True or False) for every tunable: only a throughput, concurrency or pacing number opts in, never an AI spend cap
# or anything that guards safety. The auto-tuner (cveFeed.autotune) moves one that opts in inside ``auto_min``..``auto_max`` (tighter than
# ``low``..``high`` where that is safer) by ``auto_step``. ``auto_sense``: ``more`` (a higher number does more work at once) or ``gap`` (a
# higher number waits longer between runs, so does less). ``auto_optimistic``: the tuner's target when the facts it sizes from are not reported yet
# (cveFeed.autotune_policy.size_for).
Tunable = namedtuple('Tunable', 'key label help group env default low high unit applies env_float caution window note '
                     'auto_tunable auto_min auto_max auto_step auto_sense auto_optimistic',
                     defaults=(LIVE, False, None, None, None, None, None, None, 1, 'more', None))
HOURS_CEILING = 24 * 365 * 10  # an environment value in hours is held to ten years before it reaches a timedelta
USED_SINCE = {'utc_day': 'since UTC midnight', 'rolling_day': 'in the last 24 hours'}
WINDOW_TEXT = {'run': 'at the next run', 'utc_day': 'at the next UTC midnight', 'rolling_day': 'as the oldest of the last 24 hours ages out'}

GROUPS = [
    Group('ai_spend', 'AI spend',
          'Every triage question, validation check and template draft is a call to your AI provider, which costs money with a paid key. '
          'Lower numbers spend less and leave more work waiting; higher numbers clear a backlog faster. Triage and validation count a day from UTC midnight; '
          'template drafts count the last 24 hours. The AI model tab holds the provider, the model and the planning and CVE guidance budgets.'),
    Group('throughput', 'Scan pacing',
          'How eagerly scans are started and how widely one scan spreads across your Sentinels. More at once finishes sooner but puts more load on '
          'your Sentinels and more traffic on your targets. How many things this server scans at once is under Scan concurrency.'),
    Group('autotune_pace', 'Auto-tuning pace',
          'The auto-tuner aims high for this machine first, backs off at once on trouble, then probes upward slowly. These say how slowly, and how much '
          'history it reads. Longer waits make it calmer, shorter ones let it follow a changing load sooner. The AI advisor\'s own budget is under AI spend.'),
]

TUNABLES = [
    Tunable('triage_max_per_run', 'Triage questions per run',
            'Most AI triage questions one run asks. One question serves every finding with the same evidence; a repair call and a local-check suggestion count too. '
            'What is over the cap waits for the next run.',
            'ai_spend', 'CVENGINE_TRIAGE_MAX_PER_RUN', 100, 1, 1000, 'questions', caution='cap', window='run', auto_tunable=False),
    Tunable('triage_max_per_project_day', 'Triage questions per project per day',
            'Most AI triage questions asked for one project in a day (counted from UTC midnight), so one busy project cannot use the whole day\'s budget. '
            'The same number applies to every project.',
            'ai_spend', 'CVENGINE_TRIAGE_MAX_PER_PROJECT_DAY', 500, 1, 10000, 'questions', caution='cap', window='utc_day', auto_tunable=False),
    Tunable('triage_max_per_day', 'Triage questions per day',
            'Most AI triage questions asked in a day (counted from UTC midnight) across all projects: the ceiling on triage spend. '
            'Failed and abandoned attempts count, because the provider bills them.',
            'ai_spend', 'CVENGINE_TRIAGE_MAX_PER_DAY', 2000, 1, 50000, 'questions', caution='cap', window='utc_day', auto_tunable=False),
    Tunable('validate_max_per_run', 'Validation checks per task',
            'Most validation checks one validation task runs. Each check can use up to three AI calls.',
            'ai_spend', 'CVENGINE_VALIDATE_MAX_PER_RUN', 50, 1, 500, 'checks', caution='cap', window='run', auto_tunable=False),
    Tunable('validate_max_per_project_day', 'Validation checks per project per day',
            'Most validation checks run for one project in a day (counted from UTC midnight). The same number applies to every project.',
            'ai_spend', 'CVENGINE_VALIDATE_MAX_PER_PROJECT_DAY', 300, 1, 5000, 'checks', caution='cap', window='utc_day', auto_tunable=False),
    Tunable('validate_max_per_day', 'Validation checks per day',
            'Most validation checks run in a day (counted from UTC midnight) across all projects: the ceiling on validation spend. Failed checks count.',
            'ai_spend', 'CVENGINE_VALIDATE_MAX_PER_DAY', 1500, 1, 20000, 'checks', caution='cap', window='utc_day', auto_tunable=False),
    Tunable('validate_min_gap_hours', 'Hours between validations of the same finding',
            'The least time between two automatic validations of the same host, CVE, product and version whose evidence did not change (a rescan makes a new '
            'match of the same finding each time). New evidence is validated at once. 0 turns the gap off.',
            'ai_spend', 'CVENGINE_VALIDATE_MIN_GAP_HOURS', 12, 0, 720, 'hours', LIVE, True, auto_tunable=False),
    Tunable('template_gen_max_per_day', 'AI template drafts per day',
            'Most Nuclei templates the AI may draft in the last 24 hours (a rolling window, not a calendar day) across all projects. Every attempt counts, '
            'whatever its outcome.',
            'ai_spend', 'CVENGINE_TEMPLATE_GEN_MAX_PER_DAY', 10, 1, 200, 'drafts', caution='cap', window='rolling_day', auto_tunable=False),
    Tunable('autotune_ai_max_per_day', 'Auto-tuning AI advice per day',
            'Most questions the auto-tuner asks the AI advisor in a day (counted from UTC midnight). Each question is one small call with numbers only. '
            'Over the cap the deterministic controller keeps tuning on its own; with no AI provider it always does.',
            'ai_spend', 'CVENGINE_AUTOTUNE_AI_MAX_PER_DAY', 8, 1, 96, 'questions', caution='cap', window='utc_day', auto_tunable=False),
    Tunable('stage_parallel', 'Chunks of one scan stage at once',
            'The most chunk tasks ONE scan stage keeps in flight across Sentinel slots at once (the nmap and naabu chunks of up to 64 addresses, the nuclei chunks). '
            '1 sends them one after another. The window is also limited by the Sentinel slots that are free, so raising this does nothing without free slots.',
            'throughput', 'CVENGINE_STAGE_PARALLEL', 4, 1, 16, 'chunks',
            note='Applies from the next stage that starts; a stage already running keeps the number it started with',
            auto_tunable=True, auto_min=2, auto_max=16, auto_step=1, auto_optimistic=6),
    Tunable('work_min_gap_hours', 'Hours before a target is scanned again by the conductor',
            'The work conductor never starts a discovery scan of a target scanned inside this many hours. Lower rescans sooner and costs more scanning. '
            'How many scans it keeps running is under Scan concurrency.',
            'throughput', 'CVENGINE_WORK_MIN_GAP_HOURS', 2, 0, 168, 'hours', caution='rescan',
            auto_tunable=True, auto_min=1, auto_max=12, auto_step=1, auto_sense='gap', auto_optimistic=1),
    Tunable('sentinel_refresh_gap_hours', 'Hours before a host is assessed again by the refresh',
            'When no host is missing its first pass, a live Sentinel is kept busy by assessing the hosts assessed longest ago again, none sooner than this many hours '
            'after its last assessment. 0 turns the refresh off.',
            'throughput', 'CVENGINE_SENTINEL_REFRESH_GAP_HOURS', 6, 0, 720, 'hours', LIVE, True,
            auto_tunable=True, auto_min=2, auto_max=24, auto_step=1, auto_sense='gap', auto_optimistic=3),
    Tunable('bulk_discover_now', 'Targets scanned at once when many are added',
            'How many of the targets one add (a paste of many names, the API or a tool) queues for discovery at once. The rest are created and left to the work '
            'conductor, one per project per minute, so one paste cannot push every other project\'s scans back.',
            'throughput', 'CVENGINE_BULK_DISCOVER_NOW', 50, 1, 500, 'targets', auto_tunable=False),
    Tunable('autotune_cooldown_minutes', 'Minutes between two calm auto-tune changes of one setting',
            'The least time between two changes of the same setting that no trouble forced (a one-step lowering the AI advisor recommends). A back-off '
            'for memory, database, worker or Sentinel trouble never waits for it, and an upward probe waits for the longer probe cooldown below.',
            'autotune_pace', 'CVENGINE_AUTOTUNE_COOLDOWN_MINUTES', 30, 10, 1440, 'minutes', auto_tunable=False),
    Tunable('autotune_raise_cooldown_minutes', 'Minutes before an auto-tune probe upward',
            'After aiming high and backing off, the tuner probes upward one step at a time, and only this long after the setting last changed. A probe '
            'also needs two hours without trouble for that setting, work waiting and room to spare, and never reaches a level that caused trouble in the last day.',
            'autotune_pace', 'CVENGINE_AUTOTUNE_RAISE_COOLDOWN_MINUTES', 120, 10, 1440, 'minutes', auto_tunable=False),
    Tunable('autotune_window_hours', 'Hours of measurements the auto-tuner reads',
            'How far back the auto-tuner looks at its own measurements (taken every ten minutes) when it summarises them for a decision and for the AI advisor. '
            'An upward probe also needs the last three measurements in a row to show queued work and room to spare.',
            'autotune_pace', 'CVENGINE_AUTOTUNE_WINDOW_HOURS', 3, 1, 24, 'hours', auto_tunable=False),
    Tunable('autotune_ai_interval_hours', 'Hours between two questions to the AI advisor',
            'How often the auto-tuner asks the AI advisor for a second opinion, when an AI provider is set up and the advisor is on. Between questions, '
            'and whenever the advisor is unavailable or over its daily budget, the deterministic controller tunes alone.',
            'autotune_pace', 'CVENGINE_AUTOTUNE_AI_INTERVAL_HOURS', 3, 1, 24, 'hours', auto_tunable=False),
]
BY_KEY = {t.key: t for t in TUNABLES}
GROUP_BY_ID = {g.id: g for g in GROUPS}
assert len(BY_KEY) == len(TUNABLES) and all(t.group in GROUP_BY_ID for t in TUNABLES), 'a tunable is duplicated or names no group'
assert all(t.auto_tunable in (True, False) for t in TUNABLES), 'every tunable states auto_tunable=True or auto_tunable=False'
assert not any(t.auto_tunable and t.group == 'ai_spend' for t in TUNABLES), 'an AI spend cap is never auto-tuned'
assert all(not t.auto_tunable or (t.low <= t.auto_min <= t.auto_optimistic <= t.auto_max <= t.high and t.auto_sense in ('more', 'gap')) for t in TUNABLES)
APPLIES_TEXT = {LIVE: 'Applies within a few seconds, with no restart', RESTART: 'Applies after the next restart'}


# --- resolving a value ------------------------------------------------------------------------------------------------

def env_value(tunable, environ=None):
    """The number the environment gives, or None when it is unset or not a number. Read as the readers always did: a whole number for an integer
    tunable (``7.9`` and ``1e6`` are not one, so the default applies), a number of hours that may be a fraction for the gap settings (a value that is
    not finite is not a number). Clamped up to the tunable's minimum (as every reader always did) and never capped, except that a number of hours
    is held to ``HOURS_CEILING`` so that it cannot overflow a ``timedelta``: the environment was never range-checked, and an operator who sets it
    knows."""
    raw = (environ if environ is not None else os.environ).get(tunable.env)
    if raw is None or not str(raw).strip():
        return None
    try:
        if tunable.env_float:
            number = float(str(raw).strip())
            if number != number or number in (float('inf'), float('-inf')):
                return None
        else:
            number = int(str(raw).strip())
    except ValueError:
        return None
    if tunable.unit == 'hours':
        number = min(number, HOURS_CEILING)
    return max(tunable.low, number)


def _valid_saved(tunable, saved):
    return isinstance(saved, int) and not isinstance(saved, bool) and tunable.low <= saved <= tunable.high


def resolve(key, stored=None, auto=None):
    """{'value', 'source'} for one key: ``admin`` (saved on the page: it pins the key), ``auto`` (what the auto-tuner chose, mode Auto only, for
    a tunable that opts in), ``environment`` or ``default``. ``stored`` is the saved mapping and ``auto`` the tuned one; by default the cached
    copies the processes use."""
    tunable = BY_KEY[key]
    values = stored_values() if stored is None else stored
    saved = values.get(key)
    if _valid_saved(tunable, saved):
        return {'value': saved, 'source': 'admin'}
    if tunable.auto_tunable:
        tuned = (resources.auto_values() if auto is None else auto).get(key)
        if _valid_saved(tunable, tuned):
            return {'value': tuned, 'source': 'auto'}
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
        got = resolve(key, {}, {})
    return default if default is not None and got['source'] == 'default' else got['value']


# --- the published copy -----------------------------------------------------------------------------------------------

_cache = {'at': None, 'values': {}}
_lock = threading.Lock()


def invalidate():
    """Forget this process's cached copy (a save does this at once; other processes catch up within CACHE_SECONDS)."""
    with _lock:
        _cache.update(at=None)


def _copy_values(raw):
    """The ``values`` of a published copy, or None when there is no usable copy (missing, not JSON, not an object)."""
    try:
        values = json.loads(raw).get('values') if raw else None
    except (ValueError, AttributeError):
        return None
    return values if isinstance(values, dict) else None


def stored_values(now_fn=time.monotonic):
    """What an App Admin saved, as the processes see it: the Redis copy, cached CACHE_SECONDS.

    Three different situations, because they must not be confused (a number that limits paid AI calls must not silently go back to the default):
    * the copy is there: use it;
    * Redis answers but there is no usable copy (it was restarted without persistence, flushed, recreated): the database is the truth, so read it
      (one small row, at most once per cache window per process), use it and publish it again;
    * Redis cannot be reached: keep the last copy this process saw. With none yet, nothing is saved as far as this process knows and the
      environment or the default applies, as before this page."""
    now = now_fn()
    with _lock:
        if _cache['at'] is not None and now - _cache['at'] < CACHE_SECONDS:
            return _cache['values']
    values = None
    try:
        client = resources.redis_client()
        values = _copy_values(client.get(VALUES_KEY)) if client is not None else None
    except Exception:  # noqa: BLE001 - Redis is unreachable: not the same as "nothing saved"
        logger.debug('saved tunables could not be read', exc_info=False)
        with _lock:
            _cache['at'] = now  # no retry on every call during an outage
            return _cache['values']
    if values is None:
        values = _recover(publish_again=client is not None)
        if values is None:  # the database could not be read either: keep what this process had
            with _lock:
                _cache['at'] = now
                return _cache['values']
    with _lock:
        _cache.update(at=now, values=values)
    return values


def _recover(publish_again=True):
    """The saved values from the database, published again. None when the database cannot be read."""
    try:
        values, version = _database()
    except Exception:  # noqa: BLE001
        logger.debug('saved tunables could not be read from the database', exc_info=False)
        return None
    if publish_again:
        publish(values, version)
    return values


def _database():
    """({known key: number}, version) straight from the database, without creating the row. The version is the row's last save as a number."""
    from cveFeed.models import TunableSettings
    row = TunableSettings.objects.order_by('pk').first()
    if row is None:
        return {}, 0.0
    return ({k: v for k, v in (row.values or {}).items() if k in BY_KEY and isinstance(v, int) and not isinstance(v, bool)},
            row.updated_at.timestamp() if row.updated_at else 0.0)


def publish(values, version=None):
    """Put the saved values where the processes read them. Returns whether Redis took them (the 30 second tick tries again if not).

    ``version`` is the database row's last save. The copy carries it, and a publish never replaces a copy with a newer version: the tick that read
    the row just before a save cannot overwrite the save's own publish. (Without a version the copy is written as is.)"""
    try:
        client = resources.redis_client()
        if client is None:
            return False
        payload = json.dumps({'values': values, 't': time.time(), 'v': version})
        if version is None:
            client.set(VALUES_KEY, payload)
            return True
        import redis
        for _ in range(3):
            with client.pipeline() as pipe:
                try:
                    pipe.watch(VALUES_KEY)
                    current = _copy_version(pipe.get(VALUES_KEY))
                    if current is not None and current > version:
                        return True  # a newer save already published itself
                    pipe.multi()
                    pipe.set(VALUES_KEY, payload)
                    pipe.execute()
                    return True
                except redis.WatchError:
                    continue
        return False
    except Exception:  # noqa: BLE001
        logger.warning('tunables: could not publish the saved values to Redis; processes pick them up on the next 30 second check')
        return False
    finally:
        invalidate()


def _copy_version(raw):
    try:
        version = json.loads(raw).get('v') if raw else None
    except (ValueError, AttributeError):
        return None
    return version if isinstance(version, (int, float)) and not isinstance(version, bool) else None


def saved_row():
    from cveFeed.models import TunableSettings
    return TunableSettings.current()


def saved_values():
    """The saved values straight from the database (the truth), keeping only what names a known tunable."""
    return _database()[0]


def reconcile():
    """The 30 second tick (``report_resources``): republish the saved values, so a flushed Redis heals. Never raises."""
    try:
        values, version = _database()
        return publish(values, version)
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
        publish(stored, row.updated_at.timestamp())
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

def usage_today():
    """{key: number used so far} for the caps that have a counter already: triage questions asked since UTC midnight, validation checks reserved
    today, template drafts in the last 24 hours. A counter that cannot be read is left out, never guessed."""
    from cveFeed import triage, validation
    out = {}
    from cveFeed import autotune
    for key, read in (('triage_max_per_day', triage.asked_today), ('validate_max_per_day', validation.ran_today), ('template_gen_max_per_day', _drafts_last_day),
                      ('autotune_ai_max_per_day', autotune.advisor_calls_today)):
        try:
            out[key] = int(read())
        except Exception:  # noqa: BLE001
            logger.debug('tunables: could not count today\'s use for %s', key, exc_info=False)
    return out


def _drafts_last_day():
    import datetime

    from django.utils import timezone

    from cveFeed.models import GeneratedTemplate
    return GeneratedTemplate.objects.filter(created_at__gte=timezone.now() - datetime.timedelta(days=1)).count()


def snapshot():
    """Everything the cards show, from the database (the truth) and the environment. The same shape as the Scan concurrency card's fields, so
    the page draws them with the same code."""
    row = saved_row()
    stored = {k: v for k, v in (row.values or {}).items() if k in BY_KEY}
    usage = usage_today()
    try:
        from cveFeed import autotune
        tuned = autotune.applied_values()
    except Exception:  # noqa: BLE001
        tuned = {}
    fields = []
    for t in TUNABLES:
        got = resolve(t.key, stored, tuned)
        meta = (row.meta or {}).get(t.key) or {}
        admin = got['source'] == 'admin'
        fields.append({'key': t.key, 'label': t.label, 'help': t.help, 'group': t.group, 'default': t.default, 'min': t.low, 'max': t.high,
                       'unit': t.unit, 'value': got['value'], 'source': got['source'], 'env_name': t.env, 'env_value': env_value(t),
                       'saved': stored.get(t.key) if admin else None, 'set_by': meta.get('by') if admin else None,
                       'set_at': meta.get('at') if admin else None, 'applies': t.applies, 'applies_text': t.note or APPLIES_TEXT[t.applies],
                       'caution': t.caution, 'window_text': WINDOW_TEXT.get(t.window), 'used_today': usage.get(t.key),
                       'used_since': USED_SINCE.get(t.window)})
    try:
        from cveFeed import autotune
        state = autotune.annotate(fields)
    except Exception:  # noqa: BLE001 - the cards must draw even when the auto-tuning state cannot be read
        logger.warning('tunables: the auto-tuning state could not be read', exc_info=True)
        state = None
    return {'fields': fields, 'groups': [{'id': g.id, 'title': g.title, 'intro': g.intro} for g in GROUPS], 'cache_seconds': CACHE_SECONDS,
            'autotune': state}
