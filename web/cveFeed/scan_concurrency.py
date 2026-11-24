"""Scan concurrency: how much scanning one instance does at once, chosen on Settings, configMaxxing.

Each number has a built-in default and an environment variable that existed before this page. Scanner runs are not here: every scan
runs on a Sentinel, whose own slots set how much it runs at once (the per-tool ``heavy.<kind>`` limits went with the last local scanner):

* ``discovery_concurrency`` how many discovery tasks and host assessments run at once (``DISCOVERY_CONCURRENCY``; the discovery worker's
                            autoscale ceiling)
* ``assess_batch``          how many hosts one assessment run carries (``CVENGINE_ASSESS_BATCH``)
* ``work_depth``            how many discovery scans the work conductor keeps running or queued (``CVENGINE_WORK_DEPTH``)

Precedence, one rule for every key: the value an App Admin saved here (it pins the key), else the number the auto-tuner chose (mode Auto, for a
field with ``auto_tunable=True``; ``cveFeed.autotune``), else the environment variable, else the built-in default.
The saved value is a row in the database (``ScanConcurrency``, the truth, and what ``celery-entrypoint.sh`` reads at start). Workers read a
copy that is published to Redis on every save and again every 30 seconds, and cache it in memory for ``CACHE_SECONDS``, so admission never
waits on the database and a save takes effect within seconds, with no restart. If Redis cannot be read, the last copy a process saw is kept
(none yet means the environment or the default, exactly as before this page existed).

The discovery pool is the one number a running process cannot simply re-read: it is the ceiling of a celery gevent worker's autoscaler. It is
resized live with celery's ``autoscale`` remote control (``apply_discovery``) and the result is recorded from the worker's own reply; a worker
that does not answer keeps the number it has, and the page says so. The entrypoint reads the saved value at start, so a restart also lands on it.
"""
import json
import logging
import os
import re
import time
from collections import namedtuple

from cvengine import resources

logger = logging.getLogger(__name__)

VALUES_KEY = resources.SAVED_VALUES_KEY       # the published copy of ScanConcurrency.values
LANES_KEY = 'cvengine:scanconc:lanes'  # what the worker lanes last said they run
RUNNING_KEY = 'cvengine:scanconc:running'  # what the discovery workers last said they run
CACHE_SECONDS = resources.SAVED_CACHE_SECONDS
RUNNING_STALE_SECONDS = 150                # the reconcile tick runs every 30 seconds
DISCOVERY_WORKER_PREFIX = 'discovery_worker@'
DISCOVERY_DEFAULT = 8
ASSESS_SHARE_DEFAULT = 75                  # percent of the discovery pool host assessments may hold while a scan waits (host_assessment.over_share)


def _lane_default(name, shipped):
    """What the worker lane is configured with: the number the environment names (the entrypoint reads the same variable), else the shipped one. Auto-tuning never goes above it."""
    try:
        return max(1, int(float(os.environ[name])))
    except (KeyError, ValueError):
        return shipped


CVE_FEED_LANE_DEFAULT = _lane_default('CVE_FEED_CONCURRENCY', 4)
CLASSIC_LANE_DEFAULT = _lane_default('CLASSIC_CONCURRENCY', 10)
# The lowest number auto-tuning may take a lane to (FC-1). The CVE-feed lane also runs the control tasks (auto-tuning itself, the 30 second reconcile that resizes the lanes,
# feed_sentinels, the work conductor, the reaper, the ops checks, the stage tick and the planner tick) beside long ones (CVE correlation, template updates, seed imports): with
# fewer than three slots one long task can keep every control task from running. The classic lane runs the short tasks people wait for (notifications, reports, the Live screen
# refresh, the planner's batches) beside up to eight one-at-a-time sweeps (WPScan, TLS audit, cloud storage, other sites, UDP, OpenVAS, suppliers, the screenshot drain), so
# its floor is six. A lane configured at or below its floor is not managed at all: there is no room to lower it.
LANE_FLOORS = {'lane.cve_feed': 3, 'lane.classic': 6}


def lane_range(key, configured):
    """``(auto_tunable, auto_min)`` of a worker lane configured at ``configured``: managed only when there is room above its floor, never lowered below it."""
    return configured > LANE_FLOORS[key], min(LANE_FLOORS[key], configured)
WORK_DEPTH_DEFAULT = 3

# auto_tunable must be stated for every field (True or False): the auto-tuner (cveFeed.autotune) only ever moves a field that opts in, inside
# auto_min..auto_max (tighter than low..high where that is safer), by auto_step at a time.
# auto_optimistic: the auto-tuner's target when the facts it sizes from (memory, cores, Sentinels) are not reported yet
# (cveFeed.autotune_policy.size_for).
Field = namedtuple('Field', 'key label help group env default low high env_floor auto_tunable auto_min auto_max auto_step auto_optimistic',
                   defaults=(None, None, None, 1, None))

FIELDS = [
    Field('discovery_concurrency', 'Hosts assessed at once',
          'How many discovery tasks and host assessments run at the same time. A task that waits on a Sentinel holds one of these while it waits. It is the ceiling of the discovery worker\'s autoscaler, which adds a slot a second while work is waiting, up to this number.',
          'discovery', 'DISCOVERY_CONCURRENCY', DISCOVERY_DEFAULT, 1, 32, 1, True, 4, 32, 2, 16),
    Field('assess_batch', 'Hosts per assessment batch',
          'How many hosts of one target are carried through one assessment run together, so a Sentinel is handed a batch instead of one host at a time. 1 runs every host on its own. Projects this server scans without a Sentinel always use 1.',
          'discovery', 'CVENGINE_ASSESS_BATCH', 8, 1, 64, 1, True, 4, 32, 4, 16),
    Field('work_depth', 'Discovery scans kept running',
          'How many discovery scans the work conductor keeps running or queued, starting the targets that have waited longest. 0 turns the conductor off: only people start scans.',
          'depth', 'CVENGINE_WORK_DEPTH', WORK_DEPTH_DEFAULT, 0, 32, 0, True, 1, 16, 1, 6),
    Field('assess_share_percent', 'Share of the discovery pool host assessments may hold',
          'While a discovery scan waits to start, host assessments may hold at most this share of the discovery pool, so queued scans cannot starve behind hundreds of assessments '
          '(an assessment that waits on a Sentinel holds its slot for as long as it waits). With no scan waiting, assessments may use the whole pool. 100 turns the limit off. '
          'Auto-tuning lowers it (never below 25) when scans wait for an hour behind assessments, and raises it back to 75 when they do not.',
          'discovery', 'CVENGINE_ASSESS_SHARE_PERCENT', ASSESS_SHARE_DEFAULT, 10, 100, 1, True, 25, 75, 10, 75),
    Field('lane.cve_feed', 'CVE-feed lane tasks at once',
          'How many tasks the CVE-feed worker lane (feeds, the planner of checks, the ops checks and auto-tuning itself) runs at once. A restart or an update starts it with this number. '
          'Auto-tuning lowers it (never below 3: the lane also runs the control tasks, which one long task must not stop) when the lane is killed for memory or runs at its memory limit, '
          'and raises it back, never above the number set here or in CVE_FEED_CONCURRENCY. A lane set to 3 or fewer is left alone.',
          'lanes', 'CVE_FEED_CONCURRENCY', CVE_FEED_LANE_DEFAULT, 1, max(CVE_FEED_LANE_DEFAULT, 32), 1, *lane_range('lane.cve_feed', CVE_FEED_LANE_DEFAULT), CVE_FEED_LANE_DEFAULT, 1, CVE_FEED_LANE_DEFAULT),
    Field('lane.classic', 'Classic lane tasks at once',
          'How many tasks the classic worker lane (notifications, reports, the Live screen refresh, the slow sweeps) runs at once. A restart or an update starts it with this number. '
          'Auto-tuning lowers it (never below 6: the short tasks people wait for run beside the long one-at-a-time sweeps) when the lane is killed for memory or runs at its memory limit, '
          'and raises it back, never above the number set here or in CLASSIC_CONCURRENCY. A lane set to 6 or fewer is left alone.',
          'lanes', 'CLASSIC_CONCURRENCY', CLASSIC_LANE_DEFAULT, 1, max(CLASSIC_LANE_DEFAULT, 32), 1, *lane_range('lane.classic', CLASSIC_LANE_DEFAULT), CLASSIC_LANE_DEFAULT, 1, CLASSIC_LANE_DEFAULT),
]
BY_KEY = {f.key: f for f in FIELDS}
assert all(f.auto_tunable in (True, False) for f in FIELDS), 'every scan concurrency field states auto_tunable'
assert all(not f.auto_tunable or f.low <= f.auto_min <= f.auto_optimistic <= f.auto_max <= f.high for f in FIELDS), \
    'an auto-tuning range (or its optimistic value) is outside the allowed range'
GROUP_TITLES = {'discovery': 'Discovery and assessment', 'depth': 'The work conductor', 'lanes': 'Worker lanes'}


# --- resolving a value ------------------------------------------------------------------------------------------------

def env_value(field, environ=None):
    """The value the environment gives, or None. A non-number, or a number under the floor (0 means "not set" for the scanner caps, as it
    always did), is ignored. The environment is not range-checked: it never was, and an operator who sets it knows."""
    raw = (environ if environ is not None else os.environ).get(field.env)
    if raw is None or not str(raw).strip():
        return None
    try:
        number = int(float(raw))
    except ValueError:
        return None
    if number < field.env_floor:
        return None if field.env_floor else 0  # a negative CVENGINE_WORK_DEPTH always meant 0
    return number


def env_pin(field, env=None):
    """Whether the environment pins this key: its variable is set AND differs from the built-in default. The compose files pass some variables
    to every container with the default as a fallback (``DISCOVERY_CONCURRENCY=${DISCOVERY_CONCURRENCY:-8}``), so a value equal to the
    default cannot be told from no value and is not a pin; any other value is the operator's own choice, which the auto-tuner never moves."""
    env = env_value(field) if env is None else env
    return env is not None and env != field.default


def resolve(key, stored=None, auto=None):
    """{'value', 'source'} for one key: ``admin`` (saved on the page: it pins the key), ``environment`` when the variable
    pins it (set and not the default, ``env_pin``), ``auto`` (what the auto-tuner chose, mode Auto only), ``environment`` or ``default``. ``stored`` is the saved mapping and ``auto`` the tuned one; by default the cached copies the workers use."""
    field = BY_KEY[key]
    values = stored_values() if stored is None else stored
    saved = values.get(key)
    if isinstance(saved, int) and not isinstance(saved, bool) and field.low <= saved <= field.high:
        return {'value': saved, 'source': 'admin'}
    env = env_value(field)
    if env_pin(field, env):
        return {'value': env, 'source': 'environment'}  # an operator's own number in .env pins the key: the tuner never moves it
    if field.auto_tunable:
        tuned = (resources.auto_values() if auto is None else auto).get(key)
        if isinstance(tuned, int) and not isinstance(tuned, bool) and field.low <= tuned <= field.high:
            return {'value': tuned, 'source': 'auto'}
    if env is not None:
        return {'value': env, 'source': 'environment'}
    return {'value': field.default, 'source': 'default'}


def effective(key, stored=None, auto=None):
    return resolve(key, stored, auto)['value']


# --- the published copy -----------------------------------------------------------------------------------------------

def _redis():
    return resources.redis_client()


def invalidate():
    """Forget this process's cached copy (a save does this at once; other processes catch up within CACHE_SECONDS)."""
    resources.invalidate_saved()


def stored_values(now_fn=time.monotonic):
    """What an App Admin saved, as the workers see it: the Redis copy, cached CACHE_SECONDS, shared with cvengine.resources (which reads it for
    the scanner caps). On a Redis outage the last copy this process saw is kept; with none, there are no saved values and the environment or
    the default applies, as it did before this page."""
    return resources.saved_values(now_fn)


def publish(values):
    """Put the saved values where the workers read them. Returns whether Redis took them (the reconcile tick tries again if not)."""
    try:
        client = _redis()
        if client is None:
            return False
        client.set(VALUES_KEY, json.dumps({'values': values, 't': time.time()}))
        return True
    except Exception:
        logger.warning('scan concurrency: could not publish the saved values to Redis; workers pick them up on the next 30 second check')
        return False
    finally:
        invalidate()


def saved_row():
    from cveFeed.models import ScanConcurrency
    return ScanConcurrency.current()


def recover(publish_again=True):
    """The saved values from the database without creating the row, published again when Redis is there: what a process does when Redis answers
    but has lost the published copy (``cvengine.resources.saved_values``). Raises when the database cannot be read."""
    from cveFeed.models import ScanConcurrency
    row = ScanConcurrency.objects.order_by('pk').first()
    values = {k: v for k, v in ((row.values if row else None) or {}).items() if k in BY_KEY and isinstance(v, int) and not isinstance(v, bool)}
    if publish_again:
        publish(values)
    return values


def saved_values():
    """The saved values straight from the database (the truth), keeping only what is still valid."""
    row = saved_row()
    return {k: v for k, v in (row.values or {}).items() if k in BY_KEY and isinstance(v, int) and not isinstance(v, bool)}


# --- validation and saving --------------------------------------------------------------------------------------------

def clean(key, raw):
    """A whole number inside the field's range, or None (reset to default). Raises ValueError with a sentence for the page."""
    field = BY_KEY.get(key)
    if field is None:
        raise ValueError(f'unknown setting {key}')
    if raw is None:
        return None
    if isinstance(raw, str) and re.fullmatch(r'\s*\d+\s*', raw):
        raw = int(raw)
    if isinstance(raw, float) and raw.is_integer():
        raw = int(raw)
    if isinstance(raw, bool) or not isinstance(raw, int) or not field.low <= raw <= field.high:
        raise ValueError(f'{field.label} must be a whole number from {field.low} to {field.high}')
    return raw


def update(values, user):
    """Save a partial change: ``{key: whole number}`` sets, ``{key: None}`` resets that field to its default. Everything is validated first;
    nothing is saved if one value is wrong. Each change is audited. Returns the keys changed."""
    from django.db import transaction
    from django.utils import timezone

    from cveFeed.admin_api import audit
    from cveFeed.models import ScanConcurrency
    if not isinstance(values, dict):
        raise ValueError('values must be an object of setting: number')
    cleaned = {key: clean(key, raw) for key, raw in values.items()}
    changed = []
    with transaction.atomic():
        row = ScanConcurrency.objects.select_for_update().get(pk=ScanConcurrency.current().pk)
        stored, meta = dict(row.values or {}), dict(row.meta or {})
        for key, new in cleaned.items():
            before = resolve(key, stored)
            if new is None:
                if key in stored:
                    stored.pop(key)
                    meta.pop(key, None)
                    changed.append(key)
                    audit(user, 'scan_concurrency.reset', key, before=before['value'], before_source=before['source'], after=resolve(key, stored)['value'])
            elif stored.get(key) != new:
                stored[key] = new
                meta[key] = {'by': user.username, 'at': timezone.now().isoformat()}
                changed.append(key)
                audit(user, 'scan_concurrency.set', key, before=before['value'], before_source=before['source'], after=new)
        if changed:
            row.values, row.meta, row.updated_by = stored, meta, (user if getattr(user, 'pk', None) else None)  # None: a system actor (the watchdog) has no account
            row.save()
    if changed:
        after_saved(changed, stored)
    return changed


def reset_all(user):
    """Every field back to its default (the configMaxxing "reset all" action). Audited as one entry. Returns the keys that were set."""
    from cveFeed.admin_api import audit
    row = saved_row()
    cleared = sorted(row.values or {})
    row.values, row.meta, row.updated_by = {}, {}, user
    row.save()
    audit(user, 'config_maxxing.scan_concurrency_reset_all', 'scan_concurrency', cleared=cleared)
    after_saved(cleared, {})
    return cleared


def after_saved(changed, stored):
    """Make a save take effect without a restart: publish it and ask the discovery worker (and the lanes) to resize."""
    publish(stored)
    if 'discovery_concurrency' in changed or any(k in LANE_KEYS for k in changed):
        request_apply()


def request_apply():
    """Queue the live resize of the discovery worker. A broker that is down only delays it: the 30 second tick does it too."""
    try:
        from cvengine.celery import app
        app.send_task('apply_scan_concurrency', queue='cve_feed_queue')
    except Exception:
        logger.warning('scan concurrency: could not queue the discovery worker resize; the 30 second check will do it')


def bootstrap_value(key):
    """The value a starting container should use, read from the database (the entrypoint's way in). Falls back to the environment, then
    the default, if the saved value cannot be read."""
    try:
        from cveFeed import autotune
        return effective(key, saved_values(), autotune.applied_values())
    except Exception:
        return effective(key, {}, {})


# --- the discovery worker ---------------------------------------------------------------------------------------------

def discovery_workers(app=None, timeout=1.5):
    """{worker name: its autoscale ceiling} for every discovery worker that answers a ``stats`` broadcast."""
    if app is None:
        from cvengine.celery import app
    stats = app.control.inspect(timeout=timeout).stats() or {}
    out = {}
    for name, info in stats.items():
        if str(name).startswith(DISCOVERY_WORKER_PREFIX) or 'discovery_worker' in str(name).split('@'):  # celery names a worker `-n discovery_worker` celery@discovery_worker
            ceiling = ((info or {}).get('autoscaler') or {}).get('max')
            out[name] = ceiling if isinstance(ceiling, int) else None
    return out


def apply_discovery(app=None, now_fn=time.time, saved=None):
    """Resize every discovery worker whose autoscale ceiling differs from the wanted value, with celery's ``autoscale`` remote control, and
    record what each worker says it runs. A value is recorded only when the worker confirmed it (its reply, or a later ``stats`` showing
    it): a worker that does not answer keeps the number it has. Returns {'want', 'workers': {name: ceiling or None}, 'changed': [names]}."""
    if app is None:
        from cvengine.celery import app
    if saved is None:
        want = effective('discovery_concurrency', saved_values(), _tuned_from_database())
    else:
        want = effective('discovery_concurrency', saved, _tuned_from_database())
    workers = discovery_workers(app)
    changed = []
    for name, ceiling in list(workers.items()):
        if ceiling == want:
            continue
        try:
            replies = app.control.broadcast('autoscale', arguments={'max': want}, destination=[name], reply=True, timeout=3) or []
        except Exception:
            logger.warning('scan concurrency: could not resize %s', name)
            continue
        for reply in replies:
            answer = (reply or {}).get(name)
            text = str(((answer or {}).get('ok')) or '') if isinstance(answer, dict) else ''
            match = re.search(r'max=(\d+)', text)
            if match:
                workers[name] = int(match.group(1))
                changed.append(name)
    record = {'want': want, 'workers': workers, 'changed': changed, 't': now_fn()}
    try:
        client = _redis()
        if client is not None:
            client.set(RUNNING_KEY, json.dumps(record), ex=24 * 3600)
    except Exception:
        logger.debug('scan concurrency: could not record the discovery workers', exc_info=False)
    return record


LANE_WORKERS = {'lane.cve_feed': 'cve_feed_worker', 'lane.classic': 'classic_worker'}  # the Celery node of each lane that auto-tuning may resize (``celery -n``)
LANE_KEYS = tuple(LANE_WORKERS)


def lane_ceilings(key, app=None, timeout=1.5, stats=None):
    """{worker name: its autoscale ceiling} for the worker of the lane ``key`` names (``lane.cve_feed``, ``lane.classic``). ``stats``: the answer of one ``inspect().stats()``
    broadcast, when the caller asks for several lanes (one broadcast waits its whole timeout)."""
    if app is None:
        from cvengine.celery import app
    if stats is None:
        stats = app.control.inspect(timeout=timeout).stats() or {}
    out = {}
    for name, info in stats.items():
        if LANE_WORKERS[key] in str(name).split('@'):  # celery names `-n cve_feed_worker` cve_feed_worker@<host>; `celery@cve_feed_worker` also reads right
            ceiling = ((info or {}).get('autoscaler') or {}).get('max')
            out[name] = ceiling if isinstance(ceiling, int) else None
    return out


def apply_lanes(app=None, saved=None):
    """Resize every worker lane whose autoscale ceiling differs from the number wanted (saved by a person, else tuned, else the configured one), with celery's
    ``autoscale`` remote control, as ``apply_discovery`` does for the discovery pool. A lane that does not answer keeps the number it has (the 30 second tick
    tries again). The entrypoint reads the same resolved number at start, so a restart keeps it. Returns {key: {'want', 'workers', 'changed'}}."""
    if app is None:
        from cvengine.celery import app
    out = {}
    stored = saved_values() if saved is None else saved
    tuned = _tuned_from_database()
    stats = app.control.inspect(timeout=1.5).stats() or {}  # one broadcast for both lanes
    for key in LANE_KEYS:
        want = effective(key, stored, tuned)
        workers, changed = lane_ceilings(key, app, stats=stats), []
        for name, ceiling in list(workers.items()):
            if ceiling == want:
                continue
            try:
                replies = app.control.broadcast('autoscale', arguments={'max': want}, destination=[name], reply=True, timeout=3) or []
            except Exception:  # noqa: BLE001
                logger.warning('scan concurrency: could not resize %s', name)
                continue
            for reply in replies:
                answer = (reply or {}).get(name)
                text = str(((answer or {}).get('ok')) or '') if isinstance(answer, dict) else ''
                match = re.search(r'max=(\d+)', text)
                if match:
                    workers[name] = int(match.group(1))
                    changed.append(name)
        out[key] = {'want': want, 'workers': workers, 'changed': changed}
    try:
        client = _redis()
        if client is not None:
            client.set(LANES_KEY, json.dumps({'t': time.time(), 'lanes': out}), ex=24 * 3600)
    except Exception:  # noqa: BLE001
        logger.debug('scan concurrency: could not record the lanes', exc_info=False)
    return out


def running_lane(key, now_fn=time.time):
    """What the lane last confirmed (FC-4e): ``{'ceilings': [numbers the lane's workers report], 'age_seconds'}``, or None when no resize round has recorded it, the lane did
    not answer (no worker listed) or the record is old. ``verify_pending`` leaves a lane decision "unknown" when the lane still reports another number."""
    try:
        client = _redis()
        record = json.loads(client.get(LANES_KEY) or 'null') if client is not None else None
        lane = ((record or {}).get('lanes') or {}).get(key) or {}
        ceilings = [c for c in (lane.get('workers') or {}).values() if isinstance(c, int)]
        age = int(now_fn() - record['t']) if record else None
    except Exception:  # noqa: BLE001
        return None
    return {'ceilings': ceilings, 'age_seconds': age} if ceilings and age is not None and age <= 3600 else None


def _tuned_from_database():
    """The auto-tuned numbers that apply now, from the database (the truth), or the cached copy when it cannot be read."""
    try:
        from cveFeed import autotune
        return autotune.applied_values()
    except Exception:
        return resources.auto_values()


def reconcile():
    """The 30 second tick (``report_resources``): republish the saved values (a flushed Redis heals), and resize the discovery worker if it
    differs. Never raises."""
    try:
        saved = saved_values()
        publish(saved)
    except Exception:
        logger.debug('scan concurrency: reconcile could not read the saved values', exc_info=False)
        return None
    try:
        result = apply_discovery(saved=saved)
    except Exception:
        logger.debug('scan concurrency: the discovery workers could not be reached', exc_info=False)
        return None
    try:
        apply_lanes(saved=saved)
    except Exception:
        logger.debug('scan concurrency: the worker lanes could not be reached', exc_info=False)
    return result


def running_discovery(now_fn=time.time):
    """What the discovery workers last reported: {'value': int or None, 'workers': {...}, 'age_seconds'}; value is None when none reported
    or they disagree."""
    try:
        client = _redis()
        record = json.loads(client.get(RUNNING_KEY) or 'null') if client is not None else None
    except Exception:
        record = None
    if not record or not record.get('workers'):
        return {'value': None, 'workers': {}, 'age_seconds': None}
    ceilings = list(record['workers'].values())
    agreed = ceilings[0] if None not in ceilings and len(set(ceilings)) == 1 else None
    return {'value': agreed, 'workers': record['workers'], 'age_seconds': int(now_fn() - record.get('t', 0))}


# --- what the page shows -------------------------------------------------------------------------------------------------

def snapshot():
    """Everything the Scan concurrency card shows, from the database (the truth), the environment and the workers' own reports."""
    row = saved_row()
    stored = {k: v for k, v in (row.values or {}).items() if k in BY_KEY}
    tuned = _tuned_from_database()
    running = running_discovery()
    fields = []
    for f in FIELDS:
        got = resolve(f.key, stored, tuned)
        meta = (row.meta or {}).get(f.key) or {}
        item = {'key': f.key, 'label': f.label, 'help': f.help, 'group': f.group, 'default': f.default, 'min': f.low, 'max': f.high,
                'value': got['value'], 'source': got['source'], 'env_name': f.env, 'env_value': env_value(f),
                'saved': stored.get(f.key) if got['source'] == 'admin' else None,
                'set_by': meta.get('by') if got['source'] == 'admin' else None, 'set_at': meta.get('at') if got['source'] == 'admin' else None}
        if f.key == 'discovery_concurrency':
            item.update(applies='pool', running=running['value'], running_workers=running['workers'], running_age_seconds=running['age_seconds'])
        else:
            item['applies'] = 'live'
        fields.append(item)
    return {'fields': fields, 'groups': [{'id': g, 'title': t} for g, t in GROUP_TITLES.items()],
            'discovery': discovery_status(effective('discovery_concurrency', stored, tuned), running),
            'cache_seconds': CACHE_SECONDS, 'autotune': _annotate(fields)}


def _annotate(fields):
    """Add each field's auto-tuning state (pinned, tuned, a recommendation) for the page; the mode summary is returned. Never fails the card."""
    try:
        from cveFeed import autotune
        return autotune.annotate(fields)
    except Exception:
        logger.warning('scan concurrency: the auto-tuning state could not be read', exc_info=True)
        return None


def discovery_status(saved, running):
    """An honest sentence about the discovery worker: applied, being applied, or unknown. Never says a number is running that no worker said."""
    if running['value'] is None and not running['workers']:
        return {'state': 'unknown', 'message': 'No discovery worker has reported its size yet. The saved value is applied to a running worker within a minute '
                'of it answering, and read from the database whenever the container starts or the instance updates.'}
    if running['age_seconds'] is not None and running['age_seconds'] > RUNNING_STALE_SECONDS:
        return {'state': 'unknown', 'message': f'The discovery worker last reported {running["age_seconds"]} seconds ago, so what it runs now is not known. '
                'The saved value is read from the database whenever the container starts or the instance updates.'}
    if running['value'] == saved:
        return {'state': 'applied', 'message': f'The discovery worker\'s ceiling is {saved}.'}
    return {'state': 'pending', 'message': f'The saved value is {saved}, but the worker\'s ceiling was last reported as {running["value"] if running["value"] is not None else "different sizes"}. '
            'It is resized within a minute; if it does not change, it takes effect after the next restart or update.'}
