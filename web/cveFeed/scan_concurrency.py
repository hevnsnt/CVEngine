"""Scan concurrency: how much scanning one instance does at once, chosen on Settings, configMaxxing.

Three groups of numbers, each with a built-in default and an environment variable that existed before this page:

* ``heavy.<kind>``          how many scanner runs of one kind (nmap, nuclei, bbot ...) may run at once in the celery container
                            (``HEAVY_MAX_<KIND>``; the memory gate in ``reNgine.resources`` still holds work back when memory is short)
* ``discovery_concurrency`` how many discovery tasks and host assessments run at once (``DISCOVERY_CONCURRENCY``; the discovery worker's
                            autoscale ceiling)
* ``assess_batch``          how many hosts one assessment run carries (``CVENGINE_ASSESS_BATCH``)
* ``work_depth``            how many discovery scans the work conductor keeps running or queued (``CVENGINE_WORK_DEPTH``)

Precedence, one rule for every key: the value an App Admin saved here, else the environment variable, else the built-in default.
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

from reNgine import resources

logger = logging.getLogger(__name__)

VALUES_KEY = resources.SAVED_VALUES_KEY       # the published copy of ScanConcurrency.values
RUNNING_KEY = 'cvengine:scanconc:running'  # what the discovery workers last said they run
CACHE_SECONDS = resources.SAVED_CACHE_SECONDS
RUNNING_STALE_SECONDS = 150                # the reconcile tick runs every 30 seconds
DISCOVERY_WORKER_PREFIX = 'discovery_worker@'
DISCOVERY_DEFAULT = 8
WORK_DEPTH_DEFAULT = 3

Field = namedtuple('Field', 'key label help group env default low high env_floor')

# One line per local scanner kind: what it is, in words that mean something to a person who has never read the code.
HEAVY_HELP = {
    'bbot-deep': ('Deep discovery (bbot)', 'The kitchen-sink discovery run: dozens of modules and a spider. The most memory hungry kind.'),
    'bbot-standard': ('Standard discovery (bbot)', 'Subdomain enumeration plus the quick web checks, safe modules only.'),
    'bbot-passive': ('Passive discovery (bbot)', 'Looks names up in public sources and never touches the target.'),
    'nuclei': ('Vulnerability templates (nuclei)', 'The main template scan. It loads thousands of templates.'),
    'nuclei-light': ('Vulnerability templates, light (nuclei)', 'The smaller template pass over fewer hosts at a time.'),
    'nmap': ('Port and service scan (nmap)', 'The standard top-1000 port scan with version detection.'),
    'nmap-full-bg': ('Full port sweep (nmap, background)', 'The slow all-65535-ports sweep of one address. It waits behind everything else on purpose.'),
    'nmap-udp-bg': ('UDP sweep (nmap, background)', 'The slow UDP sweep of one address.'),
    'naabu': ('Fast port discovery (naabu)', 'SYN port discovery over every TCP port.'),
    'template-test': ('Generated template tests', 'One AI-generated template against one host.'),
    'route-probe': ('Route probes', 'Safe GET requests to find routes and logins. Light on memory.'),
    'wpscan': ('WordPress scan (WPScan)', 'A thorough WordPress pass that can run for hours per site.'),
    'testssl': ('TLS audit (testssl.sh)', 'One audit of one TLS port.'),
}
# Ceilings an App Admin may choose. Eight for the CPU bound kinds; lower for the sweeps that hit one address with a very wide probe or that
# load the most memory; sixteen for the one kind that is only a few polite requests.
HEAVY_HIGH = {'bbot-deep': 4, 'nmap-full-bg': 4, 'nmap-udp-bg': 4, 'naabu': 4, 'route-probe': 16}
HEAVY_HIGH_DEFAULT = 8


def _heavy_fields():
    out = []
    for kind, default in resources.MAX_CONCURRENT.items():
        label, help_text = HEAVY_HELP.get(kind, (kind, ''))
        out.append(Field(f'heavy.{kind}', label, help_text, 'heavy', 'HEAVY_MAX_' + kind.upper().replace('-', '_'), default, 1,
                         max(HEAVY_HIGH.get(kind, HEAVY_HIGH_DEFAULT), default), 1))
    return out


FIELDS = _heavy_fields() + [
    Field('discovery_concurrency', 'Hosts assessed at once',
          'How many discovery tasks and host assessments run at the same time. A task that waits on a Sentinel holds one of these while it waits. It is the ceiling of the discovery worker\'s autoscaler: a few more can briefly run above it.',
          'discovery', 'DISCOVERY_CONCURRENCY', DISCOVERY_DEFAULT, 1, 32, 1),
    Field('assess_batch', 'Hosts per assessment batch',
          'How many hosts of one target are carried through one assessment run together, so a Sentinel is handed a batch instead of one host at a time. 1 runs every host on its own. Projects this server scans without a Sentinel always use 1.',
          'discovery', 'CVENGINE_ASSESS_BATCH', 8, 1, 64, 1),
    Field('work_depth', 'Discovery scans kept running',
          'How many discovery scans the work conductor keeps running or queued, starting the targets that have waited longest. 0 turns the conductor off: only people start scans.',
          'depth', 'CVENGINE_WORK_DEPTH', WORK_DEPTH_DEFAULT, 0, 32, 0),
]
BY_KEY = {f.key: f for f in FIELDS}
GROUP_TITLES = {'heavy': 'Scanners at once', 'discovery': 'Discovery and assessment', 'depth': 'The work conductor'}


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


def resolve(key, stored=None):
    """{'value', 'source'} for one key: ``admin`` (saved on the page), ``environment`` or ``default``. ``stored`` is the saved mapping; by
    default the cached copy the workers use."""
    field = BY_KEY[key]
    values = stored_values() if stored is None else stored
    saved = values.get(key)
    if isinstance(saved, int) and not isinstance(saved, bool) and field.low <= saved <= field.high:
        return {'value': saved, 'source': 'admin'}
    env = env_value(field)
    if env is not None:
        return {'value': env, 'source': 'environment'}
    return {'value': field.default, 'source': 'default'}


def effective(key, stored=None):
    return resolve(key, stored)['value']


def admin_value(key):
    """The value saved on the page for a key, or None."""
    got = resolve(key)
    return got['value'] if got['source'] == 'admin' else None


# --- the published copy -----------------------------------------------------------------------------------------------

def _redis():
    return resources.redis_client()


def invalidate():
    """Forget this process's cached copy (a save does this at once; other processes catch up within CACHE_SECONDS)."""
    resources.invalidate_saved()


def stored_values(now_fn=time.monotonic):
    """What an App Admin saved, as the workers see it: the Redis copy, cached CACHE_SECONDS, shared with reNgine.resources (which reads it for
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
    but has lost the published copy (``reNgine.resources.saved_values``). Raises when the database cannot be read."""
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
            row.values, row.meta, row.updated_by = stored, meta, user
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
    """Make a save take effect without a restart: publish it, drop the AI tuner's remembered step for a scanner whose limit the admin
    just set (the saved number is what they asked for, and the tuner moves from it, inside the bounds it sets), and ask the discovery
    worker to resize."""
    publish(stored)
    kinds = [k.split('.', 1)[1] for k in changed if k.startswith('heavy.')]
    if kinds:
        try:
            client = _redis()
            if client is not None:
                client.delete(*[f'cvengine:adaptive:max:{kind}' for kind in kinds])
        except Exception:
            logger.warning('scan concurrency: could not clear the AI tuner step for %s', ', '.join(kinds))
    if 'discovery_concurrency' in changed:
        request_apply()


def request_apply():
    """Queue the live resize of the discovery worker. A broker that is down only delays it: the 30 second tick does it too."""
    try:
        from reNgine.celery import app
        app.send_task('apply_scan_concurrency', queue='cve_feed_queue')
    except Exception:
        logger.warning('scan concurrency: could not queue the discovery worker resize; the 30 second check will do it')


def bootstrap_value(key):
    """The value a starting container should use, read from the database (the entrypoint's way in). Falls back to the environment, then
    the default, if the saved value cannot be read."""
    try:
        return effective(key, saved_values())
    except Exception:
        return effective(key, {})


# --- the discovery worker ---------------------------------------------------------------------------------------------

def discovery_workers(app=None, timeout=1.5):
    """{worker name: its autoscale ceiling} for every discovery worker that answers a ``stats`` broadcast."""
    if app is None:
        from reNgine.celery import app
    stats = app.control.inspect(timeout=timeout).stats() or {}
    out = {}
    for name, info in stats.items():
        if str(name).startswith(DISCOVERY_WORKER_PREFIX):
            ceiling = ((info or {}).get('autoscaler') or {}).get('max')
            out[name] = ceiling if isinstance(ceiling, int) else None
    return out


def apply_discovery(app=None, now_fn=time.time, saved=None):
    """Resize every discovery worker whose autoscale ceiling differs from the wanted value, with celery's ``autoscale`` remote control, and
    record what each worker says it runs. A value is recorded only when the worker confirmed it (its reply, or a later ``stats`` showing
    it): a worker that does not answer keeps the number it has. Returns {'want', 'workers': {name: ceiling or None}, 'changed': [names]}."""
    if app is None:
        from reNgine.celery import app
    want = effective('discovery_concurrency', saved_values() if saved is None else saved)
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
        return apply_discovery(saved=saved)
    except Exception:
        logger.debug('scan concurrency: the discovery workers could not be reached', exc_info=False)
        return None


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


# --- memory --------------------------------------------------------------------------------------------------------------

OVERCOMMIT = 2  # the worst case may be this many times the budget before the page warns: the kinds rarely all peak together


def memory_plan(caps, costs_mb, budget_mb, defaults=None):
    """What the chosen scanner limits could ask of the container's memory budget. ``caps`` {kind: limit}, ``costs_mb`` {kind: MB reserved per
    run}. The total is the worst case (every kind at its limit at once), which the memory gate never lets happen: a run starts only when its
    estimate fits, so a high total means some runs wait for memory, not that the container runs out. Two warnings, both only for what the
    admin raised above the defaults (so the defaults themselves are never flagged): one kind alone could want more than the whole budget, or
    the worst case is more than ``OVERCOMMIT`` times the budget (the kinds rarely peak together, so a plain excess is not a warning).
    Returns {'total_mb', 'default_total_mb', 'budget_mb', 'warnings': [str]}."""
    defaults = defaults or {kind: resources.MAX_CONCURRENT.get(kind, 2) for kind in caps}
    total = sum(costs_mb.get(kind, 500) * cap for kind, cap in caps.items())
    default_total = sum(costs_mb.get(kind, 500) * defaults.get(kind, cap) for kind, cap in caps.items())
    warnings = []
    if budget_mb:
        for kind, cap in caps.items():
            one = costs_mb.get(kind, 500) * cap
            if cap > defaults.get(kind, cap) and one > budget_mb:
                warnings.append(f'{HEAVY_HELP.get(kind, (kind,))[0]} at {cap} could want {one} MB by itself, more than the {budget_mb} MB budget of the scanning container: '
                                'the extra runs will only wait for memory.')
        if total > budget_mb * OVERCOMMIT and total > default_total:
            warnings.append(f'With every scanner at its limit at the same time, up to {total} MB could be wanted, more than {OVERCOMMIT} times the {budget_mb} MB budget of the scanning container. '
                            'The memory gate will hold runs back, so raising these further will not scan faster until the container has more memory (CELERY_MEM_LIMIT) or you scan on a second machine.')
    return {'total_mb': total, 'default_total_mb': default_total, 'budget_mb': budget_mb, 'warnings': warnings}


def memory_context():
    """{'budget_mb', 'limit_mb', 'costs_mb'} of the scanning container, as the celery worker published it to Redis; budget and limit are
    None when no worker has reported."""
    costs = {kind: resources.cost_mb(kind) for kind in resources.BASE_COSTS_MB}
    out = {'budget_mb': None, 'limit_mb': None, 'costs_mb': costs}
    try:
        shared = resources.cluster_snapshot()
        # without Redis the snapshot can only describe this (web) container, whose memory says nothing about the scanners
        containers = (shared.get('containers') or []) if shared.get('store') == 'redis' else []
    except Exception:
        containers = []
    budgets = [c['budget_mb'] for c in containers if c.get('budget_mb')]
    limits = [(c.get('memory') or {}).get('limit_mb') or (c.get('memory') or {}).get('total_mb') for c in containers]
    if budgets:
        out['budget_mb'] = min(budgets)  # several scanning containers: the tightest one is the one that holds work back first
        out['limit_mb'] = min(x for x in limits if x) if any(limits) else None
    return out


# --- what the page shows -------------------------------------------------------------------------------------------------

def snapshot():
    """Everything the Scan concurrency card shows, from the database (the truth), the environment and the workers' own reports."""
    row = saved_row()
    stored = {k: v for k, v in (row.values or {}).items() if k in BY_KEY}
    running = running_discovery()
    fields = []
    for f in FIELDS:
        got = resolve(f.key, stored)
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
    caps = {f.key.split('.', 1)[1]: effective(f.key, stored) for f in FIELDS if f.group == 'heavy'}
    context = memory_context()
    plan = memory_plan(caps, context['costs_mb'], context['budget_mb'])
    return {'fields': fields, 'groups': [{'id': g, 'title': t} for g, t in GROUP_TITLES.items()],
            'memory': {'budget_mb': context['budget_mb'], 'limit_mb': context['limit_mb'], 'costs_mb': context['costs_mb'],
                       'total_mb': plan['total_mb'], 'default_total_mb': plan['default_total_mb'], 'warnings': plan['warnings']},
            'discovery': discovery_status(effective('discovery_concurrency', stored), running),
            'cache_seconds': CACHE_SECONDS}


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
