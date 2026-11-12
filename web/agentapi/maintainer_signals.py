"""The measurements the AI maintainer will judge (``system.signals`` of the system status, REST and MCP ``get_system_status``).

Nothing here decides or acts. Each signal is one small function that reads one source and returns a dict with a ``state``:

* ``known``: the source answered and the numbers are what it said;
* ``partial``: some parts are known and some are not (``reason`` says which);
* ``unknown``: the source is missing, malformed, stale or too slow, ``reason`` says why and the numbers are ``None``.

A signal is never reported as healthy when it is unknown: there is no ``ok`` here at all, an unreadable number is ``None`` and never 0, and
``collect`` lists the signals that are not known in ``unknown`` (the status adds a note for them). Every read is bounded: Redis reads are one pipeline
or one hash, database reads run under a 2 second statement timeout and are reused for a minute (the ones that are not a primary-key read), and a
failing source is reused for 15 seconds so that polling a broken box does not make it worse. Nothing returns an address, a credential, a query text
or a task argument.
"""
import logging
import time
from contextlib import contextmanager

from django.core.cache import cache
from django.db import connection, transaction
from django.utils import timezone

logger = logging.getLogger(__name__)

DB_STATEMENT_MS = 2000
CACHE_SECONDS = 60
FAILED_CACHE_SECONDS = 15
STALE_LANE_SECONDS = 3600  # a lane's memory record older than this was not written by a worker that is working
STALE_CONTAINER_SECONDS = 180  # the same limit as the status's memory section (system_status.MEMORY_REPORT_STALE_SECONDS)
EXPECTED_CONTAINERS = ('web', 'worker')
AI_CAP_KEYS = ('triage_max_per_day', 'validate_max_per_day', 'template_gen_max_per_day', 'autotune_ai_max_per_day', 'nuclei_ai_max_per_day')
MAX_REFUSAL_ROWS = 20


def unknown(reason):
    return {'state': 'unknown', 'reason': reason}


def _safe(fn):
    """Run one signal; a raise becomes ``unknown`` naming the exception type only (never its message, which may carry an address)."""
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - one unreadable source must not hide the others
        logger.debug('maintainer signals: %s', fn, exc_info=True)
        return unknown(f'could not be read ({type(exc).__name__})')


def _cached(key, fn):
    try:
        hit = cache.get('maintainer_signals:' + key)
        if isinstance(hit, dict):
            return hit
    except Exception:  # noqa: BLE001 - no cache means no reuse, nothing else
        pass
    value = _safe(fn)
    try:
        cache.set('maintainer_signals:' + key, value, CACHE_SECONDS if value.get('state') != 'unknown' else FAILED_CACHE_SECONDS)
    except Exception:  # noqa: BLE001
        pass
    return value


def _number(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) and value == value else None


def _percent(used, limit):
    used, limit = _number(used), _number(limit)
    return round(100 * used / limit, 1) if used is not None and limit and limit > 0 else None


def _redis():
    from reNgine import resources
    client = resources.redis_client()
    if client is None:
        raise RuntimeError('the broker is not Redis')
    return client


@contextmanager
def _bounded():
    """A transaction in which no statement may run longer than ``DB_STATEMENT_MS`` (``SET LOCAL`` ends with it). PostgreSQL only."""
    if connection.vendor != 'postgresql':
        raise RuntimeError('not PostgreSQL')
    with transaction.atomic():
        with connection.cursor() as cur:
            cur.execute('SET LOCAL statement_timeout = %s', [DB_STATEMENT_MS])
        yield


# --- worker lanes -------------------------------------------------------------------------------------------------------------------

def lanes(now=None):
    """Each Celery lane's resident memory against its container's limit, and the restarts seen on it in the last 24 hours. The record is the one the lane's
    own worker writes after each task (``reNgine.lane_memory``); a lane that has finished no task since the record expired is ``unknown``, not 0."""
    from reNgine import lane_memory
    now = time.time() if now is None else now
    rows = {r['lane']: r for r in lane_memory.report(now)}
    out = []
    for lane in lane_memory.LANES:
        row = rows.get(lane)
        rss = _number(row.get('rss_mb')) if row else None
        if rss is None:
            out.append({'lane': lane, 'state': 'unknown', 'reason': 'no readable memory record (no task has finished on this lane lately, or the record is damaged)',
                        'rss_mb': None, 'limit_mb': None, 'percent_of_limit': None, 'restarts_24h': None})
            continue
        limit = _number(row.get('limit_mb'))
        limit_state = 'unknown' if limit is None else 'unlimited' if limit == 0 else 'limited'
        entry = {'lane': lane, 'state': 'known', 'rss_mb': rss, 'peak_mb': _number(row.get('peak_mb')), 'limit_mb': limit if limit else None,
                 'limit_state': limit_state, 'percent_of_limit': _percent(rss, limit), 'age_seconds': row.get('age_seconds')}
        if (row.get('age_seconds') or 0) > STALE_LANE_SECONDS:
            entry.update(state='unknown', reason=f"last reported {row['age_seconds'] // 60} minutes ago")
        try:
            events = lane_memory.restarts(lane, now)
            entry['restarts_24h'] = len(events)
            entry['last_restart'] = ({'at': events[-1]['at'], 'last_rss_mb': _number(events[-1].get('last_rss_mb'))} if events else None)
        except Exception:  # noqa: BLE001
            entry['restarts_24h'] = None
            entry['last_restart'] = None
            entry['restarts_state'] = 'unknown'
        out.append(entry)
    known = [e for e in out if e['state'] == 'known']
    state = 'known' if len(known) == len(out) else 'partial' if known else 'unknown'
    result = {'state': state, 'lanes': out}
    if state != 'known':
        result['reason'] = 'lanes without a recent memory record: ' + ', '.join(e['lane'] for e in out if e['state'] != 'known')
    return result


# --- containers: web and worker memory, kernel oom kills ------------------------------------------------------------------------------

def containers(now=None, client=None):
    """The memory and the kernel's oom kills of the containers that publish them (``reNgine.container_signals``): the web container, from the watchdog tick,
    and the worker container, from its resource tick."""
    from reNgine import container_signals
    now = time.time() if now is None else now
    records = container_signals.read(client or _redis(), now)
    out = []
    for rec in records:
        mem = rec['memory'] or {}
        used, limit = _number(mem.get('used_mb')), _number(mem.get('limit_mb'))
        entry = {'role': rec['role'], 'host': rec['host'], 'state': 'known', 'used_mb': used, 'limit_mb': limit if limit else None,
                 'limit_state': 'unknown' if mem.get('limit_mb') is None and used is None else 'limited' if limit else 'unlimited',
                 'percent_of_limit': _percent(used, limit), 'peak_mb': _number(mem.get('peak_mb')), 'age_seconds': rec['age_seconds'],
                 'oom_kills_24h': rec['oom_kills_24h'] if isinstance(rec['oom_total'], int) else None, 'last_oom_at': rec['last_oom_at']}
        if used is None:
            entry.update(state='unknown', reason="this container's memory could not be read")
        elif rec['age_seconds'] > STALE_CONTAINER_SECONDS:
            entry.update(state='unknown', reason=f"has not published for {rec['age_seconds']} seconds")
        out.append(entry)
    missing = [role for role in EXPECTED_CONTAINERS if not any(e['role'] == role and e['state'] == 'known' for e in out)]
    if not out:
        return {'state': 'unknown', 'containers': [], 'reason': 'no container has published its memory'}
    result = {'state': 'partial' if missing else 'known', 'containers': out}
    if missing:
        result['reason'] = ('no current reading from: ' + ', '.join(missing)
                            + (' (the web container publishes from the watchdog tick, the worker container from its resource tick)'))
    return result


# --- queues -------------------------------------------------------------------------------------------------------------------------

def _oldest_db():
    """How long the oldest queued scan, host assessment and Sentinel task has waited, from the database, one row each. Reused for a minute."""
    from agentapi.models import SentinelTask
    from cveFeed.models import HostAssessment
    from startScan.models import ScanHistory
    now = timezone.now()
    out = {}
    with _bounded():
        for name, query, field in (('scan', ScanHistory.objects.filter(scan_status=-1).order_by('id'), 'start_scan_date'),
                                   ('assessment', HostAssessment.objects.filter(status='queued').order_by('created_at'), 'created_at'),
                                   ('sentinel_task', SentinelTask.objects.filter(status='queued').order_by('created_at'), 'created_at')):
            try:
                with transaction.atomic():  # a savepoint: one timed-out statement leaves the others readable
                    since = query.values_list(field, flat=True).first()
                out[name] = {'state': 'known', 'queued': since is not None, 'age_seconds': int(max(0, (now - since).total_seconds())) if since else None}
            except Exception as exc:  # noqa: BLE001
                out[name] = unknown(f'could not be read ({type(exc).__name__})')
    known = [v for v in out.values() if v['state'] == 'known']
    return {'state': 'known' if len(known) == len(out) else 'partial' if known else 'unknown', **out}


def queues(depths, client, now=None):
    """Messages waiting per Celery queue (``depths``: the status's own queue read, passed in so the broker is not asked twice) and the age of the oldest
    message of each queue that has any, from the time stamped on it when it was published (``reNgine.queue_age``), plus the oldest queued scan, host
    assessment and Sentinel task from the database. A message from before the stamp existed has an unknown age."""
    from agentapi.system_status import PRIORITY_SUFFIXES
    from reNgine import queue_age
    if not isinstance(depths, dict) or not isinstance(depths.get('waiting'), dict):
        return unknown('the queue depths could not be read')
    waiting = depths['waiting']
    ages = queue_age.oldest(client, waiting, PRIORITY_SUFFIXES, now)
    by_queue = {q: {'waiting': waiting[q], 'oldest_age_seconds': ages[q]['age_seconds'], 'age_state': 'known' if ages[q]['known'] else 'unknown'}
                for q in waiting if waiting[q] and q in ages}
    unknown_queues = sorted(q for q, v in by_queue.items() if v['age_state'] == 'unknown')
    known_ages = [v['oldest_age_seconds'] for v in by_queue.values() if v['age_state'] == 'known']
    result = {'state': 'partial' if unknown_queues else 'known', 'by_queue': by_queue, 'oldest_age_seconds': max(known_ages) if known_ages else None,
              'oldest_queued': _cached('oldest_db', _oldest_db)}
    if unknown_queues:
        result['reason'] = ('the oldest message has no send time (sent before the stamp existed, or too large to read): ' + ', '.join(unknown_queues))
    return result


# --- Sentinel claims refused by the server's own limiter ----------------------------------------------------------------------------------

def claim_refusals(now=None):
    """Calls the server's rate limiter refused, by caller and action (``agentapi.claim_refusals``), with the Sentinel's name where the caller is a token of a
    registered agent. Zero is a real answer when the counter can be read; a cache with no Redis behind it is ``unknown``."""
    from agentapi import claim_refusals as refusals
    from agentapi.models import Agent
    rows = refusals.read(now)
    names = {}
    if rows:
        wanted = {who for (_, who) in rows if not who.startswith('user:')}
        if wanted:
            for name, kind, key_hash in Agent.objects.filter(kind='scanner').values_list('name', 'kind', 'token__key_hash')[:500]:
                if key_hash and key_hash[:16] in wanted:
                    names[key_hash[:16]] = (name, kind)
    by = []
    for (action, who), (this_hour, previous_hour, total) in sorted(rows.items(), key=lambda i: -i[1][2])[:MAX_REFUSAL_ROWS]:
        by.append({'action': action, 'caller': names.get(who, (None, None))[0] or ('a user (all that user\'s tokens)' if who.startswith('user:') else 'an agent token'),
                   'sentinel': who in names, 'this_hour': this_hour, 'previous_hour': previous_hour, 'last_24h': total})
    return {'state': 'known', 'window': 'UTC clock hours', 'this_hour': sum(v[0] for v in rows.values()), 'previous_hour': sum(v[1] for v in rows.values()),
            'last_24h': sum(v[2] for v in rows.values()),
            'claims_last_24h': sum(v[2] for (action, _), v in rows.items() if action == 'claim'), 'by': by}


# --- database and Redis ---------------------------------------------------------------------------------------------------------------

def _database():
    with _bounded(), connection.cursor() as cur:
        cur.execute('SELECT pg_database_size(current_database())')
        size = int(cur.fetchone()[0])
        cur.execute("SELECT count(*) FILTER (WHERE state = 'active'), "
                    "coalesce(max(extract(epoch FROM now() - query_start)) FILTER (WHERE state = 'active'), 0) "
                    'FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()')
        active, longest = cur.fetchone()
    return {'state': 'known', 'size_mb': size // (1 << 20), 'active_queries': int(active or 0), 'longest_query_seconds': int(longest or 0)}


def database():
    """The database's size and how long its longest running query has been running (its text is never read). Reused for a minute."""
    return _cached('database', _database)


def redis_memory(client):
    """Redis's ``used_memory`` against ``maxmemory`` (0: no limit set, so no percentage) and the keys it has evicted since it started."""
    memory = client.info('memory')
    used, limit = _number(memory.get('used_memory')), _number(memory.get('maxmemory'))
    if used is None:
        return unknown('Redis did not report used_memory')
    evicted = None
    try:
        evicted = _number(client.info('stats').get('evicted_keys'))
    except Exception:  # noqa: BLE001
        pass
    return {'state': 'known', 'used_mb': round(used / (1 << 20), 1), 'limit_mb': round(limit / (1 << 20), 1) if limit else None,
            'limit_state': 'unknown' if limit is None else 'unlimited' if not limit else 'limited', 'percent_of_limit': _percent(used, limit),
            'evicted_keys': evicted}


# --- AI spend against its caps ------------------------------------------------------------------------------------------------------------

def _ai_spend():
    from cveFeed import tunables
    used = tunables.usage_today()
    rows = []
    for key in AI_CAP_KEYS:
        spec = tunables.BY_KEY[key]
        cap, today = _number(tunables.value(key)), used.get(key)
        row = {'key': key, 'label': spec.label, 'cap': cap, 'window': tunables.USED_SINCE.get(spec.window)}
        if today is None or cap is None:
            row.update(state='unknown', used=None, percent_of_cap=None, reason='the count of today\'s calls could not be read')
        else:
            row.update(state='known', used=today, percent_of_cap=_percent(today, cap))
        rows.append(row)
    known = [r for r in rows if r['state'] == 'known']
    result = {'state': 'known' if len(known) == len(rows) else 'partial' if known else 'unknown', 'caps': rows}
    if result['state'] != 'known':
        result['reason'] = 'not every counter could be read: ' + ', '.join(r['key'] for r in rows if r['state'] != 'known')
    return result


def ai_spend():
    """Each AI call cap with what has been used against it today (the counters the settings page shows). Reused for a minute."""
    return _cached('ai_spend', _ai_spend)


# --- all of it ----------------------------------------------------------------------------------------------------------------------------

def collect(depths=None, client=None, now=None):
    """``{'signals': {name: signal}, 'unknown': [names whose state is not known], 'at'}``. ``depths`` is the status's own queue read and ``client`` the broker
    client it used (both optional: without them the queue signal is unknown)."""
    now = time.time() if now is None else now
    signals = {
        'lanes': _safe(lambda: lanes(now)),
        'containers': _safe(lambda: containers(now)),
        'queues': _safe(lambda: queues(depths, client, now)),
        'claim_refusals': _safe(lambda: claim_refusals(now)),
        'database': database(),
        'redis': _safe(lambda: redis_memory(client or _redis())),
        'ai_spend': ai_spend(),
    }
    return {'at': int(now), 'signals': signals, 'unknown': sorted(name for name, s in signals.items() if s.get('state') != 'known')}
