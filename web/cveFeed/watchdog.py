"""The outer watchdog: watches this instance from outside Celery and puts right what it safely can (docs/WATCHDOG.md).

Why it exists. Everything that watched the workers used to be a Celery task, a beat entry or a check inside the worker container, so it died with
the very lanes it was meant to watch. This is a management command (``manage.py watchdog_tick``) that runs in the WEB container, driven every 30
seconds by the host process that already supervises updates (``scripts/update-watch.sh`` -> ``scripts/watchdog.sh``). It never waits on a Celery
consumer. The few actions that need Docker (recreate the celery or celery-beat container, prune dangling images) are written as a request file the
host carries out (``web/.watchdog-action`` -> ``web/.watchdog-result``), the same pattern as every other host action.

One tick: take a snapshot (``cveFeed.watchdog_snapshot``), then walk the rules R1 to R9 in order. Each rule has the same gates, in this order:
the switches (global ``Watchdog`` setting, ``CVENGINE_WATCHDOG=0``, the rule's own), stand down during an update, hysteresis (the symptom must hold
for the rule's time), the flap guard (no action while a hold is on), a minimum gap and an hourly and daily cap. R10 is the engine itself: after
an action, two minutes later (after the host finished, for a host action) the same check runs again; cleared is recorded as fixed, not cleared is
ONE escalation notice with the exact next step and the evidence, then that rule does nothing for an hour. Every decision is a ``WatchdogEvent``
row and an activity line; the notices are ``AdminAlert`` rows (``watchdog_<rule>``), which the status strip already shows to App Admins.

A rule only ever acts on a part of the snapshot that could be read: a ``None`` (Redis did not answer, the query timed out) means "cannot tell" and
changes nothing. Nothing here deletes data. The tick never raises, and ends by itself within ``TICK_SECONDS`` (``run``) or is killed by the command's own timer.
"""
import json
import logging
import os
import re
import signal
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone as dt_timezone

from django.conf import settings
from django.utils import timezone

from cveFeed import watchdog_snapshot as snapshot

logger = logging.getLogger(__name__)

TICK_SECONDS = 25            # a tick ends itself after this long (the command kills the process a little later, the host script a little later still)
VERIFY_SECONDS = 120         # R10: the check that follows an action
HOST_WAIT_SECONDS = 600      # a host request nobody carried out in this long is a watchdog that is not running on the host
HOLD_SECONDS = 3600          # R10: after an action that did not work, nothing more for this rule for this long
SETTLED_KEEP_SECONDS = 24 * 3600  # a "fixed" notice stays visible this long, then resolves itself
EVENT_KEEP_DAYS = 30
EVENT_KEEP_ROWS = 5000
ALL = '_all'
ACTION_FILE = '.watchdog-action'
RESULT_FILE = '.watchdog-result'
HOST_ACTIONS = ('restart-celery', 'restart-celery-beat', 'prune-docker')
LANE_WORDS = {'discovery_worker': 'discovery', 'cve_feed_worker': 'CVE feed', 'validation_priority_worker': 'validation', 'classic_worker': 'classic'}
WATCHDOG_ACTOR = 'watchdog'
PAUSE_REASON = 'Paused by the watchdog: '


class TickTimeout(BaseException):
    """The tick's time limit. A BaseException so no rule's ``except Exception`` swallows it."""


# --- switches -------------------------------------------------------------------------------------------------------------

def killed(environ=None):
    """CVENGINE_WATCHDOG=0 (or off/false/no) in the environment: the watchdog does nothing at all."""
    value = str((environ if environ is not None else os.environ).get('CVENGINE_WATCHDOG', '1')).strip().lower()
    return value in ('0', 'off', 'false', 'no')


class SystemActor:
    """Who a change made by the watchdog is recorded as (scan_concurrency.update audits ``actor.username``; there is no account behind it)."""
    username = WATCHDOG_ACTOR
    pk = None
    is_superuser = False


# --- the rules ---------------------------------------------------------------------------------------------------------------

@dataclass
class Check:
    """What a rule's check found: ``firing`` True (the symptom is there), False (it is not) or None (could not tell), a plain sentence, the evidence."""
    firing: object
    text: str
    evidence: dict = field(default_factory=dict)


@dataclass
class Rule:
    code: str
    title: str                 # plain language name, shown on the Health tab
    does: str                  # what it does about it, in a sentence
    confirm: int               # seconds the symptom must hold before the rule acts (hysteresis)
    gap: int                   # minimum seconds between two actions
    per_hour: int
    per_day: int
    check: object
    act: object = None         # act(ctx, check) -> (ok, text) for a local action; None for a rule that only raises a notice
    host_action: str = ''      # a Docker action the host carries out
    verify: int = VERIFY_SECONDS
    next_step: str = ''        # what to tell a person when the rule could not fix it
    notice_title: str = ''
    doing: str = ''            # what the watchdog says it is doing while a host action runs


class Ctx:
    def __init__(self, now, snap, states, probes=None, host=None):
        self.now, self.snap, self.states, self.probes, self.host = now, snap, states, probes, host

    @property
    def epoch(self):
        return self.now.timestamp()


def human(dt, ctx_now=None):
    """The token the notice strip turns into the viewer's local time (static/cve/alertbar.js, scanners.js)."""
    return '{{time:' + dt.astimezone(dt_timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ') + '}}'


_TOKEN = re.compile(r'\{\{time:([0-9T:\-]{19})Z\}\}')


def plain_times(text):
    """A sentence with its time tokens written out in UTC, for the places that cannot turn them into the viewer's own time (the activity feed)."""
    return _TOKEN.sub(lambda m: m.group(1)[11:] + ' UTC', text)


def _lanes_text(names):
    return ', '.join(LANE_WORDS.get(n, n) for n in names)


# R1 ----------------------------------------------------------------------------------------------------------------------------

def check_lanes(ctx):
    snap = ctx.snap
    if not snap.get('redis_ok') or snap.get('lanes') is None:
        return Check(None, 'Could not ask the workers (the broker did not answer), so nothing is done.')
    status = snapshot.lane_status(snap)
    absent = [p for p, lane in status.items() if lane['present'] is False]
    queues = snap.get('queues') or {}
    if not absent:
        return Check(False, 'All four worker lanes answer.')
    waiting = {LANE_WORDS.get(p, p): queues.get(status[p]['queue'], 0) for p in absent}
    parts = ', '.join(f'{w}: {n} waiting' for w, n in waiting.items())
    return Check(True, f'No answer from the {_lanes_text(absent)} lane{"s" if len(absent) != 1 else ""} ({parts}).', {'absent': absent, 'waiting': waiting})


def after_lanes_fixed(ctx, rule, state):
    """The lanes answer again: whatever the dead containers held unacknowledged goes back to its queue (the entrypoint does this at start too; this
    catches what it could not)."""
    done = requeue_orphans(ctx, min_age=60)
    return f'{done} unacknowledged message{"s" if done != 1 else ""} returned to their queues' if done else ''


# R2 ----------------------------------------------------------------------------------------------------------------------------

R2_SECONDS = 600


def check_hung(ctx, state=None):
    """A lane answers, its queue is not empty and does not shrink, no task has finished in ten minutes, and its pool has free slots (a pool full of long
    scans is busy, not hung)."""
    snap = ctx.snap
    if not snap.get('redis_ok') or snap.get('lanes') is None:
        return Check(None, 'Could not ask the workers, so nothing is done.')
    work = snap.get('lane_work')
    queues = snap.get('queues') or {}
    status = snapshot.lane_status(snap)
    state = state or ctx.states.get('R2')
    windows = dict((state.data or {}).get('windows') or {}) if state else {}
    hung, busy, notes = [], [], []
    for prefix, lane in status.items():
        depth = queues.get(lane['queue'], 0)
        if not lane['present'] or work is None or not depth:
            windows.pop(prefix, None)  # absent is R1's; an empty queue has nothing to be hung about
            continue
        mine = [work[n] for n in lane['workers'] if n in work]
        if not mine:
            continue
        completed = sum(w['completed'] for w in mine)
        active = sum(w['active'] for w in mine)
        capacity = sum(w['capacity'] or 0 for w in mine) or None
        win = windows.get(prefix)
        if not win or completed != win['completed'] or depth < win['depth']:
            windows[prefix] = {'since': ctx.epoch, 'depth': depth, 'completed': completed}  # progress, or a shorter queue: start the window again
            continue
        if ctx.epoch - win['since'] < R2_SECONDS or depth <= win['depth']:
            continue
        if capacity is None or active >= capacity:
            busy.append(prefix)  # every slot is taken: long work, not a hung worker
            continue
        hung.append(prefix)
        notes.append(f'{LANE_WORDS.get(prefix, prefix)}: queue grew from {win["depth"]} to {depth} in {int((ctx.epoch - win["since"]) // 60)} minutes with nothing finished and {capacity - active} free slot(s)')
    if state is not None:
        state.data = {**(state.data or {}), 'windows': windows}
    if hung:
        return Check(True, 'A lane answers but takes no work: ' + '; '.join(notes) + '.', {'hung': hung})
    return Check(False, 'Every lane that answers is taking its work' + (' (a full pool is busy, not hung).' if busy else '.'))


# R3 ----------------------------------------------------------------------------------------------------------------------------

def _memory_ok(snap):
    mem = snap.get('memory')
    return not mem or all(m['used_pct'] < 90 for m in mem)


def check_pool(ctx):
    snap = ctx.snap
    d, s = snap.get('discovery'), snap.get('sentinels')
    if d is None or s is None or snap.get('queues') is None:
        return Check(None, 'Could not read the pool size, the queue or the Sentinels, so nothing is done.')
    waiting = (snap['queues'].get('discovery_queue') or 0) + (snap.get('assessments') or 0)
    floor = d['floor']
    low = d['value'] < floor
    idle = s['free'] > 0 and s['waiting'] == 0
    if not low:
        return Check(False, f'Hosts assessed at once is {d["value"]}.')
    if not waiting:
        return Check(False, f'Hosts assessed at once is {d["value"]}, below {floor}, but nothing is waiting for a slot.')
    if not idle:
        return Check(False, f'Hosts assessed at once is {d["value"]}, below {floor}; the Sentinels are busy, so it is not holding work back.')
    return Check(True, f'{waiting} host assessments wait for a slot while {s["free"]} Sentinel slot(s) are idle and hosts assessed at once is {d["value"]} (source: {d["source"]}).',
                 {'value': d['value'], 'source': d['source'], 'waiting': waiting, 'floor': floor})


def act_pool(ctx, chk):
    d = ctx.snap['discovery']
    floor = d['floor']
    if d['source'] == 'admin':
        return False, f'The value {d["value"]} was saved in Settings by {d["saved_by"] or "a person"}; the watchdog never overrides that.'
    if d['source'] != 'environment':
        return False, f'The value comes from {d["source"]}, not from the environment, so the watchdog leaves it to the auto-tuner.'
    if not _memory_ok(ctx.snap):
        return False, 'Memory is above 90 percent, so the pool is not raised now.'
    from cveFeed import scan_concurrency
    scan_concurrency.update({'discovery_concurrency': floor}, SystemActor())
    state = ctx.states['R3']
    state.data = {**(state.data or {}), 'override': {'key': 'discovery_concurrency', 'value': floor, 'env_name': d['env_name'], 'env_value': d['env_value'],
                                                   'at': ctx.now.isoformat()}}
    live = ''
    try:
        record = scan_concurrency.apply_discovery()
        live = f' The running discovery worker now has ceiling {max([c for c in record["workers"].values() if c] or [floor])}.' if record.get('workers') else ' No discovery worker answered; it takes the value when it next starts.'
    except Exception:  # noqa: BLE001
        live = ' The running worker could not be asked; it takes the value when it next starts.'
    return True, f'Held at {d["value"]} by {d["env_name"]} in .env; raised to {floor} by the watchdog (.env is not changed).' + live


def release_pool_override(ctx, force_text=''):
    """Let go of the R3 override: when a person saved their own value, or the environment no longer pins the field."""
    state = ctx.states['R3']
    override = (state.data or {}).get('override')
    if not override:
        return None
    from cveFeed import scan_concurrency
    key = override['key']
    field_ = scan_concurrency.BY_KEY[key]
    row = scan_concurrency.saved_row()
    saved = (row.values or {}).get(key)
    by = ((row.meta or {}).get(key) or {}).get('by')
    why = ''
    if saved is None:
        why = 'the saved value is gone'
    elif by != WATCHDOG_ACTOR or saved != override['value']:
        why = f'{by or "a person"} saved a value of their own, which now stands'
    else:
        env = scan_concurrency.env_value(field_)
        if not scan_concurrency.env_pin(field_, env) or (env is not None and env >= field_.auto_min):
            why = f'{override["env_name"]} in .env no longer holds it down'
            scan_concurrency.update({key: None}, SystemActor())  # the saved layer is cleared: the auto-tuner (or .env) decides again
            try:
                scan_concurrency.apply_discovery()
            except Exception:  # noqa: BLE001
                pass
    if not why:
        return None
    state.data = {k: v for k, v in (state.data or {}).items() if k != 'override'}
    return why


# R4 ----------------------------------------------------------------------------------------------------------------------------

def check_idle_sentinels(ctx):
    s = ctx.snap.get('sentinels')
    if s is None:
        return Check(None, 'Could not read the Sentinels, so nothing is done.')
    if not s['slots']:
        return Check(False, 'No Sentinel is online.')
    if s['waiting'] or not s['free']:
        return Check(False, f'The Sentinels have work ({s["waiting"]} waiting, {s["busy"]} of {s["slots"]} slots busy).')
    if s['due'] is None:
        return Check(None, 'Could not tell whether checks are due.')
    if not s['due']:
        return Check(False, 'The Sentinels are idle and nothing is due.')
    return Check(True, f'{s["free"]} of {s["slots"]} Sentinel slots are idle, nothing is queued for them and checks are due.', {'free': s['free'], 'slots': s['slots']})


def act_feed(ctx, chk):
    from cveFeed import coverage_topup
    out = coverage_topup.feed_sentinels() or {}
    queued = int(out.get('hosts_queued') or 0) + int(out.get('batches_queued') or 0) + int(((out.get('refresh') or {}).get('refreshed')) or 0)
    parts = [f'Ran the Sentinel feed: {queued} item(s) queued for {out.get("slots", "the")} Sentinel slots']
    try:
        from cveFeed import work_planner  # the work planner (when this build has it) plans the due secrets and ssh work too
        planned = work_planner.run() if hasattr(work_planner, 'run') else None
        if planned is not None:
            parts.append('ran the work planner')
    except ImportError:
        pass
    if not queued and not out.get('refresh'):
        # the feed found nothing it may queue (enough is queued already, or nothing is eligible): not an action, and nothing to check afterwards
        return None, 'The feed had nothing to queue for the Sentinels (' + (str(out.get('skipped')) if out.get('skipped') else 'nothing eligible') + ').'
    return True, '; '.join(parts)


# R5 ----------------------------------------------------------------------------------------------------------------------------

R5_SECONDS = 30 * 60


def check_unacked(ctx):
    u = ctx.snap.get('unacked')
    if u is None:
        return Check(None, 'Could not read the unacknowledged messages, so nothing is done.')
    if not u['count'] or u['oldest_age_seconds'] <= R5_SECONDS:
        return Check(False, 'No message has been held unacknowledged for long.')
    tags = orphan_tags(ctx, R5_SECONDS)  # a worker with a full pool legitimately holds messages it has not started: only what no worker holds counts
    if tags is None:
        return Check(None, 'Could not tell which unacknowledged messages a worker holds.')
    if not tags:
        return Check(False, f'{u["count"]} messages are held unacknowledged for a long time, and workers hold them (busy, not stuck).')
    return Check(True, f'{len(tags)} messages have been unacknowledged for over {R5_SECONDS // 60} minutes and no worker holds them.', {'count': len(tags)})


def act_unacked(ctx, chk):
    done = requeue_orphans(ctx, min_age=R5_SECONDS)
    return True, f'{done} message{"s" if done != 1 else ""} no worker holds returned to their queues (messages a worker holds were left alone).'


def held_task_ids(lanes=None):
    """The ids of the tasks the workers hold (running, reserved or scheduled); empty when no worker answered (``lanes`` {} says none did)."""
    if lanes == {}:
        return set()
    from reNgine.celery import app
    held = set()
    for call in ('active', 'reserved', 'scheduled'):
        found = getattr(app.control.inspect(timeout=snapshot.PING_SECONDS), call)()
        if found is None:
            break  # nobody answered the first question: there is nobody to ask
        for tasks in found.values():
            for task in tasks:
                task = task.get('request', task)
                if task.get('id'):
                    held.add(task['id'])
    return held


def orphan_tags(ctx, min_age):
    """The delivery tags of unacknowledged messages older than ``min_age`` seconds that no worker holds, or None when that cannot be told."""
    try:
        from cveFeed import broker_recovery
        client = ctx.probes.redis() if ctx.probes else snapshot.Probes().redis()
        tags = list(client.zrangebyscore(snapshot.UNACKED_INDEX_KEY, '-inf', ctx.epoch - min_age))
        if not tags:
            return []
        held = held_task_ids(ctx.snap.get('lanes'))
        out = []
        for tag in tags:
            raw = client.hget(snapshot.UNACKED_KEY, tag)
            if not ((set(broker_recovery._task_ids(raw)) & held) if raw else set()):
                out.append(tag)
        return out
    except Exception:  # noqa: BLE001
        logger.warning('watchdog: could not read the unacknowledged messages', exc_info=True)
        return None


def requeue_orphans(ctx, min_age):
    """Return the unacknowledged messages older than ``min_age`` seconds that no worker holds to their queues. Never raises; returns how many."""
    try:
        from cveFeed import broker_recovery
        return broker_recovery.requeue_tags(orphan_tags(ctx, min_age) or [])
    except Exception:  # noqa: BLE001
        logger.warning('watchdog: could not return the unacknowledged messages', exc_info=True)
        return 0


# R6 ----------------------------------------------------------------------------------------------------------------------------

BEAT_SILENT_SECONDS = 120


def check_beat(ctx):
    if not ctx.snap.get('redis_ok'):
        return Check(None, 'Could not read the scheduler heartbeat (the broker did not answer), so nothing is done.')
    age = ctx.snap.get('beat_age')
    if age is None:
        return Check(None, 'The scheduler has not written a heartbeat that can be read (it may not have started since Redis was last emptied).')
    if age > BEAT_SILENT_SECONDS:
        return Check(True, f'The scheduler (celery-beat) last ticked {age // 60} minutes {age % 60} seconds ago; it ticks every 15 seconds.', {'age': age})
    return Check(False, f'The scheduler ticked {age} seconds ago.')


# R7 ----------------------------------------------------------------------------------------------------------------------------

DISK_MIN_PCT = 10
DISK_MIN_MB = 5 * 1024
MEMORY_MAX_PCT = 90


def check_pressure(ctx):
    disk, mem = ctx.snap.get('disk'), ctx.snap.get('memory')
    if disk is None and mem is None:
        return Check(None, 'Could not read disk or memory, so nothing is done.')
    problems, evidence = [], {}
    if disk and ((disk['free_pct'] is not None and disk['free_pct'] < DISK_MIN_PCT) or disk['free_mb'] < DISK_MIN_MB):
        problems.append(f'disk is nearly full ({disk["free_mb"] // 1024} GB, {disk["free_pct"]} percent free)')
        evidence['disk'] = True
    high = [m for m in (mem or []) if m['used_pct'] > MEMORY_MAX_PCT]
    if high:
        problems.append('memory is over 90 percent in ' + ', '.join(f'{m["host"]} ({m["used_pct"]}%)' for m in high))
        evidence['memory'] = True
    if problems:
        return Check(True, 'The host is short of resources: ' + '; '.join(problems) + '.', evidence)
    return Check(False, 'Disk and memory are fine.')


def act_pressure(ctx, chk):
    """Pause the automatic starting of heavy work (running work carries on), and for disk ask the host for the safe prune."""
    from cveFeed import scan_control
    from cveFeed.models import ScanControl
    why = 'disk nearly full' if chk.evidence.get('disk') else 'memory nearly full'
    paused = False
    try:
        if not ScanControl.objects.filter(pk=1, paused=True).exists():
            scan_control.request_drain_pause(PAUSE_REASON + why)
            paused = True
    except Exception:  # noqa: BLE001
        logger.warning('watchdog: could not pause the starting of work', exc_info=True)
    state = ctx.states['R7']
    if paused:
        state.data = {**(state.data or {}), 'paused_at': ctx.now.isoformat(), 'paused_for': why}
    if chk.evidence.get('disk') and request_host_action('prune-docker', 'R7', ctx.now) is None:
        chk.evidence['disk'] = False  # another host request is waiting: the prune is asked for at the next try
    return True, ('Paused the automatic starting of scans and heavy work (running work carries on)' if paused else 'Scanning was already paused; left as it is') + (
        '; asked the host to remove dangling images and the build cache' if chk.evidence.get('disk') else '') + '.'


def release_pressure_pause(ctx):
    """Resume what R7 paused, once the pressure has been gone for a while (only a pause the watchdog set, never a person's)."""
    from cveFeed import scan_control
    from cveFeed.models import ScanControl
    state = ctx.states['R7']
    if not (state.data or {}).get('paused_at'):
        return None
    row = ScanControl.objects.filter(pk=1).first()
    state.data = {k: v for k, v in (state.data or {}).items() if k not in ('paused_at', 'paused_for')}
    if row and row.paused and row.paused_by_update and str(row.reason).startswith(PAUSE_REASON):
        scan_control.release_update_pause()
        return 'resumed the automatic starting of work'
    return None


# R8 ----------------------------------------------------------------------------------------------------------------------------

def check_db(ctx):
    db = ctx.snap.get('db')
    if db is None:
        return Check(None, 'Could not read the database connections.')
    pct = round(100 * db['connections'] / db['max']) if db['max'] else 0
    bits = []
    if pct >= 85:
        bits.append(f'{db["connections"]} of {db["max"]} database connections are in use ({pct} percent)')
    if db['idle_in_transaction_seconds'] > 600:
        bits.append(f'a database session has been idle inside a transaction for {db["idle_in_transaction_seconds"] // 60} minutes')
    if bits:
        return Check(True, '; '.join(bits).capitalize() + '.', {'connections': db['connections'], 'max': db['max']})
    return Check(False, f'{db["connections"]} of {db["max"]} database connections in use.')


# R9 ----------------------------------------------------------------------------------------------------------------------------

R9_IDLE_MINUTES = 60
R9_MESSAGE = 'interrupted: no worker held this scan and it showed no activity (closed by the watchdog)'


def check_stalled(ctx):
    scans = ctx.snap.get('scans')
    if scans is None:
        return Check(None, 'Could not read the scans.')
    if not scans['stale_candidates']:
        return Check(False, f'{scans["running"]} scan(s) running, none without activity.')
    from cveFeed import ghost_scans
    state = ctx.states.get('R9')
    last = (state.data or {}).get('checked_at') if state else None
    if last and ctx.epoch - last < 300:
        return Check(False, f'{scans["stale_candidates"]} scan(s) are quiet but a worker holds them (checked a few minutes ago).')
    found = ghost_scans.find(now=ctx.now, idle_minutes=R9_IDLE_MINUTES)  # asks the broker and the workers; None-safe: nothing is found when that cannot be told
    if state:
        state.data = {**(state.data or {}), 'checked_at': ctx.epoch if not found else 0}
    if not found:
        return Check(False, f'{scans["stale_candidates"]} scan(s) are quiet but a worker still holds them or the workers could not be asked.')
    return Check(True, f'{len(found)} running scan(s) have shown nothing for over {R9_IDLE_MINUTES} minutes and no worker holds them.', {'scans': [s.pk for s, _ in found][:20]})


def act_stalled(ctx, chk):
    from cveFeed import ghost_scans
    closed = ghost_scans.close(now=ctx.now, idle_minutes=R9_IDLE_MINUTES, message=R9_MESSAGE)
    return True, f'Marked {len(closed)} scan{"s" if len(closed) != 1 else ""} failed (interrupted) so the queue moves: {", ".join(map(str, closed[:10]))}.'


RULES = [
    Rule('R1', 'Workers answer', 'Recreates the celery container (through the host) when a lane has not answered for 3 minutes.', 180, 900, 2, 4, check_lanes,
         host_action='restart-celery', next_step='run `docker compose restart celery` on the server, then read `docker compose logs --tail 100 celery`',
         notice_title='The workers stopped answering', doing='restarting the workers'),
    Rule('R2', 'Workers take their work', 'Recreates the celery container when a lane answers but its queue grows and nothing finishes for 10 minutes.', 60, 900, 2, 4, check_hung,
         host_action='restart-celery', next_step='run `docker compose restart celery`, then read `docker compose logs --tail 100 celery`', notice_title='A worker lane took no work', doing='restarting the workers'),
    Rule('R3', 'Hosts assessed at once is not starved', 'Raises a too-small discovery pool to the auto-tune minimum while hosts wait and Sentinels idle (never a value a person saved).', 120, 600, 3, 10,
         check_pool, act=act_pool, notice_title='Hosts assessed at once was held too low'),
    Rule('R4', 'Idle Sentinels are fed', 'Runs the Sentinel feed itself when Sentinels sit idle with checks due.', 300, 600, 4, 24, check_idle_sentinels, act=act_feed,
         next_step='open Scanners, Sentinels and check that the Sentinels are allowed the due work', notice_title='Sentinels sat idle with work due'),
    Rule('R5', 'No message stuck unacknowledged', 'Returns messages no worker holds, unacknowledged for over 30 minutes, to their queues.', 0, 600, 2, 12, check_unacked, act=act_unacked,
         next_step='run `docker compose restart celery`', notice_title='Messages were stuck unacknowledged'),
    Rule('R6', 'Scheduler ticks', 'Recreates the celery-beat container (through the host) when the scheduler has been silent for over 2 minutes.', 120, 900, 2, 4, check_beat,
         host_action='restart-celery-beat', next_step='run `docker compose restart celery-beat`, then read `docker compose logs --tail 100 celery-beat`', notice_title='The scheduler went quiet', doing='restarting the scheduler'),
    Rule('R7', 'Disk and memory have room', 'Pauses the automatic starting of heavy work and, for disk, removes dangling images and build cache (never a tagged image or a volume).', 120, 1800, 2, 6,
         check_pressure, act=act_pressure, next_step='free space on the host (`docker system df`, `df -h`) or raise the memory limit', notice_title='The host is short of disk or memory'),
    Rule('R8', 'Database connections have room', 'Only raises a notice.', 120, 0, 0, 0, check_db, notice_title='The database is near its connection limit'),
    Rule('R9', 'No scan is stuck running', 'Marks a scan failed (interrupted) when it shows no activity for an hour and no worker holds it.', 0, 600, 2, 24, check_stalled, act=act_stalled,
         next_step='open the scan and stop it from the Scans page', notice_title='A scan was stuck running'),
]
BY_CODE = {r.code: r for r in RULES}


# --- persistence -------------------------------------------------------------------------------------------------------------

def _states():
    from cveFeed.models import WatchdogState
    out = {}
    for code in [ALL] + [r.code for r in RULES]:
        out[code], _ = WatchdogState.objects.get_or_create(rule=code)
    return out


def event(rule, level, observation='', action='', result='', **detail):
    """Append one WatchdogEvent and one activity line. Never raises."""
    try:
        from cveFeed import activity
        from cveFeed.models import WatchdogEvent
        row = WatchdogEvent.objects.create(rule=rule, level=level, observation=observation[:500], action=action[:80], result=result[:500], detail=detail)
        if level != 'info':
            activity.log('hygiene', plain_times('Watchdog ' + rule + ': ' + (result or observation))[:500], status='failed' if level == 'problem' else 'done', watchdog_rule=rule)
        return row
    except Exception:  # noqa: BLE001
        logger.warning('watchdog: could not record an event', exc_info=True)
        return None


def notice(rule, severity, title, detail, **facts):
    """Open (or update) the one notice of this rule for App Admins (an AdminAlert, code ``watchdog_<rule>``). Never raises."""
    try:
        import hashlib

        from cveFeed.models import AdminAlert
        code = 'watchdog_' + rule.lower()
        digest = hashlib.sha1(f'{severity}|{title}'.encode()).hexdigest()[:20]
        now = timezone.now()
        alert = AdminAlert.objects.filter(code=code, resolved_at__isnull=True).first()
        if alert is None:
            AdminAlert.objects.create(code=code, severity=severity, title=title[:200], detail=detail[:4000], facts=facts, digest=digest, first_seen=now, last_seen=now)
        else:
            alert.severity, alert.title, alert.detail, alert.facts, alert.last_seen = severity, title[:200], detail[:4000], facts, now
            if alert.digest != digest:
                alert.digest = digest  # a dismissed notice returns when what it says changes
            alert.save(update_fields=['severity', 'title', 'detail', 'facts', 'digest', 'last_seen'])
    except Exception:  # noqa: BLE001
        logger.warning('watchdog: could not write a notice', exc_info=True)


def resolve_notice(rule, why=''):
    try:
        from cveFeed.models import AdminAlert
        AdminAlert.objects.filter(code='watchdog_' + rule.lower(), resolved_at__isnull=True).update(resolved_at=timezone.now())
    except Exception:  # noqa: BLE001
        logger.warning('watchdog: could not resolve a notice', exc_info=True)


def expire_settled(now):
    """Notices that say \"fixed\" resolve themselves after a day."""
    from cveFeed.models import AdminAlert
    AdminAlert.objects.filter(code__startswith='watchdog_', severity='info', resolved_at__isnull=True,
                              last_seen__lt=now - timedelta(seconds=SETTLED_KEEP_SECONDS)).update(resolved_at=now)


def prune_events(now):
    from cveFeed.models import WatchdogEvent
    WatchdogEvent.objects.filter(at__lt=now - timedelta(days=EVENT_KEEP_DAYS)).delete()
    extra = WatchdogEvent.objects.order_by('-id').values_list('id', flat=True)[EVENT_KEEP_ROWS:EVENT_KEEP_ROWS + 1]
    if extra:
        WatchdogEvent.objects.filter(id__lte=extra[0]).delete()


# --- the host path -----------------------------------------------------------------------------------------------------------

def _home():
    """The directory the web container shares with the host (``web/`` on the host): where every request file lives."""
    return getattr(settings, 'BASE_DIR', '') or ''


def request_host_action(action, rule, now=None, home=None):
    """Write the request the host watcher carries out; returns the request or None when one is already waiting. The file holds only the action name,
    the rule and an id; the host accepts nothing else."""
    if action not in HOST_ACTIONS:
        raise ValueError(f'unknown host action {action}')
    path = os.path.join(home or _home(), ACTION_FILE)
    if os.path.lexists(path):
        return None
    request = {'id': uuid.uuid4().hex[:12], 'action': action, 'rule': rule, 'at': int((now or timezone.now()).timestamp())}
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(request, f)
    os.replace(tmp, path)
    return request


def read_host_result(home=None):
    """The host's answer ``{id, action, ok, at, detail}`` or None."""
    path = os.path.join(home or _home(), RESULT_FILE)
    try:
        if os.path.islink(path) or os.path.getsize(path) > 4096:
            return None
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get('id'), str) and isinstance(data.get('at'), (int, float)):
            return data
    except (OSError, ValueError):
        pass
    return None


def pending_request(home=None):
    path = os.path.join(home or _home(), ACTION_FILE)
    try:
        if os.path.islink(path):
            return None
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {'id': '?'} if os.path.lexists(path) else None


def clear_request(home=None):
    try:
        os.unlink(os.path.join(home or _home(), ACTION_FILE))
    except OSError:
        pass


# --- the engine -----------------------------------------------------------------------------------------------------------------

def _within(actions, epoch, seconds):
    return [a for a in actions if epoch - a < seconds]


def _set(state, status, text):
    state.status, state.status_text = status, text[:400]


def _stand_down_reason(ctx):
    u = ctx.snap.get('update')
    if u is None:
        return 'could not tell whether an update is running'
    if u.get('active'):
        why = [w for w, on in (('phase ' + str(u.get('phase')), u.get('phase') in ('draining', 'applying')), ('an approved update is waiting', u.get('approved')), ('the update lock is held', u.get('locked'))) if on]
        return 'an update is in progress (' + ', '.join(why) + ')'
    return ''


def _gate(rule, state, ctx):
    """None when the rule may act now, else (status, text)."""
    epoch = ctx.epoch
    if state.hold_until and state.hold_until > ctx.now:
        return 'problem', f'Could not fix it; not trying again until {human(state.hold_until)}. ' + (f'Next step: {rule.next_step}.' if rule.next_step else '')
    if state.verify_due or (state.verify or {}).get('host_id'):
        return 'acting', 'Waiting to see whether the last action worked.'
    recent = [a for a in state.actions or [] if epoch - a < 86400]
    if rule.gap and state.last_action_at and (ctx.now - state.last_action_at).total_seconds() < rule.gap:
        return 'watching', f'Acted {int((ctx.now - state.last_action_at).total_seconds() // 60)} minutes ago; the next try is at least {rule.gap // 60} minutes after that.'
    if rule.per_hour and len(_within(recent, epoch, 3600)) >= rule.per_hour:
        return 'problem', f'Reached the limit of {rule.per_hour} actions an hour for this rule. ' + (f'Next step: {rule.next_step}.' if rule.next_step else '')
    if rule.per_day and len(recent) >= rule.per_day:
        return 'problem', f'Reached the limit of {rule.per_day} actions a day for this rule. ' + (f'Next step: {rule.next_step}.' if rule.next_step else '')
    return None


def _record_action(state, ctx):
    state.last_action_at = ctx.now
    state.actions = [a for a in (state.actions or []) if ctx.epoch - a < 86400] + [ctx.epoch]


def _fixed(rule, state, ctx, extra=''):
    v = state.verify or {}
    symptom = v.get('symptom_at')
    acted = v.get('acted_at')
    parse = lambda s: datetime.fromisoformat(s) if s else None  # noqa: E731
    sd, ad = parse(symptom), parse(acted)
    text = f'{rule.notice_title or rule.title}' + (f' at {human(sd)}' if sd else '') + (f'; the watchdog acted at {human(ad)} and it is fixed' if ad else '; it is fixed')
    if rule.code in ('R1', 'R2'):
        text = ('The workers stopped answering' if rule.code == 'R1' else 'A worker lane took no work') + (f' at {human(sd)}' if sd else '') + (
            f'; the watchdog restarted them at {human(ad)} and they answer again' if ad else '; they answer again')
    state.verify, state.verify_due = {}, None
    state.fire_since = None
    if rule.code == 'R3':  # the override stays in force: its warning stays up until the watchdog lets go of it
        event(rule.code, 'fixed', observation='Hosts assessed at once is at the minimum.', action=v.get('action', ''), result='Verified: the pool ceiling holds. The watchdog keeps it until .env stops holding it down or a person saves a value.')
        return text
    event(rule.code, 'fixed', observation='The symptom is gone two minutes after the action.', action=v.get('action', ''), result='Verified: ' + text + (f'. {extra}' if extra else ''))
    notice(rule.code, 'info', text, (extra + ' ' if extra else '') + 'Nothing more is needed. Details: Scanners, Health.', verified=True)
    return text


def _escalate(rule, state, ctx, chk):
    v = state.verify or {}
    evidence = chk.text
    state.hold_until = ctx.now + timedelta(seconds=HOLD_SECONDS)
    state.escalated_at = ctx.now
    state.verify, state.verify_due = {}, None
    nxt = rule.next_step or 'look at the Health tab of the Scanners page'
    event(rule.code, 'problem', observation=evidence, action=v.get('action', ''), result=f'Not fixed after the action. Stopped acting on this rule for an hour. Next step: {nxt}.')
    notice(rule.code, 'critical', f'{rule.notice_title or rule.title}; the watchdog could not fix it. Next step: {nxt}', f'{evidence} The watchdog acted at {human(datetime.fromisoformat(v["acted_at"])) if v.get("acted_at") else "an earlier time"} and the symptom was still there two minutes later, so it has stopped acting on this for an hour to avoid a restart loop.',
           action=v.get('action', ''))


def _act(rule, state, ctx, chk):
    """Carry the action out. Returns True when something was done (the check that follows is scheduled)."""
    now_iso = ctx.now.isoformat()
    symptom_at = state.fire_since.isoformat() if state.fire_since else now_iso
    notice_detail = chk.text
    if rule.host_action:
        req = request_host_action(rule.host_action, rule.code, ctx.now)
        if req is None:
            _set(state, 'watching', 'Another host action is waiting to be carried out; this one follows.')
            return False
        _record_action(state, ctx)
        state.verify = {'action': rule.host_action, 'host_id': req['id'], 'requested_at': now_iso, 'symptom_at': symptom_at, 'acted_at': now_iso}
        _set(state, 'acting', f'Asked the host to {rule.host_action.replace("-", " ")}.')
        event(rule.code, 'action', observation=chk.text, action=rule.host_action, result='Asked the host to carry it out.', request=req['id'])
        notice(rule.code, 'warning', f'{rule.notice_title or rule.title}; the watchdog is {rule.doing or "acting"}', notice_detail)
        return True
    if rule.act:
        ok, text = rule.act(ctx, chk)
        if ok is None:  # nothing was needed: no action to count or to check, but the gap holds so it is not asked every tick
            state.last_action_at = ctx.now
            event(rule.code, 'info', observation=chk.text, action='none', result=text)
            _set(state, 'watching', text)
            return False
        if ok:
            _record_action(state, ctx)
        if not ok:
            event(rule.code, 'info', observation=chk.text, action='none', result=text)
            _set(state, 'problem', text)
            notice(rule.code, 'warning', f'{rule.notice_title or rule.title}', f'{chk.text} {text}')
            return False
        state.verify = {'action': rule.code.lower(), 'symptom_at': symptom_at, 'acted_at': now_iso}
        state.verify_due = ctx.now + timedelta(seconds=rule.verify)
        _set(state, 'acting', text)
        event(rule.code, 'action', observation=chk.text, action=rule.code.lower(), result=text)
        if rule.code == 'R3':
            o = (state.data or {}).get('override') or {}
            notice(rule.code, 'warning', f'Hosts assessed at once was held at {ctx.snap["discovery"]["value"]} by {o.get("env_name", "DISCOVERY_CONCURRENCY")} in .env; the watchdog raised it to {o.get("value")}',
                   f'{chk.text} Your .env file was not changed. To fix it for good, set {o.get("env_name", "DISCOVERY_CONCURRENCY")} to 8 (or remove it) in .env; the watchdog then lets go of its value on its own.')
        else:
            notice(rule.code, 'warning', f'{rule.notice_title or rule.title}; the watchdog acted', f'{chk.text} {text}')
        return True
    return False


def _process_host_result(ctx):
    """Match the host's answer to the rule that asked, and start the two-minute clock from when the host finished."""
    result = read_host_result()
    all_state = ctx.states[ALL]
    seen = (all_state.data or {}).get('last_result')
    if not result or result['id'] == seen:
        return
    all_state.data = {**(all_state.data or {}), 'last_result': result['id']}
    for rule in RULES:
        state = ctx.states[rule.code]
        v = state.verify or {}
        if v.get('host_id') == result['id']:
            done = datetime.fromtimestamp(result['at'], tz=dt_timezone.utc)
            detail = str(result.get('detail') or '')[:300]
            if result.get('standdown'):  # the host stood aside (an update or maintenance holds the stack): nothing was done, so it does not count and is asked again later
                state.verify, state.verify_due = {}, None
                state.last_action_at = None
                state.actions = list(state.actions or [])[:-1]
                event(rule.code, 'info', action=result.get('action', ''), result='The host stood aside: ' + detail + ' It is asked again when the stack is free.', request=result['id'])
                _set(state, 'standing_down', 'The host stood aside: ' + detail)
                state.save()
                continue
            v = {**v, 'host_id': '', 'host_done_at': done.isoformat()}
            state.verify = v
            if result.get('ok'):
                state.verify_due = done + timedelta(seconds=rule.verify)
                event(rule.code, 'action', action=result.get('action', ''), result='The host carried it out. ' + detail, request=result['id'])
            else:
                state.verify_due = ctx.now  # check at once: the host refused or failed
                event(rule.code, 'problem', action=result.get('action', ''), result='The host did not carry it out: ' + detail, request=result['id'])
            state.save()
    clear_request_if_done(result)


def clear_request_if_done(result):
    pending = pending_request()
    if pending and pending.get('id') == result['id']:
        clear_request()


def _process_rule(rule, ctx, stand):
    state = ctx.states[rule.code]
    off = ctx.states[ALL].enabled is False or not state.enabled or killed()
    try:
        chk = rule.check(ctx) if rule.code != 'R2' else check_hung(ctx, state)
    except Exception as exc:  # noqa: BLE001 - a rule that fails is "cannot tell", not a failed tick
        logger.warning('watchdog %s: check failed', rule.code, exc_info=True)
        chk = Check(None, f'The check could not run ({type(exc).__name__}).')
    if off:
        _set(state, 'off', 'Switched off.' + (' (CVENGINE_WATCHDOG=0)' if killed() else ''))
        state.fire_since = None
        return
    if rule.code == 'R3':
        why = release_pool_override(ctx)
        if why:
            event('R3', 'fixed', observation='The watchdog\'s override of hosts assessed at once was released.', action='release', result=f'Released: {why}.')
            resolve_notice('R3')
    if rule.code == 'R7' and chk.firing is False:
        if state.fire_since is None and (state.data or {}).get('paused_at'):
            done = release_pressure_pause(ctx)
            if done:
                event('R7', 'fixed', observation='Disk and memory are fine again.', action='resume', result=done[0].upper() + done[1:] + '.')
    if state.hold_until and state.hold_until <= ctx.now:
        state.hold_until = None
    if stand and state.verify_due and ctx.now >= state.verify_due:
        state.verify_due = ctx.now + timedelta(seconds=60)  # an update restarts the workers by design: the check waits for it to end
        _set(state, 'standing_down', f'The watchdog stands aside while {stand}.')
        return
    # R10: the check that follows an action
    if state.verify_due and ctx.now >= state.verify_due and not (state.verify or {}).get('host_id'):
        if chk.firing is False:
            extra = ''
            if rule.code == 'R1':
                extra = after_lanes_fixed(ctx, rule, state)
            _fixed(rule, state, ctx, extra)
            _set(state, 'ok', chk.text)
            return
        if chk.firing is True:
            _escalate(rule, state, ctx, chk)
            _set(state, 'problem', f'Could not fix it. Next step: {rule.next_step or "see the Health tab"}.')
            return
    if (state.verify or {}).get('host_id') and (ctx.now - datetime.fromisoformat(state.verify['requested_at'])).total_seconds() > HOST_WAIT_SECONDS:
        clear_request()
        v = state.verify
        state.verify, state.verify_due = {}, None
        state.hold_until = ctx.now + timedelta(seconds=HOLD_SECONDS)
        event(rule.code, 'problem', action=v.get('action', ''), result='The host did not carry the request out within 10 minutes (is scripts/update-watch.sh running?).')
        notice(rule.code, 'critical', f'{rule.notice_title or rule.title}; the watchdog could not act. Next step: {rule.next_step or "check scripts/update-watch.sh"}',
               'The request for the host was not carried out within 10 minutes. The host watcher (scripts/update-watch.sh, started by cron every minute) may not be running, or an update or maintenance holds the stack.')
    # hysteresis
    if chk.firing is None:
        _set(state, 'unknown', chk.text)
        return
    if chk.firing is False:
        state.fire_since = None
        if state.hold_until or state.escalated_at:
            if state.escalated_at:
                event(rule.code, 'fixed', observation=chk.text, result='The symptom went away without further help.')
            state.hold_until = state.escalated_at = None
            resolve_notice(rule.code)
        if not state.verify_due and not state.verify:
            if rule.code not in ('R3',):
                _expire_open_problem_notice(rule)
        if state.verify_due or state.verify:
            _set(state, 'acting', 'It looks fixed; checking again shortly to be sure.')
        else:
            _set(state, 'ok', chk.text)
        return
    if state.fire_since is None:
        state.fire_since = ctx.now
    seen = (ctx.now - state.fire_since).total_seconds()
    if stand:
        _set(state, 'standing_down', f'{chk.text} The watchdog stands aside while {stand}.')
        return
    if seen < rule.confirm:
        _set(state, 'watching', f'{chk.text} Seen for {int(seen)} seconds; acting after {rule.confirm} seconds.')
        return
    if not rule.host_action and not rule.act:  # a notice-only rule
        _set(state, 'problem', chk.text)
        notice(rule.code, 'warning', rule.notice_title or rule.title, chk.text)
        if not state.escalated_at:
            event(rule.code, 'problem', observation=chk.text, result='Notice raised; the watchdog changes nothing for this.')
            state.escalated_at = ctx.now
        return
    blocked = _gate(rule, state, ctx)
    if blocked:
        _set(state, *blocked)
        return
    if not _act(rule, state, ctx, chk):
        return


def _expire_open_problem_notice(rule):
    """A symptom that went away on its own closes the warning the watchdog opened for it (a settled \"fixed\" notice is left to expire)."""
    try:
        from cveFeed.models import AdminAlert
        AdminAlert.objects.filter(code='watchdog_' + rule.code.lower(), resolved_at__isnull=True, severity__in=('warning', 'critical')).update(resolved_at=timezone.now())
    except Exception:  # noqa: BLE001
        pass


def _alarm(signum, frame):
    raise TickTimeout()


def tick(now=None, probes=None, limit=TICK_SECONDS, alarm=True):
    """One pass. Returns a dict (what it did) and never raises, whatever hangs or fails; ends within ``limit`` seconds (``alarm`` uses SIGALRM, which only works
    in the main thread; ``scripts/watchdog.sh`` and the command's own timer are the hard bounds around a call that blocks in C)."""
    started = time.time()
    now = now or timezone.now()
    out = {'ok': True, 'acted': [], 'skipped': ''}
    armed = False
    if alarm:
        try:
            signal.signal(signal.SIGALRM, _alarm)
            signal.setitimer(signal.ITIMER_REAL, limit)
            armed = True
        except ValueError:  # not the main thread
            armed = False
    try:
        return _tick(now, probes, out)
    except TickTimeout:
        out.update(ok=False, skipped=f'the tick took longer than {limit} seconds and stopped itself')
        logger.warning('watchdog: tick stopped itself after %s seconds', limit)
    except Exception:  # noqa: BLE001
        logger.warning('watchdog: tick failed', exc_info=True)
        out.update(ok=False, skipped='the tick failed (see the web log)')
    finally:
        if armed:
            signal.setitimer(signal.ITIMER_REAL, 0)
        out['seconds'] = round(time.time() - started, 2)
    return out


def _tick(now, probes, out):
    states = _states()
    all_state = states[ALL]
    all_state.last_tick_at = now
    if killed() or all_state.enabled is False:
        for rule in RULES:
            _set(states[rule.code], 'off', 'Switched off.' + (' (CVENGINE_WATCHDOG=0)' if killed() else ''))
            states[rule.code].save()
        all_state.save()
        out['skipped'] = 'switched off'
        return out
    snap = snapshot.collect(probes)
    ctx = Ctx(now, snap, states, probes)
    stand = _stand_down_reason(ctx)
    try:
        _process_host_result(ctx)
    except Exception:  # noqa: BLE001
        logger.warning('watchdog: could not read the host answer', exc_info=True)
    for rule in RULES:
        before = dict(states[rule.code].verify or {})
        try:
            _process_rule(rule, ctx, stand)
        except Exception:  # noqa: BLE001 - one rule failing never stops the others
            logger.warning('watchdog %s failed', rule.code, exc_info=True)
            _set(states[rule.code], 'unknown', 'The rule failed to run (see the web log).')
        if (states[rule.code].verify or {}) != before and states[rule.code].verify:
            out['acted'].append(rule.code)
        states[rule.code].save()
    snap['stand_down'] = stand
    all_state.data = {**(all_state.data or {}), 'snapshot': json.loads(snapshot.dumps(snap))}
    all_state.status, all_state.status_text = 'ok', 'Ticking.'
    all_state.save()
    try:
        client = probes.redis() if probes else snapshot.Probes().redis()
        client.set('cvengine:watchdog:snapshot', snapshot.dumps(snap), ex=300)
    except Exception:  # noqa: BLE001
        pass
    try:
        expire_settled(now)
        if now.minute % 10 == 0 and now.second < 30:
            prune_events(now)
    except Exception:  # noqa: BLE001
        logger.debug('watchdog: housekeeping failed', exc_info=True)
    out['snapshot_seconds'] = snap.get('seconds')
    return out


# --- what the Health tab shows ---------------------------------------------------------------------------------------------------

TICK_STALE_SECONDS = 150


def status_color(status):
    return {'ok': 'green', 'watching': 'amber', 'acting': 'amber', 'standing_down': 'amber', 'unknown': 'amber', 'held': 'amber', 'problem': 'red', 'off': 'grey'}.get(status, 'amber')


def view(now=None):
    """The payload of the Health tab panel: state per rule, the last 20 actions, what the watchdog changed and still holds."""
    from cveFeed.models import WatchdogEvent, WatchdogState
    now = now or timezone.now()
    rows = {s.rule: s for s in WatchdogState.objects.all()}
    all_row = rows.get(ALL)
    tick_age = int((now - all_row.last_tick_at).total_seconds()) if all_row and all_row.last_tick_at else None
    running = tick_age is not None and tick_age <= TICK_STALE_SECONDS
    rules = []
    for rule in RULES:
        s = rows.get(rule.code)
        status = s.status if s else 'unknown'
        text = s.status_text if s else 'Not run yet.'
        held = ((s.data or {}).get('override') if s and rule.code == 'R3' else None)
        if held:
            text = f'Held by {held["env_name"]} in .env, raised to {held["value"]} by the watchdog.'
            status = 'watching' if status == 'ok' else status
        if not running and (s is None or s.enabled) and status != 'off':
            status, text = 'unknown', 'The watchdog is not ticking, so this is not known.'
        rules.append({'code': rule.code, 'title': rule.title, 'does': rule.does, 'status': status, 'color': status_color(status), 'text': text,
                      'enabled': True if s is None else s.enabled, 'last_action_at': s.last_action_at.isoformat() if s and s.last_action_at else None,
                      'hold_until': s.hold_until.isoformat() if s and s.hold_until and s.hold_until > now else None})
    changes = []
    r3 = rows.get('R3')
    o = ((r3.data or {}).get('override') if r3 else None)
    if o:
        changes.append({'rule': 'R3', 'what': f'Hosts assessed at once: held by {o["env_name"]} in .env, raised to {o["value"]} by the watchdog.', 'since': o['at'],
                        'undo': f'Set {o["env_name"]} to 8 or remove it in .env (the watchdog then lets go), or save your own value in Settings.'})
    r7 = rows.get('R7')
    if r7 and (r7.data or {}).get('paused_at'):
        changes.append({'rule': 'R7', 'what': f'The automatic starting of work is paused ({r7.data.get("paused_for")}).', 'since': r7.data['paused_at'],
                        'undo': 'It resumes by itself when disk and memory have room; or resume scanning on the Scanners page.'})
    events = [{'id': e.id, 'at': e.at.isoformat(), 'rule': e.rule, 'level': e.level, 'observation': e.observation, 'action': e.action, 'result': e.result}
              for e in WatchdogEvent.objects.all()[:20]]
    return {'enabled': True if all_row is None else all_row.enabled, 'env_off': killed(), 'running': running, 'tick_age_seconds': tick_age,
            'rules': rules, 'changes': changes, 'events': events,
            'snapshot': {k: v for k, v in ((all_row.data or {}).get('snapshot') or {}).items() if k in ('at', 'seconds', 'stand_down', 'errors')} if all_row else {}}


def set_enabled(rule, value, actor):
    """The switches: ``rule`` None is the whole watchdog (the ``Watchdog`` instance setting), else one rule's code."""
    from cveFeed.admin_api import audit
    from cveFeed.models import WatchdogState
    code = ALL if rule in (None, '', ALL) else rule
    if code != ALL and code not in BY_CODE:
        raise ValueError('unknown rule')
    state, _ = WatchdogState.objects.get_or_create(rule=code)
    if state.enabled != bool(value):
        state.enabled = bool(value)
        state.save(update_fields=['enabled', 'updated_at'])
        audit(actor, 'watchdog.' + ('on' if value else 'off'), code)
        event(code if code != ALL else 'watchdog', 'info', result=f'Switched {"on" if value else "off"} by {actor.username}.')
    return state.enabled
