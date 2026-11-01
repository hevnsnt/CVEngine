"""The auto-tuner's rules, as pure functions over plain numbers (no database, no Redis, no clock of their own), so every rule is tested on
synthetic machines and measurement histories (tests/test_autotune.py). ``cveFeed.autotune`` reads the facts, the measurements and the history
and acts on what these return; ``cveFeed.autotune_signals`` takes the measurements.

**Aim high, then scale back.** The deterministic controller is the safety envelope and works without any AI provider:

1. ``size_for`` works out, from what this machine really has (CPU cores, the scanning container's memory budget and what one run of each
   scanner kind really peaks at, Postgres ``max_connections`` and the connections in use, free disk, the live Sentinels and their slots, and how
   big the instance is), an ambitious but sensible **target** for every tunable setting: the most the hardware and the headroom rules say is
   reasonable, never outside the setting's auto-tuning range. A 4 GB box gets far less than a 64 GB one; two Sentinels with nine slots get a
   discovery pool that keeps them busy (twice their slots plus headroom), not the page's maximum. A fact nobody reported yet is replaced by the
   setting's documented optimistic value (``auto_optimistic`` in the registry), never by the minimum: the memory gate keeps holding work back
   meanwhile.
2. **Aim high**: on its first decision after each restart or update, every setting goes straight to that target (lower than the target only
   while the level that last caused trouble is remembered, below).
3. **Scale back on evidence, at once**: memory pressure or a memory kill, scanner time-outs and kills, the database above ``DB_PRESSURE`` of its
   connections, a CPU overload, a worker that stopped answering, Sentinel waits that time out and run locally, runs of a kind that wait with
   nothing of the kind running. A back-off is fast (``backoff``: a quarter to a half, at least two steps), needs no cooldown, and is then
   held for ``BACKOFF_HOLD`` before another one. The level that caused the trouble is remembered for ``BAD_MEMORY_SECONDS``: nothing goes back
   up to it before that.
4. **Probe up slowly**: one step, only after ``PROBE_HEALTHY_SECONDS`` without any trouble for that setting, with work waiting and room to spare
   in the last ``HEALTHY_SAMPLES`` measurements, after the probe cooldown since the setting's last change, at most ``DAILY_PROBES`` a day, and
   never above the target or the remembered bad level. The thresholds that allow a probe are far from the ones that force a back-off
   (hysteresis).
5. A scanner kind above what the memory budget holds at its real peak is brought down to that at once (a hard cap).

The AI advisor's answer is untrusted: ``validate_advice`` keeps only a number for a setting it was offered, inside the range the controller
gives for that setting right now (from one step down up to the controller's own target).
"""
import json
import math
import re
from collections import namedtuple

HEALTHY_SAMPLES = 3            # measurements in a row that must show queued work and room before an upward probe
PROBE_HEALTHY_SECONDS = 2 * 3600  # an upward probe needs this long without trouble for the setting (measured since the last restart)
BACKOFF_HOLD = 20 * 60         # after a back-off, the next back-off of the same setting waits this long (the first one never waits)
BAD_MEMORY_SECONDS = 24 * 3600  # a level that caused trouble is not reached again for this long
DAILY_PROBES = 2               # at most this many upward probes per setting per 24 hours (a back-off is never limited)
MEMORY_FREE_RAISE = 0.35       # a probe needs at least this share of the scanning container's memory free
MEMORY_FREE_PRESSURE = 0.10    # under this share free is pressure
DB_RAISE = 0.60                # a probe needs the database below this share of its connections
DB_PRESSURE = 0.80             # above this share is pressure
DB_TARGET = 0.70               # the discovery pool is sized to keep the database under this share
LOAD_RAISE = 1.0               # one-minute load per CPU under which a probe is allowed
LOAD_PRESSURE = 2.0            # one-minute load per CPU above which (in two measurements in a row) is pressure
CAPACITY_FAILURES = 3          # failures of one scanner kind that point at load (timeouts, out of memory, exit -9) in one interval
SENTINEL_TROUBLE = 2           # Sentinel waits that timed out or ran locally in one interval (or one in each of two) that are trouble
BACKLOG_SECONDS = 1800         # assessment work older than this is a backlog
SMALL_INSTANCE = 100           # hosts plus targets under this: a small instance, sized modestly
LOW_DISK_PERCENT = 10          # under this share of free disk, no target is above the optimistic value

# key: the setting's key. kind: what it is (``heavy:<scanner kind>``, ``discovery``, ``batch``, ``depth``, ``stage``, ``work_gap``,
# ``refresh_gap``). low/high: the auto-tuning range. step: one step. sense: ``more`` (a higher number does more at once) or ``gap`` (a higher
# number waits longer between runs, so does less). optimistic: the target when the facts it is sized from are not known.
Setting = namedtuple('Setting', 'key kind label low high step sense optimistic', defaults=(None,))

# CPU cores one run of a scanner kind keeps busy (nmap and nuclei probe in parallel; route probes and testssl mostly wait on the network).
CORES_PER_RUN = {'bbot-deep': 2, 'bbot-standard': 1, 'bbot-passive': 0.5, 'nuclei': 2, 'nuclei-light': 1, 'nmap': 1, 'route-probe': 0.25,
                 'wpscan': 1, 'testssl': 0.5, 'screenshot': 1}


def _frac(part, whole):
    return None if part is None or not whole else part / whole


def _get(sample, *path, default=None):
    value = sample
    for name in path:
        if not isinstance(value, dict):
            return default
        value = value.get(name)
    return default if value is None else value


def _clamp(setting, value):
    return max(setting.low, min(setting.high, int(value)))


def towards(setting, value, direction):
    """The number one step from ``value`` in ``direction`` (``more`` or ``less`` work), held to the setting's auto-tuning range, or ``value``
    itself when that range leaves no room in that direction. A value already outside the range only ever moves one step back towards it."""
    up = (direction == 'more') == (setting.sense == 'more')
    if up:
        new = min(setting.high, value + setting.step)
        return new if new > value else value
    new = max(setting.low, value - setting.step)
    return new if new < value else value


def direction_of(setting, old, new):
    if new == old:
        return 'hold'
    return 'more' if (new > old) == (setting.sense == 'more') else 'less'


def backoff(setting, value):
    """A fast back-off: a quarter of the value, at least two steps, never more than half, never past the range. For a gap the wait grows by
    the same rule. Returns ``value`` when there is no room."""
    cut = max(2 * setting.step, math.ceil(value * 0.25))
    if setting.sense == 'more':
        new = max(value - cut, math.ceil(value / 2), setting.low)
        new = min(new, value - setting.step)
        return new if setting.low <= new < value else value
    new = min(value + cut, max(value * 2, value + setting.step), setting.high)
    return new if new > value else value


def memory_cap(kind, sample):
    """The most runs of a scanner kind the memory budget holds at the peak those runs really reached (the learned peak with its margin, or the
    estimate, whichever is larger), or None when no scanning container reported its budget."""
    budget, cost = _get(sample, 'memory', 'budget_mb'), _get(sample, 'memory', 'cost_mb', kind)
    if not budget or not cost:
        return None
    return max(1, int(budget // cost))


# --- sizing: the ambitious but sensible target for this machine ---------------------------------------------------------

def facts_of(sample):
    """The facts ``size_for`` reads, from one measurement (anything not measured is None)."""
    mem, sent, size = sample.get('memory') or {}, sample.get('sentinel') or {}, sample.get('size') or {}
    return {'cores': sample.get('cores'), 'memory_budget_mb': mem.get('budget_mb') if mem.get('reported') else None,
            'memory_total_mb': mem.get('total_mb'), 'cost_mb': mem.get('cost_mb') or {},
            'db_max': _get(sample, 'db', 'max'), 'db_used': _get(sample, 'db', 'used'),
            'sentinel_live': sent.get('live'), 'sentinel_slots': sent.get('slots'),
            'hosts': size.get('hosts'), 'targets': size.get('targets'), 'disk_free_percent': size.get('disk_free_percent'),
            'discovery_ceiling': _get(sample, 'discovery', 'ceiling')}


def size_for(setting, facts, current=None):
    """The target for one setting on this machine, with the reason in a few words: ``(number, why)``. Every formula is here.

    * a scanner kind: as many runs as BOTH the memory budget holds at the kind's real peak (budget // MB per run) and the CPU cores carry
      (cores // ``CORES_PER_RUN``);
    * hosts assessed at once (the discovery pool): every waiting Sentinel task holds a slot, so with Sentinels twice their slots plus four;
      without, two per core; never more than the database can give while staying under ``DB_TARGET`` of ``max_connections`` (each running task
      holds a connection);
    * hosts per assessment batch: with Sentinels twice their slots (at least 8), else the optimistic value (a project with no Sentinel runs one
      host at a time anyway);
    * discovery scans kept running: half a scan per core plus one per three Sentinel slots, never more than the discovery pool;
    * chunks of one stage at once: the Sentinels' slots;
    * hours before a target is rescanned: the shortest wait (1 hour) with four cores or more, else 2;
    * hours before a Sentinel refresh: 3 with four Sentinel slots or more, else 6.

    A small instance (fewer than ``SMALL_INSTANCE`` hosts and targets) keeps the discovery pool at 8 and the conductor at 3; under
    ``LOW_DISK_PERCENT`` of free disk nothing is above its optimistic value. A fact that is not known gives the optimistic value. The result is
    always inside the setting's auto-tuning range."""
    optimistic = setting.optimistic if setting.optimistic is not None else (setting.low if setting.sense == 'gap' else setting.high)
    cores, slots, live = facts.get('cores'), facts.get('sentinel_slots'), facts.get('sentinel_live')
    budget = facts.get('memory_budget_mb')
    scale = None if facts.get('hosts') is None or facts.get('targets') is None else facts['hosts'] + facts['targets']
    small = scale is not None and scale < SMALL_INSTANCE
    kind = setting.kind
    if kind.startswith('heavy:'):
        scanner = kind.split(':', 1)[1]
        cost = (facts.get('cost_mb') or {}).get(scanner)
        parts, why = [], []
        if budget and cost:
            parts.append(budget // cost)
            why.append(f'{budget} MB budget / {cost} MB a run')
        if cores:
            parts.append(int(cores // CORES_PER_RUN.get(scanner, 1)))
            why.append(f'{cores} cores')
        if not parts:
            target, reason = optimistic, 'memory and CPU not reported yet: optimistic value'
        else:
            target, reason = min(parts), ' and '.join(why)
    elif kind == 'discovery':
        if live and slots:
            target, reason = 2 * slots + 4, f'twice the {slots} Sentinel slots plus 4'
        elif cores:
            target, reason = 2 * cores, f'two per core ({cores} cores)'
        else:
            target, reason = optimistic, 'cores and Sentinels not known: optimistic value'
        if small:
            target, reason = min(target, 8), reason + f', small instance ({scale} hosts and targets)'
        db_max, db_used = facts.get('db_max'), facts.get('db_used')
        if db_max and db_used is not None:
            room_left = int(DB_TARGET * db_max) - db_used + (current or 0)
            if room_left < target:
                target, reason = room_left, f'database: {db_used} of {db_max} connections in use'
    elif kind == 'batch':
        if live and slots:
            target, reason = max(8, 2 * slots), f'twice the {slots} Sentinel slots'
        else:
            target, reason = optimistic, 'no live Sentinel: optimistic value'
        if small:
            target, reason = min(target, 8), reason + ', small instance'
    elif kind == 'depth':
        if cores:
            target = max(3, int(cores // 2) + int((slots or 0) // 3))
            reason = f'{cores} cores' + (f' and {slots} Sentinel slots' if slots else '')
        else:
            target, reason = optimistic, 'cores not known: optimistic value'
        if small:
            target, reason = min(target, 3), reason + ', small instance'
        if facts.get('discovery_ceiling'):
            target = min(target, facts['discovery_ceiling'])
    elif kind == 'stage':
        if live and slots:
            target, reason = slots, f'{slots} Sentinel slots'
        else:
            target, reason = optimistic, 'no live Sentinel: optimistic value'
    elif kind == 'work_gap':
        if cores:
            target, reason = (1, f'{cores} cores') if cores >= 4 else (2, f'only {cores} cores')
        else:
            target, reason = optimistic, 'cores not known: optimistic value'
    elif kind == 'refresh_gap':
        if live and slots:
            target, reason = (3, f'{slots} Sentinel slots') if slots >= 4 else (6, f'only {slots} Sentinel slots')
        else:
            target, reason = optimistic, 'no live Sentinel: optimistic value'
    else:
        target, reason = optimistic, 'optimistic value'
    disk = facts.get('disk_free_percent')
    if disk is not None and disk < LOW_DISK_PERCENT:
        modest = min(target, optimistic) if setting.sense == 'more' else max(target, optimistic)
        if modest != target:
            target, reason = modest, f'only {disk:.0f}% disk free'
    return _clamp(setting, target), reason


def sized_for_text(facts):
    """'N cores, X GB memory budget, Y Sentinel slots' for the page (what is not known is left out)."""
    parts = []
    if facts.get('cores'):
        parts.append(f'{facts["cores"]} cores')
    if facts.get('memory_budget_mb'):
        parts.append(f'{facts["memory_budget_mb"] / 1024:.1f} GB memory budget')
    if facts.get('sentinel_live'):
        parts.append(f'{facts.get("sentinel_slots") or 0} Sentinel slots')
    return ', '.join(parts) or 'nothing reported yet (optimistic values)'


# --- trouble: evidence that a setting is too high ------------------------------------------------------------------------

def _memory_pressure(last):
    mem = last.get('memory') or {}
    if mem.get('kills'):
        return f'{mem["kills"]} memory kill(s)'
    if mem.get('free_frac') is not None and mem['free_frac'] < MEMORY_FREE_PRESSURE:
        return f'only {round(mem["free_frac"] * 100)}% memory free'
    return None


def _db_pressure(last):
    db = _frac(_get(last, 'db', 'used'), _get(last, 'db', 'max'))
    return f'database at {round(db * 100)}% of its connections' if db is not None and db > DB_PRESSURE else None


def _load_pressure(samples):
    recent = samples[-2:]
    if len(recent) == 2 and all((s.get('load') or 0) > LOAD_PRESSURE for s in recent):
        return f'CPU load {recent[-1]["load"]:.1f} per core'
    return None


def _worker_silent(samples):
    recent = samples[-2:]
    if len(recent) == 2 and all(_get(s, 'discovery', 'replying') is False for s in recent):
        return 'the discovery worker does not answer'
    return None


def _sentinel_trouble(samples):
    def bad(s):
        return (_get(s, 'sentinel', 'timeouts', default=0) or 0) + (_get(s, 'sentinel', 'fallbacks', default=0) or 0)
    last = bad(samples[-1])
    if last >= SENTINEL_TROUBLE or (last and len(samples) > 1 and bad(samples[-2])):
        return f'{last} Sentinel wait(s) timed out and ran locally'
    return None


def trouble(setting, samples):
    """Why this setting should back off now (a few words with the number), or None. ``samples`` oldest first; the newest decides, the CPU, a
    silent worker and occasional Sentinel time-outs need two in a row."""
    if not samples:
        return None
    last, kind = samples[-1], setting.kind
    if kind.startswith('heavy:'):
        scanner = kind.split(':', 1)[1]
        kills = _get(last, 'memory', 'kills_by_kind', scanner, default=0)
        if kills:
            return f'{kills} {scanner} run(s) stopped for memory'
        failures = _get(last, 'failures', scanner, default=0)
        if failures >= CAPACITY_FAILURES:
            return f'{failures} {scanner} runs failed for load (timeouts, out of memory, killed)'
        running = _get(last, 'memory', 'running', scanner, default=0)
        general = _memory_pressure(last) or _load_pressure(samples)
        if general and running:
            return f'{general} with {scanner} running'
        stuck = samples[-HEALTHY_SAMPLES:]
        if len(stuck) == HEALTHY_SAMPLES and all(_get(s, 'memory', 'waiting', scanner, default=0) >= 0.9 and
                                                 not _get(s, 'memory', 'running', scanner, default=0) for s in stuck):
            return f'{scanner} runs waited for memory for half an hour with none running'
        return None
    checks = {
        'discovery': (lambda: _db_pressure(last), lambda: _worker_silent(samples), lambda: _memory_pressure(last), lambda: _load_pressure(samples)),
        'depth': (lambda: _db_pressure(last), lambda: _worker_silent(samples), lambda: _memory_pressure(last)),
        'batch': (lambda: _sentinel_trouble(samples), lambda: _worker_silent(samples)),
        'stage': (lambda: _sentinel_trouble(samples),),
        'work_gap': (lambda: _memory_pressure(last), lambda: _db_pressure(last), lambda: _load_pressure(samples)),
        'refresh_gap': (lambda: _sentinel_trouble(samples), lambda: _memory_pressure(last)),
    }.get(kind, ())
    for check in checks:
        why = check()
        if why:
            return why
    return None


# --- room and demand: what an upward probe needs ---------------------------------------------------------------------

def room(sample):
    """None when this measurement leaves room for more work, else why not (a few words with the number)."""
    mem = sample.get('memory') or {}
    if not mem.get('reported') or mem.get('free_frac') is None:
        return 'no memory report from the scanning container'
    if mem['free_frac'] < MEMORY_FREE_RAISE:
        return f'{round(mem["free_frac"] * 100)}% memory free (a probe needs {round(MEMORY_FREE_RAISE * 100)}%)'
    if mem.get('kills'):
        return f'{mem["kills"]} memory kill(s)'
    db = _frac(_get(sample, 'db', 'used'), _get(sample, 'db', 'max'))
    if db is None:
        return 'database connections could not be counted'
    if db >= DB_RAISE:
        return f'database at {round(db * 100)}% of its connections (a probe needs under {round(DB_RAISE * 100)}%)'
    load = sample.get('load')
    if load is not None and load >= LOAD_RAISE:
        return f'CPU load {load:.1f} per core'
    return None


def demand(setting, value, sample):
    """None when this measurement shows work that one more step would serve, else why not."""
    kind = setting.kind
    if kind.startswith('heavy:'):
        scanner = kind.split(':', 1)[1]
        waited = _get(sample, 'memory', 'waiting', scanner, default=0)
        running = _get(sample, 'memory', 'running', scanner, default=0)
        if waited < 0.5:
            return f'no {scanner} run waited for its turn'
        if running < value:
            return f'{running} of {value} {scanner} runs in use'
        return None
    disc = sample.get('discovery') or {}
    sent = sample.get('sentinel') or {}
    if kind == 'discovery':
        if not disc.get('replying'):
            return 'the discovery worker does not answer'
        if disc.get('active') is None or not disc.get('ceiling'):
            return 'the discovery worker did not say how busy it is'
        if disc['active'] < disc['ceiling']:
            return f'{disc["active"]} of {disc["ceiling"]} discovery slots busy'
        if not disc.get('queued'):
            return 'nothing waits in the discovery queue'
        db_used, db_max = _get(sample, 'db', 'used'), _get(sample, 'db', 'max')
        if db_used is None or not db_max or (db_used + setting.step) / db_max >= DB_RAISE:
            return 'not enough database connections to spare'
        return None
    if kind == 'depth':
        conductor = sample.get('conductor') or {}
        if conductor.get('state') != 'saturated':
            return 'the work conductor is not held back by its depth'
        if disc.get('active') is None or not disc.get('ceiling') or disc['active'] >= disc['ceiling']:
            return 'the discovery worker has no free slot'
        return None
    if kind == 'work_gap':
        conductor = sample.get('conductor') or {}
        if conductor.get('state') != 'idle':
            return 'the work conductor has targets due'
        if disc.get('active') is None or not disc.get('ceiling') or disc['active'] >= disc['ceiling']:
            return 'the discovery worker has no free slot'
        return None
    live, slots, in_use = sent.get('live') or 0, sent.get('slots') or 0, sent.get('in_use') or 0
    if not live:
        return 'no live Sentinel'
    if sent.get('timeouts') or sent.get('fallbacks'):
        return 'Sentinel waits timed out'
    free = slots - in_use
    if kind == 'stage':
        if free < 2:
            return f'{free} free Sentinel slot(s)'
        if sent.get('queued'):
            return 'Sentinel work is queued'
        if not in_use and not _get(sample, 'assess', 'running'):
            return 'no scan stage is running'
        return None
    if kind == 'batch':
        if free < 1:
            return 'no free Sentinel slot'
        oldest = _get(sample, 'assess', 'oldest_s')
        if not _get(sample, 'assess', 'queued') or oldest is None or oldest < BACKLOG_SECONDS:
            return 'no assessment backlog'
        return None
    if kind == 'refresh_gap':
        if free < 1:
            return 'no free Sentinel slot'
        if sent.get('queued') or _get(sample, 'assess', 'queued'):
            return 'assessment work is queued'
        return None
    return 'not measured'


# --- the decision for one setting ---------------------------------------------------------------------------------------

def _beyond(setting, number, ceiling):
    """Whether ``number`` is past ``ceiling`` in the direction of more work."""
    return number > ceiling if setting.sense == 'more' else number < ceiling


def decide(setting, value, baseline, samples, history, *, now, boot_at, target, target_reason='', cooldown, probe_cooldown,
           hold_until=None, hard_cap=None):
    """What the controller does with one setting now.

    ``value``: the number in effect; ``baseline``: the number without the tuner (environment or default); ``samples``: the measurements since
    the last restart, oldest first; ``history``: this setting's applied changes of the last two days, ``[{'at', 'direction', 'pressure',
    'phase', 'old', 'new'}]``; ``target``: what ``size_for`` says this machine carries; ``hard_cap``: for a scanner kind, what the memory budget
    holds at its real peak (None when not reported); ``hold_until``: a revert asked for no raise before this time. All times in seconds.

    Returns {'direction': 'more'|'less'|None, 'new', 'pressure', 'phase' ('aim_high', 'back_off', 'cap', 'probe' or ''), 'reason',
    'ai_range': (lowest, highest) an AI recommendation may pick or None, 'why_not_raised', 'target', 'ceiling'}. ``new`` is None when
    nothing moves."""
    out = {'direction': None, 'new': None, 'pressure': False, 'phase': '', 'reason': '', 'ai_range': None, 'why_not_raised': '',
           'target': target, 'ceiling': target}
    if not samples:
        out['reason'] = out['why_not_raised'] = 'no measurements yet'
        return out
    ceiling, remembered = target, ''
    bad = sorted((h for h in history if h.get('pressure') and h.get('old') is not None and now - h['at'] < BAD_MEMORY_SECONDS),
                 key=lambda h: h['at'])
    if bad:
        level = bad[-1]['old']
        below = level - setting.step if setting.sense == 'more' else level + setting.step
        if _beyond(setting, ceiling, below):
            ceiling, remembered = _clamp(setting, below), f'{level} caused trouble {int((now - bad[-1]["at"]) // 3600)} h ago'
    out['ceiling'] = ceiling

    why = trouble(setting, samples)
    if why:
        backs = [h['at'] for h in history if h.get('phase') == 'back_off']
        if backs and now - max(backs) < BACKOFF_HOLD:
            out['reason'] = out['why_not_raised'] = f'{why}; backed off {int((now - max(backs)) // 60)} min ago, holding'
            return out
        new = backoff(setting, value)
        if new == value:
            out['reason'] = out['why_not_raised'] = f'{why}; already at the auto-tuning minimum'
            return out
        out.update(direction='less', new=new, pressure=True, phase='back_off', why_not_raised=why,
                   reason=f'{why}: backed off {value} to {new}')
        return out
    if hard_cap is not None and setting.sense == 'more' and value > hard_cap and max(setting.low, hard_cap) < value:
        new = max(setting.low, hard_cap)
        out.update(direction='less', new=new, phase='cap', why_not_raised='the memory budget',
                   reason=f'{value} runs do not fit the memory budget at their real peak: lowered to {new}')
        return out

    held = bool(hold_until and now < hold_until)
    since_boot = [h for h in history if h['at'] >= boot_at]
    if not since_boot and not held:
        if ceiling == value:
            out['reason'] = f'at the target for this machine ({target_reason or target})'
            out['why_not_raised'] = remembered or out['reason']
            return out
        out.update(direction=direction_of(setting, value, ceiling), new=ceiling, phase='aim_high', ai_range=tuple(sorted((value, ceiling))),
                   reason=f'aim high for this machine ({target_reason or "sized"}): {value} to {ceiling}' + (f'; {remembered}' if remembered else ''))
        return out

    last_change = max((h['at'] for h in history), default=None)
    lower = towards(setting, value, 'less')
    less_ok = lower != value and (last_change is None or now - last_change >= cooldown)
    blocker = _probe_blocker(setting, value, samples, history, now=now, ceiling=ceiling, remembered=remembered, held=held,
                             last_change=last_change, probe_cooldown=probe_cooldown, target_reason=target_reason)
    if blocker is None:
        up = towards(setting, value, 'more')
        out.update(direction='more', new=up, phase='probe', ai_range=tuple(sorted((lower if less_ok else value, up))),
                   reason=f'{_evidence(setting, samples[-1])}: probed {value} to {up}')
        return out
    out['why_not_raised'] = out['reason'] = blocker
    if less_ok:
        out['ai_range'] = tuple(sorted((lower, value)))
    return out


def _probe_blocker(setting, value, samples, history, *, now, ceiling, remembered, held, last_change, probe_cooldown, target_reason):
    up = towards(setting, value, 'more')
    if up == value:
        return f'at the auto-tuning {"maximum" if setting.sense == "more" else "minimum"} ({value})'
    if _beyond(setting, up, ceiling):
        return f'below the level that last caused trouble ({remembered})' if remembered else f'at the target for this machine ({target_reason or ceiling})'
    if held:
        return 'a person reverted the last change; no raise for a day'
    if last_change is not None and now - last_change < probe_cooldown:
        return f'changed {int((now - last_change) // 60)} min ago (a probe waits {int(probe_cooldown // 60)} min)'
    if float(samples[0].get('t', now)) > now - PROBE_HEALTHY_SECONDS:
        return f'{int((now - float(samples[0].get("t", now))) // 60)} of {PROBE_HEALTHY_SECONDS // 60} healthy minutes since the restart'
    window = [i for i, s in enumerate(samples) if float(s.get('t', 0)) >= now - PROBE_HEALTHY_SECONDS]
    for i in window:
        why = trouble(setting, samples[:i + 1])
        if why:
            return f'{why} {int((now - float(samples[i]["t"])) // 60)} min ago'
    if sum(1 for h in history if h.get('phase') == 'probe' and now - h['at'] < 86400) >= DAILY_PROBES:
        return f'already probed up {DAILY_PROBES} times in 24 hours'
    for sample in samples[-HEALTHY_SAMPLES:]:
        why = room(sample) or demand(setting, value, sample)
        if why:
            return why
    return None


def _evidence(setting, sample):
    """One sentence of the numbers behind an upward probe."""
    mem = sample.get('memory') or {}
    db = _frac(_get(sample, 'db', 'used'), _get(sample, 'db', 'max'))
    parts = [f'two healthy hours, work waiting in {HEALTHY_SAMPLES} measurements in a row']
    if mem.get('free_frac') is not None:
        parts.append(f'{round(mem["free_frac"] * 100)}% memory free')
    if db is not None:
        parts.append(f'database {round(db * 100)}% used')
    return ', '.join(parts)


# --- the AI advisor's answer ---------------------------------------------------------------------------------------------

ADVICE_SCHEMA = {
    'type': 'object', 'additionalProperties': False, 'required': ['recommendations'],
    'properties': {'recommendations': {'type': 'array', 'maxItems': 40, 'items': {
        'type': 'object', 'additionalProperties': False, 'required': ['setting', 'value', 'reason'],
        'properties': {'setting': {'type': 'string'}, 'value': {'type': 'integer'}, 'reason': {'type': 'string'}}}}},
}
MAX_RECOMMENDATIONS = 40
_FENCE = re.compile(r'^\s*```(?:json)?\s*|\s*```\s*$', re.I)


def validate_advice(reply, offered, clean=None):
    """Keep what the controller's envelope allows from the AI advisor's reply. ``offered``: {key: {'setting': Setting, 'value': number in effect,
    'range': (lowest, highest) the controller allows now}} (from one step down up to the controller's own target, the memory cap included).
    Returns ({key: {'value', 'direction', 'reason'}}, [(key or '?', why it was refused)], error or ''). A reply that is not the JSON asked for is refused whole (``error``); each recommendation
    is then judged on its own, so one bad entry does not throw away the good ones. A reason is model text: it is cleaned (no control characters,
    one line, 200 characters) and only ever shown as text."""
    if clean is None:
        def clean(value, limit):
            return re.sub(r'\s+', ' ', re.sub('[\x00-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069]', ' ', str(value))).strip()[:limit]
    try:
        data = json.loads(_FENCE.sub('', str(reply or '')))
    except (TypeError, ValueError, RecursionError):
        return {}, [], 'the reply was not JSON'
    if not isinstance(data, dict) or set(data) != {'recommendations'} or not isinstance(data['recommendations'], list):
        return {}, [], 'the reply was not {"recommendations": [...]}'
    items = data['recommendations']
    if len(items) > MAX_RECOMMENDATIONS:
        return {}, [], f'the reply had more than {MAX_RECOMMENDATIONS} recommendations'
    accepted, refused = {}, []
    for item in items:
        if not isinstance(item, dict) or set(item) != {'setting', 'value', 'reason'}:
            refused.append(('?', 'not {setting, value, reason}'))
            continue
        key, value, reason = item['setting'], item['value'], item['reason']
        if not isinstance(key, str) or key not in offered:
            refused.append(('?', 'names a setting that was not offered'))
            continue
        if key in accepted or key in {k for k, _ in refused}:
            refused.append((key, 'named twice'))
            continue
        if isinstance(value, bool) or not isinstance(value, int):
            refused.append((key, 'the value is not a whole number'))
            continue
        if not isinstance(reason, str):
            refused.append((key, 'the reason is not text'))
            continue
        entry = offered[key]
        setting, current = entry['setting'], entry['value']
        lowest, highest = entry['range']
        if not lowest <= value <= highest:
            refused.append((key, f'outside what the controller allows now ({lowest} to {highest})'))
            continue
        direction = direction_of(setting, current, value)
        accepted[key] = {'value': value, 'direction': direction, 'reason': clean(reason, 200) or 'AI advisor recommendation'}
    return accepted, refused, ''
