"""Auto-tuning of each Sentinel: its concurrency (``max_concurrent``, its slots) and its per-kind slots, from its own machine and its own outcomes.

All scanning runs on Sentinels, so how much one Sentinel takes at once is the number that decides whether its machine copes. The server-side
settings (``cveFeed.autotune``) are sized from the server's own checks; this module sizes every Sentinel from what that Sentinel reports about its
machine (``agentapi.sentinel_machine``: CPUs, load average, memory available, the kernel's out-of-memory kills by kind) and from what the server
saw it do (its tasks that were killed for memory, timed out, finished, and how long they waited).

**The same safety model as the server settings.** One mode for the instance (``AutoTuneSettings.mode``: off, suggest, auto; ``CVENGINE_AUTOTUNE=0``
forces off). A number an administrator set for that Sentinel pins it (its ``max_concurrent`` setting or its limits; a per-kind cap of its capability
policy or of the instance default), and the machine's own setting (``CVENGINE_SENTINEL_MAX_CONCURRENT``, or the CPUs it detected) is a ceiling the
server can never raise. A Sentinel that is offline, or whose report is missing or older than ``sentinel_machine.STALE_SECONDS``, is left as it is.

* **Aim high** is the machine's own number: a Sentinel nobody tuned runs at it, and the tuner only ever takes it lower and brings it back.
* **Back off fast** (``trouble``, ``kind_trouble``): a run killed for memory (the Sentinel's own count by kind, a task the server saw end out of
  memory, or the container's cgroup counting a kill), memory available under ``MEMORY_LOW`` of the machine (or its container), the load average per
  host CPU above ``LOAD_HIGH`` in two measurements in a row (or the five-minute one above it), or ``TIMEOUTS`` tasks timing out in one run. The slots
  back off by a quarter (at least two, at most half, ``autotune_policy.backoff``), a kind that was killed for memory gets a cap of half what it could
  hold. A back-off needs no cooldown and holds ``BACKOFF_HOLD`` before the next one; the level it left is not reached again for ``BAD_MEMORY_SECONDS``.
* **Probe up slowly**: one slot (or one more of a capped kind) after ``PROBE_HEALTHY_SECONDS`` of fresh reports without trouble, with
  ``HEALTHY_SAMPLES`` reports in a row showing room (``MEMORY_RAISE`` available, the load under ``LOAD_RAISE`` per CPU) and demand (every slot, or
  every slot of the kind, held, and work queued), after the raise cooldown, at most ``DAILY_PROBES`` a day per setting, never past the ceiling. A
  kind's cap that reaches the Sentinel's slots is removed.
* **Verify and revert**: a probe (or a number the AI advisor chose) is judged ``VERIFY_SETTLE_SECONDS`` later on that Sentinel's own reports
  (``autotune_policy.verdict`` on ``measure``: a kill or trouble that was not there before, or the tasks it finished per run falling by half, is a
  regression) and a regression is taken back and held for a day. One calm change per Sentinel is unverified at a time.

Every change is a ``TuningDecision`` (``setting`` is ``sentinel:<id>:max_concurrent`` or ``sentinel:<id>:kind:<kind>``, ``layer='sentinel'``) with its
reason, an audit entry and an activity line, and shows in ``get_tuning_status``. The numbers live in ``Agent.managed_settings['tuned']``; the claim enforces
them at once and the Sentinel is told its concurrency in its settings reply (``agentapi.sentinel_machine``).
"""
import logging
from datetime import datetime, timedelta

from cveFeed import autotune_policy as policy

logger = logging.getLogger(__name__)

PREFIX = 'sentinel:'
MEMORY_LOW = 0.10          # under this share of memory available is trouble
MEMORY_RAISE = 0.35        # a probe needs at least this share available
LOAD_HIGH = 2.0            # the load average per host CPU above this (two runs in a row, or the five-minute one) is trouble
LOAD_RAISE = 0.8           # a probe needs the one-minute load per host CPU under this
TIMEOUTS = 3               # tasks of this Sentinel that timed out in one run
OOM_PATTERN = r'out of memory|killed by the system'  # the Sentinel's own words for a run the kernel killed (client.tools.ToolOOMError), and the server's
HEALTHY_SAMPLES = policy.HEALTHY_SAMPLES
PROBE_HEALTHY_SECONDS = policy.PROBE_HEALTHY_SECONDS
BACKOFF_HOLD = policy.BACKOFF_HOLD
BAD_MEMORY_SECONDS = policy.BAD_MEMORY_SECONDS
DAILY_PROBES = policy.DAILY_PROBES
REVERT_HOLD_HOURS = 24
SLOTS_WORDS = "the Sentinel's slots"
MACHINE_WORDS = "its machine's own setting"
# The kinds whose per-kind slots are tuned: the ones a Sentinel's memory decides (client/admission.py weighs them at 300 MB and more), the only ones a
# kill points at. Every other kind shares the Sentinel's slots as before.
TUNED_KINDS = ('nuclei_light', 'nuclei_deep', 'nuclei_targeted', 'web_screenshot', 'bbot_discovery', 'secrets_scan', 'wpscan_thorough')


# --- keys ---------------------------------------------------------------------------------------------------------------

def slots_key(agent_id):
    return f'{PREFIX}{int(agent_id)}:max_concurrent'


def kind_key(agent_id, kind):
    return f'{PREFIX}{int(agent_id)}:kind:{kind}'


def parse_key(key):
    """``(agent_id, None)`` for a concurrency key, ``(agent_id, kind)`` for a per-kind key, or ``None`` for anything else."""
    if not isinstance(key, str) or not key.startswith(PREFIX):
        return None
    parts = key[len(PREFIX):].split(':')
    if not parts[0].isdigit():
        return None
    if parts[1:] == ['max_concurrent']:
        return int(parts[0]), None
    if len(parts) == 3 and parts[1] == 'kind':
        from agentapi.models import SentinelTask
        return (int(parts[0]), parts[2]) if parts[2] in SentinelTask.KINDS else None
    return None


def is_key(key):
    return parse_key(key) is not None


def setting_for(key, ceiling):
    """The ``autotune_policy.Setting`` of a per-Sentinel number (1 to ``ceiling``, one at a time, more is more work), for the shared rules and the advisor."""
    return policy.Setting(key, 'sentinel', key, 1, max(1, ceiling), 1, 'more', max(1, ceiling), None)


# --- the measurements: one row per Sentinel in every auto-tuning sample ----------------------------------------------------------

def collect(now_dt, interval_seconds, queued=0):
    """``{agent id as text: numbers}`` for every active Sentinel (``autotune_signals.sentinels`` stores it in each sample): whether it is live and its report
    fresh, its CPUs and load, its memory available, the kills it counted (``oom_1h`` by kind, ``cg_oom`` the container's), the slots it has and holds (by kind),
    the machine's own ceiling, and over the last interval the tasks it finished, failed for memory (by kind) and timed out, their mean run and wait in seconds.
    Numbers only: no name, no target."""
    from django.db.models import Avg, Count, DurationField, ExpressionWrapper, F, Q

    from agentapi import agent_broker as broker
    from agentapi import sentinel_machine
    from agentapi.models import Agent, SentinelTask
    since = now_dt - timedelta(seconds=interval_seconds)
    agents = list(Agent.objects.filter(kind='scanner', status='active'))
    if not agents:
        return {}
    ids = [a.pk for a in agents]
    held = {}
    for row in SentinelTask.objects.filter(agent_id__in=ids, status__in=('claimed', 'running')).values('agent_id', 'kind').annotate(n=Count('id')):
        held.setdefault(row['agent_id'], {})[row['kind']] = row['n']
    done, run_s = {}, {}
    finished = SentinelTask.objects.filter(agent_id__in=ids, status='done', finished_at__gte=since)
    for row in finished.values('agent_id').annotate(n=Count('id'), run=Avg(ExpressionWrapper(F('finished_at') - F('accepted_at'), output_field=DurationField()))):
        done[row['agent_id']] = row['n']
        run_s[row['agent_id']] = int(row['run'].total_seconds()) if row['run'] is not None else None
    oom = {}
    holder = Q(agent_id__in=ids) | Q(last_holder__in=ids)
    for row in (SentinelTask.objects.filter(holder, status='failed', finished_at__gte=since, error__iregex=OOM_PATTERN)
                .values('agent_id', 'last_holder', 'kind').annotate(n=Count('id'))):
        who = row['agent_id'] or row['last_holder']
        oom.setdefault(who, {})
        oom[who][row['kind']] = oom[who].get(row['kind'], 0) + row['n']
    timeouts = {}
    for row in (SentinelTask.objects.filter(last_holder__in=ids, status__in=('expired', 'failed'), finished_at__gte=since, error__icontains='timed out')
                .values('last_holder').annotate(n=Count('id'))):
        timeouts[row['last_holder']] = row['n']
    wait_s = {}
    for row in (SentinelTask.objects.filter(agent_id__in=ids, claimed_at__gte=since).values('agent_id')
                .annotate(w=Avg(ExpressionWrapper(F('claimed_at') - F('created_at'), output_field=DurationField())))):
        wait_s[row['agent_id']] = int(row['w'].total_seconds()) if row['w'] is not None else None
    out = {}
    now = now_dt.timestamp()
    for a in agents:
        v = sentinel_machine.view(a, now)
        live = bool(a.last_seen and now_dt - a.last_seen <= broker.LIVE_WINDOW)
        slots = min(a.max_concurrent, (a.limits or {}).get('max_concurrent') or a.max_concurrent)
        tuned = sentinel_machine.tuned_slots(a)
        row = {'live': live, 'fresh': bool(live and v and not v['stale']), 'slots': min(slots, tuned) if tuned else slots,
               'ceiling': sentinel_machine.local_ceiling(a), 'held': sum((held.get(a.pk) or {}).values()), 'held_by_kind': held.get(a.pk) or {},
               'done': done.get(a.pk, 0), 'oom_failed': oom.get(a.pk) or {}, 'timeouts': timeouts.get(a.pk, 0), 'run_s': run_s.get(a.pk),
               'wait_s': wait_s.get(a.pk), 'queued': queued}
        if v:
            load, per = v.get('load') or [None, None, None], v.get('load_per_cpu') or [None, None, None]
            row.update(cpus=v.get('cpus'), host_cpus=v.get('host_cpus'), load1=load[0], load5=load[1], load1_per_cpu=per[0], load5_per_cpu=per[1],
                       avail_share=v.get('available_share'), avail_mb=v.get('available_mb'), total_mb=v.get('total_mb'),
                       oom_1h=dict(v.get('oom_kills_1h') or {}), cg_oom=v.get('cgroup_oom_kills'))
        out[str(a.pk)] = row
    return out


def history_of(agent_id, samples):
    """This Sentinel's rows of ``samples`` (oldest first) whose report was fresh, each with the sample's time ``t``."""
    out = []
    for s in samples:
        row = ((s.get('sentinel') or {}).get('machines') or {}).get(str(agent_id))
        if isinstance(row, dict) and row.get('fresh'):
            out.append({**row, 't': float(s.get('t', 0))})
    return out


# --- the rules (pure: plain numbers in, a decision out) --------------------------------------------------------------------

def new_kills(prev, row):
    """``{kind: runs killed for memory since the previous report}`` (``''`` for a kill the container counted with no kind): the tasks the server saw
    fail out of memory in this run, and the growth of the Sentinel's own rolling count (only against a previous report: a count read for the first
    time may be an hour old) and of its cgroup's kill count."""
    out = {k: n for k, n in (row.get('oom_failed') or {}).items() if n}
    if prev:
        for kind, n in (row.get('oom_1h') or {}).items():
            grown = n - (prev.get('oom_1h') or {}).get(kind, 0)
            if grown > 0:
                out[kind] = max(out.get(kind, 0), grown)
        cg, was = row.get('cg_oom'), prev.get('cg_oom')
        if isinstance(cg, int) and isinstance(was, int) and cg > was and not out:
            out[''] = cg - was
    return out


def _kills_text(kills):
    total = sum(kills.values())
    kinds = ', '.join(sorted(k for k in kills if k)) or 'the container'
    return f'{total} run{"" if total == 1 else "s"} killed for memory ({kinds})'


def trouble(rows):
    """Why this Sentinel's slots should back off now (a few words with the number), or ``None``. ``rows`` its fresh reports, oldest first."""
    if not rows:
        return None
    last = rows[-1]
    prev = rows[-2] if len(rows) > 1 else None
    kills = new_kills(prev, last)
    if kills:
        return _kills_text(kills)
    share = last.get('avail_share')
    if share is not None and share < MEMORY_LOW:
        return f'only {round(share * 100)}% of its memory available'
    l1, l5 = last.get('load1_per_cpu'), last.get('load5_per_cpu')
    cpus = last.get('host_cpus') or last.get('cpus')
    if (l5 is not None and l5 > LOAD_HIGH) or (l1 is not None and l1 > LOAD_HIGH and prev and (prev.get('load1_per_cpu') or 0) > LOAD_HIGH):
        return f'load {last.get("load1")} on {cpus} CPUs (more than {LOAD_HIGH:g} per CPU)'
    if (last.get('timeouts') or 0) >= TIMEOUTS:
        return f'{last["timeouts"]} tasks timed out'
    return None


def kind_trouble(kind, rows):
    """Why ``kind``'s slots on this Sentinel should back off now, or ``None``: a run of it killed for memory since the previous report."""
    if not rows:
        return None
    kills = new_kills(rows[-2] if len(rows) > 1 else None, rows[-1])
    n = kills.get(kind)
    return f'{n} {kind} run{"" if n == 1 else "s"} killed for memory' if n else None


def room(row):
    """``None`` when this report leaves room for one more task, else why not."""
    share = row.get('avail_share')
    if share is None:
        return 'its memory is not reported'
    if share < MEMORY_RAISE:
        return f'{round(share * 100)}% of its memory available (a probe needs {round(MEMORY_RAISE * 100)}%)'
    l1 = row.get('load1_per_cpu')
    if l1 is not None and l1 >= LOAD_RAISE:
        return f'load {l1:g} per CPU (a probe needs under {LOAD_RAISE:g})'
    return None


def demand(row, value, kind=None):
    """``None`` when this report shows work one more slot would serve, else why not."""
    if kind is None:
        if (row.get('held') or 0) < value:
            return f'{row.get("held") or 0} of its {value} slots in use'
    elif ((row.get('held_by_kind') or {}).get(kind) or 0) < value:
        return f'{(row.get("held_by_kind") or {}).get(kind) or 0} of {value} {kind} slots in use'
    if not row.get('queued'):
        return 'no Sentinel work is queued'
    return None


def _bad_ceiling(value_ceiling, history, now):
    """The level one short of the newest level that caused trouble in ``BAD_MEMORY_SECONDS``, when lower than ``value_ceiling``: ``(ceiling, text)``."""
    bad = sorted((h for h in history if h.get('pressure') and h.get('old') is not None and now - h['at'] < BAD_MEMORY_SECONDS), key=lambda h: h['at'])
    if not bad:
        return value_ceiling, ''
    below = bad[-1]['old'] - 1
    if below < value_ceiling:
        return max(1, below), f'{bad[-1]["old"]} caused trouble {int((now - bad[-1]["at"]) // 3600)} h ago'
    return value_ceiling, ''


def decide(value, ceiling, rows, history, *, now, probe_cooldown, hold_until=None, kind=None, slots=None):
    """What to do with one per-Sentinel number now. ``value``: the number in force (for a kind, its cap, or ``slots`` when it has none); ``ceiling``: the
    most it may be (the machine's own concurrency, or for a kind the Sentinel's slots); ``rows``: this Sentinel's fresh reports (``history_of``);
    ``history``: this number's applied changes, ``[{'at', 'old', 'new', 'pressure', 'phase'}]``. Returns ``{'direction', 'new', 'phase', 'pressure',
    'reason', 'why_not_raised', 'ai_range'}``; ``new`` is None when nothing moves, and for a kind ``new`` equal to ``slots`` means "no cap"."""
    out = {'direction': None, 'new': None, 'phase': '', 'pressure': False, 'reason': '', 'why_not_raised': '', 'ai_range': None}
    if not rows:
        out['reason'] = out['why_not_raised'] = 'no fresh report from this Sentinel'
        return out
    why = kind_trouble(kind, rows) if kind else trouble(rows)
    if why:
        backs = [h['at'] for h in history if h.get('phase') == 'back_off']
        if backs and now - max(backs) < BACKOFF_HOLD:
            out['reason'] = out['why_not_raised'] = f'{why}; backed off {int((now - max(backs)) // 60)} min ago, holding'
            return out
        new = max(1, value // 2) if kind else policy.backoff(setting_for('x', max(value, ceiling)), value)
        if new >= value:
            out['reason'] = out['why_not_raised'] = f'{why}; already at 1'
            return out
        out.update(direction='less', new=new, phase='back_off', pressure=True, why_not_raised=why, reason=f'{why}: backed off {value} to {new}')
        return out
    if value > ceiling:
        out.update(direction='less', new=ceiling, phase='cap', why_not_raised=f'the most it may have is {ceiling}',
                   reason=f'the most it may have is {ceiling}: lowered {value} to {ceiling}')
        return out
    top, remembered = _bad_ceiling(ceiling, history, now)
    up = value + 1
    blocker = None
    if up > ceiling:
        blocker = f'at {SLOTS_WORDS if kind else MACHINE_WORDS} ({ceiling})'
    elif up > top:
        blocker = f'below the level that last caused trouble ({remembered})'
    elif hold_until and now < hold_until:
        blocker = 'its last change was taken back; no raise for a day'
    elif history and now - max(h['at'] for h in history) < probe_cooldown:
        blocker = f'changed {int((now - max(h["at"] for h in history)) // 60)} min ago (a probe waits {int(probe_cooldown // 60)} min)'
    elif rows[0]['t'] > now - PROBE_HEALTHY_SECONDS:
        blocker = f'{int((now - rows[0]["t"]) // 60)} of {PROBE_HEALTHY_SECONDS // 60} healthy minutes of reports'
    else:
        for i, row in enumerate(rows):
            if row['t'] < now - PROBE_HEALTHY_SECONDS:
                continue
            seen = kind_trouble(kind, rows[:i + 1]) if kind else trouble(rows[:i + 1])
            if seen:
                blocker = f'{seen} {int((now - row["t"]) // 60)} min ago'
                break
        if blocker is None and sum(1 for h in history if h.get('phase') == 'probe' and now - h['at'] < 86400) >= DAILY_PROBES:
            blocker = f'already probed up {DAILY_PROBES} times in 24 hours'
        if blocker is None:
            recent = rows[-HEALTHY_SAMPLES:]
            if len(recent) < HEALTHY_SAMPLES:
                blocker = f'{len(recent)} of {HEALTHY_SAMPLES} reports'
            for row in recent:
                blocker = blocker or room(row) or demand(row, value, kind)
    if blocker:
        out['reason'] = out['why_not_raised'] = blocker
        if value > 1 and not (hold_until and now < hold_until):
            out['ai_range'] = (value - 1, value)
        return out
    last = rows[-1]
    out.update(direction='more', new=up, phase='probe', ai_range=(max(1, value - 1), up),
               reason=(f'two healthy hours with every {"slot of the kind" if kind else "slot"} held and work queued, '
                       f'{round((last.get("avail_share") or 0) * 100)}% memory available, load {last.get("load1_per_cpu")} per CPU: probed {value} to {up}'))
    return out


def measure(rows, kind=None):
    """What a per-Sentinel change is judged by (``autotune_policy.verdict``): the tasks it finished per report (more is better), trouble (1 or 0) and the
    runs killed for memory in ``rows``."""
    if not rows:
        return {'metric': 'sentinel_done', 'better': 'higher', 'value': None, 'trouble': None, 'kills': None, 'oom': None, 'n': 0}
    kills = sum(sum(new_kills(rows[i - 1] if i else None, rows[i]).values()) for i in range(len(rows)))
    bad = any((kind_trouble(kind, rows[:i + 1]) if kind else trouble(rows[:i + 1])) for i in range(len(rows)))
    done = [r.get('done') for r in rows if isinstance(r.get('done'), int)]
    return {'metric': 'sentinel_done', 'better': 'higher', 'value': round(sum(done) / len(done), 3) if done else None, 'trouble': 1 if bad else 0,
            'kills': kills, 'oom': None, 'n': len(rows)}


# --- reading and writing one Sentinel's numbers --------------------------------------------------------------------------

def _now():
    from django.utils import timezone
    return timezone.now()


def _agent(agent_id):
    from agentapi.models import Agent
    return Agent.objects.filter(pk=agent_id, kind='scanner').select_related('token__user').first()


def _label(agent, kind=None):
    from agentapi import sentinel_policy
    return f'{sentinel_policy.label(kind).capitalize()} at once on {agent.name}' if kind else f'Tasks at once on {agent.name}'


def _write(agent_id, kind, number, *, hold_until=None, only_if=None, check_mode=True):
    """Set (``number``) or clear (``None``) one tuned number of one Sentinel under its row's lock. Returns ``(before, True)``, or ``(before, False)`` when,
    checked again under the lock, the mode is no longer Auto, the number is pinned, or (``only_if``) it is not the number expected."""
    from django.db import transaction

    from agentapi import sentinel_machine, sentinel_policy
    from agentapi.models import Agent
    from cveFeed import autotune
    with transaction.atomic():
        agent = Agent.objects.select_for_update().filter(pk=agent_id).first()
        if agent is None:
            return None, False
        stored = sentinel_machine.tuned(agent)
        before = stored['kinds'].get(kind) if kind else stored['max_concurrent']
        if check_mode and autotune.effective_mode() != 'auto':
            return before, False
        if kind and sentinel_machine.kind_pin(sentinel_policy.resolve(agent).get(kind)) or (not kind and sentinel_machine.slots_pin(agent)):
            return before, False
        if only_if is not None and before != only_if[0]:
            return before, False
        raw = dict((agent.managed_settings or {}).get('tuned') or {})
        if kind:
            kinds = dict(stored['kinds'])
            if number is None:
                kinds.pop(kind, None)
            else:
                kinds[kind] = number
            raw['kinds'] = kinds
        else:
            raw['max_concurrent'] = number
        key = kind_key(agent_id, kind) if kind else slots_key(agent_id)
        holds = dict(stored['hold_until'])
        if hold_until is not None:
            holds[key] = hold_until.isoformat()
        raw.update(hold_until=holds, at=_now().isoformat())
        managed = {**(agent.managed_settings or {}), 'tuned': raw}
        Agent.objects.filter(pk=agent_id).update(managed_settings=managed)
    return before, True


def _hold(agent, key):
    from agentapi import sentinel_machine
    raw = sentinel_machine.tuned(agent)['hold_until'].get(key)
    try:
        return datetime.fromisoformat(raw).timestamp() if raw else None
    except ValueError:
        return None


def _history(key, now_dt):
    from cveFeed.models import TuningDecision
    rows = (TuningDecision.objects.filter(setting=key, applied=True, created_at__gte=now_dt - timedelta(days=2))
            .values('created_at', 'old_value', 'new_value', 'pressure', 'phase'))
    return [{'at': r['created_at'].timestamp(), 'pressure': r['pressure'], 'phase': r['phase'], 'old': r['old_value'], 'new': r['new_value']}
            for r in rows if r['old_value'] is not None and r['new_value'] is not None]


def _activity(message, **detail):
    from cveFeed import autotune
    autotune._activity(message, **detail)


def _audit(actor, action, target, **detail):
    from cveFeed import autotune
    autotune._audit(actor, action, target, **detail)


def _decision(**fields):
    from cveFeed.models import TuningDecision
    return TuningDecision.objects.create(**fields)


def apply(agent, kind, old, new, *, ceiling, mode, source, reason, signals, pressure=False, phase='', actor=None, action=None, verify=None, only_if=None,
          hold_until=None):
    """Set one Sentinel's tuned number (mode Auto) and record it: a ``TuningDecision`` (layer ``sentinel``), an audit entry and an activity line. A kind whose
    new cap reaches the Sentinel's slots (``ceiling``) has its cap removed. Returns the decision, or None when nothing was written (``_write``)."""
    key = kind_key(agent.pk, kind) if kind else slots_key(agent.pk)
    store = None if new >= ceiling else new  # at the machine's own setting (or a kind at all the slots): nothing to hold, it follows the machine again
    before, done = _write(agent.pk, kind, store, hold_until=hold_until, only_if=only_if)
    if not done:
        return None
    extra = {}
    if verify:
        extra = {'expected': 'sentinel_done', 'baseline': verify['baseline'], 'verify_at': verify['at'] + timedelta(seconds=policy.VERIFY_SETTLE_SECONDS)}
    label = _label(agent, kind)
    decision = _decision(setting=key, old_value=old, new_value=new, mode=mode, source=source, action=action or ('raise' if new > old else 'lower'),
                         layer='sentinel', old_layer_value=before, applied=True, pressure=pressure, phase=phase, reason=reason[:300],
                         signals={**signals, 'label': label, 'sentinel': agent.name, 'agent_id': agent.pk, 'kind': kind}, actor=actor, **extra)
    who = {'controller': 'Auto-tuning', 'ai': 'Auto-tuning (AI advisor)'}.get(source, getattr(actor, 'username', None) or 'A person')
    _activity(f'{who}: {label} {old} -> {new}. {reason}', setting=key, decision_id=decision.pk)
    _audit(actor, 'autotune.sentinel', f'{agent.name}:{kind or "max_concurrent"}', before=old, after=new, source=source, reason=reason[:300],
           decision_id=decision.pk, agent_id=agent.pk)
    return decision


def recommend(agent, kind, old, new, *, mode, source, reason, signals, pressure=False, phase=''):
    """A recommendation (mode Suggest): the same number still open is kept, another one replaces it."""
    from cveFeed.models import TuningDecision
    key = kind_key(agent.pk, kind) if kind else slots_key(agent.pk)
    open_ = TuningDecision.objects.filter(setting=key, applied=False, resolution='').order_by('-created_at')
    if open_.filter(old_value=old, new_value=new).exists():
        return None
    open_.update(resolution='superseded', resolved_at=_now(), resolved_by='auto-tune')
    return _decision(setting=key, old_value=old, new_value=new, mode=mode, source=source, action='raise' if new > old else 'lower', applied=False,
                     pressure=pressure, phase=phase, reason=reason[:300],
                     signals={**signals, 'label': _label(agent, kind), 'sentinel': agent.name, 'agent_id': agent.pk, 'kind': kind})


# --- one round ---------------------------------------------------------------------------------------------------------

def _plans_for(agent, rows, now_dt, probe_cooldown):
    """``[(kind or None, value, ceiling, plan, why_skipped)]`` for one Sentinel."""
    from agentapi import sentinel_machine, sentinel_policy
    now, out = now_dt.timestamp(), []
    ceiling = sentinel_machine.local_ceiling(agent)
    stored = sentinel_machine.tuned(agent)
    pin = sentinel_machine.slots_pin(agent)
    if pin:
        out.append((None, None, ceiling, None, f'pinned by {pin}'))
        slots = rows[-1]['slots'] if rows else agent.max_concurrent
    elif ceiling is None:
        out.append((None, None, None, None, 'it does not report its own concurrency (an older client)'))
        slots = agent.max_concurrent
    else:
        slots = min(stored['max_concurrent'] or ceiling, ceiling)
        key = slots_key(agent.pk)
        out.append((None, slots, ceiling, decide(slots, ceiling, rows, _history(key, now_dt), now=now, probe_cooldown=probe_cooldown,
                                                hold_until=_hold(agent, key)), ''))
    resolved = sentinel_policy.resolve(agent)
    declared = set(agent.capabilities or [])
    for kind in TUNED_KINDS:
        entry = resolved.get(kind) or {}
        cap = stored['kinds'].get(kind)
        if kind not in declared or entry.get('mode') == 'deny':
            continue
        if sentinel_machine.kind_pin(entry):
            if cap:
                out.append((kind, None, slots, None, f'pinned by {sentinel_machine.kind_pin(entry)}'))
            continue
        key = kind_key(agent.pk, kind)
        value = min(cap or slots, slots)
        history = _history(key, now_dt)
        if cap is None and not kind_trouble(kind, rows):
            continue  # an uncapped kind only gets a number once it was killed for memory
        out.append((kind, value, slots, decide(value, slots, rows, history, now=now, probe_cooldown=probe_cooldown, hold_until=_hold(agent, key),
                                               kind=kind, slots=slots), ''))
    return out


def plan(mode, now_dt, samples):
    """Every live Sentinel's plans for this round, and what the AI advisor may be asked about. Returns ``(plans, offered, summary)``: ``plans`` a list of
    ``{'agent', 'kind', 'value', 'ceiling', 'plan', 'rows'}``, ``offered`` ``{key: offer}`` in the shape ``autotune.ask_advisor`` reads, ``summary`` one
    entry per Sentinel for the round's summary (``get_tuning_status``)."""
    from agentapi import agent_broker as broker
    from agentapi.models import Agent
    from cveFeed import autotune
    plans, offered, summary = [], {}, {}
    if mode == 'off':
        return plans, offered, summary
    probe_cooldown = autotune._cooldowns()[1]
    for agent in Agent.objects.filter(kind='scanner', status='active').select_related('token__user').order_by('pk'):
        entry = {'name': agent.name, 'settings': {}}
        summary[str(agent.pk)] = entry
        live = bool(agent.last_seen and now_dt - agent.last_seen <= broker.LIVE_WINDOW)
        rows = history_of(agent.pk, samples)
        newest = rows[-1] if rows else None
        if not live:
            entry['held'] = 'offline: left as it is'
            continue
        last_row = ((samples[-1].get('sentinel') or {}).get('machines') or {}).get(str(agent.pk)) if samples else None
        if not newest or not (last_row or {}).get('fresh'):
            entry['held'] = 'no fresh machine report (an older client, or its report stopped): left as it is'
            continue
        entry['machine'] = {k: newest.get(k) for k in ('cpus', 'host_cpus', 'load1', 'load1_per_cpu', 'avail_share', 'total_mb', 'held', 'slots', 'ceiling')}
        for kind, value, ceiling, p, skipped in _plans_for(agent, rows, now_dt, probe_cooldown):
            key = kind_key(agent.pk, kind) if kind else slots_key(agent.pk)
            if p is None:
                entry['settings'][key] = {'state': 'pinned' if skipped.startswith('pinned') else 'not tuned', 'why_not_raised': skipped}
                continue
            entry['settings'][key] = {'state': 'managed', 'value': value, 'ceiling': ceiling, 'why_not_raised': p['why_not_raised'] if p['direction'] != 'more' else '',
                                      'controller': p['reason']}
            plans.append({'agent': agent, 'kind': kind, 'value': value, 'ceiling': ceiling, 'plan': p, 'rows': rows})
            if p['ai_range'] and p['ai_range'][0] != p['ai_range'][1]:
                offered[key] = {'setting': setting_for(key, ceiling), 'value': value, 'baseline': ceiling, 'range': p['ai_range'], 'target': ceiling,
                                'controller': p['reason'] or 'hold'}
    return plans, offered, summary


def calm_unverified(agent_id):
    """Whether a calm change of this Sentinel (a probe, an AI number) waits to be judged: one at a time per Sentinel."""
    from cveFeed.models import TuningDecision
    return TuningDecision.objects.filter(setting__startswith=f'{PREFIX}{int(agent_id)}:', applied=True, layer='sentinel', outcome='', verify_at__isnull=False,
                                         pressure=False).exclude(action='revert').exists()


def act(mode, plans, advice, now_dt, summary):
    """Apply (mode Auto) or recommend (Suggest) this round's per-Sentinel plans; an AI advisor number replaces a calm plan. Returns the changes made."""
    changes = []
    gated = set()
    for item in plans:
        agent, kind, value, ceiling, p = item['agent'], item['kind'], item['value'], item['ceiling'], item['plan']
        key = kind_key(agent.pk, kind) if kind else slots_key(agent.pk)
        source, new, reason, phase, pressured = 'controller', p['new'], p['reason'], p['phase'], p['pressure']
        if not pressured and key in advice:
            source, new, reason = 'ai', advice[key]['value'], advice[key]['reason']
            phase = phase if new == p['new'] else ''
        if new is None or new == value:
            continue
        info = summary.get(str(agent.pk), {}).get('settings', {}).get(key, {})
        calm = not pressured and phase not in ('cap',)
        if mode == 'auto' and calm and (agent.pk in gated or calm_unverified(agent.pk)):
            info['why_not_raised'] = 'waiting: an earlier change of this Sentinel is still being verified (one calm change at a time)'
            continue
        signals = {'machine': {k: item['rows'][-1].get(k) for k in ('cpus', 'host_cpus', 'load1', 'load5', 'avail_share', 'avail_mb', 'held', 'slots', 'done',
                                                                    'timeouts', 'oom_failed', 'oom_1h', 'run_s', 'wait_s')}, 'controller': p['reason']}
        if mode == 'auto':
            verify = None
            if calm:
                before = measure(item['rows'][-policy.VERIFY_BEFORE_SAMPLES:], kind)
                before.update(t=item['rows'][-1]['t'], direction='more' if new > value else 'less')
                verify = {'baseline': before, 'at': now_dt}
            decision = apply(agent, kind, value, new, ceiling=ceiling, mode=mode, source=source, reason=reason, signals=signals, pressure=pressured,
                             phase=phase, verify=verify)
        else:
            decision = recommend(agent, kind, value, new, mode=mode, source=source, reason=reason, signals=signals, pressure=pressured, phase=phase)
        if decision is None:
            continue
        if calm:
            gated.add(agent.pk)
        info['value'] = new if mode == 'auto' else value
        changes.append({'setting': key, 'sentinel': agent.name, 'from': value, 'to': new, 'source': source, 'applied': mode == 'auto', 'id': decision.pk})
    return changes


def verify_pending(now_dt, samples):
    """Judge every applied per-Sentinel change whose settling time has passed, on that Sentinel's own reports; a calm change that regressed is taken back
    and the number held for a day. Returns ``[{'id', 'setting', 'outcome', 'detail', 'reverted'}]``."""
    from cveFeed.models import TuningDecision
    now, judged = now_dt.timestamp(), []
    pending = (TuningDecision.objects.filter(applied=True, layer='sentinel', outcome='', verify_at__isnull=False).exclude(action='revert')
               .order_by('created_at', 'pk')[:50])
    for d in pending:
        parsed = parse_key(d.setting)
        base = dict(d.baseline or {})
        since = float(base.get('t') or d.created_at.timestamp())
        rows = [r for r in history_of(parsed[0], samples) if r['t'] > since][:2 * policy.VERIFY_SAMPLES] if parsed else []
        due = policy.verify_due(now, d.verify_at.timestamp(), len(rows))
        if due == 'wait':
            continue
        agent = _agent(parsed[0]) if parsed else None
        if agent is None:
            outcome, detail = 'unknown', 'the Sentinel is gone, so the change was not judged'
        elif due == 'give_up':
            outcome, detail = 'unknown', f'only {len(rows)} fresh report(s) came after the change, so it was not judged'
        else:
            after = measure(rows, parsed[1])
            outcome, detail = policy.verdict(base, after)
            base['after'] = after
        TuningDecision.objects.filter(pk=d.pk).update(outcome=outcome, outcome_detail=detail[:300], verified_at=now_dt, baseline=base)
        reverted = False
        if agent is not None and policy.revert_wanted(outcome, d.phase, d.pressure):
            reverted = _auto_revert(agent, parsed[1], d, detail, now_dt)
        judged.append({'id': d.pk, 'setting': d.setting, 'outcome': outcome, 'detail': detail, 'reverted': reverted})
    return judged


def _auto_revert(agent, kind, d, detail, now_dt):
    from cveFeed.models import TuningDecision
    latest = TuningDecision.objects.filter(setting=d.setting, applied=True).exclude(resolution='reverted').order_by('-created_at', '-pk').first()
    if latest is None or latest.pk != d.pk:
        return False
    _value, ceiling = _current(agent, kind)
    stored = d.new_value if d.new_value < ceiling else None
    done = apply(agent, kind, d.new_value, d.old_value, ceiling=ceiling, mode='auto', source='controller', pressure=True, action='revert', phase='verify',
                 reason=f'verification of the change of {d.created_at.isoformat(timespec="minutes")}: {detail}; put {d.new_value} back to {d.old_value}',
                 signals={'verified_decision': d.pk}, only_if=(stored,), hold_until=now_dt + timedelta(seconds=policy.VERIFY_COOLDOWN_SECONDS))
    if done is None:
        return False
    TuningDecision.objects.filter(pk=d.pk).update(resolution='reverted', resolved_at=now_dt, resolved_by='auto-tune')
    TuningDecision.objects.filter(pk=done.pk).update(outcome='reverted', outcome_detail=f'undid decision {d.pk}: {detail}'[:300], verified_at=now_dt)
    return True


# --- a person (or the API) acting on a per-Sentinel decision -------------------------------------------------------------

def _require(decision):
    from cveFeed.autotune import TuningError
    parsed = parse_key(decision.setting)
    agent = _agent(parsed[0]) if parsed else None
    if agent is None:
        raise TuningError(409, 'this Sentinel no longer exists')
    return agent, parsed[1]


def _current(agent, kind):
    """``(number in force, ceiling)`` of one per-Sentinel number."""
    from agentapi import sentinel_machine, sentinel_policy
    ceiling = sentinel_machine.local_ceiling(agent) or agent.max_concurrent
    stored = sentinel_machine.tuned(agent)
    slots = min(stored['max_concurrent'] or ceiling, ceiling)
    if kind is None:
        return slots, ceiling
    entry = sentinel_policy.resolve(agent).get(kind) or {}
    return min(entry.get('cap') or stored['kinds'].get(kind) or slots, slots), slots


def _set_admin(agent, kind, number, user):
    """A person's number for this Sentinel, as its own setting (it pins it): ``max_concurrent``, or the kind's cap in its capability policy (``None`` clears)."""
    from agentapi import sentinel_policy, sentinel_settings
    if kind is None:
        sentinel_settings.set_managed(agent, {'max_concurrent': number}, user)
        return
    mode = (sentinel_policy.managed_kinds(agent).get(kind) or {}).get('mode') or 'allow'
    sentinel_settings.set_managed(agent, {'kinds': {kind: {'mode': mode, 'max_concurrent': number}}}, user)


def apply_decision(user, decision):
    """A person applies a per-Sentinel recommendation: in mode Auto (and not pinned) it becomes the tuned number, otherwise this Sentinel's own setting (a pin)."""
    from agentapi import sentinel_machine, sentinel_policy
    from cveFeed import autotune
    from cveFeed.autotune import TuningError
    agent, kind = _require(decision)
    current, ceiling = _current(agent, kind)
    if current != decision.old_value:
        raise TuningError(409, f'{_label(agent, kind)} is {current} now, not {decision.old_value}: wait for a new recommendation')
    if decision.new_value is None or not 1 <= decision.new_value <= max(ceiling, 1):
        raise TuningError(409, f'{decision.new_value} is outside what this Sentinel may have (1 to {ceiling})')
    reason = f'applied by {user.username}: {decision.reason}'
    pinned = sentinel_machine.kind_pin(sentinel_policy.resolve(agent).get(kind)) if kind else sentinel_machine.slots_pin(agent)
    done = None
    if autotune.effective_mode() == 'auto' and not pinned:
        done = apply(agent, kind, current, decision.new_value, ceiling=ceiling, mode='auto', source='person', reason=reason, signals=decision.signals or {},
                     actor=user, action='apply')
    if done is None:
        _set_admin(agent, kind, decision.new_value, user)
        done = _decision(setting=decision.setting, old_value=current, new_value=decision.new_value, mode=autotune.effective_mode(), source='person',
                         action='apply', layer='saved', old_layer_value=None, applied=True, reason=reason[:300], signals=decision.signals or {}, actor=user)
        _activity(f'{user.username} applied the auto-tuning recommendation: {_label(agent, kind)} {current} -> {decision.new_value}', setting=decision.setting,
                  decision_id=done.pk)
    type(decision).objects.filter(pk=decision.pk).update(resolution='applied', resolved_at=_now(), resolved_by=user.username)
    _audit(user, 'autotune.apply', decision.setting, decision_id=decision.pk, before=current, after=decision.new_value)
    return done


def revert(user, decision):
    """A person takes back the newest applied change of one per-Sentinel number: the tuned number gets back what it held before (or this Sentinel's own
    setting, for a recommendation a person applied outside Auto), and the tuner does not raise it for ``REVERT_HOLD_HOURS``."""
    from cveFeed.autotune import TuningError
    from cveFeed.models import TuningDecision
    agent, kind = _require(decision)
    latest = TuningDecision.objects.filter(setting=decision.setting, applied=True).exclude(resolution='reverted').order_by('-created_at', '-pk').first()
    if latest is None or latest.pk != decision.pk:
        raise TuningError(409, 'a later change of this setting exists: revert that one first')
    hold = _now() + timedelta(hours=REVERT_HOLD_HOURS)
    if decision.layer == 'sentinel':
        before, done = _write(agent.pk, kind, decision.old_layer_value, hold_until=hold)
        if not done:
            raise TuningError(409, 'auto-tuning is not in Auto mode, or the number is pinned by an administrator now')
        layer = 'sentinel'
    else:
        _set_admin(agent, kind, None, user)
        before, layer = decision.new_value, 'saved'
    record = _decision(setting=decision.setting, old_value=decision.new_value, new_value=decision.old_value, mode=decision.mode, source='person', action='revert',
                       layer=layer, old_layer_value=before, applied=True,
                       reason=f'{user.username} reverted the change of {decision.created_at.isoformat(timespec="minutes")}',
                       signals={'label': _label(agent, kind), 'sentinel': agent.name, 'agent_id': agent.pk, 'kind': kind}, actor=user)
    TuningDecision.objects.filter(pk=decision.pk).update(resolution='reverted', resolved_at=_now(), resolved_by=user.username)
    _activity(f'{user.username} reverted an auto-tuning change: {_label(agent, kind)} back to {decision.old_value}', setting=decision.setting, decision_id=record.pk)
    _audit(user, 'autotune.revert', decision.setting, decision_id=decision.pk, before=decision.new_value, after=decision.old_value)
    return record


def release(user, key):
    """"Let auto-tune manage this" for one Sentinel: the administrator's number for it (its ``max_concurrent`` setting, or the kind's cap in its own
    capability policy) is removed and the same number becomes the tuned one, so nothing jumps. A cap in its limits or in the instance default is changed
    where it was set."""
    from agentapi import sentinel_machine, sentinel_policy
    from cveFeed import autotune
    from cveFeed.autotune import TuningError
    parsed = parse_key(key)
    agent = _agent(parsed[0]) if parsed else None
    if agent is None:
        raise TuningError(400, 'no such Sentinel setting')
    kind = parsed[1]
    if autotune.effective_mode() != 'auto':
        raise TuningError(409, 'auto-tuning is not in Auto mode: turn it on first')
    if kind is None:
        entry = (agent.managed_settings or {}).get('max_concurrent')
        if (agent.limits or {}).get('max_concurrent'):
            raise TuningError(409, f'{_label(agent)} is held by its limits: change them on the Sentinels page')
        if not isinstance(entry, dict) or entry.get('value') is None:
            raise TuningError(409, f'{_label(agent)} is not pinned')
        ceiling = sentinel_machine.local_ceiling(agent) or agent.max_concurrent
        number = min(int(entry['value']), ceiling)
    else:
        entry = sentinel_policy.resolve(agent).get(kind) or {}
        if entry.get('source') != 'agent' or not entry.get('cap'):
            raise TuningError(409, f'{_label(agent, kind)} is not pinned on this Sentinel' + (' (its cap is the instance default: change it there)'
                                                                                             if entry.get('cap') else ''))
        number = int(entry['cap'])
    _set_admin(agent, kind, None, user)
    _before, ok = _write(agent.pk, kind, number)
    done = _decision(setting=key, old_value=number, new_value=number, mode='auto', source='person', action='release', layer='sentinel', old_layer_value=None,
                     applied=True, reason=f'{user.username} let auto-tune manage this setting',
                     signals={'label': _label(agent, kind), 'sentinel': agent.name, 'agent_id': agent.pk, 'kind': kind}, actor=user)
    _activity(f'{user.username} let auto-tuning manage {_label(agent, kind)} (from {number})', setting=key, decision_id=done.pk)
    _audit(user, 'autotune.release', key, value=number)
    return done


def drop_all():
    """Every Sentinel back to its own numbers (auto-tuning left Auto, or was reset). Returns how many Sentinels had tuned numbers."""
    from agentapi.models import Agent
    n = 0
    for agent in Agent.objects.filter(kind='scanner', managed_settings__has_key='tuned'):
        managed = dict(agent.managed_settings or {})
        managed.pop('tuned', None)
        Agent.objects.filter(pk=agent.pk).update(managed_settings=managed)
        n += 1
    return n


def status():
    """Per-Sentinel tuning for ``get_tuning_status``: every active Sentinel, what applies now and what the last round said about it."""
    from agentapi import sentinel_machine
    from agentapi.models import Agent
    from cveFeed import autotune
    last = ((autotune.last_run() or {}).get('sentinels') or {})
    out = []
    for agent in Agent.objects.filter(kind='scanner', status='active').order_by('pk'):
        machine = sentinel_machine.view(agent)
        out.append({'id': agent.pk, 'name': agent.name, 'tuning': sentinel_machine.tuning_view(agent),
                    'machine': {k: (machine or {}).get(k) for k in ('cpus', 'host_cpus', 'load', 'load_per_cpu', 'total_mb', 'available_mb', 'available_share',
                                                                    'oom_kills_1h', 'age_seconds', 'stale')} if machine else None,
                    'last_run': last.get(str(agent.pk))})
    return out


def advisor_numbers(samples):
    """The per-Sentinel numbers the AI advisor reads: ``{agent id: {...}}`` from the newest fresh report of each (numbers only, no name)."""
    out = {}
    newest = ((samples[-1].get('sentinel') or {}).get('machines') or {}) if samples else {}
    for agent_id, row in newest.items():
        if not isinstance(row, dict) or not row.get('fresh'):
            continue
        rows = history_of(agent_id, samples)
        out[agent_id] = {'cpus': row.get('cpus'), 'host_cpus': row.get('host_cpus'), 'load_per_cpu_1m': row.get('load1_per_cpu'),
                         'load_per_cpu_5m': row.get('load5_per_cpu'), 'memory_available_share': row.get('avail_share'), 'memory_mb': row.get('total_mb'),
                         'slots': row.get('slots'), 'machine_ceiling': row.get('ceiling'), 'slots_in_use': row.get('held'),
                         'finished_last_hour': sum(r.get('done') or 0 for r in rows[-6:]),
                         'killed_for_memory_last_hour': sum(sum(new_kills(rows[i - 1] if i else None, rows[i]).values()) for i in range(max(0, len(rows) - 6), len(rows))),
                         'timeouts_last_hour': sum(r.get('timeouts') or 0 for r in rows[-6:]), 'mean_run_seconds': row.get('run_s'),
                         'mean_wait_seconds': row.get('wait_s')}
    return out

