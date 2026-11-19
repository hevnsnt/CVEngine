"""A Sentinel's machine, as it reports it, and the numbers auto-tuning sets for that one Sentinel.

**Telemetry.** Every heartbeat of a Sentinel client that knows the field carries ``info.machine`` (the Sentinel client's ``client/machine.py``): the CPUs
it may use (``cpus``) and the host's (``host_cpus``), the host's load average (1, 5, 15 minutes), memory and swap from ``/proc/meminfo``, the container's
memory limit, use and out-of-memory kill count when it runs in one, and how many runs of each task kind the kernel killed for memory in the last hour.
It is data from a machine this server does not control: ``clean_machine`` keeps only well formed numbers inside fixed bounds (anything else is
dropped, never refused: a Sentinel that changes the shape keeps its heartbeat) and only the known task kinds. It is stored in ``Agent.info['machine']``
with the server's own time (``at``); a full report without it (an older client, or one that could not read it) drops the old one, so stale numbers are
never read as current. ``view`` is what the Sentinels page, ``get_sentinel`` and ``list_sentinels`` show, with the derived numbers the auto-tuner reads:
the memory really available (the lower of the host's ``MemAvailable`` and the container's limit less its use) and the load per host CPU (the load
average inside a container is the host's).

**Tuned numbers.** ``Agent.managed_settings['tuned']`` is ``{'max_concurrent': n, 'kinds': {kind: n}, 'hold_until': {key: ISO time}, 'at': ISO time}``:
what auto-tuning (``cveFeed.autotune_sentinels``) chose for this Sentinel. ``tuned_slots`` and ``tuned_kind_caps`` say what applies now: never when the
kill switch is set (``CVENGINE_AUTOTUNE=0``), never for a number an administrator set for this Sentinel (its ``max_concurrent`` setting, its limits'
``max_concurrent``, or a per-kind cap of its capability policy or the instance default: those pin it), and never above the machine's own setting
(``reported_settings['max_concurrent']``: ``CVENGINE_SENTINEL_MAX_CONCURRENT``, or the CPUs it detected), which the server can never raise. The claim
(``sentinel_broker.SentinelEff``) enforces them at once, and the settings reply tells the Sentinel its concurrency (``sentinel_settings.reply``), so a
back-off holds from the next claim and the client stops asking for more.
"""
import math
import time
from datetime import datetime

MAX_MB = 1 << 24          # 16 TB: a bound, not a guess at any real machine
MAX_CPUS = 4096
MAX_LOAD = 100_000.0
MAX_KILLS = 10 ** 6
STALE_SECONDS = 300       # a report older than this (five heartbeats) is not used for tuning: the Sentinel is left as it is


def _int(value, low, high):
    return value if isinstance(value, int) and not isinstance(value, bool) and low <= value <= high else None


def _num(value, low, high):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or isinstance(value, float) and not math.isfinite(value):
        return None
    return round(float(value), 2) if low <= value <= high else None


def clean_machine(raw):
    """``info.machine`` validated and bounded, or ``None`` when it is not an object or carries nothing usable. Never raises."""
    from agentapi.models import SentinelTask
    if not isinstance(raw, dict):
        return None
    out = {'cpus': _int(raw.get('cpus'), 1, MAX_CPUS), 'host_cpus': _int(raw.get('host_cpus'), 1, MAX_CPUS)}
    load = raw.get('load')
    if isinstance(load, list) and len(load) == 3:
        values = [_num(x, 0, MAX_LOAD) for x in load]
        out['load'] = values if None not in values else None
    else:
        out['load'] = None
    total = _int(raw.get('mem_total_mb'), 1, MAX_MB)
    out['mem_total_mb'] = total
    out['mem_available_mb'] = _int(raw.get('mem_available_mb'), 0, total) if total else None
    swap = _int(raw.get('swap_total_mb'), 0, MAX_MB)
    out['swap_total_mb'] = swap
    out['swap_free_mb'] = _int(raw.get('swap_free_mb'), 0, swap) if swap is not None else None
    out['cgroup_limit_mb'] = _int(raw.get('cgroup_limit_mb'), 1, MAX_MB)
    out['cgroup_used_mb'] = _int(raw.get('cgroup_used_mb'), 0, MAX_MB)
    out['cgroup_oom_kills'] = _int(raw.get('cgroup_oom_kills'), 0, 10 ** 9)
    kills = raw.get('oom_kills_1h')
    out['oom_kills_1h'] = {}
    if isinstance(kills, dict):
        for kind, n in list(kills.items())[:len(SentinelTask.KINDS)]:
            n = _int(n, 0, MAX_KILLS)
            if isinstance(kind, str) and kind in SentinelTask.KINDS and n:
                out['oom_kills_1h'][kind] = n
    if out['cpus'] is None and out['mem_total_mb'] is None and out['load'] is None:
        return None
    return out


def _age(stamp, now):
    try:
        return max(0, int(now - datetime.fromisoformat(stamp).timestamp()))
    except (TypeError, ValueError):
        return None


def view(agent, now=None):
    """What is shown and tuned from: the stored report and ``{available_mb, total_mb, available_share, load_per_cpu, age_seconds, stale}``, or ``None``
    for a Sentinel that reports no machine (an older client)."""
    raw = (agent.info or {}).get('machine')
    if not isinstance(raw, dict):
        return None
    now = time.time() if now is None else now
    out = {k: raw.get(k) for k in ('cpus', 'host_cpus', 'load', 'mem_total_mb', 'mem_available_mb', 'swap_total_mb', 'swap_free_mb', 'cgroup_limit_mb',
                                   'cgroup_used_mb', 'cgroup_oom_kills')}
    out['oom_kills_1h'] = dict(raw.get('oom_kills_1h') or {})
    total, available = raw.get('mem_total_mb'), raw.get('mem_available_mb')
    limit, used = raw.get('cgroup_limit_mb'), raw.get('cgroup_used_mb')
    if limit:
        total = min(total, limit) if total else limit
        if used is not None:
            room = max(0, limit - used)
            available = min(available, room) if available is not None else room
    out['total_mb'], out['available_mb'] = total, available
    out['available_share'] = round(available / total, 3) if total and available is not None else None
    cpus = raw.get('host_cpus') or raw.get('cpus')
    load = raw.get('load')
    out['load_per_cpu'] = [round(x / cpus, 2) for x in load] if load and cpus else None
    out['at'] = raw.get('at')
    out['age_seconds'] = _age(raw.get('at'), now)
    out['stale'] = out['age_seconds'] is None or out['age_seconds'] > STALE_SECONDS
    return out


# --- the numbers auto-tuning chose for one Sentinel ---------------------------------------------------------------------------------------------------

def tuned(agent):
    """The stored tuned numbers: ``{'max_concurrent': n or None, 'kinds': {kind: n}, 'hold_until': {...}, 'at'}`` (read tolerantly: anything malformed is left out)."""
    from agentapi import agent_broker as broker
    from agentapi.models import SentinelTask
    raw = (agent.managed_settings or {}).get('tuned')
    raw = raw if isinstance(raw, dict) else {}
    kinds = raw.get('kinds') if isinstance(raw.get('kinds'), dict) else {}
    return {'max_concurrent': _int(raw.get('max_concurrent'), 1, broker.MAX_CONCURRENT_CAP),
            'kinds': {k: v for k, v in kinds.items() if k in SentinelTask.KINDS and _int(v, 1, broker.MAX_CONCURRENT_CAP)},
            'hold_until': dict(raw.get('hold_until') or {}) if isinstance(raw.get('hold_until'), dict) else {}, 'at': raw.get('at')}


def local_ceiling(agent):
    """The machine's own concurrency (``CVENGINE_SENTINEL_MAX_CONCURRENT``, else the CPUs it detected), as it reports it: the most auto-tuning may ever give
    it. ``None`` when it does not report one (an older client): its concurrency is then not tuned."""
    from agentapi import agent_broker as broker
    return _int(((agent.reported_settings or {}).get('max_concurrent') or {}).get('value'), 1, broker.MAX_CONCURRENT_CAP)


def slots_pin(agent):
    """Who pins this Sentinel's concurrency, in words, or ``None``: an administrator's ``max_concurrent`` setting for it, or its limits' ``max_concurrent``."""
    entry = (agent.managed_settings or {}).get('max_concurrent')
    if isinstance(entry, dict) and entry.get('value') is not None:
        return f'{entry.get("by") or "an administrator"} (Sentinel settings, {entry["value"]})'
    cap = (agent.limits or {}).get('max_concurrent')
    if cap:
        return f'an administrator (its limits, {cap})'
    return None


def kind_pin(entry):
    """Who pins a kind's cap, from its resolved capability policy entry (``sentinel_policy.resolve``), or ``None``."""
    if entry and entry.get('cap') and entry.get('source') in ('agent', 'instance default'):
        return f'{entry.get("by") or "an administrator"} ({"this Sentinel" if entry["source"] == "agent" else "the instance default"}, {entry["cap"]})'
    return None


def _killed():
    from reNgine import resources
    return resources.autotune_killed()


def tuned_slots(agent):
    """The concurrency auto-tuning set for this Sentinel that applies now, or ``None``: not pinned, not killed, never above the machine's own setting."""
    number = tuned(agent)['max_concurrent']
    if number is None or _killed() or slots_pin(agent):
        return None
    ceiling = local_ceiling(agent)
    return min(number, ceiling) if ceiling else None


def tuned_kind_caps(agent, policy):
    """``{kind: cap}`` auto-tuning set for this Sentinel that apply now: only for a kind no administrator capped (``policy`` is ``sentinel_policy.resolve``)."""
    caps = tuned(agent)['kinds']
    if not caps or _killed():
        return {}
    return {k: v for k, v in caps.items() if not (policy.get(k) or {}).get('cap') and (policy.get(k) or {}).get('mode') != 'deny'}


def tuning_view(agent):
    """What auto-tuning does with this Sentinel, for the Sentinels page and the API: ``{'max_concurrent': the tuned concurrency in force or None,
    'ceiling': the machine's own setting, 'pinned': who pins the concurrency or None, 'kinds': {kind: tuned cap in force}, 'at', 'killed'}``."""
    from agentapi import sentinel_policy
    stored = tuned(agent)
    try:
        kinds = tuned_kind_caps(agent, sentinel_policy.resolve(agent)) if stored['kinds'] else {}
    except Exception:  # noqa: BLE001 - a page line must never fail the row
        kinds = {}
    return {'max_concurrent': tuned_slots(agent), 'ceiling': local_ceiling(agent), 'pinned': slots_pin(agent), 'kinds': kinds, 'at': stored['at'],
            'killed': _killed()}
