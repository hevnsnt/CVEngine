"""The verdicts of the maintainer's three checks: ``memory``, ``queue_starvation`` and ``sentinel_claims_refused`` (docs/AI-REVIEWER.md), and the corrected
reason of ``sentinel_waiting``. ``cveFeed.reviewer.ops_checks`` gathers the numbers (``system.signals`` of the status, ``agentapi.maintainer_signals``, and a few
counts from the database) and each function here turns them into ``{state, title, detail, facts}``; nothing here reads a source or changes anything.

The rules every verdict keeps:

* ``unknown`` is a state of its own: a signal that is missing, damaged or stale gives no verdict, never ``ok`` and never an alarm. A check made of several
  parts judges the parts it could read and lists the others in ``facts['not_read']``; one with nothing read is ``unknown``.
* The thresholds are the named constants below, in one place, and the numbers they were compared with are in the facts.
* The text says what is wrong, on what, and the one thing to do, in plain words. A fact the signals do not give is not guessed.
"""
import time

# memory
MEMORY_WARN_PERCENT = 85         # a lane or a container using this share of its memory limit is a warning
MEMORY_PROBLEM_PERCENT = 95      # ...and this share, a problem: the kernel's next kill is close
OOM_KILLS_PROBLEM = 1            # kernel oom kills of one container in 24 hours that make it a problem (one kill already lost every task that container held)
LANE_RESTARTS_PROBLEM = 3        # restarts of one worker lane in 24 hours that make it a problem (an update restarts each lane once)
LIMIT_SETTING = {'web': 'WEB_MEM_LIMIT', 'worker': 'CELERY_MEM_LIMIT'}  # the .env key of each container's memory limit (docs/CONFIGURATION.md)

# queue starvation
SCAN_STARVED_SECONDS = 3600      # a queued scan that has waited this long, while host assessments hold the discovery workers, is starved (a scan normally starts within minutes)
SENTINEL_STARVED_SECONDS = 3600  # a Sentinel task kind's oldest queued task must have waited at least this long...
SENTINEL_STARVED_FACTOR = 6      # ...and this many times what that kind normally waits (its median over the last day), when that is known
SENTINEL_BUSY_MINUTES = 30       # "the Sentinels are busy with another kind": a task of another kind was claimed within this many minutes

# claims refused by the server's rate limiter (clock hours: this one and the one before)
CLAIM_REFUSED_WARN = 10          # refused claim calls in the two hours that make a warning
CLAIM_REFUSED_PROBLEM = 100      # ...and a problem (every claim of one Sentinel refused for an hour is hundreds)

# sentinel_waiting: tasks expiring unclaimed while the slots are free
NOT_CLAIMING_SLOT_SHARE = 0.5    # slots in use at or below this share of all slots, while tasks expire unclaimed, means the Sentinels are not claiming work


def unknown(why):
    return {'state': 'unknown', 'title': 'Not known', 'detail': why, 'facts': {}}


def _known(signal):
    return isinstance(signal, dict) and signal.get('state') in ('known', 'partial')


def _num(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def span(seconds):
    """``seconds`` as a plain span (no clock time: the server does not know the reader's time zone)."""
    seconds = int(seconds or 0)
    if seconds < 90:
        return f'{seconds} seconds'
    minutes = seconds // 60
    if minutes < 120:
        return f'{minutes} minutes'
    hours, rest = divmod(minutes, 60)
    return f'{hours} hours' + (f' {rest} minutes' if rest and hours < 10 else '')


def _utc(epoch):
    try:
        return time.strftime('%H:%M UTC', time.gmtime(float(epoch)))
    except (TypeError, ValueError, OverflowError, OSError):
        return 'an unknown time'


def _mb(value):
    return f'{int(round(value)):,} MB'


def _plural(n, word):
    return f'{n} {word}' + ('' if n == 1 else 's')


# --- memory ------------------------------------------------------------------------------------------------------------------------

def memory(signals):
    """Worker lanes and containers against their memory limits, kernel oom kills, lane restarts. ``signals`` is ``system.signals['signals']``."""
    lanes_signal, containers_signal = (signals or {}).get('lanes'), (signals or {}).get('containers')
    issues = []          # (rank, sentence, next step, fact)
    facts = {'lanes': [], 'containers': [], 'not_read': [],
             'thresholds': {'warn_percent': MEMORY_WARN_PERCENT, 'problem_percent': MEMORY_PROBLEM_PERCENT, 'oom_kills_24h': OOM_KILLS_PROBLEM,
                            'lane_restarts_24h': LANE_RESTARTS_PROBLEM}}
    read = 0
    biggest = None
    for entry in (lanes_signal.get('lanes') or [] if _known(lanes_signal) else []):
        if not isinstance(entry, dict) or entry.get('state') != 'known':
            facts['not_read'].append(f"lane {entry.get('lane') if isinstance(entry, dict) else '?'}")
            continue
        read += 1
        rss, pct, restarts = _num(entry.get('rss_mb')), _num(entry.get('percent_of_limit')), entry.get('restarts_24h')
        if rss is not None and (biggest is None or rss > biggest[1]):
            biggest = (entry['lane'], rss)
        row = {'lane': entry['lane'], 'rss_mb': rss, 'limit_mb': _num(entry.get('limit_mb')), 'percent_of_limit': pct, 'restarts_24h': restarts}
        bad = False
        if pct is not None and pct >= MEMORY_WARN_PERCENT:
            bad = True
            issues.append((2 if pct >= MEMORY_PROBLEM_PERCENT else 1,
                           f"the {entry['lane']} worker lane holds {_mb(rss)}, {pct:.0f}% of its {_mb(row['limit_mb'])} limit", 'lane', row))
        if isinstance(restarts, int) and restarts >= LANE_RESTARTS_PROBLEM:
            bad = True
            last = (entry.get('last_restart') or {}).get('at')
            issues.append((2, f"the {entry['lane']} worker lane restarted {restarts} times in 24 hours" + (f' (last at {_utc(last)})' if last else ''), 'restarts', row))
        if bad:
            facts['lanes'].append(row)
    if not _known(lanes_signal):
        facts['not_read'].append('worker lanes')
    for entry in (containers_signal.get('containers') or [] if _known(containers_signal) else []):
        if not isinstance(entry, dict) or entry.get('state') != 'known':
            facts['not_read'].append(f"container {entry.get('role') if isinstance(entry, dict) else '?'}")
            continue
        read += 1
        role, used, limit, pct, kills = entry['role'], _num(entry.get('used_mb')), _num(entry.get('limit_mb')), _num(entry.get('percent_of_limit')), entry.get('oom_kills_24h')
        row = {'role': role, 'used_mb': used, 'limit_mb': limit, 'percent_of_limit': pct, 'oom_kills_24h': kills}
        bad = False
        if isinstance(kills, int) and kills >= OOM_KILLS_PROBLEM:
            bad = True
            issues.append((3, f"the {role} container was killed by the kernel for running out of memory {_plural(kills, 'time')} in 24 hours"
                              + (f" (last at {_utc(entry['last_oom_at'])})" if entry.get('last_oom_at') else ''), 'oom', row))
        if pct is not None and pct >= MEMORY_WARN_PERCENT:
            bad = True
            issues.append((2 if pct >= MEMORY_PROBLEM_PERCENT else 1,
                           f'the {role} container uses {_mb(used)}, {pct:.0f}% of its {_mb(limit)} limit', 'container', row))
        if bad:
            facts['containers'].append(row)
    if not _known(containers_signal):
        facts['not_read'].append('containers')
    facts['not_read'] = sorted(set(facts['not_read']))
    if not read:
        return unknown('no worker lane and no container has a current memory reading, so nothing can be said about memory')
    if not issues:
        return {'state': 'ok', 'title': 'Memory is within its limits', 'detail': '', 'facts': facts}
    issues.sort(key=lambda i: -i[0])
    worst = issues[0]
    state = 'problem' if worst[0] >= 2 else 'warning'
    role = worst[3].get('role')
    if role in LIMIT_SETTING:
        biggest_text = (f", and the largest lane is {biggest[0]} at {_mb(biggest[1])}" if role == 'worker' and biggest else '')
        step = (f"Next step: raise {LIMIT_SETTING[role]} in the .env file (it is {_mb(worst[3]['limit_mb']) if worst[3].get('limit_mb') else 'unset'} now) and run "
                f"`docker compose up -d`; if it keeps filling, `docker compose logs {'celery' if role == 'worker' else 'web'}` shows what ran before the kill{biggest_text}.")
    elif role:
        step = f'Next step: raise the memory limit of the {role} container in the compose file, then run `docker compose up -d`.'
    else:
        step = (f"Next step: `docker compose logs celery` shows what the {worst[3]['lane']} lane was running before each restart; the status page lists the tasks "
                'that left it largest.')
    detail = '; '.join(i[1] for i in issues[:4])
    return {'state': state, 'title': 'A container or worker lane is out of memory' if worst[0] >= 2 else 'Memory is getting close to its limit',
            'detail': detail[0].upper() + detail[1:] + '. ' + step, 'facts': facts}


# --- queue starvation ---------------------------------------------------------------------------------------------------------------

def queue_starvation(signals, work):
    """Work of one kind waiting far longer than its normal while the workers are busy with another kind. ``work`` is what ``ops_checks`` counted:
    ``{paused, scans_queued, assessments_running, assessments_queued, sentinel_kinds: [{kind, queued, oldest_age_seconds, typical_wait_seconds, busy_with}]}``
    (a number it could not count is ``None``)."""
    work = work or {}
    queues = (signals or {}).get('queues')
    oldest = (queues.get('oldest_queued') if _known(queues) else None) or {}
    scan = oldest.get('scan') if isinstance(oldest.get('scan'), dict) and oldest['scan'].get('state') == 'known' else None
    facts = {'not_read': [], 'thresholds': {'scan_seconds': SCAN_STARVED_SECONDS, 'sentinel_seconds': SENTINEL_STARVED_SECONDS, 'sentinel_factor': SENTINEL_STARVED_FACTOR,
                                              'busy_minutes': SENTINEL_BUSY_MINUTES}}
    issues = []
    read = 0
    if work.get('paused'):
        return {'state': 'ok', 'title': 'Scanning is paused', 'detail': '', 'facts': {**facts, 'paused': True}}
    running, queued = work.get('assessments_running'), work.get('assessments_queued')
    if scan is None or running is None or queued is None:
        facts['not_read'].append('scan queue')
    else:
        read += 1
        age = scan.get('age_seconds') if scan.get('queued') else None
        holders = running + queued
        facts.update(scans_queued=work.get('scans_queued'), oldest_scan_age_seconds=age, assessments_running=running, assessments_queued=queued)
        if age is not None and age >= SCAN_STARVED_SECONDS and holders:
            n = work.get('scans_queued')
            issues.append((f"{_plural(n, 'scan') + ' are' if isinstance(n, int) and n != 1 else 'A scan is'} queued, the oldest for {span(age)}, while host assessments hold the "
                           f"discovery workers ({running} running, {queued} queued); a scan normally starts within minutes. Next step: lower Hosts per assessment batch "
                           '(Settings, Scan concurrency) so assessments give way to scans between runs'))
    kinds = work.get('sentinel_kinds')
    if kinds is None:
        facts['not_read'].append('Sentinel queue')
    else:
        read += 1
        starved = []
        for k in kinds:
            floor = SENTINEL_STARVED_SECONDS
            typical = k.get('typical_wait_seconds')
            if typical is not None:
                floor = max(floor, SENTINEL_STARVED_FACTOR * typical)
            if k.get('oldest_age_seconds') is not None and k['oldest_age_seconds'] >= floor and k.get('busy_with'):
                starved.append(k)
        facts['sentinel_kinds'] = [{'kind': k['kind'], 'queued': k.get('queued'), 'oldest_age_seconds': k['oldest_age_seconds'], 'typical_wait_seconds': k.get('typical_wait_seconds'),
                                    'busy_with': k['busy_with']} for k in starved]
        for k in starved[:3]:
            normal = f", normally about {span(k['typical_wait_seconds'])}" if k.get('typical_wait_seconds') is not None else ''
            issues.append(f"{_plural(k.get('queued') or 1, k['kind'] + ' task')} queued, the oldest for {span(k['oldest_age_seconds'])}{normal}, while the Sentinels worked on "
                          f"{', '.join(k['busy_with'][:3])}. Next step: the Sentinels page says which Sentinels offer {k['kind']} and why none takes it")
    facts['not_read'] = sorted(set(facts['not_read']))
    if not read:
        return unknown('neither the scan queue nor the Sentinel queue could be read, so nothing can be said about work waiting')
    if not issues:
        return {'state': 'ok', 'title': 'No work is starved', 'detail': '', 'facts': facts}
    text = '. '.join(i[0].upper() + i[1:] for i in issues[:3])
    return {'state': 'problem', 'title': 'Work of one kind is waiting while workers do another', 'detail': text + '.', 'facts': facts}


# --- claims refused by the rate limiter ----------------------------------------------------------------------------------------------

def claim_refusals(signals):
    """Sentinel claim calls the server's own rate limiter refused in the last two clock hours."""
    signal = (signals or {}).get('claim_refusals')
    if not _known(signal):
        return unknown("the server's count of refused calls could not be read")
    rows = [r for r in signal.get('by') or [] if isinstance(r, dict) and r.get('action') == 'claim']
    total = sum((_num(r.get('this_hour')) or 0) + (_num(r.get('previous_hour')) or 0) for r in rows)
    callers = sorted(rows, key=lambda r: -((_num(r.get('this_hour')) or 0) + (_num(r.get('previous_hour')) or 0)))[:5]
    facts = {'refused_2h': total, 'refused_this_hour': sum(_num(r.get('this_hour')) or 0 for r in rows), 'refused_previous_hour': sum(_num(r.get('previous_hour')) or 0 for r in rows),
             'callers': [{'caller': r.get('caller'), 'sentinel': bool(r.get('sentinel')), 'this_hour': r.get('this_hour'), 'previous_hour': r.get('previous_hour')} for r in callers],
             'thresholds': {'warn': CLAIM_REFUSED_WARN, 'problem': CLAIM_REFUSED_PROBLEM}}
    if total < CLAIM_REFUSED_WARN:
        return {'state': 'ok', 'title': 'Sentinel claims are accepted', 'detail': '', 'facts': facts}
    who = ', '.join(f"{r.get('caller')} ({(_num(r.get('this_hour')) or 0) + (_num(r.get('previous_hour')) or 0)})" for r in callers[:3])
    return {'state': 'problem' if total >= CLAIM_REFUSED_PROBLEM else 'warning', 'title': "The server is refusing Sentinels' claims for work",
            'detail': (f"The server's own rate limiter refused {total} claim calls in the last two clock hours: {who}. Those Sentinels are being turned away although they ask "
                       'for work, so tasks wait or expire unclaimed; this is not a shortage of Sentinels, and adding more will not help. Next step: `docker compose logs web` '
                       'lines saying "rate limit reached" name the counter, and a Sentinel polling faster than the limit, or several Sentinels sharing one user, is the usual cause.'),
            'facts': facts}


def not_claiming(slots, in_use, claimed_2h, refused_2h):
    """For ``sentinel_waiting``: whether tasks that expired unclaimed mean the Sentinels are not claiming (slots are free), and why. ``(flag, reason)``;
    the reason is a sentence ending in a full stop, or '' when nothing says why."""
    if not slots or in_use is None or in_use > NOT_CLAIMING_SLOT_SHARE * slots:
        return False, ''
    if refused_2h:
        return True, (f"The server's rate limiter refused {refused_2h} claim calls in the last two clock hours (the sentinel_claims_refused check names them), "
                      'so the work was offered and turned away.')
    if claimed_2h == 0:
        return True, 'No Sentinel has claimed any task in the last two hours, and the server refused none, so the Sentinels are not asking for work: check on each Sentinel host that the Sentinel is running and can reach this server.'
    return True, ''


# --- what the AI is shown ------------------------------------------------------------------------------------------------------------

BRIEF_MAX_CHARS = 6000


def brief(signals, tuning=None):
    """The signals and auto-tuning's recent decisions as a small dict for the operations snapshot: numbers and names only, no reasons that are not
    the server's own words, at most ``BRIEF_MAX_CHARS`` characters as JSON (the lists are cut first)."""
    import json
    signals = signals if isinstance(signals, dict) else {}

    def pick(d, keys):
        return {k: (d[k][:160] if isinstance(d[k], str) else d[k]) for k in keys if isinstance(d, dict) and d.get(k) is not None}

    out = {'unknown': [], 'lanes': [], 'containers': [], 'queues': {}, 'claim_refusals': {}, 'database': {}, 'redis': {}, 'ai_spend': []}
    for name, signal in signals.items():
        if not _known(signal):
            out['unknown'].append(name)
    lanes = signals.get('lanes')
    if _known(lanes):
        out['lanes'] = [pick(e, ('lane', 'rss_mb', 'limit_mb', 'percent_of_limit', 'restarts_24h')) for e in lanes.get('lanes') or [] if isinstance(e, dict) and e.get('state') == 'known']
    containers = signals.get('containers')
    if _known(containers):
        out['containers'] = [pick(e, ('role', 'used_mb', 'limit_mb', 'percent_of_limit', 'oom_kills_24h')) for e in containers.get('containers') or []
                             if isinstance(e, dict) and e.get('state') == 'known']
    queues = signals.get('queues')
    if _known(queues):
        by = queues.get('by_queue') or {}
        out['queues'] = {'oldest_age_seconds': queues.get('oldest_age_seconds'),
                         'by_queue': {q: pick(v, ('waiting', 'oldest_age_seconds')) for q, v in sorted(by.items(), key=lambda i: -(i[1].get('waiting') or 0))[:6]},
                         'oldest_queued': {k: v.get('age_seconds') for k, v in (queues.get('oldest_queued') or {}).items() if isinstance(v, dict) and v.get('state') == 'known'}}
    refusals = signals.get('claim_refusals')
    if _known(refusals):
        out['claim_refusals'] = {**pick(refusals, ('this_hour', 'previous_hour', 'last_24h')),
                                 'by': [pick(r, ('action', 'caller', 'this_hour', 'previous_hour')) for r in (refusals.get('by') or [])[:5] if isinstance(r, dict)]}
    if _known(signals.get('database')):
        out['database'] = pick(signals['database'], ('size_mb', 'longest_query_seconds'))
    if _known(signals.get('redis')):
        out['redis'] = pick(signals['redis'], ('used_mb', 'limit_mb', 'percent_of_limit', 'evicted_keys'))
    spend = signals.get('ai_spend')
    if _known(spend):
        out['ai_spend'] = [pick(r, ('key', 'used', 'cap', 'percent_of_cap')) for r in spend.get('caps') or [] if isinstance(r, dict) and r.get('state') == 'known']
    result = {'signals': out}
    if isinstance(tuning, dict):
        result['tuning'] = {'mode': tuning.get('effective_mode') or tuning.get('mode'), 'pinned': (tuning.get('pinned') or [])[:15],
                            'last_decisions': [pick(d, ('at', 'setting', 'old_value', 'new_value', 'source', 'action', 'applied', 'reason')) for d in (tuning.get('last_decisions') or [])[:5]
                                               if isinstance(d, dict)]}
    for key in ('lanes', 'containers', 'ai_spend'):
        out[key] = out[key][:8]
    for _ in range(40):
        if len(json.dumps(result, default=str)) <= BRIEF_MAX_CHARS:
            break
        for key in ('ai_spend', 'containers', 'lanes'):
            if len(out[key]) > 1:
                out[key] = out[key][:-1]
                break
        else:
            decisions = (result.get('tuning') or {}).get('last_decisions') or []
            if decisions:
                decisions.pop()
    return result
