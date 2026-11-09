"""Which scanners run on this server: the built-in scanner, the administrator's own Sentinels, or both.

The same three choices ``install.sh`` asks (``CVENGINE_INSTALL_SENTINELS``: internal, both, external). The web container cannot write ``.env`` or touch Docker, so a
choice is handed to the host the way an update approval is: a one-word file in the application directory that ``scripts/update-watch.sh`` reads
(``.update-sentinels`` rides with an update approval, ``.scanner-plan-wanted`` is a change on its own) and applies with the shared rules in
``scripts/host-fit.sh``. The host answers in ``.scanner-plan-applied.json``; an unattended update that could not ask leaves ``.update-notice.json``.

``decision()`` is what the Update button asks before it starts: when there is a question worth asking (no choice yet, and a small host or Sentinels of the
administrator's own are live) it carries the facts and the three options, one of them recommended. Nothing here ever removes a scanner without an answer.
"""
import json
import os
import re
import time

from django.conf import settings

PLANS = ('internal', 'both', 'external')
SMALL_HOST_KB = 7000000  # the same threshold as scripts/host-fit.sh and install.sh: under it the built-in scanner gets 1g, not the 3g default
SMALL_LIMIT_MB, DEFAULT_LIMIT_MB = 1024, 3072
OFF = ('0', 'false', 'no', 'off')
PENDING_UPDATE = '.update-sentinels'
PENDING_PLAN = '.scanner-plan-wanted'
APPLIED = '.scanner-plan-applied.json'
NOTICE = '.update-notice.json'


class PlanError(Exception):
    pass


def _file(name):
    return os.path.join(settings.BASE_DIR, name)


def host_memory_mb():
    """The host's memory in MB: ``CVENGINE_HOST_MEM_MB`` when set (the tests and rehearsals fake a small host with it), else ``/proc/meminfo``; ``None`` if unknown."""
    raw = os.environ.get('CVENGINE_HOST_MEM_MB', '').strip()
    if raw.isdigit() and int(raw) > 0:
        return int(raw)
    try:
        with open('/proc/meminfo') as f:
            for line in f:
                if line.startswith('MemTotal:'):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def is_small_host(mem_mb):
    return bool(mem_mb) and mem_mb * 1024 < SMALL_HOST_KB


def _limit_mb(raw):
    match = re.fullmatch(r'(\d+)\s*([kmgKMG]?)[bB]?', (raw or '').strip())
    if not match:
        return None
    n, unit = int(match.group(1)), match.group(2).lower()
    return {'': n // (1024 * 1024), 'k': n // 1024, 'm': n, 'g': n * 1024}[unit] or None


def scanner_limit_mb(mem_mb):
    """What the built-in scanner's container may use here: the administrator's own ``SCANNER_MEM_LIMIT``, else the host-size rule."""
    own = _limit_mb(os.environ.get('SCANNER_MEM_LIMIT', ''))
    if own:
        return own
    return SMALL_LIMIT_MB if is_small_host(mem_mb) else DEFAULT_LIMIT_MB


def gb(mb, places=1):
    value = mb / 1024
    return f'{value:.{places}f}'.rstrip('0').rstrip('.') + ' GB' if places else f'{round(value)} GB'


def _pending(name):
    path = _file(name)
    try:
        if os.path.islink(path):
            return ''
        with open(path) as f:
            value = f.readline().strip()
    except OSError:
        return ''
    return value if value in PLANS else ''


def current_plan():
    """What this server runs now, from the settings its processes started with: ``external`` when the built-in scanner is off, ``both`` when
    ``CVENGINE_SENTINEL_PLAN=both``, else ``internal``."""
    if os.environ.get('CVENGINE_BUILTIN_SCANNER', '').strip().lower() in OFF:
        return 'external'
    return 'both' if os.environ.get('CVENGINE_SENTINEL_PLAN', '').strip().lower() == 'both' else 'internal'


def chosen():
    """Whether somebody already chose: either key in ``.env``, or a choice on its way to the host."""
    return bool(os.environ.get('CVENGINE_BUILTIN_SCANNER', '').strip() or os.environ.get('CVENGINE_SENTINEL_PLAN', '').strip()
                or _pending(PENDING_UPDATE) or _pending(PENDING_PLAN))


def externals_live():
    """How many Sentinels of the administrator's own are live: ``agentapi.sentinel_broker.live_externals``, the set the last-resort rule uses."""
    from agentapi import sentinel_broker
    return len(sentinel_broker.live_externals())


def options(live, limit_mb, small, recommended):
    free = gb(limit_mb)
    def label(plan, base, detail):
        return f'{base} (recommended: {detail})' if plan == recommended else (f'{base} ({detail})' if plan == 'external' and live else base)
    return [
        {'value': 'external', 'recommended': recommended == 'external',
         'label': label('external', 'Use my own Sentinels only',
                        f'you have {live} live; frees up to {free}' if live else 'none is live yet')},
        {'value': 'internal', 'recommended': recommended == 'internal',
         'label': label('internal', 'Use the built-in scanner only', f'it uses at most {free} here')},
        {'value': 'both', 'recommended': recommended == 'both',
         'label': label('both', 'Use both', f'you have {live} live Sentinel of your own and the built-in scanner stays as the backup' if live == 1
                        else 'your Sentinels first, the built-in scanner as the backup')},
    ]


def decision():
    """The facts and the question for the Update button and for Settings > Sentinels."""
    mem = host_memory_mb()
    small = is_small_host(mem)
    limit = scanner_limit_mb(mem)
    try:
        live, known = externals_live(), True
    except Exception:  # a check that cannot be made never blocks an update: no question, the updater's automatic default applies
        live, known = 0, False
    done = chosen()
    needs = known and not done and (small or live >= 1)
    recommended = 'external' if live >= 2 else ('both' if live == 1 else 'internal')
    memory_line = (f'This server has {gb(mem)} of memory; the built-in scanner reserves up to {gb(limit)}.' if mem
                   else f'The built-in scanner reserves up to {gb(limit)} of this server\'s memory.')
    return {'needs_choice': needs, 'chosen': done, 'plan': current_plan(), 'recommended': recommended, 'memory_mb': mem, 'small_host': small,
            'scanner_limit_mb': limit, 'externals_live': live, 'externals_known': known, 'memory_line': memory_line,
            'options': options(live, limit, small, recommended)}


def _write(name, text):
    tmp = _file(name + '.tmp')
    with open(tmp, 'w') as f:
        f.write(text)
    os.replace(tmp, _file(name))


def validate(plan):
    if not isinstance(plan, str) or plan not in PLANS:  # exactly one of the three words, nothing normalised
        raise PlanError('the choice must be internal, both or external')
    return plan


def with_update(plan):
    """Hand the choice to the host together with an update approval (``.update-sentinels``: read and removed by the host)."""
    _write(PENDING_UPDATE, validate(plan) + '\n')


def request(plan):
    """Ask the host to apply a choice now, with no update (``.scanner-plan-wanted``)."""
    _write(PENDING_PLAN, validate(plan) + '\n')


def clear_pending():
    for name in (PENDING_UPDATE,):
        try:
            os.remove(_file(name))
        except OSError:
            pass


def _json(name):
    path = _file(name)
    try:
        if os.path.islink(path):
            return None
        with open(path) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def applied():
    """The host's answer to the last change: ``{plan, ok, note, at}`` or ``None``."""
    data = _json(APPLIED)
    if not data or data.get('plan') not in PLANS:
        return None
    return {'plan': data['plan'], 'ok': bool(data.get('ok')), 'note': str(data.get('note') or '')[:200], 'at': data.get('at')}


def notice():
    """What an unattended update left behind when it could not ask: the built-in scanner was kept (never removed without an answer) while the
    administrator has Sentinels of their own. Shown on the Sentinels page and in the update result until somebody chooses."""
    data = _json(NOTICE)
    if not data or data.get('code') != 'scanner_kept' or chosen():
        return None
    limit = str(data.get('limit') or '')
    try:
        n = max(0, int(data.get('externals') or 0))
    except (TypeError, ValueError):
        n = 0
    if not re.fullmatch(r'\d+[kmg]?', limit):
        limit = ''
    kept = f'The built-in scanner was kept at {limit.upper().replace("G", " GB").replace("M", " MB")}' if limit else 'The built-in scanner was kept'
    who = f'You have {n} Sentinel{"s" if n != 1 else ""} of your own' if n else 'You have Sentinels of your own'
    return {'code': 'scanner_kept', 'externals': n, 'limit': limit, 'at': data.get('at'),
            'text': f'{kept}. {who}: switch to Sentinels only in Settings > Sentinels to free the memory.'}


def discovery_pin_notice():
    """The text for a DISCOVERY_CONCURRENCY in the environment that holds the whole instance to a few hosts at a time (``autotune.discovery_pin``), or None."""
    try:
        from cveFeed import autotune
        pin = autotune.discovery_pin()
    except Exception:  # noqa: BLE001 - a notice is never worth a failed page
        return None
    return pin['text'] if pin else None


PICKUP_SECONDS = 45  # the host watcher looks every second or so and starts the apply script within ~20 s; after this a live watcher is applying it, or stuck
STUCK_SECONDS = 600  # a restart of the services takes a minute or two; this long without an answer is something to look at


def asked_at():
    """When the request was written (the mtime of ``.scanner-plan-wanted``, epoch seconds), or ``None``."""
    try:
        path = _file(PENDING_PLAN)
        return None if os.path.islink(path) else os.stat(path).st_mtime
    except OSError:
        return None


def scans_running():
    """How many scans are running now (the host script waits for none, because the server's processes are recreated), or ``None`` if it cannot be told."""
    try:
        from startScan.models import ScanHistory
        return ScanHistory.objects.filter(scan_status=1).count()
    except Exception:  # noqa: BLE001 - a status line is never worth a failed page
        return None


def waiting_on(now=None):
    """What a request that has not been answered is waiting on, in plain words: ``{code, text}``. Only the facts the web container can see: the host
    watcher's heartbeat (``.updater-heartbeat``), an update's phase, the scans running and how long ago the request was written. ``None`` when nothing is waiting."""
    if not _pending(PENDING_PLAN):
        return None
    now = time.time() if now is None else now
    from cveFeed import updater
    beat = updater.host_updater()
    if not beat['alive']:
        heard = (f'The last sign of it was {max(1, beat["age_seconds"] // 60)} minute(s) ago.' if beat['seen']
                 else 'It has never reported in on this server.')
        return {'code': 'host_down', 'text': ('The host helper is not running, so nothing will apply this. ' + heard + ' Start it on the host with '
                                              'scripts/update-watch.sh (the installer sets it up as a service), or run scripts/apply-scanner-plan.sh there by hand.')}
    try:
        building = updater.update_in_progress()
    except Exception:  # noqa: BLE001
        building = False
    if building:
        return {'code': 'update', 'text': 'An update is building and restarting this server. The change is applied by the host once it has finished.'}
    n = scans_running()
    if n:
        return {'code': 'scans', 'scans_running': n,
                'text': f'{n} scan{"s are" if n != 1 else " is"} running. The change is applied when {"they finish" if n != 1 else "it finishes"}, because the server restarts to read it.'}
    at = asked_at()
    age = None if at is None else max(0, now - at)
    if age is None or age <= PICKUP_SECONDS:
        return {'code': 'pickup', 'text': 'The host updater has not picked it up yet. It looks every few seconds.'}
    if age <= STUCK_SECONDS:
        return {'code': 'applying', 'text': 'The host updater has it and is restarting the services, which takes a minute or two.'}
    return {'code': 'stuck', 'text': (f'Still not applied after {int(age // 60)} minutes although the host helper is running. Look at scanner-plan.log in the '
                                      'host\'s update state directory, or run scripts/apply-scanner-plan.sh there by hand.')}


STARTED_AT = time.time()  # when this process started: the environment it reads the running plan from is as old as this


def effective_plan(answer):
    """What runs now. The processes read the plan from their environment when they start, and the host recreates them only when the built-in scanner
    goes on or off, so after a change between ``internal`` and ``both`` the environment is older than the host's answer. An ok answer newer than this
    process is the later fact."""
    if answer and answer['ok'] and isinstance(answer['at'], (int, float)) and answer['at'] >= STARTED_AT:
        return answer['plan']
    return current_plan()


def state():
    waiting = bool(_pending(PENDING_PLAN))
    at = asked_at() if waiting else None
    answer = applied()
    return {**decision(), 'plan': effective_plan(answer), 'applied': answer, 'notice': notice(), 'discovery_pin_notice': discovery_pin_notice(),
            'waiting': waiting, 'pending_plan': _pending(PENDING_PLAN), 'asked_at': at, 'waiting_on': waiting_on() if waiting else None,
            'now': time.time()}
