"""Keep Sentinels on the newest version: when a Sentinel runs a build behind the newest published one, cvENGINE asks it to update.

The verdict is the one ``sentinel_version`` already makes (``behind`` means the newest build is a descendant of the one the Sentinel reports), read from the
cache and never from GitHub while a request is handled. A Sentinel is asked in its heartbeat answer (``sentinel_settings.update_reply``: ``requested`` and,
for these requests, ``target`` and ``reason``; a client that does not know ``target`` ignores it, and the result contract is unchanged). What a Sentinel
does with the request is its own machine's business: the host updater (scripts/update.sh) or, with CVENGINE_SENTINEL_UPDATE_EXIT, the daemon draining
and exiting for a supervisor. The install's own scanner is asked differently: this server writes a request file the host watcher (scripts/update-watch.sh)
turns into scripts/scanner-update.sh, which drains it and swaps the image.

``decide`` is the matrix. A request is made only when ALL of these hold, and every other case has a ``code`` and one plain sentence the Sentinels page shows:

- the instance switch (Settings, Sentinels, "Keep Sentinels on the newest version") is on, and this Sentinel's self-update is not Off (the per-Sentinel opt-out);
- the Sentinel is ``behind``: never a downgrade, never a build GitHub could not compare, never a Sentinel that reports no commit;
- the newest build's result contract is known and the server can run it (``newer`` otherwise: "newer than this server, waiting for the server update");
- no heavy task is running on it (it is asked again at its next heartbeat; the daemon or updater drains what is left before it stops);
- the last request was at least ``MIN_INTERVAL`` ago (6 hours); a request that fails is the backoff itself: the Sentinel is flagged and not asked again until an administrator acts;
- it is not flagged: a Sentinel that did not report a new version within ``grace_minutes`` of a request is flagged with the reason and cvENGINE stops asking
  until an administrator presses Update now (or the Sentinel changes version on its own).

The state lives in ``agent.info['auto_update']`` (written by the server only: ``record_info`` merges a Sentinel's report over it, never replaces it).
Every request and every flag is an audit entry (``sentinel.update_requested``, ``sentinel.update_flagged``).
"""
import json
import logging
import os
import re
from datetime import timedelta

from django.utils import timezone

from agentapi import sentinel_contract, sentinel_version
from agentapi.models import Agent, SentinelTask
from tenancy import audit

logger = logging.getLogger(__name__)

MIN_INTERVAL = timedelta(hours=6)  # at most one request per Sentinel in this time
DEFAULT_GRACE_MINUTES = 90  # the host updater drains for up to 30 minutes, then builds and swaps
HEAVY_KINDS = ('openvas', 'nmap_full', 'nmap_udp', 'wpscan_thorough', 'bbot_discovery', 'nuclei_deep', 'secrets_scan')  # hours, or a long sweep: never interrupted for an update
BUSY = ('claimed', 'running')
HOST_REQUEST_FILE = '.scanner-update-requested'

TEXT = {
    'switched_off': 'Keeping Sentinels on the newest version is turned off in Settings, Sentinels',
    'opted_out': 'Self-update is off for this Sentinel, so cvENGINE does not ask it to update',
    'current': 'Running the newest version',
    'unknown': 'Whether a newer version exists is not known yet',
    'waiting_for_server': 'The newest Sentinel build is newer than this server, waiting for the server update',
    'contract_unknown': 'The newest build has not been read yet, so cvENGINE does not ask for it',
    'busy': 'A long task is running; cvENGINE asks again when it is done',
    'rate_limited': 'Asked recently; the next request is not due yet',
    'host_watcher': 'The host updater of this server is not reporting, so the built-in scanner cannot be asked to update',
    'requested': 'Update requested',
    'flagged': 'Did not come back on a newer version',
    'request': 'An update will be requested at this Sentinel\'s next check-in',
}


def grace_minutes():
    try:
        value = int(os.environ.get('CVENGINE_SENTINEL_UPDATE_GRACE_MINUTES', '').strip())
    except ValueError:
        return DEFAULT_GRACE_MINUTES
    return value if 5 <= value <= 1440 else DEFAULT_GRACE_MINUTES


def _parse(value):
    from django.utils.dateparse import parse_datetime
    try:
        return parse_datetime(value) if isinstance(value, str) else None
    except ValueError:
        return None


def stored(agent):
    """The server's own record for this Sentinel: ``{status, target, from, requested_at, attempts, failures, next_after, flag, host}``."""
    value = (agent.info or {}).get('auto_update')
    return dict(value) if isinstance(value, dict) else {}


def _save(agent, state):
    info = {**(agent.info or {}), 'auto_update': state}
    agent.info = info
    Agent.objects.filter(pk=agent.pk).update(info=info)


def _is_builtin(agent):
    from agentapi import sentinel_broker
    return sentinel_broker.is_builtin(agent)


def busy_with_heavy(agent):
    return SentinelTask.objects.filter(agent=agent, status__in=BUSY, kind__in=HEAVY_KINDS).exists()


def newest_contract_state(latest_contract):
    """``ok`` (the server can run the newest build's contract), ``newer`` (it needs a server update first) or ``unknown`` (not read, or unusable)."""
    if not isinstance(latest_contract, dict):
        return 'unknown'
    wanted, minimum = latest_contract.get('version'), latest_contract.get('min_supported')
    if not isinstance(wanted, int) or not isinstance(minimum, int):
        return 'unknown'
    return 'newer' if wanted > sentinel_contract.version() else 'ok'


def pinned_target(agent):
    """The commit this server pins (``cveFeed.software.SENTINEL_PINS_COMMIT``) as the target of a Sentinel that is told to update but has no newer one named, or
    ``None``: for the built-in scanner (the host watcher moves it), for a Sentinel that already runs the pin, and for one the cached check knows is on the newest
    version or newer. A Sentinel that is ahead of the pin, with no verdict to say so, is named the pin too: its updater never moves backwards (it waits)."""
    from cveFeed import software
    pin = str(software.SENTINEL_PINS_COMMIT or '').lower()
    version = str(((agent.info or {}).get('version')) or '').strip().lower()
    if not re.fullmatch(r'[0-9a-f]{40}', pin) or _is_builtin(agent) or (version and pin.startswith(version)):
        return None
    if sentinel_version.state(agent).get('status') == 'current':
        return None
    return pin


def decide(agent, now=None, verdict=None, keep=None, instance_update=None, check_busy=True):
    """``{action, code, text, target}``: ``action`` is ``request`` (ask now), ``wait`` (a request is out, or one is due later) or ``none``. Reads state and the
    cached verdict only (the one query is whether a heavy task runs, made last, and a page that lists every Sentinel leaves it out with ``check_busy=False``)."""
    from agentapi import sentinel_settings
    now = now or timezone.now()
    keep = sentinel_settings.keep_newest() if keep is None else keep
    verdict = verdict or sentinel_version.state(agent)
    state = stored(agent)

    def out(action, code, **extra):
        return {'action': action, 'code': code, 'text': extra.pop('text', TEXT[code]), 'target': extra.pop('target', None), **extra}

    if not keep:
        return out('none', 'switched_off')
    own = sentinel_settings.explicit(agent).get('self_update') or (instance_update or sentinel_settings.instance_self_update())
    if own == 'off':
        return out('none', 'opted_out')
    status = verdict.get('status')
    if status == 'current':
        return out('none', 'current')
    if status != 'behind':
        return out('none', 'unknown', text=verdict.get('detail') or TEXT['unknown'])
    target = verdict.get('latest_full')
    if state.get('status') == 'failed':
        return out('none', 'flagged', target=target, text=state.get('flag') or TEXT['flagged'])
    if state.get('status') == 'requested' and state.get('target'):
        return out('wait', 'requested', target=state['target'])
    contract = newest_contract_state(verdict.get('latest_contract'))
    if contract == 'newer':
        return out('none', 'waiting_for_server', target=target)
    if contract == 'unknown' or not target:
        return out('none', 'contract_unknown', target=target)
    due = _parse(state.get('next_after'))
    if due and now < due:
        return out('wait', 'rate_limited', target=target, text=f'Asked recently; the next request is due after {due.strftime("%H:%M")} UTC')
    if check_busy and busy_with_heavy(agent):
        return out('wait', 'busy', target=target)
    if check_busy and _is_builtin(agent) and not _host_watcher_alive():
        return out('none', 'host_watcher', target=target)
    return out('request', 'request', target=target)


def _audit(action, agent, **detail):
    audit.record_for_user(None, action, agent.token.user, target=agent.name, agent_id=agent.pk, **detail)


def write_host_request(target, now=None, directory=None):
    """The built-in scanner is updated from this server's host: a request file the watcher (scripts/update-watch.sh) acts on. Written atomically.
    ``False`` when the application directory cannot be written."""
    from cveFeed import updater
    path = updater._file(HOST_REQUEST_FILE) if directory is None else os.path.join(directory, HOST_REQUEST_FILE)
    tmp = path + '.tmp'
    try:
        with open(tmp, 'w') as handle:
            json.dump({'target': target, 'at': (now or timezone.now()).isoformat()}, handle)
        os.replace(tmp, path)
    except OSError:
        return False
    return True


def _host_watcher_alive():
    from cveFeed import updater
    return bool(updater.host_updater().get('alive'))


def request_now(agent, target, reason='newest', now=None, actor=None):
    """Record and send one request (the caller has decided). Returns the stored state."""
    now = now or timezone.now()
    state = stored(agent)
    version = str((agent.info or {}).get('version') or '')
    builtin = _is_builtin(agent)
    attempts = int(state.get('attempts') or 0) + 1
    failures = int(state.get('failures') or 0)
    new = {'status': 'requested', 'target': target, 'from': version, 'requested_at': now.isoformat(), 'attempts': attempts, 'failures': failures,
           'next_after': (now + MIN_INTERVAL).isoformat(), 'flag': '', 'reason': reason, 'host': builtin}
    if builtin:
        if not _host_watcher_alive():
            return None
        write_host_request(target, now)
    else:
        agent.update_requested_at = now
        Agent.objects.filter(pk=agent.pk).update(update_requested_at=now)
    _save(agent, new)
    if actor is None:
        _audit('sentinel.update_requested', agent, version=version, update_to=target, reason=reason, automatic=True, how='host watcher' if builtin else 'heartbeat')
    return new


def _flag(agent, state, now, text):
    state = {**state, 'status': 'failed', 'flag': text, 'failures': int(state.get('failures') or 0) + 1, 'flagged_at': now.isoformat()}
    if agent.update_requested_at:
        agent.update_requested_at = None
        Agent.objects.filter(pk=agent.pk).update(update_requested_at=None)
    _save(agent, state)
    _audit('sentinel.update_flagged', agent, version=(agent.info or {}).get('version'), update_to=state.get('target'), reason=text)
    return state


def settle(agent, now=None):
    """Close or flag an open request: the Sentinel reports another version than the one it was asked from (done), or the grace period passed (flag)."""
    state = stored(agent)
    if state.get('status') not in ('requested', 'failed'):
        return state
    now = now or timezone.now()
    version = str((agent.info or {}).get('version') or '').lower()
    if version and version != str(state.get('from') or '').lower():  # it moved (a request answered, or an update it did on its own after a flag)
        done = {**state, 'status': 'done', 'done_at': now.isoformat(), 'failures': 0, 'flag': ''}
        _save(agent, done)
        return done
    if state.get('status') == 'failed':
        return state
    asked = _parse(state.get('requested_at'))
    if asked and now - asked > timedelta(minutes=grace_minutes()):
        return _flag(agent, state, now, flag_text(state))
    return state


def flag_text(state):
    return (f'Did not report a newer version within {grace_minutes()} minutes of the request ({"the host updater of this server" if state.get("host") else "its updater or supervisor"} '
            f'may not be running), so cvENGINE stopped asking. Press Update now to try again')


def sweep(now=None):
    """Settle every open request, so a Sentinel that never came back (and so sends no heartbeat that would settle it) is flagged and audited too. Run every few
    minutes by the ``ensure_builtin_scanner`` task. Returns how many were flagged."""
    now = now or timezone.now()
    flagged = 0
    for agent in Agent.objects.filter(kind='scanner', info__auto_update__status='requested').exclude(status='revoked'):
        try:
            if settle(agent, now).get('status') == 'failed':
                flagged += 1
        except Exception:  # noqa: BLE001 - one row must not stop the rest
            logger.exception('could not settle the update request of Sentinel %s', agent.pk)
    return flagged


def consider(agent, now=None):
    """Called at a Sentinel's heartbeat, after its report is stored. Settles an open request, and makes a new one when the matrix says so. Never raises: a
    failure here must not cost a Sentinel its heartbeat."""
    try:
        now = now or timezone.now()
        verdict = sentinel_version.state(agent)  # cache only
        if verdict.get('status') != 'behind' and not stored(agent):
            return None  # the common heartbeat (current, or nothing known): no query at all
        settle(agent, now)
        found = decide(agent, now, verdict=verdict)
        if found['action'] == 'request':
            request_now(agent, found['target'], now=now)
        return found
    except Exception:  # noqa: BLE001
        logger.exception('the update check of Sentinel %s failed', getattr(agent, 'pk', '?'))
        return None


def admin_pressed(agent, now=None):
    """An administrator's Update now: the flag and the rate limit are cleared, the request goes out as before. The target is named when the cached verdict
    says the Sentinel is behind (never a downgrade); a Sentinel that is not behind is simply asked, as it always was."""
    state = stored(agent)
    verdict = sentinel_version.state(agent)
    target = verdict.get('latest_full') if verdict.get('status') == 'behind' else None
    kept = {k: state[k] for k in ('attempts',) if k in state}
    _save(agent, {**kept, 'status': 'requested' if target else 'manual', 'target': target, 'from': str((agent.info or {}).get('version') or ''), 'failures': 0,
                  'requested_at': (now or timezone.now()).isoformat(), 'next_after': (now or timezone.now() + MIN_INTERVAL).isoformat(), 'flag': '', 'reason': 'admin', 'host': False})
    return target


def view(agent, now=None, keep=None, instance_update=None):
    """What the Sentinels page shows for one Sentinel: ``{code, text, running, newest, requested_at, flagged}``, plain text only."""
    verdict = sentinel_version.state(agent)
    now = now or timezone.now()
    state = stored(agent)
    found = decide(agent, now, verdict=verdict, keep=keep, instance_update=instance_update, check_busy=False)
    version = str(verdict.get('version') or '').lower()
    open_request = state.get('status') == 'requested' and not (version and version != str(state.get('from') or '').lower())  # a Sentinel back on another version has answered it
    requested_at = state.get('requested_at') if open_request else None
    code = found['code']
    expired = False
    if open_request:
        asked = _parse(state.get('requested_at'))
        expired = bool(asked and now - asked > timedelta(minutes=grace_minutes()))  # nobody settled it yet (a Sentinel that never came back sends no heartbeat); the page still says so
        code = 'flagged' if expired else 'requested'
    text = TEXT['requested'] if code == 'requested' else flag_text(state) if expired else found['text']
    return {'code': code, 'text': text, 'running': verdict.get('version'), 'newest': verdict.get('latest'),
            'requested_at': requested_at, 'flagged': state.get('status') == 'failed' or expired, 'next_after': state.get('next_after')}
