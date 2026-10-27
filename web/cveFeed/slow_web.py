"""Shared politeness for the two slow web sweeps, ``cveFeed.vhost_scan`` (other sites on an address) and ``cveFeed.subdir_apps`` (other
applications under a subdirectory).

Both only look for OTHER APPLICATIONS that could carry a known CVE. They are not content discovery: GET only, no body, no cookie, no
credential, redirects never followed, a small curated set of questions, and a hard cap on what one host or one address is asked per
sweep. What this module holds is what they share: the switches, the limits, the pace (a global gap between any two requests across every
worker and a longer gap between two requests to one host) and the one request function.

An edge that challenges or blocks a request is recorded by the callers as ``challenged`` and is never retried or worked around; a plain
429 or 503 stops the current host for this sweep and is asked again at the next one."""
import logging
import os
import threading
import time

logger = logging.getLogger(__name__)

QUEUE = 'vhost_queue'
GLOBAL_GAP = 1.0  # seconds between any two requests of these sweeps, across every worker process
HOST_GAP = 2.0  # seconds between two requests to one host or address
MAX_RESPONSE_BYTES = 64 * 1024
_SLOT_KEY = 'cvengine:slowweb:next'
_SLOT_LUA = """
local nxt = tonumber(redis.call('GET', KEYS[1]) or '0')
local at = math.max(tonumber(ARGV[1]), nxt)
redis.call('SET', KEYS[1], at + tonumber(ARGV[2]), 'EX', 900)
return tostring(at)
"""
_local = {'next': 0.0}
_local_lock = threading.Lock()


def truthy(value):
    return str(value).strip().lower() not in ('0', 'false', 'no', 'off', '')


def env_int(name, default, low=1, high=1000):
    try:
        return min(high, max(low, int(os.environ.get(name, default))))
    except ValueError:
        return default


def env_float(name, default, low=0.0, high=60.0):
    try:
        return min(high, max(low, float(os.environ.get(name, default))))
    except ValueError:
        return default


def global_gap():
    return env_float('CVENGINE_SLOW_WEB_GAP', GLOBAL_GAP)


def host_gap():
    return env_float('CVENGINE_SLOW_WEB_HOST_GAP', HOST_GAP)


def reserve_slot(gap, now=time.time):
    """Seconds to wait before this request may go. Slots are handed out in order and ``gap`` apart, shared by every worker process when
    Redis is there, else per process."""
    from reNgine import resources
    client = getattr(resources.get_store(), 'r', None)
    if client is not None:
        try:
            at = float(client.eval(_SLOT_LUA, 1, _SLOT_KEY, now(), gap))
            return max(0.0, at - now())
        except Exception:  # noqa: BLE001 - a Redis hiccup must not stop the sweep
            pass
    with _local_lock:
        at = max(now(), _local['next'])
        _local['next'] = at + gap
        return max(0.0, at - now())


class Pace:
    """Waits before each request: the per-host gap since the last request to that host, then the global slot. ``sleep`` and ``clock`` are
    injectable so a test checks the pacing without waiting."""

    def __init__(self, sleep=time.sleep, clock=time.monotonic, per_host=None, overall=None):
        self.sleep, self.clock = sleep, clock
        self.per_host = host_gap() if per_host is None else per_host
        self.overall = global_gap() if overall is None else overall
        self.last = {}
        self.requests = 0

    def wait(self, host):
        key = str(host).lower()
        since = self.clock() - self.last[key] if key in self.last else None
        if since is not None and since < self.per_host:
            self.sleep(self.per_host - since)
        delay = reserve_slot(self.overall) if self.overall else 0.0
        if delay > 0:
            self.sleep(delay)
        self.last[key] = self.clock()
        self.requests += 1


def get(url, connect_ip=None, project=None, probe=None):
    """One bounded, anonymous GET (``route_auth.probe_url``: pinned numeric destination vetted at connect time, no redirects, no cookie, the
    response read up to 64 KB). ``connect_ip`` sends the URL's name as the Host header and the TLS server name to that vetted address. The
    result also says which edge challenged it (``challenge``, '' when none): see ``probes.challenge_of``."""
    from cveFeed import probes, route_auth
    probe = probe or route_auth.probe_url
    kwargs = {'max_bytes': MAX_RESPONSE_BYTES, 'project': project}
    if connect_ip:
        kwargs['connect_ip'] = connect_ip
    response = probe(url, **kwargs)
    return {**response, 'challenge': probes.challenge_of(response)}


def busy(response):
    """A plain "try later" (429, 503 with no edge signature): not a result, and not asked again at this sweep."""
    return (response.get('status') or 0) in (429, 503) and not response.get('challenge')


def authority(host, port, scheme):
    """``host`` or ``host:port`` for a URL, the port omitted when it is the scheme's default, an IPv6 literal bracketed."""
    name = f'[{host}]' if ':' in host else host
    return name if port == (443 if scheme == 'https' else 80) else f'{name}:{port}'
