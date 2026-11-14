"""What the two slow web sweeps, ``cveFeed.vhost_scan`` (other sites on an address) and ``cveFeed.subdir_apps`` (other applications under a
subdirectory), and the supplier sweep share: the switches, the limits and the pace the tasks carry (a global gap between any two requests and a
longer gap between two requests to one host). The requests themselves are a Sentinel's; this server sends none.

An edge that challenges or blocks a request is recorded by the callers as ``challenged`` and is never retried or worked around; a plain
429 or 503 stops the current host for this sweep and is asked again at the next one."""
import os

QUEUE = 'vhost_queue'
GLOBAL_GAP = 1.0  # seconds between any two requests of these sweeps, across every worker process
HOST_GAP = 2.0  # seconds between two requests to one host or address


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


def busy(response):
    """A plain "try later" (429, 503 with no edge signature): not a result, and not asked again at this sweep."""
    return (response.get('status') or 0) in (429, 503) and not response.get('challenge')


def authority(host, port, scheme):
    """``host`` or ``host:port`` for a URL, the port omitted when it is the scheme's default, an IPv6 literal bracketed."""
    name = f'[{host}]' if ':' in host else host
    return name if port == (443 if scheme == 'https' else 80) else f'{name}:{port}'
