"""Everything the daemon reads from its environment, in one place, each with a sane default."""
import os
import platform
import socket

CAPABILITIES = ['nmap', 'naabu', 'nuclei_light', 'nuclei_targeted']
HEARTBEAT_SECONDS = 60  # matches agentapi.agent_broker.HEARTBEAT_SECONDS; see that constant if it ever changes
DEFAULT_TOKEN_PATH = '/var/lib/cvengine-sentinel/token.json'
DEFAULT_POLL_WAIT = 15  # seconds the long poll (sentinel/tasks/next) may block per call
SHUTDOWN_GRACE_SECONDS = 20  # how long a SIGTERM waits for in-flight tasks to finish before releasing them


def _env(name, default=None):
    value = os.environ.get(name)
    return value if value not in (None, '') else default


def sentinel_name():
    return _env('CVENGINE_SENTINEL_NAME') or socket.gethostname() or 'sentinel'


def max_concurrent():
    try:
        value = int(_env('CVENGINE_SENTINEL_MAX_CONCURRENT', '1'))
    except (TypeError, ValueError):
        return 1
    return max(1, value)


def token_path():
    return _env('CVENGINE_SENTINEL_TOKEN_FILE', DEFAULT_TOKEN_PATH)


def blob():
    return _env('CVENGINE_SENTINEL_BLOB')


def os_family():
    system = platform.system().lower()
    if system == 'linux':
        return 'linux'
    if system == 'darwin':
        return 'macos'
    if system == 'windows':
        return 'windows'
    return ''
