"""A discovery key that its provider says is over its plan's limit (or is rate-limiting) is left out for a while.

Before this, every discovery sent the key, the provider refused it again, and each refusal was written as a failed activity line: one install showed 77
of them in six hours, all the same reason, and the "Scans and tasks are failing" alert counted them. Now the first refusal pauses that key for its
project (the same pattern as the web archive breaker in ``cveFeed.archive_urls``: a cache key with a time to live), the pause leaves the key out of
the scanner's arguments (``api_credentials.bbot_config_args``, so the module runs without it, as it does for a service with no key), and ONE notice
per pause says which provider it was. The notice is not a failure (status ``notice``)."""
import logging
import re

from django.core.cache import cache

logger = logging.getLogger(__name__)

PAUSE_SECONDS = 3 * 3600   # long enough for a per-minute or hourly limit to clear, short enough to notice a plan that was raised
STREAK_WARNING = 8         # this many pauses in a row (about a day) without a break is not a passing limit: one failed line says so
KEY = 'cvengine:discovery:key-limit:'
# What a provider says when the key works but its plan or its rate is used up (SecurityTrails: "You have exceeded the usage limits for your account").
# Anchored on the provider's own phrases; a message that also says the key is bad, disabled or suspended is not a limit (it is a key to fix).
LIMIT = re.compile(r'usage limit|too many requests|rate[ _-]?limit|quota (?:exceeded|reached|used|exhausted)|exceeded (?:\w+ ){0,3}(?:limit|quota|rate)|'
                   r'(?:out of|over (?:its|the|your)) (?:quota|limit)|\b429\b|(?:daily|monthly|hourly|plan|credit|request|api) limit (?:reached|exceeded)|limit (?:reached|exceeded)', re.I)
NOT_A_LIMIT = re.compile(r'invalid|disabled|suspended|unauthori[sz]ed|forbidden|not valid|\b40[13]\b|expired|revoked|deactivated|banned', re.I)


def is_limit(reason):
    reason = str(reason or '')
    return bool(LIMIT.search(reason)) and not NOT_A_LIMIT.search(reason)


def fingerprint(values):
    """A short stable hash of a key's value(s): a pause belongs to this key, so a corrected or replaced key is sent again at once. Never the key itself."""
    import hashlib
    return hashlib.sha256('\0'.join(sorted(str(v) for v in values)).encode()).hexdigest()[:12]


def _key(project_id, service, fp=''):
    return f'{KEY}{project_id or 0}:{service}:{fp}' if fp else f'{KEY}{project_id or 0}:{service}'


def paused(project_id, service, fp=''):
    try:
        return bool(cache.get(_key(project_id, service, fp)))
    except Exception:  # noqa: BLE001 - no cache means no pause, as before
        return False


def pause(project_id, service, fp=''):
    """Start the pause of this project's key for ``service``. True for the call that started it (the one that should say so), False when it was already
    paused, None when the pause could not be taken (no cache): the caller then reports the refusal as it did before the pause existed."""
    try:
        return bool(cache.add(_key(project_id, service, fp), 1, PAUSE_SECONDS))
    except Exception:  # noqa: BLE001
        return None


def streak(project_id, service, fp=''):
    """How many pauses of this key followed one another without a break (a gap of more than two pauses ends it); 0 when the cache cannot say."""
    key = _key(project_id, service, fp) + ':streak'
    try:
        cache.add(key, 0, 2 * PAUSE_SECONDS)
        count = cache.incr(key)
        cache.touch(key, 2 * PAUSE_SECONDS)
        return count
    except Exception:  # noqa: BLE001
        return 0


def streak_text(label, count):
    return (f'{label}: the key has been over its limit or rate limited for {count} pauses in a row (about {count * PAUSE_SECONDS // 3600} hours), so discovery has run without it '
            "all that time. Raise the plan, replace the key or remove it on the provider's site and in the API keys.")


def notice_text(label):
    hours = PAUSE_SECONDS // 3600
    return (f"{label}: the key is over its plan's limit (or is being rate limited), so discovery continues without it for about {hours} hours; "
            'check the plan or the key on the provider\'s site. One notice for the whole pause.')
