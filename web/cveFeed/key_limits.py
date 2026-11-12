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
KEY = 'cvengine:discovery:key-limit:'
# What a provider says when the key works but its plan or its rate is used up (SecurityTrails: "You have exceeded the usage limits for your account")
LIMIT = re.compile(r'exceeded|usage limit|too many requests|rate[ _-]?limit|quota|\b429\b|limit (?:reached|exceeded)', re.I)


def is_limit(reason):
    return bool(LIMIT.search(str(reason or '')))


def _key(project_id, service):
    return f'{KEY}{project_id or 0}:{service}'


def paused(project_id, service):
    try:
        return bool(cache.get(_key(project_id, service)))
    except Exception:  # noqa: BLE001 - no cache means no pause, as before
        return False


def pause(project_id, service):
    """Start the pause of this project's key for ``service``. True only for the call that started it (the one that should say so)."""
    try:
        return bool(cache.add(_key(project_id, service), 1, PAUSE_SECONDS))
    except Exception:  # noqa: BLE001
        return False


def notice_text(label):
    hours = PAUSE_SECONDS // 3600
    return (f"{label}: the key is over its plan's limit (or is being rate limited), so discovery continues without it for about {hours} hours; "
            'check the plan or the key on the provider\'s site. One notice for the whole pause.')
