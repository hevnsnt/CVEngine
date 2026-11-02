"""A short per-user cache of the project ids a user may see, for the Live screen's polls only.

``roles.allowed_project_ids`` (project memberships, organization memberships, the projects of those organizations: three queries) runs at the
start of every authenticated request, and the Live page polls a handful of endpoints every few seconds from every open tab. For those polls
(``GET`` of ``LIVE_PATHS``, nothing that changes data) the answer is kept per user for ``CVENGINE_AUTH_CACHE_SECONDS`` (15, at most 30, ``0``
turns it off). Every other request reads it fresh, as before.

What keeps it from weakening tenancy:

* **It is invalidated, not only expired.** Every save or delete of a project membership, an organization membership, a project or an
  organization (``tenancy.signals``) stores a new *epoch* in the cache, and a cached set is used only while it carries the current epoch, so a
  revoked membership, a project moved to another organization or a removed organization stops counting for the next poll in every worker (the
  epoch is bumped again when the transaction commits, so a poll that ran in between and cached the old answer is dropped too).
* **The TTL is the bound for what bypasses the signals** (a raw SQL update, or a bulk ``QuerySet.update`` of ``Project.org``): such a change takes
  effect within ``CVENGINE_AUTH_CACHE_SECONDS``, 30 seconds at the most.
* **It never decides which snapshot a user reads.** The snapshot key is a hash of the ids a request actually runs under (``scope_hash``), so a user
  whose set changed hashes to another key; this cache only decides which ids that is, and a stale set can only show the user what they could see a
  few seconds ago, never what another scope holds.
* An App Admin (``is_superuser``, read from the user row of this very request) is never cached, and a user who stops being one gets a fresh lookup.
* A cache that does not answer means a fresh lookup, and so does a lookup made inside an open transaction (what it reads may be rolled back, which
  fires no signal): nothing uncommitted is ever kept.
"""
import re
import uuid

from django.core.cache import cache
from django.db import connection

from reNgine import livecache_config
from tenancy import roles

EPOCH_KEY = 'cve:tenancy:epoch'
CACHE_IN_TRANSACTION = False  # a test of the cache itself sets it: see allowed_for_request
LIVE_PATHS = re.compile(r'^/cve/api/(stats|graph|graph-live|discovery)$')


def bump_epoch():
    """Every cached set is stale from now on (a membership, a project or an organization changed)."""
    try:
        cache.set(EPOCH_KEY, uuid.uuid4().hex, timeout=None)
    except Exception:  # noqa: BLE001 - nothing is cached when the cache is down, so nothing can be stale
        pass


def _key(user):
    joined = getattr(user, 'date_joined', None)
    return f'cve:tenancy:allowed:{user.pk}:{int(joined.timestamp() * 1000) if joined else 0}'  # a recreated user (same pk) never reads the old one's


def allowed_for_request(request, user):
    """``roles.allowed_project_ids(user)``, from the per-user cache when ``request`` is one of the Live screen's polls. Always a new set."""
    ttl = livecache_config.auth_cache_seconds()
    if ttl <= 0 or request.method != 'GET' or not LIVE_PATHS.match(request.path):
        return roles.allowed_project_ids(user)
    if user.is_superuser:
        return None
    if connection.in_atomic_block and not CACHE_IN_TRANSACTION:
        # Inside an open transaction (a request never is: ATOMIC_REQUESTS is off; a test case always is) what a query sees may never be committed, and
        # a rollback fires no signal, so it must not be kept for the next reader.
        return roles.allowed_project_ids(user)
    key = _key(user)
    try:
        got = cache.get_many([EPOCH_KEY, key])
    except Exception:  # noqa: BLE001
        return roles.allowed_project_ids(user)
    epoch, hit = got.get(EPOCH_KEY), got.get(key)
    if isinstance(hit, dict) and hit.get('epoch') == epoch:
        return set(hit['ids'])
    ids = roles.allowed_project_ids(user)  # read after the epoch: a change in between leaves an entry the next epoch check refuses
    try:
        cache.set(key, {'epoch': epoch, 'ids': sorted(ids)}, ttl)
    except Exception:  # noqa: BLE001
        pass
    return ids
