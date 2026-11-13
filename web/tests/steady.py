"""Since the test runner pins these caches for every test by default (``reNgine.test_runner.pin_process_caches``; opt out with ``expiring_caches``), ``steady_caches()`` is
only needed by a test that wants none of them to read at all (the allowlist and ban list never queried, the internal table built up front).

``steady_caches()``: pin the per-process caches that expire on the clock, for a test that compares the query counts of two requests.

A request that lands after one of them expired pays for reloading it, whatever the page holds:
- the IP allowlist and ban caches (``reNgine.ip_allowlist``, ``reNgine.input_guard``: 10 seconds) cost two queries;
- the internal network table (``cveFeed.internal_view``: 5 minutes) costs one to three;
- the saved settings (``cveFeed.tunables``, ``cveFeed.scan_concurrency``, ``reNgine.resources``: 5 seconds) cost one each when Redis holds no copy.

On a slow CI worker those queries land in whichever measure comes after the expiry, so "a second engagement adds no query" read 17 against 15
and "the list does not grow with hosts" read 14 against 12. Inside ``steady_caches()`` none of them expires, so a measure counts only the page.
"""
import contextlib
from unittest import mock


@contextlib.contextmanager
def steady_caches():
    from cveFeed import internal_view, scan_concurrency, tunables
    from reNgine import input_guard, ip_allowlist, resources
    internal_view.invalidate()
    forever = float('inf')
    with mock.patch.object(internal_view, 'CACHE_SECONDS', forever), \
            mock.patch.object(tunables, 'CACHE_SECONDS', forever), \
            mock.patch.object(scan_concurrency, 'CACHE_SECONDS', forever), \
            mock.patch.object(resources, 'SAVED_CACHE_SECONDS', forever), \
            mock.patch.object(ip_allowlist, '_load', return_value=(False, [])), \
            mock.patch.object(input_guard, 'banned_ips', return_value=frozenset()):
        internal_view.table()  # built once, here, outside any measure
        yield
    internal_view.invalidate()  # the next test builds its own from its own rows


def expiring_caches(target):
    """Opt a test (or a whole test class) out of the default pin of the per-process caches (``reNgine.test_runner.pin_process_caches``): for a test that is ABOUT
    one of them, its expiry, its reload or its refresh. ``@expiring_caches`` on the method or the class."""
    target.expiring_caches = True
    return target
