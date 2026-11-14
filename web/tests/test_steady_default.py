"""Every test starts with the per-process, clock-expiring memos unloaded and pinned (``reNgine.test_runner.pin_process_caches``): a request inside it never pays an
expiry's reload. A test that is about the expiry opts out with ``tests.steady.expiring_caches``."""
import time
from unittest import mock

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext

from cveFeed import internal_view, tunables
from reNgine import input_guard, ip_allowlist
from tests.steady import expiring_caches


def reads_after_a_long_time():
    """Queries the memos cost when they are read, then read again 'an hour later' (the clock of the process moved on, the way a slow runner's does)."""
    input_guard.banned_ips(), ip_allowlist._load(), tunables.stored_values(), internal_view.table()  # the first read loads each
    later = time.time() + 3600
    with CaptureQueriesContext(connection) as ctx, mock.patch('time.time', return_value=later), mock.patch('time.monotonic', return_value=time.monotonic() + 3600):
        input_guard.banned_ips()
        ip_allowlist._load()
        tunables.stored_values(now_fn=lambda: time.monotonic() + 3600)
        internal_view.table()
    return len(ctx)


class DefaultPinTests(TestCase):
    def test_a_memo_does_not_expire_inside_an_ordinary_test(self):
        self.assertEqual(reads_after_a_long_time(), 0)


@expiring_caches
class OptedOutTests(TestCase):
    def test_a_test_about_the_expiry_still_sees_it(self):
        self.assertGreater(reads_after_a_long_time(), 0)


class PinnedCacheSecondsTests(TestCase):
    """FB-14: the test runner pins each memo's expiry to infinity whatever the module says, so a module whose cache time became 0 (no caching: every read queries) would
    pass every query-count test. The real value is read from the source, because the module's own name is pinned while a test runs."""

    def test_every_pinned_memo_really_caches_for_at_least_a_second(self):
        import re
        from pathlib import Path

        from cveFeed import egress_proxy, scan_concurrency, tailscale_scope
        from reNgine import resources
        for module, name in ((internal_view, 'CACHE_SECONDS'), (tunables, 'CACHE_SECONDS'), (scan_concurrency, 'CACHE_SECONDS'), (tailscale_scope, 'CACHE_SECONDS'),
                             (egress_proxy, 'CACHE_SECONDS'), (resources, 'SAVED_CACHE_SECONDS')):
            source = Path(module.__file__).read_text(encoding='utf-8')
            match = re.search(rf'^{name}\s*=\s*(.+?)\s*(#.*)?$', source, re.MULTILINE)
            self.assertIsNotNone(match, f'{module.__name__}.{name} is not defined in its source')
            expression = match.group(1)
            if re.fullmatch(r'[\d.]+', expression):
                self.assertGreaterEqual(float(expression), 1, f'{module.__name__}.{name} must cache for at least a second')
            else:  # an alias of another pinned name, which is checked on its own line
                self.assertRegex(expression, r'^(resources\.)?SAVED_CACHE_SECONDS$', f'{module.__name__}.{name} = {expression}')
