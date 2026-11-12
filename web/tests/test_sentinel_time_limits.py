"""The server waits at least as long as the Sentinel lets a tool run (1.4.0 tool review).

A stage that gives up first loses the result: the Sentinel reports a finished run after the stage stopped waiting and it is discarded as late, and the
targets stay due. ``SENTINEL_TOOL_SECONDS`` are the limits the Sentinel's runners run by (cvENGINE-sentinel client/tools.py, the defaults of each run
function, and the watchdog's TOOL_BUDGET_SECONDS, which a Sentinel test holds equal); the server's wait is ``sentinel_dispatch._dispatch_timeout``."""
from django.test import SimpleTestCase

from agentapi import sentinel_broker, sentinel_dispatch

SENTINEL_TOOL_SECONDS = {'testssl': 900, 'nmap_udp': 1500, 'nmap_full': 1500, 'wpscan': 900, 'discover': 900, 'nuclei_validate': 540, 'waf': 60}
REPORT_ALLOWANCE = 60  # time for the finished result to travel


class WaitAtLeastAsLongAsTheTool(SimpleTestCase):
    def test_every_kind_waits_longer_than_its_tool_may_run(self):
        for kind, tool in SENTINEL_TOOL_SECONDS.items():
            self.assertGreaterEqual(sentinel_dispatch._dispatch_timeout(kind), tool + REPORT_ALLOWANCE, f'{kind}: the stage gives up before the Sentinel does')

    def test_the_lease_cap_covers_the_wait(self):
        class Task:
            kind, target, ips = 'testssl', {}, []
        for kind in SENTINEL_TOOL_SECONDS:
            Task.kind = kind
            self.assertGreaterEqual(sentinel_broker.max_runtime(Task).total_seconds(), SENTINEL_TOOL_SECONDS[kind] + REPORT_ALLOWANCE, kind)

    def test_chunked_kinds_wait_longer_than_the_sentinel_sizes_the_run(self):
        from cvengine_scanner import flags
        for kind in ('nmap', 'naabu', 'nuclei_light', 'nuclei_targeted', 'nuclei_deep'):
            for count in (1, 8, 24, 64):
                self.assertGreaterEqual(sentinel_dispatch._dispatch_timeout(kind, count), flags.task_seconds(kind, count) + 20, f'{kind} x {count}')
