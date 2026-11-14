"""The server waits at least as long as the Sentinel lets a tool run (1.4.0 tool review).

A stage that gives up first loses the result: the Sentinel reports a finished run after the stage stopped waiting and it is discarded as late, and the
targets stay due. ``SENTINEL_TOOL_SECONDS`` are the limits the Sentinel's runners run by (cvENGINE-sentinel client/tools.py, the defaults of each run
function, and the watchdog's TOOL_BUDGET_SECONDS, which a Sentinel test holds equal); the server's wait is ``sentinel_dispatch._dispatch_timeout``."""
from django.test import SimpleTestCase

from agentapi import sentinel_broker, sentinel_dispatch

SENTINEL_TOOL_SECONDS = {'testssl': 900, 'nmap_udp': 1500, 'nmap_full': 1500, 'wpscan': 900, 'discover': 900, 'nuclei_validate': 540, 'waf': 60}

def _probe_worst_cases():
    """What the in-process probe kinds may take by the limits in their own code, one after another (cvengine_scanner.probes): the identity batch asks up to
    MAX_DNS questions and MAX_CERTS certificates with no batch deadline; a page read stops starting reads at BATCH_SECONDS and the one in progress may read
    scripts for js_libraries.DEFAULT_MAX_SECONDS."""
    from cvengine_scanner.probes import identity, js_libraries, page_read
    return {'identity_check': identity.MAX_DNS * identity.DNS_TIMEOUT + identity.MAX_CERTS * identity.TLS_TIMEOUT,
            'page_read': page_read.BATCH_SECONDS + js_libraries.DEFAULT_MAX_SECONDS}


WATCHDOG_HARD_STOP = 900 + 300  # the Sentinel's watchdog for a probe kind: DEFAULT_BUDGET_SECONDS + GRACE_SECONDS (client/watchdog.py, which the server's CI does not carry)
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


    def test_the_probe_kinds_wait_longer_than_their_batch_may_run_and_than_the_watchdog_lets_them(self):
        for kind, worst in _probe_worst_cases().items():
            ceiling = sentinel_dispatch._dispatch_timeout(kind)
            self.assertGreaterEqual(ceiling, worst + REPORT_ALLOWANCE, f'{kind}: the stage gives up while the batch may still run (worst case {worst} s)')
            self.assertGreaterEqual(ceiling, WATCHDOG_HARD_STOP + REPORT_ALLOWANCE, f'{kind}: the stage gives up before the Sentinel\'s own hard stop')
