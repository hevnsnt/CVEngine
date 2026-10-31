"""Removed-binary guard for the one-scanner plan (docs/SCANNER-ARCHITECTURE.md, 1.4).

The scan tools are leaving the server image: every tool run moves to the Sentinel-based scanner, and phase 8 drops the binaries
from the server. Until then this test stops the server from growing new local scan-tool usage. It walks the non-test code of
`cveFeed`, `reNgine` and `agentapi` (Python and shell), the three entrypoint scripts and `web/Dockerfile`, and records every
(tool, file) pair where the file mentions a scan tool or a way of running one: `subprocess`, `heavy_process.run`, a `*_BIN`
name, or one of the tool names as a whole word (case-insensitive: nmap, nuclei, naabu, wpscan, testssl, bbot, wafw00f,
gowitness, aardwolf).

The set found must be a SUBSET of ALLOWED below, which was generated from the code as it stood when the guard was added, so it
starts equal to today. Two directions are enforced:

* a new reference fails the build. Either route the work through the scanner (a Sentinel task kind), or, if the file really has
  to name the tool on the server (a parser that stays, a comment, a pure helper), add it to ALLOWED with a reason in the PR.
* an ALLOWED entry that no longer matches fails too, so deletes must shrink the list. Each phase 5 and phase 8 delete PR
  removes its entries here; the final slice leaves ALLOWED empty and the guard then forbids any reference at all.

The match is a text scan, not an import graph: a mention in a docstring counts. That is deliberate, a comment about a tool in a
file that no longer runs it is a stale leftover the same delete PR should clean up.
"""
import os
import re
import time
from pathlib import Path

from django.test import SimpleTestCase

WEB = Path(__file__).resolve().parents[1]

TOOL_WORDS = ('nmap', 'nuclei', 'naabu', 'wpscan', 'testssl', 'bbot', 'wafw00f', 'gowitness', 'aardwolf')
PATTERNS = {word: re.compile(r'\b%s\b' % word, re.I) for word in TOOL_WORDS}
PATTERNS['subprocess'] = re.compile(r'\bsubprocess\b')
PATTERNS['heavy_process.run'] = re.compile(r'\bheavy_process\.run')
PATTERNS['_BIN'] = re.compile(r'_BIN\b')

SCAN_DIRS = ('cveFeed', 'reNgine', 'agentapi')
SCAN_SUFFIXES = ('.py', '.sh')
EXTRA_FILES = ('entrypoint.sh', 'celery-entrypoint.sh', 'beat-entrypoint.sh', 'Dockerfile')
SKIP_DIRS = {'__pycache__', 'tests'}

# Phase 5 and 8 delete PRs shrink this; the final slice empties it. Paths are relative to web/.
ALLOWED = {
    'nmap': [
        'Dockerfile',
        'agentapi/mcp.py',
        'agentapi/models.py',
        'agentapi/rest.py',
        'agentapi/sentinel_broker.py',
        'agentapi/sentinel_dispatch.py',
        'agentapi/services.py',
        'agentapi/system_status.py',
        'celery-entrypoint.sh',
        'cveFeed/changes.py',
        'cveFeed/check_coverage.py',
        'cveFeed/correlation.py',
        'cveFeed/coverage_topup.py',
        'cveFeed/db_exposure.py',
        'cveFeed/db_intel.py',
        'cveFeed/detection.py',
        'cveFeed/detection_commands.py',
        'cveFeed/discovery.py',
        'cveFeed/distro.py',
        'cveFeed/egress_proxy.py',
        'cveFeed/fullscan.py',
        'cveFeed/heavy_process.py',
        'cveFeed/host_context.py',
        'cveFeed/host_inventory.py',
        'cveFeed/intel.py',
        'cveFeed/internal_scan.py',
        'cveFeed/ledger.py',
        'cveFeed/match_policy.py',
        'cveFeed/migrations/0124_os_path_schedule.py',
        'cveFeed/models.py',
        'cveFeed/naabu_scan.py',
        'cveFeed/nmap_scan.py',
        'cveFeed/nuclei_scan.py',
        'cveFeed/nuclei_templates.py',
        'cveFeed/os_detection.py',
        'cveFeed/path_probe.py',
        'cveFeed/performance_review.py',
        'cveFeed/probes.py',
        'cveFeed/rdp_shot.py',
        'cveFeed/report_data.py',
        'cveFeed/route_auth.py',
        'cveFeed/runzero_sync.py',
        'cveFeed/service_intel.py',
        'cveFeed/tailscale_sync.py',
        'cveFeed/tasks.py',
        'cveFeed/testssl_scan.py',
        'cveFeed/udp_scan.py',
        'cveFeed/validation.py',
        'cveFeed/validation_plan.py',
        'cveFeed/wpscan_scan.py',
        'reNgine/ai_providers.py',
        'reNgine/common_func.py',
        'reNgine/definitions.py',
        'reNgine/input_guard.py',
        'reNgine/nmap_service.py',
        'reNgine/resources.py',
    ],
    'nuclei': [
        'Dockerfile',
        'agentapi/mcp.py',
        'agentapi/models.py',
        'agentapi/rest.py',
        'agentapi/sentinel_broker.py',
        'agentapi/sentinel_dispatch.py',
        'agentapi/services.py',
        'agentapi/system_status.py',
        'agentapi/template_bundle.py',
        'celery-entrypoint.sh',
        'cveFeed/apps.py',
        'cveFeed/auth_checks.py',
        'cveFeed/auth_nuclei.py',
        'cveFeed/check_coverage.py',
        'cveFeed/conductor.py',
        'cveFeed/counts.py',
        'cveFeed/coverage_topup.py',
        'cveFeed/detection.py',
        'cveFeed/detection_author.py',
        'cveFeed/detection_commands.py',
        'cveFeed/diagnostics.py',
        'cveFeed/discovery.py',
        'cveFeed/egress_proxy.py',
        'cveFeed/fullscan.py',
        'cveFeed/heavy_process.py',
        'cveFeed/internal_scan.py',
        'cveFeed/ledger.py',
        'cveFeed/migrations/0016_nuclei_template_update_schedule.py',
        'cveFeed/migrations/0049_weekly_deep_nuclei.py',
        'cveFeed/migrations/0079_nuclei_templates_every_six_hours.py',
        'cveFeed/models.py',
        'cveFeed/nmap_scan.py',
        'cveFeed/notify.py',
        'cveFeed/nuclei_scan.py',
        'cveFeed/nuclei_templates.py',
        'cveFeed/performance_review.py',
        'cveFeed/reaper.py',
        'cveFeed/report_data.py',
        'cveFeed/safeyaml.py',
        'cveFeed/supplier_scan.py',
        'cveFeed/tailscale_sync.py',
        'cveFeed/tasks.py',
        'cveFeed/template_fixtures.py',
        'cveFeed/templategen.py',
        'cveFeed/triage.py',
        'cveFeed/validation.py',
        'cveFeed/views.py',
        'cveFeed/waf_scan.py',
        'reNgine/ai_providers.py',
        'reNgine/definitions.py',
        'reNgine/input_guard.py',
        'reNgine/resources.py',
        'reNgine/tasks.py',
    ],
    'naabu': [
        'Dockerfile',
        'agentapi/mcp.py',
        'agentapi/models.py',
        'agentapi/rest.py',
        'agentapi/sentinel_broker.py',
        'agentapi/sentinel_dispatch.py',
        'celery-entrypoint.sh',
        'cveFeed/check_coverage.py',
        'cveFeed/egress_proxy.py',
        'cveFeed/heavy_process.py',
        'cveFeed/ledger.py',
        'cveFeed/naabu_scan.py',
        'cveFeed/nmap_scan.py',
        'cveFeed/report_data.py',
        'reNgine/resources.py',
    ],
    'wpscan': [
        'Dockerfile',
        'agentapi/mcp.py',
        'agentapi/rest.py',
        'agentapi/sentinel_broker.py',
        'agentapi/sentinel_dispatch.py',
        'agentapi/services.py',
        'agentapi/system_status.py',
        'celery-entrypoint.sh',
        'cveFeed/api_credentials.py',
        'cveFeed/check_coverage.py',
        'cveFeed/cms.py',
        'cveFeed/conductor.py',
        'cveFeed/discovery.py',
        'cveFeed/egress_proxy.py',
        'cveFeed/heavy_process.py',
        'cveFeed/host_context.py',
        'cveFeed/internal_scan.py',
        'cveFeed/ledger.py',
        'cveFeed/models.py',
        'cveFeed/nuclei_templates.py',
        'cveFeed/probes.py',
        'cveFeed/report_data.py',
        'cveFeed/tasks.py',
        'cveFeed/wp_correlation.py',
        'cveFeed/wpscan_scan.py',
        'reNgine/input_guard.py',
        'reNgine/resources.py',
    ],
    'testssl': [
        'Dockerfile',
        'agentapi/mcp.py',
        'agentapi/rest.py',
        'agentapi/sentinel_broker.py',
        'agentapi/sentinel_dispatch.py',
        'agentapi/system_status.py',
        'cveFeed/check_coverage.py',
        'cveFeed/conductor.py',
        'cveFeed/egress_proxy.py',
        'cveFeed/heavy_process.py',
        'cveFeed/hygiene.py',
        'cveFeed/internal_scan.py',
        'cveFeed/ledger.py',
        'cveFeed/migrations/0094_testssl_schedule.py',
        'cveFeed/report_data.py',
        'cveFeed/tasks.py',
        'cveFeed/testssl_scan.py',
        'reNgine/input_guard.py',
        'reNgine/resources.py',
    ],
    'bbot': [
        'Dockerfile',
        'agentapi/mcp.py',
        'agentapi/rest.py',
        'agentapi/services.py',
        'celery-entrypoint.sh',
        'cveFeed/admin_api.py',
        'cveFeed/api_credentials.py',
        'cveFeed/changes.py',
        'cveFeed/check_coverage.py',
        'cveFeed/conductor.py',
        'cveFeed/ctmonitor.py',
        'cveFeed/diagnostics.py',
        'cveFeed/discovery.py',
        'cveFeed/egress_proxy.py',
        'cveFeed/internal_scan.py',
        'cveFeed/labels.py',
        'cveFeed/ledger.py',
        'cveFeed/migrations/0040_hostlabel.py',
        'cveFeed/migrations/0041_bbot_info_to_labels.py',
        'cveFeed/models.py',
        'cveFeed/nmap_scan.py',
        'cveFeed/nuclei_scan.py',
        'cveFeed/nuclei_templates.py',
        'cveFeed/performance_review.py',
        'cveFeed/reaper.py',
        'cveFeed/report_data.py',
        'cveFeed/route_auth.py',
        'cveFeed/shots.py',
        'cveFeed/supplier_scan.py',
        'cveFeed/tasks.py',
        'cveFeed/triage.py',
        'cveFeed/versions.py',
        'cveFeed/views.py',
        'reNgine/bbot.py',
        'reNgine/common_func.py',
        'reNgine/resources.py',
        'reNgine/tasks.py',
    ],
    'wafw00f': [
        'agentapi/sentinel_broker.py',
        'cveFeed/check_coverage.py',
        'cveFeed/discovery.py',
        'cveFeed/egress_proxy.py',
        'cveFeed/ledger.py',
        'cveFeed/waf_scan.py',
        'reNgine/bbot.py',
    ],
    'gowitness': [
        'Dockerfile',
        'agentapi/services.py',
        'cveFeed/discovery.py',
        'cveFeed/shots.py',
        'cveFeed/views.py',
        'reNgine/bbot.py',
    ],
    'aardwolf': [
        'cveFeed/rdp_shot.py',
    ],
    'subprocess': [
        'agentapi/sentinel_dispatch.py',
        'agentapi/system_status.py',
        'cveFeed/heavy_process.py',
        'cveFeed/naabu_scan.py',
        'cveFeed/nmap_scan.py',
        'cveFeed/nuclei_scan.py',
        'cveFeed/report_pdf.py',
        'cveFeed/tasks.py',
        'cveFeed/template_fixtures.py',
        'cveFeed/templategen.py',
        'cveFeed/testssl_scan.py',
        'cveFeed/validation.py',
        'cveFeed/waf_scan.py',
        'cveFeed/wpscan_scan.py',
        'reNgine/bbot.py',
        'reNgine/resources.py',
        'reNgine/tasks.py',
        'reNgine/time_limits.py',
    ],
    'heavy_process.run': [
        'cveFeed/testssl_scan.py',
        'cveFeed/waf_scan.py',
        'cveFeed/wpscan_scan.py',
    ],
    '_BIN': [
        'cveFeed/naabu_scan.py',
        'cveFeed/nmap_scan.py',
        'cveFeed/nuclei_scan.py',
        'cveFeed/probes.py',
        'cveFeed/template_fixtures.py',
        'cveFeed/templategen.py',
        'cveFeed/testssl_scan.py',
        'cveFeed/validation.py',
        'cveFeed/wpscan_scan.py',
        'reNgine/bbot.py',
    ],
}


def _is_test_file(name):
    return name.startswith('test_') or name.endswith('_test.py') or name == 'tests.py' or name == 'conftest.py'


def candidate_files():
    """Relative (to web/) POSIX paths of the files the guard reads, independent of the working directory."""
    found = []
    for top in SCAN_DIRS:
        for root, dirs, files in os.walk(WEB / top):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            for name in sorted(files):
                if name.endswith(SCAN_SUFFIXES) and not _is_test_file(name):
                    found.append(Path(root, name).relative_to(WEB).as_posix())
    for name in EXTRA_FILES:
        if (WEB / name).is_file():
            found.append(name)
    return found


def scan_usage():
    """{(tool, relative file)} for every file that mentions a scan tool or a way to run one."""
    pairs = set()
    for rel in candidate_files():
        text = (WEB / rel).read_text(encoding='utf-8', errors='replace')
        for tool, pattern in PATTERNS.items():
            if pattern.search(text):
                pairs.add((tool, rel))
    return pairs


def allowed_pairs():
    return {(tool, rel) for tool, files in ALLOWED.items() for rel in files}


class NoLocalToolsTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        started = time.monotonic()
        cls.found = scan_usage()
        cls.elapsed = time.monotonic() - started

    def test_allowlist_only_names_known_tools(self):
        self.assertFalse(set(ALLOWED) - set(PATTERNS), 'ALLOWED has a key the guard does not search for')

    def test_walk_is_fast_and_sees_the_code(self):
        self.assertLess(self.elapsed, 2.0, 'the walk must stay under two seconds')
        self.assertGreater(len(candidate_files()), 100, 'the walk found almost nothing: is it pointed at web/?')

    def test_no_new_scan_tool_reference(self):
        new = sorted(self.found - allowed_pairs())
        if new:
            lines = ['  %s: %s' % (tool, rel) for tool, rel in new]
            self.fail(
                'New scan-tool usage on the server (the tools are leaving the server image, see docs/SCANNER-ARCHITECTURE.md):\n'
                + '\n'.join(lines)
                + '\nRoute the work through the scanner (a Sentinel task kind), or add the file to ALLOWED in '
                'web/tests/test_no_local_tools.py under that tool with a reason in your PR.'
            )

    def test_allowlist_has_no_stale_entries(self):
        stale = sorted(allowed_pairs() - self.found)
        if stale:
            lines = ['  %s: %s' % (tool, rel) for tool, rel in stale]
            self.fail(
                'These ALLOWED entries no longer match any file (the reference or the file was removed):\n'
                + '\n'.join(lines)
                + '\nDelete them from ALLOWED in web/tests/test_no_local_tools.py: the list only ever shrinks, and the final '
                'phase 8 slice leaves it empty.'
            )

    def test_allowlist_has_no_duplicates_and_sorted_paths(self):
        for tool, files in ALLOWED.items():
            self.assertEqual(files, sorted(set(files)), '%s entries must be unique and sorted' % tool)
