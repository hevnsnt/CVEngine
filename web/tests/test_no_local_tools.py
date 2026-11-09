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
        'agentapi/egress.py',  # 1.3.4 outbound connection log (develop): names the tools whose probe plans it records, runs nothing
        'agentapi/mcp.py',
        'agentapi/models.py',
        'agentapi/rest.py',
        'agentapi/sentinel_broker.py',
        'agentapi/sentinel_dispatch.py',
        'agentapi/services.py',
        'agentapi/system_status.py',
        'cveFeed/autotune_policy.py',  # 1.3.2 auto-tuning (develop): names the per-tool concurrency settings, runs nothing
        'cveFeed/changes.py',
        'cveFeed/check_coverage.py',
        'cveFeed/cleartext.py',  # 1.3.2 cleartext hygiene (develop): reads stored nmap service rows, runs nothing
        'cveFeed/confirm_guide.py',  # 1.3.3 confirmation guide (develop): tells a person how to check a finding by hand, runs nothing
        'cveFeed/correlation.py',
        'cveFeed/coverage_topup.py',
        'cveFeed/db_exposure.py',
        'cveFeed/db_intel.py',
        'cveFeed/detection.py',
        'cveFeed/detection_author.py',  # 1.3.3 detection rules author (develop): prompt text about which check fits a class, runs nothing
        'cveFeed/detection_classes.py',  # 1.3.3 detection classes (develop): comments about which reader fits a class, runs nothing
        'cveFeed/detection_commands.py',
        'cveFeed/discovery.py',
        'cveFeed/distro.py',
        'cveFeed/heavy_process.py',
        'cveFeed/host_assessment.py',  # 1.3.2 assessment batches (develop): comments about the dispatched stages, runs nothing
        'cveFeed/host_context.py',
        'cveFeed/host_inventory.py',
        'cveFeed/intel.py',
        'cveFeed/internal_scan.py',
        'cveFeed/ledger.py',
        'cveFeed/local_egress.py',  # 1.3.4 egress governor (develop): budgets and logs the ports a local tool run will probe, runs nothing itself
        'cveFeed/management/commands/seed_scale_fixture.py',  # scale fixture: names the ledger services 'nmap' as stored data values (synthetic rows for scripts/scale), runs nothing
        'cveFeed/match_policy.py',
        'cveFeed/migrations/0124_os_path_schedule.py',
        'cveFeed/models.py',
        'cveFeed/nuclei_fp.py',  # 1.3.5 scanner false positives (develop): reads the stored nmap service name of a port (echo), runs nothing
        'cveFeed/nuclei_templates.py',
        'cveFeed/os_detection.py',
        'cveFeed/performance_review.py',
        'cveFeed/port_inventory.py',  # the scanner library's parser module name and the stored Port source / OS source values: data, runs nothing
        'cveFeed/port_stage.py',  # the fingerprint ledger service name 'nmap-fast' (a stored data value) and kind names: runs nothing
        'cveFeed/probes.py',
        'cveFeed/rdp_shot.py',
        'cveFeed/report_data.py',
        'cveFeed/route_auth.py',
        'cveFeed/runzero_sync.py',
        'cveFeed/scan_concurrency.py',  # 1.3.2 scan concurrency setting (develop): names the per-tool limits, runs nothing
        'cveFeed/service_intel.py',
        'cveFeed/settings_api.py',  # 1.3.2 settings API (develop): setting help text, runs nothing
        'cveFeed/setup_flow.py',  # the setup wizard (1.4): scanner kind names such as nmap or nuclei as the toggles it offers (data values written to the Sentinel settings), runs nothing
        'cveFeed/software.py',  # the About page list of the tools of both images (names, versions, licenses), runs nothing
        'cveFeed/tailscale_sync.py',
        'cveFeed/tasks.py',
        'cveFeed/triage.py',  # 1.3.3 triage (develop): docstring naming evidence sources, runs nothing
        'cveFeed/tunables.py',  # 1.3.2 tunables registry (develop): setting names and help text, runs nothing
        'cveFeed/udp_scan.py',
        'cveFeed/validation.py',
        'cveFeed/validation_plan.py',
        'reNgine/ai_providers.py',
        'reNgine/common_func.py',
        'reNgine/definitions.py',
        'reNgine/input_guard.py',
        'reNgine/resources.py',
    ],
    'nuclei': [
        'Dockerfile',
        'agentapi/egress.py',  # 1.3.4 outbound connection log (develop): names the tools whose probe plans it records, runs nothing
        'agentapi/mcp.py',
        'agentapi/models.py',
        'agentapi/rest.py',
        'agentapi/sentinel_broker.py',
        'agentapi/services.py',
        'agentapi/system_status.py',
        'agentapi/template_bundle.py',
        'celery-entrypoint.sh',
        'cveFeed/apps.py',
        'cveFeed/auth_checks.py',
        'cveFeed/auth_nuclei.py',  # T8 nuclei: ledger service keys (nuclei-auth, nuclei-auth-refused) are stored data, plus activity text; runs nothing, the signed-in pass is the built-in scanner's
        'cveFeed/autotune_policy.py',  # 1.3.2 auto-tuning (develop): names the per-tool concurrency settings, runs nothing
        'cveFeed/check_coverage.py',
        'cveFeed/conductor.py',
        'cveFeed/confirm_guide.py',  # 1.3.3 confirmation guide (develop): tells a person how to check a finding by hand, runs nothing
        'cveFeed/counts.py',
        'cveFeed/coverage_topup.py',
        'cveFeed/detection.py',
        'cveFeed/detection_author.py',
        'cveFeed/detection_commands.py',
        'cveFeed/diagnostics.py',
        'cveFeed/discovery.py',
        'cveFeed/fullscan.py',
        'cveFeed/heavy_process.py',
        'cveFeed/host_assessment.py',  # 1.3.2 assessment batches (develop): comments about the dispatched stages, runs nothing
        'cveFeed/internal_scan.py',
        'cveFeed/js_libraries.py',  # 1.3.3 JS library evidence (develop): a docstring naming evidence sources, runs nothing
        'cveFeed/ledger.py',
        'cveFeed/management/commands/backfill_secrets_inventory.py',  # 1.4 secrets inventory: names the nuclei findings it files and masks (rule ids, the finding's source), runs nothing
        'cveFeed/management/commands/seed_scale_fixture.py',  # scale fixture: names the ledger services 'nuclei' as stored data values (synthetic rows for scripts/scale), runs nothing
        'cveFeed/match_policy.py',  # 1.3.2 version-only heat cap (develop): names the confirming tools, runs nothing
        'cveFeed/migrations/0016_nuclei_template_update_schedule.py',
        'cveFeed/migrations/0049_weekly_deep_nuclei.py',
        'cveFeed/migrations/0079_nuclei_templates_every_six_hours.py',
        'cveFeed/models.py',
        'cveFeed/notify.py',
        'cveFeed/nuclei_fp.py',  # 1.3.5 scanner false positives (develop): judges nuclei results already returned, runs nothing
        'cveFeed/nuclei_scan.py',  # T8 nuclei: ledger service keys (nuclei-light, nuclei-cve) and the finding source/module value, stored data, plus activity text naming the pass; runs nothing
        'cveFeed/nuclei_templates.py',
        'cveFeed/performance_review.py',
        'cveFeed/reaper.py',
        'cveFeed/report_data.py',
        'cveFeed/reviewer.py',  # AI reviewer: names nuclei as a finding kind and the template refresh task, runs nothing
        'cveFeed/safeyaml.py',
        'cveFeed/scan_concurrency.py',  # 1.3.2 scan concurrency setting (develop): names the per-tool limits, runs nothing
        'cveFeed/secret_redaction.py',  # 1.3.2 secret masking (develop): names the tools whose output it masks, runs nothing
        'cveFeed/secrets_catalog.py',  # 1.4 secrets inventory: names the nuclei findings it files and masks (rule ids, the finding's source), runs nothing
        'cveFeed/secrets_inventory.py',  # 1.4 secrets inventory: names the nuclei findings it files and masks (rule ids, the finding's source), runs nothing
        'cveFeed/settings_api.py',  # the setting name of the model for the nuclei tag choice (nuclei_model) and its audit action: names the tool, runs nothing
        'cveFeed/setup_flow.py',  # the setup wizard (1.4): scanner kind names such as nmap or nuclei as the toggles it offers (data values written to the Sentinel settings), runs nothing
        'cveFeed/software.py',  # the About page list of the tools of both images (names, versions, licenses), runs nothing
        'cveFeed/supplier_scan.py',
        'cveFeed/tailscale_sync.py',
        'cveFeed/tasks.py',
        'cveFeed/template_gates.py',  # 1.3.5 template gates (develop): holds back a nuclei template's hit on a patched version, runs nothing
        'cveFeed/templategen.py',  # T8 nuclei: the AI prompt that asks for a nuclei template, the template library path and the nuclei-cve finding source; runs nothing
        'cveFeed/threat.py',  # 1.3.3 heat policy (develop): names the scanners whose findings carry CVEs, runs nothing
        'cveFeed/triage.py',
        'cveFeed/tunables.py',  # 1.3.2 tunables registry (develop): setting names and help text, runs nothing
        'cveFeed/validation.py',  # T8 nuclei: help text and the policy docstring naming the template policy; the nuclei_template check kind is a data value; runs nothing
        'cveFeed/views.py',
        'reNgine/ai_nuclei_model.py',  # the model of the nuclei tag choice (an AI call about tag names, the stages nuclei_targeting and nuclei_tag_selection): names the tool, runs nothing
        'reNgine/ai_providers.py',
        'reNgine/definitions.py',
        'reNgine/input_guard.py',
        'reNgine/resources.py',
        'reNgine/tasks.py',
    ],
    'naabu': [
        'agentapi/egress.py',  # 1.3.4 outbound connection log (develop): names the tools whose probe plans it records, runs nothing
        'agentapi/mcp.py',
        'agentapi/models.py',
        'agentapi/rest.py',
        'agentapi/sentinel_broker.py',
        'agentapi/sentinel_dispatch.py',
        'agentapi/system_status.py',  # 1.3.4 egress status (develop): a docstring naming the tools counted from their probe plan, runs nothing
        'cveFeed/check_coverage.py',
        'cveFeed/heavy_process.py',
        'cveFeed/host_assessment.py',  # 1.3.2 assessment batches (develop): comments about the dispatched stages, runs nothing
        'cveFeed/ledger.py',
        'cveFeed/local_egress.py',  # 1.3.4 egress governor (develop): budgets and logs the ports a local tool run will probe, runs nothing itself
        'cveFeed/management/commands/seed_scale_fixture.py',  # scale fixture: names the ledger services 'naabu' as stored data values (synthetic rows for scripts/scale), runs nothing
        'cveFeed/port_stage.py',  # the ledger service and Port source of the discovery pass, and the discovery pass's own activity text: data values, runs nothing
        'cveFeed/report_data.py',
        'cveFeed/scan_concurrency.py',  # 1.3.2 scan concurrency setting (develop): names the per-tool limits, runs nothing
        'cveFeed/setup_flow.py',  # the setup wizard (1.4): scanner kind names such as nmap or nuclei as the toggles it offers (data values written to the Sentinel settings), runs nothing
        'cveFeed/software.py',  # the About page list of the tools of both images (names, versions, licenses), runs nothing
        'cveFeed/tunables.py',  # 1.3.2 tunables registry (develop): setting names and help text, runs nothing
        'reNgine/resources.py',
    ],
    'wpscan': [
        'agentapi/mcp.py',  # capability list in a tool description names the kind, runs nothing
        'agentapi/rest.py',  # capability and task kind lists in the route help name the kind, runs nothing
        'agentapi/sentinel_broker.py',  # the kind name as a data value: result cleaner and token scrub, runs nothing
        'agentapi/sentinel_dispatch.py',  # the kind name as a data value (NEVER_LOCAL, ceilings, dispatch of the task), runs nothing
        'cveFeed/api_credentials.py',  # the stored credential service key is the kind name, a data value
        'cveFeed/autotune_policy.py',  # T8 leftover: per-kind CPU shares sum to 1; the lead removes the heavy-kind tunables in the final slice
        'cveFeed/check_coverage.py',  # ledger kinds and the check id are data values, runs nothing
        'cveFeed/confirm_guide.py',  # matches the finding source stored in the database, runs nothing
        'cveFeed/discovery.py',  # the pipeline stage name and its result key are data values, runs nothing
        'cveFeed/finding_lifecycle.py',  # finding source and template id prefix stored in the database, runs nothing
        'cveFeed/host_context.py',  # reads the stored probe name, runs nothing
        'cveFeed/ledger.py',  # ledger kind names (freshness windows) are data values, runs nothing
        'cveFeed/management/commands/close_fixed_findings.py',  # reads stored probe rows by source, runs nothing
        'cveFeed/nuclei_templates.py',  # a template tag of the public nuclei template feed, not this tool
        'cveFeed/report_data.py',  # the stage key of the report labels is a data value, runs nothing
        'cveFeed/scan_concurrency.py',  # T8 leftover: heavy-kind setting key; the lead removes the heavy-kind tunables in the final slice
        'cveFeed/setup_flow.py',  # the setup wizard (1.4): scanner kind names such as nmap or nuclei as the toggles it offers (data values written to the Sentinel settings), runs nothing
        'cveFeed/software.py',  # the About page list of the tools of both images (names, versions, licenses), runs nothing
        'cveFeed/threat.py',  # VERSION_READ_SOURCES names the stored finding source, runs nothing
        'cveFeed/wp_correlation.py',  # evidence source stored with a correlated finding, runs nothing
        'cveFeed/wpscan_scan.py',  # stores what a Sentinel reports: finding source, probe and ledger names are data values, runs nothing
        'reNgine/resources.py',  # T8 leftover: heavy-kind memory and concurrency tables; the lead removes them in the final slice
    ],
    'testssl': [
        'agentapi/mcp.py',
        'agentapi/rest.py',
        'agentapi/sentinel_broker.py',
        'agentapi/sentinel_dispatch.py',
        'cveFeed/autotune_policy.py',  # 1.3.2 auto-tuning (develop): names the per-tool concurrency settings, runs nothing
        'cveFeed/check_coverage.py',
        'cveFeed/confirm_guide.py',  # 1.3.3 confirmation guide (develop): tells a person how to check a finding by hand, runs nothing
        'cveFeed/internal_scan.py',
        'cveFeed/ledger.py',
        'cveFeed/migrations/0094_testssl_schedule.py',
        'cveFeed/report_data.py',
        'cveFeed/scan_concurrency.py',  # 1.3.2 scan concurrency setting (develop): names the per-tool limits, runs nothing
        'cveFeed/setup_flow.py',  # the setup wizard (1.4): scanner kind names such as nmap or nuclei as the toggles it offers (data values written to the Sentinel settings), runs nothing
        'cveFeed/software.py',  # the About page list of the tools of both images (names, versions, licenses), runs nothing
        'cveFeed/tls_audit.py',  # 1.4 TLS audit on a Sentinel: the kind name, the ledger key and the finding source are stored data values, runs nothing
        'reNgine/resources.py',
    ],
    'bbot': [
        'agentapi/mcp.py',  # 1.4 T8: user-facing tool descriptions that name the discovery tool (share lines with other tool words), runs nothing
        'agentapi/rest.py',  # 1.4 T8: user-facing route descriptions that name the discovery tool (share lines with other tool words), runs nothing
        'agentapi/sentinel_broker.py',  # 1.4 bbot on a Sentinel: the run's time budget and the secure read of its module keys, runs nothing
        'agentapi/sentinel_policy.py',  # 1.4 bbot on a Sentinel: the kind's label, runs nothing
        'agentapi/sentinel_settings.py',  # bbot_keys: the name of the optional heartbeat feature a Sentinel advertises for a discovery's API keys (a data value and its comment), runs nothing
        'agentapi/services.py',  # 1.4 T8: finding kind 'bbot' (a stored data value) and text shared with other tool words, runs nothing
        'cveFeed/autotune_policy.py',  # 1.3.2 auto-tuning (develop): names the per-tool concurrency settings, runs nothing
        'cveFeed/check_coverage.py',  # 1.4 T8: ledger service keys 'bbot' and 'bbot-deep' and the check label (stored data values), runs nothing
        'cveFeed/diagnostics.py',  # 1.4 T8: finding kind 'bbot' (a stored data value), runs nothing
        'cveFeed/discovery.py',  # 1.4 T8: ledger service keys 'bbot' and 'bbot-deep' and the activity title (stored data values), runs nothing
        'cveFeed/js_libraries.py',  # 1.3.3 JS library evidence (develop): a docstring naming evidence sources, runs nothing
        'cveFeed/labels.py',  # 1.4 T8: host label source default 'bbot' (a stored data value), runs nothing
        'cveFeed/ledger.py',  # 1.4 T8: ledger service keys 'bbot' and 'bbot-deep' (stored data values), runs nothing
        'cveFeed/management/commands/backfill_secrets_inventory.py',  # 1.4 secrets inventory: names the bbot findings it files and masks (rule ids, the finding's source), runs nothing
        'cveFeed/management/commands/rerate_dangling_dns.py',  # 1.3.5 backfill (develop): re-rates stored bbot/baddns findings, runs no tool
        'cveFeed/management/commands/seed_scale_fixture.py',  # scale fixture: names the ledger services 'bbot' as stored data values (synthetic rows for scripts/scale), runs nothing
        'cveFeed/migrations/0040_hostlabel.py',
        'cveFeed/migrations/0041_bbot_info_to_labels.py',
        'cveFeed/models.py',  # 1.4 T8: finding kind and source values 'bbot' (stored data values), runs nothing
        'cveFeed/nuclei_templates.py',  # 1.4 T8: technology source key 'bbot' in the host profile (a data value), runs nothing
        'cveFeed/report_data.py',  # 1.4 T8: report labels for the ledger keys 'bbot' and 'bbot-deep' (data values), runs nothing
        'cveFeed/reviewer.py',  # AI reviewer: names bbot as a finding kind to review, runs nothing
        'cveFeed/scan_concurrency.py',  # 1.3.2 scan concurrency setting (develop): names the per-tool limits, runs nothing
        'cveFeed/secrets_catalog.py',  # 1.4 secrets inventory: names the bbot findings it files and masks (rule ids, the finding's source), runs nothing
        'cveFeed/secrets_inventory.py',  # 1.4 secrets inventory: names the bbot findings it files and masks (rule ids, the finding's source), runs nothing
        'cveFeed/setup_flow.py',  # the setup wizard (1.4): scanner kind names such as nmap or nuclei as the toggles it offers (data values written to the Sentinel settings), runs nothing
        'cveFeed/software.py',  # the About page list of the tools of both images (names, versions, licenses), runs nothing
        'cveFeed/supplier_scan.py',  # 1.4 T8: docstring line shared with other tool words, runs nothing
        'cveFeed/tasks.py',  # 1.4 T8: ledger key 'bbot-deep' (a stored data value), runs nothing
        'cveFeed/threat.py',  # 1.3.5 heat rules (develop): names the sources whose severity heat is not held back, runs nothing
        'cveFeed/triage.py',  # 1.4 T8: finding kind 'bbot' (a stored data value), runs nothing
        'cveFeed/upgrade_backfills.py',  # 1.4 secrets inventory: names the bbot findings it files and masks (rule ids, the finding's source), runs nothing
        'reNgine/resources.py',  # 1.4 T8: heavy-job kind names 'bbot-deep', 'bbot-standard', 'bbot-passive' now unused: lead decides with the tunables that name them (one-line tables shared with other tools), runs nothing
        'reNgine/tasks.py',  # 1.4 T8: stores a Sentinel's discovery results with source 'bbot' (a stored data value), runs nothing
    ],
    'wafw00f': [
        'cveFeed/check_coverage.py',
        'cveFeed/discovery.py',
        'cveFeed/ledger.py',
        'cveFeed/management/commands/seed_scale_fixture.py',  # scale fixture: names the ledger services 'wafw00f' as stored data values (synthetic rows for scripts/scale), runs nothing
        'cveFeed/software.py',  # the About page list of the tools of both images (names, versions, licenses), runs nothing
        'cveFeed/waf_fingerprint.py',  # 1.4 WAF fingerprint on a Sentinel: the ledger key is a stored data value, runs nothing
    ],
    'gowitness': [
        'cveFeed/software.py',  # the About page list of the tools of both images (names, versions, licenses), runs nothing
    ],
    'aardwolf': [
        'cveFeed/software.py',  # the About page list of the tools of both images (names, versions, licenses), runs nothing
    ],
    'subprocess': [
        'agentapi/system_status.py',
        'cveFeed/heavy_process.py',
        'cveFeed/report_pdf.py',
        'cveFeed/tasks.py',
        'reNgine/resources.py',
        'reNgine/tasks.py',
        'reNgine/time_limits.py',
    ],
    'heavy_process.run': [
    ],
    '_BIN': [
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
        # CPU time, not wall-clock time: CI runs this beside other test processes on a shared
        # runner, and waiting for a CPU there is not the walk being slow.
        started = time.process_time()
        cls.found = scan_usage()
        cls.elapsed = time.process_time() - started

    def test_allowlist_only_names_known_tools(self):
        self.assertFalse(set(ALLOWED) - set(PATTERNS), 'ALLOWED has a key the guard does not search for')

    def test_walk_is_fast_and_sees_the_code(self):
        self.assertLess(self.elapsed, 5.0, 'the walk must stay under five seconds')  # about 0.4 s of CPU on a developer machine; CI runners have taken 2.0 s, so the limit is for a runaway walk, not for jitter
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
