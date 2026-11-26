"""Removed-binary guard for the one-scanner plan (docs/SCANNER-ARCHITECTURE.md, 1.4).

The scan tools are leaving the server image: every tool run moves to the Sentinel-based scanner, and phase 8 drops the binaries
from the server. Until then this test stops the server from growing new local scan-tool usage. It walks the non-test code of
`cveFeed`, `cvengine` and `agentapi` (Python and shell), the three entrypoint scripts and `web/Dockerfile`, and records every
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

SCAN_DIRS = ('cveFeed', 'cvengine', 'agentapi', 'targetApp', 'startScan', 'scanEngine', 'dashboard')
SCAN_SUFFIXES = ('.py', '.sh')
EXTRA_FILES = ('entrypoint.sh', 'celery-entrypoint.sh', 'beat-entrypoint.sh', 'Dockerfile')
SKIP_DIRS = {'__pycache__', 'tests'}

# Phase 5 and 8 delete PRs shrink this; the final slice empties it. Paths are relative to web/.
ALLOWED = {
    'nmap': [
        'agentapi/mcp.py',
        'agentapi/models.py',
        'agentapi/rest.py',
        'agentapi/sentinel_adopt.py',  # the kind name as a data key of the adopter registry and in its docstring: files a Sentinel's result, runs nothing
        'agentapi/sentinel_broker.py',
        'agentapi/sentinel_dispatch.py',
        'agentapi/sentinel_tools.py',  # 1.4 contract 5: the names of the tools whose versions a Sentinel reports, compared with the shipped ones; runs nothing
        'agentapi/services.py',
        'agentapi/system_status.py',
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
        'cveFeed/distro_releases.py',  # distro release inference: mentions nmap's stored OS CPE in a docstring, runs nothing
        'cveFeed/finding_confirm.py',  # Confirm it yourself guides for scanner and hygiene findings: the read-only commands a person runs, as text; runs nothing
        'cveFeed/host_assessment.py',  # 1.3.2 assessment batches (develop): comments about the dispatched stages, runs nothing
        'cveFeed/host_context.py',
        'cveFeed/host_inventory.py',
        'cveFeed/identities.py',  # reads the OS guess, certificates and OS CPEs a Sentinel's port scan stored (cites nmap's OS names), runs nothing
        'cveFeed/intel.py',
        'cveFeed/internal_scan.py',
        'cveFeed/java_runtime.py',  # reads the port rows the fingerprint pass stored (the service nmap's jdwp-version named) and says so; runs nothing
        'cveFeed/ledger.py',
        'cveFeed/management/commands/backfill_distro_readings.py',  # re-reads stored banners and nmap OS CPEs for distro readings, runs nothing
        'cveFeed/management/commands/seed_scale_fixture.py',  # scale fixture: names the ledger services 'nmap' as stored data values (synthetic rows for scripts/scale), runs nothing
        'cveFeed/match_policy.py',
        'cveFeed/migrations/0124_os_path_schedule.py',
        'cveFeed/models.py',
        'cveFeed/network_detection.py',  # the network detection pass (contract 10): reads the result lines a Sentinel returned and fills what the port scan left out of a port row, runs nothing
        'cveFeed/nuclei_fp.py',  # 1.3.5 scanner false positives (develop): reads the stored nmap service name of a port (echo), runs nothing
        'cveFeed/nuclei_templates.py',
        'cveFeed/os_detection.py',
        'cveFeed/performance_review.py',
        'cveFeed/port_inventory.py',  # the scanner library's parser module name and the stored Port source / OS source values: data, runs nothing
        'cveFeed/port_stage.py',  # the fingerprint ledger service name 'nmap-fast' (a stored data value) and kind names: runs nothing
        'cveFeed/probes.py',
        'cveFeed/rdp_shot.py',
        'cveFeed/report_data.py',
        'cveFeed/result_cuts.py',  # 1.4 contract 5: the names of what a result cut (a result kind or a limit), in plain words; runs nothing
        'cveFeed/route_auth.py',
        'cveFeed/runzero_sync.py',
        'cveFeed/service_intel.py',
        'cveFeed/servicefp.py',  # decodes the service fingerprint a Sentinel's port scan stored as a port's banner (its format is the tool's), runs nothing
        'cveFeed/setup_flow.py',  # the setup wizard (1.4): scanner kind names such as nmap or nuclei as the toggles it offers (data values written to the Sentinel settings), runs nothing
        'cveFeed/software.py',  # the About page list of the tools of both images (names, versions, licenses), runs nothing
        'cveFeed/source_versions.py',  # reads the versions stored results already state (the port scan's CPEs and scripts, the TLS audit's banners, the WordPress scan's headers, a discovery's CPEs) and names them as reading sources, runs nothing
        'cveFeed/tailscale_sync.py',
        'cveFeed/tasks.py',
        'cveFeed/tls_catalogue.py',  # TLS audit catalogue: the read-only nmap and testssl.sh commands a person runs to confirm a finding, as text; runs nothing
        'cveFeed/triage.py',  # 1.3.3 triage (develop): docstring naming evidence sources, runs nothing
        'cveFeed/tunables.py',  # 1.3.2 tunables registry (develop): setting names and help text, runs nothing
        'cveFeed/udp_scan.py',
        'cveFeed/validation.py',
        'cveFeed/validation_plan.py',
        'cveFeed/windows_builds.py',  # reads the NTLM and SMB script output the port scan stored (the Windows build) and says nmap's OS guess is never read, runs nothing
        'cveFeed/work_planner.py',  # 1.4 work planner: the check-to-tool table of the coverage rules, queues Sentinel tasks, runs nothing
        'cvengine/ai_providers.py',
        'cvengine/common_func.py',
        'cvengine/definitions.py',
        'cvengine/input_guard.py',
        'cvengine/resources.py',
        'startScan/migrations/0003_shodan_service_fields.py',  # widened guard (targetApp, startScan, scanEngine, dashboard): an old migration: field help about the fingerprint pass, runs nothing
        'startScan/migrations/0007_deshare_ports.py',  # widened guard (targetApp, startScan, scanEngine, dashboard): an old data migration: names the tools whose rows it moved, runs nothing
        'startScan/migrations/0016_scrub_unreviewed_nse_scripts.py',  # widened guard (targetApp, startScan, scanEngine, dashboard): an old data migration: scrubs stored script output, runs nothing
        'startScan/models.py',  # widened guard (targetApp, startScan, scanEngine, dashboard): stored results: names the tool a row came from, runs nothing
        'targetApp/target_types.py',  # widened guard (targetApp, startScan, scanEngine, dashboard): target classification: names the tools in comments about what a Sentinel takes, runs nothing
    ],
    'nuclei': [
        'agentapi/ai_checks.py',  # 1.4.0 AI-written checks on Sentinels: the rules a nuclei_validate task must keep, runs nothing (the Sentinel runs the tool)
        'agentapi/mcp.py',
        'agentapi/models.py',
        'agentapi/rest.py',
        'agentapi/sentinel_broker.py',
        'agentapi/sentinel_settings.py',  # FA-2b: a comment on the ``credential_filter`` feature a Sentinel declares; runs nothing
        'agentapi/sentinel_tools.py',  # 1.4 contract 5: the names of the tools whose versions a Sentinel reports, compared with the shipped ones; runs nothing
        'agentapi/services.py',
        'agentapi/system_status.py',
        'cveFeed/ai_disclosure.py',  # AI and your data page: says in words which AI job picks nuclei templates and what it is sent; runs nothing
        'cveFeed/apps.py',
        'cveFeed/auth_checks.py',
        'cveFeed/auth_nuclei.py',  # T8 nuclei: ledger service keys (nuclei-auth, nuclei-auth-refused) are stored data, plus activity text; runs nothing, the signed-in pass is the built-in scanner's
        'cveFeed/check_allowlist.py',  # 1.4.0 AI-written checks on Sentinels: the allowlist a nuclei template must meet (it names nuclei's parser and helpers), runs nothing
        'cveFeed/check_coverage.py',
        'cveFeed/conductor.py',
        'cveFeed/confirm_guide.py',  # 1.3.3 confirmation guide (develop): tells a person how to check a finding by hand, runs nothing
        'cveFeed/counts.py',
        'cveFeed/coverage_topup.py',
        'cveFeed/detection.py',
        'cveFeed/detection_commands.py',
        'cveFeed/diagnostics.py',
        'cveFeed/discovery.py',
        'cveFeed/finding_confirm.py',  # Confirm it yourself guides for scanner and hygiene findings: the read-only commands a person runs, as text; runs nothing
        'cveFeed/fullscan.py',
        'cveFeed/internal_scan.py',
        'cveFeed/js_libraries.py',  # 1.3.3 JS library evidence (develop): a docstring naming evidence sources, runs nothing
        'cveFeed/ledger.py',
        'cveFeed/management/commands/backfill_panel_versions.py',  # re-reads stored panel template findings for the version they extracted, runs nothing
        'cveFeed/management/commands/backfill_secrets_inventory.py',  # 1.4 secrets inventory: names the nuclei findings it files and masks (rule ids, the finding's source), runs nothing
        'cveFeed/management/commands/recheck_template_hits.py',  # re-reads stored template hits: names the nuclei-cve finding source and the stored nuclei_template step, runs nothing
        'cveFeed/management/commands/seed_scale_fixture.py',  # scale fixture: names the ledger services 'nuclei' as stored data values (synthetic rows for scripts/scale), runs nothing
        'cveFeed/match_policy.py',  # 1.3.2 version-only heat cap (develop): names the confirming tools, runs nothing
        'cveFeed/migrations/0016_nuclei_template_update_schedule.py',
        'cveFeed/migrations/0049_weekly_deep_nuclei.py',
        'cveFeed/migrations/0079_nuclei_templates_every_six_hours.py',
        'cveFeed/migrations/0175_drop_nuclei_template_refresh.py',  # removes the old template refresh schedule; runs nothing
        'cveFeed/models.py',
        'cveFeed/network_detection.py',  # the network detection pass (contract 10): reads the result lines a Sentinel returned and fills what the port scan left out of a port row, runs nothing
        'cveFeed/notify.py',
        'cveFeed/nuclei_fp.py',  # 1.3.5 scanner false positives (develop): judges nuclei results already returned, runs nothing
        'cveFeed/nuclei_scan.py',  # T8 nuclei: ledger service keys (nuclei-light, nuclei-cve) and the finding source/module value, stored data, plus activity text naming the pass; runs nothing
        'cveFeed/nuclei_templates.py',
        'cveFeed/panel_versions.py',  # reads the result lines and stored findings of panel templates for the version they extracted, runs nothing
        'cveFeed/performance_review.py',
        'cveFeed/reaper.py',
        'cveFeed/report_data.py',
        'cveFeed/result_cuts.py',  # 1.4 contract 5: the names of what a result cut (a result kind or a limit), in plain words; runs nothing
        'cveFeed/reviewer.py',  # AI reviewer: names nuclei as a finding kind and the template refresh task, runs nothing
        'cveFeed/safeyaml.py',
        'cveFeed/secret_redaction.py',  # 1.3.2 secret masking (develop): names the tools whose output it masks, runs nothing
        'cveFeed/secrets_catalog.py',  # 1.4 secrets inventory: names the nuclei findings it files and masks (rule ids, the finding's source), runs nothing
        'cveFeed/secrets_inventory.py',  # 1.4 secrets inventory: names the nuclei findings it files and masks (rule ids, the finding's source), runs nothing
        'cveFeed/settings_api.py',  # the setting name of the model for the nuclei tag choice (nuclei_model) and its audit action: names the tool, runs nothing
        'cveFeed/setup_flow.py',  # the setup wizard (1.4): scanner kind names such as nmap or nuclei as the toggles it offers (data values written to the Sentinel settings), runs nothing
        'cveFeed/setup_questions.py',  # FA-10: the update question and its note name the tool in words an administrator reads; runs nothing
        'cveFeed/software.py',  # the About page list of the tools of both images (names, versions, licenses), runs nothing
        'cveFeed/source_versions.py',  # reads the versions stored results already state, among them a network detection template's (vsrc:nuclei), and names them as reading sources, runs nothing
        'cveFeed/supplier_scan.py',
        'cveFeed/tailscale_sync.py',
        'cveFeed/tasks.py',
        'cveFeed/tech_links.py',  # the technology link source vocabulary: names which pass's stored result linked a technology, runs nothing
        'cveFeed/template_gates.py',  # 1.3.5 template gates (develop): holds back a nuclei template's hit on a patched version, runs nothing
        'cveFeed/templategen.py',  # T8 nuclei: the AI prompt that asks for a nuclei template, the template library path and the nuclei-cve finding source; runs nothing
        'cveFeed/threat.py',  # 1.3.3 heat policy (develop): names the scanners whose findings carry CVEs, runs nothing
        'cveFeed/triage.py',
        'cveFeed/tunables.py',  # 1.3.2 tunables registry (develop): setting names and help text, runs nothing
        'cveFeed/validation.py',  # T8 nuclei: help text and the policy docstring naming the template policy; the nuclei_template check kind is a data value; runs nothing
        'cveFeed/views.py',
        'cveFeed/work_planner.py',  # 1.4 work planner: the check-to-tool table of the coverage rules, queues Sentinel tasks, runs nothing
        'cvengine/ai_nuclei_model.py',  # the model of the nuclei tag choice (an AI call about tag names, the stages nuclei_targeting and nuclei_tag_selection): names the tool, runs nothing
        'cvengine/ai_providers.py',
        'cvengine/definitions.py',
        'cvengine/input_guard.py',
        'cvengine/resources.py',
        'cvengine/tasks.py',
        'dashboard/models.py',  # widened guard (targetApp, startScan, scanEngine, dashboard): the template policy settings: field help, runs nothing
        'scanEngine/migrations/0007_delete_installedexternaltool.py',  # widened guard (targetApp, startScan, scanEngine, dashboard): drops the old installed-tool table, runs nothing
        'startScan/models.py',  # widened guard (targetApp, startScan, scanEngine, dashboard): stored results: names the tool a finding came from, runs nothing
        'targetApp/target_types.py',  # widened guard (targetApp, startScan, scanEngine, dashboard): target classification: names the tools in comments about what a Sentinel takes, runs nothing
    ],
    'naabu': [
        'agentapi/mcp.py',
        'agentapi/models.py',
        'agentapi/rest.py',
        'agentapi/sentinel_adopt.py',  # the kind name as a data key of the adopter registry and in its docstring: files a Sentinel's result, runs nothing
        'agentapi/sentinel_broker.py',
        'agentapi/sentinel_dispatch.py',
        'agentapi/sentinel_tools.py',  # 1.4 contract 5: the names of the tools whose versions a Sentinel reports, compared with the shipped ones; runs nothing
        'cveFeed/check_coverage.py',
        'cveFeed/host_assessment.py',  # 1.3.2 assessment batches (develop): comments about the dispatched stages, runs nothing
        'cveFeed/ledger.py',
        'cveFeed/management/commands/seed_scale_fixture.py',  # scale fixture: names the ledger services 'naabu' as stored data values (synthetic rows for scripts/scale), runs nothing
        'cveFeed/port_stage.py',  # the ledger service and Port source of the discovery pass, and the discovery pass's own activity text: data values, runs nothing
        'cveFeed/report_data.py',
        'cveFeed/setup_flow.py',  # the setup wizard (1.4): scanner kind names such as nmap or nuclei as the toggles it offers (data values written to the Sentinel settings), runs nothing
        'cveFeed/software.py',  # the About page list of the tools of both images (names, versions, licenses), runs nothing
        'cveFeed/tunables.py',  # 1.3.2 tunables registry (develop): setting names and help text, runs nothing
        'cveFeed/work_planner.py',  # 1.4 work planner: the check-to-tool table of the coverage rules, queues Sentinel tasks, runs nothing
        'scanEngine/migrations/0007_delete_installedexternaltool.py',  # widened guard (targetApp, startScan, scanEngine, dashboard): drops the old installed-tool table, runs nothing
    ],
    'wpscan': [
        'agentapi/mcp.py',  # capability list in a tool description names the kind, runs nothing
        'agentapi/rest.py',  # capability and task kind lists in the route help name the kind, runs nothing
        'agentapi/sentinel_broker.py',  # the kind name as a data value: result cleaner and token scrub, runs nothing
        'agentapi/sentinel_dispatch.py',  # the kind name as a data value (NEVER_LOCAL, ceilings, dispatch of the task), runs nothing
        'agentapi/sentinel_tools.py',  # 1.4 contract 5: the names of the tools whose versions a Sentinel reports, compared with the shipped ones; runs nothing
        'cveFeed/api_credentials.py',  # the stored credential service key is the kind name, a data value
        'cveFeed/check_coverage.py',  # ledger kinds and the check id are data values, runs nothing
        'cveFeed/confirm_guide.py',  # matches the finding source stored in the database, runs nothing
        'cveFeed/discovery.py',  # the pipeline stage name and its result key are data values, runs nothing
        'cveFeed/finding_confirm.py',  # Confirm it yourself guides for scanner and hygiene findings: the read-only commands a person runs, as text; runs nothing
        'cveFeed/finding_lifecycle.py',  # finding source and template id prefix stored in the database, runs nothing
        'cveFeed/host_context.py',  # reads the stored probe name, runs nothing
        'cveFeed/ledger.py',  # ledger kind names (freshness windows) are data values, runs nothing
        'cveFeed/management/commands/close_fixed_findings.py',  # reads stored probe rows by source, runs nothing
        'cveFeed/nuclei_templates.py',  # a template tag of the public nuclei template feed, not this tool
        'cveFeed/report_data.py',  # the stage key of the report labels is a data value, runs nothing
        'cveFeed/scan_concurrency.py',  # a comment naming the WPScan sweep among the classic lane's one-at-a-time tasks, runs nothing
        'cveFeed/setup_flow.py',  # the setup wizard (1.4): scanner kind names such as nmap or nuclei as the toggles it offers (data values written to the Sentinel settings), runs nothing
        'cveFeed/software.py',  # the About page list of the tools of both images (names, versions, licenses), runs nothing
        'cveFeed/source_versions.py',  # reads the versions stored results already state (the port scan's CPEs and scripts, the TLS audit's banners, the WordPress scan's headers, a discovery's CPEs) and names them as reading sources, runs nothing
        'cveFeed/tech_links.py',  # the technology link source vocabulary: names which pass's stored result linked a technology, runs nothing
        'cveFeed/threat.py',  # VERSION_READ_SOURCES names the stored finding source, runs nothing
        'cveFeed/work_planner.py',  # 1.4 work planner: the check-to-tool table of the coverage rules, queues Sentinel tasks, runs nothing
        'cveFeed/wp_correlation.py',  # evidence source stored with a correlated finding, runs nothing
        'cveFeed/wpscan_scan.py',  # stores what a Sentinel reports: finding source, probe and ledger names are data values, runs nothing
    ],
    'testssl': [
        'agentapi/mcp.py',
        'agentapi/rest.py',
        'agentapi/sentinel_broker.py',
        'agentapi/sentinel_dispatch.py',
        'agentapi/sentinel_tools.py',  # 1.4 contract 5: the names of the tools whose versions a Sentinel reports, compared with the shipped ones; runs nothing
        'agentapi/services.py',  # a TLS audit finding's page: the tool's raw result is labelled "testssl.sh output" (an excerpt key and a label), runs nothing
        'cveFeed/check_coverage.py',
        'cveFeed/confirm_guide.py',  # 1.3.3 confirmation guide (develop): tells a person how to check a finding by hand, runs nothing
        'cveFeed/internal_scan.py',
        'cveFeed/ledger.py',
        'cveFeed/management/commands/rewrite_tls_findings.py',  # the update step that rewrites stored TLS audit findings from their evidence: names the tool in its help, runs nothing
        'cveFeed/match_explain.py',  # explains a match to a person: reads the stored finding source 'testssl' and writes a sentence, runs nothing
        'cveFeed/migrations/0094_testssl_schedule.py',
        'cveFeed/report_data.py',
        'cveFeed/setup_flow.py',  # the setup wizard (1.4): scanner kind names such as nmap or nuclei as the toggles it offers (data values written to the Sentinel settings), runs nothing
        'cveFeed/software.py',  # the About page list of the tools of both images (names, versions, licenses), runs nothing
        'cveFeed/source_versions.py',  # reads the versions stored results already state (the port scan's CPEs and scripts, the TLS audit's banners, the WordPress scan's headers, a discovery's CPEs) and names them as reading sources, runs nothing
        'cveFeed/tls_audit.py',  # 1.4 TLS audit on a Sentinel: the kind name, the ledger key and the finding source are stored data values, runs nothing
        'cveFeed/tls_catalogue.py',  # TLS audit catalogue: what each test means and the read-only commands a person runs to confirm it, as text; runs nothing
        'cveFeed/triage.py',  # reads the stored confidence of a TLS audit finding (confirmed or unconfirmed) as a triage fact, runs nothing
        'cveFeed/upgrade_backfills.py',  # names the update step that rewrites stored TLS audit findings, runs nothing
        'cveFeed/work_planner.py',  # 1.4 work planner: the check-to-tool table of the coverage rules, queues Sentinel tasks, runs nothing
    ],
    'bbot': [
        'agentapi/mcp.py',  # 1.4 T8: user-facing tool descriptions that name the discovery tool (share lines with other tool words), runs nothing
        'agentapi/rest.py',  # 1.4 T8: user-facing route descriptions that name the discovery tool (share lines with other tool words), runs nothing
        'agentapi/sentinel_adopt.py',  # the kind name as a data key of the adopter registry and in its docstring: files a Sentinel's result, runs nothing
        'agentapi/sentinel_broker.py',  # 1.4 bbot on a Sentinel: the run's time budget and the secure read of its module keys, runs nothing
        'agentapi/sentinel_policy.py',  # 1.4 bbot on a Sentinel: the kind's label, runs nothing
        'agentapi/sentinel_settings.py',  # bbot_keys: the name of the optional heartbeat feature a Sentinel advertises for a discovery's API keys (a data value and its comment), runs nothing
        'agentapi/sentinel_tools.py',  # 1.4 contract 5: the names of the tools whose versions a Sentinel reports, compared with the shipped ones; runs nothing
        'agentapi/services.py',  # 1.4 T8: finding kind 'bbot' (a stored data value) and text shared with other tool words, runs nothing
        'cveFeed/check_coverage.py',  # 1.4 T8: ledger service keys 'bbot' and 'bbot-deep' and the check label (stored data values), runs nothing
        'cveFeed/diagnostics.py',  # 1.4 T8: finding kind 'bbot' (a stored data value), runs nothing
        'cveFeed/discovery.py',  # 1.4 T8: ledger service keys 'bbot' and 'bbot-deep' and the activity title (stored data values), runs nothing
        'cveFeed/host_resolver.py',  # gone grace: reads the ledger TTL of the service key 'bbot-deep' (a stored data value) and names its env var, runs nothing
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
        'cveFeed/result_cuts.py',  # 1.4 contract 5: the names of what a result cut (a result kind or a limit), in plain words; runs nothing
        'cveFeed/reviewer.py',  # AI reviewer: names bbot as a finding kind to review, runs nothing
        'cveFeed/secrets_catalog.py',  # 1.4 secrets inventory: names the bbot findings it files and masks (rule ids, the finding's source), runs nothing
        'cveFeed/secrets_inventory.py',  # 1.4 secrets inventory: names the bbot findings it files and masks (rule ids, the finding's source), runs nothing
        'cveFeed/setup_flow.py',  # the setup wizard (1.4): scanner kind names such as nmap or nuclei as the toggles it offers (data values written to the Sentinel settings), runs nothing
        'cveFeed/software.py',  # the About page list of the tools of both images (names, versions, licenses), runs nothing
        'cveFeed/source_versions.py',  # reads the versions stored results already state (the port scan's CPEs and scripts, the TLS audit's banners, the WordPress scan's headers, a discovery's CPEs) and names them as reading sources, runs nothing
        'cveFeed/supplier_scan.py',  # 1.4 T8: docstring line shared with other tool words, runs nothing
        'cveFeed/tasks.py',  # 1.4 T8: ledger key 'bbot-deep' (a stored data value), runs nothing
        'cveFeed/tech_links.py',  # the technology link source vocabulary: names which pass's stored result linked a technology, runs nothing
        'cveFeed/threat.py',  # 1.3.5 heat rules (develop): names the sources whose severity heat is not held back, runs nothing
        'cveFeed/triage.py',  # 1.4 T8: finding kind 'bbot' (a stored data value), runs nothing
        'cveFeed/upgrade_backfills.py',  # 1.4 secrets inventory: names the bbot findings it files and masks (rule ids, the finding's source), runs nothing
        'cvengine/resources.py',  # 1.4 T8: heavy-job kind names 'bbot-deep', 'bbot-standard', 'bbot-passive' now unused: lead decides with the tunables that name them (one-line tables shared with other tools), runs nothing
        'cvengine/tasks.py',  # 1.4 T8: stores a Sentinel's discovery results with source 'bbot' (a stored data value), runs nothing
        'dashboard/models.py',  # widened guard (targetApp, startScan, scanEngine, dashboard): the discovery settings: names the discovery tool in field help and choices, runs nothing
        'startScan/migrations/0007_deshare_ports.py',  # widened guard (targetApp, startScan, scanEngine, dashboard): an old data migration: names the tools whose rows it moved, runs nothing
        'startScan/migrations/0011_shorten_bbot_names.py',  # widened guard (targetApp, startScan, scanEngine, dashboard): an old data migration: names the tool whose rows it shortened, runs nothing
        'startScan/migrations/0025_scanhistory_discovery_mode.py',  # widened guard (targetApp, startScan, scanEngine, dashboard): an old migration: the discovery mode field help, runs nothing
        'startScan/models.py',  # widened guard (targetApp, startScan, scanEngine, dashboard): stored results: names the tool a row came from, runs nothing
        'targetApp/models.py',  # widened guard (targetApp, startScan, scanEngine, dashboard): target settings: names the discovery tool in field help, runs nothing
        'targetApp/target_types.py',  # widened guard (targetApp, startScan, scanEngine, dashboard): target classification: names the tools in comments about what a Sentinel takes, runs nothing
    ],
    'wafw00f': [
        'agentapi/sentinel_tools.py',  # 1.4 contract 5: the names of the tools whose versions a Sentinel reports, compared with the shipped ones; runs nothing
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
        'cveFeed/report_pdf.py',
        'cveFeed/templatefixture.py',  # runs a model-written regex in a time-limited child interpreter; no scan tool (review 2 F5)
        'cvengine/time_limits.py',
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


# --- the server resolves no scanned target name -------------------------------------------------------------------------------------------------------
# All scanning runs on the Sentinels: only the Sentinel that runs the work resolves a target's name, when it connects, and refuses it when any address is one
# no Sentinel may scan (``cvengine_scanner.scope.check_host``). A lookup in this server's code is a second, divergent judgement of a target and a request
# the server makes about it, so any new one fails here. The few lookups that remain are of names that are not scan targets, each with its reason.
LOOKUP = re.compile(r'\bgetaddrinfo\b|\bgethostbyname(?:_ex)?\b|\bdns\.resolver\b|\bdns\.query\b|\bcreate_connection\b|\bdns\.asyncresolver\b')
LOOKUP_ALLOWED = {
    'cveFeed/openvas_scan.py': "own_addresses: this server's own DOMAIN_NAME, so OpenVAS is never pointed at the server itself",
    'cveFeed/self_exclusion.py': "this server's own public names (DOMAIN_NAME, CVENGINE_ALLOWED_HOSTS), so no scan is ever sent at the server itself",
    'cveFeed/settings_api.py': 'the SSRF check of an outbound URL an App Admin enters (SMTP host, AI base URL), not a scan target',
    'cvengine/ai_providers.py': "the SSRF check of the AI provider's base URL, not a scan target",
    'cvengine/hook_guard.py': 'the SSRF check of a notification webhook URL (Slack, Discord, Lark), at save and before each send, not a scan target',
}


def lookup_usage():
    """The files (relative to web/) whose code names a way to resolve a host name."""
    return {rel for rel in candidate_files() if LOOKUP.search((WEB / rel).read_text(encoding='utf-8', errors='replace'))}


class NoTargetLookupTests(SimpleTestCase):
    def test_no_server_side_lookup_of_a_target_name(self):
        found = lookup_usage()
        new = sorted(found - set(LOOKUP_ALLOWED))
        self.assertFalse(new, 'A host name lookup in server code (the server resolves no target name: the Sentinel that runs the work does). Send the '
                              'question to a Sentinel (dns_resolve, identity_check) or read the addresses a Sentinel stored; a lookup of a name that is not '
                              'a scan target goes in LOOKUP_ALLOWED with its reason: ' + ', '.join(new))
        self.assertFalse(sorted(set(LOOKUP_ALLOWED) - found), 'a LOOKUP_ALLOWED entry no longer matches: delete it')

    def test_the_guard_sees_a_lookup(self):
        self.assertTrue(LOOKUP.search('socket.getaddrinfo(host, None)'))
        self.assertTrue(LOOKUP.search('import dns.resolver'))
        self.assertFalse(LOOKUP.search('scannable_hosts(names)'))


# --- the server image ships no scan tool and no template set ------------------------------------------------------------------------------------------
REPO = WEB.parent
IMAGE_TOOL = re.compile(r'\b(?:%s)\b|nuclei-templates|go install|GOVERSION|update-templates' % '|'.join(TOOL_WORDS), re.I)


class ServerImageTests(SimpleTestCase):
    def test_the_dockerfile_builds_and_ships_no_scan_tool(self):
        text = (WEB / 'Dockerfile').read_text(encoding='utf-8')
        found = sorted({m.group(0).lower() for m in IMAGE_TOOL.finditer(text)})
        self.assertFalse(found, f'web/Dockerfile names a scan tool or builds one ({found}): every scan tool and template set lives in the Sentinel image')

    def test_no_server_service_mounts_a_template_set(self):
        for name in ('docker-compose.yml', 'docker-compose.dev.yml'):
            path = REPO / name
            if path.is_file():
                with self.subTest(file=name):
                    self.assertNotIn('nuclei-templates', path.read_text(encoding='utf-8'), f'{name} mounts a template set into a server container')

    def test_the_entrypoints_run_no_scan_tool(self):
        for name in ('entrypoint.sh', 'celery-entrypoint.sh', 'beat-entrypoint.sh'):
            path = WEB / name
            if path.is_file():
                with self.subTest(file=name):
                    commands = [line for line in path.read_text(encoding='utf-8').splitlines() if line.strip() and not line.strip().startswith('#')]
                    self.assertFalse([c for c in commands if IMAGE_TOOL.search(c)], f'{name} runs a scan tool')
