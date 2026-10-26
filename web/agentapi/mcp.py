"""MCP server (Streamable HTTP, JSON-RPC 2.0 over POST /mcp/) exposing CVEngine to agents.

Tools are thin wrappers over agentapi.services, so they inherit the same
tenancy scoping, role checks and read-only-token rules as the REST API.
"""
import json
import logging

from django.http import HttpResponse, JsonResponse
from django.core.exceptions import RequestDataTooBig

from agentapi import host_manage as hosts
from agentapi import services as svc
from agentapi import system_status
from agentapi.services import ApiError, Ctx

logger = logging.getLogger(__name__)

SUPPORTED_VERSIONS = ('2025-06-18', '2025-03-26', '2024-11-05')
SERVER_INFO = {'name': 'cvengine', 'version': '1.0.0'}
MAX_BODY_BYTES = 256 * 1024
MAX_BATCH_ITEMS = 20
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
SLUG = {'type': 'string', 'description': 'Project slug (see list_projects)'}
SLUG_OR_ALL = {'type': 'string', 'description': "Project slug (see list_projects), or '_all' for every project you can access: read-only, and each row names its own project"}


def _schema(props=None, required=()):
    return {'type': 'object', 'properties': props or {}, 'required': list(required)}


def _page_props(extra=None):
    props = {'page': {'type': 'integer'}, 'page_size': {'type': 'integer'}}
    props.update(extra or {})
    return props


# name, description, input schema, handler(ctx, args), writes
TOOLS = [
    ('whoami', 'Current user, projects with roles, and token info.', _schema(), lambda c, a: svc.me(c), False),
    ('list_projects', 'Projects you can access, with your role in each.', _schema(), lambda c, a: svc.list_projects(c), False),
    ('get_system_status', "Instance status in one call: overall ok/degraded with problems and notes, whether scanning is paused, the update phase, and for your projects the targets, hosts, exposed hosts, scans running/queued/stalled and open findings. An App Admin also gets the database and broker, queue depths, workers and what they consume, schedules past due, memory per container, disk, CVE feed freshness and today's AI validation budget. Read-only; may take up to ten seconds while workers answer.", _schema(), lambda c, a: system_status.system_status(c), False),
    ('list_engines', 'Available scan engines.', _schema(), lambda c, a: svc.list_engines(c), False),
    ('list_targets', 'Targets (domains, IPs) in a project.', _schema(_page_props({'project': SLUG_OR_ALL, 'q': {'type': 'string'}}), ['project']),
     lambda c, a: svc.list_targets(c, a.get('project'), a), False),
    ('add_target', 'Add a domain, IP, CIDR or range as a target.', _schema(
        {'project': SLUG, 'value': {'type': 'string'}, 'description': {'type': 'string'},
         'discover': {'type': 'boolean', 'description': 'also start live bbot discovery'}}, ['project', 'value']),
     lambda c, a: svc.add_target(c, a.get('project'), a.get('value', ''), a.get('description', ''), bool(a.get('discover'))), True),
    ('add_targets', 'Add many targets at once (list or pasted text) and start discovery. mode: standard (default), deep or passive.', _schema(
        {'project': SLUG, 'targets': {'type': 'array', 'items': {'type': 'string'}}, 'discover': {'type': 'boolean'},
         'mode': {'type': 'string', 'enum': ['standard', 'deep', 'passive']}}, ['project', 'targets']),
     lambda c, a: svc.add_targets(c, a.get('project'), a.get('targets'), bool(a.get('discover', True)), a.get('mode')), True),
    ('add_targets_by_org', 'Bulk add across one organization. text: "##Org" once, then "#Project" above each list of domains/IPs/CIDRs. Creates missing projects (needs org admin).', _schema(
        {'text': {'type': 'string'}, 'discover': {'type': 'boolean'}, 'mode': {'type': 'string', 'enum': ['standard', 'deep', 'passive']},
         'current_project': {'type': 'string', 'description': 'slug of the project in use; its organization is used when the paste names none'}}, ['text']),
     lambda c, a: svc.add_targets_by_org(c, a.get('text', ''), bool(a.get('discover', True)), a.get('mode'), a.get('current_project')), True),
    ('delete_targets', 'Delete targets (and their hosts, scans and results) by ids, or all matching q. Targets with a running scan are skipped. Irreversible.', _schema(
        {'project': SLUG, 'ids': {'type': 'array', 'items': {'type': 'integer'}}, 'all_matching': {'type': 'boolean'}, 'q': {'type': 'string'}}, ['project']),
     lambda c, a: svc.delete_targets(c, a.get('project'), a.get('ids'), bool(a.get('all_matching')), a.get('q') or ''), True),
    ('discover_target', 'Run standard (default), deep or passive bbot discovery and then nuclei on an existing target.', _schema(
        {'project': SLUG, 'target_id': {'type': 'integer'}, 'mode': {'type': 'string', 'enum': ['standard', 'deep', 'passive']}}, ['project', 'target_id']),
     lambda c, a: svc.discover_target(c, a.get('project'), int(a['target_id']), a.get('mode')), True),
    ('set_target_scope', 'Set a target\'s scope_mode: auto (the shared-domain list decides: a tenant on a provider domain such as acme.jfrog.com is host-only), host (this host only, never its parent domain) or parent (the parent domain is yours even if it is a provider domain; use with care).', _schema(
        {'project': SLUG, 'target_id': {'type': 'integer'}, 'scope_mode': {'type': 'string', 'enum': ['auto', 'host', 'parent']}},
        ['project', 'target_id', 'scope_mode']),
     lambda c, a: svc.set_target_scope(c, a.get('project'), int(a['target_id']), a.get('scope_mode')), True),
    ('rescan_hosts', 'Scan specific hosts of a target now (nmap, exposure check, nuclei, CVE correlation) without a bbot run. Hosts must be the target or under it; up to 200. Work done recently is skipped.', _schema(
        {'project': SLUG, 'target_id': {'type': 'integer'}, 'hosts': {'type': 'array', 'items': {'type': 'string'}}},
        ['project', 'target_id', 'hosts']),
     lambda c, a: svc.rescan_hosts(c, a.get('project'), int(a['target_id']), a.get('hosts')), True),
    ('assess_host', 'Queue a fresh scoped assessment of one stored host, including DNS, ports, templates, correlation, AI and host TLS. Returns a durable job ID.',
     _schema({'project': SLUG, 'host_id': {'type': 'integer'}}, ['project', 'host_id']),
     lambda c, a: svc.request_host_assessment(c, a.get('project'), a.get('host_id')), True),
    ('get_host_assessment', 'Get the status and individual scan stages of a host assessment.',
     _schema({'project': SLUG, 'assessment_id': {'type': 'integer'}}, ['project', 'assessment_id']),
     lambda c, a: svc.get_host_assessment(c, a.get('project'), int(a['assessment_id'])), False),
    ('stop_host_assessment', 'Stop one queued or running host assessment.',
     _schema({'project': SLUG, 'assessment_id': {'type': 'integer'}}, ['project', 'assessment_id']),
     lambda c, a: svc.stop_host_assessment(c, a.get('project'), int(a['assessment_id'])), True),
    ('list_scans', 'Scans in a project.', _schema(_page_props({'project': SLUG_OR_ALL, 'target_id': {'type': 'integer'}}), ['project']),
     lambda c, a: svc.list_scans(c, a.get('project'), a), False),
    ('get_scan', 'One scan with counts.', _schema({'project': SLUG, 'scan_id': {'type': 'integer'}}, ['project', 'scan_id']),
     lambda c, a: svc.get_scan(c, a.get('project'), int(a['scan_id'])), False),
    ('list_scan_subdomains', 'Subdomains found by one scan.', _schema(_page_props({'project': SLUG, 'scan_id': {'type': 'integer'}, 'q': {'type': 'string'}}), ['project', 'scan_id']),
     lambda c, a: svc.list_scan_subdomains(c, a.get('project'), int(a['scan_id']), a), False),
    ('list_scan_endpoints', 'Endpoints found by one scan.', _schema(_page_props({'project': SLUG, 'scan_id': {'type': 'integer'}, 'q': {'type': 'string'}}), ['project', 'scan_id']),
     lambda c, a: svc.list_scan_endpoints(c, a.get('project'), int(a['scan_id']), a), False),
    ('list_scan_vulnerabilities', 'Findings from one scan.', _schema(_page_props({'project': SLUG, 'scan_id': {'type': 'integer'}, 'severity': {'type': 'string'}}), ['project', 'scan_id']),
     lambda c, a: svc.list_scan_vulnerabilities(c, a.get('project'), int(a['scan_id']), a), False),
    ('get_scan_activity', 'Task timeline of one scan (what ran, failures).', _schema(_page_props({'project': SLUG, 'scan_id': {'type': 'integer'}}), ['project', 'scan_id']),
     lambda c, a: svc.scan_activity(c, a.get('project'), int(a['scan_id']), a), False),
    ('start_scan', 'Start a scan of a target: bbot discovery, then nmap and nuclei (work already done recently is reused). engine_id is optional and ignored.', _schema(
        {'project': SLUG, 'target_id': {'type': 'integer'}, 'engine_id': {'type': 'integer'}}, ['project', 'target_id']),
     lambda c, a: svc.start_scan(c, a.get('project'), int(a['target_id']), int(a['engine_id']) if a.get('engine_id') else None), True),
    ('search_hosts', 'Shodan-style host search. q is ANDed terms: a bare word matches hostname, IP, technology, port product/service/version/CPE, OS, finding name, CVE id and page title; field filters tech: port: product: service: os: cve: ip: (address or CIDR) host: vuln: sev: auth: (open|login|session_required|sso) sensitive: (any|credentials|pii|internal) zombie: (yes|no) country: (ISO code or name); a filter value takes a comma-separated list for OR (port:80,443) unless quoted; -term negates; "quoted phrase". heat narrows the page to that value; the response\'s facets.heat always counts every value (fire, smoke, ice, clean, unscanned) over the whole match of q, ignoring heat itself; facets (comma-separated, among port, product, tech, os, country) adds the same whole-match counting for those fields, each up to facet_size values (default 10, max 50), highest count first. Each result says what matched. Sorted by score, highest first (sort=name for names).',
     _schema(_page_props({'project': SLUG_OR_ALL, 'q': {'type': 'string'}, 'sort': {'type': 'string', 'enum': ['score', 'name']},
                          'heat': {'type': 'string', 'enum': ['fire', 'smoke', 'ice', 'clean', 'unscanned']},
                          'facets': {'type': 'string'}, 'facet_size': {'type': 'integer'}}), ['project']),
     lambda c, a: svc.search_hosts(c, a.get('project'), a), False),
    ('stop_scan', 'Stop one running or queued scan: its scanner processes are killed and the next queued scan proceeds.', _schema(
        {'project': SLUG, 'scan_id': {'type': 'integer'}}, ['project', 'scan_id']),
     lambda c, a: svc.stop_scan(c, a.get('project'), int(a['scan_id'])), True),
    ('stop_all_scans', 'Stop every running and queued scan of a project.', _schema({'project': SLUG}, ['project']),
     lambda c, a: svc.stop_scans(c, a.get('project')), True),
    ('list_hosts', 'Inventory: hosts with IPs, open ports, product/version per service and a 0-100 score with its reasons, highest score first.',
     _schema(_page_props({'project': SLUG_OR_ALL, 'q': {'type': 'string'}, 'target_id': {'type': 'integer'}, 'sort': {'type': 'string', 'enum': ['score', 'name']}}), ['project']),
     lambda c, a: svc.list_hosts(c, a.get('project'), a), False),
    ('set_host_profile', 'Set the asset information of a host: owner, purpose and criticality (unknown, low, medium, high, critical). Only the fields given change.', _schema(
        {'project': SLUG, 'host': {'type': 'string', 'description': 'exact host name'}, 'owner': {'type': 'string'}, 'purpose': {'type': 'string'},
         'criticality': {'type': 'string', 'enum': ['unknown', 'low', 'medium', 'high', 'critical']}}, ['project', 'host']),
     lambda c, a: hosts.update_host_profile(c, a.get('project'), a['host'], a.get('owner'), a.get('purpose'), a.get('criticality')), True),
    ('archive_host', 'Reversibly archive one stored host of a project, preserving evidence. Pinned hosts cannot be archived.',
     _schema({'project': SLUG, 'host': {'type': 'string'}, 'reason': {'type': 'string'}}, ['project', 'host']),
     lambda c, a: hosts.host_archive(c, a.get('project'), a['host'], 'archive', reason=a.get('reason', '')), True),
    ('restore_host', 'Restore one archived host to active scheduling. Use assess_host to request fresh checks.',
     _schema({'project': SLUG, 'host': {'type': 'string'}}, ['project', 'host']),
     lambda c, a: hosts.host_archive(c, a.get('project'), a['host'], 'restore'), True),
    ('pin_host', 'Pin or unpin one stored host against future automatic archival.',
     _schema({'project': SLUG, 'host': {'type': 'string'}, 'pinned': {'type': 'boolean'}}, ['project', 'host', 'pinned']),
     lambda c, a: hosts.host_archive(c, a.get('project'), a['host'], 'pin', pinned=a['pinned']), True),
    ('delete_host', 'Delete one host\'s data (findings, CVE matches, endpoints, state, asset information) from THIS project only. The host can be rediscovered by a later scan. Exact name, irreversible.', _schema(
        {'project': SLUG, 'host': {'type': 'string', 'description': 'exact host name'}}, ['project', 'host']),
     lambda c, a: hosts.delete_host(c, a.get('project'), a['host']), True),
    ('exclude_host', 'Remove a host from EVERY project of the organization and never scan it again anywhere in the organization. Exact name only (never a suffix or subdomain). Needs an organization-level role. Irreversible without an org admin lifting the exclusion.', _schema(
        {'project': SLUG, 'host': {'type': 'string', 'description': 'exact host name'}, 'reason': {'type': 'string'}}, ['project', 'host']),
     lambda c, a: hosts.exclude_host(c, a.get('project'), a['host'], a.get('reason', '')), True),
    ('list_exclusions', 'Hosts excluded for the project\'s organization (never scanned again).', _schema({'project': SLUG}, ['project']),
     lambda c, a: hosts.list_exclusions(c, a.get('project')), False),
    ('remove_exclusion', 'Lift an exclusion so the organization can scan the host again (organization admin only).', _schema(
        {'project': SLUG, 'host': {'type': 'string'}}, ['project', 'host']),
     lambda c, a: hosts.remove_exclusion(c, a.get('project'), a['host']), True),
    ('list_findings', 'Every finding in one list, hottest first: CVE matches on hosts, scanner findings and hygiene findings. type: all|cve|scanner|hygiene; heat: fire|smoke|ice; severity: critical|high|medium|low|info; status: actionable (default: what heats a host) or all; host: substring. counts gives each type\'s total.',
     _schema(_page_props({'project': SLUG_OR_ALL, 'type': {'type': 'string', 'enum': ['all', 'cve', 'scanner', 'hygiene']},
                          'heat': {'type': 'string', 'enum': ['all', 'fire', 'smoke', 'ice']}, 'severity': {'type': 'string'},
                          'status': {'type': 'string', 'enum': ['actionable', 'all']}, 'host': {'type': 'string'}}), ['project']),
     lambda c, a: svc.list_findings(c, a.get('project'), a), False),
    ('list_vulnerabilities', 'Scanner findings. severity: info|low|medium|high|critical, or actionable (everything but info); open: true|false.',
     _schema(_page_props({'project': SLUG_OR_ALL, 'severity': {'type': 'string'}, 'open': {'type': 'string'}}), ['project']),
     lambda c, a: svc.list_vulnerabilities(c, a.get('project'), a), False),
    ('list_routes', 'Web routes (/, /admin, /api, /login and discovered endpoints) with their auth state: open, login page, session_required (401/403 or redirect to login), sso (known identity provider).', _schema(
        _page_props({'project': SLUG_OR_ALL, 'auth_state': {'type': 'string', 'enum': ['open', 'login', 'session_required', 'sso', 'redirect', 'not_found', 'error']},
                     'host': {'type': 'string'}, 'q': {'type': 'string'}, 'sensitive': {'type': 'string', 'description': '1 for routes serving sensitive data'},
                     'zombie': {'type': 'string', 'description': '1 for retired routes that answer again'}}), ['project']),
     lambda c, a: svc.list_routes(c, a.get('project'), a), False),
    ('list_certificates', 'TLS certificates on the project hosts, soonest expiry first. expiring_within = days.', _schema(
        _page_props({'project': SLUG_OR_ALL, 'expiring_within': {'type': 'string'}, 'q': {'type': 'string'}}), ['project']),
     lambda c, a: svc.list_certificates(c, a.get('project'), a), False),
    ('list_hygiene_findings', 'TLS / certificate / SPF / DKIM / DMARC findings. check: spf|dmarc|dkim|tls|caa.', _schema(
        _page_props({'project': SLUG_OR_ALL, 'severity': {'type': 'string'}, 'check': {'type': 'string'}, 'status': {'type': 'string'}}), ['project']),
     lambda c, a: svc.list_hygiene(c, a.get('project'), a), False),
    ('list_changes', 'Inventory changes since a time (ISO or 24h/7d/30d): hosts appearing or retiring, ports opened or closed, product/version, technology, certificate and auth-state changes.', _schema(
        _page_props({'project': SLUG_OR_ALL, 'since': {'type': 'string'}, 'kind': {'type': 'string'}, 'host': {'type': 'string'}}), ['project']),
     lambda c, a: svc.list_changes(c, a.get('project'), a), False),
    ('list_activity', 'The AI activity log, newest first: what the engine read, checked, wrote, ran and validated, for this project plus system-wide entries. kind: feed|inventory|target|confirm|write_check|run_check|validate|discovery|scan|hygiene|changes|remediation.', _schema(
        _page_props({'project': SLUG_OR_ALL, 'kind': {'type': 'string'}}), ['project']),
     lambda c, a: svc.list_activity(c, a.get('project'), a), False),
    ('stats_history', "Daily snapshots of a project's inventory and findings counts, oldest first, for trend charts: {date, hosts, exposed_hosts, open_findings: {critical..info}, cve_matches: {fire, smoke, ice}, fixed, mean_days_to_fix}. days (default 90, capped at 365).", _schema(
        {'project': SLUG_OR_ALL, 'days': {'type': 'integer'}}, ['project']),
     lambda c, a: svc.stats_history(c, a.get('project'), a), False),
    ('run_hygiene_checks', 'Run the certificate, TLS and email-authentication checks now (optionally for one target).', _schema(
        {'project': SLUG, 'target_id': {'type': 'integer'}}, ['project']),
     lambda c, a: svc.run_hygiene_checks(c, a.get('project'), a.get('target_id')), True),
    ('list_cves', 'The live CVE feed. tier: fire|smoke|ice.', _schema(_page_props({'tier': {'type': 'string'}, 'q': {'type': 'string'}})),
     lambda c, a: svc.list_cve_feed(c, a), False),
    ('get_cve', 'One CVE with description, affected ranges and references.', _schema({'cve_id': {'type': 'string'}}, ['cve_id']),
     lambda c, a: svc.get_cve(c, a.get('cve_id', '')), False),
    ('get_cve_detection', 'How to tell whether a product is affected by a CVE: the shared detection strategy, remote and local checks '
     'as read-only data (version ranges, HTTP markers, package and config checks, nuclei template). The same for every organization.',
     _schema({'cve_id': {'type': 'string'}}, ['cve_id']), lambda c, a: svc.get_cve_detection(c, a.get('cve_id', '')), False),
    ('list_cve_matches', 'CVEs matched to hosts, with AI verdicts and remediation status.',
     _schema(_page_props({'project': SLUG_OR_ALL, 'status': {'type': 'string'}, 'verdict': {'type': 'string'}, 'host': {'type': 'string'}}), ['project']),
     lambda c, a: svc.list_matches(c, a.get('project'), a), False),
    ('validate_cve_match', 'Queue one owned CVE match for safe template checks and AI review; returns a request id and status.',
     _schema({'project': SLUG, 'match_id': {'type': 'integer'}}, ['project', 'match_id']),
     lambda c, a: svc.validate_match_now(c, a.get('project'), int(a['match_id'])), True),
    ('get_validation_request', 'Read the queued, running, completed or failed state and result of one match validation request.',
     _schema({'project': SLUG, 'match_id': {'type': 'integer'}, 'request_id': {'type': 'integer'}},
             ['project', 'match_id', 'request_id']),
     lambda c, a: svc.validation_request(c, a.get('project'), int(a['match_id']), int(a['request_id'])), False),
    ('get_finding', 'One finding in full (kind: match, vulnerability, route or hygiene): why it matters, how it was found, first and last seen with the host history, the AI classification (and the model original when rules overrode it), the fix, and every validation check that ran with its exact command and result.', _schema(
        {'project': SLUG, 'kind': {'type': 'string', 'enum': ['match', 'vulnerability', 'route', 'hygiene']}, 'id': {'type': 'integer'}},
        ['project', 'kind', 'id']),
     lambda c, a: svc.finding_detail(c, a.get('project'), a['kind'], int(a['id'])), False),
    ('list_triage', 'AI triage of every finding with its classification (confirmed, likely, needs_validation, likely_false_positive, not_applicable; empty when not triaged), status and validation state. A likely false positive is still listed.', _schema(
        _page_props({'project': SLUG, 'status': {'type': 'string'}, 'classification': {'type': 'string'}, 'validation': {'type': 'string'},
                     'kind': {'type': 'string'}}), ['project']),
     lambda c, a: svc.list_triage(c, a.get('project'), a), False),
    ('retriage_finding', 'Look at a finding again. CVE matches use the bounded per-match validation queue; other findings use the planned read-only checks.', _schema(
        {'project': SLUG, 'kind': {'type': 'string', 'enum': ['match', 'vulnerability', 'route', 'hygiene']}, 'id': {'type': 'integer'}},
        ['project', 'kind', 'id']),
     lambda c, a: svc.retriage_finding(c, a.get('project'), a['kind'], int(a['id'])), True),
    ('register_assets', 'Register the hosts, IPs or CIDRs you are responsible for (needs a token). get_remediation_work then defaults to them.',
     _schema({'assets': {'type': 'array', 'items': {'type': 'string'}}}, ['assets']),
     lambda c, a: svc.register_assets(c, a.get('assets')), True),
    ('get_remediation_work', 'CVE-on-host items still to fix for your registered assets (or the assets arg), fire first, with fixed versions.',
     _schema(_page_props({'project': SLUG, 'assets': {'type': 'string', 'description': 'comma separated hosts/IPs/CIDRs'}, 'tier': {'type': 'string'}}), ['project']),
     lambda c, a: svc.work_items(c, a.get('project'), a), False),
    ('update_remediation_status', 'Set a match to open, in_progress, fixed or accepted_risk, with a note.',
     _schema({'project': SLUG, 'match_id': {'type': 'integer'}, 'status': {'type': 'string', 'enum': ['open', 'in_progress', 'fixed', 'accepted_risk']},
              'note': {'type': 'string'}}, ['project', 'match_id', 'status']),
     lambda c, a: svc.update_match(c, a.get('project'), int(a['match_id']), a.get('status'), a.get('note')), True),
    ('update_finding_status', 'Set the remediation status of any finding (match, vulnerability or hygiene; a route has no remediation workflow) to open, in_progress, fixed or accepted_risk, with a note.',
     _schema({'project': SLUG, 'kind': {'type': 'string', 'enum': ['match', 'vulnerability', 'hygiene']}, 'id': {'type': 'integer'},
              'status': {'type': 'string', 'enum': ['open', 'in_progress', 'fixed', 'accepted_risk']}, 'note': {'type': 'string'}},
             ['project', 'kind', 'id', 'status']),
     lambda c, a: svc.update_finding_status(c, a.get('project'), a['kind'], int(a['id']), a.get('status'), a.get('note')), True),
    ('set_finding_assignee', 'Assign a finding (match, vulnerability or hygiene) to a project member, or unassign it with assignee: null. Logged to the audit trail.',
     _schema({'project': SLUG, 'kind': {'type': 'string', 'enum': ['match', 'vulnerability', 'hygiene']}, 'id': {'type': 'integer'},
              'assignee': {'type': ['integer', 'null'], 'description': 'A member\'s user id (see list_members), or null to unassign.'}},
             ['project', 'kind', 'id', 'assignee']),
     lambda c, a: svc.update_finding_status(c, a.get('project'), a['kind'], int(a['id']), assignee=a.get('assignee')), True),
    ('list_finding_comments', 'Every comment on one finding (match, vulnerability or hygiene), oldest first.',
     _schema({'project': SLUG, 'kind': {'type': 'string', 'enum': ['match', 'vulnerability', 'hygiene']}, 'id': {'type': 'integer'}},
             ['project', 'kind', 'id']),
     lambda c, a: svc.list_finding_comments(c, a.get('project'), a['kind'], int(a['id'])), False),
    ('add_finding_comment', 'Add a comment to one finding (match, vulnerability or hygiene). Logged to the audit trail.',
     _schema({'project': SLUG, 'kind': {'type': 'string', 'enum': ['match', 'vulnerability', 'hygiene']}, 'id': {'type': 'integer'},
              'text': {'type': 'string'}}, ['project', 'kind', 'id', 'text']),
     lambda c, a: svc.add_finding_comment(c, a.get('project'), a['kind'], int(a['id']), a.get('text')), True),
    ('finding_audit', "One finding's audit trail (match, vulnerability or hygiene): status changes, assignee changes and comments, newest first, each with who, when, and before/after.",
     _schema({'project': SLUG, 'kind': {'type': 'string', 'enum': ['match', 'vulnerability', 'hygiene']}, 'id': {'type': 'integer'}},
             ['project', 'kind', 'id']),
     lambda c, a: svc.finding_audit(c, a.get('project'), a['kind'], int(a['id'])), False),
    ('get_project_settings', "The project's settings: sla_days (days to fix per severity: critical, high, medium, low; default 7/30/90/180) and sla_defaults.",
     _schema({'project': SLUG}, ['project']),
     lambda c, a: svc.get_project_settings(c, a.get('project')), False),
    ('set_project_settings', "Change the project's SLA days: send only the severities to change (critical, high, medium, low), each 1 to 3650 days, or null for the default.",
     _schema({'project': SLUG, 'sla_days': {'type': 'object', 'properties': {sev: {'type': ['integer', 'null']} for sev in ('critical', 'high', 'medium', 'low')}}},
             ['project', 'sla_days']),
     lambda c, a: svc.set_project_settings(c, a.get('project'), a), True),
    ('list_members', "The project's members (direct, plus its organization's if it has one), for an assignee picker.",
     _schema({'project': SLUG}, ['project']),
     lambda c, a: svc.list_members(c, a.get('project')), False),
    ('bulk_update_finding_status', 'Set the same remediation status and note on up to 200 findings (match, vulnerability or hygiene) at once. Returns {updated, failed: [{kind, id, error}]} so a bad id never blocks the rest.',
     _schema({'project': SLUG, 'items': {'type': 'array', 'items': _schema(
                 {'kind': {'type': 'string', 'enum': ['match', 'vulnerability', 'hygiene']}, 'id': {'type': 'integer'}}, ['kind', 'id'])},
              'status': {'type': 'string', 'enum': ['open', 'in_progress', 'fixed', 'accepted_risk']}, 'note': {'type': 'string'}},
             ['project', 'items', 'status']),
     lambda c, a: svc.bulk_update_finding_status(c, a.get('project'), a.get('items'), a.get('status'), a.get('note')), True),
]
BY_NAME = {t[0]: t for t in TOOLS}


def _rpc_result(rpc_id, result):
    return {'jsonrpc': '2.0', 'id': rpc_id, 'result': result}


def _rpc_error(rpc_id, code, message):
    return {'jsonrpc': '2.0', 'id': rpc_id, 'error': {'code': code, 'message': message}}


def call_tool(ctx, name, arguments):
    tool = BY_NAME.get(name)
    if not tool:
        raise ApiError(404, f'unknown tool {name!r}')
    _, _, _, handler, writes = tool
    if writes:
        svc.require_write_token(ctx)
    try:
        return handler(ctx, arguments or {})
    except (KeyError, TypeError, ValueError, AttributeError):
        logger.warning('MCP tool %s called with invalid arguments', name, exc_info=True)
        raise ApiError(400, 'bad arguments: a field is missing or has the wrong type')


def handle_message(ctx, msg):
    """Handle one JSON-RPC message; returns a response dict, or None for notifications."""
    if not isinstance(msg, dict) or msg.get('jsonrpc') != '2.0' or 'method' not in msg:
        return _rpc_error(msg.get('id') if isinstance(msg, dict) else None, -32600, 'invalid request')
    method, rpc_id, params = msg['method'], msg.get('id'), msg.get('params', {})
    if not isinstance(method, str) or not isinstance(rpc_id, (str, int, float, type(None))):
        return _rpc_error(None, -32600, 'invalid request')
    if not isinstance(params, dict):
        return _rpc_error(rpc_id, -32602, 'params must be an object') if 'id' in msg else None
    if 'id' not in msg:
        return None  # notification (e.g. notifications/initialized)
    if method == 'initialize':
        asked = params.get('protocolVersion')
        return _rpc_result(rpc_id, {
            'protocolVersion': asked if asked in SUPPORTED_VERSIONS else SUPPORTED_VERSIONS[0],
            'capabilities': {'tools': {'listChanged': False}}, 'serverInfo': SERVER_INFO,
            'instructions': 'CVEngine vulnerability management. Start with whoami and list_projects. '
                            'Agents fixing issues: register_assets, then get_remediation_work, then update_remediation_status.'})
    if method == 'ping':
        return _rpc_result(rpc_id, {})
    if method == 'tools/list':
        return _rpc_result(rpc_id, {'tools': [
            {'name': n, 'description': d + (' (write)' if w else ''), 'inputSchema': s,
             'annotations': {'readOnlyHint': not w}} for n, d, s, _, w in TOOLS]})
    if method == 'tools/call':
        if not isinstance(params.get('name'), str) or not isinstance(params.get('arguments', {}), dict):
            return _rpc_error(rpc_id, -32602, 'tool name must be a string and arguments an object')
        try:
            data = call_tool(ctx, params.get('name'), params.get('arguments'))
            return _rpc_result(rpc_id, {'content': [{'type': 'text', 'text': json.dumps(data, default=str)}], 'isError': False})
        except ApiError as e:
            return _rpc_result(rpc_id, {'content': [{'type': 'text', 'text': e.message}], 'isError': True})
    return _rpc_error(rpc_id, -32601, f'method not found: {method}')


def _encode_bounded(value, limit):
    """Stop encoding at the response budget instead of building a whole batch string."""
    encoded = bytearray()
    for chunk in json.JSONEncoder().iterencode(value):
        # Default ensure_ascii means character count is also the encoded byte count.
        if len(encoded) + len(chunk) > limit:
            return None
        encoded.extend(chunk.encode('ascii'))
    return bytes(encoded)


def _bounded_result(response, limit):
    encoded = _encode_bounded(response, limit)
    if encoded is not None:
        return encoded
    rpc_id = response.get('id')
    # A user-controlled giant id must not defeat the small error response either.
    if not isinstance(rpc_id, (str, int, float, type(None))) or len(str(rpc_id)) > 128:
        rpc_id = None
    return json.dumps(_rpc_error(rpc_id, -32001,
        'Response exceeds the size limit; request a smaller page. '
        'The operation may have completed; do not blindly retry writes.')).encode('utf-8')


MAX_JSON_DEPTH = 32


def _nesting_exceeds(value, limit):
    """True if lists/objects nest deeper than ``limit`` (iterative, so the check itself cannot recurse)."""
    stack = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, (list, dict)):
            if depth > limit:
                return True
            children = item.values() if isinstance(item, dict) else item
            stack.extend((child, depth + 1) for child in children if isinstance(child, (list, dict)))
    return False


def endpoint(request):
    if request.method != 'POST':
        response = JsonResponse({'error': 'POST JSON-RPC messages to this endpoint'}, status=405)
        response['Allow'] = 'POST'
        return response
    too_large = lambda: JsonResponse(_rpc_error(None, -32600, 'Request body exceeds 256 KiB'), status=413)
    try:
        length = int(request.META.get('CONTENT_LENGTH') or 0)
    except (TypeError, ValueError):
        length = 0
    if length > MAX_BODY_BYTES:
        return too_large()
    try:
        body = request.body
    except RequestDataTooBig:
        return too_large()
    if len(body) > MAX_BODY_BYTES:
        return too_large()
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return JsonResponse(_rpc_error(None, -32700, 'parse error'))
    if _nesting_exceeds(payload, MAX_JSON_DEPTH):  # not left to RecursionError: newer Pythons parse far deeper than older ones
        return JsonResponse(_rpc_error(None, -32700, 'parse error'))
    ctx = Ctx(user=request.user, token=getattr(request, 'api_token', None))
    if isinstance(payload, list):
        if not payload:
            return JsonResponse(_rpc_error(None, -32600, 'empty batch'))
        if len(payload) > MAX_BATCH_ITEMS:
            return JsonResponse(_rpc_error(None, -32600, 'Batch exceeds 20 messages'), status=413)
        # Reserve punctuation and divide the total budget across all entries. Encode
        # each response before dispatching the next, rather than retaining catalogs
        # or tool results for the entire batch. Notifications still have no response.
        item_limit = (MAX_RESPONSE_BYTES - MAX_BATCH_ITEMS - 2) // max(1, len(payload))
        responses = []
        for message in payload:
            response = handle_message(ctx, message)
            if response is not None:
                responses.append(_bounded_result(response, item_limit))
        return HttpResponse(b'[' + b','.join(responses) + b']', content_type='application/json') if responses else HttpResponse(status=202)
    response = handle_message(ctx, payload)
    return HttpResponse(_bounded_result(response, MAX_RESPONSE_BYTES), content_type='application/json') if response is not None else HttpResponse(status=202)
