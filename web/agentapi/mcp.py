"""MCP server (Streamable HTTP, JSON-RPC 2.0 over POST /mcp/) exposing CVEngine to agents.

Tools are thin wrappers over agentapi.services, so they inherit the same
tenancy scoping, role checks and read-only-token rules as the REST API.
"""
import json

from django.http import HttpResponse, JsonResponse

from agentapi import host_manage as hosts
from agentapi import services as svc
from agentapi.services import ApiError, Ctx

SUPPORTED_VERSIONS = ('2025-06-18', '2025-03-26', '2024-11-05')
SERVER_INFO = {'name': 'cvengine', 'version': '1.0.0'}
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
    ('search_hosts', 'Shodan-style host search. q is ANDed terms: a bare word matches hostname, IP, technology, port product/service/version/CPE, OS, finding name, CVE id and page title; field filters tech: port: product: service: os: cve: ip: (address or CIDR) host: vuln: sev: auth: (open|login|session_required|sso) sensitive: (any|credentials|pii|internal) zombie: (yes|no); -term negates; "quoted phrase". Each result says what matched. Sorted by score, highest first (sort=name for names).',
     _schema(_page_props({'project': SLUG_OR_ALL, 'q': {'type': 'string'}, 'sort': {'type': 'string', 'enum': ['score', 'name']}}), ['project']),
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
    ('list_activity', 'The AI activity log, newest first: what the engine read, checked, wrote, ran and validated, for this project plus system-wide entries. kind: feed|inventory|target|confirm|write_check|run_check|validate|discovery|scan|hygiene|changes.', _schema(
        _page_props({'project': SLUG_OR_ALL, 'kind': {'type': 'string'}}), ['project']),
     lambda c, a: svc.list_activity(c, a.get('project'), a), False),
    ('run_hygiene_checks', 'Run the certificate, TLS and email-authentication checks now (optionally for one target).', _schema(
        {'project': SLUG, 'target_id': {'type': 'integer'}}, ['project']),
     lambda c, a: svc.run_hygiene_checks(c, a.get('project'), a.get('target_id')), True),
    ('list_cves', 'The live CVE feed. tier: fire|smoke|ice.', _schema(_page_props({'tier': {'type': 'string'}, 'q': {'type': 'string'}})),
     lambda c, a: svc.list_cve_feed(c, a), False),
    ('get_cve', 'One CVE with description, affected ranges and references.', _schema({'cve_id': {'type': 'string'}}, ['cve_id']),
     lambda c, a: svc.get_cve(c, a.get('cve_id', '')), False),
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
     lambda c, a: svc.update_match(c, a.get('project'), int(a['match_id']), a.get('status'), a.get('note', '')), True),
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
    except (KeyError, TypeError, ValueError) as exc:
        raise ApiError(400, f'bad arguments: {exc}')


def handle_message(ctx, msg):
    """Handle one JSON-RPC message; returns a response dict, or None for notifications."""
    if not isinstance(msg, dict) or msg.get('jsonrpc') != '2.0' or 'method' not in msg:
        return _rpc_error(msg.get('id') if isinstance(msg, dict) else None, -32600, 'invalid request')
    method, rpc_id, params = msg['method'], msg.get('id'), msg.get('params') or {}
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
        try:
            data = call_tool(ctx, params.get('name'), params.get('arguments'))
            return _rpc_result(rpc_id, {'content': [{'type': 'text', 'text': json.dumps(data, default=str)}], 'isError': False})
        except ApiError as e:
            return _rpc_result(rpc_id, {'content': [{'type': 'text', 'text': e.message}], 'isError': True})
    return _rpc_error(rpc_id, -32601, f'method not found: {method}')


def endpoint(request):
    if request.method != 'POST':
        response = JsonResponse({'error': 'POST JSON-RPC messages to this endpoint'}, status=405)
        response['Allow'] = 'POST'
        return response
    try:
        payload = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse(_rpc_error(None, -32700, 'parse error'))
    ctx = Ctx(user=request.user, token=getattr(request, 'api_token', None))
    if isinstance(payload, list):
        responses = [r for r in (handle_message(ctx, m) for m in payload) if r is not None]
        return JsonResponse(responses, safe=False) if responses else HttpResponse(status=202)
    response = handle_message(ctx, payload)
    return JsonResponse(response) if response is not None else HttpResponse(status=202)
