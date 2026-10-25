"""REST API /api/v1/: JSON over the shared service layer, tenancy-scoped, token or session auth."""
import json
import re

from django.http import JsonResponse

from agentapi import host_manage as hosts
from agentapi import services as svc
from agentapi.auth import create_token
from agentapi.services import ApiError, Ctx


def _body(request):
    try:
        data = json.loads(request.body or b'{}')
    except json.JSONDecodeError:
        raise ApiError(400, 'body must be valid JSON')
    if not isinstance(data, dict):
        raise ApiError(400, 'body must be a JSON object')
    return data


def _need(data, *keys):
    missing = [k for k in keys if data.get(k) in (None, '')]
    if missing:
        raise ApiError(400, f'missing field(s): {", ".join(missing)}')
    return [data[k] for k in keys]


# --- token management: session users only, so a token can never mint another token ---

def _session_only(request):
    if getattr(request, 'api_token', None):
        raise ApiError(403, 'tokens are managed from a signed-in session, not with a token')


def tokens_list(request, ctx, **_):
    _session_only(request)
    return {'results': [{'id': t.id, 'name': t.name, 'prefix': t.prefix, 'read_only': t.read_only,
                         'created': t.created_at.isoformat(), 'last_used': t.last_used_at.isoformat() if t.last_used_at else None,
                         'revoked': t.revoked} for t in ctx.user.api_tokens.order_by('-id')]}


def tokens_create(request, ctx, **_):
    _session_only(request)
    data = _body(request)
    (name,) = _need(data, 'name')
    token, raw = create_token(ctx.user, str(name), read_only=bool(data.get('read_only')))
    return {'id': token.id, 'name': token.name, 'read_only': token.read_only,
            'token': raw, 'note': 'Store this now. It is not shown again.'}, 201


def tokens_revoke(request, ctx, token_id, **_):
    _session_only(request)
    updated = ctx.user.api_tokens.filter(id=token_id).update(revoked=True)
    if not updated:
        raise ApiError(404, 'token not found')
    return {'revoked': True}


# --- routes ---------------------------------------------------------------------
# (method, path regex, summary, handler(request, ctx, **path_kwargs)); handlers return dict or (dict, status)

ROUTES = [
    ('GET', r'me', 'Who am I: user, projects and roles, token info', lambda r, c, **k: svc.me(c)),
    ('GET', r'projects', 'Projects visible to the caller', lambda r, c, **k: svc.list_projects(c)),
    ('GET', r'engines', 'Scan engines', lambda r, c, **k: svc.list_engines(c)),
    ('GET', r'cves', 'CVE feed (tier, q filters)', lambda r, c, **k: svc.list_cve_feed(c, r.GET)),
    ('GET', r'cves/(?P<cve_id>CVE-[0-9]{4}-[0-9]+|CVE-[A-Za-z0-9-]+)', 'One CVE with affected ranges',
     lambda r, c, cve_id, **k: svc.get_cve(c, cve_id)),
    ('GET', r'projects/(?P<slug>[-\w]+)/targets', 'List targets', lambda r, c, slug, **k: svc.list_targets(c, slug, r.GET)),
    ('POST', r'projects/(?P<slug>[-\w]+)/targets', 'Add a domain, IP, CIDR or range',
     lambda r, c, slug, **k: (svc.add_target(c, slug, *_need(_body(r), 'value'), description=_body(r).get('description', ''), discover=bool(_body(r).get('discover'))), 201)),
    ('POST', r'projects/(?P<slug>[-\w]+)/targets/bulk', 'Add many targets (list or pasted text), optionally start discovery',
     lambda r, c, slug, **k: (svc.add_targets(c, slug, _body(r).get('targets') or _body(r).get('text') or '',
                                              discover=bool(_body(r).get('discover', True)), mode=_body(r).get('mode')), 201)),
    ('POST', r'targets/bulk-org', 'Bulk add across an organization: text with ##Org, #Project headers; creates missing projects',
     lambda r, c, **k: (svc.add_targets_by_org(c, _body(r).get('text') or '', discover=bool(_body(r).get('discover', True)),
                                               mode=_body(r).get('mode'),
                                               current_project=_body(r).get('current_project')), 201)),
    ('POST', r'projects/(?P<slug>[-\w]+)/targets/delete', 'Delete targets by ids, or all matching a search (skips running scans)',
     lambda r, c, slug, **k: svc.delete_targets(c, slug, ids=_body(r).get('ids'), all_matching=bool(_body(r).get('all_matching')),
                                                q=_body(r).get('q') or '')),
    ('POST', r'projects/(?P<slug>[-\w]+)/targets/(?P<target_id>\d+)/discover', 'Run bbot discovery then nuclei on a target',
     lambda r, c, slug, target_id, **k: (svc.discover_target(c, slug, int(target_id), _body(r).get('mode')), 202)),
    ('POST', r'projects/(?P<slug>[-\w]+)/targets/(?P<target_id>\d+)/rescan-hosts',
     'Scan specific hosts of a target now (nmap, exposure check, nuclei, CVE correlation) without a bbot run; body {hosts: [...]}',
     lambda r, c, slug, target_id, **k: (svc.rescan_hosts(c, slug, int(target_id), _body(r).get('hosts')), 202)),
    ('POST', r'projects/(?P<slug>[-\w]+)/targets/(?P<target_id>\d+)/scope',
     'Set a target\'s scope_mode: auto (shared-domain list decides), host (this host only) or parent (parent domain is owned); body {scope_mode}',
     lambda r, c, slug, target_id, **k: svc.set_target_scope(c, slug, int(target_id), _need(_body(r), 'scope_mode')[0])),
    ('GET', r'projects/(?P<slug>[-\w]+)/targets/(?P<target_id>\d+)', 'One target',
     lambda r, c, slug, target_id, **k: svc.get_target(c, slug, int(target_id))),
    ('GET', r'projects/(?P<slug>[-\w]+)/scans', 'List scans', lambda r, c, slug, **k: svc.list_scans(c, slug, r.GET)),
    ('POST', r'projects/(?P<slug>[-\w]+)/scans', 'Start a scan on a target (bbot discovery, then nmap and nuclei; engine_id is optional)',
     lambda r, c, slug, **k: (svc.start_scan(c, slug, int(_need(_body(r), 'target_id')[0]),
                                             int(_body(r)['engine_id']) if _body(r).get('engine_id') not in (None, '') else None), 202)),
    ('POST', r'projects/(?P<slug>[-\w]+)/scans/stop', 'Stop every running and queued scan of the project',
     lambda r, c, slug, **k: svc.stop_scans(c, slug)),
    ('POST', r'projects/(?P<slug>[-\w]+)/scans/(?P<scan_id>\d+)/stop', 'Stop one running or queued scan',
     lambda r, c, slug, scan_id, **k: svc.stop_scan(c, slug, int(scan_id))),
    ('GET', r'projects/(?P<slug>[-\w]+)/scans/(?P<scan_id>\d+)', 'One scan',
     lambda r, c, slug, scan_id, **k: svc.get_scan(c, slug, int(scan_id))),
    ('GET', r'projects/(?P<slug>[-\w]+)/scans/(?P<scan_id>\d+)/subdomains', 'Subdomains found by a scan',
     lambda r, c, slug, scan_id, **k: svc.list_scan_subdomains(c, slug, int(scan_id), r.GET)),
    ('GET', r'projects/(?P<slug>[-\w]+)/scans/(?P<scan_id>\d+)/endpoints', 'Endpoints found by a scan',
     lambda r, c, slug, scan_id, **k: svc.list_scan_endpoints(c, slug, int(scan_id), r.GET)),
    ('GET', r'projects/(?P<slug>[-\w]+)/scans/(?P<scan_id>\d+)/vulnerabilities', 'Findings from a scan',
     lambda r, c, slug, scan_id, **k: svc.list_scan_vulnerabilities(c, slug, int(scan_id), r.GET)),
    ('GET', r'projects/(?P<slug>[-\w]+)/scans/(?P<scan_id>\d+)/activity', 'Task timeline of a scan',
     lambda r, c, slug, scan_id, **k: svc.scan_activity(c, slug, int(scan_id), r.GET)),
    ('GET', r'projects/(?P<slug>[-\w]+)/hosts', 'Inventory: hosts with IPs, ports, product/version and a score, highest score first (sort=name)',
     lambda r, c, slug, **k: svc.list_hosts(c, slug, r.GET)),
    ('POST', r'projects/(?P<slug>[-\w]+)/host-assessments', 'Queue a full, fresh assessment of one inventoried host; body {host_id}',
     lambda r, c, slug, **k: (svc.request_host_assessment(c, slug, _body(r).get('host_id')), 202)),
    ('GET', r'projects/(?P<slug>[-\w]+)/host-assessments', 'Latest assessment for an inventoried host (?host_id=)',
     lambda r, c, slug, **k: svc.latest_host_assessment(c, slug, r.GET.get('host_id'))),
    ('GET', r'projects/(?P<slug>[-\w]+)/host-assessments/(?P<assessment_id>\d+)', 'Status and scan stages of a host assessment',
     lambda r, c, slug, assessment_id, **k: svc.get_host_assessment(c, slug, int(assessment_id))),
    ('POST', r'projects/(?P<slug>[-\w]+)/host-assessments/(?P<assessment_id>\d+)/stop', 'Stop a queued or running host assessment',
     lambda r, c, slug, assessment_id, **k: svc.stop_host_assessment(c, slug, int(assessment_id))),
    ('POST', r'projects/(?P<slug>[-\w]+)/hosts/(?P<host>[^/]+)/profile', 'Set a host\'s asset information: body {owner, purpose, criticality: unknown|low|medium|high|critical}, any subset',
     lambda r, c, slug, host, **k: hosts.update_host_profile(c, slug, host, owner=_body(r).get('owner'), purpose=_body(r).get('purpose'),
                                                             criticality=_body(r).get('criticality'))),
    ('POST', r'projects/(?P<slug>[-\w]+)/hosts/(?P<host>[^/]+)/archive', 'Reversibly archive an inventoried host; body {reason}',
     lambda r, c, slug, host, **k: hosts.host_archive(c, slug, host, 'archive', reason=_body(r).get('reason', ''))),
    ('POST', r'projects/(?P<slug>[-\w]+)/hosts/(?P<host>[^/]+)/restore', 'Restore an archived host to active scheduling',
     lambda r, c, slug, host, **k: hosts.host_archive(c, slug, host, 'restore')),
    ('POST', r'projects/(?P<slug>[-\w]+)/hosts/(?P<host>[^/]+)/pin', 'Pin a host against archival; body {pinned: boolean}',
     lambda r, c, slug, host, **k: hosts.host_archive(c, slug, host, 'pin', pinned=_body(r).get('pinned'))),
    ('PATCH', r'projects/(?P<slug>[-\w]+)/hosts/(?P<host>[^/]+)/profile', 'Same as POST: set a host\'s asset information',
     lambda r, c, slug, host, **k: hosts.update_host_profile(c, slug, host, owner=_body(r).get('owner'), purpose=_body(r).get('purpose'),
                                                             criticality=_body(r).get('criticality'))),
    ('POST', r'projects/(?P<slug>[-\w]+)/hosts/(?P<host>[^/]+)/delete', 'Delete a host\'s data from this project only (it can be rediscovered); exact name, irreversible',
     lambda r, c, slug, host, **k: hosts.delete_host(c, slug, host)),
    ('POST', r'projects/(?P<slug>[-\w]+)/hosts/(?P<host>[^/]+)/exclude', 'Remove a host from every project of the organization and never scan it again; body {reason}. Needs an organization-level role',
     lambda r, c, slug, host, **k: hosts.exclude_host(c, slug, host, _body(r).get('reason', ''))),
    ('GET', r'projects/(?P<slug>[-\w]+)/exclusions', 'Hosts excluded for this project\'s organization (never scanned again)',
     lambda r, c, slug, **k: hosts.list_exclusions(c, slug)),
    ('DELETE', r'projects/(?P<slug>[-\w]+)/exclusions/(?P<host>[^/]+)', 'Lift an exclusion so the organization can scan the host again (organization admin)',
     lambda r, c, slug, host, **k: hosts.remove_exclusion(c, slug, host)),
    ('GET', r'projects/(?P<slug>[-\w]+)/search', 'Search hosts: words, tech:, port:, product:, service:, os:, cve:, ip: (CIDR), host:, vuln:, sev:, auth:, sensitive:, zombie:, -negation; sorted by score (sort=name)',
     lambda r, c, slug, **k: svc.search_hosts(c, slug, r.GET)),
    ('GET', r'projects/(?P<slug>[-\w]+)/routes', 'Web routes and how they answer an anonymous GET: open, login, session_required, sso (auth_state=, host=, sensitive=1, zombie=1)',
     lambda r, c, slug, **k: svc.list_routes(c, slug, r.GET)),
    ('GET', r'projects/(?P<slug>[-\w]+)/certificates', 'TLS certificates, soonest expiry first (?expiring_within=30)',
     lambda r, c, slug, **k: svc.list_certificates(c, slug, r.GET)),
    ('GET', r'projects/(?P<slug>[-\w]+)/hygiene', 'TLS, certificate and SPF/DKIM/DMARC findings',
     lambda r, c, slug, **k: svc.list_hygiene(c, slug, r.GET)),
    ('GET', r'projects/(?P<slug>[-\w]+)/changes', 'What changed in the inventory: new/retired hosts, ports opened/closed, version, technology, certificate and auth changes (?since=7d, kind=, host=)',
     lambda r, c, slug, **k: svc.list_changes(c, slug, r.GET)),
    ('GET', r'projects/(?P<slug>[-\w]+)/activity', 'What the AI engine did, newest first: this project plus system-wide entries (?kind=)',
     lambda r, c, slug, **k: svc.list_activity(c, slug, r.GET)),
    ('POST', r'projects/(?P<slug>[-\w]+)/hygiene/run', 'Run the hygiene checks now (all targets, or {target_id})',
     lambda r, c, slug, **k: (svc.run_hygiene_checks(c, slug, _body(r).get('target_id')), 202)),
    ('GET', r'projects/(?P<slug>[-\w]+)/api-keys', 'External-service API keys configured for this project (never the secrets)',
     lambda r, c, slug, **k: svc.list_api_credentials(c, slug)),
    ('PUT', r'projects/(?P<slug>[-\w]+)/api-keys/(?P<service>[-\w]+)', "Set this project's own key for a service",
     lambda r, c, slug, service, **k: svc.set_api_credential(c, slug, service, _body(r))),
    ('DELETE', r'projects/(?P<slug>[-\w]+)/api-keys/(?P<service>[-\w]+)', "Remove this project's own key (its org's still applies)",
     lambda r, c, slug, service, **k: svc.delete_api_credential(c, slug, service)),
    ('GET', r'projects/(?P<slug>[-\w]+)/findings', 'Every finding in one list, hottest first: CVE matches, scanner and hygiene findings (type=all|cve|scanner|hygiene, heat=fire|smoke|ice, severity=, status=actionable|all, host=)',
     lambda r, c, slug, **k: svc.list_findings(c, slug, r.GET)),
    ('GET', r'projects/(?P<slug>[-\w]+)/vulnerabilities', 'Scanner findings (severity, open filters)',
     lambda r, c, slug, **k: svc.list_vulnerabilities(c, slug, r.GET)),
    ('GET', r'projects/(?P<slug>[-\w]+)/matches', 'CVE-on-host matches (status, verdict, host filters)',
     lambda r, c, slug, **k: svc.list_matches(c, slug, r.GET)),
    ('POST', r'projects/(?P<slug>[-\w]+)/matches/(?P<match_id>\d+)/validate',
     'Queue the owned match for bounded template checks and AI review',
     lambda r, c, slug, match_id, **k: (svc.validate_match_now(c, slug, int(match_id)), 202)),
    ('GET', r'projects/(?P<slug>[-\w]+)/matches/(?P<match_id>\d+)/validate/(?P<request_id>\d+)',
     'Read the queued, running, completed or failed state of one validation request',
     lambda r, c, slug, match_id, request_id, **k: svc.validation_request(c, slug, int(match_id), int(request_id))),
    ('PATCH', r'projects/(?P<slug>[-\w]+)/matches/(?P<match_id>\d+)', 'Set remediation status and note',
     lambda r, c, slug, match_id, **k: svc.update_match(c, slug, int(match_id), *_need(_body(r), 'status'), note=_body(r).get('note'))),
    ('GET', r'projects/(?P<slug>[-\w]+)/triage', 'AI triage of every finding: classification, status and validation state (status=, classification=, validation=, kind=)',
     lambda r, c, slug, **k: svc.list_triage(c, slug, r.GET)),
    ('GET', r'projects/(?P<slug>[-\w]+)/findings/(?P<kind>match|vulnerability|route|hygiene)/(?P<finding_id>\d+)',
     'One finding in full: why it matters, how it was found, first and last seen with history, AI classification, remediation, every validation check with its exact command and result',
     lambda r, c, slug, kind, finding_id, **k: svc.finding_detail(c, slug, kind, int(finding_id))),
    ('PATCH', r'projects/(?P<slug>[-\w]+)/findings/(?P<kind>match|vulnerability|route|hygiene)/(?P<finding_id>\d+)',
     'Set remediation status (open, in_progress, fixed, accepted_risk) and note; a web route has no remediation workflow (400)',
     lambda r, c, slug, kind, finding_id, **k: svc.update_finding_status(c, slug, kind, int(finding_id), *_need(_body(r), 'status'),
                                                                        note=_body(r).get('note'))),
    ('POST', r'projects/(?P<slug>[-\w]+)/findings/status', 'Set the same remediation status and note on up to 200 findings at once; '
     "body {items: [{kind, id}, ...], status, note}; returns {updated, failed: [{kind, id, error}]}",
     lambda r, c, slug, **k: svc.bulk_update_finding_status(c, slug, _body(r).get('items'), *_need(_body(r), 'status'),
                                                             note=_body(r).get('note'))),
    ('POST', r'projects/(?P<slug>[-\w]+)/findings/(?P<kind>match|vulnerability|route|hygiene)/(?P<finding_id>\d+)/retriage',
     'Look at a finding again; CVE matches use the bounded per-match validation queue',
     lambda r, c, slug, kind, finding_id, **k: (svc.retriage_finding(c, slug, kind, int(finding_id)), 202)),
    ('GET', r'projects/(?P<slug>[-\w]+)/work', 'Remediation work for your registered assets',
     lambda r, c, slug, **k: svc.work_items(c, slug, r.GET)),
    ('GET', r'assets', 'Assets registered on this token', lambda r, c, **k: {'assets': c.token.assets if c.token else []}),
    ('PUT', r'assets', 'Register hosts/IPs/CIDRs this token is responsible for',
     lambda r, c, **k: svc.register_assets(c, _body(r).get('assets'))),
    ('GET', r'tokens', 'Your API tokens (session only)', tokens_list),
    ('POST', r'tokens', 'Create an API token (session only)', tokens_create),
    ('DELETE', r'tokens/(?P<token_id>\d+)', 'Revoke a token (session only)', tokens_revoke),
]
COMPILED = [(m, re.compile(f'^{pat}/?$'), summary, fn) for m, pat, summary, fn in ROUTES]


def openapi_spec():
    paths = {}
    for method, pattern, summary, _ in ROUTES:
        path = '/api/v1/' + re.sub(r'\(\?P<(\w+)>[^)]*\)', r'{\1}', pattern)
        paths.setdefault(path, {})[method.lower()] = {'summary': summary, 'responses': {'200': {'description': 'OK'}}}
    return {'openapi': '3.0.3', 'info': {'title': 'CVEngine API', 'version': '1'},
            'components': {'securitySchemes': {'bearer': {'type': 'http', 'scheme': 'bearer'}}},
            'security': [{'bearer': []}], 'paths': paths}


# Not csrf_exempt: bearer-token requests are exempted by AgentTokenMiddleware, session ones stay CSRF-checked.
def dispatch(request, path):
    path = path.strip('/')
    if path == 'openapi.json':
        return JsonResponse(openapi_spec())
    ctx = Ctx(user=request.user, token=getattr(request, 'api_token', None))
    allowed = []
    for method, regex, _, fn in COMPILED:
        match = regex.match(path)
        if not match:
            continue
        allowed.append(method)
        if method != request.method:
            continue
        try:
            if request.method != 'GET' and ctx.token and ctx.token.read_only and not path.startswith('tokens'):
                raise ApiError(403, 'this token is read only')
            result = fn(request, ctx, **match.groupdict())
        except ApiError as e:
            return JsonResponse({'error': e.message}, status=e.status)
        data, status = result if isinstance(result, tuple) else (result, 200)
        return JsonResponse(data, status=status)
    if allowed:
        response = JsonResponse({'error': 'method not allowed'}, status=405)
        response['Allow'] = ', '.join(sorted(set(allowed)))
        return response
    return JsonResponse({'error': 'not found'}, status=404)
