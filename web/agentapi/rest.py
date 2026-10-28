"""REST API /api/v1/: JSON over the shared service layer, tenancy-scoped, token or session auth."""
import json
import logging
import re

from django.http import JsonResponse
from django.http.response import HttpResponseBase

from agentapi import agent_broker as broker
from agentapi import host_manage as hosts
from agentapi import saved_search as saved
from agentapi import inventory
from agentapi import sentinel_broker as sentinels
from agentapi import services as svc
from agentapi import suppliers
from agentapi import system_status
from agentapi import authcheck
from agentapi import reports
from agentapi import internal_ranges, tailscale
from agentapi import auth
from agentapi.auth import create_token
from tenancy import audit
from agentapi.services import ApiError, Ctx

logger = logging.getLogger(__name__)


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


def _assignee_kw(body):
    """{'assignee': ...} when the body named the key at all (a user id, or null to unassign), else {} so the service's
    own UNSET default applies and an omitted assignee is never confused with an explicit null one."""
    return {'assignee': body['assignee']} if 'assignee' in body else {}


# --- token management: session users only, so a token can never mint another token ---

def _session_only(request):
    if getattr(request, 'api_token', None):
        raise ApiError(403, 'tokens are managed from a signed-in session, not with a token')


def tokens_list(request, ctx, **_):
    _session_only(request)
    return {'results': [{'id': t.id, 'name': t.name, 'prefix': t.prefix, 'read_only': t.read_only,
                         'scope': t.scope, 'project': t.project.slug if t.project_id else None,
                         'expires': t.expires_at.isoformat() if t.expires_at else None,
                         'created': t.created_at.isoformat(), 'last_used': t.last_used_at.isoformat() if t.last_used_at else None,
                         'revoked': t.revoked} for t in ctx.user.api_tokens.select_related('project').order_by('-id')]}


def tokens_create(request, ctx, **_):
    _session_only(request)
    data = _body(request)
    (name,) = _need(data, 'name')
    scope = data.get('scope', auth.SCOPE_FULL)
    if scope not in auth.TOKEN_SCOPES:  # a misspelt scope must never quietly become a full token
        raise ApiError(400, f'scope must be one of {", ".join(auth.TOKEN_SCOPES)}')
    if scope == auth.SCOPE_INVENTORY:  # a host reporter's token: one project, inventory reports only
        return inventory.create_token(ctx, str(data.get('project') or ''), name), 201
    token, raw = create_token(ctx.user, str(name), read_only=bool(data.get('read_only')))
    audit.record_for_user(ctx.user, 'token.create', ctx.user, token=token.prefix, read_only=token.read_only)
    return {'id': token.id, 'name': token.name, 'read_only': token.read_only,
            'token': raw, 'note': 'Store this now. It is not shown again.'}, 201


def tokens_revoke(request, ctx, token_id, **_):
    _session_only(request)
    updated = ctx.user.api_tokens.filter(id=token_id).update(revoked=True)
    if not updated:
        raise ApiError(404, 'token not found')
    broker.release_for_tokens([token_id])
    audit.record_for_user(ctx.user, 'token.revoke', ctx.user, token_id=int(token_id))
    return {'revoked': True}


def _register_agent(request, ctx, **_):
    out = broker.register(ctx, _body(request))
    return out, (201 if out['created'] else 200)


def _register_sentinel(request, ctx, **_):
    out = sentinels.register(ctx, _body(request))
    return out, (201 if out['created'] else 200)


def _sentinel_enroll(request, ctx, slug, **_):
    out = sentinels.generate_enrollment_blob(ctx, slug) if request.GET.get('format') == 'blob' else sentinels.generate_enrollment(ctx, slug)
    return out, 201


def _sentinel_org_enroll(request, ctx, org, **_):
    out = (sentinels.generate_org_enrollment_blob(ctx, org) if request.GET.get('format') == 'blob'
           else sentinels.generate_org_enrollment(ctx, org))
    return out, 201


def _sentinel_instance_enroll(request, ctx, **_):
    out = (sentinels.generate_instance_enrollment_blob(ctx) if request.GET.get('format') == 'blob'
           else sentinels.generate_instance_enrollment(ctx))
    return out, 201


def _sentinel_bootstrap(request, ctx, **_):
    out = sentinels.bootstrap(_body(request))
    return out, 201


def _queue_agent_work(request, ctx, slug, **_):
    body = _body(request)
    # kind is validated inside queue_work, after its project gate, so an _all caller gets that gate's answer first
    out = broker.queue_work(ctx, slug, body.get('kind'), match_ids=body.get('match_ids'), mode=body.get('mode'), tier=body.get('tier'),
                            host=body.get('host'), limit=body.get('limit', broker.MAX_QUEUE_BATCH))
    return out, (201 if out['queued'] else 200)


# --- routes ---------------------------------------------------------------------
# (method, path regex, summary, handler(request, ctx, **path_kwargs)); handlers return dict or (dict, status)

ROUTES = [
    ('GET', r'me', 'Who am I: user, projects and roles, token info', lambda r, c, **k: svc.me(c)),
    ('GET', r'system/status', 'Instance status: overall health with problems and notes, scanning pause, update phase, inventory counts per project (targets, hosts, exposed hosts, scans running/queued, open findings), and for an App Admin the database and broker, queue depths, workers, schedules, memory, disk, CVE feed and AI budget',
     lambda r, c, **k: system_status.system_status(c)),
    ('GET', r'projects', 'Projects visible to the caller', lambda r, c, **k: svc.list_projects(c)),
    ('GET', r'engines', 'Scan engines (legacy labels: every scan runs the same fixed pipeline)', lambda r, c, **k: svc.list_engines(c)),
    ('GET', r'cves', 'CVE feed (tier, q filters)', lambda r, c, **k: svc.list_cve_feed(c, r.GET)),
    ('GET', r'cves/(?P<cve_id>CVE-[0-9]{4}-[0-9]+|CVE-[A-Za-z0-9-]+)/detection', 'The shared detection strategy of one CVE',
     lambda r, c, cve_id, **k: svc.get_cve_detection(c, cve_id)),
    ('PUT', r'cves/(?P<cve_id>CVE-[0-9]{4}-[0-9]+|CVE-[A-Za-z0-9-]+)/detection', 'Change the shared detection record of a CVE (App Admin); body {guidance} or {strategy}',
     lambda r, c, cve_id, **k: svc.update_cve_detection(c, cve_id, guidance=_body(r).get('guidance'), strategy=_body(r).get('strategy'))),
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
    ('GET', r'projects/(?P<slug>[-\w]+)/hosts', 'Inventory: hosts with IPs, ports, product/version, a score, highest score first (sort=name), and check_coverage (which of the checks that apply to the host have run)',
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
    ('POST', r'projects/(?P<slug>[-\w]+)/hosts/bulk', 'Archive, restore, pin or unpin many hosts; body {hosts: [names], action: archive|restore|pin|unpin, reason}. Up to 200; each host is independent',
     lambda r, c, slug, **k: hosts.host_bulk(c, slug, _body(r).get('hosts'), _body(r).get('action'), reason=_body(r).get('reason', ''))),
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
     lambda r, c, slug, host, **k: hosts.delete_host(c, slug, host, with_aliases=bool(_body(r).get('with_aliases')))),
    ('POST', r'projects/(?P<slug>[-\w]+)/hosts/(?P<host>[^/]+)/exclude', 'Remove a host from every project of the organization and never scan it again; body {reason, with_aliases, include_subdomains}. Needs an organization-level role',
     lambda r, c, slug, host, **k: hosts.exclude_host(c, slug, host, _body(r).get('reason', ''), include_subdomains=bool(_body(r).get('include_subdomains')),
                                                      with_aliases=bool(_body(r).get('with_aliases')))),
    ('GET', r'projects/(?P<slug>[-\w]+)/exclusions', 'Hosts excluded for this project\'s organization (never scanned again)',
     lambda r, c, slug, **k: hosts.list_exclusions(c, slug)),
    ('DELETE', r'projects/(?P<slug>[-\w]+)/exclusions/(?P<host>[^/]+)', 'Lift an exclusion so the organization can scan the host again (organization admin)',
     lambda r, c, slug, host, **k: hosts.remove_exclusion(c, slug, host)),
    ('POST', r'projects/(?P<slug>[-\w]+)/inventory', 'Post a host inventory report (inventory v1 JSON from scripts/inventory; the only route a reporter token can call). 201 for a machine\'s first report, 200 after; the answer says matched, created or unmatched, never which host',
     lambda r, c, slug, **k: inventory.post_report(c, slug, r)),
    ('GET', r'projects/(?P<slug>[-\w]+)/inventory', 'Host inventory reports, newest first (status=matched|unmatched|stale|fresh, q=); unmatched ones wait for an administrator to adopt them',
     lambda r, c, slug, **k: inventory.list_inventories(c, slug, r.GET)),
    ('GET', r'projects/(?P<slug>[-\w]+)/inventory/(?P<inventory_id>\d+)', 'One host inventory report in full: operating system, packages with purl (q, page, page_size), patches, listening services, runtime and security posture, history',
     lambda r, c, slug, inventory_id, **k: inventory.get_inventory(c, slug, inventory_id=int(inventory_id), params=r.GET)),
    ('POST', r'projects/(?P<slug>[-\w]+)/inventory/(?P<inventory_id>\d+)/adopt', 'Tie an unmatched report to a host the project scans (body {host}) or add the machine as a target ({create: true})',
     lambda r, c, slug, inventory_id, **k: inventory.adopt(c, slug, int(inventory_id), host=_body(r).get('host'), create=bool(_body(r).get('create')))),
    ('POST', r'projects/(?P<slug>[-\w]+)/inventory/delete-unmatched', 'Delete every host inventory report that is tied to no host (organization clean-up; needs a write role)',
     lambda r, c, slug, **k: inventory.delete_unmatched(c, slug)),
    ('DELETE', r'projects/(?P<slug>[-\w]+)/inventory/(?P<inventory_id>\d+)', 'Delete a host inventory report and its history',
     lambda r, c, slug, inventory_id, **k: inventory.delete_inventory(c, slug, int(inventory_id))),
    ('GET', r'projects/(?P<slug>[-\w]+)/hosts/(?P<host>[^/]+)/inventory', 'The host inventory report tied to a host (newest if several): OS, packages, patches, listening services, with its age and whether it is stale',
     lambda r, c, slug, host, **k: inventory.get_inventory(c, slug, host=host, params=r.GET)),
    ('GET', r'projects/(?P<slug>[-\w]+)/search', 'Search hosts: words, tech:, port:, product:, service:, os:, cve:, ip: (CIDR), host:, vuln:, sev:, auth:, sensitive:, zombie:, country:, comma for OR within one filter (port:80,443), -negation; sorted by score (sort=name); heat=fire|smoke|ice|clean|unscanned narrows the page, facets.heat always counts every value; facets=port,product,tech,os,country (facet_size=10) adds the same whole-match counts for those',
     lambda r, c, slug, **k: svc.search_hosts(c, slug, r.GET)),
    ('GET', r'projects/(?P<slug>[-\w]+)/saved-searches', 'Your saved searches in this project, with the limits and the notification channels Settings has on',
     lambda r, c, slug, **k: saved.list_saved_searches(c, slug)),
    ('POST', r'projects/(?P<slug>[-\w]+)/saved-searches', 'Save a search; body {name, query, enabled, alert_new, alert_gone, threshold, channels, frequency: hourly|daily|weekly}. The query is checked like a live search',
     lambda r, c, slug, **k: saved.create_saved_search(c, slug, _body(r))),
    ('GET', r'projects/(?P<slug>[-\w]+)/saved-searches/(?P<search_id>\d+)', 'One saved search of yours',
     lambda r, c, slug, search_id, **k: saved.get_saved_search(c, slug, int(search_id))),
    ('PATCH', r'projects/(?P<slug>[-\w]+)/saved-searches/(?P<search_id>\d+)', 'Change a saved search (any subset of the create fields); a new query or switching it back on restarts its baseline',
     lambda r, c, slug, search_id, **k: saved.update_saved_search(c, slug, int(search_id), _body(r))),
    ('DELETE', r'projects/(?P<slug>[-\w]+)/saved-searches/(?P<search_id>\d+)', 'Delete a saved search',
     lambda r, c, slug, search_id, **k: saved.delete_saved_search(c, slug, int(search_id))),
    ('POST', r'projects/(?P<slug>[-\w]+)/saved-searches/(?P<search_id>\d+)/run', 'Evaluate a saved search now, as the schedule would (alerts included); the first run only learns the baseline',
     lambda r, c, slug, search_id, **k: saved.run_saved_search(c, slug, int(search_id))),
    ('GET', r'projects/(?P<slug>[-\w]+)/saved-searches/(?P<search_id>\d+)/matches', 'The hosts a saved search matches now: the live search with the saved query (page, page_size, sort, heat, facets)',
     lambda r, c, slug, search_id, **k: saved.saved_search_matches(c, slug, int(search_id), r.GET)),
    ('GET', r'projects/(?P<slug>[-\w]+)/routes', 'Web routes and how they answer an anonymous GET: open, login, session_required, sso (auth_state=, host=, sensitive=1, zombie=1)',
     lambda r, c, slug, **k: svc.list_routes(c, slug, r.GET)),
    ('GET', r'projects/(?P<slug>[-\w]+)/certificates', 'TLS certificates, soonest expiry first (?expiring_within=30)',
     lambda r, c, slug, **k: svc.list_certificates(c, slug, r.GET)),
    ('GET', r'projects/(?P<slug>[-\w]+)/hygiene', 'TLS, certificate and SPF/DKIM/DMARC findings',
     lambda r, c, slug, **k: svc.list_hygiene(c, slug, r.GET)),
    ('GET', r'projects/(?P<slug>[-\w]+)/changes', 'What changed in the inventory: new/retired hosts, ports opened/closed, version, technology, certificate and auth changes (?since=7d, kind=, host=)',
     lambda r, c, slug, **k: svc.list_changes(c, slug, r.GET)),
    ('GET', r'projects/(?P<slug>[-\w]+)/stats/history', 'Daily snapshots of hosts, exposed hosts, open findings by severity, CVE matches by heat, fixed count and mean days to fix, oldest first (?days=90, capped at 365)',
     lambda r, c, slug, **k: svc.stats_history(c, slug, r.GET)),
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
    ('GET', r'projects/(?P<slug>[-\w]+)/runzero', "runZero sync status: token saved, import on/off and its search, last sync, counts, last error (organization admin or App Admin)",
     lambda r, c, slug, **k: svc.get_runzero(c, slug)),
    ('PUT', r'projects/(?P<slug>[-\w]+)/runzero', 'Set import_enabled (add unknown runZero addresses as targets) and/or search (runZero search limiting the import)',
     lambda r, c, slug, **k: svc.set_runzero(c, slug, _body(r))),
    ('POST', r'projects/(?P<slug>[-\w]+)/runzero/sync', 'Queue a runZero sync of this project now',
     lambda r, c, slug, **k: (svc.run_runzero_sync(c, slug), 202)),
    ('GET', r'projects/(?P<slug>[-\w]+)/suppliers', "The project's third-party suppliers (never owned hosts): tier, domains, last checked, open findings by severity, host card count; can_edit says whether you may add or remove",
     lambda r, c, slug, **k: suppliers.list_suppliers(c, slug, r.GET)),
    ('POST', r'projects/(?P<slug>[-\w]+)/suppliers', 'Add a supplier: {name, domains: [exact names to check], tier: critical|high|normal, contact?, notes?}; a domain that is one of the project\'s own targets, an address, a wildcard or a private name is refused (organization admin or App Admin)',
     lambda r, c, slug, **k: (suppliers.add_supplier(c, slug, _body(r)), 201)),
    ('GET', r'projects/(?P<slug>[-\w]+)/suppliers/hosts', 'Supplier host cards (response headers and banners, certificate, technology stack with versions, last checked); ?tech=php,node.js filters by technology (any term, matched in name and version and in the Server and X-Powered-By banners), ?supplier=<id>, ?tier=',
     lambda r, c, slug, **k: suppliers.search_hosts(c, slug, r.GET)),
    ('GET', r'projects/(?P<slug>[-\w]+)/suppliers/technologies', 'The technologies the suppliers run, most widespread first, with suppliers, hosts and versions seen',
     lambda r, c, slug, **k: suppliers.list_technologies(c, slug)),
    ('GET', r'projects/(?P<slug>[-\w]+)/suppliers/findings', 'Supplier posture findings (certificate, email authentication, headers, exposed pages, known CVEs for announced versions); ?status=open|accepted|resolved|all, ?supplier=, ?severity=, ?category=tls|email|web|exposed|cve',
     lambda r, c, slug, **k: suppliers.list_supplier_findings(c, slug, r.GET)),
    ('PATCH', r'projects/(?P<slug>[-\w]+)/suppliers/findings/(?P<finding_id>\d+)', 'Accept a supplier finding or open it again: {status: accepted|open, note?} (organization admin or App Admin); resolved is set by the checks',
     lambda r, c, slug, finding_id, **k: suppliers.set_finding_status(c, slug, finding_id, _body(r))),
    ('GET', r'projects/(?P<slug>[-\w]+)/suppliers/(?P<supplier_id>\d+)/summary', 'A plain-text message about one supplier to copy and send (the technology it announces, ?tech= asks about those first, and its open findings with what to ask). Nothing is sent',
     lambda r, c, slug, supplier_id, **k: suppliers.supplier_summary(c, slug, supplier_id, r.GET)),
    ('DELETE', r'projects/(?P<slug>[-\w]+)/suppliers/(?P<supplier_id>\d+)', 'Remove a supplier with its host cards and findings (organization admin or App Admin)',
     lambda r, c, slug, supplier_id, **k: suppliers.remove_supplier(c, slug, supplier_id)),
    ('GET', r'projects/(?P<slug>[-\w]+)/auth-credentials', 'Stored sign-ins (headers and cookie the scanners send) of the project, masked: names only, never a value (App Admin or organization admin; target_id=)',
     lambda r, c, slug, **k: authcheck.list_credentials(c, slug, r.GET)),
    ('PUT', r'projects/(?P<slug>[-\w]+)/targets/(?P<target_id>\d+)/auth-credential', 'Create or replace the stored sign-in of a target or of one host of it: {label, host?, headers: [{name, secret}], cookie_secret?, origins?, expires_at?}; values are write-only (App Admin or organization admin)',
     lambda r, c, slug, target_id, **k: authcheck.set_credential(c, slug, target_id, _body(r))),
    ('DELETE', r'projects/(?P<slug>[-\w]+)/auth-credentials/(?P<credential_id>\d+)', 'Remove a stored sign-in (App Admin or organization admin)',
     lambda r, c, slug, credential_id, **k: authcheck.delete_credential(c, slug, credential_id)),
    ('GET', r'projects/(?P<slug>[-\w]+)/internal-ranges', 'The private networks this project declared internal: only a Sentinel inside one scans its addresses, this server never does (project administrators only)',
     lambda r, c, slug, **k: internal_ranges.list_ranges(c, slug)),
    ('POST', r'projects/(?P<slug>[-\w]+)/internal-ranges', 'Declare a private network (CIDR inside 10/8, 172.16/12, 192.168/16, 100.64/10 or fc00::/7, at most a /16) as internal to this project: {cidr, description}; its addresses may then be added as targets (project administrators only)',
     lambda r, c, slug, **k: (internal_ranges.add_range(c, slug, _body(r)), 201)),
    ('DELETE', r'projects/(?P<slug>[-\w]+)/internal-ranges/(?P<range_id>\d+)', 'Remove a declared internal range (project administrators only)',
     lambda r, c, slug, range_id, **k: internal_ranges.delete_range(c, slug, int(range_id))),
    ('GET', r'projects/(?P<slug>[-\w]+)/tailscale', 'The project\'s Tailscale connection: tailnet, device counts, last sync, errors, settings (administrators only; never the credentials)',
     lambda r, c, slug, **k: tailscale.tailscale_status(c, slug)),
    ('GET', r'projects/(?P<slug>[-\w]+)/tailscale/devices', 'Tailnet devices imported into the project with their Tailscale facts (state=active|offline|departed|all, q=; administrators only)',
     lambda r, c, slug, **k: tailscale.tailscale_devices(c, slug, r.GET)),
    ('POST', r'projects/(?P<slug>[-\w]+)/tailscale/sync', 'Sync the project\'s tailnet now: devices, findings and (if enabled) scans (administrators only)',
     lambda r, c, slug, **k: (tailscale.tailscale_sync(c, slug), 202)),
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
    ('PATCH', r'projects/(?P<slug>[-\w]+)/matches/(?P<match_id>\d+)', 'Set remediation status, note and/or assignee (at least one of status/assignee)',
     lambda r, c, slug, match_id, **k: svc.update_match(c, slug, int(match_id), _body(r).get('status'), note=_body(r).get('note'), **_assignee_kw(_body(r)))),
    ('GET', r'projects/(?P<slug>[-\w]+)/triage', 'AI triage of every finding: classification, status and validation state (status=, classification=, validation=, kind=)',
     lambda r, c, slug, **k: svc.list_triage(c, slug, r.GET)),
    ('GET', r'projects/(?P<slug>[-\w]+)/findings/(?P<kind>match|vulnerability|route|hygiene)/(?P<finding_id>\d+)',
     'One finding in full: why it matters, how it was found, first and last seen with history, AI classification, remediation, every validation check with its exact command and result',
     lambda r, c, slug, kind, finding_id, **k: svc.finding_detail(c, slug, kind, int(finding_id))),
    ('PATCH', r'projects/(?P<slug>[-\w]+)/findings/(?P<kind>match|vulnerability|route|hygiene)/(?P<finding_id>\d+)',
     'Set remediation status (open, in_progress, fixed, accepted_risk), note and/or assignee (at least one of status/assignee); a web route has no remediation workflow (400)',
     lambda r, c, slug, kind, finding_id, **k: svc.update_finding_status(c, slug, kind, int(finding_id), _body(r).get('status'),
                                                                        note=_body(r).get('note'), **_assignee_kw(_body(r)))),
    ('POST', r'projects/(?P<slug>[-\w]+)/findings/status', 'Set the same remediation status and note on up to 200 findings at once; '
     "body {items: [{kind, id}, ...], status, note}; returns {updated, failed: [{kind, id, error}]}",
     lambda r, c, slug, **k: svc.bulk_update_finding_status(c, slug, _body(r).get('items'), *_need(_body(r), 'status'),
                                                             note=_body(r).get('note'))),
    ('POST', r'projects/(?P<slug>[-\w]+)/findings/(?P<kind>match|vulnerability|route|hygiene)/(?P<finding_id>\d+)/retriage',
     'Look at a finding again; CVE matches use the bounded per-match validation queue',
     lambda r, c, slug, kind, finding_id, **k: (svc.retriage_finding(c, slug, kind, int(finding_id)), 202)),
    ('GET', r'projects/(?P<slug>[-\w]+)/findings/(?P<kind>match|vulnerability|hygiene)/(?P<finding_id>\d+)/comments',
     'Every comment on one finding, oldest first',
     lambda r, c, slug, kind, finding_id, **k: svc.list_finding_comments(c, slug, kind, int(finding_id), r.GET)),
    ('POST', r'projects/(?P<slug>[-\w]+)/findings/(?P<kind>match|vulnerability|hygiene)/(?P<finding_id>\d+)/comments',
     'Add a comment to one finding; body {text}',
     # text's own validation happens inside add_finding_comment, after its project gate: a body-shaped _need() here would
     # run before that gate and 400 on a missing field before an _all/unknown-project caller ever gets its own real error.
     lambda r, c, slug, kind, finding_id, **k: (svc.add_finding_comment(c, slug, kind, int(finding_id), _body(r).get('text')), 201)),
    ('GET', r'projects/(?P<slug>[-\w]+)/findings/(?P<kind>match|vulnerability|hygiene)/(?P<finding_id>\d+)/audit',
     "One finding's audit trail (status, assignee and comment events, newest first), each with who, when, and before/after",
     lambda r, c, slug, kind, finding_id, **k: svc.finding_audit(c, slug, kind, int(finding_id), r.GET)),
    ('POST', r'projects/(?P<slug>[-\w]+)/reports', 'Queue a PDF report of the project, or of one host; body {host, include_closed}. Open findings only unless include_closed. Answers 202 with the report id and a status_url to poll; a read, so a read-only token may ask',
     lambda r, c, slug, **k: reports.export_report(c, slug, _body(r))),
    ('GET', r'projects/(?P<slug>[-\w]+)/reports/(?P<token>[-\w]+)', 'The state of a report you asked for: queued, running, done (with download_url), failed or expired',
     lambda r, c, slug, token, **k: reports.report_status(c, slug, token)),
    ('GET', r'projects/(?P<slug>[-\w]+)/reports/(?P<token>[-\w]+)/download', 'Download a finished report as application/pdf (only the user who asked, until it expires, 24 hours by default)',
     lambda r, c, slug, token, **k: reports.report_download(c, slug, token)),
    ('GET', r'projects/(?P<slug>[-\w]+)/settings', "The project's settings: sla_days (days to fix per severity: critical, high, medium, low) and the defaults",
     lambda r, c, slug, **k: svc.get_project_settings(c, slug)),
    ('PUT', r'projects/(?P<slug>[-\w]+)/settings', "Change the project's settings; sla_days is a partial update, a severity set to null goes back to its default",
     lambda r, c, slug, **k: svc.set_project_settings(c, slug, _body(r))),
    ('GET', r'projects/(?P<slug>[-\w]+)/members', "The project's members, for an assignee picker",
     lambda r, c, slug, **k: svc.list_members(c, slug, r.GET)),
    ('GET', r'projects/(?P<slug>[-\w]+)/work', 'Remediation work for your registered assets',
     lambda r, c, slug, **k: svc.work_items(c, slug, r.GET)),
    ('GET', r'assets', 'Assets registered on this token', lambda r, c, **k: {'assets': c.token.assets if c.token else []}),
    ('PUT', r'assets', 'Register hosts/IPs/CIDRs this token is responsible for',
     lambda r, c, **k: svc.register_assets(c, _body(r).get('assets'))),
    ('GET', r'agent', 'The agent registered on this token: scope, capabilities, open assignments', lambda r, c, **k: broker.my_agent(c)),
    ('PUT', r'agent', 'Register or update this token\'s agent: {name, kind, scope: {orgs, projects, hosts}, capabilities, os, tools, max_concurrent}',
     _register_agent),
    ('DELETE', r'agent', 'Unregister this token\'s agent and hand its tasks back', lambda r, c, **k: broker.unregister(c)),
    ('POST', r'agent/heartbeat', 'Say the agent is alive; extends the leases of its running tasks', lambda r, c, **k: broker.heartbeat(c, _body(r))),
    ('GET', r'agent/assignments', 'Tasks leased to this agent (?status= for others)', lambda r, c, **k: broker.my_assignments(c, r.GET)),
    ('POST', r'agent/tasks/next', 'Lease the best eligible task, or none; body {wait: seconds up to 20, kinds: [validate, remediate]}',
     lambda r, c, **k: broker.next_task(c, _body(r))),
    ('GET', r'agent/tasks/(?P<task_id>\d+)', 'One of your tasks with its payload', lambda r, c, task_id, **k: broker.get_task(c, task_id)),
    ('POST', r'agent/tasks/(?P<task_id>\d+)/accept', 'Accept a leased task and start work', lambda r, c, task_id, **k: broker.accept_task(c, task_id)),
    ('POST', r'agent/tasks/(?P<task_id>\d+)/result', 'Report the outcome of a task: {outcome, summary, checks: [{id, result, output}], retryable}',
     lambda r, c, task_id, **k: broker.report_result(c, task_id, _body(r))),
    ('POST', r'agent/tasks/(?P<task_id>\d+)/release', 'Give a task back to the queue; body {reason}',
     lambda r, c, task_id, **k: broker.release_task(c, task_id, _body(r).get('reason', ''))),
    ('GET', r'agents', 'Agents of your users and your own (administrators see their organizations\' agents)', lambda r, c, **k: broker.list_agents(c, r.GET)),
    ('GET', r'agents/(?P<agent_id>\d+)', 'One agent with its recent tasks', lambda r, c, agent_id, **k: broker.get_agent(c, agent_id)),
    ('PATCH', r'agents/(?P<agent_id>\d+)', 'Administrator: set status (active, suspended, revoked), note and/or limits {capabilities, projects, max_concurrent}',
     lambda r, c, agent_id, **k: broker.update_agent(c, agent_id, _body(r))),
    ('GET', r'projects/(?P<slug>[-\w]+)/agent-tasks', 'Validation and remediation work for agents (status, kind, agent_id, host)',
     lambda r, c, slug, **k: broker.list_tasks(c, slug, r.GET)),
    ('POST', r'projects/(?P<slug>[-\w]+)/agent-tasks', 'Queue work for agents: body {kind: validate|remediate, match_ids or tier/host, mode}',
     _queue_agent_work),
    ('GET', r'projects/(?P<slug>[-\w]+)/agent-tasks/unassignable', 'Queued work no live agent can take, each with the reason',
     lambda r, c, slug, **k: broker.list_unassignable(c, slug, r.GET)),
    ('POST', r'projects/(?P<slug>[-\w]+)/agent-tasks/(?P<task_id>\d+)/cancel', 'Cancel queued or leased agent work',
     lambda r, c, slug, task_id, **k: broker.cancel_task(c, slug, task_id)),
    ('POST', r'sentinels/bootstrap', 'A Sentinel\'s first call: trade a one-time enrollment secret (from the project\'s sentinels/enroll) for its own API token and Agent row (kind=scanner), pre-scoped to what the secret was generated for; body {enrollment_token, name, capabilities, os, tools, max_concurrent}. No bearer token needed; the token is returned once',
     _sentinel_bootstrap),
    ('GET', r'sentinel', 'The Sentinel registered on this token: scope, capabilities, open assignments', lambda r, c, **k: sentinels.identity(c)),
    ('PUT', r'sentinel', 'Register or update this token\'s Sentinel (kind is always scanner): {name, scope: {orgs, projects, hosts}, capabilities: [nmap, naabu, nuclei_light, nuclei_targeted, nuclei_deep], os, tools, max_concurrent}',
     _register_sentinel),
    ('DELETE', r'sentinel', 'Unregister this token\'s Sentinel and hand its tasks back', lambda r, c, **k: sentinels.unregister(c)),
    ('POST', r'sentinel/heartbeat', 'Say the Sentinel is alive; extends the leases of its running tasks (same call as agent/heartbeat)',
     lambda r, c, **k: sentinels.heartbeat(c, _body(r))),
    ('POST', r'sentinel/tasks/next', 'Lease the best eligible SentinelTask, or none; body {wait: seconds up to 20, kinds: [nmap, naabu, nuclei_light, nuclei_targeted, nuclei_deep]}',
     lambda r, c, **k: sentinels.next_task(c, _body(r))),
    ('GET', r'sentinel/tasks/(?P<task_id>\d+)', 'One of your SentinelTasks with its target', lambda r, c, task_id, **k: sentinels.get_task(c, task_id)),
    ('POST', r'sentinel/tasks/(?P<task_id>\d+)/accept', 'Accept a leased SentinelTask and start work', lambda r, c, task_id, **k: sentinels.accept_task(c, task_id)),
    ('POST', r'sentinel/tasks/(?P<task_id>\d+)/result', 'Report the outcome of a SentinelTask: {outcome: done|error, ...the typed result fields for its kind, or error}',
     lambda r, c, task_id, **k: sentinels.report_result(c, task_id, _body(r))),
    ('POST', r'sentinel/tasks/(?P<task_id>\d+)/release', 'Give a SentinelTask back to the queue; body {reason}',
     lambda r, c, task_id, **k: sentinels.release_task(c, task_id, _body(r).get('reason', ''))),
    ('GET', r'projects/(?P<slug>[-\w]+)/sentinels/enroll', 'An org admin or App Admin generates a one-time enrollment secret scoped to this project, for a Sentinel\'s first bootstrap call: {enrollment_token, server_url, expires_at, scope: "project"}. ?format=blob also returns the same payload base64-packaged as one opaque {blob} string for CVENGINE_SENTINEL_BLOB',
     _sentinel_enroll),
    ('POST', r'projects/(?P<slug>[-\w]+)/sentinels/enroll', 'Same as GET: generates a fresh one-time enrollment secret for this project',
     _sentinel_enroll),
    ('GET', r'orgs/(?P<org>[-\w]+)/sentinels/enroll', 'An admin of this organization, or an App Admin, generates a one-time enrollment secret that scopes a Sentinel to every project of the organization, present and future: {enrollment_token, server_url, expires_at, scope: "org"}. ?format=blob also returns {blob} for CVENGINE_SENTINEL_BLOB',
     _sentinel_org_enroll),
    ('POST', r'orgs/(?P<org>[-\w]+)/sentinels/enroll', 'Same as GET: generates a fresh one-time enrollment secret for this organization',
     _sentinel_org_enroll),
    ('GET', r'sentinels/enroll', 'App Admin only: a one-time enrollment secret that scopes a Sentinel to every organization and project on this instance, present and future: {enrollment_token, server_url, expires_at, scope: "instance"}. ?format=blob also returns {blob} for CVENGINE_SENTINEL_BLOB',
     _sentinel_instance_enroll),
    ('POST', r'sentinels/enroll', 'Same as GET: generates a fresh instance-wide one-time enrollment secret',
     _sentinel_instance_enroll),
    ('GET', r'projects/(?P<slug>[-\w]+)/sentinels', 'The Sentinels whose scope covers this project (direct, via its organization or instance-wide) with status, liveness, capabilities and this project\'s task counts; {project, results: [...]}',
     lambda r, c, slug, **k: sentinels.list_project_sentinels(c, slug)),
    ('GET', r'projects/(?P<slug>[-\w]+)/sentinel-tasks', 'Scan-stage work dispatched to Sentinels for this project (status, kind, agent_id, scan_id)',
     lambda r, c, slug, **k: sentinels.list_tasks(c, slug, r.GET)),
    ('POST', r'projects/(?P<slug>[-\w]+)/sentinel-tasks/(?P<task_id>\d+)/cancel', 'Cancel a queued or leased SentinelTask',
     lambda r, c, slug, task_id, **k: sentinels.cancel_task(c, slug, task_id)),
    ('GET', r'tokens', 'Your API tokens (session only)', tokens_list),
    ('POST', r'tokens', 'Create an API token (session only); body {name, read_only} or {name, scope: "inventory", project} for a host reporter token that can only post that project\'s inventory', tokens_create),
    ('DELETE', r'tokens/(?P<token_id>\d+)', 'Revoke a token (session only)', tokens_revoke),
]
READ_ONLY_POSTS = re.compile(r'^projects/[-\w]+/reports$')  # asking for a report changes nothing a read-only token protects
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
            if request.method != 'GET' and ctx.token and ctx.token.read_only and not path.startswith('tokens') and not READ_ONLY_POSTS.match(path):
                raise ApiError(403, 'this token is read only')
            result = fn(request, ctx, **match.groupdict())
        except ApiError as e:
            return JsonResponse({'error': e.message}, status=e.status)
        except (KeyError, TypeError, ValueError, AttributeError):  # a field of the wrong type: the caller's mistake, not a crash
            logger.warning('API request with invalid parameters: %s %s', request.method, path, exc_info=True)
            return JsonResponse({'error': 'invalid request parameters'}, status=400)
        if isinstance(result, HttpResponseBase):  # a file (a report PDF), not JSON
            return result
        data, status = result if isinstance(result, tuple) else (result, 200)
        return JsonResponse(data, status=status, safe=False)  # a route (stats/history) can answer a bare list
    if allowed:
        response = JsonResponse({'error': 'method not allowed'}, status=405)
        response['Allow'] = ', '.join(sorted(set(allowed)))
        return response
    return JsonResponse({'error': 'not found'}, status=404)
