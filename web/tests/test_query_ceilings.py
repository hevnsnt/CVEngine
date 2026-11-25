"""Query ceilings for every page, every GET route of the REST API and the /cve/api dispatchers, and every read-only MCP tool.

Each entry is measured on a small copy of the scale fixture (``seed_scale_fixture``: 60 hosts over 3 targets, 180 host rows, 360 findings, 120 CVE
matches, Sentinels and their tasks) as an App Admin, after one warm-up call with the shared cache emptied and the clock-driven per-process caches
pinned (``steady_caches``): the steady cost of one request. A list answers 50 rows here, so a query per row (an N+1) adds at least 50 statements
and fails its ceiling, while the margin (``slack``) absorbs a statement or two of ordinary change.

A new route or tool fails ``test_every_route_and_tool_has_a_ceiling`` until it is given a ceiling here (or a reason in ``UNMEASURED``). When a
change really needs more statements, raise that one ceiling and say why in the commit. A few entries measure a refusal or a not found answer
(a route of a credential or a row this fixture does not have, such as another Sentinel's task); their ceiling still bounds that answer.
"""
import json
import os
import random
import re
import time
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test import Client, TestCase
from django.test.utils import CaptureQueriesContext

from cveFeed.management.commands.seed_scale_fixture import Command
from tests.test_live_cache import steady_caches

SLUG = 'scale-fixture'
PRINT = os.environ.get('CVENGINE_PRINT_CEILINGS') == '1'  # print every measured count (to refresh the tables below)


def slack(count):
    """The margin over a measured count: a statement or two of ordinary change, never as much as a query per row of a 50 row page."""
    return max(3, count // 10)


# ---------------------------------------------------------------------------------------------------------------------- the tables
# Each value is (the expected status, the measured count of statements). The ceiling is the count plus ``slack``.

PAGES = {
    '/cve/': (200, 15), '/cve/?project={slug}': (200, 16), '/cve/graph/': (200, 13),
    '/cve/welcome/': (200, 12), '/cve/update-questions/': (200, 11), '/cve/account/': (200, 9),
    '/cve/about/': (200, 9), '/cve/ai/': (200, 12), '/cve/mcp/': (200, 11),
    '/cve/how-it-works/': (200, 9), '/cve/admin/': (200, 12), '/cve/bounty/': (200, 12),
    '/cve/settings/': (200, 11), '/cve/agents/': (200, 11), '/cve/scanners/': (200, 11),
    '/cve/reports/': (200, 12), '/cve/sentinels/': (200, 13), '/cve/setup/': (200, 11),
    '/cve/cves/': (200, 11), '/cve/{slug}/scans/{scan_id}/': (200, 13), '/cve/{slug}/hosts/{host_id}/screenshot/': (404, 13),
    '/': (302, 8), '/mfa/setup/': (302, 6), '/cve/{slug}/targets/': (200, 13),
    '/cve/{slug}/scans/': (200, 13), '/cve/{slug}/hosts/': (200, 13), '/cve/{slug}/changes/': (200, 13),
    '/cve/{slug}/activity/': (200, 13), '/cve/{slug}/vulns/': (200, 13), '/cve/{slug}/matches/': (200, 13),
    '/cve/{slug}/hygiene/': (200, 13), '/cve/{slug}/secrets/': (200, 13), '/cve/{slug}/suppliers/': (200, 13),
    '/cve/{slug}/situations/': (200, 13), '/cve/{slug}/keys/': (302, 9), '/cve/{slug}/sentinels/': (200, 13),
}

# the plain /cve/api views (cveFeed.urls), as the dashboard asks them
CVE_API = {
    'feed?project={slug}': (200, 11), 'cves?project={slug}': (200, 13), 'cves/{cve_id}?project={slug}': (200, 12),
    'alive': (200, 8), 'stats?project={slug}': (200, 14), 'stats?project=_all': (200, 13),
    'overview?project={slug}': (200, 11), 'overview?project=_all': (200, 11), 'scanner': (200, 9),
    'graph?project={slug}': (200, 10), 'graph?project=_all': (200, 9), 'graph-live?project={slug}': (200, 10),
    'node?id=sub-{host_id}&project={slug}': (404, 9), 'activity?project={slug}': (200, 19), 'activity?project=_all': (200, 17),
    'discovery?project={slug}&after=0': (200, 15), 'discovery?project=_all&after=0': (200, 14),
}

# GET routes of the dispatchers under /cve/api/<prefix>/, keyed by (prefix, route pattern)
DISPATCH = {
    'settings/ai': (200, 12), 'settings/ai/usage': (200, 18), 'settings/reviewer': (200, 19),
    'settings/alerts': (200, 17), 'settings/setup_questions': (200, 24), 'settings/client_address/snippet': (409, 8),
    'settings/scan_policy': (200, 9), 'settings/cve_seed': (200, 8), 'settings/cve_seed/download/(?P<which>seed|manifest)': (404, 8),
    'settings/factory_reset': (200, 15), 'settings/resources': (200, 8), 'settings/config_maxxing': (200, 8),
    'settings/scan_concurrency': (200, 12), 'settings/tunables': (200, 18), 'settings/autotune': (200, 18),
    'settings/autotune/decisions': (200, 9), 'settings/updates': (200, 22), 'settings/scanner_plan': (200, 17),
    'settings/keys': (200, 9), 'settings/notifications': (200, 9), 'settings/email': (200, 9),
    'settings/proxy': (200, 9), 'settings/reports': (200, 9), 'settings/tailscale': (200, 10),
    'settings/openvas': (200, 44), 'settings/openvas/projects/(?P<project_id>\\d+)/queue': (200, 288), 'settings/ip_allowlist': (200, 10),
    'admin/users': (200, 14), 'admin/orgs': (200, 16), 'admin/orgs/(?P<org_id>\\d+)/api-keys': (200, 10),
    'admin/orgs/(?P<org_id>\\d+)/excluded-addresses': (200, 10), 'admin/projects': (200, 10), 'admin/timings': (200, 14),
    'admin/audit': (200, 9), 'admin/activity': (200, 10), 'admin/health': (200, 25),
    'admin/scan-control': (200, 10), 'admin/watchdog': (200, 10), 'admin/openvas': (200, 16),
    'bounty/status': (200, 11), 'bounty/programs': (200, 12), 'bounty/changes': (200, 11),
    'bounty/matches': (200, 12), 'bounty/engagements': (200, 11), 'bounty/findings': (200, 13),
    'bounty/reports': (200, 11), 'bounty/stats': (200, 15), 'bounty/workbench': (200, 13),
    'bounty/taxonomy': (200, 9), 'bounty/playbook': (200, 9), 'account/me': (200, 12),
    'welcome/state': (200, 35), 'welcome/progress': (200, 14),
}

# GET routes of the REST API (agentapi.rest.ROUTES), keyed by the route pattern; ``pattern ?query`` is a variant with the query string a page sends
REST = {
    'me': (200, 9), 'system/status': (200, 96),
    'projects': (200, 8), 'engines': (200, 8),
    'states': (200, 7), 'cves': (200, 9),
    'cves/(?P<cve_id>CVE-[0-9]{4}-[0-9]+|CVE-[A-Za-z0-9-]+)/detection': (200, 8), 'cves/(?P<cve_id>CVE-[0-9]{4}-[0-9]+|CVE-[A-Za-z0-9-]+)': (200, 8),
    'generated-templates': (200, 8), 'projects/(?P<slug>[-\\w]+)/targets': (200, 16),
    'projects/(?P<slug>[-\\w]+)/targets/(?P<target_id>\\d+)': (200, 9), 'projects/(?P<slug>[-\\w]+)/scans': (200, 14),
    'projects/(?P<slug>[-\\w]+)/scans/(?P<scan_id>\\d+)': (200, 14), 'projects/(?P<slug>[-\\w]+)/scans/(?P<scan_id>\\d+)/subdomains': (200, 13),
    'projects/(?P<slug>[-\\w]+)/scans/(?P<scan_id>\\d+)/endpoints': (200, 11),
    'projects/(?P<slug>[-\\w]+)/scans/(?P<scan_id>\\d+)/vulnerabilities': (200, 15),
    'projects/(?P<slug>[-\\w]+)/scans/(?P<scan_id>\\d+)/activity': (200, 11), 'projects/(?P<slug>[-\\w]+)/hosts': (200, 70),
    'projects/(?P<slug>[-\\w]+)/host-assessments': (400, 8), 'projects/(?P<slug>[-\\w]+)/hosts/(?P<host_id>\\d+)/review': (200, 17),
    'projects/(?P<slug>[-\\w]+)/hosts/(?P<host_id>\\d+)/screenshots': (200, 12),
    'projects/(?P<slug>[-\\w]+)/hosts/(?P<host_id>\\d+)/export': (200, 110), 'projects/(?P<slug>[-\\w]+)/exclusions': (200, 10),
    'projects/(?P<slug>[-\\w]+)/excluded-addresses': (200, 10), 'projects/(?P<slug>[-\\w]+)/inventory': (200, 11),
    'projects/(?P<slug>[-\\w]+)/search': (200, 73), 'projects/(?P<slug>[-\\w]+)/hosts/export': (200, 22),
    'orgs/(?P<org>[-\\w]+)/hosts/export': (200, 24), 'projects/(?P<slug>[-\\w]+)/saved-searches': (200, 10),
    'projects/(?P<slug>[-\\w]+)/routes': (200, 10), 'projects/(?P<slug>[-\\w]+)/certificates': (200, 10),
    'projects/(?P<slug>[-\\w]+)/hygiene': (200, 10), 'projects/(?P<slug>[-\\w]+)/changes': (200, 10),
    'projects/(?P<slug>[-\\w]+)/activity-days': (200, 9), 'projects/(?P<slug>[-\\w]+)/stats/history': (200, 9),
    'projects/(?P<slug>[-\\w]+)/activity': (200, 10), 'projects/(?P<slug>[-\\w]+)/secrets': (200, 11),
    'projects/(?P<slug>[-\\w]+)/secrets/settings': (200, 12), 'projects/(?P<slug>[-\\w]+)/secrets/(?P<secret_id>\\d+)': (200, 16),
    'projects/(?P<slug>[-\\w]+)/api-keys': (200, 10), 'projects/(?P<slug>[-\\w]+)/runzero': (200, 11),
    'projects/(?P<slug>[-\\w]+)/suppliers': (200, 10), 'projects/(?P<slug>[-\\w]+)/suppliers/hosts': (200, 9),
    'projects/(?P<slug>[-\\w]+)/suppliers/technologies': (200, 9), 'projects/(?P<slug>[-\\w]+)/suppliers/findings': (200, 10),
    'projects/(?P<slug>[-\\w]+)/auth-credentials': (200, 9), 'projects/(?P<slug>[-\\w]+)/internal-ranges': (200, 9),
    'projects/(?P<slug>[-\\w]+)/tailscale': (200, 9), 'projects/(?P<slug>[-\\w]+)/tailscale/devices': (200, 10),
    'projects/(?P<slug>[-\\w]+)/findings': (200, 21), 'projects/(?P<slug>[-\\w]+)/situations': (200, 10),
    'projects/(?P<slug>[-\\w]+)/situations/(?P<host>[^/]+)': (200, 17), 'projects/(?P<slug>[-\\w]+)/vulnerabilities': (200, 14),
    'projects/(?P<slug>[-\\w]+)/matches': (200, 17), 'projects/(?P<slug>[-\\w]+)/triage': (200, 10),
    'projects/(?P<slug>[-\\w]+)/findings/(?P<kind>match|vulnerability|route|hygiene)/(?P<finding_id>\\d+)': (200, 21),
    'projects/(?P<slug>[-\\w]+)/findings/(?P<kind>match|vulnerability|hygiene)/(?P<finding_id>\\d+)/retest': (200, 11),
    'projects/(?P<slug>[-\\w]+)/findings/(?P<kind>match|vulnerability|hygiene)/(?P<finding_id>\\d+)/comments': (200, 12),
    'projects/(?P<slug>[-\\w]+)/findings/(?P<kind>match|vulnerability|hygiene)/(?P<finding_id>\\d+)/audit': (200, 12), 'reporting/scopes': (200, 13),
    'report-subscriptions': (200, 17), 'reporting/digest-preview': (400, 7),
    'reporting/threats': (400, 7), 'reporting/zero-wire': (200, 9),
    'reporting/reports': (200, 8), 'projects/(?P<slug>[-\\w]+)/settings': (200, 11),
    'projects/(?P<slug>[-\\w]+)/members': (200, 10), 'projects/(?P<slug>[-\\w]+)/work': (200, 14),
    'assets': (200, 7), 'agent': (200, 8),
    'agent/assignments': (200, 11), 'agent/tasks/(?P<task_id>\\d+)': (404, 9),
    'agents': (200, 15), 'agents/(?P<agent_id>\\d+)': (200, 30),
    'sentinels/defaults': (200, 10), 'tuning': (200, 16),
    'tuning/decisions': (200, 8), 'tuning/report': (200, 26),
    'technology-coverage': (200, 12), 'sentinels/dispatch': (200, 7),
    'projects/(?P<slug>[-\\w]+)/agent-tasks': (200, 11), 'projects/(?P<slug>[-\\w]+)/agent-tasks/unassignable': (200, 10),
    'reviewer/config': (200, 12), 'reviewer/findings/next': (200, 9),
    'reviewer/ops/snapshot': (200, 164), 'reviewer/jobs/next': (200, 9),
    'sentinel': (200, 8), 'sentinel/secret-rules/bundle': (404, 9),
    'secrets/rules': (200, 9), 'sentinel/tasks/(?P<task_id>\\d+)': (404, 9),
    'sentinel/tasks/(?P<task_id>\\d+)/check': (404, 11), 'projects/(?P<slug>[-\\w]+)/sentinels/enroll': (201, 12),
    'orgs/(?P<org>[-\\w]+)/sentinels/enroll': (201, 12), 'sentinels/live': (200, 34),
    'sentinels/enroll': (201, 11), 'projects/(?P<slug>[-\\w]+)/sentinels': (200, 22),
    'projects/(?P<slug>[-\\w]+)/sentinel-tasks': (200, 14), 'tokens': (200, 9),
    'projects/(?P<slug>[-\\w]+)/search ?q=&sort=score&page=1&page_size=50': (200, 73),
    'projects/(?P<slug>[-\\w]+)/search ?q=nginx&page=1&page_size=50': (200, 74), 'projects/(?P<slug>[-\\w]+)/hosts ?page=2&page_size=50': (200, 58),
    'projects/(?P<slug>[-\\w]+)/hosts ?page_size=200': (200, 70), 'projects/(?P<slug>[-\\w]+)/findings ?type=all&page=1&page_size=50': (200, 21),
    'projects/(?P<slug>[-\\w]+)/findings ?type=all&group=cve&page=1&page_size=50': (200, 18),
    'projects/(?P<slug>[-\\w]+)/findings ?page_size=0&type=all': (200, 10), 'projects/(?P<slug>[-\\w]+)/matches ?page_size=200': (200, 17),
    'projects/(?P<slug>[-\\w]+)/vulnerabilities ?page_size=200': (200, 14), 'projects/(?P<slug>[-\\w]+)/scans ?page_size=200': (200, 14),
    'projects/(?P<slug>[-\\w]+)/situations ?page_size=200': (200, 10), 'projects/(?P<slug>[-\\w]+)/sentinel-tasks ?page_size=200': (200, 14),
    'projects/(?P<slug>[-\\w]+)/host-assessments ?host_id={host_id}': (200, 10), 'reporting/threats ?project={slug}': (200, 12),
    'reporting/digest-preview ?project={slug}': (200, 75), 'reporting/digest-preview ?project={slug}&format=json': (200, 75),
}
VARIANTS = ('projects/(?P<slug>[-\\w]+)/search ?q=&sort=score&page=1&page_size=50', 'projects/(?P<slug>[-\\w]+)/search ?q=nginx&page=1&page_size=50',
            'projects/(?P<slug>[-\\w]+)/hosts ?page=2&page_size=50', 'projects/(?P<slug>[-\\w]+)/hosts ?page_size=200',
            'projects/(?P<slug>[-\\w]+)/findings ?type=all&page=1&page_size=50', 'projects/(?P<slug>[-\\w]+)/findings ?type=all&group=cve&page=1&page_size=50',
            'projects/(?P<slug>[-\\w]+)/findings ?page_size=0&type=all', 'projects/(?P<slug>[-\\w]+)/matches ?page_size=200',
            'projects/(?P<slug>[-\\w]+)/vulnerabilities ?page_size=200', 'projects/(?P<slug>[-\\w]+)/scans ?page_size=200',
            'projects/(?P<slug>[-\\w]+)/situations ?page_size=200', 'projects/(?P<slug>[-\\w]+)/sentinel-tasks ?page_size=200',
            'projects/(?P<slug>[-\\w]+)/host-assessments ?host_id={host_id}', 'reporting/threats ?project={slug}',
            'reporting/digest-preview ?project={slug}', 'reporting/digest-preview ?project={slug}&format=json')

# which credential a REST route takes: a Sentinel's token, the AI reviewer's token, a signed-in session, or (every other route) a full API token
CREDENTIAL = (('sentinel/', 'sentinel'), ('reviewer/', 'reviewer'), ('agent/', 'agent'), ('tokens', 'session'))
MCP_CREDENTIAL = {'list_my_assignments': 'agent', 'get_task': 'agent', 'get_sentinel_task': 'agent'}  # the agent tools answer a registered agent only

# MCP arguments beyond ``project``: a literal, or the name of a fixture value (``fixture_ids``)
MCP_ARGS = {
    'get_secret': {'id': 'secret_id'}, 'get_finding': {'kind': 'match', 'id': 'match_id'}, 'list_finding_comments': {'kind': 'match', 'id': 'match_id'},
    'get_finding_retest': {'kind': 'match', 'id': 'match_id'}, 'finding_audit': {'kind': 'match', 'id': 'match_id'}, 'get_setting': {'name': 'tunables'},
    'export_hosts': {'project': 'slug'}, 'export_report': {'project': 'slug'}, 'get_threat_digest': {'project': 'slug'},
}

# a query string a dispatcher's GET routes need (the bounty views answer 400 "pick a project" without one)
DISPATCH_QUERY = {'bounty': '?project={slug}'}

# read-only MCP tools (agentapi.mcp.TOOLS), keyed by name
MCP = {
    'whoami': (200, 11), 'list_projects': (200, 10), 'get_system_status': (200, 98), 'list_engines': (200, 10),
    'describe_states': (200, 9), 'list_targets': (200, 18), 'get_host_review': (200, 19), 'get_host_screenshots': (200, 14),
    'list_scans': (200, 16), 'get_scan': (200, 16), 'list_scan_subdomains': (200, 15), 'list_scan_endpoints': (200, 13),
    'list_scan_vulnerabilities': (200, 17), 'get_scan_activity': (200, 13), 'search_hosts': (200, 75), 'export_hosts': (200, 24),
    'export_host': (200, 112), 'list_saved_searches': (200, 12), 'list_hosts': (200, 60), 'list_exclusions': (200, 12),
    'list_excluded_addresses': (200, 12), 'list_auth_credentials': (200, 11), 'tailscale_status': (200, 11), 'list_tailscale_devices': (200, 12),
    'list_findings': (200, 23), 'list_situations': (200, 12), 'get_situation': (200, 19), 'export_report': (200, 14),
    'get_threat_digest': (200, 14), 'list_report_scopes': (200, 15), 'list_report_subscriptions': (200, 19), 'list_vulnerabilities': (200, 16),
    'list_routes': (200, 12), 'list_certificates': (200, 12), 'list_hygiene_findings': (200, 12), 'list_secrets': (200, 13),
    'get_secret': (200, 18), 'list_changes': (200, 12), 'list_activity': (200, 12), 'stats_history': (200, 11),
    'list_cves': (200, 11), 'get_cve': (200, 10), 'get_cve_detection': (200, 10), 'list_generated_templates': (200, 10),
    'list_cve_matches': (200, 19), 'get_finding': (200, 23), 'list_triage': (200, 12), 'get_remediation_work': (200, 16),
    'list_finding_comments': (200, 14), 'get_finding_retest': (200, 13), 'finding_audit': (200, 14), 'get_project_settings': (200, 13),
    'get_runzero_sync': (200, 13), 'list_suppliers': (200, 12), 'search_supplier_technology': (200, 11), 'list_supplier_technologies': (200, 11),
    'list_supplier_findings': (200, 12), 'list_members': (200, 12), 'list_host_inventories': (200, 13), 'list_my_assignments': (200, 13),
    'get_task': (200, 11), 'list_agent_tasks': (200, 13), 'list_unassignable_work': (200, 12), 'list_agents': (200, 17),
    'get_tuning_status': (200, 18), 'list_tuning_decisions': (200, 10), 'get_maintainer_report': (200, 28), 'technology_coverage': (200, 14),
    'list_settings': (200, 9), 'get_setting': (200, 19), 'get_sentinel_defaults': (200, 12), 'get_sentinel_dispatch': (200, 9),
    'get_agent': (200, 32), 'get_sentinel_task': (200, 10), 'list_sentinel_tasks': (200, 16), 'list_sentinels': (200, 17),
    'get_sentinel': (200, 32),
}

# routes and tools that are not measured here, each with the reason
UNMEASURED = {
    'bounty/programs/(?P<program_id>\\d+)': 'the scale fixture holds no bug bounty program or report: a read of one row by id',
    'bounty/reports/(?P<report_id>\\d+)': 'the scale fixture holds no bug bounty program or report: a read of one row by id',
    'bounty/reports/(?P<report_id>\\d+)/export': 'the scale fixture holds no bug bounty program or report: a read of one row by id',
    'mcp:get_host_assessment': 'the scale fixture holds no host assessment: a read of one row by id',
    'mcp:get_saved_search_matches': 'the scale fixture holds no saved search, so neither it nor its matches can be read',
    'mcp:get_report': 'the scale fixture holds no generated report file: a read of one row by its token',
    'mcp:get_report_subscription': 'the scale fixture holds no email report subscription: a read of one row by id',
    'mcp:preview_report_subscription': 'the scale fixture holds no email report subscription: a read of one row by id',
    'mcp:list_report_deliveries': 'the scale fixture holds no email report subscription: a read of one row by id',
    'mcp:get_generated_template': 'the scale fixture holds no AI written template: a read of one row by id',
    'mcp:review_generated_template': 'the scale fixture holds no AI written template: a read of one row by id',
    'mcp:get_validation_request': 'the scale fixture holds no validation request: a read of one row by id',
    'mcp:get_supplier_message': 'the scale fixture holds no supplier record: a read of one supplier',
    'generated-templates/(?P<generated_id>\\d+)': 'the scale fixture holds no AI written template: a read of one row by id',
    'generated-templates/(?P<generated_id>\\d+)/review': 'the scale fixture holds no AI written template: a read of one row by id',
    'projects/(?P<slug>[-\\w]+)/host-assessments/(?P<assessment_id>\\d+)': 'the scale fixture holds no host assessment: a read of one row by id',
    'projects/(?P<slug>[-\\w]+)/inventory/(?P<inventory_id>\\d+)': 'the scale fixture holds no inventory report: a read of one report by id or host',
    'projects/(?P<slug>[-\\w]+)/saved-searches/(?P<search_id>\\d+)': 'the scale fixture holds no saved search, so neither it nor its matches can be read',
    'projects/(?P<slug>[-\\w]+)/saved-searches/(?P<search_id>\\d+)/matches': 'the scale fixture holds no saved search, so neither it nor its matches can be read',
    'projects/(?P<slug>[-\\w]+)/suppliers/(?P<supplier_id>\\d+)/summary': 'the scale fixture holds no supplier record: a read of one supplier',
    'projects/(?P<slug>[-\\w]+)/matches/(?P<match_id>\\d+)/validate/(?P<request_id>\\d+)': 'the scale fixture holds no validation request: a read of one row by id',
    'projects/(?P<slug>[-\\w]+)/reports/(?P<token>[-\\w]+)': 'the scale fixture holds no generated report file: a read of one row by its token',
    'projects/(?P<slug>[-\\w]+)/reports/(?P<token>[-\\w]+)/download': 'the scale fixture holds no generated report file: a read of one row by its token',
    'orgs/(?P<org>[-\\w]+)/reports/(?P<token>[-\\w]+)': 'the scale fixture holds no generated report file: a read of one row by its token',
    'orgs/(?P<org>[-\\w]+)/reports/(?P<token>[-\\w]+)/download': 'the scale fixture holds no generated report file: a read of one row by its token',
    'report-subscriptions/(?P<subscription_id>\\d+)': 'the scale fixture holds no email report subscription: a read of one row by id',
    'report-subscriptions/(?P<subscription_id>\\d+)/preview': 'the scale fixture holds no email report subscription: a read of one row by id',
    'report-subscriptions/(?P<subscription_id>\\d+)/deliveries': 'the scale fixture holds no email report subscription: a read of one row by id',
    'projects/(?P<slug>[-\\w]+)/hosts/(?P<host>[^/]+)/inventory': 'the scale fixture holds no inventory report: a read of one report by id or host',
    'mcp:get_host_inventory': 'the scale fixture holds no inventory report: a read of one report by id or host',
}


# ---------------------------------------------------------------------------------------------------------------------- the fixture


def fixture_ids():
    from agentapi.models import Agent, SentinelTask
    from cveFeed.models import CVEMatch, HygieneFinding, SecretFinding
    from dashboard.models import Project
    from startScan.models import Subdomain, Vulnerability
    from targetApp.models import Domain
    p = Project.objects.get(slug=SLUG)
    ids = {'slug': SLUG, 'project_id': p.id, 'org': p.org.slug, 'org_id': p.org_id}
    ids['scan_id'] = Subdomain.objects.filter(target_domain__project=p).order_by('-scan_history_id').values_list('scan_history_id', flat=True).first()
    ids['host_id'], ids['host'] = Subdomain.objects.filter(target_domain__project=p, scan_history_id=ids['scan_id']).order_by('id').values_list('id', 'name').first()
    ids['subdomain_id'] = ids['host_id']
    ids['target_id'] = Domain.objects.filter(project=p).order_by('id').values_list('id', flat=True).first()
    ids['vuln_id'] = Vulnerability.objects.filter(target_domain__project=p).order_by('-id').values_list('id', flat=True).first()
    ids['match_id'], ids['cve_id'] = CVEMatch.objects.filter(subdomain__target_domain__project=p).order_by('-id').values_list('id', 'cve_entry__cve_id').first()
    ids['hygiene_id'] = HygieneFinding.objects.filter(domain__project=p).order_by('-id').values_list('id', flat=True).first()
    ids['secret_id'] = SecretFinding.objects.filter(project=p).order_by('id').values_list('id', flat=True).first()
    ids['agent_id'] = Agent.objects.order_by('id').values_list('id', flat=True).first()
    ids['task_id'] = SentinelTask.objects.filter(project=p).order_by('-id').values_list('id', flat=True).first()
    return ids


KINDS = {'match': 'match_id', 'vulnerability': 'vuln_id', 'hygiene': 'hygiene_id'}


def fill(pattern, ids):
    """``pattern`` (a route regex) with each named group replaced by the fixture's value, or None when the fixture has none for a group."""
    out, i = '', 0
    while i < len(pattern):
        if pattern.startswith('(?P<', i):
            name = pattern[i + 4:pattern.index('>', i)]
            depth, k = 1, pattern.index('>', i) + 1
            while depth:
                if pattern[k] == '\\':
                    k += 2
                    continue
                depth += {'(': 1, ')': -1}.get(pattern[k], 0)
                k += 1
            if name == 'kind':
                value = 'match'
            elif name == 'finding_id':
                value = ids.get('match_id')
            elif name == 'which':
                value = 'manifest'
            else:
                value = ids.get(name)
            if value is None:
                return None
            out += str(value)
            i = k
        else:
            out += pattern[i]
            i += 1
    return out.replace('\\', '')


def rest_get_patterns():
    from agentapi import rest
    return [pat for method, pat, _summary, _fn in rest.ROUTES if method == 'GET']


def dispatcher_get_patterns():
    from cveFeed import account_api, admin_api, bounty_api, settings_api, welcome
    out = []
    for module, prefix in ((settings_api, 'settings'), (admin_api, 'admin'), (bounty_api, 'bounty'), (account_api, 'account'), (welcome, 'welcome')):
        routes = module.ROUTES
        pairs = routes.keys() if isinstance(routes, dict) else [(r[0], r[1]) for r in routes]
        out += [(prefix, pat) for method, pat in pairs if method == 'GET']
    return out


def read_only_tools():
    from agentapi import mcp
    return [(t[0], t[2]) for t in mcp.TOOLS if not t[4]]


class _NoWorkers:
    """A Celery inspector no worker answers: every question gets no reply at once."""

    def __getattr__(self, name):
        return lambda *args, **kwargs: None


class QueryCeilings(TestCase):
    @classmethod
    def setUpTestData(cls):
        # the command's own build (``handle`` adds a database-wide ANALYZE, which a test does not need)
        Command().build(60, random.Random(1), 1, TARGETS=3, n_sentinels=2, n_tasks=60, task_days=7, n_secrets=8)
        from agentapi.auth import create_token
        cls.admin = User.objects.get(username='scale-admin')
        cls.token = create_token(cls.admin, 'query-ceilings')[1]
        cls.reviewer_token = create_token(cls.admin, 'query-ceilings reviewer', scope='reviewer')[1]
        cls.sentinel_token = cls.enroll_sentinel()
        cls.agent_token = create_token(cls.admin, 'query-ceilings agent')[1]
        cls.mcp(cls.agent_token, 'register_agent', {'name': 'ceilings', 'kind': 'validation'})
        cls.ids = fixture_ids()

    @classmethod
    def mcp(cls, token, name, args, client=None):
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': name, 'arguments': args}})
        return (client or Client(HTTP_HOST='localhost')).post('/mcp/', body, content_type='application/json', HTTP_AUTHORIZATION=f'Bearer {token}')

    @classmethod
    def enroll_sentinel(cls):
        """A Sentinel's own token, minted the way a real one is (an enrollment secret traded at bootstrap)."""
        client = Client(HTTP_HOST='localhost')
        auth = {'HTTP_AUTHORIZATION': f'Bearer {cls.token}'}
        out = client.post(f'/api/v1/projects/{SLUG}/sentinels/enroll', '{}', content_type='application/json', **auth).json()
        boot = client.post('/api/v1/sentinels/bootstrap', json.dumps({'enrollment_token': out['enrollment_token'], 'name': 'ceilings',
                                                                       'capabilities': ['nmap']}), content_type='application/json')
        assert boot.status_code == 201, boot.content
        return boot.json()['token']

    def setUp(self):
        cache.clear()
        self.client = Client(HTTP_HOST='localhost')
        self.client.force_login(self.admin, backend='django.contrib.auth.backends.ModelBackend')
        session = self.client.session
        session['mfa_verified'] = True
        session.save()

    def count(self, call):
        from cvengine.celery import app
        cache.clear()
        # no worker answers in a test: the status pages would wait out each ping's timeout; they count the same statements with none answering
        with steady_caches(), mock.patch.object(app.control, 'inspect', return_value=_NoWorkers()):
            self.read(call())  # warm: the snapshots, the per-process lists and the first-use lookups are not what is measured
            connection.queries_log.clear()
            with CaptureQueriesContext(connection) as q:
                response = call()
                self.read(response)  # a streamed export reads its rows while it is sent: those statements count too
        return response, len(q), [x['sql'][:160] for x in q.captured_queries]

    @staticmethod
    def read(response):
        """The body of ``response``, read once (a streamed one is drained here), kept on ``response.body``."""
        response.body = b''.join(response.streaming_content) if response.streaming else response.content
        return response

    @staticmethod
    def refusal(response):
        """The error an answer carries (a JSON-RPC or tool error, or a 4xx body), for the print mode: a ceiling of a refusal measures nothing."""
        body = response.body[:2000].decode('utf-8', 'replace')
        if response.status_code >= 400:
            return body[:120]
        if '"isError": true' in body or '"error":' in body[:40]:
            return body[:200]
        return ''

    def check(self, table, key, call):
        started = time.monotonic()
        response, n, sql = self.count(call)
        if PRINT:
            print(f'CEILING {key!r}: ({response.status_code}, {n}),  # {time.monotonic() - started:.2f} s {self.refusal(response)!r}', flush=True)
            return
        if key not in table:
            return  # test_every_route_and_tool_has_a_ceiling names it
        status, measured = table[key]
        with self.subTest(key=key):
            self.assertEqual(response.status_code, status, (key, response.body[:200]))
            self.assertLessEqual(n, measured + slack(measured), f'{key}: {n} statements, ceiling {measured + slack(measured)}\n' + '\n'.join(sql))

    def unfilled(self, key, path):
        """True (skip it) when the fixture has no value for a part of ``key``'s path; outside the print mode that is a failure."""
        if path is not None:
            return False
        if PRINT:
            print(f'UNFILLED {key!r}', flush=True)
            return True
        self.fail(f'{key}: the fixture has no value for it; give it one or list it in UNMEASURED')

    def get(self, path, token=False):
        """A GET as the signed-in admin; ``token`` adds a bearer token (True: the admin's full token, or a token itself)."""
        token = self.token if token is True else token
        headers = {'HTTP_AUTHORIZATION': f'Bearer {token}'} if token else {}
        return lambda: self.client.get(path, **headers)

    def credential(self, path):
        kind = next((kind for prefix, kind in CREDENTIAL if path.startswith(prefix)), 'full')
        return self.tokens(kind)

    def tokens(self, kind):
        return {'full': self.token, 'session': False, 'sentinel': self.sentinel_token, 'reviewer': self.reviewer_token, 'agent': self.agent_token}[kind]

    def test_pages(self):
        for key in PAGES:
            self.check(PAGES, key, self.get(key.format(**self.ids)))

    def test_cve_api_views(self):
        for key in CVE_API:
            self.check(CVE_API, key, self.get('/cve/api/' + key.format(**self.ids)))

    def test_cve_api_dispatchers(self):
        for prefix, pattern in dispatcher_get_patterns():
            key = f'{prefix}/{pattern}'
            if key in UNMEASURED:
                continue
            path = fill(pattern, self.ids)
            if self.unfilled(key, path):
                continue
            self.check(DISPATCH, key, self.get(f'/cve/api/{prefix}/{path}' + DISPATCH_QUERY.get(prefix, '').format(**self.ids)))

    def test_rest_routes(self):
        for key in list(dict.fromkeys(rest_get_patterns() + list(VARIANTS) + [k for k in REST if ' ?' in k])):
            pattern, _, query = key.partition(' ?')
            if key in UNMEASURED:
                continue
            path = fill(pattern, self.ids)
            if self.unfilled(key, path):
                continue
            self.check(REST, key, self.get(f'/api/v1/{path}' + (f'?{query.format(**self.ids)}' if query else ''), token=self.credential(path)))

    def test_mcp_read_only_tools(self):
        values = {'project': SLUG, 'host_id': self.ids['host_id'], 'host': self.ids['host'], 'scan_id': self.ids['scan_id'],
                  'target_id': self.ids['target_id'], 'cve_id': self.ids['cve_id'], 'agent_id': self.ids['agent_id'], 'task_id': self.ids['task_id'],
                  'org': self.ids['org']}
        for name, schema in read_only_tools():
            if f'mcp:{name}' in UNMEASURED:
                continue
            missing = [k for k in schema.get('required', []) if k not in values and k not in MCP_ARGS.get(name, {})]
            if self.unfilled(f'mcp:{name}', None if missing else name):
                continue
            extra = MCP_ARGS.get(name, {})
            args = {k: values[k] for k in schema.get('required', []) if k not in extra}
            args.update({k: self.ids.get(v, v) for k, v in extra.items()})
            token = self.tokens(MCP_CREDENTIAL.get(name, 'full'))
            self.check(MCP, name, lambda n=name, a=args, t=token: self.mcp(t, n, a, self.client))

    def test_every_route_and_tool_has_a_ceiling(self):
        """A route or tool added later fails here until it has a ceiling in the tables above (or a reason in ``UNMEASURED``)."""
        missing = [f'REST {p}' for p in rest_get_patterns() if p not in REST and p not in UNMEASURED]
        missing += [f'/cve/api/{prefix}/{p}' for prefix, p in dispatcher_get_patterns() if f'{prefix}/{p}' not in DISPATCH and f'{prefix}/{p}' not in UNMEASURED]
        missing += [f'MCP {name}' for name, _schema in read_only_tools() if name not in MCP and f'mcp:{name}' not in UNMEASURED]
        self.assertEqual(missing, [], 'give each a ceiling in tests/test_query_ceilings.py')

    def test_every_value_in_the_tables_is_a_real_route(self):
        rest = set(rest_get_patterns())
        self.assertEqual([k for k in REST if k.partition(' ?')[0] not in rest], [])
        dispatch = {f'{prefix}/{p}' for prefix, p in dispatcher_get_patterns()}
        self.assertEqual([k for k in DISPATCH if k not in dispatch], [])
        tools = {name for name, _schema in read_only_tools()}
        self.assertEqual([k for k in MCP if k not in tools], [])
        self.assertTrue(all(reason and len(reason.split()) > 3 for reason in UNMEASURED.values()), 'every unmeasured entry says why')
