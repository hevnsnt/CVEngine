"""Tenancy over every route: a caller of one organization never reaches another organization's rows.

Every REST route (agentapi.rest.ROUTES), every MCP tool (agentapi.mcp.TOOLS) and every route of the web interface's JSON dispatchers
(cveFeed admin_api, settings_api, welcome, account_api, bounty_api) is listed in a table below with what another organization's caller gets.
A route or tool that is added without a line in its table fails ``test_every_route_and_tool_has_a_line``, so new surface cannot ship untested.

The fixture is two organizations. The victim's project is the synthetic scale fixture (hosts, scans, findings, matches, hygiene, certificates,
Sentinel tasks, secrets) plus the rows its admin creates through the API (a saved search, an email report, a supplier, a report, a host
assessment, an enrollment, a comment, an internal range, a stored sign-in, a key). The attacker is the admin of a second organization with a
full token, a Sentinel of its own and a signed-in session.

What is checked:
* each route and tool, called with the victim's slug, organization and row ids (and with the attacker's own slug and the victim's ids),
  answers the status in its table (404 unless a role gate answers 403 before any row is read) and its answer names nothing of the victim;
* no row that existed before those calls was changed or deleted, and the only new rows are the attacker's own log lines;
* every list and count the attacker can read (REST, MCP, the web pages' JSON) is the same whether or not the victim's organization exists,
  with the victim's caller having warmed every cache first, so a cache keyed without the scope shows up as a difference.
"""
import hashlib
import io
import json
import os
import re
from unittest import mock

from django.apps import apps
from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from agentapi import mcp, rest
from agentapi.auth import create_token
from agentapi.services import ApiError
from dashboard.models import Org, OrgMembership, Project, ProjectMembership, UserProfile
from tests.test_tenancy import client_for

V_SLUG = 'scale-fixture'  # seed_scale_fixture's project and organization slug
A_SLUG = 'rival'
# text that only the victim's rows hold: its slug and names, host names, the names its admin gave things, its people
MARKERS = re.compile(r'scale-fixture|Scale Fixture|scale-sentinel|scale-admin|scale-viewer|h\d+\.t\d+\.example\.com|\bt\d+\.example\.com|'
                     r'victim|10\.77\.0\.0|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.')

PATH_ARG = re.compile(r'\(\?P<(\w+)>[^)]*\)')
NOT_FOUND = 404

# REST: what another organization's full token gets
# key: 'METHOD pattern' exactly as in rest.ROUTES. value: the status for the cross-tenant call, or a tuple of allowed statuses with the reason
# in a comment. 'own' marks a route that only ever acts on the caller's own rows (its answer is then checked for the victim's text instead).
OWN, CATALOGUE_ROUTE = 'own', 'catalogue'
ADMIN_ONLY = 403  # an App Admin role gate that answers before any row is read
MACHINE = 403  # a route of the Sentinel or reviewer token scope: a full token is refused by the scope gate
SESSION_ONLY = 403  # tokens are managed from a signed-in session


def _rest_table():
	t = {}
	for method, pattern, _summary, _fn in rest.ROUTES:
		names = set(re.findall(r'\(\?P<(\w+)>', pattern))
		key = f'{method} {pattern}'
		if 'slug' in names or 'org' in names:
			t[key] = NOT_FOUND
	t.update({
		'GET me': OWN, 'GET system/status': OWN, 'GET projects': OWN, 'GET engines': CATALOGUE_ROUTE, 'GET states': CATALOGUE_ROUTE,
		'GET cves': CATALOGUE_ROUTE, 'GET cves/(?P<cve_id>CVE-[0-9]{4}-[0-9]+|CVE-[A-Za-z0-9-]+)/detection': CATALOGUE_ROUTE,
		'PUT cves/(?P<cve_id>CVE-[0-9]{4}-[0-9]+|CVE-[A-Za-z0-9-]+)/detection': ADMIN_ONLY,
		'GET cves/(?P<cve_id>CVE-[0-9]{4}-[0-9]+|CVE-[A-Za-z0-9-]+)': CATALOGUE_ROUTE,
		'GET generated-templates': CATALOGUE_ROUTE, 'GET generated-templates/(?P<generated_id>\\d+)': CATALOGUE_ROUTE,
		'GET generated-templates/(?P<generated_id>\\d+)/review': CATALOGUE_ROUTE,
		'POST generated-templates/(?P<generated_id>\\d+)/review': ADMIN_ONLY, 'POST generated-templates/(?P<generated_id>\\d+)/revisions': ADMIN_ONLY,
		'POST targets/bulk-org': OWN,  # the paste names the victim's organization: it is treated as one that does not exist, the projects go into the caller's own
		'GET reporting/scopes': OWN, 'GET report-subscriptions': OWN, 'POST report-subscriptions': NOT_FOUND,
		'GET report-subscriptions/(?P<subscription_id>\\d+)': NOT_FOUND, 'PATCH report-subscriptions/(?P<subscription_id>\\d+)': NOT_FOUND,
		'DELETE report-subscriptions/(?P<subscription_id>\\d+)': NOT_FOUND, 'POST report-subscriptions/(?P<subscription_id>\\d+)/test': NOT_FOUND,
		'GET report-subscriptions/(?P<subscription_id>\\d+)/preview': NOT_FOUND, 'GET report-subscriptions/(?P<subscription_id>\\d+)/deliveries': NOT_FOUND,
		'GET reporting/digest-preview': NOT_FOUND, 'GET reporting/threats': NOT_FOUND,
		'GET reporting/zero-wire': OWN, 'PUT reporting/zero-wire': 403,  # a person switches it, never a token
		'GET reporting/reports': OWN, 'GET assets': OWN, 'PUT assets': OWN,
		'GET agent': OWN, 'PUT agent': OWN, 'DELETE agent': OWN, 'POST agent/heartbeat': OWN, 'GET agent/assignments': OWN, 'POST agent/tasks/next': OWN,
		'GET agent/tasks/(?P<task_id>\\d+)': NOT_FOUND, 'POST agent/tasks/(?P<task_id>\\d+)/accept': NOT_FOUND,
		'POST agent/tasks/(?P<task_id>\\d+)/result': NOT_FOUND, 'POST agent/tasks/(?P<task_id>\\d+)/release': NOT_FOUND,
		'GET agents': OWN, 'GET agents/(?P<agent_id>\\d+)': NOT_FOUND, 'PATCH agents/(?P<agent_id>\\d+)': NOT_FOUND,
		'DELETE agents/(?P<agent_id>\\d+)': NOT_FOUND,
		'GET sentinels/defaults': OWN, 'PUT sentinels/defaults': ADMIN_ONLY,
		'GET tuning': ADMIN_ONLY, 'GET tuning/decisions': ADMIN_ONLY, 'GET tuning/report': ADMIN_ONLY, 'GET technology-coverage': ADMIN_ONLY,
		'PUT tuning/mode': ADMIN_ONLY, 'POST tuning/decisions/(?P<decision_id>\\d+)/apply': ADMIN_ONLY,
		'POST tuning/decisions/(?P<decision_id>\\d+)/revert': ADMIN_ONLY, 'POST tuning/release': ADMIN_ONLY,
		'GET sentinels/dispatch': OWN,
		'GET reviewer/config': MACHINE, 'GET reviewer/findings/next': MACHINE, 'POST reviewer/findings/(?P<ref>t\\d{1,12})/verdict': MACHINE,
		'POST reviewer/findings/(?P<ref>t\\d{1,12})/refusal': MACHINE, 'GET reviewer/ops/snapshot': MACHINE, 'POST reviewer/ops/report': MACHINE,
		'POST reviewer/usage': MACHINE, 'GET reviewer/jobs/next': MACHINE, 'POST reviewer/jobs/(?P<job_id>\\d{1,12})/result': MACHINE,
		'POST sentinels/bootstrap': 400,  # no enrollment secret of the victim is known to the caller: the one-time secret is the whole check
		'GET sentinel': OWN, 'PUT sentinel': OWN, 'DELETE sentinel': OWN, 'POST sentinel/heartbeat': OWN,
		'GET sentinel/secret-rules/bundle': 403, 'GET secrets/rules': ADMIN_ONLY, 'PUT secrets/rules': ADMIN_ONLY,
		'POST sentinel/tasks/next': OWN, 'GET sentinel/tasks/(?P<task_id>\\d+)': NOT_FOUND, 'GET sentinel/tasks/(?P<task_id>\\d+)/check': NOT_FOUND,
		'POST sentinel/tasks/(?P<task_id>\\d+)/accept': NOT_FOUND, 'POST sentinel/tasks/(?P<task_id>\\d+)/result': NOT_FOUND,
		'POST sentinel/tasks/(?P<task_id>\\d+)/partial': NOT_FOUND, 'POST sentinel/tasks/(?P<task_id>\\d+)/secret': 403,  # the built-in scanner's only
		'POST sentinel/tasks/(?P<task_id>\\d+)/release': NOT_FOUND,
		# one answer for an organization the caller does not administer, existing or not (no existence oracle): 404 since #886
		'GET orgs/(?P<org>[-\\w]+)/sentinels/enroll': NOT_FOUND, 'POST orgs/(?P<org>[-\\w]+)/sentinels/enroll': NOT_FOUND,
		'GET sentinels/live': OWN, 'GET sentinels/enroll': ADMIN_ONLY, 'POST sentinels/enroll': ADMIN_ONLY,
		'GET tokens': SESSION_ONLY, 'POST tokens': SESSION_ONLY, 'DELETE tokens/(?P<token_id>\\d+)': SESSION_ONLY,
	})
	return t


REST_TABLE = _rest_table()
# the sentinel/ and agent/ loops are also called with the attacker's own Sentinel (or agent) token: another Sentinel's task is a 404 there too
SENTINEL_TOKEN_ROUTES = {k for k in REST_TABLE if re.match(r'^\w+ sentinel/tasks/\(', k) and REST_TABLE[k] == NOT_FOUND}

# MCP: what another organization's token gets from each tool
# value: 404 when the call names the victim (a project, an organization or a row id), 403 for an App Admin gate, OWN for a tool that only
# reads the caller's own rows or the shared catalogue (its answer is checked for the victim's text and compared in the count test).
MCP_TABLE = {
	'whoami': OWN, 'list_projects': OWN, 'get_system_status': OWN, 'list_engines': OWN, 'describe_states': OWN,
	'list_cves': OWN, 'get_cve': OWN, 'get_cve_detection': OWN, 'update_cve_detection': 403,
	'list_generated_templates': OWN, 'get_generated_template': OWN, 'review_generated_template': OWN,
	'set_generated_template_verdict': 403, 'update_generated_template': 403,
	'list_report_scopes': OWN, 'list_report_subscriptions': OWN,
	'list_settings': OWN,  # the fixed catalogue of setting names and what each is: no instance value (the bridge test below covers each setting)
	'get_setting': 403, 'change_setting': 403,  # 'ai' asked by an Org Admin
	'add_targets_by_org': OWN,  # as POST targets/bulk-org
	'generate_sentinel_enrollment': (403, 404),  # 404 for the victim's project, 403 for its organization (the admin gate, as the REST route)
	'register_agent': OWN, 'unregister_agent': OWN, 'agent_heartbeat': OWN, 'list_my_assignments': OWN, 'get_next_task': OWN,
	'list_agents': OWN, 'get_tuning_status': 403, 'list_tuning_decisions': 403, 'get_maintainer_report': 403, 'technology_coverage': 403,
	'set_tuning_mode': 403, 'apply_tuning_suggestion': 403, 'revert_tuning_decision': 403, 'release_tuning_pin': 403,
	'get_sentinel_defaults': OWN, 'set_sentinel_defaults': 403, 'get_sentinel_dispatch': OWN,
	'register_sentinel': OWN, 'unregister_sentinel': OWN, 'sentinel_heartbeat': OWN, 'get_next_sentinel_task': OWN,
	'list_sentinels': OWN,
	'register_assets': OWN, 'get_threat_digest': NOT_FOUND,
}
# every other tool names a project, an organization or a row: another organization's values are a 404
for _name, _d, _schema, _fn, _w in mcp.TOOLS:
	MCP_TABLE.setdefault(_name, NOT_FOUND)

# The web interface's JSON dispatchers
from cveFeed import account_api, admin_api, bounty_api, settings_api, welcome  # noqa: E402

# admin_api is open to Org Admins: each route on another organization's user, membership, organization or project is a 404, and a route that is
# for App Admins only answers 403 first.
ADMIN_API_TABLE = {f'{m} {p}': NOT_FOUND for m, p, _fn in admin_api.ROUTES if '(?P<' in p}
ADMIN_API_TABLE.update({
	'DELETE users/(?P<user_id>\\d+)': 403,  # only an App Admin deletes accounts
	'PUT users/(?P<user_id>\\d+)/bug-bounty': 403,  # only an App Admin grants bug bounty access
})
for _m, _p, _fn in admin_api.ROUTES:
	ADMIN_API_TABLE.setdefault(f'{_m} {_p}', OWN)
ADMIN_API_TABLE.update({
	'POST memberships': NOT_FOUND,  # a membership on the victim's organization, or for the victim's user
	'POST users': NOT_FOUND,  # a new account placed in the victim's organization
	'DELETE orgs/(?P<org_id>\\d+)': 403,  # only an App Admin deletes organizations
	'PUT timings': 403, 'POST scan-control': 403, 'POST watchdog': 403, 'PUT openvas': 403,  # instance settings: App Admin
	'GET timings': OWN, 'GET scan-control': OWN, 'GET watchdog': OWN, 'GET openvas': OWN, 'GET health': OWN,
})
# settings_api and welcome: App Admins only, every route
SUPERUSER_ONLY = {f'settings {m} {p}' for m, p, _fn in settings_api.ROUTES} | {f'welcome {m} {p}' for (m, p) in welcome.ROUTES}
# account_api acts on the signed-in person only; bounty_api on the person's own engagements and reports
ACCOUNT_TABLE = {f'{m} {p}': OWN for (m, p) in account_api.ROUTES}
BOUNTY_TABLE = {f'{m} {p}': (NOT_FOUND if '(?P<engagement_id>' in p or '(?P<report_id>' in p else OWN) for m, p, _fn in bounty_api.ROUTES}
# the web pages' own JSON views: each takes ?project= (or nothing) and answers for the caller's scope
VIEW_GETS = ('/cve/api/feed', '/cve/api/cves', '/cve/api/stats', '/cve/api/overview', '/cve/api/scanner', '/cve/api/graph', '/cve/api/graph-live',
             '/cve/api/activity', '/cve/api/discovery', '/cve/api/alive')


def _text(response):
	if response.streaming:
		return b''.join(response.streaming_content).decode('utf-8', 'replace')
	return response.content.decode('utf-8', 'replace')


def _where(one, two):
	"""The two texts around the first place they differ."""
	i = next((k for k, (x, y) in enumerate(zip(one, two)) if x != y), min(len(one), len(two)))
	return f'{one[max(0, i - 150):i + 250]!r}\n  vs  {two[max(0, i - 150):i + 250]!r}'


def _mask(text):
	"""An answer with its clocks, durations and generated secrets taken out, for a comparison of two calls made a moment apart."""
	text = re.sub(r'\d{4}-\d\d-\d\d[T ][\d:.]+(?:[+-]\d\d:\d\d|Z)?', 'T', text)
	text = re.sub(r'\d{4}-\d\d-\d\d', 'D', text)  # a date alone (a day that can turn over between two calls)
	text = re.sub(r'\b\d{1,2}:\d\d(?::\d\d)?\b', 'H', text)  # a clock time written for people
	text = re.sub(r'\b\d{1,2} (?:January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)\w*(?: \d{4})?', 'D', text)
	text = re.sub(r'\b(?:January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)\w* \d{1,2}(?:, \d{4})?', 'D', text)
	text = re.sub(r'"(\w*(?:_at|_ms|seconds|time|_age|elapsed|took|duration|etag|token|secret|since|age|uptime|load|memory|rss|cpu|disk|percent|ago)\w*)": [^,}\]]+', r'"\1": X', text)
	return text


class EveryRouteTenancyTests(TestCase):
	maxDiff = None

	@classmethod
	def setUpTestData(cls):
		os.environ['CVENGINE_SCALE_FIXTURE'] = '1'
		try:
			call_command('seed_scale_fixture', hosts=12, targets=3, tasks=20, secrets=3, history_scans=1, verbosity=0, stdout=io.StringIO())
		finally:
			os.environ.pop('CVENGINE_SCALE_FIXTURE', None)
		from scanEngine.models import EngineType
		EngineType.objects.filter(engine_name=V_SLUG).update(engine_name='shared-engine')  # engines are a shared list of labels, not a tenant's rows
		cls._victim()
		cls._attacker()
		from agentapi import agent_broker, sentinel_broker
		agent_broker.reap_expired()
		sentinel_broker.reap_expired()  # every broker call sweeps expired leases instance wide: done here, so the calls below start from a swept table

	@classmethod
	def _victim(cls):
		from agentapi.models import Agent, AgentTask, SentinelTask
		from cveFeed.models import (AuthCredential, BountyEngagement, BountyProgram, BountyReport, CVEMatch, FindingComment, HostInventory,
		                            HygieneFinding, InternalRange, SecretFinding, SupplierFinding, ExcludedAddress)
		from startScan.models import ScanHistory, Subdomain, Vulnerability
		from targetApp.models import Domain
		from tests.test_agentapi import call
		cls.vorg, cls.vproj = Org.objects.get(slug=V_SLUG), Project.objects.get(slug=V_SLUG)
		cls.victim = User.objects.create_user('victim-admin', 'victim@victim.example.org', 'x')
		OrgMembership.objects.create(user=cls.victim, org=cls.vorg, role='admin')
		UserProfile.objects.update_or_create(user=cls.victim, defaults={'bugbounty_enabled': True})
		cls.vtoken_row, cls.vtok = create_token(cls.victim, 'victim-full')
		v = {}
		v['target_id'] = Domain.objects.filter(project=cls.vproj).order_by('id').first().id
		v['scan_id'] = ScanHistory.objects.filter(domain__project=cls.vproj).order_by('id').first().id
		sub = Subdomain.objects.filter(target_domain__project=cls.vproj).order_by('id').first()
		v['host_id'], v['host'] = sub.id, sub.name
		match = CVEMatch.objects.filter(subdomain__target_domain__project=cls.vproj).order_by('id').first()
		v['match'] = match.id
		v['vulnerability'] = Vulnerability.objects.filter(target_domain__project=cls.vproj).order_by('id').first().id
		v['hygiene'] = HygieneFinding.objects.filter(domain__project=cls.vproj).order_by('id').first().id
		v['route'] = v['match']  # no route finding in the fixture: any id of the victim is as good
		v['secret_id'] = SecretFinding.objects.filter(project=cls.vproj).order_by('id').first().id
		v['sentinel_agent_id'] = Agent.objects.filter(name__startswith='scale-sentinel').order_by('id').first().id
		v['sentinel_task_id'] = SentinelTask._base_manager.filter(project=cls.vproj).order_by('id').first().id
		v['agent_task_id'] = AgentTask.objects.create(project=cls.vproj, match=match, kind='validate').id
		v['range_id'] = InternalRange.objects.create(project=cls.vproj, cidr='10.77.0.0/24', description='victim range').id
		v['credential_id'] = AuthCredential.objects.create(project=cls.vproj, domain_id=v['target_id'], label='victim sign-in').id
		v['inventory_id'] = HostInventory.objects.create(project=cls.vproj, key='h:victim-inventory.example.com', hostname='victim-inventory').id
		v['comment'] = FindingComment.objects.create(project=cls.vproj, finding_kind='match', finding_id=match.id, author=cls.victim, text='victim comment').id
		v['excluded_entry'] = ExcludedAddress.objects.create(org=cls.vorg, cidr='192.0.2.250/32', note='victim exclusion', created_by=cls.victim).id
		# rows the victim's admin creates through the API, so they are shaped as the service writes them
		made = {}
		for key, method, path, body in (
				('search_id', 'POST', f'/api/v1/projects/{V_SLUG}/saved-searches', {'name': 'victim search', 'query': 'port:443'}),
				('subscription_id', 'POST', '/api/v1/report-subscriptions', {'project': V_SLUG, 'name': 'victim email', 'recipients': ['victim@victim.example.org'],
				                                                             'cadence': 'weekly', 'weekday': 1, 'send_time': '09:00', 'timezone': 'UTC'}),
				('supplier_id', 'POST', f'/api/v1/projects/{V_SLUG}/suppliers', {'name': 'victim supplier', 'domains': ['victim-supplier.example.org'], 'tier': 'high'}),
				('token', 'POST', f'/api/v1/projects/{V_SLUG}/reports', {'format': 'csv'}),
				('org_token', 'POST', f'/api/v1/orgs/{V_SLUG}/reports', {'format': 'csv'}),
				('assessment_id', 'POST', f'/api/v1/projects/{V_SLUG}/host-assessments', {'host_id': v['host_id']}),
				('agent_id', 'PUT', '/api/v1/agent', {'name': 'victim-agent', 'kind': 'validation', 'scope': {'projects': [V_SLUG]}, 'capabilities': ['validate']}),
		):
			status, data = call(cls.vtok, method, path, body)
			assert status in (200, 201, 202), (key, status, data)
			made[key] = data['id'] if key not in ('agent_id',) else data.get('agent', data).get('id')
		v.update(made)
		v['supplier_finding'] = SupplierFinding.objects.create(supplier_id=v['supplier_id'], domain='victim-supplier.example.org', check_name='tls',
		                                                         title='victim supplier finding').id
		# after the API rows: an engagement puts the project under a program's scope, which refuses the assessment above
		program = BountyProgram.objects.create(platform='hackerone', handle='shared-program', name='shared program')  # the platforms' public catalogue
		v['program_id'] = program.id
		v['engagement_id'] = BountyEngagement.objects.create(project=cls.vproj, program=program).id
		v['report_id'] = BountyReport.objects.create(project=cls.vproj, platform='hackerone', title='victim bounty report').id
		from cveFeed.models import CVEEntry, GeneratedTemplate
		v['generated_id'] = GeneratedTemplate.objects.create(cve_entry=CVEEntry.objects.get(cve_id='CVE-2099-90001'), template_id='shared-x', yaml='id: shared-x').id
		v['token_id'] = cls.vtoken_row.id
		v['user_id'] = cls.victim.id
		v['membership_id'] = OrgMembership.objects.get(user=cls.victim, org=cls.vorg).id
		v['org_id'] = cls.vorg.id
		v['project_id'] = cls.vproj.id
		cls.v = v

	@classmethod
	def _attacker(cls):
		from agentapi.models import Agent
		from targetApp.models import Domain
		cls.aorg = Org.objects.create(name='Rival', slug=A_SLUG)
		cls.aproj = Project.objects.create(name='Rival', slug=A_SLUG, insert_date=timezone.now(), org=cls.aorg)
		Domain.objects.create(name='rival.test', project=cls.aproj, insert_date=timezone.now())
		cls.attacker = User.objects.create_user('rival-admin', 'admin@rival.test', 'x')
		OrgMembership.objects.create(user=cls.attacker, org=cls.aorg, role='admin')
		UserProfile.objects.update_or_create(user=cls.attacker, defaults={'bugbounty_enabled': True})
		cls.atok = create_token(cls.attacker, 'rival-full')[1]
		stoken, cls.astok = create_token(cls.attacker, 'rival-sentinel', scope='sentinel')
		Agent.objects.create(token=stoken, name='rival-sentinel', kind='scanner', status='active', last_seen=timezone.now(),
		                     capabilities=['nmap'], max_concurrent=1, scope={'projects': [A_SLUG]})

	# Helpers

	def _value(self, name, pattern=''):
		v = self.v
		if name in ('slug', 'org'):
			return V_SLUG
		if name == 'kind':
			return 'match'
		if name == 'finding_id':
			return v['supplier_finding'] if 'suppliers/findings' in pattern else v['match']
		if name == 'task_id':
			return v['sentinel_task_id'] if 'sentinel' in pattern else v['agent_task_id']
		if name == 'agent_id':
			return v['agent_id']
		if name == 'service':
			return 'shodan'
		if name == 'cve_id':
			return 'CVE-2099-90001'
		if name == 'token':
			return v['org_token'] if pattern.startswith('orgs/') else v['token']
		if name == 'match_id':
			return v['match']
		if name == 'request_id':
			return 1
		if name in ('decision_id', 'job_id'):
			return 1
		if name == 'ref':
			return 't1'
		return v[name]

	def _path(self, pattern, own_slug=False):
		def sub(m):
			name = m.group(1)
			if own_slug and name in ('slug', 'org'):
				return A_SLUG
			return str(self._value(name, pattern))
		return PATH_ARG.sub(sub, pattern)

	# per route: the fields that differ from the shared body (a value the shared body cannot hold for every route at once)
	BODY_FOR = {
		'POST projects/(?P<slug>[-\\w]+)/reports': {'kind': 'findings'}, 'POST orgs/(?P<org>[-\\w]+)/reports': {'kind': 'findings'},
		'PATCH projects/(?P<slug>[-\\w]+)/suppliers/findings/(?P<finding_id>\\d+)': {'status': 'accepted'},
		'POST projects/(?P<slug>[-\\w]+)/findings/(?P<kind>match|vulnerability|route|hygiene)/(?P<finding_id>\\d+)/heat': {'heat': 'fire'},
		'POST projects/(?P<slug>[-\\w]+)/findings/heat': {'heat': 'fire'},
	}
	# GETs whose scope is in the query string
	QUERY_FOR = {
		'GET reporting/digest-preview': (f'?project={V_SLUG}&format=json', f'?org={V_SLUG}&format=json'), 'GET reporting/threats': (f'?project={V_SLUG}', f'?org={V_SLUG}'),
		'GET report-subscriptions': (f'?project={V_SLUG}', f'?org={V_SLUG}'),
	}

	def _body(self, key=''):
		"""One body for every write: whatever a route reads from it names the victim (its project, its hosts, its rows), and each field is
		shaped so validation passes and the call reaches the lookup. The paste of targets names the victim's organization."""
		v = self.v
		body = {'value': 'new.rival.test', 'targets': ['new.rival.test'], 'text': '##Scale Fixture\n#zz-bulk\nx.rival.test',
		        'status': 'fixed', 'scope_mode': 'host', 'discovery_mode': 'standard', 'mode': 'standard', 'expect_private_ca': True,
		        'target_id': v['target_id'], 'host_id': v['host_id'], 'host': v['host'], 'hosts': [v['host']], 'ids': [v['target_id']],
		        'match_ids': [v['match']], 'items': [{'kind': 'match', 'id': v['match']}], 'kind': 'validate', 'heat': 'fire', 'reason': 'r',
		        'name': 'n', 'query': 'port:443', 'project': V_SLUG, 'to_project': V_SLUG, 'action': 'archive',
		        'recipients': ['a@rival.test'], 'cadence': 'weekly', 'weekday': 1, 'send_time': '09:00', 'timezone': 'UTC',
		        'domains': ['x.rival.test'], 'tier': 'high', 'cidr': '10.78.0.0/24', 'label': 'l', 'scope': 'target', 'expires': '30',
		        'headers': [{'name': 'X', 'secret': 'y'}], 'verdict': 'keep', 'yaml': 'id: x', 'body': 'b', 'assignee': None,
		        'enabled': True, 'pinned': True, 'profile': 'server', 'format': 'csv', 'cve': 'CVE-2099-90001', 'outcome': 'ok', 'result': {},
		        'secret': 'x', 'settings': {}, 'capabilities': ['validate'], 'max_concurrent': 1}
		body.update(self.BODY_FOR.get(key, {}))
		return body

	def _rest(self, token, method, path, body=None):
		from django.test import Client
		headers = {'HTTP_AUTHORIZATION': f'Bearer {token}'}
		fn = getattr(Client(), method.lower())
		if method == 'GET':
			response = fn(f'/api/v1/{path}', **headers)
		else:
			response = fn(f'/api/v1/{path}', json.dumps(body or {}), content_type='application/json', **headers)
		return response.status_code, _text(response)

	def _report(self, problems):
		self.assertFalse(problems, '\n' + '\n'.join(problems))

	def _leaks(self, text, sent=''):
		"""The victim's text in an answer, leaving out what the caller sent itself (a name it typed is echoed back, and that tells it nothing)."""
		return sorted(set(MARKERS.findall(text)) - set(MARKERS.findall(sent)))

	def _snapshot(self, victim):
		"""Every row of every table: (table, pk) -> (digest of its values, whether it is one of the victim's rows or points at one)."""
		rows = {}
		for model in apps.get_models(include_auto_created=True):
			fields = model._meta.concrete_fields
			own = victim.get(model, ())
			refs = [(i, victim[f.related_model]) for i, f in enumerate(fields) if f.is_relation and f.related_model in victim]
			for values in model._base_manager.order_by().values_list(*[f.attname for f in fields]):
				mine = values[0] in own or any(values[i] in keys for i, keys in refs)
				rows[(model._meta.db_table, values[0])] = (hashlib.sha1(repr(values).encode()).hexdigest(), mine)
		return rows

	# tables a refused call still writes: who asked, the guard's strikes, the MCP history, token and agent stamps, the session
	LOG_TABLES = {'dashboard_auditlog', 'cveFeed_mcpcall', 'dashboard_abusestrike', 'dashboard_apitoken', 'django_session', 'agentapi_agent'}

	def _victim_keys(self):
		"""The victim's own rows by model."""
		from agentapi.models import Agent
		from cveFeed.models import CVEMatch
		from dashboard.models import ApiToken
		from startScan.models import ScanHistory, Subdomain, Vulnerability
		from targetApp.models import Domain
		people = list(User.objects.filter(username__in=('victim-admin', 'scale-admin', 'scale-viewer')).values_list('pk', flat=True))
		return {Project: {self.vproj.pk}, Org: {self.vorg.pk}, User: set(people),
		        Domain: set(Domain._base_manager.filter(project=self.vproj).values_list('pk', flat=True)),
		        Subdomain: set(Subdomain._base_manager.filter(target_domain__project=self.vproj).values_list('pk', flat=True)),
		        ScanHistory: set(ScanHistory._base_manager.filter(domain__project=self.vproj).values_list('pk', flat=True)),
		        CVEMatch: set(CVEMatch._base_manager.filter(subdomain__target_domain__project=self.vproj).values_list('pk', flat=True)),
		        Vulnerability: set(Vulnerability._base_manager.filter(target_domain__project=self.vproj).values_list('pk', flat=True)),
		        Agent: set(Agent._base_manager.filter(token__user__in=people).values_list('pk', flat=True)),
		        ApiToken: set(ApiToken._base_manager.filter(user__in=people).values_list('pk', flat=True))}

	def _written_tables(self):
		from django.db import connection
		with connection.cursor() as cursor:
			cursor.execute('SELECT pg_stat_clear_snapshot()')
			cursor.execute('SELECT relname, n_tup_ins + n_tup_upd + n_tup_del FROM pg_stat_xact_user_tables')
			return dict(cursor.fetchall())

	def _guarded(self, label, call, problems):
		"""Make one call inside a savepoint that is rolled back afterwards (so a call on the attacker's own project leaves nothing for the next
		call to read), and when it wrote to any table but the log tables, check that none of the victim's rows changed and that no new row
		points at one."""
		from django.db import transaction
		if not hasattr(self, '_baseline'):
			self._victim = self._victim_keys()
			self._baseline = self._snapshot(self._victim)
		with transaction.atomic():
			before = self._written_tables()
			result = call()
			after = self._written_tables()
			wrote = sorted(t for t, n in after.items() if n != before.get(t, 0) and t not in self.LOG_TABLES)
			if wrote:
				now = self._snapshot(self._victim)
				touched = sorted({f'{t} #{pk}' for (t, pk), (h, mine) in self._baseline.items()
				                  if mine and t not in self.LOG_TABLES and now.get((t, pk), (None,))[0] != h})
				pointing = sorted({f'{t} #{pk}' for (t, pk), (h, mine) in now.items()
				                   if mine and (t, pk) not in self._baseline and t not in self.LOG_TABLES})
				if touched or pointing:
					problems.append(f'{label}: changed the other organization\'s rows {touched[:5]} or added rows pointing at them {pointing[:5]}')
			transaction.set_rollback(True)
		return result

	# Coverage

	def test_every_route_and_tool_has_a_line(self):
		"""A new route or tool must be added to the tables above: the cross-tenant expectation is a decision, not a default."""
		rest_keys = {f'{m} {p}' for m, p, _s, _f in rest.ROUTES}
		self.assertEqual(sorted(rest_keys - set(REST_TABLE)), [])
		self.assertEqual(sorted(set(REST_TABLE) - rest_keys), [], 'a line for a route that no longer exists')
		self.assertEqual(sorted({n for n, *_ in mcp.TOOLS} ^ set(MCP_TABLE)), [])
		self.assertEqual(sorted({f'{m} {p}' for m, p, _f in admin_api.ROUTES} ^ set(ADMIN_API_TABLE)), [])
		self.assertEqual(sorted({f'{m} {p}' for m, p, _f in bounty_api.ROUTES} ^ set(BOUNTY_TABLE)), [])

	# REST

	def test_rest_routes_refuse_another_organizations_rows(self):
		problems = []
		for method, pattern, _s, _f in rest.ROUTES:
			key = f'{method} {pattern}'
			want = REST_TABLE[key]
			names = set(re.findall(r'\(\?P<(\w+)>', pattern))
			body = self._body(key)
			calls = [(self.atok, self._path(pattern) + q, want, body) for q in self.QUERY_FOR.get(key, ('',))]
			if method != 'GET' and not names & {'slug', 'org'}:
				calls.append((self.atok, self._path(pattern), want, {**body, 'project': None, 'org': V_SLUG}))  # the organization, not the project
			if names & {'slug', 'org'} and names - {'slug', 'org', 'kind', 'service'}:
				calls.append((self.atok, self._path(pattern, own_slug=True), OWN, body))  # the attacker's own project, the victim's row ids
			if key in SENTINEL_TOKEN_ROUTES:
				calls.append((self.astok, self._path(pattern), want, body))  # the attacker's own Sentinel, the victim's task
			for token, path, expect, sent in calls:
				cache.clear()
				status, text = self._guarded(f'{method} {path}', lambda: self._rest(token, method, path, sent), problems)
				leaks = self._leaks(text, json.dumps(sent) + path if expect in (OWN, CATALOGUE_ROUTE) else '')
				ok = (status != 500 and not leaks) if expect in (OWN, CATALOGUE_ROUTE) else (status == expect and not leaks)
				if not ok:
					problems.append(f'{method} {path}: {status} (want {expect}) {leaks} {text[:160]}')
		self._report(problems)

	# MCP

	def _tool_runs(self, name, schema, own_slug=False):
		"""The argument sets to call ``name`` with: every argument that names a project, an organization or a row gets the victim's value
		(the project is the attacker's own with ``own_slug``), the other required ones a valid value. A tool that takes a project or an
		organization is called once with each."""
		v = self.v
		props = schema.get('properties', {})
		by_name = {
			'project': A_SLUG if own_slug else V_SLUG, 'org': V_SLUG, 'current_project': V_SLUG, 'to_project': V_SLUG,
			'target_id': v['target_id'], 'host_id': v['host_id'], 'scan_id': v['scan_id'], 'match_id': v['match'], 'host': v['host'],
			'hosts': [v['host']], 'ids': [v['target_id']], 'match_ids': [v['match']], 'items': [{'kind': 'match', 'id': v['match']}],
			'kind': 'match', 'id': v['match'], 'assessment_id': v['assessment_id'], 'credential_id': v['credential_id'],
			'task_id': v['sentinel_task_id'] if 'sentinel' in name else v['agent_task_id'],
			'agent_id': v['sentinel_agent_id'] if 'sentinel' in name else v['agent_id'],
			'supplier': v['supplier_id'], 'finding': v['supplier_finding'], 'report_id': v['token'], 'request_id': 1,
			'text': '##Scale Fixture\n#zz-bulk\nx.rival.test', 'heat': 'fire', 'self_update': 'automatic',
		}
		if 'saved_search' in name:
			by_name['id'] = v['search_id']
		if 'report_subscription' in name or name == 'list_report_deliveries':
			by_name['id'] = v['subscription_id']
		if 'secret' in name and 'sentinel' not in name:
			by_name['id'] = v['secret_id']
		if name == 'get_host_inventory':
			by_name['id'] = v['inventory_id']
		if name in ('get_agent', 'update_agent', 'delete_agent'):
			by_name['id'] = v['agent_id']
		if name in ('get_sentinel', 'suspend_sentinel', 'revoke_sentinel'):
			by_name['id'] = by_name['agent_id'] = v['sentinel_agent_id']
		if name in ('remove_supplier', 'get_supplier_message'):
			by_name['id'] = by_name['supplier'] = v['supplier_id']
		if name == 'set_supplier_finding_status':
			by_name['id'] = v['supplier_finding']
		if 'generated_template' in name:
			by_name['id'] = v['generated_id']
		if name in ('get_setting', 'change_setting'):
			by_name['name'] = 'ai'
		args = {}
		for key, spec in props.items():
			if key not in by_name:
				continue
			value = by_name[key]
			if spec.get('enum') and value not in spec['enum']:
				value = spec['enum'][0]
			wanted = spec.get('type')
			wanted = [wanted] if isinstance(wanted, str) else (wanted or [])
			if wanted and 'string' in wanted and 'integer' not in wanted and isinstance(value, int):
				value = str(value)
			args[key] = value
		if 'items' in args and 'id' in args:
			args.pop('items')  # one finding or many, never both
		for key in schema.get('required', []):
			if key in args:
				continue
			spec = props.get(key, {})
			if spec.get('enum'):
				args[key] = spec['enum'][0]
				continue
			wanted = spec.get('type')
			wanted = wanted[0] if isinstance(wanted, list) else wanted
			args[key] = {'string': 'x', 'integer': 1, 'number': 1, 'boolean': False, 'array': [], 'object': {}}.get(wanted, 'x')
		if 'project' in args and 'org' in args:
			return [{k: a for k, a in args.items() if k != 'org'}, {k: a for k, a in args.items() if k != 'project'} | {'org': V_SLUG}]
		return [args]

	def _mcp(self, token, name, args):
		from tests.test_agentapi import rpc
		seen = {}
		real = mcp.call_tool

		def recording(ctx, tool, arguments):
			try:
				return real(ctx, tool, arguments)
			except ApiError as exc:
				seen['status'] = exc.status
				raise
		with mock.patch.object(mcp, 'call_tool', recording):
			status, data = rpc(token, 'tools/call', {'name': name, 'arguments': args})
		text = json.dumps(data, default=str)
		if 'error' in (data or {}):
			return 500, text
		return seen.get('status', 200), text

	def test_mcp_tools_refuse_another_organizations_rows(self):
		problems = []
		for name, _d, schema, _fn, _w in mcp.TOOLS:
			want = MCP_TABLE[name]
			runs = [(args, want) for args in self._tool_runs(name, schema)]
			if 'project' in schema.get('properties', {}) and want in (NOT_FOUND, (403, 404)):
				runs += [(args, OWN) for args in self._tool_runs(name, schema, own_slug=True) if args.get('project') == A_SLUG]
			for args, expect in runs:
				cache.clear()
				status, text = self._guarded(name, lambda: self._mcp(self.atok, name, args), problems)
				leaks = self._leaks(text, json.dumps(args) if expect == OWN else '')
				ok = (status != 500 and not leaks) if expect == OWN else (status in (expect if isinstance(expect, tuple) else (expect,)) and not leaks)
				if not ok:
					problems.append(f'{name} {json.dumps(args)[:140]}: {status} (want {expect}) {leaks} {text[:200]}')
		self._report(problems)

	# The web interface's dispatchers

	def _admin_value(self, name):
		v = self.v
		return {'user_id': v['user_id'], 'membership_id': v['membership_id'], 'org_id': v['org_id'], 'project_id': v['project_id'],
		        'entry_id': v['excluded_entry'], 'service': 'shodan', 'scope': 'org', 'engagement_id': v['engagement_id'],
		        'report_id': v['report_id'], 'program_id': v['program_id'], 'platform': 'hackerone', 'alert_id': 1, 'decision_id': 1,
		        'which': 'seed'}[name]

	def test_web_dispatchers_refuse_another_organizations_rows(self):
		client = client_for(self.attacker)
		v = self.v
		body = json.dumps({'user_id': v['user_id'], 'username': 'new-person', 'scope': 'org', 'scope_id': v['org_id'], 'role': 'admin',
		                   'email': 'new@rival.test', 'first_name': 'x', 'is_active': False, 'enabled': True, 'name': 'n', 'cidr': '192.0.2.251',
		                   'project': V_SLUG, 'program_id': v['program_id'], 'engagement_id': v['engagement_id'], 'title': 't', 'send_invite': False})
		problems = []

		def run(prefix, table, routes):
			for method, pattern in routes:
				key = f'{method} {pattern}'
				want = table[key]
				path = PATH_ARG.sub(lambda m: str(self._admin_value(m.group(1))), pattern)
				if prefix.endswith('bounty/'):
					path += f'?project={V_SLUG}'
				cache.clear()
				fn = getattr(client, method.lower())
				url = f'{prefix}{path}'
				r = self._guarded(f'{method} {url}', lambda: fn(url, body, content_type='application/json') if method != 'GET' else fn(url), problems)
				text = _text(r)
				leaks = self._leaks(text, body if want == OWN else '')
				ok = (r.status_code != 500 and not leaks) if want == OWN else (r.status_code == want and not leaks)
				if not ok:
					problems.append(f'{method} {prefix}{path}: {r.status_code} (want {want}) {leaks} {text[:160]}')

		run('/cve/api/admin/', ADMIN_API_TABLE, [(m, p) for m, p, _f in admin_api.ROUTES])
		run('/cve/api/bounty/', BOUNTY_TABLE, [(m, p) for m, p, _f in bounty_api.ROUTES])
		run('/cve/api/account/', ACCOUNT_TABLE, list(account_api.ROUTES))
		for method, pattern, _f in settings_api.ROUTES:
			path = PATH_ARG.sub(lambda m: str(self._admin_value(m.group(1))), pattern)
			url = f'/cve/api/settings/{path}'
			r = self._guarded(url, lambda: client.get(url) if method == 'GET' else getattr(client, method.lower())(url, '{}', content_type='application/json'), problems)
			if r.status_code != 403:
				problems.append(f'{method} settings/{path}: {r.status_code}, an Org Admin must get 403')
		for method, pattern in welcome.ROUTES:
			url = f'/cve/api/welcome/{pattern}'
			r = self._guarded(url, lambda: client.get(url) if method == 'GET' else getattr(client, method.lower())(url, '{}', content_type='application/json'), problems)
			if r.status_code != 403:
				problems.append(f'{method} welcome/{pattern}: {r.status_code}, an Org Admin must get 403')
		for path in VIEW_GETS:
			for query in (f'?project={V_SLUG}', f'?org={V_SLUG}', ''):
				cache.clear()
				r = client.get(f'{path}{query}')
				text = _text(r)
				if r.status_code == 500 or self._leaks(text):
					problems.append(f'GET {path}{query}: {r.status_code} {self._leaks(text)} {text[:160]}')
		r = client.get(f'/cve/{A_SLUG}/scans/{v["scan_id"]}/')  # the scan page is a shell the script fills from /api/v1: nothing of the scan is in it
		if r.status_code == 500 or self._leaks(_text(r)):
			problems.append(f'GET own scan page with the victim scan id: {r.status_code} {self._leaks(_text(r))}')
		for page in (f'/cve/{V_SLUG}/hosts/', f'/cve/{V_SLUG}/scans/{v["scan_id"]}/', f'/cve/{V_SLUG}/hosts/{v["host_id"]}/screenshot/',
		             f'/cve/{A_SLUG}/hosts/{v["host_id"]}/screenshot/',
		             f'/cve/api/node?id=sub:{v["host_id"]}', f'/cve/api/node?id=dom:{v["target_id"]}', f'/scan/export/subdomains/{v["scan_id"]}',
		             f'/scan/export/endpoints/{v["scan_id"]}', f'/scan/export/urls/{v["scan_id"]}', f'/scan/create_report/{v["scan_id"]}'):
			r = client.get(page)
			text = _text(r)
			if r.status_code not in (302, 403, 404) or self._leaks(text):
				problems.append(f'GET {page}: {r.status_code} {self._leaks(text)} {text[:120]}')
		self._report(problems)

	def test_settings_bridge_refuses_another_organizations_rows(self):
		"""get_setting and change_setting run the web interface's handlers directly (agentapi.settings_bridge): each entry, named with the victim's
		ids, answers 403 (an App Admin setting) or 404 (another organization's row), and an entry with no id answers for the caller alone."""
		from agentapi import settings_bridge
		v = self.v
		ids = {'org_id': v['org_id'], 'project_id': v['project_id'], 'entry_id': v['excluded_entry'], 'service': 'shodan', 'alert_id': 1}
		problems = []
		for name, (api, pattern, _what, ident_names) in settings_bridge.ENTRIES.items():
			ident = '/'.join(str(ids[n]) for n in re.findall(r'\(\?P<(\w+)>', pattern)) or None
			for tool, args in (('get_setting', {'name': name}), ('change_setting', {'name': name, 'values': {'enabled': False, 'cidr': '192.0.2.252'}}),
			                   ('change_setting', {'name': name, 'remove': True})):
				if ident:
					args['id'] = ident
				status, text = self._guarded(f'{tool} {name}', lambda: self._mcp(self.atok, tool, args), problems)
				if api == 'settings':
					want = (403, 405)  # an App Admin setting (405: an entry that cannot be changed at all)
				elif ident:
					want = (403, 404, 405)  # another organization's row; 403 where an agent may never do this (store a key, lift an exclusion)
				else:
					want = None  # the caller's own scope: any answer but a crash
				leaks = self._leaks(text)
				if status == 500 or leaks or (want and status not in want):
					problems.append(f'{tool} {name} {ident}: {status} (want {want}) {leaks} {text[:160]}')
		self._report(problems)

	# Lists and counts

	def _reads(self):
		"""Every read the attacker can make about itself: REST GETs on its own project and on _all, the GETs that name no project, MCP read
		tools on its own project and on _all, the pages' JSON, the admin and bug bounty lists. Each is (label, the victim's same call, the
		attacker's call)."""
		reads = []
		for method, pattern, _s, _f in rest.ROUTES:
			if method != 'GET' or REST_TABLE[f'{method} {pattern}'] in (MACHINE, ADMIN_ONLY, SESSION_ONLY, 403):
				continue
			names = set(re.findall(r'\(\?P<(\w+)>', pattern))
			if names - {'slug', 'org', 'kind'}:
				continue  # one row's page: the cross-tenant test covers it
			for slug in ((A_SLUG, '_all') if 'slug' in names else (A_SLUG,) if 'org' in names else (None,)):
				path = PATH_ARG.sub(lambda m: {'kind': 'match'}.get(m.group(1), slug), pattern)
				vpath = PATH_ARG.sub(lambda m: {'kind': 'match'}.get(m.group(1), V_SLUG if slug == A_SLUG else slug), pattern)
				for query in ((f'?project={A_SLUG}&format=json', f'?org={A_SLUG}&format=json') if f'{method} {pattern}' in self.QUERY_FOR else ('',)):
					vquery = query.replace(A_SLUG, V_SLUG)
					reads.append((f'REST {path}{query}', lambda p=vpath + vquery: self._rest(self.vtok, 'GET', p),
					              lambda p=path + query: self._rest(self.atok, 'GET', p)))
		for name, _d, schema, _fn, writes in mcp.TOOLS:
			if writes or MCP_TABLE[name] == 403 or name in ('export_report', 'generate_sentinel_enrollment', 'get_next_task', 'get_next_sentinel_task'):
				continue
			required = set(schema.get('required', []))
			if required - {'project'}:
				continue
			for slug in ((A_SLUG, '_all') if 'project' in schema.get('properties', {}) else (None,)):
				args = {'project': slug} if slug else {}
				vargs = {'project': V_SLUG if slug == A_SLUG else slug} if slug else {}
				reads.append((f'MCP {name} {slug}', lambda n=name, a=vargs: self._mcp(self.vtok, n, a), lambda n=name, a=args: self._mcp(self.atok, n, a)))
		aclient, vclient = client_for(self.attacker), client_for(self.victim)

		def page(c, path):
			r = c.get(path)
			return r.status_code, _text(r)
		for path in VIEW_GETS:
			for query in ('', f'?project={A_SLUG}', '?project=_all'):
				vquery = query.replace(A_SLUG, V_SLUG)
				reads.append((f'VIEW {path}{query}', lambda p=path + vquery: page(vclient, p), lambda p=path + query: page(aclient, p)))
		for m, p, _f in admin_api.ROUTES:
			if m == 'GET' and '(?P<' not in p:
				reads.append((f'ADMIN {p}', lambda p=p: page(vclient, f'/cve/api/admin/{p}'), lambda p=p: page(aclient, f'/cve/api/admin/{p}')))
		for m, p, _f in bounty_api.ROUTES:
			if m == 'GET' and '(?P<' not in p:
				reads.append((f'BOUNTY {p}', lambda p=p: page(vclient, f'/cve/api/bounty/{p}?project={V_SLUG}'),
				              lambda p=p: page(aclient, f'/cve/api/bounty/{p}')))
		return reads

	def test_lists_and_counts_are_the_same_with_or_without_the_other_organization(self):
		"""Pass A: the victim's caller makes each read first (filling every cache), then the attacker. Passes B1 and B2: the attacker alone on an
		empty cache, twice. Then the victim's organization is deleted and pass C runs. A read that answers the same in B1 and B2 must answer
		the same in A (no cache shared with another scope) and in C (no row or count of the other organization)."""
		reads = self._reads()
		self.assertGreater(len(reads), 150)
		problems = []
		for _label, _victim_call, attacker_call in reads:
			attacker_call()  # once first, so a read that creates something on first use (a default row) has done so before the passes
		cache.clear()
		a = {}
		for label, victim_call, attacker_call in reads:
			victim_call()
			status, text = attacker_call()
			if status == 500 or self._leaks(text):
				problems.append(f'{label}: {status} {self._leaks(text)} {text[:160]}')
			a[label] = (status, _mask(text))

		def alone():
			out = {}
			for label, _victim_call, attacker_call in reads:
				cache.clear()
				status, text = attacker_call()
				out[label] = (status, _mask(text))
			return out
		b1, b2 = alone(), alone()
		stable = [label for label, *_ in reads if b1[label] == b2[label]]
		self.assertGreater(len(stable), 120)
		from agentapi.models import Agent
		from dashboard.models import ApiToken
		people = User.objects.filter(username__in=('victim-admin', 'scale-admin', 'scale-viewer'))
		Agent.objects.filter(token__user__in=people).delete()
		ApiToken.objects.filter(user__in=people).delete()
		Project.objects.filter(org=self.vorg).delete()
		self.vorg.delete()
		people.delete()
		c = alone()
		for label in stable:
			if a[label] != b2[label]:
				problems.append(f'{label}: differs after the other organization\'s caller filled the cache\n  {_where(a[label][1], b2[label][1])}')
			if c[label] != b2[label]:
				problems.append(f'{label}: differs once the other organization is gone\n  {_where(b2[label][1], c[label][1])}')
		self._report(problems)
