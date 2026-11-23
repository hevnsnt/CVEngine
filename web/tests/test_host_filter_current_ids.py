"""The ``host`` filter of the CVE match list, the Findings list and agent work queueing reads the current hosts it names first
(``services._current_named_ids``) and hands their ids to the match query, instead of putting the name filter and the current-inventory rule
(``correlation.latest_scan_q``) in one statement. In one statement the name filter made the planner expect a row or two, and it rebuilt the rule's
window over every finished scan once per match row (26 to 59 s for one host on the live install). The answers must be exactly the ones the single
statement gave: the same rows, order, counts, pages and facets. Each test runs the route twice, once as it is and once with ``_current_named_ids``
returning None, which is the single statement it replaced, and compares the whole answers."""
from unittest import mock

from django.contrib.auth.models import User
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import agent_broker
from agentapi import services as svc
from agentapi.auth import create_token
from cveFeed import discovery
from cveFeed.correlation import latest_scan_q
from cveFeed.models import CVEEntry, CVEMatch, HygieneFinding, Triage
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain

NOW = timezone.now()
HP = [discovery.HOST_PIPELINE_TASK]
# substrings of host names: one host, several, a whole domain, every host, a case change, a scanless host, an old copy only, and none
HOSTS = ['www.acme.example', 'WWW.ACME', 'acme.example', 'beta', '.', 'ct.acme', 'old.acme', 'new.acme', 'example', 'nothing-here']
OLD = 'agentapi.services._current_named_ids'


class HostFilterCurrentIdsTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		org = Org.objects.create(name='Hostfilter', slug='hostfilter')
		cls.p = Project.objects.create(name='HF', slug='hf-a', insert_date=NOW, org=org)
		cls.q = Project.objects.create(name='HF other', slug='hf-b', insert_date=NOW, org=org)
		engine = EngineType.objects.create(engine_name='hf', yaml_configuration='x', default_engine=True)
		cls.acme = Domain.objects.create(name='acme.example', project=cls.p, insert_date=NOW)
		cls.beta = Domain.objects.create(name='beta.example', project=cls.p, insert_date=NOW)
		other = Domain.objects.create(name='acme-other.example', project=cls.q, insert_date=NOW)

		def scan(domain, names, tasks=None, status=2):
			row = ScanHistory.objects.create(domain=domain, scan_type=engine, scan_status=status, start_scan_date=NOW, tasks=tasks)
			return [Subdomain.objects.create(name=n, target_domain=domain, scan_history=row) for n in names]

		# acme: an older full scan (every copy superseded), the latest full scan, a host-pipeline rescan after it (www's newest copy and a new host),
		# a failed scan (never current) and a scanless row (certificate transparency)
		old = scan(cls.acme, ['www.acme.example', 'api.acme.example', 'old.acme.example'])
		latest = scan(cls.acme, ['www.acme.example', 'api.acme.example'])
		rescan = scan(cls.acme, ['www.acme.example', 'new.acme.example'], tasks=HP)
		failed = scan(cls.acme, ['www.acme.example'], status=3)
		ct = Subdomain.objects.create(name='ct.acme.example', target_domain=cls.acme)
		# beta: no full scan ever, two host-pipeline scans of the same host (the newest scanned copy is current) and one of another
		beta1 = scan(cls.beta, ['www.beta.example'], tasks=HP)
		beta2 = scan(cls.beta, ['www.beta.example', 'mail.beta.example'], tasks=HP)
		# another project with a name that contains the same words: never in this project's lists
		theirs = scan(other, ['www.acme.example'])
		subs = old + latest + rescan + failed + [ct] + beta1 + beta2 + theirs

		kev = CVEEntry.objects.create(cve_id='CVE-2099-8101', kev=True, cvss=9.8, title='t', published_at=NOW)
		exploit = CVEEntry.objects.create(cve_id='CVE-2099-8102', exploit_db=True, cvss=7.5, title='t', published_at=NOW)
		mild = CVEEntry.objects.create(cve_id='CVE-2099-8103', cvss=5.0, title='t', published_at=NOW)
		high = CVEEntry.objects.create(cve_id='CVE-2099-8104', cvss=8.1, title='t', published_at=NOW)
		cls.matches = []
		for i, sub in enumerate(subs):
			made = [
				# fire: a hot CVE with a template hit (hard evidence)
				CVEMatch.objects.create(cve_entry=kev, subdomain=sub, matched_product='nginx', matched_version='1.18.0', template_result='vulnerable',
										confidence=0.9 - i * 0.01),
				# smoke: a hot CVE on a version alone
				CVEMatch.objects.create(cve_entry=exploit, subdomain=sub, matched_product='openssl', matched_version='1.1.1', confidence=0.7),
				# ice: not hot, and one ruled out by the AI (actionable leaves it out, status=all keeps it)
				CVEMatch.objects.create(cve_entry=mild, subdomain=sub, matched_product='php', matched_version='8.0.1', confidence=0.5),
				CVEMatch.objects.create(cve_entry=high, subdomain=sub, matched_product='php', matched_version='8.0.1', confidence=0.5,
										ai_verdict='not_affected'),
				# a closed one, for status=closed and fixed
				CVEMatch.objects.create(cve_entry=high, subdomain=sub, matched_product='apache', matched_version='2.4.1', confidence=0.4,
										remediation_status='fixed'),
			]
			cls.matches += made
			Vulnerability.objects.create(name=f'Exposed panel {i}', severity=3, subdomain=sub, target_domain=sub.target_domain,
										 open_status=True, discovered_date=NOW, http_url=f'https://{sub.name}/')
		# a heat a person set wins: an ice match set to fire, a fire match set to ice
		for match, heat in ((cls.matches[2], 'fire'), (cls.matches[5], 'ice')):
			Triage.objects.create(project=cls.p, domain=match.subdomain.target_domain, host=match.subdomain.name, kind='match', match=match,
								  heat_override=heat, heat_override_reason='set in a test')
		HygieneFinding.objects.create(domain=cls.acme, host='www.acme.example', check_name='dmarc_none', severity=2, title='DMARC none', status='open')
		cls.root = User.objects.create_superuser('hf-root', 'r@x.io', 'x')
		cls.alice = User.objects.create_user('hf-alice', password='x')
		ProjectMembership.objects.create(user=cls.alice, project=cls.p, role='user')
		_, cls.token = create_token(cls.alice, 'hf')
		_, cls.root_token = create_token(cls.root, 'hf-root')

	def setUp(self):
		from django.core.cache import cache
		cache.clear()  # the Findings list's shared counts and snapshots: each answer is built here, never read from an earlier test

	ROUTES = {'matches': svc.list_matches, 'findings': svc.list_findings}

	def get(self, route, slug='hf-a', user=None, **params):
		"""One answer of the route, called as the REST and MCP handlers call it (the services layer, with the query parameters as strings)."""
		from agentapi.services import Ctx
		user = user or self.alice
		ctx = Ctx(user=user, token=user.api_tokens.get(name='hf-root' if user == self.root else 'hf'))
		return self.ROUTES[route](ctx, slug, {k: str(v) for k, v in params.items()})

	def both(self, route, slug='hf-a', user=None, **params):
		"""The answer as it is now and the answer of the single statement it replaced."""
		from django.core.cache import cache
		cache.clear()
		new = self.get(route, slug, user, **params)
		cache.clear()
		with mock.patch(OLD, return_value=None):
			old = self.get(route, slug, user, **params)
		return new, old

	def test_the_fixture_has_current_and_superseded_copies_and_every_heat(self):
		# the rule has work to do: a host filter that ignored it would list superseded copies, and every heat is present
		current = set(Subdomain.objects.filter(latest_scan_q(), target_domain__project=self.p).values_list('name', 'scan_history_id'))
		stored = set(Subdomain.objects.filter(target_domain__project=self.p).values_list('name', 'scan_history_id'))
		self.assertLess(len(current), len(stored))
		self.assertIn('old.acme.example', {n for n, _ in stored})
		self.assertNotIn('old.acme.example', {n for n, _ in current})
		heats = {r['heat'] for r in self.get('findings', status='all', page_size=200, type='cve')['results']}
		self.assertEqual(heats, {'fire', 'smoke', 'ice'})

	def test_current_named_ids_are_the_current_rows_with_the_name(self):
		for host in HOSTS:
			for project in (self.p, svc.AllProjects([self.p.pk, self.q.pk])):
				expected = sorted(svc._scoped(Subdomain.objects.all(), project, 'target_domain__project').filter(latest_scan_q())
								  .filter(name__icontains=host).values_list('pk', flat=True))
				self.assertEqual(sorted(svc._current_named_ids(project, host)), expected, host)
		self.assertEqual(svc._current_named_ids(self.p, 'nothing-here'), [])

	def test_match_list_answers_are_identical(self):
		for host in HOSTS:
			for params in ({}, {'status': 'open'}, {'status': 'closed'}, {'verdict': 'active'}, {'kev': '1'}, {'cve': 'CVE-2099-8102'}):
				for page in (1, 2, 3):
					new, old = self.both('matches', host=host, page=page, page_size=4, **params)
					self.assertEqual(new, old, (host, params, page))
		self.assertGreater(self.get('matches', host='www.acme')['count'], 0)
		# the old copy of a host is never listed, whichever filter finds it
		self.assertEqual(self.get('matches', host='old.acme')['count'], 0)

	def test_match_list_in_the_all_projects_view_is_identical(self):
		for host in ('www.acme', 'acme', 'nothing-here'):
			new, old = self.both('matches', '_all', self.root, host=host, page_size=50)
			self.assertEqual(new, old, host)
		projects = {r.get('project') for r in self.get('matches', '_all', self.root, host='www.acme', page_size=50)['results']}
		self.assertEqual(projects, {'hf-a', 'hf-b'})

	def test_findings_answers_are_identical(self):
		facets = ({}, {'status': 'all'}, {'status': 'closed'}, {'status': 'fixed'}, {'heat': 'fire'}, {'heat': 'smoke'}, {'heat': 'ice'},
				  {'severity': 'critical'}, {'type': 'cve'}, {'type': 'cve', 'status': 'all', 'heat': 'ice'}, {'kev': '1'}, {'group': 'cve'},
				  {'group': 'cve', 'status': 'all'}, {'page_size': 0})
		for host in HOSTS:
			for params in facets:
				for page in (1, 2):
					args = {'page': page, 'page_size': 5, **params}
					new, old = self.both('findings', host=host, **args)
					self.assertEqual(new, old, (host, params, page))

	def test_findings_in_the_all_projects_view_are_identical(self):
		for host in ('www.acme', 'example'):
			for params in ({}, {'group': 'cve'}, {'status': 'all', 'page_size': 100}):
				new, old = self.both('findings', '_all', self.root, host=host, **params)
				self.assertEqual(new, old, (host, params))

	def test_counts_match_the_rows_a_host_has(self):
		body = self.get('findings', host='www.acme.example', status='all', type='cve', page_size=200)
		current = Subdomain.objects.filter(latest_scan_q(), target_domain=self.acme, name='www.acme.example')
		self.assertEqual(body['counts']['cve'], CVEMatch.objects.filter(subdomain__in=current).count())
		self.assertEqual({r['host'] for r in body['results']}, {'www.acme.example'})

	def test_agent_work_queued_by_host_picks_the_same_matches(self):
		from agentapi.services import Ctx
		ctx = Ctx(user=self.alice, token=self.alice.api_tokens.get(name='hf'))
		for host in HOSTS:
			for kind in ('validate', 'remediate'):
				seen = {}
				for label, patch in (('new', mock.patch(OLD, wraps=svc._current_named_ids)), ('old', mock.patch(OLD, return_value=None))):
					picked = []
					with patch, mock.patch.object(agent_broker, '_limit_user'), mock.patch.object(agent_broker, '_queue_one', side_effect=lambda c, p, m, *a: picked.append(m.pk) or 'held in a test'):
						agent_broker.queue_work(ctx, 'hf-a', kind, host=host)
					seen[label] = picked
				self.assertEqual(seen['new'], seen['old'], (host, kind))

	def test_the_match_statements_no_longer_carry_the_current_scans_rule(self):
		# the rule runs once, over the named hosts (one statement on the host table); the match statements filter by their ids
		with CaptureQueriesContext(connection) as ctx:
			body = self.get('matches', host='www.acme')
		self.assertGreater(body['count'], 0)
		match_sql = [q['sql'] for q in ctx.captured_queries if q['sql'].lstrip().upper().startswith('SELECT') and 'FROM "cveFeed_cvematch"' in q['sql']]
		self.assertTrue(match_sql)
		for sql in match_sql:
			self.assertNotIn('OVER (PARTITION BY', sql)
			self.assertIn('"cveFeed_cvematch"."subdomain_id" = ANY(', sql)
		rule = [q['sql'] for q in ctx.captured_queries if 'OVER (PARTITION BY' in q['sql']]
		self.assertEqual(len(rule), 1)
		self.assertIn('FROM "startScan_subdomain"', rule[0])

	def test_current_ids_are_one_array_parameter(self):
		# the inventory counts pass every current host id: one array parameter, not one placeholder per id
		ids = list(Subdomain.objects.values_list('pk', flat=True))
		sql, params = svc._matches_qs(self.p, ids, counting=True).values('pk').query.sql_with_params()
		self.assertIn('"cveFeed_cvematch"."subdomain_id" = ANY(', sql)
		self.assertIn(sorted(ids), [sorted(p) for p in params if isinstance(p, list)])
		self.assertEqual(svc._matches_qs(self.p, [], counting=True).count(), 0)
