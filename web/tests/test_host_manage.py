import os
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi import host_manage as hm
from agentapi import services as svc
from agentapi.auth import create_token
from agentapi.services import ApiError, Ctx
from cveFeed import ctmonitor, discovery, fullscan, route_auth as ra, tasks
from cveFeed.exclusions import drop_excluded, excluded_names, is_excluded, normalize
from cveFeed.models import (AssetChange, CVEEntry, CVEMatch, HostExclusion, HostLabel, HostProfile, HostState, RouteAuth,
	ServiceRun)
from cveFeed.nuclei_scan import scan_targets
from dashboard.models import AuditLog, Org, OrgMembership, Project, ProjectMembership
from reNgine import bbot as bbot_lib, resources
from reNgine.tasks import persist_bbot_result, save_subdomain
from scanEngine.models import EngineType
from startScan.models import EndPoint, IpAddress, Port, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from targetApp.target_types import scannable_hosts
from tests.test_agentapi import call, rpc
from tests.test_perf_hostpipeline import _stages

HOST = 'provider.example'
LOOKALIKES = ['notprovider.example', 'www.provider.example', 'provider.example.evil.net', 'xprovider.example']


class Base(TestCase):
	"""Org A with two projects (a1, a2), org B with one (b1); users at every level."""

	def setUp(self):
		now = timezone.now()
		self.org_a, self.org_b = Org.objects.create(name='A', slug='oa'), Org.objects.create(name='B', slug='ob')
		self.a1 = Project.objects.create(name='A1', slug='a1', insert_date=now, org=self.org_a)
		self.a2 = Project.objects.create(name='A2', slug='a2', insert_date=now, org=self.org_a)
		self.b1 = Project.objects.create(name='B1', slug='b1', insert_date=now, org=self.org_b)
		self.engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		mk = lambda name: User.objects.create_user(name, password='x')  # noqa: E731
		self.admin, self.member, self.proj_user, self.auditor, self.outsider = (mk(n) for n in ('adm', 'mem', 'pu', 'aud', 'out'))
		OrgMembership.objects.create(user=self.admin, org=self.org_a, role='admin')
		OrgMembership.objects.create(user=self.member, org=self.org_a, role='user')
		ProjectMembership.objects.create(user=self.proj_user, project=self.a1, role='user')
		OrgMembership.objects.create(user=self.auditor, org=self.org_a, role='audit')
		OrgMembership.objects.create(user=self.outsider, org=self.org_b, role='admin')
		self.targets = {p.slug: Domain.objects.create(name=f'owned-{p.slug}.test', project=p, insert_date=now) for p in (self.a1, self.a2, self.b1)}
		self.scans = {slug: ScanHistory.objects.create(domain=d, scan_type=self.engine, start_scan_date=now, scan_status=2, results_dir='/tmp')
			for slug, d in self.targets.items()}
		patches = [mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False),
			mock.patch('reNgine.tasks.geo_localize.delay'), mock.patch('cveFeed.tasks.run_hygiene_task.delay'),
			mock.patch('cveFeed.tasks.run_bbot_discovery.delay'), mock.patch('cveFeed.tasks.watch_certificate_transparency.delay'),
			mock.patch('cveFeed.tasks.watch_certificate_transparency.apply_async')]
		for p in patches:
			p.start()
		self.addCleanup(mock.patch.stopall)

	def ctx(self, user, token=None):
		return Ctx(user=user, token=token)

	def sub(self, project, name, ip=None, scan=True):
		sub = Subdomain.objects.create(target_domain=self.targets[project.slug], scan_history=self.scans[project.slug] if scan else None, name=name)
		if ip:
			sub.ip_addresses.add(IpAddress.objects.get_or_create(address=ip)[0])  # one row per address
		return sub

	def populate(self, project, host=HOST):
		"""One host with a finding, a CVE match, an endpoint and the per-host rows, plus the lookalike names with a finding each."""
		d = self.targets[project.slug]
		s = self.sub(project, host, ip='192.0.2.10')
		Vulnerability.objects.create(name='Open admin', severity=3, subdomain=s, target_domain=d, scan_history=self.scans[project.slug],
			http_url=f'https://{host}/admin')
		cve, _ = CVEEntry.objects.get_or_create(cve_id='CVE-2099-0001')
		CVEMatch.objects.create(cve_entry=cve, subdomain=s)
		EndPoint.objects.create(subdomain=s, target_domain=d, scan_history=self.scans[project.slug], http_url=f'https://{host}/')
		HostState.objects.create(project=project, domain=d, host=host)
		HostLabel.objects.create(project=project, domain=d, host=host, label='WAF')
		RouteAuth.objects.create(project=project, domain=d, host=host, url=f'https://{host}/', path='/', auth_state='open')
		AssetChange.objects.create(project=project, domain=d, host=host, kind='host_new')
		HostProfile.objects.create(project=project, host=host, owner='x')
		for name in LOOKALIKES:
			other = self.sub(project, name)
			Vulnerability.objects.create(name='Other', severity=2, subdomain=other, target_domain=d, scan_history=self.scans[project.slug],
				http_url=f'https://{name}/')
			HostLabel.objects.create(project=project, domain=d, host=name, label='WAF')
			HostProfile.objects.create(project=project, host=name, owner='keep')
		return s

	def remaining(self, project):
		return {'subs': sorted(Subdomain.objects.filter(target_domain__project=project).values_list('name', flat=True)),
			'vulns': Vulnerability.objects.filter(target_domain__project=project).count(),
			'labels': sorted(HostLabel.objects.filter(project=project).values_list('host', flat=True)),
			'profiles': sorted(HostProfile.objects.filter(project=project).values_list('host', flat=True))}


class ProfileTests(Base):
	def test_update_creates_then_changes_only_the_given_fields(self):
		self.sub(self.a1, 'www.example.com')
		out = hm.update_host_profile(self.ctx(self.admin), 'a1', 'WWW.Example.com', owner=' Ops team ', purpose='Marketing site', criticality='High')
		self.assertEqual((out['host'], out['owner'], out['purpose'], out['criticality']), ('www.example.com', 'Ops team', 'Marketing site', 'high'))
		out = hm.update_host_profile(self.ctx(self.admin), 'a1', 'www.example.com', criticality='critical')
		self.assertEqual((out['owner'], out['purpose'], out['criticality']), ('Ops team', 'Marketing site', 'critical'))
		self.assertEqual(HostProfile.objects.filter(project=self.a1).count(), 1)
		self.assertFalse(HostProfile.objects.filter(project=self.a2).exists())  # profiles are per project
		out = hm.update_host_profile(self.ctx(self.admin), 'a1', 'www.example.com', owner='')
		self.assertEqual(out['owner'], '')

	def test_validation(self):
		ctx = self.ctx(self.admin)
		for kwargs in ({'criticality': 'urgent'}, {'criticality': 5}, {'owner': 'x' * 201}, {'purpose': 'x' * 501}, {'owner': 7}):
			with self.assertRaises(ApiError) as cm:
				hm.update_host_profile(ctx, 'a1', 'h.example.com', **kwargs)
			self.assertEqual(cm.exception.status, 400, kwargs)
		for bad in ('', '  ', '*.example.com', 'a b', 'a%b'):
			with self.assertRaises(ApiError) as cm:
				hm.update_host_profile(ctx, 'a1', bad, owner='x')
			self.assertEqual(cm.exception.status, 400, bad)
		self.assertFalse(HostProfile.objects.exists())

	def test_the_profile_and_excluded_flag_come_back_on_the_host(self):
		s = self.sub(self.a1, 'www.example.com', ip='192.0.2.1')
		self.assertEqual(svc.host_group(self.a1, s)['profile'], {'owner': '', 'purpose': '', 'criticality': 'unknown'})
		hm.update_host_profile(self.ctx(self.admin), 'a1', 'WWW.example.com', owner='Ops', criticality='low')
		h = svc.host_group(self.a1, s)
		self.assertEqual(h['profile'], {'owner': 'Ops', 'purpose': '', 'criticality': 'low'})
		self.assertFalse(h['excluded'])
		listed = svc.list_hosts(self.ctx(self.admin), 'a1', {})['results'][0]
		self.assertEqual(listed['profile']['owner'], 'Ops')

	def test_permissions(self):
		with self.assertRaises(ApiError) as cm:
			hm.update_host_profile(self.ctx(self.auditor), 'a1', 'h.example.com', owner='x')
		self.assertEqual(cm.exception.status, 403)
		with self.assertRaises(ApiError) as cm:
			hm.update_host_profile(self.ctx(self.outsider), 'a1', 'h.example.com', owner='x')
		self.assertEqual(cm.exception.status, 404)  # not even visible
		with self.assertRaises(ApiError) as cm:
			hm.update_host_profile(self.ctx(self.proj_user), 'a2', 'h.example.com', owner='x')
		self.assertEqual(cm.exception.status, 404)
		_, raw = create_token(self.admin, 'ro', read_only=True)
		status, _ = call(raw, 'POST', '/api/v1/projects/a1/hosts/h.example.com/profile', {'owner': 'x'})
		self.assertEqual(status, 403)
		self.assertFalse(HostProfile.objects.exists())


class DeleteHostTests(Base):
	def test_removes_the_host_and_its_findings_in_this_project_only(self):
		self.populate(self.a1)
		self.populate(self.a2)
		self.populate(self.b1)
		before_a2, before_b1 = self.remaining(self.a2), self.remaining(self.b1)
		out = hm.delete_host(self.ctx(self.proj_user), 'a1', HOST.upper())
		self.assertEqual((out['host'], out['project'], out['hosts'], out['findings'], out['cve_matches'], out['endpoints']), (HOST, 'a1', 1, 1, 1, 1))
		after = self.remaining(self.a1)
		self.assertNotIn(HOST, after['subs'])
		self.assertEqual(after['subs'], sorted(LOOKALIKES))  # exact name only: no suffix, no parent, no substring
		self.assertEqual(after['vulns'], len(LOOKALIKES))
		self.assertEqual(after['labels'], sorted(LOOKALIKES))
		self.assertEqual(after['profiles'], sorted(LOOKALIKES))
		self.assertFalse(HostState.objects.filter(project=self.a1, host=HOST).exists())
		self.assertFalse(RouteAuth.objects.filter(project=self.a1, host=HOST).exists())
		self.assertFalse(AssetChange.objects.filter(project=self.a1, host=HOST).exists())
		self.assertFalse(CVEMatch.objects.filter(subdomain__target_domain__project=self.a1, subdomain__name=HOST).exists())
		self.assertEqual(self.remaining(self.a2), before_a2)  # another project of the same org is untouched
		self.assertEqual(self.remaining(self.b1), before_b1)
		self.assertTrue(HostState.objects.filter(project=self.a2, host=HOST).exists())
		self.assertFalse(HostExclusion.objects.exists())  # not excluded: it can come back
		self.assertTrue(AuditLog.objects.filter(action='host.delete').exists())

	def test_it_can_be_rediscovered(self):
		self.populate(self.a1)
		hm.delete_host(self.ctx(self.admin), 'a1', HOST)
		self.assertEqual(save_subdomain(HOST, ctx={'scan_history_id': self.scans['a1'].id})[1], True)  # nothing blocks the name

	def test_findings_recorded_on_the_bare_host_go_too_but_not_lookalike_urls(self):
		d = self.targets['a1']
		Vulnerability.objects.create(name='Loose', severity=2, target_domain=d, scan_history=self.scans['a1'], http_url=HOST)
		Vulnerability.objects.create(name='Loose url', severity=2, target_domain=d, scan_history=self.scans['a1'], http_url=f'https://{HOST}:8443/a?b=c')
		for url in (f'https://not{HOST}/', f'https://{HOST}.evil.net/', f'https://x.{HOST}/', f'https://evil.net/{HOST}'):
			Vulnerability.objects.create(name='Keep', severity=2, target_domain=d, scan_history=self.scans['a1'], http_url=url)
		hm.delete_host(self.ctx(self.admin), 'a1', HOST)
		self.assertEqual(sorted(Vulnerability.objects.values_list('name', flat=True)), ['Keep'] * 4)

	def test_a_target_named_like_the_host_is_deleted_with_its_scans(self):
		Domain.objects.create(name=HOST, project=self.a1, insert_date=timezone.now())
		target = Domain.objects.get(name=HOST)
		ScanHistory.objects.create(domain=target, scan_type=self.engine, start_scan_date=timezone.now(), scan_status=2)
		Subdomain.objects.create(target_domain=target, name=HOST)
		out = hm.delete_host(self.ctx(self.admin), 'a1', HOST)
		self.assertTrue(out['target_deleted'])
		self.assertFalse(Domain.objects.filter(name=HOST).exists())
		self.assertFalse(ScanHistory.objects.filter(domain__name=HOST).exists())

	def test_a_target_that_also_holds_other_hosts_is_kept(self):
		target = Domain.objects.create(name=HOST, project=self.a1, insert_date=timezone.now())
		Subdomain.objects.create(target_domain=target, name=HOST)
		Subdomain.objects.create(target_domain=target, name=f'www.{HOST}')  # a legitimately owned subdomain
		out = hm.delete_host(self.ctx(self.admin), 'a1', HOST)
		self.assertTrue(out['target_kept'])
		self.assertTrue(Domain.objects.filter(name=HOST).exists())
		self.assertEqual(list(Subdomain.objects.filter(target_domain=target).values_list('name', flat=True)), [f'www.{HOST}'])

	def test_it_is_all_or_nothing(self):
		self.populate(self.a1)
		before = self.remaining(self.a1)
		with mock.patch('cveFeed.models.HostProfile.objects.filter', side_effect=RuntimeError('boom')):  # fails after the findings went
			with self.assertRaises(RuntimeError):
				hm.delete_host(self.ctx(self.admin), 'a1', HOST)
		self.assertEqual(self.remaining(self.a1), before)

	def test_permissions(self):
		self.populate(self.a1)
		before = self.remaining(self.a1)
		for user, status in ((self.auditor, 403), (self.outsider, 404)):
			with self.assertRaises(ApiError) as cm:
				hm.delete_host(self.ctx(user), 'a1', HOST)
			self.assertEqual(cm.exception.status, status)
		with self.assertRaises(ApiError) as cm:
			hm.delete_host(self.ctx(self.proj_user), 'a2', HOST)  # a member of a1 only
		self.assertEqual(cm.exception.status, 404)
		_, raw = create_token(self.admin, 'ro', read_only=True)
		self.assertEqual(call(raw, 'POST', f'/api/v1/projects/a1/hosts/{HOST}/delete', {})[0], 403)
		self.assertEqual(self.remaining(self.a1), before)


class ExcludeHostTests(Base):
	def test_removes_the_host_from_every_project_of_the_org_and_records_the_exclusion(self):
		for p in (self.a1, self.a2, self.b1):
			self.populate(p)
		out = hm.exclude_host(self.ctx(self.admin), 'a1', HOST.title(), reason='  not ours ')
		self.assertEqual((out['organization'], out['excluded'], out['newly_excluded'], out['reason']), ('oa', True, True, 'not ours'))
		self.assertEqual((out['projects_checked'], out['projects_affected'], out['hosts_removed'], out['findings_removed']), (2, 2, 2, 2))
		exclusion = HostExclusion.objects.get()
		self.assertEqual((exclusion.org_id, exclusion.host, exclusion.created_by_id), (self.org_a.id, HOST, self.admin.id))
		for p in (self.a1, self.a2):
			self.assertEqual(self.remaining(p)['subs'], sorted(LOOKALIKES))
			self.assertFalse(HostState.objects.filter(project=p, host=HOST).exists())
		self.assertIn(HOST, self.remaining(self.b1)['subs'])  # another organization is never touched
		self.assertTrue(HostState.objects.filter(project=self.b1, host=HOST).exists())
		self.assertEqual(excluded_names(self.a1.id), {HOST})
		self.assertEqual(excluded_names(self.a2.id), {HOST})
		self.assertEqual(excluded_names(self.b1.id), frozenset())
		self.assertTrue(AuditLog.objects.filter(action='host.exclude', org=self.org_a).exists())

	def test_it_is_idempotent_and_updates_the_reason(self):
		self.populate(self.a1)
		hm.exclude_host(self.ctx(self.admin), 'a1', HOST, 'first')
		again = hm.exclude_host(self.ctx(self.admin), 'a2', HOST, 'second')
		self.assertFalse(again['newly_excluded'])
		self.assertEqual(HostExclusion.objects.count(), 1)
		self.assertEqual(HostExclusion.objects.get().reason, 'second')
		self.assertEqual(again['hosts_removed'], 0)

	def test_it_only_removes_data_from_projects_the_caller_can_write_to(self):
		self.populate(self.a1)
		self.populate(self.a2)
		ProjectMembership.objects.create(user=self.member, project=self.a2, role='audit')  # read only in a2, though an org member
		out = hm.exclude_host(self.ctx(self.member), 'a1', HOST)
		self.assertEqual((out['projects_checked'], out['projects_affected']), (1, 1))
		self.assertNotIn(HOST, self.remaining(self.a1)['subs'])
		self.assertIn(HOST, self.remaining(self.a2)['subs'])  # not writable: its data stays...
		self.assertEqual(excluded_names(self.a2.id), {HOST})  # ...but nothing scans it again

	def test_exact_name_only(self):
		for p in (self.a1, self.a2):
			self.populate(p)
		hm.exclude_host(self.ctx(self.admin), 'a1', HOST)
		for name in LOOKALIKES + ['PROVIDER.EXAMPLE.', 'https://Provider.example:443/x']:
			if normalize(name) == HOST:
				self.assertTrue(is_excluded(self.a1.id, name), name)  # the same name in another spelling
			else:
				self.assertFalse(is_excluded(self.a1.id, name), name)
		self.assertEqual(drop_excluded(self.a1.id, LOOKALIKES + [HOST, HOST.upper()]), LOOKALIKES)
		self.assertEqual(sorted(HostExclusion.objects.values_list('host', flat=True)), [HOST])
		for p in (self.a1, self.a2):
			self.assertEqual(self.remaining(p)['subs'], sorted(LOOKALIKES))
			self.assertEqual(self.remaining(p)['vulns'], len(LOOKALIKES))

	def test_wildcards_and_patterns_are_refused(self):
		for bad in ('*.provider.example', '%provider.example', 'provider example.com', '', '.com/'):
			with self.assertRaises(ApiError) as cm:
				hm.exclude_host(self.ctx(self.admin), 'a1', bad)
			self.assertEqual(cm.exception.status, 400, bad)
		self.assertFalse(HostExclusion.objects.exists())

	def test_permissions(self):
		self.populate(self.a1)
		before = self.remaining(self.a1)
		cases = ((self.auditor, 'a1', 403), (self.outsider, 'a1', 404), (self.proj_user, 'a2', 404),
			(self.proj_user, 'a1', 403))  # a role in one project is not an organization-level role
		for user, slug, status in cases:
			with self.assertRaises(ApiError) as cm:
				hm.exclude_host(self.ctx(user), slug, HOST)
			self.assertEqual(cm.exception.status, status, (user.username, slug))
		_, ro = create_token(self.admin, 'ro', read_only=True)
		self.assertEqual(call(ro, 'POST', f'/api/v1/projects/a1/hosts/{HOST}/exclude', {})[0], 403)
		self.assertEqual(rpc(ro, 'tools/call', {'name': 'exclude_host', 'arguments': {'project': 'a1', 'host': HOST}})[1]['result']['isError'], True)
		self.assertFalse(HostExclusion.objects.exists())
		self.assertEqual(self.remaining(self.a1), before)

	def test_a_project_without_an_org_cannot_exclude(self):
		loose = Project.objects.create(name='L', slug='loose', insert_date=timezone.now())
		Project.objects.filter(pk=loose.pk).update(org=None)  # new projects are placed in an org by a signal
		root = User.objects.create_superuser('root', 'r@x.test', 'x')
		with self.assertRaises(ApiError) as cm:
			hm.exclude_host(self.ctx(root), 'loose', HOST)
		self.assertEqual(cm.exception.status, 400)
		self.assertEqual(excluded_names(loose.id), frozenset())

	def test_exclusions_never_leak_across_orgs(self):
		hm.exclude_host(self.ctx(self.admin), 'a1', HOST, 'secret reason')
		self.assertEqual([r['host'] for r in hm.list_exclusions(self.ctx(self.member), 'a2')['results']], [HOST])
		with self.assertRaises(ApiError) as cm:
			hm.list_exclusions(self.ctx(self.outsider), 'a1')
		self.assertEqual(cm.exception.status, 404)
		self.assertEqual(hm.list_exclusions(self.ctx(self.outsider), 'b1')['results'], [])
		# the same name excluded by the other org does not remove the first org's exclusion, and lifting is per org
		hm.exclude_host(self.ctx(self.outsider), 'b1', HOST)
		self.assertEqual(HostExclusion.objects.count(), 2)
		with self.assertRaises(ApiError) as cm:
			hm.remove_exclusion(self.ctx(self.member), 'a1', HOST)  # not an org admin
		self.assertEqual(cm.exception.status, 403)
		hm.remove_exclusion(self.ctx(self.outsider), 'b1', HOST)
		self.assertEqual(list(HostExclusion.objects.values_list('org_id', flat=True)), [self.org_a.id])
		self.assertEqual(hm.remove_exclusion(self.ctx(self.admin), 'a1', HOST), {'host': HOST, 'excluded': False})
		self.assertFalse(HostExclusion.objects.exists())


class EnforcementTests(Base):
	"""An excluded host never re-enters the inventory and is never scanned, at every choke point."""

	def setUp(self):
		super().setUp()
		HostExclusion.objects.create(org=self.org_a, host=HOST)

	def ctx_for(self, slug):
		return {'scan_history_id': self.scans[slug].id, 'domain_id': self.targets[slug].id}

	def test_save_subdomain_skips_it_only_inside_the_org(self):
		scan = {'scan_history_id': self.scans['a1'].id}
		self.assertEqual(save_subdomain(HOST.upper(), ctx=scan), (None, False))
		self.assertEqual(save_subdomain(HOST, ctx=scan), (None, False))
		for other in [f'www.{HOST}', f'not{HOST}'] + LOOKALIKES:  # only the exact name is excluded
			self.assertTrue(save_subdomain(other, ctx=scan)[0], other)
		self.assertFalse(Subdomain.objects.filter(name__iexact=HOST).exists())
		self.assertTrue(save_subdomain(HOST, ctx={'scan_history_id': self.scans['b1'].id})[1])  # org B scans it freely

	def test_a_discovery_batch_drops_the_host_its_ports_and_its_findings(self):
		d = self.targets['a2']
		result = bbot_lib.BbotResult(subdomains={'ok.owned-a2.test', 'owned-a2.test'}, resolutions=set(), ports={('owned-a2.test', 443)})
		HostExclusion.objects.create(org=self.org_a, host='owned-a2.test')
		persist_bbot_result(result, ctx=self.ctx_for('a2'))
		self.assertEqual(sorted(Subdomain.objects.filter(target_domain=d).values_list('name', flat=True)), ['ok.owned-a2.test'])
		self.assertFalse(Port.objects.exists())

	def test_a_discovery_batch_reads_its_scan_and_target_once_not_once_per_name(self):
		from django.db import connection
		from django.test.utils import CaptureQueriesContext
		names = {f'n{i}.owned-a2.test' for i in range(6)}
		with CaptureQueriesContext(connection) as queries:
			persist_bbot_result(bbot_lib.BbotResult(subdomains=names, resolutions=set(), ports=set()), ctx=self.ctx_for('a2'))
		self.assertEqual(Subdomain.objects.filter(target_domain=self.targets['a2']).count(), 6)
		for table in ('startScan_scanhistory', 'targetApp_domain'):
			self.assertLessEqual(sum(1 for q in queries.captured_queries if f'FROM "{table}"' in q['sql']), 2, table)  # not one per name

	def test_new_hosts_pipeline_never_creates_it(self):
		target = Domain.objects.create(name='hp.test', project=self.a1, insert_date=timezone.now())
		HostExclusion.objects.create(org=self.org_a, host='gone.hp.test')
		nmap, kwargs = _stages()
		out = discovery.run_host_pipeline(target.id, ['gone.hp.test', 'GONE.hp.test', 'kept.hp.test'], **kwargs)
		names = sorted(Subdomain.objects.filter(target_domain=target).values_list('name', flat=True))
		self.assertEqual(names, ['kept.hp.test'])
		self.assertEqual(out['hosts'], 1)
		self.assertEqual(nmap, [['192.0.2.10']])
		nmap, kwargs = _stages()
		self.assertEqual(discovery.run_host_pipeline(target.id, ['gone.hp.test'], **kwargs), {'status': 'empty', 'hosts': 0})

	def test_nuclei_and_nmap_targets_skip_it(self):
		self.sub(self.a1, 'ok.owned-a1.test', ip='192.0.2.20')
		self.sub(self.a1, HOST, ip='192.0.2.21')
		hostnames, ips, ports = scan_targets(self.scans['a1'])
		self.assertEqual((hostnames, ips), ({'ok.owned-a1.test'}, {'192.0.2.20'}))
		self.sub(self.b1, HOST, ip='192.0.2.22')
		self.assertEqual(scan_targets(self.scans['b1'])[0], {HOST})  # another org's scan still sees it

	def test_route_auth_plan_skips_it(self):
		for name, ip in (('ok.owned-a1.test', '192.0.2.30'), (HOST, '192.0.2.31')):
			s = self.sub(self.a1, name, ip=ip)
			port = Port.objects.create(number=443, protocol='tcp', state='open', service_name='https')
			s.ip_addresses.first().ports.add(port)
		self.assertEqual(sorted(ra._plan(self.scans['a1'])), ['ok.owned-a1.test'])

	def test_full_scan_selection_skips_it(self):
		os.environ.pop('CVENGINE_ALLOW_PRIVATE_TARGETS', None)
		self.sub(self.a1, HOST, ip='192.0.2.40')
		self.assertIsNone(fullscan.pick())
		ok = self.sub(self.a1, 'ok.owned-a1.test', ip='192.0.2.41')
		self.assertEqual(fullscan.pick().pk, ok.ip_addresses.first().pk)
		shared = IpAddress.objects.get(address='192.0.2.40')
		ok.ip_addresses.add(shared)  # an address that also answers to an allowed name is still in scope through that name
		self.assertTrue(fullscan.in_scope(shared))

	def test_ct_watch_does_not_recreate_it(self):
		target = Domain.objects.create(name='ct.test', project=self.a1, insert_date=timezone.now())
		HostExclusion.objects.create(org=self.org_a, host='drop.ct.test')
		out = ctmonitor.run_ct_watch(target.id, fetch=lambda name: {'drop.ct.test', 'keep.ct.test', 'adrop.ct.test'})
		self.assertEqual(sorted(Subdomain.objects.filter(target_domain=target).values_list('name', flat=True)), ['adrop.ct.test', 'keep.ct.test'])
		self.assertEqual(out['new'], 2)

	def test_deep_sweep_skips_an_excluded_apex(self):
		client = getattr(resources.get_store(), 'r', None)
		if client is not None:
			client.delete('cvengine:sweep:deep-apex')
		self.addCleanup(lambda: client is not None and client.delete('cvengine:sweep:deep-apex'))
		Domain.objects.create(name='www.apexed.com', project=self.a1, insert_date=timezone.now())
		Domain.objects.create(name='www.other.com', project=self.a1, insert_date=timezone.now())
		HostExclusion.objects.create(org=self.org_a, host='apexed.com')
		tasks.deep_scan_apexes()
		self.assertFalse(Domain.objects.filter(name='apexed.com').exists())
		self.assertTrue(Domain.objects.filter(name='other.com').exists())

	def test_adding_the_host_as_a_target_is_refused_inside_the_org_only(self):
		with self.assertRaises(ApiError) as cm:
			svc.add_target(self.ctx(self.admin), 'a2', HOST.upper())
		self.assertEqual(cm.exception.status, 409)
		self.assertFalse(Domain.objects.filter(name=HOST).exists())
		bulk = svc.add_targets(self.ctx(self.admin), 'a2', [HOST, 'fine-a2.test', f'www.{HOST}'], discover=False)
		self.assertEqual(sorted(bulk['created_names']), ['fine-a2.test', f'www.{HOST}'])
		self.assertEqual([i['value'] for i in bulk['invalid']], [HOST])
		self.assertEqual(svc.add_target(self.ctx(self.outsider), 'b1', HOST)['created'][0]['name'], HOST)  # org B may

	def test_scanning_or_rescanning_an_excluded_target_is_refused(self):
		target = Domain.objects.create(name=f'x.{HOST}', project=self.a1, insert_date=timezone.now())
		HostExclusion.objects.create(org=self.org_a, host=target.name)
		for call_ in (lambda: svc.start_scan(self.ctx(self.admin), 'a1', target.id), lambda: svc.discover_target(self.ctx(self.admin), 'a1', target.id)):
			with self.assertRaises(ApiError) as cm:
				call_()
			self.assertEqual(cm.exception.status, 409)
		with self.assertRaises(ApiError) as cm:
			svc.rescan_hosts(self.ctx(self.admin), 'a1', target.id, [target.name])
		self.assertEqual(cm.exception.status, 400)  # nothing left to scan

	def test_a_queued_scan_of_a_target_excluded_afterwards_fails_without_scanning(self):
		target = Domain.objects.create(name='late.test', project=self.a1, insert_date=timezone.now())
		scan = ScanHistory.objects.create(domain=target, scan_type=self.engine, start_scan_date=timezone.now(), scan_status=-1)
		HostExclusion.objects.create(org=self.org_a, host='late.test')
		with mock.patch('reNgine.bbot.stream_events', side_effect=AssertionError('bbot must not run')):
			out = discovery._run_pipeline(scan.id)
		self.assertEqual(out['status'], discovery.FAILED)
		self.assertEqual(ScanHistory.objects.get(pk=scan.pk).scan_status, discovery.FAILED)

	def test_the_shared_scannable_helper_filters_by_project(self):
		names = [HOST, f'https://{HOST.upper()}:8443/x', f'www.{HOST}', 'ok.owned-a1.test']
		resolver = lambda host: False  # noqa: E731
		self.assertEqual(scannable_hosts(names, resolver=resolver, project=self.a1.id), [f'www.{HOST}', 'ok.owned-a1.test'])
		self.assertEqual(scannable_hosts(names, resolver=resolver, project=self.b1.id), names)  # other org
		self.assertEqual(scannable_hosts(names, resolver=resolver), names)  # no project: only the SSRF rules apply

	def test_a_failing_lookup_never_stops_discovery(self):
		with mock.patch('cveFeed.models.HostExclusion.objects.filter', side_effect=RuntimeError('db')):
			self.assertEqual(excluded_names(self.a1.id), frozenset())


class RouteTests(Base):
	def setUp(self):
		super().setUp()
		_, self.token = create_token(self.admin, 'rw')

	def test_profile_delete_and_exclude_over_rest(self):
		self.populate(self.a1)
		self.populate(self.a2)
		status, data = call(self.token, 'POST', f'/api/v1/projects/a1/hosts/{HOST}/profile', {'owner': 'Ops', 'criticality': 'high'})
		self.assertEqual((status, data['owner'], data['criticality']), (200, 'Ops', 'high'))
		status, data = call(self.token, 'PATCH', f'/api/v1/projects/a1/hosts/{HOST}/profile', {'purpose': 'Data warehouse'})
		self.assertEqual((status, data['owner'], data['purpose']), (200, 'Ops', 'Data warehouse'))
		self.assertEqual(call(self.token, 'POST', f'/api/v1/projects/a1/hosts/{HOST}/profile', {'criticality': 'nope'})[0], 400)
		status, data = call(self.token, 'POST', f'/api/v1/projects/a1/hosts/{HOST}/delete', {})
		self.assertEqual((status, data['hosts']), (200, 1))
		self.assertIn(HOST, self.remaining(self.a2)['subs'])
		status, data = call(self.token, 'POST', f'/api/v1/projects/a1/hosts/{HOST}/exclude', {'reason': 'noise'})
		self.assertEqual((status, data['excluded'], data['hosts_removed']), (200, True, 1))
		self.assertEqual(call(self.token, 'GET', '/api/v1/projects/a2/exclusions')[1]['results'][0]['reason'], 'noise')
		self.assertEqual(call(self.token, 'DELETE', f'/api/v1/projects/a1/exclusions/{HOST}')[0], 200)
		self.assertEqual(call(self.token, 'DELETE', f'/api/v1/projects/a1/exclusions/{HOST}')[0], 404)

	def test_mcp_tools(self):
		self.populate(self.a1)
		names = {t['name'] for t in rpc(self.token, 'tools/list')[1]['result']['tools']}
		self.assertTrue({'set_host_profile', 'delete_host', 'exclude_host', 'list_exclusions', 'remove_exclusion'} <= names)

		def tool(name, **args):
			result = rpc(self.token, 'tools/call', {'name': name, 'arguments': args})[1]['result']
			return result['isError'], result['content'][0]['text']
		self.assertFalse(tool('set_host_profile', project='a1', host=HOST, owner='Ops')[0])
		self.assertTrue(tool('set_host_profile', project='a1', host=HOST, criticality='x')[0])
		self.assertFalse(tool('delete_host', project='a1', host=HOST)[0])
		self.assertFalse(tool('exclude_host', project='a1', host=HOST, reason='r')[0])
		self.assertEqual(HostExclusion.objects.get().host, HOST)
		self.assertFalse(tool('list_exclusions', project='a1')[0])
		self.assertFalse(tool('remove_exclusion', project='a1', host=HOST)[0])


class MoveHostTests(Base):
	"""Move host: the host becomes a target of the destination, its data leaves the source, and the source never brings it back."""

	def test_the_host_becomes_a_target_of_the_destination_and_leaves_the_source(self):
		from cveFeed.models import HostMove
		self.populate(self.a1)
		out = hm.move_host(self.ctx(self.admin), 'a1', HOST.upper(), 'a2')
		self.assertEqual((out['host'], out['from_project'], out['to_project'], out['target_created']), (HOST, 'a1', 'a2', True))
		self.assertTrue(Domain.objects.filter(project=self.a2, name=HOST).exists())
		self.assertFalse(Subdomain.objects.filter(target_domain__project=self.a1, name=HOST).exists())
		self.assertFalse(Vulnerability.objects.filter(target_domain__project=self.a1, name='Open admin', subdomain__name=HOST).exists())
		self.assertTrue(Subdomain.objects.filter(target_domain__project=self.a1, name='notprovider.example').exists())  # lookalikes stay
		self.assertEqual(HostMove.objects.get(project=self.a1).moved_to, self.a2)
		self.assertTrue(AuditLog.objects.filter(action='host.move').exists())

	def test_the_source_never_rediscovers_it_but_the_destination_and_the_org_still_scan_it(self):
		self.populate(self.a1)
		hm.move_host(self.ctx(self.admin), 'a1', HOST, 'a2')
		self.assertTrue(is_excluded(self.a1.pk, HOST))
		self.assertFalse(is_excluded(self.a2.pk, HOST))
		self.assertFalse(is_excluded(self.a1.pk, 'www.provider.example'))  # exact name only
		self.assertEqual(drop_excluded(self.a1.pk, [HOST, 'other.example']), ['other.example'])
		self.assertEqual(save_subdomain(HOST, ctx={'scan_history_id': self.scans['a1'].id}), (None, False))  # a scan of the old target skips it

	def test_moving_it_back_lifts_the_block(self):
		from cveFeed.models import HostMove
		self.populate(self.a1)
		hm.move_host(self.ctx(self.admin), 'a1', HOST, 'a2')
		hm.move_host(self.ctx(self.admin), 'a2', HOST, 'a1')
		self.assertFalse(is_excluded(self.a1.pk, HOST))
		self.assertTrue(is_excluded(self.a2.pk, HOST))
		self.assertEqual(list(HostMove.objects.values_list('project__slug', flat=True)), ['a2'])
		self.assertTrue(Domain.objects.filter(project=self.a1, name=HOST).exists())

	def test_a_host_that_is_also_its_own_target_moves_within_the_org(self):
		now = timezone.now()
		Domain.objects.create(name=HOST, project=self.a1, insert_date=now)
		out = hm.move_host(self.ctx(self.admin), 'a1', HOST, 'a2')
		self.assertTrue(out['target_created'])
		self.assertEqual(list(Domain.objects.filter(name=HOST).values_list('project__slug', flat=True)), ['a2'])

	def test_a_target_of_that_name_elsewhere_in_the_org_or_with_other_hosts_is_refused_before_anything_is_deleted(self):
		now = timezone.now()
		self.populate(self.a1)
		self.targets['a1'].name = HOST  # the host's own target, holding other hosts too
		self.targets['a1'].save()
		with self.assertRaises(ApiError) as e:
			hm.move_host(self.ctx(self.admin), 'a1', HOST, 'a2')
		self.assertEqual(e.exception.status, 409)
		self.assertTrue(Subdomain.objects.filter(target_domain__project=self.a1, name=HOST).exists())
		a3 = Project.objects.create(name='A3', slug='a3', insert_date=now, org=self.org_a)
		self.sub(self.a1, 'solo.example')
		Domain.objects.create(name='solo.example', project=a3, insert_date=now)  # a third project of the org holds that target name
		with self.assertRaises(ApiError) as e:
			hm.move_host(self.ctx(self.admin), 'a1', 'solo.example', 'a2')
		self.assertEqual(e.exception.status, 409)
		self.assertTrue(Subdomain.objects.filter(target_domain__project=self.a1, name='solo.example').exists())
		OrgMembership.objects.create(user=self.admin, org=self.org_b, role='user')
		self.assertTrue(hm.move_host(self.ctx(self.admin), 'a1', 'solo.example', 'b1')['target_created'])  # another org: no conflict

	def test_it_can_move_to_another_org_the_caller_writes_to(self):
		OrgMembership.objects.create(user=self.admin, org=self.org_b, role='user')
		self.populate(self.a1)
		out = hm.move_host(self.ctx(self.admin), 'a1', HOST, 'b1')
		self.assertEqual((out['to_project'], out['to_org_name']), ('b1', 'B'))
		self.assertTrue(Domain.objects.filter(project=self.b1, name=HOST).exists())

	def test_it_needs_write_access_to_both_projects(self):
		self.populate(self.a1)
		for user, to in ((self.proj_user, 'a2'), (self.auditor, 'a2'), (self.admin, 'b1'), (self.outsider, 'a2')):
			with self.assertRaises(ApiError, msg=(user.username, to)) as e:
				hm.move_host(self.ctx(user), 'a1', HOST, to)
			self.assertIn(e.exception.status, (403, 404))
		self.assertTrue(Subdomain.objects.filter(target_domain__project=self.a1, name=HOST).exists())  # nothing moved

	def test_refusals(self):
		self.populate(self.a1)
		for host, to, status in ((HOST, 'a1', 400), (HOST, '', 400), ('missing.example', 'a2', 404), ('*.provider.example', 'a2', 400)):
			with self.assertRaises(ApiError, msg=(host, to)) as e:
				hm.move_host(self.ctx(self.admin), 'a1', host, to)
			self.assertEqual(e.exception.status, status)

	def test_a_host_the_destination_org_excluded_is_refused_and_left_where_it_is(self):
		OrgMembership.objects.create(user=self.admin, org=self.org_b, role='user')
		HostExclusion.objects.create(org=self.org_b, host=HOST)
		self.populate(self.a1)
		with self.assertRaises(ApiError) as e:
			hm.move_host(self.ctx(self.admin), 'a1', HOST, 'b1')
		self.assertEqual(e.exception.status, 409)
		self.assertTrue(Subdomain.objects.filter(target_domain__project=self.a1, name=HOST).exists())

	def test_over_rest(self):
		token = create_token(self.admin, 'mover')[1]
		self.populate(self.a1)
		status, out = call(token, 'POST', f'/api/v1/projects/a1/hosts/{HOST}/move', {'to_project': 'a2'})
		self.assertEqual(status, 200, out)
		self.assertEqual(out['to_project'], 'a2')

	def test_the_project_list_names_each_projects_organization(self):
		rows = {p['slug']: p for p in svc.list_projects(self.ctx(self.admin))['results']}
		self.assertEqual((rows['a2']['org'], rows['a2']['org_name']), ('oa', 'A'))
