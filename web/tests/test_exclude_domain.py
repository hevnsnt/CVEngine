from unittest import mock

from agentapi import host_manage as hm
from agentapi import services as svc
from agentapi.auth import create_token
from agentapi.services import ApiError
from cveFeed.exclusions import ExclusionSet, drop_excluded, excluded_names, is_excluded
from cveFeed.models import HostExclusion, HostState
from reNgine.tasks import save_subdomain
from startScan.models import IpAddress, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_agentapi import call
from tests.test_host_manage import Base

ROOT = 'snow.test'
UNDER = ['snow.test', 'www.snow.test', 'a.b.snow.test']
LOOKALIKES = ['notsnow.test', 'snow.test.evil.net', 'xsnow.test', 'snowtest.example']


class ExclusionSetTests(Base):
	def test_a_subtree_exclusion_covers_the_name_and_everything_under_it_on_a_dot_boundary(self):
		banned = ExclusionSet({'exact.test', ROOT}, {ROOT})
		for name in UNDER + ['WWW.Snow.Test.', 'exact.test']:
			self.assertIn(name, banned, name)
		for name in LOOKALIKES + ['sub.exact.test', 'test']:
			self.assertNotIn(name, banned, name)

	def test_union_keeps_the_subtree_rules(self):
		banned = ExclusionSet({ROOT}, {ROOT})
		self.assertIn('www.snow.test', frozenset({'other.test'}) | banned)
		self.assertIn('www.snow.test', banned | frozenset({'other.test'}))
		self.assertIn('other.test', banned | frozenset({'other.test'}))

	def test_excluded_names_reads_the_flag_and_the_helpers_follow_it(self):
		HostExclusion.objects.create(org=self.org_a, host=ROOT, include_subdomains=True)
		HostExclusion.objects.create(org=self.org_a, host='exact.test')
		self.assertTrue(is_excluded(self.a1.id, 'deep.www.snow.test'))
		self.assertTrue(is_excluded(self.a2.id, 'https://x.snow.test:8443/path'))
		self.assertFalse(is_excluded(self.a1.id, 'sub.exact.test'))
		self.assertFalse(is_excluded(self.b1.id, 'www.snow.test'))  # another organization
		self.assertEqual(drop_excluded(self.a1.id, ['a.snow.test', 'keep.test', 'exact.test']), ['keep.test'])
		with mock.patch('cveFeed.models.HostExclusion.objects') as objects:
			objects.filter.side_effect = RuntimeError('db')
			self.assertEqual(excluded_names(self.a1.id), frozenset())  # best effort: discovery carries on
			with self.assertRaises(RuntimeError):
				excluded_names(self.a1.id, strict=True)  # an authorization check must stop instead


class WholeDomainTests(Base):
	def populate_domain(self, project, target=ROOT):
		"""A target holding the hosts under ROOT (domain names are unique per organization, so a second project of the organization uses
		its own target name), plus names that only look like it."""
		d = Domain.objects.create(name=target, project=project, insert_date=self.targets[project.slug].insert_date)
		scan = ScanHistory.objects.create(domain=d, scan_type=self.engine, start_scan_date=d.insert_date, scan_status=2, results_dir='/tmp')
		for name in UNDER:
			s = Subdomain.objects.create(target_domain=d, scan_history=scan, name=name)
			Vulnerability.objects.create(name='F', severity=3, subdomain=s, target_domain=d, scan_history=scan, http_url=f'https://{name}/')
		for name in LOOKALIKES:
			s = self.sub(project, name, ip='192.0.2.50')
			Vulnerability.objects.create(name='Keep', severity=2, subdomain=s, target_domain=self.targets[project.slug],
				scan_history=self.scans[project.slug], http_url=f'https://{name}/')
		return d, scan

	def test_it_removes_the_domain_its_names_and_its_targets_in_every_writable_project_and_keeps_lookalikes(self):
		self.populate_domain(self.a1)
		self.populate_domain(self.a2, target='sub.snow.test')
		self.populate_domain(self.b1)
		out = hm.exclude_host(self.ctx(self.admin), 'a1', '*.Snow.Test', reason='not ours', include_subdomains=True)
		self.assertEqual((out['host'], out['include_subdomains'], out['excluded']), (ROOT, True, True))
		self.assertEqual((out['projects_affected'], out['hosts_removed'], out['findings_removed'], out['targets_removed']), (2, 6, 6, 2))
		for p in (self.a1, self.a2):
			self.assertEqual(self.remaining(p)['subs'], sorted(LOOKALIKES))
			self.assertFalse(Domain.objects.filter(project=p, name__in=[ROOT, 'sub.snow.test']).exists())
			self.assertTrue(Domain.objects.filter(project=p).exists())  # its other targets stay
		self.assertEqual(Subdomain.objects.filter(target_domain__project=self.b1, name__in=UNDER).count(), 3)  # another organization
		self.assertTrue(Domain.objects.filter(project=self.b1, name=ROOT).exists())
		row = HostExclusion.objects.get()
		self.assertEqual((row.host, row.include_subdomains, row.org_id), (ROOT, True, self.org_a.id))

	def test_new_names_under_it_are_never_recorded_or_added_again(self):
		self.populate_domain(self.a1)
		hm.exclude_host(self.ctx(self.admin), 'a1', ROOT, include_subdomains=True)
		sub, _ = save_subdomain('fresh.deep.snow.test', ctx={'domain_id': self.targets['a1'].id, 'scan_history_id': self.scans['a1'].id,
			'_excluded_hosts': excluded_names(self.a1.id)})
		self.assertIsNone(sub)
		self.assertFalse(Subdomain.objects.filter(name='fresh.deep.snow.test').exists())
		out = svc.add_targets(self.ctx(self.admin), 'a1', ['x.snow.test', 'fine.example'], discover=False)
		self.assertEqual(out['created_names'], ['fine.example'])
		self.assertEqual([i['value'] for i in out['invalid']], ['x.snow.test'])

	def test_scans_of_the_removed_targets_are_stopped_first(self):
		d, scan = self.populate_domain(self.a1)
		ScanHistory.objects.filter(pk=scan.pk).update(scan_status=1)
		with mock.patch('agentapi.services._abort_scan') as abort:
			hm.exclude_host(self.ctx(self.admin), 'a1', ROOT, include_subdomains=True)
		self.assertEqual([c.args[0].pk for c in abort.call_args_list], [scan.pk])

	def test_an_exact_exclusion_is_widened_to_the_whole_domain(self):
		self.populate_domain(self.a1)
		hm.exclude_host(self.ctx(self.admin), 'a1', ROOT)
		self.assertEqual(Subdomain.objects.filter(target_domain__project=self.a1, name='www.snow.test').count(), 1)  # exact: the rest stays
		self.assertFalse(is_excluded(self.a1.id, 'www.snow.test'))
		out = hm.exclude_host(self.ctx(self.admin), 'a1', ROOT, include_subdomains=True)
		self.assertFalse(out['newly_excluded'])
		self.assertEqual(HostExclusion.objects.count(), 1)
		self.assertTrue(HostExclusion.objects.get().include_subdomains)
		self.assertTrue(is_excluded(self.a1.id, 'www.snow.test'))
		self.assertFalse(Subdomain.objects.filter(target_domain__project=self.a1, name__in=UNDER).exists())

	def test_only_real_domain_names_can_be_excluded_with_their_subdomains(self):
		for bad in ('com', 'co.uk', 'com.au', '192.0.2.1', '10.0.0.0/8', '', 'a b', 'host:8443'):
			with self.assertRaises(ApiError, msg=bad) as cm:
				hm.exclude_host(self.ctx(self.admin), 'a1', bad, include_subdomains=True)
			self.assertEqual(cm.exception.status, 400, bad)
		self.assertFalse(HostExclusion.objects.exists())

	def test_it_needs_an_organization_level_role(self):
		with self.assertRaises(ApiError) as cm:
			hm.exclude_host(self.ctx(self.proj_user), 'a1', ROOT, include_subdomains=True)
		self.assertEqual(cm.exception.status, 403)
		self.assertFalse(HostExclusion.objects.exists())


class AddTargetsExclusionTests(WholeDomainTests):
	def test_a_minus_line_excludes_the_domain_removes_its_hosts_and_targets_and_the_rest_is_added(self):
		self.populate_domain(self.a1)
		out = svc.add_targets(self.ctx(self.admin), 'a1', '-snow.test\nnew.example\n-*.gone.example', discover=False)
		self.assertEqual(out['created_names'], ['new.example'])
		by_pattern = {e['pattern']: e for e in out['excluded']}
		self.assertEqual(set(by_pattern), {ROOT, 'gone.example'})
		self.assertEqual((by_pattern[ROOT]['hosts_removed'], by_pattern[ROOT]['targets_removed'], by_pattern[ROOT]['findings_removed']), (3, 1, 3))
		self.assertEqual(out['invalid'], [])
		self.assertEqual(self.remaining(self.a1)['subs'], sorted(LOOKALIKES))
		self.assertEqual(sorted(HostExclusion.objects.values_list('host', flat=True)), ['gone.example', ROOT])

	def test_only_exclusions_is_a_valid_paste(self):
		self.populate_domain(self.a1)
		out = svc.add_targets(self.ctx(self.admin), 'a1', ['-snow.test'], discover=False)
		self.assertEqual((out['created'], [e['pattern'] for e in out['excluded']]), (0, [ROOT]))
		with self.assertRaises(ApiError):
			svc.add_targets(self.ctx(self.admin), 'a1', '   ', discover=False)

	def test_lines_that_cannot_be_applied_are_reported_and_the_rest_still_runs(self):
		out = svc.add_targets(self.ctx(self.admin), 'a1', '-com\nok.example', discover=False)
		self.assertEqual(out['created_names'], ['ok.example'])
		self.assertEqual([i['value'] for i in out['invalid']], ['-com'])
		out = svc.add_targets(self.ctx(self.proj_user), 'a1', '-snow.test\nfine.example', discover=False)
		self.assertEqual(out['created_names'], ['fine.example'])
		self.assertIn('organization-level role', out['invalid'][0]['error'])
		self.assertFalse(HostExclusion.objects.exists())

	def test_the_grouped_paste_and_the_rest_api_take_minus_lines_too(self):
		self.populate_domain(self.a1)
		out = svc.add_targets_by_org(self.ctx(self.admin), '##A\n#A1\n-snow.test\nzzz.example\n', discover=False)
		self.assertEqual(out['projects'][0]['created'], 1)
		self.assertEqual([e['pattern'] for e in out['projects'][0]['excluded']], [ROOT])
		_, raw = create_token(self.admin, 'rest')
		status, body = call(raw, 'POST', '/api/v1/projects/a2/targets/bulk', {'text': '-other.test\nq.example', 'discover': False})
		self.assertEqual(status, 201, body)
		self.assertEqual([e['pattern'] for e in body['excluded']], ['other.test'])
		self.assertTrue(HostExclusion.objects.filter(host='other.test', include_subdomains=True).exists())

	def test_normalize_keeps_the_minus(self):
		self.assertEqual(svc.normalize_target('-Example.COM'), '-example.com')
		self.assertEqual(svc.normalize_target('-https://www.example.com/x'), '-www.example.com')
		self.assertEqual(svc.normalize_target('-*.example.com'), '-example.com')  # a wildcard means the same: the domain and what is under it
		self.assertEqual(svc.normalize_target('--example.com'), '')
		self.assertEqual(svc.parse_target_list('a.example, -b.example -c.example'), ['a.example', '-b.example', '-c.example'])


class SameHostNamesTests(Base):
	"""The Hosts page shows names on the same addresses as ONE host: removing only the name on display lets the next name take its place."""

	def three_names(self):
		return [self.sub(self.a1, name, ip='198.51.100.7') for name in ('ist-a.example', 'ist-bb.example', 'ist-ccc.example')]

	def shown(self):
		return [h['host'] for h in svc.list_hosts(self.ctx(self.admin), 'a1', {})['results'] if h['host'].startswith('ist-')]

	def test_excluding_the_name_on_display_alone_leaves_the_host_listed_under_another_name(self):
		self.three_names()
		self.assertEqual(self.shown(), ['ist-a.example'])
		hm.exclude_host(self.ctx(self.admin), 'a1', 'ist-a.example')
		self.assertEqual(self.shown(), ['ist-bb.example'])  # this is what looked like "Remove & exclude does nothing"

	def test_with_aliases_the_whole_host_goes_and_every_name_is_excluded(self):
		self.three_names()
		out = hm.exclude_host(self.ctx(self.admin), 'a1', 'ist-a.example', with_aliases=True)
		self.assertEqual(out['names'], ['ist-a.example', 'ist-bb.example', 'ist-ccc.example'])
		self.assertEqual(out['hosts_removed'], 3)
		self.assertEqual(self.shown(), [])
		self.assertEqual(sorted(HostExclusion.objects.values_list('host', flat=True)), out['names'])

	def test_delete_host_data_can_take_the_aliases_too(self):
		self.three_names()
		out = hm.delete_host(self.ctx(self.admin), 'a1', 'ist-a.example', with_aliases=True)
		self.assertEqual(out['hosts'], 3)
		self.assertEqual(self.shown(), [])
		self.assertFalse(HostExclusion.objects.exists())  # deleted, not excluded
		self.three_names()
		hm.delete_host(self.ctx(self.admin), 'a1', 'ist-a.example')
		self.assertEqual(self.shown(), ['ist-bb.example'])

	def test_a_name_on_its_own_addresses_is_not_swept_up(self):
		self.three_names()
		self.sub(self.a1, 'ist-other.example', ip='203.0.113.99')
		hm.exclude_host(self.ctx(self.admin), 'a1', 'ist-a.example', with_aliases=True)
		self.assertEqual(self.shown(), ['ist-other.example'])
		self.assertFalse(HostState.objects.exists())

	def test_the_rest_route_and_the_mcp_tool_pass_the_flags(self):
		self.three_names()
		_, raw = create_token(self.admin, 'rest')
		status, body = call(raw, 'POST', '/api/v1/projects/a1/hosts/ist-a.example/exclude', {'with_aliases': True})
		self.assertEqual(status, 200, body)
		self.assertEqual(len(body['names']), 3)
		self.sub(self.a1, 'www.sn2.test')
		status, body = call(raw, 'POST', '/api/v1/projects/a1/hosts/sn2.test/exclude', {'include_subdomains': True})
		self.assertEqual((status, body['hosts_removed']), (200, 1))
