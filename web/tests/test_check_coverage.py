"""Check coverage per host (cveFeed.check_coverage): the registry, the applicability rules, freshness, the REST and MCP field, tenancy and query count.

The rules are tested on plain facts (no database) and on stored hosts through the real host list. A test at the end fails when a ledger kind,
a sweep or a scan stage exists in the code that is neither in the registry nor listed as deliberately excluded."""
import ast
import os
import pathlib
import re
from datetime import timedelta
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth.models import User
from django.db import connection
from django.test import SimpleTestCase, TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import services
from agentapi.auth import create_token
from cveFeed import check_coverage as cc
from cveFeed import ledger
from cveFeed.models import BountyEngagement, BountyProgram, HostState, ProbeObservation, RouteAuth, ServiceRun, TlsCertificate
from dashboard.models import Org, OrgMembership, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanActivity, ScanHistory, Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call, tool_call

NOW = timezone.now()


def port(number, service='', protocol='tcp', product='', extra=None):
	return SimpleNamespace(number=number, service_name=service, protocol=protocol, product=product, extra=extra or {}, state='open')


def facts(name='www.example.test', ports=(), address='203.0.113.10', **kw):
	addresses = kw.pop('addresses', None)
	if addresses is None:
		addresses = [cc.Addr(address, ports=ports)] if address else []
	kw.setdefault('target_name', 'example.test')
	kw.setdefault('target_is_domain', True)
	return cc.HostFacts(name, 1, addresses=addresses, **kw)


def state_of(host, check_id, ev=None, paused=''):
	ev = ev or cc.Evidence(NOW)
	row = {c['id']: c for c in cc.coverage(host, ev, paused=paused)['checks']}[check_id]
	return row['state'], row


def ago(**delta):
	return NOW - timedelta(**delta)


class RegistryTests(SimpleTestCase):
	def test_every_check_has_a_unique_id_a_label_and_a_known_window(self):
		ids = [c.id for c in cc.CHECKS]
		self.assertEqual(len(ids), len(set(ids)))
		for check in cc.CHECKS:
			self.assertTrue(check.label and check.id == check.id.lower(), check.id)
			self.assertGreater(check.ttl_hours(), 0, check.id)
			self.assertTrue(check.kinds or check.stages, f'{check.id} names neither a ledger kind nor a scan stage')
			for kind in check.kinds:
				self.assertIn(kind, ledger.DEFAULT_TTL_HOURS, f'{check.id}: {kind} has no ledger window')

	def test_a_check_with_no_ledger_kind_is_judged_by_its_scan_stage_window(self):
		self.assertEqual(cc.BY_ID['db-exposure'].ttl_hours(), cc.STAGE_TTL_HOURS)
		self.assertEqual(cc.BY_ID['nmap'].ttl_hours(), 7 * 24)
		with mock.patch.dict(os.environ, {'CVENGINE_TTL_NMAP_FAST': '2'}):
			self.assertEqual(cc.BY_ID['nmap'].ttl_hours(), 2)

	def test_exclusions_have_reasons_and_are_not_also_registered(self):
		for section, items in cc.EXCLUDED.items():
			for name, reason in items.items():
				self.assertTrue(len(reason) > 10, f'{section}:{name} needs a reason')
				self.assertNotIn(name, cc.covered(section), f'{section}:{name} is both registered and excluded')


class RegistryCompletenessTests(SimpleTestCase):
	"""A new ledger kind, sweep or scan stage must be added to CHECKS (or to EXCLUDED with its reason) or this fails."""

	ROOT = pathlib.Path(__file__).resolve().parents[1] / 'cveFeed'

	@classmethod
	def sources(cls):
		return {path.stem: ast.parse(path.read_text(encoding='utf-8')) for path in sorted(cls.ROOT.glob('*.py'))}

	@staticmethod
	def constants(tree):
		return {t.id: node.value.value for node in tree.body if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
			and isinstance(node.value.value, str) for t in node.targets if isinstance(t, ast.Name)}

	@staticmethod
	def base(name):
		return re.split(r'[:@{]', name)[0]

	def discovered(self):
		"""``(kinds, sweeps, stages)`` found in the source: ledger calls with a literal or constant name, ``*SERVICE*`` constants of the
		modules that use the ledger, ``sweep_claim`` names and the literal stage name of every ``_stage(...)`` call."""
		trees = self.sources()
		consts = {stem: self.constants(tree) for stem, tree in trees.items()}
		kinds, sweeps, stages = set(), set(), set()
		for stem, tree in trees.items():
			uses_ledger = any(isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == 'ledger' for n in ast.walk(tree))
			if uses_ledger:
				kinds.update(self.base(v) for k, v in consts[stem].items() if 'SERVICE' in k)
			for node in ast.walk(tree):
				if not isinstance(node, ast.Call) or not node.args:
					continue
				func, arg = node.func, node.args[0]
				if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == 'ledger':
					name = None
					if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
						name = arg.value
					elif isinstance(arg, ast.Name) and arg.id in consts[stem]:
						name = consts[stem][arg.id]
					elif isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name) and arg.value.id in consts:
						name = consts[arg.value.id].get(arg.attr)
					elif isinstance(arg, ast.JoinedStr) and arg.values and isinstance(arg.values[0], ast.Constant):
						name = arg.values[0].value
					if name and func.attr in ('record', 'fresh', 'stale_first', 'last_run'):
						kinds.add(self.base(name))
					if name and func.attr == 'sweep_claim':
						sweeps.add(name)
				if isinstance(func, ast.Name) and func.id == '_stage' and len(node.args) >= 3 and isinstance(node.args[2], ast.Constant):
					stages.add(node.args[2].value)
		return kinds, sweeps, stages

	def test_the_scan_sees_the_sources(self):
		kinds, sweeps, stages = self.discovered()
		self.assertIn('nmap-fast', kinds)
		self.assertIn('testssl', sweeps)
		self.assertIn('nmap_scan', stages)

	def test_every_ledger_ttl_kind_is_a_check_or_excluded(self):
		known = cc.covered('kinds') | set(cc.EXCLUDED['kinds'])
		missing = sorted({self.base(k) for k in ledger.DEFAULT_TTL_HOURS} - known)
		self.assertEqual(missing, [], f'ledger kinds with no check in cveFeed/check_coverage.py: {missing}. Add a Check or an EXCLUDED entry with its reason.')

	def test_every_ledger_kind_used_in_the_code_is_a_check_or_excluded(self):
		kinds, _sweeps, _stages = self.discovered()
		missing = sorted(kinds - cc.covered('kinds') - set(cc.EXCLUDED['kinds']))
		self.assertEqual(missing, [], f'ledger kinds used in the code with no check: {missing}. Add a Check or an EXCLUDED entry with its reason.')
		self.assertEqual(sorted(kinds - set(self.base(k) for k in ledger.DEFAULT_TTL_HOURS)), [],
			'a ledger kind without a window in ledger.DEFAULT_TTL_HOURS runs on the 24 hour default unseen: list it there')

	def test_every_sweep_is_a_check_or_excluded(self):
		_kinds, sweeps, _stages = self.discovered()
		missing = sorted(sweeps - cc.covered('sweeps') - set(cc.EXCLUDED['sweeps']))
		self.assertEqual(missing, [], f'sweeps with no check: {missing}. Add a Check (sweeps=...) or an EXCLUDED entry with its reason.')

	def test_every_pipeline_stage_is_a_check_or_excluded(self):
		_kinds, _sweeps, stages = self.discovered()
		missing = sorted(stages - cc.covered('stages') - set(cc.EXCLUDED['stages']))
		self.assertEqual(missing, [], f'scan stages with no check: {missing}. Add a Check (stages=...) or an EXCLUDED entry with its reason.')

	def test_nothing_registered_or_excluded_has_gone_from_the_code(self):
		kinds, sweeps, stages = self.discovered()
		known_kinds = kinds | {self.base(k) for k in ledger.DEFAULT_TTL_HOURS}
		self.assertEqual(sorted(cc.covered('kinds') - known_kinds), [])
		self.assertEqual(sorted(set(cc.EXCLUDED['kinds']) - known_kinds), [])
		self.assertEqual(sorted(set(cc.EXCLUDED['sweeps']) - sweeps), [])
		self.assertEqual(sorted(set(cc.EXCLUDED['stages']) - stages), [])
		self.assertEqual(sorted(cc.covered('sweeps') - sweeps), [])
		stage_names = stages | {'bbot_discovery', 'host_hygiene'}
		self.assertEqual(sorted(cc.covered('stages') - stage_names), [])


class ApplicabilityTests(SimpleTestCase):
	"""Only checks that apply to the host are counted."""

	def test_a_host_with_no_tls_port_is_not_counted_against_the_tls_audit(self):
		plain = facts(ports=[port(80, 'http')])
		for check in ('tls-audit', 'certificates'):
			self.assertEqual(state_of(plain, check)[0], 'not_applicable', check)
		tls = facts(ports=[port(80, 'http'), port(443, 'https')])
		for check in ('tls-audit', 'certificates'):
			self.assertEqual(state_of(tls, check)[0], 'due', check)

	def test_a_mail_port_is_tls_for_the_audit_only(self):
		smtp = facts(ports=[port(587, 'smtp')])
		self.assertEqual(state_of(smtp, 'tls-audit')[0], 'due')
		self.assertEqual(state_of(smtp, 'certificates')[0], 'not_applicable')

	def test_a_host_with_no_port_data_is_counted_for_tls_only_when_its_own_url_is_https(self):
		self.assertEqual(state_of(facts(ports=[], http_url='https://www.example.test/'), 'tls-audit')[0], 'due')
		self.assertEqual(state_of(facts(ports=[], http_url='http://www.example.test/'), 'tls-audit')[0], 'not_applicable')
		self.assertEqual(state_of(facts(ports=[]), 'tls-audit')[0], 'not_applicable')

	def test_a_non_wordpress_host_is_not_counted_against_wpscan(self):
		host = facts(ports=[port(443, 'https')])
		for check in ('wpscan', 'wpscan-thorough'):
			self.assertEqual(state_of(host, check)[0], 'not_applicable', check)

	def test_wordpress_signs_make_wpscan_apply_and_a_negative_probe_does_not(self):
		def row(probe, outcome='found', evidence=None):
			return SimpleNamespace(probe=probe, outcome=outcome, evidence=evidence or {}, source='x', version='', observed_at=NOW)
		signals = facts(probe_rows=[row('wordpress-signals', evidence={'signals': ['tech']})])
		self.assertEqual(state_of(signals, 'wpscan')[0], 'due')
		self.assertEqual(state_of(signals, 'wpscan-thorough')[0], 'not_applicable')  # waits for the quick pass
		scanned = facts(probe_rows=[row('wpscan', evidence={'state': 'scanned'})])
		self.assertEqual(state_of(scanned, 'wpscan-thorough')[0], 'due')
		absent = facts(probe_rows=[row('wordpress-detect', 'absent')])
		self.assertEqual(state_of(absent, 'wpscan')[0], 'not_applicable')

	def test_a_host_that_is_not_web_is_not_counted_against_the_web_checks(self):
		host = facts(ports=[port(22, 'ssh')])
		for check in ('web-routes', 'waf', 'wp-detect', 'subapps', 'vhost'):
			self.assertEqual(state_of(host, check)[0], 'not_applicable', check)
		web = facts(ports=[port(443, 'https')], web_bases=['https://www.example.test'], http_up=True)
		for check in ('web-routes', 'waf', 'wp-detect', 'subapps', 'vhost'):
			self.assertEqual(state_of(web, check)[0], 'due', check)

	def test_udp_counts_only_the_addresses_it_would_scan(self):
		public = facts(address='203.0.113.10')
		self.assertEqual(state_of(public, 'udp')[0], 'due')
		for address in ('10.1.2.3', '127.0.0.1', '169.254.169.254'):
			self.assertEqual(state_of(facts(address=address), 'udp')[0], 'not_applicable', address)
		self.assertEqual(state_of(facts(address=None), 'udp')[0], 'not_applicable')
		cdn = facts(addresses=[cc.Addr('203.0.113.11', is_cdn=True)])
		self.assertEqual(state_of(cdn, 'udp')[0], 'not_applicable')
		shared = facts(shared_platform=True)
		self.assertEqual(state_of(shared, 'udp')[0], 'not_applicable')
		ev = cc.Evidence(NOW)
		ev.blocked = {1}
		state, row = state_of(public, 'udp', ev)
		self.assertEqual(state, 'not_applicable')
		self.assertIn('bug bounty', row['detail'])

	def test_a_bug_bounty_blocked_project_is_kept_out_of_the_background_sweeps_only(self):
		ev = cc.Evidence(NOW)
		ev.blocked = {1}
		host = facts(ports=[port(443, 'https')], web_bases=['https://www.example.test'], http_up=True)
		for check in ('vhost', 'subapps', 'tls-audit', 'udp'):
			self.assertEqual(state_of(host, check, ev)[0], 'not_applicable', check)
		for check in ('nmap', 'nuclei', 'web-routes', 'certificates'):
			self.assertEqual(state_of(host, check, ev)[0], 'due', check)

	def test_switches_make_a_check_not_apply(self):
		host = facts(ports=[port(443, 'https')])
		for variable, check in (('CVENGINE_NAABU', 'naabu'), ('CVENGINE_FULLSCAN', 'full-ports'), ('CVENGINE_UDPSCAN', 'udp')):
			self.assertEqual(state_of(host, check)[0], 'due', check)
			with mock.patch.dict(os.environ, {variable: '0'}):
				self.assertEqual(state_of(host, check)[0], 'not_applicable', check)
		web = facts(web_bases=['https://www.example.test'], http_up=True)
		with mock.patch.dict(os.environ, {'CVENGINE_WAFW00F': '0', 'CVENGINE_VHOST': '0', 'CVENGINE_SUBDIR_APPS': '0'}):
			for check in ('waf', 'vhost', 'subapps'):
				self.assertEqual(state_of(facts(ports=[port(443, 'https')], web_bases=web.web_bases, http_up=True), check)[0], 'not_applicable', check)

	def test_node2shell_is_opt_in_and_only_for_node_runtimes(self):
		node = facts(techs={'Express'}, web_bases=['https://www.example.test'], http_up=True)
		self.assertEqual(state_of(node, 'node2shell')[0], 'not_applicable')  # off by default
		with mock.patch.dict(os.environ, {'CVENGINE_NODE2SHELL': '1'}):
			self.assertEqual(state_of(node, 'node2shell')[0], 'due')
			self.assertEqual(state_of(facts(techs={'nginx'}, web_bases=['https://www.example.test'], http_up=True), 'node2shell')[0], 'not_applicable')
			with mock.patch.dict(os.environ, {'CVENGINE_NODE2SHELL_SCOPE': 'all'}):
				self.assertEqual(state_of(facts(techs={'nginx'}, http_up=True), 'node2shell')[0], 'due')
			named = facts(root=SimpleNamespace(evidence={'fingerprint_names': ['Next.js']}))
			self.assertEqual(state_of(named, 'node2shell')[0], 'due')

	def test_rdp_screenshot_only_for_rdp_that_accepts_a_connection_without_nla(self):
		nla = port(3389, 'ms-wbt-server', extra={'scripts': {'rdp-enum-encryption': 'CredSSP (NLA): SUCCESS'}})
		weak = port(3389, 'ms-wbt-server', extra={'scripts': {'rdp-enum-encryption': 'Security layer\n    CredSSP (NLA): SUCCESS\n    RDP: SUCCESS'}})
		self.assertEqual(state_of(facts(ports=[nla]), 'rdp-screenshot')[0], 'not_applicable')
		self.assertEqual(state_of(facts(ports=[weak]), 'rdp-screenshot')[0], 'due')

	def test_database_check_only_for_a_database_port(self):
		self.assertEqual(state_of(facts(ports=[port(80, 'http')]), 'db-exposure')[0], 'not_applicable')
		self.assertEqual(state_of(facts(ports=[port(6379, 'redis')]), 'db-exposure')[0], 'due')

	def test_target_level_checks_count_on_the_target_only(self):
		sub = facts(name='www.example.test')
		target = facts(name='example.test')
		for check in ('discovery', 'ct-watch', 'archive-urls', 'email-auth'):
			self.assertEqual(state_of(sub, check)[0], 'not_applicable', check)
			self.assertEqual(state_of(target, check)[0], 'due', check)
		apex = facts(name='example.com', target_name='example.com')
		self.assertEqual(state_of(apex, 'deep-discovery')[0], 'due')
		self.assertEqual(state_of(facts(name='www.example.com', target_name='www.example.com'), 'deep-discovery')[0], 'not_applicable')
		ip_target = facts(name='203.0.113.10', target_name='203.0.113.10', target_is_domain=False)
		self.assertEqual(state_of(ip_target, 'discovery')[0], 'not_applicable')
		shared = facts(name='acme.jfrog.com', target_name='acme.jfrog.com')
		self.assertEqual(state_of(shared, 'deep-discovery')[0], 'not_applicable')  # a tenant of a provider domain has no ownable apex
		self.assertEqual(state_of(facts(name='a.example.co.uk', target_name='a.example.co.uk'), 'deep-discovery')[0], 'not_applicable')  # not its own apex

	def test_nuclei_cve_tests_count_per_fire_or_smoke_match(self):
		self.assertEqual(state_of(facts(), 'nuclei-cve')[0], 'not_applicable')
		host = facts(hot_cves=['CVE-2099-1', 'CVE-2099-2'])
		ev = cc.Evidence(NOW)
		ev.add_ledger('nuclei-cve:CVE-2099-1:abcdef0123', 1, host.name, ago(hours=2))
		state, row = state_of(host, 'nuclei-cve', ev)
		self.assertEqual((state, row['detail']), ('due', '1 of 2 covered'))
		ev.add_ledger('nuclei-cve:CVE-2099-2:abcdef0123', 1, host.name, ago(hours=3))
		self.assertEqual(state_of(host, 'nuclei-cve', ev)[0], 'done')

	def test_a_name_pointing_at_an_internal_address_is_no_scan_target(self):
		inside = facts(address='10.0.0.5')
		for check in ('nuclei', 'nuclei-tech', 'nuclei-deep'):
			self.assertEqual(state_of(inside, check)[0], 'not_applicable', check)
		self.assertEqual(state_of(facts(address='203.0.113.10'), 'nuclei')[0], 'due')
		self.assertEqual(state_of(facts(address=None), 'nuclei')[0], 'due')  # a name with no address is still a nuclei target

	def test_version_probes_apply_only_to_a_host_with_an_unversioned_product(self):
		self.assertEqual(state_of(facts(unversioned=0), 'version-probes')[0], 'not_applicable')
		self.assertEqual(state_of(facts(unversioned=2), 'version-probes')[0], 'due')

	def test_openvas_applies_only_to_a_host_a_project_opted_in(self):
		host = facts()
		self.assertEqual(state_of(host, 'openvas')[0], 'not_applicable')
		ev = cc.Evidence(NOW)
		ev.openvas = {1: {'other.example.test'}}
		self.assertEqual(state_of(host, 'openvas', ev)[0], 'not_applicable')
		ev.openvas = {1: {host.name}}
		self.assertEqual(state_of(host, 'openvas', ev)[0], 'due')

	def test_excluded_and_archived_hosts_have_no_applicable_check(self):
		host = facts(ports=[port(443, 'https')], web_bases=['https://www.example.test'], http_up=True)
		host.excluded = True
		out = cc.coverage(host, cc.Evidence(NOW))
		self.assertEqual((out['done'], out['applicable'], out['paused']), (0, 0, 'excluded'))
		host.excluded = False
		ev = cc.Evidence(NOW)
		ev.archived = {(1, host.name)}
		out = cc.coverage(host, ev)
		self.assertEqual((out['applicable'], out['paused']), (0, 'archived'))
		self.assertTrue(all(c['state'] == 'not_applicable' for c in out['checks']))


class FreshnessTests(SimpleTestCase):
	def test_done_inside_the_window_due_outside_it_and_when_never_run(self):
		host = facts()
		ev = cc.Evidence(NOW)
		self.assertEqual(state_of(host, 'nmap', ev)[1]['detail'], 'never run')
		ev.add_ledger('nmap-fast', 1, '203.0.113.10', ago(days=6))
		state, row = state_of(host, 'nmap', ev)
		self.assertEqual((state, row['last_run'], row['ttl_hours']), ('done', ago(days=6).isoformat(), 168))
		ev = cc.Evidence(NOW)
		ev.add_ledger('nmap-fast', 1, '203.0.113.10', ago(days=9))
		state, row = state_of(host, 'nmap', ev)
		self.assertEqual(state, 'due')
		self.assertIn('last run 9 days ago, repeats every 7 days', row['detail'])

	def test_the_ttl_override_of_the_ledger_applies(self):
		host = facts()
		ev = cc.Evidence(NOW)
		ev.add_ledger('nmap-fast', 1, '203.0.113.10', ago(hours=5))
		with mock.patch.dict(os.environ, {'CVENGINE_TTL_NMAP_FAST': '2'}):
			self.assertEqual(state_of(host, 'nmap', ev)[0], 'due')
		self.assertEqual(state_of(host, 'nmap', ev)[0], 'done')

	def test_a_failed_run_is_not_done_and_says_so(self):
		host = facts()
		ev = cc.Evidence(NOW)
		ev.add_ledger('nmap-fast', 1, '203.0.113.10', ago(hours=1), status='failed')
		state, row = state_of(host, 'nmap', ev)
		self.assertEqual((state, row['detail']), ('due', 'the last attempt failed'))
		ev.add_ledger('nmap-fast', 1, '203.0.113.10', ago(hours=3))  # an older success is still inside the window
		self.assertEqual(state_of(host, 'nmap', ev)[0], 'done')

	def test_a_retry_kind_is_a_failure_not_a_run(self):
		host = facts(ports=[port(443, 'https')])
		ev = cc.Evidence(NOW)
		ev.add_ledger('testssl-failed', 1, 'www.example.test:443', ago(hours=1))
		self.assertEqual(state_of(host, 'tls-audit', ev)[0], 'due')
		ev.add_ledger('testssl', 1, 'www.example.test:443', ago(days=3))
		self.assertEqual(state_of(host, 'tls-audit', ev)[0], 'done')

	def test_a_revisioned_service_counts_under_its_kind(self):
		host = facts()
		ev = cc.Evidence(NOW)
		ev.add_ledger('nuclei:cve,nginx:rev123', 1, host.name, ago(hours=3))
		self.assertEqual(state_of(host, 'nuclei', ev)[0], 'done')

	def test_every_address_of_a_host_must_be_covered(self):
		host = facts(addresses=[cc.Addr('203.0.113.10'), cc.Addr('203.0.113.11')])
		ev = cc.Evidence(NOW)
		ev.add_ledger('nmap-fast', 1, '203.0.113.10', ago(days=1))
		state, row = state_of(host, 'nmap', ev)
		self.assertEqual((state, row['detail']), ('due', '1 of 2 covered'))
		ev.add_ledger('nmap-fast', 1, '203.0.113.11', ago(days=2))
		self.assertEqual(state_of(host, 'nmap', ev)[0], 'done')

	def test_the_full_port_sweep_reads_the_address_row(self):
		host = facts(addresses=[cc.Addr('203.0.113.10', full_scanned_at=ago(days=13))])
		self.assertEqual(state_of(host, 'full-ports')[0], 'done')
		host = facts(addresses=[cc.Addr('203.0.113.10', full_scanned_at=ago(days=15))])
		self.assertEqual(state_of(host, 'full-ports')[0], 'due')
		self.assertEqual(state_of(facts(addresses=[cc.Addr('203.0.113.10')]), 'full-ports')[0], 'due')

	def test_a_stage_only_check_reads_the_scan_stage(self):
		host = facts(ports=[port(6379, 'redis')], scan_id=7)
		ev = cc.Evidence(NOW)
		ev.stages[(7, 'db_exposure_scan')] = [(2, ago(days=2))]
		self.assertEqual(state_of(host, 'db-exposure', ev)[0], 'done')
		ev.stages[(7, 'db_exposure_scan')] = [(0, ago(days=2))]  # the stage failed
		self.assertEqual(state_of(host, 'db-exposure', ev)[0], 'due')
		ev.stages[(7, 'db_exposure_scan')] = [(2, ago(days=9))]
		self.assertEqual(state_of(host, 'db-exposure', ev)[0], 'due')
		self.assertEqual(state_of(facts(ports=[port(6379, 'redis')]), 'db-exposure')[1]['detail'], 'never run')

	def test_the_totals_count_only_applicable_checks(self):
		host = facts(ports=[port(80, 'http')])
		ev = cc.Evidence(NOW)
		ev.add_ledger('nmap-fast', 1, '203.0.113.10', ago(hours=1))
		out = cc.coverage(host, ev)
		applicable = [c for c in out['checks'] if c['state'] != 'not_applicable']
		self.assertEqual(out['applicable'], len(applicable))
		self.assertEqual(out['done'], sum(c['state'] == 'done' for c in out['checks']))
		self.assertEqual(out['done'], 1)
		self.assertLess(out['applicable'], len(cc.CHECKS))

	def test_the_single_host_view_names_what_each_check_was_judged_on(self):
		host = facts(addresses=[cc.Addr('203.0.113.10'), cc.Addr('203.0.113.11')])
		ev = cc.Evidence(NOW)
		ev.add_ledger('nmap-fast', 1, '203.0.113.10', ago(days=1))
		rows = {c['id']: c for c in cc.coverage(host, ev, rich=True)['checks']}
		self.assertEqual([(u['unit'], u['state']) for u in rows['nmap']['units']], [('203.0.113.10', 'done'), ('203.0.113.11', 'due')])
		self.assertNotIn('units', {c['id']: c for c in cc.coverage(host, ev)['checks']}['nmap'])


class StoredHostTests(TestCase):
	"""The field on real hosts, through the host list, the REST API and MCP; tenancy and the query count."""

	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		cls.org_a, cls.org_b = Org.objects.create(name='A', slug='cov-a'), Org.objects.create(name='B', slug='cov-b')
		cls.pa = Project.objects.create(name='A', slug='cov-pa', insert_date=now, org=cls.org_a)
		cls.pb = Project.objects.create(name='B', slug='cov-pb', insert_date=now, org=cls.org_b)
		cls.da = Domain.objects.create(name='alpha.example.test', project=cls.pa, insert_date=now)
		cls.db = Domain.objects.create(name='beta.example.test', project=cls.pb, insert_date=now)
		engine = EngineType.objects.create(engine_name='cov', yaml_configuration='x')
		cls.scan_a = ScanHistory.objects.create(start_scan_date=now, scan_status=2, domain=cls.da, scan_type=engine)
		cls.scan_b = ScanHistory.objects.create(start_scan_date=now, scan_status=2, domain=cls.db, scan_type=engine)
		cls.member = User.objects.create_user('cov-member', password='x')
		cls.outsider = User.objects.create_user('cov-outsider', password='x')
		ProjectMembership.objects.create(user=cls.member, project=cls.pa, role='user')
		OrgMembership.objects.create(user=cls.outsider, org=cls.org_b, role='admin')
		_, cls.token = create_token(cls.member, 'cov')
		_, cls.outside_token = create_token(cls.outsider, 'cov-out')
		_, cls.superuser_token = create_token(User.objects.create_user('cov-root', password='x', is_superuser=True), 'cov-root')
		cls.www = cls.host(cls.da, cls.scan_a, 'www.alpha.example.test', '203.0.113.20', [(443, 'https'), (22, 'ssh')])
		cls.target = cls.host(cls.da, cls.scan_a, 'alpha.example.test', '203.0.113.21', [(80, 'http')])
		# the same host name in the other project, with a finished run there: it must never show in the first project
		cls.theirs = cls.host(cls.db, cls.scan_b, 'www.alpha.example.test', '203.0.113.20', [(443, 'https')])
		ServiceRun.objects.create(service='nmap-fast', asset='203.0.113.20', project=cls.pb, status='done', finished_at=now)
		ServiceRun.objects.create(service='nuclei:rev1', asset='www.alpha.example.test', project=cls.pb, status='done', finished_at=now)

	@classmethod
	def host(cls, domain, scan, name, address, ports):
		sub = Subdomain.objects.create(name=name, target_domain=domain, scan_history=scan, http_status=200, http_url=f'https://{name}/')
		ip = IpAddress.objects.get_or_create(address=address)[0]
		for number, service in ports:
			ip.ports.add(Port.objects.create(number=number, service_name=service, state='open'))
		sub.ip_addresses.add(ip)
		return sub

	def rows(self, token=None, project='cov-pa'):
		status, data = call(token or self.token, 'GET', f'/api/v1/projects/{project}/hosts')
		self.assertEqual(status, 200, data)
		return {h['host']: h for h in data['results']}

	def check(self, host, check_id):
		return {c['id']: c for c in host['check_coverage']['checks']}[check_id]

	def coverage_cost(self, project, token=None):
		"""The queries the check coverage adds to the host list: the list with it, less the list without it (the rest of the host record has
		its own cost, which is not what is measured here)."""
		def queries():
			with CaptureQueriesContext(connection) as ctx:
				status, data = call(token or self.token, 'GET', f'/api/v1/projects/{project}/hosts')
			self.assertEqual(status, 200, data)
			return ctx, data
		queries()  # the first request of a user does its own one-off work (preferences, token use)
		with_it, data = queries()
		self.assertTrue(all('check_coverage' in h for h in data['results']))
		with mock.patch.object(services, '_coverage_for', return_value=None):
			without, _ = queries()
		return len(with_it) - len(without)

	def test_the_host_record_carries_the_field(self):
		now = timezone.now()
		ServiceRun.objects.create(service='nmap-fast', asset='203.0.113.20', project=self.pa, status='done', finished_at=now - timedelta(days=1))
		ServiceRun.objects.create(service='nuclei:cve,nginx:rev9', asset='www.alpha.example.test', project=self.pa, status='done', finished_at=now)
		ServiceRun.objects.create(service='testssl', asset='www.alpha.example.test:443', project=self.pa, status='done', finished_at=now - timedelta(days=20))
		RouteAuth.objects.create(project=self.pa, domain=self.da, host='www.alpha.example.test', url='https://www.alpha.example.test/', path='/',
			auth_state='open', checked_at=now - timedelta(days=1))
		TlsCertificate.objects.create(domain=self.da, host='www.alpha.example.test', port=443)
		ScanActivity.objects.create(scan_of=self.scan_a, title='cve', name='cve_correlation', time=now, status=2)
		rows = self.rows()
		www = rows['www.alpha.example.test']
		coverage = www['check_coverage']
		self.assertEqual(set(coverage), {'done', 'applicable', 'paused', 'checks'})
		self.assertEqual(coverage['paused'], '')
		self.assertEqual(coverage['done'], sum(c['state'] == 'done' for c in coverage['checks']))
		self.assertEqual(coverage['applicable'], sum(c['state'] != 'not_applicable' for c in coverage['checks']))
		self.assertEqual(set(self.check(www, 'nmap')), {'id', 'label', 'state', 'last_run', 'ttl_hours', 'detail'})
		self.assertEqual(self.check(www, 'nmap')['state'], 'done')
		self.assertEqual(self.check(www, 'nuclei')['state'], 'done')
		self.assertEqual(self.check(www, 'tls-audit')['state'], 'due')  # tested 20 days ago, window 14 days
		self.assertEqual(self.check(www, 'web-routes')['state'], 'done')
		self.assertEqual(self.check(www, 'certificates')['state'], 'done')
		self.assertEqual(self.check(www, 'cve-correlation')['state'], 'done')
		self.assertEqual(self.check(www, 'naabu')['state'], 'due')
		self.assertEqual(self.check(www, 'discovery')['state'], 'not_applicable')  # runs on the target, not under it
		self.assertEqual(self.check(rows['alpha.example.test'], 'discovery')['state'], 'due')
		self.assertEqual(self.check(rows['alpha.example.test'], 'tls-audit')['state'], 'not_applicable')  # no TLS port: only 80

	def test_runs_recorded_under_host_pipe_assets_are_read_inside_their_window(self):
		now = timezone.now()
		name = 'www.alpha.example.test'
		ServiceRun.objects.create(service='subapp', asset=f'{name}|https://{name}', project=self.pa, status='done', finished_at=now - timedelta(days=2))
		ServiceRun.objects.create(service='vhost', asset='203.0.113.20|other.alpha.example.test', project=self.pa, status='done',
			finished_at=now - timedelta(days=1))
		ServiceRun.objects.create(service='vhost', asset='203.0.113.20|elsewhere.alpha.example.test', project=self.pb, status='done', finished_at=now)
		www = self.rows()[name]
		self.assertEqual(self.check(www, 'subapps')['state'], 'done')
		self.assertEqual(self.check(www, 'vhost')['state'], 'done')
		other = self.rows()['alpha.example.test']
		self.assertEqual(self.check(other, 'subapps')['state'], 'due')
		self.assertEqual(self.check(other, 'subapps')['detail'], 'no run inside its window')
		ServiceRun.objects.filter(service='subapp').update(finished_at=now - timedelta(days=20))
		www = self.rows()[name]
		self.assertEqual((self.check(www, 'subapps')['state'], self.check(www, 'subapps')['detail']), ('due', 'no run inside its window'))
		theirs = self.rows(self.outside_token, 'cov-pb')[name]
		self.assertEqual(self.check(theirs, 'vhost')['state'], 'done')  # their own row, not ours

	def test_another_projects_runs_never_count(self):
		www = self.rows()['www.alpha.example.test']
		self.assertEqual(self.check(www, 'nmap')['state'], 'due')
		self.assertIsNone(self.check(www, 'nmap')['last_run'])
		self.assertEqual(self.check(www, 'nuclei')['state'], 'due')
		theirs = self.rows(self.outside_token, 'cov-pb')['www.alpha.example.test']
		self.assertEqual(self.check(theirs, 'nmap')['state'], 'done')
		self.assertEqual(self.check(theirs, 'nuclei')['state'], 'done')

	def test_a_member_sees_their_own_project_only_and_another_organization_gets_nothing(self):
		status, data = call(self.token, 'GET', '/api/v1/projects/cov-pb/hosts')
		self.assertEqual(status, 404)
		self.assertNotIn('check_coverage', str(data))
		status, data = call(self.outside_token, 'GET', '/api/v1/projects/cov-pa/hosts')
		self.assertEqual(status, 404)
		status, data = call(self.token, 'GET', '/api/v1/projects/_all/hosts')
		self.assertEqual(status, 200)
		self.assertEqual({h['project'] for h in data['results']}, {'cov-pa'})
		for h in data['results']:
			self.assertIn('check_coverage', h)
		status, data = call(self.outside_token, 'GET', '/api/v1/projects/_all/search?q=alpha')
		self.assertEqual({h['project'] for h in data['results']}, {'cov-pb'})

	def test_search_and_mcp_carry_it_too(self):
		status, data = call(self.token, 'GET', '/api/v1/projects/cov-pa/search?q=www')
		self.assertEqual(status, 200)
		self.assertIn('check_coverage', data['results'][0])
		is_error, listed = tool_call(self.token, 'list_hosts', {'project': 'cov-pa'})
		self.assertFalse(is_error)
		self.assertTrue(all('check_coverage' in h for h in listed['results']))
		is_error, found = tool_call(self.token, 'search_hosts', {'project': 'cov-pa', 'q': 'www'})
		self.assertFalse(is_error)
		self.assertEqual(found['results'][0]['host'], 'www.alpha.example.test')
		self.assertEqual({c['id'] for c in found['results'][0]['check_coverage']['checks']}, {c.id for c in cc.CHECKS})
		is_error, _ = tool_call(self.outside_token, 'list_hosts', {'project': 'cov-pa'})
		self.assertTrue(is_error)

	def test_the_single_host_view_is_richer(self):
		host = services.host_group(self.pa, self.www)
		nmap = self.check(host, 'nmap')
		self.assertEqual([u['unit'] for u in nmap['units']], ['203.0.113.20'])
		listed = self.rows()['www.alpha.example.test']
		self.assertNotIn('units', self.check(listed, 'nmap'))

	def test_an_excluded_or_archived_host_is_paused(self):
		HostState.objects.create(project=self.pa, domain=self.da, host='alpha.example.test', archived_at=timezone.now())
		rows = self.rows()
		self.assertEqual(rows['alpha.example.test']['check_coverage']['paused'], 'archived')
		self.assertEqual(rows['alpha.example.test']['check_coverage']['applicable'], 0)
		self.assertNotEqual(rows['www.alpha.example.test']['check_coverage']['applicable'], 0)

	def test_bug_bounty_blocked_project_keeps_the_sweeps_out(self):
		self.assertEqual(self.check(self.rows()['www.alpha.example.test'], 'tls-audit')['state'], 'due')
		program = BountyProgram.objects.create(platform='hackerone', handle='cov', name='Program')
		engagement = BountyEngagement.objects.create(project=self.pa, program=program, status='active', automated_ok=False)
		www = self.rows()['www.alpha.example.test']
		self.assertEqual(self.check(www, 'tls-audit')['state'], 'not_applicable')
		self.assertEqual(self.check(www, 'nmap')['state'], 'due')
		engagement.automated_ok, engagement.policy_ack_at = True, timezone.now()  # the owner confirmed the program allows automated testing
		engagement.save()
		self.assertEqual(self.check(self.rows()['www.alpha.example.test'], 'tls-audit')['state'], 'due')

	def test_the_report_rows_do_not_carry_it(self):
		page = services._hosts_page(self.pa, Subdomain.objects.filter(pk=self.www.pk), {}, coverage=False)
		self.assertNotIn('check_coverage', page['results'][0])

	def test_a_failing_rule_never_breaks_the_host_list(self):
		with mock.patch.object(cc, 'coverage', side_effect=RuntimeError('boom')):
			rows = self.rows()
		self.assertIsNone(rows['www.alpha.example.test']['check_coverage'])
		self.assertEqual(rows['www.alpha.example.test']['host'], 'www.alpha.example.test')

	def test_the_host_list_costs_no_query_per_host_or_per_check(self):
		small = self.coverage_cost('cov-pa')
		now = timezone.now()
		for i in range(12):
			sub = self.host(self.da, self.scan_a, f'h{i}.alpha.example.test', f'203.0.113.{100 + i}', [(443, 'https'), (6379, 'redis'), (3389, 'ms-wbt-server')])
			ServiceRun.objects.create(service='nmap-fast', asset=f'203.0.113.{100 + i}', project=self.pa, status='done', finished_at=now)
			ServiceRun.objects.create(service='probe', asset=f'{sub.name}|wordpress-detect|https://{sub.name}', project=self.pa, status='done', finished_at=now)
			ProbeObservation.objects.create(project=self.pa, domain=self.da, host=sub.name, probe='wordpress-signals', kind='wordpress',
				product='WordPress', outcome='found', evidence={'signals': ['tech']})
			RouteAuth.objects.create(project=self.pa, domain=self.da, host=sub.name, url=f'https://{sub.name}/', path='/', auth_state='open')
			TlsCertificate.objects.create(domain=self.da, host=sub.name, port=443)
		big = self.coverage_cost('cov-pa')
		self.assertEqual(big, small, 'the check coverage must not issue queries per host or per check')
		self.assertLessEqual(big, 12)

	def test_all_projects_view_costs_the_same_however_many_hosts(self):
		small = self.coverage_cost('_all')
		for i in range(8):
			self.host(self.da, self.scan_a, f'm{i}.alpha.example.test', f'203.0.113.{150 + i}', [(443, 'https')])
			self.host(self.db, self.scan_b, f'n{i}.beta.example.test', f'203.0.113.{170 + i}', [(443, 'https')])
		self.assertEqual(self.coverage_cost('_all', token=self.superuser_token), small)


class SignedInTests(TestCase):
	def test_a_stored_sign_in_makes_the_authenticated_passes_apply(self):
		from cveFeed import auth_checks
		from cveFeed.models import AuthCredential
		now = timezone.now()
		org = Org.objects.create(name='S', slug='cov-s')
		project = Project.objects.create(name='S', slug='cov-ps', insert_date=now, org=org)
		domain = Domain.objects.create(name='signed.example.test', project=project, insert_date=now)
		cred = AuthCredential.objects.create(project=project, domain=domain, host='', label='tester', origins=['https:443'],
			secret={'headers': [['X-Test', 'v']]})
		ev = cc.Evidence(now)
		ev.credentials = {project.id: [cred]}
		host = cc.HostFacts('app.signed.example.test', project.id, target_name='signed.example.test', target_is_domain=True,
			addresses=[cc.Addr('203.0.113.9')])
		self.assertEqual(state_of(host, 'nuclei-signed-in', ev)[0], 'due')
		self.assertEqual(state_of(host, 'routes-signed-in', ev)[0], 'due')
		ev.signed[('route-auth-signed', project.id, host.name, auth_checks.revision(cred))] = [('route-auth-signed', 'done', now)]
		self.assertEqual(state_of(host, 'routes-signed-in', ev)[0], 'done')
		self.assertEqual(state_of(host, 'nuclei-signed-in', ev)[0], 'due')
		other = cc.HostFacts('other.example.org', project.id, target_name='other.example.org', target_is_domain=True)
		self.assertEqual(state_of(other, 'nuclei-signed-in', ev)[0], 'not_applicable')
		cred.expires_at = now - timedelta(days=1)
		self.assertEqual(state_of(host, 'nuclei-signed-in', ev)[0], 'not_applicable')
