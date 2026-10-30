import datetime
import os
import tempfile
import unittest
from unittest import mock

import yaml

from django.test import TestCase
from django.utils import timezone

from cveFeed import ledger, nuclei_scan, templategen, triage, validation
from cveFeed.models import CVEEntry, CVEMatch, GeneratedTemplate, ServiceRun, Triage
from dashboard.models import Org, Project
from reNgine import resources
from startScan.models import IpAddress, Port, Subdomain, Vulnerability
from targetApp.models import Domain

GET_TEMPLATE = """
id: cve-2099-1
info: {name: x, severity: high, tags: cve-2099-1}
http:
  - path: ["{{BaseURL}}/version"]
    method: GET
    matchers-condition: and
    matchers:
      - type: word
        words: ["nginx/1.18.0"]
      - type: status
        status: [200]
"""


RAW_TEMPLATE = """id: cve-2099-1
info: {name: x, severity: high}
http:
  - raw:
      - |
        GET /x HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: word
        words: [x]
"""


class AllTemplatesSettingTests(TestCase):
	"""Settings > Scan engines can let every installed Nuclei template run (the default); off, only read-only ones do."""
	def setUp(self):
		from dashboard.models import ScanPolicy
		ScanPolicy.objects.create(nuclei_all_templates=False)  # these tests start from the restricted policy and switch it on

	def library(self, directory):
		with open(os.path.join(directory, 'safe.yaml'), 'w') as output:
			output.write(GET_TEMPLATE)
		with open(os.path.join(directory, 'write.yaml'), 'w') as output:
			output.write(GET_TEMPLATE.replace('method: GET', 'method: POST'))

	def test_the_snapshot_follows_the_setting_without_waiting_for_the_cache(self):
		import shutil
		from dashboard.models import ScanPolicy
		with tempfile.TemporaryDirectory() as directory:
			self.library(directory)
			with mock.patch.object(templategen, 'TEMPLATES_ROOT', directory), mock.patch.dict(nuclei_scan._APPROVED,
				{'root': None, 'at': 0, 'value': None}), mock.patch.object(nuclei_scan, '_report_policy'):
				snapshots = []
				try:
					snapshots.append(nuclei_scan.approved_templates())
					self.assertEqual(snapshots[0][2], 1)
					ScanPolicy.objects.update(nuclei_all_templates=True)
					snapshots.append(nuclei_scan.approved_templates())
					self.assertEqual(snapshots[1][2], 2)
					self.assertTrue(os.path.isfile(os.path.join(snapshots[1][0], 'write.yaml')))
					self.assertNotEqual(snapshots[0][1], snapshots[1][1])
					ScanPolicy.objects.update(nuclei_all_templates=False)
					self.assertEqual(nuclei_scan.approved_templates()[2], 1)
				finally:
					for snapshot in snapshots:
						shutil.rmtree(snapshot[0], ignore_errors=True)
					for path, _ in nuclei_scan._APPROVED.get('retained', []):
						shutil.rmtree(path, ignore_errors=True)

	def test_a_template_that_is_not_read_only_runs_for_validation_only_when_allowed(self):
		from dashboard.models import ScanPolicy
		with tempfile.TemporaryDirectory() as directory:
			self.library(directory)
			path = os.path.join(directory, 'write.yaml')
			with mock.patch.object(templategen, 'TEMPLATES_ROOT', directory):
				self.assertIn('not read-only', validation.approved_template(path)[1])
				ScanPolicy.objects.update(nuclei_all_templates=True)
				text, problem = validation.approved_template(path)
				self.assertEqual(problem, '')
				self.assertIn('POST', text)

	def test_the_coverage_key_changes_with_the_setting(self):
		from dashboard.models import ScanPolicy
		with tempfile.TemporaryDirectory() as directory:
			self.library(directory)
			with mock.patch.object(templategen, 'TEMPLATES_ROOT', directory), mock.patch('cveFeed.validation.resolve_template',
				return_value=(os.path.join(directory, 'safe.yaml'), '')):
				before = nuclei_scan.cve_service('CVE-2099-1')
				ScanPolicy.objects.update(nuclei_all_templates=True)
				self.assertNotEqual(nuclei_scan.cve_service('CVE-2099-1'), before)

	def test_a_database_error_leaves_the_read_only_policy_in_force(self):
		with mock.patch('dashboard.models.ScanPolicy.current', side_effect=RuntimeError('db down')):
			self.assertFalse(validation.all_templates_allowed())


class ReadOnlyTemplateTests(unittest.TestCase):
	@mock.patch('cveFeed.validation.all_templates_allowed', return_value=False)  # the restricted policy an App Admin can choose
	def test_broad_pass_uses_snapshot_of_only_approved_templates(self, _restricted):
		import shutil
		with tempfile.TemporaryDirectory() as directory:
			with open(os.path.join(directory, 'safe.yaml'), 'w') as output:
				output.write(GET_TEMPLATE)
			with open(os.path.join(directory, 'write.yaml'), 'w') as output:
				output.write(GET_TEMPLATE.replace('method: GET', 'method: POST'))
			with mock.patch.object(templategen, 'TEMPLATES_ROOT', directory), mock.patch.dict(nuclei_scan._APPROVED,
				{'root': None, 'at': 0, 'value': None}), mock.patch.object(nuclei_scan, '_report_policy') as report:
				approved, revision, count = nuclei_scan.approved_templates()
				self.assertEqual(report.call_args.args[1:3], (1, {'http method POST is not read-only': 1}))
				try:
					self.assertEqual(count, 1)
					self.assertTrue(os.path.isfile(os.path.join(approved, 'safe.yaml')))
					self.assertFalse(os.path.exists(os.path.join(approved, 'write.yaml')))
					self.assertIn('-ni', nuclei_scan.build_flags(templates_dir=approved))
				finally:
					shutil.rmtree(approved, ignore_errors=True)

	def test_broad_nuclei_process_failure_is_not_a_clean_scan(self):
		import io
		class Job:
			def __enter__(self): return self
			def __exit__(self, *args): return False
			def attach(self, proc): pass
			def raise_if_killed(self): pass
		class Process:
			stdout = io.StringIO('')
			returncode = 2
			def poll(self): return self.returncode
			def wait(self): return self.returncode
		with tempfile.NamedTemporaryFile('w') as targets:
			targets.write('www.example.test\n')
			targets.flush()
			with mock.patch.object(nuclei_scan, 'approved_templates', return_value=('/tmp/approved', 'revision', 1)), \
					mock.patch('reNgine.resources.heavy_job', return_value=Job()), \
					mock.patch.object(nuclei_scan.subprocess, 'Popen', return_value=Process()):
				with self.assertRaisesRegex(RuntimeError, 'exited with status 2'):
					list(nuclei_scan.stream_nuclei(targets.name, timeout=1))

	def run_stream(self, returncode, stderr_text, stdout=''):
		import io
		class Job:
			def __enter__(self): return self
			def __exit__(self, *args): return False
			def attach(self, proc): pass
			def raise_if_killed(self): pass
		class Process:
			def __init__(self, stderr):
				stderr.write(stderr_text)
				self.stdout, self.returncode = io.StringIO(stdout), returncode
			def poll(self): return self.returncode
			def wait(self): return self.returncode
		with tempfile.NamedTemporaryFile('w') as targets:
			targets.write('www.example.test\n')
			targets.flush()
			with mock.patch.object(nuclei_scan, 'approved_templates', return_value=('/tmp/approved', 'revision', 1)), \
					mock.patch('reNgine.resources.heavy_job', return_value=Job()), \
					mock.patch.object(nuclei_scan.subprocess, 'Popen', side_effect=lambda *a, **kw: Process(kw['stderr'])):
				return list(nuclei_scan.stream_nuclei(targets.name, timeout=1, tags=['wordpress']))

	def test_a_failed_nuclei_run_says_why(self):
		with self.assertLogs('cveFeed.nuclei_scan', 'ERROR'), \
				self.assertRaisesRegex(RuntimeError, r'status 1: \[FTL\] Could not create runner: bad flag'):
			self.run_stream(1, '\x1b[31m[FTL]\x1b[0m Could not create runner: bad flag\n')

	def test_no_approved_template_for_the_tags_is_an_empty_run_not_a_failure(self):
		self.assertEqual(self.run_stream(1, '[FTL] Could not run nuclei: no templates provided for scan\n'), [])
		with self.assertRaises(RuntimeError):  # results then a fatal exit is still a failure
			self.run_stream(1, '[FTL] Could not run nuclei: no templates provided for scan\n', stdout='{"host": "x"}\n')

	def test_policy_report_logs_an_excluded_essential_template_as_failed_once_per_revision(self):
		from django.core.cache import cache
		cache.delete('cvengine:nuclei-policy-logged:rev-a')
		with mock.patch('cveFeed.activity.log') as log, self.assertLogs('cveFeed.nuclei_scan', 'ERROR'):
			nuclei_scan._report_policy('rev-a', 10, {"forbidden key 'host-redirects'": 4},
									   {'http/technologies/tech-detect.yaml': "forbidden key 'host-redirects'"})
			nuclei_scan._report_policy('rev-a', 10, {"forbidden key 'host-redirects'": 4},
									   {'http/technologies/tech-detect.yaml': "forbidden key 'host-redirects'"})
		log.assert_called_once()
		self.assertEqual(log.call_args.kwargs['status'], 'failed')
		self.assertIn('tech-detect.yaml', log.call_args.args[1])
		self.assertIn('approved 10 of 14', log.call_args.args[1])
		cache.delete('cvengine:nuclei-policy-logged:rev-b')
		with mock.patch('cveFeed.activity.log') as log:
			nuclei_scan._report_policy('rev-b', 10, {'x': 1}, {})
		self.assertEqual(log.call_args.kwargs['status'], 'done')

	def test_broad_nuclei_malformed_output_is_not_clean(self):
		import io
		class Job:
			def __enter__(self): return self
			def __exit__(self, *args): return False
			def attach(self, proc): pass
			def raise_if_killed(self): pass
		class Process:
			returncode = 0
			def __init__(self): self.stdout = io.StringIO('{broken\n')
			def poll(self): return 0
			def wait(self): return 0
		with tempfile.NamedTemporaryFile('w') as targets:
			targets.write('www.example.test\n')
			targets.flush()
			with mock.patch.object(nuclei_scan, 'approved_templates', return_value=('/tmp/approved', 'revision', 1)), \
					mock.patch('reNgine.resources.heavy_job', return_value=Job()), \
					mock.patch.object(nuclei_scan.subprocess, 'Popen', return_value=Process()):
				with self.assertRaisesRegex(RuntimeError, 'malformed JSON'):
					list(nuclei_scan.stream_nuclei(targets.name, timeout=1))
	def test_template_revision_changes_coverage_keys(self):
		with tempfile.TemporaryDirectory() as directory:
			path = os.path.join(directory, 'cve.yaml')
			with open(path, 'w') as output:
				output.write(GET_TEMPLATE)
			with mock.patch('cveFeed.validation.resolve_template', return_value=(path, '')):
				first = nuclei_scan.cve_service('CVE-2099-1')
				with open(path, 'w') as output:
					output.write(GET_TEMPLATE.replace('/version', '/version2'))
				self.assertNotEqual(first, nuclei_scan.cve_service('CVE-2099-1'))
				check1 = validation.plan_checks({'kind': 'cve_match', 'host': 'www.v.test', 'cve_id': 'CVE-2099-1', 'source': 'tech'}, 'a' * 40, (path, ''))[0][0]
				with open(path, 'w') as output:
					output.write(GET_TEMPLATE.replace('/version', '/version3'))
				check2 = validation.plan_checks({'kind': 'cve_match', 'host': 'www.v.test', 'cve_id': 'CVE-2099-1', 'source': 'tech'}, 'a' * 40, (path, ''))[0][0]
				self.assertNotEqual(check1['service'], check2['service'])
	def test_plain_reads_pass(self):
		self.assertEqual(validation.readonly_problem(GET_TEMPLATE), '')
		head = GET_TEMPLATE.replace('method: GET', 'method: HEAD')
		self.assertEqual(validation.readonly_problem(head), '')
		self.assertEqual(validation.readonly_problem(GET_TEMPLATE.replace('    method: GET\n', '')), '')  # GET is the default

	def test_state_changing_templates_are_refused(self):
		for method in ('POST', 'PUT', 'DELETE', 'PATCH'):
			problem = validation.readonly_problem(GET_TEMPLATE.replace('method: GET', f'method: {method}'))
			self.assertTrue(problem.startswith('template not validated'), method)
		raw = RAW_TEMPLATE.replace('GET /x', 'POST /x')
		self.assertIn('raw request method POST', validation.readonly_problem(raw))
		ok_raw = RAW_TEMPLATE
		self.assertEqual(validation.readonly_problem(ok_raw), '')

	def test_payloads_bodies_code_and_out_of_band_are_refused(self):
		for extra in ('    payloads: {x: [1, 2]}\n', '    attack: clusterbomb\n', '    body: "a=b"\n', '    fuzzing: [{part: query}]\n',
					  '    headless: []\n'):
			self.assertIn('not validated', validation.readonly_problem(GET_TEMPLATE.replace('    method: GET\n', '    method: GET\n' + extra)), extra)
		self.assertIn('out-of-band', validation.readonly_problem(GET_TEMPLATE + '\n# {{interactsh-url}}\n'))
		self.assertIn('not validated', validation.readonly_problem('id: x\nhttp: [1]\ncode: []\n'))
		net = 'id: x\nnetwork:\n  - host: ["{{Hostname}}"]\n    inputs:\n      - data: "EVIL"\n'
		self.assertIn('outgoing data', validation.readonly_problem(net))
		self.assertEqual(validation.readonly_problem('id: x\nnetwork:\n  - host: ["{{Hostname}}"]\n    read-size: 64\n'), '')
		for bad in ('', ':::', '- a list'):
			self.assertIn('not validated', validation.readonly_problem(bad))

	def with_redirects(self, *lines):
		return GET_TEMPLATE.replace('    method: GET\n', '    method: GET\n' + ''.join(f'    {line}\n' for line in lines))

	def test_same_host_redirects_pass_and_other_hosts_do_not(self):
		for lines in (('host-redirects: true', 'max-redirects: 2'), ('host-redirects: false',), ('redirects: false', 'max-redirects: 0'),
					  ('host-redirects: true', 'max-redirects: 3')):
			self.assertEqual(validation.readonly_problem(self.with_redirects(*lines)), '', lines)
		for lines, reason in ((('redirects: true',), 'other hosts'), (('host-redirects: true', 'max-redirects: 4'), 'max-redirects'),
							  (('max-redirects: true',), 'max-redirects'), (('host-redirects: yes please',), 'true or false'),
							  (('redirects: true', 'host-redirects: true'), 'other hosts')):
			self.assertIn(reason, validation.readonly_problem(self.with_redirects(*lines)), lines)
		# the AI-written template gate still allows no redirect at all
		doc = yaml.safe_load(self.with_redirects('host-redirects: true'))
		self.assertIn('host-redirects', templategen.destination_check(doc))

	def test_detecting_an_interactsh_server_is_in_band_but_fetching_one_is_not(self):
		tech = GET_TEMPLATE.replace('words: ["nginx/1.18.0"]', 'part: header\n        words: ["X-Interactsh-Version"]')
		self.assertEqual(validation.readonly_problem(tech), '')
		for evidence in ('{{interactsh-url}}', 'interactsh_protocol', 'Interactsh Server', 'oast'):
			self.assertIn('out-of-band', validation.readonly_problem(GET_TEMPLATE.replace('nginx/1.18.0', evidence)), evidence)


class PlanTests(unittest.TestCase):
	SIG = 'a' * 40

	def plan(self, **subject):
		subject = {'kind': 'cve_match', 'host': 'www.v.test', 'cve_id': 'CVE-2099-1', 'source': 'port', 'ip': '203.0.113.7', 'port': 443, **subject}
		return validation.plan_checks(subject, self.SIG, subject.pop('template', ('', '')))

	def test_a_port_match_gets_nmap_and_a_template_when_one_is_valid(self):
		checks, notes = validation.plan_checks({'kind': 'cve_match', 'host': 'www.v.test', 'cve_id': 'CVE-2099-1', 'source': 'port',
												'ip': '203.0.113.7', 'port': 443}, self.SIG, ('/t/cve-2099-1.yaml', ''))
		self.assertEqual([c['kind'] for c in checks], ['nuclei_template', 'nmap_sv'])
		nmap = checks[1]
		self.assertEqual(nmap['argv'], ['nmap', '-sV', '--version-intensity', '5', '-Pn', '-p', '443', '--host-timeout', '60s', '-oX', '-', '203.0.113.7'])
		self.assertEqual(nmap['display'], 'nmap -sV --version-intensity 5 -Pn -p 443 --host-timeout 60s -oX - 203.0.113.7')
		self.assertTrue(nmap['service'].startswith(f'validate:nmap_sv:{"a" * 16}:'))
		self.assertIn('-ni', checks[0]['argv'])
		self.assertIn('-retries', checks[0]['argv'])

	def test_only_the_four_kinds_with_allowlisted_argv_exist(self):
		subjects = [{'kind': 'cve_match', 'host': 'www.v.test', 'cve_id': 'CVE-1', 'source': 'port', 'ip': '203.0.113.7', 'port': 80},
					{'kind': 'cve_match', 'host': 'www.v.test', 'cve_id': 'CVE-1', 'source': 'tech', 'url': 'https://www.v.test/'},
					{'kind': 'db_exposure', 'host': 'www.v.test', 'ip': '203.0.113.7', 'port': 6379, 'db': 'redis'},
					{'kind': 'route_auth', 'host': 'www.v.test', 'url': 'https://www.v.test/admin'}]
		for subject in subjects:
			checks, _ = validation.plan_checks(subject, self.SIG, ('/t/x.yaml', ''))
			for check in checks:
				self.assertIn(check['kind'], validation.CHECK_KINDS)
				flat = ' ' + ' '.join(check['argv'] + ([] if check['kind'] == 'db_probe' else [check['display']])).lower() + ' '
				for forbidden in (' -h ', '--header', ' -d ', '--data', ' -x ', 'payload', 'sh -c', '|bash', ' -b ', '--cookie'):
					self.assertNotIn(forbidden, flat)
				if check['kind'] == 'http_head':
					self.assertEqual(check['argv'][:3], ['curl', '-I', '-k'])
				if check['kind'] == 'nmap_sv':
					self.assertEqual(check['argv'][0], 'nmap')
					self.assertIn('-sV', check['argv'])

	def test_no_template_and_no_port_means_no_check(self):
		self.assertEqual(validation.plan_checks({'kind': 'cve_match', 'host': 'www.v.test', 'cve_id': 'CVE-1', 'source': 'tech', 'url': None},
												self.SIG, ('', 'no template covers this CVE')), ([], []))

	def test_technology_match_uses_only_observed_valid_inventory_ports(self):
		checks, _ = validation.plan_checks({'kind': 'cve_match', 'host': 'www.v.test', 'cve_id': 'CVE-1', 'source': 'tech',
			'candidate_services': [{'ip': '203.0.113.7', 'port': 443}, {'ip': '203.0.113.7', 'port': 443},
				{'ip': '--script=unsafe', 'port': 80}, {'ip': '203.0.113.8', 'port': 0}]}, self.SIG)
		self.assertEqual([check['kind'] for check in checks], ['nmap_sv'])
		self.assertEqual(checks[0]['target'], '203.0.113.7:443')

	def test_a_refused_template_is_noted_not_planned(self):
		checks, notes = validation.plan_checks({'kind': 'cve_match', 'host': 'www.v.test', 'cve_id': 'CVE-1', 'source': 'tech', 'url': None},
											   self.SIG, ('', 'template not validated: http method POST is not read-only'))
		self.assertEqual((checks, notes), ([], ['template not validated: http method POST is not read-only']))

	def test_a_host_or_address_that_could_be_an_option_is_never_planned(self):
		checks, _ = validation.plan_checks({'kind': 'cve_match', 'host': '-oN', 'cve_id': 'CVE-1', 'source': 'port', 'ip': '--script=x', 'port': 80},
										   self.SIG, ('/t/x.yaml', ''))
		self.assertEqual(checks, [])
		checks, _ = validation.plan_checks({'kind': 'route_auth', 'host': 'x', 'url': 'file:///etc/passwd'}, self.SIG)
		self.assertEqual([c for c in checks if c], [])

	def test_db_probe_shows_the_equivalent_command(self):
		checks, _ = validation.plan_checks({'kind': 'db_exposure', 'host': 'www.v.test', 'ip': '203.0.113.7', 'port': 6379, 'db': 'redis'}, self.SIG)
		probe = checks[0]
		self.assertEqual((probe['kind'], probe['display']), ('db_probe', 'redis-cli -h 203.0.113.7 -p 6379 PING'))
		self.assertTrue(probe['params']['equivalent'])

	def test_interpret(self):
		subject = {'kind': 'cve_match', 'product': 'nginx', 'matched_version': '1.18.0', 'range': {'introduced': '1.0.0', 'fixed': '1.20.0'}}
		seen = {'status': 'observed', 'summary': 'x', 'observed': {'product': 'nginx', 'version': '1.18.2'}}
		self.assertEqual(validation.interpret(subject, {}, seen)['status'], 'reaffirmed')
		seen['observed']['version'] = '1.24.0'
		self.assertEqual(validation.interpret(subject, {}, seen)['status'], 'version_changed')
		seen['observed'] = {'product': 'apache', 'version': '2.4.1'}  # another product: no judgement
		self.assertEqual(validation.interpret(subject, {}, seen)['status'], 'observed')
		route = {'kind': 'route_auth'}
		self.assertEqual(validation.interpret(route, {}, {'status': 'observed', 'summary': 'x', 'http': {'status': 200}})['status'], 'reaffirmed')
		self.assertEqual(validation.interpret(route, {}, {'status': 'observed', 'summary': 'x', 'http': {'status': 404}})['status'], 'no_match')

	def test_interpret_requires_the_same_identified_product(self):
		for product, observed in (('ingress-nginx', 'nginx'), ('nginx', 'ingress-nginx'),
				('phpMyAdmin', 'php'), ('php', 'phpMyAdmin'), ('nginx', ''), ('', 'nginx'),
				('Apache HTTP Server', 'Oracle HTTP Server'), ('WAF', 'WAF')):
			for version in ('1.5.0', '3.0.0'):
				with self.subTest(product=product, observed=observed, version=version):
					subject = {'kind': 'cve_match', 'product': product, 'range': {'introduced': '1.0', 'fixed': '2.0'}}
					seen = {'status': 'observed', 'summary': 'x', 'observed': {'product': observed, 'version': version}}
					self.assertEqual(validation.interpret(subject, {}, seen)['status'], 'observed')

	def test_interpret_accepts_product_aliases_and_vendor_names(self):
		# the second part: product strings nmap really prints, with words the advisory's product name does not have
		for product, observed in (('nginx', 'NGINX'), ('Apache HTTP Server', 'Apache httpd'),
				('HTTP Server', 'Apache'), ('OpenSSH', 'OpenSSH server'),
				('tomcat', 'Apache Tomcat/Coyote JSP engine'), ('express', 'Node.js Express framework'), ('esxi', 'VMware ESXi SOAP API'),
				('internet_information_services', 'Microsoft IIS httpd'), ('sql_server', 'Microsoft SQL Server 2019'), ('weblogic_server', 'Oracle WebLogic Server')):
			with self.subTest(product=product, observed=observed):
				subject = {'kind': 'cve_match', 'product': product, 'range': {'introduced': '1.0', 'fixed': '2.0'}}
				seen = {'status': 'observed', 'summary': 'x', 'observed': {'product': observed, 'version': '1.5.0'}}
				self.assertEqual(validation.interpret(subject, {}, seen)['status'], 'reaffirmed')
				seen['observed']['version'] = '3.0.0'
				self.assertEqual(validation.interpret(subject, {}, seen)['status'], 'version_changed')

	def test_rollup_never_calls_a_failure_clean(self):
		r = validation.rollup
		self.assertEqual(r([]), 'none')
		self.assertEqual(r([{'result': 'no_match'}]), 'clean')
		self.assertEqual(r([{'result': 'no_match'}, {'result': 'failed'}]), 'failed')
		self.assertEqual(r([{'result': 'failed'}, {'result': 'hit'}]), 'hit')
		self.assertEqual(r([{'result': 'blocked'}]), 'skipped_blocked')
		self.assertEqual(r([{'result': 'observed'}]), 'observed')
		self.assertEqual(r([{'result': 'reaffirmed'}]), 'observed')


class TemplateResolutionTests(TestCase):
	def setUp(self):
		from dashboard.models import ScanPolicy
		ScanPolicy.objects.create(nuclei_all_templates=False)  # the restricted policy: only read-only templates run
		self.installed, self.generated = tempfile.mkdtemp(), tempfile.mkdtemp()
		patches = [mock.patch.object(templategen, 'TEMPLATES_ROOT', self.installed), mock.patch.object(templategen, 'GENERATED_DIR', self.generated)]
		for p in patches:
			p.start()
			self.addCleanup(p.stop)
		templategen.invalidate_template_index()
		self.addCleanup(templategen.invalidate_template_index)
		self.cve = CVEEntry.objects.create(cve_id='CVE-2099-1', published_at=timezone.now())

	def write(self, root, name, text):
		path = os.path.join(root, name)
		with open(path, 'w') as f:
			f.write(text)
		templategen.invalidate_template_index()
		return path

	def test_an_installed_read_only_template_is_used(self):
		path = self.write(self.installed, 'CVE-2099-1.yaml', GET_TEMPLATE)
		self.assertEqual(validation.resolve_template('CVE-2099-1'), (path, ''))

	def test_an_installed_post_template_is_refused(self):
		self.write(self.installed, 'CVE-2099-1.yaml', GET_TEMPLATE.replace('method: GET', 'method: POST'))
		path, reason = validation.resolve_template('CVE-2099-1')
		self.assertEqual(path, '')
		self.assertIn('POST', reason)

	def test_a_generated_template_needs_a_valid_row_and_the_gate(self):
		path = self.write(self.generated, 'cve-2099-1.yaml', GET_TEMPLATE)
		self.assertEqual(validation.resolve_template('CVE-2099-1')[0], '')  # no row at all
		row = GeneratedTemplate.objects.create(cve_entry=self.cve, template_id='cve-2099-1', yaml=GET_TEMPLATE, status='draft', path=path)
		self.assertEqual(validation.resolve_template('CVE-2099-1')[0], '')
		row.status = 'invalid'
		row.save()
		self.assertEqual(validation.resolve_template('CVE-2099-1')[0], '')
		row.status = 'valid'
		row.save()
		self.assertEqual(validation.resolve_template('CVE-2099-1')[0], '')  # older syntax-only approvals cannot run
		row.positive_fixture_verified_at = timezone.now()
		row.positive_fixture_source = 'controlled independent test fixture'
		row.save()
		self.assertEqual(validation.resolve_template('CVE-2099-1'), (path, ''))
		self.write(self.generated, 'cve-2099-1.yaml', GET_TEMPLATE.replace('/version', '/changed'))
		self.assertEqual(validation.resolve_template('CVE-2099-1')[0], '')  # approved YAML changed on disk
		self.write(self.generated, 'cve-2099-1.yaml', GET_TEMPLATE.replace('method: GET', 'method: POST'))  # edited after it was validated
		path_after, reason = validation.resolve_template('CVE-2099-1')
		self.assertEqual(path_after, '')
		self.assertIn('not validated', reason)

	def test_nothing_covers_the_cve(self):
		self.assertEqual(validation.resolve_template('CVE-2099-1'), ('', 'no template covers this CVE'))


def hit(host='www.v.test'):
	return {'host': host, 'matched-at': f'https://{host}/version', 'matcher-name': 'version', 'request': 'GET /version HTTP/1.1\r\nHost: x',
			'response': 'HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n', 'extracted-results': ['nginx/1.18.0']}


class ValidationBase(TestCase):
	def setUp(self):
		org = Org.objects.create(name='V', slug='v')
		self.project = Project.objects.create(name='P', slug='pv', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='v.test', project=self.project, insert_date=timezone.now())
		self.cve = CVEEntry.objects.create(cve_id='CVE-2099-1', kev=True, cvss=9.8, published_at=timezone.now(),
										   affected=[{'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}])
		for patched in (mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False),
						mock.patch('targetApp.target_types.is_scannable_ip', return_value=True),
						mock.patch('cveFeed.activity.log', return_value=None),
						mock.patch('cveFeed.notify._send', return_value=False)):
			patched.start()
			self.addCleanup(patched.stop)

	def match(self, name='www.v.test', version='1.18.0', in_range=True, port=443, source='port', cve=None, **kw):
		sub = Subdomain.objects.create(name=name, target_domain=self.domain)
		return CVEMatch.objects.create(
			cve_entry=cve or self.cve, subdomain=sub, matched_product='nginx', matched_version=version, version_in_range=in_range, source=source,
			evidence={'ip': '203.0.113.7', 'port': port, 'range': {'introduced': '1.0.0', 'fixed': '1.20.0'}}, **kw)

	def rows(self, **kw):
		findings = triage.with_cves(CVEMatch.objects.select_related('subdomain__target_domain'))
		pairs = triage.track(findings)
		triage.run_triage(pairs, provider=None)  # no AI: validation does not need one
		return list(Triage.objects.all())

	def runners(self, status='no_match', **extra):
		calls = []

		def make(kind):
			def run(check):
				calls.append((kind, check['target']))
				if status == 'raise':
					raise RuntimeError('boom')
				if status == 'timeout':
					import subprocess
					raise subprocess.TimeoutExpired('nmap', 1)
				return {'status': status, 'summary': f'{kind} said {status}', 'outcome': {'host': 'www.v.test', 'vulnerable': status == 'hit', 'hit': hit()},
						'evidence': {'request': 'GET', 'response': 'HTTP 200'}, **extra}
			return run
		return {k: make(k) for k in validation.CHECK_KINDS}, calls

	def template(self, cve_id):
		return ('/t/cve-2099-1.yaml', '')

	def run_validation(self, rows=None, **kw):
		runners, calls = kw.pop('runners', None) or self.runners()
		rows = rows if rows is not None else Triage.objects.all()
		template_for = kw.pop('template_for', self.template)
		stats = validation.run_validation(self.project.id, [r.pk for r in rows], runners=runners, template_for=template_for, **kw)
		return stats, calls


class ApplyValidationTests(ValidationBase):
	def check(self, kind='nuclei_template'):
		argv = ['nuclei', '-t', '/t/cve-2099-1.yaml', '-u', 'www.v.test', '-ni']
		return validation._check(kind, 'nuclei template for CVE-2099-1', argv, ' '.join(argv), 'www.v.test', 'www.v.test', 'b' * 40, 180,
								 template='/t/cve-2099-1.yaml')

	def prepared(self, **kw):
		m = self.match(**kw)
		(row,) = self.rows()
		return m, row

	def test_a_hit_confirms_records_the_finding_and_the_template_result(self):
		m, row = self.prepared()
		self.assertEqual((row.classification, row.validation_status), ('', 'none'))  # not triaged: no provider
		self.assertEqual(row.status, 'not_triaged')
		from cveFeed.templategen import _host_key
		result = validation._result_from_outcome({'host': 'www.v.test', 'vulnerable': True, 'hit': hit(), 'output': '{}'})
		validation.apply_validation(row, self.check(), result)
		row.refresh_from_db()
		m.refresh_from_db()
		self.assertEqual((row.classification, row.validation_status, m.template_result, m.ai_verdict), ('confirmed', 'hit', 'vulnerable', 'affected'))
		vuln = Vulnerability.objects.get()
		self.assertEqual((vuln.source, vuln.subdomain_id), ('nuclei-cve', m.subdomain_id))
		self.assertIn('CVE-2099-1', [c.name for c in vuln.cve_ids.all()])
		self.assertEqual(row.validation_evidence['nuclei_template']['matcher_name'], 'version')
		self.assertIn('GET /version', row.validation_evidence['nuclei_template']['request'])
		self.assertEqual(row.validation_steps[0]['display'], self.check()['display'])
		self.assertEqual(row.validation_steps[0]['result'], 'hit')
		# the signature moved with the evidence: the next triage run keeps the confirmation instead of resetting it
		again = triage.track(triage.with_cves(CVEMatch.objects.select_related('subdomain__target_domain')))
		row.refresh_from_db()
		self.assertEqual((row.classification, row.validation_status), ('confirmed', 'hit'))

	def test_a_hit_under_an_explicit_fresh_review_survives_the_next_track(self):
		# Validate now and automatic validation put a nonce on the row first; the hit must not be reset by the track() that follows
		m, row = self.prepared()
		row.review_nonce = 'request-91'
		row.save(update_fields=['review_nonce'])
		row, _ = triage.track(triage.with_cves(CVEMatch.objects.select_related('subdomain__target_domain')))[0]
		result = validation._result_from_outcome({'host': 'www.v.test', 'vulnerable': True, 'hit': hit(), 'output': '{}'})
		validation.apply_validation(row, self.check(), result)
		triage.track(triage.with_cves(CVEMatch.objects.select_related('subdomain__target_domain')))
		row.refresh_from_db()
		m.refresh_from_db()
		self.assertEqual((row.classification, row.validation_status, m.ai_verdict), ('confirmed', 'hit', 'affected'))
		self.assertIn('nuclei_template', row.validation_evidence)
		self.assertEqual(row.validation_steps[0]['result'], 'hit')

	def test_a_hit_with_an_ai_verdict_asks_again_for_the_new_evidence_but_stays_confirmed(self):
		m, row = self.prepared()
		provider = mock.Mock(model='m')
		provider.name = 'anthropic'
		provider.complete.return_value = '{"classification": "likely_false_positive", "reason": "no"}'
		triage.run_triage(triage.track(triage.with_cves(CVEMatch.objects.select_related('subdomain__target_domain'))), provider=provider)
		row.refresh_from_db()
		self.assertEqual(row.classification, 'needs_validation')
		validation.apply_validation(row, self.check(), validation._result_from_outcome({'host': 'www.v.test', 'vulnerable': True, 'hit': hit()}))
		row.refresh_from_db()
		self.assertEqual((row.classification, row.status, row.verdict_id), ('confirmed', 'pending', None))
		triage.run_triage(triage.track(triage.with_cves(CVEMatch.objects.select_related('subdomain__target_domain'))), provider=provider)
		row.refresh_from_db()
		self.assertEqual((row.classification, row.status), ('confirmed', 'triaged'))

	def test_a_clean_run_never_lowers_a_hard_evidence_finding(self):
		m, row = self.prepared()
		provider = mock.Mock(model='m')
		provider.name = 'anthropic'
		provider.complete.return_value = '{"classification": "likely_false_positive", "reason": "no"}'
		triage.run_triage(triage.track(triage.with_cves(CVEMatch.objects.select_related('subdomain__target_domain'))), provider=provider)
		row.refresh_from_db()
		self.assertEqual(row.classification, 'needs_validation')  # in range: the floor
		validation.apply_validation(row, self.check(), {'status': 'no_match', 'summary': 'the template did not match'})
		row.refresh_from_db()
		self.assertEqual((row.classification, row.validation_status, row.confidence_adjust), ('needs_validation', 'clean', -0.2))
		self.assertIn('the hard evidence', row.reason)
		self.assertIn('the version found is inside the affected range', row.reason)
		self.assertIn('did not reproduce it', row.reason)
		self.assertTrue(CVEMatch.objects.filter(pk=m.pk).exists())

	def test_no_result_ever_lowers_a_classification(self):
		m, row = self.prepared()
		for start in triage.ORDER:
			for status in validation.STEP_RESULTS:
				row.classification, row.validation_steps, row.hard_evidence = start, [], ['x']
				result = {'status': status, 'summary': 's', 'outcome': {'host': 'www.v.test', 'vulnerable': False}, 'recorded': True}
				kind = 'nuclei_template' if status != 'hit' else 'nmap_sv'
				validation.apply_validation(row, self.check(kind), result, save=False)
				self.assertGreaterEqual(triage.rank(row.classification), triage.rank(start), (start, status))

	def test_a_failure_is_failed_not_clean_and_is_retried_later(self):
		m, row = self.prepared()
		now = timezone.now()
		validation.apply_validation(row, self.check(), {'status': 'failed', 'error': 'the check timed out', 'summary': 'timed out'}, now=now)
		row.refresh_from_db()
		self.assertEqual((row.validation_status, row.attempts, row.classification), ('failed', 1, ''))
		self.assertEqual(row.next_attempt_at, now + datetime.timedelta(hours=6))
		validation.apply_validation(row, self.check(), {'status': 'failed', 'error': 'x', 'summary': 'x'}, now=now)
		self.assertEqual((row.attempts, row.next_attempt_at), (2, now + datetime.timedelta(hours=12)))
		self.assertEqual(len(row.validation_steps), 1)  # the step for the same check is replaced, not piled up
		self.assertNotEqual(row.validation_status, 'clean')

	def test_a_later_clean_check_keeps_an_earlier_failure_due_for_retry(self):
		_, row = self.prepared()
		now = timezone.now() - datetime.timedelta(hours=7)
		validation.apply_validation(row, self.check('nmap_sv'), {'status': 'failed', 'error': 'timeout', 'summary': 'timed out'}, now=now)
		retry_at = row.next_attempt_at
		validation.apply_validation(row, self.check(), {'status': 'no_match', 'summary': 'the template did not match'},
														 now=now + datetime.timedelta(minutes=1))
		row.refresh_from_db()
		self.assertEqual((row.validation_status, row.attempts, row.next_attempt_at), ('failed', 1, retry_at))
		self.assertIn(row.pk, validation.due_ids(self.project.pk))
		validation.apply_validation(row, self.check('nmap_sv'), {'status': 'no_match', 'summary': 'the service did not match'})
		self.assertEqual((row.validation_status, row.attempts, row.next_attempt_at), ('clean', 0, None))

	def test_a_failed_row_without_a_retry_date_is_recovered_by_the_sweep(self):
		_, row = self.prepared()
		validation.apply_validation(row, self.check(), {'status': 'failed', 'error': 'timeout', 'summary': 'timed out'})
		Triage.objects.filter(pk=row.pk).update(next_attempt_at=None)
		self.assertIn(row.pk, validation.due_ids(self.project.pk))

	def test_a_reaffirmed_version_alone_keeps_a_version_only_match_at_the_ceiling(self):
		"""Reading the same version a second time is not more evidence than reading it once: v1.3.1 lifted such a match to likely, and the next
		triage pass put it back about twelve minutes later (camstork, issue 210)."""
		m, row = self.prepared()
		self.assertTrue(validation._version_only(row))
		row.classification = 'needs_validation'
		validation.apply_validation(row, self.check('nmap_sv'), {'status': 'reaffirmed', 'summary': 'nmap reports nginx 1.18.2'})
		self.assertEqual(row.classification, 'needs_validation')
		row.classification = ''
		validation.apply_validation(row, self.check('nmap_sv'), {'status': 'reaffirmed', 'summary': 'again'})
		self.assertEqual(row.classification, '')  # not triaged: a version reading does not invent a classification

	def test_a_reaffirmed_version_still_raises_a_match_that_has_more_than_the_version(self):
		m, row = self.prepared()
		CVEMatch.objects.filter(pk=m.pk).update(distro_status='vulnerable')  # the distribution's own tracker lists the release as affected
		row.refresh_from_db()
		row.match.refresh_from_db()
		self.assertFalse(validation._version_only(row))
		row.classification = 'needs_validation'
		validation.apply_validation(row, self.check('nmap_sv'), {'status': 'reaffirmed', 'summary': 'nmap reports nginx 1.18.2'})
		self.assertEqual(row.classification, 'likely')

	def test_a_reaffirmed_route_is_not_a_version_match_and_still_raises(self):
		from types import SimpleNamespace
		self.assertFalse(validation._version_only(SimpleNamespace(match_id=None)))  # a route (or any finding that is not a CVE match) has no version to read twice


class RunValidationTests(ValidationBase):
	def test_explicit_fresh_review_nonce_still_runs_its_planned_check(self):
		match = self.match()
		row = self.rows()[0]
		row.review_nonce = 'request-77'
		row.save(update_fields=['review_nonce'])
		row, _ = triage.track([match])[0]
		stats, calls = self.run_validation([row])
		self.assertGreater(stats['ran'], 0)
		self.assertTrue(calls)

	def test_runs_the_planned_checks_without_any_ai_and_a_hit_confirms(self):
		self.match()
		(row,) = self.rows()
		self.assertEqual(row.status, 'not_triaged')
		runners, calls = self.runners('hit')
		stats, _ = self.run_validation(runners=(runners, calls))
		row.refresh_from_db()
		self.assertEqual([c[0] for c in calls], ['nuclei_template', 'nmap_sv'])
		self.assertEqual((stats['ran'], stats['hits']), (2, 1 + 1))
		self.assertEqual((row.classification, row.validation_status), ('confirmed', 'hit'))
		self.assertEqual(len(row.validation_steps), 2)
		self.assertEqual(ServiceRun.objects.filter(service__startswith='validate:').count(), 2)

	def test_a_global_pause_stops_the_run_before_its_next_check(self):
		from cveFeed.models import ScanControl
		self.match()
		self.rows()
		runners, calls = self.runners('no_match')
		first = runners['nuclei_template']

		def pause_after_first(check):
			ScanControl.objects.update_or_create(pk=1, defaults={'paused': True})
			return first(check)
		runners['nuclei_template'] = pause_after_first
		stats, _ = self.run_validation(runners=(runners, calls))
		self.assertTrue(stats['stopped'])
		self.assertEqual([c[0] for c in calls], ['nuclei_template'])  # nmap_sv never started

	def test_a_check_that_crashes_stores_a_diagnostic_not_the_exception_text(self):
		self.match()
		self.rows()
		with self.assertLogs('cveFeed.activity', 'WARNING'):
			self.run_validation(runners=self.runners('raise'))
		row = Triage.objects.get()
		errors = [step.get('error', '') for step in row.validation_steps]
		self.assertTrue(errors and all('diagnostic' in e and 'boom' not in e for e in errors), errors)

	def test_no_check_is_recorded_and_nothing_is_invented(self):
		self.match(source='tech', port=None)
		(row,) = self.rows()
		stats, calls = self.run_validation(template_for=lambda cve_id: ('', 'no template covers this CVE'))
		row.refresh_from_db()
		self.assertEqual(calls, [])
		self.assertEqual((row.validation_status, row.validation_steps, stats['no_check']), ('no_check', [], 1))

	def test_no_check_asks_for_local_checks(self):
		self.match(source='tech', port=None)
		(row,) = self.rows()
		with mock.patch('cveFeed.triage.suggest_local_checks') as suggest:
			self.run_validation(template_for=lambda cve_id: ('', 'no template covers this CVE'))
		self.assertEqual(suggest.call_args[0][0].pk, row.pk)

	def test_a_local_check_suggestion_failure_does_not_break_the_sweep(self):
		self.match(source='tech', port=None)
		self.rows()
		with mock.patch('cveFeed.triage.suggest_local_checks', side_effect=RuntimeError('boom')):
			stats, _ = self.run_validation(template_for=lambda cve_id: ('', 'no template covers this CVE'))
		self.assertEqual(stats['no_check'], 1)  # the sweep's own bookkeeping still completed

	def test_a_blocked_host_is_skipped_and_the_runner_never_called(self):
		self.match()
		(row,) = self.rows()
		runners, calls = self.runners()
		with mock.patch('targetApp.target_types.resolves_to_blocked', return_value=True):
			stats, _ = self.run_validation(runners=(runners, calls))
		row.refresh_from_db()
		self.assertEqual(calls, [])
		self.assertEqual(row.validation_status, 'skipped_blocked')
		self.assertIn('must not be scanned', row.validation_steps[0]['summary'])
		self.assertEqual(stats['blocked'], 2)

	def test_a_blocked_address_is_skipped_too(self):
		self.match()
		(row,) = self.rows()
		runners, calls = self.runners()
		with mock.patch('targetApp.target_types.is_scannable_ip', return_value=False):
			stats, _ = self.run_validation(runners=(runners, calls))
		self.assertEqual(calls, [('nuclei_template', 'www.v.test')])  # the name is fine; the recorded address is not, so no nmap
		self.assertEqual(stats['blocked'], 1)

	def test_a_host_outside_the_project_is_never_touched(self):
		self.match()
		(row,) = self.rows()
		Triage.objects.filter(pk=row.pk).update(host='elsewhere.test')
		runners, calls = self.runners()
		stats, _ = self.run_validation(runners=(runners, calls))
		self.assertEqual((calls, stats['blocked']), ([], 1))
		self.assertEqual(Triage.objects.get().validation_status, 'skipped_blocked')

	def test_rows_of_another_project_are_ignored(self):
		self.match()
		(row,) = self.rows()
		other = Project.objects.create(name='Q', slug='pq', insert_date=timezone.now(), org=self.project.org)
		runners, calls = self.runners()
		stats = validation.run_validation(other.id, [row.pk], runners=runners, template_for=self.template)
		self.assertEqual((stats['rows'], calls), (0, []))

	def test_the_ledger_skips_a_fresh_check_and_the_ttl_runs_it_again(self):
		self.match()
		self.rows()
		runners, calls = self.runners('no_match')
		self.run_validation(runners=(runners, calls))
		self.assertEqual(len(calls), 2)
		self.run_validation(runners=(runners, calls))
		self.assertEqual(len(calls), 2)  # fresh: not run again
		ServiceRun.objects.filter(service__startswith='validate:').update(finished_at=timezone.now() - datetime.timedelta(hours=25))
		self.run_validation(runners=(runners, calls))
		self.assertEqual(len(calls), 4)

	def test_a_failed_check_is_not_fresh_and_waits_for_its_retry_time(self):
		self.match()
		(row,) = self.rows()
		runners, calls = self.runners('timeout')
		stats, _ = self.run_validation(runners=(runners, calls))
		row.refresh_from_db()
		self.assertEqual((stats['failed'], row.validation_status), (2, 'failed'))
		self.assertEqual(row.classification, '')
		self.assertEqual(row.attempts, 2)  # one per failed check
		again, _ = self.run_validation(runners=(runners, calls))
		self.assertEqual(len(calls), 2)  # not before next_attempt_at
		Triage.objects.update(next_attempt_at=timezone.now() - datetime.timedelta(minutes=1))
		self.run_validation(runners=(runners, calls))
		self.assertEqual(len(calls), 4)

	def test_a_failed_step_of_a_check_the_plan_no_longer_holds_does_not_keep_the_row_failed(self):
		self.match()
		(row,) = self.rows()
		row.validation_steps = [{'kind': 'nmap_sv', 'label': 'gone', 'display': '', 'target': 'a-host-no-longer-planned.v.test', 'ran_at': timezone.now().isoformat(),
			'result': 'failed', 'summary': 'timed out', 'output_excerpt': '', 'error': 'timeout'}]
		row.validation_status, row.attempts, row.next_attempt_at = 'failed', 1, timezone.now() - datetime.timedelta(minutes=1)
		row.save(update_fields=['validation_steps', 'validation_status', 'attempts', 'next_attempt_at'])
		self.run_validation()
		row.refresh_from_db()
		self.assertNotEqual(row.validation_status, 'failed')
		self.assertIsNone(row.next_attempt_at)
		self.assertFalse(any(s['target'] == 'a-host-no-longer-planned.v.test' for s in row.validation_steps))

	def test_a_crashing_runner_is_failed_never_clean(self):
		self.match()
		self.rows()
		runners, calls = self.runners('raise')
		self.run_validation(runners=(runners, calls))
		self.assertEqual(Triage.objects.get().validation_status, 'failed')

	def test_per_run_per_project_and_per_day_caps(self):
		for n in range(4):
			self.match(name=f'h{n}.v.test')
		self.rows()
		runners, calls = self.runners('no_match')
		with mock.patch.dict('os.environ', {'CVENGINE_VALIDATE_MAX_PER_RUN': '3'}):
			stats, _ = self.run_validation(runners=(runners, calls))
		self.assertEqual((len(calls), stats['capped']), (3, 5))
		self.assertTrue(Triage.objects.filter(validation_status='pending').exists())
		with mock.patch.dict('os.environ', {'CVENGINE_VALIDATE_MAX_PER_PROJECT_DAY': '3'}):
			self.run_validation(runners=(runners, calls))
		self.assertEqual(len(calls), 3)  # today's three already count
		ServiceRun.objects.update(finished_at=timezone.now() - datetime.timedelta(days=2))
		from cveFeed.models import ValidationBudget
		ValidationBudget.objects.update(day=(timezone.now() - datetime.timedelta(days=2)).date())
		with mock.patch.dict('os.environ', {'CVENGINE_VALIDATE_MAX_PER_DAY': '2'}):
			self.run_validation(runners=(runners, calls))
		self.assertEqual(len(calls), 5)

	def test_the_stop_flag_stops_the_run_and_leaves_the_rest_pending(self):
		for n in range(3):
			self.match(name=f'h{n}.v.test')
		self.rows()
		runners, calls = self.runners('no_match')
		seen = []

		def abort(scan_id):
			seen.append(scan_id)
			return len(seen) > 2  # the third look says stop
		from scanEngine.models import EngineType
		from startScan.models import ScanHistory
		scan = ScanHistory.objects.create(domain=self.domain, scan_type=EngineType.objects.create(engine_name='e', yaml_configuration='x'),
										  start_scan_date=timezone.now())
		with mock.patch.object(resources, 'abort_requested', side_effect=abort):
			stats, _ = self.run_validation(runners=(runners, calls), scan_id=scan.id)
		self.assertTrue(stats['stopped'])
		self.assertLess(len(calls), 6)
		self.assertTrue(Triage.objects.filter(validation_status='none').exists())

	def test_a_scan_aborted_inside_a_check_ends_the_run_cleanly(self):
		self.match()
		self.rows()
		runners, calls = self.runners()
		runners['nuclei_template'] = mock.Mock(side_effect=resources.ScanAborted())
		stats, _ = self.run_validation(runners=(runners, calls))
		self.assertTrue(stats['stopped'])

	def test_hits_are_announced_once_per_run(self):
		for n in range(3):
			self.match(name=f'h{n}.v.test')
		self.rows()
		runners, calls = self.runners('hit')
		with mock.patch('cveFeed.notify.template_hits') as announce:
			self.run_validation(runners=(runners, calls))
		announce.assert_called_once()
		self.assertEqual(len(announce.call_args[0][0]), 3)

	def test_a_stale_row_is_left_for_triage_to_reset(self):
		m = self.match()
		(row,) = self.rows()
		CVEMatch.objects.filter(pk=m.pk).update(matched_version='1.19.0')
		runners, calls = self.runners()
		self.run_validation(runners=(runners, calls))
		self.assertEqual(calls, [])


class DispatchTests(ValidationBase):
	def test_one_task_per_project_with_only_its_own_rows(self):
		self.match()
		org = self.project.org
		other = Project.objects.create(name='Q', slug='pq', insert_date=timezone.now(), org=org)
		dom = Domain.objects.create(name='q.test', project=other, insert_date=timezone.now())
		sub = Subdomain.objects.create(name='www.q.test', target_domain=dom)
		CVEMatch.objects.create(cve_entry=self.cve, subdomain=sub, matched_product='nginx', matched_version='1.18.0', version_in_range=True,
								source='port', evidence={'ip': '203.0.113.8', 'port': 80})
		rows = self.rows()
		with mock.patch('cveFeed.tasks.validate_findings.delay') as delay:
			queued = validation.dispatch(rows, scan_id=5)
		self.assertEqual(queued, 2)
		by_project = {call[0][0]: call[0][1] for call in delay.call_args_list}
		self.assertEqual(set(by_project), {self.project.id, other.id})
		for project_id, ids in by_project.items():
			self.assertEqual(set(Triage.objects.filter(pk__in=ids).values_list('project_id', flat=True)), {project_id})
		self.assertEqual(delay.call_args_list[0][0][2], 5)

	def test_kinds_without_a_check_and_validated_rows_are_not_queued(self):
		self.match()
		rows = self.rows()
		rows[0].validation_status = 'clean'
		with mock.patch('cveFeed.tasks.validate_findings.delay') as delay:
			self.assertEqual(validation.dispatch(rows), 0)
		delay.assert_not_called()


class TemplateOutcomeFeedTests(ValidationBase):
	def test_auto_fire_template_tests_feed_the_validation_record(self):
		m = self.match()
		(row,) = self.rows()
		outcomes = [{'host': 'www.v.test', 'vulnerable': True, 'output': '{}', 'hit': hit()}]
		with mock.patch('cveFeed.validation.resolve_template', return_value=('/t/cve-2099-1.yaml', '')), \
				mock.patch.object(templategen, '_run_template_with_retry', return_value=outcomes):
			templategen.run_cve_tests(self.cve, ['www.v.test'], project=self.project.id)
		row.refresh_from_db()
		self.assertEqual((row.classification, row.validation_status), ('confirmed', 'hit'))
		self.assertEqual(row.validation_steps[0]['kind'], 'nuclei_template')
		self.assertEqual(Vulnerability.objects.count(), 1)  # recorded once, by record_outcomes

	def test_a_clean_test_is_a_clean_step_and_an_error_is_failed(self):
		self.match()
		(row,) = self.rows()
		for outcome, expected in (({'host': 'www.v.test', 'vulnerable': False, 'output': ''}, 'clean'),
								  ({'host': 'www.v.test', 'vulnerable': False, 'output': '', 'error': 'not tested'}, 'failed')):
			validation.record_template_outcomes(self.cve, [outcome], self.project.id, '/t/cve-2099-1.yaml')
			row.refresh_from_db()
			self.assertEqual(row.validation_status, expected)


class DurableValidationBudgetTests(ValidationBase):
    def test_deleted_freshness_rows_do_not_reset_daily_usage(self):
        self.match()
        self.rows()
        runners, calls = self.runners('no_match')
        with mock.patch.dict('os.environ', {'CVENGINE_VALIDATE_MAX_PER_PROJECT_DAY': '4'}):
            self.run_validation(runners=(runners, calls))
            ServiceRun.objects.filter(service__startswith='validate:').delete()
            self.run_validation(runners=(runners, calls))
            self.assertEqual(len(calls), 4)
            ServiceRun.objects.filter(service__startswith='validate:').delete()
            third, _ = self.run_validation(runners=(runners, calls))
        self.assertEqual((len(calls), third['capped']), (4, 2))
        self.assertEqual(validation.ran_today(self.project.pk), 4)
        self.assertEqual(validation.ran_today(), 4)

    def test_reused_checks_do_not_reserve_again(self):
        self.match()
        self.rows()
        self.run_validation()
        reused, _ = self.run_validation()
        self.assertEqual(reused['reused'], 2)
        self.assertEqual(validation.ran_today(self.project.pk), 2)

    def test_failed_checks_keep_their_reservations(self):
        self.match()
        self.rows()
        runners, calls = self.runners('raise')
        with mock.patch.dict('os.environ', {'CVENGINE_VALIDATE_MAX_PER_PROJECT_DAY': '2'}):
            self.run_validation(runners=(runners, calls))
            ServiceRun.objects.filter(service__startswith='validate:').delete()
            Triage.objects.update(next_attempt_at=None)
            capped, _ = self.run_validation(runners=(runners, calls))
        self.assertEqual((len(calls), capped['capped']), (2, 2))

    def test_accounting_failure_prevents_the_check(self):
        self.match()
        self.rows()
        runners, calls = self.runners()
        with mock.patch('cveFeed.validation._reserve_validation_check', side_effect=RuntimeError('database unavailable')):
            with self.assertRaises(RuntimeError):
                self.run_validation(runners=(runners, calls))
        self.assertEqual(calls, [])


from django.test import TransactionTestCase
from django.db import connection, close_old_connections


@unittest.skipUnless(connection.vendor == 'postgresql', 'requires PostgreSQL row locks')
class ValidationBudgetConcurrencyTests(TransactionTestCase):
    def test_two_projects_cannot_both_spend_the_last_global_slot(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        gate = Barrier(2)

        def reserve(project_id):
            close_old_connections()
            try:
                gate.wait(timeout=5)
                return validation._reserve_validation_check(project_id)
            finally:
                close_old_connections()

        with mock.patch.dict('os.environ', {'CVENGINE_VALIDATE_MAX_PER_DAY': '1'}):
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(reserve, project_id) for project_id in (101, 102)]
                admitted = [future.result(timeout=10) for future in futures]
        self.assertEqual(sorted(admitted), [False, True])
        self.assertEqual(validation.ran_today(), 1)
