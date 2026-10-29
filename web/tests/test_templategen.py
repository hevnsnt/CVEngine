import unittest

from cveFeed.templategen import extract_yaml, static_check

GOOD = """
id: cve-2024-1234
info:
  name: Example detection
  author: cvengine-ai
  severity: high
  tags: cve,cve2024
http:
  - method: GET
    path:
      - "{{BaseURL}}/version"
    matchers:
      - type: word
        words:
          - "nginx/1.18"
"""


class StaticCheckTests(unittest.TestCase):
	def test_good_template_passes(self):
		self.assertEqual(static_check(GOOD, 'CVE-2024-1234'), (True, ''))

	def test_rejects_code_protocol(self):
		bad = GOOD + "\ncode:\n  - engine: [sh]\n    source: id\n"
		ok, reason = static_check(bad, 'CVE-2024-1234')
		self.assertFalse(ok)
		self.assertIn('forbidden', reason)

	def test_rejects_other_dangerous_or_offschema(self):
		for extra in ('javascript:\n  - code: x\n', 'headless:\n  - steps: []\n', 'file:\n  - extensions: [all]\n', 'weird: 1\n'):
			self.assertFalse(static_check(GOOD + '\n' + extra, 'CVE-2024-1234')[0], extra)

	def test_rejects_interactsh_and_wrong_cve_and_junk(self):
		self.assertFalse(static_check(GOOD.replace('/version', '/{{interactsh-url}}'), 'CVE-2024-1234')[0])
		self.assertFalse(static_check(GOOD, 'CVE-2020-9999')[0])
		self.assertFalse(static_check('not: [valid', None)[0])
		self.assertFalse(static_check('- a list', None)[0])
		self.assertFalse(static_check('', None)[0])
		self.assertFalse(static_check(GOOD.replace('severity: high', 'severity: wild'), 'CVE-2024-1234')[0])

	def test_word_roast_is_not_oast(self):
		self.assertTrue(static_check(GOOD.replace('nginx/1.18', 'roast'), 'CVE-2024-1234')[0])

	def test_extract_yaml_from_fence(self):
		self.assertEqual(extract_yaml("here:\n```yaml\nid: x\n```\nthanks"), "id: x")
		self.assertEqual(extract_yaml("id: y"), "id: y")


class CoverageTests(unittest.TestCase):
	def test_find_existing_template_case_insensitive(self):
		import os
		import tempfile
		from cveFeed.templategen import find_existing_template
		with tempfile.TemporaryDirectory() as d:
			os.makedirs(os.path.join(d, 'http', 'cves'))
			for name in ('CVE-2024-1.yaml', 'cve-2024-2.yaml', 'CVE-2024-3.txt'):
				open(os.path.join(d, 'http', 'cves', name), 'w').close()
			self.assertEqual(len(find_existing_template('CVE-2024-1', roots=[d])), 1)
			self.assertEqual(len(find_existing_template('CVE-2024-2', roots=[d])), 1)
			self.assertEqual(find_existing_template('CVE-2024-3', roots=[d]), [])


EXTRACTOR_ONLY = """
id: cve-2024-1234
info:
  name: Version extractor
  severity: high
  tags: cve,cve2024
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    extractors:
      - type: regex
        regex:
          - "Server: (.*)"
"""


def _with_matchers(block, condition=None):
	"""GOOD with its matchers replaced by ``block`` (yaml text of the matchers list, indented 6)."""
	head = GOOD.split('    matchers:')[0]
	return head + ('    matchers-condition: %s\n' % condition if condition else '') + '    matchers:\n' + block


class GateEvidenceTests(unittest.TestCase):
	"""Review 2.2 / 5.5: a generated template must carry real evidence and stay read-only."""

	def test_extractor_only_template_is_rejected(self):
		ok, reason = static_check(EXTRACTOR_ONLY, 'CVE-2024-1234')
		self.assertFalse(ok)
		self.assertIn('no matchers', reason)

	def test_non_read_only_methods_are_rejected(self):
		for method in ('DELETE', 'PUT', 'PATCH', 'POST'):
			ok, reason = static_check(GOOD.replace('method: GET', f'method: {method}'), 'CVE-2024-1234')
			self.assertFalse(ok, method)
			self.assertIn('method', reason)
		for method in ('GET', 'HEAD', 'OPTIONS'):
			self.assertTrue(static_check(GOOD.replace('method: GET', f'method: {method}'), 'CVE-2024-1234')[0], method)

	def test_raw_request_methods_are_checked_too(self):
		raw = GOOD.split('    path:')[0] + '    raw:\n      - |\n        %s /x HTTP/1.1\n        Host: {{Hostname}}\n' % '%s' + \
			'    matchers:' + GOOD.split('    matchers:')[1]
		self.assertTrue(static_check(raw % 'GET', 'CVE-2024-1234')[0])
		self.assertFalse(static_check(raw % 'DELETE', 'CVE-2024-1234')[0])

	def test_a_status_matcher_alone_is_rejected(self):
		bad = _with_matchers('      - type: status\n        status:\n          - 200\n')
		self.assertFalse(static_check(bad, 'CVE-2024-1234')[0])

	def test_a_status_matcher_with_or_is_rejected_and_with_and_is_accepted(self):
		pair = '      - type: status\n        status:\n          - 200\n      - type: word\n        words:\n          - "nginx/1.18"\n'
		self.assertFalse(static_check(_with_matchers(pair, 'or'), 'CVE-2024-1234')[0])
		self.assertFalse(static_check(_with_matchers(pair), 'CVE-2024-1234')[0])  # nuclei's default is or
		self.assertTrue(static_check(_with_matchers(pair, 'and'), 'CVE-2024-1234')[0])

	def test_a_dsl_status_only_matcher_counts_as_status_only(self):
		bad = _with_matchers('      - type: dsl\n        dsl:\n          - "status_code == 200"\n')
		self.assertFalse(static_check(bad, 'CVE-2024-1234')[0])

	def test_a_generic_server_word_alone_is_rejected_but_paired_with_a_version_regex_is_fine(self):
		generic = _with_matchers('      - type: word\n        words:\n          - "nginx"\n')
		self.assertFalse(static_check(generic, 'CVE-2024-1234')[0])
		paired = _with_matchers('      - type: word\n        words:\n          - "nginx"\n      - type: regex\n'
			'        regex:\n          - "nginx/1\\\\.1[0-8]\\\\."\n', 'and')
		self.assertTrue(static_check(paired, 'CVE-2024-1234')[0])

	def test_request_multipliers_are_forbidden(self):
		for extra in ('    payloads:\n      p: [a, b, c]\n', '    attack: clusterbomb\n', '    threads: 50\n', '    iterate-all: true\n',
				'    fuzzing:\n      - part: query\n', '    cookie-reuse: true\n', '    skip-variables-check: true\n'):
			text = GOOD.replace('    matchers:', extra + '    matchers:')
			ok, reason = static_check(text, 'CVE-2024-1234')
			self.assertFalse(ok, extra)
			self.assertIn('forbidden', reason)


class FakeProc:
	"""Stands in for the nuclei process: its stdout is the given JSON lines."""
	lines = []
	returncode = 0

	def __init__(self, cmd, **kwargs):
		pass

	def attach(self, proc):
		pass

	def communicate(self, timeout=None):
		import json
		return '\n'.join(json.dumps(line) for line in self.lines), ''


class _Job:
	def __enter__(self):
		return self

	def __exit__(self, *exc):
		return False

	def attach(self, proc):
		pass

	def raise_if_killed(self):
		pass


class RunTimeHitTests(unittest.TestCase):
	def _run(self, lines):
		FakeProc.lines = lines
		with mock.patch('cveFeed.validation.approved_template', return_value=(GOOD, '')), \
				mock.patch('reNgine.resources.heavy_job', lambda *a, **k: _Job()), mock.patch.object(templategen.subprocess, 'Popen', FakeProc):
			return templategen.run_template('/t.yaml', ['www.t.test'])[0]

	def test_an_extractor_only_line_is_not_a_hit(self):
		out = self._run([{'host': 'https://www.t.test', 'template-id': 't', 'extracted-results': ['nginx/1.18.0']}])
		self.assertFalse(out['vulnerable'])

	def test_a_matcher_line_is_a_hit_with_its_evidence(self):
		out = self._run([{'host': 'https://www.t.test', 'template-id': 't', 'matcher-name': 'version', 'extracted-results': ['1']}])
		self.assertTrue(out['vulnerable'])
		self.assertEqual(out['hit']['matcher-name'], 'version')

	def test_an_unnamed_matcher_with_a_true_status_is_a_hit(self):
		self.assertTrue(self._run([{'host': 'https://www.t.test', 'template-id': 't', 'matcher-status': True}])['vulnerable'])

	def test_a_false_matcher_status_is_not_a_hit(self):
		self.assertFalse(self._run([{'host': 'https://www.t.test', 'template-id': 't', 'matcher-status': False,
			'matcher-name': 'x'}])['vulnerable'])

	def test_nonzero_exit_and_malformed_output_are_errors_not_negative_results(self):
		with mock.patch.object(FakeProc, 'returncode', 2):
			out = self._run([])
		self.assertFalse(out['vulnerable'])
		self.assertIn('error', out)
		with mock.patch.object(FakeProc, 'communicate', return_value=('{broken', '')):
			out = self._run([])
		self.assertEqual(out['error'], 'nuclei returned malformed JSON output')

	def test_missing_nuclei_is_not_reported_as_no_match(self):
		with mock.patch('cveFeed.validation.approved_template', return_value=(GOOD, '')), \
				mock.patch('reNgine.resources.heavy_job', lambda *a, **k: _Job()), \
				mock.patch.object(templategen.subprocess, 'Popen', side_effect=FileNotFoundError('nuclei')):
			out = templategen._run_template_with_retry('/t.yaml', ['www.t.test'])
		self.assertIn('FileNotFoundError', out[0]['error'])

	def test_timeout_is_not_reported_as_no_match(self):
		import subprocess
		with mock.patch('cveFeed.validation.approved_template', return_value=(GOOD, '')), \
				mock.patch('reNgine.resources.heavy_job', lambda *a, **k: _Job()), \
				mock.patch('reNgine.resources.terminate_group'), \
				mock.patch.object(templategen.subprocess, 'Popen', FakeProc), \
				mock.patch.object(FakeProc, 'communicate', side_effect=[subprocess.TimeoutExpired('nuclei', 1), ('', '')]):
			out = templategen._run_template_with_retry('/t.yaml', ['www.t.test'])
		self.assertIn('TimeoutExpired', out[0]['error'])


class ValidateBeforeSaveTests(unittest.TestCase):
	def setUp(self):  # the generation budget is covered by GenerationBudgetTests
		lease = mock.patch.object(templategen, '_generation_lease', return_value='cvengine:templategen:test')
		lease.start()
		self.addCleanup(lease.stop)

	def test_on_demand_candidate_stays_draft_after_syntax_and_benign_fixture(self):
		provider = mock.Mock(model='m')
		provider.name = 'test'
		provider.complete.return_value = GOOD
		cve = CVEEntry(cve_id='CVE-2024-1234', title='t', original_description='d', summary='', cvss=9.8,
			affected=[], references=[])
		with mock.patch.object(templategen, 'validate_with_nuclei', return_value=(True, 'syntax ok')), \
				mock.patch.object(templategen, 'test_benign_fixture', return_value=(True, 'no benign match')) as fixture, \
				mock.patch('cveFeed.activity.log'), mock.patch('cveFeed.activity.step') as step, \
				mock.patch('cveFeed.models.GeneratedTemplate.save'), \
				mock.patch.object(templategen, 'save_template_file') as install:
			step.return_value.__enter__.return_value = mock.Mock()
			tmpl = templategen.generate_template(cve, provider, candidate_only=True)
		self.assertEqual(tmpl.status, tmpl.STATUS_DRAFT)
		self.assertEqual(tmpl.path, '')
		self.assertIn('positive fixture', tmpl.validation_output)
		fixture.assert_called_once()
		install.assert_not_called()

	def _generate(self, valid):
		import tempfile
		provider = mock.Mock(model='m')
		provider.name = 'test'
		provider.complete.return_value = GOOD
		cve = CVEEntry(cve_id='CVE-2024-1234', title='t', original_description='d', summary='', cvss=9.8, affected=[], references=[])
		seen = {}
		with tempfile.TemporaryDirectory() as generated:
			def validate(path):
				seen['generated_during_validation'] = os.listdir(generated)
				seen['validated_path_exists'] = os.path.exists(path)
				return valid, 'ok' if valid else 'error: bad'
			with mock.patch.object(templategen, 'GENERATED_DIR', generated), mock.patch.object(templategen, 'validate_with_nuclei', validate), \
					mock.patch.object(templategen, 'test_benign_fixture', return_value=(True, 'no benign match')), \
					mock.patch('cveFeed.activity.log'), mock.patch('cveFeed.activity.step') as step, \
					mock.patch('cveFeed.models.GeneratedTemplate.save'):
				step.return_value.__enter__.return_value = mock.Mock()
				tmpl = templategen.generate_template(cve, provider)
			seen['after'] = os.listdir(generated)
		return tmpl, seen

	def test_syntax_valid_draft_never_reaches_the_scan_path(self):
		tmpl, seen = self._generate(True)
		self.assertEqual(seen['generated_during_validation'], [])
		self.assertTrue(seen['validated_path_exists'])
		self.assertEqual(seen['after'], [])
		self.assertEqual(tmpl.path, '')
		self.assertEqual(tmpl.status, 'draft')
		with self.assertRaisesRegex(ValueError, 'positive fixture'):
			templategen.generate_template(None, None, candidate_only=False)

	def test_an_invalid_template_never_reaches_the_scan_path(self):
		tmpl, seen = self._generate(False)
		self.assertEqual(seen['after'], [])
		self.assertEqual(tmpl.path, '')
		self.assertEqual(tmpl.status, 'invalid')


import datetime
import os
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import templategen
from cveFeed.models import CVEEntry, CVEMatch, GeneratedTemplate
from dashboard.models import Org, Project
from startScan.models import EngineType, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain


def _hit(host='www.t.test', **extra):
	row = {'host': host, 'matched-at': f'https://{host}/version', 'template-id': 'cve-2099-5', 'type': 'http', 'template': 'x.yaml',
		'matcher-name': 'version', 'request': 'GET /version', 'response': 'HTTP/1.1 200\nServer: nginx/1.18.0',
		'extracted-results': ['1.18.0'], 'info': {'name': 'Example detection', 'severity': 'high', 'tags': ['cve']}}
	row.update(extra)
	return row


class RecordOutcomesTests(TestCase):
	"""Review 2.1: a confirmed template hit is a finding, and a tested host remembers the result."""

	def setUp(self):
		org = Org.objects.create(name='o', slug='o')
		self.project = Project.objects.create(name='p', slug='pp', insert_date=timezone.now(), org=org)
		self.other = Project.objects.create(name='q', slug='pq', insert_date=timezone.now(), org=org)
		engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
		self.domain = Domain.objects.create(name='t.test', project=self.project, insert_date=timezone.now())
		self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=timezone.now(), scan_status=2)
		self.sub = Subdomain.objects.create(scan_history=self.scan, target_domain=self.domain, name='www.t.test')
		self.quiet = Subdomain.objects.create(scan_history=self.scan, target_domain=self.domain, name='quiet.t.test')
		self.cve = CVEEntry.objects.create(cve_id='CVE-2099-5', kev=True, cvss=9.8, published_at=timezone.now())
		for sub in (self.sub, self.quiet):
			CVEMatch.objects.create(cve_entry=self.cve, subdomain=sub, matched_product='nginx', confidence=0.9)

	def _run(self, outcomes, project=None):
		with mock.patch('cveFeed.validation.resolve_template', return_value=('/t/cve-2099-5.yaml', '')), \
				mock.patch.object(templategen, '_run_template_with_retry', return_value=outcomes):
			return templategen.run_cve_tests(self.cve, [o['host'] for o in outcomes], project=project or self.project.id)

	def test_missing_installed_template_stays_a_draft_without_customer_execution(self):
		from types import SimpleNamespace
		draft = SimpleNamespace(status='draft', STATUS_DRAFT='draft', template_id='cve-2099-5',
			validation_output='syntax passed; positive fixture unavailable')
		with mock.patch('cveFeed.validation.resolve_template', return_value=('', 'no template covers this CVE')), \
				mock.patch.object(templategen, 'generate_template', return_value=draft) as generate, \
				mock.patch.object(templategen, '_run_template_with_retry') as run:
			result = templategen.run_cve_tests(self.cve, ['www.t.test'], provider=mock.Mock(), project=self.project.id)
		self.assertEqual((result['source'], result['results']), ('candidate', []))
		self.assertIn('positive fixture', result['reason'])
		self.assertTrue(generate.call_args.kwargs['candidate_only'])
		run.assert_not_called()

	def test_a_vulnerable_host_becomes_a_vulnerability_linked_to_the_cve_and_heats_the_host(self):
		self._run([{'host': 'www.t.test', 'vulnerable': True, 'output': '{}', 'hit': _hit()},
			{'host': 'quiet.t.test', 'vulnerable': False, 'output': '', 'hit': None}])
		vuln = Vulnerability.objects.get()
		self.assertEqual(vuln.subdomain, self.sub)
		self.assertEqual(vuln.source, 'nuclei-cve')
		self.assertEqual(vuln.template_id, 'cve-2099-5')
		self.assertEqual(vuln.severity, 4)  # from the CVE's 9.8
		self.assertEqual(vuln.http_url, 'https://www.t.test/version')
		self.assertIn('CVE-2099-5', [c.name for c in vuln.cve_ids.all()])
		self.assertIn('nginx/1.18.0', vuln.response)
		from agentapi.services import _host_heat
		self.assertEqual(_host_heat(Subdomain.objects.get(pk=self.sub.pk)), 'fire')

	def test_each_tested_host_records_its_result_on_the_match(self):
		self._run([{'host': 'www.t.test', 'vulnerable': True, 'output': '{}', 'hit': _hit()},
			{'host': 'quiet.t.test', 'vulnerable': False, 'output': '', 'hit': None}])
		hot, quiet = (CVEMatch.objects.get(subdomain=s) for s in (self.sub, self.quiet))
		self.assertEqual((hot.template_result, hot.template_id), ('vulnerable', 'cve-2099-5'))
		self.assertEqual(quiet.template_result, 'no_match')
		self.assertIsNotNone(quiet.template_tested_at)

	def test_a_host_that_could_not_be_tested_is_an_error_not_a_clean_bill(self):
		self._run([{'host': 'www.t.test', 'vulnerable': False, 'output': '', 'error': 'not tested: the server ran low on memory'}])
		self.assertEqual(CVEMatch.objects.get(subdomain=self.sub).template_result, 'error')
		self.assertFalse(Vulnerability.objects.exists())

	def test_another_projects_host_of_the_same_name_is_untouched(self):
		self._run([{'host': 'www.t.test', 'vulnerable': True, 'output': '{}', 'hit': _hit()}], project=self.other.id)
		self.assertFalse(Vulnerability.objects.exists())
		self.assertEqual(CVEMatch.objects.get(subdomain=self.sub).template_result, '')

	def test_no_project_persists_nothing(self):
		outcomes = [{'host': 'www.t.test', 'vulnerable': True, 'output': '{}', 'hit': _hit()}]
		self.assertEqual(templategen.record_outcomes(self.cve, outcomes, project=None), 0)
		self.assertFalse(Vulnerability.objects.exists())

	def test_a_hit_without_the_full_nuclei_shape_is_still_recorded(self):
		self._run([{'host': 'www.t.test', 'vulnerable': True, 'output': '{}', 'hit': {'host': 'www.t.test', 'matched-at': 'http://www.t.test/x'}}])
		self.assertEqual(Vulnerability.objects.get().name, 'CVE-2099-5')

	def test_the_same_hit_twice_is_one_finding(self):
		outcomes = [{'host': 'www.t.test', 'vulnerable': True, 'output': '{}', 'hit': _hit()}]
		self._run(outcomes)
		self._run(outcomes)
		self.assertEqual(Vulnerability.objects.count(), 1)


if __name__ == '__main__':
	unittest.main()


class GenerationBudgetTests(TestCase):
	def setUp(self):
		from django.core.cache import cache
		cache.clear()
		self.provider = mock.Mock(model='m')
		self.provider.name = 'test'
		self.cve = CVEEntry.objects.create(cve_id='CVE-2099-0101', cvss=9.8, title='t', published_at=timezone.now())

	def generate(self, cve=None):
		with mock.patch.object(templategen, '_generate_template', return_value='written') as write:
			return templategen.generate_template(cve or self.cve, self.provider), write

	def test_one_attempt_per_cve_inside_the_window_whatever_its_outcome(self):
		GeneratedTemplate.objects.create(cve_entry=self.cve, yaml='', status=GeneratedTemplate.STATUS_INVALID)
		with self.assertRaisesRegex(templategen.TemplateBudgetExceeded, 'already attempted'):
			self.generate()
		GeneratedTemplate.objects.update(created_at=timezone.now() - datetime.timedelta(days=8))
		self.assertEqual(self.generate()[0], 'written')

	def test_daily_budget_across_all_cves(self):
		for i in range(templategen.generation_limit('TEMPLATE_GEN_MAX_PER_DAY')):
			other = CVEEntry.objects.create(cve_id=f'CVE-2099-02{i:02d}', title='t', published_at=timezone.now())
			GeneratedTemplate.objects.create(cve_entry=other, yaml='')
		with self.assertRaisesRegex(templategen.TemplateBudgetExceeded, 'daily'):
			self.generate()
		with mock.patch.dict(os.environ, {'CVENGINE_TEMPLATE_GEN_MAX_PER_DAY': '50'}):
			self.assertEqual(self.generate()[0], 'written')

	def test_a_cve_being_written_is_not_written_twice_and_the_lease_is_released(self):
		from django.core.cache import cache
		cache.add(f'cvengine:templategen:{self.cve.pk}', 1)
		with self.assertRaisesRegex(templategen.TemplateBudgetExceeded, 'already being written'):
			self.generate()
		cache.clear()
		self.generate()
		self.generate()  # the lease from the first call was released (no row was written by the stub)

	def test_scan_path_reports_the_budget_instead_of_calling_the_ai(self):
		GeneratedTemplate.objects.create(cve_entry=self.cve, yaml='')
		with mock.patch('cveFeed.validation.resolve_template', return_value=(None, 'no installed template')):
			outcome = templategen.run_cve_tests(self.cve, ['www.acme.example'], provider=self.provider, project=None)
		self.assertEqual(outcome['source'], 'none')
		self.assertIn('already attempted', outcome['reason'])
		self.provider.complete.assert_not_called()


class ProviderFailureLedgerTests(TestCase):
	def test_a_failed_provider_call_still_counts_as_the_attempt_for_that_cve(self):
		from django.core.cache import cache
		cache.clear()
		provider = mock.Mock(model='m')
		provider.name = 'test'
		provider.complete.side_effect = RuntimeError('provider down')
		cve = CVEEntry.objects.create(cve_id='CVE-2099-0303', cvss=9.8, title='t', published_at=timezone.now())
		with self.assertRaises(RuntimeError):
			templategen.generate_template(cve, provider)
		row = GeneratedTemplate.objects.get(cve_entry=cve)
		self.assertEqual(row.status, GeneratedTemplate.STATUS_INVALID)
		with self.assertRaisesRegex(templategen.TemplateBudgetExceeded, 'already attempted'):  # the next run does not call the provider again
			templategen.generate_template(cve, provider)
		self.assertEqual(provider.complete.call_count, 1)


class LaunchTimeResolutionTests(TestCase):
	def test_a_name_that_now_resolves_to_a_blocked_address_is_not_handed_to_nuclei(self):
		seen = []

		def fake(path, hosts, secret_file=None, redact=()):
			seen.append(list(hosts))
			return [{'host': h, 'vulnerable': False, 'output': ''} for h in hosts]
		with mock.patch.object(templategen, '_run_template', side_effect=fake), \
				mock.patch('targetApp.target_types.blocked_names', return_value={'rebind.example.test'}):
			out = templategen.run_template('/t.yaml', ['ok.example.test', 'rebind.example.test', '203.0.113.7:8443'])
		self.assertEqual(seen, [['ok.example.test', '203.0.113.7:8443']])
		self.assertEqual([o['host'] for o in out], ['ok.example.test', 'rebind.example.test', '203.0.113.7:8443'])
		self.assertIn('may not be scanned', out[1]['error'])
		self.assertNotIn('error', out[0])
		with mock.patch.object(templategen, '_run_template', side_effect=fake) as run, \
				mock.patch('targetApp.target_types.blocked_names', return_value={'rebind.example.test'}):
			out = templategen.run_template('/t.yaml', ['rebind.example.test'])
		run.assert_not_called()
		self.assertIn('error', out[0])
