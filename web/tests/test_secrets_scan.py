"""The ``secrets_scan`` kind (docs/SECRETS-PLAN.md sections 6, 9 and 13): the contract, what the server keeps of a result, the stage served by
a scanner and never run here, the validation locks, the Firebase check the references lead to, and the custom rules."""
import json
import os
from pathlib import Path
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase
from django.utils import timezone
from jsonschema import Draft202012Validator

from agentapi import sentinel_broker as broker
from agentapi import sentinel_contract as contract
from agentapi import sentinel_dispatch
from agentapi.models import SentinelTask
from cveFeed import bucket_probe, bucket_scan, ledger, secret_rules, secrets_inventory, secrets_scan, secrets_validation
from cveFeed.models import (BountyEngagement, BountyProgram, HygieneFinding, ProjectSettings, ResourceRef, RouteAuth, SecretFinding,
                            SecretOccurrence)
from dashboard.models import AuditLog
from reNgine import resources
from tests.fake_scanner import FakeScanner, assert_ran_nowhere_locally
from tests.test_scanner_unavailable_stages import NoScannerBase

FIXTURE = Path(__file__).with_name('fixtures') / 'sentinel_results' / 'secrets_scan.json'
TARGET = Path(__file__).with_name('fixtures') / 'sentinel_targets' / 'secrets_scan.json'
HOST = 'www.example.test'
AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'


def result_for(host, findings=None, fetched=None, references=None):
    """The contract fixture moved onto ``host`` (the fixture names www.example.com)."""
    body = json.loads(FIXTURE.read_text().replace('www.example.com', host))
    if findings is not None:
        body['findings'] = findings
    if fetched is not None:
        body['fetched'] = fetched
    if references is not None:
        body['references'] = references
    return body


class ContractTests(SimpleTestCase):
    def test_the_target_fixture_and_a_built_target_are_in_contract(self):
        schema = Draft202012Validator(contract.target_schema('secrets_scan'))
        self.assertEqual(list(schema.iter_errors(json.loads(TARGET.read_text()))), [])
        rows = {HOST: {'urls': [f'https://{HOST}/'], 'script_urls': [f'https://{HOST}/a.js'], 'domain_id': 1}}
        with mock.patch('cveFeed.secret_rules.current', return_value=mock.Mock(skip_words=['EXAMPLE'], skip_regex=[], rules_yaml='')):
            for validate in (False, True):
                target = secrets_scan.build_target([HOST], rows, {'excluded.example.test'}, validate=validate)
                self.assertEqual(list(schema.iter_errors(target)), [], validate)
        self.assertEqual(target['validate_rules'], secrets_validation.rule_ids())
        self.assertEqual(target['validate_kingfisher'], '2.16.0')

    def test_the_bounds_equal_the_servers(self):
        target = contract.load()['$defs']['targets']['secrets_scan']['properties']
        self.assertEqual(target['hosts']['maxItems'], secrets_scan.MAX_HOSTS)
        self.assertEqual(target['hosts']['items']['properties']['urls']['maxItems'], secrets_scan.MAX_URLS)
        self.assertEqual(target['hosts']['items']['properties']['script_urls']['maxItems'], secrets_scan.MAX_SCRIPT_URLS)
        self.assertEqual({k: v['maximum'] for k, v in target['limits']['properties'].items() if 'maximum' in v},
                         {k: v for k, v in secrets_scan.LIMITS.items() if k != 'follow_sourcemaps'})
        result = contract.load()['$defs']['results']['secrets_scan']['allOf'][1]['properties']
        self.assertEqual(result['findings']['maxItems'], secrets_scan.MAX_FINDINGS)
        self.assertEqual(result['fetched']['maxItems'], secrets_scan.MAX_FETCHED)
        self.assertEqual(result['references']['maxItems'], secrets_scan.MAX_REFERENCES)
        secret = result['findings']['items']['properties']['secret']
        self.assertEqual((secret['minLength'], secret['maxLength']), (secrets_inventory.MIN_VALUE, secrets_inventory.MAX_VALUE))
        self.assertEqual(set(result['findings']['items']['properties']['validation_meta']['properties']), set(secrets_inventory.META_KEYS))
        self.assertEqual(result['references']['items']['properties']['kind']['enum'], list(secrets_scan.REFERENCE_KINDS))
        self.assertEqual(contract.kind_since('secrets_scan'), 3)
        self.assertEqual(contract.version(), 3)

    def test_the_server_keeps_only_the_contract_and_never_a_validation_response(self):
        body = json.loads(FIXTURE.read_text())
        body['findings'][0]['validation'] = {'outcome': 'verified_active', 'response': '{"Arn": "arn:aws:iam::123456789012:user/x"}'}
        body['findings'][0]['validation_meta'] = {'account_type': 'User', 'arn': 'arn:aws:iam::1:user/x'}
        body['findings'].append({'rule_id': 'betterleaks.github-pat', 'url': 'https://elsewhere.example.net/', 'secret': 'ghp_' + 'a' * 36})
        body['findings'].append({'rule_id': 'Bad Rule', 'url': 'https://www.example.com/', 'secret': 'ghp_' + 'a' * 36})
        body['findings'].append({'rule_id': 'betterleaks.github-pat', 'url': 'https://www.example.com/', 'secret': 'short'})
        body['fetched'].append({'url': 'https://other.example.net/', 'kind': 'page', 'status': 200})
        body['unexpected'] = 'x'
        task = mock.Mock(kind='secrets_scan', target={'hosts': [{'host': 'www.example.com', 'urls': []}]})
        stored = broker.clean_result('secrets_scan', body, task=task)
        self.assertEqual(list(Draft202012Validator(contract.result_schema('secrets_scan')).iter_errors(stored)), [])
        self.assertEqual(len(stored['findings']), 2)
        self.assertEqual(stored['findings'][0]['validation'], {'outcome': 'verified_active'})
        self.assertEqual(stored['findings'][0]['validation_meta'], {'account_type': 'User'})
        self.assertNotIn('arn:aws', json.dumps(stored))
        self.assertNotIn('other.example.net', json.dumps(stored))
        self.assertNotIn('unexpected', stored)

    def test_a_good_result_goes_through_unchanged(self):
        sent = json.loads(FIXTURE.read_text())
        self.assertEqual(broker.clean_result('secrets_scan', sent), sent)


class NeverLocalTests(SimpleTestCase):
    def test_no_setting_lets_the_secrets_scan_run_here(self):
        for value in ('', 'all', '*', 'secrets_scan', 'nmap,secrets_scan'):
            with mock.patch.dict(os.environ, {'CVENGINE_LOCAL_FALLBACK': value}):
                self.assertIn('secrets_scan', sentinel_dispatch.NEVER_LOCAL, value)
                with self.assertRaises(resources.ScannerUnavailable):  # the variable is ignored since 1.4: no decision ever lets it run here
                    sentinel_dispatch._no_local('secrets_scan', 'nothing took it')


class StageBase(NoScannerBase):
    def setUp(self):
        super().setUp()
        secrets_inventory.reset_key_cache()
        self.addCleanup(secrets_inventory.reset_key_cache)
        mock.patch('cveFeed.route_auth.host_allowed', return_value=True).start()
        mock.patch('time.sleep').start()
        self.addCleanup(mock.patch.stopall)
        now = timezone.now()
        RouteAuth.objects.create(project=self.project, domain=self.domain, url=f'https://{HOST}/', host=HOST, path='/', auth_state='open',
                                 http_status=200, content_type='text/html', checked_at=now,
                                 evidence={'script_urls': [f'https://{HOST}/static/app.js']})
        RouteAuth.objects.create(project=self.project, domain=self.domain, url=f'https://{HOST}/logo.png', host=HOST, path='/logo.png',
                                 auth_state='open', http_status=200, content_type='image/png', checked_at=now, evidence={})

    def responder(self, **kw):
        return lambda task: result_for(HOST, **kw)


class StageTests(StageBase):
    def test_the_scanner_reads_the_routes_and_the_server_files_what_it_found(self):
        guard = assert_ran_nowhere_locally(self, 'secrets_scan')
        with FakeScanner(kinds=['secrets_scan'], responders={'secrets_scan': self.responder()}) as fake:
            summary = secrets_scan.run_for_scan(self.scan.id)
            again = secrets_scan.run_for_scan(self.scan.id)
        self.assertEqual(guard.calls, [])
        self.assertEqual(fake.served_kinds(), ['secrets_scan'])  # the second run found the host read within the week: not asked again
        self.assertEqual(again['hosts'], 0)
        target = fake.served[0]['target']
        self.assertEqual(target['hosts'], [{'host': HOST, 'urls': [f'https://{HOST}/'], 'script_urls': [f'https://{HOST}/static/app.js']}])
        self.assertFalse(target['validate'])
        self.assertEqual((summary['hosts'], summary['secrets'], summary['findings']), (1, 2, 2))
        kinds = dict(SecretFinding.objects.values_list('kind', 'klass'))
        self.assertEqual(kinds, {'aws-access-key-id': 'I', 'google-api-key': 'P'})
        self.assertEqual(set(SecretOccurrence.objects.values_list('source', flat=True)), {'kingfisher'})
        for row in SecretFinding.objects.values():
            self.assertNotIn('AKIAIOSFODNN7EXAMPLE', json.dumps(row, default=str))
        self.assertEqual(set(ResourceRef.objects.values_list('kind', 'identifier')),
                         {('gcs', 'example-assets'), ('firebase_rtdb', 'example-app-default-rtdb')})
        sourcemap = HygieneFinding.objects.get(check_name='src_sourcemap_public')
        self.assertEqual((sourcemap.severity, sourcemap.host), (1, HOST))
        self.assertTrue(ledger.fresh('secrets-scan', [HOST], self.project.id))

    def test_an_aws_key_id_and_its_secret_in_one_file_are_one_pair(self):
        url = f'https://{HOST}/static/app.js'
        findings = [{'rule_id': 'betterleaks.aws-access-token', 'url': url, 'secret': 'AKIAIOSFODNN7EXAMPLE', 'line': 3},
                    {'rule_id': 'betterleaks.aws-secret-access-key', 'url': url, 'secret': AWS_SECRET, 'line': 4}]
        with FakeScanner(kinds=['secrets_scan'], responders={'secrets_scan': self.responder(findings=findings)}):
            secrets_scan.run_for_scan(self.scan.id)
        row = SecretFinding.objects.get()
        self.assertEqual((row.kind, row.klass, row.severity), ('aws-access-key-pair', 'S', 3))
        self.assertEqual(set(row.rule_ids), {'betterleaks.aws-secret-access-key', 'betterleaks.aws-access-token'})
        self.assertTrue(row.masked.endswith('EKEY'))

    def test_a_url_that_no_longer_serves_the_secret_retires_it(self):
        with FakeScanner(kinds=['secrets_scan'], responders={'secrets_scan': self.responder()}) as fake:
            secrets_scan.run_for_scan(self.scan.id)
            fake.responders['secrets_scan'] = self.responder(findings=[])
            secrets_scan.run_for_scan(self.scan.id, force=True)
        self.assertEqual(set(SecretFinding.objects.values_list('remediation_status', flat=True)), {'fixed'})
        self.assertFalse(SecretOccurrence.objects.filter(retired_at__isnull=True).exists())

    def test_with_the_scanner_offline_the_stage_waits_and_the_hosts_stay_due(self):
        guard = assert_ran_nowhere_locally(self, 'secrets_scan')
        with FakeScanner(kinds=['secrets_scan'], mode='offline'):
            with self.assertRaises(resources.ScannerUnavailable):
                secrets_scan.run_for_scan(self.scan.id)
        self.assertEqual(guard.calls, [])
        self.assertFalse(ledger.fresh('secrets-scan', [HOST], self.project.id))
        self.assertFalse(SecretFinding.objects.exists())

    def test_a_bounty_project_host_is_not_read(self):
        with mock.patch('cveFeed.bounty_gate.Gate.refusal', return_value='out of the program scope'):
            self.assertEqual(secrets_scan.plan(self.project.pk, domain_id=self.domain.pk), {})


class ValidationLockTests(StageBase):
    def opt_in(self):
        admin = User.objects.create_superuser('root-sec', password='x')
        secrets_validation.switch(self.project, admin, True, secrets_validation.ATTESTATION)
        return admin

    def test_the_switch_needs_an_admin_and_the_attestation_word_for_word_and_is_audited(self):
        member = User.objects.create_user('member-sec', password='x')
        with self.assertRaises(secrets_validation.SwitchError):
            secrets_validation.switch(self.project, member, True, secrets_validation.ATTESTATION)
        admin = User.objects.create_superuser('root-sec2', password='x')
        with self.assertRaises(secrets_validation.SwitchError):
            secrets_validation.switch(self.project, admin, True, 'yes')
        secrets_validation.switch(self.project, admin, True, secrets_validation.ATTESTATION)
        row = ProjectSettings.objects.get(project=self.project)
        self.assertEqual((row.secrets_validation, row.secrets_validation_by), (True, admin))
        log = AuditLog.objects.get(action='secrets.validation.enabled')
        self.assertEqual(log.detail['attestation'], secrets_validation.ATTESTATION)

    def test_a_bounty_project_never_validates_whatever_it_confirmed(self):
        self.opt_in()
        program = BountyProgram.objects.create(platform='hackerone', handle='ex', name='Example')
        BountyEngagement.objects.create(project=self.project, program=program, status='active', automated_ok=True)
        self.assertFalse(secrets_validation.enabled_for(self.project.pk))
        self.assertEqual(secrets_validation.plan(self.project.pk, [HOST], True), (False, []))
        with self.assertRaises(secrets_validation.SwitchError):
            secrets_validation.switch(self.project, User.objects.get(username='root-sec'), True, secrets_validation.ATTESTATION)

    def test_validation_runs_on_the_built_in_scanner_only_and_writes_its_audit_lines(self):
        self.opt_in()
        findings = [{'rule_id': 'betterleaks.github-pat', 'url': f'https://{HOST}/', 'secret': 'ghp_' + 'B' * 36,
                     'validation': {'outcome': 'verified_active'}, 'validation_meta': {'account_type': 'User'}},
                    {'rule_id': 'betterleaks.datadog-api-key', 'url': f'https://{HOST}/', 'secret': 'd' * 32,
                     'validation': {'outcome': 'verified_active'}}]  # not on the allow-list: its outcome is not kept
        with FakeScanner(kinds=['secrets_scan'], responders={'secrets_scan': self.responder(findings=findings)}) as fake:
            secrets_scan.run_for_scan(self.scan.id)
        target = fake.served[0]['target']
        self.assertTrue(target['validate'])
        self.assertIn('betterleaks.github-pat', target['validate_rules'])
        github = SecretFinding.objects.get(kind='github-token')
        self.assertEqual((github.status, github.severity, github.validation_outcome), ('live', 4, 'verified_active'))
        self.assertEqual(SecretFinding.objects.get(catalogued=False).status, 'unverified')
        self.assertTrue(AuditLog.objects.filter(action='secrets.validation.requested').exists())
        result = AuditLog.objects.get(action='secrets.validation.result')
        self.assertEqual((result.detail['rule_id'], result.detail['outcome']), ('betterleaks.github-pat', 'verified_active'))
        self.assertNotIn('ghp_', json.dumps(list(AuditLog.objects.values('detail'))))
        self.assertTrue(ledger.fresh(secrets_validation.LEDGER, [HOST], self.project.id))

    def test_an_external_sentinel_is_never_offered_a_validating_task(self):
        task = SentinelTask(kind='secrets_scan', project=self.project, target={'validate': True})
        eff = mock.Mock(builtin=False)
        self.assertTrue(broker.validating(task))
        self.assertEqual(broker.SentinelEff.refusal(mock.Mock(projects={self.project.slug}, hosts=None, caps={'secrets_scan'}, builtin=False,
                                                              _internal=lambda t: False), task), ('capability', broker.VALIDATING))
        self.assertFalse(broker.validating(SentinelTask(kind='secrets_scan', target={'validate': False})))
        del eff

    def test_a_scanner_that_validates_on_its_own_is_not_believed(self):
        findings = [{'rule_id': 'betterleaks.github-pat', 'url': f'https://{HOST}/', 'secret': 'ghp_' + 'C' * 36,
                     'validation': {'outcome': 'verified_active'}}]
        with FakeScanner(kinds=['secrets_scan'], responders={'secrets_scan': self.responder(findings=findings)}):
            secrets_scan.run_for_scan(self.scan.id)  # the project never opted in: the task said validate false
        self.assertEqual(SecretFinding.objects.get().status, 'unverified')


class FirebaseTests(SimpleTestCase):
    def fetch(self, status, body):
        return lambda method, url: bucket_probe.Response(status, {}, body.encode())

    def test_the_three_answers_and_nothing_kept(self):
        db = 'example-app-default-rtdb.firebaseio.com'
        public = bucket_probe.check(bucket_probe.FIREBASE, db, fetch=self.fetch(200, '{"users": true, "orders": true}'))
        self.assertEqual((public.state, public.objects), ('public', []))
        self.assertEqual(bucket_probe.check(bucket_probe.FIREBASE, db, fetch=self.fetch(200, 'null')).state, 'public')
        self.assertEqual(bucket_probe.check(bucket_probe.FIREBASE, db, fetch=self.fetch(401, '{"error": "Permission denied"}')).state, 'private')
        self.assertEqual(bucket_probe.check(bucket_probe.FIREBASE, db, fetch=self.fetch(404, '{"error": "404 Not Found"}')).state, 'missing')

    def test_only_documented_hosts_are_asked(self):
        self.assertTrue(bucket_probe.endpoint_allowed('example-app-default-rtdb.firebaseio.com'))
        self.assertTrue(bucket_probe.endpoint_allowed('example-app.europe-west1.firebasedatabase.app'))
        self.assertFalse(bucket_probe.endpoint_allowed('firebaseio.com.evil.example'))
        self.assertEqual(bucket_scan.firebase_db('example-app'), 'example-app.firebaseio.com')
        self.assertEqual(bucket_scan.ref_from_resource('firebase_storage', 'example-app.appspot.com'), bucket_scan.Ref(bucket_probe.GCS, 'example-app.appspot.com'))
        self.assertIsNone(bucket_scan.ref_from_resource('url', 'https://example.net/x'))
        self.assertIsNone(bucket_scan.ref_from_resource('ghcr', 'example/app'))

    def test_a_readable_database_is_high_when_named_like_the_project(self):
        cand = bucket_scan.Candidate(bucket_probe.FIREBASE, 'example-db.firebaseio.com', tier='reference', hosts=['www.example.test'], name_match=True)
        outcome = bucket_scan.evaluate(cand, bucket_probe.Verdict(state='public'))
        self.assertEqual([(f.check, f.severity) for f in outcome.findings], [('bkt_firebase_read', 3)])
        cand.name_match = False
        self.assertEqual(bucket_scan.evaluate(cand, bucket_probe.Verdict(state='public')).findings[0].severity, 2)
        self.assertEqual(bucket_scan.evaluate(cand, bucket_probe.Verdict(state='missing')).findings, [])


class CustomRulesTests(SimpleTestCase):
    GOOD = 'rules:\n- name: Example token\n  id: custom.example-token\n  pattern: \'\\bexm_[A-Za-z0-9]{32}\\b\'\n  confidence: high\n  keywords: [exm_]\n'

    def test_the_allowed_subset_and_never_a_validator(self):
        self.assertEqual(secret_rules.check_rules(self.GOOD), ['custom.example-token'])
        self.assertEqual(secret_rules.check_rules(''), [])
        refused = {
            'validation': self.GOOD + '  validation:\n    type: Http\n',
            'not custom': self.GOOD.replace('custom.example-token', 'kingfisher.example'),
            'bad regex': self.GOOD.replace("'\\bexm_[A-Za-z0-9]{32}\\b'", "'(unclosed'"),
            'not yaml': 'rules: [',
            'too big': 'rules: []\n#' + 'x' * secret_rules.MAX_BYTES,
        }
        for why, text in refused.items():
            with self.assertRaises(secret_rules.RulesError, msg=why):
                secret_rules.check_rules(text)

    def test_skip_lists_are_cleaned(self):
        self.assertEqual(secret_rules.check_skip([' EXAMPLE ', 'EXAMPLE', ''], ['^x+$']), (['EXAMPLE'], ['^x+$']))
        with self.assertRaises(secret_rules.RulesError):
            secret_rules.check_skip(['a'], ['(bad'])
