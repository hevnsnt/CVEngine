"""AI-written checks run on the owner's own Sentinels (review findings D8, C6; docs/AI-REVIEWER.md).

``nuclei_validate`` (an AI-written draft's syntax check and benign loopback fixture, or an approved template's test) and ``path_probe`` (the scan path
survey) went only to the built-in scanner, so an install that scans only with its own Sentinels never ran them. While the built-in scanner is in use
nothing changes. With none, they go to the project's own Sentinels under these guards, proved here:

- the server never sends a check its gate did not approve (a draft that fails ``templategen.static_check``, a test template that is not an approved
  generated one or read-only), and never sends one that is not read-only or that reaches another port or host to a Sentinel that is not the
  built-in scanner;
- every task names the sha256 of its text; a task whose text and hash disagree (or whose text no longer passes) is never handed out, and the
  Sentinel's separate question (``GET sentinel/tasks/<id>/check``) is answered only for an unchanged, approved check it holds;
- a result that does not name the check it was sent is rejected, an outcome for a host the task did not name is dropped, and a hit whose result
  line names another host is not counted;
- only a Sentinel whose contract version is at least ``external_since`` is offered the kind (``nuclei_validate``: 4, ``path_probe``: 3);
- the path survey a Sentinel ran is kept as that Sentinel's verdict, and its own OS guesses are not believed while its path interferes.

The server reads ``external_since`` from the installed scanner library (cvengine_scanner, the commit pinned in web/requirements.txt), fail closed: with a
library that has no such table nothing here is offered outside the built-in scanner."""
import json
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import ai_checks, sentinel_broker, sentinel_contract
from agentapi import sentinel_dispatch as dispatch
from agentapi.models import SentinelTask
from agentapi.services import ApiError, Ctx
from cveFeed import os_detection, path_probe, templategen, validation
from reNgine import resources
from tests.fake_scanner import FakeScanner
from tests import test_sentinel_v3_kinds as v3

TEMPLATE = v3.NucleiValidateTests.TEMPLATE  # the contract fixture's draft: passes the static gate, read-only, own target
SHA = ai_checks.digest(TEMPLATE)
H = 'id: cve-2099-0001\ninfo:\n  name: c\n  severity: high\n'
NOT_READ_ONLY = H + 'http:\n  - method: POST\n    path: ["{{BaseURL}}/login"]\n    matchers:\n      - type: word\n        words: ["marker-1.2.3"]\n'
OTHER_PORT = H + 'network:\n  - host:\n      - "{{Hostname}}:22"\n    matchers:\n      - type: word\n        words: ["SSH-2.0-OpenSSH_7.2"]\n'
OTHER_HOST = H + 'http:\n  - method: GET\n    path: ["http://other.example.com/x"]\n    matchers:\n      - type: word\n        words: ["marker-1.2.3"]\n'
HOSTS = ['https://www.rt.test', 'https://api.rt.test']


def echo(outcomes=None, **fields):
    """A responder that answers like a contract-4 Sentinel: the hash it was sent, and ``outcomes`` (a function of the targets) for a test."""
    def answer(task):
        target = task['target']
        out = {'outcome': 'done', 'template_sha256': target['template_sha256'], **fields}
        if target['mode'] == 'validate':
            out.update(valid=True, output='ok', fixture_ok=True, fixture_note='no match on benign local fixture')
        else:
            out['outcomes'] = outcomes(target['targets']) if outcomes else [{'host': h, 'vulnerable': False, 'output': ''} for h in target['targets']]
        return out
    return answer


class Base(v3.StageBase):
    def external(self, kinds=('nuclei_validate', 'path_probe'), **kw):
        return FakeScanner(kinds=list(kinds), external=True, name=kw.pop('name', 'own-sentinel'), **kw).start_for(self)

    def builtin(self, kinds=('nuclei_validate', 'path_probe'), **kw):
        return FakeScanner(kinds=list(kinds), **kw).start_for(self)

    def queued(self, target, **kw):
        return SentinelTask.objects.create(project=self.project, kind='nuclei_validate', target=target, **kw)

    def ctx(self, fake):
        return Ctx(user=fake.agent.token.user, token=fake.agent.token)

    def claim(self, fake):
        return sentinel_broker.next_task(self.ctx(fake), {'kinds': ['nuclei_validate'], 'wait': 0})['task']


# ============================================================================== which Sentinel is offered the kinds

class RoutingTests(Base):
    def test_an_install_with_no_builtin_scanner_dispatches_a_draft_check_to_a_project_sentinel(self):
        self.arm('nuclei_validate')
        fake = self.external(responders={'nuclei_validate': echo()})
        dispatch.nuclei_validate_ready(self.project)  # does not raise: the AI may be asked for a draft
        valid, output = templategen.validate_anywhere(TEMPLATE, self.project)
        self.assertTrue(valid, output)
        self.assertEqual(fake.served[0]['target'], {'mode': 'validate', 'template': TEMPLATE, 'template_sha256': SHA})
        self.assertFalse(sentinel_broker.is_builtin(fake.agent))

    def test_a_draft_with_no_project_is_filed_under_a_project_that_has_such_a_sentinel(self):
        from dashboard.models import Project
        Project.objects.create(name='Older', slug='aaa-older', insert_date=timezone.now(), org=self.project.org)  # no Sentinel covers it
        fake = self.external(responders={'nuclei_validate': echo()}, scope={'orgs': [], 'projects': [self.project.slug], 'hosts': []})
        dispatch.nuclei_validate_ready(None)
        valid, _output = templategen.validate_anywhere(TEMPLATE, None)
        self.assertTrue(valid)
        self.assertEqual(fake.tasks()[0].project_id, self.project.id)

    def test_an_install_with_no_builtin_scanner_tests_an_approved_check_on_the_hosts_own_project_sentinel(self):
        self.arm('nuclei_validate')

        def outcomes(targets):
            return [{'host': targets[0], 'vulnerable': True, 'output': '{}', 'hit': {'matcher-name': 'word', 'matched-at': targets[0] + '/x'}},
                    {'host': targets[1], 'vulnerable': False, 'output': ''}]
        fake = self.external(responders={'nuclei_validate': echo(outcomes)})
        out = dispatch.try_template_test(TEMPLATE, HOSTS, self.project.id)
        self.assertEqual(fake.served[0]['target'], {'mode': 'test', 'template': TEMPLATE, 'template_sha256': SHA, 'targets': HOSTS})
        self.assertEqual(fake.tasks()[0].project_id, self.project.id)
        self.assertEqual([o['vulnerable'] for o in out], [True, False])
        self.assertNotIn('error', out[1])

    def test_while_the_builtin_scanner_is_in_use_both_kinds_stay_on_it(self):
        own = self.builtin()
        outside = self.external()
        for kind in ('nuclei_validate', 'path_probe'):
            with self.subTest(kind=kind):
                task = SentinelTask.objects.create(project=self.project, kind=kind, target={})
                self.assertEqual(sentinel_broker.effective(outside.agent).refusal(task), ('capability', sentinel_broker.BUILTIN))
                self.assertIsNone(sentinel_broker.effective(own.agent).refusal(task))
                task.delete()  # only asked about, never meant to run
        valid, _ = templategen.validate_anywhere(TEMPLATE, self.project)
        self.assertTrue(valid)
        self.assertEqual((len(own.served), len(outside.served)), (1, 0))

    def test_a_sentinel_older_than_contract_four_is_never_offered_a_check(self):
        self.external(contract_version=3)
        self.assertFalse(dispatch.any_scanner_for(self.project, 'nuclei_validate'))
        with self.assertRaises(resources.ScannerUnavailable):
            dispatch.nuclei_validate_ready(self.project)
        self.assertTrue(dispatch.any_scanner_for(self.project, 'path_probe'))  # nothing in the survey is new: contract 3 runs it as 4 does

    def test_the_signed_in_route_check_stays_with_the_builtin_scanner(self):
        self.external(kinds=['route_probe_signed', 'nuclei_validate'])
        self.assertFalse(dispatch.any_scanner_for(self.project, 'route_probe_signed'))
        self.assertTrue(dispatch.any_scanner_for(self.project, 'nuclei_validate'))

    def test_a_server_whose_library_has_no_external_table_offers_neither_kind_outside(self):
        self.external()
        with mock.patch.object(sentinel_contract, 'external_since', return_value=None):
            self.assertFalse(dispatch.any_scanner_for(self.project, 'nuclei_validate'))
            self.assertFalse(dispatch.any_scanner_for(self.project, 'path_probe'))


# ============================================================================== the server never sends an unapproved check

class NeverSentTests(Base):
    def assertNothingSent(self):
        self.assertFalse(SentinelTask.objects.filter(kind='nuclei_validate').exists())

    def test_a_draft_that_fails_the_static_gate_is_never_sent_to_the_builtin_scanner(self):
        self.builtin()
        self.assertDraftRefused()

    def test_a_draft_that_fails_the_static_gate_is_never_sent_to_a_sentinel(self):
        self.external()
        self.assertDraftRefused()

    def assertDraftRefused(self):
        valid, output = templategen.validate_anywhere(NOT_READ_ONLY, self.project)
        self.assertFalse(valid)
        self.assertIn('not validated', output)
        self.assertNothingSent()

    def test_a_test_template_the_server_did_not_approve_is_never_sent_to_any_scanner(self):
        self.builtin()
        with mock.patch.object(validation, 'all_templates_allowed', return_value=False):
            out = dispatch.try_template_test(NOT_READ_ONLY, HOSTS, self.project.id)
        self.assertNothingSent()
        self.assertTrue(all(o['error'].startswith('not tested: template not validated') for o in out), out)

    def test_a_template_that_is_not_read_only_never_goes_outside_the_builtin_scanner(self):
        self.external()
        with mock.patch.object(validation, 'all_templates_allowed', return_value=True):  # Settings allows every installed template
            out = dispatch.try_template_test(NOT_READ_ONLY, HOSTS, self.project.id)
        self.assertNothingSent()
        self.assertTrue(all('not tested' in o['error'] and 'read-only' in o['error'] for o in out), out)

    def test_the_builtin_scanner_still_runs_an_installed_template_the_setting_allows(self):
        own = self.builtin(responders={'nuclei_validate': echo()})
        with mock.patch.object(validation, 'all_templates_allowed', return_value=True):
            out = dispatch.try_template_test(NOT_READ_ONLY, HOSTS, self.project.id)
        self.assertEqual(len(own.served), 1)
        self.assertEqual([o.get('error', '') for o in out], ['', ''])

    def test_a_check_aimed_at_another_port_or_host_never_goes_to_a_sentinel(self):
        self.external()
        for text in (OTHER_PORT, OTHER_HOST):
            with self.subTest(text=text[-60:]):
                out = dispatch.try_template_test(text, HOSTS, self.project.id)
                self.assertTrue(all(o['error'].startswith('not tested') for o in out), out)
                valid, output = dispatch.try_nuclei_validate(text, self.project)[:2]
                self.assertFalse(valid)
                self.assertIn('not validated', output)
                self.assertNothingSent()

    def test_every_check_task_names_the_hash_of_its_own_text(self):
        own = self.builtin(responders={'nuclei_validate': echo()})
        templategen.validate_anywhere(TEMPLATE, self.project)
        dispatch.try_template_test(TEMPLATE, HOSTS, self.project.id)
        targets = [t.target for t in SentinelTask.objects.filter(kind='nuclei_validate')]
        self.assertEqual(len(targets), 2)
        for target in targets:
            self.assertEqual(target['template_sha256'], ai_checks.digest(target['template']))
        self.assertEqual(len(own.served), 2)


# ============================================================================== hand-out and the Sentinel's separate question

class HandOutTests(Base):
    def target(self, text=TEMPLATE, sha=SHA, mode='validate'):
        out = {'mode': mode, 'template': text, 'template_sha256': sha}
        return {**out, 'targets': HOSTS} if mode == 'test' else out

    def test_a_task_altered_after_dispatch_or_not_approved_is_never_handed_to_a_sentinel(self):
        fake = self.external()
        cases = {'altered text': self.target(text=TEMPLATE.replace('example-banner', 'other-banner')),
                 'no hash': {'mode': 'validate', 'template': TEMPLATE},
                 'not read-only': self.target(text=NOT_READ_ONLY, sha=ai_checks.digest(NOT_READ_ONLY), mode='test'),
                 'another port': self.target(text=OTHER_PORT, sha=ai_checks.digest(OTHER_PORT), mode='test')}
        for name, target in cases.items():
            with self.subTest(case=name):
                task = self.queued(target)
                self.assertIsNone(self.claim(fake))
                task.refresh_from_db()
                self.assertEqual(task.status, 'expired')
                self.assertIn('cancelled', task.error)

    def test_a_check_that_names_a_stored_sign_in_is_never_handed_outside(self):
        fake = self.external()
        task = self.queued(self.target(), secret_ref='authcred:1')
        self.assertIsNone(self.claim(fake))
        self.assertNotEqual(SentinelTask.objects.get(pk=task.pk).agent_id, fake.agent.pk)

    def test_the_sentinel_holding_an_approved_check_is_told_its_hash(self):
        fake = self.external()
        task = self.queued(self.target())
        self.assertEqual(self.claim(fake)['id'], task.pk)
        self.assertEqual(sentinel_broker.approved_check(self.ctx(fake), task.pk), {'task_id': task.pk, 'template_sha256': SHA, 'mode': 'validate'})

    def test_no_answer_for_a_task_not_held_altered_or_of_another_sentinel(self):
        fake = self.external()
        other = self.external(name='someone-else')
        held = self.queued(self.target())
        self.assertEqual(self.claim(fake)['id'], held.pk)
        queued = self.queued(self.target())
        with self.assertRaises(ApiError) as caught:
            sentinel_broker.approved_check(self.ctx(other), held.pk)  # held by another Sentinel
        self.assertEqual(caught.exception.status, 404)
        with self.assertRaises(ApiError):
            sentinel_broker.approved_check(self.ctx(fake), queued.pk)  # not claimed by it
        SentinelTask.objects.filter(pk=held.pk).update(target=self.target(text=TEMPLATE + '\n# changed\n'))  # the stored text changed under it
        with self.assertRaises(ApiError) as caught:
            sentinel_broker.approved_check(self.ctx(fake), held.pk)
        self.assertEqual(caught.exception.status, 404)

    def test_a_sentinel_token_reaches_the_route_over_http(self):
        from django.test import Client
        from agentapi.auth import SCOPE_SENTINEL, create_token
        fake = self.external()
        token, raw = create_token(fake.agent.token.user, 'aival-http', scope=SCOPE_SENTINEL)
        fake.agent.token = token
        fake.agent.save(update_fields=['token'])
        task = self.queued(self.target())
        self.assertEqual(self.claim(fake)['id'], task.pk)
        response = Client().get(f'/api/v1/sentinel/tasks/{task.pk}/check', HTTP_AUTHORIZATION=f'Bearer {raw}')
        self.assertEqual(response.status_code, 200, response.content[:300])
        self.assertEqual(response.json()['template_sha256'], SHA)
        other = self.queued(self.target())
        self.assertEqual(Client().get(f'/api/v1/sentinel/tasks/{other.pk}/check', HTTP_AUTHORIZATION=f'Bearer {raw}').status_code, 404)

    def test_the_route_is_published(self):
        from agentapi import rest
        self.assertTrue(any(method == 'GET' and pattern == r'sentinel/tasks/(?P<task_id>\d+)/check' for method, pattern, *_ in rest.ROUTES))


# ============================================================================== results held to the task

class ResultTests(Base):
    def test_an_external_result_that_does_not_name_the_check_it_was_sent_is_rejected(self):
        fake = self.external()
        good = {'outcome': 'done', 'valid': True, 'output': 'ok', 'fixture_ok': True, 'fixture_note': 'no match'}
        for name, body in (('another hash', {**good, 'template_sha256': 'b' * 64}), ('no hash', good)):
            with self.subTest(case=name):
                task = self.queued({'mode': 'validate', 'template': TEMPLATE, 'template_sha256': SHA})
                self.assertEqual(self.claim(fake)['id'], task.pk)
                sentinel_broker.accept_task(self.ctx(fake), task.pk)
                with self.assertRaises(ApiError) as caught:
                    sentinel_broker.report_result(self.ctx(fake), task.pk, body)
                self.assertEqual(caught.exception.status, 400)
                task.refresh_from_db()
                self.assertEqual(task.status, 'failed')
                self.assertIn('rejected', task.error)
                self.assertFalse(task.result)  # nothing of it kept

    def test_a_hit_that_names_another_host_or_an_unasked_host_is_not_counted(self):
        def outcomes(targets):
            return [{'host': targets[0], 'vulnerable': True, 'output': '{}', 'hit': {'matcher-name': 'word', 'matched-at': 'https://198.51.100.9/x'}},
                    {'host': targets[1], 'vulnerable': True, 'output': '{}', 'hit': {'matcher-name': 'word', 'host': 'https://api.rt.test'}},
                    {'host': 'https://elsewhere.example.test', 'vulnerable': True, 'output': '', 'hit': {'matcher-name': 'word'}}]
        self.external(responders={'nuclei_validate': echo(outcomes)})
        out = dispatch.try_template_test(TEMPLATE, HOSTS, self.project.id)
        self.assertFalse(out[0]['vulnerable'])
        self.assertIn('another host', out[0]['error'])
        self.assertTrue(out[1]['vulnerable'])
        self.assertEqual(len(out), 2)
        stored = SentinelTask.objects.get(kind='nuclei_validate').result
        self.assertNotIn('elsewhere.example.test', json.dumps(stored))
        self.assertNotIn('198.51.100.9', json.dumps(stored))

    def test_a_builtin_result_with_no_hash_is_still_taken(self):
        self.builtin(responders={'nuclei_validate': {'outcome': 'done', 'valid': True, 'output': '', 'fixture_ok': True, 'fixture_note': 'ok'}})
        valid, _output = templategen.validate_anywhere(TEMPLATE, self.project)
        self.assertTrue(valid)


# ============================================================================== the path survey, per Sentinel

class PathSurveyTests(Base):
    TARGETS = v3.PathProbeTests.TARGETS

    def survey(self, rows):
        fake = self.external(kinds=['path_probe'], contract_version=3, responders={'path_probe': {'outcome': 'done', 'results': rows}})
        with mock.patch.object(path_probe, 'candidates', return_value=self.TARGETS), mock.patch.object(path_probe, 'holder', return_value=self.project.id):
            return fake, path_probe.check()

    def test_with_no_builtin_scanner_the_survey_runs_on_the_projects_sentinel_and_is_kept_as_its_verdict(self):
        self.arm('path_probe')
        before = os_detection.path_state()
        fake, out = self.survey([{'ip': ip, 'port': port, 'plain': True, 'odd': False} for ip, port in self.TARGETS])
        self.assertEqual(len(fake.served), 1)
        self.assertEqual(out['sentinels'], {str(fake.agent.pk): 'interfering'})
        self.assertEqual(out['vantage'], 'sentinels')
        self.assertEqual(os_detection.sentinel_path_state(fake.agent.pk)['state'], 'interfering')
        self.assertEqual(os_detection.path_state(), before)  # the install-wide verdict is the built-in scanner's alone
        os_detection.record_path(out)  # what the daily task does with it
        self.assertEqual(os_detection.path_state()['state'], before['state'])
        self.assertEqual(os_detection.status()['path']['sentinels'], {str(fake.agent.pk): 'interfering'})  # shown, per Sentinel

    def test_an_os_guess_from_a_sentinel_whose_path_interferes_is_not_believed(self):
        fake, _out = self.survey([{'ip': ip, 'port': port, 'plain': True, 'odd': False} for ip, port in self.TARGETS])
        self.assertFalse(dispatch.os_reliable(dispatch.Result({'os_reliable': True}, agent_id=fake.agent.pk)))
        other, _ = self.survey([{'ip': ip, 'port': port, 'plain': True, 'odd': True} for ip, port in self.TARGETS])
        self.assertTrue(dispatch.os_reliable(dispatch.Result({'os_reliable': True}, agent_id=other.agent.pk)))
        self.assertFalse(dispatch.os_reliable(dispatch.Result({'os_reliable': False}, agent_id=other.agent.pk)))


# ============================================================================== one read-only rule on both sides

class SameVerdictTests(SimpleTestCase):
    def test_the_server_and_the_sentinel_judge_every_corpus_template_alike(self):
        from cvengine_scanner import checks
        from cvengine_scanner import contract as library
        corpus = json.loads((library.FIXTURES / 'checks' / 'corpus.json').read_text(encoding='utf-8'))['cases']
        self.assertGreaterEqual(len(corpus), 30)
        for case in corpus:
            with self.subTest(case=case['name']):
                self.assertEqual(validation.readonly_problem(case['template']) == '', case['read_only'])
                self.assertEqual(checks.readonly_problem(case['template']) == '', case['read_only'])
                self.assertEqual(ai_checks.external_problem(case['template']) == '', case['read_only'] and case['own_target'])
                self.assertEqual(checks.check_problem(case['template']) == '', case['read_only'] and case['own_target'])
