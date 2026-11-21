"""Sentinel contract 11 on the server: no template set, no bundle and no target-name lookup here. A nuclei task names the policy and the Sentinel builds the
approved set from its baked templates and its library's template index; an installed template's test names its path and hash and the Sentinel sends back
the text it ran; nuclei work goes only to a Sentinel of contract 11 or later; a target the Sentinel refused is said, not looked up here. Also the
heartbeat's optional ``running`` list (from the module this one replaces)."""
from datetime import timedelta
from unittest import mock

from cvengine_scanner import flags as scan_flags
from cvengine_scanner import template_index
from django.test import Client, SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import ai_checks
from agentapi import sentinel_broker as sb
from agentapi import sentinel_dispatch as dispatch
from agentapi.auth import hash_token  # noqa: F401 - used by the heartbeat tests below
from agentapi.models import Agent, SentinelTask
from cveFeed import nuclei_scan, nuclei_templates, templategen, validation
from dashboard.models import Project, ScanPolicy
from tests.test_agentapi import call
from tests.test_sentinel_hardening import enroll
from tests.test_sentinels import SentinelBase, register_sentinel, reset_rates

CVE = 'CVE-2021-44228'


def installed(cve=CVE):
    path, entry = template_index.for_cve(cve)[0]
    return path, entry


class NoBundleRouteTests(SentinelBase):
    def test_the_template_policy_routes_are_gone(self):
        token = enroll(self.t['dana'])['token']
        reset_rates({'sentinel': token})
        for path in ('/api/v1/sentinel/template-policy', '/api/v1/sentinel/template-policy/bundle'):
            with self.subTest(path=path):
                self.assertIn(Client().get(path, HTTP_AUTHORIZATION=f'Bearer {token}').status_code, (403, 404))


class TaskTargetTests(TestCase):
    def setUp(self):
        ScanPolicy.objects.all().delete()
        ScanPolicy.objects.create(nuclei_all_templates=False)

    def test_a_nuclei_target_names_the_policy_and_the_index_never_a_bundle(self):
        target = dispatch._nuclei_target('nuclei_targeted', ['www.example.com'], {'tags': ['apache']})
        self.assertEqual(target['template_policy'], {'rev': nuclei_scan.TEMPLATE_POLICY_REV, 'read_only': True, 'source': 'index'})
        self.assertIs(target['external'], True)  # outside work: the Sentinel holds every name to public space
        self.assertNotIn('external', dispatch._nuclei_target('nuclei_targeted', ['10.0.0.5'], {}, internal=True))
        from cvengine_scanner import contract
        from jsonschema import Draft202012Validator
        Draft202012Validator(contract.target_schema('nuclei_targeted')).validate(target)

    def test_the_policy_follows_the_setting(self):
        ScanPolicy.objects.update(nuclei_all_templates=True)
        target = dispatch._nuclei_target('nuclei_deep', ['www.example.com'], {})
        self.assertFalse(target['template_policy']['read_only'])
        self.assertEqual(nuclei_scan.policy_flags()[0], False)

    def test_the_approved_revision_moves_with_the_policy_and_the_index(self):
        first = nuclei_scan.approved_revision()
        ScanPolicy.objects.update(nuclei_all_templates=True)
        self.assertNotEqual(nuclei_scan.approved_revision(), first)
        with mock.patch.object(template_index, 'load', return_value={'nuclei_templates': '', 'templates': {}, 'reasons': [], 'sha256': ''}):
            with self.assertRaises(RuntimeError):
                nuclei_scan.approved_revision()


class OldSentinelTests(SentinelBase):
    def agent(self, version):
        register_sentinel(self.t['dana'])
        agent = Agent.objects.filter(kind='scanner').order_by('-id').first()
        agent.info = {**(agent.info or {}), 'contract_version': version}
        agent.capabilities = sorted(set(agent.capabilities or []) | {'nuclei_light', 'nuclei_targeted', 'nuclei_deep', 'nuclei_validate'})
        agent.save()
        return agent

    def test_a_sentinel_before_contract_11_is_never_credited_with_nuclei_work(self):
        old = sb.effective_capabilities(self.agent(10))
        self.assertFalse(old & set(sb.TEMPLATE_INDEX_KINDS))
        new = sb.effective_capabilities(self.agent(scan_flags.TEMPLATE_INDEX_SINCE))
        self.assertTrue(set(sb.TEMPLATE_INDEX_KINDS) <= new)

    def test_an_installed_template_test_is_refused_to_an_older_sentinel(self):
        task = SentinelTask(kind='nuclei_validate', target={'mode': 'test', 'template_path': 'http/x.yaml', 'template_sha256': 'a' * 64, 'targets': []})
        self.assertTrue(sb.installed_check_task(task))
        self.assertFalse(sb.installed_check_task(SentinelTask(kind='nuclei_validate', target={'mode': 'test', 'template': 'id: x'})))
        self.assertFalse(sb.runs_template_index(Agent(info={'contract_version': 10})))
        self.assertTrue(sb.runs_template_index(Agent(info={'contract_version': 11})))
        self.assertFalse(sb.runs_template_index(Agent(info={})))


class InstalledTemplateTests(TestCase):
    def setUp(self):
        ScanPolicy.objects.all().delete()
        ScanPolicy.objects.create(nuclei_all_templates=False)

    def test_a_cves_template_is_a_reference_into_the_release_never_a_file_here(self):
        found = templategen.find_existing_template(CVE)
        path, entry = installed()
        self.assertIn(templategen.INSTALLED_PREFIX + path, found)
        self.assertEqual(templategen.installed_relative(templategen.INSTALLED_PREFIX + path), path)
        ref, why = validation.resolve_template(CVE)
        if ref:  # approved under the read-only policy: the index's verdict, not a text read here
            self.assertEqual(validation.approved_template(ref), ('', ''))
            self.assertEqual(validation.template_fingerprint(ref), template_index.entry_for(templategen.installed_relative(ref))['sha256'])
        else:
            self.assertTrue(why)

    def test_a_template_the_policy_refuses_is_refused_with_the_index_reason(self):
        refused = next(p for p, e in sorted(template_index.load()['templates'].items()) if template_index.reason(e, 'ro') and not template_index.reason(e, 'refuse'))
        entry, problem = validation.installed_approval(refused)
        self.assertTrue(problem.startswith('template not validated'))
        self.assertEqual(validation.approved_template(templategen.INSTALLED_PREFIX + refused), ('', problem))
        self.assertTrue(validation.installed_approval('http/not-there.yaml')[1])

    def test_the_approval_is_bound_to_the_index_hash(self):
        path = next(p for p, e in sorted(template_index.load()['templates'].items()) if p.startswith('http/cves/') and not template_index.policy_problem(e))
        entry = template_index.entry_for(path)
        self.assertEqual(ai_checks.installed_problem(path, entry['sha256'], builtin=True), '')
        self.assertIn('another hash', ai_checks.installed_problem(path, 'f' * 64, builtin=True))

    def test_a_test_sends_the_path_and_reads_the_text_the_sentinel_ran(self):
        path, entry = installed()
        text = 'id: CVE-2021-44228\n'
        sent = []

        def fake_many(project, kind, chunks, labeler=None, prepare=None, **kw):
            for index, chunk in enumerate(chunks):
                target, _ = prepare(chunk)
                sent.append(target)
                yield index, {'template_sha256': entry['sha256'], 'template': text,
                              'outcomes': [{'host': h, 'vulnerable': False, 'output': ''} for h in chunk]}
        project = Project(pk=1, slug='p')
        with mock.patch.object(ai_checks, 'installed_problem', return_value=''), mock.patch.object(ai_checks, 'builtin_in_use', return_value=True), \
                mock.patch.object(dispatch, 'scanner_or_local'), mock.patch.object(sb, 'installed_check_scanner', return_value=True), \
                mock.patch.object(dispatch, 'dispatch_many', side_effect=fake_many), mock.patch.object(ai_checks, 'digest', return_value=entry['sha256']):
            outcomes, ran = dispatch.try_installed_template_test(path, entry['sha256'], ['www.example.com'], project)
        self.assertEqual(sent[0], {'mode': 'test', 'template_path': path, 'template_sha256': entry['sha256'], 'targets': ['www.example.com']})
        self.assertNotIn('template', sent[0])
        self.assertEqual(ran, text)
        self.assertEqual(outcomes[0]['host'], 'www.example.com')

    def test_a_hit_without_the_text_that_ran_is_not_read_as_a_confirmation(self):
        path, entry = installed()
        ref = templategen.INSTALLED_PREFIX + path
        hit = [{'host': 'www.example.com', 'vulnerable': True, 'output': 'x', 'hit': {'response': 'HTTP/1.1 200 OK'}}]
        with mock.patch.object(validation, 'installed_approval', return_value=(entry, '')), \
                mock.patch.object(dispatch, 'try_installed_template_test', return_value=(hit, '')):
            out = templategen.run_template(ref, ['www.example.com'], project=1)
        self.assertFalse(out[0]['vulnerable'])
        self.assertIn('did not send back the template', out[0]['error'])

    def test_with_no_sentinel_new_enough_every_host_waits(self):
        path, entry = installed()
        with mock.patch.object(ai_checks, 'installed_problem', return_value=''), mock.patch.object(ai_checks, 'builtin_in_use', return_value=True), \
                mock.patch.object(dispatch, 'scanner_or_local'), mock.patch.object(sb, 'installed_check_scanner', return_value=False), \
                mock.patch.object(dispatch, 'dispatch_many', side_effect=lambda *a, **k: (x for x in ())):
            outcomes, ran = dispatch.try_installed_template_test(path, entry['sha256'], ['www.example.com'], Project(pk=1, slug='p'))
        self.assertEqual(ran, '')
        self.assertTrue(outcomes[0]['error'].startswith('not tested: no scanner could take this work'))

    def test_a_result_text_that_is_not_the_sent_template_is_rejected(self):
        task = SentinelTask(kind='nuclei_validate', target={'mode': 'test', 'template_path': 'http/x.yaml', 'template_sha256': ai_checks.digest('id: x\n'), 'targets': []})
        self.assertEqual(ai_checks.result_problem(task, {'template_sha256': task.target['template_sha256'], 'template': 'id: x\n'}, builtin=True), '')
        self.assertIn('not the template', ai_checks.result_problem(task, {'template_sha256': task.target['template_sha256'], 'template': 'id: y\n'}, builtin=True))


class TemplateMetadataTests(SimpleTestCase):
    def test_the_tag_offer_and_the_panel_products_come_from_the_index(self):
        self.assertIn('tech', nuclei_templates.installed_tags())
        self.assertGreater(len(nuclei_templates.installed_index().products), 1000)
        panels = nuclei_templates.panel_products()
        self.assertGreater(len(panels), 500)
        self.assertTrue(all(set(v) == {'vendor', 'product', 'part'} and v['product'] for v in panels.values()))

    def test_an_index_of_its_own(self):
        index = {'nuclei_templates': 'v0', 'rules': 1, 'reasons': [], 'sha256': 'x' * 64, 'templates': {
            'http/exposed-panels/acme-panel.yaml': {'sha256': 'a' * 64, 'id': 'acme-panel', 'tags': ['panel', 'acme'], 'cpe': 'a:acme:widget'},
            'http/technologies/other.yaml': {'sha256': 'b' * 64, 'id': 'other', 'tags': ['tech'], 'vendor': 'acme', 'product': 'gizmo'}}}
        self.assertEqual(nuclei_templates.panel_products(index), {'acme-panel': {'vendor': 'acme', 'product': 'widget', 'part': 'a'}})
        built = nuclei_templates.installed_index(index)
        self.assertEqual(built.tags, frozenset({'panel', 'acme', 'tech'}))
        self.assertEqual(built.products['gizmo'], {'tech': 1})


class RefusedTargetTests(SimpleTestCase):
    def test_a_target_the_sentinel_refused_is_named_from_its_own_reason(self):
        named = [{'target': 'inside.example.com', 'reason': scan_flags.NUCLEI_REFUSED_PREFIX + 'the name resolves to a refused address'},
                 {'target': 'www.example.com:8443', 'reason': 'the run ran out of time'}]
        self.assertEqual(dispatch._refused_of(named, ['inside.example.com', 'www.example.com:8443', 'other.example.com']), {'inside.example.com'})
        self.assertEqual(dispatch._refused_of([], ['a.example.com']), set())


class HeartbeatRunningTests(SentinelBase):
    def setUp(self):
        super().setUp()
        self.project = Project.objects.get(slug='sen-a')

    def running_task(self, token, accepted_ago=300, host='www.a.example'):
        """A task leased to this Sentinel and accepted ``accepted_ago`` seconds ago."""
        task = SentinelTask.objects.create(project=self.project, scan=self.scan, kind='naabu', target={'addresses': ['192.0.2.50']},
                                           host=host, ips=['192.0.2.50'])
        status, out = call(token, 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.assertEqual(out['task']['id'], task.pk)
        self.assertEqual(call(token, 'POST', f'/api/v1/sentinel/tasks/{task.pk}/accept')[0], 200)
        SentinelTask.objects.filter(pk=task.pk).update(accepted_at=timezone.now() - timedelta(seconds=accepted_ago))
        return task

    def heartbeat(self, token, body=None):
        reset_rates({'t': token})
        return call(token, 'POST', '/api/v1/sentinel/heartbeat', body)

    def test_a_task_missing_from_the_list_is_ended_as_expired(self):
        register_sentinel(self.t['dana'])
        task = self.running_task(self.t['dana'])
        status, out = self.heartbeat(self.t['dana'], {'running': []})
        self.assertEqual(status, 200)
        task.refresh_from_db()
        self.assertEqual((task.status, task.error), ('expired', 'the Sentinel no longer reports this task'))
        self.assertIsNone(task.agent_id)
        self.assertEqual(out['leases'], [])  # and the reply does not offer a lease on it

    def test_a_task_in_the_list_is_kept_and_its_lease_extended(self):
        register_sentinel(self.t['dana'])
        task = self.running_task(self.t['dana'])
        status, out = self.heartbeat(self.t['dana'], {'running': [task.pk, 999999]})
        self.assertEqual(status, 200)
        task.refresh_from_db()
        self.assertEqual(task.status, 'running')
        self.assertEqual([lease['task_id'] for lease in out['leases']], [task.pk])

    def test_a_task_accepted_less_than_two_minutes_ago_is_left_alone(self):
        register_sentinel(self.t['dana'])
        fresh = self.running_task(self.t['dana'], accepted_ago=60)
        self.heartbeat(self.t['dana'], {'running': []})
        fresh.refresh_from_db()
        self.assertEqual(fresh.status, 'running')
        SentinelTask.objects.filter(pk=fresh.pk).update(accepted_at=timezone.now() - timedelta(seconds=121))
        self.heartbeat(self.t['dana'], {'running': []})
        fresh.refresh_from_db()
        self.assertEqual(fresh.status, 'expired')

    def test_another_sentinels_tasks_are_never_touched(self):
        register_sentinel(self.t['dana'], name='sentinel-dana')
        register_sentinel(self.t['alice'], name='sentinel-alice')
        mine = self.running_task(self.t['dana'])
        theirs = self.running_task(self.t['alice'], host='www2.a.example')
        self.assertNotEqual(mine.pk, theirs.pk)
        self.heartbeat(self.t['dana'], {'running': []})
        mine.refresh_from_db()
        theirs.refresh_from_db()
        self.assertEqual((mine.status, theirs.status), ('expired', 'running'))
        self.assertIsNotNone(theirs.agent_id)
        self.heartbeat(self.t['dana'], {'running': [theirs.pk]})  # naming another Sentinel's task changes nothing either
        theirs.refresh_from_db()
        self.assertEqual(theirs.status, 'running')

    def test_without_the_field_nothing_is_ended(self):
        register_sentinel(self.t['dana'])
        task = self.running_task(self.t['dana'])
        for body in (None, {}, {'running': None}, {'info': None}):
            self.assertEqual(self.heartbeat(self.t['dana'], body)[0], 200)
        task.refresh_from_db()
        self.assertEqual(task.status, 'running')

    def test_a_claimed_task_that_was_never_accepted_is_judged_by_its_claim_time(self):
        register_sentinel(self.t['dana'])
        task = SentinelTask.objects.create(project=self.project, scan=self.scan, kind='naabu', target={'addresses': ['192.0.2.50']},
                                           host='www.a.example', ips=['192.0.2.50'])
        call(self.t['dana'], 'POST', '/api/v1/sentinel/tasks/next', {'wait': 0})
        self.heartbeat(self.t['dana'], {'running': []})
        task.refresh_from_db()
        self.assertEqual(task.status, 'claimed')  # just offered
        SentinelTask.objects.filter(pk=task.pk).update(claimed_at=timezone.now() - timedelta(seconds=200), lease_expires_at=timezone.now() + timedelta(seconds=60))
        self.heartbeat(self.t['dana'], {'running': []})
        task.refresh_from_db()
        self.assertEqual(task.status, 'expired')

    def test_a_bad_value_is_a_400_naming_the_field_and_ends_nothing(self):
        register_sentinel(self.t['dana'])
        task = self.running_task(self.t['dana'])
        for bad in ('1', 5, {'a': 1}, [0], [-1], [1.5], ['1'], [True], [None], [[1]], list(range(1, 102))):
            status, out = self.heartbeat(self.t['dana'], {'running': bad})
            self.assertEqual(status, 400, bad)
            self.assertIn('running', out['error'])
        task.refresh_from_db()
        self.assertEqual(task.status, 'running')
        self.assertEqual(self.heartbeat(self.t['dana'], {'running': list(range(1, 101))})[0], 200)  # exactly 100 is fine

    def test_the_expired_task_frees_the_slot_for_the_dispatcher(self):
        register_sentinel(self.t['dana'])
        task = self.running_task(self.t['dana'])
        self.heartbeat(self.t['dana'], {'running': []})
        self.assertFalse(SentinelTask.objects.filter(pk=task.pk, status__in=('claimed', 'running')).exists())
        agent_id = Agent.objects.get(token__key_hash=hash_token(self.t['dana'])).pk
        self.assertEqual(sb.slot_usage([agent_id]).get(agent_id, {}), {})
