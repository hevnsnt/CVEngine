"""Which of a project's discovery API keys a Sentinel is sent (security review of develop @ 36d63dfa, MEDIUM 2).

Before: every key resolved for the project (its own, its organization's and the install's Chaos key) went to any Sentinel the gate allowed. Now a
Sentinel other than the built-in scanner is sent only the levels its enrolling user administers (``sentinel_stream.key_levels``), only for the modules
the task's mode runs (``sentinel_stream.modules_for``), and the levels held back are audited (``sentinel.discovery_keys.withheld``). Key values here
are fakes."""
import json

from agentapi import sentinel_stream as stream
from cveFeed import api_credentials as creds
from dashboard.models import ApiCredential, AuditLog, ChaosAPIKey, OrgMembership, ProjectMembership
from tests.test_bbot_keys_to_sentinels import KeysBase
from tests.test_sentinels import reset_rates

PROJECT_KEY, ORG_KEY, INSTANCE_KEY = 'FAKE-PROJECT-KEY-1a2b', 'FAKE-ORG-KEY-3c4d', 'FAKE-INSTANCE-CHAOS-5e6f'
ALL = {'shodan_dns': {'api_key': PROJECT_KEY}, 'virustotal': {'api_key': ORG_KEY}, 'chaos': {'api_key': INSTANCE_KEY}}


class LevelTests(KeysBase):
    def setUp(self):
        super().setUp()
        ApiCredential.objects.create(project=self.pa, service='shodan', value={'api_key': PROJECT_KEY})
        ApiCredential.objects.create(org=self.org1, service='virustotal', value={'api_key': ORG_KEY})
        ChaosAPIKey.objects.create(key=INSTANCE_KEY)

    def delivered(self, who, agent):
        reset_rates(self.t)
        task = self.keyed(agent)
        status, out = self.read(who, task)
        withheld = AuditLog.objects.filter(action='sentinel.discovery_keys.withheld', detail__task_id=task.pk).first()
        return status, (out.get('bbot_config') or {}).get('modules'), withheld.detail['levels'] if withheld else []

    def test_an_org_admins_sentinel_gets_the_project_and_org_keys_never_the_installs(self):
        status, modules, withheld = self.delivered('external', self.external)  # enrolled by dana, admin of the project's organization
        self.assertEqual(status, 200)
        self.assertEqual(modules, {k: v for k, v in ALL.items() if k != 'chaos'})
        self.assertEqual(withheld, ['instance'])
        row = AuditLog.objects.get(action='sentinel.discovery_keys.withheld')
        self.assertIn('instance level withheld from', row.target)
        self.assertNotIn(INSTANCE_KEY, json.dumps(row.detail) + row.target)
        self.assertEqual(AuditLog.objects.get(action='sentinel.discovery_keys.delivered').detail['withheld_levels'], ['instance'])

    def test_an_app_admins_sentinel_and_the_builtin_scanner_get_every_level(self):
        for who, agent in (('instance', self.instance), ('builtin', self.builtin)):
            with self.subTest(who):
                status, modules, withheld = self.delivered(who, agent)
                self.assertEqual((status, modules, withheld), (200, ALL, []))

    def test_a_sentinel_whose_enrolling_user_no_longer_administers_anything_gets_no_key(self):
        OrgMembership.objects.filter(user=self.dana, org=self.org1).update(role='user')
        status, modules, withheld = self.delivered('external', self.external)
        self.assertEqual((status, modules), (410, None))  # nothing it may be sent: the run goes on without keys (the client reads a refusal as none)
        self.assertEqual(withheld, ['project', 'org', 'instance'])
        self.assertFalse(AuditLog.objects.filter(action='sentinel.discovery_keys.delivered').exists())
        everything = self.everything()
        for key in (PROJECT_KEY, ORG_KEY, INSTANCE_KEY):
            self.assertNotIn(key, everything)

    def test_a_project_admin_who_is_not_an_org_admin_gets_the_projects_own_keys_only(self):
        OrgMembership.objects.filter(user=self.dana, org=self.org1).delete()
        ProjectMembership.objects.create(user=self.dana, project=self.pa, role='admin')
        status, modules, withheld = self.delivered('external', self.external)
        self.assertEqual((status, modules, withheld), (200, {'shodan_dns': {'api_key': PROJECT_KEY}}, ['org', 'instance']))

    def test_a_project_key_overrides_the_orgs_for_a_level_that_is_sent(self):
        ApiCredential.objects.create(org=self.org1, service='shodan', value={'api_key': 'FAKE-ORG-SHODAN'})
        OrgMembership.objects.filter(user=self.dana, org=self.org1).delete()
        ProjectMembership.objects.create(user=self.dana, project=self.pa, role='admin')
        status, modules, _ = self.delivered('external', self.external)
        self.assertEqual(modules['shodan_dns'], {'api_key': PROJECT_KEY})

    def test_the_levels_follow_the_enrolling_user(self):
        project = self.pa
        self.assertEqual(stream.key_levels(self.builtin, project), set(creds.LEVELS))
        self.assertEqual(stream.key_levels(self.instance, project), set(creds.LEVELS))
        self.assertEqual(stream.key_levels(self.external, project), {creds.PROJECT, creds.ORG})
        self.assertEqual(stream.key_levels(self.external, self.pb), set())  # an admin of another organization


class ModuleTests(KeysBase):
    def test_every_keyed_module_has_its_flags_and_every_mode_runs_them(self):
        mapped = {path.split('.')[1] for _label, _fields, mapping in creds.SERVICES.values() for path, _ in mapping}
        self.assertEqual(mapped, set(stream.KEYED_MODULE_FLAGS))
        for mode in stream.MODES:
            self.assertEqual(stream.modules_for(stream.bbot_target(self.da, mode, 3600)), mapped, mode)  # bbot 3.1.0: all are subdomain-enum, passive, safe

    def test_a_module_the_task_does_not_run_is_sent_no_key(self):
        target = stream.bbot_target(self.da, 'standard', 3600)
        self.assertNotIn('shodan_dns', stream.modules_for({**target, 'exclude_modules': ['shodan_dns']}))
        self.assertEqual(stream.modules_for({**target, 'presets': ['web', 'web-screenshots']}), set())
        self.assertEqual(stream.modules_for({**target, 'presets': ['subdomain-enum'], 'require_flags': ['code-enum']}), {'github_codesearch', 'github_org'})
        ApiCredential.objects.create(project=self.pa, service='shodan', value={'api_key': PROJECT_KEY})
        ApiCredential.objects.create(project=self.pa, service='virustotal', value={'api_key': ORG_KEY})
        task = self.keyed(self.builtin)
        task.target = {**target, 'exclude_modules': ['shodan_dns']}
        config, withheld = stream.keys_payload(task, self.builtin)
        self.assertEqual((config, withheld), ({'modules': {'virustotal': {'api_key': ORG_KEY}}}, []))
