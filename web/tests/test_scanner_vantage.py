"""The vantage point of the built-in scanner. The server-side warning that a kind moved to a built-in scanner image without the ``vantage`` feature would scan
from the wrong network (``scanner_state.vantage_warnings``, ``scanning.scanner.vantage``) is gone: it only ever named kinds that could still run on this
server, and none can (``CVENGINE_LOCAL_FALLBACK`` is ignored since 1.4, every kind is in ``sentinel_dispatch.NEVER_LOCAL``). What stays is the Tailscale reading
that ``sentinel_settings.builtin_vantage`` uses (``scanner_state.tailscale_enabled``) and the proof that no setting makes the status warn about a moved kind.
The settings the built-in scanner is sent are tested in ``tests.test_builtin_default``."""
import json
import os
import tempfile
import uuid
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi import scanner_state, sentinel_dispatch
from agentapi.auth import create_token
from agentapi.models import Agent, SentinelEnrollment
from cveFeed import egress_proxy
from cveFeed.models import ScanControl
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import Proxy
from tests.test_system_status import call, patched

ENV = 'CVENGINE_LOCAL_FALLBACK'  # ignored since 1.4
PROXY = 'http://proxy.example:3128'


def older_builtin():
    """A built-in scanner (its enrollment makes it one) whose image does not report the ``vantage`` feature."""
    user = User.objects.create_superuser(f'builtin-owner-{uuid.uuid4().hex[:8]}', 'o@example.test', 'x')
    token, _raw = create_token(user, 'builtin')
    agent = Agent.objects.create(token=token, name='CVEngine Scanner', kind='scanner', status='active', info={'builtin': True},
                                 scope={'orgs': [], 'projects': [], 'hosts': []}, capabilities=['nmap'], last_seen=timezone.now())
    SentinelEnrollment.objects.create(token_hash=uuid.uuid4().hex, prefix='cve_enr_x', created_by=user, expires_at=timezone.now(), builtin=True,
                                      used_by_agent=agent, used_at=timezone.now())
    return agent


class VantageBase(TestCase):
    def setUp(self):
        super().setUp()
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in (ENV, 'COMPOSE_PROFILES', 'CVENGINE_ALLOW_PRIVATE_TARGETS'):
            os.environ.pop(name, None)
        os.environ['CVENGINE_TAILSCALE_STATUS_FILE'] = f'/nonexistent/{uuid.uuid4().hex}/status.json'
        key = mock.patch.object(scanner_state, 'CACHE_KEY', f'test:{uuid.uuid4().hex}:')
        key.start()
        self.addCleanup(key.stop)
        egress_proxy.reset_cache()
        self.addCleanup(egress_proxy.reset_cache)
        self.builtin = older_builtin()

    def proxy_on(self):
        Proxy.objects.all().delete()
        Proxy.objects.create(use_proxy=True, proxies=PROXY)
        egress_proxy.reset_cache()


class NothingMovesSoNothingWarnsTests(VantageBase):
    def test_the_warning_machinery_is_gone(self):
        for name in ('vantage_warnings', '_uses_proxy', 'IN_PROCESS_PROXIED', 'VANTAGE_FEATURE'):
            self.assertFalse(hasattr(scanner_state, name), name)

    def test_every_kind_a_scanner_could_be_moved_to_is_never_local(self):
        from agentapi.models import SentinelTask
        self.assertEqual(set(SentinelTask.KINDS) - set(sentinel_dispatch.NEVER_LOCAL), set(scanner_state.INTERNAL_ONLY))

    def test_the_tailscale_profile_is_read_whatever_case_and_spacing(self):
        os.environ['COMPOSE_PROFILES'] = 'builtin-scanner, Tailscale'
        self.assertTrue(scanner_state.tailscale_enabled())

    def test_other_profiles_are_not_tailscale(self):
        os.environ['COMPOSE_PROFILES'] = 'builtin-scanner,openvas,tailscale-ish'
        self.assertFalse(scanner_state.tailscale_enabled())

    def test_a_published_node_status_file_is_tailscale_too(self):
        with tempfile.NamedTemporaryFile() as handle:
            os.environ['CVENGINE_TAILSCALE_STATUS_FILE'] = handle.name
            self.assertTrue(scanner_state.tailscale_enabled())

    def test_a_proxy_is_still_sent_to_the_builtin_scanner_in_its_settings(self):
        Proxy.objects.all().delete()
        Proxy.objects.create(use_proxy=True, proxies=PROXY)
        egress_proxy.reset_cache()
        from agentapi import sentinel_settings
        self.assertTrue(egress_proxy.configured())
        self.assertIn('proxies', sentinel_settings.builtin_vantage())


class StatusSurfaceTests(VantageBase):
    @classmethod
    def setUpTestData(cls):
        cls.root = User.objects.create_superuser('vantage-root', 'r@x.io', 'x')
        cls.member = User.objects.create_user('vantage-member', password='x')
        _, cls.t_root = create_token(cls.root, 'root')
        _, cls.t_member = create_token(cls.member, 'member')

    def setUp(self):
        super().setUp()
        patch = mock.patch.dict(os.environ, {'CVENGINE_STATUS_CACHE_SECONDS': '0'})
        patch.start()
        self.addCleanup(patch.stop)
        org = Org.objects.create(name='V', slug='vantage-org2')
        project = Project.objects.create(name='V', slug='vantage-p2', insert_date=timezone.now(), org=org)
        ProjectMembership.objects.create(user=self.member, project=project, role='user')

    def status(self, token):
        a, b, c = patched()
        with a, b, c:
            return call(token, 'GET', '/api/v1/system/status')[1]

    def test_no_setting_makes_the_status_warn_about_a_moved_kind(self):
        os.environ['CVENGINE_ALLOW_PRIVATE_TARGETS'] = '1'
        os.environ['COMPOSE_PROFILES'] = 'tailscale'
        for value in ('all', 'none', 'nmap,naabu'):
            os.environ[ENV] = value
            data = self.status(self.t_root)
            self.assertNotIn('vantage', data['scanning']['scanner'])
            self.assertFalse([p for p in data['problems'] if 'built-in scanner, whose image' in p])
            self.assertFalse(ScanControl.current().paused)

    def test_a_member_sees_no_server_setting(self):
        os.environ['CVENGINE_ALLOW_PRIVATE_TARGETS'] = '1'
        os.environ['COMPOSE_PROFILES'] = 'tailscale'
        data = self.status(self.t_member)
        blob = json.dumps(data)
        for word in ('CVENGINE_ALLOW_PRIVATE_TARGETS', 'Tailscale addresses', 'whose image', 'CVENGINE_LOCAL_FALLBACK'):
            self.assertNotIn(word, blob)

    def test_the_scanner_block_never_names_the_ignored_variable(self):
        os.environ[ENV] = 'none'
        out = scanner_state.status(admin=True)
        self.assertNotIn('CVENGINE_LOCAL_FALLBACK', json.dumps(out))
        self.assertNotIn('unknown_kinds', out)
