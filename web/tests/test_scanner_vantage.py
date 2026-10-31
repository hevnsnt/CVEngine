"""The vantage-point guard of ``CVENGINE_LOCAL_FALLBACK`` (``agentapi.scanner_state.vantage_warnings``): a kind taken off this server runs from the scanner's
network, which has none of this server's egress proxy, Tailscale network namespace or ``CVENGINE_ALLOW_PRIVATE_TARGETS`` setting. It only warns (an
administrator sees it in the system status), never refuses, never writes ``ScanControl`` and says nothing about internal ranges (Sentinel-only by design)."""
import json
import os
import uuid
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi import scanner_state, sentinel_dispatch
from agentapi.auth import create_token
from cveFeed import egress_proxy
from cveFeed.models import InternalRange, ScanControl
from dashboard.models import Org, Project, ProjectMembership
from scanEngine.models import Proxy
from tests.test_system_status import call, patched

ENV = sentinel_dispatch.LOCAL_FALLBACK_ENV
PROXY = 'http://proxy.example:3128'


def all_but(*moved):
    """A ``CVENGINE_LOCAL_FALLBACK`` value that keeps every kind running here except ``moved`` (the variable lists the kinds that MAY stay)."""
    from agentapi.models import SentinelTask
    return ','.join(k for k in SentinelTask.KINDS if k not in moved)


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

    def proxy_on(self):
        Proxy.objects.all().delete()
        Proxy.objects.create(use_proxy=True, proxies=PROXY)
        egress_proxy.reset_cache()


class VantageWarningTests(VantageBase):
    def test_nothing_set_nothing_to_warn_and_no_query(self):
        os.environ['CVENGINE_ALLOW_PRIVATE_TARGETS'] = '1'
        os.environ['COMPOSE_PROFILES'] = 'tailscale'
        self.proxy_on()
        for value in (None, '', 'all', '*'):
            if value is None:
                os.environ.pop(ENV, None)
            else:
                os.environ[ENV] = value
            with self.assertNumQueries(0):
                self.assertEqual(scanner_state.vantage_warnings(), [], value)

    def test_a_policy_that_takes_nothing_off_is_quiet(self):
        os.environ['CVENGINE_ALLOW_PRIVATE_TARGETS'] = '1'
        from agentapi.models import SentinelTask
        os.environ[ENV] = ','.join(SentinelTask.KINDS)
        self.assertEqual(scanner_state.vantage_warnings(), [])

    def test_none_with_no_special_vantage_is_quiet(self):
        os.environ[ENV] = 'none'
        self.assertEqual(scanner_state.vantage_warnings(), [])

    def test_a_proxy_names_only_the_kinds_that_use_it(self):
        os.environ[ENV] = 'none'
        self.proxy_on()
        out = scanner_state.vantage_warnings()
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0], "CVENGINE_LOCAL_FALLBACK moves nuclei_light, nuclei_targeted, nuclei_deep, testssl, wpscan to the built-in scanner, which does not "
                                 "use this server's egress proxy; those scans will start from the scanner's network instead.")

    def test_a_proxy_is_quiet_when_every_proxied_kind_still_runs_here(self):
        os.environ[ENV] = 'nuclei_light,nuclei_targeted,nuclei_deep,testssl,wpscan'  # nmap, naabu and udp use raw sockets: the proxy never applied
        self.proxy_on()
        self.assertEqual(scanner_state.vantage_warnings(), [])

    def test_a_proxy_that_is_switched_off_or_has_no_valid_line_is_not_configured(self):
        os.environ[ENV] = 'none'
        Proxy.objects.create(use_proxy=False, proxies=PROXY)
        egress_proxy.reset_cache()
        self.assertEqual(scanner_state.vantage_warnings(), [])
        Proxy.objects.all().update(use_proxy=True, proxies='socks4://nope:1')
        egress_proxy.reset_cache()
        self.assertEqual(scanner_state.vantage_warnings(), [])

    def test_the_tailscale_profile_warns_for_every_kind_taken_off(self):
        os.environ[ENV] = 'nmap,naabu'
        os.environ['COMPOSE_PROFILES'] = 'builtin-scanner, Tailscale'
        out = scanner_state.vantage_warnings()
        self.assertEqual(len(out), 1)
        self.assertIn('moves nuclei_light, nuclei_targeted, nuclei_deep, testssl, nmap_udp, wpscan, openvas to the built-in scanner, which does not use the '
                      'Tailscale network; those scans will start from the scanner\'s network instead.', out[0])
        self.assertTrue(out[0].startswith('CVENGINE_LOCAL_FALLBACK moves '))

    def test_other_profiles_are_not_tailscale(self):
        os.environ[ENV] = 'none'
        os.environ['COMPOSE_PROFILES'] = 'builtin-scanner,openvas,tailscale-ish'
        self.assertEqual(scanner_state.vantage_warnings(), [])

    def test_a_published_node_status_file_is_tailscale_too(self):
        import tempfile
        os.environ[ENV] = all_but('testssl')
        with tempfile.NamedTemporaryFile() as handle:
            os.environ['CVENGINE_TAILSCALE_STATUS_FILE'] = handle.name
            out = scanner_state.vantage_warnings()
        self.assertEqual(len(out), 1)
        self.assertIn('moves testssl to the built-in scanner, which does not use the Tailscale network', out[0])

    def test_private_targets_allowed_warns(self):
        os.environ[ENV] = all_but('wpscan')
        for value in ('1', 'true', 'YES'):
            os.environ['CVENGINE_ALLOW_PRIVATE_TARGETS'] = value
            out = scanner_state.vantage_warnings()
            self.assertEqual(len(out), 1, value)
            self.assertIn('moves wpscan to the built-in scanner, which does not use the private-target setting (CVENGINE_ALLOW_PRIVATE_TARGETS)', out[0])
        for value in ('0', '', 'no'):
            os.environ['CVENGINE_ALLOW_PRIVATE_TARGETS'] = value
            self.assertEqual(scanner_state.vantage_warnings(), [], value)

    def test_several_causes_give_one_sentence_each(self):
        os.environ[ENV] = 'none'
        os.environ['COMPOSE_PROFILES'] = 'tailscale'
        os.environ['CVENGINE_ALLOW_PRIVATE_TARGETS'] = '1'
        self.proxy_on()
        out = scanner_state.vantage_warnings()
        self.assertEqual(len(out), 3)
        self.assertIn('egress proxy', out[0])
        self.assertIn('Tailscale network', out[1])
        self.assertIn('private-target setting', out[2])

    def test_internal_ranges_never_warn_and_the_internal_only_kind_is_never_named(self):
        org = Org.objects.create(name='V', slug='vantage-org')
        project = Project.objects.create(name='V', slug='vantage-p', insert_date=timezone.now(), org=org)
        InternalRange.objects.create(project=project, cidr='10.20.0.0/24')
        os.environ[ENV] = 'none'
        self.assertEqual(scanner_state.vantage_warnings(), [])
        os.environ['CVENGINE_ALLOW_PRIVATE_TARGETS'] = '1'
        for sentence in scanner_state.vantage_warnings():
            self.assertNotIn('discover', sentence)

    def test_a_proxy_setting_that_cannot_be_read_is_not_a_warning_and_not_an_error(self):
        os.environ[ENV] = 'none'
        with mock.patch.object(egress_proxy, 'configured', side_effect=RuntimeError('db down')):
            self.assertEqual(scanner_state.vantage_warnings(), [])


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

    def test_unset_the_list_is_there_and_empty(self):
        os.environ['CVENGINE_ALLOW_PRIVATE_TARGETS'] = '1'
        data = self.status(self.t_root)
        self.assertEqual(data['scanning']['scanner']['vantage'], [])
        self.assertFalse([p for p in data['problems'] if 'scanner network' in p])

    def test_an_admin_gets_the_sentences_in_the_block_and_in_problems(self):
        os.environ[ENV] = 'none'
        os.environ['CVENGINE_ALLOW_PRIVATE_TARGETS'] = '1'
        os.environ['COMPOSE_PROFILES'] = 'tailscale'
        data = self.status(self.t_root)
        vantage = data['scanning']['scanner']['vantage']
        self.assertEqual(len(vantage), 2)
        for sentence in vantage:
            self.assertIn(sentence, data['problems'])
        self.assertEqual(vantage, scanner_state.vantage_warnings())
        self.assertEqual(data['overall'], 'degraded')
        self.assertFalse(data['scanning']['paused'])
        self.assertFalse(ScanControl.current().paused)

    def test_a_member_sees_no_server_setting(self):
        os.environ[ENV] = 'none'
        os.environ['CVENGINE_ALLOW_PRIVATE_TARGETS'] = '1'
        os.environ['COMPOSE_PROFILES'] = 'tailscale'
        data = self.status(self.t_member)
        self.assertEqual(data['scanning']['scanner']['vantage'], [])
        blob = json.dumps(data)
        for word in ('CVENGINE_ALLOW_PRIVATE_TARGETS', 'Tailscale network', 'scanner\'s network'):
            self.assertNotIn(word, blob)
        self.assertFalse([p for p in data['problems'] if 'scanner' in p.lower()])

    def test_the_vantage_list_is_not_in_the_page_strip_messages(self):
        os.environ[ENV] = 'none'
        os.environ['CVENGINE_ALLOW_PRIVATE_TARGETS'] = '1'
        out = scanner_state.status(admin=True)
        self.assertEqual(len(out['vantage']), 1)
        self.assertFalse([m for m in out['messages'] if 'private-target' in m])
