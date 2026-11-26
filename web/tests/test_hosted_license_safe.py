"""The hosted license-safe switch (``cveFeed.license_safe``, ``CVENGINE_HOSTED_LICENSE_SAFE``): unset, every default stays as it was; set, WPScan is
denied above every policy and the sources with non-commercial terms are off. Also the Nmap notice and the AGPL labels the pages show."""
import os
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from jsonschema import Draft202012Validator

from agentapi import sentinel_contract as contract
from agentapi import sentinel_policy as policy
from agentapi import sentinel_stream as stream
from agentapi.services import ApiError
from cveFeed import archive_urls, ctmonitor, license_safe, software, wpscan_scan, zero_wire
from tests.test_sentinel_capability_policy import PolicyBase
from tests.test_sentinel_stream import StreamBase
from tests.test_tenancy import client_for

ON = {license_safe.ENV: '1'}


def off_env():
    """The environment with the switch removed, whatever the runner's own environment holds."""
    return mock.patch.dict(os.environ, {k: v for k, v in os.environ.items() if k != license_safe.ENV}, clear=True)


class SwitchTests(SimpleTestCase):
    def test_only_a_known_on_word_turns_it_on(self):
        with off_env():
            self.assertFalse(license_safe.enabled())
            self.assertEqual(license_safe.excluded_bbot_modules(), [])
        for word, expected in (('1', True), ('true', True), ('on', True), ('0', False), ('', False), ('maybe', False)):
            with mock.patch.dict(os.environ, {license_safe.ENV: word}):
                self.assertEqual(license_safe.enabled(), expected, word)

    def test_the_server_lookups_follow_the_switch(self):
        with off_env():
            self.assertTrue(archive_urls.lookup_enabled())  # the self-hosted default is unchanged
        with mock.patch.dict(os.environ, {**ON, 'CVENGINE_ARCHIVE_LOOKUP': '1'}):
            self.assertFalse(archive_urls.lookup_enabled())  # the hosted switch wins over an explicit on
            with mock.patch('dashboard.models.SystemTimings.current') as timings:
                self.assertFalse(ctmonitor.fallback_enabled())
                timings.assert_not_called()

    def test_zero_wire_fetches_nothing(self):
        get = mock.Mock(side_effect=AssertionError('the feed must not be fetched'))
        with mock.patch.dict(os.environ, ON):
            out = zero_wire.sync(get=get)
        self.assertIn('CVENGINE_HOSTED_LICENSE_SAFE', out['skipped'])
        get.assert_not_called()


class WpscanTokenAndPassTests(TestCase):
    def test_the_token_is_never_sent_and_the_thorough_pass_sends_nothing(self):
        project = mock.Mock()
        with mock.patch('cveFeed.api_credentials.resolve_for_project', return_value={'wpscan': {'api_key': 'k' * 43}}):
            with off_env():
                self.assertEqual(wpscan_scan.api_token(project), 'k' * 43)
            with mock.patch.dict(os.environ, ON):
                self.assertEqual(wpscan_scan.api_token(project), '')
        with mock.patch.dict(os.environ, ON), mock.patch('agentapi.sentinel_dispatch.wrap_wpscan_thorough_runner') as wrap:
            out = wpscan_scan.run_thorough(1)
        self.assertEqual(out['skipped'], wpscan_scan.WPSCAN_OFF)
        wrap.assert_not_called()


class PolicyTests(PolicyBase):
    def test_wpscan_is_denied_above_an_own_allow_only_while_the_switch_is_on(self):
        agent = self.external('wp', caps=('nmap', 'wpscan', 'wpscan_thorough'))
        self.manage(agent, {'kinds': {'wpscan': {'mode': 'allow', 'max_concurrent': None}}})
        agent.refresh_from_db()
        with off_env():
            self.assertEqual((policy.resolve(agent, False)['wpscan']['mode'], policy.resolve(agent, False)['wpscan']['source']), ('allow', 'agent'))
        with mock.patch.dict(os.environ, ON):
            resolved = policy.resolve(agent, False)
            for kind in license_safe.licensed_kinds():
                self.assertEqual((resolved[kind]['mode'], resolved[kind]['source']), ('deny', 'hosted license'), kind)
            self.assertEqual(resolved['nmap']['mode'], 'allow')
            self.assertIn('wpscan', policy.wire_disabled_kinds(agent, False))
            with self.assertRaises(ApiError) as refused:
                policy.refuse_unavailable(agent, {'wpscan_thorough': {'mode': 'allow', 'max_concurrent': None}})
            self.assertEqual(refused.exception.status, 409)
        self.assertIn('hosted license', policy.SOURCES)


class DiscoveryTargetTests(StreamBase):
    def test_a_hosted_discovery_leaves_the_non_commercial_modules_out(self):
        with off_env():
            self.assertEqual(stream.bbot_target(self.da, 'standard', 3600)['exclude_modules'], ['trufflehog'])
        with mock.patch.dict(os.environ, ON):
            target = stream.bbot_target(self.da, 'standard', 3600)
            deep = stream.bbot_target(self.da, 'deep', 3600, trufflehog=True)
        self.assertEqual(target['exclude_modules'], ['trufflehog', 'certspotter', 'shodan_idb', 'wayback'])
        self.assertEqual(deep['exclude_modules'], ['certspotter', 'shodan_idb', 'wayback'])
        self.assertEqual(list(Draft202012Validator(contract.target_schema('bbot_discovery')).iter_errors(target)), [])


class NoticeTests(TestCase):
    def test_the_about_and_how_pages_carry_the_nmap_notice(self):
        user = User.objects.create_user('notice-reader', password='x')
        client = client_for(user)
        for url in ('/cve/about/', '/cve/how-it-works/'):
            html = client.get(url).content.decode()
            self.assertIn(software.NMAP_NOTICE, html, url)
            self.assertIn('href="https://nmap.org"', html, url)

    def test_the_agpl_components_are_not_labelled_gpl(self):
        by_key = {t['key']: t for t in software.TOOLS}
        for key in ('baddns', 'badsecrets', 'blasthttp', 'blastdns', 'bbot'):
            self.assertTrue(by_key[key]['license'].startswith('AGPL-3.0'), key)
