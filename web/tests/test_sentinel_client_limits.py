"""What the Sentinel client's local settings and compacted results mean to the server: machine limits, disabled kinds, compact OpenVAS entries."""
import re

from django.test import SimpleTestCase
from django.utils import timezone

from agentapi import sentinel_broker as sentinels
from agentapi import sentinel_settings as settings
from agentapi.models import Agent
from tests.test_sentinels import SentinelBase, register_sentinel


class CompactOpenvasResultTests(SimpleTestCase):
    def test_a_compact_entry_without_oid_or_cves_is_accepted_and_only_marks_the_address_scanned(self):
        body = {'results': [{'address': '203.0.113.7', 'port': '443/tcp'}, {'address': '203.0.113.7', 'port': '80/tcp'},
                            {'address': '203.0.113.8'}, {'address': 'not an address'}, 'junk'],
                'scanned_addresses': ['203.0.113.7'], 'without_cve': 3, 'unusable': 0}
        out = sentinels._clean_openvas_result(body)
        self.assertEqual(out['results'], [])  # nothing is stored as a finding
        self.assertEqual(sorted(out['scanned_addresses']), ['203.0.113.7', '203.0.113.8'])
        self.assertEqual(out['without_cve'], 3)

    def test_a_full_entry_still_counts_its_address_as_scanned(self):
        body = {'results': [{'oid': '1.3.6.1.4.1.25623.1.0.1', 'address': '203.0.113.9', 'port': '22/tcp', 'severity': 5.0, 'cves': ['CVE-2020-1234']}]}
        out = sentinels._clean_openvas_result(body)
        self.assertEqual(len(out['results']), 1)
        self.assertEqual(out['scanned_addresses'], ['203.0.113.9'])

    def test_an_empty_report_stays_empty_so_the_server_reads_it_as_inconclusive(self):
        out = sentinels._clean_openvas_result({'results': [], 'scanned_addresses': []})
        self.assertEqual((out['results'], out['scanned_addresses']), ([], []))


class MachineLimitTests(SentinelBase):
    def sentinel(self, caps=('nmap', 'nuclei_light', 'network:internal')):
        out = register_sentinel(self.t['dana'], name='limited', capabilities=list(caps))[1]
        agent = Agent.objects.get(pk=out['id'])
        Agent.objects.filter(pk=agent.pk).update(network='internal', status='active', last_seen=timezone.now())
        agent.refresh_from_db()
        return agent

    def report(self, agent, **values):
        settings.record_reported(agent, values)
        agent.refresh_from_db()

    def test_a_machine_that_says_external_is_never_raised_to_internal(self):
        agent = self.sentinel()
        self.assertIn(sentinels.INTERNAL_CAPABILITY, sentinels.effective_capabilities(agent))
        self.report(agent, network='external')
        self.assertNotIn(sentinels.INTERNAL_CAPABILITY, sentinels.effective_capabilities(agent))
        entry = settings.detail(agent)['network']
        self.assertTrue(entry['limited_by_machine'])
        self.assertEqual(entry['machine_value'], 'external')
        self.assertEqual(settings.effective_network(agent), 'external')

    def test_a_machine_that_agrees_is_not_marked_limited(self):
        agent = self.sentinel()
        self.report(agent, network='internal')
        self.assertNotIn('limited_by_machine', settings.detail(agent)['network'])
        self.assertIn(sentinels.INTERNAL_CAPABILITY, sentinels.effective_capabilities(agent))

    def test_a_machine_that_limits_self_update_is_shown_to_the_administrator(self):
        agent = self.sentinel()
        settings.set_managed(agent, {'self_update': 'automatic'}, self.dana)
        self.report(agent, self_update='manual')
        entry = settings.detail(agent)['self_update']
        self.assertTrue(entry['limited_by_machine'])
        self.assertEqual((entry['machine_value'], entry['wanted']), ('manual', 'automatic'))

    def test_a_kind_disabled_on_the_machine_or_by_an_administrator_is_not_offered(self):
        agent = self.sentinel(('nmap', 'nuclei_light', 'wpscan'))
        self.assertEqual(sentinels.effective_capabilities(agent) & {'nmap', 'nuclei_light', 'wpscan'}, {'nmap', 'nuclei_light', 'wpscan'})
        self.report(agent, disabled_kinds=['wpscan'])
        settings.set_managed(agent, {'disabled_kinds': ['nuclei_light']}, self.dana)
        agent.refresh_from_db()
        caps = sentinels.effective_capabilities(agent)
        self.assertEqual(caps & {'nmap', 'nuclei_light', 'wpscan'}, {'nmap'})  # both sides only add to the disabled set
        task_refusal = sentinels.effective(agent)
        self.assertNotIn('wpscan', task_refusal.caps)


class NginxResultRouteTests(SimpleTestCase):
    def test_only_the_sentinel_result_route_may_carry_a_large_body(self):
        import os
        repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        conf = open(os.path.join(repo, 'config', 'nginx', 'rengine.conf'), encoding='utf-8').read()
        sizes = re.findall(r'client_max_body_size\s+(\d+)M', conf)
        self.assertEqual(sizes, ['4', '24'])  # the server default, then the one route
        block = conf[conf.index('location ~ ^/api/v1/sentinel/tasks/'):]
        block = block[:block.index('proxy_pass')]
        self.assertIn('24M', block)
