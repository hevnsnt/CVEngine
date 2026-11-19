from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import path_probe
from dashboard.models import Org, Project
from startScan.models import IpAddress, Subdomain
from targetApp.models import Domain


def result(ip='93.184.216.34', plain=True, odd=True):
	return {'ip': ip, 'port': 81, 'plain': plain, 'odd': odd if plain else None}


class VerdictTests(SimpleTestCase):
	def test_a_clean_path_answers_the_odd_probe_too(self):
		self.assertEqual(path_probe.verdict([result(), result(), result(), result()]), ('direct', 4, 0))

	def test_a_translating_path_loses_it_on_most_hosts(self):
		self.assertEqual(path_probe.verdict([result(odd=False)] * 4), ('interfering', 4, 4))
		self.assertEqual(path_probe.verdict([result(odd=False)] * 3 + [result()]), ('interfering', 4, 3))

	def test_hosts_that_did_not_answer_the_control_say_nothing(self):
		many_dead = [result(plain=False)] * 10
		self.assertEqual(path_probe.verdict(many_dead + [result(odd=False)] * 2), ('unknown', 2, 2))

	def test_too_few_hosts_or_a_split_is_no_verdict(self):
		self.assertEqual(path_probe.verdict([result()] * 2)[0], 'unknown')
		self.assertEqual(path_probe.verdict([result(), result(), result(odd=False), result(odd=False)])[0], 'unknown')

	def test_one_host_with_its_own_firewall_does_not_make_a_clean_path_interfering(self):
		self.assertEqual(path_probe.verdict([result()] * 5 + [result(odd=False)])[0], 'direct')


class CandidateTests(TestCase):
	def setUp(self):
		# which project may still have an address probed is path_probe.in_scope's own test (PathProbeScopeTests below)
		patcher = mock.patch.object(path_probe, 'in_scope', return_value=True)
		patcher.start()
		self.addCleanup(patcher.stop)

	def make(self, address, port, days=1):
		import datetime
		fingerprint = {'closed_tcp': port, 'closed_tcp_at': (timezone.now() - datetime.timedelta(days=days)).isoformat()} if port else {}
		return IpAddress.objects.create(address=address, fingerprint=fingerprint)

	def test_one_address_per_network_with_a_known_closed_port_that_a_scanner_may_reach(self):
		for address, port in (('93.184.216.34', 81), ('93.184.216.35', 82), ('8.8.8.8', 83), ('1.1.1.1', 84), ('192.168.1.5', 85), ('9.9.9.9', None)):
			self.make(address, port)
		self.make('4.4.4.4', 86, days=60)
		got = dict(path_probe.candidates())
		self.assertEqual(got.get('8.8.8.8'), 83)
		self.assertEqual(got.get('1.1.1.1'), 84)
		self.assertEqual(len([a for a in got if a.startswith('93.184.')]), 1)  # one per /16
		self.assertNotIn('192.168.1.5', got)  # private addresses are refused unless the install scans its own network
		self.assertNotIn('9.9.9.9', got)      # no closed port known
		self.assertNotIn('4.4.4.4', got)      # not fingerprinted lately

	def test_check_needs_enough_hosts_and_reports_why_it_cannot_say(self):
		self.assertEqual(path_probe.check()['state'], 'unknown')
		for address in ('8.8.8.8', '1.1.1.1', '9.9.9.9', '4.4.4.4'):
			self.make(address, 81)
		rows = lambda odd: [{'ip': a, 'port': 81, 'plain': True, 'odd': odd} for a in ('8.8.8.8', '1.1.1.1', '9.9.9.9', '4.4.4.4')]  # noqa: E731
		with mock.patch.object(path_probe, 'holder', return_value=1), mock.patch('agentapi.sentinel_dispatch.try_path_probe', return_value=rows(False)):
			out = path_probe.check()
		self.assertEqual((out['state'], out['lost'], out['vantage']), ('interfering', 4, 'scanner'))
		with mock.patch.object(path_probe, 'holder', return_value=1), mock.patch('agentapi.sentinel_dispatch.try_path_probe', return_value=rows(True)):
			self.assertEqual(path_probe.check()['state'], 'direct')

	def test_with_no_scanner_the_survey_waits_and_nothing_is_sent_from_here(self):
		from reNgine.resources import ScannerUnavailable
		for address in ('8.8.8.8', '1.1.1.1', '9.9.9.9', '4.4.4.4'):
			self.make(address, 81)
		with mock.patch.object(path_probe, 'holder', return_value=1), \
				mock.patch('agentapi.sentinel_dispatch.try_path_probe', side_effect=ScannerUnavailable('path_probe', 'none')):
			out = path_probe.check()
		self.assertEqual(out['state'], 'unknown')
		self.assertIn('no scanner could take this work', out['why'])


class PathProbeScopeTests(TestCase):
    """Security review 1.3.4 (ssrf-1): the daily raw-packet path probe picks addresses from fingerprints of every organization; it must only
    send to one some project may still have probed."""

    def setUp(self):
        self.org = Org.objects.create(name='P', slug='pp-org')
        self.project = Project.objects.create(name='P', slug='pp-p', insert_date=timezone.now(), org=self.org)

    def held(self, name, address, mode='standard'):
        domain = Domain.objects.create(name=name, project=self.project, insert_date=timezone.now(), discovery_mode=mode)
        sub = Subdomain.objects.create(target_domain=domain, name=f'www.{name}')
        sub.ip_addresses.add(IpAddress.objects.create(address=address))
        return sub

    def test_only_an_address_a_project_may_still_probe(self):
        from cveFeed import path_probe
        from cveFeed.models import HostExclusion
        self.held('ok.test', '198.51.100.20')
        self.held('manual.test', '198.51.100.21', mode='manual')
        self.held('passive.test', '198.51.100.22', mode='passive')
        self.held('gone.test', '198.51.100.23')
        HostExclusion.objects.create(org=self.org, host='198.51.100.23', created_at=timezone.now())
        IpAddress.objects.create(address='198.51.100.24')  # fingerprinted once, now on no host of any project
        self.assertTrue(path_probe.in_scope('198.51.100.20'))
        for address in ('198.51.100.21', '198.51.100.22', '198.51.100.23', '198.51.100.24'):
            self.assertFalse(path_probe.in_scope(address), address)
