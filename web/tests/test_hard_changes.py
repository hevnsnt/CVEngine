from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import changes, nmap_scan, retest
from dashboard.models import Org, Project
from reNgine import bbot as bbot_lib
from reNgine.tasks import persist_bbot_result
from startScan.models import IpAddress, Subdomain, Technology
from targetApp.models import Domain
from tests.test_nmap_scan import _report


def state(techs=()):
	return {'ips': {}, 'techs': sorted(techs)}


class TechDiffTests(SimpleTestCase):
	"""Verdict 4: technologies are compared by name, a version flip is its own kind."""

	def kinds(self, before, after):
		return [(k, b, a) for k, _, _, b, a in changes.diff_states(state(before), state(after))]

	def test_a_banner_flipping_between_bare_and_versioned_is_no_change(self):
		self.assertEqual(self.kinds(['nginx'], ['nginx:1.18.0']), [])
		self.assertEqual(self.kinds(['nginx:1.18.0'], ['nginx']), [])

	def test_a_real_add_and_remove_still_report(self):
		self.assertEqual(self.kinds(['nginx:1.18.0', 'php'], ['nginx:1.18.0', 'wordpress:6.4']),
			[('tech_added', None, 'wordpress:6.4'), ('tech_removed', 'php', None)])

	def test_a_version_that_differs_on_both_sides_is_a_version_change(self):
		self.assertEqual(self.kinds(['nginx:1.18.0'], ['nginx:1.20.1']), [('tech_version_changed', 'nginx:1.18.0', 'nginx:1.20.1')])

	def test_the_same_version_is_nothing_and_case_is_ignored(self):
		self.assertEqual(self.kinds(['Nginx:1.18.0'], ['nginx:1.18.0']), [])

	def test_a_version_change_is_a_retest_trigger_and_a_name_only_flip_never_reaches_it(self):
		self.assertIn('tech_version_changed', retest.TRIGGER_KINDS)
		self.assertTrue(retest._worth_it({'kind': 'tech_version_changed', 'before': 'nginx:1.18.0', 'after': 'nginx:1.20.1'}))


class ChangeTrackingAfterPortFixesTests(TestCase):
	"""Hardening 4 and 9 are what make HostState and diff_states trustworthy."""

	def setUp(self):
		org = Org.objects.create(name='A', slug='a')
		project = Project.objects.create(name='P', slug='pa', insert_date=timezone.now(), org=org)
		domain = Domain.objects.create(name='trk.test', project=project, insert_date=timezone.now())
		self.a = Subdomain.objects.create(name='a.trk.test', target_domain=domain)
		self.b = Subdomain.objects.create(name='b.trk.test', target_domain=domain)

	def snapshot(self, sub):
		sub = Subdomain.objects.prefetch_related('ip_addresses__ports', 'technologies').get(pk=sub.pk)
		return changes.host_state(sub)

	def test_a_shared_row_bleed_produces_no_change(self):
		ip_a, _ = IpAddress.objects.get_or_create(address='198.51.100.10')
		ip_b, _ = IpAddress.objects.get_or_create(address='198.51.100.11')
		self.a.ip_addresses.add(ip_a)
		self.b.ip_addresses.add(ip_b)
		persist_bbot_result(bbot_lib.BbotResult(ports={('198.51.100.11', 443)}), ctx={})
		before = self.snapshot(self.b)
		# nmap fingerprints host A only; with a shared row B would now claim A's nginx 1.18.0
		nmap_scan.persist_inventory([{'ip': '198.51.100.10', 'ports': [
			{'number': 443, 'state': 'open', 'product': 'nginx', 'version': '1.18.0', 'service_name': 'https'}]}])
		persist_bbot_result(bbot_lib.BbotResult(ports={('198.51.100.11', 443), ('198.51.100.10', 443)}), ctx={})
		after = self.snapshot(self.b)
		self.assertEqual(changes.diff_states(before, after), [])
		self.assertEqual(after['ips']['198.51.100.11']['ports']['443/tcp']['product'], '')

	def test_a_filtered_port_is_not_in_the_snapshot(self):
		ip, _ = IpAddress.objects.get_or_create(address='198.51.100.20')
		self.a.ip_addresses.add(ip)
		nmap_scan.persist_inventory(nmap_scan.parse_xml(_report([(22, 'open', 'OpenSSH', '8.9'), (3306, 'filtered', 'MySQL', '5.7')]).replace('192.0.2.77', '198.51.100.20')))
		self.assertEqual(sorted(self.snapshot(self.a)['ips']['198.51.100.20']['ports']), ['22/tcp'])

	def test_a_port_missing_from_a_run_is_closed_and_reported_once(self):
		ip, _ = IpAddress.objects.get_or_create(address='198.51.100.30')
		self.a.ip_addresses.add(ip)
		xml = lambda ports: _report(ports).replace('192.0.2.77', '198.51.100.30')  # noqa: E731
		nmap_scan.persist_inventory(nmap_scan.parse_xml(xml([(22, 'open', 'OpenSSH', '8.9'), (8080, 'open', 'nginx', '1.18.0')])))
		first = self.snapshot(self.a)
		nmap_scan.persist_inventory(nmap_scan.parse_xml(xml([(22, 'open', 'OpenSSH', '8.9')])))
		second = self.snapshot(self.a)
		self.assertEqual([(k, p) for k, _ip, p, _b, _a in changes.diff_states(first, second)], [('port_closed', 8080)])
		nmap_scan.persist_inventory(nmap_scan.parse_xml(xml([(22, 'open', 'OpenSSH', '8.9')])))
		self.assertEqual(changes.diff_states(second, self.snapshot(self.a)), [])  # the next run reports nothing more

	def test_a_banner_that_flips_the_tech_version_does_not_retest(self):
		self.a.technologies.add(Technology.objects.create(name='nginx'))
		before = self.snapshot(self.a)
		self.a.technologies.clear()
		self.a.technologies.add(Technology.objects.create(name='nginx:1.18.0'))
		self.assertEqual(changes.diff_states(before, self.snapshot(self.a)), [])
