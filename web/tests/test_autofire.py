import unittest
from unittest import mock

from django.db.models import QuerySet
from django.test import TestCase
from django.utils import timezone

from cveFeed.autofire import fire_for_cve, keep_match, select_hosts
from cveFeed.models import AutoFireRun, CVEEntry
from cveFeed.tasks import auto_fire_new_cves
from dashboard.models import Org, Project
from startScan.models import IpAddress, Port, ScanHistory, Subdomain
from targetApp.models import Domain


class SelectTargetsTests(unittest.TestCase):
	def test_keep_match_ai_wins_over_heuristic(self):
		self.assertFalse(keep_match('not_affected', 0.99))
		self.assertTrue(keep_match('uncertain', 0.1))
		self.assertTrue(keep_match('', 0.7))
		self.assertFalse(keep_match('', 0.5))

	def test_dedupes_ranks_and_caps_hosts(self):
		rows = [
			(1, 'a.com', 'www.a.com', 'uncertain', 0.9),
			(1, 'a.com', 'www.a.com', 'affected', 0.5),   # same host: affected beats uncertain
			(1, 'a.com', 'api.a.com', '', 0.75),
			(2, 'b.com', 'www.b.com', 'not_affected', 1.0),  # dropped
			(3, 'c.com', 'www.c.com', '', 0.8),
			(4, 'd.com', 'www.d.com', '', 0.4),           # below heuristic threshold
			(None, '', 'x', 'affected', 1.0),     # no domain
			(5, 'e.com', 'www.e.com', 'affected', 0.9),
		]
		self.assertEqual(select_hosts(rows, 2), [(5, 'e.com', 'www.e.com'), (1, 'a.com', 'www.a.com')])
		self.assertEqual([h for _, _, h in select_hosts(rows, 10)], ['www.e.com', 'www.a.com', 'www.c.com', 'api.a.com'])


if __name__ == '__main__':
	unittest.main()


class AutoFireBatchTests(TestCase):
	def setUp(self):
		org = Org.objects.create(name='A', slug='a')
		self.project = Project.objects.create(name='P', slug='pa', insert_date=timezone.now(), org=org)
		self.domain = Domain.objects.create(name='af.test', project=self.project, insert_date=timezone.now())
		sub = Subdomain.objects.create(name='www.af.test', target_domain=self.domain)
		ip = IpAddress.objects.create(address='192.0.2.9')
		sub.ip_addresses.add(ip)
		ip.ports.add(Port.objects.create(number=80, product='nginx', version='1.18.0'))
		affected = [{'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}]
		self.cves = [CVEEntry.objects.create(cve_id=f'CVE-2099-{n}', kev=True, cvss=9.8, published_at=timezone.now(),
			affected=affected) for n in (1, 2)]

	def test_two_hot_cves_one_domain_start_no_scan_and_walk_subdomains_once(self):
		from dashboard.models import AIProviderSettings
		AIProviderSettings.objects.create(auto_fire=True)  # no engine needed
		scans = ScanHistory.objects.count()
		walks = []
		real_iterator = QuerySet.iterator

		def counting(qs, *a, **k):
			if qs.model is Subdomain:
				walks.append(1)
			return real_iterator(qs, *a, **k)
		calls = []
		with mock.patch.object(QuerySet, 'iterator', counting), \
				mock.patch('cveFeed.tasks.template_test_for_cve.delay', lambda *a: calls.append(a)):
			out = auto_fire_new_cves()
		self.assertEqual(out, {'fired': 2})
		self.assertEqual(ScanHistory.objects.count(), scans)
		self.assertEqual(len(calls), 2)  # once per CVE
		self.assertEqual(len(walks), 1)  # one walk for the whole batch
		self.assertEqual(AutoFireRun.objects.count(), 2)
		self.assertEqual(AutoFireRun.objects.first().scan_ids, [])
		self.assertEqual(AutoFireRun.objects.first().targets, ['af.test'])

	def test_standalone_fire_still_correlates_itself(self):
		calls = []
		run = fire_for_cve(self.cves[0], max_hosts=3, test_dispatcher=lambda *a: calls.append(a))
		self.assertEqual(run.targets, ['af.test'])
		self.assertEqual(calls[0][1], ['www.af.test'])


class PerProjectDispatchTests(TestCase):
	"""Review 5.1: one template test per project, so one tenant's hosts never reach another project's activity log."""

	def _tenant(self, slug, domain, host, ip):
		org = Org.objects.create(name=slug, slug=slug)
		project = Project.objects.create(name=slug, slug=slug, insert_date=timezone.now(), org=org)
		dom = Domain.objects.create(name=domain, project=project, insert_date=timezone.now())
		sub = Subdomain.objects.create(name=host, target_domain=dom)
		address = IpAddress.objects.create(address=ip)
		sub.ip_addresses.add(address)
		address.ports.add(Port.objects.create(number=80, product='nginx', version='1.18.0'))
		return project

	def _cve(self, cve_id):
		return CVEEntry.objects.create(cve_id=cve_id, kev=True, cvss=9.8, published_at=timezone.now(), affected=[
			{'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}])

	def test_two_projects_two_dispatches_with_their_own_hosts(self):
		a = self._tenant('ta', 'alpha.test', 'www.alpha.test', '192.0.2.31')
		b = self._tenant('tb', 'beta.test', 'www.beta.test', '192.0.2.32')
		cve = self._cve('CVE-2099-77')
		calls = []
		fire_for_cve(cve, test_dispatcher=lambda pk, hosts, project: calls.append((pk, list(hosts), project)))
		self.assertEqual(sorted(calls, key=lambda c: c[2]),
			sorted([(cve.pk, ['www.alpha.test'], a.id), (cve.pk, ['www.beta.test'], b.id)], key=lambda c: c[2]))

	def test_activity_lines_stay_in_their_own_project(self):
		from cveFeed.models import AgentActivity
		a = self._tenant('ta', 'alpha.test', 'www.alpha.test', '192.0.2.31')
		b = self._tenant('tb', 'beta.test', 'www.beta.test', '192.0.2.32')
		fire_for_cve(self._cve('CVE-2099-78'), test_dispatcher=lambda *args: None)
		for project, foreign in ((a, 'beta.test'), (b, 'alpha.test')):
			text = ' '.join(AgentActivity.objects.filter(project_id=project.id).values_list('message', flat=True))
			self.assertNotIn(foreign, text)
