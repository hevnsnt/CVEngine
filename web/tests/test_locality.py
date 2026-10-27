from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import correlation, locality
from cveFeed.models import CVEEntry, CVEMatch
from dashboard.models import Org, Project
from startScan.models import Subdomain
from targetApp.models import Domain

WIN = [{'vendor': 'Microsoft Corporation', 'product': 'Windows', 'ranges': []}]
EXCHANGE = [{'vendor': 'Microsoft', 'product': 'Exchange Server', 'ranges': []}]
NGINX = [{'vendor': 'f5', 'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}]


class ClassifyTests(SimpleTestCase):
	def local(self, vector='', description='', title='', affected=None):
		return locality.classify(vector, description, title, affected)[0]

	def test_the_cvss_attack_vector_decides_first(self):
		self.assertTrue(self.local('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'))
		self.assertTrue(self.local('CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'))
		self.assertTrue(self.local('AV:L/AC:L/Au:N/C:P/I:P/A:P'))  # CVSS 2
		self.assertTrue(self.local('CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H'))
		# a network or adjacent vector settles it the other way, whatever the words say
		self.assertFalse(self.local('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'allows a local user to gain privileges via win32k'))
		self.assertFalse(self.local('CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'))

	def test_the_windows_kernel_cves_with_no_vector_are_local(self):
		kernel = ('The Windows Kernel API in Windows 8.1 and RT 8.1, Windows Server 2012 and R2, Windows 10 Gold allows an elevation of '
				  'privilege vulnerability due to the way the Kernel API enforces permissions, aka "Windows Elevation of Privilege Vulnerability".')
		win32k = 'The Win32k component in Microsoft Windows allows an information disclosure vulnerability, aka "Win32k Information Disclosure".'
		self.assertTrue(self.local(description=kernel, affected=WIN))  # CVE-2018-0751
		self.assertTrue(self.local(description=win32k, affected=WIN))  # CVE-2017-0058
		self.assertTrue(self.local(description='The kernel-mode drivers in Windows allow local users to gain privileges via a crafted application.',
								   affected=WIN))
		self.assertTrue(self.local(description='A privilege escalation in the Linux kernel lets a local user become root.',
								   affected=[{'product': 'Linux Kernel'}]))

	def test_a_privilege_escalation_in_a_service_or_a_remote_flaw_is_not_local(self):
		self.assertFalse(self.local(description='An elevation of privilege vulnerability exists in Microsoft Exchange Server when it fails to '
												'properly handle requests.', affected=EXCHANGE))  # not an operating system: wording alone is not enough
		self.assertFalse(self.local(description='A remote code execution vulnerability exists in Windows SMB. Elevation of privilege follows.',
									affected=WIN))
		self.assertFalse(self.local(description='nginx allows remote attackers to cause a denial of service.', affected=NGINX))
		self.assertFalse(self.local(description='Unauthenticated attackers can run code over the network.', affected=WIN))
		self.assertFalse(self.local())  # nothing known: not local

	def test_a_local_phrase_in_a_non_os_product_needs_the_word_local_itself(self):
		self.assertTrue(self.local(description='A local user can read the config file of Acme Agent.', affected=[{'product': 'Acme Agent'}]))
		self.assertFalse(self.local(description='Win32k is mentioned in the changelog of Acme Agent.', affected=[{'product': 'Acme Agent'}]))


class LocalOnlyFlowTests(TestCase):
	def setUp(self):
		self.project = Project.objects.create(name='Lo', slug='lo', insert_date=timezone.now(), org=Org.objects.create(name='Lo', slug='loo'))
		self.domain = Domain.objects.create(name='lo.test', project=self.project, insert_date=timezone.now())
		self.sub = Subdomain.objects.create(name='www.lo.test', target_domain=self.domain)
		now = timezone.now()
		self.kernel = CVEEntry.objects.create(
			cve_id='CVE-2018-0751', status='PUBLISHED', affected=WIN, published_at=now, exploit_db=True,
			original_description='The Windows Kernel API allows an elevation of privilege vulnerability due to the way the Kernel API enforces permissions.')
		self.vectored = CVEEntry.objects.create(cve_id='CVE-2099-9001', status='PUBLISHED', affected=NGINX, published_at=now,
												cvss_vector='CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', original_description='x')
		self.remote = CVEEntry.objects.create(cve_id='CVE-2099-9002', status='PUBLISHED', affected=NGINX, published_at=now,
											  cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', original_description='remote flaw')
		correlation._INDEX_CACHE.update(key=None, value=None)

	def test_refresh_flags_only_the_local_ones_and_is_not_repeated(self):
		self.assertEqual(locality.refresh(), 3)
		flags = dict(CVEEntry.objects.values_list('cve_id', 'local_only'))
		self.assertEqual(flags, {'CVE-2018-0751': True, 'CVE-2099-9001': True, 'CVE-2099-9002': False})
		self.assertEqual(locality.refresh(), 0)
		CVEEntry.objects.filter(pk=self.remote.pk).update(cvss_vector='CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', synced_at=timezone.now())
		self.assertEqual(locality.refresh(), 1)  # a changed record is looked at again
		self.assertTrue(CVEEntry.objects.get(pk=self.remote.pk).local_only)

	def test_local_only_cves_leave_the_pool_and_their_open_matches_are_closed_and_rescored(self):
		locality.refresh()
		pool, _ = correlation.cve_pool()
		self.assertEqual(set(pool), {self.remote.id})
		worked = CVEMatch.objects.create(cve_entry=self.kernel, subdomain=self.sub, source='tech', remediation_status='in_progress')
		open_ = CVEMatch.objects.create(cve_entry=self.vectored, subdomain=self.sub, source='tech')
		keep = CVEMatch.objects.create(cve_entry=self.remote, subdomain=self.sub, source='tech')
		with mock.patch('cveFeed.scoring.rescore_quietly') as rescore:
			self.assertEqual(locality.close_local_matches(), 1)
		rescore.assert_called_once()
		open_.refresh_from_db()
		self.assertEqual(open_.ai_verdict, 'not_affected')
		self.assertTrue(open_.ai_reason.startswith('Closed automatically: local-only vulnerability'))
		worked.refresh_from_db()
		self.assertEqual((worked.remediation_status, worked.ai_verdict), ('in_progress', ''))  # a person's work is left as it is
		keep.refresh_from_db()
		self.assertNotEqual(keep.ai_verdict, 'not_affected')
		self.assertEqual(locality.close_local_matches(), 0)

	def test_a_wcf_technology_never_becomes_a_match_for_a_win32k_cve(self):
		"""The reported case: a "Windows Communication Foundation" technology on a web host matched a Windows kernel CVE."""
		from startScan.models import Technology
		self.sub.technologies.add(Technology.objects.create(name='Windows Communication Foundation'))
		locality.refresh()
		pool, index = correlation.cve_pool()
		self.assertNotIn(self.kernel.id, pool)
		self.sub.refresh_from_db()
		correlation.correlate_subdomains([self.sub], index, pool)
		self.assertFalse(CVEMatch.objects.filter(cve_entry=self.kernel).exists())

	def test_validation_and_triage_close_a_match_that_slipped_through_with_the_local_reason(self):
		locality.refresh()
		match = CVEMatch.objects.create(cve_entry=CVEEntry.objects.get(pk=self.kernel.pk), subdomain=self.sub, source='tech')
		reason = correlation.invalid_identity_reason(match)
		self.assertTrue(reason.startswith('Closed automatically: local-only vulnerability'))
		self.assertTrue(correlation.close_invalid_correlation(match))
		match.refresh_from_db()
		self.assertEqual((match.ai_verdict, match.ai_model), ('not_affected', 'deterministic-correlation'))
		self.assertFalse(correlation.close_invalid_correlation(match))  # already closed: not repeated

	def test_the_api_reports_it_and_the_ai_budget_skips_it(self):
		from agentapi.services import _cve
		locality.refresh()
		self.assertTrue(_cve(CVEEntry.objects.get(pk=self.kernel.pk), brief=True)['local_only'])
		self.assertFalse(_cve(CVEEntry.objects.get(pk=self.remote.pk), brief=True)['local_only'])
