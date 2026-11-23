"""A branch fix the advisory itself states closes its line in a wider range of the same advisory (cveFeed.correlation.branch_fixed).

F5's CVE records for nginx write the mainline and stable fixes beside one wide range: CVE-2026-42055 is ``1.13.10`` up to ``1.31.2`` plus
``1.30.2`` up to ``1.30.3``; CVE-2026-123634 is ``0.6.18`` with no upper bound plus ``1.31.0`` up to ``1.31.9`` and ``1.30.0`` up to
``1.30.7``. The stored ranges are exactly what the record says (cvelistV5 ``versions`` with ``lessThan``), and nginx.org's own table says
what they mean (42055: not vulnerable 1.31.2+, 1.30.3+; 123634: not vulnerable 1.31.9+, 1.30.7+). The ranges below are the stored ones,
copied from the live catalog, and the expected verdicts are nginx.org's.
"""
from io import StringIO

from django.core.management import call_command
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import upgrade_backfills
from cveFeed.correlation import branch_fixes, item_verdict, parse_version, range_verdict
from cveFeed.models import CVEEntry, CVEMatch
from dashboard.models import Org, Project
from startScan.models import Subdomain
from targetApp.models import Domain

NOW = timezone.now()

# stored ``affected`` blocks of the live catalog (product NGINX Open Source, vendor F5)
STORED = {
	'CVE-2026-42055': [{'fixed': '1.31.2', 'introduced': '1.13.10'}, {'fixed': '1.30.3', 'introduced': '1.30.2'}],
	'CVE-2026-48142': [{'fixed': '1.31.2', 'introduced': '1.13.10'}, {'fixed': '1.30.3', 'introduced': '1.30.0'}],
	'CVE-2026-90439': [{'fixed': '1.31.6', 'introduced': '1.29.2'}, {'fixed': '1.30.5', 'introduced': '1.30.4'}],
	'CVE-2026-60005': [{'fixed': '1.31.3', 'introduced': '1.31.2'}, {'fixed': '1.30.4', 'introduced': '1.15.8'}],
	'CVE-2026-123634': [{'fixed': '1.31.9', 'introduced': '1.31.0'}, {'fixed': '1.30.7', 'introduced': '1.30.0'}, {'introduced': '0.6.18'}],
	'CVE-2026-118899': [{'fixed': '1.31.9', 'introduced': '1.31.0'}, {'fixed': '1.30.7', 'introduced': '1.30.0'}, {'introduced': '1.31.0'}],
	'CVE-2026-97629': [{'fixed': '1.31.7', 'introduced': '1.31.0'}, {'fixed': '1.30.6', 'introduced': '1.30.0'}, {'introduced': '1.23.3'}],
	'CVE-2026-27654': [{'fixed': '1.29.7', 'introduced': '1.29.0'}, {'fixed': '1.28.3', 'introduced': '0.5.13'}],
}

# nginx.org/en/security_advisories.html: (vulnerable, not vulnerable) per CVE, as versions to test
NGINX_ORG = {
	'CVE-2026-42055': (['1.13.10', '1.24.0', '1.30.0', '1.30.2', '1.31.1'], ['1.30.3', '1.30.5', '1.30.7', '1.31.2', '1.31.9']),
	'CVE-2026-48142': (['1.24.0', '1.30.2', '1.31.1'], ['1.30.3', '1.30.5', '1.31.2']),
	'CVE-2026-90439': (['1.29.2', '1.30.0', '1.30.4', '1.31.5'], ['1.30.5', '1.30.7', '1.31.6']),
	'CVE-2026-123634': (['1.18.0', '1.24.0', '1.28.3', '1.30.5', '1.31.8'], ['1.30.7', '1.30.9', '1.31.9', '1.31.10']),
	'CVE-2026-118899': (['1.31.0', '1.31.8', '1.30.6'], ['1.31.9', '1.30.7']),
	'CVE-2026-97629': (['1.24.0', '1.30.5', '1.31.6'], ['1.30.6', '1.31.7', '1.31.8', '1.31.9']),
	# no branch range names a line a wider range runs past: read as written, unchanged
	'CVE-2026-27654': (['1.18.0', '1.28.2', '1.29.6'], ['1.28.3', '1.29.7']),
}


def verdict(cve, version):
	return range_verdict(parse_version(version), STORED[cve])[0]


class BranchFixReadingTests(SimpleTestCase):
	def test_every_nginx_org_verdict_holds_on_the_stored_ranges(self):
		for cve, (vulnerable, fixed) in NGINX_ORG.items():
			for version in vulnerable:
				self.assertIs(verdict(cve, version), True, f'{cve} {version} is vulnerable')
			for version in fixed:
				self.assertIs(verdict(cve, version), False, f'{cve} {version} is fixed')

	def test_the_deciding_range_is_the_one_that_still_holds(self):
		# 1.30.2 against 42055: the wide range comes first and holds it (before the 1.30 fix)
		self.assertEqual(range_verdict(parse_version('1.30.2'), STORED['CVE-2026-42055'])[1], {'introduced': '1.13.10', 'fixed': '1.31.2'})
		# 1.31.1 against 42055: no 1.31 statement besides the wide range, which decides as before
		self.assertEqual(range_verdict(parse_version('1.31.1'), STORED['CVE-2026-42055'])[1], {'introduced': '1.13.10', 'fixed': '1.31.2'})

	def test_branch_fixes_reads_only_ranges_on_one_line(self):
		self.assertEqual(branch_fixes(STORED['CVE-2026-42055']), {(1, 30): (1, 30, 3)})
		self.assertEqual(branch_fixes(STORED['CVE-2026-123634']), {(1, 31): (1, 31, 9), (1, 30): (1, 30, 7)})
		self.assertEqual(branch_fixes(STORED['CVE-2026-27654']), {(1, 29): (1, 29, 7)})
		self.assertEqual(branch_fixes([{'introduced': '2.0', 'fixed': '2.1'}, {'fixed': '3.0.1'}, {'introduced': 'x', 'fixed': '1.0.2'}]), {})

	def test_a_range_that_ends_on_the_versions_own_line_still_decides(self):
		# 1.0 up to 1.30.9 is the vendor's word on 1.30 too: a narrower 1.30.0 up to 1.30.3 beside it does not hide it
		ranges = [{'introduced': '1.0.0', 'fixed': '1.30.9'}, {'introduced': '1.30.0', 'fixed': '1.30.3'}]
		self.assertIs(range_verdict(parse_version('1.30.5'), ranges)[0], True)

	def test_a_regression_branch_on_the_same_line_still_decides(self):
		ranges = [{'introduced': '1.0.0', 'fixed': '2.0.0'}, {'introduced': '1.30.0', 'fixed': '1.30.2'}, {'introduced': '1.30.4', 'fixed': '1.30.6'}]
		self.assertIs(range_verdict(parse_version('1.30.1'), ranges)[0], True)
		self.assertIs(range_verdict(parse_version('1.30.3'), ranges)[0], False)
		self.assertIs(range_verdict(parse_version('1.30.5'), ranges)[0], True)
		self.assertIs(range_verdict(parse_version('1.29.9'), ranges)[0], True)  # a line the advisory states no fix for: the wide range

	def test_other_shapes_read_as_before(self):
		# PHP's fix-only branch list, a single range, a git range and an unparsable bound
		php = [{'fixed': '8.2.35'}, {'fixed': '8.3.36'}, {'fixed': '8.4.27'}]
		self.assertIs(range_verdict(parse_version('8.3.30'), php)[0], True)
		self.assertIs(range_verdict(parse_version('8.3.36'), php)[0], False)
		self.assertIs(range_verdict(parse_version('2.4.57'), [{'introduced': '2.4.0', 'fixed': '2.4.58'}])[0], True)
		self.assertIsNone(range_verdict(parse_version('1.2.3'), [{'introduced': 'abc1234', 'fixed': 'def5678', 'type': 'GIT'}])[0])
		self.assertIs(range_verdict(parse_version('1.30.5'), [{'introduced': '1.13.10', 'fixed': '1.31.2'}])[0], True)

	def test_item_verdict_reads_the_same(self):
		item = {'vendor': 'F5', 'product': 'NGINX Open Source', 'ranges': STORED['CVE-2026-42055']}
		self.assertIs(item_verdict(parse_version('1.30.5'), item, '1.30.5')[0], False)
		self.assertIs(item_verdict(parse_version('1.31.1'), item, '1.31.1')[0], True)


class RecheckBranchFixesCommandTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		org = Org.objects.create(name='Branch', slug='bf-org')
		project = Project.objects.create(name='Branch', slug='bf-p', insert_date=NOW, org=org)
		domain = Domain.objects.create(name='branch.example', project=project, insert_date=NOW)
		cls.stable = Subdomain.objects.create(name='stable.branch.example', target_domain=domain)
		cls.mainline = Subdomain.objects.create(name='mainline.branch.example', target_domain=domain)
		block = lambda cve: [{'vendor': 'F5', 'product': 'NGINX Open Source', 'ranges': STORED[cve]}]  # noqa: E731
		cls.c42055 = CVEEntry.objects.create(cve_id='CVE-2026-42055', cvss=8.1, affected=block('CVE-2026-42055'))
		cls.c123634 = CVEEntry.objects.create(cve_id='CVE-2026-123634', cvss=6.5, affected=block('CVE-2026-123634'))
		cls.c27654 = CVEEntry.objects.create(cve_id='CVE-2026-27654', cvss=6.5, affected=block('CVE-2026-27654'))

		def match(cve, sub, version, rng):
			return CVEMatch.objects.create(cve_entry=cve, subdomain=sub, matched_product='NGINX Open Source', matched_version=version,
										   source='tech', version_in_range=True, evidence={'source': 'tech', 'range': rng, 'affected_index': 0})
		match(cls.c42055, cls.stable, '1.30.5', STORED['CVE-2026-42055'][0])         # past the 1.30 fix: closes
		match(cls.c42055, cls.mainline, '1.31.1', STORED['CVE-2026-42055'][0])       # mainline before 1.31.2: stays
		match(cls.c123634, cls.mainline, '1.31.9', STORED['CVE-2026-123634'][2])     # the open range, past 1.31.9: closes
		match(cls.c27654, cls.stable, '1.28.2', STORED['CVE-2026-27654'][1])         # no branch fix concerns it: stays

	def test_dry_run_names_the_cves_and_writes_nothing(self):
		out = StringIO()
		call_command('recheck_branch_fixes', stdout=out)
		text = out.getvalue()
		self.assertIn('CVE-2026-42055: 1 match(es)', text)
		self.assertIn('CVE-2026-123634: 1 match(es)', text)
		self.assertNotIn('CVE-2026-27654', text)
		self.assertIn('dry run: 2 CVEs, 2 matches', text)
		self.assertFalse(CVEEntry.objects.filter(needs_recorrelation=True).exists())

	def test_apply_marks_only_those_cves_and_a_second_run_still_finds_them_until_recorrelated(self):
		call_command('recheck_branch_fixes', '--apply', stdout=StringIO())
		self.assertEqual(set(CVEEntry.objects.filter(needs_recorrelation=True).values_list('cve_id', flat=True)),
						 {'CVE-2026-42055', 'CVE-2026-123634'})
		# the match rows themselves are left to correlation
		self.assertEqual(CVEMatch.objects.filter(version_in_range=True).count(), 4)

	def test_nothing_to_recheck(self):
		CVEMatch.objects.filter(matched_version__in=['1.30.5', '1.31.9']).delete()
		out = StringIO()
		call_command('recheck_branch_fixes', '--apply', stdout=out)
		self.assertIn('nothing to recheck', out.getvalue())
		self.assertFalse(CVEEntry.objects.filter(needs_recorrelation=True).exists())

	def test_it_is_an_update_step_before_the_rescore(self):
		names = upgrade_backfills.BACKFILLS
		self.assertIn('recheck_branch_fixes', names)
		self.assertLess(names.index('recheck_branch_fixes'), names.index('rerate_findings'))
