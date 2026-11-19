"""llama.cpp's build numbers (cveFeed.correlation.llamacpp_range, cveFeed.intel._llamacpp_builds, cveFeed.ai_servers): llama.cpp names its
releases by build tag (b5662) and its advisories write their bounds that way. The records here are the real ones: the CVE List records of
CVE-2025-49847 and CVE-2025-52566 (ggml-org, "< b5662", "< b5721"), CVE-2024-42477 (ggerganov, "< b3561") and CVE-2025-53630 (a commit, trimmed
copies under tests/fixtures/cve5), and cve.now's stored ranges of CVE-2024-58399 (b1046 to b2731), CVE-2024-58400 (0 to b3701) and
CVE-2026-116829 (b10398 to b11301 next to a 0.1.0 to 0.6.0 range). A build tag is read as the build number only for llama.cpp's own entries."""
from io import StringIO
from unittest import mock

from django.core.management import call_command
from django.test import SimpleTestCase, TestCase

from cveFeed import ai_servers, correlation, intel, upgrade_backfills
from cveFeed import version_catalogue as catalogue
from cveFeed.correlation import parse_version, version_in_range
from cveFeed.models import CVEEntry
from tests.test_range_ingest import cve5, verdict
from tests.test_version_sources import ok

# what cve.now stored for these (cveFeed_cveentry.affected)
CVE_2024_58399 = [{'ranges': [{'fixed': 'b2731', 'introduced': 'b1046'}], 'vendor': 'ggml-org', 'product': 'llama.cpp'}]
CVE_2024_58400 = [{'ranges': [{'fixed': 'b3701', 'introduced': '0'}], 'vendor': 'ggml-org', 'product': 'llama.cpp'}]
CVE_2026_116829 = [{'ranges': [{'fixed': 'b11301', 'introduced': 'b10398'}, {'fixed': '0.6.0', 'introduced': '0.1.0'}], 'vendor': 'ggml-org',
                    'product': 'llama.cpp'}]


def converted(cve_id):
    return intel.convert_affected(cve5(cve_id)['containers']['cna']['affected'], cve5(cve_id)['cveMetadata']['assignerShortName'])


class FeedSideTests(SimpleTestCase):
    def test_the_cve_list_records_bounds_are_read_as_build_numbers(self):
        self.assertEqual(converted('CVE-2025-49847'), [{'vendor': 'ggml-org', 'product': 'llama.cpp', 'ranges': [{'type': 'SEMVER', 'fixed': '5662'}]}])
        self.assertEqual(converted('CVE-2025-52566')[0]['ranges'], [{'type': 'SEMVER', 'fixed': '5721'}])
        self.assertEqual(converted('CVE-2024-42477')[0]['ranges'], [{'type': 'SEMVER', 'fixed': '3561'}])  # ggerganov, before the rename
        # cve.now passes "< b5662" on as a bare versions list: the record's block is now sound and gives the range
        aff = cve5('CVE-2025-49847')['containers']['cna']['affected']
        self.assertEqual(intel.record_ranges_for({'vendor': 'ggml-org', 'product': 'llama.cpp', 'versions': ['< b5662']}, aff),
                         {'ranges': [{'type': 'SEMVER', 'fixed': '5662'}]})
        # a commit is still never a version bound
        aff = cve5('CVE-2025-53630')['containers']['cna']['affected']
        self.assertIsNone(intel.record_ranges_for({'vendor': 'ggml-org', 'product': 'llama.cpp', 'versions': [aff[0]['versions'][0]['version']]}, aff))

    def test_written_forms_and_changes(self):
        def ranges(*versions):
            return intel.convert_affected([{'vendor': 'ggml-org', 'product': 'llama.cpp', 'versions': list(versions)}])[0]['ranges']
        self.assertEqual(ranges({'version': '>= b4000, < b5662', 'status': 'affected'}), [{'type': 'SEMVER', 'introduced': '4000', 'fixed': '5662'}])
        self.assertEqual(ranges({'version': 'b4000', 'lessThan': 'b5662-a1b2c3d', 'status': 'affected'}),
                         [{'type': 'SEMVER', 'introduced': '4000', 'fixed': '5662'}])
        self.assertEqual(ranges({'version': '0', 'lessThanOrEqual': 'b5661', 'status': 'affected'}), [{'type': 'SEMVER', 'lastAffected': '5661'}])
        self.assertEqual(ranges({'version': 'b5000', 'lessThan': '*', 'status': 'affected',
                                 'changes': [{'at': 'b5500', 'status': 'unaffected'}]}), [{'type': 'SEMVER', 'introduced': '5000', 'fixed': '5500'}])

    def test_no_other_product_reads_a_b_tag(self):
        self.assertIsNone(parse_version('b5662', strict=True))  # the parser itself is unchanged
        other = intel.convert_affected([{'vendor': 'Acme', 'product': 'Widget', 'versions': [{'version': '< b5662', 'status': 'affected'}]}])
        self.assertEqual(other[0]['ranges'], [])
        python = [{'vendor': 'abetlen', 'product': 'llama-cpp-python', 'ranges': [{'fixed': 'b2731'}]}]
        self.assertEqual(correlation.clean_affected(python)[0]['ranges'], [{'fixed': 'b2731'}])
        self.assertFalse(correlation.is_llamacpp({'vendor': 'Rayon Labs', 'product': 'llama.cpp'}))
        for item in ({'vendor': 'ggml-org', 'product': 'llama.cpp'}, {'vendor': 'ggerganov', 'product': 'ggerganov/llama.cpp'},
                     {'product': 'llama_cpp'}, {'vendor': 'ggml', 'product': 'llama.cpp'}):
            with self.subTest(item=item):
                self.assertTrue(correlation.is_llamacpp(item))
        self.assertEqual((correlation.llamacpp_build('b0-unknown'), correlation.llamacpp_build('master-a1b2c3d')), ('', ''))

    def test_stored_cve_now_ranges_were_unknown_and_now_decide(self):
        """Before: a build bound read as no version, so every llama.cpp range was unknown. Now the stored ranges decide."""
        raw = CVE_2024_58399[0]['ranges'][0]
        self.assertIsNone(version_in_range(parse_version('2000'), raw))  # what correlation read before (the range as stored)
        self.assertEqual(correlation.clean_affected(CVE_2024_58399)[0]['ranges'], [{'fixed': '2731', 'introduced': '1046'}])
        for affected, table in ((CVE_2024_58399, [('1045', False), ('1046', True), ('2730', True), ('2731', False)]),
                                (CVE_2024_58400, [('1', True), ('3700', True), ('3701', False), ('5662', False)]),
                                (CVE_2026_116829, [('10397', False), ('10398', True), ('11300', True), ('11301', False)])):
            for version, expected in table:
                with self.subTest(range=affected[0]['ranges'][0], version=version):
                    self.assertIs(verdict(correlation.clean_affected(affected), 'llama.cpp', version), expected)
        # the 0.x range next to the build range never holds a build number
        self.assertIs(verdict(correlation.clean_affected(CVE_2026_116829), 'llama.cpp', '5662'), False)

    def test_the_cve_list_ranges_decide_for_a_host_build(self):
        for cve_id, table in (('CVE-2025-49847', [('5661', True), ('5662', False), ('6000', False)]),
                              ('CVE-2024-42477', [('3560', True), ('3561', False)])):
            for version, expected in table:
                with self.subTest(cve=cve_id, version=version):
                    self.assertIs(verdict(correlation.clean_affected(converted(cve_id)), 'llama.cpp', version), expected)


class HostSideTests(SimpleTestCase):
    def test_the_props_build_tag_is_stated_as_the_build_number(self):
        props = ok({'build_info': 'b5662-a1b2c3d', 'total_slots': 1, 'default_generation_settings': {'type': 'object', 'size': 2}}, path='/props',
                   headers={'server': 'llama.cpp'})
        got = catalogue.read_entry(catalogue.BY_ID['llama-cpp'], [props, ok({'object': 'list'}, path='/v1/models')])
        reading, = got['readings']
        self.assertEqual((reading['component'], reading['version']), ('llama.cpp', '5662'))
        self.assertIn('build b5662-a1b2c3d', reading['evidence'])
        # the technology it becomes is read back as that version
        self.assertEqual(correlation.split_name_version(f'{reading["label"]}:{reading["version"]}'), ('llama.cpp', '5662'))
        # a tag that is not a build (a source build: b0-unknown) states no version
        props['json'] = {**props['json'], 'build_info': 'b0-unknown'}
        self.assertEqual(ai_servers.llamacpp_parts([props, None])['version'], '')


class BackfillTests(TestCase):
    def test_a_stored_bare_block_takes_its_records_build_range_once(self):
        entry = CVEEntry.objects.create(cve_id='CVE-2025-49847', affected=[{'vendor': 'ggml-org', 'product': 'llama.cpp', 'ranges': [],
                                                                          'versions': ['< b5662']}])
        other = CVEEntry.objects.create(cve_id='CVE-2099-0001', affected=[{'vendor': 'Acme', 'product': 'Widget', 'ranges': [], 'versions': ['1.0']}])
        self.assertEqual(list(intel.llamacpp_candidates().values_list('cve_id', flat=True)), ['CVE-2025-49847'])
        self.assertIn('backfill_llamacpp_builds', upgrade_backfills.BACKFILLS)
        self.assertLess(upgrade_backfills.BACKFILLS.index('backfill_llamacpp_builds'), upgrade_backfills.BACKFILLS.index('rerate_findings'))
        out = StringIO()
        call_command('backfill_llamacpp_builds', stdout=out)
        self.assertIn('1 stored llama.cpp CVEs would', out.getvalue())
        with mock.patch('cveFeed.intel.fetch_cve5', side_effect=lambda cve, get=None: cve5(cve)):
            call_command('backfill_llamacpp_builds', '--apply', stdout=StringIO())
        entry.refresh_from_db()
        self.assertEqual(entry.affected[0]['ranges'], [{'type': 'SEMVER', 'fixed': '5662'}])
        self.assertTrue(entry.needs_recorrelation)
        other.refresh_from_db()
        self.assertFalse(other.needs_recorrelation)
        self.assertEqual(intel.llamacpp_candidates().count(), 0)
