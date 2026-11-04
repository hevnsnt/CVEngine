"""cvENGINE 1.3.5, library and version detection (audit items 8, 9, 10, 14, 27). Every fixture is synthetic: the shape of the bad stored input
the audit found, on example hosts, and the corrected output."""
from datetime import timedelta
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import cms, correlation, fingerprint, js_libraries, kev_freshness, nuclei_scan, range_corrections, template_gates, versions
from cveFeed.models import CVEEntry, CVEMatch, ProbeObservation, RouteAuth
from reNgine import bbot as bbot_lib
from startScan.models import ScanHistory, Subdomain, Technology, Vulnerability
from tests.test_js_libraries_provenance import ReviewScenarioBase
from tests.test_route_auth import RouteFixture


# ----------------------------------------------------------------------------- item 8: a library's version comes only from its own file

# what Shodan InternetDB (bbot's shodan_idb module) handed over for a WordPress site whose only jQuery is core's 3.7.1: Wappalyzer-style
# readings of other scripts' ?ver= strings and banners (SmartMenus "jQuery Plugin - v1.2.1", jQuery Migrate ?ver=3.4.1, a forms plugin's
# ?ver=3.2.1, a theme's ?ver=1.0.4) and WordPress "3.7.1", which is core's jQuery file version
SHODAN_CPES = ('cpe:/a:jquery:jquery:1.2.1', 'cpe:/a:jquery:jquery:3.4.1', 'cpe:/a:jquery:jquery:3.2.1', 'cpe:/a:getbootstrap:bootstrap:1.0.4',
               'cpe:/a:wordpress:wordpress:3.7.1', 'cpe:/a:nginx:nginx')


class OtherToolsLibraryVersionTests(SimpleTestCase):
    def test_a_library_name_from_another_tool_loses_its_version(self):
        self.assertEqual(js_libraries.unversioned('jquery:1.2.1'), 'jQuery')
        self.assertEqual(js_libraries.unversioned('jQuery:3.4.1'), 'jQuery')
        self.assertEqual(js_libraries.unversioned('bootstrap:1.0.4'), 'Bootstrap')
        self.assertEqual(js_libraries.unversioned('jquery ui:1.12.1'), 'jQuery UI')
        self.assertEqual(js_libraries.unversioned('jquery'), 'jquery')  # no version: as it was
        self.assertEqual(js_libraries.unversioned('wordpress:3.7.1'), 'wordpress:3.7.1')  # not a library
        self.assertEqual(js_libraries.unversioned('jquery-smartmenus:1.2.1'), 'jquery-smartmenus:1.2.1')  # a plugin is not jQuery

    def test_the_nuclei_technology_pass_reads_the_same_version_every_run(self):
        a = {'template-id': 'cms-detect', 'info': {'name': 'Acme CMS Detect'}, 'extracted-results': ['1.2.1', '4.3.2']}
        b = {**a, 'extracted-results': ['4.3.2', '1.2.1']}  # nuclei hands them back in no fixed order
        self.assertEqual(nuclei_scan.tech_name_from(a), 'Acme CMS:4.3.2')
        self.assertEqual(nuclei_scan.tech_name_from(b), 'Acme CMS:4.3.2')

    def test_the_nuclei_technology_pass_stores_no_library_version(self):
        line = {'template-id': 'jquery-detect', 'info': {'name': 'jQuery Detect'}, 'extracted-results': ['1.2.1']}
        self.assertEqual(nuclei_scan.tech_name_from(line), 'jQuery')


class BbotLibraryIngestTests(RouteFixture, TestCase):
    def test_shodan_library_versions_are_stored_without_their_version(self):
        from reNgine.tasks import persist_bbot_result
        scan = self.scan()
        result = bbot_lib.BbotResult(subdomains={'www.rt.test'}, resolutions=set(), ports=set())
        for cpe in SHODAN_CPES:
            result.technologies.add(('www.rt.test', cpe))
        persist_bbot_result(result, {'scan_history_id': scan.id, 'domain_id': self.domain.id})
        names = set(Subdomain.objects.get(scan_history=scan, name='www.rt.test').technologies.values_list('name', flat=True))
        self.assertEqual(names, {'jQuery', 'Bootstrap', 'wordpress:3.7.1', 'nginx'})  # one bare jQuery, never 1.2.1 / 3.4.1 / 3.2.1


# a WordPress front page: core's jQuery 3.7.1, jQuery Migrate 3.4.1, the SmartMenus plugin (a "jQuery Plugin" banner), a forms plugin's and a
# theme's scripts with their own ?ver= strings, a <script src> in an HTML comment, one inside an inline script's text and, last, a <script>
# that never closes (a browser loads its src and reads the rest of the page as its text)
WP_PAGE = """<html><head>
<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
<script src="/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1"></script>
<!-- <script src="/js/jquery-1.8.3.min.js"></script> -->
<script src="/wp-content/plugins/forms-plugin/js/jquery.json.min.js?ver=3.2.1"></script>
<script src="/wp-content/plugins/page-builder/assets/lib/smartmenus/jquery.smartmenus.min.js?ver=1.2.1"></script>
<script src="/wp-content/themes/acme/js/vendor/jquery.appear.js?ver=1.0.4"></script>
</head><body><script>var config = {a: 1};
<script src="/js/jquery-1.4.2.min.js"></script>
<script src="/wp-content/themes/acme/js/site.js">
<div>footer</div><script src="/js/jquery-1.9.1.min.js"></script-not-a-close>
</body></html>"""
MIGRATE = '/*! jQuery Migrate v3.4.1 | (c) OpenJS Foundation and other contributors | jquery.org/license */\nvar m=1;'
SMARTMENUS = '/*! SmartMenus jQuery Plugin - v1.2.1 - November 3, 2022 */\n!function(t){t.SmartMenus=function(){}}(jQuery);'


class BrowserParseTests(SimpleTestCase):
    def test_a_commented_or_swallowed_script_is_not_a_script_the_page_loads(self):
        every, local = fingerprint.script_sources(WP_PAGE, 'https://www.example.com/', limit=40)
        self.assertNotIn('https://www.example.com/js/jquery-1.8.3.min.js', every)  # inside an HTML comment
        self.assertNotIn('https://www.example.com/js/jquery-1.4.2.min.js', every)  # inside an inline script's text
        self.assertNotIn('https://www.example.com/js/jquery-1.9.1.min.js', every)  # inside the text of a <script> that never closes
        self.assertIn('https://www.example.com/wp-content/themes/acme/js/site.js', every)  # ...whose own src loads
        self.assertEqual(len(every), 6)
        # the file names are hints and the query strings never versions: no jQuery 1.8.3 / 1.4.2 / 3.2.1 / 1.2.1 hint
        self.assertEqual([n for n, _s in fingerprint.from_script_urls(every)], ['jQuery', 'jQuery Migrate'])

    def test_the_effective_copy_is_the_one_its_file_states(self):
        entries = js_libraries.parse_page(WP_PAGE, 'https://www.example.com/')
        self.assertTrue(entries.capped)  # the unclosed <script>: nothing after it is known
        files = {'https://www.example.com/wp-includes/js/jquery/jquery.min.js': '/*! jQuery v3.7.1 | (c) OpenJS Foundation and other contributors */',
                 'https://www.example.com/wp-includes/js/jquery/jquery-migrate.min.js': MIGRATE,
                 'https://www.example.com/wp-content/plugins/page-builder/assets/lib/smartmenus/jquery.smartmenus.min.js': SMARTMENUS}

        def fetch(url, **_kw):
            body = files.get(url.split('?', 1)[0])
            return {'status': 200 if body else 404, 'body': body or '', 'headers': {}}
        with mock.patch.object(js_libraries, '_cache', return_value=None):
            records = js_libraries.read_page(entries, 'https://www.example.com/', fetch, lambda url: '', {'left': 10})
        self.assertEqual((records['jquery']['version'], records['jquery']['version_source']), ('3.7.1', 'body'))
        self.assertEqual([c['version'] for c in records['jquery']['copies']], ['3.7.1'])  # SmartMenus and the forms plugin are not copies
        self.assertEqual(records['jquery-migrate']['version'], '3.4.1')
        # the same answer every time the page is read: the order is the page's, never a set's
        with mock.patch.object(js_libraries, '_cache', return_value=None):
            again = js_libraries.read_page(entries, 'https://www.example.com/', fetch, lambda url: '', {'left': 10})
        self.assertEqual(records, again)


class CoreVersionFromALibraryFileTests(SimpleTestCase):
    def test_a_lone_core_version_a_library_file_states_is_the_librarys(self):
        pairs = [correlation.split_name_version(n) for n in ('wordpress:3.7.1', 'jQuery:3.7.1')]
        self.assertEqual(cms.disproven(pairs, stated={'3.7.1'}), {('wordpress', '3.7.1')})
        self.assertEqual(cms.disproven(pairs), set())  # without the file's reading nothing says which is which

    def test_a_probe_reading_of_the_core_still_wins(self):
        pairs = [correlation.split_name_version(n) for n in ('WordPress:3.7.1', 'jQuery:3.7.1')]
        self.assertEqual(cms.disproven(pairs, attested={'wordpress': {'3.7.1'}}, stated={'3.7.1'}), set())


class StoredShodanVersionsTests(ReviewScenarioBase):
    """The stored fixture: a host whose technologies hold what an earlier scan took from Shodan, beside core's jQuery read from its file."""

    def setUp(self):
        super().setUp()
        self.wp = CVEEntry.objects.create(cve_id='CVE-2099-4001', cvss=9.8, published_at=timezone.now(), kev=True,
                                          affected=[{'vendor': 'WordPress', 'product': 'WordPress', 'ranges': [{'introduced': '3.0.0', 'fixed': '4.0.0'}]}])
        self.entries.append(self.wp)

    def test_wordpress_is_never_read_at_the_version_of_its_jquery_file(self):
        sub = self.host('wp.x.test', ['wordpress:3.7.1', 'jQuery:3.7.1'])
        self.read_root('wp.x.test', 200, '<script src="/js/jquery.min.js"></script>')  # serves jQuery 3.7.1's own file
        found = self.correlate(sub)
        self.assertNotIn(('wp.x.test', 'CVE-2099-4001', '3.7.1'), found)  # before 1.3.5: a KEV match on "WordPress 3.7.1"


# ----------------------------------------------------------------------------- item 9: X-AspNet-Version is the .NET Framework

ASPNET_CORE_CVE = [{'vendor': 'Microsoft', 'product': 'ASP.NET Core 2.1', 'ranges': [{'introduced': '2.0', 'fixed': '2.1.40'}]},
                   {'vendor': 'Microsoft', 'product': '.NET 6.0', 'ranges': [{'introduced': '6.0.0', 'fixed': '6.0.21'}]}]
NETFX_CVE = [{'vendor': 'Microsoft', 'product': 'Microsoft .NET Framework 2.0 Service Pack 2',
              'ranges': [{'type': 'SEMVER', 'introduced': '2.0.0', 'fixed': '3.0.50727.8976'}]}]


class AspNetHeaderTests(RouteFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.scan_obj = self.scan()
        self.core = CVEEntry.objects.create(cve_id='CVE-2023-38180', kev=True, cvss=7.5, published_at=timezone.now(), affected=ASPNET_CORE_CVE)
        self.netfx = CVEEntry.objects.create(cve_id='CVE-2099-4002', kev=True, cvss=7.5, published_at=timezone.now(), affected=NETFX_CVE)

    def correlate(self, *names):
        sub = Subdomain.objects.get(scan_history=self.scan_obj, name='www.rt.test')
        sub.technologies.set([Technology.objects.get_or_create(name=n)[0] for n in names])
        entries = [self.core, self.netfx]
        correlation.correlate_subdomains(Subdomain.objects.filter(pk=sub.pk).prefetch_related('technologies', 'ip_addresses__ports'),
                                         correlation.build_product_index(entries), {e.id: e for e in entries})
        return set(CVEMatch.objects.filter(subdomain=sub).values_list('cve_entry__cve_id', 'matched_version'))

    def test_the_header_names_the_dotnet_framework_runtime(self):
        found = [f['name'] for f in versions.parse_headers({'Server': 'Microsoft-IIS/10.0', 'X-AspNet-Version': '2.0.50727',
                                                            'X-Powered-By': 'ASP.NET'})]
        self.assertIn('.NET Framework CLR:2.0.50727', found)
        self.assertNotIn('ASP.NET:2.0.50727', found)
        self.assertEqual(fingerprint.categorize('.NET Framework CLR:2.0.50727'), 'language')

    def test_cve_2023_38180_no_longer_matches_from_the_header(self):
        self.assertEqual(self.correlate('.NET Framework CLR:2.0.50727', 'Microsoft IIS:10.0'), set())

    def test_a_stored_aspnet_reading_of_an_earlier_build_does_not_match_either(self):
        self.assertEqual(self.correlate('ASP.NET:2.0.50727'), set())  # before 1.3.5: CVE-2023-38180 on "ASP.NET Core 2.1 2.0.50727"

    def test_a_real_aspnet_core_version_still_matches(self):
        self.assertEqual(self.correlate('ASP.NET Core:2.1.30'), {('CVE-2023-38180', '2.1.30')})


# ----------------------------------------------------------------------------- item 10: the ranges a CVE is matched on

# CVE-2020-11022 as stored: the CNA record and GHSA-gxr4-xjj5-5px2 (edited July 2026) start jQuery at 1.12.0
JQ_11022 = [{'vendor': 'jquery', 'product': 'jQuery', 'ranges': [{'introduced': '1.12.0', 'fixed': '3.5.0'}]},
            {'package': 'drupal', 'ranges': [{'introduced': '7.0.0', 'fixed': '7.70.0'}]},
            {'package': 'jquery', 'ranges': [{'introduced': '1.12.0', 'fixed': '3.5.0'}]},
            {'package': 'jquery-rails', 'ranges': [{'introduced': '0', 'fixed': '4.4.0'}]},
            {'package': 'org.webjars.npm:jquery', 'ranges': [{'introduced': '1.12.0', 'fixed': '3.5.0'}]},
            {'package': 'components/jquery', 'ranges': [{'introduced': '1.12.0', 'fixed': '3.5.0'}]}]


def _wordpress_branches(last):
    """A Wordfence-style record: one range per WordPress release branch from 4.7 up to ``last`` (``(major, minor, last patch)``)."""
    branches = [(4, 7, 38), (4, 8, 33), (4, 9, 34)] + [(5, m, 20) for m in range(10)] + [(6, m, 10) for m in range(10)] + [(7, 0, 7), (7, 1, 3)]
    keep = branches[:branches.index(last) + 1]
    return [{'vendor': 'WordPress Foundation', 'product': 'WordPress',
             'ranges': [{'type': 'SEMVER', 'introduced': f'{a}.{b}.0', 'lastAffected': f'{a}.{b}.{c}'} for a, b, c in keep]}]


class RangeCorrectionTests(SimpleTestCase):
    def test_the_jquery_lower_bound_is_corrected_with_its_sources(self):
        out, changed = range_corrections.apply('CVE-2020-11022', JQ_11022)
        self.assertEqual(changed, 4)
        starts = {(i.get('product') or i.get('package')): i['ranges'][0].get('introduced') for i in out}
        self.assertEqual(starts, {'jQuery': '1.2.0', 'jquery': '1.2.0', 'org.webjars.npm:jquery': '1.2.0', 'components/jquery': '1.2.0',
                                  'drupal': '7.0.0', 'jquery-rails': '0'})
        note = out[0]['range_corrections'][0]
        self.assertEqual((note['from'], note['to']), ('1.12.0', '1.2.0'))
        self.assertTrue(any('nvd.nist.gov' in s for s in note['sources']) and any('exploit-db.com' in s for s in note['sources']))
        self.assertEqual(range_corrections.apply('CVE-2020-11022', out), (out, 0))  # idempotent

    def test_a_bound_the_feed_changes_again_is_left_to_the_feed(self):
        moved = [{'vendor': 'jquery', 'product': 'jQuery', 'ranges': [{'introduced': '1.0.0', 'fixed': '3.5.0'}]}]
        self.assertEqual(range_corrections.apply('CVE-2020-11022', moved), (moved, 0))
        self.assertEqual(range_corrections.apply('CVE-2020-11023', JQ_11022), (JQ_11022, 0))  # another CVE: untouched

    def test_the_structured_record_wins_and_the_description_never_extends_it(self):
        # a record whose ranges stop at 6.6.10 under a description that says "4.7 through 7.1.3": 7.1.3 is not matched
        short = _wordpress_branches((6, 6, 10))
        self.assertIsNot(correlation.range_verdict(correlation.parse_version('6.6.9'), short[0]['ranges'])[0], False)
        self.assertIsNot(correlation.range_verdict(correlation.parse_version('7.1.3'), short[0]['ranges'])[0], True)
        # the CNA's full record (CVE-2026-119977 carries 25 branches, through 7.1.3) matches 7.1.3 and not the fixed 7.1.4
        full = _wordpress_branches((7, 1, 3))
        self.assertTrue(correlation.range_verdict(correlation.parse_version('7.1.3'), full[0]['ranges'])[0])
        self.assertIsNot(correlation.range_verdict(correlation.parse_version('7.1.4'), full[0]['ranges'])[0], True)


class StoredRangeTests(TestCase):
    def test_a_feed_refresh_stores_the_corrected_range(self):
        entry, _ = CVEEntry.from_api({'id': 'CVE-2020-11022', 'title': 'jQuery XSS', 'affected': JQ_11022, 'sources': [], 'status': 'published'})
        self.assertEqual(entry.affected[0]['ranges'][0]['introduced'], '1.2.0')

    def test_the_cve_list_import_stores_the_corrected_range(self):
        from cveFeed import intel
        doc = {'cveMetadata': {'cveId': 'CVE-2020-11022', 'state': 'PUBLISHED', 'datePublished': '2020-04-29T00:00:00'},
               'containers': {'cna': {'descriptions': [{'lang': 'en', 'value': 'In jQuery starting with 1.12.0 and before 3.5.0 ...'}],
                                      'affected': [{'vendor': 'jquery', 'product': 'jQuery',
                                                    'versions': [{'version': '>= 1.12.0, < 3.5.0', 'status': 'affected'}]}]}}}
        fields = intel.entry_from_cve5(doc, {})
        self.assertEqual(fields['affected'][0]['ranges'][0]['introduced'], '1.2.0')

    def test_the_backfill_is_a_dry_run_unless_applied(self):
        from io import StringIO

        from django.core.management import call_command

        from cveFeed.models import MatchVerdict
        cve = CVEEntry.objects.create(cve_id='CVE-2020-11022', cvss=6.9, published_at=timezone.now(), affected=JQ_11022)
        out = StringIO()
        call_command('apply_range_corrections', stdout=out)
        cve.refresh_from_db()
        self.assertEqual(cve.affected[0]['ranges'][0]['introduced'], '1.12.0')  # nothing written
        self.assertIn('would correct CVE-2020-11022: 4 range(s)', out.getvalue())
        self.assertIn('dry run', out.getvalue())
        MatchVerdict.objects.create(cve_entry=cve, matched_product='jQuery', matched_version='1.11.3', version_in_range=False, source='tech',
                                    ai_verdict='uncertain')
        call_command('apply_range_corrections', '--apply', stdout=StringIO())
        cve.refresh_from_db()
        self.assertEqual((cve.affected[0]['ranges'][0]['introduced'], cve.needs_recorrelation), ('1.2.0', True))
        self.assertFalse(MatchVerdict.objects.filter(cve_entry=cve).exists())
        again = StringIO()
        call_command('apply_range_corrections', stdout=again)
        self.assertIn('nothing to correct', again.getvalue())

    def test_the_api_lists_every_range_of_a_long_record(self):
        from agentapi.services import _cve_context
        cve = CVEEntry.objects.create(cve_id='CVE-2026-119977', kev=True, published_at=timezone.now(), affected=_wordpress_branches((7, 1, 3)),
                                      original_description='WordPress Core is vulnerable in versions 4.7 through 7.1.3.')
        ranges = _cve_context(cve)['affected'][0]['ranges']
        self.assertEqual(len(ranges), 25)  # before 1.3.5 the first 20 (up to 6.6.10), which read as if 7.1.3 came from the description
        self.assertEqual(ranges[-1], {'type': 'SEMVER', 'introduced': '7.1.0', 'lastAffected': '7.1.3'})


class CorrectedRangeMatchTests(ReviewScenarioBase):
    def test_jquery_1_11_matches_cve_2020_11022_once_corrected(self):
        cve = CVEEntry.objects.create(cve_id='CVE-2020-11022', cvss=6.9, published_at=timezone.now(),
                                      affected=range_corrections.apply('CVE-2020-11022', JQ_11022)[0])
        self.entries = [cve]
        sub = self.host('old.x.test', ['jQuery:1.11.3'])
        self.assertIn(('old.x.test', 'CVE-2020-11022', '1.11.3'), self.correlate(sub))  # a false negative before


# ----------------------------------------------------------------------------- item 14: CVE-2023-5561 only on WordPress up to 6.3.1

USERS_HIT = {'template': 'http/cves/2023/CVE-2023-5561.yaml', 'template-id': 'CVE-2023-5561', 'type': 'http',
             'info': {'name': 'WordPress Core - Post Author Email Disclosure', 'severity': 'medium',
                      'classification': {'cve-id': ['cve-2023-5561']}},
             'host': 'https://www.rt.test', 'matched-at': 'https://www.rt.test/wp-json/wp/v2/users?search=@'}


class TemplateGateTests(RouteFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.scan_obj = self.scan()
        self.sub = Subdomain.objects.get(scan_history=self.scan_obj, name='www.rt.test')

    def techs(self, *names):
        self.sub.technologies.set([Technology.objects.get_or_create(name=n)[0] for n in names])

    def test_a_patched_wordpress_is_held_back(self):
        self.techs('WordPress:7.1.4')
        self.assertIn('the patched behaviour', template_gates.held_back(USERS_HIT, self.sub))

    def test_an_affected_or_unknown_wordpress_keeps_the_hit(self):
        self.techs('WordPress:6.3.1')
        self.assertEqual(template_gates.held_back(USERS_HIT, self.sub), '')
        self.techs('WordPress')
        self.assertEqual(template_gates.held_back(USERS_HIT, self.sub), '')

    def test_a_probe_reading_beats_a_stale_fingerprint(self):
        self.techs('WordPress:6.2.0')
        ProbeObservation.objects.create(project=self.project, domain=self.domain, host='www.rt.test', probe='wordpress-detect', kind='wordpress',
                                        product='WordPress', version='7.1.4', outcome='found', confidence=0.9, source='feed:generator')
        self.assertTrue(template_gates.held_back(USERS_HIT, self.sub))

    def test_the_nuclei_pass_records_no_finding_on_a_patched_wordpress(self):
        self.techs('WordPress:7.1.4')
        nuclei_scan.run_nuclei(self.scan_obj.id, stream=lambda path, **k: iter([USERS_HIT]))
        self.assertFalse(Vulnerability.objects.filter(template_id='CVE-2023-5561').exists())
        self.techs('WordPress:6.3.1')
        nuclei_scan.run_nuclei(self.scan_obj.id, stream=lambda path, **k: iter([USERS_HIT]), force=True)
        self.assertTrue(Vulnerability.objects.filter(template_id='CVE-2023-5561').exists())

    def test_a_cve_template_test_on_a_patched_wordpress_is_no_hit(self):
        from cveFeed import templategen
        cve = CVEEntry.objects.create(cve_id='CVE-2023-5561', cvss=5.3, published_at=timezone.now(),
                                      affected=[{'vendor': 'WordPress', 'product': 'WordPress', 'ranges': [{'introduced': '4.7.0', 'lastAffected': '6.3.1'}]}])
        match = CVEMatch.objects.create(cve_entry=cve, subdomain=self.sub, matched_product='WordPress', matched_version='6.3.1', version_in_range=True,
                                        source='tech')
        self.techs('WordPress:7.1.4')  # the site moved on since the match was made
        outcome = {'host': 'www.rt.test', 'vulnerable': True, 'output': '', 'error': '', 'hit': USERS_HIT}
        templategen.record_outcomes(cve, [outcome], self.project.id, template_id='CVE-2023-5561')
        match.refresh_from_db()
        self.assertEqual(match.template_result, 'no_match')
        self.assertFalse(Vulnerability.objects.filter(template_id='CVE-2023-5561').exists())


# ----------------------------------------------------------------------------- item 27: a KEV match is raised on a fresh reading only

class KevFreshnessTests(RouteFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.kev = CVEEntry.objects.create(cve_id='CVE-2099-4003', kev=True, cvss=8.1, published_at=timezone.now(),
                                           affected=[{'vendor': 'WordPress Foundation', 'product': 'WordPress',
                                                      'ranges': [{'introduced': '7.1.0', 'lastAffected': '7.1.3'}]}])
        self.plain = CVEEntry.objects.create(cve_id='CVE-2099-4004', kev=False, cvss=8.1, published_at=timezone.now(),
                                             affected=self.kev.affected)

    def host(self, read_hours_ago):
        scan = self.scan()
        when = timezone.now() - timedelta(hours=read_hours_ago)
        ScanHistory.objects.filter(pk=scan.pk).update(start_scan_date=when - timedelta(minutes=30), stop_scan_date=when, scan_status=2)
        sub = Subdomain.objects.get(scan_history=scan, name='www.rt.test')
        sub.technologies.set([Technology.objects.get_or_create(name='WordPress:7.1.3')[0]])
        return sub

    def correlate(self, sub, entries=None):
        entries = entries or [self.kev, self.plain]
        with mock.patch.object(kev_freshness, 'request_reread') as ask:
            correlation.correlate_subdomains(Subdomain.objects.filter(pk=sub.pk).prefetch_related('technologies', 'ip_addresses__ports'),
                                             correlation.build_product_index(entries), {e.id: e for e in entries})
        return set(CVEMatch.objects.filter(subdomain=sub).values_list('cve_entry__cve_id', flat=True)), ask

    def test_a_kev_match_from_a_fingerprint_two_days_old_is_held_and_the_host_read_again(self):
        sub = self.host(26)  # read 2026-11-02 23:02, correlated 2026-11-04 00:51 in the audit
        found, ask = self.correlate(sub)
        self.assertEqual(found, {'CVE-2099-4004'})  # a CVE that is not on the KEV is matched as before
        ask.assert_called_once_with({sub.pk})

    def test_a_fresh_fingerprint_raises_it(self):
        found, ask = self.correlate(self.host(2))
        self.assertEqual(found, {'CVE-2099-4003', 'CVE-2099-4004'})
        ask.assert_not_called()

    def test_a_probe_that_read_the_same_version_since_raises_it(self):
        sub = self.host(48)
        ProbeObservation.objects.create(project=self.project, domain=self.domain, host='www.rt.test', probe='wordpress-detect', kind='wordpress',
                                        product='WordPress', version='7.1.3', outcome='found', confidence=0.9, source='feed:generator')
        self.assertEqual(self.correlate(sub)[0], {'CVE-2099-4003', 'CVE-2099-4004'})

    def test_a_route_check_that_read_the_same_version_since_raises_it(self):
        sub = self.host(48)
        RouteAuth.objects.create(project=self.project, domain=self.domain, host='www.rt.test', path='/', url='https://www.rt.test/',
                                 auth_state='open', http_status=200, checked_at=timezone.now(),
                                 evidence={'fingerprint_names': ['WordPress:7.1.3']})
        self.assertEqual(self.correlate(sub)[0], {'CVE-2099-4003', 'CVE-2099-4004'})

    def test_a_reading_of_another_version_does_not(self):
        sub = self.host(48)
        ProbeObservation.objects.create(project=self.project, domain=self.domain, host='www.rt.test', probe='wordpress-detect', kind='wordpress',
                                        product='WordPress', version='7.1.4', outcome='found', confidence=0.9, source='feed:generator')
        self.assertEqual(self.correlate(sub)[0], {'CVE-2099-4004'})

    def test_an_existing_match_is_updated_not_held(self):
        sub = self.host(2)
        self.correlate(sub)
        ScanHistory.objects.filter(pk=sub.scan_history_id).update(stop_scan_date=timezone.now() - timedelta(hours=50))
        found, ask = self.correlate(sub)
        self.assertEqual(found, {'CVE-2099-4003', 'CVE-2099-4004'})
        ask.assert_not_called()

    def test_the_reread_reads_the_host_again_and_correlates_it_whatever_it_found(self):
        sub = self.host(26)
        with mock.patch('cveFeed.probes.run_one') as run_one, mock.patch('cveFeed.probes.recorrelate') as recorrelate:
            self.assertEqual(kev_freshness.reread([sub.pk]), 1)
        self.assertTrue(run_one.called)
        self.assertIn('wordpress-detect', {call.args[3]['probe'] for call in run_one.call_args_list})
        recorrelate.assert_called_once()

    def test_a_passive_target_is_not_read_again(self):
        from targetApp.models import Domain
        sub = self.host(26)
        Domain.objects.filter(pk=self.domain.pk).update(discovery_mode=Domain.DISCOVERY_PASSIVE)
        with mock.patch('cveFeed.probes.run_one') as run_one:
            self.assertEqual(kev_freshness.reread([sub.pk]), 0)
        run_one.assert_not_called()
