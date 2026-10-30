"""WordPress core older than the October 2026 security release (7.1.4 and its backports): the version check, what the answer for
``wp-content/upgrade/`` says, the extra request the WordPress probe makes, and the findings the stage records."""
from django.test import SimpleTestCase, TestCase

from cveFeed import probes, wp_core
from cveFeed.models import ProbeObservation
from startScan.models import Subdomain, Vulnerability
from tests.test_probes import answers, page
from tests.test_route_auth import RouteFixture

LINK = {'Link': '<https://www.rt.test/wp-json/>; rel="https://api.w.org/"'}
LISTING = '<html><head><title>Index of /wp-content/upgrade</title></head><body><h1>Index of /wp-content/upgrade</h1><a href="?C=N;O=D">Name</a></body></html>'
NGINX_LISTING = '<html><head><title>Index of /wp-content/upgrade/</title></head><body><h1>Index of /wp-content/upgrade/</h1><hr><pre></pre></body></html>'


class AssessTests(SimpleTestCase):
    def test_a_release_before_its_branch_fix_is_behind(self):
        for version, fixed in (('7.1.3', '7.1.4'), ('7.1', '7.1.4'), ('7.0.7', '7.0.8'), ('6.9.10', '6.9.11'), ('6.4.2', '6.4.14'), ('5.0.30', '5.0.31'),
                               ('4.7.38', '4.7.39')):
            self.assertEqual(wp_core.assess(version), (wp_core.BEHIND, fixed), version)

    def test_the_fix_and_later_releases_of_a_branch_are_patched(self):
        for version in ('7.1.4', '7.1.5', '7.0.8', '6.9.11', '6.8.12', '5.0.31', '4.7.39', '4.7.40'):
            self.assertEqual(wp_core.assess(version)[0], wp_core.PATCHED, version)

    def test_a_branch_before_4_7_has_no_fix(self):
        for version in ('4.6.30', '4.1', '3.9.2', '2.8'):
            self.assertEqual(wp_core.assess(version), (wp_core.UNSUPPORTED, ''), version)

    def test_a_newer_branch_or_an_unreadable_version_is_not_judged(self):
        self.assertEqual(wp_core.assess('7.2')[0], wp_core.NEWER)
        self.assertEqual(wp_core.assess('8.0.1')[0], wp_core.NEWER)
        for version in ('', None, 'latest', '7.2-beta3', '7', 'x.y.z', '6.9-RC1'):
            self.assertEqual(wp_core.assess(version)[0], wp_core.UNKNOWN, version)

    def test_every_branch_of_the_release_notes_is_in_the_table(self):
        self.assertEqual(len(wp_core.FIXED), 25)
        self.assertEqual(wp_core.FIXED['7.1'], '7.1.4')
        self.assertEqual(wp_core.FIXED['4.7'], '4.7.39')
        for branch, fixed in wp_core.FIXED.items():
            self.assertTrue(fixed.startswith(branch + '.'), (branch, fixed))


class ClassifyDirTests(SimpleTestCase):
    def test_a_directory_listing_is_recognised(self):
        self.assertEqual(wp_core.classify_dir(page(200, body=LISTING)), wp_core.LISTING)
        self.assertEqual(wp_core.classify_dir(page(200, body=NGINX_LISTING)), wp_core.LISTING)
        self.assertEqual(wp_core.classify_dir(page(200, body='<html><body>[To Parent Directory]<br></body></html>')), wp_core.LISTING)

    def test_an_empty_page_is_wordpresss_own_index_and_says_nothing_denies_the_path(self):
        self.assertEqual(wp_core.classify_dir(page(200, body='')), wp_core.REACHABLE)
        self.assertEqual(wp_core.classify_dir(page(200, body='<?php\n// Silence is golden.\n')), wp_core.REACHABLE)

    def test_a_server_that_answers_every_path_with_an_empty_page_says_nothing(self):
        self.assertEqual(wp_core.classify_dir(page(200, body=''), missing=page(200, body='')), wp_core.UNKNOWN_DIR)
        self.assertEqual(wp_core.classify_dir(page(200, body=''), missing=page(404, body='not found')), wp_core.REACHABLE)

    def test_a_denied_or_absent_directory_is_denied(self):
        for status in (401, 403, 404, 410):
            self.assertEqual(wp_core.classify_dir(page(status, body='no')), wp_core.DENIED, status)

    def test_a_page_a_redirect_a_challenge_or_no_answer_says_nothing(self):
        self.assertEqual(wp_core.classify_dir(page(200, body='<html>' + 'welcome to the site ' * 50 + '</html>')), wp_core.UNKNOWN_DIR)
        self.assertEqual(wp_core.classify_dir(page(301, body='')), wp_core.UNKNOWN_DIR)
        self.assertEqual(wp_core.classify_dir(page(500, body='')), wp_core.UNKNOWN_DIR)
        self.assertEqual(wp_core.classify_dir({**page(200, body=''), 'challenge': 'Cloudflare'}), wp_core.UNKNOWN_DIR)
        self.assertEqual(wp_core.classify_dir(None), wp_core.UNKNOWN_DIR)


class ProbeTests(SimpleTestCase):
    def detect(self, table):
        table = {'/wp-login.php': page(200, headers=LINK, body='<form id="loginform">'), **table}
        return probes.run_http_probe('wordpress-detect', 'https://www.rt.test', {'www.rt.test', 'rt.test'}, get=answers(table), sleep=lambda s: None)

    def test_a_wordpress_site_is_asked_for_the_upgrade_directory_and_the_wordpress_observation_stays_first(self):
        found = self.detect({'/wp-content/upgrade/': page(200, body=LISTING)})
        self.assertEqual(found[0]['kind'], 'wordpress')
        self.assertEqual((found[1]['kind'], found[1]['variant'], found[1]['outcome']), ('wp-upgrade-dir', 'listing', 'found'))

    def test_a_denied_directory_is_recorded_as_absent(self):
        found = self.detect({'/wp-content/upgrade/': page(403, body='Forbidden')})
        self.assertEqual((found[1]['variant'], found[1]['outcome']), ('denied', 'absent'))

    def test_an_empty_page_is_checked_against_a_path_that_cannot_exist(self):
        asked = []

        def get(url):
            asked.append(url)
            return answers({'/wp-login.php': page(200, headers=LINK, body='<form id="loginform">'),
                            '/wp-content/upgrade/': page(200, body='')})(url)
        found = probes.run_http_probe('wordpress-detect', 'https://www.rt.test', {'www.rt.test'}, get=get, sleep=lambda s: None)
        self.assertTrue(any(u.endswith(wp_core.UPGRADE_MISSING) for u in asked))
        self.assertEqual(found[1]['variant'], 'reachable')  # the missing path answered 404, so the empty page is the directory's own

    def test_a_catch_all_empty_page_is_not_reported_as_reachable(self):
        table = {'/wp-login.php': page(200, headers=LINK, body='<form id="loginform">'), '/wp-content/upgrade/': page(200, body=''),
                 wp_core.UPGRADE_MISSING: page(200, body='')}
        found = probes.run_http_probe('wordpress-detect', 'https://www.rt.test', {'www.rt.test'}, get=answers(table), sleep=lambda s: None)
        self.assertEqual((found[1]['variant'], found[1]['outcome']), ('unknown', 'hidden'))

    def test_a_site_that_is_not_wordpress_is_not_asked(self):
        asked = []

        def get(url):
            asked.append(url)
            return page(404, body='not found')
        found = probes.run_http_probe('wordpress-detect', 'https://www.rt.test', {'www.rt.test'}, get=get, sleep=lambda s: None)
        self.assertFalse(any('/wp-content/upgrade' in u for u in asked))
        self.assertEqual([o['kind'] for o in found], ['wordpress'])
        self.assertEqual(found[0]['outcome'], 'absent')

    def test_the_directory_adds_no_technology(self):
        found = self.detect({'/wp-content/upgrade/': page(200, body=LISTING)})
        self.assertEqual(probes.technology_names(found), ['WordPress'])


class StageTests(RouteFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.scan_obj = self.scan(names=('www.rt.test',))
        self.sub = Subdomain.objects.get(scan_history=self.scan_obj, name='www.rt.test')

    def sight(self, version, directory=None, probe='wpscan-core'):
        if version is not None:
            kind = 'version' if probe == 'wpscan-core' else 'wordpress'
            ProbeObservation.objects.create(project=self.project, domain_id=self.domain.id, host='www.rt.test', probe=probe, port=0, kind=kind,
                                            product='WordPress', version=version, outcome='found')
        if directory:
            ProbeObservation.objects.create(project=self.project, domain_id=self.domain.id, host='www.rt.test', probe='wp-upgrade-dir', port=0,
                                            kind='wp-upgrade-dir', product='WordPress', variant=directory, outcome='found')

    def findings(self):
        return list(Vulnerability.objects.filter(scan_history=self.scan_obj, source=wp_core.SOURCE))

    def test_a_core_behind_its_fix_is_a_high_finding(self):
        self.sight('7.1.3')
        self.assertTrue(wp_core.applicable(self.scan_obj))
        self.assertEqual(wp_core.run_for_scan(self.scan_obj.id), {'hosts': 1, 'behind': 1, 'exposed': 0})
        found = self.findings()
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0].name, found[0].severity), (wp_core.FINDING_NAME, 3))
        self.assertIn('7.1.4', found[0].description)
        self.assertIn('wp-content/upgrade/', found[0].remediation)
        self.assertEqual(list(found[0].cve_ids.all()), [])  # no CVE number was published: none is made up

    def test_behind_with_the_directory_served_is_critical(self):
        self.sight('6.9.8', 'reachable')
        wp_core.run_for_scan(self.scan_obj.id)
        found = self.findings()
        self.assertEqual(found[0].severity, 4)
        self.assertIn('6.9.11', found[0].description)

    def test_a_branch_with_no_fix_says_so(self):
        self.sight('4.6.30', 'listing')
        wp_core.run_for_scan(self.scan_obj.id)
        found = self.findings()
        self.assertEqual(found[0].severity, 4)
        self.assertIn('no longer receives security updates', found[0].description)

    def test_a_patched_core_with_the_directory_denied_has_no_finding(self):
        self.sight('7.1.4', 'denied')
        self.assertEqual(wp_core.run_for_scan(self.scan_obj.id), {'hosts': 1, 'behind': 0, 'exposed': 0})
        self.assertEqual(self.findings(), [])

    def test_a_patched_core_whose_directory_is_still_served_is_a_hardening_note(self):
        self.sight('7.1.4', 'listing')
        wp_core.run_for_scan(self.scan_obj.id)
        found = self.findings()
        self.assertEqual((found[0].name, found[0].severity), (wp_core.EXPOSED_NAME, 1))

    def test_the_version_wpscan_read_wins_over_the_probes(self):
        self.sight('7.1.4')                                   # WPScan read the core files
        self.sight('6.0.1', probe='wordpress-detect')          # the page's generator tag said something else
        wp_core.run_for_scan(self.scan_obj.id)
        self.assertEqual(self.findings(), [])

    def test_the_probes_version_is_used_when_wpscan_has_not_run(self):
        self.sight('7.0.2', probe='wordpress-detect')
        wp_core.run_for_scan(self.scan_obj.id)
        self.assertEqual(self.findings()[0].severity, 3)

    def test_a_host_with_no_version_is_not_judged_and_the_stage_does_not_apply(self):
        self.sight(None, 'reachable')
        self.assertFalse(wp_core.applicable(self.scan_obj))
        self.assertEqual(wp_core.run_for_scan(self.scan_obj.id), {'hosts': 0, 'behind': 0, 'exposed': 0})
        self.assertEqual(self.findings(), [])

    def test_running_it_again_keeps_one_finding(self):
        self.sight('7.1.3')
        wp_core.run_for_scan(self.scan_obj.id)
        wp_core.run_for_scan(self.scan_obj.id)
        self.assertEqual(len(self.findings()), 1)
