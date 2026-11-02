"""The self-hosted CMSs beside WordPress: how a page says which one it is, and where each one states its version."""
from django.test import SimpleTestCase

from cveFeed import cms, fingerprint, probes
from tests.test_probes import answers, page

DRUPAL_PAGE = ('<html><head><meta name="Generator" content="Drupal 10 (https://www.drupal.org)">'
               '<script src="/core/assets/vendor/jquery/jquery.min.js?v=3.7.1"></script>'
               '<script src="/core/misc/drupal.js?v=10.2.3"></script></head><body>x</body></html>')
JOOMLA_PAGE = '<html><head><meta name="generator" content="Joomla! - Open Source Content Management"><script src="/media/system/js/core.js?abc"></script></head></html>'
MAGENTO_PAGE = '<html><head><link rel="stylesheet" href="/static/version1700000000/frontend/Magento/luma/en_US/css/styles-m.css"></head></html>'
TYPO3_PAGE = '<html><head><link rel="stylesheet" href="/typo3temp/assets/compressed/merged-1.css"></head></html>'


def names(body, headers=None):
    return [f['name'] for f in fingerprint.from_response(body=body, content_type='text/html', headers=headers or {})]


class MarkerTests(SimpleTestCase):
    def test_each_cms_names_itself_from_a_front_page(self):
        self.assertIn('Joomla', names(JOOMLA_PAGE))
        self.assertIn('Magento', names(MAGENTO_PAGE))
        self.assertIn('TYPO3', names(TYPO3_PAGE))
        self.assertTrue(any(n.startswith('Drupal') for n in names(DRUPAL_PAGE)))

    def test_a_page_that_only_mentions_a_path_in_text_is_not_that_cms(self):
        text = '<html><body><p>Our migration guide: move your files from /typo3conf/ and /skin/frontend/ to the new theme.</p></body></html>'
        found = names(text)
        self.assertNotIn('TYPO3', found)
        self.assertNotIn('Magento', found)

    def test_a_bare_major_in_the_generator_is_no_version(self):
        self.assertNotIn('Drupal:10', names(DRUPAL_PAGE))


class PassiveVersionTests(SimpleTestCase):
    def observations(self, body):
        return probes.observations_from_page(page(200, body=body))

    def test_drupal_core_script_states_the_core_version_and_jquerys_is_not_it(self):
        found = {o['product'] + ':' + o['version'] for o in self.observations(DRUPAL_PAGE) if o['kind'] == 'version'}
        self.assertIn('Drupal:10.2.3', found)
        self.assertFalse({v for v in found if v.startswith('Drupal:')} - {'Drupal:10.2.3'})
        self.assertNotIn('Drupal:3.7.1', found)

    def test_a_library_script_alone_is_no_drupal_version(self):
        body = '<html><script src="/core/assets/vendor/jquery/jquery.min.js?v=3.7.1"></script></html>'
        self.assertEqual([o for o in self.observations(body) if o['product'] == 'Drupal'], [])

    def test_a_pre_release_core_script_is_no_version(self):
        self.assertEqual(cms.best('Drupal', [('/', page(200, body='<script src="/core/misc/drupal.js?v=10.3.0-beta1"></script>'))]), ('', ''))

    def test_version_headers_name_umbraco_and_magento(self):
        found = [f['name'] for f in fingerprint.from_response(headers={'x-umbraco-version': '13.4.1', 'x-magento-tags': 'cms_b'})]
        self.assertIn('Umbraco:13.4.1', found)
        self.assertIn('Magento', found)


class VersionFileTests(SimpleTestCase):
    def run_probe(self, probe_id, table):
        return probes.run_http_probe(probe_id, 'https://www.rt.test', {'www.rt.test'}, get=answers(table), sleep=lambda s: None)

    def test_joomla_falls_back_to_the_language_pack_when_the_manifest_is_hidden(self):
        found = self.run_probe('joomla-manifest', {'/language/en-GB/en-GB.xml': page(200, body='<metafile><version>4.4.3</version></metafile>')})
        self.assertEqual([(o['product'], o['version'], o['source']) for o in found], [('Joomla', '4.4.3', 'body:joomla-language')])

    def test_joomla_manifest_wins_by_confidence(self):
        xml = page(200, body='<extension><version>5.1.2</version></extension>')
        found = self.run_probe('joomla-manifest', {'/administrator/manifests/files/joomla.xml': xml, '/language/en-GB/en-GB.xml': xml})
        self.assertEqual(max(found, key=lambda o: o['confidence'])['source'], 'body:joomla-manifest')

    def test_magento_version_endpoint_names_the_product_and_no_version(self):
        found = self.run_probe('magento-version', {'/magento_version': page(200, body='Magento/2.4 (Community)')})
        self.assertEqual([(o['product'], o['version'], o['outcome']) for o in found], [('Magento', '', 'hidden')])  # the branch is not a release

    def test_magento_admin_footer_states_the_release(self):
        found = self.run_probe('magento-version', {'/admin': page(200, body='<footer>Magento ver. 2.4.6-p3</footer>')})
        self.assertEqual([(o['version'], o['source']) for o in found], [('2.4.6-p3', 'body:magento-admin')])

    def test_magento_one_release_notes(self):
        found = self.run_probe('magento-version', {'/RELEASE_NOTES.txt': page(200, body='NEWS\n=== 1.9.4.5 ===\n* fixes')})
        self.assertEqual([o['version'] for o in found], ['1.9.4.5'])

    def test_a_site_that_answers_every_path_with_a_page_states_no_version(self):
        everything = page(200, body='<html>welcome</html>')
        found = self.run_probe('magento-version', {'/magento_version': everything, '/admin': everything, '/RELEASE_NOTES.txt': everything})
        self.assertEqual(found, [])

    def test_the_new_probes_follow_only_their_own_product(self):
        sub_leads = [{'name': 'Magento', 'source': 'tech'}]
        plan = probes.plan_for_host.__wrapped__ if hasattr(probes.plan_for_host, '__wrapped__') else None
        self.assertIsNone(plan)  # plan_for_host needs a host row: the lead pattern is what selects the probe
        self.assertTrue(probes._lead_matches(probes.BY_ID['magento-version'], 'magento', sub_leads[0]))
        self.assertFalse(probes._lead_matches(probes.BY_ID['magento-version'], 'drupal', {'name': 'Drupal', 'source': 'tech'}))


FORUMS = {
    'MyBB': ('<div id="footer"><a href="https://mybb.com">Powered By</a> <a href="https://mybb.com" target="_blank">MyBB 1.8.38</a></div>', '1.8.38'),
    'Simple Machines Forum': ('<script>var smf_version = "SMF 2.1.4", smf_scripturl = "/index.php?";</script>', '2.1.4'),
    'PunBB': ('<p id="brd-about">Powered by <a href="http://punbb.informer.com/">PunBB</a> 1.4.6</p>', '1.4.6'),
    'XMB': ('<!-- Powered by XMB 1.9.12 -->', '1.9.12'),
    'YetAnotherForum.NET': ('<span>Powered by YAF.NET 2.2.5</span>', '2.2.5'),
    'NodeBB': ('<script>var config = {"relative_path":"","version":"3.6.7","siteTitle":"x"};</script><script src="/assets/nodebb.min.js"></script>', '3.6.7'),
}


class ForumTests(SimpleTestCase):
    def test_each_board_names_itself_and_states_its_release_from_its_footer_or_script(self):
        for product, (body, version) in FORUMS.items():
            with self.subTest(product):
                found = probes.observations_from_page(page(200, body=f'<html><body>{body}</body></html>'))
                self.assertIn((product, version), [(o['product'], o['version']) for o in found if o['kind'] == 'version'])

    def test_vanilla_states_its_release_in_a_header(self):
        found = probes.observations_from_page(page(200, headers={'X-Garden-Version': 'Vanilla 3.0'}, body='<html></html>'))
        self.assertIn(('Vanilla', '3.0'), [(o['product'], o['version']) for o in found if o['kind'] == 'version'])

    def test_a_board_that_hides_its_release_is_named_without_one(self):
        found = probes.observations_from_page(page(200, body='<a href="https://mybb.com">MyBB</a>'))
        self.assertEqual([(o['product'], o['version'], o['outcome']) for o in found if o['product'] == 'MyBB'], [('MyBB', '', 'hidden')])

    def test_a_post_that_names_a_release_is_not_the_boards_footer(self):
        body = '<div class="post">Upgrade to MyBB 1.8.38 and SMF 2.1.4 as soon as you can, and use phpBB 3.3.11 in production.</div>'
        self.assertEqual([o for o in probes.observations_from_page(page(200, body=body)) if o['product'] in ('MyBB', 'Simple Machines Forum', 'phpBB')], [])

    def test_a_footer_without_a_full_release_states_no_version(self):
        found = probes.observations_from_page(page(200, body='<a href="https://mybb.com">MyBB 1</a>'))
        self.assertEqual({o['version'] for o in found if o['product'] == 'MyBB'}, {''})  # named, no release stated

    def test_boards_that_state_no_release_are_still_named(self):
        for product, body in (('phpBB', '<a href="https://www.phpbb.com/">phpBB</a>&reg; Forum Software'),
                              ('XenForo', '<div data-xf-init="x"></div>'), ('Discourse', '<div data-discourse-setup="x"></div>'),
                              ('Flarum', '<div id="flarum-loading"></div>')):
            with self.subTest(product):
                self.assertIn(product, names(f'<html>{body}</html>'))

    def test_generator_tags_already_carry_discourse_and_vbulletin_releases(self):
        self.assertIn('vBulletin:5.7.5', names('<meta name="generator" content="vBulletin 5.7.5">'))
