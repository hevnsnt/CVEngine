"""Where WordPress states its version, and what the probe stores. The regression these guard against was found on a live site (WordPress 7.1.4):
the first ``?ver=`` of any asset under /wp-includes/ is jQuery's, and it was stored as the WordPress version (3.7.1)."""
from django.test import SimpleTestCase

from cveFeed import cms, probes
from tests.test_probes import answers, page

HEAD = (
    "<link rel='stylesheet' href='https://rt.test/wp-content/themes/t/main.css?ver=1790752965' />\n"
    "<script src='https://rt.test/wp-includes/js/jquery/jquery.min.js?ver=3.7.1'></script>\n"
    "<script src='https://rt.test/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1'></script>\n"
    "<script src='https://rt.test/wp-includes/js/dist/dom-ready.min.js?ver=3'></script>\n"
    "<script src='https://rt.test/wp-includes/js/dist/i18n.min.js?ver=1'></script>\n"
    "<script src='https://rt.test/wp-includes/js/dist/a11y.min.js?ver=31'></script>\n"
    "<link rel='stylesheet' href='https://rt.test/wp-content/plugins/gravityforms/css/a.css?ver=3.2.1' />\n")
EMOJI = '{"source":{"concatemoji":"https://rt.test/wp-includes/js/wp-emoji-release.min.js?ver=7.1.4"}}'
FILLER = '<div>' + 'x' * 70_000 + '</div>\n'   # the core version sits in the footer of a large page, past the 64 KB a marker is read from


def front(*parts):
    return page(200, body='<html><head>' + ''.join(parts) + '</head></html>')


def version_of(pages):
    return probes._wordpress_signals(pages)[1]


class ReadTests(SimpleTestCase):
    def test_the_core_version_in_the_footer_of_a_large_page_is_read_and_jquerys_is_not(self):
        pages = [('/', front(HEAD, FILLER, EMOJI))]
        self.assertEqual(version_of(pages), '7.1.4')

    def test_a_site_whose_only_versioned_assets_are_libraries_has_no_core_version(self):
        self.assertEqual(version_of([('/', front(HEAD))]), '')

    def test_the_login_page_states_the_core_version_through_its_own_styles(self):
        login = page(200, body="<link rel='stylesheet' href='/wp-admin/css/login.min.css?ver=6.4.2' />"
                               "<link rel='stylesheet' href='/wp-includes/css/buttons.min.css?ver=6.4.2' />"
                               "<script src='/wp-includes/js/jquery/jquery.min.js?ver=3.7.1'></script><form id='loginform'>")
        self.assertEqual(version_of([('/', front(HEAD)), ('/wp-login.php', login)]), '6.4.2')

    def test_the_block_library_style_carries_the_core_version(self):
        self.assertEqual(version_of([('/', front("<link href='/wp-includes/css/dist/block-library/style.min.css?ver=6.5.3'>"))]), '6.5.3')

    def test_the_feed_generator_states_the_version_when_the_pages_do_not(self):
        feed = page(200, body='<rss><channel><generator>https://wordpress.org/?v=6.5.3</generator></channel></rss>')
        self.assertEqual(version_of([('/', front(HEAD)), ('/feed/', feed)]), '6.5.3')

    def test_the_generator_tag_and_the_assets_agree_or_the_generator_wins(self):
        tag = '<meta name="generator" content="WordPress 6.2.1" />'
        self.assertEqual(version_of([('/', front(tag, "<script src='/wp-includes/js/wp-embed.min.js?ver=6.2.2'></script>"))]), '6.2.1')

    def test_a_readme_counts_only_when_it_is_wordpresss(self):
        self.assertEqual(version_of([('/', front(HEAD)), ('/readme.html', page(200, body='<h1>WordPress<br /> Version 6.1.3</h1>'))]), '6.1.3')
        self.assertEqual(version_of([('/', front(HEAD)), ('/readme.html', page(200, body='Some other product Version 2.9'))]), '')

    def test_candidates_keep_their_sources_best_first(self):
        found = cms.read('WordPress', [('/', front(EMOJI)), ('/feed/', page(200, body='<generator>https://wordpress.org/?v=7.1.4</generator>'))])
        self.assertEqual([(v, label) for v, label, _c in found], [('7.1.4', 'feed:generator'), ('7.1.4', 'asset:emoji-release')])

    def test_a_version_is_a_dotted_release_and_stops_at_the_end_of_the_number(self):
        self.assertEqual(version_of([('/', front("<script src='/wp-includes/js/wp-embed.min.js?ver=6.5.3-beta1'></script>"))]), '')
        self.assertEqual(version_of([('/', front("<script src='/wp-includes/js/wp-embed.min.js?ver=6.5'></script>"))]), '6.5')


class ProbeTests(SimpleTestCase):
    def run_probe(self, table):
        asked = []

        def get(url):
            asked.append('/' + url.split('://', 1)[1].split('/', 1)[1])
            return answers({'/wp-login.php': page(200, body='<form id="loginform">'), **table})(url)
        found = probes.run_http_probe('wordpress-detect', 'https://www.rt.test', {'www.rt.test'}, get=get, sleep=lambda s: None)
        return found, asked

    def test_the_version_in_the_footer_is_stored_as_the_hosts_wordpress_version(self):
        found, asked = self.run_probe({'/': front(HEAD, FILLER, EMOJI)})
        self.assertEqual(found[0]['version'], '7.1.4')
        self.assertEqual(probes.technology_names(found), ['WordPress:7.1.4'])
        self.assertNotIn('/feed/', asked)   # a page already stated it: nothing more is asked

    def test_the_feed_is_asked_only_when_no_page_states_the_version(self):
        feed = page(200, body='<generator>https://wordpress.org/?v=6.5.3</generator>')
        found, asked = self.run_probe({'/': front(HEAD), '/feed/': feed})
        self.assertIn('/feed/', asked)
        self.assertEqual(found[0]['version'], '6.5.3')

    def test_a_site_that_hides_every_source_is_detected_without_a_version(self):
        found, _asked = self.run_probe({'/': front(HEAD)})
        self.assertEqual((found[0]['outcome'], found[0]['version']), ('found', ''))
