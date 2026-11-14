"""The watchdog lives under Administration, Watchdog (App Admin), not on the Scanners page."""
from pathlib import Path

from django.test import SimpleTestCase

WEB = Path(__file__).resolve().parent.parent
STATIC = WEB / 'static' / 'cve'
TEMPLATES = WEB / 'cveFeed' / 'templates' / 'cveFeed'


class WatchdogPlacementTests(SimpleTestCase):
    def test_the_scanners_page_no_longer_carries_the_watchdog_panel(self):
        html = (TEMPLATES / 'scanners.html').read_text()
        self.assertNotIn('id="watchdog"', html)
        self.assertNotIn('/cve/api/admin/watchdog', (STATIC / 'scanners.js').read_text())
        self.assertNotIn('loadWatchdog', (STATIC / 'scanners.js').read_text())

    def test_the_scanners_page_links_to_the_watchdog_tab_for_an_app_admin_only(self):
        html = (TEMPLATES / 'scanners.html').read_text()
        line = [l for l in html.splitlines() if "#watchdog" in l]
        self.assertEqual(len(line), 1, 'one link to the Administration watchdog tab')
        self.assertIn('is_app_admin', line[0])

    def test_administration_has_a_watchdog_tab_for_an_app_admin(self):
        js = (STATIC / 'admin.js').read_text()
        self.assertIn('import { watchdogPanel } from "/staticfiles/cve/watchdog-panel.js";', js)
        self.assertRegex(js, r'if \(me\.is_superuser\) defs\.watchdog = \{ label: "Watchdog", open: watchdogPanel \};')

    def test_the_panel_polls_only_while_its_tab_is_on_the_page_and_draws_through_the_keep_open_helper(self):
        js = (STATIC / 'watchdog-panel.js').read_text()
        self.assertIn('root.isConnected', js)
        self.assertIn('renderKeepingState(wdRoot', js)
        self.assertIn('/cve/api/admin/watchdog', js)
