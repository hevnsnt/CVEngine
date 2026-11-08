"""Accessible names the interface must keep (found with axe-core on a seeded instance; see the UI audit). Source-level checks: no browser needed."""
import re
from pathlib import Path

from django.test import SimpleTestCase

WEB = Path(__file__).resolve().parent.parent
STATIC = WEB / 'static' / 'cve'
BASE = (WEB / 'cveFeed' / 'templates' / 'cveFeed' / 'base.html').read_text()


class AccessibleNameTests(SimpleTestCase):
    def test_the_icon_only_add_targets_button_has_a_name(self):
        self.assertRegex(BASE, r'<button class="btn sm add-btn"[^>]*data-add-targets[^>]*aria-label="Add targets"')

    def test_the_rail_brand_label_contains_what_is_printed_on_it(self):
        # a label that does not contain the visible words fails "label in name" for voice-control users
        self.assertIn('aria-label="cvENGINE FieldCraft Cyber, home"', BASE)
        self.assertIn('NE</span> <small>FieldCraft Cyber</small>', BASE)  # the space makes the printed text "cvENGINE FieldCraft Cyber"
        self.assertNotIn('CVEngine, by FieldCraft Cyber', BASE)

    def test_the_account_menu_label_contains_the_visible_name(self):
        self.assertIn('aria-label="{{ request.user.first_name|default:request.user.username }}, account menu"', BASE)

    def test_selectOf_can_name_the_select_and_the_filters_that_had_no_name_do(self):
        ui = (STATIC / 'ui.js').read_text()
        self.assertIn("export function selectOf(options, value, label)", ui)
        self.assertIn("s.setAttribute('aria-label', label)", ui)
        bounty = (STATIC / 'bounty.js').read_text()
        for var, name in (('plat', 'Platform'), ('pays', 'Reward'), ('harbor', 'Safe harbor'), ('fresh', 'Program age'), ('moved', 'Scope change'), ('sort', 'Sort by')):
            self.assertRegex(bounty, r'const %s = selectOf\(.*, "%s"\);' % (var, name))
        secrets = (STATIC / 'secrets.js').read_text()
        self.assertRegex(secrets, r'const status = selectOf\(.*"Show secrets that are"\);')
        self.assertRegex(secrets, r'const klass = selectOf\(.*"Class"\);')

    def test_the_settings_number_box_next_to_Write_now_has_a_name(self):
        settings = (STATIC / 'settings.js').read_text()
        self.assertRegex(settings, r'const guideNow = text\("200", \{[^}]*"aria-label": "[^"]+"')

    def test_the_settings_nav_is_not_a_tablist_it_does_not_satisfy(self):
        settings = (STATIC / 'settings.js').read_text()
        nav = settings[settings.index('const tabs = el("nav", "set-nav"'):settings.index('const panel = el("div", "set-panel")')]
        self.assertNotIn('tablist', nav)
        self.assertNotIn('role: "tab"', settings[settings.index('const tabButton'):settings.index('tabs.append(advGroup)')])
        css = (STATIC / 'cve.css').read_text()
        self.assertIn('.set-nav button[data-tab][aria-current="true"]', css)

    def test_a_project_sentinel_with_a_long_name_wraps_instead_of_widening_the_page(self):
        css = (STATIC / 'cve.css').read_text()
        self.assertRegex(css, r'#section:not\(\[data-kind\]\) \.feed li\{grid-template-columns:minmax\(0,1fr\)\}')
        self.assertIn('.grid>*{min-width:0}', css)
