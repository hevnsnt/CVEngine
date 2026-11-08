"""Touch and phone first screen (S4): 44px hit areas under pointer:coarse, and the filters behind one button on a phone.
Source-level checks; the measured result (no control under 44px on a 390px screen, rows visible on the first screen) comes from ux/capslice.py."""
import re
from pathlib import Path

from django.test import SimpleTestCase

STATIC = Path(__file__).resolve().parent.parent / 'static' / 'cve'
CSS = (STATIC / 'cve.css').read_text()
APP = (STATIC / 'app.js').read_text()


def coarse_block():
    i = CSS.index('@media (pointer:coarse){\n  :root{--hit:44px}')
    return CSS[i:CSS.index('\n}\n', i)]


class TouchTests(SimpleTestCase):
    def test_the_hit_size_is_44px_and_covers_buttons_tabs_fields_and_row_menus(self):
        block = coarse_block()
        self.assertIn('--hit:44px', block)
        for sel in ('.btn.sm', '.picker button', '[role=tab]', '.row-menu-btn', 'select', 'summary', '.set-nav button[data-tab]'):
            self.assertIn(sel, block)
        self.assertRegex(block, r'\.btn,\.btn\.sm[^{]*\{min-height:var\(--hit\)!important')

    def test_checkboxes_and_radios_answer_a_44px_square_but_are_drawn_20px(self):
        block = coarse_block()
        self.assertIn('input[type=checkbox],input[type=radio]{-webkit-appearance:none;appearance:none', block)
        self.assertRegex(block, r'width:var\(--hit\)!important;height:var\(--hit\)!important;[^}]*margin:-13px!important')
        self.assertIn('inset:12px;border:2px solid var(--muted)', block)  # 44 - 2*12 = 20px drawn box

    def test_inline_links_get_a_hit_area_without_a_layout_change(self):
        block = coarse_block()
        self.assertIn('a.host-link::after', block)
        self.assertRegex(block, r'::after\{content:"";position:absolute;left:-8px;right:-8px;top:50%;height:var\(--hit\)')

    def test_a_link_that_fills_its_own_line_is_a_44px_line(self):
        block = coarse_block()
        self.assertIn('li>a.cve-id,li .meta>a.hit,.table td a:not(.btn){display:inline-flex;align-items:center;min-height:var(--hit);min-width:var(--hit)}', block)

    def test_filters_are_one_button_at_every_width_and_the_list_comes_right_after(self):
        # (was: one button on a phone only; the head of the split lists, PR "list viewport", does it at every width: static/cve/app.js listHead)
        head = APP[APP.index('function listHead('):APP.index('function revealPane(')]
        self.assertEqual(len(re.findall(r'function listHead\(', APP)), 1)
        self.assertIn('"aria-expanded": "false", "aria-controls": id', head)
        self.assertIn('pop.hidden = true;', head)
        self.assertIn('side.append(lh.head, bulk.bar, rows, gallery);', APP)
        self.assertIn('side.append(lh.head, ...(bulk ? [bulk.note, bulk.bar] : []), rows);', APP)
        self.assertIn('.list-head .filters-pop{position:absolute;', CSS)

    def test_the_head_controls_are_44px_under_a_coarse_pointer(self):
        self.assertRegex(CSS, r'@media \(pointer:coarse\)\{\.list-head \.chip-x,\.list-head \.filters-btn,\.list-head \.list-bar>input\{min-height:var\(--hit\)')
