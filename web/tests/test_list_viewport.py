"""Split lists (Findings, CVE matches, Hosts): the rows own the column, the filters open over them, and "Load more" says what it is doing.

Source-level checks; the measured result (rows fully visible at five screen sizes, the live message, the busy state) comes from
scripts/ui_list_viewport.py against a stack with 200+ rows."""
import re
from pathlib import Path

from django.test import SimpleTestCase

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / 'static' / 'cve'
CSS = (STATIC / 'cve.css').read_text()
APP = (STATIC / 'app.js').read_text()
SCRIPT = (ROOT.parent / 'scripts' / 'ui_list_viewport.py').read_text()


class ListViewportTests(SimpleTestCase):
	def test_findings_matches_and_hosts_share_one_head(self):
		self.assertEqual(len(re.findall(r'function listHead\(', APP)), 1)
		self.assertEqual(len(re.findall(r'= listHead\(\{', APP)), 2)  # findingPage (Findings, CVE matches) and Hosts
		self.assertIn('side.append(lh.head, ...(bulk ? [bulk.note, bulk.bar] : []), rows);', APP)
		self.assertIn('side.append(lh.head, bulk.bar, rows, gallery);', APP)

	def test_the_filters_panel_is_closed_by_default_and_keeps_every_control(self):
		head = APP[APP.index('function listHead('):APP.index('function revealPane(')]
		self.assertIn('pop.hidden = true;', head)
		self.assertIn('"aria-expanded": "false", "aria-controls": id', head)
		self.assertIn("e.key !== \"Escape\"", head)
		self.assertIn('localStorage.setItem(key', head)
		self.assertIn('cvengine.filters.', head)
		# the findings page puts every filter node it was given into the head: the search line or the panel, none dropped
		self.assertIn('lead: cfg.filters.filter(isSearch), panelNodes: cfg.filters.filter((n) => !isSearch(n))', APP)
		# hosts: views, saved searches, heat chips and scope chips are in the panel, the sort too
		self.assertIn('lead: [q], panelNodes: [sortBy, views.node, ...(searches ? [searches.node] : []), heatChips, scopeChips]', APP)

	def test_the_rows_are_not_a_scroll_box_inside_the_column(self):
		self.assertIn('.split>.split-list>.host-rows{max-height:none;overflow:visible;flex:none}', CSS)
		self.assertRegex(CSS, r'\.split>\.split-list\{overflow-y:auto;[^}]*height:var\(--fit,calc\(100dvh - var\(--bar\) - var\(--s-2\)\)\)\}')
		self.assertIn('.split>.split-list>.list-head{position:sticky;', CSS)
		self.assertIn('.list-head .filters-pop{position:absolute;', CSS)  # over the rows, not pushing them

	def test_load_more_is_busy_then_counted_then_done(self):
		self.assertIn('"aria-busy", "true"', APP)
		self.assertIn('moreBtn.disabled = true', APP)
		self.assertIn('role: "status", "aria-live": "polite", "aria-atomic": "true"', APP)
		self.assertIn('LM.loadedMessage(added,', APP)
		self.assertIn('el("p", "note more-done", view.label', APP)

	def test_a_row_the_reader_picks_opens_its_detail_at_the_top(self):
		self.assertIn('function revealPane(pane)', APP)
		self.assertEqual(APP.count('revealPane(pane);'), 2)  # the findings row click and the host row click, not the first-row auto select

	def test_the_browser_check_exists_and_asserts_the_numbers(self):
		self.assertIn('1366', SCRIPT)
		self.assertIn('need = 6', SCRIPT)
		self.assertIn('All ', SCRIPT)

	def test_the_page_title_moves_beside_the_list_so_the_list_starts_under_the_top_bar(self):
		self.assertIn('.wrap:has(#view>.split:not(.gallery)){display:grid;', CSS)
		self.assertIn('.split>.split-list{grid-column:1;grid-row:1/span 6}', CSS.replace('.wrap:has(#view>.split:not(.gallery)) ', ''))
		self.assertIn('side.style.setProperty("--fit"', APP)  # the column ends at the screen's bottom wherever the page is scrolled
