"""The cards at the top of a finding use the room the pane has (source-level contract; the measured result comes from scripts/ui_glance_layout.py
against a stack: cards share the row, no value column under 180px, no word broken mid-word, no sideways scroll)."""
import re
from pathlib import Path

from django.test import SimpleTestCase

ROOT = Path(__file__).resolve().parent.parent
CSS = (ROOT / 'static' / 'cve' / 'cve.css').read_text()
GLANCE = (ROOT / 'static' / 'cve' / 'finding-glance.js').read_text()
LOGIC = (ROOT / 'static' / 'cve' / 'finding-glance-logic.js').read_text()
SCRIPT = (ROOT.parent / 'scripts' / 'ui_glance_layout.py').read_text()
WORKFLOW = (ROOT.parent / '.github' / 'workflows' / 'build-pr.yml').read_text()


def rule(selector):
	"""The declarations of the first plain rule for ``selector`` (not a media or container block)."""
	match = re.search(r'(?m)^' + re.escape(selector) + r'\{([^}]*)\}', CSS)
	assert match, selector
	return match.group(1)


class GlanceLayoutTests(SimpleTestCase):
	def test_the_card_row_wraps_instead_of_auto_fitting_around_a_spanning_card(self):
		grid = rule('.gl-grid')
		self.assertIn('display:flex', grid)
		self.assertIn('flex-wrap:wrap', grid)
		# auto-fit keeps an empty track for the full-width AI card: the two cards ended up a third short of the row
		self.assertNotIn('auto-fit', grid)
		self.assertNotIn('auto-fill', grid)
		self.assertNotIn('grid-template-columns', grid)

	def test_two_cards_share_the_row_and_the_ai_card_is_a_row_of_its_own(self):
		self.assertRegex(rule('.gl-card'), r'flex:1 1 340px')
		self.assertIn('container-type:inline-size', rule('.gl-card'))
		self.assertRegex(rule('.gl-ai'), r'flex:1 1 100%')
		self.assertNotIn('grid-column', rule('.gl-ai'))

	def test_facts_stack_in_a_narrow_card_and_get_a_label_column_in_a_wide_one(self):
		self.assertNotIn('max-content', rule('.gl-facts'))
		self.assertIn('minmax(0,1fr)', rule('.gl-facts'))
		wide = re.search(r'@container \(min-width:(\d+)px\)\{\.gl-facts\{grid-template-columns:fit-content\((\d+)em\) minmax\(0,1fr\)', CSS)
		self.assertTrue(wide)
		self.assertTrue(400 <= int(wide.group(1)) <= 440)  # a card under about 420px stacks the label over the value
		self.assertTrue(8 <= int(wide.group(2)) <= 14)  # the label column fits its longest label and no more

	def test_values_break_at_spaces_and_a_token_only_when_it_is_longer_than_the_line(self):
		for selector in ('.gl-facts dd,.sig-text', '.gl-big'):
			text = rule(selector)
			self.assertIn('overflow-wrap:break-word', text)
			self.assertIn('word-break:normal', text)
			self.assertNotIn('overflow-wrap:anywhere', text)
			self.assertNotIn('break-all', text)
		self.assertIn('white-space:nowrap', rule('.gl-unit'))  # "Tested Nov 7, 2026 12:31 AM" and "Check: name" stay whole

	def test_the_template_check_is_a_sentence_with_a_chip_and_a_readable_time(self):
		self.assertIn('templateSegments(tpl.value)', GLANCE)  # the Confidence card
		self.assertIn('x.label === "Template check" ? templateSegments(x.value)', GLANCE)  # the What was found card
		self.assertIn('fmtLong(s.iso)', GLANCE)
		self.assertIn('title: `${s.iso}', GLANCE)  # the exact value stays one hover away
		self.assertIn('el("code", "gl-code"', GLANCE)
		self.assertNotRegex(GLANCE + LOGIC, '[\u2013\u2014]')

	def test_no_other_page_relies_on_the_old_grid(self):
		for path in (ROOT / 'static' / 'cve').glob('*.js'):
			if path.name != 'finding-glance.js':
				self.assertNotIn('gl-grid', path.read_text(), path.name)
		self.assertEqual(CSS.count('.gl-grid{'), 1)

	def test_the_browser_check_and_the_node_test_are_wired(self):
		for number in ('1900', '1440', '1280', '1024', '768', '390'):
			self.assertIn(number, SCRIPT)
		for needle in ('>= 0.95 * g', '>= 180', 'broken mid-word'):
			self.assertIn(needle, SCRIPT.replace('0.95 * g[', '0.95 * g'))
		self.assertIn('node --test web/tests/*.mjs', WORKFLOW)  # every node test file runs in CI (it was a hand-kept list); test_glance_logic.mjs is one of them
		self.assertTrue((Path(__file__).parent / 'test_glance_logic.mjs').is_file())
