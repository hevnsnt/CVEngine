import os

from django.test import SimpleTestCase

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))


def read(*parts):
	with open(os.path.join(REPO, *parts), encoding='utf-8') as handle:
		return handle.read()


class FindingGlanceTests(SimpleTestCase):
	def test_a_finding_opens_on_three_cards_and_folds_the_rest(self):
		"""What was found, how sure, and what the AI said come first; the CVE record, history, validation job and checks fold away."""
		app = read('web', 'static', 'cve', 'app.js')
		self.assertIn('import { fold, glance } from "/staticfiles/cve/finding-glance.js";', app)
		body = app[app.index('function renderFinding('):app.index('// One page of findings')]
		self.assertLess(body.index('...glance(d,'), body.index('checkFold, advisoryFold'))
		for title in ('Confirm it yourself', 'Seen and history', 'AI details'):
			self.assertIn(f'fold("{title}"', body)
		self.assertIn('"What to do"', body)

	def test_the_validate_button_is_still_found_by_the_needs_validation_link(self):
		app = read('web', 'static', 'cve', 'app.js')
		self.assertIn('run.dataset.validate = "now"', app)
		self.assertIn('fix.append(controls)', app)

	def test_each_card_says_what_it_is(self):
		page = read('web', 'static', 'cve', 'finding-glance.js')
		for title in ('What was found', 'Confidence', 'AI assessment'):
			self.assertIn(f'"{title}"', page)
		# a signal that is not known says so instead of being left out
		self.assertIn('"no check has run"', page)
		self.assertNotRegex(page, '[–—]')

	def test_the_styles_exist(self):
		css = read('web', 'static', 'cve', 'cve.css')
		for selector in ('.gl-grid', '.gl-card', '.meter', '.sig-for', '.fold>summary', '.fold-body'):
			self.assertIn(selector, css)
