"""Every wait in the first run says what is happening, how long it usually takes and what comes next, and a wait that ends with nothing found
lands on a dashboard that explains itself and offers the next step (review B-ui W1, D4).

The copy gate for the build screen (harness-1.4 gate 6) still holds: no "scanning", no "discovery running", no dashes. The words are checked
here too, on every string the screen can show.
"""
import os
import re

from django.test import SimpleTestCase

BASE = os.path.join(os.path.dirname(__file__), '..')


def read(*parts):
	with open(os.path.join(BASE, *parts), encoding='utf-8') as f:
		return f.read()


def build_source():
	js = read('static', 'cve', 'welcome.js')
	return js[js.index('  build(node) {'):js.index("document.getElementById('skip-all')")]


def strings(source):
	source = re.sub(r'(?m)\s//.*$', '', source)
	return [m[0] or m[1] or m[2] for m in re.findall(r"'((?:[^'\\\n]|\\.)*)'|\"((?:[^\"\\\n]|\\.)*)\"|`((?:[^`\\]|\\.)*)`", source)]


class BuildScreenTests(SimpleTestCase):
	def test_the_build_screen_names_the_domain_the_time_and_what_comes_next(self):
		build = build_source()
		self.assertIn('Looking up', build)
		self.assertIn('usually takes about', build)
		self.assertIn('as they are found', build)
		self.assertIn('opens by itself', build)
		self.assertNotIn("'This takes about a minute.'", build)

	def test_the_build_screen_keeps_the_gate_6_words_out(self):
		for s in strings(build_source()):
			self.assertNotRegex(s, r'(?i)scanning|discovery running|[–—]', s)
			self.assertNotRegex(s, r'(?i)scan|discover|sentinel|subdomain|running', s)

	def test_the_end_of_the_wait_hands_the_dashboard_a_note_when_no_host_exists(self):
		js = read('static', 'cve', 'welcome.js')
		self.assertIn('first=1', js)
		build = build_source()
		self.assertIn('hosts_present', build)  # only when the server says no host exists
		self.assertIn('Hosts will keep appearing', build)

	def test_the_first_step_says_that_continue_starts_a_first_look(self):
		js = read('static', 'cve', 'welcome.js')
		seed = js[js.index('  seed(node) {'):js.index('  plan(node) {')]
		self.assertIn('Continue starts a first look at this domain', seed)
		self.assertIn('keep answering', seed)


class EmptyDashboardTests(SimpleTestCase):
	def test_the_dashboard_has_an_arrival_note_with_a_next_step(self):
		html = read('cveFeed', 'templates', 'cveFeed', 'dashboard.html')
		self.assertIn('id="first-note"', html)
		self.assertIn('data-first="{{ request.GET.first }}"', html)
		note = html[html.index('id="first-note"'):]
		note = note[:note.index('</div>')]
		self.assertIn('data-add-targets', note)
		self.assertRegex(note, r'usually')

	def test_the_dashboard_script_shows_the_note_only_while_no_host_exists(self):
		js = read('static', 'cve', 'dashboard.js')
		self.assertIn('first-note', js)
		self.assertRegex(js, r'first-note[\s\S]{0,400}hosts')

	def test_the_idle_discovery_line_names_the_next_step(self):
		js = read('static', 'cve', 'dashboard.js')
		self.assertIn('No discovery has run yet. Add a target to start one.', js)
		self.assertNotIn('"No discovery has run yet."', js)
