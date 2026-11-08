"""The one status strip (static/cve/statusstrip.js): the scanner notices and the admin alerts in a single 40px line with a count and a Details button.
Source-level checks; the behaviour (open, count, dismiss for the session) is exercised in a browser by ux/strip_check.py."""
from pathlib import Path

from django.test import SimpleTestCase

STATIC = Path(__file__).resolve().parent.parent / 'static' / 'cve'
STRIP = (STATIC / 'statusstrip.js').read_text()
SCANNER = (STATIC / 'scannerbar.js').read_text()
ALERTS = (STATIC / 'alertbar.js').read_text()
CSS = (STATIC / 'cve.css').read_text()


class StatusStripTests(SimpleTestCase):
    def test_both_scripts_report_to_the_one_strip_and_none_draws_its_own_bar(self):
        self.assertIn('import { setNotices } from "/staticfiles/cve/statusstrip.js"', SCANNER)
        self.assertIn('import { setNotices } from "/staticfiles/cve/statusstrip.js"', ALERTS)
        self.assertNotIn('"scannerbar"', SCANNER)
        self.assertNotIn('"alertbar"', ALERTS)
        self.assertNotIn('.alertbar', CSS)
        self.assertEqual(STRIP.count('"scannerbar"'), 1)

    def test_the_scanner_sentences_are_passed_through_unchanged(self):
        for field in ('s.message', 's.disabled_message', 's.never_seen_message'):
            self.assertIn('text: %s' % field, SCANNER)
        for word in ('Scanner offline', 'No scanner has ever registered', 'Nothing has failed'):
            self.assertNotIn(word, SCANNER + STRIP)  # the wording lives on the server only (agentapi/scanner_state.messages)

    def test_the_strip_is_forty_pixels_with_a_count_and_a_details_button(self):
        self.assertIn('.sb-strip{display:flex;align-items:center;gap:var(--s-3);height:40px', CSS)
        self.assertIn('`${items.length} notices`', STRIP)
        self.assertIn('"Details"', STRIP)
        self.assertIn('"aria-expanded"', STRIP)
        self.assertIn('details.hidden = !open', STRIP)

    def test_the_never_registered_note_can_be_dismissed_for_the_session_only(self):
        self.assertIn('dismissible: true', SCANNER)
        self.assertIn('window.sessionStorage', STRIP)
        self.assertNotIn('localStorage', STRIP)

    def test_server_text_is_set_with_textContent_only(self):
        for src in (STRIP, SCANNER, ALERTS):
            for banned in ('innerHTML', 'insertAdjacentHTML', 'outerHTML'):
                self.assertNotIn(banned, src)


class CoolingMessageInTheStripTests(SimpleTestCase):
    """#512's 'Paused after repeated failures ... retries at HH:MM UTC' message must reach the one strip with the zone swap it had in the old bar."""

    def test_the_paused_after_repeated_failures_sentence_is_a_strip_notice_with_its_retry_time_in_the_page_zone(self):
        self.assertIn('text: coolingText(s)', SCANNER)
        self.assertIn('kind: "cooling"', SCANNER)
        self.assertIn('s.cooling_message', SCANNER)
        self.assertIn('fmtTime', SCANNER)
        self.assertIn('zoneLabel()', SCANNER)
        self.assertIn('/ at \\d\\d:\\d\\d UTC/', SCANNER)
        self.assertNotIn('Paused after repeated failures', SCANNER + STRIP)  # the wording lives on the server only

    def test_a_cooling_notice_is_not_dismissible_and_has_its_own_style(self):
        line = [l for l in SCANNER.splitlines() if 'kind: "cooling"' in l][0]
        self.assertNotIn('dismissible', line)
        self.assertIn('.scannerbar .sb-cooling{', CSS)
