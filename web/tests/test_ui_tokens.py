"""The UI's design tokens and the contrast of every text/background pair (scripts/ui_contrast.py), both themes.

Source-level: reads cve.css as text. The rules are not rewritten here, they are held to the scale: a new rule that brings back a 10.5px
size, a 650 weight, tracked small text, upper-case labels or a second easing curve fails this test."""
import importlib.util
import re
from pathlib import Path

from django.test import SimpleTestCase

ROOT = Path(__file__).resolve().parent.parent.parent
CSS = (ROOT / 'web' / 'static' / 'cve' / 'cve.css').read_text()
HEAD_END = CSS.index('\n}\n', CSS.index(':root[data-theme="dark"]{')) + 3
BODY = CSS[HEAD_END:]
# the SVG graph (its own slice), the wordmark (a logotype), the one display figure and the About page (its own PR) are outside the type scale
OUTSIDE = ('.gn', '.logo', '.big b', '@font-face', '.about')


def rules():
    for m in re.finditer(r'([^{}]+)\{([^{}]*)\}', BODY):
        sel = m.group(1).strip().split('}')[-1].strip()
        if re.fullmatch(r'(from|to|[\d.]+%)(\s*,\s*(from|to|[\d.]+%))*', sel):
            continue
        yield sel, m.group(2)


def scale_rules():
    return [(s, d) for s, d in rules() if not any(o in s for o in OUTSIDE)]


class ContrastTests(SimpleTestCase):
    def test_every_text_and_mark_pair_meets_wcag_in_both_themes(self):
        spec = importlib.util.spec_from_file_location('ui_contrast', ROOT / 'scripts' / 'ui_contrast.py')
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        rows = mod.run()
        self.assertGreater(len(rows), 100)
        bad = ['%(theme)s %(fg)s on %(bg)s: %(ratio)s < %(min)s' % r for r in rows if not r['ok']]
        self.assertEqual(bad, [])
        self.assertEqual({r['theme'] for r in rows}, {'light', 'dark'})


class TokenTests(SimpleTestCase):
    def test_the_scale_tokens_exist_and_the_faint_grey_is_merged_into_muted(self):
        for token in ('--fs-1:12px', '--fs-8:32px', '--fw-regular:400', '--fw-medium:500', '--fw-semi:600', '--s-1:4px', '--s-12:48px',
                      '--r-s:4px', '--r:8px', '--r-l:12px', '--ease:cubic-bezier(.22,1,.36,1)', '--brand-ink:#b83b00', '--on-brand:#0a0a0b'):
            self.assertIn(token, CSS)
        self.assertEqual(CSS.count('--brand-ink:'), 2)  # light and dark
        self.assertNotIn('--faint', CSS)

    def test_text_sizes_and_weights_come_from_the_scale(self):
        for sel, decl in scale_rules():
            self.assertNotRegex(decl, r'font-size:\s*[\d.]+px', sel)
            self.assertNotRegex(decl, r'font:\s*(?:(?:italic|normal)\s+)?(?:\d{3}\s|[\d.]+px)', sel)  # a literal weight or size right after font:
            for w in re.findall(r'font-weight:\s*([^;!]+)', decl):
                self.assertTrue(w.strip().startswith('var(--fw-'), (sel, w))

    def test_small_text_has_no_tracking_and_only_the_brand_line_is_upper_case(self):
        for sel, decl in scale_rules():
            if '.brand small' in sel:
                continue
            self.assertNotIn('text-transform:uppercase', decl, sel)
            for v in re.findall(r'letter-spacing:\s*([^;!}]+)', decl):
                v = v.strip()
                if v in ('0', 'normal'):
                    continue
                size = re.search(r'font(?:-size)?:[^;]*var\(--fs-(\d)\)', decl)
                self.assertTrue(size and int(size.group(1)) >= 4, '%s tracks small text: %s' % (sel, v))  # 16px and up only

    def test_one_easing_curve(self):
        for sel, decl in scale_rules():
            for d in re.findall(r'(?<![\w-])(?:transition|animation)\s*:[^;}]*', decl):
                self.assertNotRegex(d, r'(?<![\w-])(ease|ease-in|ease-out|ease-in-out)(?![\w-])', sel)
                self.assertNotIn('cubic-bezier', d, sel)

    def test_radii_are_the_three_steps(self):
        for sel, decl in scale_rules():
            for v in re.findall(r'border-radius:\s*([^;!}]+)', decl):
                for part in v.split():
                    self.assertTrue(part in ('0', '50%', '999px') or part.startswith('var(--r'), '%s: %s' % (sel, v))
