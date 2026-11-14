#!/usr/bin/env python3
"""WCAG contrast of every text/background and UI-mark token pair in both themes (web/static/cve/cve.css).

    python3 scripts/ui_contrast.py            # table, exit 1 if any pair is under its minimum
    python3 scripts/ui_contrast.py --json

Text pairs need 4.5:1 (WCAG 1.4.3, AA); UI marks (dots, edges, fills that carry no text) need 3:1 (1.4.11).
The tokens are read from the :root and :root[data-theme="dark"] blocks, so a colour change that breaks a pair fails here
(and in web/tests/test_ui_contrast.py, which runs this on every build).

Exempt, on purpose: the cvENGINE wordmark (a logotype, WCAG 1.4.3 "incidental or logotype"), disabled controls, and
hairlines (--line, --line-2) that only separate things and identify no control by themselves.
"""
import json
import re
import sys
from pathlib import Path

CSS = Path(__file__).resolve().parent.parent / 'web' / 'static' / 'cve' / 'cve.css'

SURFACES = ['bg', 'surface', 'surface-2', 'sunk']
# (foreground, [backgrounds], minimum, what it is)
PAIRS = []
for fg in ('ink', 'ink-2', 'muted'):
    PAIRS.append((fg, SURFACES, 4.5, 'body and label text'))
PAIRS += [
    ('on-ink', ['ink'], 4.5, 'text on the ink fill: selected rows, primary buttons, active tab'),
    ('on-ink-2', ['ink'], 4.5, "secondary text on the ink fill (a selected row's sub line)"),
    ('on-brand', ['brand'], 4.5, 'text on the orange fill (update bar, active tab avatar)'),
    ('on-solid', ['fire'], 4.5, 'text on a solid Fire fill (badge, danger button, score)'),
    ('on-smoke', ['smoke'], 4.5, 'text on a solid Smoke fill (score, tag)'),
    ('on-ice', ['ice'], 4.5, 'text on a solid Ice fill (score, tag)'),
    ('on-ok', ['ok'], 4.5, 'text on a solid ok fill'),
    ('brand-ink', SURFACES, 4.5, 'orange used as text (links, counts) on a surface'),
    ('fire-ink', ['fire-bg'] + SURFACES, 4.5, 'Fire text'),
    ('smoke-ink', ['smoke-bg'] + SURFACES, 4.5, 'Smoke text'),
    ('ice-ink', ['ice-bg'] + SURFACES, 4.5, 'Ice text'),
    ('ok-ink', ['ok-bg'] + SURFACES, 4.5, 'ok text'),
    # marks: dots, edges, bars, rings that carry no text
    ('fire', ['surface', 'bg'], 3.0, 'Fire mark'),
    ('high', ['surface', 'bg'], 3.0, 'High mark'),
    ('smoke', ['surface', 'bg'], 3.0, 'Smoke mark'),
    ('ice', ['surface', 'bg'], 3.0, 'Ice mark'),
    ('ok', ['surface', 'bg'], 3.0, 'ok mark'),
    ('brand', ['surface'], 3.0, 'orange signal lamp (dot, 2px active edge) on a surface'),
    ('ink', ['bg', 'surface'], 3.0, 'focus ring'),
]


def blocks(css):
    light = re.search(r':root\{(.*?)\n\}', css, re.S).group(1)
    dark = re.search(r':root\[data-theme="dark"\]\{(.*?)\n\}', css, re.S).group(1)
    return light, dark


def tokens(body):
    return {m.group(1): m.group(2).strip() for m in re.finditer(r'--([\w-]+):\s*([^;]+);', body)}


def resolve(name, toks):
    v = toks[name]
    m = re.fullmatch(r'var\(--([\w-]+)\)', v)
    return resolve(m.group(1), toks) if m else v


def rgb(v):
    v = v.strip().lower()
    if re.fullmatch(r'#[0-9a-f]{3}', v):
        v = '#' + ''.join(c * 2 for c in v[1:])
    if re.fullmatch(r'#[0-9a-f]{6}', v):
        return tuple(int(v[i:i + 2], 16) for i in (1, 3, 5))
    raise ValueError('not an opaque hex colour: %r' % v)


def lum(c):
    def f(x):
        x /= 255
        return x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4
    r, g, b = (f(x) for x in c)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def ratio(a, b):
    la, lb = lum(a), lum(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def run():
    css = CSS.read_text()
    light, dark = blocks(css)
    themes = {'light': tokens(light)}
    themes['dark'] = {**themes['light'], **tokens(dark)}
    rows = []
    for theme, toks in themes.items():
        for fg, bgs, minimum, what in PAIRS:
            for bg in bgs:
                try:
                    r = ratio(rgb(resolve(fg, toks)), rgb(resolve(bg, toks)))
                except KeyError as e:
                    rows.append({'theme': theme, 'fg': fg, 'bg': bg, 'ratio': None, 'min': minimum, 'ok': False, 'what': 'missing token %s' % e})
                    continue
                rows.append({'theme': theme, 'fg': fg, 'bg': bg, 'ratio': round(r, 2), 'min': minimum, 'ok': r >= minimum, 'what': what})
    return rows


if __name__ == '__main__':
    rows = run()
    bad = [r for r in rows if not r['ok']]
    if '--json' in sys.argv:
        print(json.dumps(rows, indent=1))
    else:
        for r in rows:
            print('%-5s %-10s on %-10s %5s  (min %.1f)  %s%s' % (r['theme'], r['fg'], r['bg'], r['ratio'], r['min'], 'ok  ' if r['ok'] else 'FAIL', r['what']))
        print('%d pairs, %d under their minimum' % (len(rows), len(bad)))
    sys.exit(1 if bad else 0)
