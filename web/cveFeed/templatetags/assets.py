"""Content-versioned asset URLs. A CDN or browser that cached last release's cve.css must never serve it with this
release's HTML, so every script and stylesheet URL carries a hash of the file, and an import map does the same for the
ES modules that import each other (a plain import has no query string to change)."""
import hashlib
import json
import os

from django import template
from django.conf import settings
from django.templatetags.static import static
from django.utils.html import format_html
from django.utils.safestring import mark_safe

register = template.Library()
_hashes = {}


def _path(name):
    for root in settings.STATICFILES_DIRS:
        candidate = os.path.join(root, name)
        if os.path.isfile(candidate):
            return candidate
    return None


def version(name):
    """Short content hash of a static file; cached for the life of the process (files only change on a new release)."""
    if name not in _hashes:
        path = _path(name)
        _hashes[name] = hashlib.md5(open(path, 'rb').read()).hexdigest()[:10] if path else ''
    return _hashes[name]


@register.simple_tag
def asset(name):
    v = version(name)
    return f'{static(name)}?v={v}' if v else static(name)


@register.simple_tag
def build_stamp():
    """The build that renders this page, for static/cve/sitewatch.js to compare with the one /cve/api/alive reports (empty when unknown)."""
    from cveFeed import updater
    return format_html('<meta name="cvengine-build" content="{}">', updater.build_id())


@register.simple_tag
def importmap():
    """Map each module under static/cve to its versioned URL, so ``import ... from "/staticfiles/cve/ui.js"`` follows it."""
    root = next((r for r in settings.STATICFILES_DIRS if os.path.isdir(os.path.join(r, 'cve'))), None)
    if not root:
        return ''
    names = sorted(f for f in os.listdir(os.path.join(root, 'cve')) if f.endswith('.js') and not f.endswith('.min.js'))
    imports = {static(f'cve/{n}'): asset(f'cve/{n}') for n in names}
    body = json.dumps({'imports': imports}).replace('</', '<\\/')
    return mark_safe(f'<script type="importmap">{body}</script>')


# The first rules a page needs, inlined in <head> BEFORE the stylesheet link, so a stylesheet that arrives late (a slow or lossy link, a CDN
# revalidation) can never leave the page showing an unsized glyph or a layout that jumps when it lands. Rules of equal specificity in cve.css
# come later and win, so this is only a floor. It holds layout-neutral rules and no design decision of its own: every colour is the SAME custom
# property cve.css defines, with that property's value as the fallback (web/tests/test_critical_style.py fails if a fallback drifts from cve.css),
# and the sizes mirror cve.css (--rail 260px from 1024px, --tab 60px, the 20px icon).
CRITICAL_CSS = (
    'body{margin:0;background:var(--bg,#f4f4f5);color:var(--ink,#0a0a0b);font-family:var(--font,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif);'
    'padding-bottom:calc(var(--tab,60px) + env(safe-area-inset-bottom,0px))}'
    'html[data-theme="dark"] body{background:var(--bg,#0e0f11);color:var(--ink,#f2f2f4)}'
    '.skip{position:absolute;left:-999px;top:8px}.skip:focus{left:8px}'
    'svg{flex:none}:where(svg[viewBox="0 0 24 24"]){fill:none;stroke:currentColor;stroke-width:1.75;stroke-linecap:round;stroke-linejoin:round}'
    '.rail{display:none}'
    '.tabbar{position:fixed;left:0;right:0;bottom:0;display:flex;height:var(--tab,60px)}.tabbar>*{flex:1}'
    '@media (min-width:1024px){body{padding-bottom:0}'
    '.app{display:grid;grid-template-columns:var(--rail,260px) minmax(0,1fr)}'
    '.rail{display:flex;flex-direction:column;position:sticky;top:0;height:100dvh;overflow:auto}.tabbar{display:none}}'
    '.stage{min-width:0}'
)


@register.simple_tag
def critical_style():
    """The inline <style> block; the text is a constant with no user input, so it is safe to mark."""
    return mark_safe(f'<style>{CRITICAL_CSS}</style>')
