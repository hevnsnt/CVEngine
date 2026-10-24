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
def importmap():
    """Map each module under static/cve to its versioned URL, so ``import ... from "/staticfiles/cve/ui.js"`` follows it."""
    root = next((r for r in settings.STATICFILES_DIRS if os.path.isdir(os.path.join(r, 'cve'))), None)
    if not root:
        return ''
    names = sorted(f for f in os.listdir(os.path.join(root, 'cve')) if f.endswith('.js') and not f.endswith('.min.js'))
    imports = {static(f'cve/{n}'): asset(f'cve/{n}') for n in names}
    body = json.dumps({'imports': imports}).replace('</', '<\\/')
    return mark_safe(f'<script type="importmap">{body}</script>')
