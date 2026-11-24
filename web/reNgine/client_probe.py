"""The client address check (scripts/client-address-check.sh, run by every update): which address does the server take for a request that came in
through the install's public name? The check asks the server for a one-time token (manage.py client_address_probe start), requests
``/client-address-probe/<token>/`` through the public URL, and reads back what reNgine.client_ip resolved for it (``read``). Compared with the
address Cloudflare saw (``/cdn-cgi/trace``), that says whether the real client address arrives, or every visitor is the proxy (review r3 S2).

The route is open (no sign-in), answers 204 whatever happens, and stores an address only for a token the server itself issued and has not
answered yet, for TOKEN_TTL seconds: a stranger can neither learn anything from it nor fill the cache with it.

With the address it keeps the label the bundled proxy puts on the probe request (``X-CVEngine-Probe-Forwarded``, config/nginx/rengine.conf):
what the proxy did with the forwarding headers that came with it (``FORWARDED_LABELS``). The label says whether a host proxy in front sends the
address in a header the bundled proxy does not believe yet (cveFeed.client_address turns that into the notice). It is a diagnostic only: the
address the server records never depends on it.
"""
import re
import secrets

from django.core.cache import cache
from django.http import HttpResponse, HttpResponseNotAllowed

TOKEN = re.compile(r'^[0-9a-f]{32}$')
TOKEN_TTL = 300
PENDING = '-pending-'
FORWARDED_LABELS = ('believed', 'ignored', 'wrong-secret', 'tunnel', 'none')


def _key(token):
    return f'client_address_probe:{token}'


def _label_key(token):
    return f'client_address_probe:{token}:forwarded'


def start():
    """A new token, waiting for its probe."""
    token = secrets.token_hex(16)
    cache.set(_key(token), PENDING, TOKEN_TTL)
    return token


def read(token):
    """The address recorded for ``token``: '' while none was, None for an unknown or expired token."""
    if not TOKEN.match(token or ''):
        return None
    value = cache.get(_key(token))
    if value is None:
        return None
    return '' if value == PENDING else value


def read_forwarded(token):
    """The proxy's label for the probe of ``token`` (one of FORWARDED_LABELS), or '' when none came: no probe yet, or a request that did not
    pass the bundled proxy (its own reverse proxy straight to web, or a proxy older than the label)."""
    if not TOKEN.match(token or ''):
        return ''
    value = cache.get(_label_key(token)) or ''
    return value if value in FORWARDED_LABELS else ''


def probe(request, token):
    if request.method != 'GET':
        return HttpResponseNotAllowed(['GET'])
    if TOKEN.match(token) and cache.get(_key(token)) == PENDING:
        from reNgine.client_ip import client_ip
        cache.set(_key(token), client_ip(request) or 'unknown', TOKEN_TTL)
        label = request.META.get('HTTP_X_CVENGINE_PROBE_FORWARDED', '').strip().lower()
        if label in FORWARDED_LABELS:
            cache.set(_label_key(token), label, TOKEN_TTL)
    response = HttpResponse(status=204)
    response['Cache-Control'] = 'no-store'
    return response
