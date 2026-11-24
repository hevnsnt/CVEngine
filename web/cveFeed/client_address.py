"""The client address check's verdict, and the notice it raises (review r3 S2; docs/DEPLOYMENT.md, "Client addresses behind a host proxy").

Every update runs scripts/client-address-check.sh: one probe through the public name (cvengine.client_probe), the address the server took for
it, the address Cloudflare saw when there is one, the label the bundled proxy put on the probe (what it did with the forwarding headers) and
where the proxy's port 443 is published on the host. ``classify`` turns that into one verdict (``KINDS``) and one line for the update log;
``apply`` opens, refreshes or resolves the App Admin notice of it (an ``AdminAlert`` with code ``client_address``: the status strip, Settings,
Updates and the system status show it). The common install, where the bundled proxy faces visitors directly, needs nothing and says so.

What this never does: believe a header. The proxy believes ``X-Forwarded-For`` on 443 only with the install's upstream secret, exactly as
before; the label and this module only decide what to tell a person. ``recheck`` repeats the probe from the server itself (the notice's Check
again button, and the operations checks while a notice is open) and may only resolve the notice, never open one, because the server cannot see
where the proxy's port is published.
"""
import hashlib
import ipaddress
import logging
import os
import re

from django.utils import timezone

logger = logging.getLogger(__name__)

CODE = 'client_address'
SECRET_RE = re.compile(r'^[A-Za-z0-9_-]{32,256}$')
# The two lines config/nginx/host-proxy-client-address.conf holds (tests/test_client_address_notice.py keeps them equal).
SNIPPET_LINES = ('proxy_set_header X-Forwarded-For $remote_addr;', 'proxy_set_header X-CVEngine-Upstream "{secret}";')
SNIPPET_HEAD = (
    '# cvENGINE: hand the real client address to the bundled proxy (docs/DEPLOYMENT.md, "Client addresses behind a host proxy").',
    '# Put these lines in the location of the host nginx that holds the proxy_pass to cvENGINE, remove any other X-Forwarded-For line there,',
    '# then: sudo nginx -t && sudo systemctl reload nginx',
    '# Behind Cloudflare, first make $remote_addr the visitor (once, in the http or server block):',
    '#     real_ip_header CF-Connecting-IP;',
    '#     set_real_ip_from <every range in https://www.cloudflare.com/ips-v4 and ips-v6>;',
    '# The second line holds this install\'s secret: keep the file readable by root only (chmod 600).',
)

# kind: (what the notice does, severity, title). 'raise' opens or refreshes it, 'resolve' clears it, None leaves it as it is.
KINDS = {
    'ok': ('resolve', '', ''),
    'direct': ('resolve', '', ''),
    'front': ('raise', 'warning', "Visitors' own addresses do not reach cvENGINE yet"),
    'front_silent': ('raise', 'warning', "Visitors' own addresses do not reach cvENGINE yet"),
    'front_old_secret': ('raise', 'warning', 'The host web server sends an old cvENGINE secret'),
    'cdn': ('raise', 'warning', "Visitors' addresses arrive as Cloudflare's"),
    'cdn_direct': (None, '', ''),
    'unknown': (None, '', ''),
}

_SHARED = ('so every visitor looks like one address: five wrong passwords from anyone lock the account out for everyone, and a ban or the IP '
           'allowlist acts on all of them at once.')
_STEPS = ('Copy the lines below into the host nginx, in the location that passes requests to cvENGINE (next to its other proxy_set_header '
          'lines), then run sudo nginx -t and sudo systemctl reload nginx. This notice goes away by itself once the check passes: press Check '
          'again, or it is checked again within the hour and at every update.')
DETAIL = {
    'front': ('A web server in front of cvENGINE (a host nginx) passes on each visitor\'s address, but cvENGINE does not believe it yet, because '
              f'the request does not carry this install\'s secret. Until it does, {_SHARED} {_STEPS}'),
    'front_silent': ('A web server in front of cvENGINE (a host nginx) forwards visitors to it without saying who they are, ' + _SHARED + ' '
                     + _STEPS),
    'front_old_secret': ('The host nginx in front of cvENGINE sends a secret that is not this install\'s (the secret was made again, or the lines '
                         f'were copied from another install), so cvENGINE does not believe the address it passes on and {_SHARED} '
                         'Replace the X-CVEngine-Upstream line there with the one below, then run sudo nginx -t and sudo systemctl reload '
                         'nginx. This notice goes away by itself once the check passes: press Check again, or it is checked again within the '
                         'hour and at every update.'),
    'cdn': ('The host nginx passes on an address, but it is Cloudflare\'s, not the visitor\'s: the host nginx does not take the visitor from '
            f'Cloudflare\'s CF-Connecting-IP header yet, {_SHARED} Add the real_ip_header and set_real_ip_from lines the comments below '
            'describe to the host nginx, then reload it. This notice goes away by itself once the check passes.'),
}
LINE = {
    'ok': 'verdict: ok, nothing to do.',
    'direct': ('verdict: nothing in front of the bundled proxy, which faces visitors directly on port 443 and sees each one\'s own address. '
               'Nothing to install.'),
    'front': ('verdict: a host proxy in front sends the client address, but the bundled proxy does not believe it yet. App Admins see a notice '
              'with the lines to install (Settings, Updates and the status strip).'),
    'front_silent': ('verdict: a host proxy in front forwards visitors without their address. App Admins see a notice with the lines to install '
                     '(Settings, Updates and the status strip).'),
    'front_old_secret': ('verdict: the host proxy in front sends an old upstream secret. App Admins see a notice with the line to replace '
                         '(Settings, Updates and the status strip).'),
    'cdn': ('verdict: the host proxy passes on Cloudflare\'s address, not the visitor\'s (real_ip_header CF-Connecting-IP is missing there). '
            'App Admins see a notice.'),
    'cdn_direct': ('verdict: a CDN or proxy sends forwarding headers straight to the bundled proxy on port 443, with no host nginx in between to '
                   'add the secret. See docs/DEPLOYMENT.md, "Client addresses behind a host proxy".'),
}


def published_direct(published):
    """Whether the proxy's port 443 is published on the host's port 443 on an address that is not loopback (``docker compose port proxy 443``
    printed ``published``, one ``address:port`` per line): then it faces visitors itself. None when it cannot be read."""
    found = False
    for line in (published or '').split():
        host, _, port = line.strip().rpartition(':')
        if not host or not port.isdigit():
            continue
        found = True
        try:
            loopback = ipaddress.ip_address(host.strip('[]')).is_loopback
        except ValueError:
            loopback = False  # a name: not the usual loopback publish of a host proxy setup
        if port == '443' and not loopback:
            return True
    return False if found else None


def classify(recorded, forwarded, seen='', published=''):
    """``(kind, line)``: the verdict (a key of KINDS) and its line for the update log. ``recorded`` is the address the server took for the probe,
    ``forwarded`` the proxy's label (cvengine.client_probe.FORWARDED_LABELS, '' when none came), ``seen`` the address Cloudflare saw (''
    when there is no Cloudflare), ``published`` where the proxy's 443 is published ('' when unknown)."""
    if not recorded or recorded == 'unknown':
        return 'unknown', 'verdict: none, the probe did not arrive.'
    if not forwarded:
        return 'unknown', ('verdict: none, the probe did not pass a bundled proxy that labels it (your own reverse proxy in front of web, or a '
                           'proxy not recreated since the update).')
    if forwarded == 'tunnel':
        return 'unknown', 'verdict: none, the probe came through the tunnel listener (docs/HOSTING-ONLINE.md, "Through a Cloudflare Tunnel").'
    direct = published_direct(published)
    if forwarded == 'believed':
        kind = 'cdn' if seen and seen != recorded else 'ok'
    elif forwarded == 'wrong-secret':
        kind = 'front_old_secret'
    elif forwarded == 'ignored':
        kind = 'cdn_direct' if direct else 'front'
    elif direct is None:
        return 'unknown', 'verdict: none, where the proxy\'s port 443 is published could not be read.'
    else:
        kind = 'direct' if direct else 'front_silent'
    return kind, LINE[kind]


def _digest(kind, severity):
    return hashlib.sha1(f'{CODE}|{kind}|{severity}'.encode()).hexdigest()[:20]


def apply(kind, facts=None, now=None):
    """Open, refresh or resolve the notice for verdict ``kind``. Returns ``'raised'``, ``'resolved'`` or ``'unchanged'``. Never raises."""
    action, severity, title = KINDS.get(kind, (None, '', ''))
    try:
        from cveFeed import reviewer
        from cveFeed.models import AdminAlert
        now = now or timezone.now()
        alert = AdminAlert.objects.filter(code=CODE, resolved_at__isnull=True).first()
        if action == 'resolve':
            if alert is None:
                return 'unchanged'
            AdminAlert.objects.filter(pk=alert.pk, resolved_at__isnull=True).update(resolved_at=now)
            return 'resolved'
        if action != 'raise':
            return 'unchanged'
        facts = {**(facts or {}), 'kind': kind}
        digest = _digest(kind, severity)
        if alert is None:
            AdminAlert.objects.create(code=CODE, severity=severity, title=title, detail=DETAIL[kind], facts=facts, digest=digest,
                                      first_seen=now, last_seen=now, **reviewer.carried_dismissal(CODE, digest, severity, now))
        else:
            alert.severity, alert.title, alert.detail, alert.facts, alert.digest, alert.last_seen = severity, title, DETAIL[kind], facts, digest, now
            alert.save(update_fields=['severity', 'title', 'detail', 'facts', 'digest', 'last_seen'])
        return 'raised'
    except Exception:  # noqa: BLE001 - a report, never a reason to fail an update or a check
        logger.warning('client address: could not record the notice', exc_info=True)
        return 'unchanged'


def notice():
    """The open notice as ``{title, detail, kind, snippet}`` (``snippet``: whether the lines to install come with it), or None."""
    from cveFeed.models import AdminAlert
    alert = AdminAlert.objects.filter(code=CODE, resolved_at__isnull=True).order_by('-id').first()
    if alert is None:
        return None
    return {'id': alert.pk, 'title': alert.title, 'detail': alert.detail, 'kind': (alert.facts or {}).get('kind', ''), 'snippet': True}


def secret():
    """This install's upstream secret as web sees it (``CVENGINE_UPSTREAM_SECRET`` from .env), or '' when it has none of the right shape."""
    value = os.environ.get('CVENGINE_UPSTREAM_SECRET', '').strip()
    return value if SECRET_RE.match(value) else ''


def snippet():
    """The lines to install in the host nginx with this install's secret filled in, or '' when there is no usable secret. Holds the secret:
    App Admins only, never stored, never logged."""
    value = secret()
    if not value:
        return ''
    return '\n'.join((*SNIPPET_HEAD, SNIPPET_LINES[0], SNIPPET_LINES[1].format(secret=value))) + '\n'


def public_url():
    url = os.environ.get('CVENGINE_CLIENT_ADDRESS_URL', '').strip()
    if not url:
        domain = os.environ.get('DOMAIN_NAME', '').strip()
        url = f'https://{domain}' if domain else ''
    return url.rstrip('/')


def _get(url, timeout=10):
    """One GET with no certificate check (the probe only has to arrive); the body, at most 4 KiB, or '' on any failure."""
    import ssl
    import urllib.request
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'cvengine-client-address-check'}), timeout=timeout,
                                    context=ctx) as reply:
            return reply.read(4096).decode('utf-8', 'replace')
    except Exception:  # noqa: BLE001 - an HTTP error or no answer: the recorded address says what arrived
        return ''


def recheck(get=None):
    """The check from the server itself: one probe through the public name. Resolves the notice when it passes; never opens one (where the
    proxy's port is published cannot be seen from here). Returns ``{kind, result}``."""
    from cvengine import client_probe
    get = get or _get
    url = public_url()
    if not url:
        return {'kind': 'unknown', 'result': 'unchanged'}
    token = client_probe.start()
    get(f'{url}/client-address-probe/{token}/')
    recorded, forwarded = client_probe.read(token) or '', client_probe.read_forwarded(token)
    seen = ''
    for line in get(f'{url}/cdn-cgi/trace').splitlines():
        if line.startswith('ip='):
            seen = line[3:].strip()
            break
    kind, _line = classify(recorded, forwarded, seen)
    return {'kind': kind, 'result': apply(kind) if kind == 'ok' else 'unchanged'}


RECHECK_GATE_KEY = 'cvengine:client-address:recheck'
RECHECK_GATE_SECONDS = 3600


def recheck_if_open():
    """While a notice is open, check again at most once an hour (the operations checks call it): it then clears itself soon after the lines are
    installed. Never raises."""
    try:
        from django.core.cache import cache

        from cveFeed.models import AdminAlert
        if not AdminAlert.objects.filter(code=CODE, resolved_at__isnull=True).exists():
            return None
        if not cache.add(RECHECK_GATE_KEY, 1, RECHECK_GATE_SECONDS):
            return None
        return recheck()
    except Exception:  # noqa: BLE001
        logger.warning('client address: the check again failed', exc_info=True)
        return None
