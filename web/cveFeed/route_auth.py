"""Auth state per web route: how a route answers an anonymous request.

For each web host a handful of common routes (``/``, ``/login``, ``/admin``, ``/api`` ...) and the paths bbot saw are asked
once with a plain GET and classified as open, a login page, a session requirement, single sign-on, a redirect or not found.
The probe is deliberately small: no credentials, no cookies, redirects are never followed, and at most ROUTE_SAMPLE_BYTES of
each body are read. ``classify`` and the planning helpers are pure functions so every rule is unit tested; the network
helper (``probe_url``) is injectable.
"""
import concurrent.futures
import functools
import http.client
import logging
import re
import socket
import threading
import time
from urllib.parse import urljoin, urlparse

from cveFeed import fingerprint

logger = logging.getLogger(__name__)

SERVICE = 'route-auth'
COMMON_PATHS = ('/', '/login', '/admin', '/admin/', '/api', '/api/', '/dashboard', '/wp-login.php', '/actuator/health',
                '/swagger/index.html')
WEB_PORTS = {80: 'http', 443: 'https', 8080: 'http', 8443: 'https', 8000: 'http', 8008: 'http', 8081: 'http', 8888: 'http',
             9443: 'https', 3000: 'http'}
HTTP_SERVICE_NAMES = ('http', 'https', 'http-proxy', 'http-alt', 'https-alt', 'ssl/http', 'ssl/https')
MAX_BASES_PER_HOST = 2  # prefer 443 then 80, then other web ports by number
MAX_ENDPOINT_PATHS = 12  # EndPoint paths per host, static assets excluded
MAX_URLS_PER_HOST = 20
MAX_URLS_PER_SCAN = 1500
ROUTE_WORKERS = 8  # hosts probed in parallel; one host's paths go one after another
PER_REQUEST_GAP = 0.2  # seconds between two requests to the same host
CONNECT_TIMEOUT, READ_TIMEOUT = 3, 6
PROBE_TOTAL_SECONDS = 20  # wall-clock budget for one probe: the per-read timeouts alone let a host that trickles bytes hold a worker thread for good
ROUTE_SAMPLE_BYTES = 64 * 1024
MAX_PATH_LENGTH = 200
CHUNK = 500
STATIC_EXT = ('.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.map', '.pdf', '.xml', '.txt')
STORED_FIELDS = ('domain_id', 'host', 'path', 'auth_state', 'http_status', 'redirect_to', 'provider', 'title', 'evidence',
                 'checked_at', 'sensitive', 'sensitive_score', 'content_type', 'retired_at', 'zombie_since', 'previous_state')

# (host regex, vendor label, optional path regex that must also match)
SSO_PROVIDERS = (
    (re.compile(r'^(login\.microsoftonline\.com|login\.microsoft\.com|[^.]+\.b2clogin\.com)$', re.I), 'Entra ID', None),
    (re.compile(r'^accounts\.google\.com$', re.I), 'Google', None),
    (re.compile(r'(^|\.)(okta\.com|oktapreview\.com|okta-emea\.com)$', re.I), 'Okta', None),
    (re.compile(r'(^|\.)auth0\.com$', re.I), 'Auth0', None),
    (re.compile(r'(^|\.)onelogin\.com$', re.I), 'OneLogin', None),
    (re.compile(r'(^|\.)(pingidentity\.com|pingone\.com)$', re.I), 'Ping', None),
    (re.compile(r'(^|\.)duosecurity\.com$', re.I), 'Duo', None),
    (re.compile(r'(^|\.)cloudflareaccess\.com$', re.I), 'Cloudflare Access', None),
    (re.compile(r'^login\.salesforce\.com$', re.I), 'Salesforce', None),
    (re.compile(r'^github\.com$', re.I), 'GitHub', re.compile(r'^/login/oauth', re.I)),
)
SSO_PATH_RE = re.compile(r'/(adfs/ls|saml2?|sso|oauth2?/authorize|openid-connect/auth|auth/realms/|connect/authorize)', re.I)
LOGIN_PATH_RE = re.compile(r'(?:^|[/_-])(login|log-in|signin|sign-in|logon|session/new|wp-login\.php|account/login|user/login|auth)'
                           r'(/|\.|\?|$)', re.I)
# '[^<>]' stops each scan at the next tag, so a body of repeated '<input ' / '<meta ' with no '>' is read in linear time
PASSWORD_INPUT_RE = re.compile(r'<input\b[^<>]{0,1000}?type=["\']?password', re.I)
LOGIN_TITLE_RE = re.compile(r'\b(sign in|log in|login|logon|anmelden|connexion)\b', re.I)
SSO_BODY_RE = re.compile(r'(okta-sign-in|auth0|keycloak|SAMLRequest|microsoftonline|Sign in with (Microsoft|Google|Okta)|'
                         r'login\.microsoftonline)', re.I)
SSO_BODY_PROVIDER = (('okta', 'Okta'), ('auth0', 'Auth0'), ('keycloak', 'Keycloak'), ('samlrequest', 'SAML'),
                     ('microsoft', 'Entra ID'), ('google', 'Google'))
META_REFRESH_RE = re.compile(r'<meta\b[^<>]{0,1000}?http-equiv=["\']?refresh[^<>]{0,1000}?content=["\'][^"\'<>]{0,1000}?url=([^"\'<>\s]+)', re.I)


def page_title(text):
    """The first <title> of ``text``, whitespace collapsed and clipped. Found with plain string searches (one pass, no backtracking):
    a body of repeated '<title' with no '>' or '</title>' cost a regex quadratic time."""
    lowered = text.lower()
    start = lowered.find('<title')
    while start != -1:
        after = start + len('<title')
        if after < len(lowered) and lowered[after] not in '> \t\r\n/':  # <titles>, not <title>
            start = lowered.find('<title', after)
            continue
        open_end = lowered.find('>', after)
        if open_end == -1:
            return ''
        close = lowered.find('</title', open_end + 1)
        if close == -1:
            return ''
        return re.sub(r'\s+', ' ', text[open_end + 1:close]).strip()[:300]
    return ''


# ----------------------------------------------------------------------------- planning (pure)

def _is_ipv6(host):
    return ':' in host


def _base(scheme, host, port):
    default = 443 if scheme == 'https' else 80
    name = f'[{host}]' if _is_ipv6(host) else host
    return f'{scheme}://{name}' + ('' if port == default else f':{port}')


def web_bases(sub):
    """Base URLs (scheme, host name, port) a prefetched Subdomain (``ip_addresses__ports``) serves web pages on: from its
    ``http_url`` and from every open port that looks like HTTP. The URL carries the hostname (virtual hosts), not the IP. At
    most MAX_BASES_PER_HOST, 443 first, then 80, then the other web ports by number."""
    host = (sub.name or '').strip().lower()
    if not host:
        return []
    found = set()
    if sub.http_url:
        parsed = urlparse(sub.http_url)
        if parsed.scheme in ('http', 'https') and parsed.hostname:
            found.add((parsed.scheme, parsed.port or (443 if parsed.scheme == 'https' else 80)))
    for ip in sub.ip_addresses.all():
        for port in ip.ports.all():
            if (port.state or '') not in ('', 'open'):
                continue
            service, product = (port.service_name or '').lower(), (port.product or '').lower()
            if port.number in WEB_PORTS or service in HTTP_SERVICE_NAMES or 'http' in product:
                https = 'https' in service or 'ssl' in service or WEB_PORTS.get(port.number) == 'https'
                found.add(('https' if https else 'http', port.number))
    order = sorted(found, key=lambda sp: (0 if sp[1] == 443 else 1 if sp[1] == 80 else 2, sp[1], sp[0]))
    return [_base(scheme, host, port) for scheme, port in order[:MAX_BASES_PER_HOST]]


def _clean_path(url):
    path = urlparse(url).path or '/'
    if len(path) > MAX_PATH_LENGTH or path.lower().endswith(STATIC_EXT):
        return None
    return path


def route_paths(endpoint_urls, priority_paths=()):
    """The common paths plus up to MAX_ENDPOINT_PATHS distinct paths from a host's EndPoint URLs: static assets and very long
    paths dropped, query strings dropped. ``priority_paths`` (paths bbot once saw gone, to see whether they answer again) come
    first among them."""
    paths = list(COMMON_PATHS)
    seen, extra = set(paths), []
    for url in list(priority_paths) + list(endpoint_urls):
        path = _clean_path(url)
        if path and path not in seen:
            seen.add(path)
            extra.append(path)
            if len(extra) >= MAX_ENDPOINT_PATHS:
                break
    return paths + extra


def host_urls(bases, paths, limit=MAX_URLS_PER_HOST):
    """Every path on every base, path-major so a cap drops the least common paths first."""
    out = []
    for path in paths:
        for base in bases:
            out.append(base + path)
            if len(out) >= limit:
                return out
    return out


# ----------------------------------------------------------------------------- classification (pure)

def sso_provider(location, base_url=''):
    """The identity provider label when ``location`` (absolute or relative to ``base_url``) points at a known one, or an
    empty string."""
    parsed = urlparse(urljoin(base_url, location))
    host, path = (parsed.hostname or '').lower(), parsed.path or ''
    for host_re, label, path_re in SSO_PROVIDERS:
        if host_re.search(host) and (path_re is None or path_re.search(path)):
            return label
    return ''


def _redirect_state(location, base_url):
    """(state, provider) for a redirect target: single sign-on, a login page, or just a redirect."""
    provider = sso_provider(location, base_url)
    if provider:
        return 'sso', provider
    path = urlparse(urljoin(base_url, location)).path or ''
    if SSO_PATH_RE.search(path):
        return 'sso', ''
    if LOGIN_PATH_RE.search(path):
        return 'session_required', ''
    return 'redirect', ''


def classify(probe):
    """``(state, evidence)`` for one probe (the dict ``probe_url`` returns: status, location, www_authenticate, cookies,
    content_type, body, title, url). ``evidence`` carries the markers matched, the bytes sampled and the cookie names; it
    never carries the body."""
    status = probe.get('status') or 0
    body = probe.get('body') or ''
    evidence = {'markers': [], 'bytes': probe.get('bytes', len(body)), 'cookies': sorted(probe.get('cookies') or [])}
    markers = evidence['markers']
    # what the response says it runs: kept (headers cut short, never the body) so the host record can show it
    for key, field in (('server', 'server'), ('powered_by', 'powered_by')):
        if probe.get(field):
            evidence[key] = str(probe[field])[:100]
    page_url = probe.get('url', '')
    scripts, local = fingerprint.script_sources(body, page_url) if (urlparse(page_url).path or '/') == '/' else ([], [])
    found = fingerprint.from_response(probe.get('server', ''), probe.get('powered_by', ''), body, probe.get('content_type', ''), scripts=scripts)
    if local:
        evidence['local_scripts'] = local  # read by run_route_auth, which removes it before anything is stored
    if found:
        evidence['fingerprints'] = found
        evidence['fingerprint_names'] = [f['name'] for f in found]  # flat text for search: the dicts also hold the word "source"

    def done(state, provider='', redirect_to=''):
        evidence['provider'] = provider
        evidence['redirect_to'] = redirect_to
        return state, evidence

    if status == 401:
        header = (probe.get('www_authenticate') or '').strip()
        scheme = header.split(' ', 1)[0] if header else ''
        evidence['www_authenticate'] = scheme
        if scheme.lower() in ('negotiate', 'ntlm'):
            return done('sso', 'Windows integrated')
        markers.append('401')
        return done('session_required')
    if status == 403:
        markers.append('forbidden')
        evidence['reason'] = 'forbidden'
        return done('session_required')
    if 300 <= status < 400:
        location = (probe.get('location') or '').strip()
        if not location:
            return done('redirect')
        state, provider = _redirect_state(location, probe.get('url', ''))
        markers.append('redirect')
        return done(state, provider, location[:2000])
    if status in (404, 410):
        return done('not_found')
    if 200 <= status < 300 or status == 405:
        title = probe.get('title') or ''
        state, provider = 'open', ''
        if PASSWORD_INPUT_RE.search(body):
            markers.append('password_input')
            state = 'login'
        elif title and LOGIN_TITLE_RE.search(title):
            markers.append('login_title')
            state = 'login'
        match = SSO_BODY_RE.search(body)
        if match:
            markers.append('sso_marker')
            state = 'sso'
            lowered = match.group(0).lower()
            provider = next((label for key, label in SSO_BODY_PROVIDER if key in lowered), '')
        if state == 'open':
            refresh = META_REFRESH_RE.search(body)
            if refresh:
                target, found = refresh.group(1), _redirect_state(refresh.group(1), probe.get('url', ''))
                markers.append('meta_refresh')
                if found[0] != 'redirect':
                    return done(found[0], found[1], target[:2000])
                return done('open')
        return done(state, provider)
    return done('error')


def analyse(result):
    """Everything kept from one probe response: its state and evidence, and the kinds of sensitive data in it (counts and masked
    samples only). The body is read here and dropped, so a 64 KB page is not held until the stage ends."""
    from cveFeed import sensitive
    state, evidence = classify(result)
    content_type = (result.get('content_type') or '')[:100]
    found = sensitive.scan_text(result.get('body') or '') if sensitive.is_text(content_type) else {}
    return {'status': result.get('status'), 'title': (result.get('title') or '')[:300], 'content_type': content_type,
            'state': state, 'evidence': evidence, 'sensitive': found, 'sensitive_score': sensitive.sensitive_score(found)}


# ----------------------------------------------------------------------------- network

def _read_scripts(result, probe, scan_id):
    """Read the first bytes of up to four scripts the front page loads from its own host and add the libraries their comment banners
    name (jQuery, Bootstrap, AngularJS ...) to the page's fingerprints. The same bounded, pinned, anonymous GET as every route
    check, with the same gap between requests; a script that cannot be read is skipped."""
    from reNgine import resources
    evidence = result.get('evidence') or {}
    local = evidence.pop('local_scripts', None) or []
    pairs = []
    for src in local:
        if resources.abort_requested(scan_id):
            break
        time.sleep(PER_REQUEST_GAP)
        try:
            got = probe(src)
        except Exception:  # noqa: BLE001
            continue
        if 200 <= (got.get('status') or 0) < 300:
            pairs += fingerprint.from_script_body(got.get('body') or '')
    if pairs:
        found = fingerprint.extend(evidence.get('fingerprints'), pairs)
        evidence['fingerprints'] = found
        evidence['fingerprint_names'] = [f['name'] for f in found]


def probe_url(url, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT), max_bytes=ROUTE_SAMPLE_BYTES, headers=None, method='GET', project=None):
    """Bounded anonymous GET/HEAD using a pinned numeric destination and original Host/SNI."""
    import ssl
    from http.cookies import SimpleCookie, CookieError
    from urllib.parse import quote, urlsplit
    from cveFeed import pinned_transport

    if method not in ('GET', 'HEAD'):
        raise ValueError('route probes are read-only: GET or HEAD')
    max_bytes = min(int(max_bytes), ROUTE_SAMPLE_BYTES)
    if max_bytes < 0:
        raise ValueError('invalid probe byte limit')
    if not isinstance(url, str) or any(ord(c) <= 32 or ord(c) == 127 for c in url):
        raise ValueError('invalid probe URL')
    parsed = urlsplit(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError('probe URL must be HTTP(S) without credentials')
    if headers and any(key.lower() != 'host' for key in headers):
        raise ValueError('only a Host override is allowed for anonymous probes')
    host = parsed.hostname.encode('idna').decode('ascii')
    port = parsed.port if parsed.port is not None else (443 if parsed.scheme == 'https' else 80)
    addresses = pinned_transport.resolve(host, port, project=project)
    context = None
    if parsed.scheme == 'https':
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # scanner must inspect broken-certificate sites too
    connection = pinned_transport.HTTPConnection(host, port, addresses, timeout[0], context=context, project=project)
    authority = f'[{host}]' if ':' in host else host
    if parsed.port is not None:
        authority += f':{port}'
    request_headers = {'User-Agent': 'CVEngine route check', 'Accept': 'text/html,*/*;q=0.5',
                       'Accept-Encoding': 'identity', 'Host': authority}
    request_headers.update({key.title(): value for key, value in (headers or {}).items()})
    path = quote(parsed.path or '/', safe="/%:@!$&'()*+,;=-._~")
    if parsed.query:
        path += '?' + quote(parsed.query, safe="/%?:@!$&'()*+,;=-._~")
    response = None
    expired = threading.Event()

    def abort():  # closes the connection under a blocked read; the read then ends and the budget breach is raised below
        expired.set()
        sock = connection.sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    watchdog = threading.Timer(PROBE_TOTAL_SECONDS, abort)
    watchdog.daemon = True
    watchdog.start()
    try:
        connection.connect()
        connection.sock.settimeout(timeout[1])
        connection.request(method, path, headers=request_headers)
        response = connection.getresponse()
        if response.getheader('Content-Encoding', 'identity').lower() not in ('', 'identity'):
            raise ValueError('probe server ignored identity encoding')
        raw = response.read(max_bytes) or b''
        if expired.is_set():
            raise TimeoutError('probe exceeded its total time budget')
        encoding = response.headers.get_content_charset() or 'utf-8'
        try:
            text = raw.decode(encoding, errors='replace')
        except LookupError:
            text = raw.decode('utf-8', errors='replace')
        title = page_title(text)
        cookies = SimpleCookie()
        for value in response.headers.get_all('Set-Cookie', []):
            try:
                cookies.load(value)
            except CookieError:
                pass
        return {'url': url, 'status': response.status, 'location': response.getheader('Location', ''),
                'www_authenticate': response.getheader('WWW-Authenticate', ''), 'cookies': list(cookies.keys()),
                'content_type': (response.getheader('Content-Type') or '').split(';')[0].strip().lower(),
                'body': text, 'title': title, 'bytes': len(raw), 'server': response.getheader('Server', ''),
                'powered_by': response.getheader('X-Powered-By', '')}
    except (OSError, http.client.HTTPException):
        if expired.is_set():
            raise TimeoutError('probe exceeded its total time budget') from None
        raise
    finally:
        watchdog.cancel()
        if response is not None:
            response.close()
        connection.close()


# ----------------------------------------------------------------------------- the stage

def _chunks(items, size=CHUNK):
    items = list(items)
    for i in range(0, len(items), size):
        yield items[i:i + size]


def host_allowed(host, project=None):
    """The SSRF gate: an IP must be one a scanner may touch (``project`` may authorise a tailnet device of its own), and a name must
    not resolve to anything blocked."""
    from targetApp.target_types import IP, classify_target, is_scannable_ip, resolves_to_blocked
    if classify_target(host) == IP:
        return is_scannable_ip(host, project=project)
    return not resolves_to_blocked(host)


def _retired_endpoints(scan):
    """``{(host, path): (status, scan_id)}`` for the paths an earlier scan of this project saw answer 404 or 410 (newest first,
    at most 5,000 rows): documented as gone, so worth asking again."""
    from startScan.models import EndPoint
    out = {}
    rows = EndPoint.objects.filter(target_domain__project_id=scan.domain.project_id, http_status__in=(404, 410)) \
        .exclude(scan_history=scan).order_by('-id').values_list('subdomain__name', 'http_url', 'http_status', 'scan_history_id')
    for host, url, status, scan_id in rows[:5000]:
        path = _clean_path(url)
        if host and path:
            out.setdefault(((host or '').lower(), path), (status, scan_id))
    return out


def _plan(scan, retired=None):
    """{host: [urls]} for the scan's hosts, in name order, within MAX_URLS_PER_HOST and MAX_URLS_PER_SCAN."""
    from startScan.models import EndPoint, Subdomain
    endpoints, priority = {}, {}
    for host, url in EndPoint.objects.filter(scan_history=scan).values_list('subdomain__name', 'http_url')[:5000]:
        endpoints.setdefault((host or '').lower(), []).append(url)
    for (host, path) in (retired or {}):
        priority.setdefault(host, []).append(path)
    from cveFeed.exclusions import excluded_names
    banned = excluded_names(scan.domain.project_id)  # hosts the organization excluded for good are never probed
    plan, total = {}, 0
    subs = Subdomain.objects.filter(scan_history=scan).prefetch_related('ip_addresses__ports').order_by('name')
    for sub in subs.iterator(chunk_size=CHUNK):
        host = (sub.name or '').strip().lower()
        if not host or host in plan or host.rstrip('.') in banned:
            continue
        bases = web_bases(sub)
        if not bases:
            continue
        urls = host_urls(bases, route_paths(endpoints.get(host, []), priority.get(host, ())))[:max(0, MAX_URLS_PER_SCAN - total)]
        if not urls:
            break
        plan[host] = urls
        total += len(urls)
        if total >= MAX_URLS_PER_SCAN:
            break
    return plan


def run_route_auth(scan_id, probe=probe_url, force=False):
    """Check how the scan's web routes answer an anonymous GET and store the result per project route. Routes checked inside
    the TTL (7 days, CVENGINE_TTL_ROUTE_AUTH) are not asked again. Returns
    ``{'routes', 'hosts', 'by_state', 'reused', 'errors'}``. ``force`` (a re-test of changed hosts) ignores the TTL: a version
    or service change on an existing web port must not be judged against yesterday's auth state. The plan is the re-tested hosts'
    routes only, so it stays as bounded as the re-test itself."""
    from django.utils import timezone

    from cveFeed import activity, ledger, scoring
    from reNgine import resources
    from startScan.models import ScanHistory
    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
    domain, project = scan.domain, scan.domain.project_id
    empty = {'routes': 0, 'hosts': 0, 'by_state': {}, 'reused': 0, 'errors': 0}
    if probe is probe_url:  # the project may authorise the tailnet devices of its own
        probe = functools.partial(probe_url, project=project)
    retired = _retired_endpoints(scan)
    plan = _plan(scan, retired)
    if not plan:
        activity.log('run_check', f'Web route check skipped for {domain.name}: no web services found', project=project, scan_id=scan.id)
        return empty
    host_of = {url: host for host, urls in plan.items() for url in urls}
    all_urls = list(host_of)
    fresh = set() if force else ledger.fresh(SERVICE, all_urls, project)
    todo = [u for u in all_urls if ledger._norm(u) not in fresh]
    with ledger.claim_many(f'{SERVICE}@{project}', todo) as won:
        won_set = set(won)
        won_urls = [u for u in todo if ledger._norm(u) in won_set]
        if not won_urls:
            activity.log('run_check', f'Web route check for {domain.name}: all {len(all_urls)} routes were checked in the last '
                         f'{ledger.ttl_label(SERVICE)}' if not todo else
                         f'Web route check for {domain.name}: its routes are being checked by another scan',
                         project=project, scan_id=scan.id)
            return {**empty, 'reused': len(fresh)}
        by_host = {}
        for url in won_urls:
            by_host.setdefault(host_of[url], []).append(url)
        probed, errors, blocked = {}, {}, 0

        def probe_host(host, urls):
            if not host_allowed(host, project):
                return host, None
            out = []
            for i, url in enumerate(urls):
                if resources.abort_requested(scan_id):
                    break
                if i:
                    time.sleep(PER_REQUEST_GAP)
                try:
                    result = analyse(probe(url))
                    _read_scripts(result, probe, scan_id)
                    out.append((url, result))
                except Exception as exc:  # noqa: BLE001 - a timeout or refused connection is not an auth state
                    out.append((url, exc))
            return host, out

        running = activity.log('run_check', f'Checking {len(won_urls)} web routes on {len(by_host)} hosts of {domain.name}',
                               project=project, status='running', scan_id=scan.id)
        with resources.heavy_job('route-probe', label=f'{domain.name}: {len(won_urls)} routes'):
            with concurrent.futures.ThreadPoolExecutor(max_workers=ROUTE_WORKERS) as pool:
                futures = []
                for host, urls in by_host.items():
                    if resources.abort_requested(scan_id):
                        break
                    futures.append(pool.submit(probe_host, host, urls))
                for future in futures:
                    host, out = future.result()
                    if out is None:
                        blocked += 1
                        continue
                    for url, result in out:
                        if isinstance(result, Exception):
                            errors[url] = str(result)[:200]
                        else:
                            probed[url] = result
        stored = _persist(scan, project, probed, now=timezone.now(), retired_endpoints=retired)
        ledger.record(SERVICE, list(probed), project, scan)
        scoring.rescore_quietly(project, list(by_host))
        if errors:
            ledger.record(SERVICE, list(errors), project, scan, status='failed')
        counts = stored['by_state']
        activity.settle(running, 'done', message=(
            f'Checked {len(probed)} web routes on {len(by_host)} hosts of {domain.name}: {counts.get("open", 0)} open, '
            f'{counts.get("login", 0)} login pages, {counts.get("sso", 0)} SSO, {counts.get("session_required", 0)} require a session'
            + (f'; {stored["sensitive"]} routes serve sensitive data' if stored['sensitive'] else '')
            + (f'; {len(errors)} could not be reached' if errors else '')), routes=len(probed))
        return {'routes': len(probed), 'hosts': len(by_host), 'by_state': counts, 'reused': len(fresh), 'errors': len(errors),
                'blocked': blocked, 'sensitive': stored['sensitive']}


def _persist(scan, project, probed, now, retired_endpoints=None):
    """Store each probed route (one row per project and URL) and report state flips as auth changes, a route that now says
    not found as retired, and a retired route (or one documented as gone) that answers again as a zombie."""
    from cveFeed import changes
    from cveFeed.models import RouteAuth
    previous = {}
    for part in _chunks(probed):
        previous.update({r.url: r for r in RouteAuth.objects.filter(project_id=project, url__in=part)})
    new_rows, old_rows, by_state = [], [], {}
    for url, result in probed.items():
        state, evidence, found = result['state'], result['evidence'], result['sensitive']
        host = urlparse(url).hostname or ''
        fields = {'domain_id': scan.domain_id, 'host': host.lower(), 'path': (urlparse(url).path or '/')[:500], 'auth_state': state,
                  'http_status': result.get('status'), 'redirect_to': evidence.get('redirect_to', '')[:2000],
                  'provider': evidence.get('provider', '')[:100], 'title': result['title'], 'evidence': evidence,
                  'checked_at': now, 'sensitive': found, 'sensitive_score': result['sensitive_score'],
                  'content_type': result['content_type']}
        row = previous.get(url)
        by_state[state] = by_state.get(state, 0) + 1
        status = result.get('status') or 0
        answers = 200 <= status < 300
        after = {'url': url, 'auth_state': state, 'http_status': status}
        if row is None:
            new_row = RouteAuth(project_id=project, url=url, **fields)
            gone = (retired_endpoints or {}).get((host.lower(), fields['path']))
            if gone and answers:
                new_row.zombie_since = now
                changes.record_route_change('zombie_route', project, scan.domain_id, scan.id, host.lower(),
                                            {'endpoint_status': gone[0], 'scan_id': gone[1]}, after)
            new_rows.append(new_row)
            continue
        was, was_sensitive = row.auth_state, set(row.sensitive or {})
        explained = False  # a retirement or a zombie says more than the plain state change would
        for key, value in fields.items():
            setattr(row, key, value)
        if set(found) - was_sensitive:
            changes.record_sensitive_change(project, scan.domain_id, scan.id, host.lower(), url, was_sensitive, found)
        if was not in ('not_found', 'error') and state == 'not_found':
            row.retired_at, row.previous_state, explained = now, was, True
            changes.record_route_change('route_retired', project, scan.domain_id, scan.id, host.lower(),
                                        {'auth_state': was, 'url': url}, after)
        elif row.retired_at is not None and answers:
            explained = True
            if row.zombie_since is None:
                row.zombie_since = now
                changes.record_route_change('zombie_route', project, scan.domain_id, scan.id, host.lower(),
                                            {'retired_at': row.retired_at.isoformat(), 'url': url}, after)
        elif row.zombie_since is not None and not answers:
            row.zombie_since = None
        old_rows.append(row)
        if was != state and not explained:
            changes.record_auth_change(project, scan.domain_id, scan.id, host.lower(), url, was, state,
                                       {'http_status': result.get('status'), 'provider': evidence.get('provider', '')})
    for part in _chunks(new_rows):
        RouteAuth.objects.bulk_create(part, ignore_conflicts=True)
    for part in _chunks(old_rows):
        RouteAuth.objects.bulk_update(part, list(STORED_FIELDS), batch_size=CHUNK)
    link_technologies(scan, probed)
    return {'by_state': by_state, 'sensitive': sum(1 for r in probed.values() if r['sensitive_score'] > 0)}


def link_technologies(scan, probed):
    """Record what each host's front page says it runs (see cveFeed.fingerprint) as the host's technologies in this scan, so the
    correlation engine reads a PHP version from an X-Powered-By header like any other detected technology. Only the root page of a
    host speaks for the host; names already on the host are left alone. Returns the number of links added."""
    from startScan.models import Subdomain, Technology
    names = {}
    for url, result in probed.items():
        parsed = urlparse(url)
        if (parsed.path or '/') != '/' or not parsed.hostname:
            continue
        for found in (result.get('evidence') or {}).get('fingerprints') or []:
            names.setdefault(parsed.hostname.lower(), set()).add(found['name'])
    if not names:
        return 0
    cache, added = {}, 0
    for sub in Subdomain.objects.filter(scan_history_id=scan.id, name__in=list(names)).prefetch_related('technologies'):
        have = {t.name for t in sub.technologies.all()}
        new = []
        for name in sorted(names.get(sub.name.lower(), ()) - have):
            if name not in cache:
                cache[name] = Technology.objects.filter(name=name).first() or Technology.objects.create(name=name)
            new.append(cache[name])
        if new:
            sub.technologies.add(*new)
            added += len(new)
    return added
