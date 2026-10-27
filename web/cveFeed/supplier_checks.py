"""What a third-party supplier's public services say about themselves, and how well they secure themselves: pure evaluators, no network and
no database.

The main product is the host card of each supplier name (``cveFeed.supplier_scan``): response headers and banners, the certificate, and the
technology stack with versions where the response states them, read with the fingerprinting owned hosts use (``fingerprint`` through
``route_auth.classify``), so a project can search all its suppliers by technology ("who runs PHP 7?"). This module turns the same answers
into ``Posture`` items, a severity, the evidence and a plain-text note about what to ask the supplier. Four kinds, all from the outside and
all read-only:

* ``tls``: the certificate and protocol of the supplier's name on port 443 (expiry, name match, chain, weak signature or key, TLS 1.0/1.1),
  through the evaluator the owned-host hygiene checks use (``hygiene.evaluate_cert``);
* ``email``: SPF, DKIM, DMARC and MTA-STS of the name (``hygiene.email_findings`` and the MailFail checks), DNS only;
* ``web`` and ``exposed``: HTTP security headers of the front page, and whether a short fixed list of well-known administration and login
  pages answers (one plain GET each, never a guessed path);
* ``cve`` (secondary, informational): the versions the card shows, matched against the CVE catalog by the rules owned hosts use
  (``correlation`` and ``match_policy``) but stricter: only a version inside a bounded affected range counts, never a product name alone and
  never an unbounded advisory. Nothing is tried against the supplier, so no finding is ever "validated"; the evidence says so.

A finding is a statement about an announced fact. A distribution build ("nginx/1.18.0 (Ubuntu)") may carry backported fixes, so such a
finding is one step lower and says it is to be confirmed with the supplier."""
import re
from dataclasses import dataclass, field

from cveFeed import hygiene

INFO, LOW, MEDIUM, HIGH, CRITICAL = 0, 1, 2, 3, 4
LEVELS = ('info', 'low', 'medium', 'high', 'critical')
CATEGORIES = ('tls', 'email', 'web', 'exposed', 'cve')
MAX_CVE_PRODUCTS = 10  # products one response may be matched for
MAX_CVES_LISTED = 15  # CVE ids kept in one finding's evidence
HSTS_MIN_AGE = 15552000  # 180 days
EMAIL_SEVERITY = {'mta_sts_missing': LOW}  # an INFO in the owned-host review that matters for a supplier that receives your mail
NO_VALIDATION = ('Not validated. The version is what the supplier\'s service announces; nothing was tried against it. A distribution or the '
                 'supplier may have backported the fix, so ask the supplier to confirm the patch level.')


@dataclass
class Posture:
    check: str
    severity: int
    title: str
    detail: str
    category: str
    domain: str
    ask: str = ''
    evidence: dict = field(default_factory=dict)


def level(severity):
    return LEVELS[max(0, min(len(LEVELS) - 1, int(severity)))]


# ----------------------------------------------------------------------------- what to ask

def ask_for(check, domain, title=''):
    """The plain-text note about what to ask the supplier, by check name. Never says to do anything to the supplier's systems."""
    if check in ('tls_expired', 'tls_expiring'):
        return f'Ask the supplier to renew and deploy a new certificate for {domain}, and to monitor certificate expiry so it does not happen again.'
    if check == 'tls_hostname_mismatch':
        return f'Ask the supplier to serve a certificate that names {domain} (in its subject alternative names) on that service.'
    if check in ('tls_self_signed', 'tls_untrusted_chain'):
        return f'Ask the supplier to install a certificate from a publicly trusted authority, with its full chain, on {domain}.'
    if check in ('tls_weak_signature', 'tls_weak_key'):
        return f'Ask the supplier to reissue the certificate for {domain} with a SHA-256 signature and an RSA key of at least 2048 bits (or an ECDSA key).'
    if check == 'tls_legacy_protocol':
        return f'Ask the supplier to disable TLS 1.0 and 1.1 on {domain} and keep TLS 1.2 and 1.3.'
    if check.startswith('spf_'):
        return f'Ask the supplier to publish one SPF record for {domain} that lists only its real senders and ends in -all.'
    if check.startswith('dmarc_'):
        return f'Ask the supplier to publish a DMARC policy for {domain} of at least p=quarantine (then p=reject) with an aggregate report address (rua).'
    if check.startswith('dkim_'):
        return f'Ask the supplier to rotate the DKIM keys of {domain} to 2048 bits.'
    if check.startswith('mta_sts_'):
        return f'Ask the supplier to publish an MTA-STS policy for {domain} in mode: enforce and to keep its policy file reachable.'
    if check == 'hsts_missing':
        return f'Ask the supplier to send a Strict-Transport-Security header (max-age of at least six months) from {domain}.'
    if check == 'hsts_weak':
        return f'Ask the supplier to raise the Strict-Transport-Security max-age of {domain} to at least six months.'
    if check == 'security_headers_missing':
        return f'Ask the supplier to add the missing security response headers (Content-Security-Policy, X-Frame-Options, X-Content-Type-Options) on {domain}.'
    if check == 'http_no_redirect':
        return f'Ask the supplier to redirect every plain HTTP request for {domain} to HTTPS.'
    if check == 'no_https':
        return f'Ask the supplier to serve {domain} over HTTPS only, with a valid certificate.'
    if check.startswith('exposed_'):
        return (f'Ask the supplier to take this page off the public internet or restrict it to a VPN or an allow list, and to require '
                f'multi-factor sign-in where it must stay reachable ({domain}).')
    if check.startswith('cve_'):
        return (f'Ask the supplier which version runs on {domain}, whether it already has the fixes for the listed CVEs (a distribution may have '
                'backported them) and by when it will be updated.')
    return f'Ask the supplier to review and fix this on {domain}: {title}'.strip()


# ----------------------------------------------------------------------------- TLS and email (the owned-host evaluators, filtered)

def _discriminator(host, domain):
    """Several findings of one check on one domain (a DKIM key per selector, a DANE record per mail host) must not overwrite each other: the
    host they are about, minus the domain, keeps their keys apart. A host that is the domain itself, a ``name:port``, or a service label
    (``_dmarc``) is one per domain and needs none."""
    host = (host or '').strip().lower().rstrip('.')
    if not host or host == domain or host.startswith(f'{domain}:'):
        return ''
    if host.endswith('.' + domain):
        host = host[:-len(domain) - 1]
    return '' if host.startswith('_') else host


def _from_hygiene(found, domain, category):
    key = found.check
    disc = _discriminator(found.host, domain)
    if disc:
        key = f'{key}@{disc}'[:60]
    return Posture(key, EMAIL_SEVERITY.get(found.check, found.severity), found.title[:300], found.detail, category, domain,
                   ask_for(found.check, domain, found.title), {**(found.evidence or {}), 'where': found.host})


def tls_postures(domain, info, now=None):
    """The certificate findings of ``domain:443`` at LOW or worse, from the probed ``info`` (``hygiene.probe_tls``)."""
    return [_from_hygiene(f, domain, 'tls') for f in hygiene.evaluate_cert({**info, 'host': domain, 'port': 443}, now=now) if f.severity >= LOW]


def email_postures(domain, findings):
    """The SPF, DKIM, DMARC, MTA-STS and MailFail findings of ``domain`` at LOW or worse (``findings`` are ``hygiene.Finding`` rows)."""
    out = []
    for found in findings:
        severity = EMAIL_SEVERITY.get(found.check, found.severity)
        if severity >= LOW:
            out.append(_from_hygiene(found, domain, 'email'))
    return out


# ----------------------------------------------------------------------------- HTTP security headers

def _headers(response):
    return {str(k).lower(): str(v) for k, v in ((response or {}).get('raw_headers') or (response or {}).get('headers') or {}).items()}


def hsts_max_age(value):
    found = re.search(r'max-age\s*=\s*"?(\d+)', value or '', re.IGNORECASE)
    return int(found.group(1)) if found else None


def answered(response):
    """Whether a response is the site's own answer: it came, no edge challenged it and it was not a plain "try later"."""
    return bool(response) and not response.get('challenge') and (response.get('status') or 0) not in (429, 503)


def web_postures(domain, https, http):
    """``(postures, evaluated)`` for the front page over HTTPS and over plain HTTP (each a response dict, or None when nothing answered).
    ``evaluated`` is the set of check-name prefixes this run could decide, so a finding it no longer finds resolves and one it could not
    look at is left alone."""
    out, evaluated = [], set()
    https_ok, http_ok = answered(https), answered(http)
    if https_ok:
        status = https.get('status') or 0
        headers = _headers(https)
        if status < 400:
            evaluated.add('hsts_')
            age = hsts_max_age(headers.get('strict-transport-security'))
            if 'strict-transport-security' not in headers:
                out.append(Posture('hsts_missing', MEDIUM, f'{domain} does not send Strict-Transport-Security',
                                   'Without HSTS a browser can be tricked into using plain HTTP on first contact or after a downgrade.', 'web', domain,
                                   ask_for('hsts_missing', domain), {'header': ''}))
            elif age is not None and age < HSTS_MIN_AGE:
                out.append(Posture('hsts_weak', LOW, f'{domain} sends a short Strict-Transport-Security max-age ({age} seconds)',
                                   'A max-age under six months gives little protection once a visitor has not been back for a while.', 'web', domain,
                                   ask_for('hsts_weak', domain), {'max_age': age}))
        if 200 <= status < 300 and 'html' in (https.get('content_type') or ''):
            evaluated.add('security_headers_missing')
            csp = headers.get('content-security-policy', '')
            missing = []
            if not csp:
                missing.append('Content-Security-Policy')
            if 'x-frame-options' not in headers and 'frame-ancestors' not in csp.lower():
                missing.append('X-Frame-Options')
            if headers.get('x-content-type-options', '').strip().lower() != 'nosniff':
                missing.append('X-Content-Type-Options')
            if missing:
                out.append(Posture('security_headers_missing', LOW, f'{domain} is missing security headers: {", ".join(missing)}',
                                   'These response headers limit what a browser lets a page do (script sources, framing, content sniffing).',
                                   'web', domain, ask_for('security_headers_missing', domain), {'missing': missing}))
    if https_ok or http_ok:
        evaluated.update(('http_no_redirect', 'no_https'))
        http_status = (http or {}).get('status') or 0
        if http_ok and 200 <= http_status < 300:
            if https_ok:
                out.append(Posture('http_no_redirect', MEDIUM, f'{domain} serves its site over plain HTTP instead of redirecting to HTTPS',
                                   f'A plain HTTP request for http://{domain}/ was answered with the page itself (status {http_status}).', 'web', domain,
                                   ask_for('http_no_redirect', domain), {'http_status': http_status}))
            else:
                out.append(Posture('no_https', HIGH, f'{domain} answers only over plain HTTP',
                                   f'Nothing answered over HTTPS, and http://{domain}/ answered with the page itself (status {http_status}).', 'web', domain,
                                   ask_for('no_https', domain), {'http_status': http_status}))
    return out, evaluated


# ----------------------------------------------------------------------------- well-known administration and login pages

@dataclass(frozen=True)
class Page:
    key: str
    path: str
    label: str
    # (regex over the body and title, severity, label suffix) tried in order; the first that matches names the finding
    rules: tuple
    statuses: tuple = (200,)
    guard_catch_all: bool = False  # a page that looks like the front page is a single-page app answering everything: not a finding


WELL_KNOWN = (
    Page('wp_login', '/wp-login.php', 'WordPress login', ((r'id=["\']loginform["\']|name=["\']log["\']|wp-submit', LOW, ''),)),
    Page('joomla_admin', '/administrator/', 'Joomla administrator login', ((r'Joomla|mod-login|name=["\']passwd["\']', LOW, ''),)),
    Page('phpmyadmin', '/phpmyadmin/', 'phpMyAdmin', ((r'phpMyAdmin', MEDIUM, ''),)),
    Page('tomcat_manager', '/manager/html', 'Apache Tomcat Manager', ((r'Tomcat Web Application Manager', CRITICAL, ''), (r'Tomcat Manager', MEDIUM, '')),
         statuses=(200, 401)),
    Page('server_status', '/server-status', 'Apache server status page', ((r'Apache Server Status', MEDIUM, ''),)),
    Page('login', '/login', 'login page', ((r'Jenkins', MEDIUM, 'Jenkins'), (r'Grafana', LOW, 'Grafana'))),
    Page('solr', '/solr/', 'Apache Solr admin', ((r'Solr Admin', HIGH, ''),)),
    Page('console', '/console/', 'web console', ((r'H2 Console', CRITICAL, 'H2'), (r'WebLogic Server Administration Console|Oracle WebLogic', MEDIUM, 'WebLogic'))),
    Page('owa', '/owa/', 'Outlook on the web login', ((r'Outlook Web App|OutlookWebApp|owaLogon', LOW, ''),), statuses=(200, 302)),
    Page('fortinet', '/remote/login', 'Fortinet SSL VPN login', ((r'FortiGate|fortinet|/remote/logincheck', LOW, ''),)),
    Page('admin', '/admin/', 'administration login', ((r'<input[^>]{0,200}type=["\']password["\']', LOW, ''),), guard_catch_all=True),
)
PATHS = tuple(page.path for page in WELL_KNOWN)


def exposed_postures(domain, scheme, results, front=None):
    """``(postures, evaluated)`` for the well-known pages. ``results`` maps a path of ``WELL_KNOWN`` to its response (or None when the request
    failed). A page counts only when its status is one the page uses and what it says matches the product's own wording, so a catch-all
    "200 for everything" is not a finding. ``front`` is the front page's response, for the catch-all comparison."""
    from cveFeed import vhost_scan
    out, evaluated = [], set()
    for page in WELL_KNOWN:
        response = results.get(page.path)
        if not answered(response):
            continue
        evaluated.add(f'exposed_{page.key}')
        status = response.get('status') or 0
        if status not in page.statuses:
            continue
        text = ' '.join(((response.get('title') or ''), (response.get('www_authenticate') or ''), (response.get('body') or '')[:65536]))
        if page.key == 'login' and any(k in _headers(response) for k in ('x-jenkins',)):
            text += ' Jenkins'
        for pattern, severity, suffix in page.rules:
            if not re.search(pattern, text, re.IGNORECASE):
                continue
            if page.guard_catch_all and front and answered(front) and vhost_scan.similar(vhost_scan.fingerprint_of(response), vhost_scan.fingerprint_of(front)):
                break
            if page.key == 'tomcat_manager' and status == 401 and severity == CRITICAL:
                severity = MEDIUM
            label = f'{page.label} ({suffix})' if suffix else page.label
            key = f'exposed_{page.key}' + (f'_{suffix.lower()}' if suffix else '')
            url = f'{scheme}://{domain}{page.path}'
            out.append(Posture(key, severity, f'{label} is reachable from the internet at {domain}{page.path}',
                               f'A plain GET of {url} answered with status {status} and the page identifies itself as {label}. '
                               'An administration or login page on the public internet is a target for password guessing and for the product\'s '
                               'known flaws.', 'exposed', domain, ask_for('exposed_', domain), {'url': url, 'status': status, 'path': page.path}))
            break
    return out, evaluated


# ----------------------------------------------------------------------------- the technology stack (the host card)

def technologies_of(fingerprints):
    """The technology list of a host card from ``route_auth.classify``'s fingerprints (``[{'name': 'PHP:8.1.2', 'source': 'header:x-powered-by'}]``,
    the same fingerprinting owned hosts use): ``[{'name', 'version', 'category', 'source'}]``, version '' when the response states none."""
    from cveFeed import correlation, fingerprint
    out = []
    for found in fingerprints or []:
        name, version = correlation.split_name_version(found.get('name') or '')
        if name:
            out.append({'name': name[:80], 'version': version[:60], 'category': fingerprint.categorize(found['name']), 'source': str(found.get('source', ''))[:40]})
    return out


def tech_text(technologies, *banners):
    """The lowercase text the technology search reads: every technology name and version, then the raw banners (Server, X-Powered-By)."""
    parts = [f'{t["name"]} {t["version"]}'.strip() for t in technologies]
    parts += [str(b) for b in banners if b]
    return '\n'.join(p.lower() for p in parts)


def observations_of(technologies):
    """The shape ``cve_postures`` reads, from a card's technologies."""
    return [{'kind': 'version', 'product': t['name'], 'version': t['version'], 'source': t['source'], 'outcome': 'found' if t['version'] else 'hidden'}
            for t in technologies]


# ----------------------------------------------------------------------------- announced products and the CVE catalog (secondary: informational)

def _slug(text):
    return re.sub(r'[^a-z0-9]+', '_', (text or '').lower()).strip('_')[:30]


def cve_severity(cve):
    """A catalog CVE as a severity: the CVSS band, and a CISA KEV listing makes it critical."""
    if getattr(cve, 'kev', None):
        return CRITICAL
    cvss = getattr(cve, 'cvss', None)
    if cvss is None or cvss <= 0:
        return MEDIUM
    return CRITICAL if cvss >= 9 else HIGH if cvss >= 7 else MEDIUM if cvss >= 4 else LOW


def _cve_row(cve):
    return {'id': cve.cve_id, 'cvss': cve.cvss, 'kev': bool(cve.kev), 'severity': level(cve_severity(cve))}


def cve_postures(domain, observations, pool, edge=False, distro=''):
    """The known-CVE findings of the products a response announces. ``observations`` are ``probes.observations_from_page`` rows; ``pool`` is
    ``(cve_by_id, product_index)`` of ``correlation.cve_pool``. One finding per announced product and version, naming its CVEs, worst first.
    With an ``edge`` in front, the Server and Via headers describe the edge and are not matched. Returns ``(postures, matched)``, where
    ``matched`` lists every announced ``name:version`` that was looked up."""
    from cveFeed import correlation, match_policy
    cve_by_id, index = pool
    out, looked_up, seen = [], [], set()
    for obs in observations:
        if len(seen) >= MAX_CVE_PRODUCTS:
            break
        if obs.get('kind') != 'version' or obs.get('outcome') != 'found' or not obs.get('version'):
            continue
        if edge and obs.get('source') in ('header:server', 'header:via'):
            continue
        name, version = obs['product'], obs['version']
        token = correlation._norm(name)
        ver = correlation.parse_version(version)
        if ver is None or len(token) < correlation._MIN_TOKEN or match_policy.is_os_sighting(name) or (token, version) in seen:
            continue
        seen.add((token, version))
        looked_up.append(f'{name}:{version}')
        details, hits = {}, []
        for cve, _matched, in_range in correlation._match_candidates(name, ver, token, index, cve_by_id, details=details):
            # the same evidence rule as owned hosts, and stricter: a version inside a bounded range, never "older than every listed branch"
            if in_range is True and match_policy.hard_version_evidence(in_range, details.get(cve.id)):
                hits.append(cve)
        if not hits:
            continue
        hits.sort(key=lambda c: (-cve_severity(c), -(c.cvss or 0), c.cve_id))
        severity = cve_severity(hits[0])
        if distro:
            severity = max(LOW, severity - 1)
        worst = hits[0]
        display = f'{name} {version}'
        suffix = f' ({distro} build: fixes may be backported)' if distro else ''
        title = (f'{display} is announced on {domain} and has {len(hits)} known CVE{"s" if len(hits) != 1 else ""} '
                 f'(worst: {worst.cve_id}, {level(cve_severity(worst))}){suffix}')
        detail = (f'The service at {domain} announces {display} (from its {obs.get("source", "response")}). The version is inside the affected range of '
                  f'{len(hits)} CVE{"s" if len(hits) != 1 else ""} in the catalog. ' + NO_VALIDATION)
        out.append(Posture(f'cve_{_slug(name)}', severity, title[:300], detail, 'cve', domain,
                           ask_for('cve_', domain), {'product': name, 'version': version, 'announced_by': obs.get('source', ''), 'distro': distro,
                                                     'total_cves': len(hits), 'cves': [_cve_row(c) for c in hits[:MAX_CVES_LISTED]],
                                                     'validated': False, 'validation': NO_VALIDATION}))
    return out, looked_up


# ----------------------------------------------------------------------------- the text to send the supplier

def stack_line(card):
    """One host card's stack as text: ``name version`` for each technology, in the order the fingerprinting found them."""
    return ', '.join(f'{t["name"]} {t["version"]}'.strip() for t in (card.technologies or []))


def _tech_label(t):
    return f'{t["name"]} {t["version"]}'.strip()


def share_text(supplier, findings, cards=(), tech=''):
    """A plain-text message about one supplier, to copy and send. It lists the technology the supplier's public services announce (asking for
    the patch level; with ``tech`` it asks about the matching technology first) and the open findings with what to ask. It never names this
    installation, the project or a person, and states that the checks were passive."""
    lines = [f'Security posture summary for {supplier.name}', '']
    stamp = getattr(supplier, 'last_checked_at', None)
    lines.append(f'Checked: {stamp:%Y-%m-%d}' if stamp else 'Checked: not yet')
    lines.append(f'Names reviewed: {", ".join(supplier.domains)}' if supplier.domains else 'Names reviewed: none')
    lines.append('Method: passive checks of the supplier\'s public services only (what a browser or a TLS client is given: the certificate, the '
                 'response headers and page, email authentication records and a short list of well-known pages). Nothing was exploited or tested for weaknesses.')
    wanted = [t.strip().lower() for t in str(tech or '').split(',') if t.strip()]
    shown = [c for c in cards if stack_line(c)]
    if shown:
        lines.append('')
        hits = [(c, [t for t in c.technologies if any(w in _tech_label(t).lower() for w in wanted)]) for c in shown] if wanted else []
        hits = [(c, ts) for c, ts in hits if ts]
        if hits:
            lines.append('Your public services announce the following; please confirm each is on a supported, fully patched version:')
            for c, ts in hits:
                lines.append(f'- {c.domain}: {", ".join(_tech_label(t) for t in ts)}')
            lines.append('')
        lines.append('Technology visible from the outside (as announced by the services themselves):')
        for c in shown:
            lines.append(f'- {c.domain}: {stack_line(c)}')
        lines.append('Please confirm these are on supported, patched versions, or tell us where they are wrong (a version shown may be a distribution build with fixes backported).')
    open_rows = sorted((f for f in findings if f.status == 'open'), key=lambda f: (-f.severity, f.domain, f.check_name))
    lines.append('')
    if not open_rows:
        lines.append('No open findings at the time of the last check.')
        return '\n'.join(lines) + '\n'
    lines.append(f'Open findings ({len(open_rows)}):')
    for number, row in enumerate(open_rows, 1):
        lines.append('')
        lines.append(f'{number}. [{level(row.severity).upper()}] {row.title}')
        if row.detail:
            lines.append(f'   What we saw: {" ".join(row.detail.split())}')
        if row.ask:
            lines.append(f'   What we ask: {row.ask}')
        lines.append(f'   First seen: {row.first_seen:%Y-%m-%d}')
    lines.append('')
    lines.append('Please reply with the status of each item, or tell us if any is a false positive.')
    return '\n'.join(lines) + '\n'
