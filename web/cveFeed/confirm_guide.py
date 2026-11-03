"""How a person confirms ONE match by hand: where to look, what to look for, the exact read-only steps with the real host, port and URL,
how to read the answer, what proves exploitability beyond the version, and how to fix it.

The shared per-CVE record (cveFeed.detection) says how to check a CVE anywhere; this says how to check it HERE, from what the match itself
recorded: the script URL the page loaded and every copy of the library on it, the port and banner nmap read, the header or path a probe
read, the plugin WPScan found, the testssl test that fired, the nuclei template that matched.

Safety. Every command is built here, by code, from values validated on the way in: a host name or IP address, a port number, an http(s)
URL whose characters are checked, a version string, a plugin slug, a template id, and fixed constants. Each is shell-quoted. Text that came
from a scanned host or a feed (a banner, a header, a page's text, a testssl or nuclei line, the CVE description) is never put in a command:
it is returned as ``quote`` data, marked untrusted, for a person to compare. Every step only reads: a GET or HEAD request, a banner read, a
package listing, a grep, a console expression that runs only in the tester's own browser tab. Nothing is ever sent that changes a target,
and no exploit payload is ever generated, by rules or by a model."""
import ipaddress
import re
import shlex
from urllib.parse import urlsplit, urlunsplit

GUIDE_VERSION = 1
NOTICE = ('Commands are built by cvENGINE from this match\'s own host, port and URL and only read. Anything marked "seen on the host" or '
          '"advisory text" is data from the scanned host or a feed: compare it, never run it.')
_DNS = re.compile(r'^(?=.{1,253}$)[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?)*\.?$')
# the URL characters a script or page address uses. Quotes, ``$``, ``;``, parentheses, ``!`` and ``*`` are legal in a URL but never needed
# there unencoded: a URL that carries one is refused, so even a shell-quoted copy of it never reads like a command
_URL_CHARS = re.compile(r"^[A-Za-z0-9\-._~:/?#\[\]@&+,=%]{1,2000}$")
_VERSION = re.compile(r'^[0-9][0-9A-Za-z.+~:_-]{0,63}$')
_SLUG = re.compile(r'^[a-z0-9][a-z0-9_.-]{0,99}$')
_TEMPLATE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')
_CVE = re.compile(r'^CVE-\d{4}-\d{4,12}$')
_OID = re.compile(r'^[0-9]+(\.[0-9]+){3,40}$')
_PURL = re.compile(r'^pkg:([a-z0-9.+-]{1,20})/([A-Za-z0-9._~%@/+-]{1,200})@([A-Za-z0-9._~%+:-]{1,80})(?:[?#].*)?$')

# testssl.sh test id -> its own option for running only that test (testssl.sh 3.x)
TESTSSL_FLAGS = {'heartbleed': '--heartbleed', 'CCS': '--ccs-injection', 'ticketbleed': '--ticketbleed', 'ROBOT': '--robot',
                 'secure_client_renego': '--renegotiation', 'secure_renego': '--renegotiation', 'CRIME_TLS': '--crime',
                 'POODLE_SSL': '--poodle', 'FREAK': '--freak', 'DROWN': '--drown', 'LOGJAM': '--logjam', 'winshock': '--winshock',
                 'SWEET32': '--sweet32', 'RC4': '--rc4', 'BEAST': '--beast', 'LUCKY13': '--lucky13', 'BREACH': '--breach'}
STARTTLS = {25: 'smtp', 587: 'smtp', 143: 'imap', 110: 'pop3', 21: 'ftp', 389: 'ldap', 5432: 'postgres', 3306: 'mysql'}
# a product's own version command on the host (constants)
HOST_VERSION_COMMANDS = (
    (re.compile(r'\bnginx\b|openresty', re.I), 'nginx -v', 'Prints the nginx version the binary was built as.'),
    (re.compile(r'apache http|\bhttpd\b|apache httpd|^apache$', re.I), 'apache2ctl -v 2>/dev/null || httpd -v',
     'Prints the Apache httpd version (apache2ctl on Debian and Ubuntu, httpd on Red Hat).'),
    (re.compile(r'\bphp\b', re.I), 'php -v', 'Prints the PHP version of the command-line binary (the web server\'s PHP is usually the same package).'),
    (re.compile(r'openssh', re.I), 'ssh -V', 'Prints the OpenSSH version of the installed client, which ships with the server.'),
    (re.compile(r'openssl', re.I), 'openssl version', 'Prints the OpenSSL version.'),
    (re.compile(r'lighttpd', re.I), 'lighttpd -v', 'Prints the lighttpd version.'),
)
# how a product names itself in a Server or X-Powered-By header
HEADER_TOKENS = ((re.compile(r'openresty', re.I), 'openresty'), (re.compile(r'nginx', re.I), 'nginx'),
                 (re.compile(r'apache http|httpd|^apache$', re.I), 'Apache'), (re.compile(r'\bphp\b', re.I), 'PHP'),
                 (re.compile(r'\biis\b|internet information', re.I), 'Microsoft-IIS'), (re.compile(r'lighttpd', re.I), 'lighttpd'),
                 (re.compile(r'litespeed', re.I), 'LiteSpeed'), (re.compile(r'jetty', re.I), 'Jetty'))
# distribution security trackers, by what the banner says the host runs (the banner only chooses among these constants)
TRACKERS = (
    (re.compile(r'ubuntu', re.I), 'Ubuntu', 'https://ubuntu.com/security/{cve}', 'dpkg'),
    (re.compile(r'debian|deb\d', re.I), 'Debian', 'https://security-tracker.debian.org/tracker/{cve}', 'dpkg'),
    (re.compile(r'\.el\d|red ?hat|rhel|centos|rocky|alma', re.I), 'Red Hat', 'https://access.redhat.com/security/cve/{cve}', 'rpm'),
    (re.compile(r'suse|sles', re.I), 'SUSE', 'https://www.suse.com/security/cve/{cve}.html', 'rpm'),
    (re.compile(r'alpine', re.I), 'Alpine', 'https://security.alpinelinux.org/vuln/{cve}', 'apk'),
)

# What exploiting a few of the most common library CVEs needs, and a harmless console self-test where one exists. Curated and reviewed by
# hand: never generated. A self-test runs only in the tester's own browser tab, reads or sets nothing on the server, and executes no script.
# ``review`` is an extended regular expression that finds the calls a page's own code makes to the affected functions.
_DOM_SINKS = r'\.(html|append|prepend|after|before|replaceWith|wrap|wrapAll|wrapInner)\('
CURATED = {
    'CVE-2015-9251': {'library': 'jquery', 'needs': 'the page makes a cross-domain jQuery.ajax (or $.get) request without a dataType option '
                      'to a server an attacker controls, whose text/javascript answer jQuery then runs', 'review': r'\$\.(ajax|get|getJSON)\(|jQuery\.(ajax|get|getJSON)\('},
    'CVE-2019-11358': {'library': 'jquery', 'needs': 'the page deep-merges an object parsed from untrusted input with jQuery.extend(true, ...) '
                       '(for example a JSON body or a query string turned into an object)', 'review': r'\.extend\(\s*true',
                       'self_test': {'expression': '(function () { jQuery.extend(true, {}, JSON.parse(\'{"__proto__": {"cvengineSelfTest": true}}\')); '
                                                   'var hit = ({}).cvengineSelfTest === true; delete Object.prototype.cvengineSelfTest; '
                                                   'return hit ? "affected: a deep extend copied __proto__" : "not affected"; })()',
                                     'reads': 'Prints "affected" when this jQuery copies a __proto__ key onto Object.prototype (the flaw), '
                                              '"not affected" on 3.4.0 or later. It removes the property it set before it returns.'}},
    'CVE-2020-7656': {'library': 'jquery', 'needs': 'the page calls .load() with a URL whose HTML answer an attacker controls (a <script> tag '
                      'with whitespace before ">" is not stripped)', 'review': r'\.load\('},
    'CVE-2020-11022': {'library': 'jquery', 'needs': 'the page passes HTML from an untrusted source, even sanitized, to .html(), .append() or '
                       'another DOM manipulation method', 'review': _DOM_SINKS,
                       'self_test': {'expression': 'typeof jQuery.htmlPrefilter === "function" ? jQuery.htmlPrefilter("<div/><span/>") : '
                                                   '"no htmlPrefilter: jQuery older than 1.12.0 / 2.2.0"',
                                     'reads': 'Prints "<div></div><span></span>" when this jQuery still expands self-closing tags (the behaviour '
                                              'the 3.5.0 fix removed), "<div/><span/>" on 3.5.0 or later. Only a string is processed.'}},
    'CVE-2020-11023': {'library': 'jquery', 'needs': 'the page passes HTML containing <option> elements from an untrusted source, even '
                       'sanitized, to .html(), .append() or another DOM manipulation method', 'review': _DOM_SINKS},
    'CVE-2021-41182': {'library': 'jquery-ui', 'needs': 'the page sets the Datepicker altField option from an untrusted source',
                       'review': r'altField'},
    'CVE-2021-41183': {'library': 'jquery-ui', 'needs': 'the page sets a Datepicker *Text option (closeText, currentText, prevText, nextText, '
                       'appendText, buttonText) from an untrusted source', 'review': r'(closeText|currentText|prevText|nextText|appendText|buttonText)'},
    'CVE-2021-41184': {'library': 'jquery-ui', 'needs': 'the page passes the of option of .position() from an untrusted source',
                       'review': r'\.position\('},
    'CVE-2022-31160': {'library': 'jquery-ui', 'needs': 'the page calls .checkboxradio("refresh") on an input whose label contains HTML-encoded '
                       'text from an untrusted source', 'review': r'checkboxradio'},
}
FIX_NOTES = {'jquery': 'jQuery 3.5 and later parse HTML strings more strictly: test the page, and load jQuery Migrate 3.x while you do, '
                       'which logs code that relied on the old behaviour.'}


# --- validated values ------------------------------------------------------------------------------------------------------------------

def _host(name):
    """``name`` as a host name or IP address safe to put in a command and a URL, or ''."""
    text = str(name or '').strip().lower().rstrip('.')
    if not text or len(text) > 253:
        return ''
    try:
        return str(ipaddress.ip_address(text)) if '%' not in text else ''
    except ValueError:
        pass
    return text if _DNS.match(text) else ''


def _port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        return 0
    return port if 1 <= port <= 65535 and not isinstance(value, bool) else 0


def _url(value):
    """``value`` as an http(s) URL with a valid host, port and only URL characters, or ''. The URL may come from a scanned page: it is used
    as a link and as one shell-quoted argument, never otherwise."""
    text = str(value or '').strip()
    if not text or not _URL_CHARS.match(text):
        return ''
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return ''
    if parts.scheme not in ('http', 'https') or parts.username or parts.password or not parts.hostname:
        return ''
    host = _host(parts.hostname)
    if not host:
        return ''
    if ':' in host:
        host = f'[{host}]'
    netloc = host + (f':{port}' if port else '')
    return urlunsplit((parts.scheme, netloc, parts.path or '/', parts.query, ''))


def _version(value):
    """The version a match recorded, validated: its first word (``8.9p1`` of ``8.9p1 Ubuntu 3ubuntu0.10``, whose distribution part is shown
    as quoted banner text instead), or ''."""
    words = str(value or '').strip().split()
    text = words[0] if words else ''
    return text if _VERSION.match(text) else ''


def _q(value):
    return shlex.quote(str(value))


def _quote(text, limit=300):
    """Text from a scanned host or a feed, cleaned of control characters and capped: shown, never run."""
    from reNgine.ai_providers import clean_text
    return clean_text(str(text or ''), limit) or ''


def _base(scheme, host, port):
    name = f'[{host}]' if ':' in host else host
    default = 443 if scheme == 'https' else 80
    return f'{scheme}://{name}' + ('' if port in (0, default) else f':{port}')


# --- the pieces of a guide -------------------------------------------------------------------------------------------------------------

def _step(title, detail='', command='', run_in='shell', url=''):
    out = {'title': title, 'run_in': run_in}
    if detail:
        out['detail'] = detail
    if command:
        out['command'] = command
    if url:
        out['url'] = url
    return out


def _range_of(match):
    rng = (match.evidence or {}).get('range') if isinstance(match.evidence, dict) else None
    rng = rng if isinstance(rng, dict) else {}
    out = {}
    for src, dst in (('introduced', 'introduced'), ('fixed', 'fixed'), ('lastAffected', 'last_affected'), ('last_affected', 'last_affected')):
        version = _version(rng.get(src))
        if version and version not in ('0', '0.0', '0.0.0'):
            out[dst] = version
    return out


def _range_words(rng):
    if rng.get('introduced') and rng.get('fixed'):
        return f"from {rng['introduced']} up to but not including {rng['fixed']}"
    if rng.get('fixed'):
        return f"before {rng['fixed']}"
    if rng.get('introduced') and rng.get('last_affected'):
        return f"from {rng['introduced']} through {rng['last_affected']}"
    if rng.get('last_affected'):
        return f"up to {rng['last_affected']}"
    return 'in the range the advisory names'


def _verdict(product, version, rng, where, cant_tell, extra_not=''):
    fixed = rng.get('fixed')
    affected = (f'{where} states {product} {version or "a version"} {_range_words(rng)}: the version is affected.')
    if fixed:
        not_affected = f'{where} states {fixed} or later' + (f', or {extra_not}' if extra_not else '') + ': not affected.'
    elif rng.get('last_affected'):
        not_affected = f"{where} states a version after {rng['last_affected']}" + (f', or {extra_not}' if extra_not else '') + ': not affected.'
    else:
        not_affected = (extra_not[0].upper() + extra_not[1:] + ': not affected.') if extra_not else 'The version is outside the advisory range: not affected.'
    return {'fixed': fixed or '', 'affected_range': _range_words(rng), 'affected': affected, 'not_affected': not_affected, 'cant_tell': cant_tell}


def _strategy(cve):
    from cveFeed import detection
    row = getattr(cve, 'detection', None)
    if row is None or not row.strategy:
        return {}
    clean, _ = detection.validate_strategy(row.strategy)
    return clean or {}


def _precondition(cve, strategy):
    """The advisory's own words for what must hold (quoted data), with the curated reading of it where there is one."""
    from cveFeed.detection_classes import exploit_precondition
    text = strategy.get('exploit_precondition') or exploit_precondition(cve.original_description or cve.summary or '')
    curated = CURATED.get(cve.cve_id, {})
    if not text and not curated:
        return None
    out = {'source': 'advisory text', 'quote': _quote(text, 300)} if text else {'source': 'cvENGINE'}
    if curated.get('needs'):
        out['needs'] = f"Exploitable only when {curated['needs']}."
    return out


def _tracker_links(cve_id, hint=''):
    if not _CVE.match(cve_id or ''):
        return []
    hits = [t for t in TRACKERS if t[0].search(hint or '')]
    return [{'label': f'{name} security tracker for {cve_id}', 'url': url.format(cve=cve_id)} for _r, name, url, _e in (hits or TRACKERS[:3])]


def _host_version_step(product):
    for pattern, command, explain in HOST_VERSION_COMMANDS:
        if pattern.search(product or ''):
            return {'platform': 'linux', 'command': command, 'explain': explain}
    return None


def _os_package_commands(product, hint=''):
    """Read-only commands that print the installed OS package of ``product`` (its binary package name for each distribution family)."""
    from cveFeed.detection_classes import os_package_name
    out = []
    families = [t[3] for t in TRACKERS if t[0].search(hint or '')] or ['dpkg', 'rpm']
    for eco in dict.fromkeys(families):
        name = os_package_name(product, eco)
        if not name:
            continue
        if eco == 'dpkg':
            out.append({'platform': 'debian', 'command': f"dpkg-query -W -f='${{Package}} ${{Version}}\\n' {_q(name)}",
                        'explain': f'Prints the installed {name} package release (Debian and Ubuntu). Compare it with the fixed release '
                                   'the distribution\'s tracker lists for this CVE, not with the upstream version.'})
        elif eco == 'rpm':
            out.append({'platform': 'rhel', 'command': f"rpm -q --qf '%{{NAME}} %{{VERSION}}-%{{RELEASE}}\\n' {_q(name)}",
                        'explain': f'Prints the installed {name} version-release (Red Hat, SUSE). Compare it with the fixed build in the '
                                   'vendor\'s advisory for this CVE.'})
        elif eco == 'apk':
            out.append({'platform': 'alpine', 'command': f'apk info -v {_q(name)}', 'explain': f'Prints the installed {name} package.'})
    return out


def _review_step(cve_id):
    curated = CURATED.get(cve_id, {})
    if not curated.get('review'):
        return None
    return {'platform': 'app', 'command': f"grep -rnE --include='*.js' --exclude='*.min.js' {_q(curated['review'])} .",
            'explain': 'Lists the calls the site\'s own scripts make to the affected functions (run in the site\'s source or web root; the '
                       'library\'s own files are skipped). Each one fed with untrusted input is what makes the page exploitable.'}


def _template_section(match, host, bases):
    """What a nuclei template that ran on this match did: its id and a link to it, the request and what matched (quoted)."""
    from cveFeed.templategen import OTHER_TESTERS
    template_id = str(match.template_id or '')
    if not match.template_result or not template_id or re.match(OTHER_TESTERS, template_id) or not _TEMPLATE.match(template_id):
        return None
    out = {'template_id': template_id, 'result': match.template_result}
    try:
        from cveFeed.templategen import GENERATED_DIR, TEMPLATES_ROOT, find_existing_template
        import os
        for path in find_existing_template(match.cve_entry.cve_id):
            stem = os.path.splitext(os.path.basename(path))[0]
            if stem.lower() != template_id.lower():
                continue
            if path.startswith(TEMPLATES_ROOT.rstrip('/') + '/'):
                rel = path[len(TEMPLATES_ROOT.rstrip('/')) + 1:]
                if re.match(r'^[A-Za-z0-9._/-]{1,300}$', rel) and '..' not in rel:
                    out['template_url'] = f'https://github.com/projectdiscovery/nuclei-templates/blob/main/{rel}'
            elif path.startswith(GENERATED_DIR.rstrip('/') + '/'):
                out['generated'] = True
            break
    except Exception:  # noqa: BLE001 - a missing templates directory only costs the link
        pass
    if 'template_url' not in out and not out.get('generated'):
        out['template_search_url'] = f'https://github.com/projectdiscovery/nuclei-templates/search?q={template_id}'
    target = bases[0] if bases else (f'https://{host}' if host else '')
    if target:
        out['command'] = f'nuclei -duc -id {_q(template_id)} -u {_q(target)}'
    try:
        from startScan.models import Vulnerability
        vuln = (Vulnerability.objects.filter(subdomain__name=match.subdomain.name, cve_ids__name__iexact=match.cve_entry.cve_id,
                                             template_id=template_id).order_by('-discovered_date').first() if match.subdomain_id else None)
    except Exception:  # noqa: BLE001
        vuln = None
    if vuln is not None:
        if _url(vuln.http_url):
            out['matched_at'] = _url(vuln.http_url)
        if vuln.matcher_name:
            out['matcher'] = _quote(vuln.matcher_name, 120)
        if vuln.request:
            out['request'] = _quote(vuln.request, 800)
        extracted = [_quote(x, 120) for x in (vuln.extracted_results or [])[:5] if x]
        if extracted:
            out['extracted'] = extracted
    return out


# --- per class -------------------------------------------------------------------------------------------------------------------------

def _web_bases(sub):
    try:
        from cveFeed.route_auth import web_bases
        return [b.rstrip('/') for b in (_url(x) for x in web_bases(sub, limit=4)) if b]
    except Exception:  # noqa: BLE001
        return []


def _library_pages(match, host, script_url):
    """The pages cvENGINE read that load ``script_url``: the front-page rows of the route check and the html-libraries probe."""
    from cveFeed.models import ProbeObservation, RouteAuth
    project_id = match.subdomain.target_domain.project_id if match.subdomain and match.subdomain.target_domain_id else None
    pages = []
    if not project_id or not host:
        return pages
    for row in RouteAuth.objects.filter(project_id=project_id, host=host, path='/').only('url', 'evidence').order_by('-checked_at')[:6]:
        libraries = (row.evidence or {}).get('libraries') if isinstance(row.evidence, dict) else None
        for record in (libraries or {}).values() if isinstance(libraries, dict) else []:
            if isinstance(record, dict) and any(isinstance(c, dict) and c.get('url') == script_url for c in record.get('copies') or []):
                if _url(row.url) and _url(row.url) not in pages:
                    pages.append(_url(row.url))
    for row in ProbeObservation.objects.filter(project_id=project_id, host=host, probe='html-libraries').only('url', 'port', 'evidence')[:6]:
        record = (row.evidence or {}).get('library') if isinstance(row.evidence, dict) else None
        if isinstance(record, dict) and any(isinstance(c, dict) and c.get('url') == script_url for c in record.get('copies') or []):
            path = row.url if str(row.url or '').startswith('/') else '/'
            port = _port(row.port)
            page = _url(_base('https' if port in (0, 443, 8443) else 'http', host, port) + path)
            if page and page not in pages:
                pages.append(page)
    return pages


def _client_library(match, cve, strategy, host, bases, key):
    from cveFeed.detection import _libraries
    from cveFeed.detection_classes import LIBRARY_FACTS, console_expression, ECOSYSTEM_LABELS, LANGUAGE
    from cveFeed.detection_commands import _bundled_commands, _package_commands
    product = _libraries()[key][0]
    ev = match.evidence if isinstance(match.evidence, dict) else {}
    version = _version(match.matched_version)
    rng = _range_of(match)
    script_url = _url(ev.get('script_url'))
    copies = [c for c in ev.get('copies') or [] if isinstance(c, dict)][:8]
    body_read = ev.get('version_source') == 'body'
    pages = _library_pages(match, host, ev.get('script_url')) if script_url else []
    page = pages[0] if pages else (bases[0] + '/' if bases else '')
    where = []
    if script_url:
        where.append({'label': f'The {product} file the page loads', 'url': script_url})
    if page:
        where.append({'label': 'The page that loads it', 'url': page})
    for other in pages[1:4]:
        where.append({'label': 'Another page that loads it', 'url': other})
    others = []
    for copy in copies:
        url = _url(copy.get('url'))
        if not url or url == script_url:
            continue
        state = str(copy.get('state') or '')
        label = f"Another {product} copy on the page: {_version(copy.get('version')) or 'version not stated'}" + (f' ({state})' if state in (
            'effective', 'shadowed', 'fallback', 'unresolved') else '')
        others.append({'label': label, 'url': url})
    where += others[:6]
    banner = LIBRARY_FACTS.get(key, {}).get('banner', '').format(version=version or 'x.y.z')
    look_for = []
    if banner:
        look_for.append({'label': f"The file's first comment line (what cvENGINE {'read' if body_read else 'looks for'})", 'text': banner})
    state = str(ev.get('copy_state') or '')
    if state:
        look_for.append({'label': 'Which copy runs', 'text': {
            'effective': 'This copy loads last, so it is the one that runs (effective).',
            'shadowed': 'A later copy replaces this one (shadowed): older code or closures may still hold it.',
            'fallback': 'This copy loads only when an earlier script fails (a fallback).',
            'unresolved': 'The page loads several copies and cvENGINE could not tell which one runs.'}.get(state, state)})
    if not body_read:
        look_for.append({'label': 'How sure cvENGINE is', 'text': 'The version came from a file name, a CDN path or another tool, not from '
                                                                 'the file itself: open the file to confirm it.'})
    steps = []
    if script_url:
        steps.append(_step(f'Open the {product} file the page loads', 'Its first comment line states the version.', run_in='browser', url=script_url))
        steps.append(_step('Or read its first line from a shell', 'Prints the start of the file, where the banner is.',
                           f'curl -sS --max-time 20 {_q(script_url)} | head -c 300; echo'))
    elif page:
        steps.append(_step(f'List the {product} scripts the page loads', 'Each src that names the library is a copy to open.',
                           f"curl -sS --max-time 20 {_q(page)} | grep -oiE '<script[^>]+src=[^>]+>' | grep -i {_q(key.split('-')[0])}"))
    console = console_expression(key, version)
    if console and page:
        steps.append(_step('Ask the page which version runs', f'Open the page, open the browser\'s developer console (F12) and run the '
                           f'expression: it prints the {product} version of the copy that actually runs.', console, run_in='browser_console', url=page))
    self_test = CURATED.get(cve.cve_id, {}).get('self_test') if CURATED.get(cve.cve_id, {}).get('library') == key else None
    if self_test and page:
        steps.append(_step('Optional: a harmless self-test in your own browser', self_test['reads'] + ' It runs only in your browser tab, '
                           'changes nothing on the server and executes no script.', self_test['expression'], run_in='browser_console', url=page))
    precondition = _precondition(cve, strategy)
    local = []
    review = _review_step(cve.cve_id) if CURATED.get(cve.cve_id, {}).get('library') == key else None
    if review:
        local.append({'title': 'Find where the site\'s own code calls the affected functions', 'commands': [review]})
    local.append({'title': 'Find bundled copies on the web server', 'commands': _bundled_commands({'library': key})})
    components = [c for c in strategy.get('components', []) if c.get('library') == key]
    fixed = rng.get('fixed', '')
    deps = []
    bounds = {(c['params'].get('ecosystem'), c['params'].get('package')): c['params'].get('affected_below')
              for c in strategy.get('local_checks', []) if c['kind'] == 'package_version'}
    for coord in (components[0].get('coordinates', []) if components else []):
        if coord['ecosystem'] in LANGUAGE:
            bound = bounds.get((coord['ecosystem'], coord['package']))  # each packaging's own fix (jquery-rails 4.4.0 ships jQuery 3.5.0)
            for command in _package_commands({'ecosystem': coord['ecosystem'], 'package': coord['package'],
                                              **({'affected_below': bound} if bound else {})}):
                deps.append({**command, 'label': f"{ECOSYSTEM_LABELS[coord['ecosystem']]} {coord['package']}"})
    if not deps:
        for command in _package_commands({'ecosystem': 'npm', 'package': key, **({'affected_below': fixed} if fixed else {})}):
            deps.append({**command, 'label': f'npm {key}'})
    local.append({'title': "Find which packaging the application uses (run in its source or deployment directory)", 'commands': deps[:10]})
    cdn = bool(script_url) and any(h in (urlsplit(script_url).hostname or '') for h in ('googleapis.com', 'jsdelivr.net', 'cdnjs.cloudflare.com',
                                                                                         'unpkg.com', 'code.jquery.com', 'bootstrapcdn.com', 'aspnetcdn.com'))
    fix = (f"Load {product} {fixed} or later" if fixed else f'Load a fixed {product}') + (
        ': the file comes from a public CDN, so change the version in the script URL in the page\'s template (and its integrity hash)' if cdn
        else ': replace the bundled file, or update the packaging the application uses (above) and rebuild') + \
        '; then run Validate now to read the page again.' + (f" {FIX_NOTES[key]}" if key in FIX_NOTES else '')
    verdict = _verdict(product, version, rng, 'The file (or the console)',
                       'The file has no banner (minified with it stripped) and the console expression is undefined: the library may be '
                       'bundled under another name; search the file for its version string, or check the application\'s dependency tree.',
                       extra_not='the page no longer loads this copy')
    return {'class': 'client_library', 'class_label': f'Client-side JavaScript library ({product})',
            'headline': f'Confirm {product} {version} on {host}'.replace('  ', ' '), 'where': where, 'look_for': look_for, 'steps': steps,
            'verdict': verdict, 'precondition': precondition, 'local': [section for section in local if section['commands']], 'fix': fix}


def _probe_source(match, host, product, version):
    """``(source, port, path)`` of the probe or route-check fingerprint that read ``product`` ``version`` on ``host``: ``header:server``,
    ``header:x-powered-by``, ``body:nginx-error-page``, ... or ('', 0, '') when none was recorded."""
    from cveFeed.models import ProbeObservation, RouteAuth
    project_id = match.subdomain.target_domain.project_id if match.subdomain and match.subdomain.target_domain_id else None
    if not project_id:
        return '', 0, '', ''
    token = re.sub(r'[^a-z0-9]', '', (product or '').lower())[:12]
    for row in ProbeObservation.objects.filter(project_id=project_id, host=host, kind='version', version=version).only(
            'product', 'source', 'port', 'url')[:20]:
        name = re.sub(r'[^a-z0-9]', '', (row.product or '').lower())
        if token and (token in name or name[:8] in token):
            return str(row.source or ''), _port(row.port), (row.url if str(row.url or '').startswith('/') else ''), ''
    for row in RouteAuth.objects.filter(project_id=project_id, host=host, path='/').only('url', 'evidence').order_by('-checked_at')[:4]:
        for found in (row.evidence or {}).get('fingerprints') or [] if isinstance(row.evidence, dict) else []:
            if not isinstance(found, dict):
                continue
            name = re.sub(r'[^a-z0-9]', '', str(found.get('name') or '').lower())
            if token and token in name and version and version.replace('.', '') in name:
                return str(found.get('source') or ''), 0, '/', _url(row.url)
    return '', 0, '', ''


def _web_product(match, cve, strategy, host, bases):
    """A web server, runtime or application a fingerprint named (nginx, Apache, PHP, Tomcat, ...): the response header or page that states
    it, and the host package that decides when a distribution backports fixes."""
    product = str(match.matched_product or '')
    version = _version(match.matched_version)
    rng = _range_of(match)
    source, port, path, page = _probe_source(match, host, product, version)
    base = next((b for b in bases if port and (b.endswith(f':{port}') or (port == 443 and b.startswith('https://') and b.count(':') == 1)
                                                or (port == 80 and b.startswith('http://') and b.count(':') == 1))), bases[0] if bases else '')
    if not base and host:
        base = f'https://{host}'
    url = page or (_url(base + (path or '/')) if base else '')
    header = {'header:server': 'Server', 'header:x-powered-by': 'X-Powered-By', 'header:x-aspnet-version': 'X-AspNet-Version'}.get(source, '')
    where = [{'label': 'Where cvENGINE read it', 'url': url}] if url else []
    look_for = []
    steps = []
    if source.startswith('body:') or source.startswith('title:'):
        look_for.append({'label': 'What states the version', 'text': f'The page body of {path or "/"} ({source.split(":", 1)[1].replace("-", " ")}) '
                                                                    f'names {product} {version}.'})
        if url:
            steps.append(_step('Fetch that page and find the version', f'Look for "{version}" in the footer or title.',
                               f'curl -sS --max-time 15 {_q(url)} | grep -n -F -e {_q(version)}' if version else f'curl -sS --max-time 15 {_q(url)}'))
    else:
        name = header or 'Server (or X-Powered-By for a runtime)'
        token = next((t for pattern, t in HEADER_TOKENS if pattern.search(product)), '')
        look_for.append({'label': 'The response header to read',
                         'text': f'{name.split(" ")[0]}: {token}/{version}' if token and version else f'{name} header naming {product} {version}'.strip()})
        if url:
            steps.append(_step(f'Read the {name.split(" ")[0]} header', 'HEAD request only; the header line states the product and version.',
                               f'curl -sS -I --max-time 15 {_q(url)}' + (f" | grep -i -e {_q('^' + header + ':')}" if header else '')))
    local = []
    version_cmd = _host_version_step(product)
    if version_cmd:
        local.append({'title': 'On the host: the version of the installed binary', 'commands': [version_cmd]})
    packages = _os_package_commands(product)
    if packages:
        local.append({'title': 'On the host: the installed package release (a backported fix keeps the old upstream version)', 'commands': packages})
    verdict = _verdict(product, version, rng, 'The header (or the page)',
                       'The header hides the version or a CDN, proxy or load balancer answers instead: check the version on the host itself.',
                       extra_not="the host's package is listed as fixed by its distribution (a backport)")
    return {'class': 'web_server', 'class_label': f'Web server or runtime banner ({product})', 'headline': f'Confirm {product} {version} on {host}',
            'where': where, 'look_for': look_for, 'steps': steps, 'verdict': verdict, 'precondition': _precondition(cve, strategy),
            'local': local, 'links': _tracker_links(cve.cve_id),
            'fix': f"Upgrade {product} to {rng['fixed']} or later" + ' (or install the distribution\'s fixed package), then run Validate now.'
            if rng.get('fixed') else f'Upgrade {product} to a release the vendor lists as fixed, then run Validate now.'}


def _network_service(match, cve, strategy, host):
    ev = match.evidence if isinstance(match.evidence, dict) else {}
    product = str(match.matched_product or '')
    version = _version(match.matched_version) or ''
    rng = _range_of(match)
    ip = ''
    try:
        ip = str(ipaddress.ip_address(str(ev.get('ip') or ''))) if '%' not in str(ev.get('ip') or '') else ''
    except ValueError:
        ip = ''
    port = _port(ev.get('port'))
    udp = str(ev.get('protocol') or 'tcp').lower() == 'udp'
    target = host or ip
    banner_hint = ' '.join(str(ev.get(k) or '') for k in ('raw_version', 'service_extra', 'cpe'))
    where = [{'label': 'Service', 'text': f"{target}{f' ({ip})' if ip and ip != target else ''} port {port}/{'udp' if udp else 'tcp'}"}] if port else []
    look_for = []
    seen = ' '.join(x for x in (product, str(ev.get('raw_version') or '')) if x)
    if seen:
        look_for.append({'label': 'The banner nmap read (seen on the host)', 'quote': _quote(seen, 200)})
    if ev.get('service_extra'):
        look_for.append({'label': 'Extra service information (seen on the host)', 'quote': _quote(ev.get('service_extra'), 200)})
    if ev.get('cpe'):
        look_for.append({'label': 'CPE', 'quote': _quote(ev.get('cpe'), 120)})
    steps = []
    if port and (ip or host):
        addr = ip or host
        steps.append(_step('Read the service banner with nmap', f'The {product} line in the VERSION column is what cvENGINE matched.',
                           f"nmap -Pn {'-sU ' if udp else ''}-sV --version-intensity 5 -p {port} {_q(addr)}"))
        if not udp and re.search(r'ssh', product + ' ' + str(ev.get('service_extra') or ''), re.I):
            steps.append(_step('Or read the SSH greeting directly', 'The first line the server sends, for example SSH-2.0-OpenSSH_8.2p1 '
                               'Ubuntu-4ubuntu0.13, states the version and, after it, the distribution build.',
                               f'nc -w 5 {_q(addr)} {port} </dev/null | head -n 1'))
        elif not udp and (port in (80, 443, 8080, 8443) or re.search(r'http|nginx|apache|iis|tomcat|jetty', product, re.I)):
            scheme = 'https' if port in (443, 8443) else 'http'
            url = _url(_base(scheme, host or ip, port) + '/')
            if url:
                steps.append(_step('Or read the Server header', 'HEAD request only.', f'curl -sS -I --max-time 15 {_q(url)}'))
    local = []
    version_cmd = _host_version_step(product)
    if version_cmd:
        local.append({'title': 'On the host: the version of the installed binary', 'commands': [version_cmd]})
    packages = _os_package_commands(product, banner_hint)
    if packages:
        local.append({'title': 'On the host: the installed package release', 'commands': packages})
    from cveFeed.detection_classes import is_distro_build
    fixed = rng.get('fixed', '')
    distro_fix = is_distro_build(fixed)
    tracker = next((t for t in TRACKERS if t[0].search(banner_hint)), None)
    notes = []
    if distro_fix:
        notes.append(f'The advisory\'s fixed release {fixed} is a distribution\'s own package build: it applies only to that distribution '
                     'and release. Compare the host\'s package with its own distribution\'s tracker instead.')
    if tracker:
        notes.append(f'The banner names {tracker[1]}: a {tracker[1]} package can carry a backported fix while the banner keeps the upstream '
                     'version. Its security tracker decides.')
    verdict = _verdict(product, version, rng, 'The banner',
                       'The banner states no version, or a distribution build whose fix status the tracker must decide.',
                       extra_not="the host's package release is listed as fixed by its distribution (a backport)")
    if notes:
        verdict['notes'] = notes
    return {'class': 'network_service', 'class_label': f'Network service banner ({product})', 'headline': f'Confirm {product} {version} on {target}:{port}',
            'where': where, 'look_for': look_for, 'steps': steps, 'verdict': verdict, 'precondition': _precondition(cve, strategy),
            'local': local, 'links': _tracker_links(cve.cve_id, banner_hint),
            'fix': (f'Install the distribution\'s fixed {product} package (its tracker names the build), or upgrade to {fixed} or later where '
                    'it is built from source; restart the service and run Validate now.' if fixed and not distro_fix else
                    f'Install the fixed {product} package your distribution\'s tracker names for this CVE, restart the service and run Validate now.')}


def _cms(match, cve, strategy, host, bases):
    ev = match.evidence if isinstance(match.evidence, dict) else {}
    slug = str(ev.get('plugin') or '').lower()
    slug = slug if _SLUG.match(slug) and '..' not in slug else ''
    kind = 'theme' if ev.get('kind') == 'wp-theme' else 'plugin'
    version = _version(match.matched_version)
    rng = _range_of(match)
    base = bases[0] if bases else (f'https://{host}' if host else '')
    path = (f'/wp-content/themes/{slug}/style.css' if kind == 'theme' else f'/wp-content/plugins/{slug}/readme.txt') if slug else ''
    url = _url(base + path) if base and path else ''
    field = 'Version' if kind == 'theme' else 'Stable tag'
    where = [{'label': f'The {kind}\'s {"style.css" if kind == "theme" else "readme.txt"}', 'url': url}] if url else []
    look_for = [{'label': 'The line to read', 'text': f'{field}: {version or "x.y.z"}'}]
    steps = []
    if url:
        steps.append(_step(f'Open the {kind}\'s {"style.css" if kind == "theme" else "readme.txt"}', f'The "{field}:" line states the version '
                           'WPScan read.', run_in='browser', url=url))
        steps.append(_step('Or read that line from a shell', '', f"curl -sS --max-time 15 {_q(url)} | grep -i -m1 -E {_q('^[[:space:]]*' + field + ':')}"))
    local = []
    if slug:
        local.append({'title': 'On the WordPress server (WP-CLI, read-only)', 'commands': [
            {'platform': 'app', 'command': f'wp {kind} get {_q(slug)} --fields=name,status,version',
             'explain': f'Prints whether the {kind} is installed and active, and its version (run in the WordPress directory).'}]})
    verdict = _verdict(slug or str(match.matched_product), version, rng, f'The {kind}\'s {field} line',
                       f'The readme is missing or its {field} is "trunk": check the version in the WordPress admin ({kind.title()}s page).',
                       extra_not=f'the {kind} is not active')
    return {'class': 'cms_component', 'class_label': f'WordPress {kind}', 'headline': f'Confirm the {slug or "WordPress"} {kind} {version} on {host}',
            'where': where, 'look_for': look_for, 'steps': steps, 'verdict': verdict, 'precondition': _precondition(cve, strategy),
            'local': local, 'fix': (f'Update the {kind} to {rng["fixed"]} or later in the WordPress admin (or with wp {kind} update), then run '
                                    'Validate now.' if rng.get('fixed') else f'Update or remove the {kind}, then run Validate now.')}


def _wordpress_core(match, cve, strategy, host, bases):
    version = _version(match.matched_version)
    rng = _range_of(match)
    base = bases[0] if bases else (f'https://{host}' if host else '')
    feed = _url(base + '/feed/') if base else ''
    front = _url(base + '/') if base else ''
    steps = []
    if front:
        steps.append(_step('Read the generator tag of the front page', 'WordPress states its version there unless a plugin removes it.',
                           f"curl -sS --max-time 15 {_q(front)} | grep -o -i -E {_q('<meta name=.generator. content=.WordPress [0-9.]+')}"))
    if feed:
        steps.append(_step('Or read the feed\'s generator line', '', f"curl -sS --max-time 15 {_q(feed)} | grep -o -E {_q('wordpress.org/[?]v=[0-9.]+')}"))
    return {'class': 'cms_core', 'class_label': 'WordPress core', 'headline': f'Confirm WordPress {version} on {host}',
            'where': [{'label': 'The site', 'url': front}] if front else [],
            'look_for': [{'label': 'What states the version', 'text': f'<meta name="generator" content="WordPress {version or "x.y.z"}" /> '
                                                                      f'or https://wordpress.org/?v={version or "x.y.z"}'}],
            'steps': steps, 'verdict': _verdict('WordPress', version, rng, 'The generator tag', 'The generator tag is removed: check '
                                                'Dashboard > Updates, or wp-includes/version.php on the server.'),
            'precondition': _precondition(cve, strategy),
            'local': [{'title': 'On the WordPress server (WP-CLI, read-only)', 'commands': [
                {'platform': 'app', 'command': 'wp core version', 'explain': 'Prints the installed WordPress version (run in the WordPress directory).'}]}],
            'fix': f"Update WordPress to {rng['fixed']} or later, then run Validate now." if rng.get('fixed') else 'Update WordPress, then run Validate now.'}


def _tls(match, cve, strategy, host):
    ev = match.evidence if isinstance(match.evidence, dict) else {}
    test = str(ev.get('test') or '')
    port = _port(ev.get('port')) or 443
    flag = TESTSSL_FLAGS.get(test)
    starttls = STARTTLS.get(port)
    target = f'{host}:{port}' if host else ''
    steps = []
    if target:
        steps.append(_step(f'Run only this testssl.sh test against {target}', 'Read the line for this test: VULNERABLE confirms it, '
                           '"not vulnerable" clears it.', 'testssl.sh ' + (f'--starttls {starttls} ' if starttls else '') + (flag or '-U') + f' {_q(target)}'))
        if test in ('secure_client_renego', 'secure_renego') and not starttls:
            steps.append(_step('Or ask the server to renegotiate with openssl', 'After the handshake, type R and press Enter: a new handshake '
                               '(the certificate chain printed again) means client-initiated renegotiation is accepted; '
                               '"renegotiation failed" or a closed connection means it is refused. Nothing but a handshake is sent.',
                               f'openssl s_client -connect {_q(target)} -servername {_q(host)} -tls1_2'))
    look_for = [{'label': 'The test', 'text': test or 'a testssl.sh vulnerability test'}]
    if ev.get('result'):
        look_for.append({'label': 'What testssl.sh reported (seen on the host)', 'quote': _quote(ev.get('result'), 300)})
    return {'class': 'tls', 'class_label': 'TLS behaviour proven by testssl.sh', 'headline': f'Confirm {cve.cve_id} on {target or host}',
            'where': [{'label': 'TLS service', 'text': target}] if target else [], 'look_for': look_for, 'steps': steps,
            'verdict': {'fixed': '', 'affected': 'testssl.sh reports the test as VULNERABLE again: affected.',
                        'not_affected': 'testssl.sh reports "not vulnerable" (or the protocol or cipher is not offered): not affected.',
                        'cant_tell': 'The connection fails, times out or a load balancer answers: test the server behind it directly.'},
            'precondition': _precondition(cve, strategy), 'local': [],
            'fix': 'Change the TLS configuration of the service on that port (disable the protocol, cipher or renegotiation the test names) '
                   'or update the TLS library, then run Validate now.'}


def _openvas(match, cve, strategy, host):
    ev = match.evidence if isinstance(match.evidence, dict) else {}
    oid = str(ev.get('oid') or '')
    port_text = _quote(ev.get('port'), 40)
    look_for = []
    if _OID.match(oid):
        look_for.append({'label': 'OpenVAS test (NVT) OID', 'text': oid})
    if ev.get('nvt'):
        look_for.append({'label': 'Test name (feed text)', 'quote': _quote(ev.get('nvt'), 200)})
    if ev.get('qod') is not None:
        look_for.append({'label': 'Quality of detection', 'text': f"{_quote(ev.get('qod'), 10)}% ({_quote(ev.get('qod_type'), 40)})"})
    return {'class': 'openvas', 'class_label': 'OpenVAS (Greenbone) result', 'headline': f'Confirm {cve.cve_id} on {host}',
            'where': [{'label': 'Host and port (as OpenVAS reported it)', 'quote': f'{host} {port_text}'.strip()}], 'look_for': look_for,
            'steps': [_step('Open the result in Greenbone', 'Scans > Results, filter on the OID above and this host: the Detection Result and '
                            'Insight sections say what the test saw.', run_in='browser')],
            'verdict': {'fixed': '', 'affected': 'The result is present after a new OpenVAS scan of the host: affected (a quality of detection '
                                                 'of 97% or more is a remote check, lower ones are often version-only).',
                        'not_affected': 'A new scan no longer reports the result: not affected.', 'cant_tell': 'The test could not log in or '
                                                                                                        'reach the port: run it with credentials.'},
            'precondition': _precondition(cve, strategy), 'local': [], 'fix': 'Apply the vendor fix the OpenVAS result names, then rescan.'}


def _host_reported(match, cve, strategy, host):
    ev = match.evidence if isinstance(match.evidence, dict) else {}
    purl = str(ev.get('purl') or '')
    found = _PURL.match(purl)
    commands = []
    if found:
        kind, name = found.group(1), found.group(2).split('/')[-1]
        if re.match(r'^[A-Za-z0-9][A-Za-z0-9._+-]{0,99}$', name):
            if kind == 'deb':
                commands.append({'platform': 'debian', 'command': f"dpkg-query -W -f='${{Package}} ${{Version}}\\n' {_q(name)}",
                                 'explain': 'Prints the installed package release.'})
            elif kind == 'rpm':
                commands.append({'platform': 'rhel', 'command': f"rpm -q --qf '%{{NAME}} %{{VERSION}}-%{{RELEASE}}\\n' {_q(name)}",
                                 'explain': 'Prints the installed version-release.'})
            elif kind == 'apk':
                commands.append({'platform': 'alpine', 'command': f'apk info -v {_q(name)}', 'explain': 'Prints the installed package.'})
            elif kind == 'npm':
                commands.append({'platform': 'app', 'command': f'npm ls {_q(name)} --all', 'explain': 'Lists every copy with its version.'})
            elif kind == 'pypi':
                commands.append({'platform': 'app', 'command': f'python3 -m pip show {_q(name)}', 'explain': 'Read the Version line.'})
    look_for = [{'label': 'What the host reported', 'quote': _quote(f'{match.matched_product} {match.matched_version}', 160)}]
    if found:
        look_for.append({'label': 'Package URL', 'quote': _quote(purl, 200)})
    rng = _range_of(match)
    return {'class': 'host_inventory', 'class_label': 'Reported by the host\'s own inventory', 'headline': f'Confirm {match.matched_product} '
            f'{_version(match.matched_version)} on {host}', 'where': [{'label': 'Host', 'text': host}] if host else [], 'look_for': look_for,
            'steps': [], 'verdict': _verdict(str(match.matched_product), _version(match.matched_version), rng, 'The installed package',
                                             'The package manager does not list it: the inventory may be stale; run the reporter again.'),
            'precondition': _precondition(cve, strategy),
            'local': [{'title': 'On the host', 'commands': commands}] if commands else [],
            'fix': f"Update the package to {rng['fixed']} or later, then let the host report again." if rng.get('fixed') else
                   'Update the package to a fixed release, then let the host report again.'}


def match_guide(match):
    """The confirm-it-yourself guide for one CVEMatch (its cve_entry and subdomain loaded), or None when the match has no host. Pure but for
    a few bounded reads of what cvENGINE already recorded about the host (route-check pages, probe observations, the nuclei hit)."""
    from cveFeed.detection import library_key
    sub = match.subdomain
    if sub is None:
        return None
    cve = match.cve_entry
    host = _host(sub.name)
    strategy = _strategy(cve)
    bases = _web_bases(sub)
    source = str(match.source or '')
    ev = match.evidence if isinstance(match.evidence, dict) else {}
    key = library_key(match.matched_product) if source == 'tech' else ''
    if source == 'testssl':
        guide = _tls(match, cve, strategy, host)
    elif source == 'openvas':
        guide = _openvas(match, cve, strategy, host)
    elif source == 'host':
        guide = _host_reported(match, cve, strategy, host)
    elif source == 'wp-plugin' or ev.get('source') == 'wpscan':
        guide = _cms(match, cve, strategy, host, bases)
    elif source == 'port':
        guide = _network_service(match, cve, strategy, host)
    elif key:
        guide = _client_library(match, cve, strategy, host, bases, key)
    elif re.match(r'^wordpress$', str(match.matched_product or ''), re.I):
        guide = _wordpress_core(match, cve, strategy, host, bases)
    else:
        guide = _web_product(match, cve, strategy, host, bases)
    template = _template_section(match, host, bases)
    if template:
        guide['template'] = template
    # what the general per-CVE steps' <TARGET> and <PORT> stand for on this match, validated, so the page can fill them in there too
    port = _port(ev.get('port'))
    if not port and bases:
        parts = urlsplit(bases[0])
        port = parts.port or (443 if parts.scheme == 'https' else 80)
    guide['fill'] = {k: v for k, v in (('TARGET', host), ('PORT', str(port) if port else '')) if v}
    guide['version'] = GUIDE_VERSION
    guide['notice'] = NOTICE
    guide['cve_id'] = cve.cve_id
    return guide
