"""Version and identity probes: safe, read-only requests that find out what a product on a host is and which version it runs, so that
the deterministic CVE correlation has a fact to test instead of a name.

A product seen without a version is a *lead* (see ``leads_for``). Nothing in a banner or a technology tag says which of an advisory's
versions apply, so cvENGINE asks the host. The probes below are data: an id, a label, which products they help with, the requests
they make and the patterns that read the answers. The application renders every request itself; nothing is written by a model and no
request is built from a model's text. A probe only ever sends a GET (or an nmap service probe), never a cookie or a credential, caps its
requests, response sizes and time, goes through the same safe-address gate as every other check (``route_auth.probe_url`` pins the
resolved, vetted address), and logs to the activity feed.

What a probe finds is stored as ``ProbeObservation`` rows (with the source and a confidence) and written back as the host's technologies
(a Port row for an nmap probe), then the host is correlated again: a real version gives a real, versioned match, or none. A probe that
finds the product states no version records that too (``hidden``): the AI is told the version is unknowable from outside and never guesses.

``plan_for_host`` picks the probes for a host's leads without any AI, so this works with no AI key; the AI, when configured, may choose
among the ones this module offers (cveFeed.validation_plan) and reason over what they found."""
import logging
import os
import re
import shlex
import time
from datetime import timedelta
from urllib.parse import urljoin, urlsplit

from django.utils import timezone

from cveFeed import cms, fingerprint, js_libraries, versions

logger = logging.getLogger(__name__)

SERVICE = 'probe'
WEB = '*web'  # a probe that helps with any web product
MAX_PROBES_PER_HOST = 5
MAX_REDIRECTS = 2
REQUEST_GAP = 0.2  # seconds between two requests to one host
RETRY_DELAYS = (3.0,)  # a "try later" (429, 503) is asked again once after this pause; a challenge is not asked again at all
NMAP_TIMEOUT = 150
PROBE_PATH = '/.cvengine-probe/404'  # a path no site serves: the answer is the server's own error page
EDGE_STATUSES = (202, 403, 429, 503)
BODY_SCAN = 64 * 1024  # a response is read for markers in its first 64 KB only: a hostile page cannot make a pattern cost time by being long

# ----------------------------------------------------------------------------- the catalogue (data)
# A rule reads one response: ``request`` is the index of the request in the probe, ``where`` is body, title or header:<name>, ``regex`` the
# pattern, ``version`` the group (or groups, joined with dots) holding the version, ``kind`` version or identity, ``outcome`` hidden when
# the pattern shows the product answering without a version, and ``variant`` which look-alike product answered.
PROBES = (
    {'id': 'headers-root', 'label': 'Response headers and page markers of the front page', 'family': 'http', 'leads': WEB,
     'requests': (('GET', '/'),), 'handler': 'headers', 'safety': 'one GET of the front page'},
    {'id': 'error-page', 'label': 'Server error page signature (nginx, Apache, Tomcat, Jetty, IIS footers)', 'family': 'http',
     'leads': r'nginx|openresty|apache|httpd|tomcat|jetty|iis|internetinformation|express|nextjs|springboot|ingress', 'requests': (('GET', PROBE_PATH),),
     'safety': 'one GET of a path no site serves', 'rules': (
         {'request': 0, 'where': 'body', 'regex': r'<center>nginx/(\d+\.\d+\.\d+)</center>', 'product': 'nginx', 'version': 1,
          'kind': 'version', 'confidence': 0.95, 'source': 'body:nginx-error-page'},
         {'request': 0, 'where': 'body', 'regex': r'<center>openresty/(\d+\.\d+\.\d+(?:\.\d+)?)</center>', 'product': 'OpenResty', 'version': 1,
          'kind': 'version', 'confidence': 0.95, 'source': 'body:openresty-error-page'},
         {'request': 0, 'where': 'body', 'regex': r'<hr><center>nginx</center>', 'product': 'nginx', 'kind': 'version', 'outcome': 'hidden',
          'confidence': 0.8, 'source': 'body:nginx-error-page'},
         {'request': 0, 'where': 'body', 'regex': r'<hr><center>nginx</center>', 'product': 'nginx', 'variant': 'nginx', 'kind': 'identity',
          'confidence': 0.7, 'source': 'body:nginx-error-page'},
         {'request': 0, 'where': 'body', 'regex': r'(?i)Apache/(\d+\.\d+\.\d+) (?:\([^)]{1,30}\) )?Server at', 'product': 'Apache HTTP Server',
          'version': 1, 'kind': 'version', 'confidence': 0.9, 'source': 'body:apache-error-page'},
         {'request': 0, 'where': 'body', 'regex': r'Apache Tomcat/(\d+\.\d+\.\d+[\w.-]*)', 'product': 'Apache Tomcat', 'version': 1,
          'kind': 'version', 'confidence': 0.9, 'source': 'body:tomcat-error-page'},
         {'request': 0, 'where': 'body', 'regex': r'Powered by Jetty:// (\d+\.\d+\.\d+[\w.-]*)', 'product': 'Jetty', 'version': 1,
          'kind': 'version', 'confidence': 0.9, 'source': 'body:jetty-error-page'},
         {'request': 0, 'where': 'title', 'regex': r'IIS (\d+\.\d+) Detailed Error', 'product': 'Microsoft IIS', 'version': 1,
          'kind': 'version', 'confidence': 0.85, 'source': 'title:iis-detailed-error'},
         {'request': 0, 'where': 'body', 'regex': r'^[ \t]{0,8}default backend - 404[ \t]{0,8}$', 'product': 'nginx', 'variant': 'kubernetes-ingress',
          'kind': 'identity', 'confidence': 0.8, 'source': 'body:default-backend'},
         {'request': 0, 'where': 'body', 'regex': r'<pre>Cannot GET /', 'product': 'Express', 'variant': 'express', 'kind': 'identity',
          'confidence': 0.8, 'source': 'body:express-404'},
         {'request': 0, 'where': 'body', 'regex': r'Whitelabel Error Page', 'product': 'Spring Boot', 'variant': 'spring-boot', 'kind': 'identity',
          'confidence': 0.85, 'source': 'body:spring-whitelabel'},
         {'request': 0, 'where': 'body', 'regex': r'__NEXT_DATA__|This page could not be found', 'product': 'Next.js', 'variant': 'next.js',
          'kind': 'identity', 'confidence': 0.6, 'source': 'body:next-404'},
     )},
    {'id': 'nginx-variants', 'label': 'Tell nginx apart from nginx-ui, Nginx Proxy Manager and an ingress controller', 'family': 'http',
     'leads': r'nginx', 'requests': (('GET', '/'), ('GET', '/api/')), 'safety': 'two GETs', 'rules': (
         {'request': 0, 'where': 'title', 'regex': r'(?i)\bnginx ui\b', 'product': 'nginx', 'variant': 'nginx-ui', 'kind': 'identity',
          'confidence': 0.85, 'source': 'title:nginx-ui'},
         {'request': 0, 'where': 'title', 'regex': r'(?i)nginx proxy manager', 'product': 'nginx', 'variant': 'nginx-proxy-manager',
          'kind': 'identity', 'confidence': 0.85, 'source': 'title:nginx-proxy-manager'},
         {'request': 1, 'where': 'body', 'regex': r'"version"\s*:\s*\{\s*"major"\s*:\s*(\d+)\s*,\s*"minor"\s*:\s*(\d+)\s*,\s*"revision"\s*:\s*(\d+)',
          'product': 'Nginx Proxy Manager', 'version': (1, 2, 3), 'kind': 'version', 'confidence': 0.9, 'source': 'body:npm-api'},
     )},
    {'id': 'nextjs-version', 'label': 'Next.js version from the framework script the page loads', 'family': 'http', 'leads': r'nextjs',
     'requests': (('GET', '/'),), 'handler': 'nextjs', 'safety': 'the front page and up to three of its own framework scripts'},
    {'id': 'html-libraries', 'label': 'JavaScript library versions from the script files themselves', 'family': 'http',
     'leads': r'jquery|bootstrap|angular|lodash|moment|underscore|vue|react|swiper|datatables', 'requests': (('GET', '/'),),
     'handler': 'libraries', 'safety': 'the front page and up to six of the scripts it loads (its own site or a public library CDN, 300 KB each)'},
    {'id': 'drupal-changelog', 'label': 'Drupal version from its change log', 'family': 'http', 'leads': r'drupal',
     'requests': (('GET', '/core/CHANGELOG.txt'), ('GET', '/CHANGELOG.txt')), 'safety': 'two GETs', 'rules': (
         {'request': 0, 'where': 'body', 'regex': r'(?m)^Drupal (\d+\.\d+(?:\.\d+)?)', 'product': 'Drupal', 'version': 1, 'kind': 'version',
          'confidence': 0.9, 'source': 'body:drupal-changelog'},
         {'request': 1, 'where': 'body', 'regex': r'(?m)^Drupal (\d+\.\d+(?:\.\d+)?)', 'product': 'Drupal', 'version': 1, 'kind': 'version',
          'confidence': 0.9, 'source': 'body:drupal-changelog'},
     )},
    {'id': 'joomla-manifest', 'label': 'Joomla version from its manifest', 'family': 'http', 'leads': r'joomla',
     'requests': (('GET', '/administrator/manifests/files/joomla.xml'), ('GET', '/language/en-GB/en-GB.xml'),
                  ('GET', '/administrator/components/com_content/content.xml')), 'safety': 'three GETs of version files', 'rules': (
         {'request': 0, 'where': 'body', 'regex': r'<version>(\d+\.\d+\.\d+)</version>', 'product': 'Joomla', 'version': 1, 'kind': 'version',
          'confidence': 0.9, 'source': 'body:joomla-manifest'},
         {'request': 1, 'where': 'body', 'regex': r'<version>(\d+\.\d+\.\d+)</version>', 'product': 'Joomla', 'version': 1, 'kind': 'version',
          'confidence': 0.85, 'source': 'body:joomla-language'},
         {'request': 2, 'where': 'body', 'regex': r'<version>(\d+\.\d+\.\d+)</version>', 'product': 'Joomla', 'version': 1, 'kind': 'version',
          'confidence': 0.8, 'source': 'body:joomla-component'},
     )},
    {'id': 'magento-version', 'label': 'Magento version from its admin login page and release notes', 'family': 'http', 'leads': r'magento',
     'requests': (('GET', '/magento_version'), ('GET', '/admin'), ('GET', '/RELEASE_NOTES.txt')), 'safety': 'three GETs, no login attempt', 'rules': (
         # /magento_version answers "Magento/2.4 (Community)": the branch, never the patch release, so it names the product and no version
         {'request': 0, 'where': 'body', 'regex': r'^Magento/\d+\.\d+ \((?:Community|Enterprise)\)', 'product': 'Magento', 'kind': 'version',
          'outcome': 'hidden', 'confidence': 0.7, 'source': 'body:magento_version'},
         {'request': 1, 'where': 'body', 'regex': r'Magento ver\. (\d+\.\d+\.\d+(?:-p\d+)?)', 'product': 'Magento', 'version': 1, 'kind': 'version',
          'confidence': 0.85, 'source': 'body:magento-admin'},
         {'request': 2, 'where': 'body', 'regex': r'(?m)^=== (\d+\.\d+\.\d+\.\d+) ===', 'product': 'Magento', 'version': 1, 'kind': 'version',
          'confidence': 0.85, 'source': 'body:magento-release-notes'},
     )},
    {'id': 'robots-txt', 'label': 'robots.txt hints at the CMS behind the site', 'family': 'http', 'leads': WEB, 'requests': (('GET', '/robots.txt'),),
     'safety': 'one GET', 'rules': (
         {'request': 0, 'where': 'body', 'regex': r'(?i)Disallow:\s*/wp-admin/|/wp-sitemap\.xml', 'product': 'WordPress', 'variant': 'wordpress',
          'kind': 'identity', 'confidence': 0.6, 'source': 'body:robots-txt'},
     )},
    {'id': 'wordpress-detect', 'label': 'Is this WordPress? (login page, REST API, generator, readme)', 'family': 'http', 'leads': r'wordpress|wpengine|woocommerce',
     'requests': (('GET', '/'), ('GET', '/wp-login.php'), ('GET', '/wp-json/')), 'handler': 'wordpress',
     'safety': 'up to four GETs, browser-like headers, no login attempt'},
    {'id': 'nmap-version-all', 'label': 'nmap service probe at full intensity with the safe banner scripts', 'family': 'nmap', 'leads': '*port',
     'safety': 'nmap -sV --version-all on one port, safe scripts only'},
)
BY_ID = {p['id']: p for p in PROBES}
IDENTITY_PROBES = ('error-page', 'nginx-variants')  # the probes that say which look-alike product answers, whatever the version
# the safe scripts for a service (all are in nmap_scan.NSE_SCRIPTS, which is the reviewed list)
NMAP_SCRIPTS = {'http': 'http-server-header,http-headers,http-generator,http-title,ssl-cert,banner', 'ssh': 'ssh2-enum-algos,ssh-hostkey,banner',
                'mysql': 'mysql-info', 'redis': 'redis-info', 'memcached': 'memcached-info', 'mongodb': 'mongodb-info',
                'ms-sql': 'ms-sql-info', 'smtp': 'banner', 'ftp': 'banner,ftp-anon', 'imap': 'banner', 'pop3': 'banner'}
# products that only look like another product by name: an advisory for one of these is not an advisory for the base product
LOOKALIKES = {'nginx': {'ingressnginx', 'nginxingress', 'nginxui', 'nginxproxymanager', 'nginxunit', 'nginxrtmpmodule'}}
LOOKALIKE_VARIANTS = {'nginx': {'nginx-ui', 'nginx-proxy-manager', 'kubernetes-ingress'}}
PLAIN_VARIANTS = {'nginx': 'nginx', 'express': 'express', 'next.js': 'next.js'}


def _compiled():
    for probe in PROBES:
        for rule in probe.get('rules', ()):
            rule['_re'] = re.compile(rule['regex'], re.M)
    return True


_COMPILED = _compiled()


def _token(text):
    return re.sub(r'[^a-z0-9]', '', str(text or '').lower())


# ----------------------------------------------------------------------------- leads and the plan (no AI)

def leads_for(sub):
    """The products of ``sub`` seen without a version, the leads a probe can follow up (the matching policy's list, which also drives the host
    page's unverified products)."""
    from cveFeed.match_policy import unversioned_products
    return unversioned_products(sub)


def _lead_matches(probe, token, lead):
    pattern = probe['leads']
    if pattern == WEB:
        return lead.get('source') == 'tech' or lead.get('port') is not None
    if pattern == '*port':
        return lead.get('source') == 'port' and lead.get('port') is not None
    return bool(re.search(pattern, token))


def plan_for_host(sub, leads=None, edge_fronted=False, wanted=None):
    """``[{'probe', 'label', 'family', 'target', 'for'}]``: the probes that can find the version or identity of ``sub``'s leads, chosen
    by rule, never by a model, at most MAX_PROBES_PER_HOST. A web probe targets the host's first web base URL, an nmap probe one
    address and port (none when an edge answers there: an edge's own software is not the host's). ``wanted`` limits it to probe ids."""
    from cveFeed import route_auth
    leads = leads_for(sub) if leads is None else leads
    bases = route_auth.web_bases(sub)
    plan = {}
    for probe in PROBES:
        if wanted is not None and probe['id'] not in wanted:
            continue
        for lead in leads:
            if not _lead_matches(probe, _token(lead.get('name')), lead):
                continue
            if probe['family'] == 'http':
                target = {'base': bases[0]} if bases else None
            else:
                target = None if edge_fronted else {'ip': lead.get('ip'), 'port': lead.get('port'), 'service': lead.get('service', '')}
            if target:
                entry = plan.setdefault((probe['id'], tuple(sorted(target.items()))),
                                        {'probe': probe['id'], 'label': probe['label'], 'family': probe['family'], 'target': target, 'for': []})
                entry['for'].append(lead['name'])
    return list(plan.values())[:MAX_PROBES_PER_HOST]


def asset_key(host, entry):
    """The ledger asset of one planned probe on one host."""
    target = entry['target']
    return f"{host.lower()}|{entry['probe']}|{target.get('base') or str(target.get('ip')) + ':' + str(target.get('port'))}"


def unaddressable(sub, cve=None):
    """Why no probe can help, or '': a kernel or driver advisory, or a host with nothing web or service shaped to probe. Said plainly so a
    validation request never ends with "no executable check" for a lead a probe could address, and never pretends one could address this."""
    description = ' '.join(str(getattr(cve, name, '') or '') for name in ('title', 'original_description')).lower() if cve else ''
    if re.search(r'\blocal(?:ly)?\b', description) and re.search(r'\b(kernel|driver|module|hardware|nic|kvm)\b', description):
        return ('This advisory needs the host\'s own kernel, driver or hardware state; no network probe can read it. Install the host '
                'inventory reporter on the machine so its kernel and patch level are known.')
    return ''


def display_for(probe_id, target):
    """The command a person can repeat for a probe (curl for each request, or the nmap command line)."""
    probe = BY_ID[probe_id]
    if probe['family'] == 'nmap':
        return shlex.join(nmap_argv(target['ip'], target['port'], target.get('service', '')))
    base = target['base'].rstrip('/')
    return '; '.join(f"curl -sS -i --max-time 6 {shlex.quote(base + path)}" for _method, path in probe['requests'])


def nmap_argv(ip, port, service=''):
    from cveFeed import nmap_scan
    name = re.sub(r'^(ssl/|tcp)', '', str(service or '').lower())
    key = next((k for k in NMAP_SCRIPTS if name.startswith(k)), 'http' if name.startswith('http') or name == 'https' else '')
    scripts = NMAP_SCRIPTS.get(key, 'banner')
    return [nmap_scan.NMAP_BIN, '-sV', '--version-all', '-Pn', '-p', str(int(port)), '--script', scripts, '--script-timeout', '20s',
            '--host-timeout', '90s', '-oX', '-', str(ip)]


# ----------------------------------------------------------------------------- fetching (one bounded GET, same gates as every probe)

def challenge_of(response):
    """The edge that challenged or blocked this answer ('' when it is the site's own answer): Cloudflare's challenge header or page, an
    Akamai, Sucuri or Imperva block page, or a 202, 403, 429 or 503 an edge sent with no origin signature. cvENGINE never tries to get past
    one; it records that the edge answered and says what the owner can allow."""
    headers = {k.lower(): v for k, v in (response.get('headers') or {}).items()}
    body = (response.get('body') or '')[:20000]
    lowered = body.lower()
    if headers.get('cf-mitigated') == 'challenge' or 'cf-browser-verification' in lowered or '_cf_chl_opt' in lowered \
            or ('just a moment' in lowered and 'cloudflare' in lowered):
        return 'Cloudflare'
    if 'sucuri website firewall' in lowered or 'access denied - sucuri' in lowered:
        return 'Sucuri'
    if 'incapsula incident' in lowered or '_incapsula_' in lowered:
        return 'Imperva'
    if 'reference #' in lowered and 'edgesuite' in lowered:
        return 'Akamai'
    status = response.get('status') or 0
    edges = versions.edges_from_headers(headers)
    if status in EDGE_STATUSES and edges and not (response.get('title') or '').strip():
        return edges[0]
    return ''


def _permitted(host, project):
    """The gate every probe request passes, at the first request and at every redirect: a safe address, and not a name the organization
    excluded for good or an archived host (a redirect must not lead the probe where a scan may not go)."""
    from cveFeed import route_auth
    from cveFeed.archive_rediscovery import archived_names
    from cveFeed.exclusions import is_excluded
    if not route_auth.host_allowed(host, project):
        return False
    return not (project and (is_excluded(project, host) or host.lower().rstrip('.') in archived_names(project)))


def fetch(url, probe=None, sleep=time.sleep, allowed=None, project=None, max_bytes=None):
    """One probe GET with browser-like headers, following at most MAX_REDIRECTS redirects that stay inside ``allowed`` (the names of this host's
    group: apex and www answer for each other) and pass ``_permitted`` (safe address, exclusions) at every hop. A "try later" (429, 503) is
    asked again once after a pause; an edge challenge is never retried and never pushed against: it is returned with ``challenge`` naming the
    edge. ``project`` (an id) lets the gate and the pinned transport accept the tailnet address of a device that project's own Tailscale
    integration imported. Returns the probe dict plus ``final_url`` and ``challenge``."""
    from cveFeed import route_auth
    probe = probe or route_auth.probe_url
    last = None
    for attempt in range(len(RETRY_DELAYS) + 1):
        current, hops = url, 0
        while True:
            if not _permitted(urlsplit(current).hostname or '', project):
                raise ValueError('probe destination is not allowed')
            response = probe(current, max_bytes=max_bytes or route_auth.MAX_PROBE_BYTES, browser=True, project=project)
            location = response.get('location') or ''
            if 300 <= (response.get('status') or 0) < 400 and location and hops < MAX_REDIRECTS:
                nxt = urljoin(current, location)
                if urlsplit(nxt).hostname and (allowed is None or urlsplit(nxt).hostname.lower() in allowed):
                    current, hops = nxt, hops + 1
                    sleep(REQUEST_GAP)
                    continue
            break
        last = {**response, 'final_url': current, 'challenge': challenge_of(response)}
        if last['challenge'] or (response.get('status') or 0) not in (429, 503):
            return last
        if attempt < len(RETRY_DELAYS):
            sleep(RETRY_DELAYS[attempt])
    return last


# ----------------------------------------------------------------------------- reading answers (pure)

def _observation(kind, product, version='', variant='', outcome='found', confidence=0.0, source='', port=0, url='', evidence=None):
    return {'kind': kind, 'product': str(product)[:120], 'version': str(version)[:100], 'variant': str(variant)[:60], 'outcome': outcome,
            'confidence': confidence, 'source': str(source)[:48], 'port': port, 'url': str(url)[:500], 'evidence': evidence or {}}


def _where(response, where):
    if where == 'body':
        return (response.get('body') or '')[:BODY_SCAN]
    if where == 'title':
        return response.get('title') or ''
    return str((response.get('headers') or {}).get(where.split(':', 1)[1], ''))


def apply_rules(probe, responses):
    """Observations from the probe's data rules over ``responses`` (one response dict per request, in order, None for a request that failed)."""
    out = []
    for rule in probe.get('rules', ()):
        index = rule['request']
        response = responses[index] if index < len(responses) else None
        if not response or response.get('challenge'):  # an edge's challenge page says nothing about the site behind it
            continue
        found = rule['_re'].search(_where(response, rule['where']))
        if not found:
            continue
        number = rule.get('version')
        version = ''
        if isinstance(number, tuple):
            version = '.'.join(found.group(i) for i in number)
        elif number:
            version = found.group(number)
        out.append(_observation(rule['kind'], rule['product'], version, rule.get('variant', ''), rule.get('outcome', 'found'),
                                rule['confidence'], rule['source'], url=probe['requests'][index][1]))
    return out


def observations_from_page(response, source_prefix='page'):
    """Versions and markers a front page states, as observations: its headers (Server and modules, X-Powered-By, ASP.NET and framework
    headers, Via), every generator tag, the library versions in script names and the edge that answered. A product named with no version is
    ``hidden``, not guessed."""
    out = []
    headers = response.get('headers') or {}
    seen = set()

    def add(name, source):
        base, _, version = name.partition(':')
        if (base.lower(), version) in seen:
            return
        seen.add((base.lower(), version))
        hint = source == 'script:filename'  # a library version a script's file name carries: a hint (cveFeed.js_libraries)
        out.append(_observation('version', base, version, outcome='found' if version else 'hidden',
                                confidence=(js_libraries.CONFIDENCE['filename'] if hint else 0.9) if version else 0.7, source=source, url='/'))
    found = fingerprint.from_response(response.get('server', ''), response.get('powered_by', ''), response.get('body', ''),
                                      response.get('content_type', ''), scripts=fingerprint.script_sources(response.get('body', ''), response.get('final_url') or response.get('url', ''))[0],
                                      headers=headers)
    for item in found:
        add(item['name'], item['source'])
    for product in cms.SOURCES:  # a version the front page already carries (Drupal's core scripts); WordPress has its own probe
        if product != 'WordPress':
            version, label = cms.best(product, [('/', response)])
            if version:
                add(f'{product}:{version}', label)
    stated = {o['product'].lower() for o in out if o['kind'] == 'version' and o['version']}
    out = [o for o in out if not (o['kind'] == 'version' and not o['version'] and o['product'].lower() in stated)]  # a version replaces the bare name
    for provider in versions.edges_from_headers({**headers, 'server': response.get('server', '')}):
        out.append(_observation('edge', provider, outcome='edge', confidence=0.8, source='header:edge', url='/'))
    return out


def next_version(body):
    """The Next.js version a framework script states (``window.next={version:"14.1.0"}``), or ''."""
    found = re.search(r'\bnext\s{0,8}=\s{0,8}\{\s{0,8}version\s{0,8}:\s{0,8}["\'](\d+\.\d+\.\d+[\w.-]{0,20})["\']', body or '')
    return found.group(1) if found else ''


_NEXT_CHUNK = re.compile(r'/_next/static/chunks/(?:main|main-app|framework|webpack)-[A-Za-z0-9]{8,}\.js')


def _wordpress_signals(responses):
    """``(signals, version)`` for the WordPress probe: every signature found in a response's headers or body, and the core version a
    generator tag, a readme or a core asset states."""
    signals, generator = [], ''
    for path, response in responses:
        if not response:
            continue
        headers = {k.lower(): v for k, v in (response.get('headers') or {}).items()}
        body = (response.get('body') or '')[:BODY_SCAN]
        link = headers.get('link', '').replace("'", '"')
        if 'rel="https://api.w.org/"' in link:
            signals.append(('header:link-api.w.org', path))
        if 'xmlrpc.php' in headers.get('x-pingback', ''):
            signals.append(('header:x-pingback', path))
        if path == '/wp-login.php' and re.search(r'id=["\']loginform["\']|name=["\']log["\']|wp-submit', body):
            signals.append(('body:login-form', path))
        if path.startswith('/wp-json') and re.search(r'"namespaces"\s*:\s*\[|"wp/v2"|"code"\s*:\s*"rest_', body):
            signals.append(('body:rest-api', path))
        if path == '/' and re.search(r'/wp-content/|/wp-includes/', body):
            signals.append(('body:wp-content', path))
        for product, found in versions.generator_tags(body if path == '/' else ''):
            if product.lower() == 'wordpress':
                signals.append(('meta:generator', path))
                generator = generator or found
    # the version: the generator tag, the core's own versioned assets, the feed, the readme (cveFeed.cms: best source wins, a library's ?ver= never)
    pages = [(path, response) for path, response in responses if response and not (path == '/readme.html' and 'wordpress' not in (response.get('body') or '').lower())]
    candidates = cms.read('WordPress', pages) + ([(generator, 'meta:generator', 0.9)] if generator else [])
    candidates.sort(key=lambda c: -c[2])
    if any(label.startswith('asset:') for _v, label, _c in candidates):
        signals.append(('body:core-asset-ver', '/'))
    return signals, (candidates[0][0] if candidates else '')


def wordpress_observations(responses):
    """The observations of the WordPress probe from its responses ``[(path, response)]``: found (with how and the version when stated),
    challenged (an edge answered and no signature was readable: the owner is told what to allow), absent, or none when nothing answered."""
    signals, version = _wordpress_signals(responses)
    probed = [{'path': path, 'status': (r or {}).get('status'), 'challenge': (r or {}).get('challenge', '')} for path, r in responses]
    if signals:
        order = list(dict.fromkeys(s for s, _ in signals))
        evidence = {'signals': order, 'probed': probed}
        found = [_observation('wordpress', 'WordPress', version, 'wordpress', 'found', min(0.95, 0.6 + 0.1 * len(order)), order[0],
                              url=next(p for s, p in signals), evidence=evidence)]
        from cveFeed import wp_core
        answers = dict(responses)
        if wp_core.UPGRADE_PATH in answers:  # the directory an update is extracted into: whether the web server serves it (cveFeed.wp_core)
            state = wp_core.classify_dir(answers[wp_core.UPGRADE_PATH], answers.get(wp_core.UPGRADE_MISSING))
            status = (answers[wp_core.UPGRADE_PATH] or {}).get('status')
            found.append(_observation('wp-upgrade-dir', 'WordPress', variant=state, source='probe:upgrade-dir', url=wp_core.UPGRADE_PATH,
                                      outcome='found' if state in (wp_core.LISTING, wp_core.REACHABLE) else 'absent' if state == wp_core.DENIED else 'hidden',
                                      confidence=0.9 if state in (wp_core.LISTING, wp_core.DENIED) else 0.7 if state == wp_core.REACHABLE else 0.0,
                                      evidence={'status': status, 'state': state}))
        return found
    challenged = next((r['challenge'] for _p, r in responses if r and r.get('challenge')), '')
    reachable = [r for _p, r in responses if r]
    if not reachable:
        return []  # the host did not answer at all: nothing was learned, so nothing is recorded
    if challenged or (reachable and all((r.get('status') or 0) in EDGE_STATUSES for r in reachable)):
        provider = challenged or (versions.edges_from_headers((reachable[0].get('headers') or {})) or ['an edge'])[0]
        evidence = {'probed': probed, 'edge': provider,
                    'hint': (f'The edge ({provider}) answered cvENGINE\'s requests with a challenge or a block, so it could not be read whether '
                             'this host runs WordPress. Allow the scanner\'s address (or its user agent) in the WAF or bot rules for this host, '
                             'then rescan.')}
        return [_observation('wordpress', 'WordPress', outcome='challenged', confidence=0.0, source='edge', evidence=evidence)]
    return [_observation('wordpress', 'WordPress', outcome='absent', confidence=0.7, source='probe', evidence={'probed': probed})]


# ----------------------------------------------------------------------------- running one probe

def allowed_names(sub):
    names = {sub.name.lower()}
    domain = getattr(sub, 'target_domain', None)
    if domain is not None:
        apex = domain.name.lower()
        names |= {apex, f'www.{apex}'}
    if sub.name.lower().startswith('www.'):
        names.add(sub.name.lower()[4:])
    else:
        names.add(f'www.{sub.name.lower()}')
    return names


def run_http_probe(probe_id, base, allowed, get=None, sleep=time.sleep, project=None):
    """Run one http probe against ``base`` and return its observations. ``get(url)`` replaces the network (tests)."""
    probe = BY_ID[probe_id]
    # a script is read further than a page (cveFeed.js_libraries.MAX_SCRIPT_BYTES); a test's ``get`` reads both
    script_get = None if get else (lambda url: fetch(url, allowed=allowed, sleep=sleep, project=project, max_bytes=js_libraries.MAX_SCRIPT_BYTES))
    get = get or (lambda url: fetch(url, allowed=allowed, sleep=sleep, project=project))
    handler = probe.get('handler')
    if handler == 'wordpress':
        return wordpress_observations(_wordpress_responses(base, get, sleep))
    responses = []
    for index, (method, path) in enumerate(probe['requests']):
        if index:
            sleep(REQUEST_GAP)
        try:
            responses.append(get(base.rstrip('/') + path))
        except (OSError, ValueError) as exc:
            logger.info('probe %s: %s did not answer (%s)', probe_id, path, type(exc).__name__)
            responses.append(None)
    out = []
    first = responses[0] if responses else None
    if handler == 'headers' and first:
        out += observations_from_page(first)
    elif handler == 'nextjs' and first:
        out += _nextjs_observations(first, get, sleep)
    elif handler == 'libraries' and first:
        out += _library_observations(first, script_get or get, sleep, project)
    out += apply_rules(probe, responses)
    if first and first.get('challenge') and not any(o['kind'] == 'edge' for o in out):
        out.append(_observation('edge', first['challenge'], outcome='challenged', confidence=0.8, source='edge-challenge', url=probe['requests'][0][1]))
    return out


def _wordpress_responses(base, get, sleep):
    paths = ['/', '/wp-login.php', '/wp-json/']
    responses = []
    for index, path in enumerate(paths):
        if index:
            sleep(REQUEST_GAP)
        try:
            responses.append((path, get(base.rstrip('/') + path)))
        except (OSError, ValueError):
            responses.append((path, None))
    if _wordpress_signals(responses)[0]:  # only a site that is WordPress is asked for its readme, and for the directory updates are extracted into
        sleep(REQUEST_GAP)
        try:
            responses.append(('/readme.html', get(base.rstrip('/') + '/readme.html')))
        except (OSError, ValueError):
            pass
        for path, _sources in cms.asked('WordPress'):
            if path == '/readme.html' or _wordpress_signals(responses)[1]:
                continue   # the readme was asked above; the feed only while no page states the version
            sleep(REQUEST_GAP)
            try:
                responses.append((path, get(base.rstrip('/') + path)))
            except (OSError, ValueError):
                pass
        from cveFeed import wp_core
        sleep(REQUEST_GAP)
        try:
            answer = get(base.rstrip('/') + wp_core.UPGRADE_PATH)
        except (OSError, ValueError):
            answer = None
        responses.append((wp_core.UPGRADE_PATH, answer))
        if wp_core.classify_dir(answer) == wp_core.REACHABLE:  # an empty page: ask once for a path that cannot exist beside it, to tell a catch-all
            sleep(REQUEST_GAP)
            try:
                responses.append((wp_core.UPGRADE_MISSING, get(base.rstrip('/') + wp_core.UPGRADE_MISSING)))
            except (OSError, ValueError):
                pass
    return responses


def _same_host_scripts(response, pattern=None, limit=4):
    page = response.get('final_url') or response.get('url') or ''
    _every, local = fingerprint.script_sources(response.get('body', ''), page, limit=40)
    return [u for u in local if pattern is None or pattern.search(u)][:limit]


def _nextjs_observations(first, get, sleep):
    scripts = _same_host_scripts(first, _NEXT_CHUNK, limit=3)
    for url in scripts:
        sleep(REQUEST_GAP)
        try:
            got = get(url)
        except (OSError, ValueError):
            continue
        number = next_version(got.get('body'))
        if number:
            return [_observation('version', 'Next.js', number, outcome='found', confidence=0.9, source='script:next-chunk', url=urlsplit(url).path)]
    seen = bool(scripts) or '__NEXT_DATA__' in (first.get('body') or '')
    if seen:
        return [_observation('version', 'Next.js', outcome='hidden', confidence=0.7, source='script:next-chunk', url='/')]
    return []


def _library_observations(first, get, sleep, project=None):
    """The library versions the front page's scripts state (cveFeed.js_libraries): one observation per library, its effective copy's
    version, with every copy and which one runs in ``evidence['library']``. A version from a file name only (the file could not be read or
    states none) is kept at low confidence; a query string is never a version."""
    page = first.get('final_url') or first.get('url') or ''
    entries = js_libraries.parse_page(first.get('body', ''), page)
    records = js_libraries.read_page(entries, page, get, js_libraries.vetter(page, project), {'left': js_libraries.MAX_SCRIPTS_PER_HOST},
                                     before_each=lambda: sleep(REQUEST_GAP))
    out = []
    for record in records.values():
        version = record['version']
        out.append(_observation('version', record['product'], version, source='script:body' if record['version_source'] == 'body' else 'script:filename',
                                confidence=record['version_confidence'] if version else 0.7, outcome='found' if version else 'hidden', url='/',
                                evidence={'library': record}))
    return out


def observations_from_nmap(inventory, port):
    """Observations of the nmap probe from ``nmap_scan.parse_xml`` output for one port: the product and version (``hidden`` when nmap
    names the product only), the Server header the http-server-header script printed and every generator tag."""
    from cveFeed.correlation import parse_cpe
    record = next((p for host in inventory for p in host['ports'] if p['number'] == port), None)
    if record is None or record.get('state') != 'open':
        return []
    out = []
    if record['product']:
        version = record['version'] or next((c[2] for c in (parse_cpe(x) for x in record.get('cpes') or []) if c and c[2]), '')
        out.append(_observation('version', record['product'], version, outcome='found' if version else 'hidden',
                                confidence=0.9 if record['method'] == 'probed' else 0.4, source='nmap:-sV --version-all', port=port,
                                evidence={'extrainfo': record['service_extra'][:100], 'method': record['method'], 'tunnel': record['tunnel'],
                                          'cpe': record['cpe'][:120]}))
    scripts = record.get('scripts') or {}
    lines = scripts.get('http-server-header', '').splitlines() + re.findall(r'(?im)^\s*Server:\s*(.+)$', scripts.get('http-headers', ''))
    for line in lines[:4]:
        for item in versions.parse_server_header(line)['components']:
            base, _, version = item['name'].partition(':')
            out.append(_observation('version', base, version, outcome='found' if version else 'hidden', confidence=0.85,
                                    source='nmap:http-server-header', port=port))
    for product, version in filter(None, (versions.parse_generator(line) for line in scripts.get('http-generator', '').splitlines()[:4])):
        out.append(_observation('version', product, version, outcome='found' if version else 'hidden', confidence=0.8,
                                source='nmap:http-generator', port=port))
    return out


def run_nmap_probe(ip, port, service='', runner=None):
    """Run the nmap probe on one port. Returns ``(observations, inventory)``; ``inventory`` is what ``nmap_scan.persist_inventory`` stores."""
    from cveFeed import nmap_scan
    argv = nmap_argv(ip, port, service)
    runner = runner or (lambda args: nmap_scan.run_nmap_args(args[1:], label=f'{ip}:{port}', timeout=NMAP_TIMEOUT))
    inventory = nmap_scan.parse_xml(runner(argv))
    return observations_from_nmap(inventory, int(port)), inventory


# ----------------------------------------------------------------------------- recording

def record(project_id, domain_id, host, probe_id, observations, now=None):
    """Store ``observations`` for a host (one row per probe, port, kind and product; a repeat updates it, so a version that disappeared is
    replaced by ``hidden``). Returns the rows."""
    from cveFeed.models import ProbeObservation
    now = now or timezone.now()
    rows = []
    for o in observations:
        row, _ = ProbeObservation.objects.update_or_create(
            project_id=project_id, host=host.lower(), probe=probe_id, port=o['port'], kind=o['kind'], product=o['product'],
            defaults={'domain_id': domain_id, 'version': o['version'], 'variant': o['variant'], 'url': o['url'],
                      'outcome': o['outcome'], 'confidence': o['confidence'], 'source': o['source'], 'evidence': o['evidence'],
                      'observed_at': now})
        rows.append(row)
    return rows


def technology_names(observations):
    """The Technology names a set of observations adds to a host: a stated version ("nginx:1.24.0"), WordPress and any identity variant
    that is a product of its own. A hidden version adds nothing (the lead stays a lead), and an edge is a hosting fact, not a technology."""
    names = []
    for o in observations:
        library = (o.get('evidence') or {}).get('library') if isinstance(o.get('evidence'), dict) else None
        if o['kind'] == 'version' and isinstance(library, dict) and library.get('tech_names'):
            names += [str(n)[:500] for n in library['tech_names'] if ':' in str(n)]  # the effective copy, or each copy of an unresolved set
        elif o['kind'] == 'version' and o['outcome'] == 'found' and o['version']:
            names.append(f"{o['product']}:{o['version']}")
        elif o['kind'] == 'wordpress' and o['outcome'] == 'found':
            names.append(f"WordPress:{o['version']}" if o['version'] else 'WordPress')
        elif o['kind'] == 'identity' and o['variant'] and o['variant'] not in PLAIN_VARIANTS.values() and o['variant'] != 'kubernetes-ingress':
            names.append(o['variant'])
    return list(dict.fromkeys(names))


def apply_to_subdomain(sub, observations):
    """Add the observations' technologies to the host row so correlation reads them like any detected technology. Returns how many were new."""
    from startScan.ip_rows import get_or_create_first
    from startScan.models import Technology
    added = 0
    have = {t.name for t in sub.technologies.all()}
    for name in technology_names(observations):
        if name in have:
            continue
        tech, _ = get_or_create_first(Technology, name=name[:500])
        sub.technologies.add(tech)
        added += 1
    return added


def apply_known(scan):
    """Give this scan's host rows the technologies earlier probes found: hosts are stored once per scan, so a fresh row starts without
    what an earlier probe added. Only observations seen inside the TTL; returns the number of technologies added."""
    from cveFeed import ledger
    from cveFeed.models import ProbeObservation
    from startScan.models import Subdomain
    project = scan.domain.project_id
    cutoff = timezone.now() - timedelta(seconds=ledger.ttl(SERVICE) * 4)
    by_host = {}
    # only what a probe read (not the candidate signals or WPScan's state rows): a hint is never turned into a technology
    for row in ProbeObservation.objects.filter(project_id=project, outcome='found', observed_at__gte=cutoff, probe__in=list(BY_ID)):
        by_host.setdefault(row.host, []).append({'kind': row.kind, 'product': row.product, 'version': row.version, 'variant': row.variant,
                                                 'outcome': row.outcome, 'evidence': row.evidence or {}})
    added = 0
    for sub in Subdomain.objects.filter(scan_history=scan, name__in=list(by_host)).prefetch_related('technologies'):
        added += apply_to_subdomain(sub, by_host.get(sub.name.lower(), []))
    return added


def recorrelate(sub):
    """Correlate one host again, now that a probe changed what is known about it, so a found version gives its versioned matches (or
    closes a candidate it contradicts). Best effort: the probe's own result stands without it."""
    from cveFeed import correlation
    try:
        cve_by_id, index = correlation.cve_pool()
        return correlation.correlate_subdomains([sub], index, cve_by_id)[1]
    except Exception:  # noqa: BLE001
        logger.exception('could not correlate %s after a probe', sub.pk)
        return 0


# ----------------------------------------------------------------------------- identity: a look-alike product is not the advisory's product

def lookalike_conflict(sub, match):
    """The reason a CVE match names a product that a probe showed this host does not run, or ''. It applies only when the sighting that made
    the match is the bare base product (a technology or port named just "nginx"), a probe identified the plain product with confidence, and
    nothing else on the host (a technology, a port, another probe) says the look-alike itself runs there: a host that really runs nginx-ui
    behind a plain nginx front is not cleared of an nginx-ui advisory. Deterministic, and only on a positive identification."""
    from cveFeed.correlation import affected_product_tokens, clean_affected
    from cveFeed.models import ProbeObservation
    from startScan.models import open_ports
    project_id = sub.target_domain.project_id
    base = _token(match.matched_product)
    if base not in LOOKALIKES:
        return ''
    rows = ProbeObservation.objects.filter(project_id=project_id, host=sub.name.lower(), kind='identity')
    if not rows.filter(variant=PLAIN_VARIANTS[base], outcome='found', confidence__gte=0.7).exists():
        return ''
    if rows.filter(variant__in=LOOKALIKE_VARIANTS[base]).exists():
        return ''
    seen = [_token(t.name.partition(':')[0]) for t in sub.technologies.all()]
    seen += [_token(p.product) for ip in sub.ip_addresses.all() for p in open_ports(ip)]
    if any(token in LOOKALIKES[base] for token in seen):
        return ''
    tokens = {t for item in clean_affected(match.cve_entry.affected) if isinstance(item, dict) for t in affected_product_tokens(item)}
    if tokens and all(t in LOOKALIKES[base] for t in tokens if base in t):
        names = ', '.join(sorted(t for t in tokens if base in t))
        return (f'A probe identified the software on this host as {base} (its own error page), not the product this advisory names '
                f'({names}); the name {base} appears in both but they are different software.')
    return ''


# ----------------------------------------------------------------------------- the pipeline stage and the validation check

def _int_env(name, default):
    try:
        return max(1, int(os.environ.get(name, '')))
    except ValueError:
        return default


def max_hosts():
    return _int_env('CVENGINE_PROBE_MAX_HOSTS', 60)


def run_one(project_id, domain_id, sub, entry, get=None, nmap_runner=None, sleep=time.sleep):
    """Run one planned probe (``plan_for_host`` entry) on ``sub``, store what it found, apply it, and return the observations."""
    probe_id, target = entry['probe'], entry['target']
    if BY_ID[probe_id]['family'] == 'nmap':
        from startScan.ip_rows import org_id_of_project

        from targetApp.target_types import is_scannable_ip
        if not is_scannable_ip(target['ip'], project=project_id):
            raise ValueError('probe destination is not allowed')

        from cveFeed import nmap_scan
        found, inventory = run_nmap_probe(target['ip'], target['port'], target.get('service', ''), runner=nmap_runner)
        nmap_scan.persist_inventory(inventory, source='nmap-probe', org_id=org_id_of_project(project_id))
    else:
        found = run_http_probe(probe_id, target['base'], allowed_names(sub), get=get, sleep=sleep, project=project_id)
    record(project_id, domain_id, sub.name, probe_id, found)
    if apply_to_subdomain(sub, found):
        recorrelate(sub)
    return found


def summarize(found):
    """One line for the activity feed and a validation step: what the probe found, or that the product states no version."""
    parts = []
    for o in found:
        if o['kind'] == 'edge':
            parts.append(f"an edge answered ({o['product']})" if o['outcome'] == 'edge' else f"the edge {o['product']} challenged the request")
        elif o['kind'] == 'wordpress':
            parts.append({'found': f"WordPress{' ' + o['version'] if o['version'] else ''} (version not stated)" if not o['version'] else f"WordPress {o['version']}",
                          'absent': 'not WordPress', 'challenged': 'WordPress could not be checked: the edge challenged the scanner'}[o['outcome']])
        elif o['kind'] == 'identity':
            parts.append(f"{o['product']} is {o['variant']}")
        elif o['outcome'] == 'found':
            parts.append(f"{o['product']} {o['version']}")
        elif o['outcome'] == 'hidden':
            parts.append(f"{o['product']} states no version")
    return '; '.join(dict.fromkeys(parts))[:300] or 'nothing the probe could read'


def run_for_scan(scan_id, get=None, nmap_runner=None, force=False, sleep=time.sleep):
    """The pipeline stage: for each host of the scan with unversioned products, run the probes ``plan_for_host`` picks, inside the ledger TTL
    and ``max_hosts`` per scan, honouring exclusions, scan stop and pause. Returns ``{'hosts', 'probes', 'versions', 'reused', 'errors'}``."""
    from cveFeed import activity, host_context, ledger
    from cveFeed.nuclei_scan import scan_targets
    from reNgine import resources
    from startScan.models import ScanHistory, Subdomain
    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
    project, domain = scan.domain.project_id, scan.domain
    reused = apply_known(scan)
    allowed, _ips, _ports = scan_targets(scan)  # the same filter every stage uses: excluded, archived and blocked names are not targets
    stats = {'hosts': 0, 'probes': 0, 'versions': 0, 'reused': reused, 'errors': 0}
    subs = Subdomain.objects.filter(scan_history=scan, name__in=allowed).prefetch_related('technologies', 'ip_addresses__ports', 'waf')
    due = []
    for sub in subs.select_related('target_domain').order_by('name'):
        leads = leads_for(sub)
        if not leads:
            continue
        plan = plan_for_host(sub, leads, edge_fronted=host_context.edge_for(sub, project)['fronted'])
        assets = {asset_key(sub.name, e): e for e in plan}
        covered = set() if force else ledger.fresh(SERVICE, assets, project)
        todo = {a: e for a, e in assets.items() if ledger._norm(a) not in covered}
        if todo:
            due.append((sub, todo))
    # hosts with nothing due were dropped above, so the cap below cuts only work that is due: the never-probed and longest-waiting go first
    history = ledger.last_run(SERVICE, [a for _s, todo in due for a in todo], project)
    epoch = timezone.now() - timedelta(days=36500)
    due.sort(key=lambda item: min((history.get(ledger._norm(a)) or epoch) for a in item[1]))
    due = due[:max_hosts()]
    if not due:
        return stats
    running = activity.log('run_check', f'Version and identity probes for {len(due)} host(s) of {domain.name}', project=project,
                           status='running', scan_id=scan.id)
    for sub, todo in due:
        if resources.abort_requested(scan_id) or resources.global_pause_requested(fail_closed=True):
            break
        ran = False
        for asset, entry in todo.items():
            try:
                found = run_one(project, domain.id, sub, entry, get=get, nmap_runner=nmap_runner, sleep=sleep)
            except Exception as exc:  # noqa: BLE001 - one probe failing never stops the rest; it is retried next time, not recorded as clean
                logger.warning('probe %s failed on host %s: %s', entry['probe'], sub.pk, type(exc).__name__)
                ledger.record(SERVICE, [asset], project, scan, 'failed')
                stats['errors'] += 1
                continue
            ledger.record(SERVICE, [asset], project, scan)  # a challenged answer is a result too: asked again after the window, not at every scan
            stats['probes'] += 1
            stats['versions'] += sum(1 for o in found if o['kind'] == 'version' and o['outcome'] == 'found')
            ran = True
        stats['hosts'] += int(ran)
    activity.settle(running, 'done', message=(f'Probes for {domain.name}: {stats["probes"]} probe(s) on {stats["hosts"]} host(s), '
                                              f'{stats["versions"]} version(s) found'), **stats)
    return stats
