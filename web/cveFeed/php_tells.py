"""A link to a ``.php`` URL is never by itself evidence that a host runs PHP.

The scanner library's page markers (``cvengine_scanner.fingerprint.BODY_MARKERS``) name PHP whenever a page carries ``href``, ``src`` or ``action``
pointing at a ``.php`` URL, with the source ``page:.php link``. A link says nothing about the server that answered the page: it may point at another
site altogether (a donation form, a partner's portal), and a same-site link may be a path the server rewrites or answers with a catch-all page. An
ASP.NET site on IIS that links to one ``.php`` page was shown as running PHP, counted on the Overview's threat card as "runs PHP, version unknown" and
given PHP's CVEs as "runtime of unknown version" candidates. The rules here, applied by the server to whatever produced the tell (the route check's
front-page fingerprints, which a Sentinel computes; the ``headers-root`` probe's observations; a supplier check's fingerprints):

* a link to another host or origin is ignored outright (where the page itself is in hand, ``same_origin_links``; a Sentinel's fingerprint does not
  say where the link pointed, so there it is treated as a same-origin link at most);
* a same-origin link is at most a **lead** (``state`` ``unverified``): kept as context, never a technology, never a CVE candidate;
* it becomes PHP only when the server itself confirms PHP (``server_confirms``): an ``X-Powered-By: PHP`` header, PHP in the Server header, a
  ``PHPSESSID`` cookie, a PHP error or ``phpinfo()`` banner in a page, or another route of the same host (a linked ``.php`` URL among them) that
  answered 2xx, not as the server's catch-all page, with one of those signs (``host_confirmation``);
* a strong contrary signal (``contrary_signal``: ASP.NET headers such as ``X-AspNet-Version``, an ASP.NET session cookie, an IIS Server header with
  nothing of PHP) makes the lead weaker still (``state`` ``contradicted``, lower confidence).

The web archive's ``.php`` URLs (``cveFeed.archive_urls``) are history of the same kind: shown as *seen in the web archive*, never a technology.
"""
import re
from urllib.parse import urljoin, urlsplit

LINK_SOURCE = 'page:.php link'
PRODUCT = 'PHP'
LEAD_KIND = 'lead'  # the ProbeObservation kind of a lead: never a version or identity reading, so no reader of those takes it for one
UNVERIFIED, CONTRADICTED = 'unverified', 'contradicted'
LEAD_CONFIDENCE = {UNVERIFIED: 0.3, CONTRADICTED: 0.1}
BODY_SCAN = 64 * 1024  # as the probes: a hostile page cannot make a pattern cost time by being long
MAX_PATHS = 5

_LINK_RE = re.compile(r"""(?:href|src|action)\s{0,4}=\s{0,4}["']([^"'\s<>]{1,500}?\.php(?:[?#][^"'\s<>]{0,500})?)["']""", re.IGNORECASE)
_POWERED_PHP_RE = re.compile(r'(?i)(?:^|[\s,;(])php(?:/\d|\b)')
_SERVER_PHP_RE = re.compile(r'(?i)\bPHP/\d')
_PHP_ERROR_RE = re.compile(
    r'(?i)<b>(?:Fatal error|Parse error|Warning|Notice|Deprecated)</b>:\s[^\n]{1,600}? in <b>[^<>\n]{1,300}</b> on line <b>\d{1,7}</b>'
    r'|\bPHP (?:Fatal error|Parse error|Warning|Notice|Deprecated):\s[^\n]{1,400}? on line \d{1,7}'
    r'|<title>\s{0,4}PHP \d{1,2}\.\d{1,3}\.\d{1,4}[^<]{0,40}phpinfo\(\)\s{0,4}</title>')
_ASPNET_HEADERS = ('x-aspnet-version', 'x-aspnetmvc-version')
_ASPNET_COOKIE_RE = re.compile(r'(?i)^(?:asp\.net_sessionid|\.aspxauth|\.aspnetcore\.|aspsessionid)')
_IIS_RE = re.compile(r'(?i)microsoft-iis')
_ASPNET_RE = re.compile(r'(?i)asp\.net')


def is_link_tell(name, source):
    """Whether a fingerprint or observation is the bare ``.php`` link marker (PHP named with no version, from a link on a page)."""
    return str(source or '') == LINK_SOURCE and str(name or '').split(':', 1)[0].strip().lower() == 'php'


def _lower_headers(headers):
    return {str(k).lower(): str(v) for k, v in (headers or {}).items()} if isinstance(headers, dict) else {}


def _origin(url):
    try:
        parts = urlsplit(url or '')
    except ValueError:
        return None
    if not parts.hostname:
        return None
    scheme = (parts.scheme or 'http').lower()
    try:
        port = parts.port or {'http': 80, 'https': 443}.get(scheme)
    except ValueError:
        return None
    return scheme, parts.hostname.lower().rstrip('.'), port


def same_origin_links(body, page_url):
    """The paths of the ``.php`` URLs ``body`` links to on the page's own origin (scheme, host and port of ``page_url``), at most MAX_PATHS. A link to
    another host or origin is left out: it says nothing about this server. Empty when ``page_url`` names no host."""
    here = _origin(page_url)
    if here is None:
        return []
    out = []
    for found in _LINK_RE.finditer((body or '')[:BODY_SCAN]):
        target = urljoin(page_url, found.group(1))
        if _origin(target) != here:
            continue
        path = urlsplit(target).path or '/'
        if path not in out:
            out.append(path[:300])
        if len(out) >= MAX_PATHS:
            break
    return out


def server_confirms(headers=None, cookies=(), powered_by='', server='', body=''):
    """The source of the server's own word that it runs PHP, or '': ``header:x-powered-by``, ``header:server``, ``cookie:PHPSESSID`` or
    ``body:php-error`` (a PHP error message or a ``phpinfo()`` page)."""
    lowered = _lower_headers(headers)
    if _POWERED_PHP_RE.search(' ' + (powered_by or lowered.get('x-powered-by', ''))):
        return 'header:x-powered-by'
    if _SERVER_PHP_RE.search(server or lowered.get('server', '')):
        return 'header:server'
    if any(str(c).strip().lower() == 'phpsessid' for c in cookies or ()):
        return 'cookie:PHPSESSID'
    if body and _PHP_ERROR_RE.search(body[:BODY_SCAN]):
        return 'body:php-error'
    return ''


def contrary_signal(headers=None, cookies=(), powered_by='', server=''):
    """What says the server is an ASP.NET or IIS stack rather than PHP, or '': an ASP.NET version header, ``X-Powered-By: ASP.NET``, an ASP.NET session
    cookie, or an IIS Server header."""
    lowered = _lower_headers(headers)
    for name in _ASPNET_HEADERS:
        if lowered.get(name):
            return f'header:{name}'
    if _ASPNET_RE.search(powered_by or lowered.get('x-powered-by', '')):
        return 'header:x-powered-by ASP.NET'
    if any(_ASPNET_COOKIE_RE.match(str(c).strip()) for c in cookies or ()):
        return 'cookie:ASP.NET session'
    if _IIS_RE.search(server or lowered.get('server', '')):
        return 'header:server IIS'
    return ''


def lead(state, paths=(), reason=''):
    """The lead a ``.php`` link leaves: ``{'name', 'source', 'state', 'paths', 'reason'}``."""
    return {'name': PRODUCT, 'source': LINK_SOURCE, 'state': state, 'paths': list(paths)[:MAX_PATHS], 'reason': str(reason)[:120]}


def _verdict(cross_origin_only, confirmed, contrary, paths):
    """``(confirmed source or '', lead or None)``."""
    if confirmed:
        return confirmed, None
    if cross_origin_only:
        return '', None
    if contrary:
        return '', lead(CONTRADICTED, paths, contrary)
    return '', lead(UNVERIFIED, paths, 'the server did not confirm PHP')


def judge_evidence(evidence, page_url='', body=None, confirmed=''):
    """Apply the rules to one route answer's evidence (``route_auth.classify``'s: ``fingerprints``, ``fingerprint_names``, ``headers``, ``cookies``,
    ``powered_by``, ``server``), in place, and return it. The ``.php`` link fingerprint leaves ``fingerprints``; PHP is put back only when the server
    confirms it (its source then says how), else a same-origin link is kept under ``leads``. ``body`` (the page, when the server has it) tells a
    same-origin link from a link elsewhere; without it the link's origin is unknown and it is a lead at most. ``confirmed``: the source of a
    confirmation another route of the host gave (``host_confirmation``). Idempotent."""
    if not isinstance(evidence, dict):
        return evidence
    found = [f for f in evidence.get('fingerprints') or [] if isinstance(f, dict)]
    tells = [f for f in found if is_link_tell(f.get('name'), f.get('source'))]
    leads = [x for x in evidence.get('leads') or [] if isinstance(x, dict)]
    php_lead = next((x for x in leads if x.get('name') == PRODUCT and x.get('source') == LINK_SOURCE), None)
    if not tells and not (php_lead and confirmed):
        return evidence
    keep = [f for f in found if not is_link_tell(f.get('name'), f.get('source'))]
    signals = {'headers': evidence.get('headers'), 'cookies': evidence.get('cookies') or (), 'powered_by': evidence.get('powered_by', ''),
               'server': evidence.get('server', '')}
    paths = same_origin_links(body, page_url) if body is not None else list((php_lead or {}).get('paths') or [])
    source, new_lead = _verdict(body is not None and not paths and not php_lead, server_confirms(**signals, body=body or '') or confirmed,
                                contrary_signal(**signals), paths)
    if source and not any(str(f.get('name', '')).split(':', 1)[0].lower() == 'php' for f in keep):
        keep.append({'name': PRODUCT, 'source': source[:48]})
    leads = [x for x in leads if x is not php_lead] + ([new_lead] if new_lead else [])
    evidence['fingerprints'] = keep
    if 'fingerprint_names' in evidence or keep:
        evidence['fingerprint_names'] = [f['name'] for f in keep]
    if leads:
        evidence['leads'] = leads
    else:
        evidence.pop('leads', None)
    return evidence


def host_confirmation(results):
    """``{host: source}`` for the hosts whose routes show the server confirming PHP: a route that answered 2xx, not as the server's catch-all page
    (``route_auth.CATCH_ALL``), whose headers or cookies say PHP (``server_confirms``). ``results``: ``[(url, route answer)]``, the answers having
    ``status``, ``state`` and ``evidence``. A linked ``.php`` URL that answers 200 with nothing of PHP confirms nothing (a rewrite, a static page)."""
    out = {}
    for url, result in results:
        if not isinstance(result, dict):
            continue
        status = result.get('status') or 0
        evidence = result.get('evidence') or {}
        if not (200 <= status < 300) or result.get('state') == 'catch_all' or evidence.get('catch_all'):
            continue
        source = server_confirms(evidence.get('headers'), evidence.get('cookies') or (), evidence.get('powered_by', ''), evidence.get('server', ''))
        host = (urlsplit(url).hostname or '').lower()
        if source and host and host not in out:
            out[host] = f'{source} on {urlsplit(url).path or "/"}'[:48]
    return out


def host_contrary(results):
    """``{host: reason}`` for the hosts whose routes (``[(url, route answer)]``, answers that came from the server: 2xx, not a catch-all) show an ASP.NET
    or IIS stack (``contrary_signal``): what a Sentinel's ``headers-root`` answer may not carry by itself."""
    out = {}
    for url, result in results:
        if not isinstance(result, dict):
            continue
        status = result.get('status') or 0
        evidence = result.get('evidence') or {}
        if not (200 <= status < 300) or result.get('state') == 'catch_all':
            continue
        reason = contrary_signal(evidence.get('headers'), evidence.get('cookies') or (), evidence.get('powered_by', ''), evidence.get('server', ''))
        host = (urlsplit(url).hostname or '').lower()
        if reason and host and host not in out:
            out[host] = reason
    return out


def judge_observations(observations, response=None, page_url='', confirmed='', contrary=''):
    """Apply the rules to a probe's observations (``probes.observations_from_page`` or a Sentinel's ``headers-root`` answer). The ``.php`` link
    observation becomes a lead (kind ``lead``, outcome ``hidden``, ``variant`` the lead's state), or, when the server confirms PHP, a ``hidden``
    version observation whose source says how. ``response`` (the page, when the server read it) gives the headers, cookies and body; a Sentinel's
    answer has only the observations, so the other observations (``.NET Framework CLR`` from ``X-AspNet-Version``, PHP from a header),
    ``confirmed`` and ``contrary`` (what the host's routes say, ``host_confirmation`` and ``host_contrary``) are what decides."""
    tells = [o for o in observations if o.get('kind') == 'version' and is_link_tell(o.get('product'), o.get('source'))]
    if not tells:
        return observations
    rest = [o for o in observations if o not in tells]
    if any(str(o.get('product', '')).lower() == 'php' and o.get('kind') == 'version' for o in rest):
        return rest  # PHP read from the server's own answer: the link adds nothing
    if response is not None:
        headers = _lower_headers(response.get('headers'))
        cookies = list(response.get('cookies') or ()) + _cookie_names(headers.get('set-cookie', ''))
        signals = {'headers': headers, 'cookies': cookies, 'powered_by': response.get('powered_by', ''), 'server': response.get('server', '')}
        page_url = response.get('final_url') or response.get('url') or page_url
        paths = same_origin_links(response.get('body') or '', page_url)
        source = server_confirms(**signals, body=response.get('body') or '') or confirmed
        contrary = contrary_signal(**signals) or contrary
        cross_only = not paths
    else:
        paths, source, cross_only = [], confirmed, False
        contrary = contrary or next((o['source'] for o in rest if str(o.get('source', '')).startswith(tuple(f'header:{h}' for h in _ASPNET_HEADERS))), '') or next(
            (f"{o.get('product')} ({o.get('source')})" for o in rest if _ASPNET_RE.search(str(o.get('product', ''))) or _IIS_RE.search(str(o.get('product', '')))
             or str(o.get('product', '')).lower().startswith(('.net framework', 'microsoft iis', 'iis'))), '')
    source, new_lead = _verdict(cross_only, source, contrary, paths)
    first = tells[0]
    if source:
        return rest + [{**first, 'kind': 'version', 'outcome': 'hidden', 'version': '', 'source': source[:48], 'evidence': {'confirmed_by': source[:48]}}]
    if new_lead is None:
        return rest
    return rest + [{**first, 'kind': LEAD_KIND, 'outcome': 'hidden', 'version': '', 'variant': new_lead['state'],
                    'confidence': LEAD_CONFIDENCE[new_lead['state']], 'source': LINK_SOURCE,
                    'evidence': {'lead': True, 'paths': new_lead['paths'], 'reason': new_lead['reason']}}]


def _cookie_names(value):
    return [part.split('=', 1)[0].strip() for part in re.split(r',(?=[^;,]+=)|\n', value or '') if '=' in part]


def drop_link_tells(fingerprints):
    """``fingerprints`` (``[{'name', 'source'}]``) without the ``.php`` link marker: what a supplier check's front page says it runs, where the page is
    not in hand and nothing of the supplier's server can confirm the link."""
    return [f for f in fingerprints or [] if not (isinstance(f, dict) and is_link_tell(f.get('name'), f.get('source')))]


# ----------------------------------------------------------------------------- the update's catch-up (manage.py backfill_php_link_tells)

def _stored_signals(project_ids, hosts):
    """``({(project id, host): source}, {(project id, host): reason})``: the hosts whose stored, live routes show the server confirming PHP
    (``host_confirmation``, or a route fingerprint naming PHP from anything but a ``.php`` link: a header the Sentinel read), and those whose routes show
    an ASP.NET or IIS stack (``host_contrary``)."""
    from cveFeed.models import RouteAuth
    out, against = {}, {}
    if not hosts:
        return out, against
    rows = RouteAuth.objects.filter(project_id__in=sorted(project_ids), host__in=sorted(hosts), retired_at__isnull=True) \
        .values_list('project_id', 'host', 'url', 'http_status', 'auth_state', 'evidence')
    by_project = {}
    for project_id, host, url, status, state, evidence in rows:
        evidence = evidence if isinstance(evidence, dict) else {}
        by_project.setdefault(project_id, []).append((url, {'status': status, 'state': state, 'evidence': evidence}))
        for f in evidence.get('fingerprints') or []:
            if isinstance(f, dict) and str(f.get('name', '')).split(':', 1)[0].lower() == 'php' and f.get('source') != LINK_SOURCE \
                    and 200 <= (status or 0) < 300 and state != 'catch_all':
                out.setdefault((project_id, host), str(f.get('source') or 'route')[:48])
    for project_id, results in by_project.items():
        for host, source in host_confirmation(results).items():
            out.setdefault((project_id, host), source)
        for host, reason in host_contrary(results).items():
            against[(project_id, host)] = reason
    return out, against


def catch_up(apply=False, batch=200):
    """The one-time catch-up an update runs: PHP read from nothing but a ``.php`` link is a lead, not a technology. It

    1. judges the stored route answers whose fingerprints carry the ``page:.php link`` marker (``judge_evidence``; the page is not stored, so a link's
       origin is unknown and it becomes a lead unless the host's routes confirm PHP);
    2. turns the ``headers-root`` probe rows that state "PHP, version not stated" from the link into leads (``judge_observations``, with the host's
       other readings of that probe and its routes);
    3. removes every bare ``PHP`` technology link the route check made (source ``route``) on a host whose routes do not confirm PHP, on every stored row
       of the host (a later scan's row inherits its predecessor's links), and correlates the current rows that lost one, so the version-unknown PHP
       candidates, the threat card's "run PHP, version unknown" hosts and the situations built on them drop out.

    Idempotent: a second run finds no marker, no such probe row and no such link. Returns ``{'routes', 'probes', 'links', 'hosts', 'matches'}``."""
    from cveFeed import correlation
    from cveFeed.models import ProbeObservation, RouteAuth
    from startScan.models import Subdomain, SubdomainTechnology
    out = {'routes': 0, 'probes': 0, 'links': 0, 'hosts': 0, 'matches': 0}
    routes = [r for r in RouteAuth.objects.filter(evidence__fingerprints__contains=[{'source': LINK_SOURCE}]).only('id', 'project_id', 'host', 'url', 'evidence')
              if any(is_link_tell(f.get('name'), f.get('source')) for f in (r.evidence or {}).get('fingerprints') or [] if isinstance(f, dict))]
    probe_rows = [r for r in ProbeObservation.objects.filter(kind='version', source=LINK_SOURCE) if is_link_tell(r.product, r.source)]
    links = list(SubdomainTechnology.objects.filter(source='route', technology__name__iexact=PRODUCT)
                 .values_list('id', 'subdomain_id', 'subdomain__name', 'subdomain__target_domain__project_id'))
    hosts = {r.host for r in routes} | {r.host for r in probe_rows} | {str(name).lower() for _i, _s, name, _p in links}
    projects = {r.project_id for r in routes} | {r.project_id for r in probe_rows} | {p for _i, _s, _n, p in links if p}
    confirmed, against = _stored_signals(projects, hosts)
    drop = [(link_id, sub_id) for link_id, sub_id, name, project_id in links if (project_id, str(name).lower()) not in confirmed]
    out.update(routes=len(routes), probes=len(probe_rows), links=len(drop))
    if not apply:
        return out
    for row in routes:
        row.evidence = judge_evidence(dict(row.evidence or {}), row.url, confirmed=confirmed.get((row.project_id, row.host), ''))
        row.save(update_fields=['evidence'])
    for row in probe_rows:
        siblings = [{'kind': o.kind, 'product': o.product, 'version': o.version, 'variant': o.variant, 'outcome': o.outcome, 'confidence': o.confidence,
                     'source': o.source, 'port': o.port, 'url': o.url, 'evidence': o.evidence or {}}
                    for o in ProbeObservation.objects.filter(project_id=row.project_id, host=row.host, probe=row.probe).exclude(pk=row.pk)]
        mine = {'kind': row.kind, 'product': row.product, 'version': row.version, 'variant': row.variant, 'outcome': row.outcome, 'confidence': row.confidence,
                'source': row.source, 'port': row.port, 'url': row.url, 'evidence': row.evidence or {}}
        judged = [o for o in judge_observations(siblings + [mine], confirmed=confirmed.get((row.project_id, row.host), ''),
                                                contrary=against.get((row.project_id, row.host), '')) if o not in siblings]
        domain_id, project_id, host, probe, observed = row.domain_id, row.project_id, row.host, row.probe, row.observed_at
        row.delete()
        for o in judged:
            ProbeObservation.objects.update_or_create(
                project_id=project_id, host=host, probe=probe, port=o['port'], kind=o['kind'], product=o['product'],
                defaults={'domain_id': domain_id, 'version': o['version'], 'variant': o['variant'], 'url': o['url'], 'outcome': o['outcome'],
                          'confidence': o['confidence'], 'source': o['source'], 'evidence': o['evidence'], 'observed_at': observed})
    moved = {sub_id for _link, sub_id in drop}
    SubdomainTechnology.objects.filter(pk__in=[link_id for link_id, _sub in drop]).delete()
    current = sorted(Subdomain.objects.filter(correlation.latest_scan_q()).filter(pk__in=moved).values_list('pk', flat=True)) if moved else []
    out['hosts'] = len(current)
    if current:
        cve_by_id, index = correlation.cve_pool()
        for start in range(0, len(current), batch):
            subs = list(Subdomain.objects.filter(pk__in=current[start:start + batch]).select_related('target_domain', 'scan_history')
                        .prefetch_related('technologies', 'ip_addresses__ports'))
            out['matches'] += correlation.correlate_subdomains(subs, index, cve_by_id, min_confidence=0.4)[1]
    return out
