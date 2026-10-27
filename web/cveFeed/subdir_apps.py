"""Applications mounted under a subdirectory of a web host the project already knows (``/jira``, ``/grafana``, ``/phpmyadmin``, ``/owa`` ...).

A product installed under a path is invisible to every check that reads only the front page, and it can carry its own known CVE. This sweep
asks each web host of a project, once per window, whether a small curated set of well-known mount paths answers, and reads WHAT answers from
the response so the product and, when the page states it, the version reach the same Technology records and CVE correlation every other probe
feeds. It is not content discovery:

* the questions are the curated list in ``data/subdir_apps.json`` (about 40 paths, each with the product it indicates and the signatures that
  confirm it), plus at most ``MAX_LEADS`` directories the host's own crawled URLs, archived URLs, ``robots.txt`` and ``sitemap.xml`` already
  show; nothing is guessed, no wordlist, no extensions, no parameters;
* one GET per path per host, plus one GET of a path no site serves (the baseline that tells a real mount from a server that answers every
  path alike), ``/robots.txt`` and ``/sitemap.xml``; never more than ``CVENGINE_SUBDIR_MAX_REQUESTS`` requests per host per sweep (60);
* only 200, 301, 302, 401 and 403 count as "something is there"; redirects are never followed; no body, no cookie, no credential;
* a global and a per-host gap between requests (``cveFeed.slow_web``), the service ledger (a week), the global pause, exclusions and the
  scannable-address gate before every host, and a challenge from an edge is recorded as ``challenged`` and never retried or worked around.

A path that answers is a *lead*, never a finding. It becomes a confirmed application only when a signature of the curated data (the page's
title, a header, a marker in the body) names a product, and it becomes a Technology of the host only when the response also states a
version: product AND version, as the match rule requires (see docs/PIPELINE.md, Match). A product that answers and states no version is
recorded as ``hidden``, exactly like the version probes record it, and a path that only answered is recorded as a lead with its status."""
import functools
import json
import logging
import os
import re
from collections import Counter
from datetime import timedelta
from urllib.parse import urlsplit

from django.utils import timezone

from cveFeed import slow_web, vhost_scan

logger = logging.getLogger(__name__)

SERVICE = 'subapp'
PROBE = 'subapp-probe'
KIND = 'subapp'
DATA_FILE = os.path.join(os.path.dirname(__file__), 'data', 'subdir_apps.json')
THERE = (200, 301, 302, 401, 403)  # the only answers that mean "something is there"
CONFIRM = 0.7  # a signature at or above this names the product; below it the path is a lead with a hint
BASELINE_PATH = '/.cvengine-probe/404'
ROBOTS_PATH, SITEMAP_PATH = '/robots.txt', '/sitemap.xml'
MAX_LEADS = 10
DEFAULT_MAX_REQUESTS = 60
DEFAULT_MAX_HOSTS = 6
BODY_SCAN = 64 * 1024
CLAIM_TTL = 1800
NOISE = frozenset({
    'assets', 'static', 'images', 'image', 'img', 'css', 'js', 'fonts', 'font', 'media', 'files', 'file', 'uploads', 'upload', 'download', 'downloads',
    'wp-content', 'wp-includes', 'wp-admin', 'wp-json', 'cgi-bin', 'api', 'search', 'tag', 'tags', 'category', 'categories', 'page', 'pages', 'node',
    'user', 'users', 'login', 'logout', 'content', 'themes', 'theme', 'sites', 'public', 'dist', 'build', 'vendor', 'lib', 'libs', 'scripts', 'script',
    'styles', 'style', 'template', 'templates', 'resources', 'res', 'inc', 'include', 'includes', 'tmp', 'cache', 'data', 'news', 'blog', 'about',
    'contact', 'products', 'product', 'services', 'service', 'support', 'help', 'faq', 'cart', 'checkout', 'account', 'profile', 'sitemap', 'feed', 'rss',
})
_SEGMENT = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{1,39}$')
_ROBOTS_LINE = re.compile(r'(?im)^\s*(?:dis)?allow:\s*(/\S*)')
_SITEMAP_LOC = re.compile(r'(?is)<loc>\s*([^<\s]{1,500})\s*</loc>')


def enabled():
    """CVENGINE_SUBDIR_APPS: on unless it is 0/false/no/off."""
    return slow_web.truthy(os.environ.get('CVENGINE_SUBDIR_APPS', '1'))


def max_requests():
    return slow_web.env_int('CVENGINE_SUBDIR_MAX_REQUESTS', DEFAULT_MAX_REQUESTS, 10, 150)


def max_hosts():
    return slow_web.env_int('CVENGINE_SUBDIR_MAX_HOSTS', DEFAULT_MAX_HOSTS, 1, 100)


# ----------------------------------------------------------------------------- the curated data

class CatalogueError(ValueError):
    """The data file is not what it must be (a path that is not a plain mount path, a duplicate, a pattern that does not compile)."""


@functools.lru_cache(maxsize=1)
def catalogue():
    """The curated entries with their patterns compiled: ``[{'path', 'product', 'indicates', 'signatures': [(where, regex, confidence)],
    'version': [(where, regex)]}]``. Validated on load: every path is a plain absolute mount path, paths and products are unique."""
    with open(DATA_FILE, encoding='utf-8') as handle:
        raw = json.load(handle)
    entries, paths, products = [], set(), set()
    for item in raw:
        path, product = item.get('path'), item.get('product')
        if not isinstance(path, str) or not re.fullmatch(r'/[A-Za-z0-9][A-Za-z0-9_./-]{0,58}', path) or '..' in path:
            raise CatalogueError(f'not a plain mount path: {path!r}')
        if not product or path in paths or product in products or not item.get('indicates'):
            raise CatalogueError(f'duplicate or incomplete entry: {path}')
        paths.add(path)
        products.add(product)
        try:
            signatures = [(s['where'], re.compile(s['regex']), float(s['confidence'])) for s in item['signatures']]
            version = [(v['where'], re.compile(v['regex'])) for v in item.get('version', [])]
        except (KeyError, re.error, ValueError) as exc:
            raise CatalogueError(f'{path}: {exc}') from None
        entries.append({'path': path, 'product': product, 'indicates': item['indicates'], 'signatures': signatures, 'version': version})
    return entries


def curated_paths():
    return [entry['path'] for entry in catalogue()]


# ----------------------------------------------------------------------------- reading a response (pure)

def _value(response, where):
    if where == 'title':
        from cveFeed import route_auth
        title = response.get('title')
        return route_auth.page_title(response.get('body') or '') if title is None else title
    if where == 'body':
        return (response.get('body') or '')[:BODY_SCAN]
    if where == 'location':
        return str(response.get('location') or '')
    headers = {k.lower(): v for k, v in (response.get('raw_headers') or response.get('headers') or {}).items()}
    return str(headers.get(where.split(':', 1)[1], ''))


def identify(response, path=''):
    """``{'product', 'confidence', 'source', 'version', 'indicated'}`` for what the response says it is, or None. Every entry's signatures are
    tried on the response (a mount can hold a product the path does not suggest), the strongest signature wins and the requested path's own
    entry wins a tie. ``version`` is '' unless one of the product's own version patterns reads it from the response. A signature below
    ``CONFIRM`` leaves ``confidence`` low: the caller treats that as a lead."""
    best = None
    for entry in catalogue():
        for where, pattern, confidence in entry['signatures']:
            if pattern.search(_value(response, where)):
                rank = (confidence, entry['path'] == path)
                if best is None or rank > best[0]:
                    best = (rank, entry, f'{where}:{pattern.pattern[:30]}')
    if best is None:
        return None
    (confidence, _), entry, source = best
    version = ''
    for where, pattern in entry['version']:
        found = pattern.search(_value(response, where))
        if found:
            version = found.group(1)[:100]
            break
    return {'product': entry['product'], 'confidence': confidence, 'source': source[:48], 'version': version, 'indicated': entry['path']}


def _location_key(location):
    """Where a redirect leads, without host or query: a server that sends every path to its login page sends them all to the same place."""
    if not location:
        return ''
    try:
        return (urlsplit(location.strip()).path or '/').lower()[:200]
    except ValueError:
        return ''


def is_catch_all(fp, baselines):
    """Whether a path's answer is the answer the server gives to a path nobody serves (or to its front page): not a mount."""
    for base in baselines:
        if not base:
            continue
        if 300 <= fp['status'] < 400 and 300 <= base['status'] < 400:
            if _location_key(fp['location']) == _location_key(base['location']):
                return True
        elif vhost_scan.similar(fp, base):
            return True
    return False


def mount_of(url_or_path):
    """The mount directory (``/portal/``) a crawled or archived URL points into, or None for a root-level page, an asset or a common
    directory that holds content, not an application."""
    try:
        path = urlsplit(url_or_path).path or ''
    except ValueError:
        return None
    segments = [s for s in path.split('/') if s]
    if not segments or (len(segments) < 2 and not path.endswith('/')):
        return None
    segment = segments[0]
    if not _SEGMENT.match(segment) or segment.lower() in NOISE or (len(segment) == 2 and segment.isalpha()):
        return None
    return f'/{segment}/'


def lead_paths(urls_by_source, known):
    """``{path: source}`` for at most ``MAX_LEADS`` mount directories the host's own data shows (``urls_by_source``: ``{source: [url or path]}``),
    most often seen first, excluding the curated paths and ``known``."""
    counts, source_of = Counter(), {}
    for source, urls in urls_by_source.items():
        for url in urls:
            mount = mount_of(url)
            if mount and mount not in known:
                counts[mount] += 1
                source_of.setdefault(mount, source)
    return {path: source_of[path] for path, _n in counts.most_common(MAX_LEADS)}


def robots_paths(body):
    return [m.group(1) for m in _ROBOTS_LINE.finditer(body or '')][:200]


def sitemap_paths(body, host):
    out = []
    for m in _SITEMAP_LOC.finditer((body or '')[:BODY_SCAN]):
        try:
            parts = urlsplit(m.group(1))
        except ValueError:
            continue
        if (parts.hostname or '').lower() == host.lower():
            out.append(parts.path or '/')
    return out[:500]


# ----------------------------------------------------------------------------- what is known about a host

def known_urls(project_id, host):
    """``{'crawled': [...], 'archive': [...]}``: the URLs and example paths the project already holds for the host."""
    from cveFeed.models import HostArchive
    from startScan.models import EndPoint
    crawled = list(EndPoint.objects.filter(subdomain__target_domain__project_id=project_id, subdomain__name=host)
                   .values_list('http_url', flat=True)[:3000])
    archive = []
    row = HostArchive.objects.filter(project_id=project_id, host=host).first()
    if row is not None:
        for info in (row.technologies or {}).values():
            archive += [p for p in (info.get('sample') or []) if isinstance(p, str)]
    return {'crawled': [u for u in crawled if u], 'archive': archive}


def web_hosts(project_id):
    """``[{'name', 'sub', 'scheme', 'port', 'connect_ip', 'asset'}]``: the web hosts of the project, one per merged host (the row the Hosts page
    shows), and one per distinct application the virtual host sweep found on an address (asked at that address with its name)."""
    from cveFeed import route_auth
    from cveFeed.counts import host_reps
    from cveFeed.models import ProbeObservation
    from startScan.models import Subdomain
    from targetApp.models import Domain
    domain_ids = list(Domain._base_manager.filter(project_id=project_id).values_list('id', flat=True))
    vhosts = list(ProbeObservation.objects.filter(project_id=project_id, probe=vhost_scan.PROBE, kind=vhost_scan.KIND, outcome='found')
                  .order_by('host', 'product'))
    carried = {o.host for o in vhosts}
    out = []
    reps = host_reps(domain_ids=domain_ids).filter(target_domain__project_id=project_id)
    for sub in reps.prefetch_related('ip_addresses__ports').select_related('target_domain').order_by('name'):
        name = sub.name.strip().lower()
        if sub.scan_history_id is None and name in carried:
            continue  # a name the virtual host sweep added: asked at its own address below, never at whatever its DNS says
        bases = route_auth.web_bases(sub)
        if not bases:
            continue
        parts = urlsplit(bases[0])
        scheme, port = parts.scheme, parts.port or (443 if parts.scheme == 'https' else 80)
        out.append({'name': name, 'sub': sub, 'scheme': scheme, 'port': port, 'connect_ip': None, 'asset': f'{name}|{scheme}://{slow_web.authority(name, port, scheme)}'})
    for obs in vhosts:
        sub = Subdomain.objects.filter(target_domain__project_id=project_id, name=obs.host).order_by('-id').first()
        scheme = (obs.evidence or {}).get('scheme') or ('https' if obs.port == 443 else 'http')
        if sub is not None:
            out.append({'name': obs.host, 'sub': sub, 'scheme': scheme, 'port': obs.port, 'connect_ip': obs.product,
                        'asset': f'{obs.host}|{scheme}://{slow_web.authority(obs.host, obs.port, scheme)}@{obs.product}'})
    return out


# ----------------------------------------------------------------------------- storing

def record(project_id, domain_id, name, port, product, outcome, confidence, source, path, version='', variant='', evidence=None):
    from cveFeed.models import ProbeObservation
    row, _ = ProbeObservation.objects.update_or_create(
        project_id=project_id, host=name.lower(), probe=PROBE, port=port, kind=KIND, product=product[:120],
        defaults={'domain_id': domain_id, 'version': version[:100], 'variant': variant[:60], 'url': path[:500], 'outcome': outcome,
                  'confidence': confidence, 'source': source[:48], 'evidence': evidence or {}, 'observed_at': timezone.now()})
    return row


def _technology_rows(rows):
    """The version observations of ``rows`` as ``probes`` writes them: a Technology is added only for a product AND a stated version."""
    return [{'kind': 'version', 'product': r.product, 'version': r.version, 'variant': '', 'outcome': 'found'}
            for r in rows if r.outcome == 'found' and r.version and (r.evidence or {}).get('confirmed')]


def apply_technologies(project_id, name, rows):
    """Add the versioned applications to the host's current rows and correlate again. Returns the technologies added."""
    from cveFeed import probes
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    observations = _technology_rows(rows)
    if not observations:
        return 0
    added = 0
    for sub in Subdomain.objects.filter(latest_scan_q(), target_domain__project_id=project_id, name=name).prefetch_related('technologies'):
        count = probes.apply_to_subdomain(sub, observations)
        if count:
            probes.recorrelate(sub)
        added += count
    return added


def carry_forward(scan):
    """Hosts are stored once per scan, so a fresh row starts without the technologies an earlier sweep found. Gives this scan's rows the
    versioned applications seen in the last four ledger windows. Never fatal. Returns the technologies added."""
    from cveFeed import ledger
    from cveFeed.models import ProbeObservation
    from startScan.models import Subdomain
    try:
        project = scan.domain.project_id
        cutoff = timezone.now() - timedelta(seconds=ledger.ttl(SERVICE) * 4)
        by_host = {}
        for row in ProbeObservation.objects.filter(project_id=project, probe=PROBE, kind=KIND, outcome='found', observed_at__gte=cutoff).exclude(version=''):
            by_host.setdefault(row.host, []).append(row)
        from cveFeed import probes
        added = 0
        for sub in Subdomain.objects.filter(scan_history=scan, name__in=list(by_host)).prefetch_related('technologies'):
            added += probes.apply_to_subdomain(sub, _technology_rows(by_host.get(sub.name.lower(), [])))
        return added
    except Exception:  # noqa: BLE001
        logger.exception('could not carry the subdirectory applications onto scan %s', getattr(scan, 'pk', None))
        return 0


# ----------------------------------------------------------------------------- one host

def sweep_host(project_id, entry, fetch, pace, stop=None, budget=None):
    """Ask one web host its baseline, ``robots.txt``, ``sitemap.xml`` and then its mount paths, within ``budget`` requests. Returns the counts
    (and ``complete``: False when the sweep stopped early, so the host stays due)."""
    from cveFeed import ledger
    name, sub, scheme, port, connect_ip = entry['name'], entry['sub'], entry['scheme'], entry['port'], entry['connect_ip']
    budget = budget or max_requests()
    domain_id = sub.target_domain_id
    base = f'{scheme}://{slow_web.authority(name, port, scheme)}'
    summary = {'requests': 0, 'there': 0, 'confirmed': 0, 'versions': 0, 'leads': 0, 'catch_all': 0, 'challenged': 0, 'complete': False,
               'paused': False}
    state = {'stopped': False, 'busy': False}

    def ask(path):
        """One GET, or None (stopped, over budget, no answer). A challenge or a busy server ends this host's sweep; a pause too."""
        if state['stopped'] or summary['requests'] >= budget:
            return None
        if stop and stop():
            state['stopped'] = summary['paused'] = True
            return None
        pace.wait(connect_ip or name)
        summary['requests'] += 1
        try:
            response = fetch(base + path, connect_ip=connect_ip) if connect_ip else fetch(base + path)
        except (OSError, ValueError):
            return None
        if response.get('challenge'):
            edge = response['challenge']
            record(project_id, domain_id, name, port, edge, 'challenged', 0.0, 'edge-challenge', path, variant='edge',
                   evidence={'edge': edge, 'status': response.get('status'), 'hint': vhost_scan.HINT.format(edge=edge).replace(
                       'whether this address serves other sites', 'which applications this host serves under subdirectories')})
            summary['challenged'] += 1
            state['stopped'] = True
            return None
        if slow_web.busy(response):
            state['stopped'] = state['busy'] = True
            return None
        return response

    baseline_response = ask(BASELINE_PATH)
    baselines = [vhost_scan.fingerprint_of(baseline_response)] if baseline_response is not None else []
    root = _root_fingerprint(project_id, name)
    baselines.append(root)
    robots = ask(ROBOTS_PATH) if not state['stopped'] else None
    sitemap = ask(SITEMAP_PATH) if not state['stopped'] else None
    urls = known_urls(project_id, name)
    urls_by_source = {'crawled': urls['crawled'], 'archive': urls['archive'],
                      'robots': robots_paths((robots or {}).get('body')) if robots and robots.get('status') == 200 else [],
                      'sitemap': sitemap_paths((sitemap or {}).get('body'), name) if sitemap and sitemap.get('status') == 200 else []}
    known = set(curated_paths())
    leads = lead_paths(urls_by_source, known)
    plan = [(entry_['path'], 'curated') for entry_ in catalogue()] + [(path, source) for path, source in leads.items()]
    hits, probed = set(), set()
    for path, source in plan:
        response = ask(path)
        probed.add(path)
        if response is None:
            continue
        fp = vhost_scan.fingerprint_of(response)
        if fp['status'] not in THERE:
            continue
        summary['there'] += 1
        if is_catch_all(fp, baselines):
            summary['catch_all'] += 1
            continue
        found = identify(response, path)
        evidence = {'status': fp['status'], 'title': fp['title'], 'server': fp['server'], 'location': fp['location'], 'lead': source,
                    'base': base, 'indicated': (found or {}).get('indicated', path)}
        if connect_ip:
            evidence['ip'] = connect_ip
        if found and found['confidence'] >= CONFIRM:
            evidence['confirmed'] = True
            record(project_id, domain_id, name, port, found['product'], 'found' if found['version'] else 'hidden', found['confidence'], found['source'], path,
                   version=found['version'], evidence=evidence)
            summary['confirmed'] += 1
            summary['versions'] += int(bool(found['version']))
            hits.add(path)
        else:
            hint = found['product'] if found else (next((e['product'] for e in catalogue() if e['path'] == path), None) or path)
            evidence['confirmed'] = False
            record(project_id, domain_id, name, port, hint, 'found', 0.3, 'path-only', path, variant='lead', evidence=evidence)
            summary['leads'] += 1
            hits.add(path)
    _retire_missing(project_id, name, port, probed, hits)
    rows = _rows(project_id, name, port)
    apply_technologies(project_id, name, rows)
    summary['complete'] = not summary['paused'] and not state['busy']  # a challenged host is complete: it is asked again after the window
    if summary['complete']:
        ledger.record(SERVICE, [entry['asset']], project_id)
    return summary


def _rows(project_id, name, port):
    from cveFeed.models import ProbeObservation
    return list(ProbeObservation.objects.filter(project_id=project_id, host=name, probe=PROBE, kind=KIND, port=port, outcome__in=('found', 'hidden')))


def _retire_missing(project_id, name, port, probed, hits):
    """A mount that answered at an earlier sweep and was asked again now and did not answer: its row becomes ``absent``."""
    from cveFeed.models import ProbeObservation
    ProbeObservation.objects.filter(project_id=project_id, host=name, probe=PROBE, kind=KIND, port=port, outcome__in=('found', 'hidden'),
                                    url__in=list(probed - hits)).update(outcome='absent', observed_at=timezone.now())


def _root_fingerprint(project_id, name):
    """The stored answer of the host's front page (the route check), the second baseline: a single-page application that serves its front page
    for every path is not a set of mounts."""
    from cveFeed.models import RouteAuth
    row = RouteAuth.objects.filter(project_id=project_id, host=name, path='/').exclude(http_status__isnull=True).order_by('-checked_at').first()
    if row is None or not row.http_status:
        return None
    return {'status': int(row.http_status), 'title': ' '.join((row.title or '').split())[:200], 'length': int((row.evidence or {}).get('bytes') or 0),
            'location': row.redirect_to or '', 'server': ''}


# ----------------------------------------------------------------------------- the sweep

def _allowed(project_id, entry, banned, vet_ip):
    """The gate every host passes before one request is sent: not excluded or archived, a name that does not resolve to a prohibited
    address (a DNS host), or a vetted address that is not a shared platform's (a virtual host)."""
    from targetApp.target_types import scannable_hosts
    name = entry['name']
    if name.rstrip('.') in banned:
        return False
    if entry['connect_ip']:
        return bool(vet_ip(entry['connect_ip']))
    return bool(scannable_hosts([name], project=project_id))


def _vet_address(project_id, address):
    from cveFeed import hosting
    from targetApp.target_types import is_scannable_ip
    return is_scannable_ip(address, project=project_id) and not hosting.shared_by_address([address])


def sweep(project_id, fetch=None, pace=None, stop=None, vet_ip=None):
    """The due web hosts of one project, at most ``max_hosts`` per run, never-asked first then longest-waiting. Returns the summary (and
    ``skipped`` with the reason when nothing ran)."""
    from cveFeed import activity, exclusions, ledger
    from cveFeed.archive_rediscovery import archived_names
    from reNgine import resources
    summary = {'hosts': 0, 'requests': 0, 'there': 0, 'confirmed': 0, 'versions': 0, 'leads': 0, 'catch_all': 0, 'challenged': 0}
    if not enabled():
        return {**summary, 'skipped': 'subdirectory application discovery is turned off (CVENGINE_SUBDIR_APPS=0)'}
    stop = stop or (lambda: resources.global_pause_requested(fail_closed=True))
    if stop():
        return {**summary, 'skipped': 'scanning is paused: the hosts stay due'}
    from cveFeed.conductor import bounty_blocked_projects
    if project_id in bounty_blocked_projects():
        return {**summary, 'skipped': 'the bug bounty engagement has not confirmed automated testing'}
    owner = f'subapp-{os.getpid()}'
    with resources.redis_claim(f'cvengine:subapp:{project_id}', owner, CLAIM_TTL) as holder:
        if holder is not True:
            return {**summary, 'skipped': 'another subdirectory sweep is running for this project'}
        pace = pace or slow_web.Pace()
        fetch = fetch or functools.partial(slow_web.get, project=project_id)
        vet_ip = vet_ip or functools.partial(_vet_address, project_id)
        banned = exclusions.excluded_names(project_id) | archived_names(project_id)
        by_asset = {e['asset']: e for e in web_hosts(project_id)}
        due = ledger.stale_first(SERVICE, [(0, asset, project_id) for asset in by_asset], )
        running = None
        for _domain, asset, _project in due[:max_hosts()]:
            if stop():
                summary['skipped'] = 'scanning is paused: the hosts stay due'
                break
            entry = by_asset[asset]
            if not _allowed(project_id, entry, banned, vet_ip):
                continue
            if running is None:
                running = activity.log('run_check', 'Subdirectory application check of the project\'s web hosts', project=project_id, status='running')
            try:
                part = sweep_host(project_id, entry, fetch, pace, stop=stop)
            except Exception as exc:  # noqa: BLE001 - one host failing never stops the rest; it stays due
                logger.warning('subdirectory sweep of host %s failed: %s', entry['sub'].pk, type(exc).__name__)
                continue
            summary['hosts'] += 1
            for key in ('requests', 'there', 'confirmed', 'versions', 'leads', 'catch_all', 'challenged'):
                summary[key] += part[key]
            if part['paused']:
                summary['skipped'] = 'scanning is paused: the hosts stay due'
                break
        if running is not None:
            activity.settle(running, 'done', message=(
                f'Subdirectory applications: {summary["hosts"]} host(s) asked, {summary["confirmed"]} application(s) confirmed '
                f'({summary["versions"]} with a version), {summary["leads"]} unconfirmed lead(s)'
                + (f', {summary["challenged"]} challenged by an edge' if summary['challenged'] else '')), **summary)
    return summary


def sweep_all(**kwargs):
    """Every project's due hosts. One sweep at a time across workers; the work is spread over runs by the per-run cap."""
    from dashboard.models import Project
    from cveFeed import ledger
    if not enabled():
        return {'skipped': 'subdirectory application discovery is turned off (CVENGINE_SUBDIR_APPS=0)'}
    if not ledger.sweep_claim('subapp', 25 * 60):
        return {'skipped': 'another sweep is running'}
    totals = {}
    for project_id in Project.objects.values_list('id', flat=True):
        part = sweep(project_id, **kwargs)
        for key, value in part.items():
            if isinstance(value, int):
                totals[key] = totals.get(key, 0) + value
        if part.get('skipped', '').startswith('scanning is paused'):
            totals['skipped'] = part['skipped']
            break
    return totals


# ----------------------------------------------------------------------------- reading it back

def applications_from_rows(rows):
    """``[{'host', 'path', 'product', 'version', 'confirmed', 'outcome', 'status', 'title', 'hint', 'observed_at'}]`` from probe rows (any
    kind; only the subdirectory ones are read): the applications under subdirectories of a host, confirmed first, leads after, and an edge
    that challenged the sweep with what to allow. For the host page."""
    out = [{'host': r.host, 'path': r.url, 'product': r.product, 'version': r.version, 'confirmed': bool((r.evidence or {}).get('confirmed')),
            'outcome': r.outcome, 'status': (r.evidence or {}).get('status'), 'title': (r.evidence or {}).get('title', ''),
            'hint': (r.evidence or {}).get('hint', ''), 'observed_at': r.observed_at.isoformat()}
           for r in rows if r.probe == PROBE and r.kind == KIND and r.outcome in ('found', 'hidden', 'challenged')]
    return sorted(out, key=lambda a: (not a['confirmed'], a['host'], a['path']))[:60]


def status_counts(project_ids):
    """What the two slow web sweeps hold for these projects, for ``get_system_status``: whether each is on, the other sites found on shared
    addresses, the applications under subdirectories (with a version, and unconfirmed leads) and the edges that challenged either sweep."""
    from django.db.models import Q

    from cveFeed.models import ProbeObservation
    rows = ProbeObservation.objects.filter(project_id__in=list(project_ids), probe__in=(PROBE, vhost_scan.PROBE))
    subapp = Q(probe=PROBE)
    return {'virtual_hosts': {'enabled': vhost_scan.enabled(), 'other_sites': rows.filter(probe=vhost_scan.PROBE, outcome='found').values('host').distinct().count(),
                              'challenged': rows.filter(probe=vhost_scan.PROBE, outcome='challenged').count()},
            'subdirectory_apps': {'enabled': enabled(), 'confirmed': rows.filter(subapp, outcome__in=('found', 'hidden')).exclude(variant='lead').count(),
                                  'with_version': rows.filter(subapp, outcome='found').exclude(version='').count(),
                                  'leads': rows.filter(subapp, outcome='found', variant='lead').count(),
                                  'challenged': rows.filter(subapp, outcome='challenged').count()}}
