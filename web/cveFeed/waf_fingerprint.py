"""Names the web application firewall or edge product in front of a host: the fingerprint runs on a Sentinel (task kind ``waf``), never here.

The scanners already say that something blocks ("WAF"); they rarely say what. The fingerprint names the product from how the host answers (headers,
cookies, block pages). The product is stored as a technology of the host, like every other fingerprint, so it is searchable and the CVE correlation,
the AI and the targeted template pass see it. It gives a product and no version: say "version unknown" and let a CVE-specific template find the
version if it matters.

This module picks the sites (``web_sites``), hands each to a Sentinel (``run_for_scan``), cuts what comes back to the one product rule (``_named``)
and stores it (``store_products``, ``persist_waf_result``). Nothing a Sentinel reports is trusted beyond its bounded name fields. With no scanner able
to take the work the hosts stay due (``resources.ScannerUnavailable``): the kind never runs on this server (``sentinel_dispatch.NEVER_LOCAL``).

On by default; ``CVENGINE_WAFW00F=0`` turns it off. Bounded per scan (``CVENGINE_WAFW00F_MAX_HOSTS``) and asked at most once per host per window
(``CVENGINE_TTL_WAFW00F``, the service ledger, 7 days).
"""
import logging
import os
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

SERVICE = 'wafw00f'
DEFAULT_MAX_HOSTS = 25
GENERIC = {'generic', 'unknown', 'none', ''}
NAME_LEN = 100  # a product or manufacturer name is cut to this, here and in the Sentinel result contract (cvengine_scanner/contract/sentinel_contract.json, the ``waf`` kind)
MAX_PRODUCTS = 20  # the most products one host's result names; the contract's list bound (a handful at the very most)


def enabled():
    return os.environ.get('CVENGINE_WAFW00F', '1').strip().lower() not in ('0', 'false', 'no', 'off')


def _int_env(name, default, floor):
    try:
        return max(floor, int(os.environ.get(name, default)))
    except ValueError:
        return default


def max_hosts():
    return _int_env('CVENGINE_WAFW00F_MAX_HOSTS', DEFAULT_MAX_HOSTS, 1)


def web_sites(scan):
    """``[(Subdomain, root URL)]`` for this scan's hosts that answered over HTTP, excluded and blocked names already removed (the same target list
    every stage uses). The fingerprint is pointed at the root of the site, never at a path or a query."""
    from cveFeed.nuclei_scan import scan_targets
    from startScan.models import Subdomain
    allowed, _ips, _ports = scan_targets(scan)
    sites = []
    for sub in Subdomain.objects.filter(scan_history=scan, name__in=allowed, http_status__gt=0).order_by('name'):
        parts = urlsplit(sub.http_url or '')
        scheme = parts.scheme if parts.scheme in ('http', 'https') else 'https'
        netloc = parts.netloc if parts.scheme in ('http', 'https') and parts.netloc else sub.name
        sites.append((sub, f'{scheme}://{netloc}/'))
    return sites


def _named(pairs):
    """``[{'firewall', 'manufacturer'}]`` from ``(name, manufacturer)`` pairs: names stripped and cut, a generic or empty name and a repeat (any case)
    dropped. The one rule for a product, whatever a Sentinel's result (``persist_waf_result``) names. Pure."""
    found, seen = [], set()
    for name, manufacturer in pairs:
        product = str(name or '').strip()[:NAME_LEN]
        if product.lower() in GENERIC or product.lower() in seen:
            continue
        seen.add(product.lower())
        found.append({'firewall': product, 'manufacturer': str(manufacturer or '').strip()[:NAME_LEN]})
    return found


def store_products(project, sub, products, scan=None):
    """What one host's finished fingerprint leaves behind, as a Sentinel reported it: the host is recorded in the service ledger
    (so it is not asked again inside the window) and each product becomes a technology of it. ``products`` is ``[{'firewall', ...}]`` as
    ``_named`` makes it. Returns how many products were named. Never called for a run that failed: that host is asked again next scan."""
    from cveFeed import ledger
    from startScan.models import Technology
    ledger.record(SERVICE, [sub.name], project.id, scan)
    for product in products:
        tech = Technology.objects.filter(name=product['firewall']).order_by('id').first() or Technology.objects.create(name=product['firewall'])
        sub.technologies.add(tech)
    return len(products)


def persist_waf_result(project, host, result, scan=None):
    """Store a Sentinel's ``waf`` result (``agentapi.sentinel_broker.clean_result``, contract kind ``waf``) for ``host`` (the ``Subdomain`` the task was
    about) through the product rule (``_named``) and the one storing function (``store_products``); ``run_for_scan`` reaches the same rule through
    ``sentinel_dispatch.waf_outcome``. A result that is not
    ``done`` stores nothing and records nothing. Returns ``{'named': n, 'generic': bool, 'recorded': bool}``."""
    if not isinstance(result, dict) or result.get('outcome') != 'done':
        return {'named': 0, 'generic': False, 'recorded': False}
    if host.target_domain_id and host.target_domain.project_id != project.id:
        raise ValueError('the host is not in this project')
    products = _named((p.get('name'), p.get('manufacturer')) for p in (result.get('products') or [])[:MAX_PRODUCTS] if isinstance(p, dict))
    named = store_products(project, host, products, scan)
    return {'named': named, 'generic': result.get('generic') is True and not products, 'recorded': True}


def run_for_scan(scan_id, force=False):
    """Fingerprint the WAF in front of every web host this scan found on a Sentinel, bounded and TTL-gated. Each product is stored as a technology of
    the host. Returns a summary dict; never raises. With no scanner able to take the work the hosts stay due and the summary says so."""
    from cveFeed import activity, ledger
    from startScan.models import ScanHistory
    if not enabled():
        return {'checked': 0, 'skipped': 'disabled'}
    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
    project, domain = scan.domain.project, scan.domain
    sites = web_sites(scan)
    if not sites:
        return {'checked': 0}
    covered = set() if force else ledger.fresh(SERVICE, [s.name for s, _ in sites], project.id)
    todo = [(s, u) for s, u in sites if s.name not in covered][:max_hosts()]
    if not todo:
        return {'checked': len(sites), 'tested': 0, 'reused': len(covered)}
    from agentapi import sentinel_dispatch
    from reNgine.resources import ScannerUnavailable
    try:
        sentinel_dispatch.scanner_or_local(project, 'waf')  # raises when no scanner can take it: the kind never runs here
    except ScannerUnavailable as exc:  # the hosts stay due
        return {'checked': len(sites), 'tested': 0, 'reused': len(covered), 'skipped': f'no scanner could take this work ({exc.kind})'}
    running = activity.log('run_check', f'Fingerprinting the web application firewall of {len(todo)} host(s) of {domain.name}',
                           project=project, status='running', scan_id=scan.id)
    waiting = None
    results, left = [None] * len(todo), []
    try:
        for index, result in sentinel_dispatch.dispatch_each(
                project, 'waf', todo, lambda site: sentinel_dispatch.waf_target(site[1], _address_of(site[0], project.id)), scan=scan,
                label_of=lambda site: site[0].name, ips_of=lambda site: [a for a in [_address_of(site[0], project.id)] if a]):
            if result is None:
                left.append(index)  # no Sentinel did it (or the host has no address to hand one)
            else:
                results[index] = sentinel_dispatch.waf_outcome(result)
    except ScannerUnavailable as exc:  # what the scanner finished is stored below; the rest stays due
        waiting, left = exc, []
    if left:
        waiting = waiting or ScannerUnavailable('waf', 'the host has no address a scanner may be sent to')  # never run here: those hosts stay due
    named = generic = 0
    for (sub, _url), result in zip(todo, results):
        if result is None:
            continue  # waiting for a scanner: not asked, not recorded
        if result.get('generic'):
            generic += 1
        named += store_products(project, sub, result.get('products') or [], scan)
    tested = sum(r is not None for r in results)
    activity.settle(running, 'done', message=(
        f'WAF fingerprint for {domain.name}: {named} firewall(s) named on {tested} host(s)'
        + (f', {generic} blocked without a known product' if generic else '')
        + (f'; {len(todo) - tested} waiting: no scanner could take this work ({waiting.kind})' if waiting else '')))
    out = {'checked': len(sites), 'tested': tested, 'named': named, 'generic': generic, 'errors': 0, 'reused': len(covered)}
    if waiting:
        out['skipped'] = f'no scanner could take this work ({waiting.kind})'
    return out


def _address_of(sub, project_id):
    """The first address of ``sub`` the scanners may reach: the one a dispatched fingerprint is told to expect, or ``None``."""
    from targetApp.target_types import is_scannable_ip
    for address in sub.ip_addresses.values_list('address', flat=True).order_by('id'):
        if address and is_scannable_ip(address, project=project_id):
            return address
    return None
