"""Other sites served from the same address: virtual host discovery from the project's OWN names.

One address can serve several sites, told apart by the Host header (and, over TLS, the server name). A site that shares an address with a
host the project already knows is an application nobody listed, and it can carry its own known CVE. This sweep asks each web address of a
project, once, for each name the project already knows that is not yet recorded as answering there:

* the names come from the project's own data only: the hosts stored for it, the names in the certificates seen on that address (and the
  reverse names discovery recorded for it), and the names certificate transparency found. There is no wordlist and nothing is guessed;
* a name is asked only when it is in scope: equal to or under a domain target of the project (a host-scoped target covers its own name
  only). A name outside the scope is never asked and never added, whatever a certificate says;
* the question is one plain GET of ``/`` with that Host header (and SNI for https) at the vetted address, no body, no cookie, no
  credential, redirects never followed, at the sweep's global and per-address pace, never more than ``CVENGINE_VHOST_MAX_NAMES`` names per
  address and ``CVENGINE_VHOST_MAX_IPS`` addresses per run, once per name and address per ledger window (a week);
* the answer is compared (status, title, length, redirect target) with the address's default response and with the name's own response.
  ``distinct`` (it answers, and differs from both) is another application; ``default_site`` (the address ignores the name) and ``same_app``
  (the same application the name serves on its own address) are recorded and add nothing.

What it records. A ``ProbeObservation`` of kind ``vhost`` per name and address (host the name, product the address, outcome ``found`` for a
distinct application, ``absent`` for one of the others, ``challenged`` when an edge refused the request, with the classification and the
fingerprints in the evidence). A distinct application is added to the project: the name gets a host row of its own (the same kind of
scan-less row certificate transparency creates, linked to the address), so names that resolve to the same addresses stay one host with
aliases, exactly as the Hosts page already merges them, and what its page states (a product and a version) becomes the host's technologies,
which the existing CVE correlation reads. An edge that challenges is never retried and never worked around: the address is left alone until
the next window."""
import functools
import ipaddress
import logging
import os
import re
from datetime import timedelta
from urllib.parse import urlsplit

from django.utils import timezone

from cveFeed import slow_web

logger = logging.getLogger(__name__)

SERVICE = 'vhost'  # ledger asset: "<address>|<name>"
IP_SERVICE = 'vhost-ip'  # an address that could not be asked (nothing answered, or an edge challenged): left alone for a few days
PROBE = 'vhost-probe'
PAGE_PROBE = 'vhost-page'  # the version and edge facts the distinct application's own page states
KIND = 'vhost'
CLAIM_TTL = 1800
DEFAULT_MAX_NAMES = 20
DEFAULT_MAX_IPS = 5
ANSWERS = (200, 301, 302, 303, 307, 308, 401, 403)  # a name the address serves: anything else is "no such site here"
CLASSES = ('distinct', 'default_site', 'same_app')
HINT = ('The edge ({edge}) refused the scanner\'s request, so it could not be read whether this address serves other sites. Allow the '
        'scanner\'s address (or its user agent) in the WAF or bot rules for this host to have it checked at the next window.')


def enabled():
    """CVENGINE_VHOST: on unless it is 0/false/no/off."""
    return slow_web.truthy(os.environ.get('CVENGINE_VHOST', '1'))


def max_names():
    return slow_web.env_int('CVENGINE_VHOST_MAX_NAMES', DEFAULT_MAX_NAMES, 1, 200)


def max_ips():
    return slow_web.env_int('CVENGINE_VHOST_MAX_IPS', DEFAULT_MAX_IPS, 1, 100)


# ----------------------------------------------------------------------------- scope (pure)

def scope_targets(project_id):
    """``[(name, host_scoped, domain_id)]``: the domain-name targets of the project. An address or a range names no site, so it is no scope
    for a name."""
    from targetApp.models import Domain
    from targetApp.target_types import DOMAIN, classify_target
    return [(d.name.strip().lower().rstrip('.'), d.is_host_scoped(), d.id) for d in Domain._base_manager.filter(project_id=project_id)
            if classify_target(d.name) == DOMAIN]


def covering_domain(name, targets):
    """The id of the most specific target that covers ``name`` (the name itself, or any name under a target that is not host scoped), or None
    when the name is out of scope."""
    name = (name or '').strip().lower().rstrip('.')
    best = None
    for target, host_scoped, domain_id in targets:
        if name == target or (not host_scoped and name.endswith('.' + target)):
            if best is None or len(target) > len(best[0]):
                best = (target, domain_id)
    return best[1] if best else None


# ----------------------------------------------------------------------------- fingerprints and the verdict (pure)

def _location_path(location):
    """The part of a redirect target that says where it leads, without the host (a name redirects to itself, an address to its address)."""
    if not location:
        return ''
    try:
        parts = urlsplit(location.strip())
    except ValueError:
        return ''
    return ((parts.path or '/') + ('?' + parts.query if parts.query else '')).lower()[:200]


def fingerprint_of(response):
    """What is compared between two answers: status, title, length and where a redirect leads. Never the body."""
    from cveFeed import route_auth
    body = response.get('body') or ''
    title = response.get('title')
    if title is None:
        title = route_auth.page_title(body)
    return {'status': int(response.get('status') or 0), 'title': ' '.join(str(title or '').split())[:200],
            'length': int(response.get('bytes') if response.get('bytes') is not None else len(body)),
            'location': _location_path(response.get('location')), 'server': str(response.get('server') or '')[:60]}


def similar(a, b):
    """Whether two fingerprints are the same answer: both redirect to the same place, or the same status, the same title and a length within
    10% (or 64 bytes)."""
    a_redirect, b_redirect = 300 <= a['status'] < 400, 300 <= b['status'] < 400
    if a_redirect or b_redirect:
        return a_redirect and b_redirect and a['location'] == b['location']
    if a['status'] != b['status'] or a['title'].lower() != b['title'].lower():
        return False
    return abs(a['length'] - b['length']) <= max(64, 0.1 * max(a['length'], b['length']))


def classify(candidate, default, own):
    """``no_answer`` (the address has no site for this name), ``default_site`` (it answers as it answers any name), ``same_app`` (it answers
    as the name's own site does elsewhere) or ``distinct`` (another application). ``default`` and ``own`` are fingerprints or None."""
    if candidate['status'] not in ANSWERS:
        return 'no_answer'
    if default is not None and similar(candidate, default):
        return 'default_site'
    if own is not None and similar(candidate, own):
        return 'same_app'
    return 'distinct'


# ----------------------------------------------------------------------------- what is asked

def web_base(ip):
    """``(scheme, port)`` of the address's preferred web service (443, then 80, then the other web ports by number) or None. The same reading
    of an address's open ports as ``route_auth.web_bases``."""
    from cveFeed import route_auth
    from startScan.models import open_ports
    found = set()
    for port in open_ports(ip):
        service, product = (port.service_name or '').lower(), (port.product or '').lower()
        if port.number in route_auth.WEB_PORTS or service in route_auth.HTTP_SERVICE_NAMES or 'http' in product:
            https = ('https' in service or 'ssl' in service or route_auth.WEB_PORTS.get(port.number) == 'https'
                     or (getattr(port, 'extra', None) or {}).get('tunnel') == 'ssl')
            found.add(('https' if https else 'http', port.number))
    order = sorted(found, key=lambda sp: (0 if sp[1] == 443 else 1 if sp[1] == 80 else 2, sp[1], sp[0]))
    return order[0] if order else None


def web_addresses(project_id):
    """``{address: {'ip', 'base', 'names', 'dns_names'}}``: the project's addresses that serve web, from its current inventory. ``names`` are
    every name of the project on the address, ``dns_names`` those a scan found there (a name that resolves to the address answers there by
    definition; the others are what this sweep asks)."""
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    found = {}
    rows = Subdomain.objects.filter(latest_scan_q(), target_domain__project_id=project_id).prefetch_related('ip_addresses__ports').order_by('id')
    for sub in rows:
        for ip in sub.ip_addresses.all():
            if not ip.address or ip.is_cdn:
                continue
            entry = found.setdefault(ip.address, {'ip': ip, 'base': web_base(ip), 'names': set(), 'dns_names': set()})
            entry['names'].add(sub.name.lower())
            if sub.scan_history_id is not None:
                entry['dns_names'].add(sub.name.lower())
    return {address: entry for address, entry in found.items() if entry['base']}


def _is_name(value):
    from targetApp.target_types import DOMAIN, classify_target
    return classify_target(value) == DOMAIN


def known_names(project_id):
    """``{name: rank}``: the names the project already knows, lowest rank first asked. Stored hosts and the names of certificate
    transparency are rank 3, the names an address's own certificates and reverse lookups gave it are added per address (``names_for``)."""
    from cveFeed.correlation import latest_scan_q
    from cveFeed.models import DiscoveryEvent, HostArchive
    from startScan.models import Subdomain
    names = {}
    for name in Subdomain.objects.filter(latest_scan_q(), target_domain__project_id=project_id).values_list('name', flat=True).distinct():
        if name and _is_name(name):
            names[name.strip().lower().rstrip('.')] = 3
    for label in DiscoveryEvent.objects.filter(domain__project_id=project_id, module='ct-monitor').values_list('label', flat=True).distinct():
        if label and _is_name(label):
            names.setdefault(label.strip().lower().rstrip('.'), 2)
    for host in HostArchive.objects.filter(project_id=project_id).values_list('host', flat=True):
        if host and _is_name(host):
            names.setdefault(host.strip().lower().rstrip('.'), 3)
    return names


def names_on_address(project_id, address, attached_names):
    """``{name: rank}`` from what was seen on this very address: the names in the certificates of its hosts (rank 0) and the reverse and
    certificate names discovery recorded for the address (rank 1). Wildcards name no site and are left out."""
    from cveFeed.models import DiscoveryEvent, TlsCertificate
    found = {}
    for sans in TlsCertificate.objects.filter(domain__project_id=project_id, host__in=list(attached_names)).values_list('sans', flat=True):
        for san in sans or []:
            if isinstance(san, str) and not san.startswith('*') and _is_name(san.strip().lower()):
                found[san.strip().lower().rstrip('.')] = 0
    for label in DiscoveryEvent.objects.filter(domain__project_id=project_id, host=address, module__in=('ptr', 'tls-san')).values_list('label', flat=True):
        if label and not label.startswith('*') and _is_name(label.strip().lower()):
            found.setdefault(label.strip().lower().rstrip('.'), 1)
    return found


def candidates(address, entry, seen, targets, banned, fresh):
    """The names to ask this address, in the order they are asked and at most ``max_names``: in scope, not excluded or archived, not a name a
    scan found on the address, not asked within the ledger window. ``seen`` is every name the project knows for the address, ``{name: rank}``
    (``known_names`` and ``names_on_address``). Returns ``(names, out_of_scope)``."""
    from cveFeed import ledger
    from targetApp.target_types import apex_domain
    apexes = {apex_domain(n) for n in entry['names']}
    ranked, out_of_scope = [], 0
    for name, rank in seen.items():
        if name in entry['dns_names'] or _skip_literal(name) or name.rstrip('.') in banned:
            continue
        if covering_domain(name, targets) is None:
            out_of_scope += 1
            continue
        if ledger._norm(f'{address}|{name}') in fresh:
            continue
        ranked.append((2 if rank == 3 and apex_domain(name) in apexes else rank, name))
    return [name for _rank, name in sorted(ranked)][:max_names()], out_of_scope


def _skip_literal(name):
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return False


# ----------------------------------------------------------------------------- storing

def record_observation(project_id, domain_id, name, address, port, outcome, classification, confidence, evidence):
    """One row per (project, name, address, port): the verdict of the last time the name was asked there."""
    from cveFeed.models import ProbeObservation
    row, _ = ProbeObservation.objects.update_or_create(
        project_id=project_id, host=name.lower(), probe=PROBE, port=port, kind=KIND, product=address,
        defaults={'domain_id': domain_id, 'outcome': outcome, 'confidence': confidence, 'url': '/', 'source': 'host-header',
                  'variant': classification[:60], 'evidence': evidence, 'observed_at': timezone.now()})
    return row


def _find_domain_row(project_id, name, domain_id):
    from startScan.ip_rows import get_or_create_first
    from startScan.models import Subdomain
    existing = Subdomain.objects.filter(target_domain__project_id=project_id, name=name, scan_history__isnull=True).order_by('id').first()
    if existing is not None:
        return existing
    return get_or_create_first(Subdomain, target_domain_id=domain_id, name=name, scan_history=None,
                               defaults={'is_imported_subdomain': True, 'discovered_date': timezone.now()})[0]


def attach(project_id, domain_id, name, ip, port, scheme, response):
    """Make the distinct application a host of the project: a scan-less row of the name (as certificate transparency creates), linked to the
    address, with what its page states as technologies. The names that resolve to the same addresses are one host with aliases by the
    existing host merge, so this never makes a second host of the same machine. Returns the row and the technologies added."""
    from cveFeed import probes
    sub = _find_domain_row(project_id, name, domain_id)
    sub.ip_addresses.add(ip)
    sub.http_status = int(response.get('status') or 0)
    sub.page_title = (response.get('title') or '')[:1000] or sub.page_title
    sub.webserver = (response.get('server') or '')[:1000] or sub.webserver
    sub.content_type = (response.get('content_type') or '')[:100] or sub.content_type
    sub.save(update_fields=['http_status', 'page_title', 'webserver', 'content_type'])
    observations = probes.observations_from_page({**response, 'final_url': response.get('url', '')})
    probes.record(project_id, domain_id, name, PAGE_PROBE, observations)
    added = probes.apply_to_subdomain(sub, observations)
    if added:
        probes.recorrelate(sub)
    return sub, added


def detach(project_id, name, ip):
    """A name that no longer answers as a distinct application: the address is unlinked from its scan-less row (never from a row a scan made)."""
    from startScan.models import Subdomain
    count = 0
    for sub in Subdomain.objects.filter(target_domain__project_id=project_id, name=name, scan_history__isnull=True):
        if sub.ip_addresses.filter(pk=ip.pk).exists():
            sub.ip_addresses.remove(ip)
            count += 1
    return count


# ----------------------------------------------------------------------------- one address

def _own_fingerprint(project_id, name, scheme, port, fetch, pace, cache):
    """The fingerprint of the name's own site: its stored front-page route check when there is one, else one GET of the name at its own
    address (resolved and vetted like every request; nothing when the name is not allowed or does not answer)."""
    from cveFeed import probes
    from cveFeed.models import RouteAuth
    if name in cache:
        return cache[name]
    cache[name] = None
    row = RouteAuth.objects.filter(project_id=project_id, host=name, path='/').exclude(http_status__isnull=True).order_by('-checked_at').first()
    if row is not None and row.http_status:
        cache[name] = {'status': int(row.http_status), 'title': ' '.join((row.title or '').split())[:200],
                       'length': int((row.evidence or {}).get('bytes') or 0), 'location': _location_path(row.redirect_to), 'server': ''}
        return cache[name]
    if not probes._permitted(name, project_id):
        return None
    try:
        pace.wait(name)
        response = fetch(f'{scheme}://{slow_web.authority(name, port, scheme)}/')
    except (OSError, ValueError):
        return None
    if not response.get('challenge') and not slow_web.busy(response):
        cache[name] = fingerprint_of(response)
    return cache[name]


def sweep_address(project_id, address, entry, names, targets, fetch, pace, cache, stop=None):
    """Ask one address its default response and then each of ``names``. Returns the counts. ``stop()`` is checked before each request (pause)."""
    from cveFeed import ledger
    scheme, port = entry['base']
    ip = entry['ip']
    summary = {'asked': 0, 'distinct': 0, 'added': 0, 'challenged': 0, 'default_site': 0, 'same_app': 0, 'no_answer': 0, 'stopped': False}
    host = slow_web.authority(address, port, scheme)
    primary = sorted(entry['names'])[0]
    domain_id = covering_domain(primary, targets) or targets[0][2]
    pace.wait(address)
    try:
        default_response = fetch(f'{scheme}://{host}/')
    except (OSError, ValueError) as exc:
        logger.info('vhost: %s did not answer its default request (%s)', address, type(exc).__name__)
        ledger.record(IP_SERVICE, [address], project_id)  # nothing is serving: asked again after the short window, not at every run
        return summary
    if default_response.get('challenge'):
        _challenged(project_id, domain_id, primary, address, port, default_response, 'the default request')
        ledger.record(IP_SERVICE, [address], project_id)
        summary['challenged'] += 1
        return summary
    if slow_web.busy(default_response):
        return summary  # the server asked for time: nothing is recorded, the address is asked again at the next run
    default = fingerprint_of(default_response)
    for name in names:
        if stop and stop():
            summary['stopped'] = True
            return summary
        pace.wait(address)
        asset = f'{address}|{name}'
        try:
            response = fetch(f'{scheme}://{slow_web.authority(name, port, scheme)}/', connect_ip=address)
        except (OSError, ValueError):
            ledger.record(SERVICE, [asset], project_id)  # no answer is an answer: not asked again inside the window
            summary['no_answer'] += 1
            continue
        if response.get('challenge'):
            _challenged(project_id, covering_domain(name, targets), name, address, port, response, 'a request with the name')
            ledger.record(SERVICE, [asset], project_id)
            ledger.record(IP_SERVICE, [address], project_id)
            summary['challenged'] += 1
            return summary  # the edge answers for the whole address: nothing more is asked of it
        if slow_web.busy(response):
            return summary
        summary['asked'] += 1
        candidate = fingerprint_of(response)
        own = None
        if candidate['status'] in ANSWERS and not similar(candidate, default):
            own = _own_fingerprint(project_id, name, scheme, port, fetch, pace, cache)
        verdict = classify(candidate, default, own)
        summary[verdict] += 1
        ledger.record(SERVICE, [asset], project_id)
        domain = covering_domain(name, targets)
        evidence = {'ip': address, 'scheme': scheme, 'classification': verdict, 'answer': candidate, 'default': default, 'own': own}
        if verdict == 'distinct':
            sub, added = attach(project_id, domain, name, ip, port, scheme, response)
            record_observation(project_id, domain, name, address, port, 'found', verdict, 0.85 if candidate['status'] == 200 else 0.65, evidence)
            summary['added'] += 1
        else:
            _retire(project_id, name, address, ip, port, domain, verdict, evidence)
    return summary


def _retire(project_id, name, address, ip, port, domain, verdict, evidence):
    """A name that answers as the default site or as its own site (``default_site``, ``same_app``) is recorded as such. One that answered
    distinctly before and does not now says so in its record and has the address unlinked from its scan-less row."""
    from cveFeed.models import ProbeObservation
    was = ProbeObservation.objects.filter(project_id=project_id, host=name, probe=PROBE, kind=KIND, product=address, outcome='found').exists()
    if verdict != 'no_answer' or was:
        record_observation(project_id, domain, name, address, port, 'absent', verdict, 0.0, evidence)
    if was:
        detach(project_id, name, ip)


def _challenged(project_id, domain_id, name, address, port, response, what):
    edge = response.get('challenge') or 'an edge'
    record_observation(project_id, domain_id, name, address, port, 'challenged', 'challenged', 0.0,
                       {'ip': address, 'edge': edge, 'status': response.get('status'), 'hint': HINT.format(edge=edge), 'on': what})


# ----------------------------------------------------------------------------- the sweep

def sweep(project_id, fetch=None, pace=None, vet_ip=None, stop=None):
    """One project's due addresses, at most ``max_ips``, each asked up to ``max_names`` names. Returns the summary (and ``skipped`` with the
    reason when nothing ran)."""
    from cveFeed import activity, exclusions, fullscan, ledger
    from cveFeed.archive_rediscovery import archived_names
    from reNgine import resources
    summary = {'ips': 0, 'asked': 0, 'distinct': 0, 'added': 0, 'challenged': 0, 'default_site': 0, 'same_app': 0, 'no_answer': 0, 'out_of_scope': 0}
    if not enabled():
        return {**summary, 'skipped': 'virtual host discovery is turned off (CVENGINE_VHOST=0)'}
    stop = stop or (lambda: resources.global_pause_requested(fail_closed=True))
    if stop():
        return {**summary, 'skipped': 'scanning is paused: the addresses stay due'}
    from cveFeed.conductor import bounty_blocked_projects
    if project_id in bounty_blocked_projects():
        return {**summary, 'skipped': 'the bug bounty engagement has not confirmed automated testing'}
    targets = scope_targets(project_id)
    if not targets:
        return {**summary, 'skipped': 'the project has no domain target to give a name scope'}
    owner = f'vhost-{os.getpid()}'
    with resources.redis_claim(f'cvengine:vhost:{project_id}', owner, CLAIM_TTL) as holder:
        if holder is not True:
            return {**summary, 'skipped': 'another virtual host sweep is running for this project'}
        pace = pace or slow_web.Pace()
        fetch = fetch or functools.partial(slow_web.get, project=project_id)
        vet_ip = vet_ip or fullscan.in_scope
        banned = exclusions.excluded_names(project_id) | archived_names(project_id)
        pool = known_names(project_id)
        addresses = web_addresses(project_id)
        resting = ledger.fresh(IP_SERVICE, list(addresses), project_id)
        def due_addresses():  # lazily: a run handles at most max_ips addresses, so the ledger and certificate reads stop with them
            for address in sorted(addresses):
                if address in resting:
                    continue
                entry = addresses[address]
                seen = {**pool, **names_on_address(project_id, address, entry['names'])}
                fresh = ledger.fresh(SERVICE, [f'{address}|{n}' for n in seen], project_id)
                names, out_of_scope = candidates(address, entry, seen, targets, banned, fresh)
                summary['out_of_scope'] += out_of_scope
                if names:
                    yield address, entry, names
        running = None
        cache = {}
        for address, entry, names in due_addresses():
            if summary['ips'] >= max_ips():
                break
            if stop():
                summary['skipped'] = 'scanning is paused: the addresses stay due'
                break
            if not vet_ip(entry['ip']):  # a prohibited, shared-platform, CDN or excluded-only address is never asked, and holds no place in the run
                continue
            if running is None:
                running = activity.log('run_check', 'Virtual host check of the known names on the project\'s web addresses', project=project_id,
                                       status='running')
            part = sweep_address(project_id, address, entry, names, targets, fetch, pace, cache, stop=stop)
            summary['ips'] += 1
            for key in ('asked', 'distinct', 'added', 'challenged', 'default_site', 'same_app', 'no_answer'):
                summary[key] += part[key]
            if part['stopped']:
                summary['skipped'] = 'scanning is paused: the addresses stay due'
                break
        if running is not None:
            activity.settle(running, 'done', message=(
                f'Virtual hosts: {summary["asked"]} name(s) asked on {summary["ips"]} address(es), {summary["distinct"]} serve another application'
                + (f', {summary["challenged"]} challenged by an edge' if summary['challenged'] else '')), **summary)
    return summary


def sweep_all(**kwargs):
    """Every project's due addresses. One sweep at a time across workers; the work is spread over runs by the per-run caps."""
    from cveFeed import ledger
    from dashboard.models import Project
    if not enabled():
        return {'skipped': 'virtual host discovery is turned off (CVENGINE_VHOST=0)'}
    if not ledger.sweep_claim('vhost', 50 * 60):
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

def also_served(project_id, addresses):
    """``[{'name', 'address', 'port', 'classification', 'status', 'title', 'observed_at'}]``: the distinct applications recorded on any of
    ``addresses`` for the project, for the host page."""
    from cveFeed.models import ProbeObservation
    rows = ProbeObservation.objects.filter(project_id=project_id, probe=PROBE, kind=KIND, outcome='found', product__in=list(addresses)).order_by('host')
    return [{'name': r.host, 'address': r.product, 'port': r.port, 'classification': r.variant,
             'status': (r.evidence or {}).get('answer', {}).get('status'), 'title': (r.evidence or {}).get('answer', {}).get('title', ''),
             'observed_at': r.observed_at.isoformat()} for r in rows]
