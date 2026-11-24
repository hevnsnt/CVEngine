"""Version sources: the exact versions hosts state anonymously from outside, read through one data-driven catalogue
(``cveFeed.version_catalogue``), stored, and matched against CVEs.

What it reads. The catalogue's entries (an application's version endpoint, a platform API's ``/version``, a Prometheus ``/metrics`` page, an
ASP.NET error page) and the headers the scans already stored (a Server header naming Python under Werkzeug, X-Jenkins, Nexus's Server
header, X-AspNet-Version). Nothing is read on this server: the active reads are the Sentinel kind ``version_read`` (contract version 7),
which only fetches the GETs listed and returns the parts of each answer the entry names; this module parses them.

Where readings go. One table, ``ProbeObservation`` (the store of what a probe read about a host), one row per (host, source, port, kind,
product), probe ``vsrc:<entry>`` (``vsrc:passive`` for the readings made from stored headers):

  product   kind ``version``: the reading is also a technology of the host (``Grafana:10.2.3``), so correlation matches it like any product it
            knows (name, aliases, CPE, a distribution's tracker on a Red Hat host), version only: it never proves a version on its own
            (``match_policy.version_read_from_component``), and heat, triage ceilings and the heat cap treat it as every banner.
  runtime   kind ``runtime``: a language runtime (Python, Go, Node.js, PHP, Ruby, .NET Framework, Erlang/OTP), never a technology. Matched here
            (``collect_matches``) against the CVEs whose own record names the runtime by vendor and product (``version_catalogue.RUNTIMES``),
            by the Java runtime's rules: an exact version inside a range is a version match; a line, an inferred reading or a runtime clearly
            present with no version is at most a "runtime of unknown version" candidate (``evidence.runtime_unknown``: needs validation,
            ice, never fire, with the host owner's commands), and never ``version_in_range`` True; a weak presence (``X-Powered-By: ASP.NET``,
            a Go expvar page) matches nothing.
  java      a ``jvm_info`` metric is a Java runtime reading (``cveFeed.java_runtime``, source ``metrics``): the Java family keeps its own table
            and matcher, with the same confidence words and rules.

Exposures. An entry with an ``Exposure`` (the Docker Engine API, etcd's client API, Nomad's API, Envoy's admin interface, the Kubernetes API
server, an anonymous ``/metrics`` or ``/debug/vars``) files a finding (``save_vulnerability``, source ``version-source``) when the answer has
its shape, and closes it when a later complete read shows it gone. A template check's finding that already reports the same exposure on the host
(``Exposure.twins``) is not filed twice.

Gates. A host is asked only when an entry's product shows on it (a technology or a port product) or a port whose number belongs to the entry
answers with a generic service; it passes the organization's exclusions (fail closed), archived hosts, a bug bounty program's scope and, on the
work planner's path, its automated-testing confirmation, the address rules (a host that points at an address a scanner may not use is left
out) and the dispatcher's do-not-scan list. It is a stage of the host pipeline after the Java runtime reads, and the work planner keeps it
going (check ``version-sources``): once a week per host, again after a day when a read failed.
"""
import logging
import os
import re
import secrets
from datetime import timedelta

from django.utils import timezone

from cveFeed import version_catalogue as catalogue

logger = logging.getLogger(__name__)

KIND = 'version_read'                     # the Sentinel task kind
SERVICE = 'version-source'                # the ledger service: one row per host name, a week
FAILED_SERVICE = 'version-source-failed'  # a host whose read could not complete: asked again after a day
MATCH_SOURCE = 'runtime'                  # CVEMatch.source of a runtime match
FINDING_SOURCE = 'version-source'         # Vulnerability.source of an exposure
PROBE_PREFIX = 'vsrc:'
PASSIVE_PROBE = 'vsrc:passive'
SNMP_PROBE = 'vsrc:snmp'                  # the readings a UDP sweep's SNMP sysDescr gave (version_catalogue.from_sysdescr)
RUNTIME_KIND = 'runtime'
HINT_KIND = 'hint'                        # a product reading that is not a technology: inferred (a bundled component), weak, or not matched by name
BUNDLED_SOURCE = 'bundled'                # CVEMatch.source of a bundled component's candidate
SNMP_PORT = 161
MAX_READS_PER_TASK = 100                  # the contract's bound
MAX_ENTRIES_PER_HOST = 6
MAX_BASES_PER_ENTRY = 2
MAX_PER_SCAN = 60                         # hosts one scan sends; the rest are due on the next pass or the work planner's
STALE_DAYS = 90                           # a reading not seen again for this long is not used to match (the Java runtime's rule)
UNKNOWN_CONFIDENCE = 0.4                  # a runtime of unknown version (the correlation floor)
INFERRED_IN_RANGE_CONFIDENCE = 0.5
CONFIDENCE_SCORE = {'exact': 0.95, 'inferred': 0.6, 'weak': 0.3}
GENERIC_SERVICES = re.compile(r'^(?:|unknown|tcpwrapped|http|https|ssl/http|ssl/https|http-proxy|http-alt|https-alt|ssl/unknown|ssl)$')


def enabled():
    return os.environ.get('CVENGINE_VERSION_SOURCES', '1').strip().lower() not in ('0', 'false', 'no', 'off')


def _split(name):
    """A stored technology as correlation reads it (``correlation.read_technology``): an X-AspNet-Version CLR line stored as "ASP.NET" or
    by a technology template as "AspNet Version Disclosure" is the .NET Framework CLR's, which ``version_catalogue.from_technology`` reads as a runtime."""
    from cveFeed.correlation import read_technology
    return read_technology(name or '')


# ----------------------------------------------------------------------------- which entries a host warrants (pure)

def _port_base(host, port):
    from cveFeed.route_auth import _base
    service = (getattr(port, 'service_name', '') or '').lower()
    tunnel = (getattr(port, 'extra', None) or {}).get('tunnel') if isinstance(getattr(port, 'extra', None), dict) else None
    https = 'https' in service or 'ssl' in service or tunnel == 'ssl' or port.number in (443, 2376, 6443, 8443, 9443)
    return _base('https' if https else 'http', host, port.number)


def wanted(host, products, ports, web_bases, pages=None):
    """``[(source, base)]``: the catalogue entries a host warrants and the base each is asked on. ``products`` is ``[(name, version)]`` of its
    technologies and port products, ``ports`` its open TCP ports (rows with number, service_name, product, extra), ``web_bases`` its web
    bases. An entry is warranted by a product its ``leads`` names (asked on the port that product answers on, else on the host's first web
    base) or by an open port of its own (``ports``) whose service the port scan left generic or named the product. A ``discovered`` entry is
    asked only at a page of ``pages`` (``{entry id: [absolute URL]}``, ``discovered_pages``: what a scan already found on the host), on that
    page's own base, never at a path of its own. At most ``MAX_ENTRIES_PER_HOST``."""
    host = (host or '').strip().lower().rstrip('.')
    tcp = [p for p in ports if (getattr(p, 'protocol', 'tcp') or 'tcp') in ('tcp', '') and (getattr(p, 'state', 'open') or 'open') == 'open']
    out = []
    for source in catalogue.SOURCES:
        if source.discovered:
            out += _at_pages(host, source, (pages or {}).get(source.id) or ())
            continue
        lead = source.lead_re()
        bases = []
        if lead is not None:
            for port in tcp:
                if lead.search(getattr(port, 'product', '') or '') or lead.search(getattr(port, 'service_name', '') or ''):
                    bases.append(_port_base(host, port))
            if not bases and web_bases and any(lead.search(name or '') for name, _v in products):
                # a product the host shows (a technology names no port): on the entry's own port when the host serves web pages there
                own = [b for b in web_bases if _port_of(b) in source.ports]
                bases.append((own or web_bases)[0])
        for port in tcp:
            product = (getattr(port, 'product', '') or '').strip()
            generic = GENERIC_SERVICES.match((getattr(port, 'service_name', '') or '').lower()) and (
                not product or re.search(r'golang|net/http', product, re.I) or (source.servers and re.search(source.servers, product, re.I)))
            if port.number in source.ports and (generic or (lead is not None and lead.search(product))):
                bases.append(_port_base(host, port))
        for base in list(dict.fromkeys(bases))[:MAX_BASES_PER_ENTRY]:
            out.append((source, base.rstrip('/')))
    return out[:MAX_ENTRIES_PER_HOST]


_PAGE_PATH = re.compile(r'^/[A-Za-z0-9._~!$&\'()*+,;=:@%/-]{0,199}$')  # the Sentinel's path rule (no query: a found page is asked as it is)


def _at_pages(host, source, urls):
    """``[(source at the page, base)]`` for the pages ``urls`` a scan found on ``host``: each on the host's own base, its path one the Sentinel
    takes (no '.' or '..' segment, no query), at most ``MAX_BASES_PER_ENTRY`` and one per base."""
    from urllib.parse import urlsplit
    out, bases = [], set()
    for url in urls:
        try:
            parts = urlsplit(str(url or '').strip())
            parts.port  # noqa: B018 - a bad port raises here
        except ValueError:
            continue
        path = parts.path or '/'
        if (parts.scheme not in ('http', 'https') or (parts.hostname or '').lower().rstrip('.') != host or parts.username or parts.password
                or not _PAGE_PATH.match(path) or path.startswith('//') or any(seg in ('.', '..') for seg in path.split('/'))):
            continue
        base = f'{parts.scheme}://{parts.netloc.lower()}'
        if base in bases:
            continue
        bases.add(base)
        out.append((source.at_page(path), base))
        if len(out) >= MAX_BASES_PER_ENTRY:
            break
    return out


_PHPINFO_TITLE = r'phpinfo\(\)\s*$'
_PHPINFO_PATH = r'/[^/?#]*phpinfo[^/?#]*\.php([?#]|$)'


def discovered_pages(sub):
    """``{entry id: [URL]}``: the pages a scan already found on ``sub`` that a ``discovered`` entry reads. A phpinfo page is one a template
    check reported (a finding whose template is one the ``phpinfo`` entry's exposure names as its twin, or this stage's own finding), or one
    the crawl found answering 200 under phpinfo()'s own title ("PHP 8.2.12 - phpinfo()") or a ``phpinfo`` file name. Never a guessed path."""
    from startScan.models import EndPoint, Vulnerability
    source = catalogue.BY_ID.get('phpinfo')
    if source is None or getattr(sub, 'target_domain_id', None) is None:
        return {}
    templates = list(source.exposure.twins) + [source.exposure.template]
    urls = list(Vulnerability.objects.filter(target_domain__project_id=sub.target_domain.project_id, subdomain__name=sub.name, open_status=True,
                                             template_id__in=templates).exclude(http_url__isnull=True)
                .order_by('-id').values_list('http_url', flat=True)[:10])
    urls += list(EndPoint.objects.filter(subdomain=sub, http_status=200, page_title__iregex=_PHPINFO_TITLE)
                 .order_by('-id').values_list('http_url', flat=True)[:10])
    urls += list(EndPoint.objects.filter(subdomain=sub, http_status=200, http_url__iregex=_PHPINFO_PATH)
                 .order_by('-id').values_list('http_url', flat=True)[:10])
    urls = [u.split('#', 1)[0].split('?', 1)[0] for u in urls if isinstance(u, str) and u]
    return {source.id: list(dict.fromkeys(urls))} if urls else {}


PAGES_CHUNK = 2000  # names or Subdomain ids per query of ``discovered_pages_for``


def discovered_pages_for(subs):
    """``{Subdomain id: discovered_pages(sub)}`` for every one of ``subs``: the same answer ``discovered_pages`` gives each host, read with three
    queries per project (and per ``PAGES_CHUNK`` hosts), not three per host. A host with nothing found maps to ``{}``."""
    from startScan.models import EndPoint, Vulnerability
    out = {sub.pk: {} for sub in subs}
    source = catalogue.BY_ID.get('phpinfo')
    subs = [sub for sub in subs if getattr(sub, 'target_domain_id', None) is not None]
    if source is None or not subs:
        return out
    templates = list(source.exposure.twins) + [source.exposure.template]
    by_project = {}
    for sub in subs:
        by_project.setdefault(sub.target_domain.project_id, []).append(sub)
    vuln_urls, title_urls, path_urls = {}, {}, {}
    for project_id, group in by_project.items():
        names = sorted({sub.name for sub in group})
        for start in range(0, len(names), PAGES_CHUNK):
            rows = (Vulnerability.objects.filter(target_domain__project_id=project_id, subdomain__name__in=names[start:start + PAGES_CHUNK], open_status=True,
                                                 template_id__in=templates).exclude(http_url__isnull=True)
                    .order_by('-id').values_list('subdomain__name', 'http_url'))
            for name, url in rows:
                got = vuln_urls.setdefault((project_id, name), [])
                if len(got) < 10:
                    got.append(url)
        ids = sorted({sub.pk for sub in group})
        for start in range(0, len(ids), PAGES_CHUNK):
            chunk = ids[start:start + PAGES_CHUNK]
            for found, extra in ((title_urls, {'page_title__iregex': _PHPINFO_TITLE}), (path_urls, {'http_url__iregex': _PHPINFO_PATH})):
                for sub_id, url in (EndPoint.objects.filter(subdomain_id__in=chunk, http_status=200, **extra)
                                    .order_by('-id').values_list('subdomain_id', 'http_url')):
                    got = found.setdefault(sub_id, [])
                    if len(got) < 10:
                        got.append(url)
    for sub in subs:
        urls = vuln_urls.get((sub.target_domain.project_id, sub.name), []) + title_urls.get(sub.pk, []) + path_urls.get(sub.pk, [])
        urls = [u.split('#', 1)[0].split('?', 1)[0] for u in urls if isinstance(u, str) and u]
        out[sub.pk] = {source.id: list(dict.fromkeys(urls))} if urls else {}
    return out


def host_products(sub, ports):
    """``[(name, version)]`` of what the host runs: its technologies, its open ports' products and the products an identity reading names with
    no version (``cveFeed.identities``: a FortiGate's OS guess or factory certificate leads to the FortiOS build read)."""
    from cveFeed import identities, source_versions
    out = [_split(t.name) for t in sub.technologies.all() if t.name]
    out += [((p.product or '').strip(), (p.version or '').strip()) for p in ports if (p.product or '').strip()]
    # a product Shodan's InternetDB named that nothing first-party names yet: a lead for our own read of it, never a finding
    # (source_versions.lead_products: none on a shared edge address or once our own check ruled it out)
    return out + identities.products(sub) + source_versions.lead_products(sub)


def _ports(sub):
    from startScan.models import open_services
    return [(ip.address, p) for ip in sub.ip_addresses.all() for p in open_services(ip)]


def applies(sub, ports=None):
    """Whether the version source reads apply to ``sub`` (``check_coverage``)."""
    from cveFeed import route_auth
    ports = [p for _a, p in _ports(sub)] if ports is None else ports
    return bool(wanted(sub.name, host_products(sub, ports), ports, route_auth.web_bases(sub), discovered_pages(sub)))


# ----------------------------------------------------------------------------- plan

def _gate():
    from cveFeed.bounty_gate import Gate
    return Gate(blocked=())


def plan(project_id, subdomains, unattended=False):
    """``{host: {'subs': [Subdomain], 'reads': [(source, base)]}}`` for the hosts of ``subdomains`` that warrant an entry, less what the
    organization excluded (fail closed), archived hosts, what a bug bounty program's scope does not name (and, ``unattended``, a project whose
    engagement has not confirmed automated testing) and a host that points at an address a scanner may not use."""
    from cveFeed import route_auth
    from cveFeed.archive_rediscovery import archived_names
    from cveFeed.exclusions import excluded_names, normalize
    from targetApp.target_types import is_scannable_ip
    banned = excluded_names(project_id, strict=True)
    archived = set(archived_names(project_id))
    gate = _gate()
    if unattended and gate.project_blocked(project_id):
        return {}
    out = {}
    subdomains = list(subdomains)
    from cveFeed import source_versions
    source_versions.prefetch(subdomains)  # the hosts' stored readings (Shodan leads among them) in one query, not one per host
    admitted = []
    for sub in subdomains:
        name = sub.name.lower().rstrip('.')
        if normalize(sub.name) in banned or name in archived or gate.refusal(project_id, sub.name, unattended=unattended):
            continue
        addresses = [ip.address for ip in sub.ip_addresses.all() if ip.address]
        if any(not is_scannable_ip(a, project=project_id) for a in addresses):
            continue  # the name points at an address a scanner must never be used on
        if any(gate.refusal(project_id, a, unattended=unattended, derived=True) for a in addresses):
            continue
        admitted.append((sub, name))
    pages = discovered_pages_for([sub for sub, _name in admitted])  # the admitted hosts' discovered pages in a few queries, not three per host
    for sub, name in admitted:
        ports = [p for _a, p in _ports(sub)]
        reads = wanted(name, host_products(sub, ports), ports, route_auth.web_bases(sub), pages[sub.pk])
        if not reads:
            continue
        entry = out.setdefault(name, {'subs': [], 'reads': []})
        entry['subs'].append(sub)
        for item in reads:
            if item not in entry['reads'] and len(entry['reads']) < MAX_ENTRIES_PER_HOST:
                entry['reads'].append(item)
    return out


def candidates(scan, unattended=False):
    from startScan.models import Subdomain
    rows = (Subdomain.objects.filter(scan_history=scan).select_related('target_domain', 'scan_history')
            .prefetch_related('technologies', 'ip_addresses__ports'))
    return plan(scan.domain.project_id, rows, unattended=unattended)


def candidates_for_hosts(project_id, names, unattended=True):
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    rows = (Subdomain.objects.filter(latest_scan_q(), target_domain__project_id=project_id, name__in=sorted({n.lower().rstrip('.') for n in names}))
            .select_related('scan_history', 'target_domain').prefetch_related('technologies', 'ip_addresses__ports'))
    return plan(project_id, rows, unattended=unattended)


def due(project_id, found, force=False, limit=MAX_PER_SCAN):
    """The hosts of ``found`` to ask now, in a stable order: no complete read inside the week and no failed one inside the day."""
    from cveFeed import ledger
    names = sorted(found)
    if force or not names:
        return names[:limit]
    done = ledger.fresh(SERVICE, names, project_id)
    retry_later = ledger.fresh(FAILED_SERVICE, names, project_id)
    return [n for n in names if ledger._norm(n) not in done and ledger._norm(n) not in retry_later][:limit]


def read_id(host, source, base):
    return f'{host}|vsrc|{source.id}|{base}'[:200]


def _entries(found, names):
    """The task's read entries for ``names``: ``([(sub, entry)], {entry id: (host, source, base)})``."""
    from cveFeed import probes
    out, owner = [], {}
    for name in names:
        item = found[name]
        sub = item['subs'][0]
        allowed = sorted(probes.allowed_names(sub))[:20]
        for source, base in item['reads']:
            ident = read_id(name, source, base)
            if ident in owner:
                continue
            out.append((sub, {'id': ident, 'host': name, 'base': base, 'allowed': allowed,
                              'requests': catalogue.request_specs(source, secrets.token_hex(6))}))
            owner[ident] = (name, source, base)
    return out, owner


# ----------------------------------------------------------------------------- run

def run_for_scan(scan_id, force=False, dispatch=None):
    """The host pipeline stage: store what the hosts of the scan give away in stored headers, then send the reads that are due to a Sentinel
    and store what comes back. Returns ``{'hosts', 'asked', 'readings', 'exposed', 'waiting'}``. Raises ``ScannerUnavailable`` when no
    scanner can take the kind (the reads stay due; the passive readings are stored first)."""
    from agentapi import probe_dispatch, sentinel_dispatch
    from cveFeed import activity
    from cvengine.resources import ScannerUnavailable
    from startScan.models import ScanHistory, Subdomain
    scan = ScanHistory.objects.select_related('domain__project').get(pk=scan_id)
    project = scan.domain.project
    summary = {'hosts': 0, 'asked': 0, 'readings': 0, 'exposed': 0, 'waiting': 0}
    subs = list(Subdomain.objects.filter(scan_history=scan).select_related('target_domain', 'scan_history').prefetch_related('technologies', 'ip_addresses__ports'))
    try:
        prefetch_derived(subs)  # which hosts have stored readings at all: one query for the scan, not one per probe and host
    except Exception:  # noqa: BLE001 - without it every host reads its own rows, as before
        logger.exception('could not read the stored version readings of scan %s at once', scan.pk)
    for sub in subs:
        try:
            summary['readings'] += len(refresh_host(sub))
        except Exception:  # noqa: BLE001 - one host's stored data never stops the stage
            logger.exception('passive version readings of host %s failed', sub.pk)
    if not enabled():
        return {**summary, 'skipped': 'disabled'}
    found = candidates(scan)
    send_digest = send_rows = None if dispatch is None else dispatch
    if _digest_ready(project, found, send_digest):
        summary['digest_waiting'] = True  # an edge digest read waits for a contract 8 Sentinel; the host's other reads go ahead
    if _kind_ready(project, found, send_rows, catalogue.ROWS_KIND):
        summary['rows_waiting'] = True  # a status page's rows read waits for a contract 9 Sentinel; the host's other reads go ahead
    names = due(project.pk, found, force=force)
    summary['hosts'] = len(found)
    if not names:
        return summary
    if dispatch is None:
        sentinel_dispatch.scanner_or_local(project, KIND)  # raises ScannerUnavailable when none can take it: the kind has no local path
        dispatch = lambda project_, reads: probe_dispatch.try_version_read(project_, reads, scan=scan, unattended=False)  # noqa: E731
        send_digest = lambda project_, reads: probe_dispatch.try_version_digest(project_, reads, scan=scan, unattended=False)  # noqa: E731
        send_rows = lambda project_, reads: probe_dispatch.try_version_rows(project_, reads, scan=scan, unattended=False)  # noqa: E731
    _ask(project, names, found, lambda name: scan, dispatch, summary, send_digest=send_digest, send_rows=send_rows)
    activity.log('run_check', f'Version source reads of {summary["asked"]} of {len(names)} host(s) of {scan.domain.name}: {summary["readings"]} reading(s)'
                 + (f', {summary["exposed"]} exposure(s)' if summary['exposed'] else '')
                 + (f'; {summary["waiting"]} wait for a scanner' if summary['waiting'] else ''), project=project.pk, scan_id=scan.id)
    if summary['waiting']:
        raise ScannerUnavailable(KIND, f'a Sentinel returned no result for {summary["waiting"]} host(s): they stay due')
    return summary


def run_for_hosts(project, host_names, dispatch=None, priority=1):
    """The work planner's entry: the same plan, gates (unattended: a bug bounty engagement must have confirmed automated testing), ledger
    and storage as ``run_for_scan`` for the named hosts' current inventory rows, with no scan of its own."""
    from agentapi import probe_dispatch, sentinel_dispatch
    from cvengine.resources import ScannerUnavailable
    summary = {'hosts': 0, 'asked': 0, 'readings': 0, 'exposed': 0, 'waiting': 0}
    if not enabled():
        return {**summary, 'skipped': 'disabled'}
    found = candidates_for_hosts(project.pk, host_names, unattended=True)
    for item in found.values():
        for sub in item['subs']:
            refresh_host(sub)
    send_digest = send_rows = None if dispatch is None else dispatch
    if _digest_ready(project, found, send_digest):
        summary['digest_waiting'] = True  # an edge digest read waits for a contract 8 Sentinel; the host's other reads go ahead
    if _kind_ready(project, found, send_rows, catalogue.ROWS_KIND):
        summary['rows_waiting'] = True  # a status page's rows read waits for a contract 9 Sentinel; the host's other reads go ahead
    names = due(project.pk, found, limit=MAX_READS_PER_TASK)
    summary['hosts'] = len(found)
    if not names:
        return summary
    if dispatch is None:
        sentinel_dispatch.scanner_or_local(project, KIND)
        dispatch = lambda project_, reads: probe_dispatch.try_version_read(project_, reads, priority=priority, unattended=True)  # noqa: E731
        send_digest = lambda project_, reads: probe_dispatch.try_version_digest(project_, reads, priority=priority, unattended=True)  # noqa: E731
        send_rows = lambda project_, reads: probe_dispatch.try_version_rows(project_, reads, priority=priority, unattended=True)  # noqa: E731
    _ask(project, names, found, lambda name: found[name]['subs'][0].scan_history, dispatch, summary, send_digest=send_digest, send_rows=send_rows)
    if summary['waiting']:
        raise ScannerUnavailable(KIND, f'a Sentinel returned no result for {summary["waiting"]} host(s): they stay due')
    return summary


def _digest_ready(project, found, send_digest):
    """Drop the entries that need the ``version_digest`` kind (contract 8, ``Source.task_kind``) from ``found`` when no Sentinel can run it now:
    a contract 7 Sentinel is never sent one, and the host's other reads go ahead. Returns how many hosts lost an entry."""
    return _kind_ready(project, found, send_digest, catalogue.DIGEST_KIND)


def _kind_ready(project, found, sender, kind):
    """Drop the entries that need ``kind`` (``version_digest``, contract 8, or ``version_rows``, contract 9: ``Source.task_kind``) from ``found``
    when no Sentinel can run it now (an older Sentinel is never sent one) and the host's other reads go ahead. ``sender`` given (a caller's own
    dispatch) asks no Sentinel. Returns how many hosts lost an entry."""
    if sender is not None:
        return 0
    from agentapi import sentinel_dispatch
    try:
        ready = sentinel_dispatch.any_scanner_for(project, kind)
    except Exception:  # noqa: BLE001 - no answer is no Sentinel for it
        ready = False
    if ready:
        return 0
    dropped = 0
    for name in list(found):
        reads = found[name]['reads']
        kept = [(source, base) for source, base in reads if source.task_kind != kind]
        if len(kept) != len(reads):
            dropped += 1
            found[name]['reads'] = kept
            if not kept:
                del found[name]
    return dropped


def _ask(project, names, found, scan_for, send, summary, send_digest=None, send_rows=None):
    """Claim ``names``, send them in tasks of at most ``MAX_READS_PER_TASK`` read entries through ``send(project, reads)`` (the entries with a
    digest read through ``send_digest``: the ``version_digest`` kind, contract 8; with a rows read through ``send_rows``: ``version_rows``,
    contract 9) and store every answer."""
    from cveFeed import ledger
    from cveFeed.exclusions import excluded_names, normalize
    with ledger.claim_many(f'{SERVICE}@{project.pk}', names) as won:
        won = {ledger._norm(n) for n in won}
        names = [n for n in names if ledger._norm(n) in won]
        start = 0
        while start < len(names):
            chunk, count = [], 0
            while start < len(names) and count + len(found[names[start]]['reads']) <= MAX_READS_PER_TASK:
                chunk.append(names[start])
                count += len(found[names[start]]['reads'])
                start += 1
            if not chunk:  # cannot happen (a host has at most MAX_ENTRIES_PER_HOST reads); never loop on it
                start += 1
                continue
            banned = excluded_names(project.pk, strict=True)
            chunk = [n for n in chunk if normalize(n) not in banned]  # excluded since the plan was made: not sent
            if not chunk:
                continue
            reads, owner = _entries(found, chunk)
            digest = {read_id(name, source, base) for name, source, base in owner.values() if source.task_kind == catalogue.DIGEST_KIND}
            by_rows = {read_id(name, source, base) for name, source, base in owner.values() if source.task_kind == catalogue.ROWS_KIND}
            plain = [item for item in reads if item[1]['id'] not in digest and item[1]['id'] not in by_rows]
            rows = dict(send(project, plain) or {}) if plain else {}
            wanted_digest = [item for item in reads if item[1]['id'] in digest]
            if wanted_digest:
                rows.update((send_digest or send)(project, wanted_digest) or {})
            wanted_rows = [item for item in reads if item[1]['id'] in by_rows]
            if wanted_rows:
                rows.update((send_rows or send)(project, wanted_rows) or {})
            by_host = {}
            for ident, (name, source, base) in owner.items():
                by_host.setdefault(name, []).append((source, base, rows.get(ident)))
            for name in chunk:
                answered = by_host.get(name, [])
                if not answered or any(row is None for _s, _b, row in answered):
                    summary['waiting'] += 1  # no answer for part of this host: unknown, due again, nothing recorded as done
                stored, exposed, complete = store_answers(project.pk, scan_for(name), found[name], [a for a in answered if a[2] is not None])
                summary['readings'] += stored
                summary['exposed'] += exposed
                if answered and all(row is not None for _s, _b, row in answered):
                    summary['asked'] += 1
                    ledger.record(SERVICE if complete else FAILED_SERVICE, [name], project.pk, scan_for(name))


# ----------------------------------------------------------------------------- store

def _port_of(base):
    from urllib.parse import urlsplit
    try:
        parts = urlsplit(base)
        return parts.port or (443 if parts.scheme == 'https' else 80)
    except ValueError:
        return 0


def kind_of(r):
    """The ``ProbeObservation.kind`` a reading is stored as: ``version`` for a product the host stated exactly (it also becomes a technology, so
    correlation matches it by name), ``runtime`` for a language runtime, ``hint`` for any other product reading: an inferred bundled component, a
    weak or inferred operating system hint. A hint is shown and searched, never a technology: a bundled component is matched by
    ``collect_bundled`` only, an operating system hint by nothing."""
    if r['kind'] != 'product':
        return RUNTIME_KIND
    if r.get('release_only'):
        return HINT_KIND  # a Windows release with no patch level (cveFeed.windows_builds): matched by its own rules, never by name and version
    return 'version' if r['confidence'] == 'exact' else HINT_KIND


def expand(readings):
    """``readings`` and the components the vendor bundles with each exact product among them (``cveFeed.bundled_components``)."""
    from cveFeed import bundled_components
    readings = list(readings)
    return readings + [r for r in bundled_components.infer_from(readings) if r['kind'] in ('product', 'runtime')]


def _observation(r, port):
    from cveFeed import probes
    kind = kind_of(r)
    outcome = 'found' if r['version'] else 'hidden'
    evidence = {'confidence': r['confidence'], 'line_only': r['line_only'], 'component': r['component'], 'source': r['source'],
                'said': r['evidence'], 'version_source': True, **({'cpe': r['cpe']} if r.get('cpe') else {}),
                **({'bundled': r['bundled']} if isinstance(r.get('bundled'), dict) else {}), **({'on_port': True} if r.get('on_port') else {}),
                **({'build': r['build']} if r.get('build') else {})}  # a build the version carries (vmware-version's ESXi build)
    if r.get('release_only') and isinstance(r.get('windows'), dict):
        # the Windows release an NTLM challenge states (cveFeed.windows_builds): the release, never its update revision
        evidence.update(release_only=True, windows=r['windows'])
    if isinstance(r.get('range'), dict):
        # a build RANGE (cveFeed.edge_builds): never a technology (outcome ``range``, not ``found``), matched by edge_builds.collect_matches
        from cveFeed import edge_builds
        outcome, evidence['range'] = edge_builds.RANGE_OUTCOME, r['range']
    return probes._observation(kind, r['label'], r['version'], '', outcome, CONFIDENCE_SCORE.get(r['confidence'], 0.3),
                               f"{'header' if r['source'] in ('header', 'technology') else 'vsrc'}:{r['source']}"[:48], port=port,
                               url=r['url'], evidence=evidence)


def store_readings(sub, probe_id, readings, port=0, now=None):
    """Store ``readings`` of one host: products and runtimes as ``ProbeObservation`` rows (a product the host stated exactly is also added to
    its technologies), a Java runtime reading in ``JavaRuntime``. The components the vendor bundles with an exact product reading are inferred and
    stored with it (``expand``). Returns ``(rows stored, whether something new or changed was stored)``."""
    from cveFeed import java_runtime, probes, tech_links
    from cveFeed.models import ProbeObservation
    from cvengine_scanner import java
    project_id = sub.target_domain.project_id
    host = sub.name.lower().rstrip('.')
    now = now or timezone.now()
    observations, changed, stored = [], False, 0
    for r in expand(readings):
        if r['kind'] == 'java':
            got = java.reading(r['version'], 'metrics', (r.get('vendor') or '',), runtime=r.get('runtime') or '', url=r['url'], port=port,
                               evidence=r['evidence'])
            if got:
                key = f'metrics:{port}'
                changed = changed or java_runtime._current(project_id, host, key) != (got['version'], got['vendor'])
                java_runtime.store(project_id, sub.target_domain_id, host, key, got, now=now)
                stored += 1
            continue
        observations.append(_observation(r, port))
    if observations:
        stored_rows = list(ProbeObservation.objects.filter(project_id=project_id, host=host, probe=probe_id))
        before = {(o.kind, o.product, o.port): (o.version, (o.evidence or {}).get('range') if isinstance(o.evidence, dict) else None)
                  for o in stored_rows}
        probes.record(project_id, sub.target_domain_id, host, probe_id, observations, now=now, existing=stored_rows)
        stored += len(observations)
        changed = changed or any(before.get((o['kind'], o['product'], o['port'])) != (o['version'], o['evidence'].get('range'))
                                 for o in observations)
        if probes.apply_to_subdomain(sub, observations, tech_links.VERSION_SOURCE):
            changed = True
    return stored, changed


def store_answers(project_id, scan, item, answered):
    """Store what one host's answered read entries say, for every name in ``item['subs']``; file or close the exposures; correlate the host
    again when a reading is new or changed. Returns ``(readings stored, exposures filed, complete)``: ``complete`` is False when an entry's
    answers could not be read (unknown), so the host is asked again after a day."""
    from cveFeed import probes
    stored = exposed = 0
    complete = True
    verdicts = []
    for source, base, row in answered:
        answers = row.get('answers') if isinstance(row.get('answers'), list) else []
        verdict = catalogue.read_entry(source, answers) if not row.get('error') else {'state': 'unknown', 'readings': [], 'exposed': None}
        verdict['answers'] = answers
        complete = complete and verdict['state'] != 'unknown'
        heard = []
        for answer in answers[:len(source.requests)]:  # the headers of the entry's own answers: what the passive readers read anyway
            if isinstance(answer, dict) and isinstance(answer.get('headers'), dict) and not answer.get('error'):
                heard += catalogue.from_headers(answer['headers'], url=answer.get('path') or '/')
        verdicts.append((source, base, verdict, heard))
    for sub in item['subs']:
        changed = False
        for source, base, verdict, heard in verdicts:
            port = _port_of(base)
            if verdict['readings'] or heard:
                count, moved = store_readings(sub, f'{PROBE_PREFIX}{source.id}'[:48], verdict['readings'] + heard, port=port)
                stored += count
                changed = changed or moved
            if source.exposure and scan is not None:
                path = source.requests[0].path
                if verdict['exposed'] is True:
                    # rated by what the answer shows is open (``Exposure.rate``: a Nomad agent with ACLs on, an agent that asks for a sign-in)
                    exposed += file_exposure(scan, sub, source, base + path, verdict['readings'], severity=verdict.get('severity'))
                elif verdict['exposed'] is False:
                    close_exposure(scan, sub, source, base + path)
        if changed:
            probes.recorrelate(sub)
    return stored, exposed, complete


def passive_readings(sub, ports=None):
    """``[(port, reading)]`` a host gives away in what the scans already stored, no request made: the headers the port scan's http-headers script
    read on each port, the host's Server header, and the runtime a stored technology is (``Python:3.11.4``, ``.NET Framework CLR:4.0.30319``)."""
    ports = _ports(sub) if ports is None else ports
    out = []
    for _address, port in ports:
        scripts = ((port.extra or {}).get('scripts') or {}) if isinstance(port.extra, dict) else {}
        text = str(scripts.get('http-headers') or '')[:8000] if isinstance(scripts, dict) else ''
        if text:
            out += [(port.number, r) for r in catalogue.from_headers(catalogue.header_lines(text), url=f'port {port.number}')]
    if getattr(sub, 'webserver', ''):
        out += [(0, r) for r in catalogue.from_headers({'server': sub.webserver}, url='/')]
    from cveFeed import bundled_components
    for tech in sub.technologies.all():
        name, version = _split(tech.name)
        got = catalogue.from_technology(name, version)
        if got:
            out.append((0, got))
        if version:  # the components the vendor bundles with a product release the host shows (GitLab, Keycloak, Elasticsearch ...)
            out += [(0, r) for r in bundled_components.infer(name, version, said=f'technology {catalogue.clip(name, 40)} {catalogue.clip(version, 40)}')]
    seen, unique = set(), []
    for port, r in out:
        key = (port, r['component'], r['kind'])
        if key not in seen:
            seen.add(key)
            unique.append((port, r))
    return unique


def _store_derived(sub, probe_id, found, now):
    """Store ``found`` (``[(port, reading)]``) under ``probe_id`` and drop that probe's rows the host no longer gives. Returns whether a reading
    is new, changed or gone."""
    from cveFeed.models import ProbeObservation
    known = getattr(sub, '_derived_probes', None)  # the probes the host has rows of, read for the whole scan (``prefetch_derived``)
    if known is not None and probe_id in derived_probes():  # a probe the prefetch did not read is always read here
        if not found and probe_id not in known:
            return False  # nothing to store and no row of the probe to drop: the answer the read below would give
        known.add(probe_id)  # rows of the probe may exist from here on
    by_port, kept, changed = {}, set(), False
    for port, r in found:
        by_port.setdefault(port, []).append(r)
    for port, readings in by_port.items():
        changed = store_readings(sub, probe_id, readings, port=port, now=now)[1] or changed
        kept |= {(port, kind_of(r), r['label']) for r in expand(readings) if r['kind'] != 'java'}
    for row in ProbeObservation.objects.filter(project_id=sub.target_domain.project_id, host=sub.name.lower().rstrip('.'), probe=probe_id):
        if (row.port, row.kind, row.product) not in kept:
            row.delete()  # derived from what the host shows now: gone when that is gone
            changed = True
    return changed


def derived_probes():
    """The probes ``refresh_host`` stores and drops rows of for a host (``_store_derived`` and ``source_versions.refresh_runzero``)."""
    from cveFeed import source_versions
    return (PASSIVE_PROBE, SNMP_PROBE, source_versions.NMAP_PROBE, source_versions.WEBSERVER_PROBE, source_versions.NTLM_PROBE,
            source_versions.RUNZERO_PROBE, source_versions.RECOG_PROBE)


def prefetch_derived(subs):
    """Give each of ``subs`` ``_derived_probes``: the probes of ``derived_probes`` the host has a stored row of, read in one query (per
    ``PAGES_CHUNK`` names) instead of one per probe and host. Rows of one name share the set, so a reading stored for one is seen by the next.
    ``refresh_host`` then skips the read for a probe the host has no row of and no reading for, where it would find nothing to drop."""
    from cveFeed.models import ProbeObservation
    subs = [s for s in subs if getattr(s, 'target_domain_id', None) is not None]
    held = {(s.target_domain.project_id, s.name.lower().rstrip('.')): set() for s in subs}
    projects, names = {key[0] for key in held}, sorted({key[1] for key in held})
    for start in range(0, len(names), PAGES_CHUNK):
        rows = (ProbeObservation.objects.filter(project_id__in=projects, host__in=names[start:start + PAGES_CHUNK], probe__in=derived_probes())
                .values_list('project_id', 'host', 'probe').distinct())
        for project_id, host, probe in rows:
            if (project_id, host) in held:
                held[(project_id, host)].add(probe)
    for s in subs:
        s._derived_probes = held[(s.target_domain.project_id, s.name.lower().rstrip('.'))]


def snmp_readings(sub, ports=None):
    """``[(161, reading)]`` the SNMP agents of a host stated: the sysDescr the UDP sweep's snmp-sysdescr script stored on each UDP 161 port that
    answered (``version_catalogue.from_sysdescr``), no request made. The engine vendor snmp-info read is kept as evidence."""
    ports = _ports(sub) if ports is None else ports
    out, seen = [], set()
    for _address, port in ports:
        if (port.protocol or '') != 'udp' or port.number != SNMP_PORT or port.state != 'open':
            continue
        scripts = ((port.extra or {}).get('scripts') or {}) if isinstance(port.extra, dict) else {}
        text = scripts.get('snmp-sysdescr') if isinstance(scripts, dict) else None
        if not isinstance(text, str) or not text.strip():
            continue
        info = scripts.get('snmp-info') if isinstance(scripts.get('snmp-info'), str) else ''
        enterprise = re.search(r'enterprise:\s*([A-Za-z0-9 .,&-]{1,40})', info or '')
        for r in catalogue.from_sysdescr(text, enterprise.group(1).strip() if enterprise else ''):
            if (r['component'], r['label'], r['version']) not in seen:
                seen.add((r['component'], r['label'], r['version']))
                out.append((SNMP_PORT, r))
    return out


def refresh_host(sub, now=None):
    """Store the readings ``sub`` gives away in stored data (``passive_readings``, and what its SNMP agent said: ``snmp_readings``) and drop
    the ones it no longer gives. Returns them; ``sub._version_changed`` says whether any is new, changed or gone."""
    ports = _ports(sub)
    found = passive_readings(sub, ports)
    snmp = snmp_readings(sub, ports)
    now = now or timezone.now()
    changed = _store_derived(sub, PASSIVE_PROBE, found, now)
    changed = _store_derived(sub, SNMP_PROBE, snmp, now) or changed
    # what the stored ports and the stored Server header state beyond the port's own product and version (the other CPEs, extrainfo modules,
    # script versions) and the runZero readings of the host's addresses (cveFeed.source_versions)
    from cveFeed import source_versions
    stated, moved = source_versions.refresh_host(sub, ports, now=now)
    changed = moved or changed
    sub._version_changed = changed
    return found + snmp + stated


def refresh_snmp(ip):
    """After a UDP sweep of ``ip``: store what the SNMP agent said for every active host on the address (the hosts that carry its UDP
    findings) and what Recog reads in it (``source_versions.refresh_recog``), drop what it no longer says, and correlate a host again when that
    changed. Returns the number of readings. Never fatal."""
    from cveFeed import probes, udp_scan
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    total = 0
    try:
        for domain, name in udp_scan.finding_hosts(ip):
            for sub in (Subdomain.objects.filter(latest_scan_q(), target_domain=domain, name=name).select_related('target_domain', 'scan_history')
                        .prefetch_related('technologies', 'ip_addresses__ports')):
                snmp = snmp_readings(sub)
                moved = _store_derived(sub, SNMP_PROBE, snmp, timezone.now())
                # what Recog reads in the sysDescr (and the host's other stored banners), after the SNMP readings it gives way to
                from cveFeed import source_versions
                moved = source_versions.refresh_recog(sub)[1] or moved
                if moved:
                    probes.recorrelate(sub)
                total += len(snmp)
    except Exception:  # noqa: BLE001 - a reading never undoes the sweep
        logger.exception('could not store the SNMP readings of %s', getattr(ip, 'address', ip))
    return total


# ----------------------------------------------------------------------------- exposures

def _twin(sub, source):
    """Whether a template check's finding already reports this exposure on the host (``Exposure.twins``): then it is not filed again."""
    from startScan.models import Vulnerability
    twins = source.exposure.twins
    if not twins:
        return False
    return Vulnerability.objects.filter(target_domain__project_id=sub.target_domain.project_id, subdomain__name=sub.name, open_status=True,
                                        template_id__in=list(twins)).exclude(source=FINDING_SOURCE).exists()


def file_exposure(scan, sub, source, url, readings=(), severity=None):
    """The finding of an exposure ``source`` answered in its shape: one row per host name, entry and URL (a rescan updates it). Returns 1
    when it is new."""
    from cvengine.tasks import save_vulnerability
    if scan is None or _twin(sub, source):
        return 0
    exposure = source.exposure
    said = '; '.join(r['evidence'] for r in readings if r.get('evidence'))[:300]
    detail = exposure.description
    _vuln, created = save_vulnerability(
        target_domain=scan.domain, scan_history=scan, subdomain=sub, source=FINDING_SOURCE, template_id=exposure.template, name=exposure.name,
        severity=exposure.severity if severity is None else severity, http_url=url[:2000], type='exposure',
        description=detail + (f' It said: {said}' if said else ''), impact=exposure.impact, remediation=exposure.remediation,
        extracted_results=[said] if said else [], tags=['exposure', 'version-source', source.id])
    return 1 if created else 0


def close_exposure(scan, sub, source, url):
    """A complete read that found no such answer: the finding of an earlier read is gone. Only the liveness field changes; a status a
    person set is kept."""
    from startScan.models import Vulnerability
    Vulnerability.objects.filter(target_domain__project_id=scan.domain.project_id, subdomain__name=sub.name, source=FINDING_SOURCE,
                                 template_id=source.exposure.template, http_url=url[:2000], open_status=True).update(open_status=False)


# ----------------------------------------------------------------------------- correlation: the language runtimes

def _fresh_rows(rows, now=None):
    cutoff = (now or timezone.now()) - timedelta(days=STALE_DAYS)
    return [r for r in rows if r.observed_at and r.observed_at >= cutoff]


def host_runtimes(sub):
    """The fresh runtime readings of a host (``ProbeObservation`` kind ``runtime``), plus the runtimes its current technologies are (not yet
    stored when correlation runs before the stage), as ``[(component, version, confidence, line_only, source, port)]``."""
    rows = getattr(sub, '_runtime_rows', None)
    if rows is None:
        from cveFeed.models import ProbeObservation
        if sub.target_domain_id is None:
            return []
        rows = list(ProbeObservation.objects.filter(project_id=sub.target_domain.project_id, host=sub.name.lower().rstrip('.'), kind=RUNTIME_KIND))
    out = []
    for row in _fresh_rows(rows):
        ev = row.evidence if isinstance(row.evidence, dict) else {}
        component = ev.get('component') or ''
        if component in catalogue.RUNTIMES:
            out.append((component, row.version or '', ev.get('confidence') if ev.get('confidence') in catalogue.CONFIDENCES else 'weak',
                        bool(ev.get('line_only')), (ev.get('source') or row.source or '')[:40], row.port or 0))
    for tech in sub.technologies.all():
        got = catalogue.from_technology(*_split(tech.name))
        if got:
            out.append((got['component'], got['version'], got['confidence'], got['line_only'], 'technology', 0))
    return list(dict.fromkeys(out))


_POOL = {}


def runtime_cves(cve_by_id):
    """``{runtime: [(cve, [items])]}`` of a correlation pool: the CVEs whose own affected entries name a language runtime, memoised per pool."""
    memo = _POOL
    if memo.get('id') != id(cve_by_id) or memo.get('size') != len(cve_by_id):
        out = {}
        for cve in cve_by_id.values():
            hits = {}
            for item in cve.affected or []:
                key = catalogue.runtime_of_item(item)
                if key:
                    hits.setdefault(key, []).append(item)
            for key, items in hits.items():
                out.setdefault(key, []).append((cve, items))
        memo.update(id=id(cve_by_id), size=len(cve_by_id), cves=out)
    return memo['cves']


def _plain(version):
    return re.sub(r'^(?:go|v)', '', (version or '').strip())


def verdict(version, items):
    """``(in_range, deciding range)`` of one runtime version against a CVE's entries for that runtime (``correlation.range_verdict``)."""
    from cveFeed.correlation import parse_version, range_verdict
    ver = parse_version(_plain(version))
    if ver is None:
        return None, None
    unknown = False
    for item in items:
        result, rng, _nolow = range_verdict(ver, item.get('ranges') or [])
        if result is True:
            return True, rng
        unknown = unknown or result is None
    return (None if unknown else False), None


def _bounded(items):
    from cveFeed.correlation import _bounded as bounded, prepared_ranges
    return any(bounded(rng) for item in items for rng in prepared_ranges(item.get('ranges') or []))


def line_possible(line, items):
    """Whether a runtime line (``4.8``, ``26``) can be inside one of the CVE's ranges: either end of the line tested, or no bound decides."""
    low, high = verdict(f'{line}.0', items)[0], verdict(f'{line}.99999', items)[0]
    return low is not False or high is not False


def collect_matches(subdomain, cve_by_id, rows, scan_history=None, min_confidence=0.0, fix_lookup=None):
    """Append the runtime matches of ``subdomain`` to ``rows`` (see the module docstring). A CVE ``rows`` already holds for the host (its
    technology, port or Java match) is not matched twice. Returns how many."""
    from cveFeed import distro as distro_lib
    from cveFeed.correlation import BACKPORT_CONFIDENCE, confidence_for, distro_fix_evidence, parse_version
    pool = runtime_cves(cve_by_id)
    if not pool:
        return 0
    readings = host_runtimes(subdomain)
    if not readings:
        return 0
    taken = {r['cve_entry_id'] for r in rows if r.get('subdomain_id') == subdomain.id}
    found = 0
    for key, runtime in catalogue.RUNTIMES.items():
        mine = [r for r in readings if r[0] == key]
        if not mine or key not in pool:
            continue
        exact = [r for r in mine if r[2] == 'exact' and r[1] and not r[3]]
        lines = [r for r in mine if r[1] and (r[3] or r[2] != 'exact')]
        present = any(r[2] in ('exact', 'inferred') for r in mine)
        listed = [{'version': v, 'confidence': c, 'line_only': lo, 'source': s, 'port': p} for _k, v, c, lo, s, p in mine][:10]
        base = {'source': MATCH_SOURCE, 'runtime': key, 'runtime_label': runtime.label, 'readings': listed}
        for cve, items in pool[key]:
            if cve.id in taken:
                continue
            row = None
            bounded = _bounded(items)
            if exact:
                results = [(r, *verdict(r[1], items)) for r in exact]
                hit = next(((r, rng) for r, result, rng in results if result is True), None)
                if hit is None:
                    if all(result is False for _r, result, _rng in results) or not cve.kev:
                        continue  # every version read is outside the range, or no bound decides and only an actively exploited CVE is kept
                    r = exact[0]
                    row = _row(cve, subdomain, scan_history, runtime.label, r[1], None, UNKNOWN_CONFIDENCE,
                               {**base, 'raw_version': r[1], 'unbounded': True, 'reading': _text(runtime, r)})
                else:
                    r, rng = hit
                    confidence = confidence_for(parse_version(_plain(r[1])), True, cve.kev)
                    status, fixed, fix = distro_lib.NO_DATA, '', None
                    info = distro_lib.parse_distro(runtime.label, r[1], '')
                    if info.get('distro'):
                        info['package'] = distro_lib.package_for(runtime.label, info['distro'], info.get('upstream_version') or '')
                    if info.get('distro') and info.get('package') and fix_lookup:
                        rows_for = fix_lookup(distro_lib.fix_distro(info['distro']), info['package'], getattr(cve, 'cve_id', ''))
                        status, fixed, fix_row = distro_lib.judge_row(info, rows_for)
                        fix = distro_fix_evidence(info, fix_row, fixed)
                        if status == distro_lib.PATCHED:
                            confidence = 0.2
                        elif status == distro_lib.VULNERABLE:
                            confidence = 0.95
                        elif status in (distro_lib.BACKPORT, distro_lib.UNKNOWN):
                            confidence = min(confidence, BACKPORT_CONFIDENCE)
                    evidence = {**base, 'raw_version': r[1], 'range': rng or {}, 'reading': _text(runtime, r), 'port': r[5],
                                **({'distro': {k: v for k, v in info.items() if v}} if info.get('distro') else {}),
                                **({'distro_fix': fix} if fix else {})}
                    row = _row(cve, subdomain, scan_history, runtime.label, r[1], True, confidence, evidence, status=status, fixed=fixed)
            else:
                if not bounded and not cve.kev:
                    continue
                if not (lines or (present and runtime.unknown)):
                    continue  # a weak presence (a header any stack may send) matches nothing
                possible = [r for r in lines if line_possible(_plain(r[1]), items)] if lines else None
                if lines and bounded and not possible:
                    continue  # the host states a line no affected range reaches
                confidence, note = UNKNOWN_CONFIDENCE, ''
                inside = [r for r in (possible or []) if not r[3] and verdict(r[1], items)[0] is True]
                if inside:
                    confidence, note = INFERRED_IN_RANGE_CONFIDENCE, f'inferred {_text(runtime, inside[0])} is inside the affected range'
                    if inside[0][4] == BUNDLED_SOURCE:
                        note += f': affected only if the bundled {runtime.label} was not replaced'
                elif possible:
                    note = f'the line read, {_text(runtime, possible[0])}, can be inside the affected range'
                evidence = {**base, 'runtime_unknown': True, 'raw_version': '', **({'runtime_note': note} if note else {}),
                            **({'unbounded': True} if not bounded else {})}
                row = _row(cve, subdomain, scan_history, runtime.label, '', None, confidence, evidence)
            if row is None or row['confidence'] < min_confidence or row['confidence'] <= 0.0:
                continue
            rows.append(row)
            found += 1
    return found


def _text(runtime, r):
    what = r[1] if not r[3] else f'the {r[1]} line'
    return f'{runtime.label} {what} ({r[4]}, {r[2]})'


def _row(cve, subdomain, scan_history, label, version, in_range, confidence, evidence, status='no_data', fixed=''):
    return {'cve_entry_id': cve.id, 'subdomain_id': subdomain.id, 'source': MATCH_SOURCE, 'matched_product': label[:255],
            'matched_version': (version or '')[:100], 'version_in_range': in_range, 'confidence': confidence,
            'scan_history_id': scan_history.id if scan_history else subdomain.scan_history_id, 'distro_status': status,
            'distro_fixed_version': (fixed or '')[:64], 'evidence': evidence}


def host_bundled(sub):
    """The fresh bundled component readings of a host (``hint`` rows a vendor's bundle gave, ``cveFeed.bundled_components``), one per
    component and version: ``[(label, version, bundled detail, port)]``."""
    rows = getattr(sub, '_bundled_rows', None)
    if rows is None:
        from cveFeed.models import ProbeObservation
        if sub.target_domain_id is None:
            return []
        rows = list(ProbeObservation.objects.filter(project_id=sub.target_domain.project_id, host=sub.name.lower().rstrip('.'), kind=HINT_KIND,
                                                    outcome='found', evidence__source=BUNDLED_SOURCE))
    out, seen = [], set()
    for row in _fresh_rows(rows):
        ev = row.evidence if isinstance(row.evidence, dict) else {}
        if ev.get('source') != BUNDLED_SOURCE or ev.get('confidence') != 'inferred' or not row.version or (row.product, row.version) in seen:
            continue
        seen.add((row.product, row.version))
        out.append((row.product, row.version, ev.get('bundled') if isinstance(ev.get('bundled'), dict) else {}, row.port or 0))
    return out


def prefetch_bundled(subs):
    """Give each of ``subs`` its bundled component rows (``_bundled_rows``, read by ``host_bundled``) in one query."""
    from cveFeed.models import ProbeObservation
    subs = [s for s in subs if getattr(s, 'target_domain_id', None)]
    if not subs:
        return
    from targetApp.models import Domain
    project_of = dict(Domain.objects.filter(id__in={s.target_domain_id for s in subs}).values_list('id', 'project_id'))
    by_key = {}
    rows = ProbeObservation.objects.filter(project_id__in=set(project_of.values()), host__in={s.name.lower().rstrip('.') for s in subs},
                                           kind=HINT_KIND, outcome='found', evidence__source=BUNDLED_SOURCE)
    for row in rows:
        by_key.setdefault((row.project_id, row.host), []).append(row)
    for sub in subs:
        sub._bundled_rows = by_key.get((project_of.get(sub.target_domain_id), sub.name.lower().rstrip('.')), [])


def prefetch_readings(subs, cve_by_id):
    """Give each of ``subs`` the other per-host rows correlation reads, one query per table for the whole chunk instead of one per host: its
    runtime readings (``_runtime_rows``, ``host_runtimes``), its version range readings (``_range_rows``, ``edge_builds.range_readings``) and its
    Java runtimes (``_java_runtimes``, ``java_runtime.host_runtimes``), and its target, so ``sub.target_domain`` is not one query per host. A table
    is read only when the pool holds a CVE its reader would test (the same gate each ``collect_matches`` applies before reading): a pool with none
    costs no query."""
    from django.db.models import prefetch_related_objects

    from cveFeed import edge_builds, java_runtime
    from cveFeed.models import JavaRuntime, ProbeObservation
    wanted = {'runtime': bool(runtime_cves(cve_by_id)), 'range': bool(edge_builds.range_cves(cve_by_id)), 'java': bool(java_runtime.java_cves(cve_by_id))}
    subs = [s for s in subs if getattr(s, 'target_domain_id', None)]
    if not subs or not any(wanted.values()):
        return
    prefetch_related_objects(subs, 'target_domain')
    hosts = {s.name.lower().rstrip('.') for s in subs}
    projects = {s.target_domain.project_id for s in subs}
    tables = {'runtime': ('_runtime_rows', lambda: ProbeObservation.objects.filter(project_id__in=projects, host__in=hosts, kind=RUNTIME_KIND)),
              'range': ('_range_rows', lambda: ProbeObservation.objects.filter(project_id__in=projects, host__in=hosts, probe__startswith=PROBE_PREFIX,
                                                                              outcome=edge_builds.RANGE_OUTCOME)),
              'java': ('_java_runtimes', lambda: JavaRuntime.objects.filter(project_id__in=projects, host__in=hosts))}
    for name, (attr, read) in tables.items():
        if not wanted[name]:
            continue  # its reader returns before reading: the hosts keep no attribute, as before
        found = {}
        for row in read():
            found.setdefault((row.project_id, row.host), []).append(row)
        for sub in subs:
            setattr(sub, attr, found.get((sub.target_domain.project_id, sub.name.lower().rstrip('.')), []))


def collect_bundled(subdomain, product_index, cve_by_id, rows, scan_history=None, min_confidence=0.0):
    """Append the candidates of the components a vendor bundles on ``subdomain`` (``host_bundled``) to ``rows``: the product named like any
    technology (``correlation._match_candidates``), but its version is an inference, so a version inside an affected range is never
    ``version_in_range`` True. It is a needs-validation candidate (``evidence.bundled_inferred``: ice, never fire, with the owner's check of the
    component that actually runs), affected only if the bundled component was not replaced. A version outside every range, or a CVE with no
    usable range, gives nothing. A CVE ``rows`` already holds for the host is not matched twice. Returns how many."""
    from cveFeed.correlation import _match_candidates, _norm, parse_version
    readings = host_bundled(subdomain)
    if not readings or not product_index:
        return 0
    taken = {r['cve_entry_id'] for r in rows if r.get('subdomain_id') == subdomain.id}
    found = 0
    for label, version, detail, port in readings:
        ver = parse_version(version)
        if ver is None:
            continue
        details = {}
        for cve, matched, in_range in _match_candidates(label, ver, _norm(label), product_index, cve_by_id, details=details):
            if in_range is not True or cve.id in taken or INFERRED_IN_RANGE_CONFIDENCE < min_confidence:
                continue
            product = f"{detail.get('product') or 'its product'} {detail.get('product_version') or ''}".strip()
            note = (f'inferred {label} {version}, which {product} bundles, is inside the affected range: affected only if the bundled {label} was '
                    'not replaced')
            evidence = {'source': BUNDLED_SOURCE, 'bundled_inferred': True, 'component_label': label, 'raw_version': version, 'port': port,
                        'range': (details.get(cve.id) or {}).get('range') or {}, 'bundled': detail, 'bundled_note': note}
            rows.append(_row(cve, subdomain, scan_history, matched or label, version, None, INFERRED_IN_RANGE_CONFIDENCE, evidence) | {'source': BUNDLED_SOURCE})
            taken.add(cve.id)
            found += 1
    return found


def bundled_host_ids(base_qs):
    """The ids of the Subdomain rows of ``base_qs`` with a bundled component reading (``correlation.candidate_subdomains``)."""
    from django.db.models import Exists, OuterRef
    from cveFeed.models import ProbeObservation
    readings = ProbeObservation.objects.filter(project_id=OuterRef('target_domain__project_id'), host=OuterRef('name'), kind=HINT_KIND,
                                               evidence__source=BUNDLED_SOURCE)
    return base_qs.filter(Exists(readings)).values('id')


def index_has_runtime(product_index):
    """Whether a correlation product index may hold a CVE in a language runtime. The Go CNA names each standard library package (``net/http``,
    ``crypto/tls``) rather than Go, so no product token tells: any pool may, and the hosts with a runtime reading are always candidates (a
    bounded set: only hosts a version source or a stored header gave a runtime)."""
    return bool(product_index)


def runtime_host_ids(base_qs):
    """The ids of the Subdomain rows of ``base_qs`` with a runtime reading (``correlation.candidate_subdomains``)."""
    from django.db.models import Exists, OuterRef
    from cveFeed.models import ProbeObservation
    readings = ProbeObservation.objects.filter(project_id=OuterRef('target_domain__project_id'), host=OuterRef('name'), kind=RUNTIME_KIND)
    return base_qs.filter(Exists(readings)).values('id')


def runtime_cves_among(pks, exclude=()):
    """The stored CVEs among ``pks`` that name a language runtime (``tasks.auto_fire_new_cves`` correlates them the moment they land)."""
    from cveFeed.correlation import _CVE_FIELDS, clean_affected
    from cveFeed.models import CVEEntry
    pks = [pk for pk in (pks or ()) if pk not in set(exclude)]
    if not pks:
        return []
    rows = list(CVEEntry.objects.filter(pk__in=pks).exclude(status__iregex=r'reject|withdrawn|merged|superseded').exclude(local_only=True).only(*_CVE_FIELDS))
    for row in rows:
        row.affected = clean_affected(row.affected)
    return [row for row in rows if any(catalogue.runtime_of_item(item) for item in row.affected or [])]


# ----------------------------------------------------------------------------- what the host payload and the search show

def as_dict(row):
    """One reading as the host payload (REST and MCP ``version_sources``) and the host page show it. ``evidence`` is what the host said."""
    ev = row.evidence if isinstance(row.evidence, dict) else {}
    source = row.probe[len(PROBE_PREFIX):] if row.probe.startswith(PROBE_PREFIX) else row.probe
    bundled = ev.get('bundled') if isinstance(ev.get('bundled'), dict) else None
    return {'component': ev.get('component') or '', 'product': row.product, 'kind': 'runtime' if row.kind == RUNTIME_KIND else 'product',
            'version': row.version, 'confidence': ev.get('confidence') or 'weak', 'line_only': bool(ev.get('line_only')),
            'source': source, 'read_by': ev.get('source') or '', 'port': row.port or None, 'url': row.url, 'evidence': ev.get('said') or '',
            'matched': row.kind != HINT_KIND or bool(bundled) or bool(ev.get('release_only')), 'cpe': ev.get('cpe') or '',
            'bundled_with': ({k: bundled.get(k, '') for k in ('product', 'product_version', 'basis', 'source')} if bundled else None),
            'first_seen': row.first_seen.isoformat() if row.first_seen else None, 'last_seen': row.observed_at.isoformat() if row.observed_at else None,
            'stale': bool(row.observed_at and row.observed_at < timezone.now() - timedelta(days=STALE_DAYS)),
            # a third-party reading (cveFeed.source_versions: Shodan's InternetDB, runZero): who reported it and as of when; matched only under the
            # freshness rule (source_versions.in_use), never a technology
            **(_reported_fields(row) if row.kind == 'reported' else {}),
            # a build RANGE (cveFeed.edge_builds): the releases it can be, and how it was read; never a version
            **({'range': {k: ev['range'].get(k) for k in ('candidates', 'ranges', 'basis')}} if isinstance(ev.get('range'), dict) else {}),
            # a Windows release (cveFeed.windows_builds): the release is known, its update revision (the patch level) is not
            **({'release_only': True, 'windows': {k: ev['windows'].get(k) for k in ('line', 'candidates', 'ambiguous', 'basis', 'sources',
                                                                                   'end_of_support', 'esu_until')}}
               if ev.get('release_only') and isinstance(ev.get('windows'), dict) else {})}


def _reported_fields(row):
    from cveFeed import source_versions
    return source_versions.payload_fields(row)


_ORDER = {'exact': 0, 'inferred': 1, 'weak': 2}


def readings_qs(leads=False):
    """The version source readings a host runs: never a Shodan InternetDB reading (a lead for our own checks, not a product seen on the host),
    unless ``leads`` (the explicit ``vsource:shodan-idb`` search)."""
    from django.db.models import Q
    from cveFeed.models import ProbeObservation
    rows = ProbeObservation.objects.filter(Q(probe__startswith=PROBE_PREFIX)).filter(evidence__version_source=True)
    if leads:
        return rows
    from cveFeed import source_versions
    return rows.exclude(probe=source_versions.SHODAN_PROBE)


def readings_for(project_ids, hosts):
    """``{(project id, host): [as_dict]}`` for a page of hosts, exact readings first (one query)."""
    out = {}
    if not hosts:
        return out
    rows = readings_qs().filter(project_id__in=list(project_ids), host__in=list(hosts)).order_by('host', '-observed_at')
    for row in rows:
        out.setdefault((row.project_id, row.host), []).append(row)
    result = {}
    for key, rs in out.items():
        listed, seen = [], set()
        for r in sorted(rs, key=lambda r: (_ORDER.get((r.evidence or {}).get('confidence'), 3), r.product)):
            item = as_dict(r)
            same = (item['component'], item['version'], item['kind'], item['confidence'])
            if same not in seen:  # a bundle inferred from a reading and again from the technology that reading made: shown once
                seen.add(same)
                listed.append(item)
        result[key] = listed[:30]
    return result


def search_rows(field, value):
    """The reading rows a search term names, or None for a value it cannot read.

    ``component:<name>`` (a product or runtime read from a version source: ``component:grafana``, ``component:docker``, any name ``tech:`` takes
    through ``cveFeed.tech_search``: ``component:"apache httpd"``; ``component:any``),
    ``runtime:<name>`` (a language runtime: ``runtime:python``, ``runtime:go``, ``runtime:dotnet``; ``runtime:any``), each optionally with a
    version prefix after ``@`` (``runtime:python@3.8`` finds 3.8.10, never 3.80); ``vsource:<entry>`` (where it was read: ``vsource:prometheus-metrics``,
    ``vsource:header``, ``vsource:snmp`` for an SNMP agent's sysDescr, ``vsource:bundled`` for a component inferred from a vendor's bundle,
    ``vsource:ntlm`` for the Windows release an NTLM challenge states)."""
    from django.db.models import Q
    text = (value or '').strip().lower()
    if not text or len(text) > 80:
        return None
    rows = readings_qs()
    if field == 'vsource':
        from cveFeed import source_versions
        if text == source_versions.SHODAN_PROBE[len(PROBE_PREFIX):]:  # the one way to find Shodan's readings: they are leads, not products on the host
            return readings_qs(leads=True).filter(probe=source_versions.SHODAN_PROBE)
        if text == 'any':
            return rows
        if text in ('header', 'passive', 'technology'):
            return rows.filter(probe=PASSIVE_PROBE)
        if text == 'snmp':
            return rows.filter(probe=SNMP_PROBE)
        if text == BUNDLED_SOURCE:
            return rows.filter(evidence__source=BUNDLED_SOURCE)
        from cveFeed import source_versions
        if text in source_versions.SEARCH:  # the sources of data already received (cveFeed.source_versions.SEARCH)
            return rows.filter(probe=source_versions.SEARCH[text])
        if text == source_versions.REPORTED:  # every third-party reading (Shodan's included: an explicit, labelled filter)
            return readings_qs(leads=True).filter(kind=source_versions.REPORTED)
        if text not in catalogue.BY_ID:
            return None
        return rows.filter(probe=f'{PROBE_PREFIX}{text}')
    name, _sep, version = text.partition('@')
    if field == 'runtime':
        rows = rows.filter(kind=RUNTIME_KIND)
        aliases = {'dotnet': 'dotnet-framework', '.net': 'dotnet-framework', 'net': 'dotnet-framework', 'golang': 'go', 'node': 'nodejs',
                   'node.js': 'nodejs', 'otp': 'erlang'}
        name = aliases.get(name, name)
        if name != 'any' and name not in catalogue.RUNTIMES:
            return None
    if name != 'any' and field == 'component':
        # a product by any name tech: takes (cveFeed.tech_search: its aliases, a vendor in front, an edition or a detector's word behind,
        # a quoted name with spaces), its component slug, or the product as stored
        from cveFeed import tech_search
        name = name.strip().strip('"').strip()
        if not re.fullmatch(r'[a-z0-9][a-z0-9 ._/+-]{0,60}', name):
            return None
        spec = tech_search.parse(name)
        named = Q(evidence__component=name) | Q(evidence__component=re.sub(r'[^a-z0-9]+', '-', name).strip('-')) | Q(product__iexact=name)
        pattern = spec.name_re() if spec is not None else ''
        rows = rows.filter(named | Q(product__iregex=pattern) if pattern else named)
    elif name != 'any':
        if not re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,40}', name):
            return None
        rows = rows.filter(Q(evidence__component=name) | Q(product__iexact=name))
    if version:
        if not re.fullmatch(r'\d{1,4}(?:\.\d{1,9}){0,3}', version):
            return None
        rows = rows.filter(version__regex=rf'^{re.escape(version)}(?:$|[^0-9])')  # 3.8 finds 3.8.10, Junos 21.4 finds 21.4R3-S2, never 3.80
    return rows


# ----------------------------------------------------------------------------- the catch-up after an update

def catch_up(apply=False, batch=200):
    """The one-time catch-up an update runs (``manage.py backfill_version_sources --apply``, an upgrade backfill): for every current host,
    store the readings it already gives away in stored data (``refresh_host``: the headers the port scan's http-headers script read, the Server header, the
    runtime a technology is, what its SNMP agent's sysDescr states, and the components the vendor bundles with an exact product release), then
    correlate the hosts that gained a runtime reading against the runtime CVEs, and the hosts that gained an SNMP release or a bundled component
    against every CVE. The active reads are the work
    planner's (the ``version-sources`` check is due on every host it applies to). Idempotent. Returns ``{'hosts', 'readings', 'matches'}``."""
    from cveFeed import correlation
    from startScan.models import Subdomain
    base = Subdomain.objects.filter(correlation.latest_scan_q()).filter(target_domain__isnull=False)
    ids = list(base.order_by('id').values_list('id', flat=True))
    out = {'hosts': len(ids), 'readings': 0, 'matches': 0}
    if not apply or not ids:
        return out
    cve_by_id, full_index = correlation.cve_pool()
    pool = {cve.id: cve for entries in runtime_cves(cve_by_id).values() for cve, _items in entries}
    index = correlation.build_product_index(pool.values())
    for start in range(0, len(ids), batch):
        subs = list(Subdomain.objects.filter(id__in=ids[start:start + batch]).select_related('target_domain', 'scan_history')
                    .prefetch_related('technologies', 'ip_addresses__ports'))
        gained, whole = [], []
        for sub in subs:
            try:
                found = expand(r for _p, r in refresh_host(sub))
            except Exception:  # noqa: BLE001 - one host's stored data never stops the catch-up
                logger.exception('version source catch-up of host %s failed', sub.pk)
                continue
            out['readings'] += len(found)
            if any(kind_of(r) == 'version' and r['source'] == 'snmp' or r['source'] == BUNDLED_SOURCE and r['kind'] == 'product' for r in found):
                whole.append(sub)  # an SNMP agent's release (a technology now) or a bundled component: matched against every CVE
            elif any(r['kind'] == 'runtime' for r in found):
                gained.append(sub)
        if pool and gained:
            out['matches'] += correlation.correlate_subdomains(gained, index, pool, min_confidence=0.4)[1]
        if whole:
            out['matches'] += correlation.correlate_subdomains(whole, full_index, cve_by_id, min_confidence=0.4)[1]
    return out
