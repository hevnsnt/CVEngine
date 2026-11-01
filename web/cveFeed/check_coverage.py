"""Check coverage: which of the checks that apply to a host have run, and which are due.

There are many checks now (port discovery, nuclei passes, WPScan, the TLS audit, the slow web sweeps, ...) and no single place said what had
run on a host. This module is that place. It is internal accounting: it reads what the checks already recorded and never runs, queues or
changes anything.

One registry (``CHECKS``) lists each check once: its id and label, the facts that make it apply to a host (open ports and services,
technologies, whether the host is web, whether its project is bug bounty blocked, whether the feature switch is on), where its last run
is recorded, and how long that run stays fresh. Only checks that apply are counted: a host with no TLS port is not counted against the TLS
audit, a host that does not show WordPress is not counted against WPScan, a UDP sweep counts only the addresses it would scan.

States, per check and host:

* ``not_applicable``: the check does not apply (the detail says why). Never counted.
* ``done``: it applies and ran inside its window (the ledger TTL of its kind, ``cveFeed.ledger.DEFAULT_TTL_HOURS`` and its
  ``CVENGINE_TTL_<KIND>`` override; a check that has no ledger kind is judged by its scan stage, ``STAGE_TTL_HOURS``).
* ``due``: it applies and never ran, ran longer ago than its window, or its last attempt failed.

``coverage`` returns ``{done, applicable, paused, internal, checks: [{id, label, state, last_run, ttl_hours, detail}]}`` (``internal`` is the declared
network of a host inside one, else null: such a host is judged by what the internal scan runs, see "hosts inside a declared internal network"); the single-host view also
carries ``units`` (the addresses, ports or CVEs a check is judged on). ``done`` of ``applicable`` is the "NN of NNN applicable checks done"
the host page shows.

Evidence is read in a few batched queries for a whole page of hosts (``load``): never one query per host or per check.

Adding a check: see "Check coverage" in docs/PIPELINE.md. ``tests/test_check_coverage.py`` fails when a ledger kind, a sweep or a scan stage
exists that is neither in ``CHECKS`` nor listed in ``EXCLUDED`` with its reason.
"""
import logging
from collections import namedtuple
from datetime import timedelta
from functools import reduce
from operator import or_

from django.utils import timezone

logger = logging.getLogger(__name__)

STAGE_TTL_HOURS = 7 * 24  # a check with no ledger kind is judged by the time its scan stage finished, against this window
SCAN_STAGE_OK = 2  # ScanActivity.status of a stage that finished
MAX_UNITS = 25  # addresses, ports or CVEs one check is judged on, so a host with hundreds of ports stays a bounded record
CHUNK = 3000  # assets per query: a page of 200 hosts is a few thousand names, addresses and ports, so a page is one or two reads
TCP = ('', 'tcp')
HEAD_KINDS = ('probe', 'subapp', 'vhost')  # ledger kinds whose assets read "<host or address>|..."
BOUNTY_REASON = 'the project\'s bug bounty engagement has not confirmed automated testing'

# one fact of the evidence: when a check ran (or tried), how long that stays fresh, and whether it worked
Run = namedtuple('Run', 'when ttl ok')


class Unit:
    """What one check is judged on for a host (an address, a port, a CVE, the host itself) and its recorded runs."""
    __slots__ = ('label', 'runs', 'bounded')

    def __init__(self, label, runs, bounded=False):
        # ``bounded``: the runs were read only inside the kind's window (see ``load``), so no run means "none inside the window"
        self.label, self.runs, self.bounded = label, list(runs), bounded

    def fresh(self, now):
        return any(r.ok and r.when and (now - r.when).total_seconds() <= r.ttl for r in self.runs)

    def last(self):
        """The newest successful run, else the newest attempt, else None."""
        good = [r.when for r in self.runs if r.ok and r.when]
        any_ = [r.when for r in self.runs if r.when]
        return max(good) if good else (max(any_) if any_ else None)

    def failed_last(self):
        timed = sorted((r for r in self.runs if r.when), key=lambda r: r.when)
        return bool(timed) and not timed[-1].ok


class Check:
    """One registry entry. ``kinds`` are the ledger kinds (the part of a service name before ``:``), ``sweeps`` the ``ledger.sweep_claim``
    names and ``stages`` the scan stage names this check covers, which the registry test compares with the code. ``plan(host, evidence)``
    returns the text saying why the check does not apply, or the list of ``Unit`` it is judged on."""

    def __init__(self, id, label, plan, kinds=(), sweeps=(), stages=(), ttl_kind=None):
        self.id, self.label, self.plan = id, label, plan
        self.kinds, self.sweeps, self.stages = tuple(kinds), tuple(sweeps), tuple(stages)
        self.ttl_kind = ttl_kind or (self.kinds[0] if self.kinds else None)

    def ttl_hours(self):
        from cveFeed import ledger
        return round(ledger.ttl(self.ttl_kind) / 3600, 2) if self.ttl_kind else STAGE_TTL_HOURS


# --------------------------------------------------------------------------------------- what is known about one host

class Addr:
    """One address of a host (merged over the host's copies): the facts the checks read."""
    __slots__ = ('address', 'org_id', 'is_cdn', 'full_scanned_at', 'ports')

    def __init__(self, address, org_id=None, is_cdn=False, full_scanned_at=None, ports=()):
        self.address, self.org_id, self.is_cdn, self.full_scanned_at, self.ports = address, org_id, bool(is_cdn), full_scanned_at, list(ports)


class HostFacts:
    """The stored facts about one host the applicability rules read. ``from_rows`` builds it from a Subdomain and the other current rows
    of the same host (no queries when ``ip_addresses__ports`` and ``technologies`` are prefetched); tests build it directly."""

    def __init__(self, name, project_id, *, scan_id=None, target_name='', target_is_domain=False, addresses=(), techs=(), web_bases=(),
                 http_up=False, http_url='', excluded=False, shared_platform=False, hot_cves=(), unversioned=0, probe_rows=(), root=None,
                 target=None, internal=''):
        self.name = (name or '').strip().lower().rstrip('.')
        self.project_id = project_id
        self.scan_id = scan_id
        self.target = target
        self.target_name = (target_name or '').strip().lower().rstrip('.')
        self.target_is_domain = target_is_domain
        self.addresses = {a.address: a for a in addresses}
        self.techs = set(techs)
        self.web_bases = list(web_bases)
        self.http_up = bool(http_up)
        self.http_url = http_url or ''
        self.excluded = bool(excluded)
        self.shared_platform = bool(shared_platform)
        self.hot_cves = list(hot_cves)
        self.unversioned = int(unversioned or 0)
        self.probe_rows = list(probe_rows)
        self.root = root
        self.internal = internal or ''  # the declared internal network (cidr) the host is inside, else ''
        self._scannable = None
        self._inside = None

    @classmethod
    def from_rows(cls, sub, others, project_id):
        from cveFeed import internal_view, route_auth
        from startScan.models import open_services
        from targetApp.target_types import DOMAIN, classify_target
        rows = [sub, *others]
        addresses, seen = {}, set()
        for row in rows:
            for ip in row.ip_addresses.all():
                if not ip.address:
                    continue
                entry = addresses.get(ip.address)
                if entry is None:
                    entry = addresses[ip.address] = Addr(ip.address, ip.org_id, ip.is_cdn, ip.full_scanned_at)
                else:
                    entry.is_cdn = entry.is_cdn or bool(ip.is_cdn)
                    if ip.full_scanned_at and (not entry.full_scanned_at or ip.full_scanned_at > entry.full_scanned_at):
                        entry.full_scanned_at = ip.full_scanned_at
                for port in open_services(ip):
                    key = (ip.address, port.number, port.protocol)
                    if key not in seen:
                        seen.add(key)
                        entry.ports.append(port)
        bases = list(dict.fromkeys(b for row in rows for b in route_auth.web_bases(row)))
        domain = sub.target_domain if sub.target_domain_id else None
        return cls(sub.name, project_id, scan_id=sub.scan_history_id, target=domain, target_name=domain.name if domain else '',
                   target_is_domain=bool(domain) and classify_target(domain.name) == DOMAIN, addresses=addresses.values(),
                   techs={t.name for row in rows for t in row.technologies.all() if t.name}, web_bases=bases,
                   http_up=any((row.http_status or 0) > 0 for row in rows), http_url=sub.http_url or '',
                   internal=internal_view.network_of(project_id, sub.name) or '')

    @property
    def is_target(self):
        """The host IS a target of its project (the checks that run on a target as a whole count there, not on each host under it)."""
        return bool(self.target_name) and self.name == self.target_name

    @property
    def is_domain_target(self):
        return self.is_target and self.target_is_domain

    @property
    def web(self):
        return bool(self.web_bases)

    def scannable(self):
        """The addresses a scanner may be pointed at: not a CDN or shared platform's edge, and passing the same scannable gate every stage
        uses (an internal address only for the tailnet device of this project). A name is never resolved here."""
        if self._scannable is None:
            from targetApp.target_types import is_scannable_ip
            self._scannable = [] if self.shared_platform else [
                a for a in self.addresses.values() if not a.is_cdn and is_scannable_ip(a.address, project=self.project_id)]
        return self._scannable

    def pointing_inside(self):
        """True when an address of the host is one a scanner must never be pointed at: the name is not a scan target at all."""
        if self._inside is None:
            from targetApp.target_types import is_scannable_ip
            self._inside = any(not is_scannable_ip(a.address, project=self.project_id) for a in self.addresses.values())
        return self._inside


# --------------------------------------------------------------------------------------- the evidence

def _norm(value):
    return str(value).strip().lower()[:255]


class Evidence:
    """What the checks recorded, for a page of hosts, loaded by ``load`` in a fixed number of queries. Tests fill it with ``add_ledger``."""

    def __init__(self, now=None):
        self.now = now or timezone.now()
        self.ledger = {}       # (kind, project id or None, asset) -> [(full service name, status, finished_at)]
        self.heads = {}        # (kind, project id, text before the first "|" of the asset) -> the same
        self.signed = {}       # (kind, project id, host, credential revision) -> the same
        self.routes = {}       # (project id, host) -> newest route check
        self.certs = {}        # (project id, host, port) -> when the certificate was last read
        self.stages = {}       # (scan id, stage name) -> [(status, time)]
        self.archived = set()  # (project id, host)
        self.blocked = set()   # project ids the bug bounty gate keeps out of the background sweeps
        self.openvas = {}      # project id -> hosts someone listed for OpenVAS, for each project opted in (only while the add-on is on)
        self.openvas_forced = {}  # project id -> the listed hosts scanned whatever their heat
        self.openvas_heat = {}    # (project id, host) -> fire | smoke | ice | clean | unscanned, for the page's hosts of an opted-in project
        self.credentials = {}  # project id -> stored sign-ins
        self.facts = {}        # Subdomain id -> HostFacts built while loading
        self.sentinels = {}    # project id -> whether a live internal Sentinel exists (read lazily, only for internal hosts)

    def add_ledger(self, service, project_id, asset, when, status='done'):
        kind = service.split(':')[0]
        self.ledger.setdefault((kind, project_id, _norm(asset)), []).append((service, status, when))

    def _runs(self, entries):
        from cveFeed import ledger
        return [Run(when, ledger.ttl(service), status == 'done' and not service.split(':')[0].endswith('-failed'))
                for service, status, when in entries]

    def ledger_runs(self, kinds, project_id, asset):
        out = []
        for kind in kinds:
            out += self._runs(self.ledger.get((kind, project_id, _norm(asset)), ()))
        return out

    def head_runs(self, kind, project_id, head):
        return self._runs(self.heads.get((kind, project_id, _norm(head)), ()))

    def stage_runs(self, scan_id, stage):
        return [Run(when, STAGE_TTL_HOURS * 3600, status == SCAN_STAGE_OK) for status, when in self.stages.get((scan_id, stage), ())]


def _chunks(items, size=CHUNK):
    items = list(items)
    for i in range(0, len(items), size):
        yield items[i:i + size]


def _tls_numbers(h, starttls=False):
    """The TCP ports of the host the TLS checks would test: the sweep's own rule (an implicit TLS port, a service that says ssl or https, and
    for the audit the STARTTLS mail and directory ports). A host with no port data is counted for 443 only when its own URL is https."""
    from cveFeed import testssl_scan
    numbers = set()
    for entry in h.addresses.values():
        for port in entry.ports:
            if port.protocol not in TCP:
                continue
            name = (port.service_name or '').lower()
            if port.number in testssl_scan.IMPLICIT_PORTS or 'ssl' in name or name.startswith('https'):
                numbers.add(port.number)
            elif starttls and port.number in testssl_scan.STARTTLS_PORTS:
                numbers.add(port.number)
    if not numbers and not any(e.ports for e in h.addresses.values()) and h.http_url.startswith('https'):
        numbers.add(443)
    return sorted(numbers)[:MAX_UNITS]


def _rdp_ports(h):
    from cveFeed import service_intel
    return sorted({(a.address, p.number) for a in h.scannable() for p in a.ports
                   if p.protocol in TCP and service_intel.is_rdp_port(p) and service_intel.rdp_without_nla(p)})[:MAX_UNITS]


def _is_web_port(port):
    from cveFeed import route_auth
    service, product = (port.service_name or '').lower(), (port.product or '').lower()
    return port.protocol in TCP and (port.number in route_auth.WEB_PORTS or service in route_auth.HTTP_SERVICE_NAMES or 'http' in product)


def _web_addresses(h):
    return [a for a in h.scannable() if any(_is_web_port(p) for p in a.ports)][:MAX_UNITS]


def _udp_asset(entry):
    """The ledger asset of an address in the UDP sweep (``cveFeed.udp_scan.asset_of``): the same address of two organizations is two assets."""
    address = (entry.address or '').strip().lower()
    return f'{address}@{entry.org_id}' if entry.org_id else address


def _credentials_for(h, ev):
    from cveFeed import auth_checks
    out = []
    for cred in ev.credentials.get(h.project_id, ()):
        if auth_checks.is_expired(cred, ev.now):
            continue
        if cred.host == h.name or (not cred.host and auth_checks.host_in_target(h.name, cred.domain)):
            out.append(cred)
    return out


def load(entries, now=None):
    """``Evidence`` for a page of hosts. ``entries`` is ``[(Subdomain, [other current rows of the host], project id)]``. A fixed number of
    queries however many hosts or checks, every one limited to the page's own projects (and the ledger to the page's own assets)."""
    from cveFeed.conductor import bounty_blocked_projects
    from cveFeed.models import AuthCredential, HostState, OpenvasSettings, RouteAuth, ServiceRun, TlsCertificate
    from django.db.models import Max, Q
    from startScan.models import ScanActivity
    ev = Evidence(now)
    pids = sorted({pid for _s, _o, pid in entries if pid is not None})
    names, assets, heads, scans = set(), set(), set(), set()
    for sub, others, pid in entries:
        h = ev.facts[sub.id] = HostFacts.from_rows(sub, others, pid)
        names.add(h.name)
        assets.add(h.name)
        heads.add(h.name)
        if h.scan_id:
            scans.add(h.scan_id)
        for entry in h.addresses.values():
            assets.update((_norm(entry.address), _norm(_udp_asset(entry))))
        for number in _tls_numbers(h, starttls=True):
            assets.add(f'{h.name}:{number}')
        for address, number in _rdp_ports(h):
            assets.add(f'{address}:{number}')
        heads.update(_norm(a.address) for a in _web_addresses(h))
    if not pids:
        return ev
    for part in _chunks(sorted(assets)):
        for service, project_id, asset, status, when in ServiceRun.objects.filter(asset__in=part).filter(
                Q(project_id__in=pids) | Q(project_id__isnull=True)).values_list('service', 'project_id', 'asset', 'status', 'finished_at'):
            ev.add_ledger(service, project_id, asset, when, status)
    # assets shaped "host|..." (probes, subdirectory applications) and "address|name" (other sites) are read by their first part, and only
    # inside the kind's window: those kinds hold a row per probe or per name asked, so older rows are not worth reading for a page
    from cveFeed import ledger
    from django.db.models import CharField, F, Func, Value
    windows = reduce(or_, (Q(service=kind, finished_at__gte=ev.now - timedelta(seconds=ledger.ttl(kind))) for kind in HEAD_KINDS))
    for part in _chunks(sorted(heads)):
        for service, project_id, asset, status, when in ServiceRun.objects.filter(project_id__in=pids).filter(windows).annotate(
                head=Func(F('asset'), Value('|'), Value(1), function='split_part', output_field=CharField())).filter(head__in=part).values_list(
                'service', 'project_id', 'asset', 'status', 'finished_at'):
            ev.heads.setdefault((service, project_id, asset.split('|', 1)[0]), []).append((service, status, when))
    for project_id, host, newest in RouteAuth.objects.filter(project_id__in=pids, host__in=names).values_list('project_id', 'host').annotate(
            newest=Max('checked_at')).values_list('project_id', 'host', 'newest'):
        ev.routes[(project_id, host)] = newest
    for project_id, host, port, when in TlsCertificate.objects.filter(domain__project_id__in=pids, host__in=names).values_list(
            'domain__project_id', 'host', 'port', 'checked_at'):
        key = (project_id, host.lower(), port)
        if key not in ev.certs or when > ev.certs[key]:
            ev.certs[key] = when
    if scans:
        for scan_id, stage, status, when in ScanActivity.objects.filter(scan_of_id__in=scans, name__in=STAGE_NAMES).values_list(
                'scan_of_id', 'name', 'status', 'time'):
            ev.stages.setdefault((scan_id, stage), []).append((status, when))
    ev.archived = {(project_id, host.lower()) for project_id, host in HostState.objects.filter(
        project_id__in=pids, host__in=names, archived_at__isnull=False).values_list('project_id', 'host')}
    ev.blocked = set(bounty_blocked_projects()) & set(pids)
    if OpenvasSettings.objects.filter(enabled=True).exists():
        from cveFeed import openvas_scan
        for link in openvas_scan.links_for(list(pids)):  # the projects opted in one by one and through their organization, as the sweep reads them
            project_id = link.project_id
            ev.openvas[project_id] = {str(x).strip().lower() for x in (link.hosts or [])}
            ev.openvas_forced[project_id] = {str(x).strip().lower() for x in (link.forced_hosts or [])}
            on_page = {h.name for h in ev.facts.values() if h.project_id == project_id}
            ev.openvas_heat.update({(project_id, name): heat for name, (heat, _n) in openvas_scan.host_heat(project_id, on_page).items()})
    for cred in AuthCredential.objects.filter(project_id__in=pids).select_related('domain').defer('secret'):
        ev.credentials.setdefault(cred.project_id, []).append(cred)
    if ev.credentials:
        _load_signed(ev, pids)
    return ev


def _load_signed(ev, pids):
    """The authenticated passes' runs for the hosts a stored sign-in covers. Their ledger assets end in ``@<credential revision>``, so they
    are read by revision: nothing is fetched when no sign-in is stored."""
    from cveFeed import auth_checks
    from cveFeed.models import ServiceRun
    from django.db.models import Q
    from urllib.parse import urlsplit
    revisions = {auth_checks.revision(c) for creds in ev.credentials.values() for c in creds}
    for part in _chunks(sorted(revisions), 100):
        query = reduce(or_, (Q(asset__endswith=f'@{rev}') for rev in part))
        for service, project_id, asset, status, when in ServiceRun.objects.filter(project_id__in=pids).filter(
                Q(service__startswith='nuclei-auth') | Q(service='route-auth-signed')).filter(query).values_list(
                'service', 'project_id', 'asset', 'status', 'finished_at'):
            url, _at, revision = asset.rpartition('@')
            host = (urlsplit(url).hostname or '').lower()
            ev.signed.setdefault((service.split(':')[0], project_id, host, revision), []).append((service, status, when))


# --------------------------------------------------------------------------------------- applicability rules and where each check ran

def _one(h, ev, kinds):
    return [Unit(h.name, ev.ledger_runs(kinds, h.project_id, h.name))]


def _no_address(h):
    if not h.addresses:
        return 'the host has no resolved address'
    return 'every address is a CDN or shared platform edge, or not one a scanner may use'


def _by_address(h, ev, kinds, project_id=True):
    scannable = h.scannable()
    if not scannable:
        return _no_address(h)
    return [Unit(a.address, ev.ledger_runs(kinds, h.project_id if project_id else None, a.address)) for a in scannable[:MAX_UNITS]]


def plan_discovery(h, ev):
    if not h.is_domain_target:
        return 'discovery runs on the target, not on each host found under it'
    return _one(h, ev, ('bbot',))


def plan_deep_discovery(h, ev):
    from targetApp.shared_domains import effective_apex
    if not h.is_domain_target:
        return 'the deep discovery runs on the target\'s apex domain, not on each host under it'
    apex, host_scoped = effective_apex(h.name)
    if host_scoped or apex != h.name:
        return 'the weekly deep discovery covers only an owned apex domain'
    if h.project_id in ev.blocked:
        return BOUNTY_REASON
    return _one(h, ev, ('bbot-deep',))


def plan_ct_watch(h, ev):
    from targetApp.shared_domains import is_provider_domain
    if not h.is_domain_target:
        return 'the certificate transparency watch runs on the target, not on each host under it'
    if is_provider_domain(h.name):
        return 'a shared provider domain is never enumerated'
    if h.project_id in ev.blocked:
        return BOUNTY_REASON
    return _one(h, ev, ('ct-watch', 'ct-watch-failed'))


def plan_archive(h, ev):
    from cveFeed import archive_urls
    if not h.is_domain_target:
        return 'the web archive is asked once for the target, not for each host under it'
    if not archive_urls.lookup_enabled():
        return 'the web archive lookup is switched off (CVENGINE_ARCHIVE_LOOKUP=0)'
    return _one(h, ev, ('archive-urls',))


def plan_mail(h, ev):
    if not h.is_domain_target:
        return 'email authentication is checked for the target\'s own domain'
    return _one(h, ev, ('hygiene',))


def plan_nmap(h, ev):
    return _by_address(h, ev, ('nmap-fast',))


def plan_naabu(h, ev):
    from cveFeed import naabu_scan
    if not naabu_scan.enabled():
        return 'naabu is switched off (CVENGINE_NAABU=0)'
    return _by_address(h, ev, ('naabu',))


def plan_full_ports(h, ev):
    from cveFeed import fullscan, ledger
    if not fullscan.enabled():
        return 'the background all-ports sweep is switched off (CVENGINE_FULLSCAN=0)'
    if h.project_id in ev.blocked:
        return BOUNTY_REASON
    scannable = h.scannable()
    if not scannable:
        return _no_address(h)
    ttl = ledger.ttl('nmap-full')
    return [Unit(a.address, [Run(a.full_scanned_at, ttl, True)] if a.full_scanned_at else []) for a in scannable[:MAX_UNITS]]


def plan_udp(h, ev):
    from cveFeed import udp_scan
    if not udp_scan.enabled():
        return 'the UDP sweep is switched off (CVENGINE_UDPSCAN=0)'
    if h.project_id in ev.blocked:
        return BOUNTY_REASON
    scannable = h.scannable()
    if not scannable:
        return _no_address(h)
    return [Unit(a.address, ev.ledger_runs(('udp-scan', 'udp-scan-failed'), None, _udp_asset(a))) for a in scannable[:MAX_UNITS]]


def plan_rdp(h, ev):
    from cveFeed import rdp_shot
    if not rdp_shot.enabled():
        return 'RDP screenshots are switched off (CVENGINE_RDP_SHOT=0)'
    ports = _rdp_ports(h)
    if not ports:
        return 'no RDP service that accepts a connection without Network Level Authentication'
    return [Unit(f'{address}:{number}', ev.ledger_runs(('rdp-shot',), h.project_id, f'{address}:{number}')) for address, number in ports]


def plan_db_exposure(h, ev):
    from cveFeed import db_exposure
    if not any(p.protocol in TCP and db_exposure.checker_for(p)[1] for a in h.scannable() for p in a.ports):
        return 'no open Redis, Memcached, PostgreSQL, MySQL, MongoDB, Elasticsearch or CouchDB port'
    return [Unit(h.name, ev.stage_runs(h.scan_id, 'db_exposure_scan'))]


def _targetable(h):
    return None if not h.pointing_inside() else 'the name points at an address a scanner must not be used on'


def plan_nuclei_tech(h, ev):
    return _targetable(h) or _one(h, ev, ('nuclei-light',))


def plan_nuclei(h, ev):
    return _targetable(h) or _one(h, ev, ('nuclei',))


def plan_nuclei_deep(h, ev):
    if h.project_id in ev.blocked:
        return BOUNTY_REASON
    return _targetable(h) or _one(h, ev, ('nuclei-deep-host', 'nuclei-deep-target'))


def plan_nuclei_cve(h, ev):
    from cveFeed.nuclei_templates import MAX_CVES_PER_HOST
    if not h.hot_cves:
        return 'no fire or smoke CVE match to test'
    reason = _targetable(h)
    if reason:
        return reason
    entries = ev.ledger.get(('nuclei-cve', h.project_id, h.name), ())
    units = []
    for cve in h.hot_cves[:MAX_CVES_PER_HOST]:
        prefix = f'nuclei-cve:{cve}:'.lower()
        units.append(Unit(cve, ev._runs([e for e in entries if e[0].lower().startswith(prefix)])))
    return units


def plan_waf(h, ev):
    from cveFeed import waf_scan
    if not waf_scan.enabled():
        return 'the WAF fingerprint is switched off (CVENGINE_WAFW00F=0)'
    if not h.http_up:
        return 'the host did not answer over HTTP'
    return _targetable(h) or _one(h, ev, ('wafw00f',))


def plan_routes(h, ev):
    from cveFeed import ledger
    if not h.web:
        return 'no web service'
    reason = _targetable(h)
    if reason:
        return reason
    when = ev.routes.get((h.project_id, h.name))
    return [Unit(h.name, [Run(when, ledger.ttl('route-auth'), True)] if when else [])]


def plan_probes(h, ev):
    if not h.unversioned:
        return 'no product seen without a version'
    reason = _targetable(h)
    if reason:
        return reason
    return [Unit(h.name, ev.head_runs('probe', h.project_id, h.name), bounded=True)]


def plan_wp_probe(h, ev):
    if not h.web:
        return 'no web service'
    return _targetable(h) or _one(h, ev, ('wp-probe',))


def _wordpress(h):
    from cveFeed import wpscan_scan
    return wpscan_scan.state_of(h.probe_rows) if h.probe_rows else None


def plan_wpscan(h, ev):
    state = _wordpress(h)
    if state is None:
        return 'no sign of WordPress'
    if state['state'] == 'not_wordpress':
        return 'the WordPress probe found no WordPress'
    return _one(h, ev, ('wpscan', 'wpscan-partial'))


def plan_wpscan_thorough(h, ev):
    if h.project_id in ev.blocked:
        return BOUNTY_REASON
    state = _wordpress(h)
    if state is None or state['state'] == 'not_wordpress':
        return 'no sign of WordPress'
    if state['state'] != 'scanned':
        return 'it follows the quick WPScan pass, which has not scanned this site yet'
    return _one(h, ev, ('wpscan-thorough', 'wpscan-thorough-partial'))


def plan_node2shell(h, ev):
    from cveFeed import node2shell_scan
    if not node2shell_scan.enabled():
        return 'the node2shell check is switched off (opt in with CVENGINE_NODE2SHELL=1)'
    if node2shell_scan.scope() == 'all':
        named = h.http_up
    else:
        names = [str(n) for n in ((h.root.evidence or {}).get('fingerprint_names') or [])] if h.root else []
        named = any(node2shell_scan.NODE_NAME_RE.match(t) for t in [*h.techs, *names])
    if not named:
        return 'the host does not show Node.js, Bun or Envoy'
    return _targetable(h) or _one(h, ev, ('node2shell',))


def plan_vhost(h, ev):
    from cveFeed import vhost_scan
    if not vhost_scan.enabled():
        return 'the virtual host sweep is switched off (CVENGINE_VHOST=0)'
    if h.project_id in ev.blocked:
        return BOUNTY_REASON
    addresses = _web_addresses(h)
    if not addresses:
        return 'no address of the host serves web'
    return [Unit(a.address, ev.ledger_runs(('vhost-ip',), h.project_id, a.address) + ev.head_runs('vhost', h.project_id, a.address), bounded=True)
            for a in addresses]


def plan_subapps(h, ev):
    from cveFeed import subdir_apps
    if not subdir_apps.enabled():
        return 'the subdirectory application sweep is switched off (CVENGINE_SUBDIR_APPS=0)'
    if h.project_id in ev.blocked:
        return BOUNTY_REASON
    if not h.web:
        return 'no web service'
    return _targetable(h) or [Unit(h.name, ev.head_runs('subapp', h.project_id, h.name), bounded=True)]


def plan_testssl(h, ev):
    if h.project_id in ev.blocked:
        return BOUNTY_REASON
    ports = _tls_numbers(h, starttls=True)
    if not ports:
        return 'no TLS service'
    return _targetable(h) or [Unit(f'{h.name}:{n}', ev.ledger_runs(('testssl', 'testssl-failed'), h.project_id, f'{h.name}:{n}')) for n in ports]


def plan_certificates(h, ev):
    from cveFeed import ledger
    ports = _tls_numbers(h)
    if not ports:
        return 'no TLS service'
    reason = _targetable(h)
    if reason:
        return reason
    ttl = ledger.ttl('hygiene')
    units = []
    for number in ports:
        when = ev.certs.get((h.project_id, h.name, number))
        units.append(Unit(f'{h.name}:{number}', [Run(when, ttl, True)] if when else []))
    return units


def plan_openvas(h, ev):
    """OpenVAS is slow (hours per host), so it is spent only on hosts on fire or smoke, unless someone forced the host, and never on a CDN or a
    platform other customers share (``openvas_scan.assess`` decides the same way, and says why a host that is ready is not chosen yet)."""
    if ev.openvas.get(h.project_id) is None:
        return 'the OpenVAS add-on is off, or this project did not opt in'
    if h.project_id in ev.blocked:
        return BOUNTY_REASON
    heat = ev.openvas_heat.get((h.project_id, h.name))
    if heat not in ('fire', 'smoke') and h.name not in ev.openvas_forced.get(h.project_id, ()):
        return f'not Fire or Smoke ({heat or "unknown"}): OpenVAS is only spent on hosts on fire or smoke'
    if h.shared_platform or (h.addresses and all(a.is_cdn for a in h.addresses.values())):
        return 'a CDN or a platform shared with other customers: not the project\'s to test'
    return _one(h, ev, ('openvas', 'openvas-failed'))


def _signed_units(h, ev, kind, withheld=None, why_withheld=''):
    """``withheld(cred, h, ev)``: a sign-in that is known not to be sent is no unit of the check (it is neither planned nor covered); when none
    is left the answer is ``why_withheld``."""
    creds = _credentials_for(h, ev)
    if not creds:
        return 'no stored sign-in covers the host'
    from cveFeed import auth_checks, ledger
    ttl = ledger.ttl(kind)
    units = []
    for cred in creds:
        if withheld and withheld(cred, h, ev):
            continue
        entries = ev.signed.get((kind, h.project_id, h.name, auth_checks.revision(cred)), ())
        units.append(Unit(cred.label, [Run(when, ttl, status == 'done') for _service, status, when in entries]))
    return units or why_withheld


def _withheld(cred, h, ev):
    """Whether Nuclei will withhold this sign-in: HTTPS requires an explicit unverified-TLS opt-in.

    For a credential with mixed HTTP and HTTPS origins, use the last recorded refusal, since an explicitly selected HTTP origin
    may still be runnable. A later successful signed-in run overrides an older refusal.
    """
    from cveFeed import auth_checks
    if cred.allow_untrusted_certificate:
        return False
    if cred.origins and all(str(origin).startswith('https:') for origin in cred.origins):
        return True
    key = (h.project_id, h.name, auth_checks.revision(cred))
    refused = [when for _service, _status, when in ev.signed.get(('nuclei-auth-refused', *key), ()) if when]
    if not refused:
        return False
    sent = [when for _service, _status, when in ev.signed.get(('nuclei-auth', *key), ()) if when]
    return not sent or max(refused) > max(sent)


def plan_auth_nuclei(h, ev):
    return _signed_units(h, ev, 'nuclei-auth', withheld=_withheld,
                         why_withheld='the stored sign-in is not sent: Nuclei cannot verify TLS on its request and "Trust this certificate anyway" is off')


def plan_auth_routes(h, ev):
    return _signed_units(h, ev, 'route-auth-signed')


def plan_correlation(h, ev):
    if not h.techs and not any(a.ports for a in h.addresses.values()):
        return 'no technology or open port to match'
    return [Unit(h.name, ev.stage_runs(h.scan_id, 'cve_correlation'))]


# --------------------------------------------------------------------------------------- hosts inside a declared internal network
#
# A host whose name is an address inside a network its project declared internal is scanned only by ``cveFeed.internal_scan``, through a
# Sentinel inside the network. Most checks run from this server and have no route there, so they do not apply; the ones the internal scan
# runs are judged from what it recorded (the same ledger kinds and scan stages as for any host).

INTERNAL_REASON = ('the internal scan does not run this check: it runs from this server, which has no route into an internal network, '
                   'and it has no Sentinel path yet')


def _internal_address(h):
    return h.addresses.get(h.name) or Addr(h.name)


def plan_internal_nmap(h, ev):
    return [Unit(h.name, ev.ledger_runs(('nmap-fast',), h.project_id, h.name))]


def plan_internal_udp(h, ev):
    return [Unit(h.name, ev.ledger_runs(('udp-scan', 'udp-scan-failed'), None, _udp_asset(_internal_address(h))))]


def plan_internal_nuclei_tech(h, ev):
    return _one(h, ev, ('nuclei-light',))


def plan_internal_nuclei(h, ev):
    return _one(h, ev, ('nuclei',))


def plan_internal_testssl(h, ev):
    ports = _tls_numbers(h, starttls=True)
    if not ports:
        return 'no TLS service'
    return [Unit(f'{h.name}:{n}', ev.ledger_runs(('testssl', 'testssl-failed'), h.project_id, f'{h.name}:{n}')) for n in ports]


def plan_internal_wpscan(h, ev):
    state = _wordpress(h)
    if state is None and not any(t.lower().startswith('wordpress') for t in h.techs):
        return 'no sign of WordPress'
    if state is not None and state['state'] == 'not_wordpress':
        return 'WPScan found no WordPress'
    return _one(h, ev, ('wpscan', 'wpscan-partial'))


# check id -> the rule for an internal host; every other check does not apply to one (``INTERNAL_REASON``)
INTERNAL_PLANS = {
    'nmap': plan_internal_nmap,
    'udp': plan_internal_udp,
    'nuclei-tech': plan_internal_nuclei_tech,
    'nuclei': plan_internal_nuclei,
    'tls-audit': plan_internal_testssl,
    'wpscan': plan_internal_wpscan,
    'cve-correlation': plan_correlation,
    'openvas': plan_openvas,
}


CHECKS = (
    Check('discovery', 'Subdomain discovery (bbot)', plan_discovery, kinds=('bbot',), stages=('bbot_discovery',)),
    Check('deep-discovery', 'Weekly deep discovery', plan_deep_discovery, kinds=('bbot-deep',), sweeps=('deep-apex',)),
    Check('ct-watch', 'Certificate transparency watch', plan_ct_watch, kinds=('ct-watch', 'ct-watch-failed'), sweeps=('ct-watch',)),
    Check('archive-urls', 'Web archive history', plan_archive, kinds=('archive-urls',)),
    Check('email-auth', 'Email authentication (SPF, DKIM, DMARC, CAA)', plan_mail, kinds=('hygiene',), sweeps=('hygiene',)),
    Check('nmap', 'Service fingerprint (nmap)', plan_nmap, kinds=('nmap-fast',), stages=('nmap_scan',)),
    Check('naabu', 'Port discovery (naabu)', plan_naabu, kinds=('naabu',)),
    Check('full-ports', 'All 65,535 TCP ports (background sweep)', plan_full_ports, kinds=('nmap-full',)),
    Check('udp', 'UDP exposure sweep', plan_udp, kinds=('udp-scan', 'udp-scan-failed'), sweeps=('udp-kick',)),
    Check('rdp-screenshot', 'RDP login screen capture', plan_rdp, kinds=('rdp-shot',), stages=('rdp_screenshot',)),
    Check('db-exposure', 'Unauthenticated database check', plan_db_exposure, stages=('db_exposure_scan',)),
    Check('nuclei-tech', 'Nuclei technology pass', plan_nuclei_tech, kinds=('nuclei-light',), stages=('nuclei_light_scan',)),
    Check('nuclei', 'Nuclei template scan', plan_nuclei, kinds=('nuclei',), stages=('nuclei_targeted_scan',)),
    Check('nuclei-deep', 'Weekly deep Nuclei', plan_nuclei_deep, kinds=('nuclei-deep-host', 'nuclei-deep-target')),
    Check('nuclei-cve', 'CVE template tests', plan_nuclei_cve, kinds=('nuclei-cve',)),
    Check('waf', 'WAF fingerprint (wafw00f)', plan_waf, kinds=('wafw00f',), stages=('wafw00f',)),
    Check('web-routes', 'Web route auth check', plan_routes, kinds=('route-auth',), stages=('route_auth_scan',)),
    Check('version-probes', 'Version and identity probes', plan_probes, kinds=('probe',), stages=('version_probes',)),
    Check('wp-detect', 'WordPress detection probe', plan_wp_probe, kinds=('wp-probe',)),
    Check('wpscan', 'WPScan (quick pass)', plan_wpscan, kinds=('wpscan', 'wpscan-partial'), stages=('wpscan',)),
    Check('wpscan-thorough', 'WPScan (thorough pass)', plan_wpscan_thorough, kinds=('wpscan-thorough', 'wpscan-thorough-partial')),
    Check('node2shell', 'node2shell check (CVE-2026-111497)', plan_node2shell, kinds=('node2shell',), stages=('node2shell',)),
    Check('vhost', 'Other sites on the host\'s addresses', plan_vhost, kinds=('vhost', 'vhost-ip'), sweeps=('vhost',), ttl_kind='vhost'),
    Check('subapps', 'Applications under subdirectories', plan_subapps, kinds=('subapp',), sweeps=('subapp',)),
    Check('tls-audit', 'TLS configuration audit (testssl.sh)', plan_testssl, kinds=('testssl', 'testssl-failed'), sweeps=('testssl',),
          ttl_kind='testssl'),
    Check('certificates', 'Certificate and legacy TLS check', plan_certificates, stages=('host_hygiene',), ttl_kind='hygiene'),
    Check('openvas', 'OpenVAS scan (optional add-on)', plan_openvas, kinds=('openvas', 'openvas-failed'), ttl_kind='openvas'),
    Check('nuclei-signed-in', 'Nuclei, signed in', plan_auth_nuclei, kinds=('nuclei-auth', 'nuclei-auth-refused')),
    Check('routes-signed-in', 'Web routes, signed in', plan_auth_routes, kinds=('route-auth-signed',)),
    Check('cve-correlation', 'CVE correlation', plan_correlation, stages=('cve_correlation',)),
)

# What exists in the code and is deliberately not a per-host check, with the reason. tests/test_check_coverage.py makes the choice explicit:
# a ledger kind, sweep or scan stage that is in neither CHECKS nor here fails the build.
EXCLUDED = {
    'kinds': {
        'retest': 'a re-test of a changed host runs the checks above again; it is not a check of its own',
        'validate': 'validation of a CVE match is recorded on the match, not on the host',
        'buckets': 'cloud storage candidates belong to the project (found in page content and DNS), not to one host',
        'buckets-failed': 'the retry window of the cloud storage sweep',
        'supplier': 'a third-party supplier host card; suppliers are not owned hosts and are deliberately kept out of this registry',
        'supplier-failed': 'the retry window of the supplier sweep',
    },
    'sweeps': {
        'buckets': 'cloud storage candidates belong to the project, not to one host',
        'conductor': 'the scheduler that keeps discovery queued; it does no check',
        'distro-sync': 'a feed sync, not a check of a host',
        'triage': 'AI review of findings, not a check of a host',
        'validate': 'validation of CVE matches, recorded on the match',
        'rescore': 'recomputes host scores from stored data',
        'udp-unavailable-note': 'a once-a-day rate limit for a note in the activity feed',
        'suppliers': 'third-party supplier host cards; suppliers are not owned hosts and are deliberately kept out of this registry',
    },
    'stages': {
        'triage': 'AI review of what the scan produced, not a check of a host',
        'asset_changes': 'the change log of the scan, bookkeeping only',
        'internal_testssl': 'the TLS audit step of the internal scan driver (cveFeed.internal_scan), run by a Sentinel inside the network; it records the testssl ledger kind, which the tls-audit check judges for an internal host',
        'internal_wpscan': 'the WPScan step of the internal scan driver (cveFeed.internal_scan), run by a Sentinel inside the network; it records the wpscan ledger kind, which the wpscan check judges for an internal host',
        'internal_udp_scan': 'the UDP sweep step of the internal scan driver (cveFeed.internal_scan), run by a Sentinel inside the network; it records the udp-scan ledger kind, which the udp check judges for an internal host',
    },
}

STAGE_NAMES = tuple(sorted({s for c in CHECKS for s in c.stages}))
BY_ID = {c.id: c for c in CHECKS}


def covered(section):
    """The names the registry covers: ``kinds``, ``sweeps`` or ``stages``."""
    return {name for check in CHECKS for name in getattr(check, section)}


# --------------------------------------------------------------------------------------- the answer

def _age(delta):
    seconds = max(0, int(delta.total_seconds()))
    return f'{round(seconds / 86400)} days' if seconds >= 2 * 86400 else (f'{round(seconds / 3600)}h' if seconds >= 3600 else 'under an hour')


def _ttl_label(hours):
    return f'{round(hours / 24)} days' if hours >= 48 else f'{round(hours)}h'


def _judge(check, units, now):
    """``(state, last_run, detail)`` for a check that applies, from its units."""
    fresh = [u for u in units if u.fresh(now)]
    last = max((u.last() for u in units if u.last()), default=None)
    if len(fresh) == len(units):
        detail = f'{len(units)} of {len(units)} covered' if len(units) > 1 else ''
        return 'done', last, detail
    if not any(u.last() for u in units):
        return 'due', None, 'no run inside its window' if any(u.bounded for u in units) else 'never run'
    if fresh:
        return 'due', last, f'{len(fresh)} of {len(units)} covered'
    if all(u.failed_last() or not u.last() for u in units):
        return 'due', last, 'the last attempt failed'
    return 'due', last, f'last run {_age(now - last)} ago, repeats every {_ttl_label(check.ttl_hours())}'


def _sentinel_online(h, ev):
    """Whether a live Sentinel inside the host's internal network could take its work now (one read per project of the page): a check that
    never ran for want of one is not "never run" for any other reason."""
    state = ev.sentinels.get(h.project_id)
    if state is None:
        from cveFeed import internal_view
        from dashboard.models import Project
        project = Project.objects.select_related('org').filter(pk=h.project_id).first()
        state = ev.sentinels[h.project_id] = bool(project) and internal_view._sentinel_state(project)['state'] == 'online'
    return state


def coverage(h, ev, rich=False, paused=''):
    """``{'done', 'applicable', 'paused', 'checks': [...]}`` for one host. ``paused`` (``excluded`` or ``archived``) makes every check not
    apply: an excluded host is never scanned and an archived one has left scan scheduling."""
    paused = paused or ('excluded' if h.excluded else '') or ('archived' if (h.project_id, h.name) in ev.archived else '')
    rows, done, applicable = [], 0, 0
    for check in CHECKS:
        entry = {'id': check.id, 'label': check.label, 'state': 'not_applicable', 'last_run': None, 'ttl_hours': check.ttl_hours(), 'detail': ''}
        if paused:
            plan = f'the host is {paused}'
        elif h.internal:
            rule = INTERNAL_PLANS.get(check.id)
            plan = rule(h, ev) if rule else INTERNAL_REASON
        else:
            plan = check.plan(h, ev)
        if isinstance(plan, str):
            entry['detail'] = plan
        else:
            state, last, detail = _judge(check, plan, ev.now)
            if h.internal and state == 'due' and not last and not _sentinel_online(h, ev):
                detail = f'{detail}; no Sentinel inside the network is online' if detail else 'no Sentinel inside the network is online'
            entry.update(state=state, last_run=last.isoformat() if last else None, detail=detail)
            applicable += 1
            done += state == 'done'
            if rich:
                entry['units'] = [{'unit': u.label, 'state': 'done' if u.fresh(ev.now) else 'due',
                                   'last_run': u.last().isoformat() if u.last() else None} for u in plan]
        rows.append(entry)
    return {'done': done, 'applicable': applicable, 'paused': paused, 'internal': h.internal or None, 'checks': rows}


def for_host(ev, sub, others, project_id, *, excluded=False, shared_platform=False, hot_cves=(), unversioned=0, probe_rows=(), root=None, rich=False):
    """The coverage of one host of a loaded page: the facts built while loading, completed with what the host record already computed."""
    h = ev.facts.get(sub.id)
    if h is None:
        h = ev.facts[sub.id] = HostFacts.from_rows(sub, others, project_id)
    h.excluded, h.shared_platform, h._scannable, h._inside = bool(excluded), bool(shared_platform), None, None
    h.hot_cves, h.unversioned, h.probe_rows, h.root = list(hot_cves), int(unversioned or 0), list(probe_rows), root
    return coverage(h, ev, rich=rich)
