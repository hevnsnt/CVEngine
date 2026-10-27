"""The one definition of every number CVEngine prints.

The dashboard's status line, the section pages' filter chips, the Targets table, the attack-surface map and the agent API
all count the same things, and they used to count them with their own queries: the status line counted host rows (874),
the Hosts page counted distinct hosts (659) and the map drew only live hosts (163). Each is right for what it counted, and
none said what that was. Everything that prints a count now reads it from here, so a count cannot drift from the list it
links to. ``tests/test_counts.py`` pins every surface against every other.

Definitions (also shown to the user as the tooltip of each dashboard tile):

* **Hosts**: distinct hosts in a project's current inventory (``latest_scan_q``). The same name in two targets of one project is one
  host, and so are names that resolve to exactly the same addresses (``example.com`` and ``www.example.com`` on the same servers are one
  host with two names; names behind a CDN stay separate). The same name in two projects is two hosts. This is the Hosts page's count.
* **Live hosts**: hosts that resolved to an IP address or answered over HTTP. These are the tiles of the attack-surface map.
* **Exposed hosts**: hosts with a CVE match the AI has not ruled out, or an open finding of medium severity or worse.
* **CVE matches**: matches the AI has not ruled out. The Matches page opens on the same view.
* **Scanner findings**: open findings of low severity or worse (informational detections and closed findings excluded). The
  Findings page, Scanner type, Actionable status, shows the same set.
* **Scans running**: scans marked running that started within ``RUNNING_WINDOW``. An older one is stalled (a casualty of a
  restart) and is never shown as running anywhere.
* **Certs expiring**: certificates that expire within 30 days, including those already expired.
* **Oldest open**: the age in whole days of the longest-open critical or high item among the exposed CVE matches, actionable scanner
  findings and open hygiene findings (``oldest_open``).
"""
from datetime import timedelta

from django.db.models import Q
from django.utils import timezone

# discovery (6h cap) + nuclei (4h cap) + slack; see discovery.py
RUNNING_WINDOW = timedelta(hours=11)
CERT_WARNING_DAYS = 30
RULED_OUT = 'not_affected'  # the AI verdict that takes a CVE match off every list of exposure
CLOSED = ('fixed', 'accepted_risk')  # remediation states that do the same: someone dealt with the finding or decided to live with it


def match_is_live(match):
    """A CVE match that still counts toward a host's heat, score and exposure: not ruled out by the AI, not fixed, not an accepted risk."""
    return match.ai_verdict != RULED_OUT and match.remediation_status not in CLOSED


def finding_is_live(finding):
    """A scanner finding that still counts: open, and not fixed or an accepted risk."""
    return bool(finding.open_status) and finding.remediation_status not in CLOSED

# a host that resolved to an address, or that something saw answer over HTTP
LIVE_HOST_Q = Q(ip_addresses__isnull=False) | Q(http_status__gt=0)


def running_scans(qs=None):
    from startScan.models import ScanHistory
    qs = ScanHistory.objects.all() if qs is None else qs
    return qs.filter(scan_status=1, start_scan_date__gte=timezone.now() - RUNNING_WINDOW)


def stalled_scans(qs=None):
    from startScan.models import ScanHistory
    qs = ScanHistory.objects.all() if qs is None else qs
    return qs.filter(scan_status=1, start_scan_date__lt=timezone.now() - RUNNING_WINDOW)


def queued_scans(qs=None):
    from startScan.models import ScanHistory
    return (ScanHistory.objects.all() if qs is None else qs).filter(scan_status=-1)


def with_host_key(qs):
    """Annotate Subdomain rows with ``host_key``: the identity of the machine behind the name, so names that point at the same
    addresses are one host. The key is the project plus the sorted set of the row's IP addresses; a row with no address, or with an
    address of a CDN or shared edge (many unrelated sites share those), keeps its own name as its key. The same name (several
    scans of it) therefore shares a key, and so do ``example.com`` and ``www.example.com`` when both resolve to the same addresses."""
    from django.contrib.postgres.aggregates import StringAgg
    from django.db.models import Case, CharField, Exists, OuterRef, Subquery, TextField, Value, When
    from django.db.models.functions import Cast, Concat
    from startScan.models import IpAddress, Subdomain
    through = Subdomain.ip_addresses.through
    ipset = through.objects.filter(subdomain_id=OuterRef('pk')).order_by().values('subdomain_id').annotate(
        s=StringAgg(Cast('ipaddress_id', TextField()), delimiter=',', ordering='ipaddress_id')).values('s')
    behind_cdn = Exists(through.objects.filter(subdomain_id=OuterRef('pk'), ipaddress__in=IpAddress.objects.filter(is_cdn=True)))
    project = Cast('target_domain__project_id', CharField())
    return qs.annotate(_ipset=Subquery(ipset, output_field=TextField()), _cdn=behind_cdn).annotate(
        host_key=Case(When(_cdn=True, then=Concat(project, Value(':n:'), 'name', output_field=CharField())),
                      When(_ipset__isnull=True, then=Concat(project, Value(':n:'), 'name', output_field=CharField())),
                      default=Concat(project, Value(':i:'), '_ipset', output_field=CharField()), output_field=CharField()))


def host_siblings(sub_ids):
    """``{id: [(id, name), ...]}``: for each given row, the other current-inventory rows of the same host: other copies of its name
    (a second target, a second scan), and every name that points at the same addresses together with their copies. A few queries
    however many rows are asked about."""
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    sub_ids = list(sub_ids)
    if not sub_ids:
        return {}
    current = Subdomain.objects.filter(latest_scan_q())
    keyed = list(with_host_key(Subdomain.objects.filter(id__in=sub_ids)).values('id', 'name', 'target_domain__project_id', 'host_key'))
    names_by_key = {}
    for r in with_host_key(current).filter(host_key__in={k['host_key'] for k in keyed}).values('host_key', 'name'):
        names_by_key.setdefault(r['host_key'], set()).add(r['name'])
    wanted = {n for names in names_by_key.values() for n in names} | {k['name'] for k in keyed}
    rows = {}
    for r in current.filter(name__in=wanted).exclude(id__in=sub_ids).values('id', 'name', 'target_domain__project_id'):
        rows.setdefault((r['target_domain__project_id'], r['name']), []).append((r['id'], r['name']))
    out = {}
    for k in keyed:
        names = names_by_key.get(k['host_key'], set()) | {k['name']}
        out[k['id']] = sorted((row for n in names for row in rows.get((k['target_domain__project_id'], n), [])), key=lambda row: (row[1], row[0]))
    return out


def exposed_among(reps):
    """The hosts of ``reps`` (one row each, see ``host_reps``) that are exposed. A host is exposed when any of its names is, so a
    finding on ``www`` exposes the host whose row is ``example.com``."""
    from django.db.models import Exists, OuterRef
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    exposed = Subdomain.objects.filter(latest_scan_q()).filter(exposure_filter())
    same_name = Exists(exposed.filter(name=OuterRef('name'), target_domain__project_id=OuterRef('target_domain__project_id')))
    return with_host_key(reps).filter(Q(host_key__in=with_host_key(exposed).values('host_key')) | Q(same_name))


def host_reps(domain_id=None, domain_ids=None):
    """One row per host (project and name) of the current inventory: the row the Hosts page shows for it. ``domain_id`` (one
    target) or ``domain_ids`` (several) narrow it to those targets' hosts."""
    from agentapi.services import _one_per_host
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    base = Subdomain.objects.filter(latest_scan_q())
    if domain_id:
        base = base.filter(target_domain_id=domain_id)
    if domain_ids is not None:
        base = base.filter(target_domain_id__in=list(domain_ids))
    return _one_per_host(base, per_project=True)


def live_hosts(domain_id=None):
    """The hosts the attack-surface map draws, one row each."""
    from startScan.models import Subdomain
    return Subdomain.objects.filter(pk__in=host_reps(domain_id).filter(LIVE_HOST_Q).values('pk'))


def exposure_filter(prefix=''):
    """A Q over hosts (``prefix`` reaches the host from another model) that holds when the host is exposed."""
    from cveFeed.models import CVEMatch
    from startScan.models import Vulnerability
    matches = CVEMatch.objects.exclude(ai_verdict=RULED_OUT).exclude(remediation_status__in=CLOSED).exclude(subdomain=None).values('subdomain')
    findings = Vulnerability.objects.filter(open_status=True, severity__gte=2).exclude(remediation_status__in=CLOSED).exclude(subdomain=None).values('subdomain')
    return Q(**{prefix + 'pk__in': matches}) | Q(**{prefix + 'pk__in': findings})


def exposed_host_count():
    return exposed_among(host_reps()).count()  # a machine once, however many names point at it


def exposed_matches():
    from cveFeed.correlation import latest_scan_q
    from cveFeed.models import CVEMatch
    return CVEMatch.objects.exclude(ai_verdict=RULED_OUT).exclude(remediation_status__in=CLOSED).filter(latest_scan_q('subdomain__'))


def actionable_findings(qs):
    """Open scanner findings of low severity or worse. This is the Findings page's Actionable filter for scanner findings:
    informational detections and closed findings (fixed or an accepted risk too) are the rest (``status=all``)."""
    return qs.filter(open_status=True, severity__gte=1).exclude(remediation_status__in=CLOSED)


def oldest_open(now=None):
    """How long the worst open thing has sat: ``{'days', 'kind', 'id'}`` for the oldest open, actionable item of critical or high severity
    across the three sources, or ``{'days': None, 'kind': None, 'id': None}`` when none qualifies. Each source keeps its own definition
    of actionable so the number agrees with the page it links to:

    * ``cve``: an exposed match (``exposed_matches``: not ruled out by the AI, not fixed or accepted) whose CVE scores 7.0 or more, the
      Findings page's high and critical bands. A match is stored once per scan, so it has been open since the first scan that held
      the same CVE on the same host name of the same target.
    * ``scanner``: an actionable finding (``actionable_findings``) of severity high (3) or critical (4), open since the earliest
      discovery of the same finding on the same host.
    * ``hygiene``: an open hygiene finding of severity high or critical that is not fixed or an accepted risk, open since its first_seen.

    Whole days, rounded down. ``id`` is the id of the row to link to: the current row of that finding."""
    from django.db.models import OuterRef, Subquery

    from cveFeed.models import CVEMatch, HygieneFinding
    from cveFeed.threat import HIGH_CVSS
    from startScan.models import Vulnerability
    now = now or timezone.now()
    best = {'at': None, 'kind': None, 'id': None}

    def consider(kind, at, row_id):
        if at is not None and (best['at'] is None or at < best['at']):
            best.update(at=at, kind=kind, id=row_id)

    first_match = Subquery(CVEMatch.objects.filter(
        cve_entry=OuterRef('cve_entry'), subdomain__target_domain=OuterRef('subdomain__target_domain'),
        subdomain__name=OuterRef('subdomain__name')).order_by('created_at').values('created_at')[:1])
    row = (exposed_matches().filter(cve_entry__cvss__gte=HIGH_CVSS).annotate(first=first_match).order_by('first').values('id', 'first').first())
    if row:
        consider('cve', row['first'], row['id'])
    first_finding = Subquery(Vulnerability.objects.filter(
        name=OuterRef('name'), subdomain__target_domain=OuterRef('subdomain__target_domain'), subdomain__name=OuterRef('subdomain__name'),
        discovered_date__isnull=False).order_by('discovered_date').values('discovered_date')[:1])
    row = (actionable_findings(Vulnerability.objects.filter(severity__gte=3, subdomain__isnull=False)).annotate(first=first_finding)
           .filter(first__isnull=False).order_by('first').values('id', 'first').first())
    if row:
        consider('scanner', row['first'], row['id'])
    row = (HygieneFinding.objects.filter(status='open', severity__gte=3).exclude(remediation_status__in=CLOSED).order_by('first_seen')
           .values('id', 'first_seen').first())
    if row:
        consider('hygiene', row['first_seen'], row['id'])
    if best['at'] is None:
        return {'days': None, 'kind': None, 'id': None}
    return {'days': max(0, (now - best['at']).days), 'kind': best['kind'], 'id': best['id']}


def expiring_certificates(qs, days=CERT_WARNING_DAYS):
    return qs.filter(not_after__lte=timezone.now() + timedelta(days=days))
