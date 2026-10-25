"""The one definition of every number CVEngine prints.

The dashboard's status line, the section pages' filter chips, the Targets table, the attack-surface map and the agent API
all count the same things, and they used to count them with their own queries: the status line counted host rows (874),
the Hosts page counted distinct hosts (659) and the map drew only live hosts (163). Each is right for what it counted, and
none said what that was. Everything that prints a count now reads it from here, so a count cannot drift from the list it
links to. ``tests/test_counts.py`` pins every surface against every other.

Definitions (also shown to the user as the tooltip of each dashboard tile):

* **Hosts**: distinct host names in a project's current inventory (``latest_scan_q``). The same name in two targets of one
  project is one host; the same name in two projects is two hosts. This is the Hosts page's count.
* **Live hosts**: hosts that resolved to an IP address or answered over HTTP. These are the tiles of the attack-surface map.
* **Exposed hosts**: hosts with a CVE match the AI has not ruled out, or an open finding of medium severity or worse.
* **CVE matches**: matches the AI has not ruled out. The Matches page opens on the same view.
* **Scanner findings**: open findings of low severity or worse (informational detections and closed findings excluded). The
  Findings page, Scanner type, Actionable status, shows the same set.
* **Scans running**: scans marked running that started within ``RUNNING_WINDOW``. An older one is stalled (a casualty of a
  restart) and is never shown as running anywhere.
* **Certs expiring**: certificates that expire within 30 days, including those already expired.
"""
from datetime import timedelta

from django.db.models import Q
from django.utils import timezone

# discovery (6h cap) + nuclei (4h cap) + slack; see discovery.py
RUNNING_WINDOW = timedelta(hours=11)
CERT_WARNING_DAYS = 30
RULED_OUT = 'not_affected'  # the AI verdict that takes a CVE match off every list of exposure

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


def host_reps(domain_id=None):
    """One row per host (project and name) of the current inventory: the row the Hosts page shows for it."""
    from agentapi.services import _one_per_host
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    base = Subdomain.objects.filter(latest_scan_q())
    if domain_id:
        base = base.filter(target_domain_id=domain_id)
    return _one_per_host(base, per_project=True)


def live_hosts(domain_id=None):
    """The hosts the attack-surface map draws, one row each."""
    from startScan.models import Subdomain
    return Subdomain.objects.filter(pk__in=host_reps(domain_id).filter(LIVE_HOST_Q).values('pk'))


def exposure_filter(prefix=''):
    """A Q over hosts (``prefix`` reaches the host from another model) that holds when the host is exposed."""
    from cveFeed.models import CVEMatch
    from startScan.models import Vulnerability
    matches = CVEMatch.objects.exclude(ai_verdict=RULED_OUT).exclude(subdomain=None).values('subdomain')
    findings = Vulnerability.objects.filter(open_status=True, severity__gte=2).exclude(subdomain=None).values('subdomain')
    return Q(**{prefix + 'pk__in': matches}) | Q(**{prefix + 'pk__in': findings})


def exposed_host_count():
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    rows = Subdomain.objects.filter(latest_scan_q()).filter(exposure_filter())
    return rows.values('target_domain__project_id', 'name').distinct().count()


def exposed_matches():
    from cveFeed.correlation import latest_scan_q
    from cveFeed.models import CVEMatch
    return CVEMatch.objects.exclude(ai_verdict=RULED_OUT).filter(latest_scan_q('subdomain__'))


def actionable_findings(qs):
    """Open scanner findings of low severity or worse. This is the Findings page's Actionable filter for scanner findings:
    informational detections and closed findings are the rest (``status=all``)."""
    return qs.filter(open_status=True, severity__gte=1)


def expiring_certificates(qs, days=CERT_WARNING_DAYS):
    return qs.filter(not_after__lte=timezone.now() + timedelta(days=days))
