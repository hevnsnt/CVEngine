"""The one definition of every number CVEngine prints.

The dashboard's status line, the section pages' filter chips, the Targets table, the attack-surface map and the agent API
all count the same things, and they used to count them with their own queries: the status line counted host rows (874),
the Hosts page counted distinct hosts (659) and the map drew only live hosts (163). Each is right for what it counted, and
none said what that was. Everything that prints a count now reads it from here, so a count cannot drift from the list it
links to. ``tests/test_counts.py`` pins every surface against every other.

Definitions (also shown to the user as the tooltip of each dashboard tile):

* **Hosts**: distinct hosts in a project's current inventory (``latest_scan_q``). The same name in two targets of one project is one
  host, and so are names that resolve to exactly the same addresses (``example.com`` and ``www.example.com`` on the same servers are one
  host with two names; names behind a CDN stay separate). The same name in two projects is two hosts. An archived host is not counted
  (``archived_host_q``; archiving closed its findings, ``cveFeed.archive_closure``). This is the Hosts page's count.
* **Live hosts**: hosts that resolved to an IP address or answered over HTTP. These are the tiles of the attack-surface map.
* **Exposed hosts**: hosts with a CVE match the AI has not ruled out, or an open finding of medium severity or worse.
* **CVE matches**: matches the AI has not ruled out. The Matches page opens on the same view. Counted per host: the same jQuery file on
  six sibling hosts is six matches. ``match_group_count`` counts them as the grouped Findings list shows them (one row for the six).
* **Scanner findings**: open findings of low severity or worse (informational detections and closed findings excluded). The
  Findings page, Scanner type, Actionable status, shows the same set.
* **Scans running**: scans marked running that started within ``running_window()``. An older one is stalled (a casualty of a
  restart) and is never shown as running anywhere.
* **Hygiene, top checks**: the three checks with the most actionable hygiene findings of medium severity or worse, counted over every finding (``hygiene_top_checks``).
* **Certs expiring**: certificates that expire within 30 days, including those already expired.
* **Oldest open**: the age in whole days of the longest-open critical or high item among the exposed CVE matches, actionable scanner
  findings and open hygiene findings (``oldest_open``).
"""
from datetime import timedelta

from django.db.models import Q
from django.utils import timezone

from cveFeed.closure import CLOSED  # remediation states that close a finding: fixed, accepted_risk, false_positive

RUNNING_WINDOW_SLACK = timedelta(hours=1)
CERT_WARNING_DAYS = 30
RULED_OUT = 'not_affected'  # the AI verdict that takes a CVE match off every list of exposure


def match_is_live(match):
    """A CVE match that still counts toward a host's heat, score and exposure: not ruled out by the AI and not closed (fixed, accepted
    risk or false positive)."""
    return match.ai_verdict != RULED_OUT and match.remediation_status not in CLOSED


def finding_is_live(finding):
    """A scanner finding that still counts: open, and not closed (fixed, accepted risk or false positive)."""
    return bool(finding.open_status) and finding.remediation_status not in CLOSED

# a host that resolved to an address, or that something saw answer over HTTP
LIVE_HOST_Q = Q(ip_addresses__isnull=False) | Q(http_status__gt=0)


def running_window():
    """How long a scan may be marked running before it counts as a restart casualty: the configured discovery and nuclei timeouts
    (Settings, Timings, up to 48 h and 24 h) plus an hour of slack, 11 h with the shipped timeouts. Read live, like the workers do."""
    try:
        from dashboard.models import SystemTimings
        t = SystemTimings.current()
        return timedelta(hours=t.discovery_timeout_hours + t.nuclei_timeout_hours) + RUNNING_WINDOW_SLACK
    except Exception:  # noqa: BLE001 - a counting helper never fails on a settings lookup
        return timedelta(hours=11)


def __getattr__(name):
    if name == 'RUNNING_WINDOW':  # older importers read the window as an attribute; it is no longer a constant
        return running_window()
    raise AttributeError(name)


def running_scans(qs=None, window=None):
    """``window``: the running window when the caller already read it (it is a settings lookup)."""
    from startScan.models import ScanHistory
    qs = ScanHistory.objects.all() if qs is None else qs
    return qs.filter(scan_status=1, start_scan_date__gte=timezone.now() - (running_window() if window is None else window))


BACKGROUND_WINDOW = timedelta(hours=3)  # a "running" activity line older than this is a casualty of a restart, not work in progress
BACKGROUND_KINDS = ("run_check", "discovery", "scan", "hygiene", "validate")


def background_running(now=None, window=None):
    """The activity lines of background work in progress: a check, sweep, rescan or assessment that runs under a scan record that is
    no longer running (the weekly deep nuclei pass, a host rescan, an assessment), so it is invisible to ``running_scans``. A line that
    belongs to a scan ``running_scans`` already counts is left out, so the two never count the same work twice."""
    from cveFeed.models import AgentActivity
    now = now or timezone.now()
    under_a_running_scan = list(running_scans(window=window).values_list("id", flat=True))
    qs = AgentActivity.objects.filter(status="running", kind__in=BACKGROUND_KINDS, created_at__gte=now - BACKGROUND_WINDOW)
    if under_a_running_scan:
        # a missing key is not "in": filter first, then exclude by id. The inner query repeats the status, kind and age bounds (the lines it
        # can exclude are a subset of them) so it never reads the whole 30-day activity table on every stats poll
        qs = qs.exclude(pk__in=qs.filter(detail__scan_id__in=under_a_running_scan).values("pk"))
    return qs


def stalled_scans(qs=None):
    from startScan.models import ScanHistory
    qs = ScanHistory.objects.all() if qs is None else qs
    return qs.filter(scan_status=1, start_scan_date__lt=timezone.now() - running_window())


def queued_scans(qs=None):
    from startScan.models import ScanHistory
    return (ScanHistory.objects.all() if qs is None else qs).filter(scan_status=-1)


# A queued scan that nothing will ever start. A host pipeline row (cveFeed.discovery.run_host_pipeline) is created queued and marked running by the
# same worker task a moment later, so one still queued after PIPELINE_QUEUED_GRACE lost that task (a restart or update killed it in between). Any
# other queued scan (a discovery waiting for a discovery worker, an internal scan) waits in the broker, and the reaper sends a lost one again
# (reaper.redispatch_queued_scans), so one still queued after queued_scan_limit() hours is a row nothing advances.
PIPELINE_QUEUED_GRACE = timedelta(minutes=30)
QUEUED_SCAN_HOURS = 48


def queued_scan_limit():
    """How long a queued scan may wait before it counts as stuck: CVENGINE_SCAN_QUEUED_HOURS, else 48 hours."""
    import os
    try:
        return timedelta(hours=max(1, int(os.environ.get('CVENGINE_SCAN_QUEUED_HOURS', ''))))
    except ValueError:
        return timedelta(hours=QUEUED_SCAN_HOURS)


def stuck_queued_q(now=None, limit=None):
    """The queued scans that nothing will start (see PIPELINE_QUEUED_GRACE above). ``limit``: ``queued_scan_limit()`` when the caller already read it."""
    from cveFeed.discovery import HOST_PIPELINE_TASK
    now = now or timezone.now()
    return Q(scan_status=-1) & (Q(tasks__contains=[HOST_PIPELINE_TASK], start_scan_date__lt=now - PIPELINE_QUEUED_GRACE)
                                | Q(start_scan_date__lt=now - (limit or queued_scan_limit())))


def waiting_scans(qs=None, now=None):
    """The queued scans that really wait for a worker: ``queued_scans`` without the stuck rows (``stuck_queued_q``). This is the queue a starvation verdict
    and the assessment share read; a stuck row waits for nothing, and the reaper closes it (reaper.expire_stuck_queued)."""
    queued = queued_scans(qs)
    return queued.exclude(pk__in=queued.filter(stuck_queued_q(now)).values('pk'))


def queued_scan_split(now=None):
    """``{'waiting', 'oldest_waiting_age_seconds', 'stuck', 'stuck_ids', 'oldest_stuck_age_seconds'}``: the queued scans that wait for a worker and the
    ones nothing will start, with the age of the oldest of each (None when there is none) and the ids of the oldest ten stuck rows."""
    from django.db.models import Count, Min
    now = now or timezone.now()
    stuck_q = stuck_queued_q(now)
    queued = queued_scans()
    got = queued.aggregate(total=Count('id'), stuck=Count('id', filter=stuck_q), oldest_stuck=Min('start_scan_date', filter=stuck_q))
    oldest_waiting = waiting_scans(now=now).order_by('start_scan_date').values_list('start_scan_date', flat=True).first()

    def age(at):
        return int(max(0, (now - at).total_seconds())) if at else None
    return {'waiting': got['total'] - got['stuck'], 'oldest_waiting_age_seconds': age(oldest_waiting), 'stuck': got['stuck'],
            'stuck_ids': list(queued.filter(stuck_q).order_by('id').values_list('id', flat=True)[:10]) if got['stuck'] else [],
            'oldest_stuck_age_seconds': age(got['oldest_stuck'])}


def with_host_key(qs):
    """Annotate Subdomain rows with ``host_key``: the identity of the machine behind the name, so names that point at the same
    addresses are one host. The key is the project plus the sorted set of the row's IP addresses; a row with no address, or with an
    address of a CDN or shared edge (many unrelated sites share those), keeps its own name as its key. The same name (several
    scans of it) therefore shares a key, and so do ``example.com`` and ``www.example.com`` when both resolve to the same addresses. It is a key per
    row: two copies of one name with different addresses (or one with none) get two keys. To count machines as the Hosts page folds them, use
    ``machines``."""
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


class Machines:
    """The machines of some projects' current inventory exactly as the Hosts page folds them (``machines``). ``of_row(id)`` and ``of_name(project id,
    name)`` give the machine key (the ``with_host_key`` form: ``<project>:i:<address ids>`` or ``<project>:n:<name>``) of a current row or name,
    ``name(key)`` the name the Hosts page shows for that machine. A row or name outside the inventory read has no machine (None)."""

    def __init__(self, by_row, by_name, names):
        self._by_row, self._by_name, self._names = by_row, by_name, names

    def of_row(self, sub_id):
        return self._by_row.get(sub_id)

    def of_name(self, project_id, name):
        return self._by_name.get((project_id, name))

    def name(self, key):
        return self._names.get(key)

    def keys(self):
        return set(self._names)

    def names(self):
        """``[((project id, name), machine key)]`` for every name of the inventory read."""
        return list(self._by_name.items())


def machines(project_ids):
    """``Machines`` of the current inventory (``latest_scan_q``) of ``project_ids``, folded by the Hosts page's own rules (``agentapi.services._one_per_host``,
    worked out in Python by ``inventory_counts._collapse``, which ``tests/test_inventory_counts.py`` holds to the SQL): first one row per name (the most open
    ports, the most addresses, the newest scan), then the names whose chosen rows share an address set are one machine, shown under the target's own name,
    else the shortest. Every copy of a name (a scanless row beside the scanned one, a second target's copy) belongs to the machine of the row chosen for
    the name, never to one of its own: ``with_host_key`` keys each row by that row's addresses alone, so a copy with no address, or with another address
    set, used to count as a second machine. This is the one notion of a machine every count of hosts that links to the Hosts page reads (the Overview's
    threat card, the email digest, ``reporting/threats``, ``get_threat_digest``). Reads the rows of these projects only, with the base manager: a worker
    has no request scope, so the caller's project ids are the scope."""
    from cveFeed import inventory_counts
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    ids = sorted({int(i) for i in project_ids or ()})
    if not ids:
        return Machines({}, {}, {})
    rows = list(Subdomain._base_manager.filter(latest_scan_q()).filter(target_domain__project_id__in=ids)
                .values_list('id', 'name', 'scan_history_id', 'target_domain__project_id', 'target_domain__name'))
    rows = inventory_counts._active(rows)  # an archived host is no machine of the inventory (the Hosts page leaves it out too)
    by_name = {}
    best, _key = inventory_counts._collapse(rows, names_out=by_name)
    by_row = {sub_id: by_name[(project_id, name)] for sub_id, name, _scan, project_id, _target in rows if (project_id, name) in by_name}
    return Machines(by_row, by_name, {key: rep[1] for key, rep in best.items()})


def _host_keys(qs):
    """``[{'id', 'name', 'target_domain__project_id', 'host_key'}]`` for the Subdomain rows of ``qs``: the ``with_host_key`` key worked out here from ONE read
    of the rows beside their address links (a row per address, its CDN flag with it), the same rule: the project (empty when there is none), then ``:n:``
    and the name for a row with no address or with a CDN address, else ``:i:`` and the address ids in ascending order joined by commas. In SQL the key
    is three correlated subqueries per row, worked out once to filter and again to select (60,000 buffers and 180 ms for the other names of the 900
    hosts the graph draws on the production install; 4,700 buffers and 50 ms read this way)."""
    rows = {}
    for sub_id, name, project_id, ip_id, cdn in qs.order_by().values_list('id', 'name', 'target_domain__project_id', 'ip_addresses__id', 'ip_addresses__is_cdn'):
        row = rows.get(sub_id)
        if row is None:
            row = rows[sub_id] = {'id': sub_id, 'name': name, 'target_domain__project_id': project_id, 'ips': [], 'cdn': False}
        if ip_id is not None:
            row['ips'].append(ip_id)
            row['cdn'] = row['cdn'] or bool(cdn)
    out = []
    for row in rows.values():
        project = '' if row['target_domain__project_id'] is None else str(row['target_domain__project_id'])
        ips, cdn = row.pop('ips'), row.pop('cdn')
        row['host_key'] = f"{project}:n:{row['name']}" if cdn or not ips else f"{project}:i:" + ','.join(str(i) for i in sorted(ips))
        out.append(row)
    return out


def host_siblings(sub_ids):
    """``{id: [(id, name), ...]}``: for each given row, the other current-inventory rows of the same host: other copies of its name
    (a second target, a second scan), and every name that points at the same addresses together with their copies. A few queries
    however many rows are asked about. The host keys are ``with_host_key``'s, worked out from the address links (``_host_keys``)."""
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    sub_ids = list(sub_ids)
    if not sub_ids:
        return {}
    current = Subdomain.objects.filter(latest_scan_q())
    keyed = _host_keys(Subdomain.objects.filter(id__in=sub_ids))
    names_by_key = {}
    # only a row that could have one of these keys gets its key worked out: one with one of these names, or one on one of their addresses (an
    # address-set key equal to a row's is made of that row's addresses); every other current row of the inventory is left out
    through = Subdomain.ip_addresses.through
    near = Q(name__in={k['name'] for k in keyed}) | Q(id__in=through.objects.filter(
        ipaddress_id__in=through.objects.filter(subdomain_id__in=sub_ids).values('ipaddress_id')).values('subdomain_id'))
    wanted_keys = {k['host_key'] for k in keyed}
    for r in _host_keys(current.filter(near)):
        if r['host_key'] in wanted_keys:
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


def archived_host_q(prefix=''):
    """A Q over host rows (``prefix`` reaches a Subdomain from another model) that holds when the host is archived in its project (``HostState.archived_at``).
    Lists and counts leave such a host out by default (``qs.filter(~archived_host_q())``); its own page and the Archived view still show it. One indexed
    lookup per row (the state's project and host)."""
    from django.db.models import Exists, OuterRef
    from django.db.models.functions import Lower

    from cveFeed.models import HostState
    return Q(Exists(HostState.objects.filter(project_id=OuterRef(f'{prefix}target_domain__project_id'), host=Lower(OuterRef(f'{prefix}name')),
                                             archived_at__isnull=False)))


def archived_keys(project_ids=None):
    """``{(project id, host name)}`` of the archived hosts (of ``project_ids``, or every project): for a count worked out in Python."""
    from cveFeed.models import HostState
    qs = HostState.objects.filter(archived_at__isnull=False)
    if project_ids is not None:
        qs = qs.filter(project_id__in=list(project_ids))
    return set(qs.values_list('project_id', 'host'))


def exposed_among(reps, project_ids=None):
    """The hosts of ``reps`` (one row each, see ``host_reps``) that are exposed. A host is exposed when any of its names is, so a
    finding on ``www`` exposes the host whose row is ``example.com``. ``project_ids``: the projects ``reps`` is drawn from, so the
    exposed set is not built over every other project's hosts too (a host's key and name never cross projects, so the answer is the same)."""
    from django.db.models import CharField, Value
    from django.db.models.functions import Cast, Concat
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    exposed = Subdomain.objects.filter(latest_scan_q()).filter(exposure_filter())
    if project_ids is not None:
        exposed = exposed.filter(target_domain__project_id__in=list(project_ids))

    def named(qs):
        """Project and name as one value (the same name in two projects is two hosts), so "some row of this name is exposed" is one
        uncorrelated IN. A correlated EXISTS per host made this count take 14 s at 10,000 hosts."""
        return qs.annotate(_named=Concat(Cast('target_domain__project_id', CharField()), Value(':'), 'name', output_field=CharField()))
    return named(with_host_key(reps)).filter(Q(host_key__in=with_host_key(exposed).values('host_key')) | Q(_named__in=named(exposed).values('_named')))


def host_reps(domain_id=None, domain_ids=None, in_scope=False):
    """One row per host (project and name) of the current inventory: the row the Hosts page shows for it. ``domain_id`` (one
    target) or ``domain_ids`` (several) narrow it to those targets' hosts. ``in_scope`` (what a sweep may scan) leaves out the rows kept
    under a target that is now exactly one host before the rows are collapsed, so a name another target still holds keeps that row."""
    from agentapi.services import _one_per_host
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    base = Subdomain.objects.filter(latest_scan_q()).filter(~archived_host_q())  # an archived host is not one of the inventory's hosts
    if in_scope:
        from targetApp.models import in_target_scope_q
        base = base.filter(in_target_scope_q())
    if domain_id:
        base = base.filter(target_domain_id=domain_id)
    if domain_ids is not None:
        base = base.filter(target_domain_id__in=list(domain_ids))
    return _one_per_host(base, per_project=True)


def rep_ids(domain_id=None, domain_ids=None, in_scope=False):
    """The ids of ``host_reps``, read in ONE statement. The collapse is the dearest query CVEngine has (a window over every host's address set), so a request
    that needs several numbers over the same hosts reads the ids once and derives each number from them (``reps_of``) instead of collapsing again per number."""
    if domain_id is None and domain_ids is None and not in_scope:  # the whole inventory: worked out in Python from set-based reads (cveFeed.inventory_counts)
        from cveFeed import inventory_counts
        return inventory_counts.rep_ids()
    return list(host_reps(domain_id=domain_id, domain_ids=domain_ids, in_scope=in_scope).values_list('pk', flat=True))


def reps_of(ids):
    """The Subdomain rows with these ids (from ``rep_ids``): what ``host_reps`` returned, without running the collapse again."""
    from startScan.models import Subdomain
    return Subdomain.objects.filter(pk__in=ids)


HOST_REPS_SECONDS = 5  # how long the live screen's snapshots of one scope share one collapse (the refresher's own beat)


def snapshot_rep_ids():
    """``rep_ids()`` of the caller's scope. Called while a live-screen snapshot is being built (stats, discovery counts, graph: ``snapshot_cache.building``),
    the ids come from a snapshot of their own that all of them share for ``HOST_REPS_SECONDS``, one collapse for the three where each used to run its own
    every 5 s. Called any other time (a request that wants the hosts as they are now, a test, a task) it reads the database, exactly as before. A finding
    closed (``bump_stats_revision``) drops it with the other snapshots."""
    from cveFeed import snapshot_cache
    if not snapshot_cache.building():
        return rep_ids()
    return snapshot_cache.snapshot('host-reps', snapshot_cache.scope_hash('host-reps'), rep_ids, HOST_REPS_SECONDS, etag_of=lambda _ids: '')['payload']


def live_hosts(domain_id=None):
    """The hosts the attack-surface map draws, one row each."""
    from startScan.models import Subdomain
    return Subdomain.objects.filter(pk__in=host_reps(domain_id).filter(LIVE_HOST_Q).values('pk'))


def exposure_sources():
    """``(matches, findings)``: the CVE matches not ruled out or closed and the open findings of medium or above, each of a host (``subdomain`` set); a host
    is exposed when any of them names it."""
    from cveFeed.models import CVEMatch
    from startScan.models import Vulnerability
    matches = CVEMatch.objects.exclude(ai_verdict=RULED_OUT).exclude(remediation_status__in=CLOSED).exclude(subdomain=None)
    findings = Vulnerability.objects.filter(open_status=True, severity__gte=2).exclude(remediation_status__in=CLOSED).exclude(subdomain=None)
    return matches, findings


def exposure_filter(prefix=''):
    """A Q over hosts (``prefix`` reaches the host from another model) that holds when the host is exposed."""
    matches, findings = exposure_sources()
    return Q(**{prefix + 'pk__in': matches.values('subdomain')}) | Q(**{prefix + 'pk__in': findings.values('subdomain')})


def exposed_host_count(reps=None):
    """``reps``: the hosts to count among (``reps_of(rep_ids())``) when the caller already collapsed the inventory; by default it is collapsed here."""
    return exposed_among(host_reps() if reps is None else reps).count()  # a machine once, however many names point at it


def exposed_matches():
    from cveFeed.correlation import latest_scan_q
    from cveFeed.models import CVEMatch
    return CVEMatch.objects.exclude(ai_verdict=RULED_OUT).exclude(remediation_status__in=CLOSED).filter(latest_scan_q('subdomain__'))


def match_group_count():
    """``(rows, truncated)``: the exposed CVE matches (``exposed_matches``) counted as the grouped Findings list draws them, the same
    client-side library file on sibling hosts of one site being one (``cveFeed.finding_groups``). One values() pass, capped like the
    list's; ``truncated`` says the cap was reached, and the number is then not exact."""
    from cveFeed import finding_groups
    return finding_groups.row_count(exposed_matches())


def actionable_findings(qs):
    """Open scanner findings of low severity or worse. This is the Findings page's Actionable filter for scanner findings:
    informational detections and closed findings (fixed, an accepted risk or a false positive too) are the rest (``status=all``)."""
    return qs.filter(open_status=True, severity__gte=1).exclude(remediation_status__in=CLOSED)


def actionable_hygiene(qs, severity=1):
    """Open hygiene findings of ``severity`` or worse (low by default) that are not closed (fixed, accepted risk, false positive): the Findings page's
    Actionable filter for hygiene findings and the dashboard's Hygiene tile."""
    return qs.filter(status='open', severity__gte=severity).exclude(remediation_status__in=CLOSED)


HYGIENE_TOP_CHECKS = 3
_HYGIENE_SEVERITY_NAMES = {4: 'critical', 3: 'high', 2: 'medium'}


def hygiene_top_checks(limit=HYGIENE_TOP_CHECKS):
    """``[{check, worst, n}]``: the ``limit`` checks with the most actionable hygiene findings of medium severity or worse (``actionable_hygiene``, the
    Findings page's Actionable filter), worst severity first and then the most findings. One grouped query over every row: the dashboard's Hygiene tile
    used to count these from the first 100 rows of each severity, so a check with 400 findings said 100."""
    from django.db.models import Count, Max

    from cveFeed.models import HygieneFinding
    rows = (actionable_hygiene(HygieneFinding.objects.all(), severity=2).order_by().values('check_name')
            .annotate(n=Count('id'), worst=Max('severity')).order_by('-worst', '-n', 'check_name')[:limit])
    return [{'check': r['check_name'], 'worst': _HYGIENE_SEVERITY_NAMES.get(r['worst'], 'medium'), 'n': r['n']} for r in rows]


def oldest_open(now=None):
    """How long the worst open thing has sat: ``{'days', 'kind', 'id'}`` for the oldest open, actionable item of critical or high severity
    across the three sources, or ``{'days': None, 'kind': None, 'id': None}`` when none qualifies. Each source keeps its own definition
    of actionable so the number agrees with the page it links to:

    * ``cve``: an exposed match (``exposed_matches``: not ruled out by the AI, not fixed or accepted) whose CVE scores 7.0 or more, the
      Findings page's high and critical bands. A match is stored once per scan, so it has been open since the first scan that held
      the same CVE on the same host name of the same target.
    * ``scanner``: an actionable finding (``actionable_findings``) of severity high (3) or critical (4), open since the earliest
      discovery of the same finding on the same host.
    * ``hygiene``: an open hygiene finding of severity high or critical that is not closed, open since its first_seen.

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
    row = (exposed_matches().filter(cve_entry__cvss__gte=HIGH_CVSS).annotate(first=first_match).order_by('first', 'id').values('id', 'first').first())
    if row:
        consider('cve', row['first'], row['id'])
    # The scanner finding that has been open longest, open since the earliest discovery of the same finding (name) on the same host (target and name). It was a
    # correlated subquery per candidate (0.4 s for 20,000 findings); now the candidates and the earliest discoveries of their names are two reads and the
    # comparison is made here. Ties are broken by id (the SQL left them to the database).
    from django.db.models import Min
    candidates = list(actionable_findings(Vulnerability.objects.filter(severity__gte=3, subdomain__isnull=False, subdomain__target_domain__isnull=False))
                      .values_list('id', 'name', 'subdomain__target_domain', 'subdomain__name'))  # a host with no target never had its earliest discovery found (NULL is not equal to NULL)
    if candidates:
        earliest = {(name, domain, host): first for name, domain, host, first in
                    Vulnerability.objects.filter(name__in={c[1] for c in candidates}, discovered_date__isnull=False,  # the candidates' own names, targets and hosts only
                                                 subdomain__target_domain__in={c[2] for c in candidates}, subdomain__name__in={c[3] for c in candidates})
                    .values_list('name', 'subdomain__target_domain', 'subdomain__name').annotate(first=Min('discovered_date')).order_by()}
        found = [(earliest[(name, domain, host)], row_id) for row_id, name, domain, host in candidates if (name, domain, host) in earliest]
        if found:
            first, row_id = min(found)
            consider('scanner', first, row_id)
    row = actionable_hygiene(HygieneFinding.objects.all(), 3).order_by('first_seen', 'id').values('id', 'first_seen').first()
    if row:
        consider('hygiene', row['first_seen'], row['id'])
    if best['at'] is None:
        return {'days': None, 'kind': None, 'id': None}
    return {'days': max(0, (now - best['at']).days), 'kind': best['kind'], 'id': best['id']}


def expiring_certificates(qs, days=CERT_WARNING_DAYS):
    return qs.filter(not_after__lte=timezone.now() + timedelta(days=days))


# --- retest on fix (cveFeed.fix_retest) ----------------------------------------------------------------------------------------------------
# The states of a finding marked fixed: verified fixed (a retest ran the check that proved it and it no longer reproduces), fixed and not verified
# (queued, could not be told, no check to repeat, or not re-checked yet: never read as verified), and reopened (a retest found it still reproduces).

def retest_q(state, prefix='triage__'):
    """A filter on a finding's remediation status and its Triage row (``prefix`` is the path to the Triage row, ``triage__`` from a finding)
    for ``verified_fixed``, ``unverified_fixed`` or ``reopened``."""
    fixed = Q(remediation_status='fixed')
    verified = Q(**{f'{prefix}retest_state': 'verified_fixed'})
    if state == 'verified_fixed':
        return fixed & verified
    if state == 'unverified_fixed':
        return fixed & ~verified  # a row with no Triage row (the join is null) is not verified either
    if state == 'reopened':
        return Q(remediation_status__in=('open', 'in_progress')) & Q(**{f'{prefix}retest_state': 'still_reproduces'})
    raise ValueError('unknown retest state')


def retest_counts(project_ids):
    """``{verified_fixed, unverified_fixed, reopened}``: findings (CVE matches of the current inventory, scanner and hygiene findings) of these
    projects in each retest state. One grouped query per kind of finding."""
    from django.db.models import Count

    from cveFeed.correlation import latest_scan_q
    from cveFeed.models import CVEMatch, HygieneFinding
    from startScan.models import Vulnerability
    out = {'verified_fixed': 0, 'unverified_fixed': 0, 'reopened': 0}
    sources = (CVEMatch.objects.filter(latest_scan_q('subdomain__'), subdomain__target_domain__project_id__in=project_ids),
               Vulnerability.objects.filter(target_domain__project_id__in=project_ids),
               HygieneFinding.objects.filter(domain__project_id__in=project_ids))
    for qs in sources:
        agg = qs.aggregate(**{state: Count('pk', filter=retest_q(state)) for state in out})
        for state in out:
            out[state] += agg[state]
    return out
