"""The host, exposed-host and web-host counts of EVERY project, from a handful of set-based reads and plain Python (the system status, the live snapshots).

The SQL collapse (``agentapi.services._one_per_host`` over ``counts.host_reps``) is the dearest query CVEngine has: per candidate host it counts the open
ports behind the host's addresses twice (once for the one-row-per-name pass, once for the ranking), builds the address set for the host key three more
times, and the "current scans" filter is evaluated twice in the statement. On a 3-core install that took 1.2 s as Django timed it (200,000 buffer hits).
Here each fact is read once for all projects: the current rows (the filter evaluated once), their address links, the open ports of those addresses, the
ids of the hosts that are exposed; the same rules then run in Python over them. ``tests/test_inventory_counts.py`` compares the answer with the SQL one
on random inventories.

Ties are broken the same way here and in the SQL (``_one_per_host``): among names that share an address set and have the same length, the lowest by
byte order (``COLLATE "C"`` there, code point here), whatever locale the database sorts text in; the exposed count depends on which name stands for a
host (it also matches on the name), so the two must agree.

The pass is Python work (about 3 s of CPU at 100,000 hosts), and the Celery lanes that run it (``status_warm_rows``, the live refresher) are gevent workers:
it yields to the worker's other greenlets every ``YIELD_EVERY`` rows (``_breathe``), and does nothing of the kind outside gevent.
"""
from collections import defaultdict

YIELD_EVERY = 2000


def _breathe(i):
    """Let a gevent worker's other greenlets run every ``YIELD_EVERY`` rows of a loop; a no-op outside gevent."""
    if i % YIELD_EVERY:
        return
    from reNgine import gevent_db
    if gevent_db.gevent_patched():
        import gevent
        gevent.sleep(0)


def _fetch(qs):
    """Every row of a ``values_list`` queryset in one fetch. Django reads a result a hundred rows at a time (a call, and a wrapper that watches for database errors,
    for each hundred: 400 of them for the inventory's rows); these reads are integers, names and flags, which need no
    conversion on the way."""
    from django.core.exceptions import EmptyResultSet
    from django.db import connections
    try:
        sql, params = qs.query.sql_with_params()
    except EmptyResultSet:
        return []
    with connections[qs.db].cursor() as cursor:
        cursor.execute(sql, params)
        return cursor.fetchall()


def _chunks(rows):
    """``rows`` in slices of ``YIELD_EVERY``, a gevent worker's other greenlets let run before each (``_breathe``), so a loop over them needs no call per row."""
    for start in range(0, len(rows), YIELD_EVERY):
        _breathe(start)
        yield rows[start:start + YIELD_EVERY]


def _key_project(project_id):
    return '' if project_id is None else str(project_id)  # what the SQL host key makes of a NULL project


def current_rows():
    """``[(id, name, scan_history_id, project_id, target name)]``: the current inventory (``correlation.latest_scan_q``, which is the definition), worked out
    here from three plain reads (the finished scans, every stored host, the targets) so the rule is applied once, in Python, instead of twice inside the
    statement. A row is current when its scan is a domain's latest full scan, or a finished host-pipeline scan after it, or it has no scan, or its domain has
    no full scan at all; and no newer copy of the same name (same domain) is in a host-pipeline scan after the full scan, and, for a scanned row of a domain
    with no full scan, no newer scanned copy of the name exists."""
    from django.db import connection

    from cveFeed.discovery import HOST_PIPELINE_TASK
    from startScan.models import ScanHistory, Subdomain
    from targetApp.models import Domain
    latest_full, pipeline = {}, []
    for scan_id, domain_id, tasks in _fetch(ScanHistory.objects.filter(scan_status=2).values_list('id', 'domain_id', 'tasks')):
        if HOST_PIPELINE_TASK in (tasks or ()):
            pipeline.append((scan_id, domain_id))
        elif scan_id > latest_full.get(domain_id, 0):
            latest_full[domain_id] = scan_id
    full_ids = set(latest_full.values())
    after = {scan_id for scan_id, domain_id in pipeline if scan_id > latest_full.get(domain_id, 0)}
    targets = {domain_id: (project_id, name) for domain_id, project_id, name in _fetch(Domain.objects.values_list('id', 'project_id', 'name'))}
    # Only the rows the rules below can keep or that a kept row can be compared with are read (a fifth of the stored hosts on the reported install): a row with no scan
    # or no target, a row of a scan that is a latest full scan or a host-pipeline scan after it, and every row of a domain that has no full scan. Any other row is dropped
    # by the first test of the second pass, and takes no part in ``newest_after`` (it needs a scan in ``after``) or ``newest_scanned`` (it needs a domain with no full scan).
    wanted_scans = sorted(full_ids | after)
    unscanned_domains = sorted(set(targets) - set(latest_full))
    table = Subdomain._meta.db_table
    from tenancy import scope as tenancy_scope
    scoped = tenancy_scope.current_allowed() is not None  # the raw read skips the tenancy manager: a scoped call reads only the rows of the domains it may see (``targets`` is already scoped)
    with connection.cursor() as cursor:
        cursor.execute(f'SELECT id, name, scan_history_id, target_domain_id FROM "{table}" WHERE (scan_history_id IS NULL OR target_domain_id IS NULL '
                       'OR scan_history_id = ANY(%s) OR target_domain_id = ANY(%s))' + (' AND target_domain_id = ANY(%s)' if scoped else ''),
                       [wanted_scans, unscanned_domains] + ([sorted(targets)] if scoped else []))
        subs = cursor.fetchall()
    newest_after, newest_scanned = {}, {}
    for start in range(0, len(subs), YIELD_EVERY):
        _breathe(start)
        for sub_id, name, scan_id, domain_id in subs[start:start + YIELD_EVERY]:
            if scan_id is None or domain_id is None:
                continue
            if scan_id in after:  # only a row of a host-pipeline scan after the full scan can supersede an older copy of its name
                key = (domain_id, name)
                if scan_id > newest_after.get(key, 0):
                    newest_after[key] = scan_id
            if domain_id not in latest_full:  # and the newest scanned copy only matters for a domain with no full scan
                key = (domain_id, name)
                if sub_id > newest_scanned.get(key, 0):
                    newest_scanned[key] = sub_id
    no_target = (None, None)
    out = []
    keep = out.append
    for start in range(0, len(subs), YIELD_EVERY):
        _breathe(start)
        for sub_id, name, scan_id, domain_id in subs[start:start + YIELD_EVERY]:
            if domain_id is not None and scan_id is not None:
                unscanned_domain = domain_id not in latest_full
                if not (scan_id in full_ids or scan_id in after or unscanned_domain):
                    continue
                if newest_after and newest_after.get((domain_id, name), 0) > scan_id:
                    continue
                if unscanned_domain and newest_scanned.get((domain_id, name), 0) > sub_id:
                    continue
            project_id, target = targets.get(domain_id, no_target)
            keep((sub_id, name, scan_id, project_id, target))
    return out


def _links(ids):
    """``{subdomain id: [(ip id, is_cdn), ...]}``, one read of the address links of these hosts."""
    from startScan.models import Subdomain
    out = defaultdict(list)
    for chunk in _chunks(_fetch(Subdomain.ip_addresses.through.objects.filter(subdomain_id__in=ids).values_list('subdomain_id', 'ipaddress_id', 'ipaddress__is_cdn'))):
        for sub_id, ip_id, cdn in chunk:
            out[sub_id].append((ip_id, bool(cdn)))
    return out


def _open_ports(ip_ids):
    """``{ip id: {port id, ...}}`` for the open ports of these addresses, one read."""
    from startScan.models import OPEN_PORT_STATES, IpAddress
    out = defaultdict(set)
    for chunk in _chunks(_fetch(IpAddress.ports.through.objects.filter(ipaddress_id__in=ip_ids, port__state__in=OPEN_PORT_STATES).values_list('ipaddress_id', 'port_id'))):
        for ip_id, port_id in chunk:
            out[ip_id].add(port_id)
    return out


def _exposed_ids(ids):
    """The ids, among these hosts, of those that have an open CVE match not ruled out or an open finding of medium or above (``counts.exposure_sources``), one read each."""
    from cveFeed import counts
    matches, findings = counts.exposure_sources()
    return (set(matches.filter(subdomain_id__in=ids).values_list('subdomain_id', flat=True).distinct())
            | set(findings.filter(subdomain_id__in=ids).values_list('subdomain_id', flat=True).distinct()))


def _collapse(rows):
    """``(best, host_key, links)``: ``best`` maps each host key to ``(rank, name, project_id, subdomain id)`` of the one row that stands for the host,
    ``host_key(sub_id, name, project_id)`` is the key of any row and ``links`` the address links read for them."""
    ids = [r[0] for r in rows]
    links = _links(ids)
    ports = _open_ports({ip for ls in links.values() for ip, _ in ls})

    def open_ports(sub_id):
        found = set()
        for ip_id, _cdn in links.get(sub_id, ()):
            found |= ports.get(ip_id, set())
        return len(found)

    # one row per (project, name): the one with the most open ports, then the most addresses, then the newest scan (a scan-less row last), then the newest id
    by_name = {}
    for i, (sub_id, name, scan_id, project_id, domain_name) in enumerate(rows):
        _breathe(i)
        rank = (-open_ports(sub_id), -len(links.get(sub_id, ())), scan_id is None, -(scan_id or 0), -sub_id)
        held = by_name.get((project_id, name))
        if held is None or rank < held[0]:
            by_name[(project_id, name)] = (rank, sub_id, name, project_id, domain_name, -rank[0])

    def host_key(sub_id, name, project_id):
        ls = links.get(sub_id)
        if not ls or any(cdn for _ip, cdn in ls):  # no address, or behind a CDN or shared edge: the name is the identity
            return f'{_key_project(project_id)}:n:{name}'
        return f'{_key_project(project_id)}:i:' + ','.join(str(ip) for ip in sorted(ip for ip, _cdn in ls))

    # names that point at the same addresses are one host: the project's own target name first, else the shortest name
    best = {}
    for i, (_rank, sub_id, name, project_id, domain_name, open_count) in enumerate(by_name.values()):
        _breathe(i)
        key = host_key(sub_id, name, project_id)
        rank = (0 if name == domain_name else 1, len(name), name, -open_count, -sub_id)
        if key not in best or rank < best[key][0]:
            best[key] = (rank, name, project_id, sub_id)
    return best, host_key


def rep_ids(rows=None):
    """The ids of the one row per host of the whole inventory: what ``counts.host_reps()`` selects with no narrowing (``counts.rep_ids``)."""
    rows = current_rows() if rows is None else rows
    best, _key = _collapse(rows)
    return [sub_id for _rank, _name, _project, sub_id in best.values()]


def shared_host_counts(rows=None):
    """``{'hosts': {project_id: n}, 'exposed': {project_id: n}}`` for every project, the numbers ``compute_snapshot`` gets for each alone. ``rows``: the
    current inventory (``current_rows``) when the caller has read it."""
    rows = current_rows() if rows is None else rows
    best, host_key = _collapse(rows)
    exposed_ids = _exposed_ids([r[0] for r in rows])
    exposed_keys, exposed_names = set(), set()
    for i, (sub_id, name, _scan, project_id, _domain) in enumerate(rows):
        _breathe(i)
        if sub_id in exposed_ids:
            exposed_keys.add(host_key(sub_id, name, project_id))
            exposed_names.add((project_id, name))
    hosts, exposed = defaultdict(int), defaultdict(int)
    for key, (_rank, name, project_id, _sub_id) in best.items():
        hosts[project_id] += 1
        if key in exposed_keys or (project_id, name) in exposed_names:
            exposed[project_id] += 1
    return {'hosts': dict(hosts), 'exposed': dict(exposed)}


def web_hosts_by_project():
    """``{project_id: hosts with a web page}``: the distinct (project, name) of every stored host that has an ``http_url`` or an address with an open web
    port (``web_shot._web_evidence_q``), from two reads and no join of the wide port rows: the names with a URL, and the names behind the addresses that
    carry a web port."""
    from cveFeed import web_shot
    from startScan.models import IpAddress, Subdomain
    found = set(Subdomain.objects.filter(http_url__gt='').values_list('target_domain__project_id', 'name').distinct())
    web = web_shot.web_port_q('port__')
    ips = IpAddress.ports.through.objects.filter(web).values('ipaddress_id')  # a subquery, not a list of every such address sent back to the database
    found |= set(Subdomain.ip_addresses.through.objects.filter(ipaddress_id__in=ips).values_list('subdomain__target_domain__project_id', 'subdomain__name').distinct())
    out = defaultdict(int)
    for project_id, _name in found:
        out[project_id] += 1
    return dict(out)
