"""The host, exposed-host and web-host counts of EVERY project, from a handful of set-based reads and plain Python (the system status, the live snapshots).

The SQL collapse (``agentapi.services._one_per_host`` over ``counts.host_reps``) is the dearest query CVEngine has: per candidate host it counts the open
ports behind the host's addresses twice (once for the one-row-per-name pass, once for the ranking), builds the address set for the host key three more
times, and the "current scans" filter is evaluated twice in the statement. On a 3-core install that took 1.2 s as Django timed it (200,000 buffer hits).
Here each fact is read once for all projects: the current rows (the filter evaluated once), their address links, the open ports of those addresses, the
ids of the hosts that are exposed; the same rules then run in Python over them. ``tests/test_inventory_counts.py`` compares the answer with the SQL one
on random inventories.

One difference in how ties are broken: among names that share an address set and have the same length, the SQL ranking took the one the database's
collation sorts first and this takes the lowest code point. For lower-case host names the two agree, and the counts never depend on it.
"""
from collections import defaultdict


def _key_project(project_id):
    return '' if project_id is None else str(project_id)  # what the SQL host key makes of a NULL project


def current_rows():
    """``[(id, name, scan_history_id, project_id, target name)]``: the current inventory (``correlation.latest_scan_q``, which is the definition), worked out
    here from three plain reads (the finished scans, every stored host, the targets) so the rule is applied once, in Python, instead of twice inside the
    statement. A row is current when its scan is a domain's latest full scan, or a finished host-pipeline scan after it, or it has no scan, or its domain has
    no full scan at all; and no newer copy of the same name (same domain) is in a host-pipeline scan after the full scan, and, for a scanned row of a domain
    with no full scan, no newer scanned copy of the name exists."""
    from cveFeed.discovery import HOST_PIPELINE_TASK
    from startScan.models import ScanHistory, Subdomain
    from targetApp.models import Domain
    latest_full, pipeline = {}, []
    for scan_id, domain_id, tasks in ScanHistory.objects.filter(scan_status=2).values_list('id', 'domain_id', 'tasks'):
        if HOST_PIPELINE_TASK in (tasks or ()):
            pipeline.append((scan_id, domain_id))
        elif scan_id > latest_full.get(domain_id, 0):
            latest_full[domain_id] = scan_id
    full_ids = set(latest_full.values())
    after = {scan_id for scan_id, domain_id in pipeline if scan_id > latest_full.get(domain_id, 0)}
    subs = list(Subdomain.objects.values_list('id', 'name', 'scan_history_id', 'target_domain_id'))
    newest_after, newest_scanned = {}, {}
    for sub_id, name, scan_id, domain_id in subs:
        if scan_id is None or domain_id is None:
            continue
        if scan_id in after and scan_id > newest_after.get((domain_id, name), 0):
            newest_after[(domain_id, name)] = scan_id
        if sub_id > newest_scanned.get((domain_id, name), 0):
            newest_scanned[(domain_id, name)] = sub_id
    targets = {domain_id: (project_id, name) for domain_id, project_id, name in Domain.objects.values_list('id', 'project_id', 'name')}
    out = []
    for sub_id, name, scan_id, domain_id in subs:
        if domain_id is not None:
            if not (scan_id is None or scan_id in full_ids or scan_id in after or domain_id not in latest_full):
                continue
            if scan_id is not None and newest_after.get((domain_id, name), 0) > scan_id:
                continue
            if scan_id is not None and domain_id not in latest_full and newest_scanned.get((domain_id, name), 0) > sub_id:
                continue
        project_id, target = targets.get(domain_id, (None, None))
        out.append((sub_id, name, scan_id, project_id, target))
    return out


def _links(ids):
    """``{subdomain id: [(ip id, is_cdn), ...]}``, one read of the address links of these hosts."""
    from startScan.models import Subdomain
    out = defaultdict(list)
    for sub_id, ip_id, cdn in Subdomain.ip_addresses.through.objects.filter(subdomain_id__in=ids).values_list('subdomain_id', 'ipaddress_id', 'ipaddress__is_cdn'):
        out[sub_id].append((ip_id, bool(cdn)))
    return out


def _open_ports(ip_ids):
    """``{ip id: {port id, ...}}`` for the open ports of these addresses, one read."""
    from startScan.models import OPEN_PORT_STATES, IpAddress
    out = defaultdict(set)
    for ip_id, port_id in IpAddress.ports.through.objects.filter(ipaddress_id__in=ip_ids, port__state__in=OPEN_PORT_STATES).values_list('ipaddress_id', 'port_id'):
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
    for sub_id, name, scan_id, project_id, domain_name in rows:
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
    for _rank, sub_id, name, project_id, domain_name, open_count in by_name.values():
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
    for sub_id, name, _scan, project_id, _domain in rows:
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
    ips = set(IpAddress.ports.through.objects.filter(web).values_list('ipaddress_id', flat=True).distinct())
    if ips:
        found |= set(Subdomain.ip_addresses.through.objects.filter(ipaddress_id__in=ips).values_list('subdomain__target_domain__project_id', 'subdomain__name').distinct())
    out = defaultdict(int)
    for project_id, _name in found:
        out[project_id] += 1
    return dict(out)
