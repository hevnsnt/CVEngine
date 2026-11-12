"""Whether the network path a scanner scans from leaves a packet alone (the built-in scanner's, or with none, each Sentinel's own).

The operating system detection of a scanner sends sixteen probes, some of them deliberately malformed (a TCP segment with FIN, PSH and URG set, a
segment to a closed port with an odd option layout), and reads how the target's stack answers each. That only works if the probes arrive as
sent and the answers come back as sent. Two things in a container's path break it:

* Docker's default bridge network translates addresses with iptables and conntrack. A segment with an impossible flag combination is marked
  INVALID by conntrack, is not translated, leaves with the container's private source address, and its answer has nowhere to go. In a
  measured lab (the same target, once directly and once through a masquerading bridge) the FIN+PSH+URG probe to a closed port was
  answered directly and lost behind the NAT, the ``T7`` result changed from answered to not, and the top guess for a Linux host changed from
  "Linux 5.3 - 5.4 (97%)" to "HP P2000 G3 NAS device (93%)". Host networking and macvlan gave the direct result exactly.
* Docker Desktop's user-space network stack answers for the remote host itself (its own docs, "How Docker Desktop Networking Works Under the
  Hood"): the packets never reach the target. That is recognised from the VM kernel (cveFeed.os_detection), not measured here.

The built-in scanner measures the first (the ``path_probe`` task kind): for a host whose closed TCP port is known (the fingerprint named one),
it sends a plain SYN (the control: a reset means the host and the path are alive) and the FIN+PSH+URG segment, and reports whether each drew a
reset. This module picks the addresses (``candidates``), sends them to the scanner through ``agentapi.sentinel_dispatch.try_path_probe``, and
reads the rows it reports (``verdict``). A path that answers the control and loses the odd segment on most hosts is one that cannot fingerprint.
Nothing is sent from the server itself. The verdict is cached (``cveFeed.os_detection``).
"""
import logging

logger = logging.getLogger(__name__)

MIN_HOSTS = 3          # hosts that answered the control before a verdict is given
LOST_SHARE = 0.75      # share of those that lost the odd probe at which the path is called interfering
CLEAN_SHARE = 0.25     # and the share at or below which it is called clean (in between: no verdict)
MAX_TARGETS = 8


def verdict(results):
    """``(state, answered, lost)``: ``direct`` when the hosts that answered the plain probe nearly all answered the odd one too,
    ``interfering`` when most did not, ``unknown`` with too few hosts or a split. Pure."""
    conclusive = [r for r in results if r['plain']]
    lost = sum(1 for r in conclusive if not r['odd'])
    if len(conclusive) < MIN_HOSTS:
        return 'unknown', len(conclusive), lost
    share = lost / len(conclusive)
    if share >= LOST_SHARE:
        return 'interfering', len(conclusive), lost
    if share <= CLEAN_SHARE:
        return 'direct', len(conclusive), lost
    return 'unknown', len(conclusive), lost


def in_scope(ip):
    """Whether some project may still have ``ip`` probed (``holder``)."""
    return holder(ip) is not None


def holder(ip):
    """The first project that may still have ``ip`` probed, or ``None``: a name of one of its targets that scans by itself (not manual only, not passive)
    resolves there, that name and the address are not excluded or archived, and the address passes the project's own scope
    (``scannable_hosts`` with the project: exclusions, archives, a bug bounty program's scope). The fingerprint that made the address a
    candidate says nothing about whether anyone may still be probed (security review 1.3.4, ssrf-1)."""
    from cveFeed.archive_rediscovery import archived_names
    from cveFeed.exclusions import excluded_names
    from startScan.models import Subdomain
    from targetApp.models import Domain
    from targetApp.target_types import scannable_hosts
    held = (Domain.DISCOVERY_MANUAL, Domain.DISCOVERY_PASSIVE)
    holders = {}
    rows = (Subdomain._base_manager.filter(ip_addresses__address=ip)
            .values_list('target_domain__project_id', 'target_domain__discovery_mode', 'scan_history__domain__project_id',
                         'scan_history__domain__discovery_mode', 'name')[:200])
    for project, mode, scan_project, scan_mode, name in rows:
        # the row's own target, else the target its scan ran for (a row stored before it had one)
        project, mode = (project, mode) if project else (scan_project, scan_mode)
        if project and mode not in held:
            holders.setdefault(project, set()).add(str(name).lower().rstrip('.'))
    for project, names in holders.items():
        banned = excluded_names(project) | archived_names(project)
        if ip not in banned and names - banned and scannable_hosts([ip], project=project):
            return project
    return None


def candidates(limit=MAX_TARGETS, days=14):
    """``[(ip, closed_port)]`` for up to ``limit`` addresses a scanner fingerprinted lately and that name a closed port, each from a
    different /16 (a path problem shows on any host; several networks rule out one host's own firewall). Only addresses the scanners
    may reach. The survey leaves from the scanner, so none of it is charged to this server's egress governor."""
    from datetime import timedelta

    from django.utils import timezone
    from django.utils.dateparse import parse_datetime

    from startScan.models import IpAddress
    from targetApp.target_types import is_scannable_ip
    since = timezone.now() - timedelta(days=days)
    seen, out = set(), []
    rows = IpAddress.objects.filter(fingerprint__has_key='closed_tcp').values_list('address', 'fingerprint')[:5000]
    fresh = []
    for ip, fingerprint in rows:
        at = parse_datetime(str((fingerprint or {}).get('closed_tcp_at') or ''))
        if at is not None and at >= since:
            fresh.append((at, ip, fingerprint))
    for at, ip, fingerprint in sorted(fresh, key=lambda row: row[0], reverse=True):
        port = fingerprint.get('closed_tcp')
        if not isinstance(port, int) or not 0 < port < 65536 or ':' in str(ip):
            continue
        network = '.'.join(str(ip).split('.')[:2])
        if network in seen or not is_scannable_ip(ip) or not in_scope(ip):
            continue
        seen.add(network)
        out.append((ip, port))
        if len(out) >= limit:
            break
    return out


def check():
    """Survey ``candidates()`` on a scanner and return ``{'state', 'answered', 'lost', 'hosts', 'vantage'}``, or ``{'state': 'unknown', 'why': ...}``
    when there is too little to probe or no scanner can take the work. The path that matters is the one the scans leave from: the survey is one task
    per project that holds the addresses (so no task names another tenant's address). Run by the built-in scanner, its verdict is this install's
    (``vantage`` ``scanner``, kept by ``os_detection.record_path``). With no built-in scanner the project's own Sentinels run it, and each one's rows
    are judged apart and kept as that Sentinel's own verdict (``os_detection.record_sentinel_path``): ``vantage`` ``sentinels``, ``sentinels``
    ``{agent id: state}``, and the install-wide verdict is left alone. It never runs here."""
    from agentapi import sentinel_dispatch
    from reNgine.resources import ScannerUnavailable
    targets = candidates()
    if len(targets) < MIN_HOSTS:
        return {'state': 'unknown', 'why': 'too few fingerprinted hosts to measure with', 'hosts': len(targets)}
    groups = {}
    for ip, port in targets:
        groups.setdefault(holder(ip), []).append((ip, port))
    groups.pop(None, None)  # out of scope since the candidates were listed
    try:
        rows = sentinel_dispatch.try_path_probe(groups)
    except ScannerUnavailable as exc:
        return {'state': 'unknown', 'why': f'no scanner could take this work ({exc.kind})', 'hosts': len(targets)}
    if rows is None:
        return {'state': 'unknown', 'why': 'no address is in scope of a project any more', 'hosts': len(targets)}
    by_sentinel = {}
    for row in rows:
        if row.get('sentinel') is not None:
            by_sentinel.setdefault(row['sentinel'], []).append(row)
    if by_sentinel:
        return _per_sentinel(by_sentinel, len(targets))
    state, answered, lost = verdict(rows)
    return {'state': state, 'answered': answered, 'lost': lost, 'hosts': len(targets), 'vantage': 'scanner'}


def _per_sentinel(by_sentinel, hosts):
    """Judge and keep the rows of each Sentinel that ran the survey as that Sentinel's verdict (``os_detection.record_sentinel_path``). The
    install-wide verdict is not touched: these rows describe the Sentinels' paths, not this install's."""
    from cveFeed import os_detection
    states = {}
    for agent_id, rows in by_sentinel.items():
        state, answered, lost = verdict(rows)
        kept = os_detection.record_sentinel_path(agent_id, {'state': state, 'answered': answered, 'lost': lost, 'hosts': len(rows)})
        states[str(agent_id)] = kept.get('state', 'unknown')
    return {'state': 'unknown', 'why': "measured on this install's own Sentinels, each one's path kept as its own", 'hosts': hosts,
            'vantage': 'sentinels', 'sentinels': states}
