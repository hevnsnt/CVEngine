"""Whether the network path this server scans from leaves a packet alone.

nmap's operating system detection sends sixteen probes, some of them deliberately malformed (a TCP segment with FIN, PSH and URG set, a
segment to a closed port with an odd option layout), and reads how the target's stack answers each. That only works if the probes arrive as
sent and the answers come back as sent. Two things in a container's path break it:

* Docker's default bridge network translates addresses with iptables and conntrack. A segment with an impossible flag combination is marked
  INVALID by conntrack, is not translated, leaves with the container's private source address, and its answer has nowhere to go. In a
  measured lab (nmap 7.94, the same target, once directly and once through a masquerading bridge) the FIN+PSH+URG probe to a closed port was
  answered directly and lost behind the NAT, the ``T7`` result changed from answered to not, and the top guess for a Linux host changed from
  "Linux 5.3 - 5.4 (97%)" to "HP P2000 G3 NAS device (93%)". Host networking and macvlan gave the direct result exactly.
* Docker Desktop's user-space network stack answers for the remote host itself (its own docs, "How Docker Desktop Networking Works Under the
  Hood"): the packets never reach the target. That is recognised from the VM kernel (cveFeed.os_detection), not measured here.

This module measures the first. For a host whose closed TCP port is known (nmap named one when it fingerprinted the host), it sends a plain
SYN (the control: a reset means the host and the path are alive) and the FIN+PSH+URG segment, and records whether each drew a reset. A path
that answers the control and loses the odd segment on most hosts is one that cannot fingerprint. The probe is the one nmap itself already
sends to every host it fingerprints, so it adds two packets to a host the scans reach anyway. The verdict is cached
(``cveFeed.os_detection``).
"""
import logging
import random
import select
import socket
import struct
import time

logger = logging.getLogger(__name__)

FIN, SYN, RST, PSH, URG = 0x01, 0x02, 0x04, 0x08, 0x20
ODD_FLAGS = FIN | PSH | URG  # nmap's T7 probe
MIN_HOSTS = 3          # hosts that answered the control before a verdict is given
LOST_SHARE = 0.75      # share of those that lost the odd probe at which the path is called interfering
CLEAN_SHARE = 0.25     # and the share at or below which it is called clean (in between: no verdict)
PROBE_TIMEOUT = 1.5
MAX_TARGETS = 8


class RawSocketsUnavailable(Exception):
    """This process may not send raw packets (no CAP_NET_RAW), or the platform has none."""


def _checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _source_address(target):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((target, 9))
        return sock.getsockname()[0]
    finally:
        sock.close()


def send_probe(target, port, flags, timeout=PROBE_TIMEOUT):
    """Send one TCP segment with ``flags`` to ``target:port`` and say whether a reset came back (True) or nothing did (False). IPv4 only.
    Raises RawSocketsUnavailable where raw sockets are not allowed."""
    source = _source_address(target)
    source_port = random.randint(40000, 60000)
    header = struct.pack('!HHLLBBHHH', source_port, port, random.getrandbits(32), 0, 5 << 4, flags, 1024, 0, 0)
    pseudo = socket.inet_aton(source) + socket.inet_aton(target) + struct.pack('!BBH', 0, socket.IPPROTO_TCP, len(header))
    header = header[:16] + struct.pack('!H', _checksum(pseudo + header)) + header[18:]
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except (PermissionError, OSError) as exc:
        raise RawSocketsUnavailable(str(exc)) from exc
    try:
        sock.sendto(header, (target, 0))
        end = time.monotonic() + timeout
        while True:
            left = end - time.monotonic()
            if left <= 0:
                return False
            ready, _, _ = select.select([sock], [], [], left)
            if not ready:
                return False
            packet = sock.recv(2048)
            ihl = (packet[0] & 0x0F) * 4
            if len(packet) < ihl + 14 or socket.inet_ntoa(packet[12:16]) != target:
                continue
            reply_source, reply_dest, _, _, _, reply_flags = struct.unpack('!HHLLBB', packet[ihl:ihl + 14])
            if reply_source == port and reply_dest == source_port and reply_flags & RST:
                return True
    finally:
        sock.close()


def survey(targets, probe=send_probe, pause=0.2, sleep=time.sleep):
    """``[{'ip', 'port', 'plain', 'odd'}]`` for ``targets`` (``[(ip, closed_port)]``): did the plain SYN and the odd segment each draw a
    reset. The odd segment is only sent where the plain one was answered. Stops with what it has when raw sockets are not allowed."""
    results = []
    for ip, port in targets:
        try:
            plain = probe(ip, port, SYN)
            odd = probe(ip, port, ODD_FLAGS) if plain else None
        except OSError as exc:  # a host that cannot be reached is not evidence
            logger.info('path probe: %s not probed: %s', ip, exc)
            continue
        results.append({'ip': ip, 'port': port, 'plain': plain, 'odd': odd})
        sleep(pause)
    return results


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


def candidates(limit=MAX_TARGETS, days=14, admit=True):
    """``[(ip, closed_port)]`` for up to ``limit`` addresses this server fingerprinted lately and that name a closed port, each from a
    different /16 (a path problem shows on any host; several networks rule out one host's own firewall). Only addresses the scanners
    may reach. ``admit`` puts each port through this server's own egress governor (``cveFeed.local_egress``); a survey a scanner runs leaves from the
    scanner, so it is not charged here."""
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
        from cveFeed import local_egress
        if admit and local_egress.admit_one(port, 'path-probe', ip):  # the opt-in skip list or the egress governor holds this port: another address is asked
            continue
        if admit:
            local_egress.record_one(port, 'path-probe', address=ip)
        seen.add(network)
        out.append((ip, port))
        if len(out) >= limit:
            break
    return out


def check(probe=None):
    """Run the survey on ``candidates()`` and return ``{'state', 'answered', 'lost', 'hosts'}``, or ``{'state': 'unknown', 'why': ...}``
    when there is nothing to probe or raw sockets are not allowed.

    The path that matters is the one the scans leave from: when the built-in scanner can take the ``path_probe`` kind, the survey runs there (one
    task per project that holds the addresses, so no task names another tenant's address) and ``vantage`` is ``scanner``; otherwise it runs
    here, as before (``vantage`` ``server``), when the kind may run here."""
    if probe is None:  # an injected probe (a test) is never second-guessed
        from agentapi import sentinel_dispatch
        from reNgine.resources import ScannerUnavailable
        targets = candidates(admit=False)
        if len(targets) >= MIN_HOSTS:
            groups = {}
            for ip, port in targets:
                groups.setdefault(holder(ip), []).append((ip, port))
            groups.pop(None, None)  # out of scope since the candidates were listed
            try:
                rows = sentinel_dispatch.try_path_probe(groups)
            except ScannerUnavailable as exc:
                return {'state': 'unknown', 'why': f'no scanner could take this work ({exc.kind})', 'hosts': len(targets)}
            if rows is not None:
                state, answered, lost = verdict(rows)
                return {'state': state, 'answered': answered, 'lost': lost, 'hosts': len(targets), 'vantage': 'scanner'}
    targets = candidates()
    if len(targets) < MIN_HOSTS:
        return {'state': 'unknown', 'why': 'too few fingerprinted hosts to measure with', 'hosts': len(targets)}
    try:
        results = survey(targets, probe=probe or send_probe)
    except RawSocketsUnavailable:
        return {'state': 'unknown', 'why': 'this process may not send raw packets', 'hosts': len(targets)}
    state, answered, lost = verdict(results)
    return {'state': state, 'answered': answered, 'lost': lost, 'hosts': len(targets), 'vantage': 'server'}
