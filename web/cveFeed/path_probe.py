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


def candidates(limit=MAX_TARGETS, days=14):
    """``[(ip, closed_port)]`` for up to ``limit`` addresses this server fingerprinted lately and that name a closed port, each from a
    different /16 (a path problem shows on any host; several networks rule out one host's own firewall). Only addresses the scanners
    may reach."""
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
        if network in seen or not is_scannable_ip(ip):
            continue
        seen.add(network)
        out.append((ip, port))
        if len(out) >= limit:
            break
    return out


def check(probe=send_probe):
    """Run the survey on ``candidates()`` and return ``{'state', 'answered', 'lost', 'hosts'}``, or ``{'state': 'unknown', 'why': ...}``
    when there is nothing to probe or raw sockets are not allowed."""
    targets = candidates()
    if len(targets) < MIN_HOSTS:
        return {'state': 'unknown', 'why': 'too few fingerprinted hosts to measure with', 'hosts': len(targets)}
    try:
        results = survey(targets, probe=probe)
    except RawSocketsUnavailable:
        return {'state': 'unknown', 'why': 'this process may not send raw packets', 'hosts': len(targets)}
    state, answered, lost = verdict(results)
    return {'state': state, 'answered': answered, 'lost': lost, 'hosts': len(targets)}
