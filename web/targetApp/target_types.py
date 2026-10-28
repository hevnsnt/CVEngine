"""Classify and expand CVEngine targets: domain / ip / cidr / range.

A target the user adds is one of:
  - domain   example.com
  - ip       203.0.113.10
  - cidr     10.0.0.0/24
  - range    192.168.1.1-192.168.2.1   (or last-octet shorthand 192.168.1.1-254)

Pure Python (no Django) so it is unit testable on its own.
"""
import contextlib
import contextvars
import ipaddress
import os
import re

DOMAIN = "domain"
IP = "ip"
CIDR = "cidr"
RANGE = "range"

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*"
    r"\.[A-Za-z][A-Za-z0-9-]{0,62}$"  # TLD must start with a letter (excludes 999.1.1.1)
)
_RANGE_RE = re.compile(r"^\s*([0-9.]+)\s*-\s*([0-9.]+)\s*$")


def classify_target(value):
    """Return 'domain' / 'ip' / 'cidr' / 'range', or None if unrecognized."""
    v = (value or "").strip()
    if not v:
        return None
    if "/" in v:
        try:
            ipaddress.ip_network(v, strict=False)
            return CIDR
        except ValueError:
            return None
    match = _RANGE_RE.match(v)
    if match:
        start, end = match.group(1), match.group(2)
        try:
            ipaddress.ip_address(start)
        except ValueError:
            return None
        if end.count(".") == 3:
            try:
                ipaddress.ip_address(end)
            except ValueError:
                return None
        elif not end.isdigit():
            return None
        return RANGE
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        pass
    else:
        # reject a zone/scope id ("fe80::1%eth0"): ipaddress accepts near-arbitrary text after the
        # '%' (and round-trips it straight back through str(), so a naive str(ip) == v check does
        # NOT catch it). This value ends up as a Domain.name and is later handed to nmap/bbot/nuclei
        # as a CLI argument, so anything with a scope id must be refused here.
        if getattr(ip, 'scope_id', None) is not None:
            return None
        return IP
    if _DOMAIN_RE.match(v):
        return DOMAIN
    return None


_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu", "ltd", "plc"}
_suffix_extractor = None


def apex_domain(name):
    """The registrable domain of a domain name: ``www.example.com`` -> ``example.com``, ``a.b.example.co.uk`` ->
    ``example.co.uk`` (via the public suffix list). None for anything that is not a domain name. tldextract is used with its
    bundled list only (no network); without it a small rule stands in: the last two labels, three after a two-letter
    country code that follows a generic second level (co.uk, com.au)."""
    global _suffix_extractor
    name = (name or "").strip().lower().rstrip(".")
    if classify_target(name) != DOMAIN:
        return None
    try:
        if _suffix_extractor is None:
            import tldextract
            _suffix_extractor = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
        parts = _suffix_extractor(name)
        return parts.top_domain_under_public_suffix or None
    except ImportError:
        labels = name.split(".")
        if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
            return ".".join(labels[-3:])
        return ".".join(labels[-2:])


def range_size(value):
    """Number of addresses in a range target without expanding it (0 if invalid)."""
    match = _RANGE_RE.match((value or "").strip())
    if not match:
        return 0
    start_s, end_s = match.group(1), match.group(2)
    try:
        start = ipaddress.ip_address(start_s)
        if end_s.count(".") == 3:
            end = ipaddress.ip_address(end_s)
        else:
            octets = start_s.split(".")
            octets[-1] = end_s
            end = ipaddress.ip_address(".".join(octets))
    except ValueError:
        return 0
    return max(0, int(end) - int(start) + 1)


def expand_range(value):
    """Expand 'A.B.C.D-E.F.G.H' or 'A.B.C.D-E' into a list of IP strings."""
    match = _RANGE_RE.match((value or "").strip())
    if not match:
        return []
    start_s, end_s = match.group(1), match.group(2)
    try:
        start = ipaddress.ip_address(start_s)
        if end_s.count(".") == 3:
            end = ipaddress.ip_address(end_s)
        else:  # last-octet shorthand
            octets = start_s.split(".")
            octets[-1] = end_s
            end = ipaddress.ip_address(".".join(octets))
    except ValueError:
        return []
    if int(end) < int(start):
        return []
    return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]


def expand_cidr(value, max_hosts=65536):
    """Expand a CIDR into host IP strings (capped at max_hosts)."""
    net = ipaddress.ip_network(value, strict=False)
    hosts = net.hosts() if net.num_addresses > 2 else iter(net)
    out = []
    for i, addr in enumerate(hosts):
        if i >= max_hosts:
            break
        out.append(str(addr))
    return out


def expand_target(value):
    """Return (target_type, [host strings]).

    Domains and single IPs return themselves; CIDR/range expand to host IPs.
    """
    target_type = classify_target(value)
    if target_type == CIDR:
        return target_type, expand_cidr(value)
    if target_type == RANGE:
        return target_type, expand_range(value)
    if target_type in (IP, DOMAIN):
        return target_type, [value.strip()]
    return None, []


# Addresses a scanner must never be pointed at on a user's say-so (or because a domain they control resolves
# there): loopback, link-local (cloud metadata 169.254.169.254), multicast and "this host". Internal ranges
# (RFC1918, CGNAT, unique-local) are refused too unless the operator opts in, because on a shared instance
# they are the server's own network. Documentation ranges are harmless and stay allowed.
_ALWAYS_BLOCKED = [ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "0.0.0.0/8",
    "192.0.0.0/24",        # IETF protocol assignments (Oracle Cloud metadata 192.0.0.192)
    "198.18.0.0/15",       # benchmarking
    "240.0.0.0/4",         # reserved, and 255.255.255.255
    "168.63.129.16/32",    # Azure wire server and DNS
    "100.100.100.200/32",  # Alibaba Cloud metadata (inside CGNAT, so also blocked when private targets are allowed)
    "::1/128", "fe80::/10", "fec0::/10", "ff00::/8", "::/96",  # ::/96 holds "::" and the old IPv4-compatible form
    "2001::/32",           # Teredo tunnels
    "64:ff9b:1::/48",      # local-use NAT64
    "fd00:ec2::/32",       # AWS IPv6 metadata (inside fc00::/7, so also blocked when private targets are allowed)
)]
_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                                "fc00::/7")]


def private_targets_allowed():
    return os.environ.get("CVENGINE_ALLOW_PRIVATE_TARGETS", "").strip().lower() in ("1", "true", "yes")


def _extra_blocked():
    nets = []
    for part in os.environ.get("CVENGINE_BLOCKED_CIDRS", "").split(","):
        try:
            nets.append(ipaddress.ip_network(part.strip(), strict=False)) if part.strip() else None
        except ValueError:
            continue
    return nets


_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_SIX_TO_FOUR = ipaddress.ip_network("2002::/16")


def _embedded_v4(ip):
    """The IPv4 address an IPv6 one carries (IPv4-mapped ::ffff:a.b.c.d, NAT64 64:ff9b::a.b.c.d, 6to4 2002:aabb:ccdd::), so the
    address a packet really reaches is the one judged; ``ip`` itself otherwise."""
    if ip.version != 6:
        return ip
    mapped = ip.ipv4_mapped
    if mapped is not None:
        return mapped
    if ip in _NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip in _SIX_TO_FOUR:
        return ipaddress.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF)
    return ip


def _tailnet_authorised(ip, project):
    """Whether ``ip`` is the tailnet address of a device a connected Tailscale integration imported for ``project`` (the device's
    target is named by that very address; see cveFeed.tailscale_scope). Only consulted for an address that would otherwise be
    refused as internal; a lookup problem means "no"."""
    try:
        from cveFeed import tailscale_scope
        return tailscale_scope.is_authorised(ip, project)
    except Exception:  # noqa: BLE001 - the answer is the safe one when the table cannot be read
        return False


def is_scannable_ip(value, allow_private=None, project=None):
    """True if it is safe to point a scanner at this IP address. Any text that is not an IP is False.

    An internal address is also allowed when ``project`` (an id) is given and the address is the tailnet address of a device a
    connected Tailscale integration imported for that very project, because connecting the tailnet is what authorised it. Without a
    project there is no such authority, so every caller that does not know the project that owns the target, every address a DNS name
    resolved to and every address a person typed is refused as before. An address that was unwrapped from a mapped, NAT64 or 6to4
    form never gets it. Loopback, link-local and metadata addresses stay refused either way."""
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    if getattr(ip, "scope_id", None) is not None:
        return False
    original = ip
    ip = _embedded_v4(ip)
    if any(ip.version == n.version and ip in n for n in _ALWAYS_BLOCKED + _extra_blocked()):
        return False
    if allow_private is None:
        allow_private = private_targets_allowed()
    if not allow_private and any(ip.version == n.version and ip in n for n in _INTERNAL):
        return project is not None and ip is original and _tailnet_authorised(ip, project)
    return True


MAX_INTERNAL_RANGE_ADDRESSES = 65536  # one declared range may cover at most a /16 (IPv4) or a /112 (IPv6): the same as one target may expand to


def clean_internal_cidr(value):
    """The canonical network a project may declare as an internal range, or ``ValueError`` saying why not. It must sit entirely inside
    the private space the gate refuses (RFC1918, CGNAT, unique-local), so declaring a range can never open a public address, and
    must not touch the always-blocked ranges (loopback, link-local, metadata): CGNAT holds two metadata addresses, so a range
    covering one is refused rather than trimmed. Host bits must be zero, so what is stored is what was meant."""
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=True)
    except ValueError:
        raise ValueError('not a network in CIDR form with no host bits set (for example 10.20.0.0/24)')
    if net.num_addresses > MAX_INTERNAL_RANGE_ADDRESSES:
        raise ValueError(f'covers {net.num_addresses} addresses; the most one range may cover is {MAX_INTERNAL_RANGE_ADDRESSES}')
    if not any(net.version == n.version and net.subnet_of(n) for n in _INTERNAL):
        raise ValueError('only private ranges can be declared internal (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, fc00::/7)')
    if any(net.version == n.version and net.overlaps(n) for n in _ALWAYS_BLOCKED + _extra_blocked()):
        raise ValueError('overlaps a range that is never scanned (loopback, link-local, cloud metadata)')
    return str(net)


def internal_networks(project):
    """The networks ``project`` (an id) declared internal, as ``ip_network`` objects. A lookup problem means "none"."""
    if not project:
        return []
    try:
        from cveFeed.models import InternalRange
        return [ipaddress.ip_network(c, strict=False) for c in InternalRange.objects.filter(project_id=project).values_list("cidr", flat=True)]
    except Exception:  # noqa: BLE001 - the answer is the safe one when the table cannot be read
        return []


def in_internal_range(value, networks):
    """Whether ``value`` is an address inside one of ``networks`` (from ``internal_networks``) and is still a clean one: not an
    address unwrapped from a mapped, NAT64 or 6to4 form, and not in an always-blocked range. This says an address MAY BE ADDED as a
    target of the project; it never makes it scannable from this server (``is_scannable_ip`` is unchanged and still refuses it)."""
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    if getattr(ip, "scope_id", None) is not None or _embedded_v4(ip) is not ip:
        return False
    if any(ip.version == n.version and ip in n for n in _ALWAYS_BLOCKED + _extra_blocked()):
        return False
    return any(ip.version == n.version and ip in n for n in networks)


_INTERNAL_SCOPE = contextvars.ContextVar("cvengine_internal_scope", default=False)


@contextlib.contextmanager
def internal_scope():
    """While active, the scan stages may treat an address of a network the project declared internal as a target (``scan_targets``), and
    every local scanner refuses to run (``refuse_local``). Used only by ``cveFeed.internal_scan``, whose every step is a Sentinel's."""
    token = _INTERNAL_SCOPE.set(True)
    try:
        yield
    finally:
        _INTERNAL_SCOPE.reset(token)


def internal_scope_active():
    return _INTERNAL_SCOPE.get()


def refuse_local(what):
    """Raise when ``what`` (a local scanner) is about to run inside ``internal_scope``: an internal scan never executes a tool from this
    server, so a stage that forgot its Sentinel seam fails loudly instead of connecting to a private address from here."""
    if _INTERNAL_SCOPE.get():
        raise RuntimeError(f"{what} must not run from this server for an internal target: only a Sentinel inside the network scans it")


def sentinel_only_target(name, project, networks=None):
    """Whether the target ``name`` of ``project`` (an id) is an address inside a network the project declared internal that this server
    may not scan itself: only a Sentinel inside the network ever scans it. ``networks`` (from ``internal_networks``) saves the lookup
    when asking about many targets of one project. An address a connected tailnet or the operator's private-targets switch already makes
    scannable here is not "Sentinel only"."""
    nets = internal_networks(project) if networks is None else networks
    return bool(nets) and in_internal_range(name, nets) and not is_scannable_ip(name, project=project)


RESOLVE_TIMEOUT = 5  # seconds one name may take to answer; names come from DNS the target owner controls
RESOLVE_WORKERS = 16
RESOLVE_BATCH_SECONDS = 120  # the most a whole list of names may take


def _literal_ip(value):
    """``value`` as an address string when it is one (an IP literal, bracketed or not), else None."""
    try:
        return str(ipaddress.ip_address(str(value).strip().strip('[]')))
    except ValueError:
        return None


def _lookup_blocked(hostname):
    import socket
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    return any(not is_scannable_ip(info[4][0]) for info in infos)  # an answer from DNS is never tailnet authority: no project is passed


def resolves_to_blocked(hostname, timeout=RESOLVE_TIMEOUT, project=None):
    """True if ``hostname`` currently resolves to any address a scanner must not touch. A name that does not exist is not blocked:
    the scanners cannot reach it either. A name whose nameserver does not answer within ``timeout`` seconds is treated as blocked,
    because a nameserver that stalls the check and then answers the scanner with an internal address would otherwise get through;
    the host is checked again on the next pass. (Resolution can change between this check and the scan, so this narrows the
    DNS-rebinding window rather than closing it; the IPs are re-filtered when stored.) A name that is an address is judged as that address,
    with ``project`` as its possible tailnet authority; an address a name resolves to never has any."""
    import threading
    literal = _literal_ip(hostname)
    if literal is not None:  # an address presented as itself: no lookup, and no thread (the tailnet check reads the database)
        return not is_scannable_ip(literal, project=project)
    answer = []
    worker = threading.Thread(target=lambda: answer.append(_lookup_blocked(hostname)), daemon=True)
    worker.start()
    worker.join(timeout)
    return not answer or bool(answer[0])


def blocked_names(names, workers=RESOLVE_WORKERS, budget=RESOLVE_BATCH_SECONDS, timeout=RESOLVE_TIMEOUT, project=None):
    """The subset of ``names`` that resolves to something a scanner must not touch. Names are looked up in parallel, each bounded
    by ``timeout`` and the whole list by ``budget`` seconds, so thousands of names with dead nameservers cannot hold a worker for
    hours; a name still unanswered at the deadline counts as blocked, as in resolves_to_blocked. A name that is an address is judged
    in this thread (``project`` may authorise a tailnet one); only real names go to the pool, which never touches the database."""
    import time
    from concurrent.futures import ThreadPoolExecutor
    names = list(dict.fromkeys(names))
    literals = {name for name in names if _literal_ip(name) is not None}
    blocked = {name for name in literals if resolves_to_blocked(name, project=project)}
    names = [name for name in names if name not in literals]
    if not names:
        return blocked
    pool = ThreadPoolExecutor(max_workers=max(1, min(workers, len(names))), thread_name_prefix='dnscheck')
    futures = {name: pool.submit(resolves_to_blocked, name) for name in names}  # each bounded by RESOLVE_TIMEOUT itself
    deadline = time.monotonic() + budget
    for name, future in futures.items():
        try:
            if future.result(timeout=max(0.0, min(timeout * (1 + len(names) // max(1, workers)), deadline - time.monotonic()))):
                blocked.add(name)
        except Exception:  # noqa: BLE001 - a lookup that runs out of time is "blocked" (not verified), like resolves_to_blocked
            blocked.add(name)
    pool.shutdown(wait=False, cancel_futures=True)
    return blocked


def bare_host(value):
    """The hostname or address inside a target string: "host", "host:8443", "https://host:8443/path", "[::1]:443"."""
    text = str(value or "").strip().lower().split("://", 1)[-1].split("/", 1)[0]
    if text.startswith("["):
        return text[1:].split("]", 1)[0]
    return text.rsplit(":", 1)[0] if text.count(":") == 1 else text


def scannable_hosts(names, resolver=None, project=None):
    """The entries of ``names`` (hosts, host:port, URLs) a scanner may be pointed at, in order, without repeats. An address must pass
    is_scannable_ip; a name must not resolve to anything blocked (resolves_to_blocked, once per distinct name). Every path that
    aims a scanner at a stored host list (auto-fire, CVE re-tests, TLS checks) goes through this, because a name a tenant controls
    can be pointed at 169.254.169.254 or an internal range after it was stored. ``resolver`` replaces the DNS check in tests.
    ``project`` (an id) also drops every host its organization excluded for good (cveFeed.exclusions: the exact name only)."""
    names = list(names)
    if resolver:
        check = resolver
    else:  # one parallel, bounded pass over the distinct names, then a lookup in the result
        blocked = blocked_names([bare_host(n) for n in names if bare_host(n) and classify_target(bare_host(n)) != IP])
        check = blocked.__contains__
    banned = frozenset()
    if project:
        from cveFeed.exclusions import excluded_names
        from cveFeed.archive_rediscovery import archived_names
        banned = excluded_names(project) | archived_names(project)
    verdict, out, seen = {}, [], set()
    for entry in names:
        if entry in seen:
            continue
        seen.add(entry)
        host = bare_host(entry)
        if not host or host.rstrip('.') in banned:
            continue
        if host not in verdict:
            if classify_target(host) == IP:
                verdict[host] = is_scannable_ip(host, project=project or None)
            else:
                verdict[host] = not check(host)
        if verdict[host]:
            out.append(entry)
    return out
