"""Hosts an organization has excluded for good ("Remove & exclude"), the addresses it must never have scanned, and the checks every discovery and scan path shares.

A host is excluded for a project when its organization holds a HostExclusion with the SAME name. The match is the whole
name, lowercase: excluding ``provider.example`` does not touch ``notprovider.example`` (never a substring or a bare suffix).
An exclusion made with ``include_subdomains`` (``-provider.example`` in Add targets) also covers every name under it, on a dot
boundary: ``www.provider.example`` and ``a.b.provider.example``, still never ``notprovider.example``.

Everything here is read through the project's own org, so one org's list never reaches another's scans. A project without
an org has no exclusions. All the NAME checks are non-fatal: if the lookup fails, nothing is excluded (the owner's explicit
deletion has already removed the data; the lookup only prevents it from coming back).

The ADDRESS list (``ExcludedAddress``, "addresses we must never scan") is the opposite: a name list cannot protect an address, and a list that
cannot be read must not let work through. ``address_excluded`` is the ONE decision function for it: it covers an address inside a listed network
and a host name whose resolved addresses (the inventory's stored ones, plus any result a task resolved itself) fall inside one, and it answers
a ``Refusal`` (a ``str`` with ``.unreadable``) for an excluded match AND for a list that could not be read (fail closed, with the reason). The
set ``excluded_names`` returns carries the same rule (``name in set``), so every scan path that already asks it is address-aware; the sites
that decide what the INVENTORY keeps pass ``names_only=True`` (an address-excluded host stays visible, with the reason it is not scanned).
"""
import ipaddress
import logging

logger = logging.getLogger(__name__)

MAX_HOST_LENGTH = 500
MAX_ENTRIES = 500  # the most addresses or networks one organization may list
MIN_V4_PREFIX, MIN_V6_PREFIX = 8, 32  # a broader network needs ``confirm_broad`` (0.0.0.0/0 and ::/0 are never accepted)
MAX_ENTRY_LENGTH = 64
UNREADABLE = ("the organization's do-not-scan address list could not be read, so nothing that touches an address runs for this project "
              'until it can be (nothing was scanned)')


def normalize(value):
    """The comparable form of a host: a bare lowercase name, without scheme, port, path or trailing dot. '' if empty."""
    from targetApp.target_types import bare_host
    return bare_host(value).strip().rstrip('.')[:MAX_HOST_LENGTH]


class Refusal(str):
    """Why work for an address was refused. ``unreadable`` is True when the cause is a list that could not be read (not a match)."""

    def __new__(cls, text, unreadable=False, entry=''):
        self = super().__new__(cls, text)
        self.unreadable, self.entry = unreadable, entry
        return self


def as_address(value):
    """The ``ip_address`` of ``value`` (a bare literal, ``[v6]:port``, ``v4:port``, a URL), or None. An IPv4-mapped IPv6 address is its IPv4 address."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    for candidate in (text, normalize(text)):
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        return ip.ipv4_mapped or ip if ip.version == 6 else ip
    return None


def parse_entry(text, confirm_broad=False):
    """``(network, None)`` for a list entry (an address, or an address/prefix; host bits are cleared), or ``(None, why)``. Private ranges are valid.
    0.0.0.0/0 and ::/0 are never accepted; a network broader than /8 (v4) or /32 (v6) needs ``confirm_broad``."""
    if not isinstance(text, str) or not text.strip():
        return None, 'enter an address or a network such as 198.51.100.0/24'
    text = text.strip()
    if len(text) > MAX_ENTRY_LENGTH:
        return None, f'an entry is at most {MAX_ENTRY_LENGTH} characters'
    try:
        net = ipaddress.ip_network(text if '/' in text else text.strip('[]'), strict=False)
    except ValueError:
        return None, f'{text[:60]!r} is not an IPv4 or IPv6 address or network (a host name belongs on the excluded hosts list)'
    if net.version == 6 and net.network_address.ipv4_mapped is not None and net.prefixlen >= 96:
        net = ipaddress.ip_network((net.network_address.ipv4_mapped, net.prefixlen - 96), strict=False)
    if net.prefixlen == 0:
        return None, 'that would exclude the whole internet, so it is never accepted'
    floor = MIN_V4_PREFIX if net.version == 4 else MIN_V6_PREFIX
    if net.prefixlen < floor and not confirm_broad:
        return None, f'/{net.prefixlen} is a very large network (broader than /{floor}); confirm it to add it'
    return net, None


def _networks_of(rows):
    out = []
    for cidr in rows:
        try:
            out.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue  # cannot happen through the editor; one unparseable stored row never hides the rest
    return tuple(out)


def _containing(networks, ip):
    return next((net for net in networks if ip.version == net.version and ip in net), None)


class ExclusionSet(frozenset):
    """The names an organization excluded: ``name in excluded`` is true for an excluded name and for any name under an excluded
    domain (one made with ``include_subdomains``). A frozenset of the exact names, so every existing ``in`` check keeps working;
    ``|`` keeps the subdomain rules.

    Address awareness: ``networks`` are the do-not-scan networks, so an address literal inside one is ``in`` the set; the names whose stored
    addresses fall inside one are members of the set itself (``by_address``: a name test, an SQL ``NOT IN`` and an iteration all see them). When the
    address list could not be read, ``unreadable`` is True and EVERYTHING is ``in`` the set (fail closed: nothing is scanned until it can be read)."""

    def __new__(cls, names=(), subtrees=(), networks=(), by_address=(), unreadable=False):
        self = super().__new__(cls, frozenset(names) | frozenset(by_address))
        self.subtrees = frozenset(subtrees)
        self.networks, self.by_address, self.unreadable = tuple(networks), frozenset(by_address), bool(unreadable)
        return self

    def __bool__(self):
        return bool(len(self) or self.networks or self.unreadable)

    def __contains__(self, name):
        if self.unreadable:
            return True
        if super().__contains__(name):
            return True
        if not isinstance(name, str):
            return False
        if self.networks:
            ip = as_address(name)
            if ip is not None:
                return _containing(self.networks, ip) is not None
        if not self.subtrees:
            return False
        name = name.strip().lower().rstrip('.')
        while '.' in name:
            name = name.split('.', 1)[1]
            if name in self.subtrees:
                return True
        return False

    def __or__(self, other):
        return ExclusionSet(frozenset(self) | frozenset(other), self.subtrees | getattr(other, 'subtrees', frozenset()),
                            self.networks + tuple(n for n in getattr(other, 'networks', ()) if n not in self.networks),
                            self.by_address | getattr(other, 'by_address', frozenset()), self.unreadable or getattr(other, 'unreadable', False))

    def __ror__(self, other):
        return self.__or__(other)


def address_networks(project_id):
    """The do-not-scan networks of the project's org, a tuple of ip_network. Raises when the list cannot be read (the callers fail closed)."""
    if not project_id:
        return ()
    from cveFeed.models import ExcludedAddress
    return _networks_of(ExcludedAddress.objects.filter(org__projects__id=project_id).values_list('cidr', flat=True))


def stored_addresses(project_id, names):
    """``{name: [ip_address, ...]}``: the addresses the inventory holds for each of ``names`` in the project (what it last resolved to). One query."""
    from django.db.models import F
    from django.db.models.functions import Lower
    from startScan.models import IpAddress
    wanted = {normalize(n) for n in names} - {''}
    out = {}
    if not wanted:
        return out
    rows = (IpAddress.objects.filter(ip_addresses__target_domain__project_id=project_id).annotate(host=Lower(F('ip_addresses__name')))
            .filter(host__in=wanted).values_list('host', 'address').distinct())
    for host, address in rows:
        ip = as_address(address)
        if ip is not None:
            out.setdefault(host.rstrip('.'), []).append(ip)
    return out


def _names_resolving_into(project_id, networks):
    """The inventory names of the project with a stored address inside ``networks`` (two queries: the distinct addresses, then the names)."""
    from startScan.models import IpAddress, Subdomain
    seen = IpAddress.objects.filter(ip_addresses__target_domain__project_id=project_id).values_list('address', flat=True).distinct()
    bad = [a for a in seen if a and (ip := as_address(a)) is not None and _containing(networks, ip)]
    if not bad:
        return set()
    names = Subdomain.objects.filter(target_domain__project_id=project_id, ip_addresses__address__in=bad).values_list('name', flat=True)
    return {n.strip().lower().rstrip('.') for n in names}


def address_refusals(project_id, values, resolved=None, networks=None):
    """``{value: Refusal}`` for each of ``values`` (addresses, ``host:port``, URLs, host names) that must not be worked on for this project: THE rule of the
    do-not-scan list, for one value or a whole task (the lookups are batched, not per name). A value inside a listed network is refused, and so is a name
    with a stored address inside one, or one that ``resolved`` (``{name: [addresses]}``, what a task resolved the name to itself) places inside one.
    Fails closed: a list that cannot be read refuses EVERY value, with a ``Refusal`` whose ``unreadable`` is set. A project without an org has no list."""
    values = [v for v in values if isinstance(v, str) and v.strip()]
    if not project_id or not values:
        return {}
    try:
        networks = address_networks(project_id) if networks is None else networks  # ``networks``: a caller that already read the list for this project
    except Exception:  # noqa: BLE001 - fail closed: never let work through on a list that was not read
        logger.warning('could not read the do-not-scan address list for project %s', project_id, exc_info=True)
        return {v: Refusal(UNREADABLE, unreadable=True) for v in values}
    if not networks:
        return {}
    out, names = {}, {}
    for value in values:
        ip = as_address(value)
        if ip is not None:
            net = _containing(networks, ip)
            if net:
                out[value] = Refusal(f"{ip} is on the organization's do-not-scan list ({net})", entry=str(net))
        elif normalize(value):
            names[value] = normalize(value)
    if names:
        try:
            known = stored_addresses(project_id, names.values())
        except Exception:  # noqa: BLE001
            logger.warning('could not read the stored addresses of the hosts of project %s', project_id, exc_info=True)
            return {**out, **{v: Refusal(UNREADABLE, unreadable=True) for v in names}}
        for value, name in names.items():
            told = [a for a in (as_address(r) for r in (resolved or {}).get(name, ())) if a is not None]
            for ip in told + known.get(name, []):
                net = _containing(networks, ip)
                if net:
                    out[value] = Refusal(f"{name} resolves to {ip}, which is on the organization's do-not-scan list ({net})", entry=str(net))
                    break
    return out


def address_excluded(project_id, value, resolved=()):
    """The ONE decision for one value: a ``Refusal`` (why) when work for ``value`` must not run for this project, else None (``address_refusals`` is the same
    rule for many). ``resolved`` is what a task resolved the name to itself (addresses). Fails closed on an unreadable list (``.unreadable``)."""
    return address_refusals(project_id, [value], {normalize(value): list(resolved)} if resolved else None).get(value)


def excluded_names(project_id, strict=False, names_only=False):
    """The ExclusionSet of lowercase names excluded for ``project_id`` (its org's list, plus the hosts moved out of the project), made address-aware
    (the do-not-scan networks, and the inventory names that resolve into them) unless ``names_only``: the sites that decide what the INVENTORY keeps ask
    for names only, so an address-excluded host stays visible. Empty for no project or no org. ``strict`` lets a failed NAME lookup raise (an
    authorization check must stop, not carry on with nothing excluded); a failed ADDRESS lookup always fails closed (``unreadable``: everything is in the set)."""
    if not project_id:
        return ExclusionSet()
    from cveFeed.models import HostExclusion, HostMove
    try:
        rows = list(HostExclusion.objects.filter(org__projects__id=project_id).values_list('host', 'include_subdomains'))
        # a host moved out of this project into another stays out of this one (exact name), whatever its org's list says
        rows += [(host, False) for host in HostMove.objects.filter(project_id=project_id).values_list('host', flat=True)]
    except Exception:  # noqa: BLE001 - never let a lookup problem stop discovery
        if strict:
            raise
        logger.warning('could not read the host exclusions for project %s', project_id, exc_info=True)
        rows = []
    networks, by_address, unreadable = (), (), False
    if not names_only:
        try:
            networks = address_networks(project_id)
            by_address = _names_resolving_into(project_id, networks) if networks else ()
        except Exception:  # noqa: BLE001 - fail closed
            logger.warning('could not read the do-not-scan address list for project %s', project_id, exc_info=True)
            unreadable = True
    return ExclusionSet((host for host, _ in rows), (host for host, subtree in rows if subtree), networks, by_address, unreadable)


def covers(pattern, name, subtree):
    """Whether the exclusion ``pattern`` (made with or without ``include_subdomains``) covers ``name``."""
    name = normalize(name)
    return name == pattern or bool(subtree and name.endswith('.' + pattern))


def is_excluded(project_id, host, names_only=False):
    """Whether ``host`` (any case; a URL or host:port is reduced to its name) is excluded for the project's org. An address literal, and a name that
    resolves into the do-not-scan list, count unless ``names_only``."""
    name = normalize(host)
    return bool(name) and name in excluded_names(project_id, names_only=names_only)


def drop_excluded(project_id, names, names_only=False):
    """``names`` (a list, in order) without the excluded ones. One query."""
    names = list(names)
    banned = excluded_names(project_id, names_only=names_only)
    if not banned:
        return names
    return [n for n in names if normalize(n) not in banned]


def org_id_of(project_id):
    from dashboard.models import Project
    return Project._base_manager.filter(pk=project_id).values_list('org_id', flat=True).first()
