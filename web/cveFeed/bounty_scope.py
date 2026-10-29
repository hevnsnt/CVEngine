"""Is this host inside a bug bounty program's scope?

The most expensive mistake in bug bounty is testing or reporting something that is out of scope: programs refuse the report, platforms
subtract reputation, and repeat offenders lose access (Bugcrowd's reporting guide says so in as many words). This module answers
the question for one host against one program's scope entries, and is deliberately cautious.

States
  in_scope       a scope entry names the host (exactly, or through a wildcard)
  out_of_scope   an out-of-scope entry names the host or one of its parents; this beats every in-scope entry
  ambiguous      probably in scope but not provably: the apex of an in-scope wildcard (``*.example.com`` does not name
                 ``example.com``), a host named only with a path restriction, a pattern entry (``api-*.example.com``), or a
                 program whose scope is described in prose. The policy text decides; a person must confirm
  not_listed     nothing in the program's scope names it

A host is reportable on in_scope; on ambiguous only after the user confirms the policy. Pure functions, no database.
"""
import fnmatch
import ipaddress

from cveFeed.bounty_data import HOST_RE, _strip_url

IN, OUT, AMBIGUOUS, NOT_LISTED = "in_scope", "out_of_scope", "ambiguous", "not_listed"
STATES = (IN, OUT, AMBIGUOUS, NOT_LISTED)
MAX_IMPORT_HOSTS_PER_CIDR = 64


def _get(asset, key, default=None):
    return asset.get(key, default) if isinstance(asset, dict) else getattr(asset, key, default)


class Verdict:
    __slots__ = ("state", "reason", "asset", "eligible_for_bounty", "max_severity")

    def __init__(self, state, reason, asset=None):
        self.state, self.reason, self.asset = state, reason, _get(asset, "identifier", "") if asset is not None else ""
        self.eligible_for_bounty = _get(asset, "eligible_for_bounty") if asset is not None else None
        self.max_severity = _get(asset, "max_severity", "") if asset is not None else ""

    def as_dict(self):
        return {"state": self.state, "reason": self.reason, "asset": self.asset,
                "eligible_for_bounty": self.eligible_for_bounty, "max_severity": self.max_severity}

    @property
    def reportable(self):
        return self.state == IN

    @property
    def needs_confirmation(self):
        return self.state == AMBIGUOUS


def parse_host(value):
    """``("ip", address)``, ``("domain", name)`` or None for a host name, IP address or URL."""
    text = str(value or "").strip()
    if not text or len(text) > 2000:
        return None
    host, _ = _strip_url(text)
    if not host:
        return None
    try:
        return "ip", str(ipaddress.ip_address(host))
    except ValueError:
        pass
    return ("domain", host) if HOST_RE.match(host) else None


class ScopeIndex:
    """One program's scope entries, indexed for host lookups. ``assets`` are rows or dicts with kind, identifier, in_scope,
    eligible_for_bounty and max_severity; removed entries (``removed_at`` set) are ignored."""

    def __init__(self, assets):
        self.in_domains, self.out_domains = {}, {}
        self.in_wild, self.out_wild = {}, {}
        self.in_urls, self.in_nets, self.out_nets = {}, [], []
        self.in_ips, self.out_ips = {}, {}
        self.in_patterns, self.out_patterns = [], []
        self.prose = False
        self.entries = 0
        for a in assets:
            if _get(a, "removed_at"):
                continue
            kind, ident, inside = _get(a, "kind"), (_get(a, "identifier") or "").lower() if _get(a, "kind") != "url" else _get(a, "identifier"), bool(_get(a, "in_scope"))
            self.entries += 1
            if kind == "domain":
                (self.in_domains if inside else self.out_domains)[ident] = a
            elif kind == "wildcard":
                (self.in_wild if inside else self.out_wild)[ident[2:]] = a
            elif kind == "url":
                host, _, path = ident.partition("/")
                if inside:
                    self.in_urls.setdefault(host.lower(), []).append(a)
                else:
                    self.out_domains.setdefault(host.lower(), a) if not path else None
            elif kind == "ip":
                (self.in_ips if inside else self.out_ips)[ident] = a
            elif kind == "cidr":
                try:
                    (self.in_nets if inside else self.out_nets).append((ipaddress.ip_network(ident, strict=False), a))
                except ValueError:
                    continue
            elif kind == "other" and inside:
                if "*" in ident:
                    self.in_patterns.append((ident, a))
                elif ident:
                    self.prose = True  # "all", a paragraph, a name: the real scope is in the program text
            elif kind == "other":
                if "*" in ident:
                    self.out_patterns.append((ident, a))

    def check(self, value):
        parsed = parse_host(value)
        if parsed is None:
            return Verdict(NOT_LISTED, "not a host name or IP address")
        kind, host = parsed
        return self._check_ip(host) if kind == "ip" else self._check_domain(host)

    def _check_ip(self, host):
        addr = ipaddress.ip_address(host)
        if host in self.out_ips:
            return Verdict(OUT, f"{host} is listed as out of scope", self.out_ips[host])
        for net, a in self.out_nets:
            if addr in net:
                return Verdict(OUT, f"{host} is inside the out-of-scope range {net}", a)
        if host in self.in_ips:
            return Verdict(IN, f"{host} is listed", self.in_ips[host])
        inside = [(net, a) for net, a in self.in_nets if addr in net]
        if inside:
            net, a = max(inside, key=lambda x: x[0].prefixlen)
            return Verdict(IN, f"{host} is inside the in-scope range {net}", a)
        if self.prose:
            return Verdict(AMBIGUOUS, "the program describes part of its scope in text; confirm in the policy")
        return Verdict(NOT_LISTED, f"{host} is not in any listed range")

    def _check_domain(self, host):
        labels = host.split(".")
        for i in range(len(labels)):  # an out-of-scope host also rules out everything under it: its own name and each parent
            suffix = ".".join(labels[i:])
            if suffix in self.out_domains:
                return Verdict(OUT, f"{suffix} is listed as out of scope", self.out_domains[suffix])
            if suffix in self.out_wild:
                return Verdict(OUT, f"*.{suffix} is listed as out of scope", self.out_wild[suffix])
        for pat, a in self.out_patterns:
            if fnmatch.fnmatchcase(host, pat):
                return Verdict(OUT, f"{pat} is listed as out of scope", a)
        if host in self.in_domains:
            return Verdict(IN, f"{host} is listed", self.in_domains[host])
        if host in self.in_urls:
            only = sorted({x for a in self.in_urls[host] for x in [_get(a, "identifier").partition("/")[2]] if x})
            whole = any(not _get(a, "identifier").partition("/")[2] for a in self.in_urls[host])
            if whole:
                return Verdict(IN, f"{host} is listed", self.in_urls[host][0])
            return Verdict(AMBIGUOUS, "the scope names this host only with a path (" + ", ".join("/" + p for p in only[:3]) + ")",
                           self.in_urls[host][0])
        best = None
        for base, a in self.in_wild.items():
            if host.endswith("." + base) and (best is None or len(base) > len(best[0])):
                best = (base, a)
        if best:
            return Verdict(IN, f"*.{best[0]} is listed", best[1])
        if host in self.in_wild:
            return Verdict(AMBIGUOUS, f"*.{host} is listed but a wildcard does not name {host} itself; check the policy", self.in_wild[host])
        for pat, a in self.in_patterns:
            if fnmatch.fnmatchcase(host, pat):
                return Verdict(AMBIGUOUS, f"{host} matches the pattern entry {pat}, which this tool does not interpret", a)
        for d in self.in_domains:
            if host.endswith("." + d):
                return Verdict(NOT_LISTED, f"only {d} is listed, not its subdomains (that would need a wildcard)", self.in_domains[d])
        if self.prose:
            return Verdict(AMBIGUOUS, "the program describes part of its scope in text; confirm in the policy")
        return Verdict(NOT_LISTED, f"{host} is not named by the program's scope")


def import_plan(assets, scannable=lambda host: True):
    """What importing a program's scope as targets would do: ``{'targets': [...], 'skipped': [...]}``. Only in-scope entries are
    considered. A wildcard becomes its base domain (discovery then finds the subdomains, and the scope check keeps the apex and
    anything out of scope from being reported). A URL becomes its host. A CIDR block becomes its addresses when it is small
    (at most 64 addresses); a larger one is skipped with the reason, because a scan of it is not a decision to take silently.
    Nothing here touches the network."""
    targets, skipped, seen = [], [], set()

    def add(value, ident, note=""):
        if value in seen:
            return
        seen.add(value)
        targets.append({"value": value, "asset": ident, "note": note})

    named = {(_get(a, "identifier") or "").partition("/")[0] for a in assets
             if _get(a, "kind") in ("domain", "url") and _get(a, "in_scope") and not _get(a, "removed_at")}
    for a in assets:
        if _get(a, "removed_at") or not _get(a, "in_scope"):
            continue
        kind, ident = _get(a, "kind"), _get(a, "identifier")
        if kind == "wildcard" and ident[2:] in named:
            continue  # an entry that names the host itself wins over a wildcard's base, whatever order they come in
        if kind == "domain":
            add(ident, ident)
        elif kind == "wildcard":
            add(ident[2:], ident, "wildcard: subdomains are discovered; the apex itself is flagged for confirmation")
        elif kind == "url":
            add(ident.partition("/")[0], ident, "the scope names a path on this host" if "/" in ident else "")
        elif kind == "ip":
            if scannable(ident):
                add(ident, ident)
            else:
                skipped.append({"asset": ident, "reason": "not a public address this scanner may touch"})
        elif kind == "cidr":
            net = ipaddress.ip_network(ident, strict=False)
            if net.num_addresses > MAX_IMPORT_HOSTS_PER_CIDR:
                skipped.append({"asset": ident, "reason": f"{net.num_addresses} addresses; add the hosts you mean to test"})
                continue
            for ip in net.hosts() if net.num_addresses > 2 else net:
                if scannable(str(ip)):
                    add(str(ip), ident)
        else:
            skipped.append({"asset": ident, "reason": {"mobile": "a mobile app is not a scan target", "code": "source code is not a scan target"}
                            .get(kind, "scope that is described in text or by a pattern: add the hosts you mean to test")})
    return {"targets": targets, "skipped": skipped}
