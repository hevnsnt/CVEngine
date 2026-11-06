"""The scope policy a probe task carries: the answer to "may this hop be asked?", computed once when the server builds the task.

A probe that runs in this server's workers asks the database at every hop (``probes._permitted``: exclusions and archived hosts, and the
address gate; ``js_libraries.vetter``: which other hosts a page's scripts may be read from). A probe that runs on a Sentinel cannot, so the server
answers those questions up front and the task carries the answer (``target['scope']``, the contract's ``$defs/probe_scope``). The Sentinel
(``cvengine_scanner.probes.policy``) asks it at every hop, redirects and script reads included, on top of its own floor, and reports the hosts
it touched and the hops it refused.

What a policy lists:

- ``hosts``: every name the task may ask. For each host, its own name and its redirect group (the apex and ``www``, ``probes.allowed_names``);
  for the html-libraries probe, the other hosts of the same site this project holds under a target that is neither manual only, passive nor
  host scoped (``js_libraries._refusal``'s rules, without the DNS lookup: the Sentinel judges addresses itself), and the public library CDNs.
  A name that is excluded, archived or outside the bug bounty program's scope is never listed;
- ``excluded``: the candidates that were left out for that reason, so the Sentinel names the reason when a redirect leads there;
- ``private``, ``addresses``, ``blocked``: this server's address rules (``CVENGINE_ALLOW_PRIVATE_TARGETS``, the tailnet devices the project's
  Tailscale integration imported, ``CVENGINE_BLOCKED_CIDRS``). The Sentinel's own floor (loopback, metadata, link-local, its own addresses,
  private space unless it is internal) applies whatever the policy says.

``domains`` and ``excluded_trees`` are part of the contract for kinds that need a whole tree (none of the probe kinds does: every name is listed).
"""
MAX_HOSTS = 5000  # the contract's bound
MAX_SAME_SITE = 1000  # other hosts of one site a page's scripts may be read from, per task


def address_rules(project_id):
    """``{'private', 'addresses', 'blocked'}``: what ``targetApp.target_types.is_scannable_ip`` allows besides public space, as data."""
    from cveFeed import tailscale_scope
    from targetApp.target_types import _extra_blocked, private_targets_allowed
    try:
        authorised = sorted(ip for ip, owner in tailscale_scope.authorised_addresses().items() if owner == project_id)
    except Exception:  # noqa: BLE001 - the safe answer when the table cannot be read: no device is authorised
        authorised = []
    return {'private': private_targets_allowed(), 'addresses': authorised[:1000], 'blocked': [str(n) for n in _extra_blocked()][:100]}


class _Gate:
    """The name-level gates of one project, each name asked once: exclusions, archived hosts and the bug bounty program's scope."""

    def __init__(self, project_id, unattended=True):
        from cveFeed.archive_rediscovery import archived_names
        from cveFeed.bounty_gate import Gate
        self.project, self.unattended = project_id, unattended
        self.archived = set(archived_names(project_id))
        self.bounty = Gate()
        self.memo = {}

    def refusal(self, name):
        name = (name or '').strip().lower().rstrip('.')
        if name not in self.memo:
            from cveFeed.exclusions import is_excluded
            if not name:
                why = 'no host'
            elif is_excluded(self.project, name) or name in self.archived:
                why = 'excluded'
            else:
                why = self.bounty.refusal(self.project, name, unattended=self.unattended) or ''
            self.memo[name] = why
        return self.memo[name]


def _same_site_hosts(project_id, sub, gate):
    """The other hosts of ``sub``'s site that a page of ``sub`` may read scripts from (``js_libraries.vetter``'s same-site rule): none for a
    host-scoped, passive or manual only target; else this project's own hosts of that site held by a target that is none of those."""
    from cveFeed import js_libraries
    from startScan.models import Subdomain
    from targetApp.models import Domain
    target = getattr(sub, 'target_domain', None)
    if target is None or target.is_host_scoped() or js_libraries._held_back(target):
        return []
    site = js_libraries._site(sub.name)
    if not site:
        return []
    names = (Subdomain.objects.filter(target_domain__project_id=project_id, name__iendswith='.' + site)
             .exclude(target_domain__discovery_mode__in=(Domain.DISCOVERY_MANUAL, Domain.DISCOVERY_PASSIVE))
             .exclude(name__iexact=sub.name).values_list('name', flat=True).distinct()[:MAX_SAME_SITE * 2])
    from cveFeed.manual_only import other_holder
    out = []
    for name in dict.fromkeys(n.lower().rstrip('.') for n in names):
        if js_libraries._site(name) != site or gate.refusal(name):
            continue
        holder = other_holder(project_id, name)  # the vetter's own rule: held by a target that is neither manual only nor passive
        if holder is None or js_libraries._held_back(holder):
            continue
        out.append(name)
        if len(out) >= MAX_SAME_SITE:
            break
    return out


def for_probes(project_id, planned, unattended=True):
    """The policy of an http_probe task: ``planned`` is ``[(sub, entry)]`` (``probes.plan_for_host`` entries of the http family)."""
    from cveFeed import js_libraries, probes
    gate = _Gate(project_id, unattended=unattended)
    hosts, excluded = [], set()

    def add(name):
        name = (name or '').strip().lower().rstrip('.')
        if not name or name in hosts:
            return
        if gate.refusal(name):
            excluded.add(name)
        elif len(hosts) < MAX_HOSTS:
            hosts.append(name)

    seen_subs = set()
    libraries = False
    for sub, entry in planned:
        libraries = libraries or entry['probe'] == 'html-libraries'
        if sub.pk in seen_subs:
            continue
        seen_subs.add(sub.pk)
        for name in sorted(probes.allowed_names(sub)):
            add(name)
    if libraries:
        for sub, entry in planned:
            if entry['probe'] == 'html-libraries':
                for name in _same_site_hosts(project_id, sub, gate):
                    add(name)
        for name in sorted(js_libraries.CDN_HOSTS):  # a public library CDN touches no target (probes.scope_hop asks nothing of one either)
            if name not in hosts and len(hosts) < MAX_HOSTS:
                hosts.append(name)
    return {'hosts': hosts, 'domains': [], 'excluded': sorted(excluded)[:5000], 'excluded_trees': [], **address_rules(project_id)}


def for_routes(project_id, scan, hosts, unattended=False):
    """The policy of a route_probe task: the hosts the route plan chose (``route_auth._plan`` already applied the exclusions and the bug bounty gate;
    an exclusion made since is applied again here), then, for the scripts of their front pages, the other hosts of the same site this project holds
    under a target that is neither manual only, passive nor host scoped (the library reader's own rule, ``_same_site_hosts``) and the public library
    CDNs. A same-site host that is excluded, archived or outside the bounty program's scope is never listed. Sorted, so the same task is the same
    task on every pass of an asynchronous stage."""
    from cveFeed import js_libraries
    from cveFeed.exclusions import is_excluded
    from startScan.models import Subdomain
    names = sorted({(h or '').strip().lower().rstrip('.') for h in hosts} - {''})
    listed, excluded = [], set()
    for name in names:
        if is_excluded(project_id, name):
            excluded.add(name)
        else:
            listed.append(name)
    gate = _Gate(project_id, unattended=unattended)
    subs = Subdomain.objects.filter(scan_history=scan, name__in=listed).select_related('target_domain').order_by('name')
    for sub in subs:
        for name in sorted(_same_site_hosts(project_id, sub, gate)):
            if name in listed or name in excluded:
                continue
            if gate.refusal(name):
                excluded.add(name)
            elif len(listed) < MAX_HOSTS:
                listed.append(name)
    for name in sorted(js_libraries.CDN_HOSTS):  # a public library CDN touches no target
        if name not in listed and len(listed) < MAX_HOSTS:
            listed.append(name)
    return {'hosts': listed, 'domains': [], 'excluded': sorted(excluded)[:5000], 'excluded_trees': [], **address_rules(project_id)}


def for_addresses(project_id, addresses):
    """The policy of an alive_check task: the last known addresses it asks, each as itself (``zombie.endpoints`` already kept only the ones a
    scanner may touch, by this server's address rules, which travel along for the scanner to apply again)."""
    hosts = list(dict.fromkeys(str(a).strip().lower() for a in addresses if str(a).strip()))[:MAX_HOSTS]
    return {'hosts': hosts, 'domains': [], 'excluded': [], 'excluded_trees': [], **address_rules(project_id)}


def for_buckets(project_id, candidates):
    """The policy of a bucket_check task: the storage platforms' own endpoints, never a project host. An S3 bucket's regional host is learnt
    from the platform's answer, so S3 and GCS are named by their endpoint domain (the scanner also holds every request to the documented
    endpoint patterns); an Azure account by its own host. The candidates were already filtered by the project's exclusions."""
    from cveFeed import bucket_probe
    providers = {c.provider for c in candidates}
    domains = (['amazonaws.com'] if bucket_probe.S3 in providers else []) + (['storage.googleapis.com'] if bucket_probe.GCS in providers else [])
    hosts = sorted({bucket_probe.azure_host(c.name) for c in candidates if c.provider == bucket_probe.AZURE})[:MAX_HOSTS]
    return {'hosts': hosts, 'domains': domains, 'excluded': [], 'excluded_trees': [], **address_rules(project_id)}


def for_suppliers(project_id, domains):
    """The policy of a supplier_check task: the exact names of one supplier (``supplier_scan.clean_domain`` already refused anything but a bare
    DNS name) and each one's ``mta-sts.`` host, which the policy file is fetched from. Never a wildcard, never a tree. A supplier is not an owned
    host, so the policy refuses every private address whatever ``CVENGINE_ALLOW_PRIVATE_TARGETS`` says and authorises no tailnet device; the
    server's blocked ranges still travel along. The names were already filtered by the project's exclusions and own targets."""
    hosts = []
    for name in dict.fromkeys(str(d).strip().lower().rstrip('.') for d in domains if str(d).strip()):
        hosts += [name, f'mta-sts.{name}']
    return {'hosts': hosts[:MAX_HOSTS], 'domains': [], 'excluded': [], 'excluded_trees': [], **{**address_rules(project_id), 'private': False, 'addresses': []}}


def for_vhosts(project_id, addresses, names):
    """The policy of a vhost_probe task: the addresses it asks (each as itself, for its default request) and the names it sends as the Host
    header. The names were already filtered by the project's exclusions and archived hosts; a name's own front page is asked at the address the
    scanner resolves it to, judged by the scanner's floor and the address rules that travel along."""
    hosts = list(dict.fromkeys(str(h).strip().lower().rstrip('.') for h in [*addresses, *names] if str(h).strip()))[:MAX_HOSTS]
    return {'hosts': hosts, 'domains': [], 'excluded': [], 'excluded_trees': [], **address_rules(project_id)}


def for_subdirs(project_id, names):
    """The policy of a subdir_probe task: the host names it asks (a virtual host is asked at its address with its name; the address is pinned
    by the task, never resolved)."""
    hosts = list(dict.fromkeys(str(h).strip().lower().rstrip('.') for h in names if str(h).strip()))[:MAX_HOSTS]
    return {'hosts': hosts, 'domains': [], 'excluded': [], 'excluded_trees': [], **address_rules(project_id)}


def for_names(project_id, domain, names, unattended=False):
    """The policy of a dns_resolve task for ``names`` of target ``domain``: each name the target holds that no gate refuses. A lookup asks the
    Sentinel's resolver, never the host, so this is about which names the scanner is told of at all."""
    gate = _Gate(project_id, unattended=unattended)
    hosts, excluded = [], []
    for name in names:
        name = (name or '').strip().lower().rstrip('.')
        if not name:
            continue
        if not domain.includes_host(name) or gate.refusal(name):
            excluded.append(name)
        elif name not in hosts and len(hosts) < MAX_HOSTS:
            hosts.append(name)
    return {'hosts': hosts, 'domains': [], 'excluded': excluded[:5000], 'excluded_trees': [], **address_rules(project_id)}



def for_identity(project_id, names, unattended=True):
    """The policy of an identity_check task: the exact names and addresses it asks about (a DNS question about a name, a reverse question about an
    address, a certificate read at an endpoint), each once. A name that is excluded, archived or outside the bug bounty program's scope is never
    listed (and so never asked: ``probe_dispatch.try_identity`` leaves its question out, which reads as no answer). Sorted-stable, so the same task
    is the same task on every pass of an asynchronous stage."""
    gate = _Gate(project_id, unattended=unattended)
    hosts, excluded = [], set()
    for name in dict.fromkeys(str(n).strip().lower().rstrip('.') for n in names if str(n).strip()):
        if gate.refusal(name):
            excluded.add(name)
        elif len(hosts) < MAX_HOSTS:
            hosts.append(name)
    return {'hosts': hosts, 'domains': [], 'excluded': sorted(excluded)[:5000], 'excluded_trees': [], **address_rules(project_id)}
