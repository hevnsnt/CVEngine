"""The probe kinds through a Sentinel (contract version 3): ``http_probe`` (the version and identity probes, ``cveFeed.probes``) and
``dns_resolve`` (the discovery pipeline's name lookups) and ``page_read`` (a validation re-test's HEAD of a URL and re-read of a host's pages and scripts).

The server keeps the choice of what to probe (the plan, the ledger, the per-scan cap), the scope policy (``cveFeed.probe_scope``), the
validation of what comes back (``agentapi.probe_results``) and what is stored. The Sentinel runs the requests (``cvengine_scanner.probes``) under
the policy the task carries. None of these kinds has a local path (``sentinel_dispatch.NEVER_LOCAL``): with no Sentinel able to take the work the
stage waits for a scanner (``reNgine.resources.ScannerUnavailable``) and the work stays due."""
import logging
import os

from agentapi import sentinel_dispatch

logger = logging.getLogger(__name__)

MAX_PROBES_PER_TASK = 300  # the contract's bound (cvengine_scanner.probes.version_probes.MAX_ENTRIES)
MAX_NAMES_PER_TASK = 500   # the contract's bound (cvengine_scanner.probes.dns.MAX_NAMES)


def _offered(project, kind):
    """True when a Sentinel may take ``kind`` work of ``project`` now. When none can: ``ScannerUnavailable`` (the kind never runs here, the stage waits)."""
    if sentinel_dispatch.any_scanner_for(project, kind):
        return True
    sentinel_dispatch._no_scanner(kind, project)


def _hosts_label(names):
    names = list(dict.fromkeys(names))
    return ','.join(names)[:480] if len(names) <= 5 else f'{len(names)} hosts'


def _unfinished(kind, what):
    """A task of a kind with no local path that ended without a result: nothing was asked, the work stays due."""
    from reNgine.resources import ScannerUnavailable
    return ScannerUnavailable(kind, f'a Sentinel returned no result for {what}')


def try_http_probes(project, scan, planned, unattended=True):
    """``{asset: observations}`` for the planned http probes a Sentinel ran. ``planned`` is ``[(sub, asset, entry)]`` (``probes.asset_key`` and a
    ``plan_for_host`` entry of the http family). A probe the Sentinel reports with an error is in the answer as that error (an ``Exception``), so the
    caller treats it as a failed probe: retried later, never recorded as clean. The kind has no local path (``sentinel_dispatch.NEVER_LOCAL``):
    ``ScannerUnavailable`` when no Sentinel can take the work or a task ended without a result."""
    from cveFeed import probe_scope
    if not planned or not _offered(project, 'http_probe'):
        return {}
    answered = {}
    for start in range(0, len(planned), MAX_PROBES_PER_TASK):
        chunk = planned[start:start + MAX_PROBES_PER_TASK]
        target = {'probes': [{'id': asset, 'host': sub.name.lower(), 'probe': entry['probe'], 'base': entry['target']['base'].rstrip('/'),
                              'allowed': sorted(_allowed(sub))[:20]} for sub, asset, entry in chunk],
                  'scope': probe_scope.for_probes(project.pk, [(sub, entry) for sub, _asset, entry in chunk], unattended=unattended)}
        result = sentinel_dispatch.dispatch_or_none(project, 'http_probe', target, host=_hosts_label(sub.name for sub, _a, _e in chunk),
                                                    scan=scan)
        if result is None:
            raise _unfinished('http_probe', 'a version probe task')
        reported = {row['id']: row for row in result.get('probes') or []}
        for sub, asset, entry in chunk:
            row = reported.get(asset)
            if row is None:
                answered[asset] = RuntimeError('the scanner did not report this probe')
            elif row.get('error'):
                answered[asset] = RuntimeError(row['error'])
            else:
                answered[asset] = row['observations']
        if result.get('refused'):
            logger.info('http_probe task for %s: the scanner refused hops to %s host(s) outside the scope policy', project.pk, len(result['refused']))
    return answered


def _allowed(sub):
    from cveFeed import probes
    return probes.allowed_names(sub)


def try_dns_resolve(domain, names, scan=None):
    """``(pairs, errors)`` (``{(name, ip)}`` and ``{name: reason}``) from a Sentinel's lookups. The kind has no local path
    (``sentinel_dispatch.NEVER_LOCAL``): ``ScannerUnavailable`` when no Sentinel can take it. A name the scope policy left out is never sent and
    is an error, as is a name the Sentinel refused or a task nobody finished: looked up again later, never a name without an address."""
    from cveFeed import probe_scope
    project = domain.project
    names = [n for n in dict.fromkeys((n or '').strip().lower().rstrip('.') for n in names) if n]
    if not names or not _offered(project, 'dns_resolve'):
        return set(), {}
    scope = probe_scope.for_names(project.pk, domain, names)
    allowed = scope['hosts']
    pairs, errors = set(), {}
    for name in names:  # a name the policy left out is not looked up: unknown, never a name without an address (a retire check reads absent as gone)
        if name not in allowed:
            errors[name] = 'not looked up: outside the scope policy'
    for start in range(0, len(allowed), MAX_NAMES_PER_TASK):
        chunk = allowed[start:start + MAX_NAMES_PER_TASK]
        result = sentinel_dispatch.dispatch_or_none(project, 'dns_resolve', {'names': chunk, 'scope': {**scope, 'hosts': chunk}},
                                                    host=_hosts_label(chunk), scan=scan)
        if result is None:  # a task nobody finished: no answer for these names, so none is read as a name without an address
            errors.update({name: 'no answer from the scanner' for name in chunk})
            continue
        resolved = result.get('resolved') or {}
        pairs |= {(name, ip) for name, ips in resolved.items() for ip in ips}
        failed = result.get('errors') or {}
        for name in chunk:
            if name not in resolved and name in failed:
                errors[name] = failed[name]
            elif name not in resolved and name in (result.get('refused') or []):
                errors[name] = 'the scanner refused the name'
    return pairs, errors


MAX_BUCKETS_PER_TASK = 100  # the contract's bound


def try_buckets(project, candidates, rate):
    """``{asset: Verdict}`` for the bucket candidates (``bucket_scan.Candidate``) a Sentinel checked. The kind has no local path
    (``sentinel_dispatch.NEVER_LOCAL``): ``ScannerUnavailable`` when no Sentinel can take it. A candidate no Sentinel reported is missing from the
    answer: unknown, checked again later."""
    from cveFeed import bucket_probe, probe_scope
    if not candidates or not _offered(project, 'bucket_check'):
        return {}
    answered = {}
    for start in range(0, len(candidates), MAX_BUCKETS_PER_TASK):
        chunk = candidates[start:start + MAX_BUCKETS_PER_TASK]
        target = {'buckets': [{'id': c.asset, 'provider': c.provider, 'name': c.name, **({'container': c.container} if c.container else {})}
                              for c in chunk],
                  'rate': bucket_probe.request_rate(), 'scope': probe_scope.for_buckets(project.pk, chunk)}
        result = sentinel_dispatch.dispatch_or_none(project, 'bucket_check', target,
                                                    host=_hosts_label(h for c in chunk for h in (c.hosts or [c.asset])))
        if result is None:  # a task nobody finished: these candidates are unknown
            continue
        answered.update({row['id']: bucket_probe.Verdict(**row['verdict']) for row in result.get('buckets') or []})
    return answered


MAX_SUPPLIER_DOMAINS_PER_TASK = 25  # the contract's bound
MAX_SUPPLIER_REQUESTS = 5000  # the contract's bound


def try_suppliers(project, domains, max_requests):
    """``{domain: row}`` for the supplier names a Sentinel checked (each row as ``probe_results.clean_supplier_check`` leaves it). A name the task did
    not ask about, or that the Sentinel did not report, is simply not in the answer: it was not checked. ``max_requests`` is what the sweep's budget
    still allows (the Sentinel counts requests as the server does and reports a name that does not fit as partial). The kind has no local path
    (``sentinel_dispatch.NEVER_LOCAL``): ``ScannerUnavailable`` when no Sentinel can take the work or the task ended without a result."""
    from cveFeed import probe_scope, slow_web
    domains = list(dict.fromkeys(domains))[:MAX_SUPPLIER_DOMAINS_PER_TASK]
    if not domains or max_requests < 1 or not _offered(project, 'supplier_check'):
        return {}
    target = {'domains': domains,
              'pace': {'gap': min(60.0, max(0.25, slow_web.global_gap())), 'host_gap': min(60.0, max(0.5, slow_web.host_gap()))},
              'max_requests': min(MAX_SUPPLIER_REQUESTS, int(max_requests)), 'scope': probe_scope.for_suppliers(project.pk, domains)}
    result = sentinel_dispatch.dispatch_or_none(project, 'supplier_check', target, host=_hosts_label(domains))
    if result is None:
        raise _unfinished('supplier_check', 'a supplier check task')
    if result.get('refused'):
        logger.info('supplier_check task for %s: the scanner refused hops to %s host(s) outside the scope policy', project.pk, len(result['refused']))
    return {row['domain']: row for row in result.get('domains') or []}


MAX_VHOST_ADDRESSES_PER_TASK = 10  # the contract's bound
MAX_SUBDIR_HOSTS_PER_TASK = 10     # the contract's bound


def try_vhosts(project, items, gap):
    """``{address: report}`` for the addresses (``items``: ``[{'id', 'address', 'scheme', 'port', 'names': [{'name', 'own'?}]}]``, ``id`` is the
    address) a Sentinel asked their default response and each name. A report is what ``probe_results.clean_vhost_probe`` keeps of one address; an
    address or a name the Sentinel did not report is missing from the answer: unknown, so it stays due. The kind has no local path
    (``sentinel_dispatch.NEVER_LOCAL``): ``ScannerUnavailable`` when no Sentinel can take the work or a task ended without a result."""
    from cveFeed import probe_scope
    if not items or not _offered(project, 'vhost_probe'):
        return {}
    answered = {}
    for start in range(0, len(items), MAX_VHOST_ADDRESSES_PER_TASK):
        chunk = items[start:start + MAX_VHOST_ADDRESSES_PER_TASK]
        target = {'addresses': [{'id': i['id'], 'address': i['address'], 'scheme': i['scheme'], 'port': i['port'],
                                 'names': [dict(n) for n in i['names']]} for i in chunk],
                  'gap': gap, 'scope': probe_scope.for_vhosts(project.pk, [i['address'] for i in chunk], [n['name'] for i in chunk for n in i['names']])}
        result = sentinel_dispatch.dispatch_or_none(project, 'vhost_probe', target, host=_hosts_label(i['address'] for i in chunk),
                                                    ips=[i['address'] for i in chunk][:64])
        if result is None:
            raise _unfinished('vhost_probe', 'a virtual host task')
        answered.update({row['id']: row for row in result.get('addresses') or []})
    return answered


def try_subdirs(project, items, paths, max_requests, gap):
    """``{id: report}`` for the web hosts (``items``: ``[{'id', 'name', 'scheme', 'port', 'connect_ip'?, 'root'?, 'leads'?}]``) a Sentinel asked
    for their mount paths. A host the Sentinel did not report is missing from the answer: unknown, so it stays due. The kind has no local path
    (``sentinel_dispatch.NEVER_LOCAL``): ``ScannerUnavailable`` when no Sentinel can take the work or a task ended without a result."""
    from cveFeed import probe_scope
    if not items or not _offered(project, 'subdir_probe'):
        return {}
    answered = {}
    for start in range(0, len(items), MAX_SUBDIR_HOSTS_PER_TASK):
        chunk = items[start:start + MAX_SUBDIR_HOSTS_PER_TASK]
        target = {'hosts': chunk, 'paths': list(paths), 'max_requests': max_requests, 'gap': gap,
                  'scope': probe_scope.for_subdirs(project.pk, [i['name'] for i in chunk])}
        result = sentinel_dispatch.dispatch_or_none(project, 'subdir_probe', target, host=_hosts_label(i['name'] for i in chunk),
                                                    ips=[i['connect_ip'] for i in chunk if i.get('connect_ip')][:64] or None)
        if result is None:
            raise _unfinished('subdir_probe', 'a subdirectory task')
        answered.update({row['id']: row for row in result.get('hosts') or []})
    return answered


MAX_CHECKS_PER_TASK = 600  # the contract's bound


def try_alive(project, scan, checks):
    """``{id: alive}`` for ``checks`` (``[{'id', 'host', 'ip', 'port', 'scheme'}]``, the zombie check's endpoints) as a Sentinel answered them. The
    kind has no local path (``sentinel_dispatch.NEVER_LOCAL``): ``ScannerUnavailable`` when no Sentinel can take it. A check the Sentinel reports
    with an error, or not at all, is missing from the answer: the caller reads it as unknown, never as gone."""
    from cveFeed import probe_scope
    if not checks or not _offered(project, 'alive_check'):
        return {}
    answered = {}
    for start in range(0, len(checks), MAX_CHECKS_PER_TASK):
        chunk = checks[start:start + MAX_CHECKS_PER_TASK]
        target = {'checks': chunk, 'scope': probe_scope.for_addresses(project.pk, [c['ip'] for c in chunk])}
        result = sentinel_dispatch.dispatch_or_none(project, 'alive_check', target, host=_hosts_label(c['host'] for c in chunk),
                                                    ips=list(dict.fromkeys(c['ip'] for c in chunk))[:64], scan=scan)
        if result is None:  # a task nobody finished (dispatch_or_none raised when the kind may not run here): its checks are unknown
            continue
        answered.update({row['id']: row['alive'] for row in result.get('checks') or [] if not row.get('error')})
    return answered


MAX_IDENTITY_DNS_PER_TASK = 200    # the contract's bounds (cvengine_scanner.probes.identity)
MAX_IDENTITY_CERTS_PER_TASK = 50


def try_identity(project, scan, dns=(), certs=(), unattended=True, allow_archived=False):
    """``(dns_answers, cert_answers)`` for the DNS questions ``[{'id', 'name', 'type'}]`` (``A``, ``CNAME``, ``NS``, ``MX``; ``PTR`` with an address) and
    the certificate reads ``[{'id', 'host', 'port'}]`` a Sentinel answered: ``{id: {'status', 'records', 'canonical'}}`` and ``{id: {'status',
    'names'}}``. The kind has no local path (``sentinel_dispatch.NEVER_LOCAL``): when no Sentinel can take it ``ScannerUnavailable`` is raised and
    nothing is asked. A question the scope policy left out (an excluded or archived name) is never sent, and a question the Sentinel did not
    answer, refused or could not answer is missing from the answer or has status ``unknown``: the caller reads that as no answer, never as ``none``."""
    from cveFeed import probe_scope
    dns, certs = list(dns), list(certs)
    if not dns and not certs:
        return {}, {}
    if not _offered(project, 'identity_check'):  # unreachable while the kind is in NEVER_LOCAL (_offered raises); never let a missing answer read as none
        return {}, {}
    # A Sentinel refuses a whole identity_check task when one question is malformed, and a question about an address that is not a PTR is: an IP-only
    # host (a Subdomain named by its address) has no CNAME, NS or MX to read, and nothing to look up for an A question. Such a question is never sent,
    # so it is missing from the answer (no answer, never "none") instead of failing the 200 others sent with it.
    dns = [q for q in dns if (q.get('type') == 'PTR') == _is_address(q.get('name'))]
    if not dns and not certs:
        return {}, {}
    ungated = [q['name'] for q in dns if q.get('ungated')]  # an internal key: a name the server made up, never sent as such
    dns = [{k: v for k, v in q.items() if k != 'ungated'} for q in dns]
    scope = probe_scope.for_identity(project.pk, [*(q['name'] for q in dns), *(c['host'] for c in certs)], unattended=unattended,
                                     allow_archived=allow_archived, ungated=ungated)
    allowed = set(scope['hosts'])
    dns = [q for q in dns if q['name'].strip().lower().rstrip('.') in allowed]
    certs = [c for c in certs if c['host'].strip().lower().rstrip('.') in allowed]
    dns_out, cert_out = {}, {}
    start_dns = start_certs = 0
    while start_dns < len(dns) or start_certs < len(certs):
        d = dns[start_dns:start_dns + MAX_IDENTITY_DNS_PER_TASK]
        c = certs[start_certs:start_certs + MAX_IDENTITY_CERTS_PER_TASK]
        start_dns, start_certs = start_dns + len(d), start_certs + len(c)
        hosts = [*(q['name'] for q in d), *(x['host'] for x in c)]
        target = {'scope': {**scope, 'hosts': list(dict.fromkeys(h.strip().lower().rstrip('.') for h in hosts))}}
        if d:
            target['dns'] = d
        if c:
            target['certs'] = c
        ips = [h for h in dict.fromkeys(hosts) if _is_address(h)][:64]
        result = sentinel_dispatch.dispatch_or_none(project, 'identity_check', target, host=_hosts_label(hosts), ips=ips, scan=scan)
        if result is None:  # not finished: dispatch_or_none raised when the kind may not run here, so this is a task that never answered: unknown
            continue
        dns_out.update({row['id']: row for row in result.get('dns') or []})
        cert_out.update({row['id']: row for row in result.get('certs') or []})
    return dns_out, cert_out


def resolve_addresses(project, names, scan=None, allow_archived=False, ungated=()):
    """``{name: (state, addresses)}`` for hostnames, read by a Sentinel (``identity_check`` ``A`` questions): ``state`` is ``resolved`` (with its addresses),
    ``absent`` (the resolver said there is no address) or ``error`` (not asked, not answered or refused by the scope policy: never read as absent).
    Raises ``ScannerUnavailable`` when no Sentinel can take the kind (it has no local path)."""
    names = list(dict.fromkeys(str(n).strip().lower().rstrip('.') for n in names if str(n).strip()))
    free = {str(n).strip().lower().rstrip('.') for n in ungated}
    queries = [{'id': name, 'name': name, 'type': 'A', **({'ungated': True} if name in free else {})} for name in names]
    answers, _certs = try_identity(project, scan, dns=queries, allow_archived=allow_archived)
    out = {}
    for name in names:
        row = answers.get(name)
        if row and row.get('status') == 'ok' and row.get('records'):
            out[name] = ('resolved', {a for a in (_address_text(r) for r in row['records']) if a})
        elif row and row.get('status') == 'none':
            out[name] = ('absent', set())
        else:
            out[name] = ('error', set())
    return out


def _address_text(value):
    import ipaddress
    try:
        return str(ipaddress.ip_address(str(value).strip().strip('[]')))
    except ValueError:
        return ''


def _is_address(value):
    import ipaddress
    try:
        ipaddress.ip_address(str(value).strip('[]'))
        return True
    except ValueError:
        return False


MAX_TLS_PER_TASK = 300   # the contract's bounds (cvengine_scanner.probes.hygiene)
MAX_MAIL_PER_TASK = 101
MAX_FINDINGS_PER_TASK = 50  # the contract's bound (cvengine_scanner.probes.dangling_dns.MAX_CHECKS)


def _confirm_resolvers():
    """The confirming resolvers the installation opted in to (``hygiene.confirm_resolvers``), only the ones that are IP addresses."""
    import ipaddress

    from cveFeed import hygiene
    out = []
    for address in hygiene.confirm_resolvers():
        try:
            out.append(str(ipaddress.ip_address(address)))
        except ValueError:
            continue
    return out[:5]


def try_hygiene(domain, tls, mail):
    """The cleaned result of one ``hygiene_check`` task (``probe_results.clean_hygiene_check``) for ``domain``: ``tls`` is ``[(host, port)]`` and
    ``mail`` is ``[(name, always)]`` (a name flagged ``always`` is reviewed whatever its records, the others only when they have an MX record of their
    own and are not a CNAME). The kind has no local path (``sentinel_dispatch.NEVER_LOCAL``): ``ScannerUnavailable`` when no Sentinel can take the work
    or the task ended unanswered. Nothing in the answer says an endpoint or a name was checked unless its row is there: the caller reads a missing one
    as unknown."""
    from cveFeed import probe_scope
    project = domain.project
    if not (tls or mail):
        return {'certs': [], 'mail': []}
    _offered(project, 'hygiene_check')  # raises ScannerUnavailable when none can take it
    tls, mail = list(tls)[:MAX_TLS_PER_TASK], list(mail)[:MAX_MAIL_PER_TASK]
    target = {'tls': [{'host': h, 'port': p} for h, p in tls], 'mail': [{'name': n, 'always': bool(a)} for n, a in mail],
              'confirm_resolvers': _confirm_resolvers(), 'rdap': os.environ.get('CVENGINE_HYGIENE_RDAP', '1') != '0',
              'scope': probe_scope.for_hygiene(project.pk, tls, [n for n, _a in mail])}
    result = sentinel_dispatch.dispatch_or_none(project, 'hygiene_check', target, host=_hosts_label([domain.name] + [h for h, _p in tls]))
    if result.get('refused'):
        logger.info('hygiene_check task for %s: the scanner refused %s host(s) outside the scope policy', project.pk, len(result['refused']))
    return result


def try_dangling(project, checks, providers):
    """``{id: row}`` for the baddns findings (``checks``: ``[{'id', 'host', 'kind', 'triggers'}]``) a Sentinel rated, each row ``{'state': 'rated'|'unknown',
    'severity', 'drop', 'note', 'zone'}``. The kind has no local path (``sentinel_dispatch.NEVER_LOCAL``): ``ScannerUnavailable`` when no Sentinel can
    take the work or a task ended unanswered. A finding the Sentinel did not report is missing from the answer: the caller keeps baddns's own rating."""
    from cveFeed import probe_scope
    if not checks:
        return {}
    _offered(project, 'dangling_dns_check')  # raises ScannerUnavailable when none can take it
    answered = {}
    for start in range(0, len(checks), MAX_FINDINGS_PER_TASK):
        chunk = checks[start:start + MAX_FINDINGS_PER_TASK]
        scope = probe_scope.for_dangling(project.pk, [c['host'] for c in chunk])
        chunk = [c for c in chunk if c['host'] in scope['hosts']]  # a host the policy leaves out (excluded, archived, out of the bounty scope) is never sent
        if not chunk:
            continue
        target = {'checks': chunk, 'providers': providers, 'scope': scope}
        result = sentinel_dispatch.dispatch_or_none(project, 'dangling_dns_check', target, host=_hosts_label(c['host'] for c in chunk))
        answered.update({row['id']: row for row in result.get('ratings') or []})
    return answered


MAX_SSH_TARGETS_PER_TASK = 25  # the contract's bound (cvengine_scanner.probes.ssh_probe.MAX_TARGETS)


def try_ssh_probe(project, keys, scan=None):
    """``{(address, port): host row}`` for the SSH endpoints (``keys``: ``[(address, port)]``, at most ``MAX_SSH_TARGETS_PER_TASK``) a Sentinel inspected
    (``probe_results.clean_ssh_probe``, cut to the endpoints asked). The kind has no local path (``sentinel_dispatch.NEVER_LOCAL``): ``ScannerUnavailable``
    when no Sentinel can take it. A task that ended without a result, and an endpoint the result has no row for, are missing from the answer: unknown, the
    caller leaves them due and never reads a missing one as a clean host."""
    from cveFeed import probe_scope
    keys = list(dict.fromkeys(keys))[:MAX_SSH_TARGETS_PER_TASK]
    if not keys or not _offered(project, 'ssh_probe'):
        return {}
    target = {'targets': [{'address': a, 'port': p} for a, p in keys], 'scope': probe_scope.for_ssh(project.pk, [a for a, _p in keys])}
    result = sentinel_dispatch.dispatch_or_none(project, 'ssh_probe', target, host=_hosts_label(a for a, _p in keys), ips=[a for a, _p in keys])
    if result is None:
        return {}
    if result.get('refused'):
        logger.info('ssh_probe task for %s: the scanner refused %s endpoint(s) outside the scope policy', project.pk, len(result['refused']))
    return {(row['address'], row['port']): row for row in result.get('hosts') or []}


MAX_ROUTE_HOSTS_PER_TASK = 25  # the contract's bound (cvengine_scanner.probes.routes.MAX_HOSTS)


def try_routes(project, scan, by_host):
    """``{url: result or error}`` for the routes of ``by_host`` (``{host: [urls]}``, the route plan's) a Sentinel asked. A result has the shape
    ``route_auth.analyse`` gives (plus the soft 404 comparison and the front page's scripts, which the scanner did); a route the Sentinel reports
    with an error, or not at all, is in the answer as an ``Exception``, so the caller treats it as unanswered: asked again later, never recorded as a
    state. The kind has no local path (``sentinel_dispatch.NEVER_LOCAL``): ``ScannerUnavailable`` when no Sentinel can take the work or a task ended
    without a result; nothing was asked, nothing is recorded, the routes stay due."""
    from cveFeed import probe_scope
    if not by_host or not _offered(project, 'route_probe'):
        return {}
    hosts = list(by_host)
    answered = {}
    for start in range(0, len(hosts), MAX_ROUTE_HOSTS_PER_TASK):
        chunk = hosts[start:start + MAX_ROUTE_HOSTS_PER_TASK]
        target = {'hosts': [{'host': host, 'urls': by_host[host]} for host in chunk],
                  'scope': probe_scope.for_routes(project.pk, scan, chunk)}
        result = sentinel_dispatch.dispatch_or_none(project, 'route_probe', target, host=_hosts_label(chunk), scan=scan)
        if result is None:
            raise _unfinished('route_probe', 'a route check task')
        answered.update(_route_answers(result, by_host, chunk))
        if result.get('refused'):
            logger.info('route_probe task for %s: the scanner refused hops to %s host(s) outside the scope policy', project.pk, len(result['refused']))
    return answered


def _route_answers(result, by_host, chunk):
    """``{url: result or error}`` for the routes of ``chunk`` hosts in a route_probe or route_probe_signed result."""
    reported = {row['id']: row for row in result.get('routes') or []}
    answered = {}
    spent = bool(result.get('values_scrubbed'))  # read again after its credentials were taken and dropped: they are not asked for twice
    for host in chunk:
        for url in by_host[host]:
            row = reported.get(url)
            if row is None:
                answered[url] = RuntimeError('the scanner did not report this route')
            elif row.get('error'):
                answered[url] = RuntimeError(row['error'])
            elif spent and row.get('credentials'):
                answered[url] = RuntimeError('the credentials of this answer were already filed and dropped')  # asked again later, never read as "no credential"
            else:
                answered[url] = {'credentials': [(c['type'], c['value']) for c in row['credentials']],
                                 'credential_context': [(c.get('line'), c.get('context', '')) for c in row['credentials']], 'status': row['status'], 'title': row['title'],
                                 'content_type': row['content_type'], 'state': row['state'], 'evidence': row['evidence'],
                                 'sensitive': row['sensitive'], 'sensitive_score': row['sensitive_score'], 'fp': None, 'bytes': row['bytes']}
    if getattr(result, 'task_id', None) and any(isinstance(a, dict) and a['credentials'] for a in answered.values()):
        from agentapi import sentinel_broker
        sentinel_broker.scrub_values(result.task_id)  # the values are in memory now, on their way to the inventory: the task row does not keep them
    return answered


def try_signed_routes(project, scan, credential, by_host):
    """``{url: result or error}`` for the routes of ``by_host`` (``{host: [urls]}``, all covered by the one stored sign-in ``credential``) asked signed in by
    the built-in scanner (kind ``route_probe_signed``): one task per 25 hosts, carrying ``secret_ref`` (a reference to the credential, never a value), which
    only a built-in scanner that reads stored sign-ins is ever offered; it reads the credential once through ``sentinel/tasks/<id>/secret``. The answers
    have the shape ``route_auth.analyse`` gives, and a route the scanner reports with an error, or not at all, is in the answer as an ``Exception``
    (asked again later, never a state). The kind is in ``NEVER_LOCAL`` and has no local path: when no scanner can take the work, or a task ended
    without a result, this raises ``ScannerUnavailable`` (nothing recorded, the routes stay due)."""
    from agentapi import sentinel_broker
    from cveFeed import probe_scope
    from reNgine.resources import ScannerUnavailable
    hosts = list(by_host)
    answered = {}
    for start in range(0, len(hosts), MAX_ROUTE_HOSTS_PER_TASK):
        chunk = hosts[start:start + MAX_ROUTE_HOSTS_PER_TASK]
        target = {'hosts': [{'host': host, 'urls': by_host[host]} for host in chunk],
                  'scope': probe_scope.for_signed_routes(project.pk, chunk)}
        result = sentinel_dispatch.dispatch_or_none(project, 'route_probe_signed', target, host=_hosts_label(chunk), scan=scan,
                                                    secret_ref=sentinel_broker.secret_ref_for(credential.pk))
        if result is None:  # dispatch_or_none raised ScannerUnavailable when no scanner took it: this is a task that ended without a result
            raise ScannerUnavailable('route_probe_signed', 'the built-in scanner returned no result for a signed-in route check')
        answered.update(_route_answers(result, by_host, chunk))
    return answered


def try_page_reads(project, reads, scope, scan=None):
    """The rows of a Sentinel's answer to a ``page_read`` task of ``reads`` (at most ``probe_results.MAX_READS``; ``scope`` is a ``probe_scope`` policy
    naming every host of the reads), in the order of ``reads``: ``{'id', 'head' | 'reading' | 'control' | 'readme'}``, or ``{'id', 'error'}`` for a read
    the Sentinel could not make (unknown, never a state). The kind is in ``NEVER_LOCAL`` and has no local path: with no scanner able to take the work this
    raises ``ScannerUnavailable`` (nothing was read, nothing is recorded), and so does a task that ended with no result. A read the Sentinel did not
    report is an error row too."""
    from reNgine.resources import ScannerUnavailable
    target = {'reads': list(reads), 'scope': scope}
    label = _hosts_label(read['host'] for read in reads)
    result = sentinel_dispatch.dispatch_or_none(project, 'page_read', target, host=label, scan=scan)
    if result is None:  # dispatch_or_none raised ScannerUnavailable when no scanner took it: this is a task that ended without a result
        raise ScannerUnavailable('page_read', 'the scanner returned no result for a page read')
    if result.get('refused'):
        logger.info('page_read task for %s: the scanner refused hops to %s host(s) outside the scope policy', project.pk, len(result['refused']))
    by_id = {r.get('id'): r for r in result.get('reads') or []}
    return [by_id.get(read['id']) or {'id': read['id'], 'error': 'the scanner did not report this read'} for read in reads]


def try_page_read(project, read, scope, scan=None):
    """The answer of a Sentinel to one ``page_read`` (``read`` is ``{'id', 'op', 'host', ...}``: ``op`` is ``head`` with a ``url``, or ``libraries`` with the
    ``bases`` of the host, the ``library`` a match is about and the ``seen_urls`` the host was seen to load it from; ``scope`` is
    ``probe_scope.for_page_read``): the row of the result, ``{'id', 'head'}`` or ``{'id', 'reading'}``. ``ScannerUnavailable`` as ``try_page_reads``
    says; a read the Sentinel could not make is a ``RuntimeError`` carrying its reason: the check is unknown, never a state."""
    (row,) = try_page_reads(project, [read], scope, scan=scan)
    if row.get('error'):
        raise RuntimeError(row['error'])
    return row


def control_reads(project, scan, urls, unattended=False):
    """``{url: (status, location, digest) or None}`` for ``urls``, control paths (``nuclei_fp.control_url``) of hosts a template match was made on, each one GET
    of a path no site serves made by a Sentinel (``page_read``, op ``control``): the status, the redirect target and the SHA-256 of the body with its
    whitespace collapsed, never the body. ``None`` for a URL the Sentinel could not read (refused by the scope policy, no answer): an unanswered control
    decides nothing, and the caller must not treat it as a host that does not answer everything. ``ScannerUnavailable`` when no Sentinel can take the
    work: the stage waits and its targets stay due. At most ``probe_results.MAX_READS`` URLs make one task."""
    from urllib.parse import urlsplit

    from cveFeed import probe_scope
    from agentapi import probe_results
    urls = list(dict.fromkeys(urls))
    out = {}
    for start in range(0, len(urls), probe_results.MAX_READS):
        chunk = urls[start:start + probe_results.MAX_READS]
        reads = [{'id': f'control:{url}'[:200], 'op': 'control', 'host': (urlsplit(url).hostname or '').lower().rstrip('.'), 'url': url} for url in chunk]
        scope = probe_scope.for_hosts(project.pk, [r['host'] for r in reads], unattended=unattended)
        for url, row in zip(chunk, try_page_reads(project, reads, scope, scan=scan)):
            got = row.get('control') if not row.get('error') else None
            out[url] = (got['status'] or 0, got['location'], got['digest']) if got else None
    return out


def readme_titles(project, scan, sub, base, slugs, unattended=True):
    """``{slug: title}`` the plugins of the WordPress site ``base`` of the host ``sub`` give in their ``readme.txt`` (``=== Plugin Name ===``), read by a
    Sentinel (``page_read``, op ``readme``; the policy is the host's own, ``probe_scope.for_page_read``). A plugin whose readme gave no title is absent.
    ``ScannerUnavailable`` when no Sentinel can take the work; a read the Sentinel could not make is a ``RuntimeError``: the titles are unknown."""
    from cveFeed import probe_scope
    read = {'id': f'readme:{sub.name.lower()}'[:200], 'op': 'readme', 'host': sub.name.lower().rstrip('.'), 'base': base.rstrip('/'), 'slugs': list(slugs)}
    row = try_page_read(project, read, probe_scope.for_page_read(project.pk, sub, unattended=unattended), scan=scan)
    return dict(row.get('readme', {}).get('titles') or {})


def resolve_for(domain, names, errors=None, scan=None):
    """The addresses of the names of target ``domain`` as a Sentinel resolved them (``{(name, ip)}``, and ``errors`` filled with the lookups that could
    not be answered). ``ScannerUnavailable`` when no Sentinel can take ``dns_resolve``."""
    pairs, failed = try_dns_resolve(domain, names, scan=scan)
    if errors is not None:
        errors.update(failed)
    return pairs
