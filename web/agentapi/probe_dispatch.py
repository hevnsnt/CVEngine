"""The probe kinds through a Sentinel (contract version 3): ``http_probe`` (the version and identity probes, ``cveFeed.probes``) and
``dns_resolve`` (``cveFeed.discovery.resolve_names``).

The server keeps the choice of what to probe (the plan, the ledger, the per-scan cap), the scope policy (``cveFeed.probe_scope``), the
validation of what comes back (``agentapi.probe_results``) and what is stored. The Sentinel runs the requests (``cvengine_scanner.probes``) under
the policy the task carries. Like every other kind: a project with no Sentinel for the kind runs the work here as before, and when
``CVENGINE_LOCAL_FALLBACK`` takes the kind off its list the stage waits for a scanner instead (``reNgine.resources.ScannerUnavailable``) and the
work stays due."""
import logging

from agentapi import sentinel_dispatch

logger = logging.getLogger(__name__)

MAX_PROBES_PER_TASK = 300  # the contract's bound (cvengine_scanner.probes.version_probes.MAX_ENTRIES)
MAX_NAMES_PER_TASK = 500   # the contract's bound (cvengine_scanner.probes.dns.MAX_NAMES)


def _offered(project, kind):
    """Whether a Sentinel may take ``kind`` work of ``project`` now. When none can: ``ScannerUnavailable`` if the kind may not run here (the
    stage waits), else ``False`` (the caller runs it here, as before)."""
    if sentinel_dispatch.any_scanner_for(project, kind):
        return True
    sentinel_dispatch._no_scanner(kind, project)
    sentinel_dispatch.offline_fallback(project, kind)
    return False


def _hosts_label(names):
    names = list(dict.fromkeys(names))
    return ','.join(names)[:480] if len(names) <= 5 else f'{len(names)} hosts'


def try_http_probes(project, scan, planned, unattended=True):
    """``{asset: observations}`` for the planned http probes a Sentinel ran, and the list of ``(sub, asset, entry)`` left to run here, or
    ``None`` when no Sentinel can take the kind (the caller runs everything here). ``planned`` is ``[(sub, asset, entry)]`` (``probes.asset_key``
    and a ``plan_for_host`` entry of the http family). A probe the Sentinel reports with an error is in the answer as that error (an ``Exception``),
    so the caller treats it as a failed probe: retried later, never recorded as clean. Raises ``ScannerUnavailable`` when no Sentinel can take the
    work and the kind may not run here."""
    from cveFeed import probe_scope
    if not planned or not _offered(project, 'http_probe'):
        return None
    answered, local = {}, []
    for start in range(0, len(planned), MAX_PROBES_PER_TASK):
        chunk = planned[start:start + MAX_PROBES_PER_TASK]
        target = {'probes': [{'id': asset, 'host': sub.name.lower(), 'probe': entry['probe'], 'base': entry['target']['base'].rstrip('/'),
                              'allowed': sorted(_allowed(sub))[:20]} for sub, asset, entry in chunk],
                  'scope': probe_scope.for_probes(project.pk, [(sub, entry) for sub, _asset, entry in chunk], unattended=unattended)}
        result = sentinel_dispatch.dispatch_or_none(project, 'http_probe', target, host=_hosts_label(sub.name for sub, _a, _e in chunk),
                                                    scan=scan)
        if result is None:  # not claimed, failed or timed out: this chunk runs here (dispatch_or_none recorded the fallback, or raised)
            local += chunk
            continue
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
    return answered, local


def _allowed(sub):
    from cveFeed import probes
    return probes.allowed_names(sub)


def try_dns_resolve(domain, names, scan=None):
    """``(pairs, errors)`` as ``discovery.resolve_names`` returns them (``{(name, ip)}`` and ``{name: reason}``) from a Sentinel's lookups, or
    ``None`` when no Sentinel can take the kind or one did not answer (the caller resolves here). A name the scope policy left out is never sent and
    is an error, as is a name the Sentinel refused: looked up again later, never a name without an address. Raises
    ``ScannerUnavailable`` when no Sentinel can take the work and the kind may not run here."""
    from cveFeed import probe_scope
    project = domain.project
    names = [n for n in dict.fromkeys((n or '').strip().lower().rstrip('.') for n in names) if n]
    if not names or not _offered(project, 'dns_resolve'):
        return None
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
        if result is None:
            return None  # the caller resolves every name here, as before
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
    """``{asset: Verdict}`` for the bucket candidates (``bucket_scan.Candidate``) a Sentinel checked, or ``None`` when no Sentinel can take
    ``bucket_check`` or one did not answer (the caller checks them here, as before). Raises ``ScannerUnavailable`` when no Sentinel can take the
    work and the kind may not run here."""
    from cveFeed import bucket_probe, probe_scope
    if not candidates or not _offered(project, 'bucket_check'):
        return None
    answered = {}
    for start in range(0, len(candidates), MAX_BUCKETS_PER_TASK):
        chunk = candidates[start:start + MAX_BUCKETS_PER_TASK]
        target = {'buckets': [{'id': c.asset, 'provider': c.provider, 'name': c.name, **({'container': c.container} if c.container else {})}
                              for c in chunk],
                  'rate': bucket_probe.request_rate(), 'scope': probe_scope.for_buckets(project.pk, chunk)}
        result = sentinel_dispatch.dispatch_or_none(project, 'bucket_check', target,
                                                    host=_hosts_label(h for c in chunk for h in (c.hosts or [c.asset])))
        if result is None:
            return None
        answered.update({row['id']: bucket_probe.Verdict(**row['verdict']) for row in result.get('buckets') or []})
    return answered


MAX_SUPPLIER_DOMAINS_PER_TASK = 25  # the contract's bound
MAX_SUPPLIER_REQUESTS = 5000  # the contract's bound


def try_suppliers(project, domains, max_requests):
    """``{domain: row}`` for the supplier names a Sentinel checked (each row as ``probe_results.clean_supplier_check`` leaves it), or ``None`` when
    no Sentinel can take ``supplier_check`` or one did not answer (the caller checks them here, as before). A name the task did not ask about, or
    that the Sentinel did not report, is simply not in the answer: it was not checked. ``max_requests`` is what the sweep's budget still allows
    (the Sentinel counts requests as the server does and reports a name that does not fit as partial). Raises ``ScannerUnavailable`` when no Sentinel
    can take the work and the kind may not run here."""
    from cveFeed import probe_scope, slow_web
    domains = list(dict.fromkeys(domains))[:MAX_SUPPLIER_DOMAINS_PER_TASK]
    if not domains or max_requests < 1 or not _offered(project, 'supplier_check'):
        return None
    target = {'domains': domains,
              'pace': {'gap': min(60.0, max(0.25, slow_web.global_gap())), 'host_gap': min(60.0, max(0.5, slow_web.host_gap()))},
              'max_requests': min(MAX_SUPPLIER_REQUESTS, int(max_requests)), 'scope': probe_scope.for_suppliers(project.pk, domains)}
    result = sentinel_dispatch.dispatch_or_none(project, 'supplier_check', target, host=_hosts_label(domains))
    if result is None:
        return None
    if result.get('refused'):
        logger.info('supplier_check task for %s: the scanner refused hops to %s host(s) outside the scope policy', project.pk, len(result['refused']))
    return {row['domain']: row for row in result.get('domains') or []}


MAX_VHOST_ADDRESSES_PER_TASK = 10  # the contract's bound
MAX_SUBDIR_HOSTS_PER_TASK = 10     # the contract's bound


def try_vhosts(project, items, gap):
    """``{address: report}`` for the addresses (``items``: ``[{'id', 'address', 'scheme', 'port', 'names': [{'name', 'own'?}]}]``, ``id`` is the
    address) a Sentinel asked their default response and each name, or ``None`` when no Sentinel can take ``vhost_probe`` or one did not answer
    (the caller asks them here, as before). A report is what ``probe_results.clean_vhost_probe`` keeps of one address; an address or a name the
    Sentinel did not report is missing from the answer: unknown, so it stays due. Raises ``ScannerUnavailable`` when no Sentinel can take the
    work and the kind may not run here."""
    from cveFeed import probe_scope
    if not items or not _offered(project, 'vhost_probe'):
        return None
    answered = {}
    for start in range(0, len(items), MAX_VHOST_ADDRESSES_PER_TASK):
        chunk = items[start:start + MAX_VHOST_ADDRESSES_PER_TASK]
        target = {'addresses': [{'id': i['id'], 'address': i['address'], 'scheme': i['scheme'], 'port': i['port'],
                                 'names': [dict(n) for n in i['names']]} for i in chunk],
                  'gap': gap, 'scope': probe_scope.for_vhosts(project.pk, [i['address'] for i in chunk], [n['name'] for i in chunk for n in i['names']])}
        result = sentinel_dispatch.dispatch_or_none(project, 'vhost_probe', target, host=_hosts_label(i['address'] for i in chunk),
                                                    ips=[i['address'] for i in chunk][:64])
        if result is None:
            return None
        answered.update({row['id']: row for row in result.get('addresses') or []})
    return answered


def try_subdirs(project, items, paths, max_requests, gap):
    """``{id: report}`` for the web hosts (``items``: ``[{'id', 'name', 'scheme', 'port', 'connect_ip'?, 'root'?, 'leads'?}]``) a Sentinel asked
    for their mount paths, or ``None`` when no Sentinel can take ``subdir_probe`` or one did not answer (the caller asks them here, as before).
    A host the Sentinel did not report is missing from the answer: unknown, so it stays due. Raises ``ScannerUnavailable`` when no Sentinel can
    take the work and the kind may not run here."""
    from cveFeed import probe_scope
    if not items or not _offered(project, 'subdir_probe'):
        return None
    answered = {}
    for start in range(0, len(items), MAX_SUBDIR_HOSTS_PER_TASK):
        chunk = items[start:start + MAX_SUBDIR_HOSTS_PER_TASK]
        target = {'hosts': chunk, 'paths': list(paths), 'max_requests': max_requests, 'gap': gap,
                  'scope': probe_scope.for_subdirs(project.pk, [i['name'] for i in chunk])}
        result = sentinel_dispatch.dispatch_or_none(project, 'subdir_probe', target, host=_hosts_label(i['name'] for i in chunk),
                                                    ips=[i['connect_ip'] for i in chunk if i.get('connect_ip')][:64] or None)
        if result is None:
            return None
        answered.update({row['id']: row for row in result.get('hosts') or []})
    return answered


MAX_CHECKS_PER_TASK = 600  # the contract's bound


def try_alive(project, scan, checks):
    """``{id: alive}`` for ``checks`` (``[{'id', 'host', 'ip', 'port', 'scheme'}]``, the zombie check's endpoints) as a Sentinel answered them, or
    ``None`` when no Sentinel can take ``alive_check`` or one did not answer (the caller checks here, as before). A check the Sentinel reports
    with an error, or not at all, is missing from the answer: the caller reads it as unknown, never as gone. Raises ``ScannerUnavailable`` when no
    Sentinel can take the work and the kind may not run here."""
    from cveFeed import probe_scope
    if not checks or not _offered(project, 'alive_check'):
        return None
    answered = {}
    for start in range(0, len(checks), MAX_CHECKS_PER_TASK):
        chunk = checks[start:start + MAX_CHECKS_PER_TASK]
        target = {'checks': chunk, 'scope': probe_scope.for_addresses(project.pk, [c['ip'] for c in chunk])}
        result = sentinel_dispatch.dispatch_or_none(project, 'alive_check', target, host=_hosts_label(c['host'] for c in chunk),
                                                    ips=list(dict.fromkeys(c['ip'] for c in chunk))[:64], scan=scan)
        if result is None:
            return None
        answered.update({row['id']: row['alive'] for row in result.get('checks') or [] if not row.get('error')})
    return answered


MAX_ROUTE_HOSTS_PER_TASK = 25  # the contract's bound (cvengine_scanner.probes.routes.MAX_HOSTS)


def try_routes(project, scan, by_host):
    """``({url: result or error}, local_hosts)`` for the routes of ``by_host`` (``{host: [urls]}``, the route plan's) a Sentinel asked, or ``None`` when no
    Sentinel can take ``route_probe`` (the caller asks every route here). A result has the shape ``route_auth.analyse`` gives (plus the soft 404
    comparison and the front page's scripts, which the scanner did); a route the Sentinel reports with an error, or not at all, is in the answer as an
    ``Exception``, so the caller treats it as unanswered: asked again later, never recorded as a state. ``local_hosts`` are the hosts of a task that
    nobody finished (the caller asks them here, ``dispatch_or_none`` having recorded that, or raised). Raises ``ScannerUnavailable`` when no Sentinel can
    take the work and the kind may not run here: nothing was asked, nothing is recorded, the routes stay due."""
    from cveFeed import probe_scope
    if not by_host or not _offered(project, 'route_probe'):
        return None
    hosts = list(by_host)
    answered, local = {}, []
    for start in range(0, len(hosts), MAX_ROUTE_HOSTS_PER_TASK):
        chunk = hosts[start:start + MAX_ROUTE_HOSTS_PER_TASK]
        target = {'hosts': [{'host': host, 'urls': by_host[host]} for host in chunk],
                  'scope': probe_scope.for_routes(project.pk, scan, chunk)}
        result = sentinel_dispatch.dispatch_or_none(project, 'route_probe', target, host=_hosts_label(chunk), scan=scan)
        if result is None:  # not claimed, failed or timed out: this chunk is asked here (dispatch_or_none recorded the fallback, or raised)
            local += chunk
            continue
        reported = {row['id']: row for row in result.get('routes') or []}
        for host in chunk:
            for url in by_host[host]:
                row = reported.get(url)
                if row is None:
                    answered[url] = RuntimeError('the scanner did not report this route')
                elif row.get('error'):
                    answered[url] = RuntimeError(row['error'])
                else:
                    answered[url] = {'credentials': [(c['type'], c['value']) for c in row['credentials']], 'status': row['status'], 'title': row['title'],
                                     'content_type': row['content_type'], 'state': row['state'], 'evidence': row['evidence'],
                                     'sensitive': row['sensitive'], 'sensitive_score': row['sensitive_score'], 'fp': None, 'bytes': row['bytes']}
        if result.get('refused'):
            logger.info('route_probe task for %s: the scanner refused hops to %s host(s) outside the scope policy', project.pk, len(result['refused']))
    return answered, local


def resolve_for(domain, names, errors=None, scan=None):
    """``discovery.resolve_names`` for the names of target ``domain``, through a Sentinel when one can take ``dns_resolve``: the same answer
    (``{(name, ip)}``, and ``errors`` filled with the lookups that could not be answered)."""
    from cveFeed import discovery
    got = try_dns_resolve(domain, names, scan=scan)
    if got is None:
        return discovery.resolve_names(names, errors=errors)
    pairs, failed = got
    if errors is not None:
        errors.update(failed)
    return pairs
