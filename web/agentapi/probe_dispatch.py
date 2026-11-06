"""The probe kinds through a Sentinel (contract version 3): ``http_probe`` (the version and identity probes, ``cveFeed.probes``) and
``dns_resolve`` (``cveFeed.discovery.resolve_names``).

The server keeps the choice of what to probe (the plan, the ledger, the per-scan cap), the scope policy (``cveFeed.probe_scope``), the
validation of what comes back (``agentapi.probe_results``) and what is stored. The Sentinel runs the requests (``cvengine_scanner.probes``) under
the policy the task carries. Like every other kind: a project with no Sentinel for the kind runs the work here as before, and when
``CVENGINE_LOCAL_FALLBACK`` takes the kind off its list the stage waits for a scanner instead (``reNgine.resources.ScannerUnavailable``) and the
work stays due."""
import logging
import os

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
    own and are not a CNAME). ``None`` when no Sentinel can take ``hygiene_check`` or the one that took it did not answer (the caller does the work here, as
    before). Raises ``ScannerUnavailable`` when no Sentinel can take the work and the kind may not run here. Nothing in the answer says an endpoint or a
    name was checked unless its row is there: the caller reads a missing one as unknown."""
    from cveFeed import probe_scope
    project = domain.project
    if not (tls or mail) or not _offered(project, 'hygiene_check'):
        return None
    tls, mail = list(tls)[:MAX_TLS_PER_TASK], list(mail)[:MAX_MAIL_PER_TASK]
    target = {'tls': [{'host': h, 'port': p} for h, p in tls], 'mail': [{'name': n, 'always': bool(a)} for n, a in mail],
              'confirm_resolvers': _confirm_resolvers(), 'rdap': os.environ.get('CVENGINE_HYGIENE_RDAP', '1') != '0',
              'scope': probe_scope.for_hygiene(project.pk, tls, [n for n, _a in mail])}
    result = sentinel_dispatch.dispatch_or_none(project, 'hygiene_check', target, host=_hosts_label([domain.name] + [h for h, _p in tls]))
    if result is None:
        return None
    if result.get('refused'):
        logger.info('hygiene_check task for %s: the scanner refused %s host(s) outside the scope policy', project.pk, len(result['refused']))
    return result


def try_dangling(project, checks, providers):
    """``{id: row}`` for the baddns findings (``checks``: ``[{'id', 'host', 'kind', 'triggers'}]``) a Sentinel rated, each row ``{'state': 'rated'|'unknown',
    'severity', 'drop', 'note', 'zone'}``; ``None`` when no Sentinel can take ``dangling_dns_check`` or one did not answer (the caller rates them here, as
    before). A finding the Sentinel did not report is missing from the answer: the caller keeps baddns's own rating. Raises ``ScannerUnavailable``
    when no Sentinel can take the work and the kind may not run here."""
    from cveFeed import probe_scope
    if not checks or not _offered(project, 'dangling_dns_check'):
        return None
    answered = {}
    for start in range(0, len(checks), MAX_FINDINGS_PER_TASK):
        chunk = checks[start:start + MAX_FINDINGS_PER_TASK]
        scope = probe_scope.for_dangling(project.pk, [c['host'] for c in chunk])
        chunk = [c for c in chunk if c['host'] in scope['hosts']]  # a host the policy leaves out (excluded, archived, out of the bounty scope) is never sent
        if not chunk:
            continue
        target = {'checks': chunk, 'providers': providers, 'scope': scope}
        result = sentinel_dispatch.dispatch_or_none(project, 'dangling_dns_check', target, host=_hosts_label(c['host'] for c in chunk))
        if result is None:
            return None
        answered.update({row['id']: row for row in result.get('ratings') or []})
    return answered


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
