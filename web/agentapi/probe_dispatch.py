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
    ``None`` when no Sentinel can take the kind or one did not answer (the caller resolves here). A name the scope policy left out is never sent; a
    name the Sentinel refused or did not report is an error (looked up again later), never a name without an address. Raises
    ``ScannerUnavailable`` when no Sentinel can take the work and the kind may not run here."""
    from cveFeed import probe_scope
    project = domain.project
    names = [n for n in dict.fromkeys((n or '').strip().lower().rstrip('.') for n in names) if n]
    if not names or not _offered(project, 'dns_resolve'):
        return None
    scope = probe_scope.for_names(project.pk, domain, names)
    allowed = scope['hosts']
    pairs, errors = set(), {}
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
