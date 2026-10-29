"""Nuclei with a stored sign-in (cveFeed.auth_checks): the authenticated pass that ``nuclei_scan.run_nuclei`` and the CVE template checks run
for the hosts a credential covers.

How the values reach nuclei: in a secrets file (nuclei's ``-sf``, the ``static`` authenticated-scan format) written to a private temporary
directory as a 0600 file and removed afterwards, never on the command line, in the environment or in a log. Nuclei 3.11 matches each
secret against the request's host (and port, unless it is 80 or 443) and sends it only there, so a template that reaches out to another
host sends nothing. The run is also given ``-dr`` (no redirects): nuclei would otherwise carry the custom headers to wherever a redirect
leads. The targets are explicit ``scheme://host[:port]`` URLs for exactly the origins the credential was stored for.

TLS: nuclei's own HTTP client does not verify server certificates, so before a stored sign-in is handed to it the server of each HTTPS origin is
checked here (``trusted_plan``: a pinned handshake that verifies the chain and the name). An origin whose certificate does not verify gets no
sign-in, unless the sign-in has "trust this certificate anyway" switched on, as for the web route check (``route_auth.probe_url``).

Every result line is redacted (``auth_checks.redact_obj``) before anything reads it, so no request, response, curl command or extracted
value that echoes a secret reaches the database, the activity feed or an AI prompt, and a finding it produced is tagged
``seen-while-authenticated``.
"""
import hashlib
import logging
import os
import tempfile

from cveFeed import auth_checks

logger = logging.getLogger(__name__)

SERVICE = 'nuclei-auth'
REFUSED_SERVICE = 'nuclei-auth-refused'  # ledger: an origin whose stored sign-in was withheld for its certificate (asset: <url>@<credential revision>)
CHUNK = 100  # targets per nuclei process, as in nuclei_scan


def scope_for_scan(scan_id):
    """The ``AuthScope`` of the scan's target, or None when the target has no stored sign-in (the common case: nothing else changes)."""
    from startScan.models import ScanHistory
    domain = ScanHistory.objects.select_related('domain').get(pk=scan_id).domain
    scope = auth_checks.AuthScope.for_domain(domain)
    return scope if scope else None


def trusted_plan(plan, project, check=None):
    """``(kept, refused)`` for the ``plan`` of ``auth_checks.plan_nuclei``: ``kept`` are the items whose sign-in may be sent (plain HTTP
    origins, which have no certificate; HTTPS ones whose certificate verifies; HTTPS ones whose credential has ``allow_untrusted_certificate``),
    ``refused`` is ``[(url, reason)]`` for the rest. One handshake per host and port. ``check`` is ``auth_checks.certificate_verifies``."""
    from urllib.parse import urlsplit
    check = check or auth_checks.certificate_verifies
    seen, kept, refused = {}, [], []
    for item in plan:
        url, sign_in, _key = item
        parts = urlsplit(url)
        if parts.scheme != 'https' or sign_in.allow_untrusted_certificate:
            kept.append(item)
            continue
        where = (parts.hostname, parts.port or 443)
        if where not in seen:
            seen[where] = check(where[0], where[1], project)
        ok, reason = seen[where]
        if ok:
            kept.append(item)
        else:
            refused.append((url, reason))
    return kept, refused


def refusal_line(refused):
    """The activity sentence for the origins ``trusted_plan`` refused: what was not sent, why, and the switch that changes it. No value in it."""
    urls = sorted({url for url, _reason in refused})
    more = f' and {len(urls) - 5} more' if len(urls) > 5 else ''
    return (f'the stored sign-in was not sent to {", ".join(urls[:5])}{more}: the server certificate does not verify ({refused[0][1]}). '
            f'Turn on "Trust this certificate anyway" for the sign-in to send it regardless')


def ledger_service(base, stream_is_real):
    """The coverage key of the authenticated pass for the plain pass keyed ``base``: the same selection (tags, template policy), kept apart so
    a host covered anonymously is still run signed in, and a replaced credential (the asset carries its revision) is run again at once."""
    from cveFeed import nuclei_scan
    if stream_is_real:
        base = f'{base}:{nuclei_scan.approved_templates()[1]}'
    return f'{SERVICE}:{hashlib.sha1(base.encode()).hexdigest()[:16]}'


def _asset(url, cred):
    return f'{url}@{auth_checks.revision(cred)}'


def run_authenticated(scan, scope, targets, stream, tags=None, severities=None, service='nuclei', force=False):
    """Run the plain pass's selection (``tags``, ``severities``) signed in over the nuclei ``targets`` the scope covers. Returns a summary
    dict (``targets``, ``findings``, ``new``, ``error`` when it failed); never raises, so the plain pass's result stands whatever happens here."""
    from cveFeed import activity, ledger, nuclei_scan
    from cveFeed.models import DiscoveryEvent
    from reNgine import resources
    from reNgine.definitions import NUCLEI_SEVERITY_MAP
    from reNgine.resources import MemoryKill
    from reNgine.tasks import parse_nuclei_result, save_vulnerability
    from startScan.models import Subdomain
    from targetApp.target_types import scannable_hosts
    domain, project = scan.domain, scan.domain.project_id
    values = scope.secret_values()
    summary = {'targets': 0, 'findings': 0, 'new': 0}
    try:
        auth_checks.note_expired(scope, domain, project, scan)
        if resources.global_pause_requested(fail_closed=True) or resources.abort_requested(scan.id):
            return {**summary, 'skipped': 'paused or stopped'}
        # the normal vetting again, right before the credential could be sent: a name that now resolves somewhere a scanner must not go, an
        # excluded host or an archived one is dropped, and with it any chance of the credential going there
        vetted = scannable_hosts(list(dict.fromkeys(targets)), project=project)
        plan = auth_checks.plan_nuclei(scope, vetted)
        if not plan:
            return {**summary, 'skipped': 'no covered host'}
        planned = plan
        plan, refused = trusted_plan(plan, project)
        if refused:
            activity.log('run_check', f'Authenticated nuclei for {domain.name}: {refusal_line(refused)}', project=project, scan_id=scan.id,
                         status='failed')
            kept = {id(item) for item in plan}
            # a durable record of what was withheld, for the check coverage view (which says the sign-in is not sent, not that it is planned)
            ledger.record(REFUSED_SERVICE, [_asset(item[0], item[1]) for item in planned if id(item) not in kept], project, scan, 'refused')
        if not plan:
            return {**summary, 'skipped': 'certificate not trusted'}
        stream_is_real = stream is nuclei_scan.stream_nuclei
        ledger_name = ledger_service(service, stream_is_real)
        assets = {_asset(url, cred): (url, cred, key) for url, cred, key in plan}
        done = set() if force else ledger.fresh(ledger_name, list(assets), project)
        todo = [a for a in assets if ledger._norm(a) not in done]
        if not todo:
            activity.log('run_check', f'Authenticated nuclei skipped for {domain.name}: its signed-in hosts were checked in the last '
                         f'{ledger.ttl_label(ledger_name)}', project=project, scan_id=scan.id)
            return {**summary, 'skipped': 'recent'}
        by_name = {sub.name: sub for sub in Subdomain.objects.filter(scan_history=scan)}
        profiles = ['normal', 'light'] if stream_is_real else ['normal']
        with ledger.claim_many(f'{ledger_name}@{project}', todo) as won:
            won_assets = [a for a in todo if ledger._norm(a) in set(won)]
            if not won_assets:
                return {**summary, 'skipped': 'busy'}
            running = activity.log('run_check', f'Authenticated nuclei is checking {len(won_assets)} signed-in target(s) of {domain.name}, '
                                   f'scan #{scan.id}', project=project, status='running', scan_id=scan.id)
            counts, scanned = {'findings': 0, 'only_signed_in': 0}, []
            try:
                for start in range(0, len(won_assets), CHUNK):
                    chunk = won_assets[start:start + CHUNK]
                    items = [assets[a] for a in chunk]
                    with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as handle:
                        handle.write('\n'.join(url for url, _cred, _key in items) + '\n')
                        path = handle.name
                    try:
                        with auth_checks.secrets_file(auth_checks.entries_for(items)) as secret_path:
                            for profile in profiles:
                                kwargs = {'secret_file': secret_path}
                                if tags:
                                    kwargs['tags'] = tags
                                if severities:
                                    kwargs['severities'] = severities
                                if profile != 'normal':
                                    kwargs['profile'] = profile
                                try:
                                    for line in stream(path, **kwargs):
                                        line = auth_checks.redact_obj(line, values)
                                        try:
                                            data = parse_nuclei_result(line)
                                        except (KeyError, TypeError):
                                            continue
                                        data['tags'] = [*(data.get('tags') or []), auth_checks.SEEN_TAG]
                                        host = nuclei_scan.host_of(line)
                                        vuln, created = save_vulnerability(
                                            target_domain=domain, scan_history=scan, subdomain=by_name.get(host),
                                            http_url=line.get('matched-at') or line.get('host') or host, **data)
                                        counts['findings'] += 1
                                        sev = line.get('info', {}).get('severity', 'unknown')
                                        if created:
                                            counts['only_signed_in'] += 1
                                            DiscoveryEvent.objects.create(scan=scan, domain=domain, type='FINDING', host=host, module='nuclei',
                                                                          label=f"{data['name']} ({sev}), {auth_checks.SEEN_LABEL}")
                                            if NUCLEI_SEVERITY_MAP.get(sev, -1) >= 2:
                                                activity.log('validate', f"Nuclei confirmed {data['name']} ({sev}) on {host}, "
                                                             f'{auth_checks.SEEN_LABEL}', project=project, severity=sev)
                                    break
                                except MemoryKill:
                                    if profile == profiles[-1]:
                                        raise
                                    activity.log('run_check', f'Authenticated nuclei ran out of memory on {domain.name}; retrying with '
                                                 f'fewer parallel hosts', project=project, scan_id=scan.id)
                    finally:
                        os.unlink(path)
                    ledger.record(ledger_name, chunk, project, scan)
                    scanned += chunk
            except Exception as exc:  # noqa: BLE001 - the plain pass's result stands; say what failed without any value
                message = auth_checks.safe_error(exc, values)
                logger.error('authenticated nuclei failed for scan %s: %s', scan.id, message)
                ledger.record(ledger_name, [a for a in won_assets if a not in set(scanned)], project, scan, 'failed')
                activity.settle(running, 'failed', message=f'Authenticated nuclei failed for {domain.name}: {message}')
                return {**summary, 'targets': len(won_assets), 'error': message}
        scope.mark_used()
        activity.settle(running, 'done', message=(
            f'Authenticated nuclei finished {domain.name}: {counts["findings"]} finding(s) {auth_checks.SEEN_LABEL} '
            f'({counts["only_signed_in"]} not seen without signing in), {len(won_assets)} target(s)'), **counts)
        return {'targets': len(won_assets), 'findings': counts['findings'], 'new': counts['only_signed_in']}
    except Exception as exc:  # noqa: BLE001
        message = auth_checks.safe_error(exc, values)
        logger.error('authenticated nuclei could not run for scan %s: %s', scan.id, message)
        return {**summary, 'error': message}


def merge_template_outcomes(path, hosts, outcomes, project):
    """The CVE template check (``templategen.run_cve_tests``) for hosts a stored sign-in covers: after the plain run of the template at
    ``path`` over ``hosts`` gave ``outcomes``, run it once more signed in over the covered hosts, and where only the signed-in run matched,
    return that outcome (marked ``authenticated``) in place of the plain one. Other outcomes are returned unchanged, and a signed-in run
    that cannot happen (paused, nothing covered, nuclei failed) leaves the plain result as it was."""
    from cveFeed import templategen
    from reNgine import resources
    from targetApp.target_types import scannable_hosts
    creds = auth_checks.credentials_for_hosts(project, hosts)
    if not creds:
        return outcomes
    scope = auth_checks.AuthScope(creds)
    values = scope.secret_values()
    try:
        if resources.global_pause_requested(fail_closed=True):
            return outcomes
        plan = auth_checks.plan_nuclei(scope, scannable_hosts(list(hosts), project=project))
        plan, refused = trusted_plan(plan, project)
        if refused:
            logger.info('signed-in template check: the stored sign-in was withheld from %d origin(s) whose certificate does not verify', len(refused))
        if not plan:
            return outcomes
        with auth_checks.secrets_file(auth_checks.entries_for(plan)) as secret_path:
            signed_in = templategen.run_template(path, [item[0] for item in plan], secret_file=secret_path, redact=values)
        scope.mark_used()
    except Exception as exc:  # noqa: BLE001 - MemoryKill, a timeout or nuclei failing: the plain result stands
        logger.error('signed-in template check could not run: %s', auth_checks.safe_error(exc, values))
        return outcomes
    matched = {}
    for row in signed_in:
        if row.get('vulnerable') and not row.get('error'):
            matched.setdefault(templategen._host_key(row['host']), row)
    merged = []
    for outcome in outcomes:
        found = matched.get(templategen._host_key(outcome['host']))
        if found is not None and not outcome.get('vulnerable'):
            outcome = {**found, 'host': outcome['host'], 'authenticated': True}
        merged.append(outcome)
    return merged
