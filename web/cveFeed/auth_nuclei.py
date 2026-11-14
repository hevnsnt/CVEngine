"""A template pass with a stored sign-in (cveFeed.auth_checks): the authenticated pass that ``nuclei_scan.run_nuclei`` runs for the hosts a credential
covers.

Where it runs: on the built-in scanner only, through the stream's ``signed_in`` runner (``sentinel_dispatch.wrap_nuclei_stream``): one task per
credential and chunk, carrying only ``secret_ref`` (a reference to the credential); the built-in scanner reads the credential once through
``POST sentinel/tasks/<id>/secret`` and no other Sentinel is ever offered the task. Without a built-in scanner that reads stored sign-ins the pass
waits for one (nothing is recorded, the targets stay due): it never runs on this server, and the server never writes the values to a file. The
scanner keeps them in a 0600 file on a memory file system for the run and wipes it afterwards, never on a command line, in the environment or in a
log; it sends each only to the host it was stored for and follows no redirect. The targets are explicit ``scheme://host[:port]`` URLs for exactly
the origins the credential was stored for.

TLS: the scanner's HTTP client does not verify server certificates. A separate preflight handshake cannot secure the later connection that
carries a sign-in. Therefore an HTTPS origin receives no stored sign-in unless its owner explicitly enabled the unverified-certificate
switch. The in-process web route check verifies its own TLS connection and does not need this exception.

Every result line is redacted (``auth_checks.redact_obj``) before anything reads it, so no request, response, curl command or extracted
value that echoes a secret reaches the database, the activity feed or an AI prompt, and a finding it produced is tagged
``seen-while-authenticated``.
"""
import hashlib
import logging

from cvengine_scanner import flags as scan_flags

from cveFeed import auth_checks

logger = logging.getLogger(__name__)

SERVICE = 'nuclei-auth'
REFUSED_SERVICE = 'nuclei-auth-refused'  # ledger: an origin whose stored sign-in was withheld for its certificate (asset: <url>@<credential revision>)
CHUNK = 100  # targets per call to the stream, as in nuclei_scan


def scope_for_scan(scan_id):
    """The ``AuthScope`` of the scan's target, or None when the target has no stored sign-in (the common case: nothing else changes)."""
    from startScan.models import ScanHistory
    domain = ScanHistory.objects.select_related('domain').get(pk=scan_id).domain
    scope = auth_checks.AuthScope.for_domain(domain)
    return scope if scope else None


def trusted_plan(plan, project):
    """Keep explicit HTTP origins and HTTPS origins whose owner accepted Nuclei's unverified TLS.

    A successful certificate preflight cannot authenticate Nuclei's later, separate connection. In particular, an active network
    attacker could allow the preflight through and intercept the request carrying the stored sign-in. ``project`` is retained in the
    interface for callers; this policy does not need a network request.
    """
    from urllib.parse import urlsplit
    kept, refused = [], []
    for item in plan:
        url = item.url
        parts = urlsplit(url)
        if parts.scheme != 'https' or item.credential.allow_untrusted_certificate:
            kept.append(item)
            continue
        refused.append((url, 'Nuclei does not verify TLS on the request carrying the sign-in'))
    return kept, refused


def refusal_line(refused):
    """The activity sentence for the origins ``trusted_plan`` refused: what was not sent, why, and the switch that changes it. No value in it."""
    urls = sorted({url for url, _reason in refused})
    more = f' and {len(urls) - 5} more' if len(urls) > 5 else ''
    return (f'the stored sign-in was not sent to {", ".join(urls[:5])}{more}: {refused[0][1]}. '
            f'Turn on "Trust this certificate anyway" for the sign-in only if you accept Nuclei\'s unverified TLS risk')


def ledger_service(base):
    """The coverage key of the authenticated pass for the plain pass keyed ``base``: the same selection (tags, template policy), kept apart so
    a host covered anonymously is still run signed in, and a replaced credential (the asset carries its revision) is run again at once."""
    return f'{SERVICE}:{hashlib.sha1(base.encode()).hexdigest()[:16]}'


def _asset(url, cred):
    return f'{url}@{auth_checks.revision(cred)}'


def run_authenticated(scan, scope, targets, stream, tags=None, severities=None, service='nuclei', force=False):
    """Run the plain pass's selection (``tags``, ``severities``) signed in over the nuclei ``targets`` the scope covers. Returns a summary
    dict (``targets``, ``findings``, ``new``, ``error`` when it failed); never raises, so the plain pass's result stands whatever happens here."""
    from cveFeed import activity, ledger, nuclei_fp, template_gates
    from cveFeed.models import DiscoveryEvent
    from reNgine import resources
    from reNgine.definitions import NUCLEI_SEVERITY_MAP
    from reNgine.resources import ScannerUnavailable
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
            ledger.record(REFUSED_SERVICE, [_asset(item.url, item.credential) for item in planned if id(item) not in kept], project, scan, 'refused')
        if not plan:
            return {**summary, 'skipped': 'Nuclei TLS is not verified'}
        dispatched = getattr(stream, 'signed_in', None)  # the built-in scanner's secure read (sentinel_dispatch.signed_in_stream)
        if dispatched is None:  # a stream with no secure read (an internal one): a stored sign-in is sent nowhere else
            return {**summary, 'skipped': 'a signed-in pass runs only on the built-in scanner'}
        ledger_name = ledger_service(service)
        assets = {_asset(item.url, item.credential): item for item in plan}
        done = set() if force else ledger.fresh(ledger_name, list(assets), project)
        todo = [a for a in assets if ledger._norm(a) not in done]
        if not todo:
            activity.log('run_check', f'Authenticated nuclei skipped for {domain.name}: its signed-in hosts were checked in the last '
                         f'{ledger.ttl_label(ledger_name)}', project=project, scan_id=scan.id)
            return {**summary, 'skipped': 'recent'}
        by_name = {sub.name: sub for sub in Subdomain.objects.filter(scan_history=scan)}
        with ledger.claim_many(f'{ledger_name}@{project}', todo) as won:
            won_assets = [a for a in todo if ledger._norm(a) in set(won)]
            if not won_assets:
                return {**summary, 'skipped': 'busy'}
            running = activity.log('run_check', f'Authenticated nuclei is checking {len(won_assets)} signed-in target(s) of {domain.name}, '
                                   f'scan #{scan.id}', project=project, status='running', scan_id=scan.id)
            counts, scanned = {'findings': 0, 'only_signed_in': 0}, []
            same_body = nuclei_fp.SameBody(project, scan)
            try:
                for start in range(0, len(won_assets), CHUNK):
                    chunk = won_assets[start:start + CHUNK]
                    items = [assets[a] for a in chunk]
                    kwargs = {}
                    if tags:
                        kwargs['tags'] = tags
                    if severities:
                        kwargs['severities'] = severities
                    lines = [auth_checks.redact_obj(line, values) for line in dispatched(items, **kwargs)]
                    same_body.prefetch(lines)  # the control reads the chunk's error pages need, by a Sentinel (ScannerUnavailable: the chunk stays due)
                    for line in lines:
                        verdict = same_body.judge(line) if isinstance(line, dict) else nuclei_fp.CLEAN
                        if verdict == nuclei_fp.ARTEFACT:
                            continue  # the host answers anything with this error page (cveFeed.nuclei_fp)
                        try:
                            data = parse_nuclei_result(line)
                        except (KeyError, TypeError):
                            continue
                        data['tags'] = [*(data.get('tags') or []), auth_checks.SEEN_TAG, *([nuclei_fp.UNSCREENED_TAG] if verdict == nuclei_fp.UNSCREENED else [])]
                        host = scan_flags.host_of(line)
                        if template_gates.held_back(line, by_name.get(host)):
                            continue  # a template that matches patched releases too, on a patched host
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
                    ledger.record(ledger_name, chunk, project, scan)
                    scanned += chunk
            except ScannerUnavailable as exc:  # no built-in scanner can take it and nuclei may not run here: not a failure, the targets stay due
                message = auth_checks.safe_error(exc, values)
                left = len([a for a in won_assets if a not in set(scanned)])
                activity.settle(running, 'done', message=f'Authenticated nuclei for {domain.name} is waiting: no scanner could take this work '
                                f'({exc.kind}); {left} signed-in target(s) stay due until one can')
                return {**summary, 'targets': len(won_assets), 'skipped': message}
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
