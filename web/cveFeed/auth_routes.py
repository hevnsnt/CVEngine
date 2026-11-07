"""The web route check, signed in: for the routes a stored sign-in (cveFeed.auth_checks) covers, the same bounded GET as
the anonymous route check but with the target's headers and cookie, so a person can see what the application answers behind its login.

Where it runs: on the built-in scanner only (task kind ``route_probe_signed``, ``agentapi.probe_dispatch.try_signed_routes``), never on this server: the
server keeps the credential store and decides which routes a credential covers, but it sends no stored sign-in to any host. A task carries the routes
and a scope policy plus ``secret_ref`` (a reference to the credential, never a value); the scanner reads the credential once through
``POST sentinel/tasks/<id>/secret``, sends it only to a route that credential was stored for, follows no redirect and returns no value. Without a
built-in scanner that reads stored sign-ins the pass waits (``ScannerUnavailable``): nothing is recorded and the routes stay due.

The anonymous answer stays what a route's state, auth-change history and sensitive-data scan are about; this pass only adds
``evidence['authenticated']`` to the route (state, status, title, redirect target, when, which credential revision), marked
``seen_while_authenticated``. The body of a signed-in page is never searched for sensitive data and never stored: it belongs to the
test account.

Scope: ``AuthScope.credential`` decides per URL (exact host, ``scheme:port`` among the origins, not expired) before a task is built, and the scanner
decides it again from the credential it reads; the SSRF gate (``route_auth.host_allowed``), the exclusions and the pause apply as for the anonymous
check, and redirects are never followed. The values go only over a connection whose certificate verifies, unless the sign-in has "trust this
certificate anyway" switched on; a route not sent for that reason is counted and said in the activity line.
"""
import logging
from urllib.parse import urlsplit

from django.utils import timezone

from cveFeed import auth_checks

logger = logging.getLogger(__name__)

SERVICE = 'route-auth-signed'
UNTRUSTED_CERTIFICATE = 'sign-in not sent: the server certificate does not verify'  # what the scanner reports (and starts its error with) for a route it did not send to
LOGIN_STATES = ('login', 'sso', 'session_required')  # a signed-in answer like these says the stored session did not work


def _origin(url):
    parts = urlsplit(url)
    host = (parts.hostname or '').lower()
    return host, parts.scheme, parts.port or (443 if parts.scheme == 'https' else 80)


def signed_evidence(result, cred, values, now):
    """What is kept of one signed-in answer: state and the few facts the anonymous evidence has, redacted. Never the body."""
    evidence = result.get('evidence') or {}
    keep = {'seen_while_authenticated': True, 'state': result['state'], 'http_status': result.get('status'),
            'title': result.get('title') or '', 'content_type': result.get('content_type') or '',
            'redirect_to': evidence.get('redirect_to', ''), 'provider': evidence.get('provider', ''),
            'checked_at': now.isoformat(), 'revision': auth_checks.revision(cred)}
    return auth_checks.redact_obj(keep, values)


def _ask(project, scan, cred, by_host):
    """The seam: ``{url: result or Exception}`` for the routes of one credential, through the built-in scanner (tests replace it)."""
    from agentapi import probe_dispatch
    return probe_dispatch.try_signed_routes(project, scan, cred, by_host)


def run_signed_in(scan_id, force=False, ask=None):
    """The signed-in pass for the scan's routes. Returns None when the target has no stored sign-in, else a summary dict (``routes``,
    ``differs`` answers that differ from the anonymous one, ``not_signed_in`` routes that still showed a login page, ``errors``);
    never raises, so the anonymous check's result stands. ``ask(project, scan, credential, {host: [urls]})`` replaces the scanner (tests)."""
    from cveFeed import activity, ledger, route_auth
    from cveFeed.models import RouteAuth
    from reNgine import resources
    from startScan.models import ScanHistory
    ask = ask or _ask
    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
    domain, project = scan.domain, scan.domain.project_id
    scope = auth_checks.AuthScope.for_domain(domain)
    if not scope:
        return None
    values = scope.secret_values()
    summary = {'routes': 0, 'differs': 0, 'not_signed_in': 0, 'errors': 0, 'untrusted_certificate': 0}
    try:
        auth_checks.note_expired(scope, domain, project, scan)
        if resources.global_pause_requested(fail_closed=True) or resources.abort_requested(scan_id):
            return {**summary, 'skipped': 'paused or stopped'}
        items = []  # (host, url, credential)
        for host, urls in route_auth._plan(scan).items():
            if not route_auth.host_allowed(host, project):  # the SSRF gate, as for the anonymous check: no task names a host a scanner must not touch
                continue
            for url in urls:
                cred = scope.credential(*_origin(url))
                if cred is not None:
                    items.append((host, url, cred))
        if not items:
            return {**summary, 'skipped': 'no covered route'}
        rows = {}
        for part in route_auth._chunks([url for _h, url, _c in items]):
            rows.update({r.url: r for r in RouteAuth.objects.filter(project_id=project, url__in=part)})
        revisions = {url: auth_checks.revision(cred) for _h, url, cred in items}
        assets = {f'{url}@{revisions[url]}': (host, url, cred) for host, url, cred in items}
        done = set() if force else ledger.fresh(SERVICE, list(assets), project)
        todo = []
        for asset, (_host, url, _cred) in assets.items():
            row = rows.get(url)
            if row is None:  # a route the anonymous check could not reach has no row to add to
                continue
            # a route the anonymous check just stored again has lost its signed-in evidence (the row is rewritten whole): it is asked again
            kept = (row.evidence or {}).get('authenticated') or {}
            if force or ledger._norm(asset) not in done or kept.get('revision') != revisions[url]:
                todo.append(asset)
        if not todo:
            return {**summary, 'skipped': 'recent'}
        with ledger.claim_many(f'{SERVICE}@{project}', todo) as won:
            won_set = set(won)
            mine = [a for a in todo if ledger._norm(a) in won_set]
            if not mine:
                return {**summary, 'skipped': 'busy'}
            running = activity.log('run_check', f'Checking {len(mine)} web routes of {domain.name} signed in', project=project,
                                   status='running', scan_id=scan.id)
            finished, failed = [], []
            by_cred = {}  # credential pk -> (credential, {host: [asset]}): one task set per stored sign-in
            for asset in mine:
                host, _url, cred = assets[asset]
                by_cred.setdefault(cred.pk, (cred, {}))[1].setdefault(host, []).append(asset)
            try:
                for cred, hosts in by_cred.values():
                    if resources.abort_requested(scan_id) or resources.global_pause_requested(fail_closed=True):
                        break
                    answers = ask(scan.domain.project, scan, cred, {host: [assets[a][1] for a in group] for host, group in hosts.items()})
                    for asset in (a for group in hosts.values() for a in group):
                        _host, url, _cred = assets[asset]
                        result = answers.get(url)
                        if result is None or isinstance(result, Exception):  # a timeout, a refusal or a route not asked: not an answer; no value in the message
                            message = auth_checks.safe_error(result, values) if isinstance(result, Exception) else 'not answered'
                            if UNTRUSTED_CERTIFICATE in message:  # nothing was sent; the person is told why and what to do
                                summary['untrusted_certificate'] += 1
                            else:
                                logger.info('signed-in route check failed: %s', message)
                                summary['errors'] += 1
                            failed.append(asset)
                            continue
                        now = timezone.now()
                        row = rows[url]
                        evidence = dict(row.evidence or {})
                        evidence['authenticated'] = signed_evidence(result, cred, values, now)
                        RouteAuth.objects.filter(pk=row.pk).update(evidence=evidence)
                        summary['routes'] += 1
                        summary['differs'] += result['state'] != row.auth_state
                        summary['not_signed_in'] += result['state'] in LOGIN_STATES
                        finished.append(asset)
            except resources.ScannerUnavailable as exc:  # no built-in scanner can take it and it may not run here: not a failure, the routes stay due
                ledger.record(SERVICE, finished, project, scan)
                message = f'no scanner could take this work ({exc.kind}); the targets stay due until one can'
                logger.warning('signed-in route check of scan %s is waiting for a scanner: %s', scan.id, exc)
                activity.settle(running, 'done', message=f'Signed-in web route check for {domain.name} is waiting: {message}')
                return {**summary, 'skipped': message}
            ledger.record(SERVICE, finished, project, scan)
            if failed:
                ledger.record(SERVICE, failed, project, scan, status='failed')
        note = (f'; {summary["not_signed_in"]} still showed a login page (the stored session may no longer be valid)'
                if summary['not_signed_in'] else '')
        activity.settle(running, 'done', message=(
            f'Checked {summary["routes"]} web routes of {domain.name} signed in ({auth_checks.SEEN_LABEL}): {summary["differs"]} answered '
            f'differently from the anonymous check{note}' + (f'; {summary["errors"]} could not be reached' if summary['errors'] else '')
            + (f'; the sign-in was not sent to {summary["untrusted_certificate"]} because the server certificate does not verify (turn on '
               f'"Trust this certificate anyway" for the sign-in to send it regardless)' if summary['untrusted_certificate'] else '')),
            routes=summary['routes'])
        return summary
    except Exception as exc:  # noqa: BLE001
        message = auth_checks.safe_error(exc, values)
        logger.error('signed-in route check failed for scan %s: %s', scan_id, message)
        return {**summary, 'error': message}
