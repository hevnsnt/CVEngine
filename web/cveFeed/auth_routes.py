"""The web route check, signed in: for the routes a stored sign-in (cveFeed.auth_checks) covers, the same bounded GET as
``route_auth.probe_url`` but with the target's headers and cookie, so a person can see what the application answers behind its login.

The anonymous answer stays what a route's state, auth-change history and sensitive-data scan are about; this pass only adds
``evidence['authenticated']`` to the route (state, status, title, redirect target, when, which credential revision), marked
``seen_while_authenticated``. The body of a signed-in page is never searched for sensitive data and never stored: it belongs to the
test account.

Scope: ``AuthScope.credential`` decides per URL (exact host, ``scheme:port`` among the origins, not expired) before anything is sent; the
SSRF gate (``route_auth.host_allowed``), the pinned transport, the exclusions and the pause apply as for the anonymous check, and
redirects are never followed.
"""
import functools
import logging
import time
from urllib.parse import urlsplit

from django.utils import timezone

from cveFeed import auth_checks

logger = logging.getLogger(__name__)

SERVICE = 'route-auth-signed'
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


def run_signed_in(scan_id, probe, force=False):
    """The signed-in pass for the scan's routes. Returns None when the target has no stored sign-in, else a summary dict (``routes``,
    ``differs`` answers that differ from the anonymous one, ``not_signed_in`` routes that still showed a login page, ``errors``);
    never raises, so the anonymous check's result stands."""
    from cveFeed import activity, ledger, route_auth
    from cveFeed.models import RouteAuth
    from reNgine import resources
    from startScan.models import ScanHistory
    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
    domain, project = scan.domain, scan.domain.project_id
    scope = auth_checks.AuthScope.for_domain(domain)
    if not scope:
        return None
    values = scope.secret_values()
    summary = {'routes': 0, 'differs': 0, 'not_signed_in': 0, 'errors': 0}
    try:
        auth_checks.note_expired(scope, domain, project, scan)
        if resources.global_pause_requested(fail_closed=True) or resources.abort_requested(scan_id):
            return {**summary, 'skipped': 'paused or stopped'}
        items = []  # (host, url, credential)
        for host, urls in route_auth._plan(scan).items():
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
        if probe is route_auth.probe_url:
            send = functools.partial(route_auth.probe_url, project=project, auth_scope=scope)
        else:
            send = functools.partial(probe, auth_scope=scope)
        with ledger.claim_many(f'{SERVICE}@{project}', todo) as won:
            won_set = set(won)
            mine = [a for a in todo if ledger._norm(a) in won_set]
            if not mine:
                return {**summary, 'skipped': 'busy'}
            running = activity.log('run_check', f'Checking {len(mine)} web routes of {domain.name} signed in', project=project,
                                   status='running', scan_id=scan.id)
            finished, failed, last_host = [], [], None
            with resources.heavy_job('route-probe', label=f'{domain.name}: {len(mine)} signed-in routes'):
                for asset in mine:
                    host, url, cred = assets[asset]
                    if resources.abort_requested(scan_id) or resources.global_pause_requested(fail_closed=True):
                        break
                    if not route_auth.host_allowed(host, project):  # the SSRF gate, as for the anonymous check
                        continue
                    if last_host == host:
                        time.sleep(route_auth.PER_REQUEST_GAP)
                    last_host = host
                    try:
                        result = route_auth.analyse(send(url))
                    except Exception as exc:  # noqa: BLE001 - a timeout or refusal is not an answer; keep no value in the message
                        logger.info('signed-in route check failed: %s', auth_checks.safe_error(exc, values))
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
            ledger.record(SERVICE, finished, project, scan)
            if failed:
                ledger.record(SERVICE, failed, project, scan, status='failed')
        scope.mark_used()
        note = (f'; {summary["not_signed_in"]} still showed a login page (the stored session may no longer be valid)'
                if summary['not_signed_in'] else '')
        activity.settle(running, 'done', message=(
            f'Checked {summary["routes"]} web routes of {domain.name} signed in ({auth_checks.SEEN_LABEL}): {summary["differs"]} answered '
            f'differently from the anonymous check{note}' + (f'; {summary["errors"]} could not be reached' if summary['errors'] else '')),
            routes=summary['routes'])
        return summary
    except Exception as exc:  # noqa: BLE001
        message = auth_checks.safe_error(exc, values)
        logger.error('signed-in route check failed for scan %s: %s', scan_id, message)
        return {**summary, 'error': message}
