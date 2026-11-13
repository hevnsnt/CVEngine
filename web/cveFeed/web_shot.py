"""Web screenshots: a picture of the front page of every web port of every host, taken by a real browser on a Sentinel (task kind ``web_screenshot``).

Why this exists: the only screenshots cvENGINE used to take were a side effect of a full discovery run, so a host that was
rescanned, found by certificate transparency, retested or only ever assessed never got one, and a rescan could hide the one it had.

How it works (docs/PIPELINE.md, "Web screenshots"):

* **Queue, then capture.** Planning a capture only writes a ``HostScreenshot`` row with outcome ``queued``; it is cheap and happens in three
  places: the scan stage after the port stage (``queue_for_scan``: full scans, host assessments, Rescan host, certificate transparency hosts and
  retests all run it), the Take screenshot button (``queue_host``) and an hourly backfill of hosts that have none (``backfill``). One drain
  task (``drain``, on its own ``screenshot_queue``, one at a time) takes the queued rows and hands them to Sentinels, so a burst of scans can
  never pile up work: the second drain finds the first holding the claim and returns.
* **The server chooses, a Sentinel photographs.** This server never runs a browser. ``drain`` re-checks every queued page (still in the inventory,
  not excluded or archived, inside the bug bounty scope, not set to manual only), computes the scope policy of the task (``cveFeed.probe_scope.for_screenshots``:
  the hosts of its pages, the exclusions, the address rules) and sends up to ``MAX_PAGES_PER_TASK`` pages of one project as a ``web_screenshot`` task.
  The Sentinel's Chromium (``cvengine_scanner.probes.screenshots`` and the client's ``shot`` module there) opens each page through a vetting proxy
  that asks the policy for EVERY connection: the page, each redirect hop and every sub-resource.
* **Nothing a Sentinel sends is trusted.** ``agentapi.web_screenshot_results`` cuts the result to the task's own pages and checks every picture
  (base64, size, a PNG signature and checksum, its sides, its closing chunk); ``finish_image`` then looks at it once more (a flat single color
  is a blank page) and writes it to a path of this server's own making. No name a Sentinel reports is ever used.
* **Chromium's sandbox, or no picture.** A Sentinel proves the sandbox engaged before it opens any page (the task's result says so, ``sandbox``);
  one that cannot opens nothing, and the pages say why. The last proof is shown in the system status (``record_sandbox``).
* **Without a scanner the pages wait.** ``web_screenshot`` is in ``sentinel_dispatch.NEVER_LOCAL``: with no Sentinel able to take it nothing is
  recorded, the pages stay queued (``ScannerUnavailable``) and the next pass tries again.
* **Nothing is silently missing.** Each attempt records an ``outcome`` and a plain ``reason`` on the row; the host page shows them instead of "none".
"""
import base64
import hashlib
import logging
import os
import re
import time
from collections import namedtuple
from datetime import timedelta
from urllib.parse import urlsplit

from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

SANDBOX_KEY = 'screenshots:sandbox'          # what the last Sentinel result said of Chromium's sandbox (cache)
SANDBOX_FAILED_SECONDS = 3600                # a failed proof is shown this long, then forgotten unless it is shown again
SANDBOX_OK_SECONDS = 7 * 24 * 3600
KIND = 'web_screenshot'                      # the Sentinel task kind
DRAIN_CLAIM = 'cvengine:screenshots:drain'  # one drain at a time, across workers
SWEEP_CLAIM = 'screenshot-backfill'
CURSOR_KEY = 'cvengine:screenshots:cursor'
QUEUE = 'screenshot_queue'

OK, QUEUED, BLANK, BLOCKED, NLA = 'ok', 'queued', 'blank', 'blocked', 'nla_required'
FAILURES = ('timeout', 'unreachable', 'tls_error', 'error', 'blank', 'unavailable', 'too_big')  # an attempt that produced nothing: tried again after the retry window
STATIC = (BLOCKED, NLA)                    # decided without a scanner, re-evaluated when the host is planned again

MAX_PORTS_PER_HOST = 6
MAX_PAGES_PER_TASK = 6          # pages one web_screenshot task carries (the contract's bound, agentapi.web_screenshot_results.MAX_PAGES)
DEFAULT_TTL_HOURS = 72          # a capture is refreshed after this long (CVENGINE_SCREENSHOT_TTL_HOURS)
DEFAULT_RETRY_HOURS = 24        # a failed capture is tried again after this long (CVENGINE_SCREENSHOT_RETRY_HOURS)
DEFAULT_PER_SCAN = 50           # most pages one scan queues (CVENGINE_SCREENSHOT_MAX_PER_SCAN)
DEFAULT_BACKFILL_PER_PROJECT = 20
DEFAULT_BACKFILL_TOTAL = 100
DEFAULT_MAX_BYTES = 2 * 1024 * 1024
DEFAULT_PROJECT_MB = 500
BATCH_PAGES = 60                # queued pages one round of the drain takes (several tasks of ``MAX_PAGES_PER_TASK``)
DRAIN_SECONDS = 40 * 60         # one drain stops taking new batches after this long (the next backfill continues)
THUMB_SUFFIX = '.thumb-320.jpg'  # what cveFeed.shots.thumbnail_path writes beside an image
KNOWN_WEB_PORTS = {80: 'http', 443: 'https', 8080: 'http', 8443: 'https', 8000: 'http', 8008: 'http', 8081: 'http', 8888: 'http', 9443: 'https', 3000: 'http'}
HTTP_SERVICE_NAMES = ('http', 'https', 'http-proxy', 'http-alt', 'https-alt', 'ssl/http', 'ssl/https', 'http-mgmt', 'https-mgmt')
CDN_PORTS = (80, 443)           # a CDN edge answers on many ports that belong to the edge, not to the host: only the web ports are captured


def _env_int(name, default, low=0, high=10 ** 9):
    try:
        return max(low, min(high, int(str(os.environ.get(name, '')).strip())))
    except ValueError:
        return default


def enabled():
    return os.environ.get('CVENGINE_SCREENSHOTS', '1').strip().lower() not in ('0', 'false', 'no', 'off')


def ttl():
    return timedelta(hours=_env_int('CVENGINE_SCREENSHOT_TTL_HOURS', DEFAULT_TTL_HOURS, 1, 24 * 365))


def retry_after():
    return timedelta(hours=_env_int('CVENGINE_SCREENSHOT_RETRY_HOURS', DEFAULT_RETRY_HOURS, 1, 24 * 90))


def per_scan_cap():
    return _env_int('CVENGINE_SCREENSHOT_MAX_PER_SCAN', DEFAULT_PER_SCAN, 1, 1000)


def backfill_caps():
    return (_env_int('CVENGINE_SCREENSHOT_BACKFILL_PER_PROJECT', DEFAULT_BACKFILL_PER_PROJECT, 1, 1000),
            _env_int('CVENGINE_SCREENSHOT_BACKFILL_MAX', DEFAULT_BACKFILL_TOTAL, 1, 5000))


def max_bytes():
    return _env_int('CVENGINE_SCREENSHOT_MAX_BYTES', DEFAULT_MAX_BYTES, 64 * 1024, 8 * 1024 * 1024)


def project_cap_bytes():
    return _env_int('CVENGINE_SCREENSHOT_PROJECT_MB', DEFAULT_PROJECT_MB, 10, 100000) * 1024 * 1024


def nav_timeout_seconds():
    return _env_int('CVENGINE_SCREENSHOT_TIMEOUT', 20, 8, 60)


# ----------------------------------------------------------------------------- availability and the sandbox proof

def unavailable_reason():
    """Why captures are not taken at all, or ''. Only the switch: with no scanner able to take the kind the pages wait (the drain says so)."""
    if not enabled():
        return 'Screenshots are switched off on this server (CVENGINE_SCREENSHOTS=0).'
    return ''


def sandbox_state():
    """What the last Sentinel result said of Chromium's sandbox, ``{'engaged', 'reason', 'at', 'version'}``, or None (nothing reported lately)."""
    try:
        from django.core.cache import cache
        return cache.get(SANDBOX_KEY)
    except Exception:  # noqa: BLE001 - a cache outage is "not known"; every Sentinel proves the sandbox before each task by itself
        return None


def record_sandbox(engaged, reason='', version=''):
    """Remember what a Sentinel's proof of the sandbox found, and say so in the log and the activity feed when it changes."""
    previous = sandbox_state() or {}
    state = {'engaged': bool(engaged), 'reason': '' if engaged else (reason or 'Chromium sandbox did not engage.')[:400],
             'at': timezone.now().isoformat(), 'version': version or previous.get('version') or ''}
    try:
        from django.core.cache import cache
        cache.set(SANDBOX_KEY, state, SANDBOX_OK_SECONDS if engaged else SANDBOX_FAILED_SECONDS)
    except Exception:  # noqa: BLE001
        pass
    if not engaged and (previous.get('engaged') is not False or previous.get('reason') != state['reason']):
        logger.error('A scanner took no web screenshot, its browser sandbox did not engage: %s', state['reason'])
        try:
            from cveFeed import activity
            activity.log('run_check', f"Screenshots are off on a scanner: {state['reason']}"[:500])
        except Exception:  # noqa: BLE001
            pass
    elif engaged and previous.get('engaged') is False:
        logger.warning("A scanner's Chromium sandbox engaged: web screenshots are on again")
    return state


def sandbox_status():
    """For the system status: what the last proof of the sandbox found (``state``: engaged, failed or unchecked). A Sentinel proves it before every task."""
    state = sandbox_state()
    if not state:
        return {'required': True, 'state': 'unchecked', 'reason': None, 'checked_at': None}
    return {'required': True, 'state': 'engaged' if state.get('engaged') else 'failed', 'reason': state.get('reason') or None,
            'checked_at': state.get('at'), 'chromium_version': state.get('version') or None}


def available():
    return not unavailable_reason()


# ----------------------------------------------------------------------------- planning

def host_of(sub):
    return (sub.name or '').strip().lower().rstrip('.')


def url_for(host, scheme, port):
    name = f'[{host}]' if ':' in host else host
    default = 443 if scheme == 'https' else 80
    return f'{scheme}://{name}' + ('' if port == default else f':{port}') + '/'


def _is_cdn(sub):
    return bool(sub.is_cdn) or any(ip.is_cdn for ip in sub.ip_addresses.all())


def web_targets(sub, manual=False, raw=False):
    """``[(scheme, port)]`` to photograph for a Subdomain row with ``ip_addresses__ports`` prefetched: the page its own URL names, and every open
    TCP port the port stage identified as HTTP(S) or that is a well-known web port. HTTPS is tried first on 443, then 80, then the rest by
    number, at most ``MAX_PORTS_PER_HOST``. A host behind a CDN is photographed on 80 and 443 only. ``manual`` (a person pressed the button)
    tries 443 and 80 for a host nothing is known about."""
    found = set()
    if sub.http_url:
        parts = urlsplit(sub.http_url)
        if parts.scheme in ('http', 'https') and parts.hostname:
            found.add((parts.scheme, parts.port or (443 if parts.scheme == 'https' else 80)))
    for ip in sub.ip_addresses.all():
        for port in ip.ports.all():
            if (port.state or '') not in ('', 'open') or (port.protocol or '') not in ('', 'tcp'):
                continue
            service, product = (port.service_name or '').lower(), (port.product or '').lower()
            if port.number in KNOWN_WEB_PORTS or service in HTTP_SERVICE_NAMES or service.startswith(('http', 'ssl/http')) or 'http' in product:
                tls = ('https' in service or 'ssl' in service or KNOWN_WEB_PORTS.get(port.number) == 'https' or (port.extra or {}).get('tunnel') == 'ssl')
                found.add(('https' if tls else 'http', port.number))
    if _is_cdn(sub) and not raw:
        found = {(scheme, number) for scheme, number in found if number in CDN_PORTS}
    if not found and manual:
        found = {('https', 443), ('http', 80)}
    ordered = sorted(found, key=lambda sp: (0 if sp[1] == 443 else 1 if sp[1] == 80 else 2, sp[1], sp[0]))
    return ordered[:MAX_PORTS_PER_HOST]


def rdp_outcomes(sub):
    """``[(port, reason)]`` for the RDP ports the port stage showed insist on Network Level Authentication: such a server paints nothing before sign-in,
    so the outcome is recorded instead of nothing. (A server that accepts a connection without NLA is captured by ``cveFeed.rdp_shot``.)"""
    from cveFeed import service_intel
    from startScan.models import open_ports
    out = {}
    for ip in sub.ip_addresses.all():
        for port in open_ports(ip):
            if service_intel.is_rdp_port(port) and service_intel.rdp_requires_nla(port):
                out[port.number] = 'Network Level Authentication is required, so the server shows no sign-in screen before credentials; nothing can be captured.'
    return sorted(out.items())


# ----------------------------------------------------------------------------- queueing

def _row_window_open(row, now):
    """Whether a row that exists is due for another capture on its own (``queue`` without force)."""
    if row.outcome == QUEUED:
        return False
    if row.outcome == OK:
        return not row.captured_at or now - row.captured_at >= ttl()
    return not row.attempted_at or now - row.attempted_at >= retry_after()


def queue(project_id, domain_id, host, scheme, port, *, by_person=False, force=False, now=None):
    """Make sure ``scheme://host:port`` of the project is waiting for a scanner. Returns ``'new'``, ``'queued'`` (an existing row
    that was due, or forced) or ``'kept'`` (already queued, or captured or tried inside its window)."""
    from cveFeed.models import HostScreenshot
    now = now or timezone.now()
    row, created = HostScreenshot.objects.get_or_create(
        project_id=project_id, host=host, scheme=scheme, port=port,
        defaults={'domain_id': domain_id, 'outcome': QUEUED, 'queued_at': now, 'by_person': by_person})
    if created:
        return 'new'
    if row.outcome == QUEUED:
        if by_person and not row.by_person:
            HostScreenshot.objects.filter(pk=row.pk).update(by_person=True)
        return 'kept'
    if not force and not _row_window_open(row, now):
        return 'kept'
    HostScreenshot.objects.filter(pk=row.pk).update(outcome=QUEUED, queued_at=now, domain_id=domain_id, by_person=by_person)  # asked again: a person's earlier request is not carried over
    return 'queued'


def _record_static(project_id, domain_id, host, scheme, port, outcome, reason, now=None):
    from cveFeed.models import HostScreenshot
    now = now or timezone.now()
    row, created = HostScreenshot.objects.get_or_create(
        project_id=project_id, host=host, scheme=scheme, port=port,
        defaults={'domain_id': domain_id, 'outcome': outcome, 'reason': reason[:300], 'attempted_at': now})
    if not created and row.outcome != QUEUED:  # a page already waiting is left to the drain
        HostScreenshot.objects.filter(pk=row.pk).update(outcome=outcome, reason=reason[:300], attempted_at=now, domain_id=domain_id)


def queue_refusal(project_id, host, gate, unattended):
    """Why this host is not photographed at all, or '' (the organization's exclusion and the program's scope are read afresh; an unreadable
    exclusion list stops the stage rather than clearing everything)."""
    from cveFeed.exclusions import excluded_names, normalize
    from cveFeed.archive_rediscovery import archived_names
    if normalize(host) in excluded_names(project_id, strict=True):
        return 'excluded'
    if host in archived_names(project_id):
        return 'archived'
    return gate.refusal(project_id, host, unattended=unattended)


def queue_for_subs(subs, project_id, *, by_person=False, force=False, limit=None, manual=False):
    """Plan the pages of ``subs`` (Subdomain rows of one project, ports prefetched) and queue them. Returns
    ``{'queued', 'kept', 'blocked', 'hosts', 'rdp'}``. A host the organization excluded or archived is left alone (no row), one the bug bounty
    scope or confirmation holds back, or inside a network only a Sentinel can reach, gets a row that says so."""
    from cveFeed.bounty_gate import Gate
    from targetApp.models import Domain
    from targetApp.target_types import sentinel_only_target
    gate, seen = Gate(), set()
    summary = {'queued': 0, 'kept': 0, 'blocked': 0, 'hosts': 0, 'rdp': 0, 'targets': []}
    limit = limit or per_scan_cap()
    now = timezone.now()
    for sub in subs:
        host = host_of(sub)
        if not host or host in seen or not sub.target_domain_id:
            continue
        seen.add(host)
        domain_id = sub.target_domain_id
        if not by_person and sub.target_domain.discovery_mode == Domain.DISCOVERY_MANUAL:  # "just add them, do not scan yet": no page is opened unless a person asks
            continue
        why = queue_refusal(project_id, host, gate, unattended=not by_person)
        if why in ('excluded', 'archived'):
            continue
        targets = web_targets(sub, manual=manual)
        planned = {(scheme, number) for scheme, number in targets}
        if not why and not sentinel_only_target(host, project_id):
            for number, reason in rdp_outcomes(sub):
                _record_static(project_id, domain_id, host, 'rdp', number, NLA, reason, now)
                planned.add(('rdp', number))
                summary['rdp'] += 1
        _settle_unplanned(project_id, host, planned, now)
        if not targets:
            edge = web_targets(sub, raw=True)[:1] if not why else []  # a CDN host whose only web port is not 80 or 443: say so, so it is not planned again every hour
            for scheme, number in edge:
                _record_static(project_id, domain_id, host, scheme, number, BLOCKED,
                               'Not captured: this host is behind a CDN and only a port of the edge other than 80 and 443 looks like a web port.', now)
            continue
        summary['hosts'] += 1
        if why or sentinel_only_target(host, project_id):
            text = f'Not captured: {why}' if why else 'Blocked: the address is inside a network only a Sentinel can reach; screenshots of internal addresses are not taken yet.'
            for scheme, number in targets:
                _record_static(project_id, domain_id, host, scheme, number, BLOCKED, text, now)
            summary['blocked'] += len(targets)
            continue
        for scheme, number in targets:
            if summary['queued'] >= limit:
                return summary  # the rest are picked up by the hourly backfill
            state = queue(project_id, domain_id, host, scheme, number, by_person=by_person, force=force, now=now)
            summary['queued' if state in ('new', 'queued') else 'kept'] += 1
            summary['targets'].append(f'{scheme}://{host}:{number}')
    return summary


def _settle_unplanned(project_id, host, planned, now):
    """Rows of this host for a page that is no longer planned (the port closed, or stopped looking like a web port): one that never gave a picture
    is deleted, one that did is only marked as looked at, so the backfill does not pick it up again every hour."""
    from cveFeed.models import HostScreenshot
    stale = [r for r in HostScreenshot.objects.filter(project_id=project_id, host=host).exclude(outcome=QUEUED) if (r.scheme, r.port) not in planned]
    if not stale:
        return
    gone = [r.pk for r in stale if not r.image_path]
    HostScreenshot.objects.filter(pk__in=gone).delete()  # no picture, so no file (a post_delete hook removes any that exist)
    HostScreenshot.objects.filter(pk__in=[r.pk for r in stale if r.image_path]).update(attempted_at=now)


def planned_subs(scan):
    from startScan.models import Subdomain
    return Subdomain.objects.filter(scan_history=scan).select_related('target_domain').prefetch_related('ip_addresses__ports').order_by('id')


def queue_for_scan(scan_id, by_person=False, force=False):
    """The scan stage: queue the web pages of the hosts this scan found (it runs after the port stage, so the ports are known). Never captures; kicks the
    drain when anything was queued. Returns the summary."""
    from startScan.models import ScanHistory
    if not enabled():
        return {'queued': 0, 'skipped': 'switched off'}
    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
    summary = queue_for_subs(planned_subs(scan), scan.domain.project_id, by_person=by_person, force=force)
    if summary['queued']:
        kick()
    return summary


def has_work_for_scan(scan):
    """Whether the stage has anything to do for this scan (a page to queue): so a scan with no web service gets no stage row."""
    if not available():
        return False
    return any(web_targets(sub) or rdp_outcomes(sub) for sub in planned_subs(scan))


def queue_host(project, sub, by_person=True):
    """The Take screenshot button: queue every web page of this host now, whatever its window says, and run the drain. ``ValueError`` for a
    host that may not be photographed (the caller has already run the scan admission gates)."""
    summary = queue_for_subs([sub], project.pk, by_person=by_person, force=True, limit=MAX_PORTS_PER_HOST, manual=True)
    if summary['queued']:
        kick()
    return summary


def kick(delay=0):
    """Ask for the drain to run (best effort: the hourly sweep drains too, so a lost message only delays the pictures). A message while a drain
    runs is cheap: the second drain finds the claim held and returns, and the running one takes what was queued meanwhile."""
    try:
        from cveFeed.tasks import drain_screenshots
        drain_screenshots.apply_async(queue=QUEUE, countdown=delay)
        return True
    except Exception:  # noqa: BLE001 - a broker problem must never break a scan stage or a button
        logger.warning('could not queue the screenshot drain', exc_info=True)
        return False


# ----------------------------------------------------------------------------- the backfill

def _web_evidence_q():
    from django.db.models import Q
    ports = Q(ip_addresses__ports__state='open', ip_addresses__ports__protocol__in=('', 'tcp')) & (
        Q(ip_addresses__ports__number__in=list(KNOWN_WEB_PORTS)) | Q(ip_addresses__ports__service_name__in=list(HTTP_SERVICE_NAMES))
        | Q(ip_addresses__ports__service_name__startswith='http'))
    return ports | Q(http_url__gt='')


SCAN_CAP = 1000  # candidate names one project's backfill looks at before it gives up for this run


def _due_names(project_id, limit, now):
    """The names of the project's hosts to plan next: first those with a web port and no capture row at all (a host nobody has ever photographed),
    then those whose rows are older than their window, longest-waiting first. At most ``limit``. Names the organization excluded are skipped while
    looking (they have no row to mark them), reading further down the list so a large excluded subtree cannot starve the rest."""
    from django.db.models import Exists, F, Max, OuterRef, Q
    from django.db.models.functions import Lower
    from cveFeed.exclusions import excluded_names, normalize
    from cveFeed.models import HostScreenshot
    from startScan.models import Subdomain
    from cveFeed.archive_rediscovery import archived_names
    limit = min(limit, 200)
    banned = excluded_names(project_id)
    names = []
    from targetApp.models import Domain, in_target_scope_q
    never = (Subdomain.objects.filter(target_domain__project_id=project_id).exclude(target_domain__discovery_mode=Domain.DISCOVERY_MANUAL)  # manual only: not photographed on a schedule
             .filter(in_target_scope_q())  # a name kept under a target that is now exactly one host is not photographed on a schedule
             .filter(_web_evidence_q()).annotate(lname=Lower('name'))
             .exclude(lname__in=list(archived_names(project_id)))
             .annotate(has=Exists(HostScreenshot.objects.filter(project_id=project_id, host=OuterRef('lname'))))
             .filter(has=False).values('lname').annotate(newest=Max('id')).order_by('-newest'))
    for row in never[:SCAN_CAP]:
        name = row['lname'].rstrip('.')
        if normalize(name) in banned:
            continue
        names.append(name)
        if len(names) >= limit:
            break
    if len(names) < limit:
        stale = Q(outcome=OK, captured_at__lt=now - ttl()) | Q(outcome__in=FAILURES + STATIC, attempted_at__lt=now - retry_after())
        due = (HostScreenshot.objects.filter(project_id=project_id).filter(stale).exclude(scheme='rdp')
               .order_by(F('attempted_at').asc(nulls_first=True)).values_list('host', flat=True)[:limit * 4])
        due = list(due)
        from cveFeed.manual_only import only_manual_hosts
        held = only_manual_hosts(project_id, set(due))  # held only by manual only targets: not photographed on a schedule
        from targetApp.models import narrowed_names
        held |= narrowed_names(project_id, due)  # held only under a target that is now exactly one host: not photographed again
        for host in due:
            if host not in names and normalize(host) not in banned and host.strip().lower().rstrip('.') not in held:
                names.append(host)
            if len(names) >= limit:
                break
    return names[:limit]


def _current_row(project_id, name):
    from cveFeed.manual_only import held_expr
    from startScan.models import Subdomain
    return (Subdomain.objects.filter(target_domain__project_id=project_id, name__iexact=name).select_related('target_domain')
            .prefetch_related('ip_addresses__ports').annotate(held=held_expr()).order_by('held', '-id').first())  # a host two targets hold is photographed as the one that is not manual only


def backfill(now=None, per_project=None, total=None):
    """Queue the hosts that have no capture (or an old one) with per-project and overall caps, a project at a time starting after the one the
    last run ended on. Skips while scanning is paused or an update drains, for a project whose bug bounty engagement has not confirmed
    automated testing, and when screenshots are switched off. Returns ``{'queued', 'projects', 'skipped'}``."""
    from cveFeed.conductor import bounty_blocked_projects
    from cveFeed.scan_control import pause_requested
    from dashboard.models import Project
    summary = {'queued': 0, 'projects': 0, 'skipped': None}
    reason = unavailable_reason()
    if reason:
        summary['skipped'] = reason
        return summary
    if pause_requested(fail_closed=True):
        summary['skipped'] = 'scanning is paused'
        return summary
    per_project, total = (per_project or backfill_caps()[0]), (total or backfill_caps()[1])
    now = now or timezone.now()
    blocked = bounty_blocked_projects()
    try:
        from django.core.cache import cache
        cursor = int(cache.get(CURSOR_KEY) or 0)
    except Exception:  # noqa: BLE001
        cursor = 0
    ids = list(Project.objects.exclude(pk__in=blocked).order_by('pk').values_list('pk', flat=True))
    ids = [i for i in ids if i > cursor] + [i for i in ids if i <= cursor]
    last = cursor
    for project_id in ids:
        if summary['queued'] >= total:
            break
        last = project_id
        budget = min(per_project, total - summary['queued'])
        queued_here = 0
        try:
            for name in _due_names(project_id, budget * 5, now):
                if queued_here >= budget:
                    break
                sub = _current_row(project_id, name)
                if sub is not None:
                    queued_here += queue_for_subs([sub], project_id, limit=budget - queued_here)['queued']
            summary['projects'] += 1
        except Exception:  # noqa: BLE001 - one project's trouble never stops the others
            logger.exception('screenshot backfill failed for project %s', project_id)
        summary['queued'] += queued_here
    try:
        from django.core.cache import cache
        cache.set(CURSOR_KEY, last, None)
    except Exception:  # noqa: BLE001
        pass
    return summary


def sweep():
    """The hourly task: queue what is missing, then drain. One sweep at a time."""
    from cveFeed import ledger
    if not ledger.sweep_claim(SWEEP_CLAIM, 50 * 60):
        return {'skipped': 'another sweep is running'}
    out = {'backfill': backfill()}
    out['drain'] = drain()
    return out


# ----------------------------------------------------------------------------- saving what was captured
def media_root():
    return os.path.realpath(settings.MEDIA_ROOT)


def safe_name(host):
    """The directory name of a host's pictures: readable, and unique to the exact name (two names that differ only in characters the readable part
    replaces, or only after its length cap, never share a directory, so deleting one host never deletes another's pictures)."""
    readable = re.sub(r'[^a-z0-9.-]+', '_', host.lower())[:60] or 'host'
    return f'{readable}-{hashlib.sha1(host.lower().encode("utf-8", "replace")).hexdigest()[:8]}'


def new_paths(row):
    """``(absolute, relative)`` of the PNG a capture of this row is written to: screenshots/<project>/<host>/<scheme>-<port>-<time>.png."""
    rel = os.path.join('screenshots', str(row.project_id), safe_name(row.host), f'{row.scheme}-{row.port}-{int(time.time() * 1000)}.png')
    return os.path.join(media_root(), rel), rel


def remove_files(*rel_paths):
    """Delete stored pictures (and their thumbnails) by path relative to MEDIA_ROOT; never anything outside ``screenshots``. Never raises."""
    base = os.path.join(media_root(), 'screenshots')
    for rel in rel_paths:
        if not rel:
            continue
        for path in (os.path.join(media_root(), rel), os.path.join(media_root(), rel) + THUMB_SUFFIX):
            real = os.path.realpath(path)
            if real.startswith(base + os.sep):
                try:
                    os.remove(real)
                except OSError:
                    continue
                parent = os.path.dirname(real)  # a host's or a project's directory left empty goes too
                for _ in range(2):
                    if parent.startswith(base + os.sep):
                        try:
                            os.rmdir(parent)
                        except OSError:
                            break
                        parent = os.path.dirname(parent)


def remove_row_files(row):
    remove_files(row.image_path, row.previous_image_path)


def sweep_orphans(older_than=24 * 3600):
    """Delete picture files under ``screenshots/`` that no row names (a project or target deleted with its rows, a crash between writing and saving),
    when they are older than a day. Returns how many. Part of the weekly maintenance."""
    from cveFeed.models import HostScreenshot
    base = os.path.join(media_root(), 'screenshots')
    if not os.path.isdir(base):
        return 0
    known = set()
    for rel in HostScreenshot.objects.values_list('image_path', 'thumb_path', 'previous_image_path'):
        for item in rel:
            if item:
                known.add(os.path.join(media_root(), item))
                known.add(os.path.join(media_root(), item) + THUMB_SUFFIX)
    removed, cutoff = 0, time.time() - older_than
    for folder, _dirs, names in os.walk(base):
        for name in names:
            path = os.path.join(folder, name)
            try:
                if path not in known and os.lstat(path).st_mtime < cutoff:
                    os.remove(path)
                    removed += 1
            except OSError:
                continue
    for folder, _dirs, _names in os.walk(base, topdown=False):  # empty directories
        if folder != base:
            try:
                os.rmdir(folder)
            except OSError:
                pass
    return removed


def project_bytes(project_id):
    from django.db.models import Sum
    from cveFeed.models import HostScreenshot
    totals = HostScreenshot.objects.filter(project_id=project_id).aggregate(now=Sum('image_bytes'), before=Sum('previous_image_bytes'))
    return (totals['now'] or 0) + (totals['before'] or 0)


def write_new(path, data):
    """Create ``path`` with the picture, mode 0644, failing if anything is there already (no link is followed, no mode is changed afterwards)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o644)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)


def finish_image(row, data):
    """Store the picture a Sentinel took of ``row`` (``agentapi.web_screenshot_results`` already checked it is a PNG of a sane size). Returns
    ``(fields, outcome, reason)``: the model fields of a good capture, or an outcome (blank, error) and why. Looked at once more here: a flat single
    color is a blank page, whatever the scanner said, and a picture over this server's own size cap is refused. The file is a new one of this process's
    own, at a path made from the row, never from anything the scanner sent."""
    from agentapi import web_screenshot_results
    from cveFeed import shots
    from cveFeed.rdp_shot import is_meaningful
    if not data:
        return {}, 'error', 'The scanner reported a picture that was not sent.'
    if len(data) > min(shots.MAX_SHOT_BYTES, max_bytes()) or web_screenshot_results.png_problem(data):
        return {}, 'error', 'The picture is larger than the size allowed.' if len(data) > max_bytes() else 'The scanner sent a picture that is not a usable PNG.'
    if not is_meaningful(data):
        return {}, BLANK, 'The page rendered blank (a single flat color).'
    size = len(data)
    if project_bytes(row.project_id) + size > project_cap_bytes():
        _free_previous(row.project_id)
        if project_bytes(row.project_id) + size > project_cap_bytes():
            return {}, 'error', f'This project\'s screenshot storage ({project_cap_bytes() // (1024 * 1024)} MB) is full.'
    final, rel = new_paths(row)
    write_new(final, data)
    thumb = shots.thumbnail_path(final)
    return {'image_path': rel, 'thumb_path': os.path.relpath(thumb, media_root()) if thumb else '', 'image_hash': shots.dhash_file(final),
            'image_bytes': size}, OK, ''


def _free_previous(project_id):
    """Drop every project's "previous capture" file, the part of the storage that is only kept for comparing."""
    from cveFeed.models import HostScreenshot
    rows = HostScreenshot.objects.filter(project_id=project_id).exclude(previous_image_path='')
    remove_files(*rows.values_list('previous_image_path', flat=True))
    rows.update(previous_image_path='', previous_image_hash='', previous_image_bytes=0)


def _same_host(final_url, host):
    return (urlsplit(final_url).hostname or '').lower().rstrip('.') == host


def apply_result(row, result, now=None, image=b''):
    """Write one page's result onto its row. A failure keeps the previous picture and says what happened; a success keeps one earlier picture
    (the one it replaces) for comparison and deletes older ones. ``image`` is the picture's bytes of a page the scanner photographed. Returns the outcome."""
    from cveFeed.models import HostScreenshot
    now = now or timezone.now()
    outcome, reason = result.get('outcome') or 'error', str(result.get('reason') or '')[:300]
    fields = {}
    if outcome == OK:
        fields, outcome, reason = finish_image(row, image)
    update = {'outcome': outcome, 'reason': reason, 'attempted_at': now, 'queued_at': None, 'by_person': False}  # a person's request is used up by this attempt
    if outcome == OK:
        final = str(result.get('final_url') or '')[:2000]
        status = result.get('status')
        if not reason and status and status >= 400:
            reason = f'The server answered HTTP {status}.'
        if not reason and final and not _same_host(final, row.host):
            reason = f'Redirects to {final[:180]} (another host).'
        stale_previous = row.previous_image_path
        update.update(fields)
        update.update(reason=reason, final_url=final, http_status=status, title=str(result.get('title') or '')[:300], captured_at=now,
                      previous_image_path=row.image_path, previous_image_hash=row.image_hash, previous_image_bytes=row.image_bytes)
        HostScreenshot.objects.filter(pk=row.pk).update(**update)
        if stale_previous and stale_previous != row.image_path:
            remove_files(stale_previous)
    else:
        if result.get('final_url') and not row.image_path:
            update['final_url'] = str(result['final_url'])[:2000]
        HostScreenshot.objects.filter(pk=row.pk).update(**update)
    return outcome


# ----------------------------------------------------------------------------- the drain

Item = namedtuple('Item', 'row host scheme port url')


def _precheck(row, ctx):
    """``None`` to go ahead, or ``(outcome, reason)`` / ``'gone'`` for a queued row that must not be captured now (re-read at the point of use)."""
    from cveFeed.exclusions import normalize
    from startScan.models import Subdomain
    project_id = row.project_id
    if not Subdomain.objects.filter(target_domain__project_id=project_id, name__iexact=row.host).exists():
        return 'gone'
    project = ctx.setdefault(project_id, {})
    if 'excluded' not in project:
        from cveFeed.exclusions import excluded_names
        from cveFeed.archive_rediscovery import archived_names
        from cveFeed.bounty_gate import Gate
        project['excluded'], project['archived'], project['gate'] = excluded_names(project_id, strict=True), archived_names(project_id), Gate()
    if normalize(row.host) in project['excluded']:
        return 'gone'
    if row.host in project['archived']:
        return BLOCKED, 'Not captured: the host is archived.'
    why = project['gate'].refusal(project_id, row.host, unattended=not row.by_person)
    if why:
        return BLOCKED, f'Not captured: {why}'
    from cveFeed.manual_only import only_manual_hosts
    if not row.by_person and row.host.strip().lower().rstrip('.') in only_manual_hosts(project_id, [row.host]):  # made manual only while the page waited
        return BLOCKED, 'Not captured: the target is set to manual only.'
    return None


def _kill_switch():
    from reNgine import resources
    return resources.global_pause_requested(fail_closed=True)


def _count(summary, outcome):
    summary['captured' if outcome == OK else 'blocked' if outcome == BLOCKED else 'failed'] += 1


def _task_target(project_id, items):
    """The target of one ``web_screenshot`` task: its pages (an id that is the row's own, never a name), the scope policy and the limits."""
    from cveFeed import probe_scope
    scope, open_web = probe_scope.for_screenshots(project_id, [item.host for item in items])
    return {'pages': [{'id': str(item.row.pk), 'url': item.url} for item in items], 'scope': scope, 'open_web': open_web,
            'timeout_seconds': nav_timeout_seconds(), 'max_bytes': max_bytes()}


def _apply_task(items, result, summary):
    """Write what a Sentinel reported for the pages of one task. A page it did not report on was not photographed: it says so on its row (and is
    tried again after the retry window), never a picture and never a state of the page."""
    from cveFeed.models import HostScreenshot
    sandbox = result.get('sandbox') or {}
    if 'engaged' in sandbox:
        record_sandbox(sandbox['engaged'], sandbox.get('reason', ''), sandbox.get('version', ''))
    reported = {page['id']: page for page in result.get('pages') or []}
    summary['dropped_requests'] = summary.get('dropped_requests', 0) + int(result.get('dropped_requests') or 0)
    for item in items:
        row = HostScreenshot.objects.filter(pk=item.row.pk).first()
        if row is None:
            continue
        page = reported.get(str(item.row.pk))
        if page is None:
            if sandbox.get('engaged') is False:
                reason = f"Not captured: the scanner's browser sandbox did not engage. {sandbox.get('reason') or ''}".strip()
            else:
                reason = 'The scanner reported nothing for this page.'
            _count(summary, apply_result(row, {'outcome': 'unavailable', 'reason': reason[:300]}))
            continue
        try:
            image = base64.b64decode(page['image'], validate=True) if page.get('image') else b''
        except ValueError:
            image = b''
        _count(summary, apply_result(row, page, image=image))


def process(rows, summary=None):
    """Capture ``rows`` (queued HostScreenshot rows, any projects) through Sentinels. Every page is re-checked first (still in the inventory, not
    excluded or archived, inside the bug bounty scope, not manual only), then sent in tasks of at most ``MAX_PAGES_PER_TASK`` pages of one project, and
    each task's result is written as it arrives, so a kill part-way keeps what was done. A project with no scanner able to take the kind keeps its
    pages queued (``ScannerUnavailable``): nothing is recorded for them. Returns the summary; ``summary['waiting']`` lists those projects."""
    from agentapi import sentinel_dispatch
    from cveFeed.models import HostScreenshot
    from reNgine.resources import ScanAborted, ScannerUnavailable
    summary = summary if summary is not None else {}
    for key in ('captured', 'failed', 'blocked', 'dropped'):
        summary.setdefault(key, 0)
    ctx, by_project = {}, {}
    for row in rows:
        verdict = _precheck(row, ctx)
        if verdict == 'gone':
            HostScreenshot.objects.filter(pk=row.pk).delete()
            summary['dropped'] += 1
        elif verdict is not None:
            _count(summary, apply_result(row, {'outcome': verdict[0], 'reason': verdict[1]}))
        else:
            by_project.setdefault(row.project_id, []).append(Item(row, row.host, row.scheme, row.port, url_for(row.host, row.scheme, row.port)))
    for project_id, items in by_project.items():
        if _kill_switch():
            summary['stopped'] = 'paused'
            return summary
        project = sentinel_dispatch._project_of(project_id)
        if project is None:
            continue
        chunks = [items[i:i + MAX_PAGES_PER_TASK] for i in range(0, len(items), MAX_PAGES_PER_TASK)]
        try:
            sentinel_dispatch.scanner_or_local(project, KIND)  # raises ScannerUnavailable when none is live: the kind has no local path at all
            for index, result in sentinel_dispatch.dispatch_each(project, KIND, chunks, lambda chunk: _task_target(project_id, chunk), label_of=lambda chunk: chunk[0].host):
                if result is not None:
                    _apply_task(chunks[index], result, summary)
        except ScannerUnavailable as exc:  # what a scanner did finish is written above; the rest stays queued
            summary.setdefault('waiting', []).append(project_id)
            summary['skipped'] = f'no scanner could take this work ({exc.kind})'
        except ScanAborted as exc:
            summary['stopped'] = type(exc).__name__  # paused or stopped: the rows stay queued
            return summary
        except Exception:  # noqa: BLE001 - an unexpected failure ends this project's pages for now, never the drain worker; they stay queued
            logger.exception('screenshot task for project %s failed', project_id)
            summary['error'] = 'a screenshot task failed'
    return summary


def queued_rows(limit, exclude_projects=()):
    from cveFeed.models import HostScreenshot
    return list(HostScreenshot.objects.filter(outcome=QUEUED).exclude(project_id__in=list(exclude_projects)).order_by('-by_person', 'queued_at', 'pk')[:limit])


def drain(budget_seconds=DRAIN_SECONDS, now_fn=time.monotonic, batch=BATCH_PAGES):
    """Hand the queued pages to Sentinels, a batch at a time, until none are left or the budget is spent (then ask for another drain). One at a time: a
    second call while one runs returns at once, and the running one picks up what was queued meanwhile. A project that has no scanner for the kind is
    left alone for the rest of this drain and its pages stay queued."""
    from reNgine import resources
    summary = {'captured': 0, 'failed': 0, 'blocked': 0, 'dropped': 0}
    reason = unavailable_reason()
    if reason:
        from cveFeed.models import HostScreenshot
        if HostScreenshot.objects.filter(outcome=QUEUED).exists():
            summary['skipped'] = reason
        return summary
    started = now_fn()
    with resources.redis_claim(DRAIN_CLAIM, f'drain-{os.getpid()}', 15 * 60) as holder:
        if holder is not True:
            summary['skipped'] = 'another drain is running'
            return summary
        while True:
            if _kill_switch():
                summary['skipped'] = 'scanning is paused'
                break
            rows = queued_rows(batch, summary.get('waiting', ()))
            if not rows:
                break
            if now_fn() - started > budget_seconds:
                kick(delay=5)
                summary['continued'] = True
                break
            before = (summary['captured'], summary['failed'], summary['blocked'], summary['dropped'])
            process(rows, summary=summary)
            if summary.get('stopped') or before == (summary['captured'], summary['failed'], summary['blocked'], summary['dropped']) and not summary.get('waiting'):
                break  # stopped, or a batch settled nothing: leave the rest for the next run rather than spin
    worked = summary['captured'] or summary['failed'] or summary['blocked'] or summary['dropped']
    if worked:
        if summary['captured'] or summary['failed'] or summary['blocked']:
            _log(summary)
        if not (summary.get('stopped') or summary.get('skipped') or summary.get('continued')) and queued_rows(1, summary.get('waiting', ())):
            kick(delay=5)  # a page queued while this drain was finishing, after its last look: another drain takes it
    return summary


def _log(summary):
    from cveFeed import activity
    activity.log('run_check', f'Screenshots: {summary["captured"]} captured, {summary["failed"]} not captured, {summary["blocked"]} blocked')


# ----------------------------------------------------------------------------- reading: what the host page and the status show

def rank(row):
    """Sort key of a project's captures of one host: the page a person would open first (https on 443, then 80, then the rest), newest first."""
    first = (0 if row.port == 443 else 1 if row.port == 80 else 2, 0 if row.scheme == 'https' else 1, row.port)
    return first + (-(row.captured_at.timestamp() if row.captured_at else 0),)


def pictures(rows):
    """The captures of one host that have a picture, best first, with duplicates (the same picture on 80 and 443) left out."""
    out, seen = [], set()
    for row in sorted((r for r in rows if r.scheme != 'rdp' and r.image_path), key=rank):
        if row.image_hash and row.image_hash in seen:
            continue
        seen.add(row.image_hash)
        out.append(row)
    return out


def primary(rows):
    found = pictures(rows)
    return found[0] if found else None


def alt_text(host, row):
    when = row.captured_at.strftime('%Y-%m-%d') if row.captured_at else 'an unknown date'
    target = f'{row.scheme}://{host}:{row.port}'
    shown = f' ({row.final_url})' if row.final_url and row.final_url.rstrip('/') != url_for(host, row.scheme, row.port).rstrip('/') else ''
    return f'Screenshot of {target}{shown}, captured {when}'


def describe(row, host):
    """What the host record sends about one capture (never a file path)."""
    return {'scheme': row.scheme, 'port': row.port, 'has_image': bool(row.image_path), 'outcome': row.outcome, 'reason': row.reason,
            'final_url': row.final_url, 'http_status': row.http_status, 'title': row.title,
            'captured_at': row.captured_at.isoformat() if row.captured_at else None,
            'attempted_at': row.attempted_at.isoformat() if row.attempted_at else None,
            'alt': alt_text(host, row) if row.image_path else '', 'bytes': row.image_bytes,
            'has_previous': bool(row.previous_image_path)}


FAILURE_TEXT = {'timeout': 'timed out', 'unreachable': 'could not be reached', 'tls_error': 'failed the TLS handshake', 'error': 'failed', 'blank': 'rendered blank',
                'unavailable': 'could not be photographed by the scanner', 'too_big': 'needed too much memory'}


def note_for(rows, *, has_web_evidence, legacy=False, network=None, ports_known=False):
    """The line the host page shows next to (or instead of) a screenshot, from what the attempts recorded. Empty when a current picture is shown
    and nothing needs saying. ``legacy`` is True when an older discovery screenshot is shown because no scanner has taken a picture of the host."""
    web = [r for r in rows if r.scheme != 'rdp']
    if primary(web) is not None:
        return ''
    failed = [r for r in sorted(web, key=rank) if r.outcome not in (QUEUED, OK)]
    queued = [r for r in web if r.outcome == QUEUED]
    if legacy:
        if not failed:
            return ''
        return 'An older screenshot from discovery is shown. The latest capture attempt: ' + _reasons(failed)
    if not web:
        if network:
            return (f'No screenshot: this host is inside the internal network {network}. Only a Sentinel there scans it, and screenshots of '
                    'internal hosts are not taken yet; this server never captures internal hosts.')
        why = unavailable_reason()
        if why:
            return f'No screenshot: {why}'
        if not has_web_evidence:
            if ports_known:
                return 'No screenshot: no web port (such as 80 or 443) is recorded open on this host, so there is no page to capture.'
            return 'No screenshot: no web page has answered on this host, so there is nothing to capture.'
        return 'No screenshot yet: this host answers on the web and is waiting for the next screenshot pass (every hour), or press Take screenshot.'
    if queued:
        why = unavailable_reason()
        if why:
            return f'No screenshot: {why}'
        return 'Waiting for a scanner to take the screenshot (the pages stay queued until one can): ' + ', '.join(f'{r.scheme}://{r.host}:{r.port}' for r in queued[:3]) + '.'
    return 'No screenshot: ' + _reasons(failed)


def _reasons(rows):
    parts = []
    for row in rows[:3]:
        text = (row.reason or FAILURE_TEXT.get(row.outcome, row.outcome)).strip()
        parts.append(f'{row.scheme}://{row.host}:{row.port}: {text}' + ('' if text.endswith('.') else '.'))
    return ' '.join(parts)


def web_hosts_by_project():
    """``{project_id: hosts with a web page}`` for every project in one statement (what ``status_counts`` counts for one)."""
    from startScan.models import Subdomain
    found = {}
    for project_id, _name in Subdomain.objects.filter(_web_evidence_q()).values_list('target_domain__project_id', 'name').distinct():
        found[project_id] = found.get(project_id, 0) + 1
    return found


def status_counts(project_ids, web_hosts=None):
    """For ``get_system_status``: how many of the projects' hosts have a screenshot, what is queued, what failed and the last capture error."""
    from django.db.models import Count
    from cveFeed.models import HostScreenshot
    from startScan.models import Subdomain
    rows = HostScreenshot.objects.filter(project_id__in=list(project_ids)).exclude(scheme='rdp')
    by_outcome = {row['outcome']: row['n'] for row in rows.values('outcome').annotate(n=Count('id'))}
    shot_hosts = rows.exclude(image_path='').values('project_id', 'host').distinct().count()
    if web_hosts is None:  # ``web_hosts_by_project`` gives a caller that asks for many projects the number of each in one statement
        web_hosts = (Subdomain.objects.filter(target_domain__project_id__in=list(project_ids)).filter(_web_evidence_q())
                     .values('target_domain__project_id', 'name').distinct().count())
    last = rows.filter(outcome__in=FAILURES).exclude(attempted_at=None).order_by('-attempted_at').values('host', 'scheme', 'port', 'outcome', 'reason', 'attempted_at').first()
    return {'enabled': enabled(), 'available': available(), 'unavailable_reason': unavailable_reason() or None, 'sandbox': sandbox_status(),
            'hosts_with_web': web_hosts, 'hosts_with_screenshot': shot_hosts, 'pages': by_outcome,
            'queued': by_outcome.get(QUEUED, 0), 'failed': sum(by_outcome.get(k, 0) for k in FAILURES), 'blocked': by_outcome.get(BLOCKED, 0),
            'nla_required': HostScreenshot.objects.filter(project_id__in=list(project_ids), outcome=NLA).count(),
            'last_error': ({'page': f'{last["scheme"]}://{last["host"]}:{last["port"]}', 'outcome': last['outcome'], 'reason': last['reason'],
                            'at': last['attempted_at'].isoformat()} if last else None)}