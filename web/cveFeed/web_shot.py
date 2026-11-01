"""Web screenshots: a picture of the front page of every web port of every host, taken by a real browser (Playwright's Chromium).

Why this exists: the only screenshots cvENGINE used to take were a side effect of a full bbot discovery (gowitness), so a host that was
rescanned, found by certificate transparency, retested or only ever assessed never got one, and a rescan could hide the one it had.

How it works (docs/PIPELINE.md, "Web screenshots"):

* **Queue, then capture.** Planning a capture only writes a ``HostScreenshot`` row with outcome ``queued``; it is cheap and happens in three
  places: the scan stage after nmap (``queue_for_scan``: full scans, host assessments, Rescan host, certificate transparency hosts and
  retests all run it), the Take screenshot button (``queue_host``) and an hourly backfill of hosts that have none (``backfill``). One drain
  task (``drain``, on its own ``screenshot_queue``, one at a time) takes the queued rows and captures them, so a burst of scans can never pile
  up browsers: the second drain finds the first holding the claim and returns.
* **A child process per batch.** The browser runs in ``cveFeed/shot_worker.py`` (no Django; the Celery workers are gevent pools, where
  Playwright does not belong), under ``resources.heavy_job('screenshot')`` so memory is admitted and a pause, stop or low-memory kill reaches
  it. One browser, one page at a time, a fresh context for each, then the child exits and its memory is returned.
* **Every address is vetted, every hop.** The browser cannot connect anywhere itself: all of its traffic, loopback included, goes to a loopback
  vetting proxy in the worker (``cveFeed/shot_proxy.py``), which asks the platform's guards about EVERY connection (the page, each redirect hop,
  every sub-resource: the organization's exclusions, the bug bounty scope and the addresses a scanner may never touch) and connects to the
  address it vetted, through Settings > Proxy when one is set. A redirect to an internal address never leaves the proxy.
* **Nothing is silently missing.** Each attempt records an ``outcome`` and a plain ``reason`` on the row; the host page shows them instead of "none".
"""
import concurrent.futures
import json
import logging
import os
import pwd
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections import namedtuple
from datetime import timedelta
from urllib.parse import urlsplit

from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'shot_worker.py')
HEAVY_KIND = 'screenshot'                   # the heavy_job kind (reNgine.resources.BASE_COSTS_MB)
DRAIN_CLAIM = 'cvengine:screenshots:drain'  # one drain at a time, across workers
SWEEP_CLAIM = 'screenshot-backfill'
CURSOR_KEY = 'cvengine:screenshots:cursor'
QUEUE = 'screenshot_queue'

OK, QUEUED, BLANK, BLOCKED, NLA = 'ok', 'queued', 'blank', 'blocked', 'nla_required'
FAILURES = ('timeout', 'unreachable', 'tls_error', 'error', 'blank', 'unavailable')  # an attempt that produced nothing: tried again after the retry window
STATIC = (BLOCKED, NLA)                    # decided without a browser, re-evaluated when the host is planned again

MAX_PORTS_PER_HOST = 6
DEFAULT_TTL_HOURS = 72          # a capture is refreshed after this long (CVENGINE_SCREENSHOT_TTL_HOURS)
DEFAULT_RETRY_HOURS = 24        # a failed capture is tried again after this long (CVENGINE_SCREENSHOT_RETRY_HOURS)
DEFAULT_PER_SCAN = 50           # most pages one scan queues (CVENGINE_SCREENSHOT_MAX_PER_SCAN)
DEFAULT_BACKFILL_PER_PROJECT = 20
DEFAULT_BACKFILL_TOTAL = 100
DEFAULT_MAX_BYTES = 2 * 1024 * 1024
DEFAULT_PROJECT_MB = 500
BATCH_PAGES = 20                # pages one browser serves before it is replaced
DRAIN_SECONDS = 40 * 60         # one drain stops taking new batches after this long (the next backfill continues)
HEAVY_WAIT_SECONDS = 30 * 60    # how long a batch waits for memory before the drain gives up for now
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


# ----------------------------------------------------------------------------- the browser

def _playwright_root():
    import importlib.util
    spec = importlib.util.find_spec('playwright')
    return os.path.join(os.path.dirname(spec.origin), 'driver', 'package') if spec and spec.origin else ''


def pinned_browser():
    """``{'revision', 'version'}`` of the Chromium the pinned Playwright drives (its own ``browsers.json``), or ``{}``."""
    try:
        with open(os.path.join(_playwright_root(), 'browsers.json'), encoding='utf-8') as handle:
            for entry in json.load(handle).get('browsers', []):
                if entry.get('name') == 'chromium-headless-shell':
                    return {'revision': str(entry.get('revision') or ''), 'version': str(entry.get('browserVersion') or '')}
    except (OSError, ValueError, AttributeError):
        pass
    return {}


def browsers_dir():
    path = os.environ.get('PLAYWRIGHT_BROWSERS_PATH', '').strip()
    return path if path and path != '0' else os.path.expanduser('~/.cache/ms-playwright')


def browser_installed():
    """Whether the headless Chromium this Playwright release drives is on disk (its installer's completion marker). Looks, never launches."""
    revision = pinned_browser().get('revision')
    if not revision:
        return False
    return os.path.isfile(os.path.join(browsers_dir(), f'chromium_headless_shell-{revision}', 'INSTALLATION_COMPLETE'))


def unavailable_reason():
    """Why captures cannot be taken on this server, or ''."""
    if not enabled():
        return 'Screenshots are switched off on this server (CVENGINE_SCREENSHOTS=0).'
    if not browser_installed():
        return 'Chromium is not installed on this server, so screenshots cannot be taken (the image has to be rebuilt).'
    return ''


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


def web_targets(sub, manual=False):
    """``[(scheme, port)]`` to photograph for a Subdomain row with ``ip_addresses__ports`` prefetched: the page its own URL names, and every open
    TCP port that nmap or naabu identified as HTTP(S) or that is a well-known web port. HTTPS is tried first on 443, then 80, then the rest by
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
    if _is_cdn(sub):
        found = {(scheme, number) for scheme, number in found if number in CDN_PORTS}
    if not found and manual:
        found = {('https', 443), ('http', 80)}
    ordered = sorted(found, key=lambda sp: (0 if sp[1] == 443 else 1 if sp[1] == 80 else 2, sp[1], sp[0]))
    return ordered[:MAX_PORTS_PER_HOST]


def rdp_outcomes(sub):
    """``[(port, reason)]`` for the RDP ports nmap showed insist on Network Level Authentication: such a server paints nothing before sign-in,
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
    """Make sure ``scheme://host:port`` of the project is waiting for the capture worker. Returns ``'new'``, ``'queued'`` (an existing row
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
    HostScreenshot.objects.filter(pk=row.pk).update(outcome=QUEUED, queued_at=now, domain_id=domain_id, by_person=by_person or row.by_person)
    return 'queued'


def _record_static(project_id, domain_id, host, scheme, port, outcome, reason, now=None):
    from cveFeed.models import HostScreenshot
    now = now or timezone.now()
    row, created = HostScreenshot.objects.get_or_create(
        project_id=project_id, host=host, scheme=scheme, port=port,
        defaults={'domain_id': domain_id, 'outcome': outcome, 'reason': reason[:300], 'attempted_at': now})
    if not created and row.outcome != QUEUED:  # a page already waiting for the worker is left to it
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
            continue
        summary['hosts'] += 1
        if why or sentinel_only_target(host, project_id):
            text = f'Not captured: {why}' if why else 'Blocked: the address is inside a network only a Sentinel can reach; this server never captures internal addresses.'
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
    HostScreenshot.objects.filter(pk__in=gone).delete()
    HostScreenshot.objects.filter(pk__in=[r.pk for r in stale if r.image_path]).update(attempted_at=now)


def planned_subs(scan):
    from startScan.models import Subdomain
    return Subdomain.objects.filter(scan_history=scan).select_related('target_domain').prefetch_related('ip_addresses__ports').order_by('id')


def queue_for_scan(scan_id, by_person=False, force=False):
    """The scan stage: queue the web pages of the hosts this scan found (it runs after nmap, so the ports are known). Never captures; kicks the
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


def _due_names(project_id, limit, now):
    """The names of the project's hosts to plan next: first those with a web port and no capture row at all (a host nobody has ever photographed),
    then those whose rows are older than their window, longest-waiting first. At most ``limit``."""
    from django.db.models import Exists, F, Max, OuterRef, Q
    from django.db.models.functions import Lower
    from cveFeed.models import HostScreenshot
    from startScan.models import Subdomain
    from cveFeed.archive_rediscovery import archived_names
    limit = min(limit, 200)
    names = []
    never = (Subdomain.objects.filter(target_domain__project_id=project_id).filter(_web_evidence_q()).annotate(lname=Lower('name'))
             .exclude(lname__in=list(archived_names(project_id)))
             .annotate(has=Exists(HostScreenshot.objects.filter(project_id=project_id, host=OuterRef('lname'))))
             .filter(has=False).values('lname').annotate(newest=Max('id')).order_by('-newest')[:limit])
    names += [row['lname'].rstrip('.') for row in never]
    if len(names) < limit:
        stale = Q(outcome=OK, captured_at__lt=now - ttl()) | Q(outcome__in=FAILURES + STATIC, attempted_at__lt=now - retry_after())
        due = (HostScreenshot.objects.filter(project_id=project_id).filter(stale).exclude(scheme='rdp')
               .order_by(F('attempted_at').asc(nulls_first=True)).values_list('host', flat=True)[:limit * 4])
        for host in due:
            if host not in names:
                names.append(host)
            if len(names) >= limit:
                break
    return names[:limit]


def _current_row(project_id, name):
    from startScan.models import Subdomain
    return (Subdomain.objects.filter(target_domain__project_id=project_id, name__iexact=name).select_related('target_domain')
            .prefetch_related('ip_addresses__ports').order_by('-id').first())


def backfill(now=None, per_project=None, total=None):
    """Queue the hosts that have no capture (or an old one) with per-project and overall caps, a project at a time starting after the one the
    last run ended on. Skips while scanning is paused or an update drains, for a project whose bug bounty engagement has not confirmed
    automated testing, and when the browser is not installed. Returns ``{'queued', 'projects', 'skipped'}``."""
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


def sweep(runner=None):
    """The hourly task: queue what is missing, then drain. One sweep at a time."""
    from cveFeed import ledger
    if not ledger.sweep_claim(SWEEP_CLAIM, 50 * 60):
        return {'skipped': 'another sweep is running'}
    out = {'backfill': backfill()}
    out['drain'] = drain(runner=runner)
    return out


# ----------------------------------------------------------------------------- the guards, per request

class Guard:
    """The platform's answer to "may this page's browser connect to host:port?", for ONE page being captured. It is asked by the vetting proxy
    (``cveFeed.shot_proxy``) for every connection the page makes: its own address, each redirect hop and every sub-resource. Every host is held
    to the same rules: the organization's exclusions, the bug bounty scope (for a project that works a program, a host its scope does not name is
    not visited, so a page's assets from a third party are not loaded) and the addresses a scanner may never touch (the name is resolved here,
    every answer is vetted, and the connection is made to that vetted address). ``denied`` records what was refused, in order, so the result can
    say why a page that never loaded is ``blocked``, and how many sub-resources were dropped."""

    def __init__(self, project_id, primary, unattended, gate=None, excluded=None, resolver=None):
        from cveFeed.bounty_gate import Gate
        self.project_id, self.primary, self.unattended = project_id, primary, unattended
        self.gate = gate if gate is not None else Gate()
        self.excluded = excluded
        self.resolver = resolver or self._resolve
        self.denied = []          # [(host, reason)]
        self._verdicts = {}

    def _resolve(self, host, port):
        """Every address of the name, vetted (``pinned_transport.resolve`` refuses a prohibited one). A literal address is judged as itself, with the
        project's own tailnet as authority only for the page's own host."""
        from cveFeed import pinned_transport
        return pinned_transport.resolve(host, port, project=self.project_id if host == self.primary else None)

    def admit(self, host, port):
        """``((addresses, project), '')`` to let a connection through, or ``(None, reason)``. Remembered per host for this page, so one
        page is judged consistently and the guards are not asked twice for a host."""
        host = (host or '').lower().rstrip('.')
        if host in self._verdicts:
            return self._verdicts[host]
        verdict = self._judge(host, port)
        self._verdicts[host] = verdict
        if verdict[0] is None:
            self.denied.append((host, verdict[1]))
        return verdict

    def _judge(self, host, port):
        from cveFeed.exclusions import excluded_names, normalize
        try:
            names = self.excluded if self.excluded is not None else excluded_names(self.project_id, strict=True)
        except Exception:  # noqa: BLE001 - an unreadable exclusion list stops the request, never clears it
            return None, 'The exclusion list could not be read.'
        if normalize(host) in names:
            return None, f'{host} is excluded for this organization.'
        if host != self.primary:
            why = self.gate.refusal(self.project_id, host, unattended=self.unattended)
            if why:
                return None, f'{host} cannot be visited: {why}'
        try:
            addresses = self.resolver(host, port)
        except ValueError:
            return None, f'{host} resolves to an internal or reserved address; it is not visited.'
        except OSError as exc:
            return None, f'{host} could not be resolved ({str(exc)[:80] or "no answer"}).'
        return (addresses, self.project_id if host == self.primary else None), ''

    def blocked_reason(self):
        """Why a page that failed to load was refused, from the first refusal that is not just a sub-resource, else the first of any."""
        if not self.denied:
            return ''
        host, reason = next(((h, r) for h, r in self.denied if h == self.primary), self.denied[0])
        return reason if host == self.primary else f'Redirects to {host}, which is not visited: {reason}'


def connect(target, host, port, timeout):
    """The socket the proxy uses for an admitted connection: to the vetted address, through Settings > Proxy when one is set (never directly
    instead of it): ``pinned_transport.open_socket``."""
    from cveFeed import pinned_transport
    addresses, project = target
    return pinned_transport.open_socket(addresses, timeout, project=project, host=host)


# ----------------------------------------------------------------------------- the child process

def _unprivileged():
    """``(uid, gid)`` of the account the browser runs as, or None to run as the worker's own. The browser renders pages hostile hosts control and runs
    without its own sandbox (a container has no user namespaces to give it one), so as root it would hand a renderer exploit the worker's whole
    container: when the worker is root, the child runs as ``nobody`` (``CVENGINE_SCREENSHOT_USER`` names another account; ``root`` or ``-`` turns this off)."""
    if os.geteuid() != 0:
        return None
    name = os.environ.get('CVENGINE_SCREENSHOT_USER', 'nobody').strip() or 'nobody'
    if name in ('root', '-', '0'):
        return None
    try:
        entry = pwd.getpwnam(name)
    except KeyError:
        logger.warning('the screenshot account %r does not exist: the browser runs as the worker', name)
        return None
    return entry.pw_uid, entry.pw_gid


def make_workdir():
    """A private directory the browser child writes into (its profile, its temporary files, the pictures before they are checked and moved into
    the media root)."""
    path = tempfile.mkdtemp(prefix='cvengine-shots-')
    identity = _unprivileged()
    if identity:
        os.chown(path, *identity)
    os.chmod(path, 0o700)
    return path


def _child_env(workdir):
    keep = ('PATH', 'LANG', 'LC_ALL', 'PLAYWRIGHT_BROWSERS_PATH', 'TZ')
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env.setdefault('PATH', '/usr/local/bin:/usr/bin:/bin')
    env['HOME'] = env['TMPDIR'] = workdir  # nothing of the worker's environment (database and broker passwords) reaches the browser
    if 'PLAYWRIGHT_BROWSERS_PATH' not in env:
        env['PLAYWRIGHT_BROWSERS_PATH'] = browsers_dir()  # the browser lives under the worker's home, which the child's own home is not
    return env


def run_child(job, on_result, wall_seconds, argv=None, heavy=True, label='', workdir=None):
    """Run the browser child on ``job`` (see ``shot_worker``), hand each ``result`` to ``on_result``, and return ``''`` or why the child ended without
    finishing. A wall-clock limit kills the whole process group; a pause, a stop or a low-memory kill reaches it through the heavy-job gate
    (``ScanAborted`` / ``MemoryKill`` propagate)."""
    from reNgine import resources
    argv = argv or [sys.executable, SCRIPT]

    def drive(proc, job_handle=None):
        timer = threading.Timer(wall_seconds, lambda: resources.terminate_group(proc, grace=3))
        timer.daemon = True
        timer.start()
        fatal, done = '', False
        try:
            proc.stdin.write(json.dumps(job, separators=(',', ':')) + '\n')
            proc.stdin.flush()
            proc.stdin.close()
            for line in proc.stdout:
                try:
                    message = json.loads(line)
                except ValueError:
                    continue
                op = message.get('op')
                if op == 'result':
                    on_result(message)
                elif op == 'fatal':
                    fatal = str(message.get('reason') or 'the browser failed')
                elif op == 'done':
                    done = True
        except (BrokenPipeError, OSError, ValueError):
            pass
        finally:
            timer.cancel()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                resources.terminate_group(proc, grace=3)
        if job_handle is not None:
            job_handle.raise_if_killed()
        if fatal:
            return fatal
        if not done:
            return f'the browser process ended before it finished (status {proc.returncode})'
        return ''

    def start():
        identity = _unprivileged()
        extra = {'user': identity[0], 'group': identity[1], 'extra_groups': []} if identity else {}
        return subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1,
                                env=_child_env(workdir or tempfile.gettempdir()), start_new_session=True, **extra)
    if not heavy:
        return drive(start())
    with resources.heavy_job(HEAVY_KIND, label=label or 'pages', wait_timeout=HEAVY_WAIT_SECONDS) as handle:
        proc = start()
        handle.attach(proc)
        return drive(proc, handle)


# ----------------------------------------------------------------------------- saving what was captured

def media_root():
    return os.path.realpath(settings.MEDIA_ROOT)


def safe_name(host):
    return re.sub(r'[^a-z0-9.-]+', '_', host.lower())[:100] or 'host'


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
                    pass


def project_bytes(project_id):
    from django.db.models import Sum
    from cveFeed.models import HostScreenshot
    return HostScreenshot.objects.filter(project_id=project_id).aggregate(total=Sum('image_bytes'))['total'] or 0


def _shrink(path):
    """Re-encode a picture over the size cap as JPEG (quality 80, then 60). Returns ``(path, error)``; the PNG is removed on success."""
    try:
        from PIL import Image
        jpg = os.path.splitext(path)[0] + '.jpg'
        with Image.open(path) as image:
            rgb = image.convert('RGB')
        for quality in (80, 60):
            rgb.save(jpg, 'JPEG', quality=quality, optimize=True)
            if os.path.getsize(jpg) <= max_bytes():
                os.remove(path)
                return jpg, ''
        os.remove(jpg)
        return path, 'The picture is larger than the size allowed.'
    except Exception as exc:  # noqa: BLE001 - a picture that cannot be shrunk is not stored
        return path, f'The picture could not be reduced ({type(exc).__name__}).'


def _inside(path, base):
    real, root = os.path.realpath(path), os.path.realpath(base)
    return real.startswith(root + os.sep)


def finish_image(row, result, workdir):
    """Validate and store what the browser wrote for ``row`` (a file in ``workdir``). Returns ``(fields, outcome, reason)``: the model fields of a
    good capture, or an outcome (blank, error) and why. The file is moved into the media root only when it is kept, and is deleted otherwise."""
    from cveFeed import shots
    from cveFeed.rdp_shot import is_meaningful
    path = result.get('path') or ''
    if not path or not _inside(path, workdir) or not os.path.isfile(path) or os.path.islink(path):
        return {}, 'error', 'The browser reported a picture that was not written.'
    size = os.path.getsize(path)
    if size > shots.MAX_SHOT_BYTES:
        os.remove(path)
        return {}, 'error', 'The picture is larger than the size allowed.'
    with open(path, 'rb') as handle:
        if not is_meaningful(handle.read()):
            os.remove(path)
            return {}, BLANK, 'The page rendered blank (a single flat color).'
    if size > max_bytes():
        path, error = _shrink(path)
        if error:
            os.remove(path)
            return {}, 'error', error
        size = os.path.getsize(path)
    if project_bytes(row.project_id) + size > project_cap_bytes():
        _free_previous(row.project_id)
        if project_bytes(row.project_id) + size > project_cap_bytes():
            os.remove(path)
            return {}, 'error', f'This project\'s screenshot storage ({project_cap_bytes() // (1024 * 1024)} MB) is full.'
    final, rel = new_paths(row)
    final = os.path.splitext(final)[0] + os.path.splitext(path)[1]  # a shrunk picture is a JPEG
    rel = os.path.splitext(rel)[0] + os.path.splitext(path)[1]
    os.makedirs(os.path.dirname(final), exist_ok=True)
    shutil.move(path, final)
    os.chmod(final, 0o644)
    thumb = shots.thumbnail_path(final)
    return {'image_path': rel, 'thumb_path': os.path.relpath(thumb, media_root()) if thumb else '', 'image_hash': shots.dhash_file(final),
            'image_bytes': size}, OK, ''


def _free_previous(project_id):
    """Drop every project's "previous capture" file, the part of the storage that is only kept for comparing."""
    from cveFeed.models import HostScreenshot
    rows = HostScreenshot.objects.filter(project_id=project_id).exclude(previous_image_path='')
    remove_files(*rows.values_list('previous_image_path', flat=True))
    rows.update(previous_image_path='', previous_image_hash='')


def _same_host(final_url, host):
    return (urlsplit(final_url).hostname or '').lower().rstrip('.') == host


def apply_result(row, result, now=None, workdir=''):
    """Write one page's result onto its row. A failure keeps the previous picture and says what happened; a success keeps one earlier picture
    (the one it replaces) for comparison and deletes older ones. Returns the outcome."""
    from cveFeed.models import HostScreenshot
    now = now or timezone.now()
    outcome, reason = result.get('outcome') or 'error', str(result.get('reason') or '')[:300]
    fields = {}
    if outcome == OK:
        fields, outcome, reason = finish_image(row, result, workdir)
    update = {'outcome': outcome, 'reason': reason, 'attempted_at': now, 'queued_at': None}
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
                      previous_image_path=row.image_path, previous_image_hash=row.image_hash)
        HostScreenshot.objects.filter(pk=row.pk).update(**update)
        if stale_previous and stale_previous != row.image_path:
            remove_files(stale_previous)
    else:
        if result.get('final_url') and not row.image_path:
            update['final_url'] = str(result['final_url'])[:2000]
        HostScreenshot.objects.filter(pk=row.pk).update(**update)
    return outcome


# ----------------------------------------------------------------------------- the drain

Item = namedtuple('Item', 'row host scheme port url address')


def _resolve(host, port, project_id, timeout=10):
    """The address the browser is pinned to: every answer for the name is vetted (``pinned_transport.resolve`` refuses a prohibited one), IPv4 first.
    Raises ``ValueError`` for a prohibited address, ``OSError`` when the name does not resolve or does not answer in time."""
    from cveFeed import pinned_transport
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        answers = pool.submit(pinned_transport.resolve, host, port, project_id).result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        raise OSError('the name server did not answer in time') from None
    finally:
        pool.shutdown(wait=False)
    ordered = sorted(answers, key=lambda item: item[0] != socket.AF_INET)
    return ordered[0][1][0]


def _precheck(row, ctx, resolve):
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
    try:
        address = resolve(row.host, row.port, project_id)
    except ValueError:
        return BLOCKED, 'Blocked: the name resolves to an internal or reserved address, which this server never visits.'
    except OSError as exc:
        return 'unreachable', f'The name could not be resolved ({str(exc)[:100] or "no answer"}).'
    return ('item', address)


def _batches(rows, size=BATCH_PAGES):
    return [rows[i:i + size] for i in range(0, len(rows), size)]


def _kill_switch():
    from reNgine import resources
    return resources.global_pause_requested(fail_closed=True)


def process(rows, runner=None, resolve=None, summary=None, proxy_factory=None):
    """Capture ``rows`` (queued HostScreenshot rows, any projects). Every page is re-checked first (still in the inventory, not excluded or
    archived, inside the bug bounty scope, resolves only to addresses a scanner may visit), then captured by the browser child, and each result is
    written as it arrives, so a kill part-way keeps what was done. The rows not reached stay queued."""
    from cveFeed.models import HostScreenshot
    summary = summary if summary is not None else {}
    for key in ('captured', 'failed', 'blocked', 'dropped'):
        summary.setdefault(key, 0)
    resolve = resolve or _resolve
    ctx, runner = {}, runner or run_child
    items = []
    for row in rows:
        verdict = _precheck(row, ctx, resolve)
        if verdict == 'gone':
            HostScreenshot.objects.filter(pk=row.pk).delete()
            summary['dropped'] += 1
        elif verdict[0] != 'item':
            apply_result(row, {'outcome': verdict[0], 'reason': verdict[1]})
            summary['blocked' if verdict[0] == BLOCKED else 'failed'] += 1
        else:
            items.append(Item(row, row.host, row.scheme, row.port, url_for(row.host, row.scheme, row.port), verdict[1]))
    for batch in _batches(items):
        if _kill_switch():
            return summary
        _run_batch(batch, runner, summary, proxy_factory=proxy_factory)
    return summary


def _run_batch(items, runner, summary, proxy_factory=None):
    """One browser child over ``items`` (``Item`` tuples), every page through its own vetting proxy connection (``shot_proxy``), each result written as it
    arrives. ``proxy_factory(admit, connect, secret)`` replaces the proxy in tests."""
    import secrets
    from reNgine import resources
    from cveFeed import shot_proxy
    from cveFeed.models import HostScreenshot
    by_key, paths, guards, done, order = {}, {}, {}, set(), []
    targets = []
    workdir = make_workdir()
    for index, item in enumerate(items):
        key = str(index)
        paths[key] = os.path.join(workdir, f'{key}.png')
        by_key[key] = item
        order.append(key)
        guards[key] = Guard(item.row.project_id, item.host, unattended=not item.row.by_person)
        targets.append({'key': key, 'url': item.url, 'out': paths[key]})

    def admit(key, host, port):
        guard = guards.get(key)
        return guard.admit(host, port) if guard else (None, 'unknown page')

    def on_result(message):
        key = message.get('key')
        item = by_key.get(key)
        if item is None or key in done:
            return
        done.add(key)
        message['path'] = paths[key]  # the file is the one this side named, whatever the child says
        guard = guards[key]
        if message.get('outcome') in ('unreachable', 'error', 'timeout') and guard.denied:
            message['outcome'], message['reason'] = BLOCKED, guard.blocked_reason()[:300]  # the page never loaded because a guard refused it
        elif message.get('outcome') == OK:
            summary['dropped_requests'] = summary.get('dropped_requests', 0) + len(guard.denied)
        row = HostScreenshot.objects.filter(pk=item.row.pk).first()
        if row is None:
            return
        outcome = apply_result(row, message, workdir=workdir)
        summary['captured' if outcome == OK else 'blocked' if outcome == BLOCKED else 'failed'] += 1

    secret = secrets.token_urlsafe(24)
    proxy = (proxy_factory or shot_proxy.VettingProxy)(admit, connect, secret)
    wall = len(items) * (nav_timeout_seconds() + 10) + 60
    failure = ''
    try:
        with proxy:
            job = {'targets': targets, 'proxy': {'server': proxy.server, 'password': secret},
                   'settings': {'total_seconds': nav_timeout_seconds(), 'nav_timeout_ms': min(nav_timeout_seconds() - 3, 15) * 1000}}
            failure = runner(job, on_result, wall, label=f'{len(items)} pages', workdir=workdir)
    except (resources.ScanAborted, resources.MemoryBusy, resources.MemoryKill) as exc:
        summary['stopped'] = type(exc).__name__  # paused, stopped or short of memory: the rows stay queued
    except Exception as exc:  # noqa: BLE001 - an unexpected failure ends the batch, not the drain worker
        logger.exception('screenshot batch failed')
        failure = f'{type(exc).__name__}'
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    if not failure and done:
        _note_error(None)  # the browser ran: whatever it last said is over
    if failure:
        summary['error'] = failure
        _note_error(failure)
        # nothing came back for the pages the browser never reached: say so on their rows, so they are not retried in a tight loop
        for key in order:
            if key not in done:
                apply_result(by_key[key].row, {'outcome': 'unavailable', 'reason': f'The browser could not run: {failure}'[:300]})
                summary['failed'] += 1


def _note_error(text):
    try:
        from django.core.cache import cache
        if text is None:
            cache.delete('screenshots:last_browser_error')
            return
        cache.set('screenshots:last_browser_error', {'at': timezone.now().isoformat(), 'error': text[:300]}, 7 * 24 * 3600)
    except Exception:  # noqa: BLE001
        pass


def queued_rows(limit):
    from cveFeed.models import HostScreenshot
    return list(HostScreenshot.objects.filter(outcome=QUEUED).order_by('-by_person', 'queued_at', 'pk')[:limit])


def drain(runner=None, resolve=None, budget_seconds=DRAIN_SECONDS, now_fn=time.monotonic, batch=BATCH_PAGES, proxy_factory=None):
    """Capture the queued pages, a batch at a time, until none are left or the budget is spent (then ask for another drain). One at a time: a
    second call while one runs returns at once, and the running one picks up what was queued meanwhile."""
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
            rows = queued_rows(batch)
            if not rows:
                break
            if now_fn() - started > budget_seconds:
                kick(delay=5)
                summary['continued'] = True
                break
            before = (summary['captured'], summary['failed'], summary['blocked'], summary['dropped'])
            process(rows, runner=runner, resolve=resolve, summary=summary, proxy_factory=proxy_factory)
            if summary.get('stopped') or before == (summary['captured'], summary['failed'], summary['blocked'], summary['dropped']):
                break  # stopped, or a batch settled nothing: leave the rest for the next run rather than spin
    worked = summary['captured'] or summary['failed'] or summary['blocked'] or summary['dropped']
    if worked:
        if summary['captured'] or summary['failed'] or summary['blocked']:
            _log(summary)
        if not (summary.get('stopped') or summary.get('skipped') or summary.get('continued')) and queued_rows(1):
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
                'unavailable': 'could not run the browser'}


def note_for(rows, *, has_web_evidence, legacy=False, network=None, ports_known=False):
    """The line the host page shows next to (or instead of) a screenshot, from what the attempts recorded. Empty when a current picture is shown
    and nothing needs saying. ``legacy`` is True when an older discovery screenshot is shown because the browser has no picture of the host."""
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
            return (f'No screenshot: this host is inside the internal network {network}. Only a Sentinel there scans it, and Sentinels do not '
                    'take screenshots; this server never captures internal hosts.')
        why = unavailable_reason()
        if why:
            return f'No screenshot: {why}'
        if not has_web_evidence:
            if ports_known:
                return 'No screenshot: no web port (such as 80 or 443) is recorded open on this host, so there is no page to capture.'
            return 'No screenshot: no web page has answered on this host, so there is nothing to capture.'
        return 'No screenshot yet: this host answers on the web and is waiting for the next screenshot pass (every hour), or press Take screenshot.'
    if queued:
        return 'Waiting for the screenshot worker: ' + ', '.join(f'{r.scheme}://{r.host}:{r.port}' for r in queued[:3]) + '.'
    return 'No screenshot: ' + _reasons(failed)


def _reasons(rows):
    parts = []
    for row in rows[:3]:
        text = (row.reason or FAILURE_TEXT.get(row.outcome, row.outcome)).strip()
        parts.append(f'{row.scheme}://{row.host}:{row.port}: {text}' + ('' if text.endswith('.') else '.'))
    return ' '.join(parts)


def status_counts(project_ids):
    """For ``get_system_status``: how many of the projects' hosts have a screenshot, what is queued, what failed and the last capture error."""
    from django.db.models import Count
    from cveFeed.models import HostScreenshot
    from startScan.models import Subdomain
    rows = HostScreenshot.objects.filter(project_id__in=list(project_ids)).exclude(scheme='rdp')
    by_outcome = {row['outcome']: row['n'] for row in rows.values('outcome').annotate(n=Count('id'))}
    shot_hosts = rows.exclude(image_path='').values('project_id', 'host').distinct().count()
    web_hosts = (Subdomain.objects.filter(target_domain__project_id__in=list(project_ids)).filter(_web_evidence_q())
                 .values('target_domain__project_id', 'name').distinct().count())
    last = rows.filter(outcome__in=FAILURES).exclude(attempted_at=None).order_by('-attempted_at').values('host', 'scheme', 'port', 'outcome', 'reason', 'attempted_at').first()
    return {'enabled': enabled(), 'available': available(), 'unavailable_reason': unavailable_reason() or None,
            'hosts_with_web': web_hosts, 'hosts_with_screenshot': shot_hosts, 'pages': by_outcome,
            'queued': by_outcome.get(QUEUED, 0), 'failed': sum(by_outcome.get(k, 0) for k in FAILURES), 'blocked': by_outcome.get(BLOCKED, 0),
            'nla_required': HostScreenshot.objects.filter(project_id__in=list(project_ids), outcome=NLA).count(),
            'last_error': ({'page': f'{last["scheme"]}://{last["host"]}:{last["port"]}', 'outcome': last['outcome'], 'reason': last['reason'],
                            'at': last['attempted_at'].isoformat()} if last else None)}
