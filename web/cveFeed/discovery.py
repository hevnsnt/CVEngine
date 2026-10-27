"""Live bbot discovery for a target: streams events into the DB as they arrive.

Entering a domain starts this. A ScanHistory row is created (so the scan shows up
in Scans, scoped to the project like every other scan), bbot runs in the celery
worker, and every few seconds the batch it has seen is persisted as Subdomain,
IP and Port rows plus DiscoveryEvent rows, which the dashboard polls to draw the
discovery graph and the live feed while it happens.
"""
import functools
import logging
import os
import shutil
import time
from contextlib import contextmanager

from django.conf import settings
from django.utils import timezone

from reNgine import bbot as bbot_lib

logger = logging.getLogger(__name__)

FLUSH_EVERY_EVENTS = 15
FLUSH_EVERY_SECONDS = 2.0
MAX_EVENTS_PER_SCAN = 5000
DEFAULT_DISCOVERY_TIMEOUT = 6 * 3600
BBOT_SCANS_HOME = os.path.expanduser('~/.bbot/scans')


def discovery_timeout():
    """Seconds bbot may run, from the App Admin timings (read at the start of each run)."""
    try:
        from dashboard.models import SystemTimings
        return SystemTimings.current().discovery_timeout_hours * 3600
    except Exception:  # noqa: BLE001 - never let a settings problem stop a scan
        return DEFAULT_DISCOVERY_TIMEOUT

QUEUED, RUNNING, FAILED, SUCCESS, ABORTED = -1, 1, 0, 2, 3


def pick_engine():
    from scanEngine.models import EngineType
    return EngineType.objects.filter(default_engine=True).first() or EngineType.objects.order_by('id').first()


FALLBACK = {'deep': ['deep', 'standard', 'passive'], 'standard': ['standard', 'passive']}  # modes tried when memory runs out
HOST_PIPELINE_TASK = 'host_pipeline'  # marks a ScanHistory made by run_host_pipeline (in ScanHistory.tasks)
RETEST_TASK = 'retest'  # also on a host pipeline started because its hosts changed (cveFeed.retest)
MAX_PIPELINE_HOSTS = 200
RUNNING_WINDOW_SECONDS = 11 * 3600  # a scan marked running for longer than this is a casualty of a restart (see views.RUNNING_WINDOW)
DUPLICATE_WINDOW = 10 * 60  # seconds; the domain lock below is what really serialises long runs


def _active_filter():
    """Scans that count as "this target is being discovered": any queued one, whatever its age (it is waiting its turn), and a
    running one only inside the window (a restart can leave an old row "running"; that must not block the target)."""
    from datetime import timedelta
    from django.db.models import Q
    cutoff = timezone.now() - timedelta(seconds=DUPLICATE_WINDOW)
    # a host pipeline (a handful of new hosts) is not a discovery of the target, whatever else it is doing
    return (Q(scan_status=QUEUED) | Q(scan_status=RUNNING, start_scan_date__gte=cutoff)) & ~Q(tasks__contains=[HOST_PIPELINE_TASK])


def running_discovery(domain):
    """A discovery of this domain that is queued or started in the last few minutes and still going, if any: a double click
    or a repeated bulk add."""
    from startScan.models import ScanActivity, ScanHistory
    return ScanHistory.objects.filter(_active_filter(), domain=domain).order_by('-id').first()


def start_discoveries(domains, mode=bbot_lib.DEFAULT_MODE, quiet=False):
    """Queue the streaming bbot task for each domain, in the order given, with rows created in bulk. Returns one ScanHistory
    per domain; a domain that is already being discovered returns that scan instead of a second, since two runs of one target
    only compete for memory. Scans are created queued (-1); the pipeline marks one running when a worker starts it."""
    from cveFeed.tasks import run_bbot_discovery
    from startScan.models import ScanActivity, ScanHistory
    domains = list(domains)
    active = {}
    for start in range(0, len(domains), 1000):
        for scan in ScanHistory.objects.filter(_active_filter(), domain_id__in=[d.id for d in domains[start:start + 1000]]).order_by('id'):
            active[scan.domain_id] = scan
    fresh = list({d.id: d for d in domains if d.id not in active}.values())
    created = {}
    if fresh:
        engine = pick_engine()
        if engine is None:
            raise RuntimeError('no scan engine is configured')
        now = timezone.now()
        for start in range(0, len(fresh), 500):
            part = fresh[start:start + 500]
            scans = ScanHistory.objects.bulk_create([
                ScanHistory(domain=d, scan_type=engine, start_scan_date=now, scan_status=QUEUED, results_dir='/usr/src/scan_results')
                for d in part])
            ScanActivity.objects.bulk_create([
                ScanActivity(scan_of=scan, title='BBOT discovery', name='bbot_discovery', time=now, status=QUEUED) for scan in scans])
            created.update((scan.domain_id, scan) for scan in scans)
    if not quiet:  # a bulk add logs one summary line instead
        from cveFeed import activity
        for d in domains:
            if d.id in created:
                activity.log('discovery', f'Queued bbot discovery of {d.name}', project=d.project_id, scan_id=created[d.id].id)
            elif d.id in active:
                activity.log('discovery', f'{d.name} is already being discovered (scan #{active[d.id].id}); not starting another',
                             project=d.project_id, scan_id=active[d.id].id)
    for scan in sorted(created.values(), key=lambda s: s.id):  # first in, first out
        run_bbot_discovery.delay(scan.id, mode)
    return [created.get(d.id) or active[d.id] for d in domains]


def start_discovery(domain, mode=bbot_lib.DEFAULT_MODE, quiet=False):
    """Queue discovery of one domain (see ``start_discoveries``). Returns the ScanHistory."""
    return start_discoveries([domain], mode, quiet)[0]


def queued_ids():
    """Ids of every queued scan, oldest first. The queue is one first-in, first-out line shared by all projects, so a scan's
    place in it is not limited to what the caller can see."""
    from startScan.models import ScanHistory
    return list(ScanHistory._base_manager.filter(scan_status=QUEUED).order_by('id').values_list('id', flat=True))


def queue_position(scan_id, ids=None):
    """How many queued scans are ahead of this one (0 is next up): the queued scans with a smaller id. A list that already
    holds the queue (``ids``) is searched; otherwise it is one count."""
    if ids is not None:
        from bisect import bisect_left
        return bisect_left(ids, scan_id)
    from startScan.models import ScanHistory
    return ScanHistory._base_manager.filter(scan_status=QUEUED, id__lt=scan_id).count()


def mark_running(scan_id):
    """A worker has picked the scan up: queued becomes running, and the clock starts now rather than when it was queued."""
    from startScan.models import ScanActivity, ScanHistory
    ScanHistory.objects.filter(pk=scan_id, scan_status=QUEUED).update(scan_status=RUNNING, start_scan_date=timezone.now())
    ScanActivity.objects.filter(scan_of_id=scan_id, name='bbot_discovery', status=QUEUED).update(status=RUNNING, time=timezone.now())


def _flush(scan, ctx, batch, observed, bbot_scan_name='', stored=0):
    """Persist what the stream has produced since the last flush. ``stored`` is how many events the scan already has
    (the caller keeps the running count, so a flush never needs a COUNT(*)); returns the new total."""
    from cveFeed.models import DiscoveryEvent
    from reNgine.tasks import persist_bbot_result
    persist_bbot_result(batch, ctx=ctx)
    persist_screenshots(scan, batch.screenshots, bbot_scan_name)
    room = MAX_EVENTS_PER_SCAN - stored
    if room > 0 and observed:
        DiscoveryEvent.objects.bulk_create([
            DiscoveryEvent(scan=scan, domain_id=scan.domain_id, type=o.type, label=o.label[:500], host=o.host[:500],
                           parent_host=o.parent_host[:500], module=o.module[:64])
            for o in observed[:room]])
        stored += min(room, len(observed))
    return stored


def persist_screenshots(scan, screenshots, bbot_scan_name):
    """Copy each gowitness screenshot bbot saved (under its own ~/.bbot/scans/<name>/ home, which bbot
    may clean up later) into this scan's permanent scan-results storage, Shodan-style, and record it on
    the matching Subdomain. A missing source file, an unknown bbot scan name, or no matching Subdomain
    is skipped quietly - this must never interrupt discovery."""
    if not (screenshots and bbot_scan_name):
        return
    from cveFeed import shots
    from startScan.models import Subdomain
    dest_dir = os.path.join(settings.MEDIA_ROOT, f'{scan.domain.name}_{scan.id}', 'screenshots')
    hashed = 0
    shots.warn_unavailable(scan)
    for shot in screenshots:
        host, rel_path = shot.get('host'), shot.get('rel_path')
        if not (host and rel_path):
            continue
        base = os.path.realpath(os.path.join(BBOT_SCANS_HOME, str(bbot_scan_name)))
        source = os.path.realpath(os.path.join(base, str(rel_path)))
        if not source.startswith(base + os.sep):  # event fields are tool output: never copy outside bbot's own scan dir
            logger.warning('ignoring bbot screenshot path outside its scan dir: %r', rel_path)
            continue
        if not os.path.isfile(source):
            logger.warning('bbot screenshot missing on disk: %s', source)
            continue
        subdomain = Subdomain.objects.filter(scan_history=scan, name=host).first()
        if not subdomain:
            continue
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, os.path.basename(rel_path))
        try:
            shutil.copy2(source, dest)
        except OSError:
            logger.exception('could not copy bbot screenshot %s', source)
            continue
        subdomain.screenshot_path = os.path.relpath(dest, settings.MEDIA_ROOT)
        if hashed < shots.MAX_HASH_PER_FLUSH:  # one small image decode per screenshot, at copy time
            subdomain.screenshot_hash = shots.dhash_file(dest)
            hashed += 1
        subdomain.save(update_fields=['screenshot_path', 'screenshot_hash'])


def _report_key_problems(problems, extra_args, scan):
    """One activity line per service whose key bbot rejected (or never received). bbot skips such a module and carries on, so without
    this a stored key that is wrong looks like a service that found nothing."""
    from cveFeed import activity
    from cveFeed.api_credentials import service_for_module
    configured = {a.split('=', 1)[0].split('.')[1] for prev, a in zip(extra_args, extra_args[1:])
                  if prev == '-c' and a.startswith('modules.') and '=' in a}
    said = set()
    for module, reason in problems:
        service = service_for_module(module)
        if module not in configured or not service or service[0] in said:
            continue
        said.add(service[0])
        activity.log('discovery', f'{service[1]}: the key was not accepted ({reason[:120]}); {module} did not run on {scan.domain.name}',
                     project=scan.domain.project_id, status='failed', scan_id=scan.id)


def run_discovery(scan_id, mode=bbot_lib.DEFAULT_MODE, stream=bbot_lib.stream_events, finalize=True):
    """Body of the celery task; ``stream`` is injectable so tests need no bbot binary."""
    from cveFeed.api_credentials import bbot_config_args
    from startScan.models import ScanActivity, ScanHistory
    scan = ScanHistory.objects.select_related('domain__project').get(pk=scan_id)
    mark_running(scan_id)
    ctx = {'scan_history_id': scan.id, 'domain_id': scan.domain_id, 'subscan_id': None}
    extra_args = bbot_config_args(scan.domain.project) if scan.domain.project_id else []
    strict_scope = scan.domain.is_host_scoped()  # a tenant on a shared provider domain: this host only, never its parent or siblings
    batch, hosts, observed = bbot_lib.BbotResult(), {}, []
    shown = set()  # bbot reports the same name from several modules; show each thing once
    bbot_scan_name = ''  # bbot's own directory name for this run (~/.bbot/scans/<name>/), from its SCAN event
    last_flush = time.time()
    status, error = SUCCESS, ''
    from cveFeed import activity
    from cveFeed.models import DiscoveryEvent
    from reNgine.resources import MemoryKill, ScanAborted
    stored = DiscoveryEvent.objects.filter(scan=scan).count()  # once; _flush is then told the running total
    running = activity.log('discovery', f'bbot is discovering {scan.domain.name}', project=scan.domain.project_id,
                           status='running', scan_id=scan.id)
    # A run that is stopped for lack of memory (by the gate's watchdog, or by the kernel: status -9) is retried one step
    # lighter: deep as standard, standard as passive. What the heavier run already found is kept.
    modes = FALLBACK.get(mode, [mode])
    finished_mode = mode
    problems = []  # (bbot module, reason) for modules bbot skipped at start-up, e.g. because a key was rejected
    try:
        # Same policy the nuclei, route-auth and validation stages apply: never start a scanner against a name
        # that currently resolves to a loopback, link-local, metadata or (unless allowed) internal address.
        from targetApp.target_types import resolves_to_blocked
        if resolves_to_blocked(scan.domain.name, project=scan.domain.project_id):
            raise ValueError(f'{scan.domain.name} resolves to a loopback, link-local or internal address; '
                             'discovery refused (CVENGINE_ALLOW_PRIVATE_TARGETS=1 allows internal ranges)')
        for attempt, run_mode in enumerate(modes):
            try:
                for event in stream([scan.domain.name], mode=run_mode, timeout=discovery_timeout(), extra_args=extra_args,
                               strict_scope=strict_scope, problems=problems):
                    if not bbot_scan_name and event.get('type') == 'SCAN':
                        bbot_scan_name = (event.get('data_json') or {}).get('name') or ''
                    seen = bbot_lib.parse_event(event, batch, hosts)
                    if seen and (seen.type, seen.label) not in shown:
                        shown.add((seen.type, seen.label))
                        observed.append(seen)
                    if len(observed) >= FLUSH_EVERY_EVENTS or time.time() - last_flush >= FLUSH_EVERY_SECONDS:
                        stored = _flush(scan, ctx, batch, observed, bbot_scan_name, stored)
                        batch, observed, last_flush = bbot_lib.BbotResult(), [], time.time()
                finished_mode = run_mode
                break
            except Exception as exc:
                out_of_memory = isinstance(exc, MemoryKill) or getattr(exc, 'returncode', None) == -9
                if out_of_memory and attempt + 1 < len(modes):
                    lighter = modes[attempt + 1]
                    logger.warning('bbot ran out of memory on scan %s; retrying as %s discovery', scan_id, lighter)
                    activity.log('discovery', f'{run_mode.capitalize()} discovery of {scan.domain.name} ran out of memory; '
                                 f'retrying as {lighter}', project=scan.domain.project_id, scan_id=scan.id)
                    continue
                raise
        stored = _flush(scan, ctx, batch, observed, bbot_scan_name, stored)
        _report_key_problems(problems, extra_args, scan)
    except ScanAborted:  # stopped by a person: the stop already marked the scan and its activities aborted
        activity.settle(running, 'failed', message=f'Discovery of {scan.domain.name} was stopped')
        return {'scan_id': scan.id, 'status': ABORTED, 'error': 'stopped'}
    except Exception as exc:  # the scan must end in a visible state, never stay "running"
        logger.exception('bbot discovery failed for scan %s', scan_id)
        status, error = FAILED, str(exc)[:290]
    ScanActivity.objects.filter(scan_of=scan, name='bbot_discovery').update(
        status=status, time=timezone.now(), error_message=error or None)
    if finalize or status == FAILED:
        scan.scan_status, scan.stop_scan_date, scan.error_message = status, timezone.now(), error or None
        scan.save(update_fields=['scan_status', 'stop_scan_date', 'error_message'])
    from startScan.models import Subdomain
    found = Subdomain.objects.filter(scan_history=scan).count()
    activity.settle(running, 'done' if status == SUCCESS else 'failed', message=(
        f'Discovery of {scan.domain.name} finished: {found} host{"s" if found != 1 else ""} found'
        if status == SUCCESS else f'Discovery of {scan.domain.name} failed: {error}'), hosts=found)
    if status == SUCCESS:
        from cveFeed import ledger
        ledger.record('bbot', [scan.domain.name], scan.domain.project_id, scan)
        if finished_mode == 'deep':  # the weekly deep sweep (tasks.deep_scan_apexes) counts only runs that really were deep
            ledger.record('bbot-deep', [scan.domain.name], scan.domain.project_id, scan)
    if status == SUCCESS and finalize:
        from cveFeed.tasks import correlate_cves
        correlate_cves.delay(scan_history_id=scan.id)
    return {'scan_id': scan.id, 'status': status, 'error': error}


LOCK_TTL = 180  # seconds; refreshed while the pipeline runs, so a crashed worker frees its target within minutes


@contextmanager
def domain_lock(domain_id, scan_id):
    """One pipeline per target at a time. Yields True when this scan holds the lock (or no Redis is available to ask), else
    the id of the scan that does. A task the queue delivers twice, or the same domain queued twice, then cannot run in
    parallel and compete for memory."""
    from reNgine import resources
    with resources.redis_claim(f'cvengine:discovery:domain:{domain_id}', scan_id, LOCK_TTL) as holder:
        yield holder


def run_pipeline(scan_id, *args, **kwargs):
    """Run the pipeline for one scan unless this target is already being worked on (see ``domain_lock``)."""
    from cveFeed import activity
    from startScan.models import ScanActivity, ScanHistory
    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
    if scan.scan_status == 3:  # aborted while it waited in the queue
        return {'scan_id': scan_id, 'status': 'aborted'}
    with domain_lock(scan.domain_id, scan_id) as holder:
        if holder is True:
            from reNgine import resources
            with resources.scan_context(scan_id):  # a stop of this scan reaches the heavy jobs it starts
                return _run_pipeline(scan_id, *args, **kwargs)
    if str(holder) == str(scan_id):
        return {'scan_id': scan_id, 'status': 'duplicate'}  # the queue delivered this very task twice; the first one is running
    message = f'another discovery of {scan.domain.name} is already running (scan #{holder})'
    ScanHistory.objects.filter(pk=scan_id).update(scan_status=3, stop_scan_date=timezone.now(), error_message=message[:290])
    ScanActivity.objects.filter(scan_of=scan, name='bbot_discovery').update(status=3, time=timezone.now(), error_message=message[:290])
    activity.log('discovery', f'Skipped a second discovery of {scan.domain.name}: scan #{holder} is already running',
                 project=scan.domain.project_id, scan_id=scan_id)
    return {'scan_id': scan_id, 'status': 'skipped', 'error': message}


IP_LOOKUP_TIMEOUT = 3  # seconds for the PTR lookup and for the certificate connection


def ptr_names(ip, timeout=IP_LOOKUP_TIMEOUT):
    """The reverse-DNS name of ``ip`` (``[]`` when it has none or the lookup is slow). gethostbyaddr has no timeout of its own."""
    import concurrent.futures
    import socket
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        return [pool.submit(socket.gethostbyaddr, ip).result(timeout=timeout)[0].lower().rstrip('.')]
    except Exception:  # noqa: BLE001 - no PTR record, a resolver error or a timeout: nothing to record
        return []
    finally:
        pool.shutdown(wait=False)


def tls_names(ip, timeout=IP_LOOKUP_TIMEOUT, project=None):
    """The hostnames on the certificate ``ip`` serves on 443: the subject name and the subject alternative names."""
    from cveFeed import hygiene
    info = hygiene._fetch_cert(ip, 443, timeout=timeout, project=project)
    if not info:
        return []
    names = [info.get('subject') or ''] + list(info.get('sans') or [])
    return list(dict.fromkeys(n.lower().lstrip('*.').rstrip('.') for n in names if n and '.' in n))


def discover_ip(scan, ptr=None, certificate=None):
    """Stand in for bbot on an IP target. bbot is a subdomain finder, and an IP has no subdomains: all it could do here is a
    reverse lookup and read the certificate, which is cheap to do directly. Creates the host for the IP, records the names
    it answers to (PTR and certificate) as DNS events on it, and leaves them out of the targets: they may be out of scope.
    ``ptr`` and ``certificate`` (``ip -> [names]``) are injectable so tests need no network. Returns the discovery result."""
    import concurrent.futures
    from cveFeed import activity
    from cveFeed.models import DiscoveryEvent
    from reNgine.tasks import persist_bbot_result
    from startScan.models import ScanActivity
    domain, ip = scan.domain, scan.domain.name
    running = activity.log('discovery', f'Looking up {ip}: reverse DNS and certificate names (no bbot for a bare IP)',
                           project=domain.project_id, status='running', scan_id=scan.id)
    status, error, found = SUCCESS, '', {}
    try:
        persist_bbot_result(bbot_lib.BbotResult(subdomains={ip}, resolutions={(ip, ip)}),
                            ctx={'scan_history_id': scan.id, 'domain_id': domain.id, 'subdomain_id': None, 'subscan_id': None})
        for module, lookup in (('ptr', ptr or ptr_names), ('tls-san', certificate or functools.partial(tls_names, project=domain.project_id))):
            try:
                found[module] = [n for n in lookup(ip) if n and n != ip]
            except Exception:  # noqa: BLE001 - a dead port or a refused connection is the normal case
                found[module] = []
        events = [DiscoveryEvent(scan=scan, domain=domain, type='DNS_NAME', label=n[:500], host=ip, parent_host=ip, module=module)
                  for module, names in found.items() for n in names]
        events.insert(0, DiscoveryEvent(scan=scan, domain=domain, type='IP_ADDRESS', label=ip, host=ip, module='target'))
        DiscoveryEvent.objects.bulk_create(events)
    except Exception as exc:  # noqa: BLE001 - the scan ends in a visible state
        logger.exception('ip discovery failed for scan %s', scan.id)
        status, error = FAILED, str(exc)[:290]
    ScanActivity.objects.filter(scan_of=scan, name='bbot_discovery').update(
        status=status, time=timezone.now(), error_message=error or None, title='IP lookup (reverse DNS, certificate)')
    names = sorted({n for v in found.values() for n in v})
    activity.settle(running, 'done' if status == SUCCESS else 'failed', message=(
        f'{ip}: ' + (f'answers to {", ".join(names[:5])}{" and more" if len(names) > 5 else ""}' if names else 'no reverse DNS or certificate names'))
        if status == SUCCESS else f'Lookup of {ip} failed: {error}', names=len(names))
    return {'scan_id': scan.id, 'status': status, 'error': error, 'names': names}


def covering_scan(scan):
    """A scan of a parent (or an earlier Domain of the same name) in this project whose bbot run finished inside the bbot TTL
    and found hosts under this target, as (ScanHistory, Domain name), else None. Its hosts make a second bbot run pointless."""
    from datetime import timedelta
    from django.db.models import Q
    from cveFeed import ledger
    from cveFeed.models import ServiceRun
    from startScan.models import Subdomain
    domain = scan.domain
    name = domain.name.lower()
    labels = name.split('.')
    names = {'.'.join(labels[i:]) for i in range(len(labels) - 1)}  # the target itself and each parent; never a bare TLD
    cutoff = timezone.now() - timedelta(seconds=ledger.ttl('bbot'))
    runs = ServiceRun.objects.filter(service='bbot', project_id=domain.project_id, asset__in=names, status='done',
                                     finished_at__gte=cutoff, scan__isnull=False).exclude(scan__domain_id=domain.id) \
        .select_related('scan__domain').order_by('-finished_at')
    for run in runs:
        if Subdomain.objects.filter(scan_history=run.scan).filter(Q(name=name) | Q(name__endswith='.' + name)).exists():
            return run.scan, run.scan.domain.name
    return None


def seed_from_scan(scan, source):
    """Copy the hosts of ``source`` that belong to ``scan``'s target into ``scan``, with their IPs and technologies linked
    (not duplicated). Returns how many hosts were copied."""
    from django.db.models import Q
    from startScan.models import Subdomain
    name = scan.domain.name.lower()
    fields = ('name', 'http_url', 'screenshot_path', 'discovered_date', 'cname', 'is_cdn', 'cdn_name', 'http_status',
              'content_type', 'response_time', 'webserver', 'content_length', 'page_title')
    originals = list(Subdomain.objects.filter(scan_history=source).filter(Q(name=name) | Q(name__endswith='.' + name))
                     .prefetch_related('ip_addresses', 'technologies').order_by('id'))
    from cveFeed.exclusions import excluded_names
    banned = excluded_names(scan.domain.project_id)  # an excluded host is never copied back into the inventory
    originals = [o for o in originals if o.name.lower().rstrip('.') not in banned]
    copies = Subdomain.objects.bulk_create([
        Subdomain(scan_history=scan, target_domain=scan.domain, **{f: getattr(o, f) for f in fields}) for o in originals])
    ips, techs = Subdomain.ip_addresses.through, Subdomain.technologies.through
    ips.objects.bulk_create([ips(subdomain_id=c.pk, ipaddress_id=ip.pk) for c, o in zip(copies, originals)
                             for ip in o.ip_addresses.all()])
    techs.objects.bulk_create([techs(subdomain_id=c.pk, technology_id=t.pk) for c, o in zip(copies, originals)
                               for t in o.technologies.all()])
    return len(copies)


def reuse_discovery(scan, source, parent):
    """Stand in for bbot when ``source`` (a scan of ``parent``) already discovered this target: copy its hosts and settle
    the bbot activity as done. The pipeline carries on to nmap and nuclei, where the ledger dedupes them. Returns False
    (nothing copied) if the copy failed, so the caller runs bbot after all."""
    from cveFeed import activity
    from startScan.models import ScanActivity
    try:
        copied = seed_from_scan(scan, source)
    except Exception:  # noqa: BLE001
        logger.exception('could not reuse scan %s for scan %s', source.id, scan.id)
        return False
    ScanActivity.objects.filter(scan_of=scan, name='bbot_discovery').update(
        status=SUCCESS, time=timezone.now(), title=f'BBOT discovery (covered by scan #{source.id} of {parent})')
    activity.log('discovery', f'Discovery of {scan.domain.name} covered by scan #{source.id} of {parent}: {copied} host(s) reused, '
                 f'bbot not run', project=scan.domain.project_id, scan_id=scan.id, hosts=copied)
    return True


def stopped(scan_id):
    """Whether a person stopped this scan (its row says aborted, or the stop flag is up)."""
    from reNgine import resources
    from startScan.models import ScanHistory
    return resources.abort_requested(scan_id) or ScanHistory.objects.filter(pk=scan_id, scan_status=ABORTED).exists()


def _stage(scan, title, name, run, failed=lambda result: bool(result.get('error')), fallback=None):
    """Run one pipeline stage with its own ScanActivity row. A stage that raises or reports an error is marked failed and
    never takes the pipeline down; ``fallback`` is the result then (a ``dict`` with an ``error`` is built when omitted)."""
    from startScan.models import ScanActivity
    ScanActivity.objects.create(scan_of=scan, title=title, name=name, time=timezone.now(), status=RUNNING)
    try:
        result = run()
    except Exception as exc:  # noqa: BLE001 - every stage after discovery records its own trouble
        logger.exception('%s failed for scan %s', name, scan.id)
        result = {**(fallback or {}), 'error': str(exc)[:290]}
    error = result.get('error') or result.get('full_error')
    ScanActivity.objects.filter(scan_of=scan, name=name).update(
        status=FAILED if (failed(result) or error) else SUCCESS, time=timezone.now(), error_message=error)
    return result


def _run_pipeline(scan_id, mode=bbot_lib.DEFAULT_MODE, stream=bbot_lib.stream_events, light_stream=None, targeted_stream=None,
                  nmap_runner=None, db_exposure_checks=None, provider=False, cve_runner=None, ip_lookups=None, route_probe=None):
    """Discovery (bbot for a domain; a reverse lookup and the certificate for a bare IP), then nmap (fingerprint + full port
    sweep, by IP), then a read-only unauthenticated-database exposure check, then a light nuclei technology pass, then CVE
    correlation for this scan, then the AI-targeted nuclei pass. The scan stays "running" until the whole pipeline is
    done, so the dashboard never reports a half-finished scan as finished. Every stage after discovery records its own
    trouble but never undoes the discovery that already succeeded."""
    from startScan.models import ScanHistory
    mark_running(scan_id)
    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
    from cveFeed.exclusions import is_excluded
    if is_excluded(scan.domain.project_id, scan.domain.name):  # the organization excluded this host for good after the scan was queued
        message = f'{scan.domain.name} is excluded for this organization and is not scanned'
        ScanHistory.objects.filter(pk=scan_id).update(scan_status=FAILED, stop_scan_date=timezone.now(), error_message=message)
        return {'scan_id': scan_id, 'status': FAILED, 'error': message}
    from targetApp.target_types import IP, classify_target
    covered = None
    if classify_target(scan.domain.name) == IP:  # bbot finds subdomains; a bare IP has none
        found = discover_ip(scan, **(ip_lookups or {}))
        if found['status'] != SUCCESS:
            ScanHistory.objects.filter(pk=scan_id).update(scan_status=FAILED, stop_scan_date=timezone.now(), error_message=found['error'] or None)
            return found
    else:
        try:
            covered = covering_scan(scan)
        except Exception:  # noqa: BLE001 - a ledger problem means "run bbot"
            logger.exception('could not look for a covering discovery of scan %s', scan_id)
        if covered and reuse_discovery(scan, *covered):
            found = {'scan_id': scan.id, 'status': SUCCESS, 'error': '', 'covered_by': covered[0].id}
        else:
            found = run_discovery(scan_id, mode, stream=stream, finalize=False)
            if found['status'] != SUCCESS:
                return found
    return _run_stages(scan_id, found, light_stream=light_stream, targeted_stream=targeted_stream, nmap_runner=nmap_runner,
                       db_exposure_checks=db_exposure_checks, provider=provider, cve_runner=cve_runner, route_probe=route_probe)


def _run_stages(scan_id, found, light_stream=None, targeted_stream=None, nmap_runner=None, db_exposure_checks=None,
                provider=False, cve_runner=None, hygiene=True, route_probe=None, retest=False,
                force=False, hygiene_host=None, wpscan_runner=None, rdp_capturer=None, rdp_reader=None,
                node2shell_checker=None, waf_runner=None, probe_get=None, probe_nmap=None):
    """Everything after discovery: nmap, the exposure check, the light nuclei pass, the web route auth check, correlation, the targeted nuclei pass, AI triage of what the scan produced (which queues the read-only
    validation checks, one task per project) and (unless ``hygiene`` is off) the hygiene sweep of the target. Shared by a full discovery and by the new-hosts pipeline;
    the stop flag is honoured between stages."""
    from cveFeed import db_exposure, nuclei_scan, service_intel
    from startScan.models import ScanActivity, ScanHistory
    gone = {'scan_id': scan_id, 'status': 'aborted'}
    if stopped(scan_id):
        return gone
    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)

    nmap_kwargs = {'runner': nmap_runner} if nmap_runner else {}
    if force:
        nmap_kwargs['force'] = True
    nmap_result = _stage(scan, 'nmap scan', 'nmap_scan', lambda: service_intel.run_nmap_stage(scan_id, **nmap_kwargs),
                         fallback={'targets': 0})
    if stopped(scan_id):
        return gone
    from cveFeed import rdp_shot
    rdp_kwargs = {}
    if rdp_capturer:
        rdp_kwargs['capturer'] = rdp_capturer
    if rdp_reader:
        rdp_kwargs['reader'] = rdp_reader
    if retest or force:
        rdp_kwargs['force'] = True
    rdp_result = None
    if (rdp_capturer or rdp_shot.available()) and rdp_shot.rdp_candidates(scan):  # only hosts nmap already confirmed are RDP without NLA
        rdp_result = _stage(scan, 'RDP screenshot', 'rdp_screenshot', lambda: rdp_shot.run_for_scan(scan_id, **rdp_kwargs),
                            fallback={'attempted': 0})
        if stopped(scan_id):
            return gone
    db_result = _stage(scan, 'Database exposure check', 'db_exposure_scan',
                       lambda: db_exposure.run_db_exposure_checks(scan_id, checks=db_exposure_checks),
                       fallback={'checked': 0, 'exposed': 0})
    if stopped(scan_id):
        return gone
    light_kwargs = {'stream': light_stream} if light_stream else {}
    if force:
        light_kwargs['force'] = True
    light_result = _stage(scan, 'Nuclei HTTP and technology pass', 'nuclei_light_scan',
                          lambda: nuclei_scan.run_light_nuclei(scan_id, **light_kwargs), fallback={'targets': 0, 'techs': {}})

    if stopped(scan_id):
        return gone
    from cveFeed import waf_scan
    waf_kwargs = {'runner': waf_runner} if waf_runner else {}
    if retest or force:
        waf_kwargs['force'] = True
    waf_result = None
    if waf_scan.enabled() and (waf_runner or waf_scan.installed()) and waf_scan.web_sites(scan):  # the product behind a host's firewall
        waf_result = _stage(scan, 'WAF fingerprint (wafw00f)', 'wafw00f', lambda: waf_scan.run_for_scan(scan_id, **waf_kwargs),
                            fallback={'checked': 0})
        if stopped(scan_id):
            return gone
    from cveFeed import route_auth
    route_kwargs = {'probe': route_probe} if route_probe else {}
    if retest or force:
        route_kwargs['force'] = True  # the re-tested hosts' routes are asked again now, not after the 24 hour ledger window
    route_result = _stage(scan, 'Web route auth check', 'route_auth_scan', lambda: route_auth.run_route_auth(scan_id, **route_kwargs),
                          fallback={'routes': 0})
    if stopped(scan_id):
        return gone
    from cveFeed import probes, wpscan_scan
    probe_kwargs = {k: v for k, v in (('get', probe_get), ('nmap_runner', probe_nmap)) if v}
    if retest or force:
        probe_kwargs['force'] = True
    probe_result = _stage(scan, 'Version and identity probes', 'version_probes', lambda: probes.run_for_scan(scan_id, **probe_kwargs),
                          fallback={'hosts': 0})  # finds the version of what the stages above saw without one, before correlation reads it
    if stopped(scan_id):
        return gone
    from cveFeed import subdir_apps
    subdir_apps.carry_forward(scan)  # the versioned applications the background subdirectory sweep found, on this scan's fresh host rows
    wp_kwargs = {'runner': wpscan_runner} if wpscan_runner else {}
    if probe_get:
        wp_kwargs['probe_get'] = probe_get
    if retest or force:
        wp_kwargs['force'] = True
    wpscan_result = _stage(scan, 'WordPress detection and WPScan', 'wpscan', lambda: wpscan_scan.run_wpscan(scan_id, **wp_kwargs),
                           fallback={'sites': 0})  # every host with any sign of WordPress, and the names grouped with it
    if stopped(scan_id):
        return gone
    from cveFeed import node2shell_scan
    n2s_kwargs = {'checker': node2shell_checker} if node2shell_checker else {}
    if retest or force:
        n2s_kwargs['force'] = True
    node2shell_result = None
    if node2shell_scan.enabled() and node2shell_scan.node_sites(scan):  # only for hosts already fingerprinted as Node.js or Express
        node2shell_result = _stage(scan, 'node2shell check', 'node2shell', lambda: node2shell_scan.run_for_scan(scan_id, **n2s_kwargs),
                                   fallback={'checked': 0})
        if stopped(scan_id):
            return gone
    from cveFeed.tasks import correlate_cves, run_hygiene_task
    def correlate():
        result = correlate_cves(scan_history_id=scan.id)
        from cveFeed import testssl_scan
        testssl_scan.carry_forward(scan)  # the TLS vulnerabilities the background audit proved are evidence on this scan's host rows too
        return result
    correlation = _stage(scan, 'CVE correlation', 'cve_correlation', correlate,
                         fallback={'subdomains': 0, 'matches': 0})  # run inline: the AI-targeted pass needs the matches
    if stopped(scan_id):
        return gone
    from cveFeed import openvas_scan
    openvas_scan.carry_forward(scan)  # the optional OpenVAS add-on's findings are evidence on this scan's host rows too (a no-op while it is off)

    targeted_kwargs = {'stream': targeted_stream} if targeted_stream else {}
    if force:
        targeted_kwargs['force'] = True
    targeted_result = _stage(scan, 'AI-targeted nuclei scan', 'nuclei_targeted_scan',
                             lambda: nuclei_scan.run_targeted_nuclei(scan_id, provider=provider, light_techs=light_result.get('techs'),
                                                                     cve_runner=cve_runner, force_cve_checks=retest or force, **targeted_kwargs),
                             fallback={'targets': 0, 'findings': 0})

    if stopped(scan_id):
        return gone
    from cveFeed import triage
    triage_result = _stage(scan, 'AI triage and validation', 'triage', lambda: triage.run_for_scan(scan_id, provider=provider),
                           fallback={'rows': 0})  # after the targeted pass, so its findings exist; before the change log, which can cite the verdicts
    if stopped(scan_id):
        return gone
    from cveFeed import changes
    changes_result = _stage(scan, 'Asset changes', 'asset_changes', lambda: changes.record_scan_changes(scan_id),
                            fallback={'changes': 0})
    hygiene_result = None
    if hygiene_host and not stopped(scan_id):
        from cveFeed.hygiene import run_hygiene
        hygiene_result = _stage(scan, 'Host TLS hygiene', 'host_hygiene',
                                lambda: run_hygiene(scan.domain_id, hosts=[hygiene_host]), fallback={'tls_hosts': 0})
    if stopped(scan_id):
        return gone
    # Discovery itself succeeded, so the scan does and its hosts become the domain's current inventory (correlation.latest_scan_q
    # reads successful scans only). A later stage that failed is recorded on its stage row, in the scan's error and in
    # ``failed_stages`` (assessments and re-tests read that); failing the whole scan would hide every host it found and keep
    # correlating the previous scan's ports and technologies.
    failed_names = list(ScanActivity.objects.filter(scan_of=scan, status=FAILED).values_list('name', flat=True))
    scan.scan_status, scan.stop_scan_date = SUCCESS, timezone.now()
    scan.error_message = ('Failed stages: ' + ', '.join(failed_names))[:290] if failed_names else None
    scan.save(update_fields=['scan_status', 'stop_scan_date', 'error_message'])
    found['status'] = scan.scan_status
    found['error'] = scan.error_message or ''
    found['failed_stages'] = failed_names
    if hygiene and not hygiene_host:
        run_hygiene_task.delay(scan.domain_id)  # certificates and email authentication for what was just found
    result = {**found, 'nmap': nmap_result, 'db_exposure': db_result, 'nuclei_light': light_result, 'route_auth': route_result,
              'correlation': correlation, 'nuclei_targeted': targeted_result, 'triage': triage_result,
              'asset_changes': changes_result}
    if hygiene_result is not None:
        result['hygiene'] = hygiene_result
    if waf_result is not None:
        result['wafw00f'] = waf_result
    result['version_probes'] = probe_result
    result['wpscan'] = wpscan_result
    if node2shell_result is not None:
        result['node2shell'] = node2shell_result
    if rdp_result is not None:
        result['rdp_screenshot'] = rdp_result
    _announce(scan, result, summary=hygiene)
    return result


def _announce(scan, result, summary=True):
    """Notification channels: at most one message each for the scan's new fire-tier matches, its confirmed template-test hits
    and (for a full discovery) its one-line summary. Best effort, see cveFeed.notify."""
    from cveFeed import notify
    notify.fire_matches(scan.start_scan_date, scan)
    notify.template_hits((result.get('nuclei_targeted') or {}).get('vulnerable') or [], scan)
    if summary:
        notify.scan_finished(scan, result)


# --- new hosts found between scans -------------------------------------------------------------------------------

def resolve_names(names, timeout=IP_LOOKUP_TIMEOUT, workers=20):
    """{(name, ip)} for the names that resolve. getaddrinfo has no timeout of its own, so each lookup runs in a pool."""
    import concurrent.futures
    import socket
    pairs = set()
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    try:
        futures = {pool.submit(socket.getaddrinfo, name, None, 0, socket.SOCK_STREAM): name for name in names}
        for future, name in futures.items():
            try:
                pairs.update((name, info[4][0]) for info in future.result(timeout=timeout))
            except Exception:  # noqa: BLE001 - no record, a resolver error or a timeout: the name stays unresolved
                continue
    finally:
        pool.shutdown(wait=False)
    return pairs


def run_host_pipeline(domain_id, names, resolver=resolve_names, celery_id=None, retest=False, source_scan_id=None,
                      force=False, hygiene=False, assessment_id=None, **stage_kwargs):
    """Take a handful of new hosts of a target (certificate transparency found them between scans) through the same stages
    a discovery ends with: resolve and record them, then nmap, the database exposure check, the light nuclei pass, CVE
    correlation and the targeted nuclei pass. The ledger still dedupes each scanner per asset, so a host or IP covered
    recently is not scanned again. A ScanHistory carries the run (queued, then running) so it shows in Scans and can be
    stopped; the stop flag is honoured between stages. ``retest`` marks a run started because these hosts changed (see
    cveFeed.retest): its CVE checks ignore the ledger. Returns the stage results."""
    from cveFeed import activity
    from reNgine.tasks import persist_bbot_result
    from startScan.models import ScanActivity, ScanHistory
    from targetApp.models import Domain
    domain = Domain.objects.get(pk=domain_id)
    suffix = domain.name.lower()
    wanted = sorted({n.strip().lower().rstrip('.') for n in names if n and n.strip()})
    from cveFeed.exclusions import drop_excluded
    wanted = drop_excluded(domain.project_id, [n for n in wanted if n == suffix or n.endswith('.' + suffix)])[:MAX_PIPELINE_HOSTS]
    from cveFeed.archive_rediscovery import archived_names
    archived = archived_names(domain.project_id)
    wanted = [n for n in wanted if n not in archived]
    if not wanted:
        return {'status': 'empty', 'hosts': 0}
    engine = pick_engine()
    if engine is None:
        raise RuntimeError('no scan engine is configured')
    now = timezone.now()
    scan = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=now, scan_status=QUEUED,
                                      results_dir='/usr/src/scan_results',
                                      tasks=[HOST_PIPELINE_TASK, RETEST_TASK] if retest else [HOST_PIPELINE_TASK],
                                      celery_ids=[celery_id] if celery_id else [])
    if assessment_id:
        from cveFeed.models import HostAssessment
        HostAssessment.objects.filter(pk=assessment_id).update(scan=scan)
        if not HostAssessment.objects.filter(pk=assessment_id, status='running').exists():
            ScanHistory.objects.filter(pk=scan.pk).update(scan_status=ABORTED, stop_scan_date=timezone.now())
            return {'scan_id': scan.pk, 'status': 'aborted'}
    step = ScanActivity.objects.create(scan_of=scan, title='Resolve and record new hosts', name='host_resolve', time=now, status=QUEUED)
    mark_running(scan.id)
    ScanActivity.objects.filter(pk=step.pk).update(status=RUNNING, time=timezone.now())
    from reNgine import resources
    try:
        with resources.scan_context(scan.id):
            found = {'scan_id': scan.id, 'status': SUCCESS, 'error': '', 'hosts': len(wanted)}
            hosts_text = f'({", ".join(wanted[:3])}{", ..." if len(wanted) > 3 else ""})'
            activity.log('discovery', (f'Re-testing {len(wanted)} changed host{"s" if len(wanted) != 1 else ""} of {domain.name} {hosts_text}'
                                       + (f' after scan #{source_scan_id}' if source_scan_id else '')) if retest else
                         f'Scanning {len(wanted)} new host{"s" if len(wanted) != 1 else ""} of {domain.name} {hosts_text}',
                         project=domain.project_id, scan_id=scan.id)
            pairs = resolver(wanted)
            if force:
                from targetApp.target_types import is_scannable_ip
                pairs = {(name, address) for name, address in pairs if is_scannable_ip(address, project=domain.project_id if name == address else None)}
            persist_bbot_result(bbot_lib.BbotResult(subdomains=set(wanted), resolutions=pairs),
                                ctx={'scan_history_id': scan.id, 'domain_id': domain.id, 'subdomain_id': None, 'subscan_id': None})
            ScanActivity.objects.filter(pk=step.pk).update(status=SUCCESS, time=timezone.now())
            found['resolved'] = len({name for name, _ in pairs})
            if force and not pairs:
                message = 'No scannable IP address resolved; no active checks ran'
                ScanHistory.objects.filter(pk=scan.pk).update(scan_status=FAILED, stop_scan_date=timezone.now(), error_message=message)
                return {**found, 'status': 'inconclusive', 'error': message}
            return _run_stages(scan.id, found, hygiene=hygiene, hygiene_host=wanted[0] if assessment_id else None,
                               retest=retest, force=force, **stage_kwargs)
    except resources.ScanAborted:
        return {'scan_id': scan.id, 'status': 'aborted'}
    except Exception as exc:  # noqa: BLE001 - the scan must end in a visible state
        logger.exception('host pipeline failed for scan %s', scan.id)
        ScanActivity.objects.filter(pk=step.pk).update(status=FAILED, time=timezone.now(), error_message=str(exc)[:290])
        ScanHistory.objects.filter(pk=scan.id).update(scan_status=FAILED, stop_scan_date=timezone.now(), error_message=str(exc)[:290])
        return {'scan_id': scan.id, 'status': FAILED, 'error': str(exc)[:290]}
