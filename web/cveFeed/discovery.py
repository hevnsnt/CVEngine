"""Live discovery for a target: a Sentinel streams what it finds and each batch lands in the DB as it arrives.

Entering a domain starts this. A ScanHistory row is created (so the scan shows up
in Scans, scoped to the project like every other scan), the scan is driven from the celery
worker (the discovery itself runs on a Sentinel, never here), and every few seconds the batch it has seen is persisted as Subdomain,
IP and Port rows plus DiscoveryEvent rows, which the dashboard polls to draw the
discovery graph and the live feed while it happens.
"""
import logging
import os
from contextlib import contextmanager

from django.conf import settings
from django.utils import timezone

from cveFeed import scanner_wait
from reNgine import discovery_events as bbot_lib

logger = logging.getLogger(__name__)

MAX_EVENTS_PER_SCAN = 5000
DEFAULT_DISCOVERY_TIMEOUT = 6 * 3600


def discovery_timeout():
    """Seconds a discovery may run, from the App Admin timings (read at the start of each run)."""
    try:
        from dashboard.models import SystemTimings
        return SystemTimings.current().discovery_timeout_hours * 3600
    except Exception:  # noqa: BLE001 - never let a settings problem stop a scan
        return DEFAULT_DISCOVERY_TIMEOUT

QUEUED, RUNNING, FAILED, SUCCESS, ABORTED = -1, 1, 0, 2, 3

# The ScanActivity ``name`` values that mean "nuclei ran against this host's scan": the current light and AI-targeted
# passes (see ``run_light_nuclei``/``run_targeted_nuclei`` below), plus the retired single-stage name kept so an old
# scan's history still counts. Every "has this host been nuclei'd at all" query across the app (heat, the graph
# overview, the host list page, the live graph) reads this one tuple, so a stage rename never again drops silently out
# of only some of them - which is exactly how it drifted the first time (the light pass's own stage name was missing
# from every one of these for a release, undercounting "unscanned" hosts that had, in fact, had a light pass run).
NUCLEI_SCAN_ACTIVITY_NAMES = ('nuclei_scan', 'nuclei_light_scan', 'nuclei_targeted_scan')


RECOMMENDED_ENGINE = 'CVEngine Recommended'


def pick_engine():
    """The ScanHistory.scan_type row a new scan is filed under. It is only a label: every scan runs the fixed pipeline below, and nothing
    reads an engine's YAML (the editable engines were inherited from reNgine and never did anything). All the inherited engines are flagged
    default, so "the first default" used to file every scan under "Full Scan", one-second host retests included; the recommended one is
    taken by name and the order of the rest is fixed."""
    from scanEngine.models import EngineType
    return (EngineType.objects.filter(engine_name=RECOMMENDED_ENGINE).order_by('id').first()
            or EngineType.objects.filter(default_engine=True).order_by('id').first() or EngineType.objects.order_by('id').first())


HOST_PIPELINE_TASK = 'host_pipeline'  # marks a ScanHistory made by run_host_pipeline (in ScanHistory.tasks)
RETEST_TASK = 'retest'  # also on a host pipeline started because its hosts changed (cveFeed.retest)
MAX_PIPELINE_HOSTS = 200
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
    from startScan.models import ScanHistory
    return ScanHistory.objects.filter(_active_filter(), domain=domain).order_by('-id').first()


def start_discoveries(domains, mode=bbot_lib.DEFAULT_MODE, quiet=False, initiated_by=None):
    """Queue the streaming discovery task for each domain, in the order given, with rows created in bulk. Returns one ScanHistory
    per domain; a domain that is already being discovered returns that scan instead of a second, since two runs of one target
    only compete for memory. Scans are created queued (-1); the pipeline marks one running when a worker starts it.

    ``initiated_by`` records who asked for this scan (a person behind an API/MCP call); leave it unset for a scan the
    system itself started (the setup wizard, the work conductor, a scheduled sweep) - ``ScanHistory.initiated_by`` stays
    null, the same as it already does for every automatic scan."""
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
                ScanHistory(domain=d, scan_type=engine, start_scan_date=now, scan_status=QUEUED, results_dir='/usr/src/scan_results',
                           initiated_by=initiated_by, discovery_mode=mode)
                for d in part])
            ScanActivity.objects.bulk_create([
                ScanActivity(scan_of=scan, title='BBOT discovery', name='bbot_discovery', time=now, status=QUEUED) for scan in scans])
            created.update((scan.domain_id, scan) for scan in scans)
    if not quiet:  # a bulk add logs one summary line instead
        from cveFeed import activity
        for d in domains:
            if d.id in created:
                activity.log('discovery', f'Queued discovery of {d.name}', project=d.project_id, scan_id=created[d.id].id)
            elif d.id in active:
                activity.log('discovery', f'{d.name} is already being discovered (scan #{active[d.id].id}); not starting another',
                             project=d.project_id, scan_id=active[d.id].id)
    for scan in sorted(created.values(), key=lambda s: s.id):  # first in, first out
        run_bbot_discovery.delay(scan.id, mode)
    return [created.get(d.id) or active[d.id] for d in domains]


def start_discovery(domain, mode=bbot_lib.DEFAULT_MODE, quiet=False, initiated_by=None):
    """Queue discovery of one domain (see ``start_discoveries``). Returns the ScanHistory."""
    return start_discoveries([domain], mode, quiet, initiated_by=initiated_by)[0]


def start_in_stored_modes(domains, quiet=False, initiated_by=None):
    """Queue discovery of each domain in the mode stored on it (``Domain.discovery_mode``): the way every start that nobody asked for
    one by one goes (the work conductor, a Tailscale sweep, a move), so a target added as passive is never
    rescanned in standard. A manual only target ("just add it, do not scan yet") is left out. Returns the scans of the rest; targets
    of one mode are queued together, each group in the order given."""
    from targetApp.models import Domain
    groups = {}
    for d in domains:
        if d.discovery_mode != Domain.DISCOVERY_MANUAL:
            groups.setdefault(d.discovery_mode, []).append(d)
    scans = []
    for mode, group in groups.items():
        scans += start_discoveries(group, mode=mode, quiet=quiet, initiated_by=initiated_by)
    return scans


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


def _flush(scan, ctx, batch, observed, stored=0):
    """Persist what the stream has produced since the last flush. ``stored`` is how many events the scan already has
    (the caller keeps the running count, so a flush never needs a COUNT(*)); returns the new total."""
    from cveFeed.models import DiscoveryEvent
    from reNgine.tasks import persist_bbot_result
    persist_bbot_result(batch, ctx=ctx)
    room = MAX_EVENTS_PER_SCAN - stored
    if room > 0 and observed:
        DiscoveryEvent.objects.bulk_create([
            DiscoveryEvent(scan=scan, domain_id=scan.domain_id, type=o.type, label=o.label[:500], host=o.host[:500],
                           parent_host=o.parent_host[:500], module=o.module[:64])
            for o in observed[:room]])
        stored += min(room, len(observed))
    return stored


def _report_key_problems(problems, extra_args, scan):
    """One activity line per service whose key the scanner rejected (or never received). The scanner skips such a module and carries on, so without
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


MIN_HOSTS_FOR_WEB_CHECK = 5  # a target with a handful of hosts may honestly have no web page; many hosts and not one is a sign the scanner's web module did not work


def _report_no_web_pages(scan, mode, web_events):
    """One activity line when a standard or deep discovery found many hosts and the scanner reported no web page at all (no URL and no HTTP_RESPONSE event).
    Its web module (``http``) is what turns a host into a URL, so without it a discovery records no endpoint, no HTTP status and no page title, and
    there is nothing to photograph; that was seen on a live instance (a 43 host discovery with 0 endpoints) and the cause was not in the logs
    cvENGINE keeps. The line says what to look at."""
    if mode not in ('standard', 'deep') or any(web_events.values()):
        return
    from cveFeed import activity
    from startScan.models import Subdomain
    hosts = Subdomain.objects.filter(scan_history=scan).count()
    if hosts < MIN_HOSTS_FOR_WEB_CHECK:
        return
    activity.log('discovery', f'{mode.capitalize()} discovery of {scan.domain.name} found {hosts} hosts but the scanner reported no web page for any of them '
                 f'(no URL and no HTTP_RESPONSE event), so no endpoint, HTTP status or title was recorded from it. Its web module may have failed '
                 f'to start or reach the hosts: look in the scan log on the Sentinel that ran it (docs/PIPELINE.md, "When discovery finds no web pages"). '
                 'Web screenshots and the route checks make their own requests and are not affected.',
                 project=scan.domain.project_id, status='failed', scan_id=scan.id, hosts=hosts)


def _report_module_failures(hard_failures, scan):
    """One activity line per module the scanner could not set up (a front-page screenshot module without a working browser is the usual one). With
    --force the scanner carries on without it, so without this line a discovery that lacks what the module finds looks like one that found nothing."""
    from cveFeed import activity
    seen = set()
    for module, reason in hard_failures:
        if module in seen:
            continue
        seen.add(module)
        reason = ((reason or '').strip().splitlines() or ['no reason given'])[0][:160] or 'no reason given'
        activity.log('discovery', f'A discovery module failed to set up: {module} ({reason}); what it covers is missing from this run '
                     '(the browser screenshot stage is separate and not affected)', project=scan.domain.project_id, status='failed', scan_id=scan.id)


def persist_screenshot_blobs(scan, screenshots):
    """Write each screenshot a Sentinel sent with a discovery batch (``sentinel_stream.clean_partial`` already checked its host, name, type and
    size) into this scan's scan-results storage and record it on the matching Subdomain.
    A screenshot whose host has no Subdomain in this scan, or whose bytes cannot be written, is skipped quietly."""
    if not screenshots:
        return
    import base64
    from cveFeed import shots
    from startScan.models import Subdomain
    dest_dir = os.path.join(settings.MEDIA_ROOT, f'{scan.domain.name}_{scan.id}', 'screenshots')
    hashed = 0
    shots.warn_unavailable(scan)
    for shot in screenshots:
        subdomain = Subdomain.objects.filter(scan_history=scan, name=shot.get('host') or '').first()
        name = os.path.basename(str(shot.get('filename') or ''))
        if not subdomain or not name or name.startswith('.'):
            continue
        try:
            raw = base64.b64decode(shot.get('data') or '', validate=True)
            os.makedirs(dest_dir, exist_ok=True)
            dest = os.path.join(dest_dir, f'sentinel-{name}')
            with open(dest + '.part', 'wb') as out:
                out.write(raw)
            os.replace(dest + '.part', dest)
        except (OSError, ValueError):
            logger.exception('could not store a Sentinel screenshot of %s for scan %s', subdomain.name, scan.id)
            continue
        subdomain.screenshot_path = os.path.relpath(dest, settings.MEDIA_ROOT)
        if hashed < shots.MAX_HASH_PER_FLUSH:
            subdomain.screenshot_hash = shots.dhash_file(dest)
            hashed += 1
        subdomain.save(update_fields=['screenshot_path', 'screenshot_hash'])


def batch_result(batch):
    """A Sentinel's batch (``sentinel_stream.clean_partial``) as the ``BbotResult`` and the live feed lines."""
    result = bbot_lib.BbotResult(
        subdomains=set(batch.get('subdomains') or ()), ips=set(batch.get('ips') or ()),
        ports={(p['host'], p['port']) for p in batch.get('ports') or ()}, urls={(u['url'], u['status']) for u in batch.get('urls') or ()},
        technologies={(t['host'], t['technology']) for t in batch.get('technologies') or ()},
        resolutions={(r['name'], r['ip']) for r in batch.get('resolutions') or ()},
        edges={(e['parent'], e['child']) for e in batch.get('edges') or ()},
        findings=[dict(f) for f in batch.get('findings') or ()], http=[dict(h) for h in batch.get('http') or ()])
    observed = [bbot_lib.Observed(type=e['type'], label=e['label'], host=e['host'], parent_host=e['parent_host'], module=e['module'])
                for e in batch.get('events') or ()]
    return result, observed


def _discover_on_sentinel(scan, mode, ctx, extra_args, stored, shown):
    """Run the discovery on a Sentinel that declares ``bbot_discovery`` (contract version 3), persisting each batch it posts as it arrives.
    The kind has no local path (``sentinel_dispatch.NEVER_LOCAL``): with no Sentinel able to take it, ``ScannerUnavailable`` is raised and the
    target stays due. Returns ``{stored, mode, scan_name, web_events, problems, hard_failures, incomplete}``; ``incomplete`` says why a run stopped
    part way after it found something (empty for a whole run).

    A project's API keys for the scanner's modules are never in the task: such a task names them by reference and only the built-in scanner is
    offered it (it reads them once through the secure read)."""
    from agentapi import sentinel_stream
    domain = scan.domain
    api_keys = bool(extra_args and any(a != bbot_lib.TRUFFLEHOG_FLAG for a in extra_args))
    trufflehog = bbot_lib.TRUFFLEHOG_FLAG in extra_args
    target = sentinel_stream.bbot_target(domain, mode, discovery_timeout(), api_keys=api_keys, trufflehog=trufflehog)
    state = {'stored': stored}

    def on_partial(batch):
        result, observed = batch_result(batch)
        fresh = [o for o in observed if (o.type, o.label) not in shown]
        shown.update((o.type, o.label) for o in fresh)
        state['stored'] = _flush(scan, ctx, result, fresh, state['stored'])
        persist_screenshot_blobs(scan, batch.get('screenshots'))

    out = sentinel_stream.dispatch_stream(domain.project, sentinel_stream.KIND, target, scan, on_partial, label=domain.name,
                                          secret_ref=sentinel_stream.keys_ref(domain.project_id) if api_keys and domain.project_id else None,
                                          builtin_only=api_keys)
    if out is None:  # unreachable while the kind is in NEVER_LOCAL (dispatch_stream raises); never let a missing answer read as a finished run
        from reNgine.resources import ScannerUnavailable
        raise ScannerUnavailable(sentinel_stream.KIND)
    final = out['result'] or {}
    return {'stored': state['stored'], 'mode': final.get('mode') or mode, 'scan_name': final.get('scan_name') or '',
            'web_events': final.get('web_events') or {'URL': 0, 'HTTP_RESPONSE': 0},
            'problems': [(p['module'], p['reason']) for p in final.get('problems') or ()],
            'hard_failures': [(p['module'], p['reason']) for p in final.get('hard_failures') or ()],
            'incomplete': final.get('incomplete') or ('' if out['result'] is not None else out.get('error') or 'the Sentinel did not finish the run')}


def run_discovery(scan_id, mode=bbot_lib.DEFAULT_MODE, finalize=True):
    """Body of the celery task: the discovery runs on a Sentinel (``bbot_discovery``) and never on this server. With no Sentinel able to take it the
    scan ends as waiting for a scanner and the target stays due."""
    from cveFeed.api_credentials import bbot_config_args
    from startScan.models import ScanActivity, ScanHistory
    scan = ScanHistory.objects.select_related('domain__project').get(pk=scan_id)
    mark_running(scan_id)
    ctx = {'scan_history_id': scan.id, 'domain_id': scan.domain_id, 'subscan_id': None}
    extra_args = bbot_config_args(scan.domain.project) if scan.domain.project_id else []
    if bbot_lib.trufflehog_allowed(scan.domain.project_id):  # opt-in (CVENGINE_BBOT_TRUFFLEHOG=1), never for a bug bounty project
        extra_args = [*extra_args, bbot_lib.TRUFFLEHOG_FLAG]
    shown = set()  # the scanner reports the same name from several modules; show each thing once
    status, error, partial = SUCCESS, '', ''
    from cveFeed import activity
    from cveFeed.models import DiscoveryEvent
    from reNgine.resources import ScanAborted, ScannerUnavailable
    stored = DiscoveryEvent.objects.filter(scan=scan).count()  # once; _flush is then told the running total
    running = activity.log('discovery', f'Discovering {scan.domain.name}', project=scan.domain.project_id,
                           status='running', scan_id=scan.id)
    finished_mode = mode
    problems = []  # (module, reason) for modules the scanner skipped at start-up, e.g. because a key was rejected
    web_events = {'URL': 0, 'HTTP_RESPONSE': 0}  # what the scanner's web module reported, counted over the whole run
    hard_failures = []  # (module, reason) for modules whose set-up hard-failed, e.g. a screenshot module without a working browser
    try:
        # Same policy the nuclei, route-auth and validation stages apply: never start a scanner against a name
        # that currently resolves to a loopback, link-local, metadata or (unless allowed) internal address.
        from targetApp.target_types import resolves_to_blocked, sentinel_only_target
        if sentinel_only_target(scan.domain.name, scan.domain.project_id):
            raise ValueError(f'{scan.domain.name} is inside an internal range of this project: only a Sentinel inside that network scans it, '
                             'never this server')
        if resolves_to_blocked(scan.domain.name, project=scan.domain.project_id):
            raise ValueError(f'{scan.domain.name} resolves to a loopback, link-local or internal address; '
                             'discovery refused (CVENGINE_ALLOW_PRIVATE_TARGETS=1 allows internal ranges)')
        remote = _discover_on_sentinel(scan, mode, ctx, extra_args, stored, shown)
        stored, finished_mode, web_events = remote['stored'], remote['mode'], remote['web_events']
        problems[:], hard_failures[:], partial = remote['problems'], remote['hard_failures'], remote['incomplete'][:290]
        _report_key_problems(problems, extra_args, scan)
        _report_no_web_pages(scan, finished_mode, web_events)
        _report_module_failures(hard_failures, scan)
    except ScanAborted:  # stopped by a person: the stop already marked the scan and its activities aborted
        activity.settle(running, 'failed', message=f'Discovery of {scan.domain.name} was stopped')
        return {'scan_id': scan.id, 'status': ABORTED, 'error': 'stopped'}
    except ScannerUnavailable as exc:  # no Sentinel could take it and it may not run here: nothing ran, the target stays due
        status, error = FAILED, f'waiting for a scanner: {exc}'[:290]
        logger.warning('discovery of scan %s is waiting for a scanner: %s', scan_id, exc)
    except Exception as exc:  # the scan must end in a visible state, never stay "running"
        logger.exception('discovery failed for scan %s', scan_id)
        status, error = FAILED, str(exc)[:290]
    ScanActivity.objects.filter(scan_of=scan, name='bbot_discovery').update(
        status=FAILED if partial else status, time=timezone.now(), error_message=(partial or error) or None)
    if finalize or status == FAILED:
        scan.scan_status, scan.stop_scan_date, scan.error_message = status, timezone.now(), error or None
        scan.save(update_fields=['scan_status', 'stop_scan_date', 'error_message'])
    from startScan.models import Subdomain
    found = Subdomain.objects.filter(scan_history=scan).count()
    activity.settle(running, 'done' if status == SUCCESS else 'failed', message=(
        f'Discovery of {scan.domain.name} finished: {found} host{"s" if found != 1 else ""} found'
        + (f', but incomplete ({partial})' if partial else '')
        if status == SUCCESS else f'Discovery of {scan.domain.name} failed: {error}'), hosts=found)
    if status == SUCCESS and not partial:
        from cveFeed import ledger
        ledger.record('bbot', [scan.domain.name], scan.domain.project_id, scan)
        if finished_mode == 'deep':  # the weekly deep sweep (tasks.deep_scan_apexes) counts only runs that really were deep
            ledger.record('bbot-deep', [scan.domain.name], scan.domain.project_id, scan)
    if status == SUCCESS and finalize:
        from cveFeed.tasks import correlate_cves
        correlate_cves.delay(scan_history_id=scan.id)
    return {'scan_id': scan.id, 'status': status, 'error': error, **({'partial': partial} if partial else {})}


LOCK_TTL = 180  # seconds; refreshed while the pipeline runs, so a crashed worker frees its target within minutes


def stage_runs_adapter(name):
    from agentapi import stage_runs
    return stage_runs.adapter(name, queue='discovery_queue')


def _once(name, fn):
    """A step between the stages that must not be repeated when a StageRun continues the pipeline (``agentapi.stage_runs.once``); its result is not kept."""
    from agentapi import stage_runs
    return stage_runs.once(name, lambda: (fn(), None)[1])


def _lock_key(domain_id):
    return f'cvengine:discovery:domain:{domain_id}'


@contextmanager
def domain_lock(domain_id, scan_id, keep=None, resumed=False):
    """One pipeline per target at a time. Yields True when this scan holds the lock (or no Redis is available to ask), else
    the id of the scan that does. A task the queue delivers twice, or the same domain queued twice, then cannot run in
    parallel and compete for memory. A pipeline whose stages wait on Sentinels without a worker (``agentapi.stage_runs``) keeps the lock
    while it waits (``keep``), and the pass that continues it takes it back (``resumed``)."""
    from reNgine import resources
    with resources.redis_claim(_lock_key(domain_id), scan_id, LOCK_TTL, adopt=resumed, hold=resumed, keep=keep) as holder:
        yield holder


def _scan_hosts(result, args, kwargs):
    return None  # every host the scan recorded


def _named_hosts(result, args, kwargs):
    return kwargs.get('names') if 'names' in kwargs else (args[1] if len(args) > 1 else None)


@scanner_wait.requeues(_scan_hosts)
def run_pipeline(scan_id, *args, **kwargs):
    """Run the pipeline for one scan unless this target is already being worked on (see ``domain_lock``)."""
    from cveFeed import activity
    from startScan.models import ScanActivity, ScanHistory
    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
    if scan.scan_status == 3:  # aborted while it waited in the queue
        return {'scan_id': scan_id, 'status': 'aborted'}
    if scan.scan_status in (FAILED, SUCCESS):  # a second message for a scan that already ended (the reaper may send one again) runs nothing
        return {'scan_id': scan_id, 'status': 'finished'}
    from targetApp.target_types import sentinel_only_target
    if sentinel_only_target(scan.domain.name, scan.domain.project_id):  # nothing at all runs from this server against a Sentinel-only address
        message = (f'{scan.domain.name} is inside an internal range of this project: only a Sentinel inside that network scans it, '
                   'never this server')
        ScanHistory.objects.filter(pk=scan_id).update(scan_status=FAILED, stop_scan_date=timezone.now(), error_message=message[:290])
        ScanActivity.objects.filter(scan_of=scan, name='bbot_discovery').update(status=FAILED, time=timezone.now(), error_message=message[:290])
        activity.log('discovery', f'Refused discovery of {scan.domain.name}: Sentinel-only target', project=scan.domain.project_id, scan_id=scan_id)
        return {'scan_id': scan_id, 'status': FAILED, 'error': message}
    keep = {}
    with domain_lock(scan.domain_id, scan_id, keep=keep) as holder:
        if holder is True:
            from reNgine import resources
            from agentapi import stage_runs
            with resources.scan_context(scan_id):  # a stop of this scan reaches the heavy jobs it starts
                out = _run_pipeline(scan_id, *args, **kwargs)
            if stage_runs.is_waiting(out):  # its stages wait on Sentinels without this worker: the target stays locked for them
                keep['seconds'] = stage_runs.HOLD_SECONDS
                stage_runs.add_claim(out['stage_run'], _lock_key(scan.domain_id), str(scan_id))
            return out
    if str(holder) == str(scan_id):
        return {'scan_id': scan_id, 'status': 'duplicate'}  # the queue delivered this very task twice; the first one is running
    message = f'another discovery of {scan.domain.name} is already running (scan #{holder})'
    ScanHistory.objects.filter(pk=scan_id).update(scan_status=3, stop_scan_date=timezone.now(), error_message=message[:290])
    ScanActivity.objects.filter(scan_of=scan, name='bbot_discovery').update(status=3, time=timezone.now(), error_message=message[:290])
    activity.log('discovery', f'Skipped a second discovery of {scan.domain.name}: scan #{holder} is already running',
                 project=scan.domain.project_id, scan_id=scan_id)
    return {'scan_id': scan_id, 'status': 'skipped', 'error': message}


IP_LOOKUP_TIMEOUT = 3  # seconds for the PTR lookup and for the certificate connection


def identity_names(scan, ip):
    """``{'ptr': [names], 'tls-san': [names]}`` of an IP target: its reverse-DNS name and the names on the certificate it serves on 443, both read by
    a Sentinel (``identity_check``; this server asks nothing of the address). The kind has no local path: ``ScannerUnavailable`` when no Sentinel can
    take it. A read the Sentinel could not answer gives no names for that source, as a dead port always did."""
    from agentapi import probe_dispatch
    dns, certs = probe_dispatch.try_identity(scan.domain.project, scan, dns=[{'id': 'ptr', 'name': ip, 'type': 'PTR'}],
                                             certs=[{'id': 'tls', 'host': ip, 'port': 443}])
    ptr, tls = dns.get('ptr') or {}, certs.get('tls') or {}
    ptr_found = [r.lower().rstrip('.') for r in ptr.get('records') or []] if ptr.get('status') == 'ok' else []
    named = ([n for n in tls.get('names') or []] if tls.get('status') == 'ok' else [])
    return {'ptr': ptr_found, 'tls-san': list(dict.fromkeys(n.lower().lstrip('*.').rstrip('.') for n in named if n and '.' in n))}


def discover_ip(scan, ptr=None, certificate=None):
    """Stand in for the discovery on an IP target. The discovery finds subdomains, and an IP has none: all it could do here is a
    reverse lookup and read the certificate, which a Sentinel does (``identity_names``). Creates the host for the IP, records the names
    it answers to (PTR and certificate) as DNS events on it, and leaves them out of the targets: they may be out of scope.
    ``ptr`` and ``certificate`` (``ip -> [names]``) are injectable so tests need no network. Returns the discovery result."""
    from cveFeed import activity
    from cveFeed.models import DiscoveryEvent
    from reNgine.resources import ScannerUnavailable
    from reNgine.tasks import persist_bbot_result
    from startScan.models import ScanActivity
    domain, ip = scan.domain, scan.domain.name
    running = activity.log('discovery', f'Looking up {ip}: reverse DNS and certificate names (no subdomain discovery for a bare IP)',
                           project=domain.project_id, status='running', scan_id=scan.id)
    status, error, found = SUCCESS, '', {}
    try:
        persist_bbot_result(bbot_lib.BbotResult(subdomains={ip}, resolutions={(ip, ip)}),
                            ctx={'scan_history_id': scan.id, 'domain_id': domain.id, 'subdomain_id': None, 'subscan_id': None})
        if ptr is None and certificate is None:
            found = {module: [n for n in names if n and n != ip] for module, names in identity_names(scan, ip).items()}
        else:  # injected lookups (tests)
            for module, lookup in (('ptr', ptr), ('tls-san', certificate)):
                try:
                    found[module] = [n for n in (lookup(ip) if lookup else []) if n and n != ip]
                except Exception:  # noqa: BLE001 - a dead port or a refused connection is the normal case
                    found[module] = []
        events = [DiscoveryEvent(scan=scan, domain=domain, type='DNS_NAME', label=n[:500], host=ip, parent_host=ip, module=module)
                  for module, names in found.items() for n in names]
        events.insert(0, DiscoveryEvent(scan=scan, domain=domain, type='IP_ADDRESS', label=ip, host=ip, module='target'))
        DiscoveryEvent.objects.bulk_create(events)
    except ScannerUnavailable as exc:  # no Sentinel can take the lookup and it may not run here: nothing was read, the target stays due
        status, error = FAILED, f'waiting for a scanner: {exc}'[:290]
        logger.warning('the IP lookup of scan %s is waiting for a scanner: %s', scan.id, exc)
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
    """A scan of a parent (or an earlier Domain of the same name) in this project whose discovery finished inside the discovery TTL
    and found hosts under this target, as (ScanHistory, Domain name), else None. Its hosts make a second discovery pointless."""
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
    under = Q(name=name) if domain.exact_host_only() else Q(name=name) | Q(name__endswith='.' + name)  # exactly one host: only its own row counts
    for run in runs:
        if Subdomain.objects.filter(scan_history=run.scan).filter(under).exists():
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
    under = Q(name=name) if scan.domain.exact_host_only() else Q(name=name) | Q(name__endswith='.' + name)  # =example.com: nothing under it is copied
    originals = list(Subdomain.objects.filter(scan_history=source).filter(under)
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
    """Stand in for the discovery when ``source`` (a scan of ``parent``) already discovered this target: copy its hosts and settle
    the discovery activity as done. The pipeline carries on to nmap and nuclei, where the ledger dedupes them. Returns False
    (nothing copied) if the copy failed, so the caller runs the discovery after all."""
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
                 f'discovery not run', project=scan.domain.project_id, scan_id=scan.id, hosts=copied)
    return True


def stopped(scan_id):
    """Whether a person stopped this scan (its row says aborted, or the stop flag is up)."""
    from reNgine import resources
    from startScan.models import ScanHistory
    return resources.abort_requested(scan_id) or ScanHistory.objects.filter(pk=scan_id, scan_status=ABORTED).exists()


def _stage(scan, title, name, run, failed=lambda result: bool(result.get('error')), fallback=None):
    """Run one pipeline stage with its own ScanActivity row. A stage that raises or reports an error is marked failed and
    never takes the pipeline down; ``fallback`` is the result then (a ``dict`` with an ``error`` is built when omitted).

    Inside a StageRun (``agentapi.stage_runs``: the pipeline gave its worker back while a stage waits on Sentinels) the pipeline is run again by
    the pass that continues it: a stage that already finished returns the result it had, and the stage that was waiting goes on with the row it
    already has."""
    from agentapi import stage_runs
    from startScan.models import ScanActivity
    current = stage_runs.current()
    memo = f'stage:{name}'
    if current is not None and memo in current.memo:
        return current.memo[memo]
    stage_runs.stage(name)
    if current is None or not ScanActivity.objects.filter(scan_of=scan, name=name, status=RUNNING).exists():
        ScanActivity.objects.create(scan_of=scan, title=title, name=name, time=timezone.now(), status=RUNNING)
    try:
        result = run()
    except Exception as exc:  # noqa: BLE001 - every stage after discovery records its own trouble
        logger.exception('%s failed for scan %s', name, scan.id)
        result = {**(fallback or {}), 'error': str(exc)[:290]}
    error = result.get('error') or result.get('full_error')
    ScanActivity.objects.filter(scan_of=scan, name=name).update(
        status=FAILED if (failed(result) or error) else SUCCESS, time=timezone.now(), error_message=error)
    if current is not None:
        current.memo[memo] = stage_runs._jsonable(result)
    return result


def _waiting_for_scanner(scan, what, exc, result):
    """A stage no scanner could take, and whose kind may not run on this server (``CVENGINE_LOCAL_FALLBACK``): nothing ran, nothing is recorded in
    the ledger (the targets stay due) and the stage is not a failure. ``result`` (no ``error``) is what the stage reports, plus why it did not run."""
    from cveFeed import activity
    message = f'no scanner could take this work ({exc.kind}); the targets stay due until one can'
    logger.warning('%s of scan %s is waiting for a scanner: %s', what, scan.id, exc)
    activity.log('run_check', f'{what} for {scan.domain.name} is waiting: {message}', project=scan.domain.project_id, scan_id=scan.id)
    return {**result, 'skipped': message}


def _run_pipeline(scan_id, mode=bbot_lib.DEFAULT_MODE, light_stream=None, targeted_stream=None,
                  nmap_runner=None, db_exposure_checks=None, provider=False, cve_runner=None, ip_lookups=None, route_probe=None):
    """Discovery (a scanner's subdomain run for a domain; a reverse lookup and the certificate for a bare IP), then nmap (fingerprint + full port
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
    from targetApp.models import Domain
    if scan.initiated_by_id is None and scan.domain.discovery_mode == Domain.DISCOVERY_MANUAL:  # set to manual only after the system queued it: no person asked for this one
        message = f'{scan.domain.name} is set to manual only and is not scanned on its own; choose a discovery mode to scan it'
        ScanHistory.objects.filter(pk=scan_id).update(scan_status=FAILED, stop_scan_date=timezone.now(), error_message=message[:290])
        return {'scan_id': scan_id, 'status': FAILED, 'error': message}
    from cveFeed.bounty_gate import Gate
    why = Gate().refusal(scan.domain.project_id, scan.domain.name, unattended=scan.initiated_by_id is None)  # a bug bounty program: confirmed automated testing (unless a person started this) and a target its scope names
    if why:
        message = f'{scan.domain.name} is not scanned: {why}'
        ScanHistory.objects.filter(pk=scan_id).update(scan_status=FAILED, stop_scan_date=timezone.now(), error_message=message[:290])
        return {'scan_id': scan_id, 'status': FAILED, 'error': message}
    from targetApp.target_types import IP, classify_target
    covered = None
    if classify_target(scan.domain.name) == IP:  # the discovery finds subdomains; a bare IP has none
        found = discover_ip(scan, **(ip_lookups or {}))
        if found['status'] != SUCCESS:
            ScanHistory.objects.filter(pk=scan_id).update(scan_status=FAILED, stop_scan_date=timezone.now(), error_message=found['error'] or None)
            return found
    else:
        try:
            covered = covering_scan(scan)
        except Exception:  # noqa: BLE001 - a ledger problem means "run the discovery"
            logger.exception('could not look for a covering discovery of scan %s', scan_id)
        if covered and reuse_discovery(scan, *covered):
            found = {'scan_id': scan.id, 'status': SUCCESS, 'error': '', 'covered_by': covered[0].id}
        else:
            found = run_discovery(scan_id, mode, finalize=False)
            if found['status'] != SUCCESS:
                return found
    stage_kwargs = dict(light_stream=light_stream, targeted_stream=targeted_stream, nmap_runner=nmap_runner, db_exposure_checks=db_exposure_checks,
                        provider=provider, cve_runner=cve_runner, route_probe=route_probe)
    from agentapi import stage_runs
    # the stages wait on Sentinels without this worker when they can (agentapi.stage_runs): the callback continues them (``_resume_pipeline``)
    return stage_runs.run('pipeline', {'scan_id': scan_id, 'found': found, 'kwargs': stage_kwargs, 'domain_id': scan.domain_id},
                          first=lambda: _run_stages(scan_id, found, **stage_kwargs), project=scan.domain.project_id, scan=scan_id)


@stage_runs_adapter('pipeline')
def _resume_pipeline(context):
    """The completion callback of a discovery's stages: take the target's lock back and run the stages again from where they stopped."""
    from reNgine import resources
    scan_id = context['scan_id']
    with domain_lock(context['domain_id'], scan_id, resumed=True) as holder:
        if holder is not True:
            logger.warning('scan %s continues its stages without the lock of its target (held by %s)', scan_id, holder)
        with resources.scan_context(scan_id):
            try:
                return _run_stages(scan_id, context['found'], **context.get('kwargs') or {})
            except Exception as exc:  # noqa: BLE001 - the scan must end in a visible state, as the worker that started it would have
                from startScan.models import ScanHistory
                logger.exception('the stages of scan %s failed in their callback', scan_id)
                ScanHistory.objects.filter(pk=scan_id, scan_status=RUNNING).update(scan_status=FAILED, stop_scan_date=timezone.now(),
                                                                                    error_message=str(exc)[:290])
                return {'scan_id': scan_id, 'status': FAILED, 'error': str(exc)[:290]}


def _run_stages(scan_id, found, light_stream=None, targeted_stream=None, nmap_runner=None, db_exposure_checks=None,
                provider=False, cve_runner=None, hygiene=True, route_probe=None, retest=False,
                force=False, hygiene_host=None, wpscan_runner=None, rdp_reader=None,
                node2shell_checker=None, waf_runner=None, probe_get=None, probe_nmap=None, by_person=False, screenshot_queuer=None):
    """Everything after discovery: nmap, the exposure check, the light nuclei pass, the web route auth check, correlation, the targeted nuclei pass, AI triage of what the scan produced (which queues the read-only
    validation checks, one task per project) and (unless ``hygiene`` is off) the hygiene sweep of the target. Shared by a full discovery and by the new-hosts pipeline;
    the stop flag is honoured between stages."""
    from cveFeed import db_exposure, nuclei_scan, service_intel
    from reNgine import resources
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
    if rdp_reader:
        rdp_kwargs['reader'] = rdp_reader
    if retest or force:
        rdp_kwargs['force'] = True
    rdp_result = None
    if rdp_shot.rdp_candidates(scan):  # only hosts nmap already confirmed are RDP without NLA
        rdp_result = _stage(scan, 'RDP screenshot', 'rdp_screenshot', lambda: rdp_shot.run_for_scan(scan_id, **rdp_kwargs),
                            fallback={'attempted': 0})
        if stopped(scan_id):
            return gone
    from cveFeed import web_shot
    shot_result = None
    if (screenshot_queuer or web_shot.has_work_for_scan(scan)):  # a web page to photograph: queued here, taken by the screenshot worker (its own queue and memory gate)
        shot_result = _stage(scan, 'Web screenshots', 'web_screenshot',
                             lambda: (screenshot_queuer or web_shot.queue_for_scan)(scan_id, by_person=by_person or scan.initiated_by_id is not None, force=retest or force),
                             fallback={'queued': 0})
        if stopped(scan_id):
            return gone
    db_result = _stage(scan, 'Database exposure check', 'db_exposure_scan',
                       lambda: db_exposure.run_db_exposure_checks(scan_id, checks=db_exposure_checks),
                       fallback={'checked': 0, 'exposed': 0})
    if stopped(scan_id):
        return gone
    # A test that injects its own light_stream is never second-guessed; otherwise a registered Sentinel gets first refusal
    # at the stage (agentapi.sentinel_dispatch), and wrap_nuclei_stream returns the real stream_nuclei, unwrapped, when
    # none is eligible, so a project with no Sentinels runs exactly as before this existed.
    from agentapi import sentinel_dispatch

    def run_light():
        try:
            light_kwargs = {'stream': light_stream or sentinel_dispatch.wrap_nuclei_stream(scan, 'nuclei_light')}
        except resources.ScannerUnavailable as exc:  # no scanner can take it and this kind may not run here: the stage waits, it does not fail
            return _waiting_for_scanner(scan, 'Nuclei technology pass', exc, {'targets': 0, 'techs': {}})
        if force:
            light_kwargs['force'] = True
        return nuclei_scan.run_light_nuclei(scan_id, **light_kwargs)
    light_result = _stage(scan, 'Nuclei HTTP and technology pass', 'nuclei_light_scan', run_light, fallback={'targets': 0, 'techs': {}})

    if stopped(scan_id):
        return gone
    from cveFeed import waf_scan
    waf_kwargs = {'runner': waf_runner} if waf_runner else {}
    if retest or force:
        waf_kwargs['force'] = True
    waf_result = None
    if waf_scan.enabled() and (waf_runner or waf_scan.runnable(scan.domain.project_id)) and waf_scan.web_sites(scan):  # the product behind a host's firewall
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
    from cveFeed import secrets_scan

    def run_secrets():  # Kingfisher over the routes just probed and the front pages' own scripts, in a scanner only (docs/SECRETS-PLAN.md 6.1)
        try:
            return secrets_scan.run_for_scan(scan_id, force=bool(retest or force))
        except resources.ScannerUnavailable as exc:  # no scanner takes it, and it never runs here: the stage waits, the hosts stay due
            return _waiting_for_scanner(scan, 'Secrets scan', exc, {'hosts': 0})
    secrets_result = _stage(scan, 'Secrets scan (Kingfisher)', 'secrets_scan', run_secrets, fallback={'hosts': 0})
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
    _once('subdir_apps', lambda: subdir_apps.carry_forward(scan))  # the versioned applications the background subdirectory sweep found, on this scan's fresh host rows
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
    _once('openvas_carry', lambda: openvas_scan.carry_forward(scan))  # the optional OpenVAS add-on's findings are evidence on this scan's host rows too (a no-op while it is off)

    def run_targeted():
        try:
            targeted_kwargs = {'stream': targeted_stream or sentinel_dispatch.wrap_nuclei_stream(scan, 'nuclei_targeted')}
        except resources.ScannerUnavailable as exc:  # as for the light pass: waits, never fails
            return _waiting_for_scanner(scan, 'AI-targeted nuclei scan', exc, {'targets': 0, 'findings': 0})
        if force:
            targeted_kwargs['force'] = True
        return nuclei_scan.run_targeted_nuclei(scan_id, provider=provider, light_techs=light_result.get('techs'),
                                               cve_runner=cve_runner, force_cve_checks=retest or force, **targeted_kwargs)
    targeted_result = _stage(scan, 'AI-targeted nuclei scan', 'nuclei_targeted_scan', run_targeted, fallback={'targets': 0, 'findings': 0})

    if stopped(scan_id):
        return gone
    from cveFeed import finding_lifecycle
    from startScan.models import Subdomain
    # a host that only redirects to another host of the project (www to the apex): what it shares with that host is that host's finding
    _once('fold_aliases', lambda: finding_lifecycle.fold_aliases_quietly(scan.domain.project_id, set(Subdomain.objects.filter(scan_history=scan).values_list('name', flat=True))))
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
        hygiene_hosts = [hygiene_host] if isinstance(hygiene_host, str) else list(hygiene_host)  # one host, or every host of a batch
        hygiene_result = _stage(scan, 'Host TLS hygiene', 'host_hygiene',
                                lambda: run_hygiene(scan.domain_id, hosts=hygiene_hosts), fallback={'tls_hosts': 0})
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
    result = {**found, 'nmap': nmap_result, 'db_exposure': db_result, 'nuclei_light': light_result, 'route_auth': route_result, 'secrets_scan': secrets_result,
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
    if shot_result is not None:
        result['web_screenshot'] = shot_result
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

def _no_such_name(exc):
    """True when a lookup error is the resolver's definitive answer that the name has no address (NXDOMAIN, or the name exists with no A or AAAA
    record), as opposed to a resolver that could not answer (a timeout, a temporary failure, an unreachable server)."""
    import socket
    return isinstance(exc, socket.gaierror) and exc.errno in {code for code in (getattr(socket, 'EAI_NONAME', None), getattr(socket, 'EAI_NODATA', None))
                                                              if code is not None}


def resolve_names(names, timeout=IP_LOOKUP_TIMEOUT, workers=20, errors=None):
    """{(name, ip)} for the names that resolve. getaddrinfo has no timeout of its own, so each lookup runs in a pool.

    A name the resolver answers "no such name" for is simply absent. A lookup that could not be answered (a timeout, a temporary resolver
    failure) is not an answer about the name: it is put in ``errors`` (``{name: reason}``) when the caller passes one, so it is never mistaken for
    a host that has no address, and it is counted in the log either way."""
    import concurrent.futures
    import socket
    pairs = set()
    failed = errors if errors is not None else {}
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    try:
        futures = {pool.submit(socket.getaddrinfo, name, None, 0, socket.SOCK_STREAM): name for name in names}
        for future, name in futures.items():
            try:
                pairs.update((name, info[4][0]) for info in future.result(timeout=timeout))
            except concurrent.futures.TimeoutError:
                failed[name] = f'no answer within {timeout} seconds'
            except Exception as exc:  # noqa: BLE001 - one lookup failing never stops the rest
                if not _no_such_name(exc):
                    failed[name] = f'{type(exc).__name__}: {exc}'[:120]
    finally:
        pool.shutdown(wait=False)
    if failed:
        logger.warning('DNS lookup could not be answered for %s of %s names (for example %s: %s)', len(failed), len(list(names)),
                       next(iter(failed)), next(iter(failed.values())))
    return pairs


@scanner_wait.requeues(_named_hosts)
def run_host_pipeline(domain_id, names, resolver=None, celery_id=None, retest=False, source_scan_id=None,
                      force=False, hygiene=False, assessment_id=None, by_person=False, assessment_ids=None, then=None, **stage_kwargs):
    """Take a handful of new hosts of a target (certificate transparency found them between scans) through the same stages
    a discovery ends with: resolve and record them, then nmap, the database exposure check, the light nuclei pass, CVE
    correlation and the targeted nuclei pass. The ledger still dedupes each scanner per asset, so a host or IP covered
    recently is not scanned again. A ScanHistory carries the run (queued, then running) so it shows in Scans and can be
    stopped; the stop flag is honoured between stages. ``retest`` marks a run started because these hosts changed (see
    cveFeed.retest): its CVE checks ignore the ledger. ``by_person`` marks a run a person asked for: any other run does nothing for a bug
    bounty project whose owner has not confirmed automated testing, and no run scans a host the program's scope does not name
    (cveFeed.bounty_gate). Returns the stage results.

    ``assessment_ids`` (a batch of host assessments, see ``host_assessment.execute_batch``) carries many hosts of the target through one run, so
    each stage hands a Sentinel multi-target tasks instead of one tiny task per host. Every host keeps its own outcome: a host the gates drop,
    whose lookup is not answered or that has no scannable address is named in the result's ``per_host`` (its own status, error and ``resolved``
    count) and the rest go on; the run as a whole fails only when no host is left. The stages are the scan's, so a failed stage is every host's.

    When a stage hands its work to Sentinels and gives the worker back (``agentapi.stage_runs``) this returns the ``waiting`` marker; the callback
    finishes the stages and hands the result to the continuation ``then`` (``(name, {args})``), which is where a caller does with it what it
    would have done with the return value."""
    from cveFeed import activity
    from reNgine.tasks import persist_bbot_result
    from startScan.models import ScanActivity, ScanHistory
    from targetApp.models import Domain
    domain = Domain.objects.get(pk=domain_id)
    if not by_person and domain.discovery_mode == Domain.DISCOVERY_MANUAL:  # "just add them, do not scan yet": only a person's own request takes its hosts through the stages
        return {'status': 'inconclusive', 'hosts': 0, 'error': 'the target is set to manual only; nothing was scanned'}
    wanted = sorted({n.strip().lower().rstrip('.') for n in names if n and n.strip()})
    requested = list(wanted)
    from cveFeed.exclusions import drop_excluded
    in_target = [n for n in wanted if domain.includes_host(n)]  # the target or a name under it; only the target itself when it is exactly one host
    wanted = drop_excluded(domain.project_id, in_target)[:MAX_PIPELINE_HOSTS]
    not_excluded = set(wanted)
    from cveFeed.archive_rediscovery import archived_names
    archived = archived_names(domain.project_id)
    wanted = [n for n in wanted if n not in archived]
    not_archived = set(wanted)
    from cveFeed.bounty_gate import Gate
    gate = Gate()
    if not by_person and gate.project_blocked(domain.project_id):
        return {'status': 'inconclusive', 'hosts': 0, 'error': 'the bug bounty engagement has not confirmed automated testing; nothing was scanned'}
    wanted = [n for n in wanted if gate.allows(domain.project_id, n, unattended=False)]  # a host the program's scope does not name is never scanned
    assessment_ids = list(assessment_ids or ([assessment_id] if assessment_id else []))
    per_host = {}  # a batch only: the hosts that do not go on to the stages, each with its own outcome
    if len(assessment_ids) > 1:
        def why(name):  # the reason a host of a batch was not scanned, so its row never shows a blank outcome
            if name not in in_target:
                return 'host is outside the target'
            if name not in not_excluded:
                return 'host is excluded'
            if name not in not_archived:
                return 'host is archived'
            return 'host is outside the program scope'
        per_host = {n: {'status': 'empty', 'hosts': 0, 'error': why(n)} for n in requested if n not in wanted}
    if not wanted:
        return {'status': 'empty', 'hosts': 0, **({'per_host': per_host} if per_host else {})}
    engine = pick_engine()
    if engine is None:
        raise RuntimeError('no scan engine is configured')
    now = timezone.now()
    scan = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=now, scan_status=QUEUED,
                                      results_dir='/usr/src/scan_results',
                                      tasks=[HOST_PIPELINE_TASK, RETEST_TASK] if retest else [HOST_PIPELINE_TASK],
                                      celery_ids=[celery_id] if celery_id else [])
    if assessment_ids:
        from cveFeed.models import HostAssessment
        HostAssessment.objects.filter(pk__in=assessment_ids).update(scan=scan)
        if not HostAssessment.objects.filter(pk__in=assessment_ids, status='running').exists():  # every one was stopped while it waited
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
            lookup_errors = {}
            if resolver is None or resolver is resolve_names:  # through a Sentinel when one can take dns_resolve (agentapi.probe_dispatch), else here
                from agentapi import probe_dispatch
                try:
                    pairs = probe_dispatch.resolve_for(domain, wanted, errors=lookup_errors, scan=scan)
                except resources.ScannerUnavailable as exc:  # no scanner can resolve them and it may not run here: nothing is recorded, all stay due
                    pairs = set()
                    lookup_errors.update({name: f'waiting for a scanner ({exc.why or "none is live"})'[:120] for name in wanted})
            else:
                pairs = resolver(wanted)
            if lookup_errors:  # a name whose lookup was not answered is not recorded as a host with no address: the next pass looks again
                wanted = [n for n in wanted if n not in lookup_errors]
                activity.log('discovery', f'DNS could not answer {len(lookup_errors)} lookup{"s" if len(lookup_errors) != 1 else ""} for {domain.name} '
                                          f'({next(iter(lookup_errors.values()))}); those hosts are not recorded and are looked up again later',
                             project=domain.project_id, scan_id=scan.id)
                if len(assessment_ids) > 1:
                    for name, reason in lookup_errors.items():  # that host's own outcome: the other hosts of the batch are not held to it
                        per_host[name] = {'scan_id': scan.id, 'status': 'inconclusive', 'hosts': 1, 'resolved': 0, 'lookup_errors': 1,
                                          'error': f'DNS could not answer any lookup ({reason}); nothing was recorded'}
            if force:
                from targetApp.target_types import is_scannable_ip
                pairs = {(name, address) for name, address in pairs if is_scannable_ip(address, project=domain.project_id if name == address else None)}
            persist_bbot_result(bbot_lib.BbotResult(subdomains=set(wanted), resolutions=pairs),
                                ctx={'scan_history_id': scan.id, 'domain_id': domain.id, 'subdomain_id': None, 'subscan_id': None})
            ScanActivity.objects.filter(pk=step.pk).update(status=SUCCESS, time=timezone.now())
            resolved_names = {name for name, _ in pairs}
            found['resolved'] = len(resolved_names)
            if force and len(assessment_ids) > 1:
                for name in wanted:
                    if name not in resolved_names:  # no scannable address: this host did nothing, the others carry on
                        per_host[name] = {'scan_id': scan.id, 'status': 'inconclusive', 'hosts': 1, 'resolved': 0,
                                          'error': 'No scannable IP address resolved; no active checks ran'}
            if lookup_errors:
                found['lookup_errors'] = len(lookup_errors)
                if not wanted:  # every lookup failed: nothing was learned, and the run says so instead of reporting success
                    message = f'DNS could not answer any lookup ({next(iter(lookup_errors.values()))}); nothing was recorded'
                    ScanHistory.objects.filter(pk=scan.pk).update(scan_status=FAILED, stop_scan_date=timezone.now(), error_message=message[:290])
                    return {**found, 'status': 'inconclusive', 'error': message, **({'per_host': per_host} if per_host else {})}
            if force and not pairs:
                message = 'No scannable IP address resolved; no active checks ran'
                ScanHistory.objects.filter(pk=scan.pk).update(scan_status=FAILED, stop_scan_date=timezone.now(), error_message=message)
                return {**found, 'status': 'inconclusive', 'error': message, **({'per_host': per_host} if per_host else {})}
            scanned = [n for n in wanted if n in resolved_names] if force else wanted  # the hosts the stages have something to do for
            kwargs = dict(hygiene=hygiene, hygiene_host=scanned if assessment_ids else None, retest=retest, force=force, by_person=by_person,
                          **stage_kwargs)
            from agentapi import stage_runs
            # the stages wait on Sentinels without this worker when they can; ``then`` is what the caller does with the result then
            result = stage_runs.run('pipeline.host', {'scan_id': scan.id, 'found': found, 'kwargs': kwargs, 'per_host': per_host, 'step_id': step.pk},
                                    first=lambda: _run_stages(scan.id, found, **kwargs), project=domain.project_id, scan=scan.id, then=then)
            if stage_runs.is_waiting(result):
                return result
            if per_host:
                result['per_host'] = per_host
            return result
    except resources.ScanAborted:
        return {'scan_id': scan.id, 'status': 'aborted', **({'per_host': per_host} if per_host else {})}
    except Exception as exc:  # noqa: BLE001 - the scan must end in a visible state
        logger.exception('host pipeline failed for scan %s', scan.id)
        ScanActivity.objects.filter(pk=step.pk).update(status=FAILED, time=timezone.now(), error_message=str(exc)[:290])
        ScanHistory.objects.filter(pk=scan.id).update(scan_status=FAILED, stop_scan_date=timezone.now(), error_message=str(exc)[:290])
        return {'scan_id': scan.id, 'status': FAILED, 'error': str(exc)[:290], **({'per_host': per_host} if per_host else {})}


@stage_runs_adapter('pipeline.host')
def _resume_host_pipeline(context):
    """The completion callback of a host pipeline's stages: run them again from where they stopped, ending the scan as ``run_host_pipeline`` does."""
    from reNgine import resources
    from startScan.models import ScanActivity, ScanHistory
    scan_id, per_host = context['scan_id'], context.get('per_host') or {}
    try:
        with resources.scan_context(scan_id):
            result = _run_stages(scan_id, context['found'], **context.get('kwargs') or {})
            if per_host:
                result['per_host'] = per_host
            return result
    except resources.ScanAborted:
        return {'scan_id': scan_id, 'status': 'aborted', **({'per_host': per_host} if per_host else {})}
    except Exception as exc:  # noqa: BLE001 - the scan must end in a visible state
        logger.exception('host pipeline failed for scan %s', scan_id)
        ScanActivity.objects.filter(pk=context.get('step_id')).update(status=FAILED, time=timezone.now(), error_message=str(exc)[:290])
        ScanHistory.objects.filter(pk=scan_id).update(scan_status=FAILED, stop_scan_date=timezone.now(), error_message=str(exc)[:290])
        return {'scan_id': scan_id, 'status': FAILED, 'error': str(exc)[:290], **({'per_host': per_host} if per_host else {})}
