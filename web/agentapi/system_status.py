"""One read-only snapshot of the instance for the REST API and MCP: is it healthy, what is queued and running, how much memory
and disk is left, and how big the inventory is.

Anyone may read the inventory part (their own projects' targets, hosts, scans and open findings) and whether scanning is paused
or an update is running. The infrastructure part
(database and broker, queue depths, workers, schedules, memory, disk, feeds, AI budget) belongs to an App Admin: it describes the
whole server, not a project, so for anyone else it is left out and ``system_note`` says so.

Every probe is wrapped, so one that fails or times out turns into ``{"error": ...}`` and a line in ``problems`` instead of failing
the whole answer. Nothing here returns an address, credential, command line or task argument."""
import re
import shutil
import time
from datetime import datetime, timezone as dt_timezone

from django.conf import settings
from django.utils import timezone

QUEUES = ('discovery_queue', 'cve_feed_queue', 'validation_priority_queue', 'api_queue', 'wpscan_queue', 'celery')
PRIORITY_SUFFIXES = ('', '\x06\x163', '\x06\x166', '\x06\x169')  # kombu's Redis priority steps share one queue name
MAX_PROJECTS = 100
DISK_LOW_PERCENT = 10
FEED_STALE_HOURS = 48
MEMORY_REPORT_STALE_SECONDS = 180


def _probe(problems, name, fn):
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - a probe must never fail the whole snapshot, and never leak its message
        problems.append(f'{name}: could not be read ({type(exc).__name__})')
        return {'error': type(exc).__name__}


def _iso(value):
    return value.isoformat() if value else None


def _version():
    return getattr(settings, 'RENGINE_CURRENT_VERSION', None)


def _scanning():
    from cveFeed.models import ScanControl
    row = ScanControl.current()
    return {'paused': bool(row.paused), 'paused_by_update': bool(row.paused_by_update), 'reason': row.reason or None,
            'by': row.actor or None, 'changed_at': _iso(row.changed_at), 'last_error': row.last_error or None}


def _update():
    from cveFeed import updater
    phase = updater.read_phase()
    return {'phase': phase.get('phase'), 'detail': phase.get('detail') or None,
            'scans_running': phase.get('scans_running'), 'changed_at': phase.get('changed_at')}


def _projects(ctx):
    from agentapi.services import _allowed_ids
    from cveFeed import counts, wpscan_scan
    from cveFeed.stats_history import compute_snapshot
    from dashboard.models import Project
    from startScan.models import ScanHistory
    from targetApp.models import Domain

    rows = []
    for project in Project.objects.filter(id__in=list(_allowed_ids(ctx.user))).order_by('name')[:MAX_PROJECTS]:
        snap = compute_snapshot(project)
        scans = ScanHistory.objects.filter(domain__project=project)
        rows.append({
            'slug': project.slug, 'name': project.name,
            'targets': Domain.objects.filter(project=project).count(),
            'hosts': snap['hosts'], 'exposed_hosts': snap['exposed_hosts'],
            'scans': {'running': counts.running_scans(scans).count(), 'queued': counts.queued_scans(scans).count(),
                      'stalled': counts.stalled_scans(scans).count()},
            'open_findings': snap['open_findings'], 'open_findings_total': sum(snap['open_findings'].values()),
            'cve_matches': snap['cve_matches'],
            # WordPress hosts: how many, how many WPScan has covered, and why the rest were not (blocked by an edge, failed, waiting)
            'wordpress': wpscan_scan.status_counts([project.id]),
        })
    return rows


def _totals(rows):
    total = {'projects': len(rows), 'targets': 0, 'hosts': 0, 'exposed_hosts': 0, 'open_findings': 0,
             'scans_running': 0, 'scans_queued': 0, 'scans_stalled': 0}
    for row in rows:
        total['targets'] += row['targets']
        total['hosts'] += row['hosts']
        total['exposed_hosts'] += row['exposed_hosts']
        total['open_findings'] += row['open_findings_total']
        total['scans_running'] += row['scans']['running']
        total['scans_queued'] += row['scans']['queued']
        total['scans_stalled'] += row['scans']['stalled']
    return total


# --- infrastructure (App Admin only) -------------------------------------------------------------

def _database():
    from django.db import connection
    started = time.monotonic()
    with connection.cursor() as cursor:
        cursor.execute('SELECT 1')
        cursor.fetchone()
    return {'ok': True, 'latency_ms': int((time.monotonic() - started) * 1000)}


def _broker_client():
    from reNgine.celery import app
    return app.connection_for_read().default_channel.client


def _broker():
    started = time.monotonic()
    client = _broker_client()
    client.ping()
    return {'ok': True, 'latency_ms': int((time.monotonic() - started) * 1000)}


def _queues():
    """Messages waiting in each Celery queue, plus those a worker has taken but not yet acknowledged."""
    client = _broker_client()
    waiting = {name: sum(client.llen(name + suffix) for suffix in PRIORITY_SUFFIXES) for name in QUEUES}
    return {'waiting': waiting, 'waiting_total': sum(waiting.values()), 'unacknowledged': client.hlen('unacked')}


def _workers_and_jobs(user):
    from cveFeed import admin_api
    return admin_api.scheduler_health(None, user)  # the App Admin check there is the one system_status already made


def _schedules(health):
    past_due = [s['name'] for s in health.get('schedules', []) if s.get('next_due_state') == 'past_due_unconfirmed']
    return {'enabled': len(health.get('schedules', [])), 'past_due': past_due,
            'note': health.get('scheduler_note')}


def _memory():
    from reNgine import resources
    snap = resources.cluster_snapshot()
    containers = []
    for c in snap.get('containers', []):
        mem = c.get('memory') or {}
        containers.append({
            'host': c.get('host'), 'total_mb': mem.get('total_mb'), 'used_mb': mem.get('used_mb'),
            'available_mb': mem.get('available_mb'), 'job_budget_mb': c.get('budget_mb'),
            'headroom_mb': c.get('headroom_mb'), 'critical_mb': c.get('critical_mb'),
            'jobs_running': len(c.get('running', [])), 'jobs_waiting': len(c.get('waiting', [])),
            'memory_kills_24h': len(c.get('memory_kills', [])), 'report_age_seconds': c.get('age_seconds'),
        })
    return {'store': snap.get('store'), 'containers': containers}


def _disk():
    import os
    path = settings.RENGINE_RESULTS if os.path.isdir(settings.RENGINE_RESULTS) else settings.RENGINE_HOME
    usage = shutil.disk_usage(path)
    mb = 1 << 20
    return {'path': 'scan results' if path == settings.RENGINE_RESULTS else 'application', 'total_mb': usage.total // mb,
            'used_mb': usage.used // mb, 'free_mb': usage.free // mb,
            'free_percent': round(usage.free * 100 / usage.total, 1) if usage.total else None}


def _feeds():
    from django_celery_beat.models import PeriodicTask

    from cveFeed.models import CVEEntry
    last = PeriodicTask.objects.filter(task='sync_cve_now_feed').values_list('last_run_at', flat=True).first()
    newest = CVEEntry.objects.order_by('-published_at').values_list('published_at', flat=True).first()
    try:
        from cveFeed import detection_author
        guidance = detection_author.progress()
    except Exception:  # noqa: BLE001 - status must not fail on a counting problem
        guidance = None
    return {'cve_entries': CVEEntry.objects.count(), 'newest_cve_published': _iso(newest), 'last_feed_dispatch': _iso(last),
            'cve_guidance': guidance}


def _ai():
    from cveFeed.models import ValidationBudget
    from dashboard.models import AIProviderSettings
    cfg = AIProviderSettings.objects.first()
    today = {row.scope: row.reserved for row in ValidationBudget.objects.filter(day=timezone.localdate())}
    return {'provider_enabled': bool(cfg and cfg.enabled), 'provider': cfg.provider if cfg and cfg.enabled else None,
            'validation_attempts_today': today}


TEMPLATE_STALE_HOURS = 36  # the refresh runs every six hours: a day and a half without a successful one means it is failing
TEMPLATE_REFRESH_KEY = 'nuclei_templates_refresh'  # written by the cveFeed.tasks.update_nuclei_templates worker task, read here
_VERSION_CACHE = {}
_VERSION_LINE = re.compile(r'\d+\.\d+')


def _tool_version(argv):
    """The version line of ``<tool> -version``, cached for ten minutes; None when the tool is missing or slow. A tool may print a
    warning of its own first (nuclei does, on a Go release its JSON library has not caught up with): the first line that is not a
    warning and carries a version number, else the first line that is not a warning."""
    import subprocess
    now = time.monotonic()
    cached = _VERSION_CACHE.get(argv)
    if cached and now - cached[0] < 600:
        return cached[1]
    try:
        proc = subprocess.run(list(argv), capture_output=True, text=True, timeout=5, check=False)
        lines = [line.strip() for line in ((proc.stdout or '') + (proc.stderr or '')).splitlines() if line.strip()]
        lines = [line for line in lines if not line.lower().startswith(('warning', '[wrn]', 'warn'))] or lines
        value = next((line[:120] for line in lines if _VERSION_LINE.search(line)), lines[0][:120] if lines else None)
    except (OSError, subprocess.SubprocessError):
        value = None
    _VERSION_CACHE[argv] = (now, value)
    return value


def _template_refresh():
    """What the last ``nuclei -update-templates`` run said, as the worker recorded it: ``{'at', 'ok', 'result'}`` or None."""
    from django.core.cache import cache
    try:
        record = cache.get(TEMPLATE_REFRESH_KEY)
    except Exception:  # noqa: BLE001 - a cache that is down must not take the status with it
        return None
    return record if isinstance(record, dict) and record.get('at') else None


def _template_problem(templates):
    """The status line for stale nuclei templates, or ''. The template files only change when a new release is published, so their age
    says nothing about whether the refresh works; it is judged on the refresh's own last run when there is one, and on the files only
    when no run has been recorded and none has been dispatched for a day and a half either."""
    refresh = templates.get('last_refresh')
    if refresh:
        try:
            hours = (timezone.now() - datetime.fromisoformat(refresh['at'])).total_seconds() / 3600
        except (KeyError, TypeError, ValueError):
            hours = None
        if hours is not None and not refresh.get('ok'):
            return f"nuclei templates: the last refresh failed ({str(refresh.get('result') or 'no detail')[:100]})"
        if hours is not None and hours > TEMPLATE_STALE_HOURS:
            return f'nuclei templates: no successful refresh for {int(hours)} hours'
        return ''
    age, dispatched = templates.get('age_hours'), templates.get('last_refresh_dispatch')
    if age is None or age <= TEMPLATE_STALE_HOURS:
        return ''
    if dispatched and (timezone.now() - datetime.fromisoformat(dispatched)).total_seconds() / 3600 <= TEMPLATE_STALE_HOURS:
        return ''  # the refresh was dispatched recently and has not reported yet (right after an update): not a failure
    return f'nuclei templates: not refreshed for {int(age)} hours'


def _tools():
    """How current the detection tools are: the nuclei templates (when they were last refreshed) and the scanner versions."""
    import os
    from django_celery_beat.models import PeriodicTask
    root = os.environ.get('NUCLEI_TEMPLATES_DIR', '/root/nuclei-templates')
    marker = os.path.join(root, '.checksum')
    try:
        updated = datetime.fromtimestamp(os.stat(marker).st_mtime, tz=dt_timezone.utc)
    except OSError:
        updated = None
    last_run = PeriodicTask.objects.filter(task='update_nuclei_templates').values_list('last_run_at', flat=True).first()
    refresh = _template_refresh()
    return {'nuclei_templates': {'updated_at': _iso(updated),  # when the template files last changed: nothing changes between releases
                                 'age_hours': round((timezone.now() - updated).total_seconds() / 3600, 1) if updated else None,
                                 'last_refresh_dispatch': _iso(last_run),
                                 'last_refresh': refresh},  # the last run of the refresh itself and what it said
            'versions': {'nuclei': _tool_version(('nuclei', '-version')), 'nmap': _tool_version(('nmap', '--version')),
                         'wpscan': _tool_version(('wpscan', '--version', '--no-banner'))}}


def _runzero(problems):
    """Each project that has a runZero token: when it last synced and how it went. A failing sync is a problem worth seeing here."""
    from cveFeed import runzero_sync
    from dashboard.models import Project
    rows = []
    for project in Project.objects.filter(pk__in=runzero_sync.configured_project_ids()).order_by('slug')[:MAX_PROJECTS]:
        s = runzero_sync.status(project)
        rows.append({'project': project.slug, 'state': s['state'], 'last_sync_at': s['last_sync_at'], 'last_error': s['last_error'],
                     'import_enabled': s['import_enabled'], 'assets': (s['counts'] or {}).get('assets')})
        if s['state'] == 'error':
            problems.append(f"runZero: the sync of {project.slug} is failing: {s['last_error']}")
    return {'interval_hours': runzero_sync.interval_hours(), 'projects': rows}


def _work():
    """What the work conductor (cveFeed.conductor) is doing: scans running and queued against the depth it keeps, and its last round."""
    from cveFeed import conductor
    from cveFeed.scan_control import pause_requested
    from targetApp.models import Domain
    out = conductor.status()
    out['paused'] = pause_requested(fail_closed=False)
    out['targets'] = Domain.objects.exclude(project=None).exists()
    return out


def _system(user, problems, notes):
    out = {}
    out['database'] = _probe(problems, 'database', _database)
    out['broker'] = _probe(problems, 'broker', _broker)
    out['queues'] = _probe(problems, 'queues', _queues)
    health = _probe(problems, 'workers', lambda: _workers_and_jobs(user))
    if 'error' in health:
        out['workers'] = health
    else:
        out['workers'] = {'state': health.get('workers_state'), 'note': health.get('worker_note'),
                          'consumers': health.get('workers')}
        out['jobs'] = health.get('jobs')
        out['schedules'] = _schedules(health)
        out['last_activity'] = health.get('last_activity')
        if health.get('workers_state') != 'responding':
            problems.append(f"workers: {health.get('worker_note')}")
        if out['schedules']['past_due']:
            problems.append('schedules past due: ' + ', '.join(out['schedules']['past_due'][:10]))
    out['work'] = _probe(problems, 'work', _work)
    work = out['work']
    if isinstance(work, dict) and 'error' not in work and work.get('wanted_depth') and not work.get('paused') \
            and work.get('targets') and not work.get('running') and not work.get('queued'):
        problems.append('work: nothing is running or queued although there are targets to scan; the work conductor '
                        + ('has not run yet' if not work.get('last_round') else f"last ran at {work['last_round'].get('at')}")
                        + ' (is celery beat running?)')
    out['memory'] = _probe(problems, 'memory', _memory)
    if 'containers' in out['memory']:
        for c in out['memory']['containers']:
            if c['available_mb'] is not None and c['critical_mb'] is not None and c['available_mb'] < c['critical_mb']:
                problems.append(f"memory: {c['host']} has {c['available_mb']} MB free, below its critical level")
            if (c['report_age_seconds'] or 0) > MEMORY_REPORT_STALE_SECONDS:
                problems.append(f"memory: {c['host']} has not reported for {c['report_age_seconds']} seconds")
    out['disk'] = _probe(problems, 'disk', _disk)
    if out['disk'].get('free_percent') is not None and out['disk']['free_percent'] < DISK_LOW_PERCENT:
        problems.append(f"disk: only {out['disk']['free_percent']}% free ({out['disk']['free_mb']} MB)")
    out['feeds'] = _probe(problems, 'feeds', _feeds)
    last = out['feeds'].get('last_feed_dispatch')
    if last:
        age = (timezone.now() - datetime.fromisoformat(last)).total_seconds() / 3600
        if age > FEED_STALE_HOURS:
            problems.append(f'feeds: the CVE feed has not been dispatched for {int(age)} hours')
    out['ai'] = _probe(problems, 'ai', _ai)
    out['runzero'] = _probe(problems, 'runzero', lambda: _runzero(problems))
    out['tools'] = _probe(problems, 'tools', _tools)
    problem = _template_problem((out['tools'] or {}).get('nuclei_templates') or {})
    if problem:
        problems.append(problem)
    queues = out['queues']
    if isinstance(queues, dict) and queues.get('waiting_total'):
        notes.append(f"{queues['waiting_total']} message(s) waiting in the work queues")
    return out


def system_status(ctx):
    problems, notes = [], []
    admin = ctx.user.is_superuser
    scanning = _probe(problems, 'scan control', _scanning)
    if scanning.get('paused'):
        notes.append('scanning is paused' + (f": {scanning['reason']}" if admin and scanning.get('reason') else ''))
    update = _probe(problems, 'update', _update)
    if update.get('phase') not in (None, 'idle', 'done'):
        notes.append(f"an update is in progress ({update['phase']})")
    if not admin:  # who paused, why, and what the whole instance is running describe the server, not the caller's projects
        scanning = {k: scanning.get(k) for k in ('paused', 'paused_by_update', 'error') if k in scanning}
        update = {k: update.get(k) for k in ('phase', 'error') if k in update}
    projects = _probe(problems, 'inventory', lambda: _projects(ctx))
    totals = _totals(projects) if isinstance(projects, list) else None
    if totals and totals['scans_stalled']:
        problems.append(f"{totals['scans_stalled']} scan(s) marked running for too long (stalled)")
    out = {'at': timezone.now().isoformat(), 'version': _version(), 'scanning': scanning, 'update': update,
           'totals': totals, 'projects': projects if isinstance(projects, list) else []}
    if admin:
        out['system'] = _system(ctx.user, problems, notes)
        out['scope'] = 'instance'
    else:
        out['system'] = None
        out['system_note'] = 'Server internals (queues, workers, memory, disk, feeds) are for an App Admin; this shows your projects only.'
        out['scope'] = 'projects'
    out['overall'] = 'degraded' if problems else 'ok'
    out['problems'] = problems
    out['notes'] = notes
    return out
