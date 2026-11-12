"""Adoption: a result a Sentinel held during an update, taken when the server is back.

An update does not wait for scans that run on Sentinels (docs/UPDATES.md): the server pauses, rebuilds and resumes, and a Sentinel that finished its
tool while the server was down keeps the result on disk (the client's spool) and delivers it afterwards. The stage that dispatched the task died with
its worker in the restart (or its scan was closed as interrupted by the update), so nothing is waiting for the answer. ``report_result`` hands such a
result to ``adopt`` here, inside the lock that moves the task to ``done``, so the work is filed once (a second delivery is answered ``duplicate``
and never reaches this module).

What each kind lands through is the persistence the stage itself uses (never a second copy of its rules):

* ``nmap``: ``cveFeed.port_inventory.persist_inventory`` on the hosts of the chunk, then the ledger says the fingerprint pass is done for them;
* ``naabu``: ``cveFeed.port_stage.persist_open_ports`` (a tarpit is left out, as the stage does), then the ledger says discovery is done;
* ``nuclei_*``: every finding through ``reNgine.tasks.save_vulnerability`` (one row per finding, so a repeat changes nothing). The stage's catch-all
  screening needs control reads from a Sentinel and cannot be made now, so the findings carry the ``unscreened-same-body`` tag the stage uses for the same
  case. The ledger is left alone: the hosts are due again at their normal time, which also takes the technology fingerprint the light pass writes;
* ``bbot_discovery``: the batches the Sentinel posted before it ended go through the discovery stage's own ``_flush``, and the ledger says discovery
  is done when the run was complete.

A kind with no adopter keeps its result on the task row and the ledger schedules the host again as usual.
"""
import logging

logger = logging.getLogger(__name__)

ADOPTERS = {}


def adopter(*kinds):
    def register(fn):
        for kind in kinds:
            ADOPTERS[kind] = fn
        return fn
    return register


def has_adopter(kind):
    return kind in ADOPTERS


def covered_by_stage_run(task):
    """Whether an open ``StageRun`` still waits on ``task``: its callback consumes the result itself, so it is never adopted."""
    from agentapi.models import StageRun
    rows = StageRun.objects.filter(state__in=StageRun.OPEN_STATES)
    rows = rows.filter(scan_id=task.scan_id) if task.scan_id else rows.filter(project_id=task.project_id)
    return any(task.pk in {int(t) for t in (row.task_ids or []) if str(t).isdigit()} for row in rows.only('task_ids'))


def orphaned(task, now=None):
    """Whether nothing waits for ``task`` any more: no open stage run holds it, and an update ran after it was claimed (the worker that waited for it
    died with the update, so its stage ended and its scan was interrupted). A closed scan alone is not enough, see below."""
    from django.utils import timezone

    from cveFeed import scan_control
    if covered_by_stage_run(task):
        return False
    # a closed scan alone is not enough: a sweep that is not a StageRun (the weekly deep sweep) blocks on its own task and files its own result
    started, ended, _grace = scan_control.update_window()
    if started is None:
        return False
    since = task.claimed_at or task.created_at
    return since is not None and since <= (ended or (now or timezone.now()))


def adopt(task, result, agent=None):
    """File ``result`` for ``task`` through its kind's adopter. Returns ``{'adopted': True, ...}`` (what it filed), ``{'adopted': True, 'kept': True}``
    when the kind has no adopter (the result stays on the task row), or ``{'adopted': False, 'error': ...}`` when the adopter failed: the result still
    stays on the task row and the failure is logged, never raised (the task is done either way)."""
    fn = ADOPTERS.get(task.kind)
    if fn is None:
        return {'adopted': True, 'kept': True}
    from django.db import transaction
    try:
        with transaction.atomic():
            filed = fn(task, result, agent) or {}
    except Exception:  # noqa: BLE001 - one result that cannot be filed must not turn a Sentinel's report into an error
        logger.exception('adopting a %s result of task %s failed', task.kind, task.pk)
        return {'adopted': False, 'error': 'the result could not be filed'}
    return {'adopted': True, **filed}


@adopter('nmap')
def _nmap(task, result, agent):
    from agentapi import sentinel_dispatch
    from cveFeed import ledger, port_stage
    from cveFeed.port_inventory import persist_inventory
    from startScan.ip_rows import org_id_of_project
    chunk = {str(i) for i in (task.ips or (task.target or {}).get('addresses') or [])}
    inventory = [{'ip': host['ip'], 'os_guess': host.get('os_guess', ''), 'os_accuracy': None, 'ports': host.get('ports', [])}
                 for host in result.get('hosts', []) if host.get('ip') in chunk]
    reliable = sentinel_dispatch.os_reliable(sentinel_dispatch.Result(result, agent_id=getattr(agent, 'pk', None)))
    done = persist_inventory(inventory, org_id=org_id_of_project(task.project_id), os_reliable=reliable) if inventory else {}
    if inventory:
        ledger.record(port_stage.FAST_SERVICE, [host['ip'] for host in inventory], task.project_id, task.scan)
    return {'hosts': len(inventory), 'ports': (done or {}).get('ports', 0)}


@adopter('naabu')
def _naabu(task, result, agent):
    from cveFeed import ledger, port_stage
    from startScan.ip_rows import org_id_of_project
    found = {ip: list(ports) for ip, ports in dict(result.get('ports') or {}).items()}
    attempted = [str(i) for i in (task.ips or (task.target or {}).get('addresses') or [])]
    rejected = {ip for ip, ports in found.items() if len(ports) > port_stage.MAX_OPEN_PER_IP}  # a tarpit is not a result
    kept = {ip: ports for ip, ports in found.items() if ip not in rejected and ip in set(attempted)}
    port_stage.persist_open_ports(kept, org_id_of_project(task.project_id))
    ledger.record(port_stage.SERVICE, [ip for ip in attempted if ip not in rejected], task.project_id, task.scan)
    if rejected:
        ledger.record(port_stage.SERVICE, rejected, task.project_id, task.scan, 'failed')
    return {'hosts': len(kept), 'ports': sum(len(p) for p in kept.values())}


@adopter('nuclei_light', 'nuclei_targeted', 'nuclei_deep')
def _nuclei(task, result, agent):
    from agentapi import sentinel_dispatch
    from cveFeed import nuclei_fp
    from cvengine_scanner.flags import host_of
    from reNgine.tasks import parse_nuclei_result, save_vulnerability
    from startScan.models import Subdomain
    scan = task.scan
    if scan is None:
        return {'findings': 0}
    domain = scan.domain
    by_name, by_ip = {}, {}
    for sub in Subdomain.objects.filter(scan_history=scan).prefetch_related('ip_addresses'):
        by_name.setdefault(sub.name, sub)
        for ip in sub.ip_addresses.all():
            by_ip.setdefault(ip.address, sub)
    filed = 0
    for finding in result.get('findings', []):
        line = sentinel_dispatch._finding_to_nuclei_line(finding)
        try:
            data = parse_nuclei_result(line)
        except (KeyError, TypeError):
            continue
        data['tags'] = [*(data.get('tags') or []), nuclei_fp.UNSCREENED_TAG]
        host = host_of(line)
        sub = by_name.get(host) or by_ip.get(host)
        save_vulnerability(target_domain=domain, scan_history=scan, subdomain=sub, http_url=line.get('matched-at') or line.get('host') or host, **data)
        filed += 1
    return {'findings': filed}


@adopter('bbot_discovery')
def _bbot(task, result, agent):
    from agentapi.models import SentinelPartial
    from cveFeed import discovery, ledger
    from cveFeed.models import DiscoveryEvent
    scan = task.scan
    if scan is None:
        return {}
    ctx = {'scan_history_id': scan.id, 'domain_id': scan.domain_id, 'subscan_id': None}
    stored = DiscoveryEvent.objects.filter(scan=scan).count()
    shown = set()
    rows = list(SentinelPartial._base_manager.filter(task_id=task.pk).order_by('seq'))
    for row in rows:
        out, observed = discovery.batch_result(row.body)
        fresh = [o for o in observed if (o.type, o.label) not in shown]
        shown.update((o.type, o.label) for o in fresh)
        stored = discovery._flush(scan, ctx, out, fresh, stored)
        discovery.persist_screenshot_blobs(scan, row.body.get('screenshots'))
    SentinelPartial._base_manager.filter(task_id=task.pk).delete()
    if result.get('outcome') == 'done' and not result.get('incomplete'):
        ledger.record('bbot', [scan.domain.name], scan.domain.project_id, scan)
    return {'batches': len(rows)}


def note_adopted(task):
    """One activity line per project for the whole update, counting what its Sentinels handed over afterwards: 'Adopted N results a Sentinel held
    during the update'. The same line is counted up, not repeated per task."""
    from django.utils import timezone

    from cveFeed import activity, scan_control
    from cveFeed.models import AgentActivity
    started, _ended, _grace = scan_control.update_window()
    window = started.isoformat() if started else ''
    try:
        entry = AgentActivity.objects.filter(project_id=task.project_id, kind='run_check', detail__adopted_window=window).order_by('-id').first()
        if entry is None:
            activity.log('run_check', 'Adopted 1 result a Sentinel held during the update', project=task.project, adopted_window=window, adopted=1)
            return
        total = int((entry.detail or {}).get('adopted', 1)) + 1
        entry.message = f'Adopted {total} result{"s" if total != 1 else ""} a Sentinel held during the update'
        entry.detail = {**(entry.detail or {}), 'adopted': total}
        entry.finished_at = timezone.now()
        entry.save(update_fields=['message', 'detail', 'finished_at'])
    except Exception:  # noqa: BLE001 - a line in the feed never decides whether a result is kept
        logger.warning('could not record the adoption activity', exc_info=True)
