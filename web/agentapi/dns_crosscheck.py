"""A Sentinel's DNS answers, checked against a second source before they change a host (LOW1 of the Nov 2026 review).

The server never resolves a name itself (``tests.test_no_local_tools``): what a name points at is what a Sentinel said, through a ``dns_resolve``
answer (``agentapi.probe_dispatch.try_dns_resolve``) or the resolutions a discovery run reports in its batches (``agentapi.sentinel_stream``). The
answers are held to the names the task asked about (``probe_results.bind``, the stream's scope policy), but an address literal itself was taken as
given, so one Sentinel could point an in-scope name at any address and that address became the host's inventory: it was shown as the host's,
worked on as the host's, and it could move the host into or out of the organization's do-not-scan list.

Every answer is now recorded as a ``DnsReading`` (one row per project, name and address: which Sentinels said so, how many runs, when) and judged
(``judge``) before the inventory takes it:

* an address the host already has in the inventory, or one already confirmed, is taken;
* a host with no address yet takes an answer that keeps it out of the do-not-scan list (there is nothing to disagree with);
* anything else is HELD: an address that is new for a host that already has addresses (``adds``), an answer that shares no address with what the host
  has (``replaces``), and an answer that would move the host into (``into_list``) or out of (``out_of_list``) the do-not-scan list. A held address is kept
  in ``DnsReading`` and shown as unconfirmed (``held_for``: the host page, ``list_hosts`` / ``search_hosts`` field
  ``unconfirmed_addresses``, an activity line), but it is not stored on the host, and the host keeps the addresses it had (``Verdict.carried``).

A held address is confirmed, and then added to the host (``release``), when:

* a SECOND Sentinel gives the same answer (``second_sentinel``): its own ``dns_resolve`` (a confirming lookup ``request_confirmation`` hands to a
  different eligible Sentinel, ``SentinelTask.avoid_agent``, whenever an answer is held) or its discovery run's resolutions, within ``SOURCE_WINDOW``;
* or, with only one Sentinel (or none other that could take the lookup), the same Sentinel gave the same answer in ``CONFIRM_RUNS`` runs over at least
  ``CONFIRM_SPAN`` (``repeated``): an answer that stays the same over a day is taken as the name's, a one-off answer is not.

What is not changed: a safety decision is never held open. Before a discovery run of a single host (``address_guard.resolve_before_discovery``) a held
answer that places the host in the do-not-scan list still refuses the run, and every scan task carries the deny ranges to the scanner's own scope floor.
"""
import ipaddress
import logging
from collections import namedtuple
from datetime import datetime, timedelta

from django.utils import timezone

logger = logging.getLogger(__name__)

CONFIRM_RUNS = 3  # one Sentinel alone: the same answer in this many runs ...
CONFIRM_SPAN = timedelta(hours=12)  # ... the first and the last at least this far apart
SOURCE_WINDOW = timedelta(days=30)  # a second Sentinel's answer counts when it gave it within this long
CONFIRM_REQUEST_EVERY = timedelta(hours=6)  # a name is handed to a confirming lookup at most once in this long
MAX_TASKS_KEPT = 10
MAX_SOURCES = 20
MAX_CONFIRM_NAMES = 500  # the contract's bound on a dns_resolve target (probe_dispatch.MAX_NAMES_PER_TASK)
REASONS = {'adds': 'a new address for a host that already has addresses', 'replaces': 'different addresses from the ones the host has',
           'into_list': "an address on the organization's do-not-scan list", 'out_of_list': "moves the host off the organization's do-not-scan list"}

Verdict = namedtuple('Verdict', 'accepted held carried')  # {(name, ip)} taken, {name: {ip: reason}} held, {(name, ip)} the host keeps meanwhile


def _norm(name):
    return str(name or '').strip().lower().rstrip('.')


def _address(value):
    try:
        ip = ipaddress.ip_address(str(value).strip().strip('[]'))
    except ValueError:
        return ''
    return str(ip.ipv4_mapped or ip) if ip.version == 6 else str(ip)


def _pairs(pairs):
    out = set()
    for name, address in pairs:
        name, address = _norm(name), _address(address)
        if name and address:
            out.add((name, address))
    return out


def record(project_id, agent_id, task_id, pairs, via, now=None):
    """Write down that Sentinel ``agent_id`` answered ``pairs`` (``(name, address)``) in task ``task_id`` (``via`` is ``dns_resolve`` or ``discovery``). A task is
    counted once per answer however often it is read (a stage continued by a later pass, a retried batch)."""
    from agentapi.models import DnsReading
    pairs = _pairs(pairs)
    if not project_id or not pairs:
        return {}
    now = now or timezone.now()
    names = {n for n, _ in pairs}
    rows = {(r.name, r.address): r for r in DnsReading.objects.filter(project_id=project_id, name__in=names)}
    missing = [DnsReading(project_id=project_id, name=n, address=a, first_seen=now, last_seen=now) for n, a in sorted(pairs - set(rows))]
    if missing:
        DnsReading.objects.bulk_create(missing, ignore_conflicts=True)
        rows = {(r.name, r.address): r for r in DnsReading.objects.filter(project_id=project_id, name__in=names)}
    changed = []
    for key in pairs:
        row = rows.get(key)
        if row is None:
            continue
        sources = dict(row.sources or {})
        if agent_id is not None:
            sources[str(agent_id)] = now.isoformat()
            if len(sources) > MAX_SOURCES:
                sources = dict(sorted(sources.items(), key=lambda kv: kv[1])[-MAX_SOURCES:])
        tasks = list(row.tasks or [])
        if task_id is not None and task_id not in tasks:
            tasks = (tasks + [task_id])[-MAX_TASKS_KEPT:]
            row.runs += 1
        row.sources, row.tasks, row.last_seen = sources, tasks, max(row.last_seen, now)
        row.via = sorted(set(row.via or []) | {via})
        changed.append(row)
    DnsReading.objects.bulk_update(changed, ['sources', 'tasks', 'runs', 'last_seen', 'via'])
    return rows


def confirmation(row, now=None):
    """How ``row`` (a ``DnsReading``) is confirmed by now: ``second_sentinel``, ``repeated``, or '' (not yet)."""
    now = now or timezone.now()
    recent = 0
    for when in (row.sources or {}).values():
        try:
            at = datetime.fromisoformat(when)
        except (TypeError, ValueError):
            continue
        if now - at <= SOURCE_WINDOW:
            recent += 1
    if recent >= 2:
        return 'second_sentinel'
    if row.runs >= CONFIRM_RUNS and row.last_seen - row.first_seen >= CONFIRM_SPAN:
        return 'repeated'
    return ''


def _networks(project_id):
    from cveFeed import exclusions
    try:
        return exclusions.address_networks(project_id)
    except Exception:  # noqa: BLE001 - an unreadable list: every answer that is new for a host is held (nothing can say it keeps the host off the list)
        return None


def _in_list(networks, address):
    from cveFeed import exclusions
    if networks is None:
        return True
    ip = exclusions.as_address(address)
    return ip is not None and exclusions._containing(networks, ip) is not None


def current_addresses(project_id, names):
    """``{name: {address}}``: the addresses of the newest inventory row of each name (what the host shows now)."""
    from startScan.models import IpAddress, Subdomain
    newest = {}
    for name, row_id in (Subdomain.objects.filter(target_domain__project_id=project_id, name__in=names).order_by('name', '-id')
                         .values_list('name', 'id')):
        newest.setdefault(_norm(name), row_id)
    out = {}
    if newest:
        by_row = {row_id: name for name, row_id in newest.items()}
        for row_id, address in IpAddress.objects.filter(ip_addresses__id__in=list(by_row)).values_list('ip_addresses__id', 'address'):
            if _address(address):
                out.setdefault(by_row[row_id], set()).add(_address(address))
    return out


def judge(project_id, answers, now=None):
    """The ``Verdict`` on ``answers`` (``{name: [address]}``, already ``record``-ed): which pairs the inventory takes, which are held (with the reason), and
    the addresses a host with a held answer keeps meanwhile. Marks the readings held or confirmed."""
    from agentapi.models import DnsReading
    from cveFeed import exclusions
    now = now or timezone.now()
    answers = {_norm(n): {_address(a) for a in (addrs or ()) if _address(a)} for n, addrs in (answers or {}).items() if _norm(n)}
    answers = {n: a for n, a in answers.items() if a}
    if not project_id or not answers:
        return Verdict(set(), {}, set())
    known = {_norm(n): {_address(str(ip)) for ip in ips} for n, ips in exclusions.stored_addresses(project_id, list(answers)).items()}
    networks = None if not answers else _networks(project_id)
    rows = {(r.name, r.address): r for r in DnsReading.objects.filter(project_id=project_id, name__in=list(answers))}
    accepted, held, changed = set(), {}, []
    for name, addresses in answers.items():
        have = known.get(name) or set()
        have_listed = any(_in_list(networks, a) for a in have)
        for address in sorted(addresses):
            row = rows.get((name, address))
            listed = _in_list(networks, address)
            if address in have or (not have and not listed):
                accepted.add((name, address))
                if row is not None and row.status == 'held':  # it reached the host another way (a confirmation, another stage): nothing is held any more
                    row.status, row.reason = 'seen', ''
                    changed.append(row)
                continue
            if row is not None and row.status == 'confirmed':
                accepted.add((name, address))
                continue
            how = confirmation(row, now) if row is not None else ''
            if how:
                accepted.add((name, address))
                row.status, row.reason, row.confirmed_how, row.confirmed_at = 'confirmed', row.reason, how, now
                changed.append(row)
                continue
            if not have or (listed and not have_listed):
                reason = 'into_list'
            elif have_listed and not listed:
                reason = 'out_of_list'
            elif not addresses & have:
                reason = 'replaces'
            else:
                reason = 'adds'
            held.setdefault(name, {})[address] = reason
            if row is not None and (row.status != 'held' or row.reason != reason):
                row.status, row.reason = 'held', reason
                changed.append(row)
    if changed:
        DnsReading.objects.bulk_update(changed, ['status', 'reason', 'confirmed_how', 'confirmed_at'])
    carried = set()
    if held:
        current = current_addresses(project_id, list(held))
        for name in held:
            carried |= {(name, a) for a in current.get(name, ()) if (name, a) not in accepted}
    return Verdict(accepted, held, carried)


def note_held(project, held, scan=None, sentinel=''):
    """One activity line for the answers held now."""
    if not held:
        return None
    from cveFeed import activity
    names = sorted(held)
    reasons = sorted({r for addrs in held.values() for r in addrs.values()})
    count = sum(len(a) for a in held.values())
    what = ', '.join(names[:5]) + (f' and {len(names) - 5} more' if len(names) > 5 else '')
    return activity.log('discovery', f"Held {count} unconfirmed DNS answer{'s' if count != 1 else ''} for {what}{f' from {sentinel}' if sentinel else ''}: "
                        f"single source, {'; '.join(REASONS[r] for r in reasons)}. The host keeps the addresses it had until a second Sentinel or "
                        f"{CONFIRM_RUNS} consistent runs confirm the answer",
                        project=project, status='done', scan_id=getattr(scan, 'id', scan), dns_unconfirmed=True, hosts=names[:50])


def request_confirmation(project, domain, names, avoid_agent, scan=None, now=None):
    """Hand ``names`` to a confirming ``dns_resolve`` that only a Sentinel other than ``avoid_agent`` may take, without waiting for it: its answer is filed
    when it reports (``ingest``). Returns the task, or None when no other eligible Sentinel is live (the ``repeated`` rule applies then), every name was
    asked about recently, or nothing is left to ask."""
    from agentapi import sentinel_broker
    from agentapi.models import SentinelTask
    from cveFeed import activity, probe_scope
    now = now or timezone.now()
    names = [n for n in dict.fromkeys(_norm(n) for n in names) if n]
    if not names or avoid_agent is None or domain is None:
        return None
    others = [e for e in sentinel_broker.eligible_sentinels(project, 'dns_resolve', now=now, live_only=True) if e.agent.pk != avoid_agent]
    if not others:
        return None
    asked = set()
    for target in SentinelTask._base_manager.filter(project=project, kind='dns_resolve', avoid_agent__isnull=False,
                                                    created_at__gte=now - CONFIRM_REQUEST_EVERY).values_list('target', flat=True):
        asked |= {_norm(n) for n in ((target or {}).get('names') or []) if isinstance(n, str)}
    scope = probe_scope.for_names(project.pk, domain, [n for n in names if n not in asked])
    wanted = scope['hosts'][:MAX_CONFIRM_NAMES]
    if not wanted:
        return None
    from agentapi import probe_dispatch
    task = SentinelTask.objects.create(project=project, scan=scan if getattr(scan, 'pk', None) else None, kind='dns_resolve',
                                       target={'names': wanted, 'scope': {**scope, 'hosts': wanted}}, host=probe_dispatch._hosts_label(wanted)[:500],
                                       priority=1, avoid_agent=avoid_agent)
    activity.log('discovery', f"Asked a second Sentinel to confirm the addresses of {len(wanted)} host{'s' if len(wanted) != 1 else ''} "
                 f"({', '.join(wanted[:3])}{', ...' if len(wanted) > 3 else ''})", project=project, status='running',
                 scan_id=getattr(scan, 'id', None), sentinel_task_id=task.pk, dns_unconfirmed=True)
    return task


def release(project_id, pairs):
    """Add confirmed ``pairs`` to the newest inventory row of each name (the host as shown). An address the inventory never stores (internal, loopback) stays out."""
    from cvengine.tasks import save_ip_address
    from startScan.ip_rows import org_id_of_project
    from startScan.models import Subdomain
    by_name = {}
    for name, address in pairs:
        by_name.setdefault(name, set()).add(address)
    if not by_name:
        return 0
    org_id = org_id_of_project(project_id)
    added = 0
    for name, addresses in by_name.items():
        row = Subdomain.objects.filter(target_domain__project_id=project_id, name=name).order_by('-id').first()
        if row is None:
            continue
        for address in sorted(addresses):
            ip, _ = save_ip_address(address, subdomain=row, org_id=org_id)
            added += 1 if ip else 0
    return added


def ingest(task, agent_id, result, now=None):
    """A ``dns_resolve`` result as it is filed (``sentinel_broker.report_result``): its answers recorded, and every held answer it now confirms added to
    its host. A confirming lookup (``avoid_agent``) that did not give a held answer says so: the answer stays unconfirmed."""
    from agentapi.models import DnsReading
    from cveFeed import activity
    now = now or timezone.now()
    resolved = (result or {}).get('resolved') if isinstance(result, dict) else None
    if not isinstance(resolved, dict):
        return
    pairs = _pairs((n, a) for n, addrs in resolved.items() if isinstance(addrs, list) for a in addrs)
    record(task.project_id, agent_id, task.pk, pairs, 'dns_resolve', now=now)
    names = {n for n, _ in pairs} | {_norm(n) for n in ((task.target or {}).get('names') or []) if isinstance(n, str)} if task.avoid_agent else {n for n, _ in pairs}
    if not names:
        return
    confirmed, unconfirmed = [], []
    for row in DnsReading.objects.filter(project_id=task.project_id, name__in=names, status='held'):
        how = confirmation(row, now) if (row.name, row.address) in pairs else ''
        if how:
            row.status, row.confirmed_how, row.confirmed_at = 'confirmed', how, now
            row.save(update_fields=['status', 'confirmed_how', 'confirmed_at'])
            confirmed.append((row.name, row.address))
        elif task.avoid_agent:
            unconfirmed.append(row.name)
    if confirmed:
        release(task.project_id, confirmed)
        hosts = sorted({n for n, _ in confirmed})
        activity.log('discovery', f"Confirmed {len(confirmed)} DNS answer{'s' if len(confirmed) != 1 else ''} for {', '.join(hosts[:5])}"
                     f"{f' and {len(hosts) - 5} more' if len(hosts) > 5 else ''}: a second source gave the same address, added to the host",
                     project=task.project_id, status='done', scan_id=task.scan_id, sentinel_task_id=task.pk, dns_unconfirmed=False, hosts=hosts[:50])
    if unconfirmed:
        hosts = sorted(set(unconfirmed))
        activity.log('discovery', f"A second Sentinel did not confirm the held DNS answers for {', '.join(hosts[:5])}"
                     f"{f' and {len(hosts) - 5} more' if len(hosts) > 5 else ''}: they stay unconfirmed and the hosts keep their addresses",
                     project=task.project_id, status='done', scan_id=task.scan_id, sentinel_task_id=task.pk, dns_unconfirmed=True, hosts=hosts[:50])


def screen_batch(task, batch, now=None):
    """A discovery batch's ``resolutions`` as the inventory may take them (``sentinel_stream.report_partial``): recorded, judged, the held ones taken out (the
    host keeps the addresses it had), and a confirming lookup asked for them. Returns the batch."""
    if not isinstance(batch, dict) or not batch.get('resolutions'):
        return batch
    now = now or timezone.now()
    pairs = _pairs((r.get('name'), r.get('ip')) for r in batch['resolutions'] if isinstance(r, dict))
    agent_id = task.agent_id or task.last_holder
    record(task.project_id, agent_id, task.pk, pairs, 'discovery', now=now)
    answers = {}
    for name, address in pairs:
        answers.setdefault(name, set()).add(address)
    verdict = judge(task.project_id, answers, now=now)
    if not verdict.held:
        return batch
    kept = verdict.accepted | verdict.carried
    note_held(task.project, verdict.held, scan=task.scan_id, sentinel=getattr(task.agent, 'name', '') if task.agent_id else '')
    domain = task.scan.domain if task.scan_id and task.scan else None
    try:
        request_confirmation(task.project, domain, list(verdict.held), agent_id, scan=task.scan, now=now)
    except Exception:  # noqa: BLE001 - a confirmation that could not be asked for leaves the answer held; the batch is still stored
        logger.exception('could not ask for a confirming lookup for task %s', task.pk)
    return {**batch, 'resolutions': [{'name': n, 'ip': a} for n, a in sorted(kept)]}


def held_for(project_ids, names):
    """``{(project_id, name): [{address, state, single_source, reason, why, sentinels, runs, first_seen, last_seen}]}``: the unconfirmed answers of these hosts,
    for every place that shows a host's addresses. One query."""
    from agentapi.models import DnsReading
    names = {_norm(n) for n in names} - {''}
    out = {}
    if not names or not project_ids:
        return out
    for row in DnsReading.objects.filter(project_id__in=list(project_ids), name__in=names, status='held').order_by('name', 'address'):
        sentinels = len(row.sources or {})
        out.setdefault((row.project_id, row.name), []).append({
            'address': row.address, 'state': 'unconfirmed', 'single_source': sentinels <= 1, 'reason': row.reason, 'why': REASONS.get(row.reason, ''),
            'sentinels': sentinels, 'runs': row.runs, 'first_seen': row.first_seen.isoformat(), 'last_seen': row.last_seen.isoformat()})
    return out
