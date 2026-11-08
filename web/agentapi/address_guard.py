"""The do-not-scan address list, applied to Sentinel work: one guard, three places.

``cveFeed.exclusions.address_refusals`` is the rule (an address inside a listed network, a name that resolves into one, an unreadable list refuses
everything). This module only turns a task into the values the rule is asked about, and says what happens to a refused one:

* DISPATCH: ``sentinel_dispatch`` asks ``dispatch_refusal`` before it creates any SentinelTask (``_Dispatch``, ``dispatch_or_none``, ``dispatch_many``
  and ``prefetch``), and ``SentinelTask.save`` asks it again for every new row, so a task created any other way (the OpenVAS sweep, a kind added
  later) cannot skip it: nothing is created for a refused address.
* CLAIM: ``sentinel_broker`` asks ``task_refusal`` before it leases a queued task. A task whose address was excluded after it was queued is
  cancelled with the reason; one whose list could not be read is left queued (not cancelled: nothing is lost, nothing runs).
* INGESTION: ``sentinel_broker.report_result`` asks ``result_refusal`` for the task and for the addresses its result names. A result for an excluded
  address is dropped (the task ends ``failed`` with the reason, the result is not stored) and logged. ``dns_resolve`` is the one kind that only asks DNS
  for names and never contacts an address: it is not refused at dispatch, and its result is KEPT (the addresses must reach the inventory, that is how a
  name that moved into the range is found), with the host noted.

``COVERAGE`` lists every contract kind and how it is guarded; ``tests.test_address_guard`` fails when a kind is added without an entry.
"""
import ipaddress
import logging
from types import SimpleNamespace

logger = logging.getLogger(__name__)

LOOKUP_ONLY = ('dns_resolve',)  # asks DNS for names, contacts no address: allowed through, its answers are checked as they come in
IGNORED_KEYS = ('scope', 'template', 'token', 'api_keys', 'presets', 'require_flags', 'exclude_modules')  # target keys that carry no address of work
RESULT_KEYS = ('ip', 'address', 'host', 'addresses', 'ips', 'hosts', 'ip_address', 'matched-at', 'target', 'url')  # result keys read for the addresses a Sentinel reached
NOTE_TTL = 6 * 3600  # seconds: a host's skip line is written once per this long
MAX_VALUES = 5000


def coverage():
    """``{kind: 'guarded' | 'lookup_only'}`` for every contract kind (the table the contract test holds to the kind list)."""
    from agentapi import sentinel_contract
    return {kind: 'lookup_only' if kind in LOOKUP_ONLY else 'guarded' for kind in sentinel_contract.KINDS}


def _strings(value, depth=0):
    """Every string in a target or result (any depth), skipping the keys that hold no address of work."""
    if depth > 8:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            if key not in IGNORED_KEYS:
                yield from _strings(item, depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item, depth + 1)


def _is_address_like(text):
    from cveFeed.exclusions import as_address
    if len(text) > 300:
        return False
    if '/' in text and '://' not in text:
        try:
            ipaddress.ip_network(text.strip(), strict=False)
            return True
        except ValueError:
            return False
    return as_address(text) is not None


def task_values(kind, target, host='', ips=None):
    """The addresses and names a task acts on: what ``sentinel_broker.task_hosts`` reads for the Sentinel's scope, plus the ``domain`` of a discovery run, the
    ``cidr`` of an internal sweep, the ``ip`` of an endpoint, and any other address written anywhere in the target (a kind added later names its addresses
    somewhere; a literal address in it is never missed)."""
    from agentapi import sentinel_broker
    target = target if isinstance(target, dict) else {}
    stand_in = SimpleNamespace(target=target, host=host or '', ips=list(ips or []))
    names, addresses = sentinel_broker.task_hosts(stand_in)
    values = list(names) + list(addresses)
    for key in ('domain', 'cidr'):
        if isinstance(target.get(key), str):
            values.append(target[key])
    for group in ('targets', 'endpoints', 'probes', 'reads', 'checks'):
        values += [i['ip'] for i in target.get(group) or [] if isinstance(i, dict) and isinstance(i.get('ip'), str)]
    values += [s for s in _strings(target) if _is_address_like(s)]
    seen, out = set(), []
    for value in values:
        key = value.strip().lower()
        if key and key not in seen:
            seen.add(key)
            out.append(value.strip())
    return out[:MAX_VALUES]


def _networks_overlap(project_id, cidr):
    from cveFeed import exclusions
    try:
        wanted = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return None
    net = next((n for n in exclusions.address_networks(project_id) if n.version == wanted.version and n.overlaps(wanted)), None)
    return exclusions.Refusal(f"{wanted} overlaps {net}, which is on the organization's do-not-scan list", entry=str(net)) if net else None


def _refusals(project_id, values, resolved=None):
    """``{value: Refusal}`` for the values the rule refuses: networks (a sweep of a range) by overlap, everything else by ``address_refusals``."""
    from cveFeed import exclusions
    networks = [v for v in values if '/' in v and '://' not in v and _is_address_like(v)]
    out = {}
    plain = [v for v in values if v not in networks]
    out.update(exclusions.address_refusals(project_id, plain, resolved))
    for cidr in networks:
        try:
            refusal = _networks_overlap(project_id, cidr)
        except Exception:  # noqa: BLE001 - fail closed
            refusal = exclusions.Refusal(exclusions.UNREADABLE, unreadable=True)
        if refusal:
            out[cidr] = refusal
    return out


def _project_id(project):
    return getattr(project, 'pk', project)


def task_refusals(project, kind, target, host='', ips=None, resolved=None):
    """``{value: Refusal}`` for a task as it would be (or was) created. Empty when the task may run (and for a lookup-only kind at dispatch)."""
    project_id = _project_id(project)
    if not project_id:
        return {}
    return _refusals(project_id, task_values(kind, target, host, ips), resolved)


def dispatch_refusal(project, kind, target, host='', ips=None, scan=None, note=True):
    """The first ``Refusal`` for a task about to be created, or None. A lookup-only kind is never refused. Writes the skip line (once per host)."""
    if kind in LOOKUP_ONLY:
        return None
    refusals = task_refusals(project, kind, target, host, ips)
    if not refusals:
        return None
    if note:
        note_skipped(project, refusals, scan=scan, kind=kind)
    return next(iter(refusals.values()))


def task_refusal(task):
    """The first ``Refusal`` for a stored task (at claim, and at ingestion), or None."""
    if task.kind in LOOKUP_ONLY:
        return None
    refusals = task_refusals(task.project_id, task.kind, task.target, task.host, task.ips)
    return next(iter(refusals.values())) if refusals else None


def result_addresses(result):
    """The addresses a Sentinel's result names under the keys that carry the address it reached (``RESULT_KEYS``), at any depth."""
    out = []

    def walk(value, depth=0):
        if depth > 8:
            return
        if isinstance(value, dict):
            for key, item in value.items():
                if key in RESULT_KEYS:
                    out.extend(s for s in _strings(item) if _is_address_like(s))
                if key == 'ports' and isinstance(item, dict):
                    out.extend(k for k in item if isinstance(k, str) and _is_address_like(k))  # nmap / naabu: {address: [ports]}
                walk(item, depth + 1)
        elif isinstance(value, (list, tuple)):
            for item in value:
                walk(item, depth + 1)
    walk(result if isinstance(result, dict) else {})
    return list(dict.fromkeys(out))[:MAX_VALUES]


def result_refusal(task, result):
    """The ``Refusal`` for a result that is about to be stored (the task's own addresses again, and the addresses the result names), or None.
    For ``dns_resolve`` nothing is refused (the answers are kept); the names that resolved into the list are noted, see ``note_resolved``."""
    if task.kind in LOOKUP_ONLY:
        note_resolved(task, result)
        return None
    refusal = task_refusal(task)
    if refusal:
        return refusal
    refusals = _refusals(task.project_id, result_addresses(result))
    return next(iter(refusals.values())) if refusals else None


def _item_values(item):
    """The addresses one entry of a streamed batch (a finding, an http record, an event, a screenshot) says it reached: address literals under ``RESULT_KEYS``.
    Names are not judged here: a name seen in a batch is a record of what discovery learned (it keeps the host visible), and it carries no address."""
    out = []

    def walk(value, depth=0):
        if depth > 6:
            return
        if isinstance(value, dict):
            for key, inner in value.items():
                if key in RESULT_KEYS:
                    out.extend(s for s in _strings(inner) if _is_address_like(s))
                walk(inner, depth + 1)
        elif isinstance(value, (list, tuple)):
            for inner in value:
                walk(inner, depth + 1)
    walk(item)
    return out


def filter_batch(task, batch):
    """``(batch, dropped)``: the partial batch of a streamed task without the entries about an address on the list; with an unreadable list every entry
    that names an address is dropped. The sequence number still advances. One activity line says how many were dropped."""
    if not isinstance(batch, dict):
        return batch, 0
    dropped, kept = 0, {}
    for key, value in batch.items():
        if isinstance(value, list) and value and all(isinstance(i, dict) for i in value):
            refused = _refusals(task.project_id, [v for i in value for v in _item_values(i)])
            keep = [i for i in value if not any(v in refused for v in _item_values(i))]
            dropped += len(value) - len(keep)
            kept[key] = keep
        else:
            kept[key] = value
    if dropped:
        from cveFeed import activity
        activity.log('scan', f'Dropped {dropped} discovery result{"s" if dropped != 1 else ""} for addresses on the organization\'s do-not-scan list', project=task.project,
                     status='done', address_excluded=True, sentinel_task_id=task.pk, scan_id=task.scan_id)
    return kept, dropped


def note_resolved(task, result):
    """A ``dns_resolve`` result that placed names inside the list: one skip line for the names (they are not scanned from now on)."""
    resolved = result.get('resolved') if isinstance(result, dict) else None
    if not isinstance(resolved, dict):
        return
    refusals = _refusals(task.project_id, [n for n in resolved if isinstance(n, str)], {n.strip().lower().rstrip('.'): v for n, v in resolved.items() if isinstance(v, list)})
    if refusals:
        note_skipped(task.project, refusals, scan=task.scan, kind=task.kind)


def _first_time(project_id, value):
    """True the first time per ``NOTE_TTL`` this host is noted (the activity line says it once per host)."""
    try:
        from django.core.cache import cache
        return bool(cache.add(f'excluded-address-note:{project_id}:{value.lower()}', 1, NOTE_TTL))
    except Exception:  # noqa: BLE001 - a cache that is down writes the line again, never hides it
        return True


def note_skipped(project, refusals, scan=None, kind=''):
    """One activity line for the hosts skipped now, naming each host once (``Skipped 3 hosts that resolve to an address on the organization's do-not-scan list``)."""
    from cveFeed import activity
    project_id = _project_id(project)
    fresh = {v: r for v, r in refusals.items() if _first_time(project_id, v)}
    if not fresh:
        return None
    unreadable = [r for r in fresh.values() if getattr(r, 'unreadable', False)]
    if unreadable:
        message = f"Refused {kind or 'scan'} work: {unreadable[0]}"
    else:
        addresses = [v for v in fresh if _is_address_like(v)]
        names = [v for v in fresh if v not in addresses]
        parts = []
        if names:
            parts.append(f"Skipped {len(names)} host{'s' if len(names) != 1 else ''} that resolve{'s' if len(names) == 1 else ''} to an address on the organization's do-not-scan list")
        if addresses:
            parts.append(f"Skipped {len(addresses)} address{'es' if len(addresses) != 1 else ''} on the organization's do-not-scan list")
        message = '. '.join(parts)
    detail = {'address_excluded': True, 'hosts': sorted(fresh)[:50], 'work': kind or ''}
    if scan is not None and getattr(scan, 'id', None):
        detail['scan_id'] = scan.id
    return activity.log('scan', message, project=project, status='done', **detail)


def drop_result(task, refusal, ctx_user=None):
    """End ``task`` as failed, its result not stored, and say so (activity line, audit row). Returns the task."""
    from agentapi import sentinel_broker
    from agentapi.models import SentinelTask
    from cveFeed import activity
    from django.utils import timezone
    reason = f'result dropped: {refusal}'[:300]
    SentinelTask.objects.filter(pk=task.pk).update(status='failed', result={}, finished_at=timezone.now(), lease_expires_at=None, error=reason,
                                                   **sentinel_broker._scrubbed(task))
    activity.log('scan', f'Dropped a {task.kind} result: {refusal}', project=task.project, status='failed', address_excluded=True,
                 sentinel_task_id=task.pk, trace_id=task.trace_id, scan_id=task.scan_id)
    return task


def cancel_pending(org_id, actor=None, reason=None):
    """Cancel the queued and leased tasks of the org's projects that now name an address on the list (the list changed after they were created). Each is
    expired with a plain reason; a task that is already running is told to stop by its lease ending. Returns how many were cancelled."""
    from agentapi import sentinel_broker
    from agentapi.models import SentinelTask
    from dashboard.models import Project
    project_ids = list(Project._base_manager.filter(org_id=org_id).values_list('pk', flat=True))
    active = SentinelTask._base_manager.filter(project_id__in=project_ids, status__in=sentinel_broker.SENTINEL_ACTIVE_STATUSES).select_related('project')
    cancelled = 0
    for task in active:
        refusal = task_refusal(task)
        if refusal is None or getattr(refusal, 'unreadable', False):
            continue
        sentinel_broker.expire(task, reason=reason or f'cancelled: {refusal}', actor=actor)
        cancelled += 1
    if cancelled:
        logger.info('cancelled %s pending task(s) for org %s: their addresses are now on the do-not-scan list', cancelled, org_id)
    return cancelled
