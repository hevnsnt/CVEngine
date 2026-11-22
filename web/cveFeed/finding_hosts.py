"""Do the open findings point at hosts of the current inventory? The audit behind ``manage.py audit_finding_hosts`` and the system status check.

Every open CVE match, scanner finding and hygiene finding is put in one class by what ``host_resolver`` makes of the host it names:

* ``ok``: the name is a host of the current inventory as it stands (one current row, shown under its own name).
* ``port`` (cause A): the finding names an endpoint, ``name:port`` (certificate and TLS findings), and the name is a host.
* ``alias`` (cause B): the name is a host only through the collapse: it is folded into another name on the same addresses, or it has more than one
  current row (a scanless row beside the scanned one, the same name under two targets), so a lookup of one of its rows could miss the host.
* ``gone`` (cause C): the name was a host of the project and is not in the current inventory (``host_resolver.gone_names``). ``--apply`` closes these
  (``archive_closure.close_gone``); they reopen when the name is back.
* ``archived``: the host is archived and the finding is still open (archived before archiving closed findings). ``--apply`` closes these too
  (``archive_closure.backfill``).
* ``not_a_host``: the name never was a host row of the project (a DNS record or mail domain name): reported, never closed.

``ok``, ``port`` and ``alias`` need nothing: every place that groups, counts or links by host reads ``host_resolver``. A CVE match or scanner finding is
counted on its current host row; the copies on older scans' rows are not findings anyone sees and are left out, unless the name has no current row.
"""
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

CLASSES = ('ok', 'port', 'alias', 'gone', 'archived', 'not_a_host')
UNRESOLVED = ('gone', 'archived', 'not_a_host')
CACHE_KEY, CACHE_SECONDS = 'cvengine:finding-hosts:audit', 1800


def _rows(pids):
    """``[(kind, project id, host as stored, n, current)]``: the open findings grouped by the host they name. ``current`` says the CVE match or
    scanner finding hangs on a current-inventory row (a hygiene finding has no row: ``None``)."""
    from django.db.models import Count

    from cveFeed import archive_closure
    from cveFeed.correlation import latest_scan_q
    from cveFeed.models import CVEMatch, HygieneFinding
    from startScan.models import Vulnerability
    out = []
    hygiene = archive_closure._live('hygiene', HygieneFinding.objects.filter(domain__project_id__in=pids))
    for pid, host, n in hygiene.values_list('domain__project_id', 'host').annotate(n=Count('id')).order_by():
        out.append(('hygiene', pid, host, n, None))
    for model, kind in ((CVEMatch, 'match'), (Vulnerability, 'vulnerability')):
        live = archive_closure._live(kind, model._base_manager.filter(subdomain__target_domain__project_id__in=pids, subdomain__isnull=False))
        current = live.filter(latest_scan_q('subdomain__'))
        for flag, qs in ((True, current), (False, live)):
            for pid, name, n in qs.values_list('subdomain__target_domain__project_id', 'subdomain__name').annotate(n=Count('id')).order_by():
                out.append((kind, pid, name, n, flag))
    return out


def audit(project_ids=None):
    """``{'projects': {project id: {class: n}}, 'totals': {class: n}, 'unresolved': n, 'samples': {class: [(project id, host)]}}`` over the open
    findings of ``project_ids`` (every project when None). A handful of grouped queries and one read of the inventory."""
    from cveFeed import host_resolver
    from cveFeed.archive_rediscovery import archived_names
    from dashboard.models import Project
    pids = sorted(Project.objects.values_list('id', flat=True)) if project_ids is None else sorted(project_ids)
    out = {'projects': {}, 'totals': dict.fromkeys(CLASSES, 0), 'unresolved': 0, 'samples': defaultdict(list)}
    if not pids:
        return out
    inventory = host_resolver.Inventory(pids)
    copies = defaultdict(int)
    for pid, name in host_resolver.current_rows(pids).values_list('target_domain__project_id', 'name'):
        copies[(pid, host_resolver.normalize(name))] += 1
    rows = _rows(pids)
    archived = {pid: archived_names(pid) for pid in pids}
    unresolved_names = defaultdict(set)
    resolved_rows, pending = [], []
    for kind, pid, host, n, current in rows:
        found = inventory.resolve(pid, host)
        if kind != 'hygiene' and found is not None and not current:
            continue  # an older scan's copy of a host that is current: no one sees it
        if kind != 'hygiene' and found is None and current is True:
            continue  # counted below with every copy of a name that is not a host
        if found is None:
            unresolved_names[pid].add(host_resolver.base_name(host))
            pending.append((kind, pid, host, n))
        else:
            resolved_rows.append((pid, host, n, found))
    gone = host_resolver.gone_names(pids, unresolved_names)

    def count(pid, cls, n, host):
        per = out['projects'].setdefault(pid, dict.fromkeys(CLASSES, 0))
        per[cls] += n
        out['totals'][cls] += n
        if len(out['samples'][cls]) < 10 and (pid, host) not in out['samples'][cls]:
            out['samples'][cls].append((pid, host))

    for pid, host, n, found in resolved_rows:
        name = host_resolver.normalize(host)
        if (pid, name) not in inventory.hosts:
            cls = 'port'
        elif found['name'].lower() != name or copies[(pid, name)] > 1:
            cls = 'alias'
        else:
            cls = 'ok'
        count(pid, cls, n, host)
    for _kind, pid, host, n in pending:
        base = host_resolver.base_name(host)
        cls = 'archived' if base in archived[pid] else 'gone' if (pid, base) in gone else 'not_a_host'
        count(pid, cls, n, host)
    out['unresolved'] = sum(out['totals'][c] for c in UNRESOLVED)
    out['samples'] = dict(out['samples'])
    return out


def fix(project_ids=None):
    """Close what the audit calls ``archived`` and ``gone`` (the other classes need no change). Returns ``{'archived': {...}, 'gone': {...}}``."""
    from cveFeed import archive_closure
    archived = archive_closure.backfill(apply=True) if project_ids is None else {'hosts': 0}
    return {'archived': archived, 'gone': archive_closure.close_gone(project_ids)}


def status_check(problems):
    """The system status line: how many open findings point at hosts not in the inventory (``audit``, kept for ``CACHE_SECONDS``)."""
    from django.core.cache import cache
    try:
        found = cache.get(CACHE_KEY)
    except Exception:  # noqa: BLE001 - an unreadable cache: counted now
        found = None
    if found is None:
        result = audit()
        found = {'totals': result['totals'], 'unresolved': result['unresolved']}
        try:
            cache.set(CACHE_KEY, found, CACHE_SECONDS)
        except Exception:  # counted again next time
            logger.debug('could not keep the finding hosts audit', exc_info=True)
    closable = found['totals'].get('gone', 0) + found['totals'].get('archived', 0)
    if closable:
        problems.append(f"{closable} open finding{'s' if closable != 1 else ''} point at hosts not in the inventory (gone from the latest full scan or "
                        "archived); python3 manage.py audit_finding_hosts --apply closes them")
    return found
