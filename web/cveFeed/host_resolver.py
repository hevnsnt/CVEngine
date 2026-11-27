"""Which current-inventory host a finding is about: one answer for every place that groups, counts or links findings by host.

A finding names its host in one of three ways: a CVE match and a scanner finding hang on a host row (``subdomain``), a hygiene finding and a secret
store a name in ``host``, and a TLS or certificate finding stores the endpoint, ``name:port`` (one finding per endpoint: ``HygieneFinding`` is unique
per target, host and check, so the port is part of the key). The Hosts page shows one host per machine: the current inventory
(``correlation.latest_scan_q``), archived hosts left out (``counts.archived_host_q``), names on the same addresses folded into one host
(``agentapi.services._one_per_host``).

``Inventory(project_ids)`` reads that inventory once (``services.host_of_names``: two statements) and ``resolve(project_id, host)`` answers the host row
the Hosts page lists for ``host``: the name as given, else the name without its port. ``None`` means the name is not a host of the current inventory:
gone from the latest full scan (``gone_names``, closed by ``archive_closure.close_gone``), archived, or never a host at all (a DNS record name, a mail
domain with no host row of its own).

Situations, the Overview's Fix first list, the reports and the host counts read it, so a finding is never grouped under ``name:443`` or under a name the
inventory folds into another, and every link to a host opens a host that exists (``host_link``).
"""
import re

_PORT = re.compile(r'^(?P<name>.+):(?P<port>[0-9]{1,5})$')
_BRACKETED = re.compile(r'^\[(?P<name>[0-9a-f:.]+)\](?::[0-9]{1,5})?$')


def normalize(host):
    """``host`` as the inventory spells a name: lower case, no surrounding space, no trailing dot."""
    return str(host or '').strip().lower().rstrip('.')


def candidates(host):
    """The names ``host`` may stand for, best first: itself, then itself without a port (``mail.example.com:443`` is ``mail.example.com``,
    ``[2001:db8::1]:443`` is ``2001:db8::1``). A bare IPv6 address is never cut at its last colon."""
    name = normalize(host)
    if not name:
        return []
    bracketed = _BRACKETED.match(name)
    if bracketed:
        return [bracketed.group('name')]
    out = [name]
    match = _PORT.match(name)
    if match and ':' not in match.group('name'):
        out.append(normalize(match.group('name')))
    return out


def base_name(host):
    """``host`` without a port: the host name a finding about an endpoint is about."""
    names = candidates(host)
    return names[-1] if names else ''


def current_rows(project_ids):
    """The Subdomain rows the Hosts page lists the hosts of these projects from: the current inventory, archived hosts left out."""
    from cveFeed.correlation import latest_scan_q
    from cveFeed.counts import archived_host_q
    from startScan.models import Subdomain
    return Subdomain.objects.filter(latest_scan_q(), target_domain__project_id__in=list(project_ids)).filter(~archived_host_q())


def current_target_rows(domain):
    """The current-inventory rows of one target (``current_rows``), what a check that reads a target's hosts from stored data looks at: a name that
    dropped out of the latest full scan keeps its old rows, whose stored ports are not the host's any more."""
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain
    if not domain.project_id:
        return Subdomain.objects.filter(latest_scan_q(), target_domain=domain)
    return current_rows([domain.project_id]).filter(target_domain=domain)


def current_target_names(domain):
    """The lower-case names of ``current_target_rows``."""
    return {normalize(n) for n in current_target_rows(domain).values_list('name', flat=True).distinct()}


class Inventory:
    """The current-inventory hosts of some projects, by name (see the module text). ``hosts`` maps ``(project id, name)`` to
    ``{'id', 'name', 'pid'}`` of the host row the Hosts page shows, for every name of the inventory, aliases included."""

    def __init__(self, project_ids):
        from agentapi.services import host_of_names
        self.project_ids = sorted({int(i) for i in project_ids})
        self.hosts = {}
        if not self.project_ids:
            return
        for pid, name, rep_id, rep_name in host_of_names(current_rows(self.project_ids)):
            self.hosts[(pid, normalize(name))] = {'id': rep_id, 'name': rep_name, 'pid': pid}

    def resolve(self, project_id, host):
        """The host row (``{'id', 'name', 'pid'}``) the Hosts page lists for ``host`` in ``project_id``, or None."""
        for name in candidates(host):
            found = self.hosts.get((project_id, name))
            if found is not None:
                return found
        return None

    def names_of(self, rep_id):
        """Every inventory name folded into the host row ``rep_id``."""
        return sorted(name for (_pid, name), rep in self.hosts.items() if rep['id'] == rep_id)


def host_link(slug, rep):
    """The Hosts page link that opens ``rep`` (a resolved host): by its shown name, whether or not it is archived."""
    from urllib.parse import quote
    return f"/cve/{slug}/hosts/?host={quote(rep['name'], safe='')}"


GONE_MISSED_SCANS = 2  # successful full scans of its target in a row that must miss a name before its findings close as gone
GONE_AFTER_DAYS_DEFAULT = 7
DEEP_MARGIN_DAYS = 2  # past the deep discovery cadence: the daily sweep that queues the next deep run, and the run itself


def gone_after_days():
    """How many days a name must have been missing (since a scan last saw it) before its findings close as gone: ``CVENGINE_GONE_AFTER_DAYS``,
    but never less than the deep discovery cadence (``CVENGINE_TTL_BBOT_DEEP``, a week, ``tasks.deep_scan_apexes``) plus ``DEEP_MARGIN_DAYS``.

    Only the weekly deep discovery finds some names; the standard runs between deep ones miss them. With a grace no longer than the deep
    cadence, such a name closed as gone just before each deep run and reopened when it finished (``archive_closure.reopen_returned``), every
    week. A name that is really gone is missed by the deep run as well and still closes, with the defaults 9 days after it was last seen
    instead of 7."""
    import math
    import os

    from cveFeed import ledger
    try:
        days = max(0, int(os.environ.get('CVENGINE_GONE_AFTER_DAYS', GONE_AFTER_DAYS_DEFAULT)))
    except (TypeError, ValueError):
        days = GONE_AFTER_DAYS_DEFAULT
    return max(days, math.ceil(max(0, ledger.ttl('bbot-deep')) / 86400) + DEEP_MARGIN_DAYS)


def absent_names(project_ids, names_by_project, now=None):
    """``{(project id, name): {'last_seen', 'missed_scans', 'eligible'}}`` for the names (``names_by_project``: ``{project id: {name}}``, lower case,
    without ports) that were hosts of the project (they have a host row) but are not in its current inventory and not archived or excluded.

    ``eligible`` (the name is gone: its findings may close, ``archive_closure.close_gone``) needs all of: missed by at least ``GONE_MISSED_SCANS``
    successful full scans of each target that held it, counted after the newest scan that did; and missing for at least ``gone_after_days()`` days, from
    the time a scan last saw it (``HostState.last_seen``, the clock the inventory already keeps; the newest row's scan date when it has none). One lighter
    or passive full scan that finds fewer names never closes anything: the name is only absent, inside the grace period.

    Never absent at all: a name held by a target with no successful full scan (its rows all stay in the inventory) or a scan queued or running (started
    in the last three days), and a target's own name."""
    from collections import defaultdict
    from datetime import timedelta

    from django.db.models import Max
    from django.utils import timezone

    from cveFeed.archive_rediscovery import archived_names
    from cveFeed.discovery import HOST_PIPELINE_TASK
    from cveFeed.exclusions import excluded_names
    from cveFeed.models import HostState
    from startScan.models import ScanHistory, Subdomain
    from targetApp.models import Domain
    now = now or timezone.now()
    out = {}
    wanted = {pid: {normalize(n) for n in names} for pid, names in names_by_project.items() if names and pid in set(project_ids)}
    if not wanted:
        return out
    pids = sorted(wanted)
    full_scans = defaultdict(list)  # target -> ids of its successful full scans
    for scan_id, domain_id in (ScanHistory.objects.filter(domain__project_id__in=pids, scan_status=2).exclude(tasks__contains=[HOST_PIPELINE_TASK])
                               .values_list('id', 'domain_id')):
        full_scans[domain_id].append(scan_id)
    busy = set(ScanHistory.objects.filter(domain__project_id__in=pids, scan_status__in=(-1, 1),
                                          start_scan_date__gte=now - timedelta(days=3)).values_list('domain_id', flat=True))
    targets = {}
    for pid, domain_id, name in Domain.objects.filter(project_id__in=pids).values_list('project_id', 'id', 'name'):
        targets.setdefault(pid, set()).add(normalize(name))
        if domain_id in busy:
            full_scans.pop(domain_id, None)
    current = {(pid, normalize(n)) for pid, n in current_rows(pids).values_list('target_domain__project_id', 'name')}
    rows = (Subdomain.objects.filter(target_domain__project_id__in=pids).values('target_domain__project_id', 'name', 'target_domain_id')
            .annotate(last=Max('discovered_date'), last_scan=Max('scan_history_id'), scan_date=Max('scan_history__start_scan_date')).order_by())
    seen, missed, unsettled = {}, {}, set()
    for row in rows:
        pid, name = row['target_domain__project_id'], normalize(row['name'])
        if name not in wanted[pid]:
            continue
        key = (pid, name)
        scans = full_scans.get(row['target_domain_id'])
        if not scans:
            unsettled.add(key)  # a target whose inventory no finished full scan decides holds it: never absent
            continue
        after = sum(1 for scan_id in scans if scan_id > (row['last_scan'] or 0))  # full scans of this target since the newest one that held the name
        missed[key] = after if key not in missed else min(missed[key], after)
        when = max(d for d in (row['last'], row['scan_date']) if d) if (row['last'] or row['scan_date']) else None
        if when and (seen.get(key) is None or when > seen[key]):
            seen[key] = when
        seen.setdefault(key, None)
    states = {(pid, host): last for pid, host, last in HostState.objects.filter(project_id__in=pids, host__in={n for _p, n in seen})
              .values_list('project_id', 'host', 'last_seen')}
    banned = {pid: (archived_names(pid), excluded_names(pid, names_only=True)) for pid in pids}
    grace = timedelta(days=gone_after_days())
    for key, last in seen.items():
        pid, name = key
        archived, excluded = banned[pid]
        if key in current or key in unsettled or name in targets.get(pid, ()) or name in archived or name in excluded:
            continue
        last_seen = states.get(key) or last
        out[key] = {'last_seen': last_seen, 'missed_scans': missed[key],
                    'eligible': missed[key] >= GONE_MISSED_SCANS and last_seen is not None and last_seen <= now - grace}
    return out


def gone_names(project_ids, names_by_project, now=None):
    """``{(project id, name): last seen}``: the names of ``absent_names`` that are gone (``eligible``)."""
    return {key: info['last_seen'] for key, info in absent_names(project_ids, names_by_project, now=now).items() if info['eligible']}
