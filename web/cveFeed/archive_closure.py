"""Archiving a host closes what is open on it, and restoring it reopens exactly that.

An archived host is out of scan scheduling, so nothing would ever close its findings: its open CVE matches, scanner findings and hygiene
findings stayed open in every count, list and report. Now archiving closes them, and bringing the host back reopens them.

* **What a person archives** is the host the Hosts page shows: the name and the other names of the project that point at the same addresses
  (``agentapi.host_manage.host_group_names``). Those names are archived with it (``archive_aliases``: reason ``Archived with <name>``, a pinned
  one is left out), or the next name of the group would stand in its place in every list. Restoring any of them restores the group
  (``restore_aliases``). An automatic archive (``inactive_archive``, ``unresolved_archive``, ``tailscale_sync``) is about one name that is gone:
  it archives and closes that name only, never a sibling that still answers.
* **Close** (``close_host``): every open or in-progress CVE match (not one the AI ruled out), scanner finding still reported (``open_status``)
  and hygiene finding still found (``status`` open) of those names in the host's project. Never another project's host of the same name. Each is set
  ``fixed`` (the status that means the issue is gone; the host is) with no ``remediation_by``, and its note starts with ``ARCHIVED`` and says
  when, by whom or why, and which host was archived: "Closed automatically: the host was archived on 2026-11-21 by alice
  (survey.example.com)." A note a person had written stays below that line. ``closure.closure_of`` reads it back as an automatic closure.
  Every closure gets an audit event (``by: host_archive``) and the host one activity line. One transaction per host, at most ``MAX_ROWS`` rows
  of each kind.
* **Reopen** (``reopen_host``): a restore by a person, the daily rediscovery (``archive_rediscovery``), a scan that finds the host again
  (``changes``) or a Tailscale device that comes back reopens only the findings that archiving that host closed: still ``fixed``, still nobody's
  (``remediation_by`` empty), first line still the archive closure naming that host. A finding a person closed before the archive was never
  closed by it; one a person changed after it is theirs. Each goes back to the status it had (open or in progress, from its audit event), the
  person's own note is kept, and the next scan confirms or closes it as usual.
* **The next scan** also undoes an archive closure by itself, in case a host returns some other way: a new scan's CVE match does not inherit it
  (``correlation._carry_remediation``), a scanner finding reported again reopens (``finding_lifecycle.seen_again``) and a hygiene check that
  finds the issue again reopens it (``hygiene.store_findings``), each only once the host is no longer archived (``reopens_on_sight``). A person's
  own fixed status still sticks.

Manual and automatic archives otherwise behave the same: an archived host is out of every count either way (``counts.archived_host_q``), and every
route back reopens what was closed. ``backfill`` closes the open findings of hosts archived before this existed (``manage.py close_archived_findings``,
an upgrade backfill), each name on its own: it archives no sibling name.
"""
import logging
import re
from functools import reduce
from operator import or_

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from cveFeed.closure import AUTOMATIC, NOTE_MAX, prepend_note

logger = logging.getLogger(__name__)

ARCHIVED = AUTOMATIC + ' the host was archived'  # every archive closure's note starts with this (the marker)
GONE = AUTOMATIC + ' the host is no longer in the current inventory'  # a closure because the host left the inventory (``close_gone``)
PREFIXES = (ARCHIVED, GONE)  # the closures this module makes, and reopens
HOST_CLOSED = AUTOMATIC + ' the host '  # what both of them start with
REOPENED = 'Reopened automatically: the host was restored'
RETURNED = 'Reopened automatically: the host is back in the current inventory'
BY_ARCHIVE, BY_RESTORE, BY_GONE = 'host_archive', 'host_restore', 'host_gone'  # the ``by`` of the audit events
MAX_GONE = 500  # gone host names one ``close_gone`` pass closes
GONE_EVERY = 3600  # seconds between two ``close_gone`` passes of a project from its hygiene runs (``close_gone_due``)
FINISHED = (0, 2, 3)  # failed, success, aborted: the scans whose end can change what is gone
LIVE = ('open', 'in_progress')  # the statuses an archive closes; a closed finding is left as it is
KINDS = ('match', 'vulnerability', 'hygiene')
MAX_ROWS = 5000  # rows of each kind one host's closure or reopening touches
BATCH = 500
BACKFILL_PAGE = 200
# why an automatic archive happened, as the closure note says it
WHY_GONE = 'it was no longer found'
WHY_UNRESOLVED = 'it did not resolve to a scannable address'
WHY_TAILNET = 'the device left the tailnet'
WITH = 'Archived with '  # the archive reason of a name archived together with the host a person archived (``archive_aliases``)


def closure_note(host, when, who='', why=''):
    """The line an archive closure starts the note with: when, by whom (a person) or why (automatic), and which host."""
    day = timezone.localtime(when).date().isoformat() if timezone.is_aware(when) else when.date().isoformat()
    if who:
        text = f'{ARCHIVED} on {day} by {who}'
    else:
        text = f'{ARCHIVED} automatically on {day}' + (f' because {why}' if why else '')
    return f'{text} ({host}).'


def is_archive_closed(obj, host=None):
    """Whether ``obj`` (a CVE match, scanner or hygiene finding) is still closed because its host was archived or left the inventory (``host``, when
    given): fixed, by nobody, with that closure as the first line of its note. A person who changed it since made it theirs."""
    note = obj.remediation_note or ''
    if obj.remediation_status != 'fixed' or getattr(obj, 'remediation_by_id', None) is not None or not note.startswith(PREFIXES):
        return False
    return host is None or note.split('\n', 1)[0].endswith(f' ({host}).')


def still_archived(project_id, host):
    """Whether ``host`` (a name, or ``name:port``) is archived in project ``project_id`` now: an archive closure then stays closed whatever a scan
    reports, until the host comes back."""
    from cveFeed.models import HostState
    name = (host or '').lower().rstrip('.')
    if ':' in name and name.rsplit(':', 1)[1].isdigit():
        name = name.rsplit(':', 1)[0]
    return bool(project_id and name) and HostState.objects.filter(project_id=project_id, host=name, archived_at__isnull=False).exists()


def reopens_on_sight(obj, project_id, host):
    """Whether a scan or check that reports ``obj`` again reopens it as an archive closure: it is one (``is_archive_closed``) and its host is no
    longer archived (``still_archived``)."""
    return is_archive_closed(obj) and not still_archived(project_id, host)


def _names_q(field, names):
    return reduce(or_, (Q(**{f'{field}__iexact': n}) for n in names))


def _querysets(project_id, names):
    """``{kind: queryset}``: every CVE match, scanner finding and hygiene finding of these host names in this project (any status). A scanner finding
    filed against the bare host (no host row) is matched by its URL, a certificate finding (host ``name:port``) by its name."""
    from agentapi.host_manage import _url_host_pattern
    from cveFeed.models import CVEMatch, HygieneFinding
    from startScan.models import Vulnerability
    orphans = reduce(or_, (Q(http_url__iregex=_url_host_pattern(n)) for n in names))
    ports = reduce(or_, (Q(host__iregex=r'^' + re.escape(n) + r':[0-9]+$') for n in names))
    return {
        'match': CVEMatch._base_manager.filter(subdomain__target_domain__project_id=project_id).filter(_names_q('subdomain__name', names)),
        'vulnerability': Vulnerability._base_manager.filter(
            Q(subdomain__target_domain__project_id=project_id, subdomain__isnull=False) & _names_q('subdomain__name', names)
            | Q(subdomain__isnull=True, target_domain__project_id=project_id) & orphans),
        'hygiene': HygieneFinding.objects.filter(domain__project_id=project_id).filter(_names_q('host', names) | ports),
    }


def _live(kind, qs):
    qs = qs.filter(remediation_status__in=LIVE)
    if kind == 'match':
        return qs.exclude(ai_verdict='not_affected')  # ruled out by the AI: already closed, automatically
    if kind == 'vulnerability':
        return qs.filter(open_status=True)
    return qs.filter(status='open')


_FIELDS = ('remediation_status', 'remediation_note', 'remediation_by', 'remediation_updated_at')


def _locked(qs):
    return list(qs.select_for_update(of=('self',)).only('pk', *_FIELDS).order_by('pk')[:MAX_ROWS])


def host_names(project_id, host, aliases=True):
    """``host`` and, with ``aliases``, every other name of the project on the same addresses (lower case)."""
    name = host.lower().rstrip('.')
    if not aliases:
        return [name]
    from agentapi.host_manage import host_group_names
    return host_group_names(project_id, name)


def _after_write(project_id, names):
    from cveFeed import scoring, snapshot_cache
    snapshot_cache.bump_on_commit()  # the counts on the live screen change with this commit
    transaction.on_commit(lambda: scoring.rescore_quietly(project_id, list(names)))


def archive_aliases(project, host, when, by_user=True):
    """Archive the other names of ``host``'s group in ``project`` with it (see the module text): a name not archived yet gets reason ``Archived with
    <host>``; a pinned name is left alone. Returns ``host`` and the names of the group that are archived now, the names whose findings close."""
    from cveFeed.models import HostState
    from startScan.models import Subdomain
    name = host.lower().rstrip('.')
    out = [name]
    for alias in host_names(project.pk, name):
        if alias == name:
            continue
        sub = Subdomain.objects.filter(target_domain__project=project, name__iexact=alias).select_related('target_domain').order_by('-id').first()
        if sub is None:
            continue
        state, _ = HostState.objects.get_or_create(project=project, host=alias, defaults={'domain': sub.target_domain})
        if state.pinned:
            continue
        if not state.archived_at:
            state.archived_at, state.archive_reason, state.archived_by_user, state.archive_check_status = when, (WITH + name)[:300], by_user, ''
            state.save(update_fields=['archived_at', 'archive_reason', 'archived_by_user', 'archive_check_status'])
        out.append(alias)
    return out


def primary_of(state):
    """The name a person archived when ``state``'s name was archived with it (``archive_aliases``), else ``state``'s own name."""
    reason = state.archive_reason or ''
    return reason[len(WITH):].strip().lower() if reason.startswith(WITH) and len(reason) > len(WITH) else state.host


def restore_aliases(project_id, host):
    """Lift the archive of the names archived with ``host`` (``archive_aliases``). Returns their names."""
    from cveFeed.models import HostState
    rows = HostState.objects.filter(project_id=project_id, archived_at__isnull=False, archive_reason=(WITH + host.lower().rstrip('.'))[:300])
    names = list(rows.values_list('host', flat=True))
    rows.update(archived_at=None, archive_reason='', archived_by_user=False, inactive_first_absent_at=None, inactive_last_absent_at=None,
                inactive_absent_checks=0, unresolved_first_at=None, unresolved_last_at=None, unresolved_checks=0)
    return names


def pending(project_id, host, aliases=False):
    """``{kind: n}``: what ``close_host`` would close now (a dry run)."""
    names = host_names(project_id, host, aliases)
    return {kind: _live(kind, qs).count() for kind, qs in _querysets(project_id, names).items()}


def close_host(project_id, host, *, user=None, who='', why='', when=None, aliases=False, names=None):
    """Close every open finding of ``host`` in project ``project_id`` because the host was archived (see the module text): of ``names`` when given
    (a person's archive: the names ``archive_aliases`` archived with it), else of ``host`` (and, with ``aliases``, its group). ``user``: the person
    who archived it (named in the note and the audit trail), else ``why`` says why it was archived automatically. Idempotent: a closed finding is not
    touched again. Returns ``{kind: n closed}``."""
    when = when or timezone.now()
    name = host.lower().rstrip('.')
    names = sorted({n.lower().rstrip('.') for n in names} | {name}) if names else host_names(project_id, name, aliases)
    who = who or (user.get_username() if user is not None else '')
    return _close(project_id, name, names, closure_note(name, when, who=who, why=why), BY_ARCHIVE, user, 'the host was archived')


def _close_kind(kind, qs, project_id, line, by, user, now):
    """Close the live rows of one kind (``qs``, already live and of these names) in keyset batches of ``BATCH``, at most ``MAX_ROWS``: each batch
    is one locking read of the ids, one UPDATE that puts ``line`` on top of the note, and one INSERT of the audit events. Rows used to be loaded
    whole and written back with a CASE per row. A note too long to keep whole under the line goes through ``prepend_note`` row by row, as before."""
    from django.db.models import Case, F, TextField, Value, When
    from django.db.models.functions import Concat, Length
    from cveFeed.models import FindingAuditEvent
    model = qs.model
    room = NOTE_MAX - len(line) - 1  # the longest note that fits whole under the line (closure.prepend_note keeps it as it is)
    after = {'status': 'fixed', 'note': line, 'by': by}
    closed, last = 0, 0
    while closed < MAX_ROWS:
        size = min(BATCH, MAX_ROWS - closed)
        batch = list(qs.filter(pk__gt=last).select_for_update(of=('self',)).order_by('pk')
                     .values_list('pk', 'remediation_status', Length('remediation_note'))[:size])
        if not batch:
            break
        last = batch[-1][0]
        fits = [pk for pk, _status, length in batch if (length or 0) <= room]
        if fits:
            model._base_manager.filter(pk__in=fits).update(
                remediation_status='fixed', remediation_by=None, remediation_updated_at=now,
                remediation_note=Case(When(remediation_note='', then=Value(line)), default=Concat(Value(line + '\n'), F('remediation_note')),
                                      output_field=TextField()))
        if len(fits) < len(batch):  # a person's note below is never cut (closure.prepend_note)
            rows = list(model._base_manager.filter(pk__in=[pk for pk, *_ in batch if pk not in set(fits)]).only('pk', *_FIELDS))
            for row in rows:
                row.remediation_status, row.remediation_by, row.remediation_updated_at = 'fixed', None, now
                row.remediation_note = prepend_note(line, row.remediation_note)
            model._base_manager.bulk_update(rows, list(_FIELDS), batch_size=BATCH)
        FindingAuditEvent.objects.bulk_create([FindingAuditEvent(project_id=project_id, finding_kind=kind, finding_id=pk, event='status', actor=user,
                                                                 before={'status': status}, after=after) for pk, status, _length in batch],
                                              batch_size=BATCH)
        closed += len(batch)
        if len(batch) < size:
            break
    return closed


def _close(project_id, name, names, line, by, user, why):
    """Close the live findings of ``names`` in the project with ``line`` as the first line of the note (see ``close_host``)."""
    from cveFeed import activity
    now = timezone.now()
    done = dict.fromkeys(KINDS, 0)
    with transaction.atomic():
        for kind, qs in _querysets(project_id, names).items():
            done[kind] = _close_kind(kind, _live(kind, qs), project_id, line, by, user, now)
        if any(done.values()):
            _after_write(project_id, names)
            total = sum(done.values())
            activity.log('remediation', f'{total} open finding{"s" if total != 1 else ""} on {name} closed: {why}',
                         project=project_id, host=name, names=names[:20], after='fixed', **{k: v for k, v in done.items() if v})
    return done


def _reopen_sources(project_id, mine):
    """``{kind: queryset}``: the findings of the project that ``mine`` selects, as a reopening reads them (a scanner finding of the bare host too)."""
    from cveFeed.models import CVEMatch, HygieneFinding
    from startScan.models import Vulnerability
    return {
        'match': CVEMatch._base_manager.filter(mine, subdomain__target_domain__project_id=project_id),
        'vulnerability': Vulnerability._base_manager.filter(mine).filter(Q(subdomain__target_domain__project_id=project_id)
                                                                          | Q(subdomain__isnull=True, target_domain__project_id=project_id)),
        'hygiene': HygieneFinding.objects.filter(mine, domain__project_id=project_id),
    }


def closed_host(note, prefixes=PREFIXES):
    """The host the first line of ``note`` names when that line is a closure of this module (one of ``prefixes``), ending ``(name).``, else None.
    The same test as ``reopen_host``'s note pattern, read in Python so one read serves every host of a scan."""
    first = (note or '').split('\n', 1)[0]
    if not first.startswith(prefixes) or not first.endswith(').'):
        return None
    cut = first.rfind(' (')
    return first[cut + 2:-2] if cut >= 0 else None


def _reopen(project_id, planned, user):
    """Reopen the locked rows of ``planned`` (``{kind: [(row, host, line)]}``): each to the status it had before (its audit event), ``line`` on top
    of its own note. One audit event per row and one activity line per host. Returns ``{host: {kind: n}}``."""
    from cveFeed import activity, host_resolver
    from cveFeed.models import CVEMatch, FindingAuditEvent, HygieneFinding
    from startScan.models import Vulnerability
    done, lines = {}, {}
    touched = set()
    for kind, items in planned.items():
        if not items:
            continue
        rows = [row for row, _host, _line in items]
        earlier = {}
        for finding_id, before in (FindingAuditEvent.objects.filter(project_id=project_id, finding_kind=kind, finding_id__in=[r.pk for r in rows],
                                                                   event='status', after__by__in=(BY_ARCHIVE, BY_GONE))
                                   .order_by('finding_id', '-created_at', '-id').values_list('finding_id', 'before')):
            earlier.setdefault(finding_id, (before or {}).get('status'))
        events = []
        for row, host, line in items:
            status = earlier.get(row.pk) if earlier.get(row.pk) in LIVE else 'open'
            rest = row.remediation_note.split('\n', 1)[1] if '\n' in row.remediation_note else ''
            row.remediation_status, row.remediation_by, row.remediation_updated_at = status, None, timezone.now()
            row.remediation_note = prepend_note(line, rest)
            events.append(FindingAuditEvent(project_id=project_id, finding_kind=kind, finding_id=row.pk, event='status', actor=user,
                                            before={'status': 'fixed'}, after={'status': status, 'note': line, 'by': BY_RESTORE}))
            done.setdefault(host, dict.fromkeys(KINDS, 0))[kind] += 1
            lines[host] = line
            touched.add(host)
        type(rows[0])._base_manager.bulk_update(rows, list(_FIELDS), batch_size=BATCH)
        FindingAuditEvent.objects.bulk_create(events, batch_size=BATCH)
        if kind == 'hygiene':
            touched |= {host_resolver.base_name(h) for h in HygieneFinding.objects.filter(pk__in=[r.pk for r in rows]).values_list('host', flat=True)}
        else:
            model = CVEMatch if kind == 'match' else Vulnerability
            touched |= {n.lower() for n in model._base_manager.filter(pk__in=[r.pk for r in rows], subdomain__isnull=False)
                        .values_list('subdomain__name', flat=True)}
    if done:
        _after_write(project_id, touched)
        for host, counts in done.items():
            total, line = sum(counts.values()), lines[host]
            activity.log('remediation', f'{total} finding{"s" if total != 1 else ""} on {host} reopened: {line[len("Reopened automatically: "):].rstrip(".")}',
                         project=project_id, host=host, after='open', **{k: v for k, v in counts.items() if v})
    return done


def reopen_host(project_id, host, *, user=None, when=None, prefixes=PREFIXES, line=None):
    """Reopen what archiving ``host`` closed in project ``project_id`` (its aliases' findings included, whatever their addresses are now): each to
    the status it had before, its own note kept. Idempotent. Returns ``{kind: n reopened}``."""
    name = host.lower().rstrip('.')
    when = when or timezone.now()
    day = timezone.localtime(when).date().isoformat()
    line = line or f'{REOPENED} on {day}.'
    first_line = r'^(' + '|'.join(re.escape(p) for p in prefixes) + r')[^\n]* \(' + re.escape(name) + r'\)\.(\n|$)'
    mine = Q(remediation_status='fixed', remediation_by__isnull=True, remediation_note__regex=first_line)
    with transaction.atomic():
        planned = {kind: [(row, name, line) for row in _locked(qs)] for kind, qs in _reopen_sources(project_id, mine).items()}
        done = _reopen(project_id, planned, user)
    return done.get(name, dict.fromkeys(KINDS, 0))


def reopen_scan(project_id, restored=(), seen=()):
    """What a finished scan reopens (``changes``), from one read of the project's host closures per kind: what archiving each host of ``restored``
    closed (``reopen_host``: the scan lifted its archive), then what closed as gone for the names of ``seen`` (every host the scan holds) that are
    back (``reopen_returned``). The same rows, statuses and notes as ``reopen_host`` once per restored host and then ``reopen_returned``, which ran
    three regular expression reads per restored host and three more reads per scan. One transaction. Returns ``{host: {kind: n}}``."""
    from cveFeed import host_resolver
    restored = {h.lower().rstrip('.') for h in restored if h}
    wanted = {host_resolver.normalize(n) for n in seen if n}
    if not restored and not wanted:
        return {}
    day = timezone.localdate().isoformat()
    back, returned = f'{REOPENED} on {day}.', f'{RETURNED} on {day}.'
    closed_by_host = Q(remediation_status='fixed', remediation_by__isnull=True, remediation_note__startswith=HOST_CLOSED)
    read = {}
    for kind, qs in _reopen_sources(project_id, closed_by_host).items():
        read[kind] = sorted(qs.values_list('pk', 'remediation_note', 'host' if kind == 'hygiene' else 'subdomain__name'))
    gone = set()  # the names whose findings closed as gone (reopen_returned): a hygiene row's host without its port, a host row's name
    for kind, rows in read.items():
        for _pk, note, own in rows:
            if own and note.startswith(GONE):
                gone.add(host_resolver.base_name(own) if kind == 'hygiene' else host_resolver.normalize(own))
    back_again = gone & wanted
    plan = {}
    for kind, rows in read.items():
        taken = {}
        for pk, note, _own in rows:
            host = closed_host(note)
            if host in restored:
                line = back
            elif host in back_again and note.startswith(GONE):
                line = returned
            else:
                continue
            if taken.get(host, 0) >= MAX_ROWS:  # as reopen_host: at most MAX_ROWS rows of each kind per host
                continue
            taken[host] = taken.get(host, 0) + 1
            plan.setdefault(kind, {})[pk] = (host, line)
    if not plan:
        return {}
    with transaction.atomic():
        planned = {}
        for kind, wanted_rows in plan.items():
            rows = list(_model(kind)._base_manager.filter(pk__in=list(wanted_rows), remediation_status='fixed', remediation_by__isnull=True)
                        .select_for_update(of=('self',)).only('pk', *_FIELDS).order_by('pk'))  # capped per host above
            planned[kind] = []
            for row in rows:  # read again under the lock: a row a person or another run changed meanwhile is left alone
                host, line = wanted_rows[row.pk]
                if closed_host(row.remediation_note, PREFIXES if line == back else (GONE,)) == host:
                    planned[kind].append((row, host, line))
        return _reopen(project_id, planned, None)


def _model(kind):
    from cveFeed.models import CVEMatch, HygieneFinding
    from startScan.models import Vulnerability
    return {'match': CVEMatch, 'vulnerability': Vulnerability, 'hygiene': HygieneFinding}[kind]


def reopen_quietly(project_id, host, user=None):
    """``reopen_host`` for a pipeline (a scan, the rediscovery, a Tailscale sync): never raises."""
    try:
        return reopen_host(project_id, host, user=user)
    except Exception:  # the host is back either way; its findings reopen at its next scan
        logger.exception('could not reopen the archive-closed findings of %s in project %s', host, project_id)
        return dict.fromkeys(KINDS, 0)


def close_quietly(project_id, host, why=''):
    """``close_host`` for an automatic archive: never raises (archiving the host again closes what stayed open)."""
    try:
        return close_host(project_id, host, why=why)
    except Exception:  # the host is archived either way, and out of every list and count
        logger.exception('could not close the open findings of archived host %s in project %s', host, project_id)
        return dict.fromkeys(KINDS, 0)


def gone_note(host, last_seen):
    """The first line of a closure because ``host`` left the current inventory."""
    day = (timezone.localtime(last_seen) if timezone.is_aware(last_seen) else last_seen).date().isoformat() if last_seen else ''
    return f'{GONE}' + (f', last seen {day}' if day else '') + f' ({host}).'


def _names_with_live_findings(project_ids):
    """``{project id: {host name}}``: the names (without a port) that hold an open finding of any kind in these projects."""
    from cveFeed import host_resolver
    from cveFeed.models import CVEMatch, HygieneFinding
    from startScan.models import Vulnerability
    out = {}
    pids = list(project_ids)
    for pid, host in _live('hygiene', HygieneFinding.objects.filter(domain__project_id__in=pids)).values_list('domain__project_id', 'host').distinct():
        out.setdefault(pid, set()).add(host_resolver.base_name(host))
    for model, kind, path in ((CVEMatch, 'match', 'subdomain__target_domain__project_id'), (Vulnerability, 'vulnerability', 'subdomain__target_domain__project_id')):
        qs = _live(kind, model._base_manager.filter(**{f'{path}__in': pids}, subdomain__isnull=False))
        for pid, name in qs.values_list(path, 'subdomain__name').distinct():
            out.setdefault(pid, set()).add(host_resolver.normalize(name))
    return out


def gone_hosts(project_ids=None):
    """``{(project id, name): last seen}``: the names with an open finding that were hosts of their project and are gone from its current inventory
    (``host_resolver.gone_names``: missed by two successful full scans of their target in a row and for ``CVENGINE_GONE_AFTER_DAYS`` days; never because
    a scan failed, is still running or found fewer names once), at most ``MAX_GONE``."""
    from cveFeed import host_resolver
    from dashboard.models import Project
    pids = list(Project.objects.values_list('id', flat=True)) if project_ids is None else list(project_ids)
    found = host_resolver.gone_names(pids, _names_with_live_findings(pids))
    return dict(sorted(found.items(), key=lambda kv: (kv[0][0], kv[0][1]))[:MAX_GONE])


def close_gone(project_ids=None, apply=True):
    """Close the open findings of every host that left the current inventory (``gone_hosts``), as fixed, the note saying so and when it was last seen;
    each name on its own, one transaction each. They reopen when the name is back (``reopen_returned``, and a scan or check that reports them again).
    Idempotent. Returns ``{'hosts', 'match', 'vulnerability', 'hygiene', 'projects': {project id: {...}}}``."""
    out = {'hosts': 0, **dict.fromkeys(KINDS, 0), 'projects': {}}
    for (pid, name), last in gone_hosts(project_ids).items():
        done = _close(pid, name, [name], gone_note(name, last), BY_GONE, None, 'the host is no longer in the current inventory') if apply else \
            pending(pid, name)
        if not any(done.values()):
            continue
        out['hosts'] += 1
        per = out['projects'].setdefault(pid, {'hosts': 0, **dict.fromkeys(KINDS, 0)})
        per['hosts'] += 1
        for kind in KINDS:
            out[kind] += done[kind]
            per[kind] += done[kind]
    return out


def close_gone_due(project_id):
    """Whether a hygiene run of project ``project_id`` runs ``close_gone`` now. It recomputed the whole project on every hygiene run of every target
    (the daily sweep queues up to 500 of them on the queue the work conductor runs on), and its answer only changes when a scan of the project
    finishes or as time passes: so at most once per ``GONE_EVERY`` seconds, and again as soon as another scan of the project has finished. A
    cache that cannot answer lets it run."""
    from django.core.cache import cache
    from django.db.models import Count, Max
    from startScan.models import ScanHistory
    try:
        mark = ScanHistory.objects.filter(domain__project_id=project_id, scan_status__in=FINISHED).aggregate(n=Count('id'), top=Max('id'))
        return bool(cache.add(f'cvengine:close-gone:{project_id}:{mark["n"]}:{mark["top"]}', 1, timeout=GONE_EVERY))
    except Exception:  # noqa: BLE001 - run it, as before
        logger.exception('could not read the close_gone throttle of project %s', project_id)
        return True


def close_gone_quietly(project_ids):
    """``close_gone`` for a pipeline (the hygiene run): never raises."""
    try:
        return close_gone(project_ids)
    except Exception:  # a finding left open is closed at the next run
        logger.exception('could not close the findings of hosts gone from the inventory of projects %s', project_ids)
        return None


def reopen_returned(project_id, names):
    """The names among ``names`` that are back in the project's inventory and had their findings closed as gone: reopen those (``RETURNED``).
    Returns how many findings reopened."""
    try:
        done = reopen_scan(project_id, (), names)
    except Exception:  # the next scan that reports a finding again reopens it
        logger.exception('could not reopen the findings of hosts back in project %s', project_id)
        return 0
    return sum(sum(counts.values()) for counts in done.values())


def _archived_by(state):
    """Who archived ``state``'s host, as the admin audit log recorded it (a person's archive), or ''."""
    from dashboard.models import AuditLog
    row = (AuditLog.objects.filter(action='host.archive', detail__host=state.host, detail__project=state.project.slug)
           .order_by('-id').values_list('actor_name', flat=True).first())
    return row or ''


def automatic_why(reason):
    """Why an automatic archive happened, in the words of a closure note, from the reason stored on the host."""
    text = (reason or '').lower()
    if 'scannable ip' in text or 'resolv' in text:
        return WHY_UNRESOLVED
    if 'tailnet' in text or 'tailscale' in text:
        return WHY_TAILNET
    return WHY_GONE


def backfill(apply=False, page=BACKFILL_PAGE):
    """Close the open findings of every host that is archived now, as an archive does today (``manage.py close_archived_findings``). Bounded (a page
    of hosts at a time, ``MAX_ROWS`` rows of each kind per host) and idempotent (a closed finding no longer counts as open). Returns
    ``{'hosts': archived hosts with something open, 'match': n, 'vulnerability': n, 'hygiene': n}``."""
    from cveFeed.models import HostState
    out = {'hosts': 0, **dict.fromkeys(KINDS, 0)}
    last = 0
    while True:
        rows = list(HostState.objects.filter(archived_at__isnull=False, pk__gt=last).select_related('project').order_by('pk')[:page])
        if not rows:
            break
        last = rows[-1].pk
        for state in rows:
            found = pending(state.project_id, state.host)
            if not any(found.values()):
                continue
            out['hosts'] += 1
            if apply:
                who = (_archived_by(state) or 'a project user') if state.archived_by_user else ''
                found = close_host(state.project_id, state.host, who=who, why='' if who else automatic_why(state.archive_reason),
                                   when=state.archived_at)
            for kind in KINDS:
                out[kind] += found[kind]
    return out
