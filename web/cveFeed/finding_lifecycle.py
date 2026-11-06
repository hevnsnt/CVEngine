"""One finding, one row, for as long as it lives: rescans update it, copies fold into it, a fixed version closes it.

Scanner findings (startScan.models.Vulnerability) are filed under a scan's own host row, so every scan used to make a new row for a finding
it saw again, and the earlier scans' rows stayed open beside it (the same advisories open eight times on one host). A hygiene finding is
filed under a target, so a host covered by two targets of one project had each finding twice. Four rules keep that from happening:

* **Upsert.** A scanner finding seen again is the same row, moved onto the scan that saw it (``earlier_copy``, called by
  ``reNgine.tasks.save_vulnerability``): the same project, host name, source, template, name, URL and matcher. Its first-seen date, status,
  note, assignee, comments, audit trail and AI triage stay with it. A hygiene finding a second target finds on the same host updates the row the
  first target filed (cveFeed.hygiene.store_findings).
* **Duplicates.** Rows filed before this existed are merged by ``manage.py dedupe_findings`` (dry run by default): the row that stays
  is the copy in the host's current scan, which takes the earliest first-seen date, the status a person set and the assignee from the
  others, and every other live copy is closed with a note that names it (``DUPLICATE``).
* **Redirect aliases.** A host whose every front page only redirects permanently (301 or 308) to another host of the project
  (www to the apex) serves nothing of its own: a finding it shares with that host is the host's finding, and the alias's copy is closed
  with a note that names both (``ALIAS``, ``fold_aliases``). A finding only the alias has stays open. A name that is a CNAME has no mail
  of its own (its MX is its target's), so the email checks skip it (cveFeed.hygiene.email_domains).
* **Fixed versions.** A later WPScan of the same host that reads a component at or past an advisory's fixed version closes that
  advisory's row as fixed, automatically, with the scan and the version it read (``close_fixed_wpscan_rows``).

None of this touches a finding a person closed, set in progress or reopened by hand, and a closure the engine made itself is marked so
(``cveFeed.closure.AUTOMATIC``) and read back as ``closed_automatically``. An engine closure as fixed is undone when a later scan reports the
finding again; a person's fixed status is not (it sticks, as before).
"""
import logging
import re

from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone

from cveFeed.closure import AUTOMATIC, CLOSED

logger = logging.getLogger(__name__)

DUPLICATE = AUTOMATIC + ' duplicate of'
ALIAS = AUTOMATIC + ' redirect alias.'
FIXED_VERSION = AUTOMATIC + ' fixed version read.'
FOLDED = (DUPLICATE, ALIAS)  # a copy the engine folded into another row: it stays closed when a scan sees it again
REOPENED_NOTE = 'Reopened automatically: a later scan reports this again.'

# what makes two scanner rows the same finding, besides the project and the host name (reNgine.tasks.VULNERABILITY_KEY without the scan's
# own rows: target, scan, host row and endpoint)
IDENTITY = ('source', 'template_id', 'name', 'http_url', 'matcher_name')
LOCATION = ('target_domain', 'scan_history', 'subdomain', 'endpoint')
EARLIER_CANDIDATES = 20


def _note(text):
    return text[:2000]


def is_folded(vuln):
    """A scanner row the engine closed as a copy of another (a duplicate or a redirect alias's copy)."""
    return vuln.open_status is False and (vuln.remediation_note or '').startswith(FOLDED)


def engine_fixed(obj):
    """A finding the engine closed as fixed on a version it read (never one a person closed)."""
    return (obj.remediation_status == 'fixed' and obj.remediation_by_id is None
            and (obj.remediation_note or '').startswith(FIXED_VERSION))


def person_worked(obj):
    """A person set its status (any status but open, or open with their name on it) or wrote a note: the engine leaves its status alone."""
    return obj.remediation_status != 'open' or obj.remediation_by_id is not None


def _identity_q(lookup):
    q = Q()
    for key in IDENTITY:
        value = lookup.get(key)
        q &= Q(**{key: value}) if value not in (None, '') else (Q(**{f'{key}__isnull': True}) | Q(**{key: ''}))
    return q


def earlier_copy(lookup):
    """The row of the same finding filed earlier on this host in this project (another scan's, or another target's copy), or None: the
    row a scan that sees the finding again moves onto its own host row. One query. A copy the engine folded is taken only when no live one
    exists (it then stays folded); a copy whose status a person set wins over one nobody touched, so their decision is what the host keeps."""
    from startScan.models import Vulnerability
    sub, domain = lookup.get('subdomain'), lookup.get('target_domain')
    if sub is None or domain is None or not getattr(sub, 'name', None):
        return None
    scope = Q(target_domain__project_id=domain.project_id) if domain.project_id else Q(target_domain=domain)
    rows = list(Vulnerability._base_manager.filter(scope, _identity_q(lookup), subdomain__name=sub.name)
                .order_by('-id')[:EARLIER_CANDIDATES])
    if not rows:
        return None
    # a live copy before a folded one; among those, the one a person decided on (what the next scan used to inherit from it), then the newest
    return max(rows, key=lambda row: (not is_folded(row), row.remediation_status != 'open', row.id))


def move_onto(row, lookup, defaults):
    """Move ``row`` onto the scan, host row and target of ``lookup`` and refresh its evidence from ``defaults``. Returns False when the move
    would collide with a row filed meanwhile (the caller then creates as before)."""
    for key in LOCATION:
        setattr(row, key, lookup.get(key))
    for key, value in defaults.items():
        if key != 'discovered_date':  # the first time it was seen stays
            setattr(row, key, value)
    seen_again(row)
    try:
        with transaction.atomic():
            row.save()
    except IntegrityError:
        return False
    return True


def seen_again(row):
    """A scan reports ``row`` again: it is open (a copy the engine folded stays folded), and an engine closure as fixed is undone, since
    the version it rested on is back. Returns the changed field names; a person's status is never touched."""
    changed = []
    if is_folded(row):
        return changed
    if not row.open_status:
        row.open_status = True
        changed.append('open_status')
    if engine_fixed(row):
        row.remediation_status, row.remediation_updated_at = 'open', timezone.now()
        row.remediation_note = _note(f'{REOPENED_NOTE}\n{row.remediation_note}')
        changed += ['remediation_status', 'remediation_updated_at', 'remediation_note']
    return changed


# --------------------------------------------------------------------------------------------------- fixed versions (WPScan)

_FIXED_IN = re.compile(r'\bFixed in ([0-9][0-9A-Za-z.\-]*?)\.(?:\s|$)')


def _version_key(value):
    from cveFeed.correlation import parse_version
    parsed = parse_version(value)
    if parsed is None:
        return None
    parts = list(parsed)
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def wpscan_versions(report):
    """``{component label: version}`` for every component a WPScan report read a version of: the labels cveFeed.wpscan_scan files its rows
    under (``WordPress``, ``WordPress plugin <slug>``, ``WordPress theme <slug>``)."""
    out = {}
    core = str(((report.get('version') or {}).get('number')) or '')
    if core:
        out['WordPress'] = core
    theme = report.get('main_theme') or {}
    if theme.get('slug') and (theme.get('version') or {}).get('number'):
        out[f'WordPress theme {theme["slug"]}'] = str(theme['version']['number'])
    for kind, items in (('plugin', report.get('plugins')), ('theme', report.get('themes'))):
        for slug, info in (items or {}).items():
            number = ((info or {}).get('version') or {}).get('number') if isinstance(info, dict) else None
            if number:
                out[f'WordPress {kind} {slug}'] = str(number)
    return out


def _row_version(name, component):
    """The version a stored WPScan row's name gives for ``component`` ("WordPress 6.5.2: title", "WordPress 6.5.2 is outdated ..."), or ''."""
    if not name.startswith(component + ' '):
        return ''
    rest = name[len(component) + 1:]
    match = re.match(r'([0-9][0-9A-Za-z.\-]*?)(?::\s|\s+is outdated\b)', rest)
    return match.group(1) if match else ''


def close_fixed_wpscan_rows(scan, sub, report, seen=None):
    """Close as fixed the open WPScan rows of this host (every target and scan of the project) that the version this report read is not
    affected by: an advisory whose stated fixed version is at or below it, and an "outdated" row once the component is no longer outdated.
    A row for an older version of a component that this report still names at its new version (the same advisory, still not fixed) is the
    same finding as the new row and is closed as its duplicate. A component the report has no version for proves nothing and is left alone,
    and so is every row a person set. ``seen`` is ``{name: id}`` of the rows this report just saved. Returns the rows closed. At most three
    queries, however many rows."""
    if sub is None or scan.domain is None:
        return 0
    when = timezone.now().date().isoformat()
    return close_fixed_for_host(scan.domain, sub.name, report, seen=seen, read_in=f'in scan #{scan.pk} on {when}')['closed']


def close_fixed_for_host(domain, host, report, seen=None, read_in='', apply=True, judge_outdated=True):
    """``close_fixed_wpscan_rows`` for ``host`` in ``domain``'s project, from a WPScan ``report`` (or one rebuilt from the versions WPScan
    last stored, ``stored_wpscan_report``). ``read_in`` says where the version was read, for the note. ``judge_outdated`` False leaves the
    "outdated" rows alone (a rebuilt report does not know what WPScan called outdated). Returns ``{'closed', 'folded'}``; with ``apply``
    False nothing is written and the counts are what would be."""
    from startScan.models import Vulnerability
    versions = wpscan_versions(report)
    seen = seen or {}
    if not versions or domain is None or not host:
        return {'closed': 0, 'folded': 0}
    still_outdated = {component for component, _info in _outdated_components(report)}
    # the template ids cveFeed.wpscan_scan.persist_report files them under
    templates = {'wpscan:' + c[:150] for c in versions} | ({'wpscan:' + f'{c} outdated'[:150] for c in versions} if judge_outdated else set())
    scope = Q(target_domain__project_id=domain.project_id) if domain.project_id else Q(target_domain=domain)
    rows = (Vulnerability._base_manager.filter(scope, subdomain__name=host, source='wpscan', template_id__in=templates, open_status=True,
                                               remediation_status='open', remediation_by__isnull=True)
            .exclude(pk__in=list(seen.values())).only('id', 'name', 'template_id', 'description'))
    now = timezone.now()
    close, folded = {}, {}
    rows = list(rows)
    seen = {**{row.name: row.pk for row in rows if _row_version(row.name, row.template_id[len('wpscan:'):]) == versions.get(
        row.template_id[len('wpscan:'):])}, **seen}  # an open row at the version just read is the current one too (a backfill saves none)
    current = set(seen.values())
    for row in rows:
        if row.pk in current:
            continue
        template = row.template_id[len('wpscan:'):]
        outdated = template.endswith(' outdated') and template[:-len(' outdated')] in versions
        component = template[:-len(' outdated')] if outdated else template
        read = versions.get(component)
        old = _row_version(row.name, component)
        if not read or not old or _version_key(old) is None or _version_key(read) is None:
            continue
        if outdated:
            if component in still_outdated or _version_key(read) <= _version_key(old):
                continue
            why = f'{component} {read} is no longer reported as outdated (this finding was {component} {old})'
        else:
            fixed = _FIXED_IN.search(row.description or '')
            if not fixed or _version_key(fixed.group(1)) is None or _version_key(read) < _version_key(fixed.group(1)):
                title = row.name[len(component) + 1 + len(old):].lstrip(': ')
                newer = seen.get(f'{component} {read}: {title}'[:500]) if read != old else None
                if newer:  # the same advisory, still open at the version just read: that row is the finding now
                    folded.setdefault(newer, []).append(row.pk)
                continue
            why = f'{component} {read} is at or past the fixed version {fixed.group(1)} (this finding was {component} {old})'
        note = _note(f'{FIXED_VERSION} {why}: read by WPScan on {host}' + (f' {read_in}' if read_in else '') + '.')
        close.setdefault(note, []).append(row.pk)
    if apply:
        for note, ids in close.items():
            Vulnerability._base_manager.filter(pk__in=ids, remediation_status='open', remediation_by__isnull=True).update(
                remediation_status='fixed', remediation_note=note, remediation_updated_at=now)
        for keeper, ids in folded.items():
            Vulnerability._base_manager.filter(pk__in=ids, remediation_status='open', remediation_by__isnull=True).update(
                open_status=False, remediation_note=duplicate_note(
                    'scanner finding', keeper, 'the same WPScan advisory, read again at a newer version' + (f' {read_in}' if read_in else '')))
    return {'closed': sum(len(ids) for ids in close.values()), 'folded': sum(len(ids) for ids in folded.values())}


def stored_wpscan_report(project_id, host):
    """A WPScan report rebuilt from the versions WPScan last stored for ``host`` (cveFeed.wpscan_scan.record_components): the core, plugin
    and theme versions it read, and when. ``(report, observed_at)``; the report is empty when nothing was stored."""
    from cveFeed.models import ProbeObservation
    report, when = {}, None
    for row in ProbeObservation.objects.filter(project_id=project_id, host=host.lower(), source='wpscan',
                                               probe__in=('wpscan-core', 'wpscan-plugin', 'wpscan-theme')).exclude(version=''):
        when = max(when, row.observed_at) if when and row.observed_at else (row.observed_at or when)
        if row.probe == 'wpscan-core':
            report['version'] = {'number': row.version}
        else:
            key = 'plugins' if row.probe == 'wpscan-plugin' else 'themes'
            report.setdefault(key, {})[row.product] = {'version': {'number': row.version}}
    return report, when


def duplicate_note(kind, keeper_id, why):
    """The note on a copy the engine closed as a duplicate of ``keeper_id`` (it names the row that stays)."""
    return _note(f'{DUPLICATE} {kind} #{keeper_id}: {why}.')


def alias_note(kind, keeper_id, host, target):
    """The note on a redirect alias's copy of a finding its target host has."""
    return _note(f'{ALIAS} {host} only redirects (301/308) to {target}, which has the same finding as {kind} #{keeper_id}; it is tracked there.')


def _outdated_components(report):
    out = []
    version = report.get('version') or {}
    if version.get('status') == 'outdated' and version.get('number'):
        out.append(('WordPress', version))
    theme = report.get('main_theme') or {}
    if theme.get('slug') and theme.get('outdated'):
        out.append((f'WordPress theme {theme["slug"]}', theme))
    for kind, items in (('plugin', report.get('plugins')), ('theme', report.get('themes'))):
        for slug, info in (items or {}).items():
            if isinstance(info, dict) and info.get('outdated'):
                out.append((f'WordPress {kind} {slug}', info))
    return out


# --------------------------------------------------------------------------------------------------- merging duplicates (backfill)

def _worked_status(obj):
    return obj.remediation_status != 'open' or obj.remediation_by_id is not None or bool((obj.remediation_note or '').strip())


def _absorb(keeper, dup):
    """Give ``keeper`` what a person set on ``dup`` that it lacks (status with its note, who and when; the assignee). Returns the changed
    field names, or None when the two disagree (each has its own status, or its own assignee): that copy is then left open for a person."""
    changed = []
    if _worked_status(dup):
        if _worked_status(keeper):
            if (keeper.remediation_status, keeper.remediation_note) != (dup.remediation_status, dup.remediation_note):
                return None
        else:
            keeper.remediation_status, keeper.remediation_note = dup.remediation_status, dup.remediation_note
            keeper.remediation_by_id, keeper.remediation_updated_at = dup.remediation_by_id, dup.remediation_updated_at
            changed += ['remediation_status', 'remediation_note', 'remediation_by', 'remediation_updated_at']
    if dup.assignee_id is not None:
        if keeper.assignee_id is None:
            keeper.assignee_id = dup.assignee_id
            changed.append('assignee')
        elif keeper.assignee_id != dup.assignee_id:
            return None
    return changed


def _repoint_history(project_id, kind, keeper_id, dup_ids):
    """The comments and audit events of the merged copies move to the row that stays, so its history is the whole finding's."""
    from cveFeed.models import FindingAuditEvent, FindingComment
    for model in (FindingComment, FindingAuditEvent):
        model.objects.filter(project_id=project_id, finding_kind=kind, finding_id__in=dup_ids).update(finding_id=keeper_id)


def _norm(value):
    return value or ''


def _live_vulnerability(row):
    return bool(row.open_status) and row.remediation_status not in CLOSED


def dedupe_vulnerabilities(project, apply=False):
    """Merge the scanner findings of ``project`` filed more than once (the same host name, source, template, name, URL and matcher, from
    several scans or targets). For each such finding with more than one live copy (open, not closed by a person), the copy that stays is the
    one in the host's current scan (the newest scan's copy there; else the oldest live one): it takes the earliest first-seen date and, when it has none
    of its own, the status, note and assignee a person set on another copy, plus every copy's comments and audit trail; every other live copy
    is closed with a note naming it. A copy a person worked differently is left open (``conflicts``). Closed and gone copies are not touched.
    Returns ``{'groups', 'closed', 'conflicts'}``; nothing is written unless ``apply``."""
    from cveFeed.correlation import latest_scan_q
    from startScan.models import Subdomain, Vulnerability
    current = set(Subdomain.objects.filter(latest_scan_q(), target_domain__project=project).values_list('id', flat=True))
    rows = (Vulnerability._base_manager.filter(target_domain__project=project, subdomain__isnull=False)
            .select_related('subdomain').order_by('id')
            .only('id', 'subdomain__name', 'subdomain', 'scan_history', 'source', 'template_id', 'name', 'http_url', 'matcher_name', 'open_status',
                  'remediation_status', 'remediation_note', 'remediation_by', 'remediation_updated_at', 'assignee', 'discovered_date'))
    groups = {}
    for row in rows.iterator(chunk_size=2000):
        key = (row.subdomain.name.lower(), _norm(row.source), _norm(row.template_id), row.name, _norm(row.http_url), _norm(row.matcher_name))
        groups.setdefault(key, []).append(row)
    out = {'groups': 0, 'closed': 0, 'conflicts': 0}
    for copies in groups.values():
        live = [row for row in copies if _live_vulnerability(row) and not is_folded(row)]
        if len(live) < 2:
            continue
        out['groups'] += 1
        in_current = [row for row in live if row.subdomain_id in current]
        keeper = max(in_current, key=lambda row: (row.scan_history_id or 0, row.id)) if in_current else live[0]
        first_seen = min((row.discovered_date for row in copies if row.discovered_date), default=None)
        changed, merged = [], []
        for dup in [row for row in live if row is not keeper]:
            absorbed = _absorb(keeper, dup)
            if absorbed is None:
                out['conflicts'] += 1
                continue
            changed += absorbed
            merged.append(dup)
        if first_seen and keeper.discovered_date != first_seen:
            keeper.discovered_date = first_seen
            changed.append('discovered_date')
        out['closed'] += len(merged)
        if not apply or not merged:
            continue
        with transaction.atomic():
            if changed:
                keeper.save(update_fields=sorted(set(changed)))
            for dup in merged:
                Vulnerability._base_manager.filter(pk=dup.pk).update(open_status=False, remediation_note=duplicate_note(
                    'scanner finding', keeper.pk, 'the same finding on the same host, filed again by another scan or target'))
            _repoint_history(project.pk, 'vulnerability', keeper.pk, [dup.pk for dup in merged])
    return out


def _live_hygiene(row):
    return row.status == 'open' and row.remediation_status not in CLOSED


def dedupe_hygiene(project, apply=False):
    """Merge the hygiene findings of ``project`` filed under more than one target for the same host and check (the TLS, certificate, email
    and cleartext checks of cveFeed.hygiene.run_hygiene, the ones it now files once). The oldest live copy stays
    (with the others' comments, audit trail and, when it has none, a person's status and assignee); every other live copy is resolved with a
    note naming it. Returns ``{'groups', 'closed', 'conflicts'}``; nothing is written unless ``apply``."""
    from cveFeed.models import HygieneFinding
    groups = {}
    # the tailnet, the TLS audit, cloud storage and UDP checks file under a target of their own choosing (cveFeed.hygiene.store_findings)
    for row in HygieneFinding.objects.filter(domain__project=project).exclude(check_name__regex=r'^(ts|tlsa|bkt|udp)_').order_by('id').only(
            'id', 'host', 'check_name', 'status', 'remediation_status', 'remediation_note', 'remediation_by', 'remediation_updated_at',
            'assignee', 'first_seen'):
        groups.setdefault((row.host.lower(), row.check_name), []).append(row)
    out = {'groups': 0, 'closed': 0, 'conflicts': 0}
    now = timezone.now()
    for copies in groups.values():
        live = [row for row in copies if _live_hygiene(row)]
        if len(live) < 2:
            continue
        out['groups'] += 1
        keeper, changed, merged = live[0], [], []
        for dup in live[1:]:
            absorbed = _absorb(keeper, dup)
            if absorbed is None:
                out['conflicts'] += 1
                continue
            changed += absorbed
            merged.append(dup)
        out['closed'] += len(merged)
        if not apply or not merged:
            continue
        with transaction.atomic():
            if changed:
                keeper.save(update_fields=sorted(set(changed)))
            for dup in merged:
                HygieneFinding.objects.filter(pk=dup.pk).update(status='resolved', resolved_at=now, remediation_note=duplicate_note(
                    'hygiene finding', keeper.pk, 'the same check on the same host, filed under another target of this project'))
            _repoint_history(project.pk, 'hygiene', keeper.pk, [dup.pk for dup in merged])
    return out


# --------------------------------------------------------------------------------------------------- redirect aliases

def alias_map(project_id, names=None, now=None):
    """``(aliases, plain)`` for the project's current hosts with a fresh front-page reading (``names`` limits it): ``aliases`` maps each host
    that only redirects permanently to another host the project inventories (cveFeed.js_libraries.redirect_alias_of: every web port's root
    answered 301 or 308, at least one to another host) to that host, following a chain of aliases to its end; ``plain`` holds the hosts read
    to serve something of their own. A host with no fresh reading is in neither. Four queries."""
    from datetime import timedelta

    from cveFeed.correlation import latest_scan_q
    from cveFeed.js_libraries import FRESH_DAYS, _origin, redirect_alias_of
    from cveFeed.models import RouteAuth
    from cveFeed.route_auth import web_bases
    from startScan.models import Subdomain
    cutoff = (now or timezone.now()) - timedelta(days=FRESH_DAYS)
    roots = RouteAuth.objects.filter(project_id=project_id, path='/', checked_at__gte=cutoff)
    if names is not None:
        roots = roots.filter(host__in={n.lower() for n in names})
    by_host = {}
    for row in roots.only('host', 'url', 'http_status', 'redirect_to', 'checked_at').order_by('checked_at'):
        try:
            by_host.setdefault(row.host.lower(), {})[_origin(row.url)] = row  # the newest reading of each web port
        except ValueError:
            continue
    if not by_host:
        return {}, set()
    current = Subdomain.objects.filter(latest_scan_q(), target_domain__project_id=project_id)
    bases = {}
    for sub in current.filter(name__in=list(by_host)).prefetch_related('ip_addresses__ports'):
        bases.setdefault(sub.name.lower(), []).extend(web_bases(sub, limit=None))
    found, plain = {}, set()
    for host, rows in by_host.items():
        if host not in bases:
            continue  # not in the project's current inventory
        target = redirect_alias_of([(r.url, r.http_status, r.redirect_to) for r in rows.values()], host, bases[host] or None)
        if target:
            found[host] = target
        elif bases[host] and {_origin(b) for b in bases[host]} <= set(rows):
            plain.add(host)  # every web port's front page was read, and it is not only a redirect
    if not found:
        return {}, plain
    known = {n.lower() for n in current.filter(name__in=set(found.values())).values_list('name', flat=True)}
    aliases = {}
    for host, target in found.items():
        seen = {host}
        while target in found and target not in seen:  # www -> example.net -> example.com: fold into the end of the chain
            seen.add(target)
            target = found[target]
        if target in known and target not in seen:
            aliases[host] = target
    return aliases, plain


def _split_port(host):
    name, sep, port = host.rpartition(':')
    return (name, sep + port) if sep and port.isdigit() else (host, '')


def host_name(host):
    """The host name of a hygiene finding's host (``name`` or ``name:port``), lower case."""
    return _split_port((host or '').lower())[0]


def fold_aliases(project_id, names=None, apply=True, now=None):
    """Fold the findings of the project's redirect aliases (``alias_map``) into their target hosts: an open scanner finding of the alias
    (same source, template and name) or hygiene finding (same check on the same port; for a certificate check, the same certificate expiry)
    that the target host also has is closed with a note that names the target's row. A finding only the alias has stays open, and so does
    one a person set or was assigned. A copy folded earlier whose host now serves a page of its own is reopened. ``names`` limits the work to
    those hosts (a scan's); returns ``{'aliases', 'vulnerability', 'hygiene', 'reopened'}``, and writes nothing unless ``apply``."""
    from cveFeed.models import HygieneFinding
    from startScan.models import Vulnerability
    aliases, plain = alias_map(project_id, names, now)
    out = {'aliases': len(aliases), 'vulnerability': 0, 'hygiene': 0, 'reopened': 0}
    touched = set()
    if aliases:
        targets = set(aliases.values())
        counterpart = {}
        for row in (Vulnerability._base_manager.filter(target_domain__project_id=project_id, subdomain__name__in=targets)
                    .only('id', 'subdomain', 'subdomain__name', 'source', 'template_id', 'name', 'open_status', 'remediation_status', 'remediation_note')
                    .select_related('subdomain').order_by('id')):
            if is_folded(row) or not (row.open_status or row.remediation_status in CLOSED):
                continue
            counterpart[(row.subdomain.name.lower(), _norm(row.source), _norm(row.template_id), row.name)] = row.pk  # the newest one
        fold = {}
        for row in (Vulnerability._base_manager.filter(target_domain__project_id=project_id, subdomain__name__in=list(aliases), open_status=True,
                                                       remediation_status='open', remediation_by__isnull=True, assignee__isnull=True)
                    .only('id', 'subdomain', 'subdomain__name', 'source', 'template_id', 'name').select_related('subdomain')):
            host = row.subdomain.name.lower()
            keeper = counterpart.get((aliases[host], _norm(row.source), _norm(row.template_id), row.name))
            if keeper:
                fold.setdefault((keeper, host), []).append(row.pk)
        out['vulnerability'] = sum(len(ids) for ids in fold.values())
        hyg = HygieneFinding.objects.filter(domain__project_id=project_id).only(
            'id', 'host', 'check_name', 'evidence', 'status', 'remediation_status', 'remediation_note', 'remediation_by', 'assignee')
        target_rows, alias_rows = {}, []
        for row in hyg.order_by('id'):
            name, port = _split_port(row.host.lower())
            if name in targets and (row.status == 'open' or row.remediation_status in CLOSED) and not (row.remediation_note or '').startswith(FOLDED):
                target_rows[(name + port, row.check_name)] = row
            if (name in aliases and _live_hygiene(row) and row.remediation_status == 'open' and row.remediation_by_id is None
                    and row.assignee_id is None):
                alias_rows.append((row, aliases[name] + port, name))
        hfold = {}
        for row, target_host, host in alias_rows:
            keeper = target_rows.get((target_host, row.check_name))
            if keeper is None:
                continue
            if row.check_name.startswith('tls_'):
                mine, theirs = (row.evidence or {}).get('not_after'), (keeper.evidence or {}).get('not_after')
                if mine != theirs:
                    continue  # another certificate: the alias's own finding
            hfold.setdefault((keeper.pk, host), []).append(row.pk)
        out['hygiene'] = sum(len(ids) for ids in hfold.values())
        if apply:
            stamp = now or timezone.now()
            for (keeper, host), ids in fold.items():
                Vulnerability._base_manager.filter(pk__in=ids, open_status=True, remediation_status='open', remediation_by__isnull=True).update(
                    open_status=False, remediation_note=alias_note('scanner finding', keeper, host, aliases[host]))
                touched.add(host)
            for (keeper, host), ids in hfold.items():
                HygieneFinding.objects.filter(pk__in=ids, status='open', remediation_status='open', remediation_by__isnull=True).update(
                    status='resolved', resolved_at=stamp, remediation_note=alias_note('hygiene finding', keeper, host, aliases[host]))
                touched.add(host)
    if plain:  # an alias that serves a page of its own again: what was folded for it is its own finding again
        again_v = Vulnerability._base_manager.filter(target_domain__project_id=project_id, subdomain__name__in=list(plain), open_status=False,
                                                     remediation_note__startswith=ALIAS)
        again_h = [row.pk for row in HygieneFinding.objects.filter(domain__project_id=project_id, status='resolved',
                                                                   remediation_note__startswith=ALIAS).only('id', 'host')
                   if _split_port(row.host.lower())[0] in plain]
        out['reopened'] = again_v.count() + len(again_h)
        if apply and out['reopened']:
            touched |= set(again_v.values_list('subdomain__name', flat=True))
            again_v.update(open_status=True, remediation_note='')
            HygieneFinding.objects.filter(pk__in=again_h).update(status='open', resolved_at=None, remediation_note='')
            touched |= {_split_port(h.lower())[0] for h in HygieneFinding.objects.filter(pk__in=again_h).values_list('host', flat=True)}
    if apply and touched:
        from cveFeed import scoring
        hosts = sorted(touched)
        for i in range(0, len(hosts), scoring.CHUNK):
            scoring.rescore_quietly(project_id, hosts[i:i + scoring.CHUNK])
    return out


def fold_aliases_quietly(project_id, names=None):
    """``fold_aliases`` from a pipeline stage: never fatal to it."""
    if not project_id:
        return None
    try:
        return fold_aliases(project_id, names)
    except Exception:  # noqa: BLE001
        logger.exception('could not fold the redirect aliases of project %s', project_id)
        return None
