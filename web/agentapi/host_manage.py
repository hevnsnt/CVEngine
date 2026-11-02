"""Host management: editable asset information, "Delete host data" (one project) and "Remove & exclude" (the whole organization).

Both removals are destructive, so each runs in one transaction, needs write access (get_project(..., write=True): an audit
role or a read-only token gets 403) and only ever touches projects the caller may write to. A host is matched by its WHOLE name,
case-insensitively: never a suffix or a substring, so ``provider.example`` leaves ``notprovider.example`` and
``www.provider.example`` alone.

* ``delete_host``: this project only. The host can be rediscovered by a later scan.
* ``move_host``: hands the host to another project the caller can write to. It is added there as a target and scanned
  from scratch, its data is deleted from this project, and a HostMove keeps this project from bringing it back.
* ``exclude_host``: removes the host from every project of the organization the caller can write to, and records a
  HostExclusion so no discovery or scanner ever brings it back anywhere in the organization (see cveFeed.exclusions). That
  changes what the other projects of the org scan, so it needs an organization-level role (or an App Admin), not just a role in
  one project. ``with_aliases`` also takes the other names the host answers to (the Hosts page shows names on the same addresses
  as one host, so excluding only the name on display makes the next one take its place). ``include_subdomains`` excludes a whole
  domain: the name, every name under it and the targets named like them (``-example.com`` in Add targets).
"""
import os
import re
import time

from django.db import transaction
from django.db.models import Q

from agentapi.services import ApiError, get_one_project, get_project
from tenancy import roles

HOST_RE = re.compile(r'^[a-z0-9_]([a-z0-9._:-]*[a-z0-9_])?$')
MAX_OWNER, MAX_PURPOSE, MAX_REASON = 200, 500, 300
PURGE_ATTEMPTS, PURGE_RETRY_SECONDS = 4, 2  # a removal retried while scans already under way finish writing (see _purge_settled)
MOVE_LIST_MAX = 50  # host names a whole-target refusal lists
PUBLIC_SUFFIX_RE = re.compile(r'^(com|net|org|edu|gov|co|ac|or|ne|go)\.[a-z]{2}$')  # co.uk, com.au ...: never a whole-domain exclusion


def clean_host(value):
    """The comparable host name for ``value`` or a 400. Exact names only: a wildcard or a pattern is refused."""
    from cveFeed.exclusions import normalize
    name = normalize(str(value or ''))
    if not name:
        raise ApiError(400, 'host is required')
    if '*' in name or '%' in name or not HOST_RE.match(name):
        raise ApiError(400, 'host must be one exact host name or IP address (no wildcards or patterns)')
    return name


def clean_pattern(value):
    """The domain for a whole-domain exclusion (``example.com`` or ``*.example.com``) or a 400: a real name with at least two labels,
    not an address and not a public suffix, so one mistyped line cannot exclude a whole top-level domain."""
    from targetApp.target_types import IP, classify_target
    name = str(value or '').strip().lower()
    if name.startswith('*.'):
        name = name[2:]
    name = clean_host(name)
    if classify_target(name) == IP or '.' not in name or PUBLIC_SUFFIX_RE.match(name) or ':' in name:
        raise ApiError(400, f'{name} is not a domain name that can be excluded with its subdomains (use a name like example.com)')
    return name


def _profile(p):
    return {'host': p.host, 'owner': p.owner, 'purpose': p.purpose, 'criticality': p.criticality, 'alias': p.alias, 'note': p.note,
            'updated': p.updated_at.isoformat() if p.updated_at else None}


def update_host_profile(ctx, slug, host, owner=None, purpose=None, criticality=None, alias=None, note=None):
    """Set the owner, purpose, criticality, alias (a short display name) and/or note of a host of this project (only the fields given change;
    an empty alias or note clears it). The alias and note are kept per host name and project, so they outlast rescans; they are display
    only, the address and the names a scan found never change."""
    from agentapi.services import clean_alias_note
    from cveFeed.admin_api import audit
    from cveFeed.models import HostProfile
    project, _ = get_project(ctx, slug, write=True)
    name = clean_host(host)
    fields = {}
    for key, value, limit in (('owner', owner, MAX_OWNER), ('purpose', purpose, MAX_PURPOSE)):
        if value is not None:
            if not isinstance(value, str):
                raise ApiError(400, f'{key} must be text')
            value = value.strip()
            if len(value) > limit:
                raise ApiError(400, f'{key} is at most {limit} characters')
            fields[key] = value
    if criticality is not None:
        level = str(criticality).strip().lower()
        if level not in HostProfile.CRITICALITY:
            raise ApiError(400, f'criticality must be one of {", ".join(HostProfile.CRITICALITY)}')
        fields['criticality'] = level
    fields.update(clean_alias_note(alias, note))
    from startScan.models import Subdomain
    if not Subdomain.objects.filter(target_domain__project=project, name__iexact=name).exists():  # as host_archive: no rows for names the project lacks
        raise ApiError(404, 'host not found in this project')
    profile, _ = HostProfile.objects.get_or_create(project=project, host=name)
    changed = [key for key, value in fields.items() if getattr(profile, key) != value]
    for key, value in fields.items():
        setattr(profile, key, value)
    if fields:
        profile.save()
    if {'alias', 'note'} & set(changed):
        audit(ctx.user, 'host.profile', f'{name} in {slug}', project.org, project=slug, host=name, fields=[k for k in changed if k in ('alias', 'note')])
    return _profile(profile)


MAX_BULK_HOSTS = 200
BULK_ACTIONS = ('archive', 'restore', 'pin', 'unpin')


def host_bulk(ctx, slug, hosts, action, reason=''):
    """Archive, restore, pin or unpin up to MAX_BULK_HOSTS hosts of one project in one call. Each host is independent (a pinned host
    that cannot be archived, or a name that is not in the project, never blocks the rest); returns {done, failed: [{host, error}]}."""
    get_project(ctx, slug, write=True)  # the _all / audit-role / read-only-token gate comes before any body validation
    if action not in BULK_ACTIONS:
        raise ApiError(400, f'action must be one of {", ".join(BULK_ACTIONS)}')
    if not isinstance(hosts, list) or not hosts:
        raise ApiError(400, 'hosts must be a non-empty list of host names')
    if len(hosts) > MAX_BULK_HOSTS:
        raise ApiError(400, f'at most {MAX_BULK_HOSTS} hosts per call')
    done, failed = [], []
    for host in dict.fromkeys(h for h in hosts if isinstance(h, str)):  # a repeated name is done once
        try:
            if action in ('pin', 'unpin'):
                host_archive(ctx, slug, host, 'pin', pinned=action == 'pin')
            else:
                host_archive(ctx, slug, host, action, reason=reason)
            done.append(host)
        except ApiError as e:
            failed.append({'host': host[:200], 'error': e.message})
    failed += [{'host': str(h)[:200], 'error': 'host names must be text'} for h in hosts if not isinstance(h, str)]
    return {'done': len(done), 'hosts': done, 'failed': failed}


def host_archive(ctx, slug, host, action, reason='', pinned=None):
    """Reversible project-scoped archive and owner pin; historical evidence is retained."""
    from cveFeed.models import HostAssessment, HostState
    from cveFeed.exclusions import is_excluded
    from startScan.models import Subdomain
    from django.utils import timezone

    project, _ = get_project(ctx, slug, write=True)
    name = clean_host(host)
    if action not in ('archive', 'restore', 'pin'):
        raise ApiError(400, 'unknown archive action')
    if is_excluded(project.pk, name) and action == 'restore':
        raise ApiError(409, 'host is excluded; an organization admin must remove the exclusion first')
    if not isinstance(reason, str) or len(reason.strip()) > MAX_REASON:
        raise ApiError(400, f'reason must be text of at most {MAX_REASON} characters')
    sub = Subdomain.objects.filter(target_domain__project=project, name__iexact=name).select_related('target_domain').order_by('-id').first()
    if not sub:
        raise ApiError(404, 'host not found in this project')
    state, _ = HostState.objects.get_or_create(project=project, host=name, defaults={'domain': sub.target_domain})
    if action == 'archive':
        if state.pinned:
            raise ApiError(409, 'host is pinned; unpin it before archiving')
        if HostAssessment.objects.filter(project=project, host=name, status__in=('queued', 'running')).exists():
            raise ApiError(409, 'a host assessment is active; stop it before archiving')
        if not state.archived_at:
            state.archived_at, state.archive_reason = timezone.now(), reason.strip() or 'Manually archived by an authorized project user'
            state.archive_check_status, state.archived_by_user = '', True
            state.save(update_fields=['archived_at', 'archive_reason', 'archive_check_status', 'archived_by_user'])
    elif action == 'restore':
        if state.archived_at:
            state.archived_at, state.archive_reason, state.archived_by_user = None, '', False
            state.inactive_first_absent_at, state.inactive_last_absent_at, state.inactive_absent_checks = None, None, 0
            # A host archived for never resolving to a scannable IP (cveFeed.unresolved_archive) must not be
            # immediately re-eligible on the very next daily sweep; a manual restore clears that streak too.
            state.unresolved_first_at, state.unresolved_last_at, state.unresolved_checks = None, None, 0
            state.save(update_fields=['archived_at', 'archive_reason', 'archived_by_user', 'inactive_first_absent_at',
                                      'inactive_last_absent_at', 'inactive_absent_checks', 'unresolved_first_at',
                                      'unresolved_last_at', 'unresolved_checks'])
    elif action == 'pin':
        if not isinstance(pinned, bool):
            raise ApiError(400, 'pinned must be true or false')
        state.pinned = pinned
        state.save(update_fields=['pinned'])
    from cveFeed.admin_api import audit
    audit(ctx.user, f'host.{action}', f'{name} in {slug}', project.org, project=slug, host=name,
          reason=reason.strip() if action == 'archive' else '', pinned=state.pinned)
    return {'host': name, 'archived_at': state.archived_at.isoformat() if state.archived_at else None,
            'archive_reason': state.archive_reason, 'pinned': state.pinned,
            'last_check_at': state.archive_checked_at.isoformat() if state.archive_checked_at else None,
            'last_check_status': state.archive_check_status, 'linked_assessment_id': state.archive_assessment_id}


def _url_host_pattern(name, subtree=False):
    """A Postgres regex for a URL whose host part is exactly ``name`` (any scheme, optional port and path); with ``subtree`` also any
    name under it."""
    below = r'([^/?#@]*\.)?' if subtree else ''
    return r'^([a-z][a-z0-9+.-]*://)?' + below + re.escape(name) + r'(:[0-9]+)?([/?#].*)?$'


def _host_q(field, name, subtree=False):
    """A filter on a host-name column: the exact name (any case), or with ``subtree`` the name and every name under it."""
    if subtree:
        return Q(**{f'{field}__iregex': r'(^|\.)' + re.escape(name) + '$'})
    return Q(**{f'{field}__iexact': name})


def host_group_names(project, name):
    """``name`` and every other name of this project that points at the same addresses: the Hosts page shows them as ONE host, so
    removing only the name on display makes the next name take its place and the host seems not to go."""
    from cveFeed.counts import host_siblings
    from startScan.models import Subdomain
    ids = list(Subdomain.objects.filter(target_domain__project=project, name__iexact=name).values_list('id', flat=True)[:50])
    names = {name}
    for rows in host_siblings(ids).values():
        names.update(n.lower().rstrip('.') for _, n in rows)
    return sorted(names)


def _purge(project, name, subtree=False):
    """Remove everything recorded for the host ``name`` in ``project`` (exact name, any case; with ``subtree`` also every name under
    it). Returns the counts."""
    from cveFeed.models import (AssetChange, CVEMatch, DiscoveryEvent, FindingAuditEvent, FindingComment, HostArchive, HostAssessment,
                                HostInventory, HostLabel, HostProfile, HostScreenshot, HostState, HygieneFinding, ProbeObservation, RdpScreenshot,
                                RouteAuth, TlsCertificate, Triage)
    from startScan.models import EndPoint, ScanHistory, Subdomain, Vulnerability
    from targetApp.models import Domain
    counts = {}
    subs = Subdomain.objects.filter(target_domain__project=project).filter(_host_q('name', name, subtree))
    sub_ids = list(subs.values_list('id', flat=True))
    counts['hosts'] = len(sub_ids)
    vuln_ids = list(Vulnerability.objects.filter(subdomain_id__in=sub_ids).values_list('id', flat=True))
    match_ids = list(CVEMatch.objects.filter(subdomain_id__in=sub_ids).values_list('id', flat=True))
    hygiene = HygieneFinding.objects.filter(_host_q('host', name, subtree), domain__project=project)
    hygiene_ids = list(hygiene.values_list('id', flat=True))
    counts['findings'] = len(vuln_ids)
    counts['cve_matches'] = len(match_ids)
    counts['endpoints'] = EndPoint.objects.filter(subdomain_id__in=sub_ids).count()
    # a finding recorded against the bare host (no Subdomain row) is still this host's
    orphans = Vulnerability.objects.filter(target_domain__project=project, subdomain__isnull=True).filter(
        http_url__iregex=_url_host_pattern(name, subtree))
    orphan_ids = list(orphans.values_list('id', flat=True))
    counts['findings'] += len(orphan_ids)
    orphans.delete()
    subs.delete()  # cascades findings, CVE matches and endpoints
    # the notes and audit trail of the findings just deleted (named by kind and id, so nothing cascades to them)
    for kind, ids in (('vulnerability', vuln_ids + orphan_ids), ('match', match_ids), ('hygiene', hygiene_ids)):
        for model in (FindingComment, FindingAuditEvent):
            model.objects.filter(project=project, finding_kind=kind, finding_id__in=ids).delete()
    # evidence kept per host name: a screenshot's file goes with its row
    shots = RdpScreenshot.objects.filter(_host_q('host', name, subtree), project=project)
    shot_files = [path for path in shots.values_list('image_path', flat=True) if path]
    web_shots = HostScreenshot.objects.filter(_host_q('host', name, subtree), project=project)  # the browser's captures: the picture, its thumbnail and the one before
    for row in web_shots.values('image_path', 'thumb_path', 'previous_image_path'):
        shot_files += sorted({os.path.dirname(path) for path in (row['image_path'], row['thumb_path'], row['previous_image_path']) if path})  # a host's own directory: pictures, thumbnails and the one before
    for label, model, flt in (
            ('states', HostState, {'project': project}), ('labels', HostLabel, {'project': project}),
            ('routes', RouteAuth, {'project': project}), ('changes', AssetChange, {'project': project}),
            ('profiles', HostProfile, {'project': project}), ('triage', Triage, {'project': project}),
            ('inventories', HostInventory, {'project': project}),
            ('probes', ProbeObservation, {'project': project}), ('archives', HostArchive, {'project': project}),
            ('screenshots', RdpScreenshot, {'project': project}), ('web_screenshots', HostScreenshot, {'project': project}),
            ('assessments', HostAssessment, {'project': project}),
            ('certificates', TlsCertificate, {'domain__project': project}),
            ('hygiene', HygieneFinding, {'domain__project': project}),
            ('events', DiscoveryEvent, {'domain__project': project})):
        counts[label] = model.objects.filter(_host_q('host', name, subtree), **flt).delete()[0]
    scan_dirs = list(shot_files)  # relative to the results root, like the scan directories
    counts['target_deleted'], counts['target_kept'] = False, False
    if subtree:  # a whole domain: the targets named like it or under it go with their scans, whatever else they held
        domains = list(Domain.objects.filter(project=project).filter(_host_q('name', name, True)))
        for domain in domains:
            scan_dirs += [f'{domain.name}_{sid}' for sid in ScanHistory.objects.filter(domain=domain).values_list('id', flat=True)]
            scan_dirs.append(domain.name)
        if domains:
            Domain.objects.filter(pk__in=[d.pk for d in domains]).delete()
        counts['targets_deleted'] = len(domains)
        counts['target_deleted'] = bool(domains)
        return counts, scan_dirs
    # A target named exactly like the host goes too, unless it also holds other hosts: those were not asked for.
    domain = Domain.objects.filter(project=project, name__iexact=name).first()
    if domain:
        if Subdomain.objects.filter(target_domain=domain).exclude(name__iexact=name).exists():
            counts['target_kept'] = True
        else:
            scan_dirs += [f'{domain.name}_{sid}' for sid in ScanHistory.objects.filter(domain=domain).values_list('id', flat=True)]
            scan_dirs.append(domain.name)
            domain.delete()  # cascades its scans
            counts['target_deleted'] = True
    return counts, scan_dirs


def _remove_result_dirs(names):
    from reNgine.common_func import SCAN_RESULTS_ROOT, safe_remove_path
    for name in names:  # exact directory names, never a prefix match
        try:
            safe_remove_path(os.path.join(SCAN_RESULTS_ROOT, name), SCAN_RESULTS_ROOT)
        except Exception:  # noqa: BLE001 - result files are a courtesy; the database rows are already gone
            pass


def _sum_counts(parts):
    total = {}
    for counts in parts:
        for key, value in counts.items():
            total[key] = (total.get(key) or 0) + value if isinstance(value, int) and not isinstance(value, bool) else (total.get(key) or value)
    return total


def delete_host(ctx, slug, host, with_aliases=False):
    """Delete a host's data from THIS project only (its findings, CVE matches, endpoints, state and asset information). It is not
    excluded: a later scan can discover it again. ``with_aliases`` also deletes the other names the host answers to (names on the
    same addresses show as one host)."""
    project, _ = get_project(ctx, slug, write=True)
    name = clean_host(host)
    names = host_group_names(project, name) if with_aliases else [name]
    done = _purge_settled(lambda: [_purge(project, n) for n in names])
    counts = _sum_counts(c for c, _ in done)
    _remove_result_dirs([d for _, dirs in done for d in dirs])
    from cveFeed.admin_api import audit
    audit(ctx.user, 'host.delete', f'{name} in {slug}', project.org, project=slug, host=name, names=names,
          **{k: v for k, v in counts.items() if v})
    return {'host': name, 'names': names, 'project': project.slug, **counts}


def _purge_settled(purge):
    """Run ``purge`` (a function that deletes inside one transaction) and run it again when a scan that was already under way
    wrote a row for what is being deleted before the commit: the constraint is checked at commit, so the transaction fails whole
    and nothing was deleted. Each retry deletes what the last attempt missed."""
    from django.db import IntegrityError
    for attempt in range(PURGE_ATTEMPTS):
        try:
            with transaction.atomic():
                return purge()
        except IntegrityError:
            if attempt == PURGE_ATTEMPTS - 1:
                raise ApiError(409, 'scans of this host kept writing results while it was being removed; try again in a minute')
            time.sleep(PURGE_RETRY_SECONDS)


def _target_hosts(project, name):
    """The other host names of the target ``name`` of ``project`` (names under it, and any target of this project under it)."""
    from startScan.models import Subdomain
    from targetApp.models import Domain
    names = set(Subdomain.objects.filter(target_domain__project=project, target_domain__name__iexact=name).values_list('name', flat=True))
    names |= set(Subdomain.objects.filter(target_domain__project=project).filter(_host_q('name', name, True)).values_list('name', flat=True))
    names |= set(Domain.objects.filter(project=project).filter(_host_q('name', name, True)).values_list('name', flat=True))
    return sorted({n.lower() for n in names} - {name})


def move_host(ctx, slug, host, to_project, discover=True, whole_target=False):
    """Move a host out of this project into ``to_project`` (any project the caller can write to, in this organization or another).
    Its data is deleted from this project (findings, CVE matches, state and asset information: its history does not move) and a
    HostMove keeps this project's scans from finding it again; then it is added to the destination as a target and, with ``discover``,
    scanned there. Moving it back later lifts that block. Needs write access to both projects. Everything that could refuse the move
    is checked before anything is deleted.

    A target moved within its organization is not deleted and discovered again: it is pointed at the new project with everything it holds
    (``target_move``). The rest of this function is the other case, a host under a larger target or a move to another organization.

    A host that is also a target of this project with other hosts under it moves only with ``whole_target``: the target, every host
    under it and every target of this project under it go together (one HostMove per name), and the destination discovers them
    again. Without it the 409 says how many hosts the target holds, so the caller can ask before moving them all."""
    from cveFeed.exclusions import is_excluded
    from cveFeed.models import HostMove
    from startScan.models import Subdomain
    from targetApp.models import Domain, org_domains
    from agentapi.services import _expand_target, add_target
    source, _ = get_project(ctx, slug, write=True)
    if not isinstance(to_project, str) or not to_project.strip():
        raise ApiError(400, 'to_project is required')
    dest, _ = get_project(ctx, to_project.strip(), write=True)
    if dest.pk == source.pk:
        raise ApiError(400, 'the host is already in that project')
    name = clean_host(host)
    if not (Subdomain.objects.filter(target_domain__project=source, name__iexact=name).exists()
            or Domain.objects.filter(project=source, name__iexact=name).exists()):
        raise ApiError(404, 'host not found in this project')
    _expand_target(name, dest.id)  # refused here (a blocked address, say) before anything is deleted
    is_target = Domain.objects.filter(project=source, name__iexact=name).exists()
    if is_target and source.org_id == dest.org_id:  # the same organization: the target is pointed at the new project, with its history (target_move)
        from agentapi.target_move import move_target
        return move_target(ctx, source, dest, name, discover=discover, whole_target=whole_target)
    others = _target_hosts(source, name) if is_target else []
    if others and not whole_target:
        raise ApiError(409, f'{name} is a target of this project with {len(others)} other host{"s" if len(others) != 1 else ""} under it: '
                            'move the whole target (whole_target) or move those hosts first', whole_target={'host': name, 'hosts': others[:MOVE_LIST_MAX],
                            'count': len(others)})
    whole = bool(others)
    # target names are unique within an organization: a target of that name (or, for a whole target, under it) held by a third
    # project would keep the destination from adding it, or would leave part of the domain behind
    held = org_domains(dest).exclude(project__in=(dest, source)).filter(_host_q('name', name, whole) if whole else Q(name__iexact=name))
    clash = held.values_list('name', flat=True).first()
    if clash:
        raise ApiError(409, f'another project of the destination\'s organization already has a target named {clash}')
    names = [name, *others]
    if whole:
        _stop_scans_under([source], name, ctx.user)  # their rows go next; a running scan would keep writing into them

    def purge():
        back = HostMove.objects.filter(project=dest)  # they once left the destination: moving them back lifts that block
        (back.filter(_host_q('host', name, True)) if whole else back.filter(host__in=names)).delete()
        if is_excluded(dest.pk, name):
            raise ApiError(409, f'{name} is excluded in the destination\'s organization (an organization admin can lift the exclusion)')
        for n in names:
            HostMove.objects.update_or_create(project=source, host=n, defaults={'moved_to': dest, 'moved_by': ctx.user})
        return _purge(source, name, subtree=whole)  # first: a target of the same name here would otherwise stop the destination adding it
    counts, dirs = _purge_settled(purge)  # a refusal leaves the destination's own block in place
    _remove_result_dirs(dirs)
    added = add_target(ctx, dest.slug, name, description=f'Moved from {source.name}', discover=discover)
    from cveFeed.admin_api import audit
    extra = {'hosts_moved': len(names)} if whole else {}
    audit(ctx.user, 'host.move', f'{name} from {source.slug} to {dest.slug}', source.org, project=source.slug, host=name,
          to_project=dest.slug, **extra, **{k: v for k, v in counts.items() if v})
    if dest.org_id != source.org_id:
        audit(ctx.user, 'host.move', f'{name} from {source.slug} to {dest.slug}', dest.org, project=dest.slug, host=name,
              from_project=source.slug, **extra)
    return {'host': name, 'from_project': source.slug, 'to_project': dest.slug, 'to_project_name': dest.name,
            'to_org_name': dest.org.name if dest.org_id else None, 'target_created': bool(added['created']),
            'scan_ids': added['scan_ids'], 'findings_removed': counts.get('findings', 0), 'hosts_moved': len(names)}


def _org_level_role(user, org):
    """The user's role in ``org`` itself (not through one project), or None. App Admins count as admin."""
    from dashboard.models import OrgMembership
    if user.is_superuser:
        return roles.ADMIN
    return OrgMembership.objects.filter(user=user, org=org).values_list('role', flat=True).first()


def _writable_projects(ctx, org):
    """Projects of ``org`` the caller can see and write to: the only ones an org-wide removal ever touches."""
    from dashboard.models import Project
    out = []
    for project in Project.objects.filter(org=org).order_by('id'):  # scoped: only projects the caller can see
        role = roles.effective_role(ctx.user, project)
        if role and role != roles.AUDIT:
            out.append(project)
    return out


def _stop_scans_under(projects, name, user):
    """Stop every queued or running scan of the targets a whole-domain exclusion is about to delete (their files and rows go next)."""
    from agentapi.services import _abort_scan
    from startScan.models import ScanHistory
    from targetApp.models import Domain
    ids = Domain.objects.filter(project__in=projects).filter(_host_q('name', name, True)).values('id')
    for scan in ScanHistory.objects.filter(domain_id__in=ids, scan_status__in=(-1, 1)).select_related('domain'):
        _abort_scan(scan, user)


def exclude_host(ctx, slug, host, reason='', include_subdomains=False, with_aliases=False):
    """Remove a host everywhere in this project's organization and never scan it again. Records the exclusion for the org, then
    deletes the host's data from every project of the org the caller can write to. Excluding an already excluded host runs the
    clean-up again. ``with_aliases`` takes the other names this project shows as the same host (same addresses) with it.
    ``include_subdomains`` makes it a whole-domain exclusion: ``host`` and every name under it, and the targets named like them
    (their scans are stopped first)."""
    from cveFeed.models import HostExclusion
    project, _ = get_project(ctx, slug, write=True)
    org = project.org
    if org is None:
        raise ApiError(400, 'this project is not in an organization, so there is no organization to exclude the host from; use delete host data')
    org_role = _org_level_role(ctx.user, org)
    if org_role is None or org_role == roles.AUDIT:
        raise ApiError(403, 'excluding a host for the whole organization needs an organization-level role, not only a role in this project')
    subtree = bool(include_subdomains)
    name = clean_pattern(host) if subtree else clean_host(host)
    reason = '' if reason is None else reason
    if not isinstance(reason, str):
        raise ApiError(400, 'reason must be text')
    reason = reason.strip()
    if len(reason) > MAX_REASON:
        raise ApiError(400, f'reason is at most {MAX_REASON} characters')
    projects = _writable_projects(ctx, org)
    names = host_group_names(project, name) if with_aliases and not subtree else [name]
    if subtree:
        _stop_scans_under(projects, name, ctx.user)
    # the exclusion is committed before anything is deleted: from then on no new scan or discovery picks these names up, so a
    # deletion that a scan already under way got in the way of settles when it is run again (_purge_settled)
    with transaction.atomic():
        created_any, reason_kept = False, reason
        for n in names:
            exclusion, created = HostExclusion.objects.get_or_create(
                org=org, host=n, defaults={'reason': reason, 'created_by': ctx.user, 'include_subdomains': subtree})
            created_any = created_any or created
            changed = []
            if not created and reason and exclusion.reason != reason:
                exclusion.reason = reason
                changed.append('reason')
            if not created and subtree and not exclusion.include_subdomains:
                exclusion.include_subdomains = True  # an exact exclusion widened to the whole domain
                changed.append('include_subdomains')
            if changed:
                exclusion.save(update_fields=changed)
            if n == name:
                reason_kept = exclusion.reason

    def purge():
        per_project, scan_dirs = {}, []
        for n in names:
            for p in projects:
                counts, dirs = _purge(p, n, subtree)
                scan_dirs += dirs
                if any(v for v in counts.values()):
                    per_project.setdefault(p.slug, []).append(counts)
        return [{'project': slug_, **_sum_counts(parts)} for slug_, parts in per_project.items()], scan_dirs
    per_project, scan_dirs = _purge_settled(purge)
    _remove_result_dirs(scan_dirs)
    from cveFeed.admin_api import audit
    audit(ctx.user, 'host.exclude', f'{name} in {org.slug}', org, host=name, names=names, include_subdomains=subtree, reason=reason,
          projects=[p.slug for p in projects], findings=sum(c['findings'] for c in per_project))
    return {'host': name, 'names': names, 'include_subdomains': subtree, 'organization': org.slug, 'excluded': True,
            'newly_excluded': created_any, 'reason': reason_kept,
            'projects_checked': len(projects), 'projects_affected': len(per_project),
            'hosts_removed': sum(c['hosts'] for c in per_project), 'findings_removed': sum(c['findings'] for c in per_project),
            'targets_removed': sum(c.get('targets_deleted', 1 if c.get('target_deleted') else 0) for c in per_project),
            'projects': per_project}


def list_exclusions(ctx, slug):
    """The hosts excluded for this project's organization (read-only; needs any access to the project)."""
    from cveFeed.models import HostExclusion
    project, _ = get_one_project(ctx, slug)  # exclusions belong to one project's organization
    if project.org_id is None:
        return {'organization': None, 'results': []}
    rows = HostExclusion.objects.filter(org_id=project.org_id).select_related('created_by').order_by('host')[:1000]
    return {'organization': project.org.slug,
            'results': [{'host': r.host, 'include_subdomains': r.include_subdomains, 'reason': r.reason, 'created': r.created_at.isoformat(),
                         'by': r.created_by.username if r.created_by else None} for r in rows]}


def remove_exclusion(ctx, slug, host):
    """Let the organization scan a host again (an org admin only: it changes what every project of the org scans). The data that
    was deleted does not come back; the host returns when a scan next finds it."""
    from cveFeed.models import HostExclusion
    project, _ = get_project(ctx, slug, write=True)
    if project.org is None or not roles.can_manage_org(ctx.user, project.org_id):
        raise ApiError(403, 'only an organization admin can lift an exclusion')
    name = clean_host(host)
    deleted = HostExclusion.objects.filter(org_id=project.org_id, host=name).delete()[0]
    if not deleted:
        raise ApiError(404, 'that host is not excluded')
    from cveFeed.admin_api import audit
    audit(ctx.user, 'host.unexclude', f'{name} in {project.org.slug}', project.org, host=name)
    return {'host': name, 'excluded': False}
