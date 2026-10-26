"""Host management: editable asset information, "Delete host data" (one project) and "Remove & exclude" (the whole organization).

Both removals are destructive, so each runs in one transaction, needs write access (get_project(..., write=True): an audit
role or a read-only token gets 403) and only ever touches projects the caller may write to. A host is matched by its WHOLE name,
case-insensitively: never a suffix or a substring, so ``provider.example`` leaves ``notprovider.example`` and
``www.provider.example`` alone.

* ``delete_host``: this project only. The host can be rediscovered by a later scan.
* ``exclude_host``: removes the host from every project of the organization the caller can write to, and records a
  HostExclusion so no discovery or scanner ever brings it back anywhere in the organization (see cveFeed.exclusions). That
  changes what the other projects of the org scan, so it needs an organization-level role (or an App Admin), not just a role in
  one project. ``with_aliases`` also takes the other names the host answers to (the Hosts page shows names on the same addresses
  as one host, so excluding only the name on display makes the next one take its place). ``include_subdomains`` excludes a whole
  domain: the name, every name under it and the targets named like them (``-example.com`` in Add targets).
"""
import os
import re

from django.db import transaction
from django.db.models import Q

from agentapi.services import ApiError, get_one_project, get_project
from tenancy import roles

HOST_RE = re.compile(r'^[a-z0-9_]([a-z0-9._:-]*[a-z0-9_])?$')
MAX_OWNER, MAX_PURPOSE, MAX_REASON = 200, 500, 300
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
    return {'host': p.host, 'owner': p.owner, 'purpose': p.purpose, 'criticality': p.criticality,
            'updated': p.updated_at.isoformat() if p.updated_at else None}


def update_host_profile(ctx, slug, host, owner=None, purpose=None, criticality=None):
    """Set the owner, purpose and/or criticality of a host of this project (only the fields given change)."""
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
    profile, _ = HostProfile.objects.get_or_create(project=project, host=name)
    for key, value in fields.items():
        setattr(profile, key, value)
    if fields:
        profile.save()
    return _profile(profile)


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
            state.save(update_fields=['archived_at', 'archive_reason', 'archived_by_user', 'inactive_first_absent_at',
                                      'inactive_last_absent_at', 'inactive_absent_checks'])
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
    from cveFeed.models import (AssetChange, CVEMatch, DiscoveryEvent, HostLabel, HostProfile, HostState, HygieneFinding,
                                RouteAuth, TlsCertificate, Triage)
    from startScan.models import EndPoint, ScanHistory, Subdomain, Vulnerability
    from targetApp.models import Domain
    counts = {}
    subs = Subdomain.objects.filter(target_domain__project=project).filter(_host_q('name', name, subtree))
    sub_ids = list(subs.values_list('id', flat=True))
    counts['hosts'] = len(sub_ids)
    counts['findings'] = Vulnerability.objects.filter(subdomain_id__in=sub_ids).count()
    counts['cve_matches'] = CVEMatch.objects.filter(subdomain_id__in=sub_ids).count()
    counts['endpoints'] = EndPoint.objects.filter(subdomain_id__in=sub_ids).count()
    # a finding recorded against the bare host (no Subdomain row) is still this host's
    orphans = Vulnerability.objects.filter(target_domain__project=project, subdomain__isnull=True).filter(
        http_url__iregex=_url_host_pattern(name, subtree))
    counts['findings'] += orphans.count()
    orphans.delete()
    subs.delete()  # cascades findings, CVE matches and endpoints
    for label, model, flt in (
            ('states', HostState, {'project': project}), ('labels', HostLabel, {'project': project}),
            ('routes', RouteAuth, {'project': project}), ('changes', AssetChange, {'project': project}),
            ('profiles', HostProfile, {'project': project}), ('triage', Triage, {'project': project}),
            ('certificates', TlsCertificate, {'domain__project': project}),
            ('hygiene', HygieneFinding, {'domain__project': project}),
            ('events', DiscoveryEvent, {'domain__project': project})):
        counts[label] = model.objects.filter(_host_q('host', name, subtree), **flt).delete()[0]
    scan_dirs = []
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
            scan_dirs = [f'{domain.name}_{sid}' for sid in ScanHistory.objects.filter(domain=domain).values_list('id', flat=True)]
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
    with transaction.atomic():
        done = [_purge(project, n) for n in names]
    counts = _sum_counts(c for c, _ in done)
    _remove_result_dirs([d for _, dirs in done for d in dirs])
    from cveFeed.admin_api import audit
    audit(ctx.user, 'host.delete', f'{name} in {slug}', project.org, project=slug, host=name, names=names,
          **{k: v for k, v in counts.items() if v})
    return {'host': name, 'names': names, 'project': project.slug, **counts}


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
    with transaction.atomic():
        created_any, per_project, scan_dirs, reason_kept = False, {}, [], reason
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
            for p in projects:
                counts, dirs = _purge(p, n, subtree)
                scan_dirs += dirs
                if any(v for v in counts.values()):
                    per_project.setdefault(p.slug, []).append(counts)
        per_project = [{'project': slug_, **_sum_counts(parts)} for slug_, parts in per_project.items()]
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
