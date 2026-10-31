"""Move a target to another project of the same organization by pointing it at the new project, not by deleting it and discovering it again.

Everything a target holds (its scans, hosts, findings, CVE matches, certificates, hygiene findings and discovery events) hangs off the target record, so
changing the record's project moves all of it, with its history, remediation status and notes. What is keyed by project and host name instead (labels,
state, triage, assessments, comments and the like) is pointed at the new project here. A scan that finishes later updates the same records.

Only a target moves this way. A single host under a larger target, and a move into another organization (where targets, addresses and ports are separate
records), still go through ``host_manage.move_host``'s delete-and-rediscover path."""
from django.db import IntegrityError, transaction

HOST_CHUNK = 500  # host names per UPDATE


def _repoint(queryset, dest):
    """Point ``queryset`` (rows keyed by project) at ``dest``. A row that would duplicate one the destination already holds (a label or state for
    the same host, say) is dropped: the destination's own record wins and nothing there is overwritten."""
    try:
        with transaction.atomic():
            return queryset.update(project=dest)
    except IntegrityError:
        moved = 0
        for row in queryset:
            try:
                with transaction.atomic():
                    row.project = dest
                    row.save(update_fields=['project'])
                moved += 1
            except IntegrityError:
                row.delete()
        return moved


def moving(project, name):
    """``(domains, hosts)``: the targets of ``project`` named ``name`` or under it, and the host names they hold (the target names included)."""
    from agentapi.host_manage import _host_q
    from startScan.models import Subdomain
    from targetApp.models import Domain
    domains = list(Domain.objects.filter(project=project).filter(_host_q('name', name, True)))
    hosts = {d.name.lower() for d in domains}
    hosts |= {n.lower() for n in Subdomain.objects.filter(target_domain__in=domains).values_list('name', flat=True)}
    return domains, hosts


def repoint(source, dest, domains, hosts):
    """Point ``domains`` and everything keyed by their hosts at ``dest`` (the same organization as ``source``). Returns counts. Run it inside a
    transaction: it is all or nothing."""
    from cveFeed.models import (AssetChange, AutomaticValidation, CVEMatch, DeferredRetest, FindingAuditEvent, FindingComment, HostArchive,
                                HostAssessment, HostLabel, HostProfile, HostState, HygieneFinding, OnDemandValidation, ProbeObservation,
                                RdpScreenshot, RouteAuth, Triage, AuthCredential)
    from cveFeed.models import BountyEngagementTarget
    from startScan.models import Vulnerability
    from targetApp.models import Domain
    ids = [d.pk for d in domains]
    counts = {'targets': Domain.objects.filter(pk__in=ids, project=source).update(project=dest)}  # org stays: the same organization
    for model in (HostLabel, ProbeObservation, HostState, HostArchive, RdpScreenshot, HostAssessment, AssetChange, RouteAuth, DeferredRetest,
                  Triage, AuthCredential):
        _repoint(model.objects.filter(project=source, domain_id__in=ids), dest)
    names = sorted(hosts)
    for start in range(0, len(names), HOST_CHUNK):
        _repoint(HostProfile.objects.filter(project=source, host__in=names[start:start + HOST_CHUNK]), dest)
    # comments and the audit trail name their finding by kind and id; validation requests name a match or a triage
    for model in (FindingComment, FindingAuditEvent):
        for kind, ids_of in (('vulnerability', Vulnerability.objects.filter(target_domain_id__in=ids).values('id')),
                             ('match', CVEMatch.objects.filter(subdomain__target_domain_id__in=ids).values('id')),
                             ('hygiene', HygieneFinding.objects.filter(domain_id__in=ids).values('id'))):
            _repoint(model.objects.filter(project=source, finding_kind=kind, finding_id__in=ids_of), dest)
    _repoint(OnDemandValidation.objects.filter(project=source, match__subdomain__target_domain_id__in=ids), dest)
    _repoint(AutomaticValidation.objects.filter(project=source, triage__domain_id__in=ids), dest)
    # a bug bounty engagement of the old project no longer lists the target (as when the target was deleted)
    BountyEngagementTarget.objects.filter(domain_id__in=ids).update(domain=None)
    return counts


def move_target(ctx, source, dest, name, discover=True, whole_target=False):
    """The target ``name`` of ``source`` (and any target of ``source`` under it) moves to ``dest``, a project of the same organization, with
    everything it holds. A target holding other hosts asks for ``whole_target`` first. A queued or running scan of it is stopped (it would keep
    writing under the old project); with ``discover`` the moved target is scanned in its new project, and the scan updates the same records."""
    from agentapi.host_manage import MOVE_LIST_MAX, _stop_scans_under
    from agentapi.services import ApiError, _not_internal
    from cveFeed.discovery import start_in_stored_modes
    from cveFeed.exclusions import is_excluded
    from cveFeed.models import HostMove
    domains, hosts = moving(source, name)
    others = sorted(hosts - {name})
    if others and not whole_target:
        raise ApiError(409, f'{name} is a target of this project with {len(others)} other host{"s" if len(others) != 1 else ""} under it: '
                            'move the whole target (whole_target) or move those hosts first',
                       whole_target={'host': name, 'hosts': others[:MOVE_LIST_MAX], 'count': len(others), 'keeps_history': True})
    target_names = [d.name.lower() for d in domains]
    with transaction.atomic():
        HostMove.objects.filter(project=dest, host__in=target_names).delete()  # they once left the destination: moving back lifts that block
        if is_excluded(dest.pk, name):  # (an organization-wide exclusion is the same for both projects; a block of the destination's own is lifted above)
            raise ApiError(409, f'{name} is excluded in the destination\'s organization (an organization admin can lift the exclusion)')
        _stop_scans_under([source], name, ctx.user)
        for n in target_names:  # the old project's other targets must not find the name again and start tracking it
            HostMove.objects.update_or_create(project=source, host=n, defaults={'moved_to': dest, 'moved_by': ctx.user})
        counts = repoint(source, dest, domains, hosts)
    scan_ids = []
    if discover:
        root = [d for d in _not_internal(dest, domains) if d.name.lower() == name]
        scan_ids = [scan.id for scan in start_in_stored_modes(root, initiated_by=ctx.user)]
    from cveFeed.admin_api import audit
    audit(ctx.user, 'host.move', f'{name} from {source.slug} to {dest.slug}', source.org, project=source.slug, host=name, to_project=dest.slug,
          hosts_moved=len(hosts), repointed=True, targets=counts['targets'])
    return {'host': name, 'from_project': source.slug, 'to_project': dest.slug, 'to_project_name': dest.name,
            'to_org_name': dest.org.name if dest.org_id else None, 'target_created': False, 'scan_ids': scan_ids,
            'findings_removed': 0, 'hosts_moved': len(hosts)}
