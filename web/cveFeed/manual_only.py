"""Which hosts a target set to manual only ("just add them, do not scan yet") holds back from the sweeps that pick work by themselves.

A host name can be held by more than one target of a project: a row under each (a certificate-transparency find under one, a scan of another),
or a target's own name that is also stored under a second target. It is held back only when EVERY target that holds it is manual only: a host that
a standard target also holds is that target's to scan, whichever row happens to be the newest. Sweeps that choose among a host's rows therefore
prefer the rows of targets that are not manual only (``held_expr``), and sweeps that start from a name ask ``only_manual_hosts`` or
``other_holder``.
"""
from django.db.models import Case, IntegerField, Value, When
from django.db.models.functions import Lower


def held_expr(prefix='target_domain__'):
    """0 for a row of a target that is not manual only, 1 for one that is: ``.annotate(held=held_expr()).order_by('held', ...)`` picks the
    row of a target that may be scanned before the row of one that may not."""
    from targetApp.models import Domain
    return Case(When(**{f'{prefix}discovery_mode': Domain.DISCOVERY_MANUAL}, then=Value(1)), default=Value(0), output_field=IntegerField())


def _holders(project_id, names):
    """``({names held by a manual only target}, {names held by any other target})`` among ``names`` (lower case), for one project."""
    from startScan.models import Subdomain
    from targetApp.models import Domain
    manual, other = set(), set()
    domains = list(Domain._base_manager.filter(project_id=project_id).values_list('id', 'name', 'discovery_mode'))
    for _id, name, mode in domains:
        if name.lower().rstrip('.') in names:
            (manual if mode == Domain.DISCOVERY_MANUAL else other).add(name.lower().rstrip('.'))
    if names:
        rows = (Subdomain._base_manager.filter(target_domain__project_id=project_id).annotate(lowered=Lower('name')).filter(lowered__in=list(names))
                .values_list('lowered', 'target_domain__discovery_mode').distinct())
        for lowered, mode in rows:
            (manual if mode == Domain.DISCOVERY_MANUAL else other).add(lowered.rstrip('.'))
    return manual, other


def only_manual_hosts(project_id, names):
    """The lower-case ``names`` that are held by manual only targets of the project and by no other target."""
    wanted = {str(n).strip().lower().rstrip('.') for n in names if n}
    if not wanted:
        return set()
    manual, other = _holders(project_id, wanted)
    return manual - other


def other_holder(project_id, host):
    """The ``Domain`` of a target that is not manual only and holds ``host`` (a row of it, or its own name), or ``None``."""
    from startScan.models import Subdomain
    from targetApp.models import Domain
    from django.db.models.functions import Lower
    name = host.strip().lower().rstrip('.')
    own = Domain._base_manager.filter(project_id=project_id).exclude(discovery_mode=Domain.DISCOVERY_MANUAL).annotate(lowered=Lower('name')).filter(lowered=name).first()
    if own is not None:
        return own
    row = (Subdomain._base_manager.filter(target_domain__project_id=project_id).exclude(target_domain__discovery_mode=Domain.DISCOVERY_MANUAL)
           .annotate(lowered=Lower('name')).filter(lowered=name).select_related('target_domain').order_by('-id').first())
    return row.target_domain if row is not None else None
