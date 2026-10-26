from django.db import IntegrityError, transaction

from startScan.models import IpAddress


def org_id_of_project(project_id):
    """The organization id of a project (read from the database, not a cached object), or None."""
    if not project_id:
        return None
    from dashboard.models import Project
    return Project._base_manager.filter(pk=project_id).values_list('org_id', flat=True).first()


def org_id_of_subdomain(subdomain):
    return org_id_of_project(getattr(subdomain.target_domain, 'project_id', None)) if subdomain is not None else None


def get_or_create_ip(address, org_id=None):
    """``(IpAddress, created)`` for one address of one organization. IP rows are per organization (the banners and service data one
    organization's scans found are never visible through another's hosts), so the lookup is ``(org, address)``. Safe when another
    worker creates the same row at the same moment: the unique constraint makes the loser's insert fail, and it reads the winner's
    row instead of failing the scan."""
    lookup = {'address': address, 'org_id': org_id}
    try:
        with transaction.atomic():
            return IpAddress.objects.get_or_create(**lookup)
    except IntegrityError:
        return IpAddress.objects.get(**lookup), False
    except IpAddress.MultipleObjectsReturned:  # rows from before the constraint existed
        return IpAddress.objects.filter(**lookup).order_by('id').first(), False


def get_or_create_first(model, defaults=None, **lookup):
    """``get_or_create`` for a table without a unique constraint on the lookup (Technology by name, Subdomain by scan and name): when
    two workers created the same row, or older data holds a duplicate, the oldest row is used instead of raising
    MultipleObjectsReturned and failing the scan."""
    try:
        return model.objects.get_or_create(defaults=defaults, **lookup)
    except model.MultipleObjectsReturned:
        return model.objects.filter(**lookup).order_by('id').first(), False
