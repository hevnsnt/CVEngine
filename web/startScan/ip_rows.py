from django.db import IntegrityError, transaction

from startScan.models import IpAddress


def get_or_create_ip(address):
    """``(IpAddress, created)`` for one address, safe when another worker creates the same address at the same moment: the unique
    constraint makes the loser's insert fail, and it reads the winner's row instead of failing the scan."""
    try:
        with transaction.atomic():
            return IpAddress.objects.get_or_create(address=address)
    except IntegrityError:
        return IpAddress.objects.get(address=address), False
    except IpAddress.MultipleObjectsReturned:  # rows from before the constraint existed
        return IpAddress.objects.filter(address=address).order_by('id').first(), False


def get_or_create_first(model, defaults=None, **lookup):
    """``get_or_create`` for a table without a unique constraint on the lookup (Technology by name, Subdomain by scan and name): when
    two workers created the same row, or older data holds a duplicate, the oldest row is used instead of raising
    MultipleObjectsReturned and failing the scan."""
    try:
        return model.objects.get_or_create(defaults=defaults, **lookup)
    except model.MultipleObjectsReturned:
        return model.objects.filter(**lookup).order_by('id').first(), False
