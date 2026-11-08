"""The organization's "Addresses we must never scan" list: the editor behind Administration (organization admins and App Admins) and the read-only
list the API and MCP show. The rule that uses the list is ``cveFeed.exclusions.address_excluded``; this module only edits and reads it.

Adding an entry takes effect at once: every task already queued for an address inside it is cancelled with a plain reason (``agentapi.address_guard.cancel_pending``).
Every change is audit logged. Entries are normalised (``cveFeed.exclusions.parse_entry``): a bare address is a /32 or /128, host bits are cleared, IPv6 is compressed.
Private ranges are valid. 0.0.0.0/0 and ::/0 are never accepted, a network broader than /8 (IPv4) or /32 (IPv6) needs ``confirm_broad``, and a list holds at most
``MAX_ENTRIES`` entries."""
from django.db import IntegrityError, transaction

from cveFeed import exclusions

MAX_NOTE = 300


class EntryError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status, self.message = status, message


def _row(r):
    from ipaddress import ip_network
    net = ip_network(r.cidr, strict=False)
    return {'id': r.pk, 'cidr': r.cidr, 'version': net.version, 'addresses': net.num_addresses if net.num_addresses < 2 ** 64 else None, 'note': r.note,
            'created': r.created_at.isoformat(), 'by': r.created_by.username if r.created_by else None}


def list_rows(org_id):
    from cveFeed.models import ExcludedAddress
    rows = ExcludedAddress.objects.filter(org_id=org_id).select_related('created_by').order_by('id')[:exclusions.MAX_ENTRIES + 1]
    return {'organization_id': org_id, 'limit': exclusions.MAX_ENTRIES, 'results': [_row(r) for r in rows]}


def add(actor, org, text, note='', confirm_broad=False):
    """Add one address or network to ``org``'s list (the caller has already checked the actor may manage the org). Returns the row and how many queued tasks were cancelled."""
    from agentapi import address_guard
    from cveFeed.admin_api import audit
    from cveFeed.models import ExcludedAddress
    if not isinstance(note, str):
        raise EntryError(400, 'note must be text')
    note = note.strip()
    if len(note) > MAX_NOTE:
        raise EntryError(400, f'note is at most {MAX_NOTE} characters')
    net, why = exclusions.parse_entry(text, confirm_broad=bool(confirm_broad is True))
    if net is None:
        raise EntryError(400, why)
    cidr = str(net)
    with transaction.atomic():
        if ExcludedAddress.objects.filter(org=org).count() >= exclusions.MAX_ENTRIES:
            raise EntryError(400, f'the list holds at most {exclusions.MAX_ENTRIES} entries: remove some, or use a wider network')
        try:
            with transaction.atomic():
                row = ExcludedAddress.objects.create(org=org, cidr=cidr, note=note, created_by=actor)
        except IntegrityError:
            raise EntryError(409, f'{cidr} is already on the list') from None
    cancelled = address_guard.cancel_pending(org.pk, actor=actor)
    audit(actor, 'org.excluded_address.add', f'{cidr} in {org.slug}', org, cidr=cidr, note=note, confirmed_broad=bool(confirm_broad is True), cancelled_tasks=cancelled)
    return row, cancelled


def remove(actor, org, entry_id):
    from cveFeed.admin_api import audit
    from cveFeed.models import ExcludedAddress
    row = ExcludedAddress.objects.filter(org=org, pk=entry_id).first() if str(entry_id).isdigit() else None
    if row is None:
        raise EntryError(404, 'that address is not on the list')
    cidr = row.cidr
    row.delete()
    audit(actor, 'org.excluded_address.remove', f'{cidr} in {org.slug}', org, cidr=cidr)
    return cidr
