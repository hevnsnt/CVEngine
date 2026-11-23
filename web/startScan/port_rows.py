"""Storing new Port rows without duplicates. A port row belongs to one address (``Port.ip_address``, the address ``IpAddress.ports`` links it
to), and ``uniq_port_ip_number_proto`` keeps one row per (address, number, protocol). Every writer looks the address's ports up first and
inserts only what it did not find; two writers that find the same new port at the same moment (a bbot batch and an nmap report of one
address) both insert it, the database refuses the second, and that writer uses the first one's row instead."""
from django.db import IntegrityError, transaction


def _key(port):
    return port.ip_address_id, port.number, port.protocol


def create_ports(pairs, on_conflict=()):
    """Insert the new ports of ``pairs`` (``[(IpAddress id, unsaved Port)]``) and link each to its address. Each port's ``ip_address_id`` is
    set from its pair. The batch is one insert, in key order (two writers inserting several of the same keys take their locks in the same
    order, so neither waits on the other's later key). When another writer stored one of the keys meanwhile, the batch is rolled back to its
    savepoint and each port is inserted on its own; a port whose key is taken then gets the stored row's id, and only the columns
    ``on_conflict`` names (a tuple, or a callable given the port) are written onto that row, as the writer updates a port it found. Every
    port has its id afterwards, and its address is linked to it. Returns the ports that took a stored row instead of a new one."""
    from startScan.models import IpAddress, Port
    taken = []
    if not pairs:
        return taken
    for ip_id, port in pairs:
        port.ip_address_id = ip_id
    ports = sorted((port for _, port in pairs), key=lambda p: (p.ip_address_id, p.number, p.protocol or ''))
    try:
        with transaction.atomic():
            Port.objects.bulk_create(ports, batch_size=500)
    except IntegrityError:
        for port in ports:
            port.pk = port.id = None
            port._state.adding = True
            if not _create_one(Port, port, on_conflict):
                taken.append(port)
    through = IpAddress.ports.through
    through.objects.bulk_create([through(ipaddress_id=port.ip_address_id, port_id=port.pk) for port in ports], ignore_conflicts=True,
                                batch_size=1000)
    return taken


def create_port(ip_id, port, on_conflict=()):
    """``create_ports`` for one port, with a plain insert (no batch): True when it went in, False when it took the stored row of its key."""
    from startScan.models import IpAddress, Port
    port.ip_address_id = ip_id
    inserted = _create_one(Port, port, on_conflict)
    IpAddress.ports.through.objects.get_or_create(ipaddress_id=ip_id, port_id=port.pk)
    return inserted


def _create_one(Port, port, on_conflict):
    """Insert ``port``; True when it went in, False when it took the stored row of its key."""
    try:
        with transaction.atomic():
            port.save(force_insert=True)
        return True
    except IntegrityError as exc:
        ip_id, number, protocol = _key(port)
        stored = Port.objects.filter(ip_address_id=ip_id, number=number, protocol=protocol).values_list('pk', flat=True).first()
        if stored is None:  # the insert failed on something else than the key: the caller sees it
            raise exc
    port.pk = port.id = stored
    port._state.adding = False
    fields = on_conflict(port) if callable(on_conflict) else on_conflict
    if fields:
        port.save(update_fields=list(fields))
    return False


def release_ports(ip_id, port_ids):
    """The ports ``port_ids`` stop being ports of address ``ip_id`` (it is unlinked from them): their key no longer names it, so the address can
    have its own rows of the same numbers."""
    from startScan.models import Port
    if port_ids:
        Port.objects.filter(pk__in=list(port_ids), ip_address_id=ip_id).update(ip_address=None)
