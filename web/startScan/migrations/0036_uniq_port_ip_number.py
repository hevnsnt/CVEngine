from django.db import migrations, models

from startScan.dedupe import merge_groups, unique_operations

TABLE = '"startScan_port"'
LINKS = '"startScan_ipaddress_ports"'
CONSTRAINT = 'uniq_port_ip_number_proto'


def merge_duplicate_ports(apps, schema_editor):
    """One port row per (address, number, protocol). Each port row is linked to one address (``IpAddress.ports``), but nothing kept a second
    row of the same port of the same address out: the duplicates are copies ``0007_deshare_ports`` made of a row the discovery once shared between
    addresses, for an address that already had its own row of that port, and two writers that store the same new port at the same moment
    leave two rows too. Each address's lookups already read the oldest row (by number, then id).

    In order: a row still linked to more than one address gets a copy per further address, as 0007 did (the first address keeps the row);
    each row is given the address it is linked to (``ip_address``); a protocol stored empty is written as ``tcp`` (every reader already reads
    it as TCP); then the duplicates are merged onto the oldest row of each group, every row that pointed at a newer copy is moved onto it,
    and a link of the address to a copy is dropped (the address is linked to the kept row already). The copies' own columns are not copied
    onto the kept row: they hold what another address's scan once saw. Safe to run again."""
    Port = apps.get_model('startScan', 'Port')
    IpAddress = apps.get_model('startScan', 'IpAddress')
    Through = IpAddress.ports.through
    connection = schema_editor.connection
    with connection.cursor() as cursor:
        cursor.execute(f'SELECT port_id FROM {LINKS} GROUP BY port_id HAVING count(DISTINCT ipaddress_id) > 1 ORDER BY port_id')
        shared = [row[0] for row in cursor.fetchall()]
    fields = [f.attname for f in Port._meta.concrete_fields if f.name not in ('id', 'ip_address')]
    for port_id in shared:
        port = Port.objects.get(pk=port_id)
        links = list(Through.objects.filter(port_id=port_id).order_by('ipaddress_id', 'id'))
        for link in links[1:]:
            if link.ipaddress_id == links[0].ipaddress_id:
                continue
            copy = Port.objects.create(**{name: getattr(port, name) for name in fields})
            link.port_id = copy.pk
            link.save(update_fields=['port'])
    with connection.cursor() as cursor:
        cursor.execute(f'UPDATE {TABLE} p SET ip_address_id = l.ipaddress_id FROM (SELECT port_id, min(ipaddress_id) AS ipaddress_id FROM {LINKS} '
                       'GROUP BY port_id) l WHERE l.port_id = p.id AND p.ip_address_id IS DISTINCT FROM l.ipaddress_id')
        cursor.execute(f"UPDATE {TABLE} SET protocol = 'tcp' WHERE protocol = ''")
    merge_groups(connection, TABLE, ['ip_address_id', 'number', 'protocol'])


class Migration(migrations.Migration):
    """A port row names the address it belongs to (``Port.ip_address``, filled from its link), and the database refuses a second row of the
    same port of the same address. The column is added (no default, so no table rewrite), the rows are filled and the duplicates merged in
    one transaction (above), then the unique index is built CONCURRENTLY, so scans keep writing ports while it builds, and the constraint is
    attached to it. If the build is interrupted, run ``DROP INDEX CONCURRENTLY IF EXISTS uniq_port_ip_number_proto;`` and ``migrate`` again.
    Reversing drops the constraint and the column; merged rows stay merged."""

    atomic = False
    dependencies = [('startScan', '0035_uniq_cweid_name')]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunSQL(f'ALTER TABLE {TABLE} ADD COLUMN IF NOT EXISTS ip_address_id integer NULL',
                                  reverse_sql=f'ALTER TABLE {TABLE} DROP COLUMN IF EXISTS ip_address_id'),
            ],
            state_operations=[
                migrations.AddField(
                    model_name='port',
                    name='ip_address',
                    field=models.ForeignKey(blank=True, db_constraint=False, db_index=False, editable=False, null=True,
                                            on_delete=models.deletion.DO_NOTHING, related_name='+', to='startScan.ipaddress'),
                ),
            ],
        ),
        migrations.RunPython(merge_duplicate_ports, migrations.RunPython.noop, atomic=True),
        unique_operations('port', TABLE, CONSTRAINT, ['ip_address_id', 'number', 'protocol'], ['ip_address', 'number', 'protocol']),
    ]
