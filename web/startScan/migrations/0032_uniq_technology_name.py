from django.db import migrations

from startScan.dedupe import merge_groups, unique_operations

TABLE = '"startScan_technology"'


def merge_duplicate_names(apps, schema_editor):
    """One Technology row per exact name. Two writers that met a new name at the same moment each inserted one. The oldest row stays and
    the host and endpoint links of the others move onto it (a link the kept row already has is dropped). Spellings in another case are
    not touched here (cveFeed.tech_rows.merge_duplicates folds them)."""
    merge_groups(schema_editor.connection, TABLE, ['name'])


class Migration(migrations.Migration):
    """Technology names are unique: the duplicates are merged, then the index is built CONCURRENTLY and the constraint attached to it. If the
    build is interrupted, run ``DROP INDEX CONCURRENTLY IF EXISTS uniq_technology_name;`` and ``migrate`` again."""

    atomic = False
    dependencies = [('startScan', '0031_uniq_subdomain_scan_host')]

    operations = [
        migrations.RunPython(merge_duplicate_names, migrations.RunPython.noop, atomic=True),
        unique_operations('technology', TABLE, 'uniq_technology_name', ['name'], ['name']),
    ]
