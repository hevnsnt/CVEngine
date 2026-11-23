from django.db import migrations

from startScan.dedupe import merge_groups, unique_operations

TABLE = '"startScan_vulnerabilitytags"'


def merge_duplicate_names(apps, schema_editor):
    """One VulnerabilityTags row per name. Two finding saves that met a new tag at the same moment each inserted one, and every later
    ``get_or_create`` for it then raised MultipleObjectsReturned and failed the save. The oldest row stays and the findings linked to the
    others are linked to it (a finding already linked to it keeps one link)."""
    merge_groups(schema_editor.connection, TABLE, ['name'])


class Migration(migrations.Migration):
    """VulnerabilityTags names are unique: the duplicates are merged, then the index is built CONCURRENTLY and the constraint attached to it. If the
    build is interrupted, run ``DROP INDEX CONCURRENTLY IF EXISTS uniq_vulntag_name;`` and ``migrate`` again."""

    atomic = False
    dependencies = [('startScan', '0032_uniq_technology_name')]

    operations = [
        migrations.RunPython(merge_duplicate_names, migrations.RunPython.noop, atomic=True),
        unique_operations('vulnerabilitytags', TABLE, 'uniq_vulntag_name', ['name'], ['name']),
    ]
