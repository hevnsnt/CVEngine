from django.db import migrations, models


def on_unless_chosen(apps, schema_editor):
    """The library now runs by default. An install where an App Admin switched the setting (the audit log records every change) keeps
    its choice; a row nobody ever changed holds the old factory default and follows the new one."""
    ScanPolicy = apps.get_model('dashboard', 'ScanPolicy')
    AuditLog = apps.get_model('dashboard', 'AuditLog')
    if AuditLog.objects.filter(action='scan_policy.nuclei_all_templates').exists():
        return
    ScanPolicy.objects.filter(nuclei_all_templates=False).update(nuclei_all_templates=True)


class Migration(migrations.Migration):
    dependencies = [('dashboard', '0029_db_defaults_for_columns_added_by_the_update')]
    operations = [
        migrations.AlterField(model_name='scanpolicy', name='nuclei_all_templates',
                              field=models.BooleanField(default=True, db_default=True)),
        migrations.RunPython(on_unless_chosen, migrations.RunPython.noop),
    ]
