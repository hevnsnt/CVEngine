from django.db import migrations, models


def mark_manual_archives(apps, schema_editor):
    """An archive the inactive-host review did not write was made by a person (its reason is theirs, or the default one)."""
    HostState = apps.get_model('cveFeed', 'HostState')
    HostState.objects.filter(archived_at__isnull=False).exclude(archive_reason__startswith='Automatically archived') \
        .update(archived_by_user=True)


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0066_reap_stuck_jobs_schedule')]
    operations = [
        migrations.AddField(model_name='hoststate', name='archived_by_user', field=models.BooleanField(default=False)),
        migrations.RunPython(mark_manual_archives, migrations.RunPython.noop),
    ]
