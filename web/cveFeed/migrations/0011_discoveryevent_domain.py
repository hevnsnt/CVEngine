import django.db.models.deletion
from django.db import migrations, models


def backfill_domain(apps, schema_editor):
    """Every existing DiscoveryEvent came from a scan; give it that scan's domain directly."""
    DiscoveryEvent = apps.get_model('cveFeed', 'DiscoveryEvent')
    for event in DiscoveryEvent.objects.filter(domain__isnull=True, scan__isnull=False).select_related('scan'):
        event.domain_id = event.scan.domain_id
        event.save(update_fields=['domain'])


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('targetApp', '0001_initial'),
        ('cveFeed', '0010_cve_sync_schedule'),
    ]

    operations = [
        migrations.AlterField(
            model_name='discoveryevent',
            name='scan',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE,
                                    related_name='discovery_events', to='startScan.scanhistory'),
        ),
        migrations.AddField(
            model_name='discoveryevent',
            name='domain',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='+',
                                    to='targetApp.domain'),
        ),
        migrations.RunPython(backfill_domain, noop),
        migrations.AlterField(
            model_name='discoveryevent',
            name='domain',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='+', to='targetApp.domain'),
        ),
    ]
