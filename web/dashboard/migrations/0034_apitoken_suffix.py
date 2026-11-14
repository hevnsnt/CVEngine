from django.db import migrations, models


def keep_four(apps, schema_editor):
    """A token's list entry shows its first 4 characters and last 2, never more: older rows kept 8 leading characters, now cut to 4."""
    ApiToken = apps.get_model('dashboard', 'ApiToken')
    for token in ApiToken.objects.exclude(prefix='').iterator():
        if len(token.prefix) > 4:
            ApiToken.objects.filter(pk=token.pk).update(prefix=token.prefix[:4])


class Migration(migrations.Migration):
    dependencies = [('dashboard', '0033_aiprovidersettings_nuclei_model')]
    operations = [
        migrations.AddField(model_name='apitoken', name='suffix', field=models.CharField(blank=True, default='', max_length=2)),
        migrations.RunPython(keep_four, migrations.RunPython.noop),
    ]
