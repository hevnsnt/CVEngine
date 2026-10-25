from django.db import migrations, models


def fill(apps, schema_editor):
    from cveFeed.correlation import split_name_version
    from cveFeed.fingerprint import categorize
    Technology = apps.get_model('startScan', 'Technology')
    batch = []
    for tech in Technology.objects.all().iterator(chunk_size=2000):
        _base, version = split_name_version(tech.name or '')
        category = categorize(tech.name or '')
        if (tech.version, tech.category) != (version, category):
            tech.version, tech.category = version, category
            batch.append(tech)
        if len(batch) >= 2000:
            Technology.objects.bulk_update(batch, ['version', 'category'])
            batch = []
    if batch:
        Technology.objects.bulk_update(batch, ['version', 'category'])


class Migration(migrations.Migration):
    dependencies = [('startScan', '0014_ip_fingerprint')]
    operations = [
        migrations.AddField('technology', 'version', models.CharField(blank=True, default='', max_length=200)),
        migrations.AddField('technology', 'category', models.CharField(blank=True, db_index=True, default='', max_length=40)),
        migrations.RunPython(fill, migrations.RunPython.noop),
    ]
