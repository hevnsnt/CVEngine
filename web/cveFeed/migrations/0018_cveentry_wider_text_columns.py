from django.db import migrations, models


class Migration(migrations.Migration):
    """cve.now's severity source is often a 36-character identifier; the 32-character columns rejected those CVEs."""

    dependencies = [('cveFeed', '0017_resources_report_schedule')]

    operations = [
        migrations.AlterField(model_name='cveentry', name=name, field=models.CharField(blank=True, default='', max_length=128))
        for name in ('severity_source', 'stated_severity', 'status')
    ]
