from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cveFeed', '0061_cve_coverage_schedule'),
    ]

    operations = [
        migrations.AddField(
            model_name='triage',
            name='evidence_key',
            field=models.CharField(blank=True, default='', max_length=40),
        ),
    ]
