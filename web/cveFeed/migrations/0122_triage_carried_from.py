from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cveFeed', '0121_feedwatermark'),
    ]

    operations = [
        migrations.AddField(
            model_name='triage',
            name='carried_from',
            field=models.PositiveBigIntegerField(blank=True, null=True),
        ),
    ]
