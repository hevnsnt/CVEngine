from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cveFeed', '0177_service_features'),
    ]

    operations = [
        migrations.AddField(
            model_name='hostassessment',
            name='front',
            field=models.BooleanField(default=False),
        ),
    ]
