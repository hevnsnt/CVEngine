from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cveFeed', '0151_secretoccurrence_context'),
    ]

    operations = [
        migrations.AddField(
            model_name='aiusage',
            name='stop_reason',
            field=models.CharField(blank=True, db_default='', default='', max_length=24),
        ),
    ]
