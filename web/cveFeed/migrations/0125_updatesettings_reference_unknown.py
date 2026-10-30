from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('cveFeed', '0124_os_path_schedule'),
    ]

    operations = [
        migrations.AddField(
            model_name='updatesettings',
            name='reference_unknown',
            field=models.BooleanField(default=False, db_default=False),  # a database default: the old code, still running between the migration and the restart, inserts without this column
        ),
    ]
