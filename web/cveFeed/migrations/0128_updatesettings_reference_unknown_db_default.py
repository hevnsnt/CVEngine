from django.db import migrations, models


class Migration(migrations.Migration):
    """0125 first added ``reference_unknown`` without a database default, which the old code (still running between a migration and the restart) cannot
    insert around. 0125 now carries ``db_default``; an install that already applied the first version of it gets the default here."""

    dependencies = [
        ('cveFeed', '0127_scan_history_retention'),
    ]

    operations = [
        migrations.AlterField(
            model_name='updatesettings',
            name='reference_unknown',
            field=models.BooleanField(default=False, db_default=False),
        ),
    ]
