from django.db import migrations, models


class Migration(migrations.Migration):
    """0034 added ``suffix`` NOT NULL with only a Python default, so a row inserted by the code of the version before (during an update, or after a rollback)
    failed on the missing column default. The upgrade rehearsal caught it on the Batch 5 head. A database-level default closes it; on an install that already ran
    0034 this only sets the default."""
    dependencies = [('dashboard', '0034_apitoken_suffix')]
    operations = [
        migrations.AlterField(model_name='apitoken', name='suffix', field=models.CharField(blank=True, default='', db_default='', max_length=2)),
    ]
