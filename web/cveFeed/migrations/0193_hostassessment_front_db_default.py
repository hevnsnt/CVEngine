from django.db import migrations, models


class Migration(migrations.Migration):
    """0178 added ``front`` to the host assessment NOT NULL with only a Python default, and Django drops the column default right after it adds
    the column. The code of the version before (1.4.2) does not know the column, so each host assessment it queued failed with *null value in
    column "front"*: from the migration until the restart during an update, and for good after a rollback. A database default of false (the
    model's own default) closes it. On an install that ran 0178 this only sets the column default: PostgreSQL changes the catalogue entry, no
    row is read or rewritten, and the brief ACCESS EXCLUSIVE lock on ``cveFeed_hostassessment`` (a small table) lasts no longer than that."""

    dependencies = [
        ('cveFeed', '0192_cve_pub_id_desc_idx'),
    ]

    operations = [
        migrations.AlterField(
            model_name='hostassessment',
            name='front',
            field=models.BooleanField(db_default=False, default=False),
        ),
    ]
