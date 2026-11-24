from django.db import migrations, models


class Migration(migrations.Migration):
    """1.5.0 renames everything that carried the upstream project's name (docs/UPGRADE.md, "The rename to cvENGINE names"): the report
    setting that shows the credit line in a PDF report becomes ``show_cvengine_banner``. A column rename, then a database default of true
    (an insert that leaves the column out gets the model's default): no row is read or written, and PostgreSQL changes the catalogue entry in
    place, so it takes a moment on any size of table."""

    dependencies = [
        ("scanEngine", "0008_drop_unused_legacy_models"),
    ]

    operations = [
        migrations.RenameField(
            model_name="vulnerabilityreportsetting",
            old_name="show_rengine_banner",
            new_name="show_cvengine_banner",
        ),
        migrations.AlterField(
            model_name="vulnerabilityreportsetting",
            name="show_cvengine_banner",
            field=models.BooleanField(db_default=True, default=True),
        ),
    ]
