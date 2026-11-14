from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dashboard", "0032_setup_wizard"),
    ]

    operations = [
        migrations.AddField(
            model_name="aiprovidersettings",
            name="nuclei_model",
            field=models.CharField(blank=True, db_default="", default="", max_length=200),
        ),
    ]
