from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("targetApp", "0007_domain_alias_note"),
    ]

    operations = [
        migrations.AddField(
            model_name="domain",
            name="expect_private_ca",
            field=models.BooleanField(db_default=False, default=False),
        ),
    ]
