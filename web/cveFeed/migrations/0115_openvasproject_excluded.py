from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("cveFeed", "0114_authcredential_allow_untrusted_certificate"),
    ]

    operations = [
        migrations.AddField(
            model_name="openvasproject",
            name="excluded",
            field=models.BooleanField(default=False, db_default=False),
        ),
    ]
