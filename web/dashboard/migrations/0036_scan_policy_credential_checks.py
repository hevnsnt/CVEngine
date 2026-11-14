from django.db import migrations, models


class Migration(migrations.Migration):
    """Checks that send credentials (default-login and brute-force templates) are off unless an App Admin turns them on. The column is new, so every row, a
    new install's and an upgraded install's, starts off: an upgraded install stops running default-login checks until someone turns them on."""
    dependencies = [('dashboard', '0035_apitoken_suffix_db_default')]
    operations = [
        migrations.AddField(model_name='scanpolicy', name='allow_credential_checks', field=models.BooleanField(default=False, db_default=False)),
    ]
