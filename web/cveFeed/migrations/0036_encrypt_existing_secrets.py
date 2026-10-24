from django.db import migrations


def encrypt_existing(apps, schema_editor):
    """Encrypt the update-check token already stored, in place (see reNgine.crypto_fields)."""
    for row in apps.get_model('cveFeed', 'UpdateSettings').objects.all().iterator():
        row.save(update_fields=['token'])


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0035_encrypted_secret_columns')]
    operations = [migrations.RunPython(encrypt_existing, migrations.RunPython.noop)]
