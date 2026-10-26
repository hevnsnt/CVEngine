from django.db import migrations

from reNgine.crypto_fields import ENCRYPTED_COLUMN_LENGTH, EncryptedCharField


def encrypt_existing(apps, schema_editor):
    """Write every stored TOTP seed back through the encrypting field (a plaintext value is read as is and saved encrypted)."""
    model = apps.get_model('dashboard', 'UserProfile')
    for row in model.objects.exclude(mfa_secret='').iterator():
        row.save(update_fields=['mfa_secret'])


class Migration(migrations.Migration):
    dependencies = [('dashboard', '0021_searchhistory_user')]
    operations = [
        migrations.AlterField(model_name='userprofile', name='mfa_secret',
                              field=EncryptedCharField(blank=True, default='', max_length=ENCRYPTED_COLUMN_LENGTH)),
        # no reverse: the plaintext would have to be written back into a column that no longer holds it
        migrations.RunPython(encrypt_existing, migrations.RunPython.noop),
    ]
