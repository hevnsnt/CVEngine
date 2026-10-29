import reNgine.crypto_fields
from django.db import migrations


def encrypt_existing(apps, schema_editor):
    """Encrypt the proxy list already stored (its lines may carry passwords), in place (see reNgine.crypto_fields)."""
    for row in apps.get_model('scanEngine', 'Proxy').objects.all().iterator():
        row.save(update_fields=['proxies'])


def decrypt_existing(apps, schema_editor):
    """Reverse: put the plaintext back in the column, so the code before this migration reads it. The write goes around the encrypting
    field (it would encrypt again), straight to the column."""
    table = schema_editor.quote_name(apps.get_model('scanEngine', 'Proxy')._meta.db_table)
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(f'SELECT id, proxies FROM {table} WHERE proxies IS NOT NULL')
        for pk, value in cursor.fetchall():
            cursor.execute(f'UPDATE {table} SET proxies = %s WHERE id = %s', [reNgine.crypto_fields.decrypt_text(value), pk])


class Migration(migrations.Migration):
    dependencies = [('scanEngine', '0005_drop_legacy_models')]
    operations = [
        migrations.AlterField(model_name='proxy', name='proxies', field=reNgine.crypto_fields.EncryptedTextField(blank=True, null=True)),
        migrations.RunPython(encrypt_existing, decrypt_existing),
    ]
