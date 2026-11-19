from django.db import migrations

# (model, the secret fields). The fields are the encrypting kind (see reNgine.crypto_fields), so re-saving a row writes its
# plaintext value encrypted; a row that is already encrypted is read, decrypted and written back the same.
TARGETS = [('AIProviderSettings', ['api_key']), ('ApiCredential', ['value']), ('OpenAiAPIKey', ['key']), ('NetlasAPIKey', ['key']),
           ('ChaosAPIKey', ['key']), ('HackerOneAPIKey', ['key'])]


def encrypt_existing(apps, schema_editor):
    """Encrypt the secrets already stored, in place. Reads stay backward compatible meanwhile (a plaintext value is returned as is)."""
    for model_name, fields in TARGETS:
        try:
            model = apps.get_model('dashboard', model_name)
        except LookupError:  # dropped by 0037 (a migration run always has the historical model; only a call with today's registry lacks it)
            continue
        for row in model.objects.all().iterator():
            row.save(update_fields=fields)


class Migration(migrations.Migration):
    dependencies = [('dashboard', '0018_encrypted_secret_columns')]
    # no reverse: the plaintext would have to be written back into a column that no longer holds it
    operations = [migrations.RunPython(encrypt_existing, migrations.RunPython.noop)]
