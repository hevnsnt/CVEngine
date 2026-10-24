from django.db import migrations

FIELDS = ['slack_hook_url', 'lark_hook_url', 'discord_hook_url', 'telegram_bot_token']


def encrypt_existing(apps, schema_editor):
    """Encrypt the webhook URLs and bot token already stored, in place (see reNgine.crypto_fields)."""
    for row in apps.get_model('scanEngine', 'Notification').objects.all().iterator():
        row.save(update_fields=FIELDS)


class Migration(migrations.Migration):
    dependencies = [('scanEngine', '0003_encrypted_secret_columns')]
    operations = [migrations.RunPython(encrypt_existing, migrations.RunPython.noop)]
