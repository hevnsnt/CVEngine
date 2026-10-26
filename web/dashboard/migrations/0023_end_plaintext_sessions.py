from django.db import migrations


def end_sessions(apps, schema_editor):
    """Sessions used to be stored under the cookie value itself. They are keyed by a hash now, so the old rows can no longer be found, and
    leaving them would keep working logins in the table until they expire: delete them (everyone signs in once more)."""
    apps.get_model('sessions', 'Session').objects.all().delete()


class Migration(migrations.Migration):
    dependencies = [('dashboard', '0022_mfa_secret_encrypted'), ('sessions', '0001_initial')]
    operations = [migrations.RunPython(end_sessions, migrations.RunPython.noop)]
