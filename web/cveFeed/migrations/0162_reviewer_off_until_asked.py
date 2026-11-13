"""1.4.0: an AI reviewer row that nobody has touched is switched off, until an administrator answers the question about it.

The reviewer shipped in 1.4 development builds with ``enabled`` and ``auto_close`` on, and its row is created on first use, so an install that ran such a
build holds a row with both on that no person ever chose. Saving the reviewer settings (Settings, the MCP, or the update question) always records who
did it in ``updated_by``; a row with no ``updated_by`` was never changed by a person, so only that row is turned off. A row a person saved is left exactly
as it is, whatever it says. Writes no ``SetupAnswer``.
"""
from django.db import migrations


def off_until_asked(apps, schema_editor):
    ReviewerSettings = apps.get_model('cveFeed', 'ReviewerSettings')
    ReviewerSettings.objects.filter(updated_by__isnull=True).update(enabled=False, auto_close=False)


class Migration(migrations.Migration):

    dependencies = [('cveFeed', '0161_setup_answer')]

    operations = [migrations.RunPython(off_until_asked, migrations.RunPython.noop)]
