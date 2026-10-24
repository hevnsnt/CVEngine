from django.db import migrations


class Migration(migrations.Migration):
    """HygieneFinding.check shadowed Model.check(), which Django 5 rejects: rename the field to check_name."""

    dependencies = [('cveFeed', '0014_update_settings')]

    operations = [
        migrations.RenameField(model_name='hygienefinding', old_name='check', new_name='check_name'),
    ]
