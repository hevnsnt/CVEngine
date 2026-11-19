"""Stop the nuclei template refresh: the server keeps no copy of the templates.

All scanning runs on the Sentinels. The server no longer ships nuclei or a template set, and what it needs to know about the templates comes from the
template index of the Sentinel library it installs (``cvengine_scanner.template_index``), so the ``update_nuclei_templates`` task is gone and its
schedule (0016, every six hours since 0079) is removed here. Going back restores nothing: the code that ran the task is gone.
"""
from django.db import migrations


def unschedule(apps, schema_editor):
    apps.get_model('django_celery_beat', 'PeriodicTask').objects.filter(task='update_nuclei_templates').delete()


class Migration(migrations.Migration):
    dependencies = [('cveFeed', '0174_ai_review_indexes'), ('django_celery_beat', '0001_initial')]
    operations = [migrations.RunPython(unschedule, migrations.RunPython.noop)]  # no reverse: the task is gone from the code
