"""An agent approved or reinstated before update_agent cleared the note of its old status still shows "another agent of this user is suspended
or revoked; an administrator must reinstate this one" while it is active (the Sentinels page draws it in amber). Clear that note, and only that
note, on agents that are active now. Nothing else is touched; there is nothing to reverse."""
from django.db import migrations

NOTE = 'another agent of this user is suspended or revoked; an administrator must reinstate this one'  # agent_broker.INHERITED_SUSPENSION_NOTE


def clear(apps, schema_editor):
    Agent = apps.get_model('agentapi', 'Agent')
    Agent.objects.filter(status='active', status_note=NOTE).update(status_note='')


class Migration(migrations.Migration):

    dependencies = [('agentapi', '0007_sentinel_network')]

    operations = [migrations.RunPython(clear, migrations.RunPython.noop)]
