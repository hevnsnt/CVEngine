from django.db import migrations, models


def grandfather_internal(apps, schema_editor):
    """A Sentinel that declared ``network:internal`` before the server decided it was provisioned as internal by an administrator (the setup
    choice is the only way to declare it), so it keeps its place. Anything else is external."""
    Agent = apps.get_model("agentapi", "Agent")
    for agent in Agent.objects.filter(kind="scanner"):
        if "network:internal" in (agent.capabilities or []):
            Agent.objects.filter(pk=agent.pk).update(network="internal")


class Migration(migrations.Migration):
    dependencies = [("agentapi", "0006_sentinel_enrollment_token")]
    operations = [
        migrations.AddField(model_name="agent", name="network", field=models.CharField(default="external", max_length=10)),
        migrations.AddField(model_name="sentinelenrollment", name="network", field=models.CharField(default="external", max_length=10)),
        migrations.RunPython(grandfather_internal, migrations.RunPython.noop),
    ]
