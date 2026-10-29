from django.db import migrations, models


def tie_existing_sentinels(apps, schema_editor):
    """A Sentinel enrolled before sentinel tokens existed holds a full token of its enrolling administrator. Its client only ever calls the
    Sentinel endpoints, so narrow that token to the ``sentinel`` scope and remember which enrollment (and so which scope ceiling) it came from."""
    SentinelEnrollment = apps.get_model("agentapi", "SentinelEnrollment")
    ApiToken = apps.get_model("dashboard", "ApiToken")
    for enrollment in SentinelEnrollment.objects.filter(used_by_agent__isnull=False, token__isnull=True).select_related("used_by_agent"):
        token_id = enrollment.used_by_agent.token_id
        if SentinelEnrollment.objects.filter(token_id=token_id).exists():
            continue
        enrollment.token_id = token_id
        enrollment.save(update_fields=["token"])
        ApiToken.objects.filter(pk=token_id, scope="full").update(scope="sentinel")


class Migration(migrations.Migration):
    dependencies = [("agentapi", "0005_sentinel_defaults"), ("dashboard", "0030_nuclei_all_templates_on_by_default")]
    operations = [
        migrations.AddField(
            model_name="sentinelenrollment",
            name="token",
            field=models.OneToOneField(blank=True, null=True, on_delete=models.deletion.SET_NULL, related_name="+", to="dashboard.apitoken"),
        ),
        migrations.RunPython(tie_existing_sentinels, migrations.RunPython.noop),
    ]
