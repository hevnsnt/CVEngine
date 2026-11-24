from django.db import migrations


class Migration(migrations.Migration):
    """Drop seven legacy tables that nothing reads or writes any more (docs/UPGRADE.md, "Dropped legacy tables and columns"): the OpenAI,
    Netlas and HackerOne entries of the old key vault (the AI model's key is in AIProviderSettings, discovery keys in ApiCredential, a HackerOne
    submission uses the person's own credentials), the Ollama settings the AI layer never read, the search history, the per-user preferences row
    and the in-app notifications of the deleted classic screens. Schema only: the rows go with the tables."""

    dependencies = [
        ("dashboard", "0036_scan_policy_credential_checks"),
    ]

    operations = [
        migrations.DeleteModel(
            name="HackerOneAPIKey",
        ),
        migrations.RemoveField(
            model_name="inappnotification",
            name="project",
        ),
        migrations.DeleteModel(
            name="NetlasAPIKey",
        ),
        migrations.DeleteModel(
            name="OllamaSettings",
        ),
        migrations.DeleteModel(
            name="OpenAiAPIKey",
        ),
        migrations.RemoveField(
            model_name="searchhistory",
            name="user",
        ),
        migrations.RemoveField(
            model_name="userpreferences",
            name="user",
        ),
        migrations.DeleteModel(
            name="InAppNotification",
        ),
        migrations.DeleteModel(
            name="SearchHistory",
        ),
        migrations.DeleteModel(
            name="UserPreferences",
        ),
    ]
