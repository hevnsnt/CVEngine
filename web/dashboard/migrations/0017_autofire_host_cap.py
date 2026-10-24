from django.db import migrations, models


def widen_old_default(apps, schema_editor):
    """The setting used to cap domains per CVE (default 5); it now caps hosts, where 5 would strangle auto-fire."""
    apps.get_model('dashboard', 'AIProviderSettings').objects.filter(auto_fire_max_scans=5).update(auto_fire_max_scans=200)


class Migration(migrations.Migration):

    dependencies = [
        ("dashboard", "0016_ai_providers_openrouter_vllm"),
    ]

    operations = [
        migrations.AlterField(
            model_name="aiprovidersettings",
            name="auto_fire_max_scans",
            field=models.IntegerField(default=200),
        ),
        migrations.RunPython(widen_old_default, migrations.RunPython.noop),
    ]
