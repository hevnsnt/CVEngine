from django.db import migrations


class Migration(migrations.Migration):
    """Drop the classic command log (``startScan_command``: the command lines and output of the reNgine tool runs, which no longer run on the
    server). Nothing has written it since the scan engine moved to Sentinels and nothing reads it. Schema only."""

    dependencies = [
        ("startScan", "0026_vulnerability_severity_id_idx"),
    ]

    operations = [
        migrations.DeleteModel(
            name="Command",
        ),
    ]
