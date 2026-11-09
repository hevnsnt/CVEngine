from django.db import migrations, models


class Migration(migrations.Migration):
    """The window of the last update (it started, it ended, and how long the broker keeps what the outage left open), so that an update does
    not wait for scans that run on Sentinels and a Sentinel's late result is still taken (cveFeed.scan_control, agentapi.sentinel_adopt).
    Numbered 0157: claude/watchdog-srv holds 0156. Renumber at merge time if the order changes (one leaf per app)."""

    dependencies = [('cveFeed', '0155_detection_ai_backoff')]

    operations = [
        migrations.AddField(model_name='scancontrol', name='update_started_at', field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name='scancontrol', name='update_ended_at', field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name='scancontrol', name='update_grace_until', field=models.DateTimeField(blank=True, null=True)),
    ]
