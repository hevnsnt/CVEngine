from django.db import migrations, models


class Migration(migrations.Migration):
    """The window of the last update (it started, it ended, and how long the broker keeps what the outage left open), so that an update does
    not wait for scans that run on Sentinels and a Sentinel's late result is still taken (cveFeed.scan_control, agentapi.sentinel_adopt).
    Numbered 0158: it follows 0157_watchdog (the outer watchdog), which follows 0156_work_planner (one leaf per app)."""

    dependencies = [('cveFeed', '0157_watchdog')]

    operations = [
        migrations.AddField(model_name='scancontrol', name='update_started_at', field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name='scancontrol', name='update_ended_at', field=models.DateTimeField(blank=True, null=True)),
        migrations.AddField(model_name='scancontrol', name='update_grace_until', field=models.DateTimeField(blank=True, null=True)),
    ]
