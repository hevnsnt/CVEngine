from django.db import migrations


def baseline(apps, schema_editor):
    """The update that introduces the KEV heat policy pages nothing it did not page before: every CVE match that is fire under the rule in force
    and was never paged is marked as announced (cveFeed.notify.baseline_heat_policy), before any worker runs. Later switches of the policy are
    baselined the same way by the workers. No schema change; idempotent."""
    from cveFeed import notify
    notify.baseline_heat_policy(match_model=apps.get_model("cveFeed", "CVEMatch"), cursor_model=apps.get_model("cveFeed", "BackgroundCursor"))


class Migration(migrations.Migration):
    dependencies = [
        ("cveFeed", "0136_cvematch_fire_notified"),
    ]

    operations = [
        migrations.RunPython(baseline, migrations.RunPython.noop),
    ]
