from django.db import migrations, models


class Migration(migrations.Migration):
    """When a CVE match was announced as fire (cveFeed.notify): a nullable column with no default, so adding it rewrites nothing."""

    dependencies = [
        ("cveFeed", "0135_autotune"),
    ]

    operations = [
        migrations.AddField(
            model_name="cvematch",
            name="fire_notified_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
