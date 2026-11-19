from django.db import migrations


class Migration(migrations.Migration):
    """Drop the classic HackerOne report settings (``scanEngine_hackerone``): only the Django admin listed them; a submission to HackerOne is
    sent under the person's own credentials (cveFeed.bounty_api). Schema only."""

    dependencies = [
        ("scanEngine", "0007_delete_installedexternaltool"),
    ]

    operations = [
        migrations.DeleteModel(
            name="Hackerone",
        ),
    ]
