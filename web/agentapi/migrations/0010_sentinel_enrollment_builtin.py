from django.db import migrations, models


class Migration(migrations.Migration):
    # Numbered 0008 on 1.4-develop before develop's 0008 and 0009 (released in 1.3.x) were merged in: renumbered past them, and
    # ``replaces`` keeps a database that already applied it under the old name from applying it twice. It still follows 0007, so
    # 1.4's chain (this to 0014) and develop's 0008 and 0009 are two branches, joined by 0015_merge_agent_hold: a database that has
    # 1.4's chain and not develop's two must still get them, which it would not if this one followed 0009 and were marked applied.
    replaces = [("agentapi", "0008_sentinel_enrollment_builtin")]
    dependencies = [("agentapi", "0007_sentinel_network")]
    operations = [
        migrations.AddField(model_name="sentinelenrollment", name="builtin", field=models.BooleanField(default=False, db_default=False)),
    ]
