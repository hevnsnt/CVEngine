from django.db import migrations


class Migration(migrations.Migration):
    """Joins develop's 0008_clear_stale_status_note and 0009_agent_hold (released in 1.3.x) and 1.4's chain 0010 to 0014, which both follow
    0007_sentinel_network. Nothing runs. This is the leaf, and it is never applied anywhere yet, so ``migrate`` plans every unapplied node
    under it: a database that applied 1.4's chain under its old names (``replaces`` marks the renumbered ones applied) still gets
    develop's two."""

    dependencies = [
        ("agentapi", "0009_agent_hold"),
        ("agentapi", "0014_sentinel_defaults_kinds"),
    ]
    operations = []
