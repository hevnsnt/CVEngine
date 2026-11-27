"""The owner's per sign-in switch that lets an external Sentinel read a stored sign-in (agentapi.signin_delivery).

A database default of false: every stored sign-in keeps going only to the built-in scanner until its owner turns the switch on, and the code of the
version before, which does not know the column, can still store one during the update or after a rollback.
"""
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("cveFeed", "0195_resolve_untested_direct_send"),
    ]

    operations = [
        migrations.AddField(
            model_name="authcredential",
            name="allow_external_sentinels",
            field=models.BooleanField(default=False, db_default=False),
        ),
    ]
