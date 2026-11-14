# Joins the two 0142 leaves: 1.4-develop's merge of the built-in scanner schedule with the update-window defaults, and 1.3.5's manual heat
# override from develop. Neither touches what the other does; nothing runs here.
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cveFeed', '0142_merge_0137_merge_builtin_scanner_schedule_0141_db_default_for_update_window'),
        ('cveFeed', '0142_triage_heat_override'),
    ]

    operations = []
