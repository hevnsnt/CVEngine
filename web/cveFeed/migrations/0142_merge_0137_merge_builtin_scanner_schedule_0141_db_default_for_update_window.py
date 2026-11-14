from django.db import migrations


class Migration(migrations.Migration):
    """Joins the two cveFeed leaves the 1.3.3/1.3.4 sync left: 1.4-develop's 0137_merge_builtin_scanner_schedule and develop's 0138 to 0141, which
    both follow 0136_cvematch_fire_notified. Neither is renumbered (each is applied somewhere under its name, and develop's are released), so one
    graph leaf comes from this empty merge instead. Nothing runs."""

    dependencies = [
        ('cveFeed', '0137_merge_builtin_scanner_schedule'),
        ('cveFeed', '0141_db_default_for_update_window'),
    ]
    operations = []
