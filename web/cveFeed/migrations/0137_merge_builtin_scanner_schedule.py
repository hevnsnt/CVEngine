from django.db import migrations


class Migration(migrations.Migration):
    """Joins the two cveFeed leaves the 1.3.2 merge left: 1.4-develop's 0129_builtin_scanner_schedule and develop's 0130 to 0136, which both follow
    0129_feedwatermark_failures_assumed. Neither is renumbered (each is applied somewhere under its name, and develop's are released), so one
    graph leaf comes from this empty merge instead. Nothing runs."""

    dependencies = [
        ('cveFeed', '0129_builtin_scanner_schedule'),
        ('cveFeed', '0136_cvematch_fire_notified'),
    ]
    operations = []
