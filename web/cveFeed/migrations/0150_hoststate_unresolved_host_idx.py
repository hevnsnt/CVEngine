"""A partial index for the due-host query (cveFeed.coverage_topup.host_coverage_due), which asks for every host whether its name was tried and found no
address. Without it Postgres read the whole host-state table once per host (3000 hosts: 0.4 s a call, every minute and every five minutes). The index holds
only the rows that were tried, so it is tiny. Reversing drops it."""
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cveFeed', '0149_cve_explorer_search_index'),
    ]

    operations = [
        migrations.AddIndex(
            model_name='hoststate',
            index=models.Index(fields=['project', 'host'], condition=models.Q(unresolved_checks__gte=1), name='hoststate_unresolved_host_idx'),
        ),
    ]
