from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):
    """One index, built CONCURRENTLY outside a transaction like 0174, so the CVE feed sync is never blocked while it builds. Index only: no column, no data.

    ``cvefeed_pub_id_desc_idx`` is the CVE explorer's order (``cve_explorer.search``: ``published_at`` newest first with undated rows last, then
    ``id`` newest first). ``cvefeed_pub_idx`` is ascending with nulls last, which no scan direction turns into that order, so every page of
    GET /cve/api/cves read and sorted the whole catalogue (18,500 buffers, 78 to 137 ms on 59,000 CVEs); in index order a page reads its 50 rows."""

    atomic = False

    dependencies = [('cveFeed', '0191_ct_lookup_day')]

    operations = [
        AddIndexConcurrently(model_name='cveentry', index=models.Index(models.F('published_at').desc(nulls_last=True), models.F('id').desc(),
                                                                      name='cvefeed_pub_id_desc_idx')),
    ]
