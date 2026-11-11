from django.db import migrations, models


class Migration(migrations.Migration):
    """The partial index behind ``detection_author.progress``: ``GROUP BY source`` over the CVE detections that have checks (``strategy`` is not ``{}``) took up
    to 6.4 s on a production instance because it read the ``strategy`` JSON of all 38,000 rows. The index holds the rows that have checks, with their source and
    id, so the count is an index-only scan. An index on a table of tens of thousands of rows builds in under a second, so it is built in the migration's own
    transaction. Index only: no column, no data."""

    dependencies = [('cveFeed', '0158_scancontrol_update_window')]

    operations = [
        migrations.AddIndex(
            model_name='cvedetection',
            index=models.Index(fields=['source', 'id'], name='cvedetection_source_filled_idx', condition=models.Q(('strategy', {}), _negated=True)),
        ),
    ]
