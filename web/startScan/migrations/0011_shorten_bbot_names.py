from django.db import IntegrityError, migrations, transaction

MAX_ROWS = 100000  # bounded


def shorten(apps, schema_editor):
    """bbot findings were named with their whole description. Recompute the name from the description (the description is kept as
    is) and set the matcher key to a digest of the full text, which is what keeps two findings with the same short name apart (and
    makes a rescan update these rows instead of adding twins). Idempotent. A row that would collide with another under the unique
    finding key keeps its old name. Never touches other sources."""
    from reNgine.bbot import finding_key, short_title
    Vulnerability = apps.get_model('startScan', 'Vulnerability')
    rows = Vulnerability.objects.filter(source='bbot').exclude(description__isnull=True).exclude(description='') \
        .only('id', 'name', 'description', 'matcher_name').order_by('id')[:MAX_ROWS]
    for v in rows.iterator(chunk_size=500):
        title, key = short_title(v.description), finding_key(v.description)
        if title == v.name and v.matcher_name == key:
            continue
        try:
            with transaction.atomic():
                Vulnerability.objects.filter(pk=v.pk).update(name=title, matcher_name=key)
        except IntegrityError:
            continue


class Migration(migrations.Migration):

    dependencies = [('startScan', '0010_ip_full_scan')]

    operations = [migrations.RunPython(shorten, migrations.RunPython.noop)]
