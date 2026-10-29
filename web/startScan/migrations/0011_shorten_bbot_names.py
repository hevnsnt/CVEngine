import re

from django.db import IntegrityError, migrations, transaction

# Frozen copy of reNgine.bbot (short_title, finding_key) as of this migration.
# Never import the live code into a migration: a later change to it must not alter (or break at import)
# what this migration does when a fresh install replays them all.
TITLE_MAX = 80
_TITLE_BREAK = re.compile(r'\s[-\u2013\u2014]\s|:\s|:$|\.\s|\n')


def short_title(description):
    """A concise finding name from bbot's description, which runs on into confidence, signature, trigger and module lines:
    "No DMARC record found - domain has no protection ... Trigger: [...]" -> "No DMARC record found". The text before the first
    " - ", ": ", ". " or line break, capped at ``TITLE_MAX`` on a word boundary. The full text stays in the description."""
    text = str(description or '').strip()
    head = ' '.join(_TITLE_BREAK.split(text, 1)[0].split()).strip(' -:.') or ' '.join(text.split())[:TITLE_MAX]
    if len(head) > TITLE_MAX:
        head = head[:TITLE_MAX].rsplit(' ', 1)[0].rstrip(' ,;-:') + '\u2026'
    return (head[:1].upper() + head[1:]) or 'Finding'


def finding_key(description):
    """A short stable digest of a finding's full text. The short name no longer tells two findings apart ("Open S3 bucket: a" and
    "...: b" are both "Open S3 bucket"), so the digest goes in the finding's matcher key and neither is merged into the other."""
    import hashlib
    return hashlib.sha1(str(description or '').encode('utf-8', 'replace')).hexdigest()[:16]


MAX_ROWS = 100000  # bounded


def shorten(apps, schema_editor):
    """bbot findings were named with their whole description. Recompute the name from the description (the description is kept as
    is) and set the matcher key to a digest of the full text, which is what keeps two findings with the same short name apart (and
    makes a rescan update these rows instead of adding twins). Idempotent. A row that would collide with another under the unique
    finding key keeps its old name. Never touches other sources."""
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
