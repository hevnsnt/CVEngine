from django.db import migrations

BATCH = 500
MAX_ROWS = 50000  # bounded


def to_labels(apps, schema_editor):
    """Informational bbot detections were stored as info-severity findings. Turn the ones that read as pure detections into host
    labels and remove those finding rows. Conservative: only severity 0 rows from bbot, never anything that reads like an exposure
    (reNgine.bbot.is_informational), never a row that has a triage record, and never a row without a host. Low-or-higher findings are
    not touched. Idempotent: a second run finds nothing left to move; labels already present are kept."""
    from reNgine.bbot import is_informational, label_for
    Vulnerability = apps.get_model('startScan', 'Vulnerability')
    Triage = apps.get_model('cveFeed', 'Triage')
    HostLabel = apps.get_model('cveFeed', 'HostLabel')
    qs = Vulnerability.objects.filter(source='bbot', severity=0, target_domain__isnull=False).select_related('subdomain', 'target_domain') \
        .order_by('id')[:MAX_ROWS]
    batch = []

    def flush():
        ids = [v.id for v in batch]
        triaged = set(Triage.objects.filter(vulnerability_id__in=ids).values_list('vulnerability_id', flat=True))
        move = []
        for v in batch:
            host = ((v.subdomain.name if v.subdomain_id else '') or (v.extracted_results or [''])[0] or '').strip().lower()
            if v.id in triaged or not host or not is_informational(v.name, v.description or '', 0, severity_stated=False):
                continue
            label = label_for(v.name)[:64]
            seen = v.discovered_date
            row = HostLabel.objects.filter(project_id=v.target_domain.project_id, host=host, label=label).first()
            if row is None and HostLabel.objects.filter(project_id=v.target_domain.project_id, host=host).count() < 30:
                row = HostLabel.objects.create(
                    project_id=v.target_domain.project_id, domain_id=v.target_domain_id, host=host, label=label, source='bbot',
                    detail=(v.name or '')[:300], **({'first_seen': seen, 'last_seen': seen} if seen else {}))
            if row is not None:  # only a finding whose label exists is removed: nothing is lost
                move.append(v.id)
        Vulnerability.objects.filter(id__in=move).delete()
        batch.clear()

    for v in qs.iterator(chunk_size=BATCH):
        batch.append(v)
        if len(batch) >= BATCH:
            flush()
    if batch:
        flush()


class Migration(migrations.Migration):

    dependencies = [('cveFeed', '0040_hostlabel'), ('startScan', '0011_shorten_bbot_names')]

    operations = [migrations.RunPython(to_labels, migrations.RunPython.noop)]
