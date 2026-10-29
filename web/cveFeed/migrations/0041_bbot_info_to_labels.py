import re

from django.db import migrations

# Frozen copy of reNgine.bbot (short_title, is_informational, label_for) as of this migration.
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


# Informational bbot detections ("WAF Detection", "Nginx version detect", "uses federated authentication") are host labels, not
# findings. The cutoff is conservative, because a real exposure dropped is a false negative:
#   * bbot severity LOW or higher is always a finding, whatever the text;
#   * text that reads like an exposure (leak, takeover, missing SPF/DMARC, a bucket, a credential...) is always a finding, even at
#     info: it is hidden by the list's default severity filter but never lost;
#   * otherwise severity INFO that bbot stated is a label, and so is a FINDING bbot gave no severity when its text reads like a
#     detection (detect, version, WAF, technology, federated, ...). Anything else with no severity stays a finding.
_EXPOSURE = re.compile(
    r'leak|disclos|credential|secret|passw|token|api[ _-]?key|takeover|vulnerab|misconfig|\bno (spf|dmarc|dkim|dnssec|caa|mx)\b|'
    r'\bmissing\b|default (login|cred|pass)|backup|\.git\b|\.env\b|directory listing|bucket|unauth|anonymous|admin(istrat\w+)? panel|'
    r'open redirect|inject|traversal|\bcve-\d|\bexploit|\bexpos(ed|ure)\b.*\b(database|admin|panel|file|key|config)|private key|sensitive',
    re.I)
_DETECTION = re.compile(
    r'detect|version|\bwaf\b|firewall|technolog|fingerprint|identified|federated|powered by|\buses\b|response \(body\)|\bcdn\b|banner', re.I)
_DETECTION_LABELS = (
    (re.compile(r'\bwaf\b|web application firewall', re.I), 'WAF'),
    (re.compile(r'federated auth', re.I), 'federated auth'),
    (re.compile(r'^http response \(body\)', re.I), 'response body match'),
)
_VERSION_DETECT = re.compile(r'^(.+?)\s+version\b', re.I)
_DETECT_TAIL = re.compile(r'\s*\b(detect(ed|ion|ed)?|identified)\b\s*$', re.I)
LABEL_MAX = 40


def is_informational(name, description, severity, severity_stated=True):
    """True for a bbot detection that is a host label rather than a finding (see the cutoff above). Pure."""
    if severity and severity > 0:
        return False
    text = f'{name} {description}'
    if _EXPOSURE.search(text):
        return False
    return True if severity_stated else bool(_DETECTION.search(name or ''))


def label_for(name):
    """A short chip label for a detection name: "WAF Detection" -> "WAF", "Nginx version detect" -> "nginx version", a
    sensible fallback (the first four words without a trailing "detect") for the rest. Bounded to ``LABEL_MAX``. Pure."""
    title = short_title(name)
    for pattern, label in _DETECTION_LABELS:
        if pattern.search(title):
            return label
    m = _VERSION_DETECT.match(title)
    if m and len(m.group(1)) <= 24:
        product = m.group(1)
        return f'{product.lower() if product.istitle() else product} version'
    words = _DETECT_TAIL.sub('', title).split()
    return (' '.join(words[:4])[:LABEL_MAX].rstrip(' ,;-:') or 'detection')


BATCH = 500
MAX_ROWS = 50000  # bounded


def to_labels(apps, schema_editor):
    """Informational bbot detections were stored as info-severity findings. Turn the ones that read as pure detections into host
    labels and remove those finding rows. Conservative: only severity 0 rows from bbot, never anything that reads like an exposure
    (is_informational, frozen above), never a row that has a triage record, and never a row without a host. Low-or-higher findings are
    not touched. Idempotent: a second run finds nothing left to move; labels already present are kept."""
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
