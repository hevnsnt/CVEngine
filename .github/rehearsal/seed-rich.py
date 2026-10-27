"""More data in the INSTALLED (old) version, for the rehearsal: a bulk domain with hosts, CVEs and 5000 CVE matches, half of them closed under
the first wording of the product-correlation closure ("invalid product correlation") that a newer version rewrites. Run inside the web container:
`manage.py shell < seed-rich.py`. It only uses what the released version has, and leaves the rehearsal's own seed (rehearsal.example) alone."""
from django.utils import timezone

from cveFeed.models import CVEEntry, CVEMatch, TriageVerdict
from dashboard.models import Org, Project
from startScan.models import Subdomain
from targetApp.models import Domain

now = timezone.now()
project = Project.objects.filter(slug='rehearsal').first()
if project is None:
    org = Org.objects.first() or Org.objects.create(name='Rehearsal Org', slug='rehearsal-org')
    project = Project.objects.create(name='Rehearsal', slug='rehearsal', insert_date=now, org=org)
domain, _ = Domain.objects.get_or_create(name='bulk.rehearsal.example', project=project, defaults={'insert_date': now})
OLD_1 = ('Closed automatically: invalid product correlation; the recorded product identity does not match an affected product in the advisory. '
         'This closes this candidate match only; it does not establish that the software is absent elsewhere on the host.')
OLD_2 = ('Closed automatically: invalid product correlation; the recorded fingerprint is a generic cloud or service label, not the affected product. '
         'This closes this candidate match only; it does not establish that the software is absent elsewhere on the host.')
subs = [Subdomain.objects.get_or_create(target_domain=domain, name=f'm{i}.bulk.rehearsal.example')[0] for i in range(300)]
matches = 0
for c in range(200):
    cve, _ = CVEEntry.objects.get_or_create(cve_id=f'CVE-2025-{10000 + c}', defaults={
        'title': f'rehearsal cve {c}', 'affected': [{'vendor': 'v', 'product': f'p{c}'}], 'published_at': now, 'created_at': now, 'synced_at': now})
    for sub in subs[:25]:
        CVEMatch.objects.get_or_create(cve_entry=cve, subdomain=sub, matched_product='p', matched_version='1.0', source='tech', defaults={
            'version_in_range': True, 'ai_verdict': 'not_affected' if c % 2 else '',
            'ai_reason': OLD_1 if c % 4 == 1 else OLD_2 if c % 4 == 3 else '', 'created_at': now, 'updated_at': now})
        matches += 1
for c in range(0, 200, 4):
    TriageVerdict.objects.get_or_create(kind='cve_match', signature=f'rehearsal{c}', defaults={
        'classification': 'not_applicable', 'reason': OLD_1})
print('SEEDED RICH', matches, 'matches,', CVEMatch.objects.filter(ai_reason__contains='invalid product correlation').count(), 'with the old wording')
