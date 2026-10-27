from django.utils import timezone
from django.contrib.auth.models import User
from dashboard.models import Project, Org
from targetApp.models import Domain
from startScan.models import Subdomain, IpAddress, ScanHistory
from cveFeed.models import CVEEntry, CVEMatch, TriageVerdict, Triage, MatchVerdict, HostExclusion
import inspect
now = timezone.now()
org = Org.objects.first() or Org.objects.create(name='Rehearsal Org', slug='rehearsal-org')
project = Project.objects.filter(slug='rehearsal').first() or Project.objects.create(name='Rehearsal', slug='rehearsal', insert_date=now, org=org) if 'org' in [f.name for f in Project._meta.fields] else Project.objects.create(name='Rehearsal', slug='rehearsal', insert_date=now)
domain = Domain.objects.create(name='rehearsal.example', project=project, insert_date=now)
LEGACY = ('Closed automatically: invalid product correlation; the recorded product identity does not match an affected product in the advisory. '
          'This closes this candidate match only; it does not establish that the software is absent elsewhere on the host.')
LEGACY2 = ('Closed automatically: invalid product correlation; the recorded fingerprint is a generic cloud or service label, not the affected product. '
           'This closes this candidate match only; it does not establish that the software is absent elsewhere on the host.')
n = 0
subs = []
for i in range(300):
    s = Subdomain.objects.create(target_domain=domain, name=f'h{i}.rehearsal.example')
    subs.append(s)
for c in range(200):
    cve = CVEEntry.objects.create(cve_id=f'CVE-2025-{10000+c}', title=f'cve {c}', affected=[{'vendor': 'v', 'product': 'p%d' % c}], published_at=now, created_at=now, synced_at=now)
    for s in subs[:25]:
        m = CVEMatch.objects.create(cve_entry=cve, subdomain=s, matched_product='p', matched_version='1.0', version_in_range=True,
                                    ai_verdict='not_affected' if c % 2 else '', ai_reason=(LEGACY if c % 4 == 1 else LEGACY2 if c % 4 == 3 else ''), source='tech', created_at=now, updated_at=now)
        n += 1
for c in range(0, 200, 4):
    TriageVerdict.objects.create(kind='cve_match', signature='sig%d' % c, classification='not_applicable', reason=LEGACY)
print('SEEDED matches', n, 'subdomains', Subdomain.objects.count(), 'cves', CVEEntry.objects.count(), 'legacy rows',
      CVEMatch.objects.filter(ai_reason__contains='invalid product correlation').count(), TriageVerdict.objects.filter(reason__contains='invalid product correlation').count())
