"""The PDF of a big project or organization must stay a readable report of a few dozen pages and render in seconds.

WeasyPrint lays a ``display: grid`` box out by measuring the min and max content of every cell, and ``overflow-wrap: anywhere`` on the whole
body makes it count every possible break in every min-content width: with ~3000 key/value lists in a 500-host report those two were over
half of a 40 s render (scripts/scale, SCALE-REPORT.md). The template keeps them out of the repeated parts.

The findings report groups findings into issues and writes up only the critical, high and medium ones (cveFeed.report_data), so its size
follows the number of distinct serious issues, not the number of findings: ``build_org`` makes an organization shaped like a real tenant (a
few hundred hosts, hundreds of version-only CVE matches, mostly low-heat, and a long tail of scanner and hygiene findings) and the report
of it must stay within a page budget. ``CVENGINE_REPORT_SCALE=1`` runs the full-size tenant too (about 650 CVE matches on 300 hosts and
1,000 scanner and hygiene findings) and prints its page count and render time; ``CVENGINE_REPORT_SCALE_OUT=<dir>`` keeps its PDF there."""
import os
import random
import re
import shutil
import tempfile
import time
import unittest
from datetime import timedelta

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone
from pypdf import PdfReader

from agentapi import report_scope
from agentapi.services import Ctx
from cveFeed import report_data, report_pdf
from cveFeed.models import CVEEntry, CVEMatch, HygieneFinding
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain

TEMPLATE = os.path.join(os.path.dirname(report_pdf.__file__), 'templates', 'cveFeed', 'report.html')


def stylesheet():
    return re.sub(r'/\*.*?\*/', '', open(TEMPLATE, encoding='utf-8').read().split('</style>')[0], flags=re.DOTALL)


# products the synthetic hosts run: (product, versions seen, fixed releases, port)
PRODUCTS = (('PHP', ('7.4.33', '8.1.2', '8.2.10'), ('8.1.29', '8.2.20', '8.3.8'), 443), ('nginx', ('1.18.0', '1.22.1'), ('1.25.5', '1.26.1'), 443),
            ('Apache httpd', ('2.4.41', '2.4.52'), ('2.4.62',), 80), ('OpenSSH', ('7.4', '8.2p1', '8.9p1'), ('9.8p1',), 22),
            ('Microsoft IIS', ('10.0',), (), 443), ('jQuery', ('1.12.4', '3.4.1'), ('3.5.0',), 443), ('Exim', ('4.94',), ('4.97.1',), 25),
            ('ProFTPD', ('1.3.5',), ('1.3.8b',), 21))
SCANNER_TEMPLATES = (('Exposed .git directory', 'git-config', 3), ('Apache Tomcat manager login page', 'tomcat-manager', 2),
                     ('Directory listing enabled', 'dir-listing', 2), ('phpinfo page exposed', 'phpinfo', 2), ('Missing security headers', 'http-missing-headers', 1),
                     ('Server version disclosed in a header', 'server-header', 1), ('WordPress user enumeration', 'wp-users', 2),
                     ('Open redirect', 'open-redirect', 2), ('Cookie without the Secure flag', 'cookie-secure', 1), ('Weak TLS cipher suites', 'weak-cipher', 1),
                     ('robots.txt discloses paths', 'robots-paths', 1), ('Default IIS page', 'iis-default', 1), ('CORS allows any origin', 'cors-any', 2),
                     ('Elasticsearch without authentication', 'elastic-noauth', 3), ('Grafana login page', 'grafana-login', 1))
HYGIENE_CHECKS = (('tls_expired', 4, 'Certificate for {h}:443 expired', 3), ('tls_self_signed', 2, 'Self-signed certificate on {h}:443', 15),
                  ('hsts_missing', 1, 'No HSTS on {h}', 160), ('tls_legacy_protocol', 2, 'TLS 1.0 enabled on {h}:443', 70),
                  ('tls_expiring', 2, 'Certificate for {h}:443 expires in 12 days', 10), ('cleartext_ftp', 3, 'FTP login over cleartext on {h}', 2),
                  ('tls_hostname_mismatch', 2, 'Certificate does not name {h}', 25))


def build_org(projects=8, hosts=300, cves=60, matches=650, scanner=600, hygiene=400, seed=7):
    """An organization shaped like a real tenant, and a superuser who can read it. Returns ``(org, user)``."""
    rng = random.Random(seed)
    now = timezone.now()
    org = Org.objects.create(name='Marlow Holdings', slug='marlow')
    user = User.objects.create_user('scale-admin', password='x', is_superuser=True)
    engine = EngineType.objects.create(engine_name='scale', yaml_configuration='x')
    subs = []
    for p in range(projects):
        project = Project.objects.create(name=f'Region {p + 1}', slug=f'region-{p + 1}', insert_date=now, org=org)
        domain = Domain.objects.create(name=f'region{p + 1}.example.test', project=project, insert_date=now)
        scan = ScanHistory.objects.create(domain=domain, scan_type=engine, scan_status=2, start_scan_date=now - timedelta(days=p), tasks=[])
        for i in range(hosts // projects):
            subs.append((Subdomain(name=f'h{i:03d}.region{p + 1}.example.test', target_domain=domain, scan_history=scan, http_status=200, score=rng.randint(0, 90)), domain, scan))
    Subdomain.objects.bulk_create([s for s, _, _ in subs])
    ips = IpAddress.objects.bulk_create([IpAddress(address=f'10.{n // 250}.{n % 250}.{n % 7 + 1}') for n in range(len(subs))])
    host_products = []
    for n, ((sub, domain, scan), ip) in enumerate(zip(subs, ips)):
        sub.ip_addresses.add(ip)
        mine = rng.sample(PRODUCTS, rng.randint(1, 3))
        for product, versions, _, port in mine:
            ip.ports.add(Port.objects.create(number=port, service_name='http' if port in (80, 443) else 'svc', product=product, version=versions[0], state='open'))
        host_products.append((sub, domain, scan, ip, [(p, rng.choice(v), port) for p, v, _, port in mine]))
    entries = []
    for c in range(cves):
        product, _, fixed, _ = PRODUCTS[c % len(PRODUCTS)]
        hot = c in (0, 1, 2)  # three known-exploited CVEs, one with a public exploit
        entries.append(CVEEntry(cve_id=f'CVE-2025-{4000 + c}', cvss=round(rng.uniform(4.3, 9.8), 1), kev=c in (0, 1), exploit_db=hot, published_at=now,
                                title=f'{product} flaw number {c}', summary=f'A flaw in {product} lets a remote attacker do something unwelcome ({c}).',
                                affected=[{'product': product.lower(), 'ranges': [{'introduced': '0', 'fixed': f}] } for f in fixed]))
    CVEEntry.objects.bulk_create(entries)
    by_product = {}
    for e, c in zip(entries, range(cves)):
        by_product.setdefault(PRODUCTS[c % len(PRODUCTS)][0], []).append(e)
    rows, seen = [], set()
    while len(rows) < matches:
        sub, domain, scan, ip, mine = rng.choice(host_products)
        product, version, port = rng.choice(mine)
        cve = rng.choice(by_product[product])
        if (sub.pk, cve.pk) in seen:
            continue
        seen.add((sub.pk, cve.pk))
        confirmed = cve.cve_id == 'CVE-2025-4000' and len([r for r in rows if r.cve_entry_id == cve.pk]) < 2
        rows.append(CVEMatch(cve_entry=cve, subdomain=sub, scan_history=scan, matched_product=product, matched_version=version, version_in_range=True,
                             confidence=.7, source='port', evidence={'ip': ip.address, 'port': port, 'method': 'probed'},
                             template_result='vulnerable' if confirmed else '', template_id='synthetic-check' if confirmed else ''))
    CVEMatch.objects.bulk_create(rows)
    vulns, seen = [], set()
    while len(vulns) < scanner:
        sub, domain, scan, _, _ = rng.choice(host_products)
        name, template, severity = SCANNER_TEMPLATES[min(len(SCANNER_TEMPLATES) - 1, int(rng.expovariate(0.25)))]
        if (sub.pk, template) in seen:
            continue
        seen.add((sub.pk, template))
        vulns.append(Vulnerability(name=name, template_id=template, severity=severity, source='nuclei', subdomain=sub, target_domain=domain, scan_history=scan,
                                   open_status=True, http_url=f'https://{sub.name}/{template}', discovered_date=now, description=f'{name} on the host.',
                                   remediation=f'Fix the {name.lower()} condition.'))
    Vulnerability.objects.bulk_create(vulns)
    found, made = [], 0
    for check, severity, title, count in HYGIENE_CHECKS:
        for sub, domain, _, _, _ in rng.sample(host_products, min(count, len(host_products))):
            if made >= hygiene:
                break
            found.append(HygieneFinding(domain=domain, host=sub.name, check_name=check, severity=severity, title=title.format(h=sub.name),
                                        detail=f'{check} seen on {sub.name}.', evidence={'port': 443}))
            made += 1
    for d in Domain.objects.filter(project__org=org):
        found.append(HygieneFinding(domain=d, host=d.name, check_name='spf_missing', severity=2, title='No SPF record', detail='No SPF record is published.'))
        found.append(HygieneFinding(domain=d, host=d.name, check_name='dmarc_none', severity=1, title='DMARC policy is p=none', detail='Monitoring only.'))
    HygieneFinding.objects.bulk_create(found)
    return org, user


def render(data, keep=None):
    """``(pages, seconds, html bytes)`` of the real PDF of ``data``; the PDF is copied to ``keep`` when given."""
    html = report_pdf.build_html(data)
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, 'r.pdf')
        start = time.monotonic()
        report_pdf.render_pdf(html, path, timeout=600)
        took = time.monotonic() - start
        pages = len(PdfReader(path).pages)
        if keep:
            shutil.copy(path, keep)
    return pages, took, len(html)


class TemplateLayoutTests(SimpleTestCase):
    def test_repeated_blocks_do_not_use_grid_layout(self):
        css = stylesheet()
        self.assertNotRegex(css, r'display:\s*grid', 'a grid is measured cell by cell: use floats or a table for the key/value lists')

    def test_anywhere_wrapping_is_only_on_table_cells(self):
        css = stylesheet()
        for rule in re.findall(r'([^{}]+)\{([^{}]*overflow-wrap:\s*anywhere[^{}]*)\}', css):
            self.assertRegex(rule[0], r'^\s*(table\.grid t[dh]|\.cover td)', rule[0])


class RenderTimeTests(TestCase):
    FINDINGS = 120

    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        project = Project.objects.create(name='R', slug='rr', insert_date=now, org=Org.objects.create(name='R', slug='rr-org'))
        domain = Domain.objects.create(name='rr.example.test', project=project, insert_date=now)
        scan = ScanHistory.objects.create(domain=domain, scan_type=EngineType.objects.create(engine_name='rr'), start_scan_date=now, scan_status=2)
        for i in range(cls.FINDINGS):
            sub = Subdomain.objects.create(name=f'h{i}.rr.example.test', target_domain=domain, scan_history=scan, http_status=200)
            ip = IpAddress.objects.create(address=f'192.0.2.{i % 250 + 1}')
            ip.ports.add(Port.objects.create(number=8000 + i, service_name='http', state='open'))
            sub.ip_addresses.add(ip)
            Vulnerability.objects.create(name=f'Finding {i % 30}', severity=3, subdomain=sub, target_domain=domain, scan_history=scan, open_status=True,
                                         http_url=f'https://h{i}.rr.example.test/a', discovered_date=now, description='x ' * 150, impact='y ' * 100)
        cls.project = project

    def test_a_report_of_many_findings_renders_in_seconds(self):
        data = report_data.collect(self.project)
        self.assertEqual(len(data['issues']), 30)  # 120 findings of 30 titles: 30 issues of 4 hosts each
        self.assertEqual({i['host_count'] for i in data['issues']}, {4})
        html = report_pdf.build_html(data)
        self.assertEqual(html.count('<article class="issue'), 30)
        with tempfile.TemporaryDirectory() as d:
            start = time.monotonic()
            report_pdf.render_pdf(html, os.path.join(d, 'r.pdf'), timeout=120)
            took = time.monotonic() - start
            pages = len(PdfReader(os.path.join(d, 'r.pdf')).pages)
        self.assertLess(took, 30, f'{took:.1f} s for {self.FINDINGS} findings')
        self.assertLess(pages, 40)


class OrgSizeTests(TestCase):
    """A smaller tenant of the same shape, always run: the report stays short, the write-ups are the serious issues only, and the version-only
    tail goes to the appendix."""

    @classmethod
    def setUpTestData(cls):
        cls.org, cls.user = build_org(projects=4, hosts=80, cves=30, matches=200, scanner=150, hygiene=120)

    def test_the_report_of_a_tenant_is_grouped_short_and_fast(self):
        scope = report_scope.resolve(Ctx(user=self.user), org='marlow')
        data = report_data.collect(scope.svc_scope(), org=scope.org)
        self.assertGreater(data['summary']['findings'], 300)
        self.assertLess(len(data['issues']), 120)  # 200 matches of 30 CVEs, 150 scanner findings of 15 templates, 9 hygiene checks
        self.assertTrue(all(i['level'] in report_data.DETAILED for i in data['detailed']))
        self.assertTrue(all(i['level'] not in report_data.DETAILED for i in data['minor']))
        self.assertEqual(data['issues'][0]['level'], 'critical')  # the KEV CVE a check confirmed
        pages, took, _ = render(data)
        self.assertLess(pages, 40, pages)
        self.assertLess(took, 60, f'{took:.1f} s')


@unittest.skipUnless(os.environ.get('CVENGINE_REPORT_SCALE'), 'set CVENGINE_REPORT_SCALE=1 to render the full-size tenant')
class FullSizeOrgTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org, cls.user = build_org()

    def test_the_full_size_tenant(self):
        scope = report_scope.resolve(Ctx(user=self.user), org='marlow')
        start = time.monotonic()
        data = report_data.collect(scope.svc_scope(), org=scope.org)
        collected = time.monotonic() - start
        out = os.environ.get('CVENGINE_REPORT_SCALE_OUT')
        pages, took, size = render(data, keep=os.path.join(out, 'org-report.pdf') if out else None)
        print(f'\nfull-size tenant: {data["summary"]["findings"]} findings + {data["summary"]["hygiene"]} hygiene, {len(data["issues"])} issues, '
              f'{len(data["detailed"])} write-ups; collect {collected:.1f} s, HTML {size // 1024} KB, {pages} pages in {took:.1f} s')
        self.assertLess(pages, 45)
