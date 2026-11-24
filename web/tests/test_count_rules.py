"""One counting rule on every surface: the weekly email, the PDF report, the dashboard tiles and the Findings list are built from one fixture and
the numbers they share must be equal.

The rule (``cveFeed.counts``): a finding is open when it is not closed by a person (fixed, accepted risk, false positive) and the triage did not
dismiss it (``counts.dismissed_q``: classed a likely false positive or not applicable), of any kind; the heat line (fire, smoke, ice) counts the
open CVE matches and scanner findings (``counts.HEAT_KINDS``), the two kinds that carry a heat of their own, and says so beside it.

Before this, the email counted a scanner finding the triage dismissed (375 on the live install where the PDF said 370, the five dismissed
ones), and its heat line counted CVE matches only while the PDF's counted CVE matches and scanner findings.
"""
from agentapi.services import Ctx, list_findings
from cveFeed import counts, overview, report_data, report_digest
from cveFeed.models import CVEEntry, CVEMatch, Triage
from startScan.models import Vulnerability
from tests.test_report_email_digest import END, Base
from tests.test_report_threats import NOW, START


class CountRuleBase(Base):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        web, dom, scan, www = cls.web, cls.domains['acme-web'], cls.scans['acme-web'], cls.www

        def finding(name, severity, classification=''):
            v = Vulnerability.objects.create(subdomain=www, target_domain=dom, scan_history=scan, name=name, severity=severity, source='nuclei',
                                             http_url='https://www.acme.test/', discovered_date=NOW)
            if classification:
                Triage.objects.create(project=web, domain=dom, host=www.name, kind='nuclei', vulnerability=v, status='triaged',
                                      classification=classification)
            return v

        cls.open_finding = finding('Exposed admin panel', 3, 'needs_validation')
        cls.low_finding = finding('Directory listing', 1)
        cls.dismissed = [finding('Vulnerable Host [mail1.zendesk.com] in TXT Record', 1, 'likely_false_positive'),
                         finding('IIS Shortname Vulnerability Detected', 1, 'not_applicable')]
        ice = CVEEntry.objects.create(cve_id='CVE-2099-7001', cvss=5.3, title='ice one', published_at=NOW,
                                      affected=[{'product': 'nginx', 'ranges': [{'introduced': '1.0.0', 'fixed': '1.20.0'}]}])
        cls.ice_match = CVEMatch.objects.create(cve_entry=ice, subdomain=www, matched_product='nginx', matched_version='1.18.0', version_in_range=True,
                                                confidence=.6, source='port')
        # closed automatically as a different product (triage not applicable) while its legacy verdict still read uncertain: open nowhere
        odd = CVEEntry.objects.create(cve_id='CVE-2099-7002', cvss=7.5, title='other product', published_at=NOW, affected=[])
        cls.na_match = CVEMatch.objects.create(cve_entry=odd, subdomain=www, matched_product='nginx', matched_version='1.18.0', version_in_range=True,
                                               confidence=.6, source='port', ai_verdict='uncertain')
        Triage.objects.create(project=web, domain=dom, host=www.name, kind='cve_match', match=cls.na_match, status='triaged',
                              classification='not_applicable')

    def surfaces(self, org=False):
        """The shared numbers of one scope as each surface computes them."""
        scope = self.scope(self.org_admin, **({'org': 'acme-org'} if org else {'project': 'acme-web'}))
        ids = list(scope.ids)
        digest = report_digest.build(scope, START, END, 'weekly', END)
        pdf = report_data.collect(scope.svc_scope(), org=scope.org if org else None)
        hosts_pdf = report_data.collect(scope.svc_scope(), org=scope.org if org else None, kind='hosts', now=NOW)
        dash = {'matches': counts.exposed_matches().filter(subdomain__target_domain__project_id__in=ids).count(),
                'scanner': counts.actionable_findings(Vulnerability.objects.filter(target_domain__project_id__in=ids)).count(),
                'needs': overview.needs_hosts(ids)}
        slug = '_all' if org else 'acme-web'
        listed = list_findings(Ctx(user=self.org_admin), slug, {'page_size': 0})  # the organization admin sees exactly the organization's projects
        return digest, pdf, hosts_pdf, dash, listed


class CountConsistencyTests(CountRuleBase):
    def test_email_pdf_dashboard_and_findings_agree(self):
        for org in (False, True):
            digest, pdf, hosts_pdf, dash, listed = self.surfaces(org)
            h, s = digest['headline'], pdf['summary']
            with self.subTest(org=org):
                # the open CVE matches and scanner findings
                self.assertEqual(s['by_kind']['cve'], dash['matches'])
                self.assertEqual(s['by_kind']['cve'], listed['counts']['cve'])
                self.assertEqual(s['by_kind']['scanner'], dash['scanner'])
                self.assertEqual(s['by_kind']['scanner'], listed['counts']['scanner'])
                self.assertEqual(h['heat_kinds'], s['by_kind'])
                # the heat line: one definition, the same numbers in the email, the findings PDF and the hosts PDF
                self.assertEqual(h['heat'], s['heat'])
                self.assertEqual(h['heat'], hosts_pdf['summary']['heat'])
                self.assertEqual(sum(h['heat'].values()), s['findings'])
                # every open finding of low severity or worse, hygiene too: the email's total is the Findings list's
                self.assertEqual(h['open_findings'], listed['total'])
                self.assertEqual(h['open_findings'], s['findings'] + s['hygiene'])
                # the hosts that need attention: the Overview's tile is the email's number
                self.assertEqual(h['needs'], dash['needs'])

    def test_the_dismissed_findings_count_nowhere_and_are_still_listed_under_all(self):
        digest, pdf, _hosts, dash, listed = self.surfaces()
        scanner_open = Vulnerability.objects.filter(target_domain=self.domains['acme-web'], open_status=True, severity__gte=1).count()
        self.assertEqual(dash['scanner'], scanner_open - len(self.dismissed))  # exactly the two the triage dismissed
        self.assertEqual(pdf['summary']['ruled_out'], len(self.dismissed) + 1)  # and the CVE match: the PDF still says how many it left out
        self.assertNotIn(self.na_match.pk, set(counts.exposed_matches().values_list('pk', flat=True)))
        every = list_findings(Ctx(user=self.org_admin), 'acme-web', {'status': 'all', 'page_size': 100})
        shown = {(r['type'], r['id']) for r in every['results']}
        self.assertTrue({('scanner', v.pk) for v in self.dismissed} <= shown)
        self.assertIn(('cve', self.na_match.pk), shown)

    def test_the_heat_line_counts_scanner_findings_and_says_so(self):
        digest, pdf, _hosts, _dash, _listed = self.surfaces()
        self.assertGreater(pdf['summary']['by_kind']['scanner'], 0)
        cve_only = report_data._tally({'cve': report_data._sources(self.web, False)[0]['cve']})[1]
        self.assertNotEqual(digest['headline']['heat'], cve_only)  # the scanner findings' heat is in the line
        _, text, html = report_digest.render(digest, None, 'a@example.org', 'https://x/u/')
        self.assertIn('(CVE matches and scanner findings by heat)', text)
        self.assertIn('CVE matches and scanner findings by heat', html)
        self.assertNotIn('(CVE matches by heat)', text)

    def test_no_individual_heat_changes(self):
        """The rule decides what is counted, never a finding's own heat: a dismissed finding keeps the heat it shows in the list."""
        before = {r['id']: r['heat'] for r in list_findings(Ctx(user=self.org_admin), 'acme-web', {'status': 'all', 'type': 'scanner', 'page_size': 100})['results']}
        Triage.objects.filter(vulnerability__in=self.dismissed).update(classification='needs_validation')
        after = {r['id']: r['heat'] for r in list_findings(Ctx(user=self.org_admin), 'acme-web', {'status': 'all', 'type': 'scanner', 'page_size': 100})['results']}
        self.assertEqual(before, after)
