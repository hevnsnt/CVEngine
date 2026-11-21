"""The findings report as a penetration test report (cveFeed.report_data): findings grouped into issues across hosts, the five severity levels,
the order of the summary of findings, low and informational issues in the appendix, the caps and their "N more" lines, and the executive
summary of a scope with nothing open. The HTML stage is read here (fast); tests.test_report_pdf renders real PDFs."""
import os
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import report_scope
from agentapi.services import Ctx
from cveFeed import report_data, report_pdf
from cveFeed.models import CVEEntry, CVEMatch, HygieneFinding, ServiceRun, Triage
from cveFeed.report_data import cve_base, rate
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain

NOW = timezone.now()


class SeverityTests(SimpleTestCase):
    def test_a_cve_carries_its_band_and_the_kev_list_makes_it_critical(self):
        self.assertEqual([cve_base(c, False) for c in (9.8, 9.0, 7.5, 5.0, 3.1, None)], ['critical', 'critical', 'high', 'medium', 'low', 'medium'])
        self.assertEqual(cve_base(5.0, True), 'critical')

    def test_heat_caps_the_base_the_way_the_rest_of_cvengine_rates_it(self):
        cases = [
            # (kind, heat, base, flags, expected)
            ('cve', 'fire', 'critical', {'kev': True, 'confirmed': True}, 'critical'),  # on the KEV and proven on the host
            ('cve', 'fire', 'high', {'confirmed': True}, 'high'),  # a public exploit, proven, CVSS 7.5
            ('cve', 'smoke', 'critical', {'kev': True, 'version_only': True}, 'high'),  # on the KEV, version not proven
            ('cve', 'smoke', 'medium', {'version_only': True}, 'medium'),
            ('cve', 'ice', 'critical', {'version_only': True}, 'low'),  # CVSS 9.8, not exploited, version only: the long tail
            ('cve', 'ice', 'critical', {'confirmed': True}, 'medium'),  # proven but not exploited: proof outranks the missing signal
            ('cve', 'ice', 'high', {'weak': True}, 'info'),  # a backported fix, an unknown version or CVSS below 4
            ('scanner', 'smoke', 'critical', {}, 'high'),  # a template's critical waits for a check to confirm it
            ('scanner', 'fire', 'critical', {'confirmed': True}, 'critical'),
            ('scanner', 'ice', 'high', {}, 'low'),
            ('scanner', 'ice', 'info', {}, 'info'),
            ('hygiene', 'fire', 'critical', {}, 'high'),  # a configuration finding is at most High
            ('hygiene', 'smoke', 'medium', {}, 'medium'),
            ('cve', '', 'high', {}, 'info'),
        ]
        for kind, heat, base, flags, expected in cases:
            self.assertEqual(rate(kind, heat, base, **flags), expected, (kind, heat, base, flags))

    def test_a_version_only_match_is_never_critical_unless_it_is_on_the_kev_list(self):
        # the legacy heat rule can make a version-only CVSS 9.8 fire
        self.assertEqual(rate('cve', 'fire', 'critical', version_only=True), 'high')
        self.assertEqual(rate('cve', 'fire', 'critical', version_only=True, kev=True), 'critical')

    def test_the_fixed_release_that_applies_is_on_the_hosts_branch(self):
        fixed = ['8.1.29', '8.2.20', '8.3.8']
        self.assertEqual(report_data._fix_for('8.1.2', fixed), '8.1.29')
        self.assertEqual(report_data._fix_for('8.2.10', fixed), '8.2.20')
        self.assertEqual(report_data._fix_for('7.4.33', fixed), '8.1.29')
        self.assertEqual(report_data._fix_for('', fixed), '8.3.8')
        self.assertEqual(report_data._fix_for('8.1.2', []), '')


class IssueBase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.org = Org.objects.create(name='Harbor Org', slug='harbor')
        cls.user = User.objects.create_user('harbor-admin', password='x', is_superuser=True)
        engine = EngineType.objects.create(engine_name='issues', yaml_configuration='x')
        cls.projects, cls.hosts = {}, {}
        for slug in ('north', 'south'):
            project = Project.objects.create(name=slug.title(), slug=slug, insert_date=NOW, org=cls.org)
            domain = Domain.objects.create(name=f'{slug}.test', project=project, insert_date=NOW)
            scan = ScanHistory.objects.create(domain=domain, scan_type=engine, scan_status=2, start_scan_date=NOW - timedelta(days=1), tasks=[])
            cls.projects[slug] = (project, domain, scan)
        cls.php = CVEEntry.objects.create(cve_id='CVE-2098-0001', cvss=9.8, title='PHP CGI argument injection', published_at=NOW, kev=True,
                                          summary='Argument injection in PHP-CGI.', affected=[{'product': 'php', 'ranges': [{'introduced': '0', 'fixed': '8.1.29'}]}])
        cls.tail = CVEEntry.objects.create(cve_id='CVE-2098-0002', cvss=7.5, title='Old OpenSSH flaw', published_at=NOW, affected=[])
        for n in range(3):
            cls.host('north', f'web{n}.north.test', f'198.51.100.{10 + n}')
        cls.host('south', 'web0.south.test', '198.51.100.20')
        cls.host('south', 'quiet.south.test', '198.51.100.21')
        # one PHP CVE on four hosts in two projects: version only on three, a template confirmed it on one
        for name in ('web0.north.test', 'web1.north.test', 'web2.north.test', 'web0.south.test'):
            CVEMatch.objects.create(cve_entry=cls.php, subdomain=cls.hosts[name], matched_product='PHP', matched_version='8.1.2', version_in_range=True,
                                    confidence=.8, source='port', evidence={'ip': '198.51.100.10', 'port': 443},
                                    template_result='vulnerable' if name == 'web0.south.test' else '')
        CVEMatch.objects.create(cve_entry=cls.tail, subdomain=cls.hosts['web1.north.test'], matched_product='OpenSSH', matched_version='7.4',
                                version_in_range=True, confidence=.6, source='port')
        # a scanner finding of one template on two hosts, and one on one host
        for name in ('web0.north.test', 'web2.north.test'):
            cls.vuln(name, 'Exposed .git directory', 'git-config', 3)
        cls.vuln('web1.north.test', 'Directory listing enabled', 'dir-listing', 2)
        # the same hygiene check on two hosts
        for name in ('web0.north.test', 'web1.north.test'):
            project, domain, _ = cls.projects['north']
            HygieneFinding.objects.create(domain=domain, host=name, check_name='tls_expired', severity=4, title=f'Certificate for {name}:443 expired',
                                          detail=f'The certificate of {name} expired on 2026-01-01.', evidence={'not_after': '2026-01-01'})

    @classmethod
    def host(cls, slug, name, address):
        _, domain, scan = cls.projects[slug]
        sub = Subdomain.objects.create(target_domain=domain, scan_history=scan, name=name, score=40)
        ip = IpAddress.objects.create(address=address)
        sub.ip_addresses.add(ip)
        ip.ports.add(Port.objects.create(number=443, service_name='https', product='PHP', version='8.1.2'))
        cls.hosts[name] = sub
        return sub

    @classmethod
    def vuln(cls, name, title, template, severity):
        sub = cls.hosts[name]
        _, domain, scan = cls.projects['north' if name.endswith('north.test') else 'south']
        return Vulnerability.objects.create(subdomain=sub, target_domain=domain, scan_history=scan, name=title, template_id=template, severity=severity,
                                            source='nuclei', open_status=True, http_url=f'https://{name}/{template}', discovered_date=NOW,
                                            description=f'{title}.', remediation=f'Remove the {title.lower()}.')

    def org_report(self, **kw):
        scope = report_scope.resolve(Ctx(user=self.user), org='harbor')
        return report_data.collect(scope.svc_scope(), org=scope.org, **kw)

    def issue(self, data, title):
        return next(i for i in data['issues'] if i['title'] == title)


class GroupingTests(IssueBase):
    def test_one_cve_on_several_hosts_is_one_issue_that_lists_every_host_with_its_project(self):
        data = self.org_report()
        php = self.issue(data, 'CVE-2098-0001 in PHP')
        self.assertEqual((php['host_count'], php['instances']), (4, 4))
        self.assertEqual(php['level'], 'critical')  # on the KEV and confirmed on one host
        self.assertEqual((php['basis'], php['basis_note']), ('Confirmed', 'Confirmed on 1 of 4 hosts'))
        self.assertEqual({(h['project'], h['host']) for h in php['hosts']},
                         {('North', 'web0.north.test'), ('North', 'web1.north.test'), ('North', 'web2.north.test'), ('South', 'web0.south.test')})
        self.assertEqual(php['hosts'][0]['host'], 'web0.south.test')  # the confirmed host first
        self.assertTrue(php['mixed_basis'])
        self.assertEqual(sum(1 for i in data['issues'] if 'CVE-2098-0001' in i['title']), 1)
        html = report_pdf.build_html(data)
        self.assertEqual(html.count('id="issue-1"'), 1)
        self.assertIn('PHP 8.1.2, port 443', html)  # what was detected on each host

    def test_scanner_findings_group_by_template_and_hygiene_by_check(self):
        data = self.org_report()
        git = self.issue(data, 'Exposed .git directory')
        self.assertEqual((git['host_count'], git['kind'], git['level']), (2, 'scanner', 'high'))
        cert = self.issue(data, 'Expired TLS certificate')  # the check's name, not one host's title
        self.assertEqual((cert['host_count'], cert['level']), (2, 'high'))  # the check says critical; configuration is at most High
        self.assertTrue(cert['description'].startswith('Found on 2 hosts. For example, on '))
        self.assertIn('Renew the certificate', cert['remediation'])
        self.assertNotIn('Certificate for web0.north.test:443 expired', [i['title'] for i in data['issues']])

    def test_the_summary_of_findings_is_ordered_by_severity_then_hosts(self):
        data = self.org_report()
        order = [(i['title'], i['level'], i['host_count']) for i in data['issues']]
        ranks = [(-report_data.LEVEL_RANK[level], -hosts) for _, level, hosts in order]
        self.assertEqual(ranks, sorted(ranks))
        self.assertEqual([i['number'] for i in data['issues']], list(range(1, len(order) + 1)))
        self.assertEqual(order[0][0], 'CVE-2098-0001 in PHP')
        self.assertEqual([t for t, _, _ in order[1:3]], ['Expired TLS certificate', 'Exposed .git directory'])  # High, 2 hosts each: by title

    def test_low_and_informational_issues_go_to_the_appendix_table_not_a_write_up(self):
        data = self.org_report()
        tail = self.issue(data, 'CVE-2098-0002 in OpenSSH')
        self.assertEqual((tail['level'], tail['basis']), ('low', 'Version match'))  # CVSS 7.5, not exploited, version only
        self.assertIn(tail, data['minor'])
        self.assertNotIn(tail, data['detailed'])
        self.assertTrue(all(i['level'] in ('critical', 'high', 'medium') for i in data['detailed']))
        html = report_pdf.build_html(data)
        appendix = html[html.index('id="appendix-minor"'):]
        self.assertIn('CVE-2098-0002 in OpenSSH', appendix)
        self.assertNotIn('CVE-2098-0002', html[html.index('id="details"'):html.index('id="method"')])

    def test_the_executive_summary_names_the_top_issues_and_says_what_is_only_likely(self):
        data = self.org_report()
        text = ' '.join(data['executive']['paragraphs'])
        self.assertIn('The external security posture needs urgent attention.', text)
        self.assertIn('The most serious issue is CVE-2098-0001 in PHP (Critical, on 4 hosts), confirmed by a check.', text)
        self.assertIn('into 5 distinct issues: 1 critical, 2 high, 1 medium.', text)
        self.assertIn('Upgrade PHP on 4 hosts to 8.1.29 or later (1 issue in this report).', data['actions'])
        self.assertNotIn('No CVE listed in CISA', ' '.join(data['executive']['positives']))  # one is: no such positive note

    def test_a_version_only_kev_match_reads_as_likely_not_proven(self):
        CVEMatch.objects.filter(template_result='vulnerable').update(template_result='')
        data = self.org_report()
        php = self.issue(data, 'CVE-2098-0001 in PHP')
        self.assertEqual((php['level'], php['basis']), ('high', 'Version match'))  # on the KEV, version not proven: smoke
        text = ' '.join(data['executive']['paragraphs'])
        self.assertIn('CVE-2098-0001 in PHP (High, on 4 hosts), likely, based on the detected version only; not proven.', text)
        self.assertIn('1 of these issues rests on a version match: the version a service reports is in the affected range.', text)
        self.assertIn('Rated High rather than Critical because the version is not proven', php['rating_reason'])


class CapTests(IssueBase):
    def test_affected_hosts_beyond_the_cap_are_counted_in_an_and_more_line(self):
        with mock.patch.dict(os.environ, {'CVENGINE_REPORT_MAX_ISSUE_HOSTS': '2'}):
            data = self.org_report()
        php = self.issue(data, 'CVE-2098-0001 in PHP')
        self.assertEqual((len(php['hosts']), php['hosts_more'], php['host_count']), (2, 2, 4))
        html = report_pdf.build_html(data)
        self.assertIn('And 2 more hosts, listed on the Findings page in cvENGINE.', html)
        self.assertIn('shortened the host lists of 1 issue', html)

    def test_write_ups_and_appendix_rows_beyond_their_caps_say_what_was_left_out(self):
        self.vuln('web2.north.test', 'Server banner', 'server-banner', 1)  # a second low issue
        with mock.patch.dict(os.environ, {'CVENGINE_REPORT_MAX_WRITEUPS': '1', 'CVENGINE_REPORT_MAX_MINOR': '1'}):
            data = self.org_report()
        self.assertEqual((len(data['detailed']), data['caps']['writeups_omitted']), (1, 3))
        self.assertEqual((len(data['minor']), data['minor_more'], data['minor_total']), (1, 1, 2))
        html = report_pdf.build_html(data)
        self.assertEqual(html.count('<article class="issue'), 1)
        self.assertEqual(html.count('>not detailed<'), 3)
        self.assertIn('Showing 1 of 2; the rest are in cvENGINE.', html)
        self.assertIn('the limits left out 3 write-ups, 1 low or informational issue', html)

    def test_the_read_cap_is_said(self):
        with mock.patch.dict(os.environ, {'CVENGINE_REPORT_MAX_ROWS': '2'}):
            data = self.org_report()
        self.assertGreater(data['caps']['rows_omitted'], 0)
        self.assertGreater(data['summary']['findings'], 2)  # the counts still cover everything
        self.assertIn('past the read limit of 2 per kind', report_pdf.build_html(data))


class EmptyScopeTests(TestCase):
    def test_a_scope_with_nothing_open_says_so_plainly(self):
        project = Project.objects.create(name='Calm', slug='calm', insert_date=NOW, org=Org.objects.create(name='Calm Org', slug='calm-org'))
        domain = Domain.objects.create(name='calm.test', project=project, insert_date=NOW)
        scan = ScanHistory.objects.create(domain=domain, scan_type=EngineType.objects.create(engine_name='calm'), scan_status=2, start_scan_date=NOW, tasks=[])
        Subdomain.objects.create(target_domain=domain, scan_history=scan, name='www.calm.test')
        data = report_data.collect(project)
        self.assertEqual(data['issues'], [])
        self.assertEqual(data['executive']['posture'], 'No open issues.')
        self.assertEqual(data['executive']['paragraphs'],
                         ['No open security issues were found on 1 host in scope. No CVE match, scanner finding or configuration finding is open at the time of this report.'])
        self.assertIn('No CVE listed in CISA\'s Known Exploited Vulnerabilities catalog was matched to these hosts.', data['executive']['positives'])
        self.assertEqual(data['actions'], [])
        html = report_pdf.build_html(data)
        self.assertIn('No critical, high or medium issues are open.', html)
        self.assertIn('No low or informational issues are open.', html)
        self.assertNotIn('<article', html)


class PositiveNotesTests(IssueBase):
    def test_positive_notes_are_only_what_the_data_supports(self):
        project, _, _ = self.projects['north']
        ServiceRun.objects.create(service='hygiene', asset='web0.north.test', project=project, finished_at=NOW)
        CVEMatch.objects.filter(template_result='vulnerable').update(template_result='')
        CVEEntry.objects.filter(pk=self.php.pk).update(kev=False)
        HygieneFinding.objects.all().delete()
        notes = self.org_report()['executive']['positives']
        self.assertIn('No issue was reproduced by an active check; the issues rest on version information, scanner detections and configuration checks.', notes)
        self.assertIn('No CVE listed in CISA\'s Known Exploited Vulnerabilities catalog was matched to these hosts.', notes)
        self.assertIn('No expired TLS certificates were found.', notes)  # the TLS checks ran and found none
        self.assertIn('No cleartext login services (Telnet, FTP, rlogin or rsh) were found.', notes)
        self.assertIn('No critical issues were found.', notes)
        HygieneFinding.objects.create(domain=self.projects['north'][1], host='web0.north.test', check_name='cleartext_ftp', severity=3, title='FTP')
        self.assertNotIn('No cleartext login services (Telnet, FTP, rlogin or rsh) were found.', self.org_report()['executive']['positives'])


class TriagedFalsePositiveTests(IssueBase):
    def test_a_finding_triage_ruled_out_is_not_a_host_of_its_issue(self):
        match = CVEMatch.objects.get(subdomain=self.hosts['web1.north.test'], cve_entry=self.php)
        project, domain, _ = self.projects['north']
        Triage.objects.create(project=project, domain=domain, host='web1.north.test', kind='cve_match', match=match, status='triaged',
                              classification='likely_false_positive')
        data = self.org_report()
        php = self.issue(data, 'CVE-2098-0001 in PHP')
        self.assertEqual(php['host_count'], 3)
        self.assertNotIn('web1.north.test', [h['host'] for h in php['hosts']])
        self.assertEqual(data['summary']['ruled_out'], 1)
