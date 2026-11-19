"""The Windows release an NTLM challenge states (cveFeed.windows_builds): every NTLM script's output and smb-os-discovery's, the build table, the
reading it stores (``vsrc:ntlm``, release known, patch level unknown), the candidates it makes (KEV or critical, network-reachable, never a
version in range, never read as revision 0), end of support, the explanation and its commands, the update backfill, and that nmap's OS guess
alone makes nothing."""
import io
import json
import re
from datetime import date, datetime, timezone as dt_timezone
from types import SimpleNamespace

from django.core.management import call_command
from django.test import SimpleTestCase, TestCase

from agentapi import services
from cveFeed import (confirm_guide, correlation, match_explain, match_policy, source_versions, tech_search, threat, triage, upgrade_backfills,
                     version_sources, windows_builds)
from cveFeed.models import CVEEntry, CVEMatch, ProbeObservation
from startScan.models import IpAddress, Subdomain
from tests.test_version_sources import VersionFixture

# realistic NSE output, as nmap stores a script's ``output`` attribute (Port.extra['scripts'][id]; smb-os-discovery on the address)
RDP = """
  Target_Name: ACME
  NetBIOS_Domain_Name: ACME
  NetBIOS_Computer_Name: SRV22
  DNS_Domain_Name: acme.example
  DNS_Computer_Name: srv22.acme.example
  DNS_Tree_Name: acme.example
  Product_Version: 10.0.20348
  System_Time: 2026-11-18T09:12:44+00:00"""
MSSQL = """
  203.0.113.7:1433:
    Target_Name: ACME
    NetBIOS_Domain_Name: ACME
    NetBIOS_Computer_Name: SQL01
    DNS_Domain_Name: acme.example
    DNS_Computer_Name: sql01.acme.example
    DNS_Tree_Name: acme.example
    Product_Version: 10.0.17763"""
HTTP = """
  Target_Name: ACME
  NetBIOS_Domain_Name: ACME
  NetBIOS_Computer_Name: EXCH01
  DNS_Domain_Name: acme.example
  DNS_Computer_Name: exch01.acme.example
  DNS_Tree_Name: acme.example
  Product_Version: 10.0.14393"""
SMTP = """
  Target_Name: ACME
  NetBIOS_Domain_Name: ACME
  NetBIOS_Computer_Name: MAIL
  DNS_Domain_Name: acme.example
  DNS_Computer_Name: mail.acme.example
  DNS_Tree_Name: acme.example
  Product_Version: 6.3.9600"""
IMAP = POP3 = """
  Target_Name: ACME
  NetBIOS_Domain_Name: ACME
  NetBIOS_Computer_Name: MAIL
  DNS_Domain_Name: acme.example
  DNS_Computer_Name: mail.acme.example
  Product_Version: 6.1.7601"""
TELNET = """
  Target_Name: WORKGROUP
  NetBIOS_Domain_Name: WORKGROUP
  NetBIOS_Computer_Name: LEGACY
  DNS_Domain_Name: LEGACY
  DNS_Computer_Name: LEGACY
  Product_Version: 6.2.9200"""
OLD_FORMAT = """
  Target_Name: ACME
  Product_Version: 6.1 (Build 7601)"""
SMB_SERVER = """
  OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
  Computer name: srv19
  NetBIOS computer name: SRV19\\x00
  Domain name: acme.example
  FQDN: srv19.acme.example
  System time: 2026-11-18T09:12:44+00:00"""
SMB_CLIENT = """
  OS: Windows 10 Enterprise LTSC 2019 17763 (Windows 10 Enterprise LTSC 2019 6.3)
  Computer name: kiosk
  NetBIOS computer name: KIOSK\\x00
  Workgroup: WORKGROUP\\x00"""
SMB_2008R2 = """
  OS: Windows Server 2008 R2 Standard 7601 Service Pack 1 (Windows Server 2008 R2 Standard 6.1)
  OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
  Computer name: old
  NetBIOS computer name: OLD\\x00"""
SMB_SAMBA = """
  OS: Unix (Samba 4.13.17-Ubuntu)
  Computer name: files
  NetBIOS computer name: FILES\\x00"""

NETWORK = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'


def server_2022(fixed='10.0.20348.2762', product='Windows Server 2022'):
    return [{'vendor': 'Microsoft', 'product': product, 'ranges': [{'type': 'SEMVER', 'introduced': '10.0.20348.0', 'fixed': fixed}]}]


def cve(cve_id, items, kev=False, cvss=9.8, vector=NETWORK, published=None, local_only=False):
    return CVEEntry.objects.create(cve_id=cve_id, title=cve_id, affected=items, kev=kev, cvss=cvss, cvss_vector=vector, local_only=local_only,
                                   published_at=published or datetime(2026, 6, 9, tzinfo=dt_timezone.utc))


class ParseTests(SimpleTestCase):
    def test_every_ntlm_script_states_the_build(self):
        for text, build in ((RDP, '10.0.20348'), (MSSQL, '10.0.17763'), (HTTP, '10.0.14393'), (SMTP, '6.3.9600'), (IMAP, '6.1.7601'),
                            (POP3, '6.1.7601'), (TELNET, '6.2.9200'), (OLD_FORMAT, '6.1.7601')):
            with self.subTest(build=build):
                self.assertEqual(windows_builds.parse_ntlm(text)['build'], build)

    def test_smb_os_discovery_names_the_system_and_its_build(self):
        self.assertEqual({k: v for k, v in windows_builds.parse_smb_os(SMB_SERVER).items() if k != 'said'},
                         {'build': '10.0.17763', 'line': 'server', 'os': 'Windows Server 2019 Standard 17763'})
        self.assertEqual(windows_builds.parse_smb_os(SMB_CLIENT)['line'], 'client')
        self.assertEqual((windows_builds.parse_smb_os(SMB_2008R2)['build'], windows_builds.parse_smb_os(SMB_2008R2)['line']), ('6.1.7601', 'server'))
        self.assertEqual(windows_builds.parse_smb_os(SMB_SAMBA), {})  # not Windows

    def test_nothing_stated_reads_nothing(self):
        for text in ('', None, 'Target_Name: ACME', 'Product_Version: banana', 'Product_Version: 10.0', '  OS: Windows XP (Windows 2000 LAN Manager)'):
            self.assertEqual(windows_builds.parse_ntlm(text), {})
            self.assertEqual(windows_builds.parse_smb_os(text), {})


class TableTests(SimpleTestCase):
    def test_the_builds_name_the_releases_server_and_client(self):
        want = {'6.1.7601': {'Windows Server 2008 R2 Service Pack 1', 'Windows 7 Service Pack 1'},
                '6.2.9200': {'Windows Server 2012', 'Windows 8'},
                '6.3.9600': {'Windows Server 2012 R2', 'Windows 8.1'},
                '10.0.14393': {'Windows Server 2016', 'Windows 10 Version 1607'},
                '10.0.17763': {'Windows Server 2019', 'Windows 10 Version 1809'},
                '10.0.20348': {'Windows Server 2022'},
                '10.0.26100': {'Windows Server 2025', 'Windows 11 Version 24H2'},
                '10.0.19045': {'Windows 10 Version 22H2'}, '10.0.19044': {'Windows 10 Version 21H2'}, '10.0.22000': {'Windows 11 version 21H2'},
                '10.0.22621': {'Windows 11 version 22H2'}, '10.0.22631': {'Windows 11 Version 23H2'}, '10.0.26200': {'Windows 11 Version 25H2'}}
        for build, names in want.items():
            with self.subTest(build=build):
                self.assertEqual({e['name'] for e in windows_builds.releases(build)}, names)
        self.assertEqual(windows_builds.releases('10.0.99999'), [])

    def test_every_release_cites_its_lifecycle_and_its_dates_read(self):
        doc = windows_builds.data()
        for url in doc['sources'].values():
            self.assertTrue(url.startswith('https://learn.microsoft.com/'), url)
        for entry in doc['releases']:
            with self.subTest(release=entry['name']):
                self.assertTrue(entry['lifecycle'].startswith('https://learn.microsoft.com/lifecycle/'))
                self.assertIn(entry['line'], ('server', 'client'))
                eos = date.fromisoformat(entry['end_of_support'])
                if entry.get('esu_until'):
                    self.assertGreater(date.fromisoformat(entry['esu_until']), eos)
                self.assertRegex(entry['build'], r'^\d+\.\d+\.\d+$')
        by_name = {e['name']: e for e in doc['releases']}
        self.assertEqual(by_name['Windows Server 2008 R2 Service Pack 1']['end_of_support'], '2020-01-14')
        self.assertEqual(by_name['Windows 7 Service Pack 1']['end_of_support'], '2020-01-14')
        self.assertEqual((by_name['Windows Server 2012 R2']['end_of_support'], by_name['Windows Server 2012']['end_of_support']), ('2023-10-10', '2023-10-10'))

    def test_the_names_microsofts_records_use_reach_one_release(self):
        # the product names of a real MSRC record (tests/fixtures/cve5/CVE-2024-38063.json) and the other spellings records use
        with open('tests/fixtures/cve5/CVE-2024-38063.json', encoding='utf-8') as fh:
            products = [a['product'] for a in json.load(fh)['containers']['cna']['affected']]
        for product in products:
            self.assertIsNotNone(windows_builds.release_named(product), product)
        for spelling, release in (('Windows Server 2019 (Server Core installation)', 'Windows Server 2019'),
                                  ('Windows Server 2008  Service Pack 2 (Server Core installation)', 'Windows Server 2008 Service Pack 2'),
                                  ('Windows 7 for x64-based Systems Service Pack 1', 'Windows 7 Service Pack 1'),
                                  ('Windows 11 version 22H3', 'Windows 11 Version 23H2'), ('windows_server_2022', 'Windows Server 2022')):
            self.assertEqual(windows_builds.release_named(spelling)['name'], release, spelling)
        # a different release with a longer name is not this one
        self.assertEqual(windows_builds.release_named('Windows Server 2022, 23H2 Edition (Server Core installation)')['build'], '10.0.25398')
        for other in ('Windows', 'Windows 10', 'Windows Server', 'Exchange Server 2019', ''):
            self.assertIsNone(windows_builds.release_named(other), other)


class ReadingTests(SimpleTestCase):
    def test_a_shared_build_keeps_both_releases_and_says_so(self):
        found = windows_builds.readings_from([('rdp-ntlm-info', 3389, windows_builds.parse_ntlm(MSSQL))])
        self.assertEqual([(p, r['label'], r['version']) for p, r in found],
                         [(3389, 'Windows Server 2019', '10.0.17763'), (3389, 'Windows 10 Version 1809', '10.0.17763')])
        for _p, r in found:
            self.assertTrue(r['release_only'] and r['windows']['ambiguous'])
            self.assertIn('nothing read tells which', r['windows']['basis'])

    def test_smb_os_discovery_tells_server_from_client(self):
        server = windows_builds.readings_from([('rdp-ntlm-info', 3389, windows_builds.parse_ntlm(MSSQL)),
                                               ('smb-os-discovery', 445, windows_builds.parse_smb_os(SMB_SERVER))])
        self.assertEqual([r['label'] for _p, r in server], ['Windows Server 2019'])
        self.assertFalse(server[0][1]['windows']['ambiguous'])
        self.assertEqual([s['script'] for s in server[0][1]['windows']['sources']], ['rdp-ntlm-info', 'smb-os-discovery'])
        client = windows_builds.readings_from([('smb-os-discovery', 445, windows_builds.parse_smb_os(SMB_CLIENT))])
        self.assertEqual([r['label'] for _p, r in client], ['Windows 10 Version 1809'])

    def test_a_build_the_table_does_not_list_makes_no_reading(self):
        self.assertEqual(windows_builds.readings_from([('rdp-ntlm-info', 3389, {'build': '10.0.99999', 'said': 'x'})]), [])


class CoverTests(SimpleTestCase):
    def test_the_release_is_never_read_as_revision_zero(self):
        rng = {'type': 'SEMVER', 'introduced': '10.0.20348.0', 'fixed': '10.0.20348.2762'}
        # the trap: read as a version, 10.0.20348 is 10.0.20348.0 and inside every such range
        self.assertTrue(correlation.range_verdict(correlation.parse_version('10.0.20348'), [rng])[0])
        # here it only says some revision of the release can be inside: a candidate, never a version in range
        self.assertTrue(windows_builds.covers('10.0.20348', rng))
        self.assertFalse(windows_builds.covers('10.0.20348', {'introduced': '10.0.20348.0', 'fixed': '10.0.20348.0'}))

    def test_the_first_three_components_decide(self):
        self.assertTrue(windows_builds.covers('10.0.20348', {'introduced': '10.0.0', 'fixed': '10.0.22000.3197'}))  # a range across releases
        self.assertFalse(windows_builds.covers('10.0.20348', {'introduced': '10.0.17763.0', 'fixed': '10.0.17763.6293'}))  # another release
        self.assertFalse(windows_builds.covers('10.0.17763', {'introduced': '10.0.20348.0', 'fixed': '10.0.20348.2762'}))
        self.assertTrue(windows_builds.covers('6.3.9600', {'introduced': '6.3.0', 'lastAffected': '6.3.9600.20207'}))
        self.assertTrue(windows_builds.covers('6.3.9600', {'introduced': '6.3.9600.100', 'lastAffected': '6.3.9600.100'}))

    def test_a_range_with_no_usable_upper_bound_covers_nothing(self):
        for rng in ({'introduced': '10.0.0'}, {'introduced': '2016', 'lastAffected': '2016'}, {'introduced': '32-bit', 'lastAffected': '32-bit'},
                    {'introduced': '10.0.0', 'fixed': 'unspecified'}, {}, None):
            self.assertFalse(windows_builds.covers('10.0.20348', rng), rng)


class EligibleTests(SimpleTestCase):
    def one(self, **kw):
        fields = {'cvss_vector': NETWORK, 'kev': False, 'cvss': 9.8, 'local_only': False, **kw}
        return windows_builds.eligible(SimpleNamespace(**fields))

    def test_kev_or_critical_network_cves_with_no_user_interaction(self):
        self.assertEqual(self.one(kev=True, cvss=7.5), 'kev')
        self.assertEqual(self.one(cvss=9.8), 'critical')
        self.assertEqual(self.one(cvss=9.0), 'critical')
        self.assertEqual(self.one(cvss=8.8), '')  # neither on the KEV list nor critical
        self.assertEqual(self.one(cvss=None), '')

    def test_only_network_reachable_and_never_local(self):
        self.assertEqual(self.one(kev=True, cvss_vector='CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'), '')
        self.assertEqual(self.one(kev=True, cvss_vector='CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), '')
        self.assertEqual(self.one(kev=True, cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'), '')  # a user must open something
        self.assertEqual(self.one(kev=True, cvss_vector=''), '')
        self.assertEqual(self.one(kev=True, local_only=True), '')
        self.assertEqual(self.one(kev=True, cvss_vector='AV:N/AC:L/Au:N/C:C/I:C/A:C'), 'kev')  # CVSS 2 has no user-interaction field


class WindowsFixture(VersionFixture):
    def windows_host(self, scripts=None, smb=None, os_guess='', name='srv.rt.test', address='203.0.113.7'):
        ports = []
        for number, service, product, text_by_script in (scripts or ()):
            ports.append((number, service, product, '', {'scripts': text_by_script}))
        scan = self.host_scan(ports=ports, names=(name,), web=False, address=address)
        ip = IpAddress.objects.get(address=address)
        if smb or os_guess:
            ip.fingerprint = {'scripts': {'smb-os-discovery': smb}} if smb else {}
            ip.os_guess = os_guess
            ip.save()
        return scan, Subdomain.objects.get(scan_history=scan, name=name)

    def correlate(self, scan, row=None):
        cve_by_id, index = correlation.cve_pool()
        subs = correlation.candidate_subdomains(index).filter(scan_history=scan)
        correlation.correlate_subdomains(list(subs), index, cve_by_id, min_confidence=0.4)
        qs = CVEMatch.objects.filter(subdomain__scan_history=scan).exclude(ai_verdict='not_affected')
        return list(qs.filter(cve_entry=row) if row is not None else qs)

    def rdp_2022(self, **kw):
        return self.windows_host(scripts=[(3389, 'ms-wbt-server', 'Microsoft Terminal Services', {'rdp-ntlm-info': RDP})], **kw)


class StoreTests(WindowsFixture, TestCase):
    def test_the_release_is_a_reading_with_its_port_and_script_never_a_technology(self):
        _scan, sub = self.rdp_2022()
        version_sources.refresh_host(sub)
        row = ProbeObservation.objects.get(probe='vsrc:ntlm', host='srv.rt.test')
        self.assertEqual((row.product, row.version, row.kind, row.port), ('Windows Server 2022', '10.0.20348', 'hint', 3389))
        self.assertTrue(row.evidence['release_only'] and row.evidence['version_source'])
        self.assertEqual(row.evidence['windows']['sources'], [{'script': 'rdp-ntlm-info', 'port': 3389}])
        self.assertEqual(list(sub.technologies.values_list('name', flat=True)), [])  # never a technology: never matched by name and version
        shown, = version_sources.readings_for([self.project.pk], ['srv.rt.test'])[(self.project.pk, 'srv.rt.test')]
        self.assertEqual((shown['product'], shown['version'], shown['source'], shown['release_only'], shown['matched']),
                         ('Windows Server 2022', '10.0.20348', 'ntlm', True, True))
        self.assertEqual([r.product for r in version_sources.search_rows('vsource', 'ntlm')], ['Windows Server 2022'])
        self.assertEqual(source_versions.SEARCH['ntlm'], windows_builds.PROBE)

    def test_every_ntlm_port_and_the_smb_answer_are_read(self):
        _scan, sub = self.windows_host(scripts=[(1433, 'ms-sql-s', 'Microsoft SQL Server 2019', {'ms-sql-ntlm-info': MSSQL}),
                                                (25, 'smtp', 'Microsoft ESMTP', {'smtp-ntlm-info': MSSQL.replace('    ', '  ')}),
                                                (445, 'microsoft-ds', '', {})], smb=SMB_SERVER)
        version_sources.refresh_host(sub)
        row, = ProbeObservation.objects.filter(probe='vsrc:ntlm')
        self.assertEqual(row.product, 'Windows Server 2019')
        self.assertEqual({s['script'] for s in row.evidence['windows']['sources']}, {'ms-sql-ntlm-info', 'smtp-ntlm-info', 'smb-os-discovery'})

    def test_an_os_guess_alone_makes_nothing(self):
        cve('CVE-2026-47291', server_2022(), kev=True)
        scan, sub = self.windows_host(scripts=[(3389, 'ms-wbt-server', 'Microsoft Terminal Services', {})],
                                      os_guess='Microsoft Windows Server 2022')
        version_sources.refresh_host(sub)
        self.assertFalse(ProbeObservation.objects.filter(probe='vsrc:ntlm').exists())
        self.assertEqual(self.correlate(scan), [])

    def test_a_reading_the_scripts_no_longer_state_is_dropped(self):
        scan, sub = self.rdp_2022()
        version_sources.refresh_host(sub)
        port = IpAddress.objects.get(address='203.0.113.7').ports.get(number=3389)
        port.extra = {'scripts': {}}
        port.save()
        sub = Subdomain.objects.prefetch_related('ip_addresses__ports', 'technologies').get(pk=sub.pk)
        version_sources.refresh_host(sub)
        self.assertFalse(ProbeObservation.objects.filter(probe='vsrc:ntlm').exists())


class CorrelationTests(WindowsFixture, TestCase):
    def stored(self, **kw):
        scan, sub = self.rdp_2022(**kw)
        version_sources.refresh_host(sub)
        return scan, sub

    def test_a_kev_network_cve_is_a_patch_unknown_candidate_never_a_version_in_range(self):
        row = cve('CVE-2026-33824', server_2022(), kev=True)
        scan, _sub = self.stored()
        match, = self.correlate(scan)
        self.assertEqual((match.cve_entry_id, match.source, match.version_in_range, match.matched_version, match.matched_product),
                         (row.id, 'windows', None, '', 'Windows Server 2022'))
        self.assertEqual(match.confidence, windows_builds.UNKNOWN_CONFIDENCE)
        ev = match.evidence
        self.assertTrue(ev['windows_patch_unknown'])
        self.assertEqual((ev['build'], ev['fixed_build'], ev['limit'], ev['port']), ('10.0.20348', '10.0.20348.2762', 'kev', 3389))
        self.assertTrue(match_policy.version_unknown(match))
        self.assertTrue(CVEMatch.objects.filter(match_policy.version_unknown_q(), pk=match.pk).exists())
        self.assertEqual(threat.match_heat(match), threat.ICE)
        self.assertEqual(threat.heat_reason(match), threat.REASON_WINDOWS_PATCH)
        loaded = CVEMatch.objects.select_related('cve_entry', 'subdomain__target_domain').get(pk=match.pk)
        facts = triage.describe_cve_match(loaded)['facts']
        self.assertTrue(facts['version_unknown'] and facts['windows_patch_unknown'])
        self.assertEqual(triage.version_unknown_outcome(windows_patch_unknown=True)['reason'], match_policy.REASON_WINDOWS_PATCH)
        self.assertEqual(match_policy.unknown_reason(ev), match_policy.REASON_WINDOWS_PATCH)
        self.assertEqual(correlation.invalid_identity_reason(loaded), '')
        self.assertFalse(CVEMatch.objects.filter(version_in_range=True).exists())

    def test_correlating_again_keeps_one_match_and_a_gone_reading_closes_it(self):
        cve('CVE-2026-33824', server_2022(), kev=True)
        scan, sub = self.stored()
        self.assertEqual(len(self.correlate(scan)), 1)
        self.assertEqual(len(self.correlate(scan)), 1)
        ProbeObservation.objects.filter(probe='vsrc:ntlm').delete()
        self.assertEqual(self.correlate(scan), [])

    def test_only_network_cves_without_user_interaction_that_are_not_local(self):
        cve('CVE-2026-90001', server_2022(), kev=True, vector='CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H')
        cve('CVE-2026-90002', server_2022(), kev=True, vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H')
        cve('CVE-2026-90003', server_2022(), kev=True, local_only=True)
        cve('CVE-2026-90004', server_2022(), kev=True, vector='')
        scan, _sub = self.stored()
        self.assertEqual(self.correlate(scan), [])

    def test_the_kev_and_critical_limit(self):
        cve('CVE-2026-90011', server_2022(), cvss=8.8)  # high, not on the KEV list: left out
        critical = cve('CVE-2026-90012', server_2022(), cvss=9.8)
        scan, _sub = self.stored()
        match, = self.correlate(scan)
        self.assertEqual((match.cve_entry_id, match.evidence['limit']), (critical.id, 'critical'))

    def test_a_record_that_does_not_reach_the_release_matches_nothing(self):
        cve('CVE-2026-90021', [{'vendor': 'Microsoft', 'product': 'Windows Server 2019',
                                'ranges': [{'type': 'SEMVER', 'introduced': '10.0.17763.0', 'fixed': '10.0.17763.6293'}]}], kev=True)
        cve('CVE-2026-90022', server_2022(fixed='10.0.20348.0'), kev=True)
        cve('CVE-2026-90023', [{'vendor': 'Microsoft', 'product': 'Windows Server 2022', 'ranges': []}], kev=True)  # no range at all
        cve('CVE-2026-90024', [{'vendor': 'Acme', 'product': 'Windows Server 2022', 'ranges': server_2022()[0]['ranges']}], kev=True)
        scan, _sub = self.stored()
        self.assertEqual(self.correlate(scan), [])

    def test_a_server_core_entry_and_a_cross_release_range_count(self):
        row = cve('CVE-2026-90031', server_2022(product='Windows Server 2022 (Server Core installation)'), kev=True)
        scan, _sub = self.stored()
        match, = self.correlate(scan)
        self.assertEqual(match.cve_entry_id, row.id)

    def test_a_shared_build_matches_either_release_once(self):
        both = cve('CVE-2026-90041', [{'vendor': 'Microsoft', 'product': name, 'ranges': [{'type': 'SEMVER', 'introduced': '10.0.17763.0',
                                                                                            'fixed': '10.0.17763.6293'}]}
                                      for name in ('Windows 10 Version 1809', 'Windows Server 2019')], kev=True)
        scan, sub = self.windows_host(scripts=[(1433, 'ms-sql-s', 'Microsoft SQL Server', {'ms-sql-ntlm-info': MSSQL})])
        version_sources.refresh_host(sub)
        match, = self.correlate(scan)
        self.assertEqual(match.cve_entry_id, both.id)
        self.assertTrue(match.evidence['windows']['ambiguous'])
        self.assertEqual(match.evidence['windows']['candidates'], ['Windows Server 2019', 'Windows 10 Version 1809'])
        self.assertIn('Windows Server 2019 and Windows 10 Version 1809', match_explain.explain(match)['why'])

    def test_end_of_support_raises_confidence_but_stays_unknown(self):
        ranges = [{'type': 'SEMVER', 'introduced': '6.3.9600.0', 'fixed': '6.3.9600.23470'}]
        after = cve('CVE-2026-96951', [{'vendor': 'Microsoft', 'product': 'Windows Server 2012 R2', 'ranges': ranges}], kev=True,
                    published=datetime(2026, 10, 13, 17, 0, tzinfo=dt_timezone.utc))
        before = cve('CVE-2023-21554', [{'vendor': 'Microsoft', 'product': 'Windows Server 2012 R2', 'ranges': ranges}], cvss=9.8,
                     published=datetime(2023, 4, 11, tzinfo=dt_timezone.utc))
        scan, sub = self.windows_host(scripts=[(25, 'smtp', 'Microsoft ESMTP', {'smtp-ntlm-info': SMTP})], smb=SMB_SERVER.replace(
            'Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)', 'Windows Server 2012 R2 Standard 9600 (Windows Server 2012 R2 Standard 6.3)'))
        version_sources.refresh_host(sub)
        matches = {m.cve_entry_id: m for m in self.correlate(scan)}
        late, early = matches[after.id], matches[before.id]
        self.assertEqual((late.confidence, early.confidence), (windows_builds.END_OF_SUPPORT_CONFIDENCE, windows_builds.UNKNOWN_CONFIDENCE))
        self.assertEqual(late.evidence['end_of_support'], {'date': '2023-10-10', 'esu_until': '2026-10-13', 'after_esu': False})
        self.assertNotIn('end_of_support', early.evidence)
        self.assertIsNone(late.version_in_range)
        self.assertTrue(match_policy.version_unknown(late))
        self.assertEqual(threat.match_heat(late), threat.ICE)
        explained = match_explain.explain(late)
        self.assertIn('End of support', explained['why'])
        self.assertTrue(any('slmgr.vbs /dlv' in s['command'] for s in explained['steps']))
        self.assertFalse(any('slmgr' in s['command'] for s in match_explain.explain(early)['steps']))
        self.assertEqual(windows_builds.end_of_support({'end_of_support': '2020-01-14', 'esu_until': '2023-01-10'},
                                                       datetime(2024, 1, 9, tzinfo=dt_timezone.utc))['after_esu'], True)

    def test_the_explanation_and_the_owners_commands(self):
        cve('CVE-2026-33824', server_2022(), kev=True)
        scan, _sub = self.stored()
        self.correlate(scan)
        match = CVEMatch.objects.select_related('cve_entry', 'subdomain__target_domain').get(subdomain__scan_history=scan)
        explained = match_explain.explain(match)
        self.assertEqual((explained['basis'], explained['confidence']), ('windows_patch_unknown', match_explain.NOT_CONFIRMED))
        self.assertEqual(explained['question'], match_explain.WINDOWS_QUESTION)
        self.assertIn('Windows Server 2022, build 10.0.20348', explained['found'])
        self.assertIn('never its update revision', explained['why'])
        self.assertIn('never raises the host\'s heat', explained['why'])
        commands = [s['command'] for s in explained['steps']]
        self.assertIn('ver', commands)
        self.assertIn('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" /v UBR', commands)
        self.assertTrue(any('[System.Environment]::OSVersion' in c for c in commands))
        self.assertTrue(any(c.startswith('Get-HotFix') for c in commands))
        self.assertTrue(all(s['read_only'] for s in explained['steps']))
        self.assertIn('2762 or higher', explained['steps'][0]['outcomes']['fixed'])
        guide = confirm_guide.match_guide(match)
        self.assertEqual(guide['class'], 'windows_release')
        self.assertEqual({c['platform'] for c in guide['local'][0]['commands']}, {'windows'})
        self.assertIn('2762 or higher', guide['verdict']['not_affected'])
        self.assertIn('lower than 2762', guide['verdict']['affected'])
        plan, = match_explain.validate_plan([match])
        self.assertEqual((plan['key'], plan['count'], plan['cves']), ('windows:ubr', 1, ['CVE-2026-33824']))
        for step in explained['steps']:  # constants only: nothing a host said reaches a command
            self.assertNotIn('srv.rt.test', step['command'])


class SearchTests(WindowsFixture, TestCase):
    def hosts(self, value):
        spec = tech_search.parse(value)
        return sorted(Subdomain.objects.filter(services._tech_q(spec, self.project)).values_list('name', flat=True).distinct())

    def test_tech_finds_the_release_and_counts_it_as_patch_level_unknown(self):
        _scan, sub = self.rdp_2022()
        version_sources.refresh_host(sub)
        _scan2, other = self.windows_host(scripts=[(3389, 'ms-wbt-server', 'Microsoft Terminal Services', {'rdp-ntlm-info': MSSQL})],
                                          smb=SMB_SERVER, name='srv19.rt.test', address='203.0.113.9')
        version_sources.refresh_host(other)
        self.assertEqual(self.hosts('windows server 2022'), ['srv.rt.test'])
        self.assertEqual(self.hosts('windows'), ['srv.rt.test', 'srv19.rt.test'])
        self.assertEqual(self.hosts('windows@unknown'), ['srv.rt.test', 'srv19.rt.test'])  # the release is known, the patch level is not
        self.assertEqual(self.hosts('windows@known'), [])
        self.assertEqual(self.hosts('windows server 2022@10.0.20348'), ['srv.rt.test'])  # the release itself is stated
        self.assertEqual(self.hosts('windows server 2022@10.0.20348.2762'), [])  # an update revision is not
        shared = {'versions': version_sources.readings_for([self.project.pk], ['srv.rt.test'])}
        sub = Subdomain.objects.prefetch_related('technologies', 'ip_addresses__ports').select_related('target_domain').get(pk=sub.pk)
        reasons = services._tech_reasons(sub, tech_search.parse('windows@unknown'), shared=shared)
        self.assertIn('version source Windows Server 2022 10.0.20348 (ntlm, patch level unknown)', reasons)


class BackfillTests(WindowsFixture, TestCase):
    def test_older_hosts_get_their_reading_and_candidates_once_and_a_dry_run_writes_nothing(self):
        row = cve('CVE-2026-33824', server_2022(), kev=True)
        scan, _sub = self.rdp_2022()
        out = io.StringIO()
        call_command('backfill_windows_builds', stdout=out)
        self.assertIn('Dry run: 1 hosts', out.getvalue())
        self.assertFalse(ProbeObservation.objects.filter(probe='vsrc:ntlm').exists())
        call_command('backfill_windows_builds', apply=True, stdout=out)
        self.assertEqual(ProbeObservation.objects.get(probe='vsrc:ntlm').product, 'Windows Server 2022')
        match, = CVEMatch.objects.filter(subdomain__scan_history=scan)
        self.assertEqual((match.cve_entry_id, match.source), (row.id, 'windows'))
        call_command('backfill_windows_builds', apply=True, stdout=out)  # idempotent
        self.assertEqual(CVEMatch.objects.filter(subdomain__scan_history=scan).count(), 1)
        self.assertRegex(out.getvalue().splitlines()[-1], r'^Applied: 1 hosts; 1 Windows release readings stored, \d+ CVE matches\.$')

    def test_it_runs_as_an_update_step_before_the_rescore(self):
        steps = upgrade_backfills.BACKFILLS
        self.assertLess(steps.index('backfill_windows_builds'), steps.index('rerate_findings'))
        self.assertTrue(re.match(r'^[a-z_]+$', 'backfill_windows_builds'))
