from django.test import SimpleTestCase, TestCase

from cveFeed import service_intel
from startScan.models import IpAddress, Port, Subdomain, Vulnerability
from tests.test_route_auth import RouteFixture

RDP = """Target_Name: ACME
  NetBIOS_Domain_Name: ACME
  NetBIOS_Computer_Name: SRV01
  DNS_Domain_Name: acme.example
  DNS_Computer_Name: srv01.acme.example
  Product_Version: 10.0.17763
  System_Time: 2026-10-25T12:00:00+00:00"""
SMB = """  OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
  Computer name: srv01
  NetBIOS computer name: SRV01\\x00
  Domain name: acme.example
  FQDN: srv01.acme.example
  System time: 2026-10-25T12:00:00+00:00"""
FTP = """Anonymous FTP login allowed (FTP code 230)
-rw-r--r--   1 ftp      ftp          1024 Jan 01 00:00 readme.txt
drwxr-xr-x   2 ftp      ftp          4096 Jan 01 00:00 pub"""


class ParseTests(SimpleTestCase):
    def test_rdp_ntlm_names_the_windows_build_and_computer(self):
        facts = service_intel.parse_rdp_ntlm(RDP)
        self.assertEqual(facts['os'], 'Windows Server 2019 / Windows 10 1809')
        self.assertEqual((facts['computer_name'], facts['domain'], facts['fqdn']), ('SRV01', 'ACME', 'srv01.acme.example'))

    def test_an_unknown_build_is_still_reported(self):
        self.assertEqual(service_intel.parse_rdp_ntlm('Product_Version: 99.1.2')['os'], 'Windows (build 99.1.2)')

    def test_smb_os_discovery(self):
        facts = service_intel.parse_smb_os(SMB)
        self.assertEqual((facts['os'], facts['computer_name'], facts['fqdn']), ('Windows Server 2019 Standard 17763', 'srv01', 'srv01.acme.example'))

    def test_nothing_in_nothing_out(self):
        self.assertEqual(service_intel.parse_rdp_ntlm(''), {})
        self.assertEqual(service_intel.parse_smb_os(None), {})


class FindingTests(RouteFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.scan_obj = self.scan(names=('ftp.rt.test',), ports=())
        self.sub = Subdomain.objects.get(scan_history=self.scan_obj)
        self.ip = self.sub.ip_addresses.get()

    def port(self, number, scripts, **fields):
        port = Port.objects.create(number=number, state='open', extra={'scripts': scripts}, **fields)
        self.ip.ports.add(port)
        return port

    def test_anonymous_ftp_is_a_finding_with_the_listing_as_evidence(self):
        self.port(21, {'ftp-anon': FTP}, service_name='ftp')
        self.assertEqual(service_intel.record_service_findings(self.scan_obj), 1)
        vuln = Vulnerability.objects.get(name='Anonymous FTP login allowed')
        self.assertEqual((vuln.severity, vuln.http_url, vuln.subdomain_id), (2, f'ftp://{self.ip.address}:21', self.sub.id))
        self.assertEqual(len(vuln.extracted_results), 2)
        self.assertIn('readme.txt', vuln.extracted_results[0])
        self.assertEqual(service_intel.record_service_findings(self.scan_obj), 0)  # one row per port, not one per scan stage

    def test_a_server_that_refuses_anonymous_is_not_reported(self):
        self.port(21, {'ftp-anon': 'Can\'t get directory listing: TIMEOUT'}, service_name='ftp')
        self.assertEqual(service_intel.record_service_findings(self.scan_obj), 0)

    def test_a_closed_port_is_not_reported(self):
        port = self.port(21, {'ftp-anon': FTP}, service_name='ftp')
        port.state = 'closed'
        port.save()
        self.assertEqual(service_intel.record_service_findings(self.scan_obj), 0)

    def test_rdp_and_smb_facts_fill_an_empty_os_guess_only(self):
        self.port(3389, {'rdp-ntlm-info': RDP}, service_name='ms-wbt-server')
        service_intel.record_service_findings(self.scan_obj)
        ip = IpAddress.objects.get(pk=self.ip.pk)
        self.assertEqual(ip.os_guess, 'Windows Server 2019 / Windows 10 1809')
        self.assertEqual(ip.fingerprint['facts']['computer_name'], 'SRV01')
        ip.os_guess = 'Microsoft Windows Server 2019'
        ip.save()
        ip.fingerprint = {'scripts': {'smb-os-discovery': SMB}}
        ip.save()
        service_intel.record_service_findings(self.scan_obj)
        ip.refresh_from_db()
        self.assertEqual(ip.os_guess, 'Microsoft Windows Server 2019')
        self.assertEqual(ip.fingerprint['facts']['source'], 'smb-os-discovery')
