import os
import tempfile

from django.test import TestCase
from django.utils import timezone

from cveFeed.models import CVEEntry
from reNgine.definitions import NMAP
from reNgine.tasks import parse_nmap_results, parse_nmap_vulners_output, parse_nmap_vulscan_output

VULNERS = """
  cpe:/a:apache:http_server:2.4.49:
    	CVE-2021-41773	7.5	https://vulners.com/cve/CVE-2021-41773
    	CVE-2021-42013	9.8	https://vulners.com/cve/CVE-2021-42013
    	CVE-2021-41773	7.5	https://vulners.com/cve/CVE-2021-41773
    	CVE-2099-0001	5.0	https://vulners.com/cve/CVE-2099-0001
"""

VULSCAN = """VulDB - https://vuldb.com:
[184412] Apache HTTP Server up to 2.4.49 path traversal

MITRE CVE - https://cve.mitre.org:
[CVE-2021-41773] A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49.

Exploit-DB - https://www.exploit-db.com:
No findings
"""


def nmap_xml(script_id, output, hostname='www.acme.example', port='443'):
	return f"""<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <hostnames><hostname name="{hostname}" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="{port}">
        <state state="open"/>
        <service name="https" product="Apache httpd" version="2.4.49"/>
        <script id="{script_id}" output="{output.replace('"', '&quot;').replace(chr(10), '&#xa;')}"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class NmapParsingTests(TestCase):
	"""nmap's vulners and vulscan script output become Vulnerability dicts for the CVEs the feed knows."""

	@classmethod
	def setUpTestData(cls):
		now = timezone.now()
		CVEEntry.objects.create(cve_id='CVE-2021-41773', cvss=7.5, title='Apache path traversal',
								original_description='CVE-2021-41773 Path traversal in Apache HTTP Server 2.4.49.',
								published_at=now)
		CVEEntry.objects.create(cve_id='CVE-2021-42013', cvss=9.8, title='Apache path traversal (incomplete fix)',
								published_at=now)

	def parse(self, xml):
		with tempfile.NamedTemporaryFile('w', suffix='.xml', delete=False) as f:
			f.write(xml)
		self.addCleanup(os.unlink, f.name)
		return parse_nmap_results(f.name)

	def test_vulners_lists_each_known_cve_once(self):
		vulns = parse_nmap_vulners_output(VULNERS)
		self.assertEqual([v['cve_ids'] for v in vulns], [['CVE-2021-41773'], ['CVE-2021-42013']])  # unknown CVE skipped
		high, critical = vulns
		self.assertEqual((high['cvss_score'], high['type']), (7.5, 'nmap-vulners-nse'))
		self.assertEqual(high['description'], 'Path traversal in Apache HTTP Server 2.4.49.')  # its own id stripped
		self.assertGreater(critical['severity'], high['severity'])

	def test_vulscan_reads_the_mitre_cve_section(self):
		vulns = parse_nmap_vulscan_output(VULSCAN)
		self.assertEqual([v['cve_ids'] for v in vulns], [['CVE-2021-41773']])  # VulDB and Exploit-DB are not supported

	def test_results_carry_the_host_url_and_source(self):
		vulns = self.parse(nmap_xml('vulners', VULNERS))
		self.assertEqual(len(vulns), 2)
		for vuln in vulns:
			self.assertEqual(vuln['source'], NMAP)
			self.assertEqual(vuln['http_url'], 'https://www.acme.example')  # port 443 read as https
		self.assertEqual([v['cve_ids'] for v in self.parse(nmap_xml('vulscan', VULSCAN))], [['CVE-2021-41773']])

	def test_an_unsupported_script_or_bad_xml_gives_nothing(self):
		self.assertEqual(self.parse(nmap_xml('http-title', 'Acme')), [])
		self.assertEqual(self.parse('<nmaprun><host>'), [])
