"""What a host is, from what the scans already stored: an unidentified service's nmap fingerprint decoded and read, a network operating system
named by its OS guess, factory certificate or OS CPE (a FortiGate: "Fortinet FortiOS 6.2 - 7.2", ``CN=FG101FTK...,O=Fortinet``), Recog's
identities and hardware, and the SSH banner the SSH inspection read. Each fixture is the shape seen on real hosts; nothing makes a request."""
import json
from io import StringIO
from pathlib import Path

from django.core.management import call_command
from django.db.models import Q
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import services
from cveFeed import correlation, identities, port_inventory, recog, servicefp, source_versions, upgrade_backfills, version_sources
from cveFeed.models import CVEEntry, ProbeObservation
from startScan.models import IpAddress, Port, Subdomain
from tests.test_version_sources import VersionFixture

FIXTURES = json.loads((Path(__file__).with_name('fixtures') / 'identities' / 'servicefp.json').read_text())
HOST = 'app.rt.test'
FORTI_SUBJECT = 'commonName=FG101FTK19000000/organizationName=Fortinet/stateOrProvinceName=California/countryName=US'


class DecodeTests(SimpleTestCase):
    def test_a_wrapped_escaped_fingerprint_reads_as_the_replies(self):
        replies = servicefp.decode(FIXTURES['web_8088'])
        self.assertEqual([p for p, _r in replies], ['GetRequest', 'HTTPOptions'])
        self.assertTrue(replies[0][1].startswith('HTTP/1.0 301 Moved Permanently\r\nServer: nginx/1.18.0\r\n'))
        self.assertEqual(servicefp.http_headers(replies)['server'], 'nginx/1.18.0')
        self.assertEqual(servicefp.http_cookies(replies), ['PHPSESSID'])
        self.assertIn('Server: nginx/1.18.0', servicefp.text(FIXTURES['web_8088']))

    def test_a_reply_the_clip_cut_short_is_read_as_far_as_it_goes(self):
        replies = servicefp.decode(FIXTURES['web_8088_clipped'])
        self.assertEqual(servicefp.http_headers(replies)['server'], 'nginx/1.18.0')

    def test_the_greeting_and_anything_that_is_no_fingerprint(self):
        self.assertEqual(servicefp.greeting(servicefp.decode(FIXTURES['ftp_2121'])), '220 ProFTPD 1.3.5e Server (Debian) [::ffff:203.0.113.9]')
        self.assertEqual(servicefp.decode('SSH-2.0-OpenSSH_8.9p1'), [])
        self.assertEqual(servicefp.decode('SF-Port1-TCP:V=7.94%r(NULL,4,"\\x00ab\\"")'), [('NULL', 'ab"')])  # a NUL dropped, an escaped quote kept


class FingerprintReadTests(VersionFixture, TestCase):
    def test_the_decoded_text_is_stored_searched_and_read_for_the_server_and_the_greeting(self):
        self.host_scan(web=False)
        port_inventory.persist_inventory([{'ip': self.ADDRESS, 'ports': [
            {'number': 8088, 'state': 'open', 'service_name': 'unknown', 'method': 'probed', 'banner': FIXTURES['web_8088']},
            {'number': 2121, 'state': 'open', 'service_name': 'unknown', 'method': 'probed', 'banner': FIXTURES['ftp_2121']}]}], os_reliable=True)
        port = Port.objects.get(number=8088)
        self.assertIn('Server: nginx/1.18.0', port.extra['servicefp'])
        self.assertTrue(Subdomain.objects.filter(services._banner_q('Server: nginx')).filter(name=HOST).exists())  # banner:"Server: nginx"
        sub = Subdomain.objects.select_related('target_domain').prefetch_related('technologies', 'ip_addresses__ports').get(name=HOST)
        version_sources.refresh_host(sub)
        nmap = {(r.product, r.version, r.port) for r in ProbeObservation.objects.filter(probe=source_versions.NMAP_PROBE)}
        self.assertIn(('nginx', '1.18.0', 8088), nmap)  # the Server header of the reply nmap's GetRequest got
        recogs = {(r.product, r.version, r.port) for r in ProbeObservation.objects.filter(probe=source_versions.RECOG_PROBE)}
        self.assertIn(('ProFTPD', '1.3.5e', 2121), recogs)  # the greeting, read by Recog's FTP database
        self.assertIn('nginx:1.18.0', {t.name for t in sub.technologies.all()})


class SentinelPortTextTests(VersionFixture, TestCase):
    def test_a_fingerprint_is_kept_to_4096_and_version_scripts_are_kept_apart_and_searched(self):
        from agentapi import sentinel_broker as broker
        port = {'number': 902, 'state': 'open', 'service_name': 'unknown', 'banner': 'SF-Port902-TCP:' + 'x' * 5000,
                'version_scripts': {'vmware-version': 'Server version: 7.0.3\nBuild: 20328353', 'banner': 'reviewed id: dropped', 'Bad Id': 'x'},
                'scripts': {'banner': 'b'}}
        row = broker._clean_ports([port])[0]
        self.assertEqual(len(row['banner']), broker.MAX_BANNER)
        self.assertEqual(row['version_scripts'], {'vmware-version': 'Server version: 7.0.3\nBuild: 20328353'})
        self.host_scan(web=False)
        port_inventory.persist_inventory([{'ip': self.ADDRESS, 'ports': [{**row, 'method': 'probed'}]}], os_reliable=True)
        self.assertIn('Build: 20328353', Port.objects.get(number=902).extra['version_script_text'])
        self.assertTrue(Subdomain.objects.filter(services._banner_q('Server version: 7.0.3')).filter(name=HOST).exists())


class NetworkOsTests(VersionFixture, TestCase):
    def fortigate(self, guess='Fortinet FortiOS 6.2 - 7.2', subject=FORTI_SUBJECT, source='sentinel'):
        scan = self.host_scan()
        ip = IpAddress.objects.get(address=self.ADDRESS)
        ip.os_guess, ip.fingerprint = guess, {'os_source': source, 'os_matches': [{'name': guess, 'accuracy': 96}]}
        ip.save(update_fields=['os_guess', 'fingerprint'])
        Port.objects.filter(number=443).update(tls={'subject': subject, 'issuer': subject}, product='', service_name='https')
        sub = scan.subdomain_set.select_related('target_domain').prefetch_related('technologies', 'ip_addresses__ports').get()
        version_sources.refresh_host(sub)
        return Subdomain.objects.select_related('target_domain').prefetch_related('technologies', 'ip_addresses__ports').get(pk=sub.pk)

    def test_the_os_guess_and_the_factory_certificate_name_fortios(self):
        sub = self.fortigate()
        rows = {(r.port, r.product): r for r in ProbeObservation.objects.filter(probe=source_versions.NMAP_PROBE, product='FortiOS')}
        self.assertEqual(set(rows), {(0, 'FortiOS'), (443, 'FortiOS')})
        for row in rows.values():
            self.assertEqual((row.kind, row.version, row.outcome, row.evidence['cpe']), ('version', '', 'hidden', 'cpe:/o:fortinet:fortios'))
        self.assertNotIn('FortiOS', {t.name for t in sub.technologies.all()})  # an identity, never a technology
        self.assertIn(('FortiOS', ''), version_sources.host_products(sub, [p for _a, p in version_sources._ports(sub)]))
        self.assertTrue(version_sources.search_rows('component', 'fortios').filter(host=HOST).exists())

    def test_the_identity_leads_to_the_fortios_build_read_and_to_correlation_leads(self):
        sub = self.fortigate(subject='commonName=vpn.rt.test')
        from cveFeed import route_auth
        ports = [p for _a, p in version_sources._ports(sub)]
        reads = version_sources.wanted(sub.name, version_sources.host_products(sub, ports), ports, route_auth.web_bases(sub))
        self.assertTrue(any('forti' in source.id for source, _base in reads), reads)
        CVEEntry.objects.create(cve_id='CVE-2099-7001', title='x', cvss=9.8, published_at=timezone.now(),
                                affected=[{'vendor': 'Fortinet', 'product': 'FortiOS', 'ranges': [{'type': 'ECOSYSTEM', 'introduced': '7.0.0', 'fixed': '7.2.5'}]}])
        cve_by_id, index = correlation.cve_pool()
        leads, rows = {}, []
        correlation.collect_subdomain_matches(sub, index, cve_by_id, rows=rows, leads=leads)
        self.assertEqual(rows, [])  # no version: never a match
        self.assertIn((sub.target_domain_id, HOST), leads[CVEEntry.objects.get(cve_id='CVE-2099-7001').id])

    def test_a_guess_that_cannot_be_believed_or_a_plain_certificate_names_nothing(self):
        from unittest import mock
        with mock.patch('cveFeed.os_detection.unreliable', return_value=True), mock.patch('cveFeed.os_detection.cause', return_value='docker'):
            self.fortigate(subject='commonName=www.rt.test/organizationName=Example', source='nmap')
        self.assertFalse(ProbeObservation.objects.filter(product='FortiOS').exists())

    def test_a_port_os_cpe_and_the_other_appliances(self):
        port = Port(number=443, cpe='cpe:/o:fortinet:fortios', extra={'cpes': ['cpe:/o:paloaltonetworks:pan-os:10.2.9']}, state='open')
        got = {(r['label'], r['version']) for r in identities.cpe_readings(port)}
        self.assertEqual(got, {('FortiOS', ''), ('PAN-OS', '10.2.9')})
        for subject, issuer, product in (
                ('commonName=192.168.168.168/organizationName=HTTPS Management Certificate for SonicWALL (self-signed)', '', 'SonicOS'),
                ('commonName=gp.example.test', 'commonName=013201027270/organizationName=Palo Alto Networks/countryName=US', 'PAN-OS'),
                ('commonName=ASA Temporary Self Signed Certificate', '', 'Cisco Adaptive Security Appliance Software'),
                ('commonName=IOS-Self-Signed-Certificate-1234567', '', 'Cisco IOS')):
            got = identities.certificate_readings(Port(number=443, tls={'subject': subject, 'issuer': issuer}))
            self.assertEqual([r['label'] for r in got], [product], subject)
        self.assertEqual(identities.certificate_readings(Port(number=443, tls={'subject': 'commonName=FGT.example.test/organizationName=Fortinet'})), [])


class RecogIdentityTests(SimpleTestCase):
    def test_an_unversioned_service_is_an_identity_and_hardware_is_a_hint(self):
        params = {'service.vendor': 'Acme', 'service.product': 'Widget Server', 'hw.vendor': 'Cisco', 'hw.product': 'RV042', 'hw.version': '2.0',
                  'os.vendor': 'Cisco', 'os.product': 'IOS'}
        got = {r['part']: r for r in recog.results(params)}
        self.assertEqual(set(got), {'service', 'hw', 'os'})
        service = source_versions._recog_reading(got['service'], 'http_header.server', 'Server: Widget', 'Acme Widget')
        self.assertEqual((service['label'], service['version']), ('Widget Server', ''))
        network = source_versions._recog_reading(got['os'], 'snmp.sys_description', 'sysDescr', 'IOS')
        self.assertEqual((network['label'], network['version']), ('Cisco IOS', ''))
        hw = source_versions._recog_reading(got['hw'], 'snmp.sys_description', 'sysDescr', 'RV042')
        self.assertEqual((hw['label'], hw['version'], hw['confidence']), ('Cisco RV042', '2.0', 'weak'))  # shown and searched, never matched


class SshTests(VersionFixture, TestCase):
    def test_the_banner_is_a_reading_unless_the_port_states_it(self):
        self.assertEqual([(r['label'], r['version']) for r in source_versions.ssh_readings('SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6')],
                         [('OpenSSH', '8.9p1')])
        scan = self.host_scan(web=False, ports=((22, 'ssh', '', ''),))
        sub = scan.subdomain_set.select_related('target_domain').get()
        self.assertTrue(source_versions.store_ssh(sub, 22, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6'))
        row = ProbeObservation.objects.get(probe=source_versions.SSH_PROBE)
        self.assertEqual((row.product, row.version, row.port), ('OpenSSH', '8.9p1', 22))
        self.assertTrue(version_sources.search_rows('vsource', 'ssh').exists())
        Port.objects.filter(number=22).update(product='OpenSSH', version='8.9p1')
        source_versions.store_ssh(sub, 22, 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6')
        self.assertFalse(ProbeObservation.objects.filter(probe=source_versions.SSH_PROBE).exists())  # nmap states it: not twice


class BackfillTests(VersionFixture, TestCase):
    def test_the_backfill_decodes_stored_fingerprints_and_reads_the_hosts(self):
        scan = self.host_scan(web=False, ports=((8088, 'unknown', '', ''),))
        scan.scan_status = 2
        scan.save(update_fields=['scan_status'])
        Port.objects.filter(number=8088).update(banner=FIXTURES['web_8088'])
        out = StringIO()
        call_command('backfill_identities', stdout=out)
        self.assertIn('1 service fingerprints would be decoded', out.getvalue())
        call_command('backfill_identities', apply=True, stdout=out)
        self.assertIn('Server: nginx/1.18.0', Port.objects.get(number=8088).extra['servicefp'])
        self.assertTrue(ProbeObservation.objects.filter(Q(probe=source_versions.NMAP_PROBE), product='nginx', version='1.18.0').exists())
        self.assertLess(upgrade_backfills.BACKFILLS.index('backfill_identities'), upgrade_backfills.BACKFILLS.index('rerate_findings'))
