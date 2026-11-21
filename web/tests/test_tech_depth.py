"""Technology and version capture: what the sources already hand over stays in the inventory, with its version, searchable and correlated.

Each fixture is the shape seen on real hosts: a skipped source's technologies carried as a set difference (bbot's "cloudflare" no longer hides the
previous nuclei pass's WordPress 7.1.4), a version the network detection pass filled that a later port scan without a version keeps, every
Shodan InternetDB CPE as a reported reading ("apache http server", never a technology named "http server" or "cpe:/o:..."), MariaDB's "5.5.5-"
handshake prefix, and one Technology row per spelling ("Caddy" and "caddy")."""
from datetime import timedelta
from io import StringIO

from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from cveFeed import correlation, ledger, network_detection, nuclei_scan, port_inventory, source_versions, tech_carry, tech_rows, upgrade_backfills
from cveFeed.models import CVEEntry, CVEMatch, DiscoveryEvent, ProbeObservation, ServiceRun
from startScan.models import EndPoint, Port, Subdomain, Technology
from tests.test_version_sources import VersionFixture

HOST = 'app.rt.test'


def names(sub):
    return {t.name for t in Subdomain.objects.get(pk=sub.pk).technologies.all()}


def tech(sub, *items):
    for name in items:
        sub.technologies.add(Technology.objects.get_or_create(name=name)[0])


class CarryTests(VersionFixture, TestCase):
    """A source the ledger says covered a host is not run again: what it found last time is carried onto the new row, as a set difference."""

    def two_scans(self, service, asset=HOST):
        first = self.host_scan(web=False)
        old = first.subdomain_set.get()
        tech(old, 'WordPress:7.1.4', 'jQuery', 'nginx:1.18.0', 'cloudflare')
        ServiceRun.objects.create(service=service, asset=asset, project=self.project, scan=first, status='done')
        second = self.host_scan(web=False)
        new = second.subdomain_set.get()
        tech(new, 'Cloudflare', 'hsts', 'nginx:1.20.0')  # what bbot attached this time
        return second, new

    def test_the_light_pass_technologies_are_carried_into_a_row_another_source_already_filled(self):
        scan, new = self.two_scans(nuclei_scan.LIGHT_SERVICE)
        self.assertEqual(nuclei_scan.reuse_technologies(scan, self.project.id, {HOST: HOST}), 1)
        # WordPress and jQuery are carried; nginx is named this scan at another version and cloudflare in another case: never carried
        self.assertEqual(names(new), {'Cloudflare', 'hsts', 'nginx:1.20.0', 'WordPress:7.1.4', 'jQuery'})
        self.assertEqual(nuclei_scan.reuse_technologies(scan, self.project.id, {HOST: HOST}), 0)  # nothing left to carry

    def test_the_row_read_is_the_one_of_the_scan_that_last_ran_the_source(self):
        scan, new = self.two_scans('wafw00f')
        middle = Subdomain.objects.create(name=HOST, target_domain=self.domain, scan_history=self.host_scan(web=False, names=('other.rt.test',)))
        tech(middle, 'Imperva')  # a newer row of the host from a scan that did not run the fingerprint: not what it found
        out = tech_carry.carry(scan, self.project.id, {HOST: HOST}, 'wafw00f')
        self.assertEqual(sorted(out[HOST]), ['WordPress:7.1.4', 'jQuery'])
        self.assertNotIn('Imperva', names(new))

    def test_a_run_whose_scan_is_gone_falls_back_to_the_newest_other_row(self):
        scan, new = self.two_scans(nuclei_scan.LIGHT_SERVICE)
        ServiceRun.objects.update(scan=None)
        tech_carry.carry(scan, self.project.id, {f'{HOST}:8443': HOST}, nuclei_scan.LIGHT_SERVICE)
        self.assertIn('WordPress:7.1.4', names(new))

    def test_the_waf_stage_carries_the_products_of_a_host_inside_its_window(self):
        from cveFeed import waf_fingerprint
        first = self.host_scan()
        Subdomain.objects.filter(scan_history=first).update(http_status=200)
        waf_fingerprint.store_products(self.project, first.subdomain_set.get(), [{'firewall': 'FortiWeb', 'manufacturer': 'Fortinet'}], first)
        second = self.host_scan()
        Subdomain.objects.filter(scan_history=second).update(http_status=200)
        tech(second.subdomain_set.get(), 'cloudflare')
        out = waf_fingerprint.run_for_scan(second.id)
        self.assertEqual(out['reused'], 1)
        self.assertEqual(names(second.subdomain_set.get()), {'cloudflare', 'FortiWeb'})


class NetworkFillTests(VersionFixture, TestCase):
    """The version the network detection pass filled is a first-party reading, and a later port scan that names the product without one keeps it."""

    def setUp(self):
        super().setUp()
        self.scan_row = self.host_scan(web=False, ports=((6379, 'redis', 'Redis key-value store', ''),))
        self.sub = self.scan_row.subdomain_set.select_related('target_domain').get()
        self.port = Port.objects.get(number=6379)
        line = {'template-id': 'redis-detect', 'info': {'name': 'Redis Service - Detect'}, 'matched-at': f'{HOST}:6379',
                'extracted-results': ['7.2.4']}
        self.out = network_detection.ingest(self.scan_row, [line], [f'{HOST}:6379'])

    def nmap(self, **rec):
        port_inventory.persist_inventory([{'ip': self.ADDRESS, 'ports': [{'number': 6379, 'state': 'open', 'service_name': 'redis', 'method': 'probed',
                                                                          **rec}]}], os_reliable=True)
        return Port.objects.get(pk=self.port.pk)

    def test_the_fill_is_a_reading_and_not_a_second_technology(self):
        self.assertEqual(Port.objects.get(pk=self.port.pk).version, '7.2.4')
        row = ProbeObservation.objects.get(probe=source_versions.NUCLEI_PROBE, port=6379)
        self.assertEqual((row.kind, row.product, row.version, row.outcome, row.evidence['on_port']), ('version', 'Redis', '7.2.4', 'found', True))
        self.assertNotIn('Redis:7.2.4', names(self.sub))  # the port row states it and is matched: no duplicate match

    def test_a_port_scan_without_a_version_keeps_the_fresh_reading_version(self):
        port = self.nmap(product='Redis key-value store', cpe='cpe:/a:redislabs:redis')
        self.assertEqual((port.version, port.cpe), ('7.2.4', 'cpe:/a:redislabs:redis'))

    def test_a_stale_or_dropped_reading_lets_the_scan_clear_it(self):
        ProbeObservation.objects.filter(probe=source_versions.NUCLEI_PROBE).update(
            observed_at=timezone.now() - timedelta(seconds=ledger.ttl(network_detection.SERVICE) + 60))
        self.assertEqual(self.nmap(product='Redis key-value store').version, '')

    def test_another_product_answering_still_resets_the_row(self):
        port = self.nmap(product='KeyDB')
        self.assertEqual((port.product, port.version), ('KeyDB', ''))


class MariaDbTests(VersionFixture, TestCase):
    def test_the_handshake_prefix_is_off_the_version_and_the_cpe(self):
        rec = port_inventory.mariadb_version({'product': 'MariaDB', 'version': '5.5.5-10.11.19', 'cpe': 'cpe:/a:mariadb:mariadb:5.5.5-10.11.19',
                                              'cpes': ['cpe:/a:mariadb:mariadb:5.5.5-10.11.19']})
        self.assertEqual((rec['version'], rec['cpe'], rec['cpes']), ('10.11.19', 'cpe:/a:mariadb:mariadb:10.11.19', ['cpe:/a:mariadb:mariadb:10.11.19']))
        self.assertEqual(port_inventory.mariadb_version({'product': 'MySQL', 'version': '5.5.5'})['version'], '5.5.5')  # only MariaDB's

    def test_the_port_is_matched_against_the_server_records_and_searchable_by_release(self):
        CVEEntry.objects.create(cve_id='CVE-2099-5501', title='x', cvss=7.5, published_at=timezone.now(),
                                affected=[{'vendor': 'mariadb', 'product': 'mariadb', 'ranges': [{'type': 'ECOSYSTEM', 'introduced': '10.11.0', 'fixed': '10.11.20'}]}])
        self.host_scan(web=False)
        port_inventory.persist_inventory([{'ip': self.ADDRESS, 'ports': [{'number': 3306, 'state': 'open', 'service_name': 'mysql', 'method': 'probed',
                                                                          'product': 'MariaDB', 'cpe': 'cpe:/a:mariadb:mariadb:5.5.5-10.11.19',
                                                                          'cpes': ['cpe:/a:mariadb:mariadb:5.5.5-10.11.19']}]}], os_reliable=True)
        self.assertEqual(Port.objects.get(number=3306).cpe, 'cpe:/a:mariadb:mariadb:10.11.19')
        sub = Subdomain.objects.select_related('target_domain').get(name=HOST)
        cve_by_id, index = correlation.cve_pool()
        correlation.correlate_subdomain(sub, index, cve_by_id)
        match = CVEMatch.objects.get(cve_entry__cve_id='CVE-2099-5501')
        self.assertEqual((match.matched_version, match.version_in_range), ('10.11.19', True))

    def test_the_backfill_takes_the_prefix_off_stored_ports(self):
        self.host_scan(web=False, ports=((3306, 'mysql', 'MariaDB', '5.5.5-10.11.19'),))
        Port.objects.filter(number=3306).update(cpe='cpe:/a:mariadb:mariadb:5.5.5-10.11.19')
        out = StringIO()
        call_command('backfill_technology_names', stdout=out)
        self.assertIn('1 MariaDB port versions would', out.getvalue())
        call_command('backfill_technology_names', apply=True, stdout=out)
        port = Port.objects.get(number=3306)
        self.assertEqual((port.version, port.cpe), ('10.11.19', 'cpe:/a:mariadb:mariadb:10.11.19'))


class TechnologyRowTests(VersionFixture, TestCase):
    def test_a_name_in_another_case_reuses_the_row(self):
        caddy = Technology.objects.create(name='Caddy')
        self.assertEqual(tech_rows.technology('caddy').pk, caddy.pk)
        php = Technology.objects.create(name='PHP:8.1.2')
        self.assertEqual(tech_rows.technology('php:8.1.2').pk, php.pk)
        self.assertNotEqual(tech_rows.technology('php:8.1.3').pk, php.pk)  # another version is another row

    def test_the_backfill_folds_the_stored_duplicates(self):
        scan = self.host_scan()
        sub = scan.subdomain_set.get()
        upper, lower = Technology.objects.create(name='Caddy'), Technology.objects.create(name='caddy')
        other = Subdomain.objects.create(name='two.rt.test', target_domain=self.domain, scan_history=scan)
        sub.technologies.add(upper, lower)
        other.technologies.add(lower)
        page = EndPoint.objects.create(scan_history=scan, target_domain=self.domain, subdomain=sub, http_url='https://app.rt.test/')
        page.techs.add(lower)
        out = tech_rows.merge_duplicates(apply=True)
        self.assertEqual((out['groups'], out['rows']), (1, 1))
        self.assertFalse(Technology.objects.filter(pk=lower.pk).exists())
        self.assertEqual(names(sub), {'Caddy'})
        self.assertEqual(names(other), {'Caddy'})
        self.assertEqual([t.name for t in EndPoint.objects.get(pk=page.pk).techs.all()], ['Caddy'])


class ShodanBackfillTests(VersionFixture, TestCase):
    def test_stored_cpe_technologies_and_old_labels_become_vendor_product_readings(self):
        scan = self.host_scan(web=False)
        scan.scan_status = 2
        scan.save(update_fields=['scan_status'])
        sub = scan.subdomain_set.select_related('target_domain').get()
        tech(sub, 'cpe:/o:canonical:ubuntu_linux', 'http server', 'nginx:1.24.0')  # what earlier builds stored
        DiscoveryEvent.objects.create(scan=scan, domain=self.domain, type='TECHNOLOGY', label=f'cpe:/a:apache:http_server on {HOST}', host=HOST,
                                      module='shodan_idb')
        old = source_versions.product_reading('openssh', '8.9p1', source_versions.SHODAN_PROVIDER, cpe='cpe:/a:openbsd:openssh:8.9p1')
        source_versions.store_reported(self.project.id, self.domain.id, HOST, source_versions.SHODAN_PROBE, [old], source_versions.SHODAN_PROVIDER,
                                       timezone.now(), undated=True)
        dry = source_versions.catch_up_shodan()
        self.assertEqual((dry['relabelled'], dry['technologies']), (1, 1))
        out = StringIO()
        call_command('backfill_shodan_cpes', apply=True, stdout=out)
        got = dict(ProbeObservation.objects.filter(probe=source_versions.SHODAN_PROBE).values_list('product', 'version'))
        self.assertEqual(got, {'openbsd openssh': '8.9p1', 'canonical ubuntu linux': '', 'apache http server': ''})
        self.assertEqual(names(sub), {'nginx:1.24.0'})
        self.assertFalse(Technology.objects.filter(name__startswith='cpe:').exists())
        call_command('backfill_shodan_cpes', apply=True, stdout=out)  # idempotent
        self.assertEqual(ProbeObservation.objects.filter(probe=source_versions.SHODAN_PROBE).count(), 3)

    def test_the_backfills_are_registered_before_the_rerate(self):
        for name in ('backfill_shodan_cpes', 'backfill_technology_names'):
            self.assertLess(upgrade_backfills.BACKFILLS.index(name), upgrade_backfills.BACKFILLS.index('rerate_findings'))
