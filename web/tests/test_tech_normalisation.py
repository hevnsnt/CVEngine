"""Technology names reaching the names CVE records use (cveFeed/data/product_aliases.json, cveFeed.correlation.named_hits) and the coverage
report that measures what is still unmatched (cveFeed.tech_coverage, manage.py technology_coverage, the technology_coverage tool).

Every alias is tested against a record spelled the way its evidence says, and never across vendors; every collision found while measuring the
published seed has a regression here (Apple's iOS and Cisco's IOS, Oracle's HTTP Server and Apache's, the Node.js Express framework and
Ubiquiti's UniFi Express, .NET and Go's net packages)."""
import gzip
import io
import json
import os
import re
import tempfile
import unittest

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import correlation, tech_coverage, upgrade_backfills
from cveFeed.correlation import _match_candidates, _norm, build_product_index, named_hits, parse_version

ALIASES = os.path.join(os.path.dirname(correlation.__file__), 'data', 'product_aliases.json')
EVIDENCE = re.compile(r'(?:cpe:2\.3:[aoh]:[^:\s]+:[^:\s]+|CVE-\d{4}-\d{4,})')


class FakeCVE:
    def __init__(self, cid, affected, kev=False, cve_id=''):
        self.id = cid
        self.cve_id = cve_id or f'CVE-2099-{cid}'
        self.affected = correlation.clean_affected(affected)
        self.kev = kev


def item(vendor, product, introduced='1.0', fixed='99.0'):
    out = {'product': product, 'ranges': [{'introduced': introduced, 'fixed': fixed}]}
    if vendor is not None:
        out['vendor'] = vendor
    return out


class Pool:
    def __init__(self, *entries):
        self.cves = [FakeCVE(i + 1, [e] if isinstance(e, dict) else e) for i, e in enumerate(entries)]
        self.by_id = {c.id: c for c in self.cves}
        self.index = build_product_index(self.cves)

    def reach(self, name, cpe=None):
        """The ids of the CVEs ``name`` connects to (1-based: the order the entries were given)."""
        return {cve.id for cve, _hit in named_hits(_norm(name), self.index, self.by_id, cpe=cpe)}

    def matches(self, name, version, cpe=None):
        return {cve.id: in_range for cve, _p, in_range in
                _match_candidates(name, parse_version(version), _norm(name), self.index, self.by_id, cpe=cpe, raw=version)}


class AliasDataTests(unittest.TestCase):
    """The data file itself: every entry cites a CPE or a CVE, names its vendors, and no name points at two entries' vendors."""

    @classmethod
    def setUpClass(cls):
        with open(ALIASES, encoding='utf-8') as fh:
            cls.doc = json.load(fh)

    def test_every_entry_cites_a_cpe_or_cve_record(self):
        for section in ('aliases', 'restrict', 'ambiguous_products', 'vendor_renames'):
            for entry in self.doc[section]:
                self.assertTrue(entry.get('evidence'), entry)
                for line in entry['evidence']:
                    self.assertRegex(line, EVIDENCE, f'{section}: {line}')

    def test_every_alias_names_its_vendors_so_it_never_merges_across_vendors(self):
        for entry in self.doc['aliases']:
            self.assertTrue(entry['vendors'], entry['names'])
            self.assertTrue(entry['products'], entry['names'])

    def test_a_name_belongs_to_one_vendor(self):
        seen = {}
        for entry in self.doc['aliases']:
            for name in entry['names']:
                vendors = frozenset(_norm(v) for v in entry['vendors'])
                self.assertEqual(seen.setdefault(_norm(name), vendors), vendors, name)

    def test_the_tables_are_read_from_the_file(self):
        self.assertIn('adaptivesecurityappliancesoftware', correlation.PRODUCT_ALIASES['ciscoasa'])
        self.assertEqual(correlation.ALIAS_VENDORS[('ciscoasa', 'adaptivesecurityappliancesoftware')], ('cisco',))
        self.assertIn('ios', correlation.AMBIGUOUS_PRODUCTS)
        self.assertEqual(correlation.NAME_VENDORS['express'], (('expressjs', 'openjs'), False))
        self.assertIn('f5', correlation.VENDOR_CLASSES['igorsysoev'])


class EveryAliasTests(unittest.TestCase):
    """Each alias reaches a record spelled as its evidence spells the product, by its first vendor, and does not reach the same product
    spelled the same way by an unrelated vendor."""

    def test_each_alias_reaches_its_records_and_only_its_vendors(self):
        with open(ALIASES, encoding='utf-8') as fh:
            doc = json.load(fh)
        for entry in doc['aliases']:
            vendor = entry['vendors'][0]
            for product in entry['products']:
                if len(_norm(product)) < 3:
                    continue
                pool = Pool(item(vendor, product), item('Unrelated Widgets Inc', product))
                for name in entry['names']:
                    if _norm(name) == _norm(product):
                        continue
                    with self.subTest(name=name, product=product):
                        reached = pool.reach(name)
                        self.assertIn(1, reached, f'{name} should reach {vendor}:{product}')
                        if not correlation.name_matches_token(_norm(name), _norm(product)):  # reached only through the alias: held to its vendors
                            self.assertNotIn(2, reached, f'{name} must not reach another vendor\'s {product}')


class NamedAliasTests(unittest.TestCase):
    """The gaps measured on the published seed, each with the records it now reaches."""

    def test_cisco_asa_under_every_name_reaches_all_three_spellings(self):
        pool = Pool(item('cisco', 'adaptive_security_appliance_software', '9.16.0', '9.16.4.19'),
                    item('Cisco', 'Cisco Adaptive Security Appliance (ASA) Software', '9.16.0', '9.16.4.19'),
                    item('Cisco', 'Cisco Secure Firewall Adaptive Security Appliance (ASA) Software', '9.16.0', '9.16.4.19'))
        for name in ('Cisco ASA', 'Cisco Adaptive Security Appliance Software', 'Cisco Adaptive Security Appliance',
                     'Cisco Adaptive Security Appliance (ASA) Software'):
            self.assertEqual(pool.matches(name, '9.16.4.18'), {1: True, 2: True, 3: True}, name)

    def test_ivanti_and_pulse_connect_secure_are_one_product(self):
        pool = Pool(item('Ivanti', 'Connect Secure', '22.0', '22.7.4'), item(None, 'Pulse Connect Secure', '9.0', '9.1.11'),
                    item('Acme', 'Connect Secure'))
        self.assertEqual(pool.reach('Ivanti Connect Secure'), {1, 2})
        self.assertEqual(pool.reach('Pulse Secure'), {1, 2})
        self.assertEqual(pool.matches('Pulse Connect Secure', '9.1.10'), {1: False, 2: True})

    def test_citrix_gateway_reaches_the_netscaler_records(self):
        pool = Pool(item('NetScaler', 'Gateway'), item('Citrix', 'NetScaler ADC'), item(None, 'Citrix ADC, Citrix Gateway, Citrix SDWAN WAN-OP'),
                    item('Someone', 'Gateway'))
        self.assertEqual(pool.reach('Citrix Gateway'), {1, 2, 3})

    def test_a_globalprotect_portal_is_pan_os(self):
        pool = Pool(item('Palo Alto Networks', 'PAN-OS', '10.2.0', '10.2.9'), item('Palo Alto Networks', 'GlobalProtect App', '6.0', '6.2'))
        self.assertEqual(pool.reach('GlobalProtect'), {1})
        self.assertEqual(pool.reach('Palo Alto Networks GlobalProtect'), {1})

    def test_outlook_on_the_web_reaches_every_exchange_cumulative_update(self):
        pool = Pool(item('Microsoft', 'Microsoft Exchange Server 2019 Cumulative Update 12'), item('Microsoft', 'Microsoft Outlook 2016'))
        self.assertEqual(pool.reach('Outlook Web App'), {1})

    def test_cisco_ios_reaches_the_records_written_for_ios_and_ios_xe(self):
        pool = Pool(item(None, 'Cisco IOS and IOS XE'), item('Cisco', 'IOS'))
        self.assertEqual(pool.reach('Cisco IOS'), {1, 2})

    def test_serv_u_synology_sitecore_and_liferay(self):
        pool = Pool(item('SolarWinds', 'Serv-U Managed File Transfer Server and Serv-U Secured FTP'), item('Synology', 'DiskStation Manager (DSM)'),
                    item('Sitecore', 'Experience Platform (XP)'), item('liferay', 'portal'))
        self.assertEqual(pool.reach('Serv-U ftpd'), {1})
        self.assertEqual(pool.reach('Synology DSM'), {2})
        self.assertEqual(pool.reach('Sitecore'), {3})
        self.assertEqual(pool.reach('Liferay Portal'), {4})

    def test_a_name_that_leads_with_the_records_own_vendor(self):
        pool = Pool(item('Fortra', 'GoAnywhere MFT'), item('Progress Software Corporation', 'MOVEit Transfer'), item('QNAP Systems Inc.', 'QTS'),
                    item('Other', 'GoAnywhere MFT'))
        self.assertEqual(pool.reach('Fortra GoAnywhere MFT'), {1})
        self.assertEqual(pool.reach('Progress MOVEit Transfer'), {2})
        self.assertEqual(pool.reach('QNAP QTS'), {3})

    def test_a_vendor_lead_never_reaches_a_vendor_whose_name_only_starts_the_same(self):
        pool = Pool(item('Progressive Labs', 'Transfer Suite'), item('Progress', 'Transfer Suite'))
        self.assertEqual(pool.reach('Progress Transfer Suite'), {2})

    def test_a_template_word_an_earlier_build_stored_is_dropped(self):
        self.assertEqual(correlation.tech_name('Nginx version'), 'Nginx')
        self.assertEqual(correlation.tech_name('Microsoft IIS Detect'), 'Microsoft IIS')
        self.assertEqual(correlation.tech_name('version'), 'version')
        sighting = tech_coverage.normalise_sighting('Nginx version:1.24.0')
        self.assertEqual((sighting['name'], sighting['version']), ('Nginx', '1.24.0'))


class CpeTests(unittest.TestCase):
    def test_nmaps_nginx_cpe_vendor_reaches_the_f5_and_nginx_records(self):
        pool = Pool(item('F5', 'NGINX Open Source', '1.0.0', '1.27.4'), item('nginx', 'nginx', '1.0.0', '1.13.3'),
                    item('[UNKNOWN]', 'nginx', '1.0.0', '1.15.6'), item('0xJacky', 'nginx-ui'), item('kubernetes', 'ingress-nginx'))
        self.assertEqual(pool.matches('nginx', '1.12.0', cpe='cpe:/a:igor_sysoev:nginx:1.12.0'), {1: True, 2: True, 3: True})

    def test_nmaps_werkzeug_cpe_vendor_reaches_pallets(self):
        pool = Pool(item('pallets', 'werkzeug', '0.1', '3.0.3'))
        self.assertEqual(pool.reach('Werkzeug httpd', cpe='cpe:/a:pocoo:werkzeug:2.0.1'), {1})

    def test_a_cpe_reaches_a_record_with_no_vendor_whose_product_carries_the_cpe_vendor(self):
        pool = Pool(item('Apache Software Foundation', 'Apache Tomcat'), item(None, 'Apache Tomcat'), item(None, 'Tomcat Commander'))
        self.assertEqual(pool.reach('Apache Tomcat', cpe='cpe:/a:apache:tomcat:9.0.50'), {1, 2})

    def test_a_cpe_still_refuses_another_vendors_product(self):
        pool = Pool(item('Apache Software Foundation', 'Apache HTTP Server'), item('apache', 'http_server'), item('Oracle', 'http_server'))
        self.assertEqual(pool.reach('Oracle HTTP Server', cpe='cpe:/a:oracle:http_server:12.2.1'), {3})
        self.assertEqual(pool.reach('Apache httpd', cpe='cpe:/a:apache:http_server:2.4.37'), {1, 2})


class CollisionTests(unittest.TestCase):
    """Names two vendors use for different products: each reaches only its own vendor's records."""

    def setUp(self):
        self.pool = Pool(item('Apple', 'iOS', '1.0', '17.0'), item('apple', 'iphone_os', '1.0', '17.0'), item(None, 'iOS', '1.0', '17.0'),
                         item('Cisco', 'IOS', '12.0', '15.9'), item(None, 'Cisco IOS', '12.0', '15.9'))

    def test_cisco_ios_never_reaches_apples_ios(self):
        self.assertEqual(self.pool.reach('Cisco IOS'), {4, 5})
        self.assertEqual(self.pool.reach('Cisco IOS http config'), {4})

    def test_apple_ios_never_reaches_ciscos_ios(self):
        self.assertEqual(self.pool.reach('Apple iOS'), {1})

    def test_a_record_naming_no_vendor_does_not_vouch_for_either(self):
        self.assertNotIn(3, self.pool.reach('Cisco IOS'))
        self.assertNotIn(3, self.pool.reach('Apple iOS'))

    def test_bare_ios_is_an_operating_system_sighting_and_reaches_nothing(self):
        self.assertEqual(tech_coverage.connect('IOS', '', self.pool.index, self.pool.by_id)['cves'], set())

    def test_oracle_http_server_never_reaches_apache(self):
        pool = Pool(item('Apache Software Foundation', 'Apache HTTP Server'), item('apache', 'http_server'), item('n/a', 'Apache HTTP Server'),
                    item('Oracle Corporation', 'Oracle HTTP Server'))
        self.assertEqual(pool.reach('Oracle HTTP Server'), {4})
        self.assertEqual(pool.reach('Oracle HTTP Server Powered by Apache'), set())
        self.assertEqual(pool.reach('Apache httpd'), {1, 2, 3})
        self.assertEqual(pool.reach('httpd'), {1, 2, 3})

    def test_the_express_framework_never_reaches_ubiquitis_unifi_express_or_fastify(self):
        pool = Pool(item('Ubiquiti Inc', 'Express'), item('Ubiquiti Inc', 'Express 7'), {'package': '@fastify/express', 'vendor': '@fastify/express',
                    'ranges': [{'introduced': '0', 'fixed': '9'}]}, {'package': 'express', 'ecosystem': 'npm', 'ranges': [{'introduced': '0', 'fixed': '4.19.2'}]},
                    item('expressjs', 'express'))
        self.assertEqual(pool.reach('Express'), {4, 5})
        self.assertEqual(pool.reach('Node.js Express framework'), {4, 5})

    def test_dotnet_never_reaches_gos_net_packages(self):
        pool = Pool(item('Go standard library', 'net/http'), {'package': 'golang.org/x/net', 'ranges': [{'introduced': '0', 'fixed': '0.23.0'}]},
                    item('Microsoft', 'Microsoft .NET Framework', '4.0', '4.8.1'))
        self.assertEqual(pool.reach('.NET Framework'), {3})
        self.assertEqual(pool.reach('.net_framework'), {3})

    def test_a_vendor_rename_does_not_reach_an_unrelated_product(self):
        pool = Pool(item('F5', 'BIG-IP'), item('nginx', 'nginx'))
        self.assertEqual(pool.reach('nginx', cpe='cpe:/a:igor_sysoev:nginx:1.18.0'), {2})


class CoverageReportTests(unittest.TestCase):
    def setUp(self):
        self.pool = Pool(item('Acme', 'Widget Server'), item('Globex', 'Widget'), item('Acme', 'Widget', '1.0', '2.0'),
                         item('Initech', 'Frobnicator'), [item('Initech', 'Frobnicator'), item('Initech', 'Frobnicator Pro')])
        self.pool.cves[0].kev = True

    def report(self, sightings, limit=50):
        return tech_coverage.report(sightings, self.pool.by_id, self.pool.index, limit)

    def test_unmatched_unversioned_and_ambiguous(self):
        s = tech_coverage.normalise_sighting
        out = self.report([s('Frobnicator', hosts=3), s('Frobnicator:1.2', hosts=2), s('Widget', hosts=4), s('Cloudflare', hosts=9),
                           s('Initech Frobnicator Ultra', hosts=1), s('Windows', hosts=5)])
        self.assertEqual(out['catalogue']['cves'], 5)
        self.assertEqual(out['os_sightings'], 1)
        self.assertEqual([(r['name'], r['hosts']) for r in out['unmatched']], [('Cloudflare', 9), ('Initech Frobnicator Ultra', 1)])
        self.assertEqual(out['unmatched'][0]['near'], [])
        self.assertEqual(out['unmatched'][1]['near'][0], {'product': 'Initech:Frobnicator', 'cves': 2})
        lead = {r['name']: r for r in out['unversioned']}
        self.assertEqual((lead['Frobnicator']['cves'], lead['Frobnicator']['unversioned_hosts'], lead['Frobnicator']['versioned_hosts']), (2, 3, 2))
        self.assertEqual([r['name'] for r in out['unversioned']], ['Widget', 'Frobnicator'])
        self.assertEqual(out['ambiguous'][0]['name'], 'Widget')
        self.assertEqual({v['vendor'] for v in out['ambiguous'][0]['vendors']}, {'acme', 'globex'})

    def test_spellings_of_one_vendor_and_a_vendor_named_after_its_product_are_one_vendor(self):
        pool = Pool(item('F5', 'nginx'), item('nginx', 'nginx'), item('Citrix', 'NetScaler ADC'), item('Cloud Software Group', 'NetScaler ADC'))
        out = tech_coverage.report([tech_coverage.normalise_sighting('nginx'), tech_coverage.normalise_sighting('NetScaler ADC')],
                                   pool.by_id, pool.index)
        self.assertEqual(out['ambiguous'], [])

    def test_limit_is_bounded(self):
        out = self.report([tech_coverage.normalise_sighting(f'Nothing {i}') for i in range(20)], limit=10_000)
        self.assertEqual(out['limit'], tech_coverage.MAX_LIMIT)
        out = self.report([tech_coverage.normalise_sighting(f'Nothing {i}') for i in range(20)], limit=3)
        self.assertEqual((len(out['unmatched']), out['unmatched_count']), (3, 20))


class CommandFromSeedTests(TestCase):
    def test_the_command_reads_a_seed_and_a_names_file_without_the_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            seed = os.path.join(tmp, 'seed.jsonl.gz')
            with gzip.open(seed, 'wt', encoding='utf-8') as fh:
                fh.write(json.dumps({'format': 1}) + '\n')
                fh.write(json.dumps({'cve_id': 'CVE-2020-3452', 'kev': True, 'affected': [item('Cisco', 'Cisco Adaptive Security Appliance (ASA) Software')]}) + '\n')
                fh.write(json.dumps({'cve_id': 'CVE-2000-1', 'status': 'REJECTED', 'affected': [item('Acme', 'Thing')]}) + '\n')
            names = os.path.join(tmp, 'names.json')
            with open(names, 'w', encoding='utf-8') as fh:
                json.dump(['Cisco ASA', {'name': 'Thing', 'hosts': 4}, {'name': 'nginx', 'source': 'port', 'cpe': 'cpe:/a:igor_sysoev:nginx', 'version': '1.18.0'}], fh)
            out = io.StringIO()
            call_command('technology_coverage', seed=seed, names=names, json=True, stdout=out)
            report = json.loads(out.getvalue())
            self.assertEqual(report['catalogue']['cves'], 1)
            self.assertEqual([r['name'] for r in report['unversioned']], ['Cisco ASA'])
            self.assertEqual({r['name'] for r in report['unmatched']}, {'Thing', 'nginx'})
            text = io.StringIO()
            call_command('technology_coverage', seed=seed, names=names, stdout=text)
            self.assertIn('Unmatched (2)', text.getvalue())


class DatabaseTests(TestCase):
    """The coverage tool and the update backfill against stored hosts."""

    def setUp(self):
        from cveFeed.models import CVEEntry
        from dashboard.models import Org, Project
        from scanEngine.models import EngineType
        from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Technology
        from targetApp.models import Domain
        correlation._INDEX_CACHE.update(key=None, value=None)
        org = Org.objects.create(name='A', slug='a')
        self.project = Project.objects.create(name='P', slug='pa', insert_date=timezone.now(), org=org)
        domain = Domain.objects.create(name='norm.test', project=self.project, insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
        scan = ScanHistory.objects.create(domain=domain, scan_type=engine, scan_status=2, start_scan_date=timezone.now())
        self.asa = CVEEntry.objects.create(cve_id='CVE-2020-3452', kev=True, cvss=7.5, published_at=timezone.now(),
                                           affected=[item('Cisco', 'Cisco Adaptive Security Appliance (ASA) Software', '9.16.0', '9.16.4.19')])
        CVEEntry.objects.create(cve_id='CVE-2026-34909', cvss=7.0, published_at=timezone.now(), affected=[item('Ubiquiti Inc', 'Express', '1.0', '9.0')])
        self.fw = Subdomain.objects.create(name='fw.norm.test', target_domain=domain, scan_history=scan)
        self.fw.technologies.add(Technology.objects.create(name='Cisco ASA:9.16.4.18'))
        self.web = Subdomain.objects.create(name='web.norm.test', target_domain=domain, scan_history=scan)
        self.web.technologies.add(Technology.objects.create(name='Express:4.18.2'), Technology.objects.create(name='Cloudflare'))
        self.svc = Subdomain.objects.create(name='svc.norm.test', target_domain=domain, scan_history=scan)
        ip = IpAddress.objects.create(address='192.0.2.10')
        self.svc.ip_addresses.add(ip)
        ip.ports.add(Port.objects.create(number=443, product='Cisco Adaptive Security Appliance', version=''))
        self.admin = User.objects.create_superuser('root', 'root@example.test', 'x')
        self.member = User.objects.create_user('member', 'm@example.test', 'x')
        from dashboard.models import ProjectMembership
        ProjectMembership.objects.create(user=self.member, project=self.project, role='admin')

    def test_sightings_count_hosts_per_name(self):
        rows = {(s['name'], s['source']): s for s in tech_coverage.sightings_from_db()}
        self.assertEqual(rows[('Cisco ASA', 'tech')]['version'], '9.16.4.18')
        self.assertEqual(rows[('Cloudflare', 'tech')]['hosts'], 1)
        self.assertEqual(rows[('Cisco Adaptive Security Appliance', 'port')]['hosts'], 1)

    def test_the_tool_is_for_an_app_admin_only(self):
        from tests.test_agentapi import call, tool_call
        admin, member = create_token(self.admin, 'a')[1], create_token(self.member, 'm')[1]
        read_only = create_token(self.admin, 'ro', read_only=True)[1]
        status, data = call(admin, 'GET', '/api/v1/technology-coverage?limit=5')
        self.assertEqual(status, 200, data)
        self.assertEqual([r['name'] for r in data['unmatched']], ['Cloudflare', 'Express'])  # the framework is not Ubiquiti's UniFi Express
        self.assertEqual({r['name'] for r in data['unversioned']}, {'Cisco Adaptive Security Appliance'})
        error, mcp = tool_call(read_only, 'technology_coverage', {'project': 'pa'})
        self.assertFalse(error, mcp)
        self.assertEqual((mcp['project'], mcp['unmatched_count']), ('pa', 2))
        self.assertEqual(call(member, 'GET', '/api/v1/technology-coverage')[0], 403)
        error, text = tool_call(member, 'technology_coverage')
        self.assertTrue(error)
        self.assertIn('App Admin', text)
        self.assertEqual(call(admin, 'GET', '/api/v1/technology-coverage?project=nope')[0], 404)
        self.assertEqual(call(admin, 'GET', '/api/v1/technology-coverage?limit=x')[0], 400)

    def test_the_backfill_correlates_the_hosts_the_name_rules_touch(self):
        from cveFeed.models import CVEMatch
        from cveFeed.management.commands.backfill_name_aliases import touched_hosts
        _cves, index = correlation.cve_pool()
        self.assertEqual(set(touched_hosts(index).values_list('name', flat=True)), {'fw.norm.test', 'web.norm.test', 'svc.norm.test'})
        out = io.StringIO()
        call_command('backfill_name_aliases', stdout=out)
        self.assertIn('dry run: 3 current hosts', out.getvalue())
        self.assertFalse(CVEMatch.objects.exists())
        call_command('backfill_name_aliases', apply=True, stdout=out)
        self.assertEqual(list(CVEMatch.objects.filter(subdomain=self.fw).values_list('cve_entry__cve_id', 'version_in_range')),
                         [('CVE-2020-3452', True)])
        self.assertFalse(CVEMatch.objects.filter(subdomain=self.web).exists())  # the framework is not Ubiquiti's device
        call_command('backfill_name_aliases', apply=True, stdout=out)  # again: nothing changes
        self.assertEqual(CVEMatch.objects.count(), 1)

    def test_the_backfill_is_registered_before_the_rescore(self):
        names = upgrade_backfills.BACKFILLS
        self.assertIn('backfill_name_aliases', names)
        self.assertLess(names.index('backfill_name_aliases'), names.index('rerate_findings'))
