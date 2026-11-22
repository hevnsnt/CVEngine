"""The threat card counts machines exactly as the Hosts page folds them (``counts.machines``).

The reported case: a PHP card said "2 hosts match by version" and linked ``?names=cloud.oceanx.org,repo.oceanx.org``; the Hosts page showed one host,
repo.oceanx.org, "also answers to cloud.oceanx.org". The matches were on two current copies of cloud.oceanx.org: the scanned row (on the address
repo.oceanx.org shares) and a scanless row with no address (a certificate-transparency name stays current beside the scanned copy).
``counts.with_host_key`` keys each row by its own addresses, so the copies were two keys, one labelled with the shortest name on the address
(repo.oceanx.org) and one with its own name. Every count (card, email digest, ``reporting/threats``, ``get_threat_digest``) now reads one fold."""
from urllib.parse import parse_qs, urlsplit

from django.core.cache import cache

from agentapi.auth import create_token
from cveFeed import counts, overview, report_digest, report_threats
from cveFeed.models import CVEMatch
from startScan.models import IpAddress, Subdomain
from tests.test_agentapi import call, tool_call
from tests.test_report_threats import END, NOW, START, ThreatBase


class MachineCountTests(ThreatBase):
    def setUp(self):
        cache.clear()
        web, scan = self.domains['acme-web'], self.scans['acme-web']
        self.cve = self.kev('CVE-2099-4101')
        address = IpAddress.objects.create(address='203.0.113.77')
        self.cloud = Subdomain.objects.create(target_domain=web, scan_history=scan, name='cloud.acme.test', score=1)
        self.repo = Subdomain.objects.create(target_domain=web, scan_history=scan, name='repo.acme.test', score=1)
        for sub in (self.cloud, self.repo):
            sub.ip_addresses.add(address)
        # a second current copy of cloud.acme.test: no scan (certificate transparency), no address
        self.cloud_ct = Subdomain.objects.create(target_domain=web, scan_history=None, name='cloud.acme.test', score=0)
        for sub in (self.cloud, self.cloud_ct):
            CVEMatch.objects.create(cve_entry=self.cve, subdomain=sub, matched_product='nginx', matched_version='1.18.0', version_in_range=True, confidence=.9,
                                    source='tech')

    def test_the_row_keys_were_two_and_the_machines_are_one(self):
        keys = dict(counts.with_host_key(Subdomain.objects.filter(pk__in=[self.cloud.pk, self.cloud_ct.pk])).values_list('pk', 'host_key'))
        self.assertEqual(len(set(keys.values())), 2)  # the per-row key: what the card used to count
        machines = counts.machines([self.web.pk])
        self.assertEqual(machines.of_row(self.cloud.pk), machines.of_row(self.cloud_ct.pk))
        self.assertEqual(machines.of_row(self.cloud.pk), machines.of_row(self.repo.pk))
        self.assertEqual(machines.name(machines.of_row(self.cloud.pk)), 'repo.acme.test')  # the Hosts page's name: the shortest on the addresses

    def test_impact_counts_one_host(self):
        row = report_threats.impact(self.scope().ids, [self.cve])[self.cve.id]
        self.assertEqual(len(row['matched']), 1)

    def hosts_page_count(self, href):
        names = parse_qs(urlsplit(href).query)['names'][0]
        status, body = call(self.org_member, 'GET', f'/api/v1/projects/acme-web/search?names={names}&facets=none')
        self.assertEqual(status, 200, body)
        return names, body['count'], [r['host'] for r in body['results']]

    def test_the_card_its_link_and_the_hosts_page_agree(self):
        built = overview._threats([self.web.pk], 'Acme Web', {self.web.pk: 'Acme Web'}, NOW, slugs={self.web.pk: 'acme-web'})
        group = next(g for g in built['groups'] if 'CVE-2099-4101' in g['cve_ids'])
        self.assertEqual(group['matched'], 1)
        link = group['links']['matched']
        self.assertEqual((link['n'], link['exact']), (1, True))
        names, n, hosts = self.hosts_page_count(link['href'])
        self.assertEqual((names, n, hosts), ('repo.acme.test', 1, ['repo.acme.test']))
        # the two names the old link listed open the same one host
        self.assertEqual(self.hosts_page_count('/x?names=cloud.acme.test%2Crepo.acme.test')[1], 1)

    def test_the_email_digest_counts_one_host_and_names_it_once(self):
        digest = report_digest.build(self.scope(), START, END, 'weekly', NOW)
        item = next(t for t in digest['threats'] if 'CVE-2099-4101' in t['cve_ids'])
        self.assertEqual((item['hosts_total'], [h['host'] for h in item['hosts']]), (1, ['repo.acme.test']))

    def test_rest_and_mcp_count_one_host(self):
        status, body = call(self.org_member, 'GET', '/api/v1/reporting/threats?project=acme-web')
        self.assertEqual(status, 200, body)
        item = next(i for i in body['items'] if i['cve_ids'] == ['CVE-2099-4101'])
        self.assertEqual(item['matched'], 1)
        _, ro = create_token(self.org_member, 'ro', read_only=True)
        error, data = tool_call(ro, 'get_threat_digest', {'project': 'acme-web'})
        self.assertFalse(error, data)
        self.assertEqual(next(i for i in data['items'] if i['cve_ids'] == ['CVE-2099-4101'])['matched'], 1)

    def test_a_version_unknown_host_is_one_machine_too(self):
        cve = self.kev('CVE-2099-4102', affected=[{'product': 'Caddy', 'ranges': [{'fixed': '9.0.0'}]}])
        from startScan.models import Technology
        caddy = Technology.objects.get_or_create(name='Caddy')[0]
        for sub in (self.cloud, self.cloud_ct, self.repo):
            sub.technologies.add(caddy)
        self.assertEqual(len(report_threats.impact(self.scope().ids, [cve])[cve.id]['product_only']), 1)

    def test_situations_count_the_machine_once(self):
        from cveFeed import situations
        groups, _hosts = situations._build_groups([self.web.pk])
        mine = [g for g in groups if g['all'] & {'cloud.acme.test', 'repo.acme.test'}]
        self.assertEqual(len(mine), 1)
        self.assertEqual(mine[0]['name'], 'repo.acme.test')

    def tearDown(self):
        cache.clear()

