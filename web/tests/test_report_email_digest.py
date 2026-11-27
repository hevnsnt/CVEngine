"""The email report's calm rework: the At a glance block (the Overview's own status sentence, a neutral hosts delta, only what needs a person in the headline),
the vulnerabilities section (only what is found on the scope's hosts, grouped by product, five at most, hosts named with their project), the grouped top findings, the
subject and preheader, and tenancy."""
import re
from datetime import timedelta
from unittest import mock

from cveFeed import counts, overview, report_digest, report_threats, situations
from cveFeed.models import CVEEntry, CVEMatch, HygieneFinding, StatsSnapshot
from startScan.models import Subdomain, Vulnerability
from tests.test_report_subscriptions import SubBase
from tests.test_report_threats import NOW, START, ThreatBase

END = NOW + timedelta(days=1)  # the fixtures are created a moment after NOW


class Base(SubBase, ThreatBase):
    def digest(self, org=False, user=None, cadence='weekly'):
        scope = self.scope(user or self.org_admin, **({'org': 'acme-org'} if org else {'project': 'acme-web'}))
        return report_digest.build(scope, START, END, cadence, END)

    def product_cve(self, cve_id, product, **kw):
        intel = {'kev': {'cisa_kev': {'added': (NOW - timedelta(days=2)).date().isoformat(), 'ransomware': False, 'name': f'{product} flaw', 'vendor': 'V', 'product': product}}}
        return self.kev(cve_id, affected=[{'product': product, 'ranges': [{'fixed': '9.9.9'}]}], intel=intel, **kw)

    def hit(self, cve, sub, product='nginx', **kw):
        return CVEMatch.objects.create(cve_entry=cve, subdomain=sub, matched_product=product, matched_version='1.0', confidence=.9, source='port', **{'version_in_range': True, **kw})

    def host(self, name, project='acme-web', address=None):
        from startScan.models import IpAddress
        sub = Subdomain.objects.create(target_domain=self.domains[project], scan_history=self.scans[project], name=name, score=1)
        if address:
            sub.ip_addresses.add(IpAddress.objects.create(address=address))
        return sub

    def quiet(self):
        """Nothing proven, nothing on fire, nothing worth a look in the Acme organization: only low-level items."""
        CVEMatch.objects.filter(subdomain__target_domain__project__org=self.org_a).delete()
        Vulnerability.objects.filter(target_domain__project__org=self.org_a).delete()
        HygieneFinding.objects.filter(domain__project__org=self.org_a).delete()


class StatusAndTileTests(Base):
    def test_with_nothing_proven_the_email_is_calm_whatever_the_raw_totals(self):
        self.quiet()
        for i in range(30):  # a new Sentinel's first deep scan: a heap of Ice matches
            self.hit(CVEEntry.objects.create(cve_id=f'CVE-2099-5{i:03d}', cvss=3.1, title='minor', published_at=NOW, affected=[]), self.www, version_in_range=False)
        digest = self.digest()
        h = digest['headline']
        self.assertEqual((h['heat']['fire'], h['needs'], h['new_worth_a_look']), (0, 0, 0))
        self.assertGreaterEqual(h['new_findings'], 30)  # the raw count is there, but never a headline
        self.assertEqual(digest['status']['headline'], 'Nothing needs you right now.')
        tiles = {t['label']: t for t in report_digest._tiles(digest)}
        self.assertEqual(tiles['Needs attention']['value'], '0')
        self.assertEqual(tiles['New issues worth a look']['value'], '0')
        self.assertNotIn('Open findings', tiles)
        self.assertTrue(report_digest.totals_line(digest).startswith('30 lower-priority items are tracked in cvENGINE ('))
        self.assertTrue(report_digest.subject(digest).endswith(': nothing needs you'))
        pre = report_digest._preheader(digest)
        self.assertIn('Nothing needs you right now', pre)
        self.assertNotIn('fire', pre.lower())
        self.assertNotIn('30', pre)
        self.assertEqual(report_digest.heat_line(digest)[0], {'heat': 'fire', 'text': 'No Fire', 'gloss': ''})

    def test_the_status_sentence_is_the_overviews_own(self):
        digest = self.digest()
        ranking, hosts = situations.ranked(list(self.scope().ids))
        expected = overview.status_block(hosts, overview.host_counts(ranking), situations.last_scan(list(self.scope().ids)), END, None, None)
        self.assertEqual(digest['status']['headline'], expected['headline'])

    def test_a_fire_shows_in_the_subject_and_the_tiles(self):
        digest = self.digest()
        self.assertEqual(digest['headline']['heat']['fire'], 1)
        self.assertTrue(report_digest.subject(digest).endswith(': 1 on fire'))
        self.assertGreaterEqual(digest['headline']['new_worth_a_look'], 1)
        _, text, html = report_digest.render(digest, None, 'a@example.org', 'https://x/u/')
        for body in (text, html):
            self.assertIn('Hosts with open findings', body)
            self.assertNotIn('Externally facing', body)
            self.assertNotIn('Exposed hosts', body)
        self.assertIn('1 Fire (needs action now). No Smoke. No Ice', text)

    def test_the_hosts_delta_is_neutral_and_the_attention_delta_is_red_only_when_it_rises(self):
        digest = self.digest()
        digest['headline'].update({'exposed_hosts': 24, 'exposed_hosts_prev': 16, 'needs': 3, 'needs_prev': 1})
        tiles = {t['label']: t for t in report_digest._tiles(digest)}
        self.assertEqual((tiles['Hosts with open findings']['delta'], tiles['Hosts with open findings']['tone']), ('▲ 8 since last week', 'neutral'))
        self.assertEqual(tiles['Needs attention']['tone'], 'bad')
        digest['headline'].update({'exposed_hosts': 8, 'needs_prev': 5})
        tiles = {t['label']: t for t in report_digest._tiles(digest)}
        self.assertEqual((tiles['Hosts with open findings']['tone'], tiles['Needs attention']['tone']), ('neutral', 'good'))
        _, _, html = report_digest.render(digest, None, 'a@example.org', 'https://x/u/')
        cell = re.search(r'<div class="(\w+)"[^>]*>(▼ 8 since last week)</div>', html)
        self.assertEqual(cell.group(1), 'soft')  # grey, not the red or green class

    def test_the_comparison_reads_the_snapshot_of_the_hosts_that_need_attention(self):
        StatsSnapshot.objects.create(project=self.web, date=(NOW - timedelta(days=9)).date(), hosts=1, exposed_hosts=3, open_findings={}, needs_hosts=0)
        h = self.digest()['headline']
        self.assertEqual((h['needs_prev'], h['needs']), (0, 1))
        tiles = {t['label']: t for t in report_digest._tiles({**self.digest(), 'headline': h})}
        self.assertEqual((tiles['Needs attention']['delta'], tiles['Needs attention']['tone']), ('▲ 1 since last week', 'bad'))
        StatsSnapshot.objects.all().update(needs_hosts=None)  # a day from before the figure was kept: no comparison, no invented one
        self.assertIsNone(self.digest()['headline']['needs_prev'])

    def test_the_overviews_needs_tile_says_the_emails_number(self):
        for org in (False, True):
            ids = list(self.scope(**({'org': 'acme-org'} if org else {'project': 'acme-web'})).ids)
            StatsSnapshot.objects.update_or_create(project_id=ids[0], date=overview.timezone.localdate(), defaults={'hosts': 1, 'exposed_hosts': 0, 'open_findings': {}, 'needs_hosts': 99})
            email = self.digest(org=org)['headline']['needs']
            tile = next(k for k in overview.build(ids)['kpis'] if k['key'] == 'needs')
            self.assertEqual((tile['label'], tile['value']), ('Needs attention', email), org)  # never the stale 99 of today's row
            self.assertEqual(tile['value'], overview.needs_hosts(ids))
            self.assertGreater(email, 0)


class ThreatSectionTests(Base):
    def test_only_what_is_found_on_a_host_of_the_scope_is_listed(self):
        found = self.product_cve('CVE-2099-6001', 'Nginxish')
        self.hit(found, self.www, 'Nginxish')
        self.product_cve('CVE-2099-6002', 'Ghostware')  # announced, found nowhere
        self.unversioned_nginx_host()
        self.kev('CVE-2099-6003')  # nginx runs on a host with no version read: a product-only reading
        digest = self.digest()
        self.assertEqual([t['cve_ids'] for t in digest['threats']], [['CVE-2099-6001']])
        self.assertEqual(digest['threats_checked'], 3)

    def test_nothing_in_the_tenant_is_one_calm_line(self):
        self.product_cve('CVE-2099-6010', 'Ghostware')
        self.unversioned_nginx_host()
        self.kev('CVE-2099-6011')
        digest = self.digest()
        self.assertEqual(digest['threats'], [])
        self.assertEqual(digest['threats_empty'], "None of this week's newly exploited or critical vulnerabilities were found on your hosts. We checked 2.")
        _, text, html = report_digest.render(digest, None, 'a@example.org', 'https://x/u/')
        self.assertIn("None of this week&#x27;s newly exploited or critical vulnerabilities were found on your hosts. We checked 2.", html)
        self.assertIn("None of this week's newly exploited or critical vulnerabilities were found on your hosts.", text)
        self.assertNotIn('Ghostware', html)
        self.assertNotIn('Version unknown', html)

    def test_cves_of_one_product_are_one_item_listing_their_ids(self):
        cves = [self.product_cve(f'CVE-2099-61{i}', 'PHP') for i in range(3)]
        other = self.host('b.acme.test')  # a host is one row per scan
        for cve in cves:
            for sub in (self.www, other):
                self.hit(cve, sub, 'PHP')
        digest = self.digest()
        self.assertEqual(len(digest['threats']), 1)
        item = digest['threats'][0]
        self.assertEqual(item['title'], 'PHP: three critical flaws')
        self.assertEqual(sorted(item['cve_ids']), sorted(c.cve_id for c in cves))
        self.assertEqual(item['hosts_total'], 2)
        self.assertEqual(item['fixed_in'], ['9.9.9'])
        _, text, html = report_digest.render(digest, None, 'a@example.org', 'https://x/u/')
        self.assertIn('PHP: three critical flaws', html)
        for cve in cves:
            self.assertIn(cve.cve_id, text)
        self.assertIn('Fixed in 9.9.9', text)

    def test_at_most_five_items_then_plus_n_more(self):
        for i in range(7):
            cve = self.product_cve(f'CVE-2099-62{i}', f'Product{i}', cvss=9.0 + i / 10)
            self.hit(cve, self.www, f'Product{i}')
        digest = self.digest()
        self.assertEqual((len(digest['threats']), digest['threats_more']), (5, 2))
        _, text, html = report_digest.render(digest, None, 'a@example.org', 'https://x/u/')
        self.assertIn('plus 2 more in cvENGINE', html)
        self.assertIn('plus 2 more in cvENGINE: https://cve.example.org/cve/?project=acme-web', text)
        self.assertEqual(html.count('class="threat box"'), 5)
        self.assertIn('2 important vulnerabilities'.replace('2', '7'), report_digest._preheader(digest))

    def test_each_item_names_up_to_five_hosts_with_their_project_then_plus_n_more_hosts(self):
        cve = self.product_cve('CVE-2099-6301', 'nginx')
        self.hit(cve, self.www, 'nginx')  # a host with an address (its key names the address set)
        for i in range(1, 8):
            self.hit(cve, self.host(f'h{i}.acme.test'), 'nginx')  # and hosts with none (their key is their name)
        self.unversioned_nginx_host()  # runs nginx, no version read: said as a note, since the item has hosts
        item = self.digest()['threats'][0]
        self.assertEqual((len(item['hosts']), item['hosts_more'], item['hosts_total'], item['unknown']), (5, 3, 8, 1))
        self.assertTrue(all(h['project'] == 'Acme Web' for h in item['hosts']))
        _, text, html = report_digest.render(self.digest(), None, 'a@example.org', 'https://x/u/')
        self.assertIn('+3 more hosts', html)
        self.assertIn('Version unknown on 1 more host.', html)
        self.assertRegex(html, r'h1\.acme\.test &middot; <span[^>]*>Acme Web</span>')
        self.assertIn('    h1.acme.test - Acme Web\n', text)
        self.assertIn('+3 more hosts', text)

    def test_an_organization_report_names_each_hosts_own_project(self):
        cve = self.product_cve('CVE-2099-6401', 'tomcat')
        self.hit(cve, self.www, 'tomcat')
        self.hit(cve, self.api_host, 'tomcat')
        item = self.digest(org=True)['threats'][0]
        self.assertEqual({(h['host'], h['project']) for h in item['hosts']}, {('www.acme.test', 'Acme Web'), ('api.acme.test', 'Acme API')})

    def test_another_organizations_hosts_are_never_listed(self):
        cve = self.product_cve('CVE-2099-6501', 'tomcat')
        self.hit(cve, self.www, 'tomcat')
        self.hit(cve, self.twin, 'tomcat')  # the same name, in Other Org
        for digest in (self.digest(), self.digest(org=True)):
            item = digest['threats'][0]
            self.assertEqual((item['hosts_total'], [h['project'] for h in item['hosts']]), (1, ['Acme Web']))
        _, text, html = report_digest.render(self.digest(org=True), None, 'a@example.org', 'https://x/u/')
        self.assertNotIn('Other Co', html + text)
        keys = dict(counts.with_host_key(Subdomain.objects.filter(pk__in=[self.www.pk, self.twin.pk])).values_list('pk', 'host_key'))
        labels = report_threats.host_labels(self.scope().ids, set(keys.values()))
        self.assertEqual(list(labels), [keys[self.www.pk]])  # the other organization's key is not labelled, whatever it says

    def test_the_overview_cards_keep_their_own_fold(self):
        self.product_cve('CVE-2099-6601', 'Ghostware')
        threats = overview._threats(list(self.scope().ids), 'Acme Web', {self.web.pk: 'Acme Web'}, NOW)
        self.assertEqual(threats['groups'], [])
        self.assertEqual(len(threats['folded']), 1)  # the Overview still folds "N more checked"; only the email drops them
        entry = {'source': 'cve', 'title': 't', 'summary': '', 'badges': [], 'cve_ids': ['CVE-1'], 'fixed_in': [], 'product': 'x', 'matched': 1, 'confirmed': 0, 'product_only': 0,
                 'cvss': 9.8, '_hosts': {'matched': {'1:n:a'}, 'confirmed': set(), 'product_only': set()}}
        groups, folded = overview.threat_groups([entry], {1: 'P'}, False)
        self.assertEqual((groups[0]['hosts'], folded), ([], []))  # no host list unless the caller asked for one


class TopFindingTests(Base):
    TITLE = 'Dangling NS Records (NS records without SOA) with known impact'

    def dangling(self, count, project='acme-web', start=0):
        for i in range(count):
            Vulnerability.objects.create(subdomain=self.host(f'ns{start + i}.{project}.test', project), target_domain=self.domains[project], scan_history=self.scans[project],
                                         name=self.TITLE, severity=4, source='nuclei', http_url='https://x.test/', discovered_date=NOW)

    def test_findings_of_one_title_in_a_project_are_one_row_with_their_hosts(self):
        self.quiet()
        self.dangling(7)
        rows = self.digest()['top_findings']
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual((row['title'], row['count'], len(row['hosts']), row['more']), ('Dangling NS Records (NS records without SOA)', 7, 5, 2))
        self.assertEqual(row['hosts'], sorted(row['hosts']))
        _, text, html = report_digest.render(self.digest(), None, 'a@example.org', 'https://x/u/')
        self.assertIn('Dangling NS Records (NS records without SOA)', html)
        self.assertIn(': 7 hosts</span>', html)
        self.assertIn(', +2 more', html)
        self.assertIn('Dangling NS Records (NS records without SOA): 7 hosts\n  ns0.acme-web.test, ns1.acme-web.test', text)
        self.assertNotIn('with known impact', html)

    def test_an_organization_report_groups_by_project_hottest_then_largest_first(self):
        self.quiet()
        self.dangling(2, 'acme-web')
        self.dangling(4, 'acme-api')
        rows = self.digest(org=True)['top_findings']
        self.assertEqual([(r['project'], r['count']) for r in rows], [('Acme API', 4), ('Acme Web', 2)])
        _, _, html = report_digest.render(self.digest(org=True), None, 'a@example.org', 'https://x/u/')
        self.assertIn(': 4 hosts in Acme API</span>', html)

    def test_a_single_finding_keeps_its_host_age_and_status_and_the_list_is_capped(self):
        self.quiet()
        for i in range(8):
            Vulnerability.objects.create(subdomain=self.host(f'solo{i}.acme.test'), target_domain=self.domains['acme-web'], scan_history=self.scans['acme-web'],
                                         name=f'Distinct finding {i}', severity=4, source='nuclei', http_url='https://x.test/', discovered_date=NOW)
        rows = self.digest()['top_findings']
        self.assertEqual(len(rows), report_digest.TOP_FINDINGS)
        self.assertTrue(all(r['count'] == 1 and r['host'].startswith('solo') and r['status'] for r in rows))

    def test_another_organizations_findings_are_never_grouped_in(self):
        self.dangling(2, 'acme-web')
        self.dangling(3, 'other-co')
        digest = self.digest(org=True)
        self.assertTrue(all(r['project'] != 'Other Co' for r in digest['top_findings']))
        self.assertEqual(sum(r['count'] for r in digest['top_findings'] if r['title'].startswith('Dangling')), 2)
