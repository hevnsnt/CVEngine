"""The Overview's summary (cveFeed.overview): the sentences are templates filled from counts, the tiles read the daily snapshots, the threats of the week are
grouped by product, Fix first folds hosts that share a fix, and the summary is shared per set of project ids and never across them."""
import json
from datetime import date, datetime, timedelta, timezone as dt_timezone
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import overview, situations
from cveFeed.models import AssetChange, CVEEntry, CVEMatch, HygieneFinding, StatsSnapshot, TlsCertificate, Triage
from dashboard.models import Org, Project, ProjectMembership
from tests.steady import steady_caches
from tests.test_situations import Fixture

NOW = datetime(2026, 11, 21, 15, 54, tzinfo=dt_timezone.utc)
NONE = {'proven': 0, 'likely': 0, 'hygiene': 0, 'exposure': 0, 'minor': 0, 'needs': 0}


def counts(**kw):
    c = {**NONE, **kw}
    c['needs'] = c['proven'] + c['likely'] + c['hygiene']
    return c


def group(**kw):
    return {'product': 'PHP', 'items': 4, 'matched': 3, 'all_kev': False, 'all_critical': True, **kw}


def tile(**kw):
    return {'key': 'exposed', 'value': 55, 'delta': 29, 'since': '2026-11-14', 'as_of': '2026-11-21', **kw}


class WordTests(SimpleTestCase):
    def test_small_numbers_are_spelled_at_the_start_of_a_sentence_only_up_to_ten(self):
        self.assertEqual([overview.word(n, True) for n in (1, 4, 10, 11)], ['One', 'Four', 'Ten', '11'])
        self.assertEqual(overview.word(1345), '1,345')

    def test_a_week_back_is_last_weekday_and_anything_else_is_a_date(self):
        self.assertEqual(overview.since_words(date(2026, 11, 14), date(2026, 11, 21)), 'last Saturday')
        self.assertEqual(overview.since_words(date(2026, 11, 15), date(2026, 11, 21)), 'Nov 15')


class StatusTests(SimpleTestCase):
    def status(self, c, hosts=100, last=NOW - timedelta(hours=2), **kw):
        return overview.status_block(hosts, c, last, NOW, **kw)

    def test_proven_and_likely(self):
        s = self.status(counts(proven=1, likely=26))
        self.assertEqual(s['headline'], '1 host has a confirmed vulnerability, and 26 more have likely ones to review.')
        self.assertEqual((s['tone'], s['pill']), ('fire', 'Needs you now'))

    def test_plural_and_singular(self):
        self.assertEqual(self.status(counts(proven=3, likely=1))['headline'], '3 hosts have a confirmed vulnerability, and 1 more has a likely one to review.')
        self.assertEqual(self.status(counts(proven=2))['headline'], '2 hosts have a confirmed vulnerability.')
        self.assertEqual(self.status(counts(proven=1))['headline'], '1 host has a confirmed vulnerability.')

    def test_nothing_proven_leads_with_the_likely_ones(self):
        self.assertEqual(self.status(counts(likely=26))['headline'], '26 hosts have likely vulnerabilities to review, none confirmed yet.')
        self.assertEqual(self.status(counts(likely=1))['headline'], '1 host has a likely vulnerability to review, not confirmed yet.')

    def test_high_hygiene_alone_needs_you(self):
        s = self.status(counts(hygiene=5))
        self.assertEqual(s['headline'], '5 hosts have a high-priority hygiene problem, such as an expired certificate.')
        self.assertEqual(s['pill'], 'Needs you now')
        self.assertIn('2 hosts have a high-priority hygiene problem as well.', self.status(counts(proven=1, hygiene=2))['sub'])

    def test_nothing_needs_you(self):
        s = self.status(counts())
        self.assertEqual((s['headline'], s['pill'], s['tone'], s['state'], s['sub']), ('Nothing needs you right now.', 'All clear', 'ok', 'clear', ''))

    def test_only_exposure_or_minor_is_a_watch_not_a_clear(self):
        s = self.status(counts(exposure=2))
        self.assertEqual((s['headline'], s['pill']), ('Nothing needs you right now.', 'Watch'))
        self.assertIn('2 hosts have a service open that should not be', s['sub'])
        self.assertIn('1 host has lower-priority items only.', self.status(counts(minor=1))['sub'])

    def test_nothing_scanned_recently_is_said(self):
        old = NOW - timedelta(days=10)
        s = self.status(counts(), last=old)
        self.assertEqual(s['headline'], 'Nothing needs you right now, but nothing was scanned in the last 7 days.')
        self.assertEqual((s['pill'], s['sub']), ('Watch', 'The last scan finished Nov 11.'))
        s = self.status(counts(proven=1), last=old)
        self.assertEqual(s['pill'], 'Needs you now')  # what needs you still leads
        self.assertTrue(s['sub'].startswith('The last scan finished Nov 11, so this may be out of date.'))
        self.assertIn('No scan of these hosts has finished yet', self.status(counts(), last=None)['sub'])

    def test_a_new_install_has_no_hosts(self):
        s = self.status(counts(), hosts=0, last=None)
        self.assertEqual((s['headline'], s['pill'], s['state']), ('Nothing has been scanned yet.', 'Not scanned yet', 'new'))

    def test_the_threat_and_exposure_clauses_follow_and_drop_when_empty(self):
        s = self.status(counts(proven=1, likely=26), threat_group=group(), exposed_tile=tile(value=55, delta=29))
        self.assertEqual(s['sub'], 'Four new critical PHP flaws this week match 3 of your hosts by version. Internet-exposed hosts went from 26 to 55 since last Saturday.')
        quiet = self.status(counts(proven=1), threat_group=None, exposed_tile=tile(delta=0))
        self.assertEqual(quiet['sub'], '')
        self.assertEqual(self.status(counts(proven=1), threat_group=group(matched=0))['sub'], '')  # no host matches: the clause goes

    def test_every_headline_is_one_sentence_without_dashes(self):
        variants = [counts(proven=1, likely=26), counts(proven=2), counts(likely=3), counts(hygiene=4), counts(), counts(exposure=1), counts(minor=1)]
        for c in variants:
            for last in (NOW - timedelta(hours=1), NOW - timedelta(days=9), None):
                s = self.status(c, last=last)
                for text in (s['headline'], *[t for t in s['sub'].split('. ') if t]):
                    self.assertNotRegex(text, '[\u2013\u2014]|--', text)
                self.assertRegex(s['headline'], r'^[^.?!]+\.$', s['headline'])

    def test_threat_sentence_variants(self):
        self.assertEqual(overview.threat_sentence(group(items=1, matched=1)), 'One new critical PHP flaw this week matches 1 of your hosts by version.')
        self.assertEqual(overview.threat_sentence(group(all_critical=False, all_kev=True)), 'Four new known-exploited PHP flaws this week match 3 of your hosts by version.')
        self.assertEqual(overview.threat_sentence(group(all_critical=False)), 'Four new PHP flaws this week match 3 of your hosts by version.')
        self.assertEqual(overview.threat_sentence(group(product='', all_critical=False, items=2)), 'Two new threats this week reach 3 of your hosts by version.')
        self.assertEqual(overview.threat_sentence(None), '')

    def test_exposure_sentence_says_a_date_when_the_baseline_is_not_a_week_back(self):
        self.assertEqual(overview.exposure_sentence(tile(since='2026-11-18', delta=-3, value=10)), 'Internet-exposed hosts went from 13 to 10 since Nov 18.')
        self.assertEqual(overview.exposure_sentence(tile(delta=None, since=None)), '')


class SentinelLineTests(SimpleTestCase):
    def test_the_line(self):
        self.assertEqual(overview.sentinel_line_text(2, 4, 4), '2 Sentinels live, all 4 scan slots busy')
        self.assertEqual(overview.sentinel_line_text(1, 4, 0), '1 Sentinel live, all 4 scan slots free')
        self.assertEqual(overview.sentinel_line_text(1, 4, 1), '1 Sentinel live, 1 of 4 scan slots busy')
        self.assertEqual(overview.sentinel_line_text(1, 1, 1), '1 Sentinel live, its scan slot is busy')
        self.assertEqual(overview.sentinel_line_text(0, 0, 0), 'No Sentinel is live')


def row(host, action, project='a', lead='likely', rank=1, **kw):
    return {'rank': rank, 'host': host, 'project': project, 'project_name': project.upper(), 'first_action': action, 'lead': lead, 'internal': False,
            'host_link': f'/cve/{project}/hosts/?host={host}', 'headline': '', 'counts': {'proven': 0, 'likely': 1, 'hygiene': 0, 'exposure': 0, 'minor': 0},
            'findings': [{'title': 'CVE-2026-1', 'known_exploited': True}], **kw}


class FixFirstTests(SimpleTestCase):
    def test_hosts_of_one_project_with_one_first_action_are_one_row(self):
        action = 'Update OpenSSH (fixes CVE-2026-123158)'
        rows = [row('vpn.x.org', action, rank=1), row('other.y.org', 'Update Sudo (fixes CVE-2025-32463)', project='b', rank=2), row('mail.x.org', action, rank=3),
                row('test.x.org', action, rank=4), row('same.z.org', action, project='b', rank=5)]
        got = overview.fix_first_groups(rows)
        self.assertEqual([(g['rank'], g['n']) for g in got], [(1, 3), (2, 1), (5, 1)])  # the project is part of the key
        first = got[0]
        self.assertEqual((first['title'], first['action'], first['hosts']), ('3 A hosts', 'Update OpenSSH', ['vpn.x.org', 'mail.x.org', 'test.x.org']))
        self.assertEqual(first['reason'], 'vpn.x.org, mail.x.org and test.x.org all need the same fix: Update OpenSSH (fixes CVE-2026-123158). The same update fixes all three.')
        self.assertEqual(first['link'], '/cve/a/situations/')
        self.assertEqual(got[1]['link'], '/cve/b/hosts/?host=other.y.org')

    def test_many_hosts_are_listed_by_three_and_counted(self):
        rows = [row(f'h{i}.x.org', 'Renew the certificate', lead='hygiene', rank=i) for i in range(1, 6)]
        (g,) = overview.fix_first_groups(rows)
        self.assertEqual((g['n'], g['action'], g['chip']), (5, 'Renew the certificates', 'Hygiene · high'))
        self.assertEqual(g['reason'], 'h1.x.org, h2.x.org, h3.x.org and 2 more all need the same fix: Renew the certificate. The same step applies to all five.')

    def test_at_most_the_limit_of_rows_but_a_late_host_still_joins_an_early_row(self):
        rows = [row(f'a{i}.x.org', f'Update P{i}', rank=i) for i in range(1, 12)] + [row('late.x.org', 'Update P1', rank=12)]
        got = overview.fix_first_groups(rows, limit=8)
        self.assertEqual(len(got), 8)
        self.assertEqual(got[0]['n'], 2)

    def test_the_generic_action_is_never_a_group(self):
        rows = [row('a.x.org', 'Look at the open findings'), row('b.x.org', 'Look at the open findings', rank=2)]
        self.assertEqual([g['n'] for g in overview.fix_first_groups(rows)], [1, 1])

    def test_one_line_reasons(self):
        base = {'proven': 1, 'likely': 0, 'hygiene': 0, 'exposure': 0, 'minor': 0}
        proven = row('p', 'Update Apache HTTP Server', lead='proven', counts={**base, 'proven': 3, 'likely': 18}, findings=[{'title': 'CVE-2023-25690', 'known_exploited': False}])
        self.assertEqual(overview.row_reason(proven), 'A check reproduced CVE-2023-25690 and 2 more. Internet-facing. 18 more findings look real.')
        likely = row('l', 'Update Sudo', counts={**base, 'proven': 0, 'likely': 13})
        self.assertEqual(overview.row_reason(likely), '13 findings look real, starting with CVE-2026-1 (known exploited).')
        one = row('l', 'Update Sudo', counts={**base, 'proven': 0, 'likely': 1})
        self.assertEqual(overview.row_reason(one), 'CVE-2026-1 (known exploited). Internet-facing.')
        cert = row('c', 'Renew the certificate', lead='hygiene', counts={**base, 'proven': 0, 'hygiene': 1}, findings=[{'title': 'Certificate for c:443 expired 39 days ago'}])
        self.assertEqual(overview.row_reason(cert), 'Certificate for c:443 expired 39 days ago. Browsers show a warning once it has expired.')

    def test_the_button_says_the_action_without_its_cve(self):
        self.assertEqual(overview.action_label('Update nginx (fixes CVE-2099-1)'), 'Update nginx')
        self.assertEqual(overview.action_label('Renew the certificate'), 'Renew the certificate')


def entry(cve, product='PHP', matched=(), unknown=(), cvss=9.2, source='kev', kev_added='2026-11-20', title=None, summary='A first sentence. A second one.', **kw):
    return {'source': source, 'title': f'{cve}: {title or "a flaw"}', 'summary': summary, 'link': '', 'badges': [f'CISA KEV, added Nov 20', f'CVSS {cvss:g}', 'High exploitation probability (EPSS)'],
            'cve_ids': [cve], 'fixed_in': ['8.2.36', '8.3.37'], 'matched': len(matched), 'confirmed': 0, 'product_only': len(unknown), 'product': product, 'cvss': cvss,
            'kev_added': kev_added, 'remote_no_login': True, '_hosts': {'matched': set(matched), 'confirmed': set(), 'product_only': set(unknown)}, **kw}


class ThreatGroupTests(SimpleTestCase):
    names = {1: 'Marino', 2: 'Trifident'}

    def test_cves_of_one_product_are_one_card_and_hosts_are_counted_once(self):
        entries = [entry('CVE-2026-1', matched={'1:i:1', '1:i:2', '1:i:3'}, unknown={'1:n:a', '2:n:b'}), entry('CVE-2026-2', matched={'1:i:1', '1:i:2'}, unknown={'2:n:b', '2:n:c'}, cvss=8.0),
                   entry('CVE-2026-3', matched={'1:i:3'}), entry('CVE-2026-4', matched=set(), unknown={'1:n:a'}, summary='Only one sentence.')]
        groups, folded = overview.threat_groups(entries, self.names, True)
        self.assertEqual(folded, [])
        (g,) = groups
        self.assertEqual((g['items'], g['matched'], g['product_only']), (4, 3, 3))  # 3 hosts match; a, b and c run PHP, version unknown
        self.assertEqual(g['cve_ids'], ['CVE-2026-1', 'CVE-2026-2', 'CVE-2026-3', 'CVE-2026-4'])
        self.assertEqual(g['badges'][0], {'text': '4 CVEs · CVSS 9.2', 'kind': 'count'})
        self.assertIn({'text': 'Remote, no login', 'kind': 'remote'}, g['badges'])
        self.assertEqual(sum(1 for b in g['badges'] if 'EPSS' in b['text']), 1)  # a badge two items share shows once
        self.assertEqual(g['fix'], 'update PHP to 8.2.36 or 8.3.37.')
        self.assertEqual(g['by_project']['matched'], [{'project': 'Marino', 'n': 3}])
        self.assertEqual(g['by_project']['product_only'], [{'project': 'Trifident', 'n': 2}, {'project': 'Marino', 'n': 1}])
        self.assertEqual(g['summary'], 'A first sentence. Only one sentence.')  # the first sentence of each item, once
        self.assertEqual(g['title'], 'PHP: four flaws, worst CVSS 9.2, 4 known exploited')
        self.assertEqual(g['hosts_query'], 'tech:"PHP"')

    def test_a_card_says_critical_only_when_every_item_is_and_remote_only_when_every_item_is(self):
        e = [entry('CVE-2026-1', matched={'1:i:1'}), entry('CVE-2026-2', matched={'1:i:1'}, remote_no_login=False)]
        (g,) = overview.threat_groups(e, self.names, False)[0]
        self.assertEqual(g['title'], 'PHP: two critical flaws')
        self.assertNotIn('Remote, no login', [b['text'] for b in g['badges']])
        self.assertIsNone(g['by_project'])  # one project: no breakdown

    def test_a_single_cve_card_uses_its_own_title_and_its_own_link_filter(self):
        (g,) = overview.threat_groups([entry('CVE-2026-9', title='auth bypass', matched={'1:i:1'}, summary='It lets anyone in.')], self.names, False)[0]
        self.assertEqual((g['title'], g['summary'], g['hosts_query']), ('PHP: auth bypass', 'It lets anyone in.', 'cve:CVE-2026-9'))

    def test_groups_that_reach_no_host_are_folded_one_line_per_entry(self):
        entries = [entry('CVE-2026-1', product='VMware vCenter', title='auth bypass'), entry('CVE-2026-2', product='Apache Roller', title='code execution', kev_added='2026-11-18'),
                   entry('CVE-2026-3', matched={'1:i:1'}), entry('CVE-2026-4', product='Other', source='critical', kev_added=None, cvss=9.8, title='x' * 100)]
        groups, folded = overview.threat_groups(entries, self.names, False)
        self.assertEqual([g['product'] for g in groups], ['PHP'])
        self.assertEqual([(f['product'], f['title'], f['detail']) for f in folded][:2],
                         [('VMware vCenter', 'auth bypass', 'KEV Nov 20 · 0 hosts'), ('Apache Roller', 'code execution', 'KEV Nov 18 · 0 hosts')])
        self.assertEqual(folded[2]['detail'], 'CVSS 9.8 · 0 hosts')
        self.assertTrue(folded[2]['title'].endswith('…') and len(folded[2]['title']) <= overview.FOLDED_TITLE + 1)

    def test_a_group_with_hosts_that_only_run_the_product_stays_a_card(self):
        groups, folded = overview.threat_groups([entry('CVE-2026-1', unknown={'1:n:a'})], self.names, False)
        self.assertEqual((len(groups), folded), (1, []))

    def test_third_party_text_is_data_it_is_cut_not_trusted(self):
        (g,) = overview.threat_groups([entry('CVE-2026-1', matched={'1:i:1'}, summary='<img src=x onerror=alert(1)>' + 'a' * 900)], self.names, False)[0]
        self.assertLessEqual(len(g['summary']), 600)  # the page draws it with textContent; here it is only bounded


class TileTests(TestCase):
    """The tiles read the daily snapshots, summed over the projects of the scope."""

    @classmethod
    def setUpTestData(cls):
        org = Org.objects.create(name='O', slug='o')
        cls.a = Project.objects.create(name='A', slug='oa', insert_date=NOW, org=org)
        cls.b = Project.objects.create(name='B', slug='ob', insert_date=NOW, org=org)
        today = date(2026, 11, 21)
        for i in range(15):  # 14 days ago to today
            d = today - timedelta(days=14 - i)
            for p, k in ((cls.a, 1), (cls.b, 2)):
                StatsSnapshot.objects.create(project=p, date=d, hosts=100 * k, exposed_hosts=i * k, open_findings={'critical': 10 * k + i, 'high': 5 * k}, cve_matches={'fire': k, 'smoke': i * k},
                                             fixed=k * 2, mean_days_to_fix=1.0 * k + (0.1 * i if k == 2 else 0))

    def tiles(self, ids=None, **kw):
        return {t['key']: t for t in overview.kpis(ids or [self.a.pk, self.b.pk], now=NOW, **kw)}

    def test_values_deltas_and_series(self):
        t = self.tiles()
        self.assertEqual(t['exposed']['value'], 14 * 3)  # 14*1 + 14*2 on the 21st
        self.assertEqual(t['exposed']['delta'], (14 - 7) * 3)
        self.assertEqual(t['exposed']['delta_text'], '▲ 21')
        self.assertEqual(t['exposed']['tone'], 'worse')
        self.assertEqual(t['exposed']['foot'], 'since last Saturday · of 300 hosts')
        self.assertEqual(len(t['exposed']['series']), 14)
        self.assertEqual(t['exposed']['series'][-1], 42)
        self.assertEqual(t['needs']['value'], 3 + 14 * 3)
        self.assertEqual(t['needs']['foot'], 'since last Saturday · 3 Fire, 42 Smoke')
        self.assertEqual(t['critical']['value'], (10 + 14) + (20 + 14))
        self.assertEqual(t['critical']['foot'], 'since last Saturday · 15 high')

    def test_mean_time_to_fix_is_weighted_by_what_was_fixed_and_a_higher_one_is_slower(self):
        t = self.tiles()['mttf']
        # day 14: project A 1.0 x 2 fixed, project B 2.0 + 1.4 = 3.4 x 4 fixed -> (2 + 13.6) / 6
        self.assertEqual(t['value'], round((1.0 * 2 + 3.4 * 4) / 6, 2))
        self.assertEqual(t['tone'], 'worse')
        self.assertTrue(t['foot'].startswith('slower than Nov 14'), t['foot'])
        self.assertEqual(t['unit'], 'days')

    def test_better_flat_and_missing(self):
        StatsSnapshot.objects.filter(project=self.a, date=date(2026, 11, 14)).update(exposed_hosts=100)
        StatsSnapshot.objects.filter(project=self.b, date=date(2026, 11, 14)).update(exposed_hosts=0)
        t = self.tiles()['exposed']
        self.assertEqual((t['delta'], t['tone'], t['delta_text']), (42 - 100, 'better', '▼ 58'))
        StatsSnapshot.objects.filter(project=self.a, date=date(2026, 11, 14)).update(exposed_hosts=42, hosts=100)
        StatsSnapshot.objects.filter(project=self.b, date=date(2026, 11, 14)).update(exposed_hosts=0)
        StatsSnapshot.objects.filter(project=self.a, date=date(2026, 11, 14)).update(exposed_hosts=42)
        self.assertEqual((self.tiles()['exposed']['tone'], self.tiles()['exposed']['delta_text']), ('flat', 'no change'))
        empty = {t['key']: t for t in overview.kpis([], now=NOW)}
        self.assertEqual((empty['exposed']['value_text'], empty['exposed']['delta'], empty['exposed']['series']), ('–', None, []))
        self.assertEqual(empty['mttf']['foot'], 'nothing marked fixed yet')

    def test_only_the_projects_asked_for_are_summed(self):
        self.assertEqual(self.tiles([self.a.pk])['exposed']['value'], 14)

    def test_the_live_count_is_today_and_beats_a_snapshot(self):
        t = self.tiles(live={'hosts': 321, 'exposed_hosts': 99})['exposed']
        self.assertEqual((t['value'], t['delta'], t['foot']), (99, 99 - 21, 'since last Saturday · of 321 hosts'))
        self.assertEqual(t['series'][-1], 99)
        self.assertEqual(self.tiles(live={'hosts': 321, 'exposed_hosts': 99})['needs']['value'], 45)  # the others stay the snapshot's

    def test_a_young_install_compares_with_its_first_day(self):
        StatsSnapshot.objects.filter(date__lt=date(2026, 11, 19)).delete()
        t = self.tiles()['exposed']
        self.assertEqual(t['since'], '2026-11-19')
        self.assertTrue(t['foot'].startswith('since Nov 19'), t['foot'])


class SummaryTests(Fixture):
    """The whole summary over real rows: threats, Fix first, What changed, the status, and who may read which entry."""

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.now = timezone.now()
        cls.php = CVEEntry.objects.create(cve_id='CVE-2099-50', title='PHP session flaw', cvss=9.8, kev=True, exploit_db=True, epss_reached=True, published_at=cls.now - timedelta(days=2),
                                          cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', summary='Session handling lets an attacker inject objects. More text.',
                                          intel={'kev': {'cisa_kev': {'added': (cls.now - timedelta(days=1)).date().isoformat(), 'product': 'PHP', 'name': 'PHP flaw'}}},
                                          affected=[{'product': 'PHP', 'ranges': [{'fixed': '8.2.36'}]}])
        cls.php2 = CVEEntry.objects.create(cve_id='CVE-2099-51', title='PHP upload flaw', cvss=9.1, kev=True, published_at=cls.now - timedelta(days=2),
                                           intel={'kev': {'cisa_kev': {'added': (cls.now - timedelta(days=1)).date().isoformat(), 'product': 'PHP', 'name': 'PHP flaw 2'}}},
                                           affected=[{'product': 'PHP', 'ranges': [{'fixed': '8.3.37'}]}])
        cls.unmatched = CVEEntry.objects.create(cve_id='CVE-2099-52', title='Roller code execution', cvss=9.0, kev=True, published_at=cls.now - timedelta(days=2),
                                                intel={'kev': {'cisa_kev': {'added': (cls.now - timedelta(days=1)).date().isoformat(), 'product': 'Apache Roller', 'name': 'Roller'}}})
        cls.h1 = cls.host('one.sa.test', http=200)
        cls.h2 = cls.host('two.sa.test', http=200)
        for h in (cls.h1, cls.h2):
            for cve in (cls.php, cls.php2):
                cls.match(h, cve)
            cls.m = None
        cls.proven = cls.host('proven.sa.test')
        cls.match(cls.proven, cls.kev, validation='hit', steps=cls.hit())
        cls.cert_host = cls.host('cert.sa.test')
        HygieneFinding.objects.create(domain=cls.da, host='cert.sa.test', check_name='tls_expired', severity=4, title='Certificate for cert.sa.test:443 expired 5 days ago')
        TlsCertificate.objects.create(domain=cls.da, host='soon.sa.test', port=443, not_after=cls.now + timedelta(days=3))
        TlsCertificate.objects.create(domain=cls.da, host='cert.sa.test', port=443, not_after=cls.now - timedelta(days=5))
        TlsCertificate.objects.create(domain=cls.da, host='fine.sa.test', port=443, not_after=cls.now + timedelta(days=300))
        AssetChange.objects.create(project=cls.pa, domain=cls.da, host='new.sa.test', kind='host_new', detected_at=cls.now - timedelta(days=1))
        AssetChange.objects.create(project=cls.pa, domain=cls.da, host='new.sa.test', kind='host_new', detected_at=cls.now - timedelta(days=2))  # one host, found twice
        AssetChange.objects.create(project=cls.pa, domain=cls.da, host='old.sa.test', kind='host_retired', detected_at=cls.now - timedelta(days=3))
        AssetChange.objects.create(project=cls.pa, domain=cls.da, host='ancient.sa.test', kind='host_new', detected_at=cls.now - timedelta(days=30))
        AssetChange.objects.create(project=cls.pa, domain=cls.da, host='pii.sa.test', kind='sensitive_found', detected_at=cls.now - timedelta(days=1),
                                   after={'url': 'https://pii.sa.test/a', 'types': ['email', 'phone_number'], 'counts': {'email': 3}})
        AssetChange.objects.create(project=cls.pb, domain=cls.db, host='other.sb.test', kind='sensitive_found', detected_at=cls.now - timedelta(days=1), after={'types': ['card']})
        for d in range(15):
            StatsSnapshot.objects.create(project=cls.pa, date=timezone.localdate() - timedelta(days=14 - d), hosts=10, exposed_hosts=d, open_findings={'critical': 2, 'high': 3},
                                         cve_matches={'fire': 1, 'smoke': 2}, fixed=1, mean_days_to_fix=2.0)

    def setUp(self):
        cache.clear()

    def build(self, ids=None):
        return overview.build(ids or [self.pa.pk], live={'hosts': 7, 'exposed_hosts': 30}, now=self.now)

    def test_threats_are_grouped_and_counted_over_the_whole_group(self):
        data = self.build()
        (g,) = data['threats']['groups']
        self.assertEqual((g['product'], g['items'], g['matched']), ('PHP', 2, 2))
        self.assertEqual(g['cve_ids'], ['CVE-2099-50', 'CVE-2099-51'])
        self.assertEqual(g['fix'], 'update PHP to 8.2.36 or 8.3.37.')
        self.assertEqual(g['badges'][0]['text'], '2 CVEs · CVSS 9.8')
        self.assertEqual([f['product'] for f in data['threats']['folded']], ['Apache Roller'])
        self.assertEqual(data['threats']['folded_note'], 'all added to CISA KEV this week')
        self.assertEqual(data['threats']['empty'], '')
        self.assertIn('match 2 of your hosts by version.', data['status']['sub'])
        self.assertIn('Two new known-exploited PHP flaws this week match 2 of your hosts by version.', data['status']['sub'])
        self.assertNotIn('_hosts', json.dumps(data))
        json.dumps(data)  # the whole summary is plain JSON

    def test_no_threats_says_so(self):
        CVEEntry.objects.all().delete()
        data = self.build()
        self.assertEqual((data['threats']['groups'], data['threats']['folded']), ([], []))
        self.assertEqual(data['threats']['empty'], 'No new KEV or critical CVEs this week.')

    def test_fix_first_and_the_status_from_the_ranking(self):
        data = self.build()
        ff = data['fix_first']
        self.assertEqual(ff['state'], 'attention')
        # proven first, then the two PHP hosts that share a fix as one row, then the hygiene host
        self.assertEqual([(r['title'], r['n'], r['lead']) for r in ff['rows']][0], ('proven.sa.test', 1, 'proven'))
        folded = next(r for r in ff['rows'] if r['n'] == 2)
        self.assertEqual((folded['title'], folded['lead']), ('2 A hosts', 'likely'))
        self.assertTrue(folded['action'].startswith('Update nginx'))
        cert = next(r for r in ff['rows'] if r['title'] == 'cert.sa.test')
        self.assertEqual((cert['chip'], cert['action']), ('Hygiene · high', 'Renew the certificate'))
        self.assertLess([r['title'] for r in ff['rows']].index('2 A hosts'), [r['title'] for r in ff['rows']].index('cert.sa.test'))  # likely and known exploited, then the hygiene slip
        self.assertEqual(data['status']['headline'], '1 host has a confirmed vulnerability, and 2 more have likely ones to review.')
        self.assertEqual(data['status']['pill'], 'Needs you now')
        self.assertEqual(ff['total'], len(situations.ranked([self.pa.pk])[0]))

    def test_what_changed(self):
        lines = {l['key']: l for l in self.build()['what_changed']['lines']}
        self.assertEqual((lines['exposed']['value'], lines['exposed']['title']), ('+23', 'Hosts newly exposed'))
        self.assertRegex(lines['exposed']['detail'], r'^7 last \w+day, 30 now$')
        self.assertEqual((lines['sensitive']['value'], lines['sensitive']['detail']), ('1', 'email, phone number on pii.sa.test'))  # the other project's row is not counted
        self.assertEqual((lines['certs']['value'], lines['certs']['detail']), ('2', 'next: soon.sa.test in 3 days'))
        self.assertEqual((lines['hosts']['value'], lines['hosts']['detail']), ('1 / 1', 'new: new.sa.test'))  # found twice is one host; a month ago is not this week

    def test_everything_is_read_for_the_ids_it_was_given(self):
        data = self.build([self.pb.pk])
        self.assertEqual(data['threats']['groups'], [])
        self.assertEqual([l['value'] for l in data['what_changed']['lines'] if l['key'] == 'sensitive'], ['1'])
        self.assertNotIn('sa.test', json.dumps(data['fix_first']))

    def test_the_number_of_queries_does_not_grow_with_the_hosts(self):
        from django.db import connection
        from django.test.utils import CaptureQueriesContext

        def queries():
            cache.clear()
            with CaptureQueriesContext(connection) as ctx:
                self.build()
            return len(ctx)
        with steady_caches():  # the per-process settings caches expire on the clock: a measure counts the summary only
            self.assert_bounded(queries)

    def assert_bounded(self, queries):
        queries()  # the first read loads the saved settings, once
        small = queries()
        for i in range(30):
            h = self.host(f'bulk{i}.sa.test', http=200)
            self.match(h, self.exploit)
            HygieneFinding.objects.create(domain=self.da, host=h.name, check_name='tls_expired', severity=4, title=f'Certificate for bulk{i}.sa.test:443 expired 1 days ago')
        self.assertEqual(queries(), small)

    def test_an_empty_scope_costs_nothing_and_says_it_is_new(self):
        with self.assertNumQueries(0):
            data = overview.summary([])
        self.assertEqual(data['status']['state'], 'new')

    def test_one_build_serves_every_viewer_of_the_same_ids_and_never_another_set(self):
        with mock.patch.object(overview, 'build', side_effect=lambda ids, *a, **k: {'ids': list(ids)}) as build:
            a1 = overview.summary([self.pa.pk])
            a2 = overview.summary([self.pa.pk])
            both = overview.summary([self.pb.pk, self.pa.pk])
            both_again = overview.summary([self.pa.pk, self.pb.pk])  # the same set in another order
            b = overview.summary([self.pb.pk])
        self.assertEqual(build.call_count, 3)
        self.assertEqual((a1['ids'], a2['ids'], both['ids'], both_again['ids'], b['ids']), ([self.pa.pk], [self.pa.pk], sorted([self.pa.pk, self.pb.pk]), sorted([self.pa.pk, self.pb.pk]), [self.pb.pk]))

    def test_the_key_includes_who_may_see_what(self):
        """Two callers with different access to the same ids share nothing: ``scope_hash`` holds the caller's allowed projects as well as the ids."""
        from cveFeed import snapshot_cache
        from tenancy import scope
        keys = set()
        for allowed in ({self.pa.pk}, {self.pa.pk, self.pb.pk}, None):
            tokens = scope.set_scope(allowed, None) if allowed is not None else None
            try:
                keys.add(snapshot_cache.scope_hash('overview', [self.pa.pk]))
            finally:
                if tokens:
                    scope.reset_scope(tokens)
        self.assertEqual(len(keys), 3)

    def test_the_sentinel_line_is_for_an_app_admin_and_never_in_the_shared_entry(self):
        fake = {'live': 2, 'held_total': 4, 'agents': [{'slots': 2}, {'slots': 2}]}
        with mock.patch.object(overview, 'build', return_value={'status': {}}), mock.patch('agentapi.sentinel_broker.planner_capacity', return_value=fake):
            plain = overview.summary([self.pa.pk])
            admin = overview.summary([self.pa.pk], sentinels_too=True)
            again = overview.summary([self.pa.pk])
        self.assertIsNone(plain['sentinels'])
        self.assertEqual(admin['sentinels']['text'], '2 Sentinels live, all 4 scan slots busy')
        self.assertIsNone(again['sentinels'])  # the admin's line did not leak into the entry the others read


class EndpointTests(Fixture):
    """GET /cve/api/overview: the permission model of the stats endpoint (scoped to the caller, 404 for a project that is not theirs, the Sentinel line for an App Admin only)."""

    def setUp(self):
        cache.clear()

    def get(self, user, **params):
        from django.test import Client
        c = Client()
        c.force_login(user)
        return c.get('/cve/api/overview', params)

    def test_a_member_reads_their_project_and_not_another(self):
        r = self.get(self.user, project='sa')
        self.assertEqual(r.status_code, 200, r.content)
        data = r.json()
        self.assertEqual(set(data), {'status', 'kpis', 'threats', 'fix_first', 'what_changed', 'updated_at', 'projects', 'sentinels'})
        self.assertIsNone(data['sentinels'])
        self.assertEqual(self.get(self.user, project='sb').status_code, 404)
        self.assertEqual(self.get(self.other, project='sa').status_code, 404)

    def test_all_projects_is_only_what_the_caller_may_see(self):
        self.match(self.host('seen.sa.test'), self.kev)
        self.match(self.host('hidden.sb.test', domain=self.db), self.kev)
        text = json.dumps(self.get(self.user, project='_all').json()['fix_first'])
        self.assertIn('seen.sa.test', text)
        self.assertNotIn('hidden.sb.test', text)
        other = json.dumps(self.get(self.other).json()['fix_first'])
        self.assertIn('hidden.sb.test', other)
        self.assertNotIn('seen.sa.test', other)

    def test_a_second_poll_with_the_etag_is_a_304(self):
        from django.test import Client
        c = Client()
        c.force_login(self.user)
        first = c.get('/cve/api/overview', {'project': 'sa'})
        again = c.get('/cve/api/overview', {'project': 'sa'}, HTTP_IF_NONE_MATCH=first['ETag'])
        self.assertEqual(again.status_code, 304)

    def test_sign_in_is_required(self):
        from django.test import Client
        self.assertIn(Client().get('/cve/api/overview').status_code, (302, 401, 403))

    def test_only_an_app_admin_gets_the_sentinel_line(self):
        admin = User.objects.create_superuser('ov-admin', 'a@example.com', 'x')
        fake = {'live': 1, 'held_total': 0, 'agents': [{'slots': 3}]}
        with mock.patch('agentapi.sentinel_broker.planner_capacity', return_value=fake):
            self.assertEqual(self.get(admin, project='sa').json()['sentinels']['text'], '1 Sentinel live, all 3 scan slots free')
            self.assertIsNone(self.get(self.user, project='sa').json()['sentinels'])

    def test_the_page_links_the_weekly_email_with_the_scope(self):
        from cveFeed.views import _email_report_href
        self.assertEqual(_email_report_href('sa', {}), '/cve/reports/?project=sa#email')
        self.assertEqual(_email_report_href('_all', {'scope_org': 's'}), '/cve/reports/?org=s#email')
        self.assertEqual(_email_report_href('_all', {}), '/cve/reports/#email')
