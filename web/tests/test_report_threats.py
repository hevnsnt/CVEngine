"""This period's most important vulnerabilities: the Zero Wire feed (parsed from a trimmed copy of the real one, never storing its HTML, refusing foreign links), the
KEV and critical CVE candidates, the impact counts in distinct machines, the ranking and wording, the email section, the REST route and the MCP tool."""
import os
from datetime import timedelta, timezone as dt_timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.core import mail
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import report_scope
from agentapi.auth import create_token
from agentapi.services import Ctx
from cveFeed import mailer, report_digest, report_digests, report_threats, zero_wire
from cveFeed.models import CVEEntry, CVEMatch, ReportingSettings, ReportSubscription, ZeroWireBriefing
from startScan.models import IpAddress, Subdomain, Technology
from tests.test_agentapi import call, tool_call
from tests.test_report_subscriptions import SubBase, configure
from tests.test_reporting import ReportingBase

FIXTURE = Path(__file__).parent / 'fixtures' / 'zero-wire-feed.xml'
NOW = timezone.now()
START, END = NOW - timedelta(days=7), NOW


def feed():
    return FIXTURE.read_bytes()


class FakeResponse:
    def __init__(self, body, status=200):
        self.body, self.status_code = body, status

    def iter_content(self, size):
        for i in range(0, len(self.body), size):
            yield self.body[i:i + size]

    def close(self):
        pass


class ParseTests(SimpleTestCase):
    def test_the_real_feed_is_read_into_short_plain_records(self):
        items = zero_wire.parse(feed())
        self.assertEqual([i['slug'] for i in items], ['nginx2root', 'wordpress-7-1-5-template-part-privilege-escalation', 'ruby2shell-heap-overflow-in-ruby-string-case-conversion'][:2] + [items[2]['slug']])
        nginx = items[0]
        self.assertEqual(nginx['link'], 'https://radar.cloudflare.com/zero-wire/nginx2root')
        self.assertEqual(nginx['guid'], 'nginx2root@2026-11-18')
        self.assertEqual(nginx['published_at'].astimezone(dt_timezone.utc).date().isoformat(), '2026-11-18')
        self.assertTrue(nginx['summary'].startswith('Prioritize patching.'))
        self.assertLessEqual(len(nginx['summary']), 400)
        self.assertIn("vendor's fixed build", nginx['summary'])  # entities read once
        self.assertIn('nginx', nginx['categories'])
        self.assertIn('RCE', nginx['categories'])

    def test_cve_ids_come_from_the_briefing_and_a_briefing_with_none_has_none(self):
        items = {i['slug']: i for i in zero_wire.parse(feed())}
        self.assertEqual(len(items['nginx2root']['cve_ids']), 7)
        self.assertTrue(all(c.startswith('CVE-') and c == c.upper() for c in items['nginx2root']['cve_ids']))
        self.assertEqual(items['wordpress-7-1-5-template-part-privilege-escalation']['cve_ids'], [])

    def test_no_html_of_the_briefing_is_kept(self):
        items = zero_wire.parse(feed())
        text = repr(items)
        for needle in ('<p>', '<strong>', '<time', 'CDATA', 'Last reviewed', 'content:encoded'):
            self.assertNotIn(needle, text)
        self.assertEqual(set(items[0]), {'guid', 'slug', 'title', 'link', 'published_at', 'summary', 'cve_ids', 'categories'})

    def test_only_zero_wire_links_are_kept(self):
        good = 'https://radar.cloudflare.com/zero-wire/nginx2root'
        self.assertEqual(zero_wire.safe_link(good + '?utm=1#x'), good)
        for bad in ('http://radar.cloudflare.com/zero-wire/x', 'https://evil.example/zero-wire/x', 'https://radar.cloudflare.com.evil.example/zero-wire/x',
                    'https://radar.cloudflare.com/other/x', 'https://radar.cloudflare.com/zero-wire/', 'https://user@radar.cloudflare.com/zero-wire/x',
                    'https://radar.cloudflare.com:8443/zero-wire/x', 'javascript:alert(1)', '', None):
            self.assertEqual(zero_wire.safe_link(bad), '', bad)
        foreign = feed().replace(b'https://radar.cloudflare.com/zero-wire/nginx2root', b'https://evil.example/zero-wire/nginx2root')
        self.assertNotIn('nginx2root', [i['slug'] for i in zero_wire.parse(foreign)])

    def test_a_document_type_an_entity_a_huge_body_and_a_non_feed_are_refused(self):
        bomb = b'<?xml version="1.0"?><!DOCTYPE rss [<!ENTITY a "aaaa">]><rss version="2.0"><channel><item><title>&a;</title></item></channel></rss>'
        for raw in (bomb, b'<!doctype html><html></html>', b'<rss version="2.0"><!ENTITY x "y"><channel/></rss>', b'x' * (zero_wire.MAX_BYTES + 1), b'<html/>', b'not xml'):
            with self.assertRaises(zero_wire.FeedError, msg=raw[:30]):
                zero_wire.parse(raw)

    def test_the_item_count_is_capped(self):
        item = (b'<item><title>t</title><link>https://radar.cloudflare.com/zero-wire/a%d</link><guid>g%d</guid><pubDate>Wed, 18 Nov 2026 00:00:00 GMT</pubDate></item>')
        raw = b'<rss version="2.0"><channel>' + b''.join(item % (i, i) for i in range(80)) + b'</channel></rss>'
        self.assertEqual(len(zero_wire.parse(raw)), zero_wire.MAX_ITEMS)


class SyncTests(TestCase):
    def test_with_the_switch_off_nothing_is_fetched(self):
        ReportingSettings.objects.create(zero_wire_enabled=False)
        get = mock.Mock()
        self.assertEqual(zero_wire.sync(get=get), {'skipped': 'switched off'})
        get.assert_not_called()
        self.assertEqual(ZeroWireBriefing.objects.count(), 0)

    def test_it_is_on_by_default_and_stores_each_briefing_once(self):
        get = mock.Mock(return_value=FakeResponse(feed()))
        self.assertEqual(zero_wire.sync(now=NOW, get=get), {'briefings': 3})
        self.assertEqual(zero_wire.sync(now=NOW, get=get), {'briefings': 3})
        self.assertEqual(ZeroWireBriefing.objects.count(), 3)
        self.assertEqual(get.call_args.args[0], zero_wire.FEED_URL)
        row = ReportingSettings.objects.get()
        self.assertEqual((row.zero_wire_error, row.zero_wire_synced_at), ('', NOW))
        self.assertEqual(len(ZeroWireBriefing.objects.get(slug='nginx2root').cve_ids), 7)

    def test_a_failure_is_recorded_and_the_stored_briefings_stay(self):
        zero_wire.sync(now=NOW, get=mock.Mock(return_value=FakeResponse(feed())))
        self.assertEqual(zero_wire.sync(get=mock.Mock(side_effect=OSError('down'))), {'error': 'Zero Wire could not be reached'})
        self.assertEqual(ReportingSettings.objects.get().zero_wire_error, 'Zero Wire could not be reached')
        self.assertEqual(zero_wire.sync(get=mock.Mock(return_value=FakeResponse(b'', status=503)))['error'], 'Zero Wire answered 503')
        self.assertIn('not valid XML', zero_wire.sync(get=mock.Mock(return_value=FakeResponse(b'<rss')))['error'])
        self.assertEqual(ZeroWireBriefing.objects.count(), 3)

    def test_an_oversized_answer_is_cut_off(self):
        self.assertIn('larger than the limit', zero_wire.sync(get=mock.Mock(return_value=FakeResponse(b'x' * (zero_wire.MAX_BYTES + 5))))['error'])

    def test_the_task_runs_the_sync_and_the_schedule_exists(self):
        from django_celery_beat.models import PeriodicTask

        from cveFeed import tasks
        with mock.patch.object(zero_wire, 'sync', return_value={'briefings': 0}) as sync:
            self.assertEqual(tasks.sync_zero_wire(), {'briefings': 0})
        sync.assert_called_once()
        task = PeriodicTask.objects.get(name='cvengine-zero-wire')
        self.assertEqual((task.task, task.queue, task.interval.every, task.interval.period), ('sync_zero_wire', 'cve_feed_queue', 6, 'hours'))


class ThreatBase(ReportingBase):
    def scope(self, user=None, **kw):
        return report_scope.resolve(Ctx(user=user or self.org_admin), **(kw or {'project': 'acme-web'}))

    def kev(self, cve_id, added_days_ago=2, **kw):
        fields = {'kev': True, 'cvss': 9.8, 'title': f'{cve_id} title', 'published_at': NOW - timedelta(days=30), 'affected': [{'product': 'nginx', 'ranges': [{'fixed': '1.20.0'}]}],
                  'intel': {'kev': {'cisa_kev': {'added': (NOW - timedelta(days=added_days_ago)).date().isoformat(), 'ransomware': False, 'name': 'KEV name', 'vendor': 'F5',
                                                 'product': 'nginx'}}}, **kw}
        return CVEEntry.objects.create(cve_id=cve_id, **fields)

    def briefing(self, slug='nginx2root', cve_ids=(), categories=('nginx', 'RCE'), days_ago=1, **kw):
        return ZeroWireBriefing.objects.create(guid=f'{slug}@x', slug=slug, title=kw.pop('title', f'{slug}: update now'), link=f'https://radar.cloudflare.com/zero-wire/{slug}',
                                               published_at=NOW - timedelta(days=days_ago), summary=kw.pop('summary', 'Prioritize patching. Update nginx.'),
                                               cve_ids=list(cve_ids), categories=list(categories), **kw)

    def unversioned_nginx_host(self, name='plain.acme.test', address='203.0.113.40'):
        sub = Subdomain.objects.create(target_domain=self.domains['acme-web'], scan_history=self.scans['acme-web'], name=name, score=1)
        sub.ip_addresses.add(IpAddress.objects.create(address=address))
        sub.technologies.add(Technology.objects.get_or_create(name='nginx')[0])
        return sub


class CandidateTests(ThreatBase):
    def test_a_kev_addition_in_the_period_is_picked_and_one_before_it_is_not(self):
        inside, before = self.kev('CVE-2099-3001', 2), self.kev('CVE-2099-3002', 20)
        ids = {c.cve_id for c in report_threats.candidates(START, END)}
        self.assertIn(inside.cve_id, ids)
        self.assertNotIn(before.cve_id, ids)

    def test_a_local_only_cve_is_left_out(self):
        self.kev('CVE-2099-3003', 1, local_only=True)
        self.assertNotIn('CVE-2099-3003', {c.cve_id for c in report_threats.candidates(START, END)})

    def test_a_new_critical_cve_needs_a_public_exploit_or_a_high_exploitation_probability(self):
        fresh = dict(kev=None, published_at=NOW - timedelta(days=1), intel={}, affected=[])
        self.kev('CVE-2099-3004', cvss=9.8, epss_reached=True, **{k: v for k, v in fresh.items()})
        self.kev('CVE-2099-3005', cvss=9.8, **fresh)  # critical but neither: not news
        self.kev('CVE-2099-3006', cvss=8.1, exploit_db=True, **fresh)  # exploit but not critical
        self.assertEqual({c.cve_id for c in report_threats.candidates(START, END)}, {'CVE-2099-3004'})

    def test_vulncheck_additions_count_too(self):
        cve = self.kev('CVE-2099-3007', intel={'kev': {'vulncheck_kev': {'added': (NOW - timedelta(days=1)).date().isoformat()}}})
        self.assertIn(cve.cve_id, {c.cve_id for c in report_threats.candidates(START, END)})


class ImpactTests(ThreatBase):
    def impact(self, cve, user=None, **kw):
        return report_threats.impact(self.scope(user, **kw).ids, [cve])[cve.id]

    def test_two_names_on_one_set_of_addresses_are_one_matched_host(self):
        cve = self.kev('CVE-2099-3101')
        alias = Subdomain.objects.create(target_domain=self.domains['acme-web'], scan_history=self.scans['acme-web'], name='alias.acme.test', score=0)
        alias.ip_addresses.add(*self.www.ip_addresses.all())
        for sub in (self.www, alias):
            CVEMatch.objects.create(cve_entry=cve, subdomain=sub, matched_product='nginx', matched_version='1.18.0', version_in_range=True, confidence=.9, source='port',
                                    template_result='vulnerable' if sub == self.www else '')
        row = self.impact(cve)
        self.assertEqual((len(row['matched']), len(row['confirmed'])), (1, 1))

    def test_a_closed_or_ruled_out_match_is_not_counted(self):
        cve = self.kev('CVE-2099-3102')
        for status, verdict in (('fixed', ''), ('accepted_risk', ''), ('open', 'not_affected')):
            sub = Subdomain.objects.create(target_domain=self.domains['acme-web'], scan_history=self.scans['acme-web'], name=f'{status}.acme.test', score=0)
            CVEMatch.objects.create(cve_entry=cve, subdomain=sub, matched_product='nginx', matched_version='1.18.0', confidence=.9, remediation_status=status, ai_verdict=verdict)
        self.assertEqual(self.impact(cve)['matched'], set())

    def test_a_host_with_nginx_and_no_version_is_a_product_only_host_and_a_versioned_one_is_not(self):
        cve = self.kev('CVE-2099-3103')
        plain = self.unversioned_nginx_host()
        row = self.impact(cve)
        self.assertEqual(len(row['product_only']), 1)  # plain.acme.test; www.acme.test runs nginx 1.18.0 (a version is read, so not "unknown")
        self.assertEqual(row['matched'], set())
        keys = dict(__import__('cveFeed.counts', fromlist=['x']).with_host_key(Subdomain.objects.filter(pk=plain.pk)).values_list('pk', 'host_key'))
        self.assertEqual(row['product_only'], {keys[plain.pk]})

    def test_a_host_that_matches_is_not_also_counted_as_version_unknown(self):
        cve = self.kev('CVE-2099-3104')
        plain = self.unversioned_nginx_host()
        CVEMatch.objects.create(cve_entry=cve, subdomain=plain, matched_product='nginx', matched_version='1.18.0', confidence=.9)
        row = self.impact(cve)
        self.assertEqual((len(row['matched']), row['product_only']), (1, set()))

    def test_another_organizations_hosts_are_never_counted(self):
        cve = self.kev('CVE-2099-3105')
        CVEMatch.objects.create(cve_entry=cve, subdomain=self.twin, matched_product='tomcat', matched_version='9.0', confidence=.9)
        self.assertEqual(self.impact(cve)['matched'], set())
        self.assertEqual(len(self.impact(cve, user=self.root, project='other-co')['matched']), 1)


class WordingAndRankingTests(ThreatBase):
    def test_the_sentences(self):
        line = report_threats.impact_line
        self.assertEqual(line(3, 1, 0, 'nginx', 'Acme'), ('3 of your hosts match by version (1 confirmed by a check)', 'matched'))
        self.assertEqual(line(1, 0, 0, 'nginx', 'Acme'), ('1 of your hosts matches by version', 'matched'))
        self.assertEqual(line(3, 0, 5, 'nginx', 'Acme'), ('3 of your hosts match by version · 5 more run nginx, version unknown', 'matched'))
        self.assertEqual(line(0, 0, 5, 'nginx', 'Acme'), ('5 of your hosts run nginx, version unknown', 'product'))
        self.assertEqual(line(0, 0, 1, 'nginx', 'Acme'), ('1 of your hosts runs nginx, version unknown', 'product'))
        self.assertEqual(line(0, 0, 0, 'nginx', 'Acme Web'), ('No host in Acme Web is known to run nginx.', 'none'))

    def test_a_cve_that_reaches_your_hosts_ranks_above_a_higher_scored_one_that_does_not(self):
        reaches = self.kev('CVE-2099-3201', cvss=7.5)
        CVEMatch.objects.create(cve_entry=reaches, subdomain=self.www, matched_product='nginx', matched_version='1.18.0', version_in_range=True, confidence=.9)
        quiet = self.kev('CVE-2099-3202', cvss=10.0, affected=[{'product': 'nothing-here', 'ranges': []}],
                         intel={'kev': {'cisa_kev': {'added': (NOW - timedelta(days=2)).date().isoformat(), 'product': 'nothing-here'}}})
        entries, note = report_threats.top(self.scope(), START, END)
        self.assertEqual([e['cve_ids'] for e in entries][:2], [['CVE-2099-3201'], ['CVE-2099-3202']])
        self.assertEqual(entries[0]['impact'], 'matched')
        self.assertEqual(entries[1]['impact_line'], 'No host in Acme Web is known to run nothing-here.')
        self.assertIn('Known Exploited Vulnerabilities', note)
        self.assertNotIn('Zero Wire', note)
        self.assertEqual({e['source'] for e in entries}, {'kev'})

    def test_the_writeup_is_the_stored_summary_else_the_first_two_sentences(self):
        a = self.kev('CVE-2099-3203', summary='A stored summary.')
        b = self.kev('CVE-2099-3204', summary='', title='Title', original_description='One. Two. Three.')
        self.assertEqual(report_threats.writeup(a), 'A stored summary.')
        self.assertEqual(report_threats.writeup(b), 'Title. One.')

    def test_the_list_is_capped_by_the_environment(self):
        for i in range(8):
            self.kev(f'CVE-2099-33{i:02d}')
        self.assertEqual(len(report_threats.top(self.scope(), START, END)[0]), 6)
        with mock.patch.dict(os.environ, {'CVENGINE_DIGEST_TOP_VULNS': '3'}):
            self.assertEqual(len(report_threats.top(self.scope(), START, END)[0]), 3)
        for value, expected in (('', 6), ('0', 1), ('50', 12), ('x', 6)):
            with mock.patch.dict(os.environ, {'CVENGINE_DIGEST_TOP_VULNS': value}):
                self.assertEqual(report_threats.top_limit(), expected, value)


class BriefingTests(ThreatBase):
    def test_a_briefing_that_names_cves_we_hold_is_counted_through_them_and_they_are_not_listed_twice(self):
        cve = self.kev('CVE-2099-3301')
        CVEMatch.objects.create(cve_entry=cve, subdomain=self.www, matched_product='nginx', matched_version='1.18.0', version_in_range=True, confidence=.9, template_result='vulnerable')
        self.briefing(cve_ids=['CVE-2099-3301', 'CVE-2099-0001'])
        entries, note = report_threats.top(self.scope(), START, END)
        self.assertEqual([e['source'] for e in entries], ['zero_wire'])  # the CVE is covered by the briefing
        e = entries[0]
        self.assertEqual((e['matched'], e['confirmed']), (1, 1))
        self.assertEqual(e['impact_line'], '1 of your hosts matches by version (1 confirmed by a check)')
        self.assertIn('Cloudflare Zero Wire', e['badges'])
        self.assertIn('CISA KEV', e['badges'])
        self.assertEqual(e['link'], 'https://radar.cloudflare.com/zero-wire/nginx2root')
        self.assertIn('Cloudflare Radar Zero Wire (radar.cloudflare.com/zero-wire)', note)

    def test_a_briefing_with_no_cves_is_matched_by_its_product_tags(self):
        self.unversioned_nginx_host()
        self.briefing(slug='nginx-only', categories=['nginx', 'RCE', 'Memory corruption'])
        e = report_threats.top(self.scope(), START, END)[0][0]
        self.assertEqual(e['impact_line'], '2 of your hosts run nginx')  # plain.acme.test and www.acme.test (nginx 1.18.0): the product, not a version match
        self.assertEqual(e['impact'], 'product')

    def test_a_product_nobody_runs_says_so_and_class_tags_are_ignored(self):
        self.briefing(slug='wp', categories=['CMS', 'RCE', 'SQL injection', 'Runtime', 'WordPress'])
        e = report_threats.top(self.scope(), START, END)[0][0]
        self.assertEqual(e['impact_line'], 'No host in Acme Web is known to run WordPress.')
        self.briefing(slug='only-classes', categories=['RCE', 'Memory corruption', 'CMS'], days_ago=0.5)
        classes = next(e for e in report_threats.top(self.scope(), START, END)[0] if e['link'].endswith('only-classes'))
        self.assertEqual((classes['impact_line'], classes['impact']), ('', 'none'))

    def test_the_product_aliases_of_correlation_are_used(self):
        self.assertTrue(report_threats._same_product('Apache HTTP Server', 'apache httpd') or report_threats._same_product('apache httpd', 'Apache HTTP Server'))
        self.assertFalse(report_threats._same_product('nginx', 'tomcat'))

    def test_briefings_come_first_newest_first_and_only_those_in_the_period(self):
        self.kev('CVE-2099-3302')
        self.briefing(slug='old', days_ago=1), self.briefing(slug='newer', days_ago=0.5), self.briefing(slug='ancient', days_ago=40)
        entries, _ = report_threats.top(self.scope(), START, END)
        self.assertEqual([e['source'] for e in entries], ['zero_wire', 'zero_wire', 'kev'])
        self.assertEqual([e['link'].rsplit('/', 1)[-1] for e in entries[:2]], ['newer', 'old'])

    def test_with_the_switch_off_no_briefing_is_used(self):
        self.briefing()
        ReportingSettings.objects.create(zero_wire_enabled=False)
        self.assertEqual(report_threats.top(self.scope(), START, END)[0], [])


class EmailTests(SubBase, ThreatBase):
    def test_the_email_names_a_briefing_with_its_text_escaped(self):
        cve = self.kev('CVE-2099-3301')  # a briefing is listed only when it reaches a host: this one names a CVE that matches www.acme.test
        CVEMatch.objects.create(cve_entry=cve, subdomain=self.www, matched_product='nginx', matched_version='1.18.0', version_in_range=True, confidence=.9, source='port')
        self.briefing(title='nginx <b>2root</b>', summary='Update <img src=x onerror=1> now.', cve_ids=[cve.cve_id])
        sub = self.make(next_run_at=NOW - timedelta(hours=1))
        report_digests.deliver_period(sub, NOW)
        html, text = mail.outbox[0].alternatives[0][0], mail.outbox[0].body
        self.assertIn('most important vulnerabilities', html)
        self.assertIn('nginx &lt;b&gt;2root&lt;/b&gt;', html)
        self.assertNotIn('<img src=x', html)
        self.assertNotIn('<b>2root</b>', html)
        self.assertIn('Cloudflare Zero Wire', html)
        self.assertIn('https://radar.cloudflare.com/zero-wire/nginx2root', html)
        self.assertIn('Zero Wire', text)
        self.assertIn('Cloudflare Radar Zero Wire (radar.cloudflare.com/zero-wire)', html)
        self.assertLess(len(html.encode()), 100_000)

    def test_an_empty_period_still_shows_the_section(self):
        sub = self.make(next_run_at=NOW - timedelta(hours=1))
        report_digests.deliver_period(sub, NOW)
        self.assertIn('No newly exploited or critical vulnerabilities were announced this week.', mail.outbox[0].alternatives[0][0])
        self.assertIn('No newly exploited', mail.outbox[0].body)

    def test_a_failure_in_the_section_never_stops_the_email(self):
        sub = self.make(next_run_at=NOW - timedelta(hours=1))
        with mock.patch.object(report_threats, 'top', side_effect=RuntimeError('boom')):
            report_digests.deliver_period(sub, NOW)
        self.assertEqual(len(mail.outbox), 2)

    def test_the_digest_carries_the_entries_and_the_note(self):
        cve = self.kev('CVE-2099-3401')
        CVEMatch.objects.create(cve_entry=cve, subdomain=self.www, matched_product='nginx', matched_version='1.18.0', version_in_range=True, confidence=.9, source='port')
        digest = report_digest.build(self.scope(), START, END, 'weekly', NOW)
        self.assertEqual([t['source'] for t in digest['threats']], ['cve'])
        self.assertTrue(digest['threats_note'])
        self.assertEqual(digest['threats_empty'], '')
        self.assertIn('1 important vulnerability', report_digest._preheader(digest))


class RouteTests(ThreatBase):
    def test_the_route_returns_the_entries_for_a_scope_the_caller_can_read(self):
        self.briefing()
        status, body = call(self.org_member, 'GET', '/api/v1/reporting/threats?project=acme-web')
        self.assertEqual(status, 200, body)
        self.assertEqual((body['days'], body['scope']['slug'], [i['source'] for i in body['items']]), (7, 'acme-web', ['zero_wire']))
        self.assertIn('Zero Wire', body['note'])
        self.assertEqual(call(self.org_member, 'GET', '/api/v1/reporting/threats?org=acme-org&days=3')[1]['days'], 3)
        self.assertEqual(call(self.org_member, 'GET', '/api/v1/reporting/threats?project=acme-web&cadence=monthly')[1]['days'], 30)

    def test_an_outsider_gets_404_and_bad_input_400(self):
        self.assertEqual(call(self.outsider, 'GET', '/api/v1/reporting/threats?project=acme-web')[0], 404)
        self.assertEqual(call(self.web_user, 'GET', '/api/v1/reporting/threats?org=other-org')[0], 404)
        for query in ('', '?project=acme-web&org=acme-org', '?project=acme-web&days=0', '?project=acme-web&days=x', '?project=acme-web&cadence=daily', '?project=_all'):
            self.assertEqual(call(self.org_member, 'GET', '/api/v1/reporting/threats' + query)[0], 400, query)

    def test_the_mcp_tool_is_a_read(self):
        self.briefing()
        _, ro = create_token(self.org_member, 'ro', read_only=True)
        error, data = tool_call(ro, 'get_threat_digest', {'project': 'acme-web', 'days': 7})
        self.assertFalse(error, data)
        self.assertEqual(data['items'][0]['title'], 'nginx2root: update now')
        error, _ = tool_call(ro, 'get_threat_digest', {'org': 'other-org'})
        self.assertTrue(error)

    def test_only_an_app_admin_in_the_web_interface_switches_zero_wire(self):
        self.assertEqual(call(self.org_member, 'GET', '/api/v1/reporting/zero-wire')[1], {'enabled': True})
        status, body = call(self.root, 'GET', '/api/v1/reporting/zero-wire')
        self.assertEqual((status, body['enabled'], body['briefings'], body['error']), (200, True, 0, ''))
        self.assertEqual(call(self.root, 'PUT', '/api/v1/reporting/zero-wire', {'enabled': False})[1]['enabled'], False)
        self.assertFalse(ReportingSettings.current().zero_wire_enabled)
        self.assertEqual(call(self.org_admin, 'PUT', '/api/v1/reporting/zero-wire', {'enabled': True})[0], 403)  # an Org Admin is not an App Admin
        _, token = create_token(self.root, 'agent')
        status, body = call(token, 'PUT', '/api/v1/reporting/zero-wire', {'enabled': True})
        self.assertEqual(status, 403)
        self.assertIn('web interface', body['error'])
        self.assertFalse(ReportingSettings.current().zero_wire_enabled)
        self.assertEqual(call(self.root, 'PUT', '/api/v1/reporting/zero-wire', {'enabled': 'yes'})[0], 400)
        from dashboard.models import AuditLog
        self.assertEqual(AuditLog.objects.filter(action='reporting.zero_wire').count(), 1)
