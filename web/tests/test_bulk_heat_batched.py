"""A bulk heat change reads and writes its findings in a fixed number of statements (review finding A10).

``bulk_set_finding_heat`` took up to 500 findings one at a time: a read of each finding (and three prefetches for a scanner finding), a hot CVE
lookup before and after, a Triage UPDATE and an audit INSERT each, about 3,000 statements in autocommit, so a failure half way left half the batch
written. The findings of each kind are now read at once, the hot CVEs once, and the overrides and their audit events written in one transaction.
Each item still answers what it answered before: the same counts, the same failures in the same order, the same audit rows.
"""
from django.db import connection
from django.test.utils import CaptureQueriesContext

from agentapi import services
from cveFeed.models import CVEMatch, FindingAuditEvent, Triage
from cveFeed.threat import ICE
from startScan.models import CveId, Vulnerability
from tests.test_agentapi import call
from tests.test_heat_override import Fixture


class BulkHeatBatchedTests(Fixture):
    def many(self, n, tag='a'):
        cve = CveId.objects.get(name='CVE-2099-8801')
        vulns = []
        for i in range(n):
            v = Vulnerability.objects.create(name=f'bulk {tag} {i}', severity=3 + i % 2, subdomain=self.sub, target_domain=self.domain,
                                             open_status=True, http_url=f'https://www.example.com/{tag}/{i}', source='nuclei')
            if i % 2:
                v.cve_ids.add(cve)
            vulns.append(v)
        matches = [CVEMatch.objects.create(cve_entry=self.kev if i % 2 else self.cold, subdomain=self.sub, source='tech', matched_product=f'lib-{tag}-{i}',
                                           matched_version='1.2', version_in_range=True, confidence=0.8, scan_history=self.scan, evidence={'source': 'tech'})
                   for i in range(n)]
        return vulns, matches

    def bulk(self, items, heat='ice', reason='rated too high'):
        with CaptureQueriesContext(connection) as ctx:
            status, data = call(self.t_alice, 'POST', f'{self.base}/findings/heat', {'items': items, 'heat': heat, 'reason': reason})
        self.assertEqual(status, 200, data)
        return data, ctx.captured_queries

    def test_the_statements_do_not_grow_with_the_findings(self):
        def items(vulns, matches):
            return [{'kind': 'vulnerability', 'id': v.pk} for v in vulns] + [{'kind': 'match', 'id': m.pk} for m in matches]
        small, big = items(*self.many(2)), items(*self.many(30, 'b'))
        for batch in (small, big):  # the first rating makes the findings' Triage rows (``triage.track``, whose reads are its own)
            self.bulk(batch)
        _, few = self.bulk(small, heat='smoke')
        data, lots = self.bulk(big, heat='smoke')
        self.assertEqual((data['updated'], data['unchanged'], data['failed']), (60, 0, []))
        writes = lambda qs: [q for q in qs if q['sql'].startswith(('UPDATE "cveFeed_triage"', 'INSERT INTO "cveFeed_findingauditevent"'))]  # noqa: E731
        self.assertEqual(len(writes(lots)), 2)  # one UPDATE of the overrides, one INSERT of the audit events
        self.assertLess(len(lots), len(few) + 10)  # the findings are read per kind, not per finding (it was about 6 statements per finding)

    def test_each_audit_row_says_what_one_change_says(self):
        vulns, matches = self.many(4)
        objs = [('vulnerability', v) for v in vulns] + [('match', m) for m in matches]
        shown = {(k, o.pk): services._shown_heat(k, services._finding_obj(self.proj, k, o.pk)) for k, o in objs}
        data, _ = self.bulk([{'kind': k, 'id': o.pk} for k, o in objs])
        self.assertEqual(data['updated'], 8)
        for k, o in objs:
            with self.subTest(kind=k, id=o.pk):
                event = FindingAuditEvent.objects.get(finding_kind=k, finding_id=o.pk, event='heat')
                self.assertEqual(event.before, {'heat': shown[(k, o.pk)], 'override': None})
                self.assertEqual(event.after, {'heat': ICE, 'override': ICE, 'reason': 'rated too high'})
                self.assertEqual(event.actor_id, self.alice.pk)
                row = Triage.objects.get(**{'match' if k == 'match' else 'vulnerability': o})
                self.assertEqual((row.heat_override, row.heat_override_reason, row.heat_override_by_id), (ICE, 'rated too high', self.alice.pk))

    def test_a_finding_listed_twice_changes_once(self):
        vulns, _ = self.many(1)
        item = {'kind': 'vulnerability', 'id': vulns[0].pk}
        data, _ = self.bulk([item, dict(item, id=str(vulns[0].pk)), {'kind': 'vulnerability', 'id': 99999999}, item])
        self.assertEqual((data['updated'], data['unchanged']), (1, 2))
        self.assertEqual(data['failed'], [{'kind': 'vulnerability', 'id': 99999999, 'error': 'finding not found'}])
        self.assertEqual(FindingAuditEvent.objects.filter(event='heat', finding_id=vulns[0].pk).count(), 1)
        cleared, _ = self.bulk([item, item], heat=None, reason=None)
        self.assertEqual((cleared['updated'], cleared['unchanged']), (1, 1))
        self.assertEqual(Triage.objects.get(vulnerability=vulns[0]).heat_override, '')

    def test_a_failed_write_writes_nothing_and_says_so_for_each(self):
        vulns, _ = self.many(3)
        from unittest import mock
        with mock.patch.object(FindingAuditEvent.objects, 'bulk_create', side_effect=RuntimeError('boom')):
            data, _ = self.bulk([{'kind': 'vulnerability', 'id': v.pk} for v in vulns])
        self.assertEqual((data['updated'], [f['error'] for f in data['failed']]), (0, ['could not be updated'] * 3))
        self.assertFalse(Triage.objects.filter(vulnerability__in=vulns).exclude(heat_override='').exists())
