"""The OpenVAS queue explanation (``openvas_scan.explain``, the Settings page's per-project queue and the live-cache refresh) reads each candidate
host's newest row and vets the hosts left in a fixed number of queries, whatever the number of candidates. It read them one host at a time: four
queries per host, 3,895 queries and 5.2 s for one project of the 10,000-host scale fixture (47 queries and 0.7 s now)."""
from unittest import mock

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext

from cveFeed import openvas_scan as ov
from cveFeed.models import OpenvasProject
from tests.test_openvas import Fixture


class ExplainQueryTests(Fixture, TestCase):
    def listed(self, count, start=0):
        """``count`` more hosts of the project, listed and forced so every one is a candidate that reaches the vetting and the stored address. They
        share an address in a documentation range, which OpenVAS refuses (``refuse_reason``) before the shared platform check, the one step a
        host that is really ready still pays on its own (``hosting.shared_by_address`` caps its name lookups per call, so it stays per address)."""
        names = [f'h{i:02d}.rt.test' for i in range(start, start + count)]
        self.scan(names=tuple(names), ip=f'192.0.2.{start + 10}')  # one scan: the current inventory check is per scan, not per host
        link = OpenvasProject.objects.get(pk=self.link.pk)
        link.hosts = sorted(set(link.hosts) | set(names))
        link.forced_hosts = sorted(set(link.forced_hosts) | set(names))
        link.save()
        return link

    def count(self, link):
        ov.explain(link)  # warm: per-process reads (internal networks, the exclusion lists) are not what is measured
        with CaptureQueriesContext(connection) as q:
            rows = ov.explain(link)
        return len(q), rows

    def test_the_explanation_costs_the_same_for_3_and_23_candidate_hosts(self):
        small, rows = self.count(self.listed(1))
        self.assertGreaterEqual(len(rows), 3)
        large, rows = self.count(self.listed(20, start=1))
        self.assertGreaterEqual(len(rows), 23)
        self.assertLessEqual(large, small + 2, (small, large))

    def test_the_batched_reading_gives_the_same_rows_as_one_read_per_host(self):
        link = self.listed(6)
        # the old reading: one query per host for its newest row (_latest_row), each host vetted on its own (scannable_hosts per host)
        per_host = mock.patch.object(ov, '_latest_rows', create=True,
                                     side_effect=lambda project_id, hosts, scoped=False: {h: r for h in hosts if (r := ov._latest_row(project_id, h, scoped=scoped))})
        with per_host:
            old = ov.explain(link)
        new = ov.explain(link)
        key = lambda r: r['host']  # noqa: E731
        self.assertEqual(sorted(old, key=key), sorted(new, key=key))
        self.assertEqual([r['host'] for r in old], [r['host'] for r in new])  # the scan order too
