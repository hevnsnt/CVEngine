"""Lists built from a GROUP BY come back in a fixed order. Postgres gives a grouped result no order of its own (it is hash order, and it changes
with the data and the plan), so a list that is sliced or shown in the order it was read needs an ORDER BY with a tie breaker: without one, the
Sentinel starvation check kept 30 arbitrary kinds of a longer queue, and the AI usage page and the bounty stats reordered rows between two
identical requests."""
from datetime import timedelta

from django.db import connection
from django.test import TestCase
from django.utils import timezone

from agentapi.models import SentinelTask
from cveFeed import ai_usage, reviewer
from cveFeed.models import AIUsage, BountyReport
from dashboard.models import Org, Project
from tests.test_bounty_api import B, ReportBase, call


class StarvedKindsTests(TestCase):
    def test_the_thirty_kinds_that_waited_longest_are_read_oldest_first(self):
        org = Org.objects.create(name='G', slug='glo-org')
        project = Project.objects.create(name='G', slug='glo', insert_date=timezone.now(), org=org)
        now = timezone.now()
        # 36 kinds whose ages (1 to 36 minutes, each once) follow neither their names nor the order they were written
        ages = {f'k{i:02d}': (i * 7) % 36 + 1 for i in range(1, 37)}
        for kind, minutes in ages.items():
            task = SentinelTask.objects.create(project=project, kind=kind, target={})
            SentinelTask.objects.filter(pk=task.pk).update(created_at=now - timedelta(minutes=minutes))
        work = reviewer._starvation_inputs(now, False, 1)
        oldest = sorted(ages, key=lambda k: (-ages[k], k))[:30]
        self.assertEqual([row['kind'] for row in work['sentinel_kinds']], oldest)


class AIUsageOrderTests(TestCase):
    def test_tied_models_and_stages_come_in_a_fixed_order(self):
        for stage in ('triage', 'assess', 'verdict', 'author'):
            for model in ('m-c', 'm-a', 'm-b'):
                AIUsage.objects.create(provider='anthropic', model=model, stage=stage, status='succeeded')
        out = ai_usage.snapshot(days=1, with_cost=False)
        self.assertEqual([m['model'] for m in out['models']], ['m-a', 'm-b', 'm-c'])  # four attempts each: a tie, broken by name
        self.assertEqual([s['stage'] for s in out['stages']], ['assess', 'author', 'triage', 'verdict'])  # three attempts each


class BountyPaidOrderTests(ReportBase):
    def test_paid_lines_come_one_per_currency_in_currency_order(self):
        _, report = self.draft()
        first = BountyReport.objects.get(pk=report['id'])
        currencies = ('USD', 'EUR', 'GBP', 'CHF', 'JPY', 'AUD', 'SEK', 'CAD')
        for amount, currency in enumerate(currencies, 1):
            row = BountyReport.objects.get(pk=first.pk)
            if currency != 'USD':
                row.pk = row.id = row.finding_id = None  # a copy of the report that names no finding (one report per finding)
            row.bounty_amount, row.bounty_currency = amount, currency
            row.save()
        with connection.cursor() as cursor:
            # a small table is grouped by sorting, which happens to read back in order; a larger one is hashed: plan it the way it would be
            cursor.execute('SET LOCAL enable_sort = off')
        status, stats = call(self.c, 'GET', B + 'stats?project=a1')
        self.assertEqual(status, 200, stats)
        self.assertEqual([p['currency'] for p in stats['paid']], sorted(currencies))
