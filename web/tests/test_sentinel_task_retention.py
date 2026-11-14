"""Finished Sentinel tasks are kept for a retention that an App Admin can set on Settings (configMaxxing, Data retention), else CVENGINE_AGENT_TASK_RETENTION_DAYS,
else 30 days; the weekly cleanup deletes what is older (``sentinel_broker.prune_tasks``). A task that is not finished is never deleted."""
from datetime import timedelta
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import sentinel_broker
from agentapi.models import SentinelTask
from cveFeed import tunables
from dashboard.models import Org, Project


class RetentionTunableTests(SimpleTestCase):
    def test_it_is_registered_with_the_documented_default_and_environment_variable(self):
        t = tunables.BY_KEY['sentinel_task_retention_days']
        self.assertEqual((t.default, t.low, t.high, t.env, t.group, t.auto_tunable), (30, 1, 365, 'CVENGINE_AGENT_TASK_RETENTION_DAYS', 'retention', False))
        self.assertEqual(sentinel_broker.RETENTION_DAYS, t.default)

    def test_the_card_for_its_group_exists_on_the_page(self):
        import os
        js = open(os.path.join(os.path.dirname(__file__), '..', 'static', 'cve', 'tunables-card.js')).read()
        self.assertIn('registerTunableGroup("retention"', js)

    def test_the_documentation_says_where_to_set_it(self):
        import os
        doc = open(os.path.join(os.path.dirname(__file__), '..', '..', 'docs', 'CONFIGURATION.md')).read()
        row = [line for line in doc.splitlines() if line.startswith('| `CVENGINE_AGENT_TASK_RETENTION_DAYS`')][0]
        self.assertIn('Data retention', row)
        self.assertIn('1 to 365', row)


class PruneTests(TestCase):
    def setUp(self):
        org = Org.objects.create(name='R', slug='ret-org')
        self.project = Project.objects.create(name='R', slug='ret', insert_date=timezone.now(), org=org)
        self.now = timezone.now()

    def task(self, status, age_days):
        t = SentinelTask.objects.create(project=self.project, kind='nmap', target={}, status=status, finished_at=self.now - timedelta(days=age_days) if status in ('done', 'failed', 'expired') else None)
        return t.pk

    def test_the_default_keeps_thirty_days_and_never_touches_unfinished_work(self):
        old, young = self.task('done', 31), self.task('failed', 29)
        old_expired, queued = self.task('expired', 90), self.task('queued', 90)
        self.assertEqual(sentinel_broker.prune_tasks(self.now), 2)
        self.assertEqual(set(SentinelTask.objects.values_list('pk', flat=True)), {young, queued})
        self.assertNotIn(old, SentinelTask.objects.values_list('pk', flat=True))
        self.assertNotIn(old_expired, SentinelTask.objects.values_list('pk', flat=True))

    def test_a_saved_setting_is_obeyed(self):
        a, b, c = self.task('done', 2), self.task('done', 8), self.task('failed', 20)
        with mock.patch.object(tunables, 'resolve', return_value={'value': 7, 'source': 'saved'}):
            self.assertEqual(sentinel_broker.prune_tasks(self.now), 2)
        self.assertEqual(list(SentinelTask.objects.values_list('pk', flat=True)), [a])

    def test_the_environment_variable_still_works_when_nothing_is_saved(self):
        keep, drop = self.task('done', 5), self.task('done', 12)
        with mock.patch.dict('os.environ', {'CVENGINE_AGENT_TASK_RETENTION_DAYS': '10'}):
            self.assertEqual(sentinel_broker.prune_tasks(self.now), 1)
        self.assertEqual(list(SentinelTask.objects.values_list('pk', flat=True)), [keep])
        self.assertNotIn(drop, SentinelTask.objects.values_list('pk', flat=True))

    def test_an_explicit_days_argument_wins(self):
        self.task('done', 3)
        self.assertEqual(sentinel_broker.prune_tasks(self.now, days=2), 1)
