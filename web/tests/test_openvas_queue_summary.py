"""The one line above the OpenVAS queue's collapsed "Not due" list: the per-host reasons grouped into stable categories, counted on the server over every host."""
import os
import time
from unittest import mock

from django.core.cache import cache
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import openvas_scan as ov
from cveFeed.models import CVEEntry, OpenvasProject
from tests.test_openvas import Fixture


def row(host, reason=None, ready=False):
    return {'host': host, 'heat': '', 'ready': ready, 'reason': reason, 'retry': False, 'order': 0 if ready else None}


class GroupingTests(SimpleTestCase):
    SENTENCES = {
        'not_fire_smoke': ['not Fire or Smoke (ice): OpenVAS is only spent on hosts on fire or smoke', 'not Fire or Smoke (unknown): OpenVAS is only spent on hosts on fire or smoke'],
        'scanned_this_week': ['scanned 2 days ago; due again after a week', 'scanned today; due again after a week'],
        'shared_platform': ["a CDN edge (Cloudflare): not the project's to test", "a third-party platform (Microsoft 365) shared with other customers: not the project's to test",
                            "a platform other tenants share (its address): not the project's to test"],
        'failed_lately': [f'{ov.INCONCLUSIVE} 1 day ago; asked again after three days', 'could not be scanned 2 days ago; asked again after three days', ov.interrupted_reason(3)],
        'excluded': ['excluded from scanning'],
        'bug_bounty': ['bug bounty: not in the program scope'],
        'manual_only': ['the target is set to manual only: OpenVAS scans its hosts only when a person names them'],
        'single_host_target': ['its target is set to this host only: a name under it is not scanned'],
        'no_usable_address': ['a scanner may not be pointed at it (a prohibited address range, or it does not resolve to a public address)', 'the name does not resolve to an address a scanner may use',
                              'no address is recorded for the host yet', "a tailnet address: not the project's to test", "this cvENGINE server: not the project's to test"],
        'same_address': ['the same address as www.example.com'],
        'not_in_project': ['not a host of this project'],
    }

    def test_every_sentence_assess_writes_lands_in_its_group(self):
        for key, sentences in self.SENTENCES.items():
            for text in sentences:
                with self.subTest(text=text):
                    self.assertEqual(ov.reason_group(text)[0], key)

    def test_the_table_covers_every_key_it_defines_and_nothing_else_is_expected(self):
        self.assertEqual({k for k, _m, _w in ov.QUEUE_REASONS}, set(self.SENTENCES))
        self.assertEqual(len({k for k, _m, _w in ov.QUEUE_REASONS}), len(ov.QUEUE_REASONS))

    def test_an_unknown_or_missing_reason_is_other(self):
        for text in ('something new someone wrote', '', None):
            self.assertEqual(ov.reason_group(text), ('other', 'for other reasons'))

    def test_the_summary_line_is_the_biggest_group_first_and_the_numbers_add_up(self):
        reasons = (['not Fire or Smoke (ice): x'] * 20 + ['scanned 1 day ago; due again after a week'] * 8
                   + ["a CDN edge (Fastly): not the project's to test"] * 5)
        groups = ov.group_reasons(reasons)
        self.assertEqual(ov.not_due_summary(groups), '33 not due: 20 not Fire or Smoke, 8 scanned this week, 5 on shared platforms')
        self.assertEqual(sum(g['count'] for g in groups), 33)

    def test_ties_follow_the_table_and_other_comes_last(self):
        groups = ov.group_reasons(['excluded from scanning', 'scanned 1 day ago; due again after a week', 'brand new', 'not Fire or Smoke (ice): x'])
        self.assertEqual([g['key'] for g in groups], ['not_fire_smoke', 'scanned_this_week', 'excluded', 'other'])
        self.assertEqual(ov.not_due_summary(groups), '4 not due: 1 not Fire or Smoke, 1 scanned this week, 1 excluded from scanning, 1 for other reasons')

    def test_nothing_not_due_says_nothing(self):
        self.assertEqual(ov.not_due_summary(ov.group_reasons([])), '')

    def test_no_wording_has_a_long_dash(self):
        words = ' '.join(w for _k, _m, w in ov.QUEUE_REASONS) + ov.OTHER_REASON[1]
        self.assertNotRegex(words, '[\u2013\u2014]')


class QueueTests(Fixture, TestCase):
    def setUp(self):
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)

    def overview(self):
        return ov.overview([self.project.id])

    def test_the_counts_and_the_summary_come_from_every_host_not_the_rows_shown(self):
        rows = [row(f'ok{i}.example.test', ready=True) for i in range(120)]
        rows += [row(f'ice{i}.example.test', 'not Fire or Smoke (ice): OpenVAS is only spent on hosts on fire or smoke') for i in range(130)]
        rows += [row(f'wk{i}.example.test', 'scanned 1 day ago; due again after a week') for i in range(7)]
        rows += [row('odd.example.test', 'a sentence from the future')]
        with mock.patch.object(ov, 'explain', return_value=rows):
            data = self.overview()
        self.assertEqual(data['counts'], {'next': 120, 'not_due': 138})
        self.assertEqual(data['not_due_summary'], '138 not due: 130 not Fire or Smoke, 7 scanned this week, 1 for other reasons')
        self.assertEqual([(g['key'], g['count']) for g in data['not_due_groups']], [('not_fire_smoke', 130), ('scanned_this_week', 7), ('other', 1)])
        self.assertEqual(len(data['not_due']), 12)  # the list is still capped, as before
        self.assertEqual(len(data['next']), 12)

    def test_two_projects_add_up(self):
        rows = [row('a.example.test', 'excluded from scanning'), row('b.example.test', 'excluded from scanning')]
        with mock.patch.object(ov, 'explain', return_value=rows), mock.patch.object(ov, 'links_for') as links:
            second = mock.Mock(project_id=991, project=mock.Mock(slug='second'))
            first = mock.Mock(project_id=990, project=mock.Mock(slug='first'))
            links.return_value = [first, second]
            data = ov.overview([990, 991])
        self.assertEqual(data['counts']['not_due'], 4)
        self.assertEqual(data['not_due_summary'], '4 not due: 4 excluded from scanning')

    def test_the_real_reasons_of_real_hosts(self):
        from cveFeed import ledger
        os.environ.setdefault('CVENGINE_HEAT_POLICY', 'legacy')
        with mock.patch.dict(os.environ, {'CVENGINE_HEAT_POLICY': 'legacy'}):
            self.link.hosts, self.link.forced_hosts = ['www.rt.test', 'api.rt.test', 'db.rt.test'], []
            self.link.save()
            hot = CVEEntry.objects.create(cve_id='CVE-2024-0002', title='High', published_at=timezone.now(), cvss=7.5)  # smoke under the legacy rule
            from startScan.models import Subdomain
            from cveFeed.models import CVEMatch
            for host in ('api.rt.test', 'db.rt.test'):
                sub = Subdomain.objects.filter(name=host).order_by('-scan_history_id').first()
                CVEMatch.objects.update_or_create(cve_entry=hot, subdomain=sub, matched_product='x', defaults={'confidence': 0.9, 'matched_version': '1'})
            ledger.record(ov.SERVICE, ['api.rt.test'], self.project.id)  # smoke, scanned just now
            ledger.record(ov.FAILED_SERVICE, ['db.rt.test'], self.project.id)  # smoke, failed just now
            data = self.overview()
        by = {g['key']: g['count'] for g in data['not_due_groups']}
        self.assertEqual(by, {'not_fire_smoke': 1, 'scanned_this_week': 1, 'failed_lately': 1})  # www is clean
        self.assertEqual(data['not_due_summary'], '3 not due: 1 not Fire or Smoke, 1 scanned this week, 1 failed or interrupted lately')
        self.assertEqual(data['counts']['not_due'], 3)


class QueueNeverWaitsTests(Fixture, TestCase):
    """The Sentinels page reads the kept OpenVAS explanation and never waits for a new one (``openvas_scan.queue_explained``)."""

    def setUp(self):
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        self.first = [row('a.example.test', 'excluded from scanning')]
        self.second = [row('a.example.test', 'excluded from scanning'), row('b.example.test', 'excluded from scanning')]

    def test_the_first_look_works_it_out_once_and_the_next_one_inside_a_minute_does_no_work(self):
        with mock.patch.object(ov, 'explain', return_value=self.first) as explain, mock.patch('cveFeed.tasks.refresh_openvas_queue.delay') as delay:
            self.assertEqual(ov.overview([self.project.id])['counts']['not_due'], 1)
            self.assertEqual(ov.overview([self.project.id])['counts']['not_due'], 1)
        self.assertEqual(explain.call_count, 1)
        delay.assert_not_called()

    def test_an_old_answer_is_shown_at_once_and_one_refresh_is_asked_for(self):
        with mock.patch.object(ov, 'explain', return_value=self.first):
            ov.overview([self.project.id])
        later = time.time() + ov.QUEUE_FRESH_SECONDS + 5
        with mock.patch.object(ov, 'explain', return_value=self.second) as explain, mock.patch('cveFeed.tasks.refresh_openvas_queue.delay') as delay, \
                mock.patch.object(ov.time, 'time', return_value=later):
            self.assertEqual(ov.overview([self.project.id])['counts']['not_due'], 1)  # the kept answer, no waiting
            self.assertEqual(ov.overview([self.project.id])['counts']['not_due'], 1)
        explain.assert_not_called()
        delay.assert_called_once_with(self.project.id)  # one refresh, not one per poll

    def test_the_refresh_replaces_the_answer_and_frees_the_next_one(self):
        with mock.patch.object(ov, 'explain', return_value=self.first):
            ov.overview([self.project.id])
        cache.add(f'{ov._queue_key(self.project.id)}:refreshing', 1, 300)
        with mock.patch.object(ov, 'explain', return_value=self.second):
            from cveFeed.tasks import refresh_openvas_queue
            refresh_openvas_queue(self.project.id)
        self.assertIsNone(cache.get(f'{ov._queue_key(self.project.id)}:refreshing'))
        self.assertEqual(ov.overview([self.project.id])['counts']['not_due'], 2)

    def test_a_broker_that_cannot_be_reached_still_shows_the_page(self):
        with mock.patch.object(ov, 'explain', return_value=self.first):
            ov.overview([self.project.id])
        with mock.patch('cveFeed.tasks.refresh_openvas_queue.delay', side_effect=OSError('broker down')), \
                mock.patch.object(ov.time, 'time', return_value=time.time() + 120):
            self.assertEqual(ov.overview([self.project.id])['counts']['not_due'], 1)
        self.assertIsNone(cache.get(f'{ov._queue_key(self.project.id)}:refreshing'))  # asked again at the next poll

    def test_a_project_no_longer_opted_in_drops_its_kept_answer(self):
        cache.set(ov._queue_key(424242), {'at': 0, 'value': {'rows': [], 'ready': 0, 'refused': 0, 'groups': []}}, 60)
        self.assertIsNone(ov.refresh_queue(424242))
        self.assertIsNone(cache.get(ov._queue_key(424242)))
