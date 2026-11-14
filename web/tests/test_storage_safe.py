"""A NUL or a lone surrogate from a scanned host must never make Postgres refuse a Sentinel's result (review 2 of 2026-11-09, P1 and P2).

Before: probe and route evidence copied header and URL text with the characters in it, and the write of the whole ``SentinelTask.result`` failed with
``DataError``; the Sentinel sent the same result again until the task's lease ran out."""
from django.db import DataError, transaction
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import probe_results, storage_safe
from agentapi.models import SentinelTask
from dashboard.models import Org, Project
from reNgine.ai_providers import clean_text


class StorageSafeTests(SimpleTestCase):
    def test_a_nul_is_dropped_and_a_lone_surrogate_is_replaced(self):
        self.assertEqual(storage_safe.text('a\x00b'), 'ab')
        self.assertEqual(storage_safe.text('x\ud800y'), 'x\ufffdy')
        self.assertEqual(storage_safe.text('plain \u00e9 \U0001f600'), 'plain \u00e9 \U0001f600')  # a real pair is not a lone surrogate

    def test_it_reaches_nested_values_and_keys_and_leaves_the_rest_alone(self):
        value = {'a\x00': ['b\ud83d', {'c': 'd\x00e', 'n': 3, 'f': 1.5, 'ok': True, 'none': None}], 'k': ('t\x00',)}
        self.assertEqual(storage_safe.clean(value), {'a': ['b\ufffd', {'c': 'de', 'n': 3, 'f': 1.5, 'ok': True, 'none': None}], 'k': ['t']})

    def test_a_document_nested_past_the_limit_is_cut_not_followed(self):
        deep = cur = {}
        for _ in range(storage_safe.MAX_DEPTH + 5):
            cur['x'] = {}
            cur = cur['x']
        out = storage_safe.clean(deep)
        depth = 0
        while isinstance(out, dict) and out.get('x') is not None:
            out = out['x']
            depth += 1
        self.assertLessEqual(depth, storage_safe.MAX_DEPTH)

    def test_clean_text_no_longer_lets_a_surrogate_through(self):
        self.assertEqual(clean_text('banner \ud800 x', 50), 'banner x')
        self.assertEqual(clean_text('a\x00b', 20), 'ab')


class StoredResultTests(TestCase):
    def setUp(self):
        org = Org.objects.create(name='O', slug='o-storage-safe')
        self.project = Project.objects.create(name='P', slug='p-storage-safe', insert_date=timezone.now(), org=org)
        self.task = SentinelTask.objects.create(project=self.project, kind='route_probe', target={}, host='www.example.com')

    def _store(self, result):
        with transaction.atomic():
            SentinelTask.objects.filter(pk=self.task.pk).update(result=result)

    def test_postgres_refuses_the_raw_text_which_is_why_it_is_cleaned(self):
        with self.assertRaises(DataError):
            self._store({'outcome': 'done', 'routes': [{'evidence': {'headers': {'x-test': 'a\x00b'}}}]})

    def test_the_cleaned_result_is_stored(self):
        ev = probe_results._route_evidence({'headers': {'x-test': 'a\x00b'}})  # cleaned on the way in now
        lib = probe_results._evidence({'library': {'url': 'https://h/x\x00.js', 'banner': 'v\ud800'}})
        self._store(storage_safe.clean({'outcome': 'done', 'routes': [{'evidence': ev}], 'observations': [{'evidence': lib}]}))
        stored = SentinelTask.objects.get(pk=self.task.pk).result
        self.assertEqual(stored['routes'][0]['evidence']['headers']['x-test'], 'ab')
        self.assertEqual(stored['observations'][0]['evidence']['library']['url'], 'https://h/x.js')
        self.assertEqual(stored['observations'][0]['evidence']['library']['banner'], 'v\ufffd')


class ProbeEvidenceTests(SimpleTestCase):
    def test_evidence_with_a_lone_surrogate_is_measured_and_kept_clean_instead_of_raising(self):
        # before: UnicodeEncodeError out of ``_evidence`` (the size check encodes to UTF-8), a 500 for the report that carried it
        ev = probe_results._evidence({'library': {'url': 'https://h/x\x00.js', 'banner': 'v\ud800'}})
        self.assertEqual(ev, {'library': {'url': 'https://h/x.js', 'banner': 'v\ufffd'}})


class ThroughTheBrokerTests(SimpleTestCase):
    def test_a_route_probe_result_with_hostile_header_text_is_cleaned_before_it_is_stored(self):
        from agentapi import sentinel_broker as broker
        from tests.fake_scanner import fixture
        good = fixture('route_probe')['routes'][0]
        evidence = {**good['evidence'], 'headers': {'x-a\x00': 'b\x00c', 'x-b': 'v\ud800'}}
        got = broker.clean_result('route_probe', {**fixture('route_probe'), 'routes': [{**good, 'evidence': evidence}]})['routes'][0]['evidence']
        self.assertEqual(got['headers'], {'x-a': 'bc', 'x-b': 'v\ufffd'})
        import json
        json.dumps(got).encode('utf-8')  # a lone surrogate would raise here
