"""A DNS lookup the resolver could not answer is an error, never a host with no address."""
from unittest import mock

from django.test import TestCase

from cveFeed import discovery, unresolved_archive
from tests.fake_scanner import FakeScanner


def busy(*answers):
    """A fake Sentinel that answers ``answers`` by name (an address) and cannot answer any other name: a temporary resolver failure, for the
    name lookups (``dns_resolve``) and the address reads (``identity_check``) alike."""
    table = dict(answers)

    def resolve(task):
        names = task['target']['names']
        return {'outcome': 'done', 'resolved': {n: [table[n]] for n in names if n in table},
                'errors': {n: 'gaierror: Temporary failure in name resolution' for n in names if n not in table}, 'refused': []}

    def identity(task):
        return {'outcome': 'done', 'touched': [], 'refused': [], 'certs': [],
                'dns': [({'id': q['id'], 'status': 'ok', 'records': [table[q['name']]]} if q['name'] in table else
                         {'id': q['id'], 'status': 'unknown', 'records': [], 'error': 'Timeout'}) for q in task['target'].get('dns', [])]}
    return FakeScanner(kinds=['dns_resolve', 'identity_check'], responders={'dns_resolve': resolve, 'identity_check': identity})


from datetime import timedelta  # noqa: E402

from cveFeed import changes  # noqa: E402
from cveFeed.models import AssetChange, HostState  # noqa: E402
from tests.test_changes import ChangeFixture  # noqa: E402
from tests.test_sentinel_feed import Base  # noqa: E402


class RecheckCallerTests(Base):
    def test_recheck_leaves_the_streak_of_a_host_the_resolver_could_not_answer(self):
        sub = self.host('busy', unresolved=2, last=self.now - timedelta(days=1), note='no DNS answer')
        with busy():
            out = unresolved_archive.recheck(self.now)
        state = HostState.objects.get(host=sub.name)
        self.assertEqual((out['checked'], out['dns_errors'], out['no_dns']), (1, 1, 0))
        self.assertEqual((state.unresolved_checks, state.resolution_note), (2, 'no DNS answer'))
        self.assertEqual(state.unresolved_last_at, self.now - timedelta(days=1))  # untouched: it is asked again at the next pass


class RetireCallerTests(ChangeFixture, TestCase):
    def test_a_missing_host_is_not_retired_when_its_lookup_was_not_answered(self):
        changes.record_scan_changes(self.baseline().id)
        second = self.scan({'a.ct.test': {'ip': '203.0.113.5', 'ports': [(443, 'https', 'nginx', '1.18.0')], 'techs': ['nginx']}})
        with busy():
            out = changes.record_scan_changes(second.id)
        self.assertEqual(out['retired'], 0)
        self.assertFalse(AssetChange.objects.filter(kind='host_retired').exists())
        self.assertIsNone(HostState.objects.get(host='b.ct.test').retired_at)


class HostPipelineCallerTests(ChangeFixture, TestCase):
    def setUp(self):
        super().setUp()
        mock.patch('reNgine.tasks.geo_localize.delay').start()
        mock.patch('cveFeed.tasks.run_hygiene_task.delay').start()
        self.addCleanup(mock.patch.stopall)

    def test_when_every_lookup_fails_the_run_says_so_and_records_no_host(self):
        from startScan.models import ScanHistory, Subdomain
        with busy():
            out = discovery.run_host_pipeline(self.domain.id, ['new.ct.test', 'other.ct.test'])
        self.assertEqual(out['status'], 'inconclusive')
        self.assertIn('DNS could not answer', out['error'])
        self.assertEqual(ScanHistory.objects.get(pk=out['scan_id']).scan_status, discovery.FAILED)
        self.assertFalse(Subdomain.objects.filter(name__in=['new.ct.test', 'other.ct.test']).exists())  # not stored as hosts with no address

    def test_a_partial_failure_records_only_what_was_answered(self):
        from startScan.models import Subdomain
        from tests.test_changes import _stages
        _, kwargs = _stages()
        kwargs.pop('resolver', None)  # the fake Sentinel resolves
        with busy(('new.ct.test', '203.0.113.9')):
            out = discovery.run_host_pipeline(self.domain.id, ['new.ct.test', 'other.ct.test'], **kwargs)
        self.assertEqual(out['lookup_errors'], 1)
        self.assertTrue(Subdomain.objects.filter(name='new.ct.test').exists())
        self.assertFalse(Subdomain.objects.filter(name='other.ct.test').exists())
