"""A DNS lookup the resolver could not answer is an error, never a host with no address."""
import socket
from unittest import mock

from django.test import SimpleTestCase, TestCase

from cveFeed import discovery, unresolved_archive


def lookup(table):
    """A ``socket.getaddrinfo`` answering from ``table``: an address list, or an exception to raise."""
    def get(name, *a, **k):
        answer = table[name]
        if isinstance(answer, Exception):
            raise answer
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 0)) for ip in answer]
    return get


class ResolveNamesTests(SimpleTestCase):
    def resolve(self, table, **kw):
        errors = {}
        with mock.patch('socket.getaddrinfo', lookup(table)):
            pairs = discovery.resolve_names(list(table), errors=errors, **kw)
        return pairs, errors

    def test_a_name_with_no_record_is_absent_and_not_an_error(self):
        pairs, errors = self.resolve({'ok.rt.test': ['203.0.113.5'], 'gone.rt.test': socket.gaierror(socket.EAI_NONAME, 'Name or service not known')})
        self.assertEqual(pairs, {('ok.rt.test', '203.0.113.5')})
        self.assertEqual(errors, {})

    def test_a_temporary_resolver_failure_is_an_error_not_a_missing_host(self):
        pairs, errors = self.resolve({'ok.rt.test': ['203.0.113.5'], 'busy.rt.test': socket.gaierror(socket.EAI_AGAIN, 'Temporary failure in name resolution')})
        self.assertEqual(pairs, {('ok.rt.test', '203.0.113.5')})
        self.assertEqual(list(errors), ['busy.rt.test'])
        self.assertIn('gaierror', errors['busy.rt.test'])

    def test_a_lookup_that_does_not_answer_in_time_is_an_error(self):
        import threading
        release = threading.Event()

        def slow(name, *a, **k):
            release.wait(5)
            return []
        errors = {}
        with mock.patch('socket.getaddrinfo', slow):
            pairs = discovery.resolve_names(['slow.rt.test'], timeout=0.05, errors=errors)
        release.set()
        self.assertEqual(pairs, set())
        self.assertIn('slow.rt.test', errors)
        self.assertIn('no answer within', errors['slow.rt.test'])

    def test_the_old_call_without_errors_still_returns_the_pairs(self):
        with mock.patch('socket.getaddrinfo', lookup({'ok.rt.test': ['203.0.113.5'], 'busy.rt.test': socket.gaierror(socket.EAI_AGAIN, 'x')})):
            self.assertEqual(discovery.resolve_names(['ok.rt.test', 'busy.rt.test']), {('ok.rt.test', '203.0.113.5')})

    def test_a_failure_is_logged_not_swallowed(self):
        with mock.patch('socket.getaddrinfo', lookup({'busy.rt.test': socket.gaierror(socket.EAI_AGAIN, 'x')})):
            with self.assertLogs('cveFeed.discovery', level='WARNING') as logs:
                discovery.resolve_names(['busy.rt.test'])
        self.assertIn('could not be answered for 1 of 1', logs.output[0])


def busy(*answers):
    """getaddrinfo that answers ``answers`` by name and fails every other name as a temporary resolver failure."""
    table = dict(answers)

    def get(name, *a, **k):
        if name in table:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (table[name], 0))]
        raise socket.gaierror(socket.EAI_AGAIN, 'Temporary failure in name resolution')
    return mock.patch('socket.getaddrinfo', get)


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
        kwargs.pop('resolver', None)  # the real resolver runs, against the patched getaddrinfo
        with busy(('new.ct.test', '203.0.113.9')):
            out = discovery.run_host_pipeline(self.domain.id, ['new.ct.test', 'other.ct.test'], **kwargs)
        self.assertEqual(out['lookup_errors'], 1)
        self.assertTrue(Subdomain.objects.filter(name='new.ct.test').exists())
        self.assertFalse(Subdomain.objects.filter(name='other.ct.test').exists())
