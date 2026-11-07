"""The ``page_read`` kind: a validation re-test's HEAD of a URL and re-read of a host's pages and scripts, asked of a Sentinel (cvENGINE-sentinel's
``cvengine_scanner.probes.page_read``, tested there) and never sent from this server.

Held here: what the server keeps of a result (``probe_results.clean_page_read``), the scope policy it sends (``probe_scope.for_page_read``: the rules a
redirect hop or a script read is held to now live in the task, not in a local fetch), the checks end to end through the fake built-in scanner with
``CVENGINE_LOCAL_FALLBACK=none`` (nothing may run here), and the checks with no scanner able to take them (``failed``: retried later, never clean).
"""
from unittest import mock

from django.test import SimpleTestCase, TestCase

from agentapi import probe_results, sentinel_broker
from agentapi.services import ApiError
from cveFeed import probe_scope, validation
from cveFeed.models import CVEMatch
from cveFeed import triage
from startScan.models import Subdomain
from targetApp.models import Domain
from tests import page_read_double
from tests.fake_scanner import FakeScanner, LocalFallback, assert_ran_nowhere_locally, fixture
from tests.test_client_library_validation import Base, jquery_site


class CleanResultTests(SimpleTestCase):
    def clean(self, body):
        return sentinel_broker.clean_result('page_read', {'outcome': 'done', **body}, None)

    def test_the_contract_fixture_is_kept_whole(self):
        got = self.clean(fixture('page_read'))
        (head, libraries) = got['reads']
        self.assertEqual(head['head'], {'status': 200, 'method': 'HEAD', 'server': 'nginx/1.24.0', 'powered_by': '', 'title': ''})
        (page,) = libraries['reading']['pages']
        self.assertEqual((page['outcome'], page['records']['jquery']['version'], page['read_whole']), ('read', '3.6.0', 1))
        self.assertEqual((got['touched'], got['refused']), (['www.example.com'], []))

    def test_a_read_with_neither_an_answer_nor_an_error_is_an_error_not_a_state(self):
        (row,) = self.clean({'reads': [{'id': 'x'}]})['reads']
        self.assertIn('neither an answer nor an error', row['error'])

    def test_a_read_the_scanner_could_not_make_keeps_its_error_only(self):
        (row,) = self.clean({'reads': [{'id': 'x', 'error': 'OSError: reset', 'head': {'status': 200}}]})['reads']
        self.assertEqual(row, {'id': 'x', 'error': 'OSError: reset'})

    def test_a_page_with_an_outcome_outside_the_list_is_dropped_and_a_record_that_is_too_large_is_emptied(self):
        reading = {'pages': [{'outcome': 'victory', 'status': 200},
                             {'outcome': 'read', 'status': 200, 'records': {'jquery': {'version': 'x' * 40_000}, 'Bad Key!': {'version': '1'}, 'lodash': {'version': '4'}}}]}
        (row,) = self.clean({'reads': [{'id': 'x', 'reading': reading}]})['reads']
        (page,) = row['reading']['pages']
        self.assertEqual(page['records'], {'jquery': {}, 'lodash': {'version': '4'}})

    def test_a_status_that_is_not_a_number_is_none_and_only_the_three_headers_are_kept(self):
        (row,) = self.clean({'reads': [{'id': 'x', 'head': {'status': 'ok', 'method': 'POST', 'server': 's' * 1000, 'cookie': 'secret', 'body': '<html>'}}]})['reads']
        self.assertEqual(row['head']['status'], None)
        self.assertEqual((row['head']['method'], len(row['head']['server']), set(row['head'])), ('HEAD', 300, {'status', 'method', 'server', 'powered_by', 'title'}))

    def test_more_reads_than_the_contract_allows_is_refused(self):
        with self.assertRaises(ApiError):
            self.clean({'reads': [{'id': str(n), 'error': 'x'} for n in range(probe_results.MAX_READS + 1)]})


class PolicyTests(Base):
    """The rules the server's own local read used at every hop (the bug bounty program, a one-host target, the project's exclusions) are sent to the Sentinel
    as the task's scope: a host listed there may be asked, one in ``excluded`` never."""

    def scope(self, m, **kw):
        sub = Subdomain.objects.select_related('target_domain').get(pk=m.subdomain_id)
        return probe_scope.for_page_read(self.project.id, sub, **kw)

    def test_the_host_its_apex_and_www_twin_and_the_library_cdns_are_listed(self):
        m = self.match()
        hosts = self.scope(m)['hosts']
        self.assertEqual(hosts[0], 'www.v.test')
        self.assertIn('cdnjs.cloudflare.com', hosts)

    def test_a_host_scoped_target_reads_its_own_host_only(self):
        Domain.objects.filter(pk=self.domain.pk).update(name='www.v.test', scope_mode=Domain.SCOPE_HOST)
        m = self.match()
        hosts = self.scope(m)['hosts']
        self.assertEqual(hosts[0], 'www.v.test')
        self.assertNotIn('v.test', hosts)

    def test_a_host_outside_the_bug_bounty_scope_is_excluded_not_listed_and_is_asked_at_every_name(self):
        m = self.match()
        asked = []

        def refusal(_self, project_id, host=None, unattended=True, derived=False):
            asked.append((host, unattended))
            return 'not in the program scope' if host == 'v.test' else ''
        with mock.patch('cveFeed.bounty_gate.Gate.refusal', refusal):
            scope = self.scope(m)
        self.assertIn('v.test', scope['excluded'])
        self.assertNotIn('v.test', scope['hosts'])
        self.assertIn(('v.test', True), asked)

    def test_a_person_s_own_request_is_held_to_the_programs_confirmation_too(self):
        m = self.match()
        asked = []
        with mock.patch('cveFeed.bounty_gate.Gate.refusal', lambda _self, project_id, host=None, unattended=True, derived=False: asked.append(unattended) or ''):
            self.scope(m, unattended=False)
        self.assertEqual(set(asked), {False})

    def test_an_excluded_host_is_never_listed(self):
        m = self.match()
        with mock.patch('cveFeed.bounty_gate.Gate.refusal', lambda _self, project_id, host=None, unattended=True, derived=False: 'excluded' if host == 'www.v.test' else ''):
            scope = self.scope(m)
        self.assertNotIn('www.v.test', scope['hosts'])
        self.assertIn('www.v.test', scope['excluded'])


class EndToEndTests(Base):
    """The two checks through the fake built-in scanner: the task a Sentinel gets, what the check does with its answer, and nothing run here."""

    def setUp(self):
        super().setUp()
        LocalFallback('none').apply(self)
        self.guard = assert_ran_nowhere_locally(self, 'page_read')

    def check(self, m):
        (row, _d), = triage.track(triage.with_cves(CVEMatch.objects.select_related('subdomain__target_domain')))
        return validation._script_read_check({**validation.subject_for(row, triage.load_findings([row])[0]), 'project_id': self.project.id}, row.signature)

    def libraries_answer(self, task):
        (read,) = task['target']['reads']
        site = jquery_site('3.6.0')
        return {'outcome': 'done', 'touched': [read['host']], 'refused': [], 'reads': [page_read_double.reading_row(site, read)]}

    def test_the_script_read_is_a_page_read_task_with_the_hosts_bases_and_scope(self):
        m = self.match()
        with FakeScanner(kinds=['page_read'], responders={'page_read': self.libraries_answer}) as fake:
            result = validation.run_script_read(self.check(m))
        (served,) = fake.served
        (read,) = served['target']['reads']
        self.assertEqual((served['kind'], read['op'], read['host'], read['library']), ('page_read', 'libraries', 'www.v.test', 'jquery'))
        self.assertEqual(read['bases'], ['https://www.v.test'])
        self.assertEqual(served['target']['scope']['hosts'][0], 'www.v.test')
        self.assertEqual(self.guard.calls, [])
        self.assertEqual(result['status'], 'observed')

    def test_the_http_head_is_a_page_read_task_and_keeps_what_the_scanner_read(self):
        self.match()
        row = {'status': 200, 'method': 'HEAD', 'server': 'nginx/1.24.0', 'powered_by': 'PHP/8.1', 'title': ''}

        def answer(task):
            (read,) = task['target']['reads']
            return {'outcome': 'done', 'touched': [read['host']], 'refused': [], 'reads': [{'id': read['id'], 'head': row}]}
        check = {'kind': 'http_head', 'target': 'https://www.v.test/', 'params': {'url': 'https://www.v.test/', 'project_id': self.project.id}}
        with FakeScanner(kinds=['page_read'], responders={'page_read': answer}) as fake:
            result = validation.run_http_head(check)
        (served,) = fake.served
        self.assertEqual(served['target']['reads'][0]['op'], 'head')
        self.assertEqual((result['status'], result['observed'], result['http']), ('observed', {'product': 'nginx', 'version': '1.24.0'}, {'status': 200, 'method': 'HEAD'}))
        self.assertIn('X-Powered-By: PHP/8.1', result['output_excerpt'])
        self.assertEqual(self.guard.calls, [])

    def test_a_read_the_scanner_could_not_make_fails_the_check_never_reads_it_as_clean(self):
        m = self.match()

        def answer(task):
            (read,) = task['target']['reads']
            return {'outcome': 'done', 'touched': [], 'refused': [], 'reads': [{'id': read['id'], 'error': 'OSError: refused'}]}
        with FakeScanner(kinds=['page_read'], responders={'page_read': answer}):
            result = validation.run_script_read(self.check(m))
        self.assertEqual((result['status'], 'refused' in result['error']), ('failed', True))

    def test_with_no_scanner_able_to_take_it_the_check_is_failed_and_nothing_is_sent_from_here(self):
        m = self.match()
        result = validation.run_script_read(self.check(m))
        self.assertEqual((result['status'], self.guard.calls), ('failed', []))
        self.assertIn('no scanner', result['summary'])
        head = validation.run_http_head({'kind': 'http_head', 'target': 'x', 'params': {'url': 'https://www.v.test/', 'project_id': self.project.id}})
        self.assertEqual((head['status'], self.guard.calls), ('failed', []))

    def test_a_scanner_that_is_offline_leaves_the_check_failed_and_retryable(self):
        m = self.match()
        with FakeScanner(kinds=['page_read'], mode='offline'):
            result = validation.run_script_read(self.check(m))
        self.assertEqual((result['status'], self.guard.calls), ('failed', []))

    def test_a_host_that_left_the_inventory_is_not_read(self):
        m = self.match()
        check = self.check(m)
        check['params']['host'] = 'gone.v.test'
        with FakeScanner(kinds=['page_read']) as fake:
            result = validation.run_script_read(check)
        self.assertEqual((result['status'], fake.served), ('failed', []))

    def test_one_host_read_for_three_matches_is_asked_of_the_scanner_once(self):
        m = self.match()
        with FakeScanner(kinds=['page_read'], responders={'page_read': self.libraries_answer}) as fake:
            for _ in range(3):
                validation.run_script_read(self.check(m))
        self.assertEqual(fake.served_kinds(), ['page_read'])

    def test_a_person_s_own_validate_now_reads_again(self):
        m = self.match()
        check = self.check(m)
        check['params']['unattended'] = False
        with FakeScanner(kinds=['page_read'], responders={'page_read': self.libraries_answer}) as fake:
            for _ in range(2):
                validation.run_script_read(check)
        self.assertEqual(fake.served_kinds(), ['page_read', 'page_read'])
