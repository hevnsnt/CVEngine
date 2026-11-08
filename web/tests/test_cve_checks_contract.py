"""run_cve_checks and templategen.run_cve_tests share one contract: ``run_cve_tests(cve, hosts, ai=False, project=None)``.

``ai`` says whether an AI reviewer job may be queued for a CVE without a safe installed template; no provider object travels any
more (AI reviewer phase 2: the reviewer container writes the draft). Every other test injects a fake ``cve_runner`` that takes
``**kw``, which hid the day ``run_cve_checks`` kept passing ``provider=`` to the real function: every per-CVE check raised TypeError,
was caught by the one-CVE-must-not-stop-the-rest handler and recorded ``failed``. These tests use the REAL signature.
"""
import ast
import inspect
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import ledger, nuclei_scan, templategen
from cveFeed.models import CVEEntry, CVEMatch, ServiceRun
from startScan.models import Subdomain
from tests.fake_scanner import FakeScanner, LocalFallback, assert_ran_nowhere_locally
from tests.test_changes import ChangeFixture
from tests.test_fake_scanner import NoRealSleep
from tests.test_route_auth import RouteFixture

HOST = {'ip': '203.0.113.5', 'ports': [(443, 'https', 'nginx', '1.18.0')], 'techs': ['nginx']}
TEMPLATE = json.loads((Path(__file__).with_name('fixtures') / 'sentinel_targets' / 'nuclei_validate.json').read_text())['template']
WEB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def strict_runner(seen=None):
    """A cve_runner that refuses any call the real ``run_cve_tests`` would refuse."""
    real = inspect.signature(templategen.run_cve_tests)

    def runner(*args, **kwargs):
        real.bind(*args, **kwargs)  # TypeError, exactly as the real function raises it
        if seen is not None:
            seen.append((args, kwargs))
        host = args[1][0]
        return {'source': 'existing', 'results': [{'host': h, 'vulnerable': False} for h in args[1]]}
    return runner


class CveChecksFixture(ChangeFixture):
    def setUp(self):
        super().setUp()
        self.scan_ = self.scan({'www.ct.test': HOST})
        self.sub = Subdomain.objects.get(scan_history=self.scan_)
        self.cve = CVEEntry.objects.create(cve_id='CVE-2099-7', kev=True, cvss=9.8, title='t', published_at=timezone.now())
        CVEMatch.objects.create(cve_entry=self.cve, subdomain=self.sub, confidence=0.9)
        self.service = nuclei_scan.cve_service('CVE-2099-7')

    def rows(self):
        return list(ServiceRun.objects.filter(service=self.service).values_list('asset', 'status'))


class RunCveChecksContractTests(CveChecksFixture, TestCase):
    def test_the_call_binds_to_the_real_run_cve_tests_signature(self):
        seen = []
        out = nuclei_scan.run_cve_checks(self.scan_, [self.sub], False, cve_runner=strict_runner(seen))
        self.assertEqual(self.rows(), [('www.ct.test', 'done')])
        self.assertEqual(out['not_tested'], 0)
        (args, kwargs), = seen
        self.assertEqual(kwargs, {'ai': False, 'project': self.project.id})

    def test_ai_is_passed_through_as_ai(self):
        seen = []
        nuclei_scan.run_cve_checks(self.scan_, [self.sub], True, cve_runner=strict_runner(seen))
        self.assertIs(seen[0][1]['ai'], True)

    def test_the_default_runner_is_the_real_one_and_the_real_path_records_done(self):
        """No injected runner: run_cve_tests itself runs, the Sentinel dispatch (``_test_chunk``) is stubbed."""
        def chunk(path, hosts, project=None):
            return [{'host': h, 'vulnerable': False} for h in hosts]
        with mock.patch('cveFeed.validation.resolve_template', return_value=('/t/CVE-2099-7.yaml', '')), \
                mock.patch.object(templategen, 'evidence_of_template', return_value='flaw'), \
                mock.patch.object(templategen, '_test_chunk', side_effect=chunk) as ran, \
                mock.patch.object(templategen, 'record_outcomes'), \
                mock.patch('cveFeed.validation.record_template_outcomes'), \
                mock.patch('targetApp.target_types.scannable_hosts', side_effect=lambda hosts, project=None: list(hosts)), \
                mock.patch('cveFeed.nuclei_scan.logger') as log:
            out = nuclei_scan.run_cve_checks(self.scan_, [self.sub], False)
        ran.assert_called_once()
        log.exception.assert_not_called()  # the old failure was logged here: "CVE check ... failed"
        self.assertEqual((out['hosts'], out['not_tested']), (1, 0))
        self.assertEqual(self.rows(), [('www.ct.test', 'done')])

    def test_run_targeted_nuclei_passes_ai_only_when_a_provider_is_in_use_and_the_queue_is_on(self):
        got = []
        for provider, ai_on, expected in ((None, True, False), (object(), False, False), (object(), True, True)):
            with mock.patch('cveFeed.ai_jobs.ai_on', return_value=ai_on), \
                    mock.patch.object(nuclei_scan, 'run_cve_checks', side_effect=lambda scan, subs, ai, *a, **k: got.append(ai) or
                                      {'cves': 0, 'hosts': 0, 'vulnerable': []}), \
                    mock.patch('cveFeed.nuclei_templates.plan_targeting', return_value=([], [])):
                nuclei_scan.run_targeted_nuclei(self.scan_.id, stream=lambda *a, **k: iter([]), provider=provider)
            self.assertIs(got[-1], expected)

    def test_a_failed_ledger_row_is_retried_at_the_next_sweep_and_becomes_done(self):
        """The ledger design: ``ledger.fresh`` counts only ``done`` rows, so a ``failed`` row is due again and is overwritten."""
        ledger.record(self.service, ['www.ct.test'], self.project, self.scan_, 'failed')
        self.assertEqual(ledger.fresh(self.service, ['www.ct.test'], self.project), set())
        seen = []
        nuclei_scan.run_cve_checks(self.scan_, [self.sub], False, cve_runner=strict_runner(seen))
        self.assertEqual(len(seen), 1)
        self.assertEqual(self.rows(), [('www.ct.test', 'done')])


class ThroughTheFakeSentinelTests(NoRealSleep, RouteFixture, TestCase):
    """run_cve_checks -> the real run_cve_tests -> run_template -> sentinel_dispatch -> a fake Sentinel serving ``nuclei_validate``.
    Nothing between the scan and the scanner is stubbed except the choice of template file (an installed community template)."""

    def test_the_check_reaches_the_sentinel_and_the_ledger_says_done(self):
        LocalFallback('none').apply(self)
        self.no_real_sleep()
        mock.patch('agentapi.sentinel_dispatch._resolves', return_value=True).start()
        assert_ran_nowhere_locally(self, 'nuclei_validate')
        scan = self.scan()
        sub = Subdomain.objects.get(scan_history=scan)
        cve = CVEEntry.objects.create(cve_id='CVE-2099-8', kev=True, cvss=9.8, title='t', published_at=timezone.now())
        CVEMatch.objects.create(cve_entry=cve, subdomain=sub, confidence=0.9)
        service = nuclei_scan.cve_service('CVE-2099-8')
        answer = lambda task: {'outcome': 'done', 'outcomes': [{'host': h, 'vulnerable': False, 'output': ''} for h in task['target']['targets']]}  # noqa: E731
        with mock.patch('cveFeed.validation.resolve_template', return_value=('/t/cve-2099-8.yaml', '')), \
                mock.patch('cveFeed.validation.approved_template', return_value=(TEMPLATE, '')), \
                mock.patch.object(templategen, 'record_outcomes'), mock.patch('cveFeed.validation.record_template_outcomes'), \
                mock.patch('cveFeed.nuclei_scan.logger') as log, \
                FakeScanner(kinds=['nuclei_validate'], responders={'nuclei_validate': answer}) as fake:
            out = nuclei_scan.run_cve_checks(scan, [sub], False)
        log.exception.assert_not_called()
        self.assertEqual(len(fake.served), 1)
        self.assertEqual((out['hosts'], out['not_tested']), (1, 0))
        self.assertEqual(list(ServiceRun.objects.filter(service=service).values_list('asset', 'status')), [('www.rt.test', 'done')])


class CallSitesBindTests(SimpleTestCase):
    """No non-test caller passes a keyword or an argument count the real function does not accept (the drift of AI reviewer
    phase 2, commit 58966d7, which changed these signatures). Found by name over the whole web tree, tests and fakes excluded."""

    def functions(self):
        from cveFeed import detection_author, nuclei_scan as ns, rdp_shot, templategen as tg, validation_plan
        found = {f.__name__: f for f in (tg.run_cve_tests, tg.generate_template, ns.run_cve_checks, ns.run_targeted_nuclei,
                                        detection_author.author_with_ai, detection_author.author_pending, detection_author.enrich_with_ai,
                                        detection_author.revise_with_guidance, rdp_shot.run_for_scan, rdp_shot.queue_reading)}
        found['cve_runner'] = tg.run_cve_tests  # run_cve_checks' injected runner defaults to it: the call that drifted
        return found

    def calls(self):
        for root, dirs, files in os.walk(WEB):
            dirs[:] = [d for d in dirs if d not in ('tests', 'migrations', 'node_modules', 'staticfiles', 'static')]
            for name in files:
                if not name.endswith('.py'):
                    continue
                path = os.path.join(root, name)
                tree = ast.parse(open(path, encoding='utf-8').read(), path)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        fn = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, 'id', None)
                        yield path, fn, node

    def test_every_call_site_binds_to_the_real_signature(self):
        funcs = self.functions()
        # a module's own helper of the same name is not this function: only these owners' modules are checked per name
        checked, bad = {}, []
        for path, fn, node in self.calls():
            if fn not in funcs or any(isinstance(a, ast.Starred) for a in node.args) or any(k.arg is None for k in node.keywords):
                continue
            if fn == 'run_for_scan' and os.path.basename(path) != 'discovery.py':
                continue
            if fn == 'run_for_scan':  # discovery calls several stages' run_for_scan: only the rdp one is this function
                if 'rdp_shot.run_for_scan' not in ast.unparse(node.func):
                    continue
            sig = inspect.signature(funcs[fn])
            try:
                sig.bind(*[None] * len(node.args), **{k.arg: None for k in node.keywords})
            except TypeError as exc:
                bad.append(f'{os.path.relpath(path, WEB)}:{node.lineno} {fn}: {exc}')
            checked[fn] = checked.get(fn, 0) + 1
        self.assertEqual(bad, [])
        for must in ('run_cve_tests', 'run_cve_checks', 'run_targeted_nuclei', 'generate_template'):
            self.assertGreaterEqual(checked.get(must, 0), 1, f'no call site of {must} found: the scan is broken')
