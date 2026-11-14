"""The WPScan API token never reaches a log, an activity record, a stored row or a returned value, however the runner fails.

CodeQL traced its clear-text-logging alerts back to the token (``wpscan_scan.api_token``); the code redacts it everywhere the failure text goes. This
holds that: the token is configured, the runner fails every way that carries text (non-zero exit with the token echoed on stderr, an exception that
contains it, a timeout, a block, an unreachable site), and the token is looked for in all captured log records, the activity feed, every row the
scan stored and the stage's return value."""
import json
import logging
from unittest import mock

from django.apps import apps
from django.test import TestCase

from cveFeed import wpscan_scan
from dashboard.models import ApiCredential
from startScan.models import Subdomain, Technology
from tests import test_wpscan
from tests.test_route_auth import RouteFixture

TOKEN = 'wpsTOKEN-9f3a7c1d2b8e4a60'


class Collect(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())
        if record.exc_info:
            self.lines.append(logging.Formatter().formatException(record.exc_info))


def classified(returncode, stderr, report=None):
    def run(url, token):
        wpscan_scan._classify(report, returncode, stderr, token)
        return {}
    return run


class TokenNeverShowsTests(RouteFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.scan_obj = self.scan(names=('www.rt.test', 'plain.rt.test'))
        wp = Subdomain.objects.get(scan_history=self.scan_obj, name='www.rt.test')
        wp.technologies.add(Technology.objects.create(name='WordPress'))
        test_wpscan.StageTests.start_scanner(self)
        ApiCredential.objects.create(project=self.project, service='wpscan', value={'api_key': TOKEN})
        self.assertEqual(wpscan_scan.api_token(self.project), TOKEN)

    def stored(self):
        rows = []
        for model in apps.get_models():
            if model._meta.app_label in ('cveFeed', 'startScan', 'agentapi') and model is not ApiCredential:
                rows.append(json.dumps(list(model.objects.values()), default=str))
        return '\n'.join(rows)

    def check(self, runner, name):
        handler, root = Collect(), logging.getLogger()
        old = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        try:
            out = wpscan_scan.run_wpscan(self.scan_obj.id, runner=runner)
        finally:
            root.removeHandler(handler)
            root.setLevel(old)
        self.assertNotIn(TOKEN, '\n'.join(handler.lines), f'{name}: a log record')
        self.assertNotIn(TOKEN, repr(out), f'{name}: the return value')
        self.assertNotIn(TOKEN, self.stored(), f'{name}: a stored row or activity record')

    def test_every_failure_that_carries_text_keeps_the_token_out(self):
        cases = {
            'exit code with the token on stderr': classified(2, f'boom --api-token {TOKEN} refused'),
            'exit code with the token on stdout-like last line': classified(3, f'x\nrequest failed token={TOKEN}'),
            'killed (timeout) with the token echoed': classified(-9, f'terminated token {TOKEN}'),
            'scan aborted, token in the reason': classified(4, '', {'scan_aborted': f'something odd {TOKEN}'}),
            'abort without a report, token on stderr': classified(4, f'Scan Aborted: {TOKEN}'),
            'a plain exception': mock.Mock(side_effect=RuntimeError(f'failed with {TOKEN}')),
            'a ToolFailure': mock.Mock(side_effect=wpscan_scan.ToolFailure('the scan failed', f'detail {TOKEN}')),
            'a timeout exception': mock.Mock(side_effect=TimeoutError(f'timed out calling with {TOKEN}')),
            'a block': mock.Mock(side_effect=wpscan_scan.Blocked(f'the edge refused {TOKEN}')),
            'an unreachable site': mock.Mock(side_effect=wpscan_scan.SiteUnreachable(f'did not answer {TOKEN}')),
        }
        for name, runner in cases.items():
            with self.subTest(name):
                self.check(runner, name)
