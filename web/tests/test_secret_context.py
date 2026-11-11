"""The optional masked ``context`` of a secret, from a Sentinel to the detail panel (docs/SECRETS-PLAN.md section 11).

What a Sentinel sends is checked three ways: the server keeps only a bounded, typed string (``clean_context``); it masks it again with the finding's value in
hand (``secrets_inventory.record``), and keeps nothing it cannot prove clean; and the masking the Sentinel did and the server's own are one rule (a parity test
runs both on one corpus, with the Sentinel library that is on the path). A CANARY, a made-up key that only looks like one, goes through the whole broker path
and must be in no row, answer, page, log line or audit entry: only the contract's value field carries it, in memory, until the finding is filed."""
import json
import logging
import unittest
from unittest import mock

from django.contrib.auth.models import User
from django.db import connection
from django.test import Client, SimpleTestCase, TestCase

from agentapi import probe_results, secrets_api
from agentapi.services import Ctx
from cveFeed import secret_redaction
from cveFeed import secrets_catalog as catalog
from cveFeed import secrets_scan
from cveFeed.models import SecretFinding, SecretOccurrence
from dashboard.models import AuditLog, ProjectMembership
from tests.fake_scanner import FakeScanner
from tests.test_secrets_scan import HOST, StageBase

sentinel_context = sentinel_kf = sentinel_routes = None
try:  # the masking the Sentinel does (its PR; the server's pin in web/requirements.txt moves to it after that merges)
    from cvengine_scanner import context as sentinel_context
    from cvengine_scanner import secrets as sentinel_kf
    from cvengine_scanner.probes import routes as sentinel_routes
except ImportError:
    pass
_NEEDS = 'needs the Sentinel library that sends the masked context (re-pin web/requirements.txt after its PR merges)'
needs_sentinel = unittest.skipUnless(sentinel_context is not None and hasattr(sentinel_context, 'mask_context'), _NEEDS)
needs_sentinel_routes = unittest.skipUnless(sentinel_context is not None and sentinel_routes is not None and hasattr(sentinel_routes, 'analyse')
                                            and hasattr(sentinel_routes, '_row'), _NEEDS)

CANARY = 'AIza' + 'SyD-CANARYfakeLABkey01234567890Zq9w'  # 39 characters, a Google key's shape
OTHER = 'ghp_' + 'Fak3Canary0ther' + 'TokenAbCdEfGhIjKlMnOpQrSt'
HEX_KEY = 'f4k3canary' + '0123456789abcdef0123456789'
PIECES = (CANARY, CANARY[4:-4], CANARY[8:30])
HTML_LINE = f'  "x-api-key": "{CANARY}",'
PAGE = f'<html>\n<script>\nfetch(u, {{headers: {{\n{HTML_LINE}\n  "accept": "application/json"\n}}}});\n</script>\n</html>\n'
SCRIPT = f'/* bundle */\nvar cfg = {{region: "eu"}};\nvar mapsKey = "{CANARY}"; var x = "{OTHER}"; function init(){{ return mapsKey; }}\n'


class CleanContext(SimpleTestCase):
    def test_only_a_bounded_string_is_kept_and_its_controls_become_spaces(self):
        self.assertEqual(catalog.clean_context('a\x00b\x1b[0mc\u202ed\u200be  \n f'), 'a b [0mc d e f')
        self.assertEqual(catalog.clean_context('x' * 400), 'x' * 400)
        for bad in ('x' * 401, None, 5, ['a'], {'a': 1}, b'bytes', True):
            self.assertEqual(catalog.clean_context(bad), '', repr(bad)[:20])

    def test_a_scanner_report_keeps_a_clean_context_and_drops_the_rest_of_a_bad_one(self):
        url = f'https://{HOST}/'
        findings = [{'rule_id': 'betterleaks.gcp-api-key', 'url': url, 'secret': CANARY, 'line': 4, 'context': 'k = "AIza…Zq9w"\x00'},
                    {'rule_id': 'betterleaks.gcp-api-key', 'url': url, 'secret': CANARY + 'x', 'context': 'y' * 500},
                    {'rule_id': 'betterleaks.gcp-api-key', 'url': url, 'secret': CANARY + 'z', 'context': {'a': 1}}]
        got = secrets_scan.clean_result({'findings': findings, 'fetched': [{'url': url, 'kind': 'page'}]})['findings']
        self.assertEqual([f.get('context') for f in got], ['k = "AIza…Zq9w"', None, None])
        self.assertEqual(len(got), 3)  # a bad context never costs the finding

    def test_a_route_credential_keeps_a_line_and_a_clean_context(self):
        got = probe_results._route_credentials([{'type': 'google_key', 'value': CANARY, 'line': 4, 'context': 'k = "AIza…Zq9w"'},
                                                {'type': 'google_key', 'value': CANARY + '1', 'line': 0, 'context': 'x' * 401},
                                                {'type': 'google_key', 'value': CANARY + '2', 'line': True},
                                                {'type': 'google_key', 'value': CANARY + '3'}])
        self.assertEqual(got[0], {'type': 'google_key', 'value': CANARY, 'line': 4, 'context': 'k = "AIza…Zq9w"'})
        self.assertEqual([sorted(g) for g in got[1:]], [['type', 'value']] * 3)


class MaskOnReceipt(SimpleTestCase):
    """The server masks again whatever arrives, with the value of the finding in hand: defence in depth."""

    def test_a_value_the_sentinel_left_in_is_masked(self):
        self.assertEqual(catalog.mask_context(f'k = "{CANARY}";', CANARY), f'k = "AIza…{CANARY[-4:]}";')

    def test_a_run_of_the_values_shape_that_is_not_the_value_is_not_kept(self):
        # a long token a scanner hid the wrong copy of is masked by shape; a short one no shape rule knows is not kept at all
        near = CANARY[:-3] + 'abc'
        out = catalog.mask_context(f'a="{near}"', CANARY)
        self.assertNotIn(near[8:], out)
        value = 'Zx9Qw3Lm8Vb2Nc7T'
        self.assertEqual(catalog.mask_context('a="Zx9Qw3Lm8Vb2Nc7U"', value), '')
        self.assertEqual(catalog.mask_context('a="Zx9Qw3Lm8Vb2Nc7T"', value), 'a="…Nc7T"')

    def test_another_secret_is_masked_whatever_its_provider(self):
        for text in (f'x-api-key: {HEX_KEY}', f'"x-api-key": "{HEX_KEY}",', f'a={OTHER}; b=postgres://u:s3cretPass@h/db'):
            out = catalog.mask_context(text, CANARY)
            for leaked in (HEX_KEY, OTHER, 's3cretPass'):
                self.assertNotIn(leaked, out)

    def test_a_context_that_arrives_masked_is_left_exactly_as_it_is(self):
        sent = f'"x-api-key": "AIza…{CANARY[-4:]}", "k": "…[redacted 30 chars, token]", p = "postgres://u:…[redacted 8 chars, url_password]@h/db"'
        self.assertEqual(catalog.mask_context(sent, CANARY), sent)

    def test_ordinary_text_is_not_touched(self):
        text = 'var path = "/assets/images/hero-banner-final.png"; const version = 20240101; getElementsByClassName("x");'
        self.assertEqual(catalog.mask_context(text, CANARY), text)


@needs_sentinel
class ParityWithTheSentinel(SimpleTestCase):
    """One rule on both sides (cvengine_scanner.context is a copy of the server's masking, as probes.sensitive is of the server's detectors)."""
    CORPUS = (
        f'k = "{CANARY}";', f'a={CANARY}, b="{OTHER}", c=postgres://app:s3cretPass@db.example.com/x', f'x-api-key: {HEX_KEY}',
        'Authorization: Bearer abcdefghijklmnop0123456789', 'password=Hunter2!x&user=bob', 'AccountKey=' + 'A' * 40 + '==',
        '-----BEGIN RSA PRIVATE KEY-----\n' + 'MIIEpAIBAAKCAQEA' * 6 + '\n-----END RSA PRIVATE KEY-----', 'plain text with no secrets in it at all', 'a\u202eb\u200bc and a right-to-left override',
        'var path = "/assets/images/hero-banner-final.png"; const version = 20240101;', 'a\x00b\x1bc', 'AKIA' + '0' * 16 + ' and ' + 'AKIA' + '1' * 16,
        'https://hooks.slack.com/services/T00000000/B00000000/' + 'x' * 24, 'eyJ' + 'a' * 20 + '.eyJ' + 'b' * 20 + '.' + 'c' * 20, 'sk-' + 'q' * 30,
    )

    def setUp(self):
        keyless = mock.patch.object(secret_redaction, '_KEY_CACHE', [None])  # the server adds a keyed fingerprint to its masks; a Sentinel has no key
        keyless.start()
        self.addCleanup(keyless.stop)

    def test_the_mask_and_the_redaction_are_the_same(self):
        for value in (CANARY, 'AKIA' + '0' * 16, 'short-value1', '-----BEGIN RSA PRIVATE KEY-----\nMIIE', 'sk-ant-api03-' + 'z' * 40, 'ghp_' + 'a' * 36):
            self.assertEqual(sentinel_context.mask(value), catalog.mask(value), value[:12])
        for text in self.CORPUS:
            self.assertEqual(sentinel_context.redact_text(text), secret_redaction.redact_text(text), text[:30])
            self.assertEqual(sentinel_context.mask_runs(text), catalog.mask_runs(text), text[:30])

    def test_mask_context_and_snippet_are_the_same(self):
        for text in self.CORPUS:
            self.assertEqual(sentinel_context.mask_context(text, CANARY), catalog.mask_context(text, CANARY), text[:30])
        body = f'one\n{HTML_LINE}\nthree\n'
        self.assertEqual(sentinel_context.context_snippet(body, CANARY), catalog.context_snippet(body, CANARY))

    def test_what_a_sentinel_sends_the_server_leaves_as_it_is(self):
        for text in self.CORPUS:
            if len(text) < 40:
                continue
            for value in (CANARY, OTHER):
                sent = sentinel_context.snippet(text + ' ' + CANARY, len(text) + 1, len(text) + 1 + len(CANARY), CANARY)
                self.assertEqual(catalog.mask_context(sent, CANARY), sent, text[:30])
        line = 'x' * 300 + f' "{CANARY}" ' + 'y' * 300  # the 200 character cut, from the middle of a long line
        sent = sentinel_context.snippet(line, line.index(CANARY), line.index(CANARY) + len(CANARY), CANARY)
        self.assertEqual(catalog.mask_context(sent, CANARY), sent)
        self.assertLessEqual(len(sent), 200)


def real_sentinel_result(self):
    """What the Sentinel library makes of a Kingfisher report over ``PAGE`` and ``SCRIPT``: its own masking, its own contract fields."""
    def finding(name, line, column):
        return {'rule': {'id': 'betterleaks.gcp-api-key', 'name': 'gcp-api-key'},
                'finding': {'snippet': CANARY, 'path': f'/w/in/{name}', 'line': line, 'column_start': column, 'confidence': 'high', 'entropy': '4.5',
                            'validation': {'outcome': 'not_attempted', 'response': ''}}}
    manifest = {'0.html': {'url': f'https://{HOST}/'}, '1.js': {'url': f'https://{HOST}/static/app.js'}}
    bodies = {'0.html': PAGE, '1.js': SCRIPT}
    found, _ = sentinel_kf.read_report(json.dumps({'findings': [finding('0.html', 4, 16), finding('1.js', 3, 14)]}), manifest, body_of=bodies.get)
    fetched = [{'url': u['url'], 'status': 200, 'bytes': 100, 'content_type': 'text/html', 'kind': 'page' if n.endswith('html') else 'script'} for n, u in manifest.items()]
    return {'outcome': 'done', 'summary': 'canary', 'findings': found, 'fetched': fetched, 'references': [], 'stats': {'files': 2, 'bytes': 1, 'findings': 2}}


class CanaryBase(StageBase):
    """A Sentinel's result for a page and a script that serve the canary, filed through the real broker path (``FakeScanner`` reports through
    ``report_result``, which runs ``clean_result``), then read back through every door."""

    def setUp(self):
        super().setUp()
        self.member = User.objects.create_user('m-ctx', password='x')
        ProjectMembership.objects.create(user=self.member, project=self.project, role='user')
        self.log = []
        handler = logging.Handler()
        handler.emit = lambda record: self.log.append(record.getMessage() + ' ' + str(record.args))
        logging.getLogger().addHandler(handler)
        self.addCleanup(logging.getLogger().removeHandler, handler)
        self.old_level = logging.getLogger().level
        logging.getLogger().setLevel(logging.DEBUG)
        self.addCleanup(logging.getLogger().setLevel, self.old_level)

    def sentinel_result(self):
        """What a Sentinel that sends the masked context reports for ``PAGE`` and ``SCRIPT`` (written out here, as the contract says it: the value only in
        ``secret``, the text around it masked)."""
        mask = f'AIza\u2026{CANARY[-4:]}'
        found = [{'rule_id': 'betterleaks.gcp-api-key', 'rule_name': 'gcp-api-key', 'url': f'https://{HOST}/', 'line': 4, 'confidence': 'high', 'entropy': '4.5',
                  'secret': CANARY, 'validation': {'outcome': 'not_attempted'}, 'context': f'"x-api-key": "{mask}",'},
                 {'rule_id': 'betterleaks.gcp-api-key', 'rule_name': 'gcp-api-key', 'url': f'https://{HOST}/static/app.js', 'line': 3, 'confidence': 'high', 'entropy': '4.5',
                  'secret': CANARY, 'validation': {'outcome': 'not_attempted'},
                  'context': f'var mapsKey = "{mask}"; var x = "ghp_\u2026QrSt"; function init(){{ return mapsKey; }}'}]
        fetched = [{'url': f'https://{HOST}/', 'status': 200, 'bytes': 100, 'content_type': 'text/html', 'kind': 'page'},
                   {'url': f'https://{HOST}/static/app.js', 'status': 200, 'bytes': 100, 'content_type': 'application/javascript', 'kind': 'script'}]
        return {'outcome': 'done', 'summary': 'canary', 'findings': found, 'fetched': fetched, 'references': [], 'stats': {'files': 2, 'bytes': 1, 'findings': 2}}

    def run_stage(self, result=None):
        result = result or self.sentinel_result()
        with FakeScanner(kinds=['secrets_scan'], responders={'secrets_scan': lambda task: result}):
            return secrets_scan.run_for_scan(self.scan.id)

    def dump(self, find=None):
        """Every row of every table, as text; with ``find``, the names of the tables whose rows hold it."""
        out, holding = [], set()
        with connection.cursor() as cursor:
            for table in connection.introspection.table_names():
                cursor.execute(f'SELECT t::text FROM "{table}" t')
                for row in cursor.fetchall():
                    out.append(row[0])
                    if find and find in row[0]:
                        holding.add(table)
        return holding if find else '\n'.join(out)



class CanaryTests:
    def test_the_sentinels_context_is_stored_and_shown_and_the_canary_is_nowhere_else(self):
        sent = self.sentinel_result()
        self.assertTrue(all('context' in f for f in sent['findings']))
        self.run_stage(sent)
        occurrences = {o.url: o for o in SecretOccurrence.objects.all()}
        page, script = occurrences[f'https://{HOST}/'], occurrences[f'https://{HOST}/static/app.js']
        self.assertEqual((page.line, page.context), (4, f'"x-api-key": "AIza…{CANARY[-4:]}",'))
        self.assertEqual(script.line, 3)
        self.assertIn(f'var mapsKey = "AIza…{CANARY[-4:]}";', script.context)
        self.assertNotIn(OTHER, script.context)
        row = SecretFinding.objects.get()
        shown = secrets_api.get_secret(Ctx(user=self.member, token=None), self.project.slug, row.pk)
        self.assertEqual({o['context_note'] for o in shown['occurrence_list']}, {''})
        self.assertEqual({o['context'] for o in shown['occurrence_list']}, {page.context, script.context})
        answers = [shown, secrets_api.list_secrets(Ctx(user=self.member, token=None), self.project.slug, {'status': 'all'})]
        client = Client()
        client.force_login(self.member)
        pages = [client.get(f'/cve/{self.project.slug}/{section}/').content.decode('utf-8', 'replace') for section in ('secrets', 'hosts')]
        audit = json.dumps([[log.action, log.detail] for log in AuditLog.objects.all()], default=str)
        everything = {'api': json.dumps(answers, default=str, ensure_ascii=False), 'html': '\n'.join(pages), 'audit': audit, 'log': '\n'.join(self.log),
                      'secret rows': json.dumps(list(SecretFinding.objects.values()) + list(SecretOccurrence.objects.values()), default=str)}
        for where, text in everything.items():
            for piece in PIECES:
                self.assertNotIn(piece, text, where)
            self.assertNotIn(OTHER, text, where)

    def test_the_canary_is_in_no_row_of_any_table(self):
        self.run_stage()
        for piece in PIECES:
            self.assertEqual(self.dump(find=piece), set(), piece)
        self.assertEqual(self.dump(find=OTHER), set())

    def test_a_sentinel_that_sends_the_value_unmasked_in_the_context_is_masked_on_receipt(self):
        result = self.sentinel_result()
        for f in result['findings']:
            f['context'] = f'a = "{CANARY}"; b = "{HEX_KEY}"; c = "{OTHER}"'
        self.run_stage(result)
        for occurrence in SecretOccurrence.objects.all():
            for leaked in (CANARY, CANARY[4:-4], HEX_KEY, OTHER):
                self.assertNotIn(leaked, occurrence.context)
            self.assertIn(f'AIza…{CANARY[-4:]}', occurrence.context)
        dump = self.dump()
        for context_only in (HEX_KEY, OTHER):
            self.assertNotIn(context_only, dump)

    def test_an_old_sentinel_with_no_context_files_the_finding_as_before(self):
        result = self.sentinel_result()
        for f in result['findings']:
            f.pop('context')
        self.run_stage(result)
        self.assertEqual(SecretFinding.objects.count(), 1)
        self.assertEqual({o.context for o in SecretOccurrence.objects.all()}, {''})
        row = SecretFinding.objects.get()
        notes = {o['context_note'] for o in secrets_api.get_secret(Ctx(user=self.member, token=None), self.project.slug, row.pk)['occurrence_list']}
        self.assertEqual(len(notes), 1)
        self.assertIn('Update the Sentinel', notes.pop())

    def test_a_context_that_is_too_long_or_not_text_costs_the_context_not_the_finding(self):
        result = self.sentinel_result()
        result['findings'][0]['context'] = 'x' * 401
        result['findings'][1]['context'] = 12345
        self.run_stage(result)
        self.assertEqual(SecretFinding.objects.count(), 1)
        self.assertEqual({o.context for o in SecretOccurrence.objects.all()}, {''})


class Canary(CanaryTests, CanaryBase):
    pass


@needs_sentinel
class CanaryFromTheRealSentinel(CanaryTests, CanaryBase):
    """The same tests over what the Sentinel library itself makes of the page and the script."""
    sentinel_result = real_sentinel_result


class CanaryOnTheRouteCheck(TestCase):
    """The route_probe path: a credential row with its line and masked context, cleaned by the broker and filed by the route stage.
    The row is made by hand here (what a Sentinel with the context code sends); the same test over the library's own row is the subclass below."""
    URL = 'https://www.rt.test/'
    PAGE = f'<html>\n<script>\nvar cfg = {{mapsKey: "{CANARY}", zoom: 4}};\n</script></html>\n'
    MASKED = f'var cfg = {{mapsKey: "AIza…{CANARY[-4:]}", zoom: 4}};'

    def sent_row(self):
        """The credential fields a Sentinel sends for ``PAGE``, made by hand: the masked context and the line, never the value in them."""
        return {'credentials': [{'type': 'google_key', 'value': CANARY, 'line': 3, 'context': self.MASKED}],  # the contract's value field, in memory, until filed
                'sensitive': {'google_key': {'count': 1, 'sample': 'Google API key, 39 chars (AIza...)'}}}

    def test_a_route_credentials_context_is_filed_and_the_canary_is_nowhere_else(self):
        from tests.test_probe_kinds import RouteProbeStageTests
        suite = RouteProbeStageTests('test_a_credential_the_scanner_read_goes_to_the_inventory_and_is_never_stored_in_the_route')
        suite.setUp()
        self.addCleanup(suite.doCleanups)
        sent = self.sent_row()
        self.assertEqual(sent['credentials'][0]['line'], 3)
        self.assertNotIn(CANARY, sent['credentials'][0]['context'])
        row = {**suite.row(self.URL, 'open', 200), 'credentials': sent['credentials'], 'sensitive': sent['sensitive'], 'sensitive_score': 25}
        log = []
        handler = logging.Handler()
        handler.emit = lambda record: log.append(record.getMessage() + ' ' + str(record.args))
        logging.getLogger().addHandler(handler)
        self.addCleanup(logging.getLogger().removeHandler, handler)

        def serve(task):
            urls = [u for h in task['target']['hosts'] for u in h['urls']]
            return {'outcome': 'done', 'touched': [h['host'] for h in task['target']['hosts']], 'refused': [],
                    'routes': [row if u == 'https://www.rt.test/' else suite.row(u) for u in urls]}
        suite.run_stage(suite.scan(), serve)
        occurrence = SecretOccurrence.objects.get(source='route')
        self.assertEqual((occurrence.line, occurrence.context), (3, self.MASKED))
        with connection.cursor() as cursor:
            tables = connection.introspection.table_names()
            dump = []
            for table in tables:
                cursor.execute(f'SELECT t::text FROM "{table}" t')
                dump.extend(r[0] for r in cursor.fetchall())
        text = '\n'.join(dump) + '\n'.join(log)
        for piece in PIECES:
            self.assertNotIn(piece, text)


@needs_sentinel_routes
class CanaryOnTheRouteCheckFromTheRealSentinel(CanaryOnTheRouteCheck):
    """The same test over the row the Sentinel library itself makes from the page."""

    def sent_row(self):
        analysed = sentinel_routes.analyse({'url': self.URL, 'status': 200, 'content_type': 'text/html', 'body': self.PAGE, 'title': 'T', 'headers': {}})
        return sentinel_routes._row(self.URL, analysed)
