"""The secret detail view (docs/SECRETS-PLAN.md section 11): a secret in plain words, where it was found with a masked text around the match, why it is
rated as it is, and the decisions a person can take. A CANARY value, never a real key, must be in no stored row, API answer or page."""
import json
from unittest import mock

from django.contrib.auth.models import User
from django.db import connection
from django.test import Client, SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import secrets_api
from agentapi.services import ApiError, Ctx
from cveFeed import route_auth
from cveFeed import secrets_catalog as catalog
from cveFeed import secrets_inventory as inv
from cveFeed.models import SecretFinding, SecretOccurrence
from dashboard.models import AuditLog, Org, Project, ProjectMembership
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain

CANARY = 'CANARY' + 'x' * 40 + 'dea4'  # 50 characters, ends like the real finding's mask
RULE = 'betterleaks.rapidapi-access-token'
GOOGLE = 'AIza' + 'CANARYgoogleKEY0123456789abcdefghijk'[:35]
LINE = "var h = {headers: {'x-rapidapi-key': '%s', 'accept': 'json'}};"


class ContextMasking(SimpleTestCase):
    def test_the_value_is_masked_in_every_form_it_can_take_in_a_page(self):
        for form in (CANARY, CANARY.replace('/', '\\/'), '"%s"' % CANARY):
            out = catalog.mask_context(f"k: {form} ;", CANARY, 'rapidapi-access-token')
            self.assertNotIn(CANARY, out)
            self.assertIn('…dea4', out)

    def test_a_snippet_is_the_line_around_the_match_with_its_number(self):
        body = 'a' * 400 + '\n' + LINE % CANARY + '\n' + 'tail'
        line, snippet = catalog.context_snippet(body, CANARY, 'rapidapi-access-token')
        self.assertEqual(line, 2)
        self.assertEqual(snippet, LINE % '…dea4')
        self.assertNotIn(CANARY, snippet)

    def test_a_long_minified_line_is_cut_around_the_match_and_says_so(self):
        body = 'p' * 500 + "{'x-rapidapi-key':'%s'}" % CANARY + 'q' * 500
        line, snippet = catalog.context_snippet(body, CANARY)
        self.assertEqual(line, 1)
        self.assertTrue(snippet.startswith('... ') and snippet.endswith(' ...'))
        self.assertLessEqual(len(snippet), catalog.MAX_CONTEXT + 8)
        self.assertNotIn(CANARY, snippet)

    def test_another_secret_in_the_window_is_redacted_too(self):
        _, snippet = catalog.context_snippet(f"a='{GOOGLE}', b='{CANARY}'", CANARY)
        self.assertNotIn(GOOGLE, snippet)
        self.assertNotIn(CANARY, snippet)
        self.assertIn('redacted', snippet)

    def test_a_private_key_block_is_masked_whole(self):
        pem = '-----BEGIN RSA PRIVATE KEY-----\n' + ('MIIEpAIBAAKCAQEA' * 8 + '\n') * 3 + '-----END RSA PRIVATE KEY-----'
        line, snippet = catalog.context_snippet(f'key = """\n{pem}\n"""', pem, 'private-key')
        self.assertEqual(line, 2)
        self.assertNotIn('MIIEpAIBAAKCAQEA', snippet)
        self.assertIn('PEM RSA PRIVATE KEY', snippet)

    def test_no_value_in_the_text_or_a_short_one_gives_no_snippet(self):
        self.assertEqual(catalog.context_snippet('nothing here', CANARY), (None, ''))
        self.assertEqual(catalog.context_snippet('abc', 'abc'), (None, ''))

    def test_a_piece_of_the_value_left_in_the_text_drops_the_whole_snippet(self):
        self.assertEqual(catalog.mask_context('key=%s' % CANARY[10:40], CANARY), '')

    def test_control_characters_are_removed(self):
        self.assertEqual(catalog.mask_context('a\x00b\x1bc\n\td', CANARY), 'a b c d')


class Base(TestCase):
    def setUp(self):
        inv.reset_key_cache()
        self.addCleanup(inv.reset_key_cache)
        self.org = Org.objects.create(name='A', slug='sd-org')
        self.project = Project.objects.create(name='A', slug='sd-p', insert_date=timezone.now(), org=self.org)
        self.domain = Domain.objects.create(name='example.com', project=self.project, insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='e-sd', yaml_configuration='x', default_engine=True)
        self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=timezone.now(), scan_status=2, results_dir='/tmp')
        Subdomain.objects.create(scan_history=self.scan, target_domain=self.domain, name='example.com')
        self.member = User.objects.create_user('m-sd', password='x')
        ProjectMembership.objects.create(user=self.member, project=self.project, role='user')
        self.auditor = User.objects.create_user('a-sd', password='x')
        ProjectMembership.objects.create(user=self.auditor, project=self.project, role='audit')
        self.outsider = User.objects.create_user('o-sd', password='x')

    def ctx(self, user):
        return Ctx(user=user, token=None)

    def record(self, value=CANARY, rule=RULE, url='https://example.com/', **kw):
        return inv.record(self.project.pk, host='example.com', url=url, source=kw.pop('source', 'kingfisher'), rule_id=rule, value=value,
                          domain_id=self.domain.pk, scan_id=self.scan.pk, **kw)


class Capture(Base):
    def test_a_raw_context_is_masked_before_it_is_stored(self):
        row = self.record(line=2, context='x' + LINE % CANARY)
        occ = row.occurrences.get()
        self.assertEqual((occ.line, occ.context), (2, 'x' + LINE % '…dea4'))

    def test_a_context_that_cannot_be_proved_clean_is_dropped(self):
        row = self.record(context="k='%s'" % CANARY[5:30])  # a piece of the value, cut by the caller: the mask cannot find it whole
        self.assertEqual(row.occurrences.get().context, '')

    def test_a_read_that_captured_none_keeps_what_an_earlier_one_did(self):
        self.record(line=2, context=LINE % CANARY)
        self.record(line=2)
        self.assertEqual(SecretOccurrence.objects.get().context, LINE % '…dea4')

    def test_the_route_check_files_the_line_and_the_masked_text_and_never_the_value(self):
        body = '<script>\n' + 'x' * 100 + '\nvar cfg = {mapsKey: \'%s\', zoom: 4};\n</script>' % GOOGLE
        analysed = route_auth.analyse({'url': 'https://example.com/', 'status': 200, 'content_type': 'text/html', 'body': body, 'title': '', 'headers': {}})
        self.assertEqual(analysed['credential_context'][0][0], 3)
        probed = {'https://example.com/': analysed}
        route_auth._feed_inventory(self.scan, self.project.pk, probed, timezone.now())
        self.assertNotIn('credentials', probed['https://example.com/'])
        self.assertNotIn('credential_context', probed['https://example.com/'])
        occ = SecretOccurrence.objects.get()
        self.assertEqual((occ.source, occ.line, occ.context), ('route', 3, "var cfg = {mapsKey: 'AIza…ghij', zoom: 4};"))
        self.assertNotIn(GOOGLE, occ.context)


class DetailApi(Base):
    def test_a_server_credential_is_explained_in_plain_words(self):
        row = self.record(line=1270, context=LINE % CANARY)
        d = secrets_api.get_secret(self.ctx(self.member), self.project.slug, row.pk)
        ex = d['explain']
        self.assertEqual(ex['title'], 'Rapidapi access token')
        self.assertIn('This is a server credential', ex['what'])
        self.assertEqual(ex['provider_fix'], '')  # the generic rotate text is said once, in how_to_fix
        self.assertIn('call the provider as you', ex['abuse'])
        self.assertIn('Rotate it at the provider', ex['how_to_fix'])
        self.assertIn('move the call', ex['how_to_fix'])
        self.assertIn('not in the secrets catalogue', ex['catalogue'])
        self.assertIn('medium severity', ex['catalogue'])
        self.assertIn('uncatalogued secret', ex['rating'])
        self.assertEqual(ex['validated']['done'], False)
        where = d['occurrence_list'][0]
        self.assertEqual((where['url'], where['line'], where['source_label']), ('https://example.com/', 1270, 'Kingfisher scan of the page and its scripts'))
        self.assertEqual((where['context'], where['context_note']), (LINE % '…dea4', ''))
        self.assertEqual(d['status_actions'], ['public_by_design', 'false_positive', 'accepted'])
        self.assertIs(d['can_write'], True)

    def test_a_browser_key_and_an_identifier_have_their_own_fix(self):
        google = self.record(value=GOOGLE, rule='betterleaks.gcp-api-key', url='https://example.com/a.js')
        jwt = self.record(value='eyJ' + 'a' * 20 + '.eyJ' + 'b' * 20 + '.' + 'c' * 20, rule='betterleaks.jwt', url='https://example.com/b.js')
        g = secrets_api.get_secret(self.ctx(self.member), self.project.slug, google.pk)['explain']
        j = secrets_api.get_secret(self.ctx(self.member), self.project.slug, jwt.pk)['explain']
        self.assertIn('Restrict it at the provider', g['how_to_fix'])
        self.assertIn('is in the secrets catalogue', g['catalogue'])
        self.assertIn('Review it', j['how_to_fix'])

    def test_a_place_without_context_says_why_and_a_validated_secret_says_so(self):
        row = self.record(line=1270)
        row.validation_outcome = 'verified_active'
        row.save()
        d = secrets_api.get_secret(self.ctx(self.member), self.project.slug, row.pk)
        self.assertIn('Context not stored', d['occurrence_list'][0]['context_note'])
        self.assertIn('scanner reported the line number', d['occurrence_list'][0]['context_note'])
        self.assertIn('verified active', d['explain']['validated']['words'])
        route = self.record(value=GOOGLE, rule='route:google_key', source='route', url='https://example.com/r')
        note = secrets_api.get_secret(self.ctx(self.member), self.project.slug, route.pk)['occurrence_list'][0]['context_note']
        self.assertIn('rescan to capture', note)

    def test_other_places_are_counted_and_the_list_says_where(self):
        row = self.record(url='https://example.com/a.js')
        self.record(url='https://example.com/b.js', line=7)
        d = secrets_api.get_secret(self.ctx(self.member), self.project.slug, row.pk)
        self.assertEqual((d['occurrences'], d['hosts']), (2, 1))
        listed = secrets_api.list_secrets(self.ctx(self.member), self.project.slug, {})['results'][0]
        self.assertEqual(listed['where']['url'], 'https://example.com/b.js')
        self.assertEqual(listed['where']['line'], 7)

    def test_an_auditor_can_read_but_not_decide(self):
        row = self.record()
        self.assertIs(secrets_api.get_secret(self.ctx(self.auditor), self.project.slug, row.pk)['can_write'], False)


class Assign(Base):
    def test_a_member_assigns_and_unassigns_and_it_is_audited(self):
        row = self.record()
        out = secrets_api.set_secret_assignee(self.ctx(self.member), self.project.slug, row.pk, {'assignee': self.member.pk})
        self.assertEqual(out['assignee']['username'], 'm-sd')
        self.assertEqual(secrets_api.get_secret(self.ctx(self.member), self.project.slug, row.pk)['assignee']['username'], 'm-sd')
        secrets_api.set_secret_assignee(self.ctx(self.member), self.project.slug, row.pk, {'assignee': None})
        row.refresh_from_db()
        self.assertIsNone(row.assignee)
        self.assertEqual(AuditLog.objects.filter(action='secrets.assign').count(), 2)
        self.assertNotIn(CANARY, json.dumps([log.detail for log in AuditLog.objects.all()], default=str))

    def test_only_someone_who_can_see_the_project_can_be_assigned_and_only_a_writer_assigns(self):
        row = self.record()
        with self.assertRaises(ApiError) as caught:
            secrets_api.set_secret_assignee(self.ctx(self.member), self.project.slug, row.pk, {'assignee': self.outsider.pk})
        self.assertEqual(caught.exception.status, 400)
        with self.assertRaises(ApiError) as caught:
            secrets_api.set_secret_assignee(self.ctx(self.auditor), self.project.slug, row.pk, {'assignee': self.member.pk})
        self.assertEqual(caught.exception.status, 403)
        with self.assertRaises(ApiError) as caught:
            secrets_api.set_secret_assignee(self.ctx(self.member), self.project.slug, row.pk, {})
        self.assertEqual(caught.exception.status, 400)


class NothingShowsTheValue(Base):
    def test_the_canary_is_in_no_row_answer_or_page(self):
        row = self.record(line=1270, context=LINE % CANARY)
        self.record(value=GOOGLE, rule='betterleaks.gcp-api-key', url='https://example.com/a.js', context="k='%s'" % GOOGLE)
        secrets_api.set_secret_assignee(self.ctx(self.member), self.project.slug, row.pk, {'assignee': self.member.pk})
        answers = [secrets_api.get_secret(self.ctx(self.member), self.project.slug, r.pk) for r in SecretFinding.objects.all()]
        answers.append(secrets_api.list_secrets(self.ctx(self.member), self.project.slug, {'status': 'all'}))
        for blob in answers:
            text = json.dumps(blob, default=str, ensure_ascii=False)
            for value in (CANARY, CANARY[6:-4], GOOGLE, GOOGLE[4:-4]):
                self.assertNotIn(value, text)
        client = Client()
        client.force_login(self.member)
        for path in ('/cve/sd-p/secrets/', '/cve/sd-p/hosts/', '/cve/'):
            page = client.get(path).content.decode('utf-8', 'replace')
            self.assertNotIn(CANARY, page)
            self.assertNotIn(GOOGLE, page)
        with connection.cursor() as cursor:  # and in no column of the two tables
            for model in (SecretOccurrence, SecretFinding):
                cursor.execute(f'SELECT t::text FROM "{model._meta.db_table}" t')
                dump = ' '.join(r[0] for r in cursor.fetchall())
                self.assertNotIn(CANARY, dump)
                self.assertNotIn(GOOGLE, dump)
