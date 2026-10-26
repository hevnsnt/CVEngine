import json
import os
from unittest import mock

from django.test import SimpleTestCase

from cveFeed import bounty_playbook, bounty_report as br, bounty_scope, bounty_submit


class TaxonomyTests(SimpleTestCase):
    def test_bundled_taxonomy_is_intact(self):
        v = br.vrt()
        self.assertGreater(len(v['entries']), 500)
        self.assertEqual(v['release_date'][:2], '20')
        self.assertTrue(all(len(r) == 3 and r[2] in (None, 1, 2, 3, 4, 5) for r in v['entries']))

    def test_every_suggested_category_exists(self):
        for table in (br.VRT_BY_TAG, br.VRT_BY_CWE):
            for key, vrt_id in table.items():
                self.assertIsNotNone(br.vrt_entry(vrt_id), f'{key} -> {vrt_id}')

    def test_suggestions(self):
        self.assertEqual(br.suggest_vrt(cwes=['CWE-89']), 'server_side_injection.sql_injection')
        self.assertEqual(br.suggest_vrt(tags=['XSS']), 'cross_site_scripting_xss')
        self.assertEqual(br.suggest_vrt(cwes=['CWE-89'], tags=['xss']), 'server_side_injection.sql_injection')
        self.assertEqual(br.suggest_vrt(tags=['unknown-thing']), '')
        self.assertTrue(br.suggest_vrt(name='Outdated PHP version').startswith('using_components'))

    def test_known_priority_five_examples_from_the_taxonomy(self):
        for vrt_id in ('server_security_misconfiguration.fingerprinting_banner_disclosure',
                       'using_components_with_known_vulnerabilities.outdated_software_version'):
            self.assertEqual(br.vrt_entry(vrt_id)['priority'], 5)

    def test_licence_file_notice_is_present(self):
        with open(os.path.join(os.path.dirname(br.__file__), 'data', 'vrt.json'), encoding='utf-8') as fh:
            self.assertEqual(json.load(fh)['license'], 'Apache-2.0')


class RedactTests(SimpleTestCase):
    def test_headers_cookies_tokens_and_keys(self):
        raw = ('GET / HTTP/1.1\nAuthorization: Bearer abcdefghijklmnopqrstuvwxyz\nCookie: sid=0123456789abcdef; theme=dark\n'
               'X-Api-Key: sk_live_ABCDEFGHIJKLMNOP\npassword=hunter2hunter2&x=1\nAKIAABCDEFGHIJKLMNOP\n'
               'https://user:s3cretpass@db.example.com/x\n-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n-----END RSA PRIVATE KEY-----')
        out, n = br.redact(raw)
        for secret in ('abcdefghijklmnopqrstuvwxyz', '0123456789abcdef', 'sk_live_ABCDEFGHIJKLMNOP', 'hunter2hunter2', 'AKIAABCDEFGHIJKLMNOP',
                       's3cretpass', 'MIIEabc'):
            self.assertNotIn(secret, out)
        self.assertGreaterEqual(n, 7)
        self.assertIn('GET / HTTP/1.1', out)  # plain text stays; cookie values are masked whole, which errs toward hiding
        self.assertIsNone(br.SECRET_LEFT.search(out))

    def test_a_short_prefix_is_kept(self):
        out, _ = br.redact('Authorization: Bearer abcdefghijklmnop')
        self.assertIn('Bearer abcd[redacted', out)

    def test_jwt(self):
        out, n = br.redact('t=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuvwxyz')
        self.assertEqual(n, 1)
        self.assertNotIn('eyJzdWIi', out)

    def test_size_cap_and_plain_text_untouched(self):
        out, n = br.redact('x' * 100, limit=10)
        self.assertTrue(out.startswith('x' * 10) and out.endswith('[truncated]'))
        self.assertEqual(br.redact('nothing secret here')[1], 0)
        self.assertEqual(br.redact(None), ('', 0))


VULN = {'name': 'Exposed admin panel', 'severity': 3, 'description': 'The admin panel is reachable.', 'impact': '', 'remediation': 'Restrict it.',
        'http_url': 'https://app.example.com/admin', 'curl_command': "curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwx' https://app.example.com/admin",
        'request': '', 'response': 'HTTP/1.1 200 OK\nSet-Cookie: sid=0123456789abcdef\n\n<title>Admin</title>', 'template_id': 'admin-panel',
        'matcher_name': 'title', 'extracted_results': ['Admin'], 'tags': ['exposure'], 'references': ['https://example.com/ref', 'javascript:alert(1)'],
        'cve_ids': ['CVE-2026-1001'], 'cwe_ids': ['CWE-200'], 'cvss_score': 7.5, 'cvss_metrics': 'CVSS:3.1/AV:N', 'host': 'app.example.com'}


class DraftTests(SimpleTestCase):
    def test_a_draft_carries_the_request_and_leaves_the_impact_empty(self):
        d = br.draft_from_vulnerability(VULN)
        self.assertEqual(d['severity'], 'high')
        self.assertEqual(d['asset'], 'app.example.com')
        self.assertEqual(d['impact'], '')
        self.assertTrue(any('impact' in n.lower() for n in d['notes']))
        self.assertIn('curl', d['steps'])
        self.assertNotIn('abcdefghijklmnopqrstuvwx', d['steps'])
        self.assertIn('TODO', d['steps'])
        self.assertTrue(d['title'].startswith('Exposed admin panel'))

    def test_secrets_are_masked_in_every_part(self):
        d = br.draft_from_vulnerability(VULN)
        blob = json.dumps(d)
        self.assertNotIn('0123456789abcdef', blob)
        self.assertNotIn('abcdefghijklmnopqrstuvwx', blob)

    def test_references_keep_only_web_addresses_and_add_the_cve(self):
        d = br.draft_from_vulnerability(VULN)
        self.assertIn('https://nvd.nist.gov/vuln/detail/CVE-2026-1001', d['references'])
        self.assertIn('https://example.com/ref', d['references'])
        self.assertNotIn('javascript', d['references'])

    def test_a_bare_finding_says_what_is_missing(self):
        d = br.draft_from_vulnerability({'name': 'x', 'severity': 1})
        self.assertTrue(any('no request' in n for n in d['notes']))
        self.assertTrue(any('description' in n for n in d['notes']))

    def test_unknown_severity_is_empty_not_guessed(self):
        self.assertEqual(br.draft_from_vulnerability({**VULN, 'severity': -1})['severity'], '')

    def test_oversize_text_is_cut(self):
        d = br.draft_from_vulnerability({**VULN, 'description': 'd' * 100000})
        self.assertEqual(len(d['summary']), br.FIELD_LIMITS['summary'])


class CleanFieldsTests(SimpleTestCase):
    def test_limits_and_unknown_keys(self):
        out = br.clean_fields({'title': 't' * 1000, 'evil': 'x', 'steps': 'a\x00b'})
        self.assertEqual(len(out['title']), 300)
        self.assertNotIn('evil', out)
        self.assertEqual(out['steps'], 'ab')

    def test_validation(self):
        for bad in ({'severity': 'urgent'}, {'vrt': 'nope.nope'}, {'cvss_score': 11}, {'cvss_score': 'x'}):
            with self.assertRaises(ValueError):
                br.clean_fields(bad)
        self.assertEqual(br.clean_fields({'cvss_score': ''})['cvss_score'], None)
        self.assertEqual(br.clean_fields({'cvss_score': '7.46'})['cvss_score'], 7.5)

    def test_checklist_is_reduced_to_known_keys(self):
        out = br.clean_fields({'checklist': {'reproduced': 1, 'junk': True}})
        self.assertEqual(set(out['checklist']), {k for k, _ in br.CHECKLIST})
        self.assertTrue(out['checklist']['reproduced'])


GOOD = {'title': 'Exposed admin panel on app.example.com lets anyone sign in as staff', 'asset': 'app.example.com', 'severity': 'high', 'cvss_score': 7.5,
        'summary': 'The admin panel is reachable without a VPN.', 'steps': '1. Open https://app.example.com/admin\n2. Sign in with the default account.',
        'impact': 'Anyone on the internet can reach the staff console and, with the default password, change every customer record in the tenant.',
        'evidence': {'response': 'HTTP/1.1 200 OK'}, 'vrt': 'server_side_injection.sql_injection', 'checklist': {k: True for k, _ in br.CHECKLIST}}
PROGRAM = {'policy_ack': True, 'automated_ok': True}
IN = bounty_scope.Verdict(bounty_scope.IN, 'listed')


def codes(findings, level=None):
    return {f['code'] for f in findings if level is None or f['level'] == level}


class LintTests(SimpleTestCase):
    def test_a_complete_report_has_no_blockers(self):
        self.assertEqual(codes(br.lint(GOOD, IN, PROGRAM), 'block'), set())

    def test_each_missing_part_blocks(self):
        for field, code in (('title', 'title_short'), ('steps', 'steps_missing'), ('impact', 'impact_missing'), ('asset', 'asset_missing')):
            self.assertIn(code, codes(br.lint({**GOOD, field: ''}, IN, PROGRAM), 'block'), field)

    def test_a_todo_in_the_steps_blocks(self):
        self.assertIn('steps_todo', codes(br.lint({**GOOD, 'steps': '1. x\nTODO: finish'}, IN, PROGRAM), 'block'))

    def test_scope_verdicts(self):
        out = bounty_scope.Verdict(bounty_scope.OUT, 'listed as out of scope')
        self.assertIn('out_of_scope', codes(br.lint(GOOD, out, PROGRAM), 'block'))
        self.assertIn('not_listed', codes(br.lint(GOOD, bounty_scope.Verdict(bounty_scope.NOT_LISTED, 'x'), PROGRAM), 'block'))
        self.assertIn('scope_ambiguous', codes(br.lint(GOOD, bounty_scope.Verdict(bounty_scope.AMBIGUOUS, 'x'), PROGRAM), 'warn'))

    def test_policy_must_be_acknowledged_and_scanning_confirmed(self):
        self.assertIn('policy_unacknowledged', codes(br.lint(GOOD, IN, {'policy_ack': False}), 'block'))
        self.assertIn('automated_unconfirmed', codes(br.lint(GOOD, IN, {'policy_ack': True, 'automated_ok': False}), 'warn'))
        self.assertIn('scope_changed', codes(br.lint(GOOD, IN, {**PROGRAM, 'scope_changed_since_ack': True}), 'warn'))

    def test_a_removed_program_blocks(self):
        self.assertIn('program_removed', codes(br.lint(GOOD, IN, {**PROGRAM, 'removed': True}), 'block'))

    def test_checklist_blocks_until_every_box_is_ticked(self):
        self.assertIn('checklist', codes(br.lint({**GOOD, 'checklist': {'reproduced': True}}, IN, PROGRAM), 'block'))

    def test_a_leftover_secret_blocks(self):
        bad = {**GOOD, 'steps': '1. use AKIAABCDEFGHIJKLMNOP to read the bucket'}
        self.assertIn('secret_in_text', codes(br.lint(bad, IN, PROGRAM), 'block'))
        bad = {**GOOD, 'evidence': {'response': '-----BEGIN PRIVATE KEY-----'}}
        self.assertIn('secret_in_evidence', codes(br.lint(bad, IN, PROGRAM), 'block'))

    def test_severity_must_match_the_score(self):
        self.assertIn('severity_mismatch', codes(br.lint({**GOOD, 'severity': 'critical', 'cvss_score': 4.3}, IN, PROGRAM), 'warn'))
        self.assertNotIn('severity_mismatch', codes(br.lint(GOOD, IN, PROGRAM)))

    def test_priority_five_class_warns(self):
        bad = {**GOOD, 'vrt': 'server_security_misconfiguration.fingerprinting_banner_disclosure'}
        self.assertIn('vrt_p5', codes(br.lint(bad, IN, PROGRAM), 'warn'))

    def test_generic_title_unnumbered_steps_thin_impact_no_evidence_warn(self):
        out = codes(br.lint({**GOOD, 'title': 'XSS found in application', 'steps': 'open it and see', 'impact': 'bad', 'evidence': {}}, IN, PROGRAM), 'warn')
        self.assertTrue({'title_generic', 'steps_unnumbered', 'impact_thin', 'no_evidence'} <= out)

    def test_no_bounty_is_information_and_duplicates_warn(self):
        out = br.lint(GOOD, IN, {**PROGRAM, 'offers_bounties': False}, duplicates=[7])
        self.assertIn('no_bounty', codes(out, 'info'))
        self.assertIn('duplicate_local', codes(out, 'warn'))

    def test_severity_scale_is_the_cvss_one(self):
        for score, name in ((0, 'none'), (0.1, 'low'), (3.9, 'low'), (4.0, 'medium'), (6.9, 'medium'), (7.0, 'high'), (8.9, 'high'), (9.0, 'critical'), (10, 'critical')):
            self.assertEqual(br.severity_for_score(score), name, score)


class RenderTests(SimpleTestCase):
    def test_markdown_has_the_sections_in_order(self):
        md = br.to_markdown({**GOOD, 'remediation': 'Restrict it.', 'references': 'https://example.com/a\nhttps://example.com/b'})
        order = [md.index(h) for h in ('# Exposed', '## Summary', '## Steps to reproduce', '## Evidence', '## Impact', '## Suggested fix', '## References')]
        self.assertEqual(order, sorted(order))
        self.assertIn('- https://example.com/b', md)

    def test_hackerone_payload_has_the_required_fields_only_from_the_report(self):
        p = br.hackerone_payload(GOOD, 'acme')['data']
        self.assertEqual(p['type'], 'report')
        a = p['attributes']
        self.assertEqual((a['team_handle'], a['severity_rating']), ('acme', 'high'))
        self.assertTrue(a['title'] and a['vulnerability_information'] and a['impact'])
        self.assertNotIn('# Exposed', a['vulnerability_information'])
        self.assertEqual(set(a), {'team_handle', 'title', 'vulnerability_information', 'impact', 'severity_rating'})

    def test_bugcrowd_fields_use_their_names(self):
        names = [n for n, _ in br.platform_fields(GOOD, 'bugcrowd')]
        self.assertEqual(names[:4], ['Summary title', 'Target', 'Technical severity (VRT)', 'URL / location of vulnerability'])

    def test_transitions(self):
        self.assertIn('submitted', br.TRANSITIONS['ready'])
        self.assertNotIn('submitted', br.TRANSITIONS['draft'])
        self.assertEqual(br.TRANSITIONS['closed'], ())
        self.assertTrue(set(br.TRANSITIONS) == set(br.STATUSES))


class SubmitTests(SimpleTestCase):
    def resp(self, status, body=None):
        r = mock.Mock(status_code=status)
        r.json.return_value = body
        return r

    def test_success(self):
        post = mock.Mock(return_value=self.resp(201, {'data': {'id': '12345'}}))
        out = bounty_submit.submit_hackerone({'a': 1}, 'u', 't', post=post)
        self.assertEqual(out, {'id': '12345', 'url': 'https://hackerone.com/reports/12345'})
        args, kw = post.call_args
        self.assertEqual(args[0], bounty_submit.HACKERONE_REPORTS)
        self.assertEqual((kw['auth'], kw['allow_redirects']), (('u', 't'), False))

    def test_refusals_never_echo_credentials_and_map_to_hints(self):
        for status, text in ((401, 'credentials'), (403, 'may not submit'), (404, 'program handle'), (422, 'rejected')):
            post = mock.Mock(return_value=self.resp(status, {'errors': [{'title': 'bad', 'detail': 'field x'}]}))
            with self.assertRaises(bounty_submit.SubmitError) as ctx:
                bounty_submit.submit_hackerone({}, 'user-id', 'secret-token', post=post)
            self.assertIn(text, ctx.exception.message)
            self.assertNotIn('secret-token', ctx.exception.message)
            self.assertFalse(ctx.exception.uncertain)

    def test_a_timeout_is_uncertain(self):
        import requests
        with self.assertRaises(bounty_submit.SubmitError) as ctx:
            bounty_submit.submit_hackerone({}, 'u', 't', post=mock.Mock(side_effect=requests.Timeout()))
        self.assertTrue(ctx.exception.uncertain)

    def test_a_connection_failure_is_certain_nothing_was_sent(self):
        import requests
        with self.assertRaises(bounty_submit.SubmitError) as ctx:
            bounty_submit.submit_hackerone({}, 'u', 't', post=mock.Mock(side_effect=requests.ConnectionError()))
        self.assertFalse(ctx.exception.uncertain)

    def test_an_odd_id_is_not_trusted(self):
        for body in ({'data': {'id': '../../x'}}, {'data': {}}, None):
            with self.assertRaises(bounty_submit.SubmitError) as ctx:
                bounty_submit.submit_hackerone({}, 'u', 't', post=mock.Mock(return_value=self.resp(201, body)))
            self.assertTrue(ctx.exception.uncertain)

    def test_credential_check(self):
        get = lambda s: mock.Mock(return_value=mock.Mock(status_code=s))
        self.assertIs(bounty_submit.check_hackerone('u', 't', get=get(200)), True)
        self.assertIs(bounty_submit.check_hackerone('u', 't', get=get(401)), False)
        self.assertIsNone(bounty_submit.check_hackerone('u', 't', get=get(500)))
        self.assertIn('not your email', bounty_submit.verify_hackerone('u', 't', get=get(401))['reason'])
        self.assertIn('inactive', bounty_submit.verify_hackerone('u', 't', get=get(403))['reason'])
        self.assertEqual(bounty_submit.hackerone_username('@granted'), 'granted')
        self.assertEqual(bounty_submit.hackerone_username('https://www.hackerone.com/granted/'), 'granted')


class PlaybookTests(SimpleTestCase):
    def test_every_section_names_sources_that_exist_and_are_https(self):
        pb = bounty_playbook.PLAYBOOK
        for key, src in pb['sources'].items():
            self.assertTrue(src['url'].startswith('https://'), key)
        for s in pb['sections']:
            self.assertTrue(s['sources'], s['id'])
            for k in s['sources']:
                self.assertIn(k, pb['sources'])

    def test_no_dashes_that_are_not_ascii_hyphens(self):
        blob = json.dumps(bounty_playbook.PLAYBOOK, ensure_ascii=False)
        self.assertNotIn('\u2014', blob)
        self.assertNotIn('\u2013', blob)

    def test_report_state_table_matches_the_documented_reputation_changes(self):
        table = dict((a, b) for a, b in next(s for s in bounty_playbook.PLAYBOOK['sections'] if s['id'] == 'after')['table'])
        self.assertIn('+7', table['Resolved'])
        self.assertIn('-5', table['Not Applicable'])
        self.assertIn('-10', table['Spam'])
        self.assertIn('30 days', table['Needs More Info'])


class RedactionBoundsTests(SimpleTestCase):
    def test_megabytes_of_private_key_openers_are_cut_before_they_are_scanned(self):
        import time
        started = time.monotonic()
        text, _ = br.redact('-----BEGIN RSA PRIVATE KEY----- ' * 200_000, 4000)
        self.assertLess(time.monotonic() - started, 2)
        self.assertLessEqual(len(text), 4000 + len('\n[truncated]'))

    def test_a_secret_just_past_the_limit_never_appears_in_the_output(self):
        body = 'x' * 3990 + ' password=hunter2hunter2 and AKIAABCDEFGHIJKLMNOP'
        text, count = br.redact(body, 4000)
        self.assertNotIn('hunter2hunter2', text)
        self.assertNotIn('AKIAABCDEFGHIJKLMNOP', text)
        self.assertGreaterEqual(count, 1)
