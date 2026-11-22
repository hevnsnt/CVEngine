"""How TLS audit (testssl.sh) findings read: the catalogue of every test, the plain translation of its result strings, titles that state the
confidence, the severity cap, the triage rule, the how-found labels, the page detail and the rewrite of stored findings."""
from types import SimpleNamespace

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import services
from agentapi.auth import create_token
from cveFeed import tls_audit, tls_catalogue as cat, triage, upgrade_backfills
from cveFeed.models import HygieneFinding
from dashboard.models import Org, Project, ProjectMembership
from targetApp.models import Domain
from tests.test_agentapi import call

WHERE = 'links.greetings.daliofamilyoffice.com:443'
HOST = 'links.greetings.daliofamilyoffice.com'


def ccs(result='likely VULNERABLE with 00', level='CRITICAL'):
    return tls_audit.build_finding('CCS', level, result, WHERE, ['CVE-2014-0224'])


class CatalogueTests(SimpleTestCase):
    def test_every_test_cvengine_records_has_a_complete_entry(self):
        recorded = set(tls_audit.VULNS) | set(tls_audit.CONFIG) | {cat.NO_HANDSHAKE}
        self.assertEqual(recorded - set(cat.CATALOGUE), set(), 'a recorded test has no catalogue entry')
        self.assertEqual(set(cat.CATALOGUE) - recorded, set(), 'the catalogue names a test cvENGINE does not record')
        for test_id, entry in cat.CATALOGUE.items():
            self.assertTrue(entry.name and entry.what and entry.fix and entry.steps and entry.read, test_id)
            self.assertIn(test_id, cat.TEST_LABELS, test_id)
            self.assertIn(entry.ceiling, (1, 2, 3, 4), test_id)
            for cve in entry.cves:
                self.assertRegex(cve, r'^CVE-\d{4}-\d{4,}$')
                if test_id in tls_audit.VULNS and len(entry.cves) == 1:
                    self.assertIn(cve, entry.name, test_id)  # the name carries the CVE where there is one
            self.assertLessEqual(len(entry.what.split()), 60, f'{test_id}: a practitioner reads it in 15 seconds')

    def test_every_check_name_maps_back_to_its_entry(self):
        for test_id in tls_audit.VULNS:
            self.assertIs(cat.entry_for(tls_audit.check_name(test_id)), cat.CATALOGUE[test_id])
        for test_id in tls_audit.CONFIG:
            self.assertIs(cat.entry_for(tls_audit.check_name(test_id)), cat.CATALOGUE[test_id])
        self.assertIs(cat.entry_for('tlsa_no_handshake'), cat.CATALOGUE[cat.NO_HANDSHAKE])

    def test_every_command_is_filled_with_the_host_and_port_and_is_read_only(self):
        for test_id in cat.CATALOGUE:
            for port in (443, 25):
                steps = cat.steps(test_id, HOST, port)
                self.assertEqual(len(steps), len(cat.CATALOGUE[test_id].steps), test_id)
                for step in steps:
                    command = step['command']
                    self.assertNotRegex(command, r'[{}]', command)
                    if '<origin-address>' in command or command.startswith('powershell'):  # the server behind a load balancer; a check on the Windows host itself
                        continue
                    self.assertIn(HOST, command)
                    if not (command.startswith('curl') and port == 443):  # an https URL names no default port
                        self.assertRegex(command, rf'\b{port}\b')
                    self.assertNotRegex(command, r'\b(sudo|rm|curl -X|-d |POST)\b')

    def test_the_ccs_commands_are_the_ones_a_practitioner_would_type(self):
        commands = [s['command'] for s in cat.steps('CCS', HOST, 443)]
        self.assertIn(f'nmap -Pn -p 443 --script ssl-ccs-injection {HOST}', commands)
        self.assertIn(f'testssl.sh --ccs {HOST}:443', commands)

    def test_a_starttls_port_gets_the_starttls_option_and_an_address_gets_no_server_name(self):
        smtp = [s['command'] for s in cat.steps('FS', HOST, 25)]
        self.assertEqual(smtp[0], f'testssl.sh --starttls smtp -f {HOST}:25')
        self.assertIn('-starttls smtp', smtp[1])
        v6 = cat.steps('FS', '2001:db8::1', 443)
        self.assertIn("'[2001:db8::1]:443'", v6[1]['command'])
        self.assertNotIn('-servername', v6[1]['command'])

    def test_a_host_that_is_not_a_name_gets_no_command(self):
        self.assertEqual(cat.steps('CCS', 'x; rm -rf /', 443), [])
        self.assertEqual(cat.steps('CCS', HOST, 0), [])

    def test_the_guide_has_the_headline_commands_fix_and_notice(self):
        g = cat.guide('tlsa_ccs', {'test': 'CCS'}, WHERE)
        self.assertEqual(g['headline'], f'Confirm OpenSSL CCS injection (CVE-2014-0224) on {WHERE}')
        self.assertEqual(g['class'], 'tls')
        self.assertIn('Upgrade OpenSSL', g['fix'])
        self.assertIn('does not run these commands', g['notice'])
        self.assertTrue(g['steps'] and g['verdict']['affected'])
        self.assertIsNone(cat.guide('spf_missing', {}, WHERE))


class TranslationTests(SimpleTestCase):
    def test_the_ccs_result_the_owner_asked_about(self):
        self.assertEqual(
            cat.describe_result('CCS', 'likely VULNERABLE with 00'),
            'The server answered an early ChangeCipherSpec probe with a 0x00 byte instead of rejecting it. testssl.sh reads that as likely vulnerable, but '
            'load balancers and TLS terminators often answer this way, so it is not proof.')

    def test_the_other_ccs_results(self):
        self.assertIn('bad_record_mac', cat.describe_result('CCS', 'likely VULNERABLE'))
        self.assertIn('CVE-2014-0224 flaw', cat.describe_result('CCS', 'VULNERABLE'))
        self.assertIn('0x0B byte', cat.describe_result('CCS', 'likely VULNERABLE with 0b'))

    def test_the_formats_testssl_3_2_emits(self):
        cases = {
            ('heartbleed', 'VULNERABLE'): 'memory',
            ('ticketbleed', 'VULNERABLE'): 'leaked server memory',
            ('ROBOT', 'VULNERABLE'): 'Bleichenbacher oracle',
            ('ROBOT', 'VULNERABLE, but the attack would take too long'): 'impractically long',
            ('secure_client_renego', 'VULNERABLE, DoS threat'): 'several times in a row',
            ('secure_client_renego', 'VULNERABLE, potential DoS threat'): 'accepted once',
            ('CRIME_TLS', 'VULNERABLE'): 'TLS compression',
            ('CRIME_TLS', 'VULNERABLE, but not using HTTP. Probably no exploit known'): 'not HTTP',
            ('BREACH', 'potentially VULNERABLE, gzip HTTP compression detected  - only supplied "/" tested'): 'compresses its HTTP responses (gzip)',
            ('POODLE_SSL', 'VULNERABLE, uses SSLv3+CBC'): 'SSLv3 with CBC',
            ('FREAK', 'VULNERABLE, uses EXPORT RSA ciphers'): 'export-grade RSA',
            ('LOGJAM', 'VULNERABLE, uses DH EXPORT ciphers'): 'export-grade Diffie-Hellman',
            ('DROWN', 'VULNERABLE, SSLv2 offered with 3 ciphers. Make sure you do not use this certificate elsewhere'): 'SSLv2 with 3 cipher',
            ('DROWN', 'SSLv2 offered, but could not detect a cipher. Make sure'): 'no cipher it accepts',
            ('winshock', 'probably vulnerable (NOT OK) - missing: TLS_DHE_RSA_WITH_AES_256_GCM_SHA384'): 'MS14-066 is missing (probably vulnerable)',
            ('winshock', 'seems vulnerable (NOT OK) '): 'guess from the cipher list',
            ('SWEET32', 'uses 64 bit block ciphers'): '64-bit blocks',
            ('SWEET32', 'uses 64 bit block ciphers with SSLv2 only'): 'only under SSLv2',
            ('RC4', 'VULNERABLE, Detected ciphers: RC4-SHA ECDHE-RSA-RC4-SHA'): 'RC4 cipher suites (RC4-SHA ECDHE-RSA-RC4-SHA)',
            ('BEAST', 'VULNERABLE -- but also supports higher protocols  TLSv1.1 TLSv1.2 (likely mitigated)'): 'also supports TLSv1.1 TLSv1.2',
            ('BEAST', 'VULNERABLE -- and no higher protocols as mitigation supported'): 'nothing newer',
            ('LUCKY13', 'potentially vulnerable, uses obsolete TLS CBC ciphers'): 'measures no timing',
            ('secure_renego', 'VULNERABLE'): 'secure renegotiation (RFC 5746)',
            ('fallback_SCSV', 'NOT supported'): 'cannot refuse a forced protocol downgrade',
            ('fallback_SCSV', 'received non-RFC-compliant "handshake failure" instead of "inappropriate fallback"'): 'not implemented correctly',
            ('FS', 'No ciphers supporting Forward Secrecy offered'): 'no cipher suite with forward secrecy',
            ('DH_groups', 'Unknown DH group (1024 bits)'): '1024 bits',
            ('SSLv3', 'offered'): 'POODLE',
            ('SSLv2', 'offered, no cipher'): 'no cipher suite it accepts',
            ('SSLv2', 'vulnerable with 5 ciphers'): 'speaks SSLv2',
            ('cipherlist_NULL', 'offered'): 'no encryption',
            ('cipherlist_aNULL', 'offered'): 'no authentication',
            ('cipherlist_EXPORT', 'offered'): 'export-grade',
            ('cipherlist_LOW', 'offered'): '64 bits or less',
            ('cipherlist_3DES_IDEA', 'offered'): '64-bit blocks',
        }
        for (test_id, text), expected in cases.items():
            sentence = cat.describe_result(test_id, text)
            self.assertIn(expected, sentence, (test_id, text, sentence))
            self.assertTrue(sentence.endswith('.'), sentence)
            self.assertNotIn('NOT ok', sentence)
            self.assertNotIn('VULNERABLE', sentence, (test_id, text, sentence))

    def test_the_generic_patterns(self):
        for word in ('likely', 'probably', 'seems', 'potentially'):
            sentence = cat.describe_result('somethingnew', f'{word} VULNERABLE (NOT ok)')
            self.assertIn(f'{word} vulnerable', sentence)
            self.assertIn('not confirmed', sentence)
        self.assertEqual(cat.describe_result('somethingnew', 'VULNERABLE (NOT ok)'), "testssl.sh's test reports the server as vulnerable.")
        self.assertIn('(uses odd thing)', cat.describe_result('somethingnew', 'VULNERABLE, uses odd thing'))
        self.assertEqual(cat.describe_result('somethingnew', 'weird'), 'testssl.sh reported "weird" for this test.')


class AssessmentTests(SimpleTestCase):
    def test_plain_vulnerable_is_proven_and_titled_confirmed(self):
        f = tls_audit.build_finding('heartbleed', 'CRITICAL', 'VULNERABLE', 'x.test:443', ['CVE-2014-0160'])
        self.assertEqual((f['severity'], f['title']), (4, 'Heartbleed (CVE-2014-0160) confirmed on x.test:443'))
        self.assertEqual((f['evidence']['proven'], f['evidence']['confidence']), (True, 'confirmed'))
        proven = tls_audit.build_finding('CCS', 'CRITICAL', 'VULNERABLE', 'x.test:443', ['CVE-2014-0224'])
        self.assertEqual(proven['title'], 'OpenSSL CCS injection (CVE-2014-0224) confirmed on x.test:443')

    def test_a_likely_result_is_titled_possible_not_confirmed_and_never_critical(self):
        f = ccs()
        self.assertEqual(f['title'], f'Possible OpenSSL CCS injection (CVE-2014-0224) on {WHERE}, not confirmed')
        self.assertEqual(f['severity'], 2)
        self.assertEqual((f['evidence']['proven'], f['evidence']['confidence'], f['evidence']['state']), (False, 'unconfirmed', 'possible'))
        self.assertEqual((f['evidence']['testssl_severity'], f['evidence']['result']), ('critical', 'likely VULNERABLE with 00'))
        self.assertNotIn('VULNERABLE', f['detail'])

    def test_a_proven_ccs_is_high_not_critical_because_it_needs_a_man_in_the_middle(self):
        f = ccs('VULNERABLE')
        self.assertEqual(f['severity'], 3)
        self.assertEqual(f['evidence']['testssl_severity'], 'critical')

    def test_nothing_that_is_not_proven_is_above_medium(self):
        for test_id in tls_audit.VULNS:
            for text in ('likely VULNERABLE', 'probably vulnerable (NOT OK)', 'seems vulnerable (NOT OK)', 'potentially vulnerable, x',
                         'VULNERABLE -- but also supports higher protocols TLSv1.2 (likely mitigated)', 'uses 64 bit block ciphers'):
                f = tls_audit.build_finding(test_id, 'CRITICAL', text, 'x.test:443', [])
                self.assertLessEqual(f['severity'], 2, (test_id, text))
                self.assertEqual(f['evidence']['confidence'], 'unconfirmed', (test_id, text))
                self.assertEqual(f['evidence']['testssl_severity'], 'critical')

    def test_the_proven_severity_of_each_test(self):
        chosen = {test_id: tls_audit.build_finding(test_id, 'CRITICAL', 'VULNERABLE', 'x.test:443', [])['severity']
                  for test_id in tls_audit.VULNS if tls_audit.VULNS[test_id][1]}
        self.assertEqual(chosen['heartbleed'], 4)
        self.assertEqual({chosen[t] for t in ('CCS', 'ticketbleed', 'ROBOT', 'FREAK', 'DROWN', 'LOGJAM')}, {3})
        self.assertEqual({chosen[t] for t in ('secure_client_renego', 'CRIME_TLS', 'POODLE_SSL', 'POODLE_TLS', 'RC4')}, {2})
        self.assertEqual(chosen['SWEET32'], 1)  # a precondition (64-bit blocks), never an exploit
        self.assertTrue(max(chosen.values()) <= 4)

    def test_a_lower_testssl_severity_is_never_raised(self):
        self.assertEqual(tls_audit.build_finding('secure_client_renego', 'MEDIUM', 'VULNERABLE, potential DoS threat', 'x.test:443', [])['severity'], 2)
        self.assertEqual(tls_audit.build_finding('CCS', 'LOW', 'VULNERABLE', 'x.test:443', [])['evidence']['proven'], False)  # low is not proof

    def test_a_configuration_result_is_a_direct_observation_at_testssls_severity_held_to_the_ceiling(self):
        null = tls_audit.build_finding('cipherlist_NULL', 'CRITICAL', 'offered', 'x.test:443', [])
        self.assertEqual((null['severity'], null['title'], null['evidence']['confidence']), (4, 'x.test:443 offers NULL ciphers (no encryption)', 'confirmed'))
        renego = tls_audit.build_finding('secure_renego', 'CRITICAL', 'VULNERABLE', 'x.test:443', [])
        self.assertEqual(renego['severity'], 2)
        self.assertEqual(renego['evidence']['testssl_severity'], 'critical')

    def test_an_exposure_is_titled_as_a_precondition(self):
        f = tls_audit.build_finding('BREACH', 'MEDIUM', 'potentially VULNERABLE, gzip HTTP compression detected', 'x.test:443', ['CVE-2013-3587'])
        self.assertEqual(f['title'], 'BREACH, HTTP compression (CVE-2013-3587): precondition present on x.test:443, not confirmed exploitable')
        self.assertEqual(f['severity'], 2)

    def test_evaluate_uses_the_same_findings(self):
        from tests.test_tls_audit import CLEAN, item, report
        result = tls_audit.evaluate(report(item('CCS', 'CRITICAL', 'likely VULNERABLE with 00', 'CVE-2014-0224')), 'x.test:443')
        finding = next(f for f in result.findings if f['check'] == 'tlsa_ccs')
        self.assertEqual(finding['title'], 'Possible OpenSSL CCS injection (CVE-2014-0224) on x.test:443, not confirmed')
        self.assertEqual(result.vulnerable, {})  # not proof: no CVE evidence either
        proven = tls_audit.evaluate(report(item('CCS', 'CRITICAL', 'VULNERABLE', 'CVE-2014-0224')), 'x.test:443')
        self.assertEqual(proven.vulnerable['CCS']['severity'], 3)
        self.assertEqual(len(tls_audit.evaluate(CLEAN, 'x.test:443').findings), 2)


class TriageRuleTests(SimpleTestCase):
    def test_an_unconfirmed_testssl_result_is_not_hard_evidence(self):
        self.assertEqual(triage.hard_evidence('hygiene', {'testssl': 'unconfirmed'}), ('', []))

    def test_a_confirmed_testssl_result_and_any_other_hygiene_finding_still_count(self):
        floor, found = triage.hard_evidence('hygiene', {'testssl': 'confirmed'})
        self.assertEqual(floor, 'confirmed')
        self.assertIn('testssl.sh confirmed', found[0])
        self.assertEqual(triage.hard_evidence('hygiene', {}), ('confirmed', ['a deterministic check failed']))

    def test_the_models_needs_validation_stands_for_an_unconfirmed_result(self):
        parsed = {'classification': 'needs_validation', 'reason': 'a load balancer often answers this way', 'model_reason': '', 'impact': '',
                  'remediation': '', 'validation_steps': [], 'severity_adjust': 0, 'severity_reason': ''}
        out = triage.apply_rules('hygiene', {'testssl': 'unconfirmed'}, dict(parsed))
        self.assertEqual((out['classification'], out['hard_evidence']), ('needs_validation', []))
        out = triage.apply_rules('hygiene', {}, dict(parsed))
        self.assertEqual(out['classification'], 'confirmed')  # the old rule, for every other hygiene finding

    def test_the_description_carries_the_confidence_into_the_signature(self):
        row = SimpleNamespace(host=WHERE, domain=SimpleNamespace(name='daliofamilyoffice.com'), check_name='tlsa_ccs', severity=2, title='t', detail='d',
                              evidence=ccs()['evidence'])
        d = triage.describe_hygiene(row)
        self.assertEqual(d['facts']['testssl'], 'unconfirmed')
        self.assertEqual(d['signature_fields']['testssl'], 'unconfirmed')
        self.assertEqual(triage.hard_evidence(d['kind'], d['facts']), ('', []))
        other = SimpleNamespace(**{**vars(row), 'check_name': 'spf_missing', 'evidence': {}})
        self.assertNotIn('testssl', triage.describe_hygiene(other)['facts'])

    def test_a_stored_finding_without_the_confidence_is_judged_from_its_result(self):
        old = {'source': 'testssl.sh', 'test': 'CCS', 'result': 'likely VULNERABLE with 00', 'cve': ['CVE-2014-0224']}
        self.assertEqual(tls_audit.confidence_of('tlsa_ccs', old, 4), 'unconfirmed')
        self.assertEqual(tls_audit.confidence_of('tlsa_ccs', {**old, 'result': 'VULNERABLE'}, 4), 'confirmed')
        self.assertEqual(tls_audit.confidence_of('tlsa_sslv3', {'source': 'testssl.sh', 'test': 'SSLv3', 'result': 'offered'}, 3), 'confirmed')
        self.assertEqual(tls_audit.confidence_of('spf_missing', {}, 2), '')


class HowFoundTests(SimpleTestCase):
    def row(self, **kw):
        base = {'check_name': 'tlsa_ccs', 'host': WHERE, 'severity': 2, 'evidence': ccs()['evidence']}
        return SimpleNamespace(**{**base, **kw})

    def test_labels_are_plain_english_and_cves_are_text(self):
        how = services._how_found_hygiene(self.row())
        by = {s['label']: s['value'] for s in how['steps']}
        self.assertEqual(by['Test'], 'testssl.sh CCS injection test')
        self.assertEqual(by['Found by'], 'testssl.sh TLS audit, run by a Sentinel')
        self.assertEqual(by['CVE'], 'CVE-2014-0224')
        self.assertEqual(by['Severity reported by testssl.sh'], 'Critical')
        self.assertIn('never rated above Medium', by['Severity here'])
        self.assertTrue(by['Confidence'].startswith('Not confirmed'))
        for step in how['steps']:
            self.assertRegex(step['label'], r'^[A-Z]')
            self.assertNotRegex(step['value'], r"[\[\]{}]|tlsa_|'CVE")
            self.assertNotIn('likely VULNERABLE', step['value'])
        self.assertEqual(how['excerpts'], {'testssl_output': 'likely VULNERABLE with 00'})

    def test_no_list_repr_is_shown_anywhere(self):
        self.assertEqual(services._kv('CVE', ['CVE-2014-0224', 'CVE-2014-0160'])['value'], 'CVE-2014-0224, CVE-2014-0160')
        self.assertEqual(services._kv('x', {'days_left': 3, 'ok': True})['value'], 'Days left: 3; Ok: Yes')
        self.assertEqual(services._kv('x', None)['value'], '')
        for value in (['a', 'b'], {'k': ['a']}, ('a', 'b'), {'a', 'b'}):
            self.assertNotRegex(services._kv('x', value)['value'], r"[\[\]'{}]")

    def test_other_hygiene_findings_get_plain_labels_and_no_reprs(self):
        row = SimpleNamespace(check_name='tls_expiring', host='www.x.test:443', severity=2,
                              evidence={'days_left': 4, 'names': ['a.x.test', 'b.x.test'], 'issuer': 'R3', 'rating': {'from': 3, 'why': ['managed platform']}})
        by = {s['label']: s['value'] for s in services._how_found_hygiene(row)['steps']}
        self.assertEqual(by['Check'], 'TLS expiring')
        self.assertEqual((by['Days left'], by['Names']), ('4', 'a.x.test, b.x.test'))
        self.assertEqual(by['Severity adjusted'], 'Lowered from High: managed platform')
        self.assertNotIn('Rating', by)


class FindingPageTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        org = Org.objects.create(name='T', slug='t-org')
        cls.project = Project.objects.create(name='Dalio', slug='dalio', insert_date=now, org=org)
        cls.domain = Domain.objects.create(name='daliofamilyoffice.com', project=cls.project, insert_date=now)
        user = User.objects.create_user('tlsuser', password='x')
        ProjectMembership.objects.create(user=user, project=cls.project, role='user')
        _, cls.token = create_token(user, 'agent')

    def stored(self, finding=None, **kw):
        finding = finding or ccs()
        return HygieneFinding.objects.create(domain=self.domain, host=WHERE, check_name=finding['check'], severity=finding['severity'],
                                             title=finding['title'], detail=finding['detail'], evidence=finding['evidence'], **kw)

    def detail(self, row):
        status, data = call(self.token, 'GET', f'/api/v1/projects/dalio/findings/hygiene/{row.id}')
        self.assertEqual(status, 200)
        return data

    def test_the_page_says_what_it_is_how_to_confirm_it_and_the_fix(self):
        data = self.detail(self.stored())
        self.assertEqual(data['title'], f'Possible OpenSSL CCS injection (CVE-2014-0224) on {WHERE}, not confirmed')
        self.assertEqual(data['severity'], 'medium')
        self.assertTrue(data['description'].startswith('The server answered an early ChangeCipherSpec probe with a 0x00 byte'))
        self.assertNotIn('likely VULNERABLE', data['description'])
        self.assertIn('man-in-the-middle', data['why_it_matters'])
        self.assertEqual(data['how_found']['excerpts'], {'testssl_output': 'likely VULNERABLE with 00'})
        commands = [s['command'] for s in data['confirm']['steps']]
        self.assertIn(f'nmap -Pn -p 443 --script ssl-ccs-injection {HOST}', commands)
        self.assertIn(f'testssl.sh --ccs {HOST}:443', commands)
        self.assertIn('Upgrade OpenSSL', data['remediation']['scanner'])
        self.assertIn('does not run these commands', data['confirm']['notice'])

    def test_a_finding_of_another_kind_has_no_tls_context(self):
        row = HygieneFinding.objects.create(domain=self.domain, host='www.daliofamilyoffice.com', check_name='spf_missing', severity=2, title='No SPF',
                                            detail='The domain publishes no SPF record.', evidence={'record': 'none', 'mx': ['a', 'b']})
        data = self.detail(row)
        self.assertEqual(data['confirm']['class'], 'hygiene')  # its own read-only check (cveFeed.finding_confirm), not a TLS audit guide
        self.assertNotEqual(data['confirm'].get('class_label'), 'testssl.sh TLS audit')
        self.assertEqual(data['description'], 'The domain publishes no SPF record.')
        by = {s['label']: s['value'] for s in data['how_found']['steps']}
        self.assertEqual(by['Mx'] if 'Mx' in by else by['MX'], 'a, b')


class RewriteTests(TestCase):
    """The upgrade backfill: stored findings say what a new test would."""

    @classmethod
    def setUpTestData(cls):
        org = Org.objects.create(name='R', slug='rw-org')
        cls.project = Project.objects.create(name='RW', slug='rw', insert_date=timezone.now(), org=org)
        cls.domain = Domain.objects.create(name='daliofamilyoffice.com', project=cls.project, insert_date=timezone.now())

    def legacy(self, **kw):
        """A finding as the old code stored it: testssl.sh's own severity, "may apply", the raw string as the description."""
        base = {'domain': self.domain, 'host': WHERE, 'check_name': 'tlsa_ccs', 'severity': 4,
                'title': f'{WHERE}: CCS injection may apply', 'detail': 'likely VULNERABLE with 00',
                'evidence': {'source': 'testssl.sh', 'test': 'CCS', 'result': 'likely VULNERABLE with 00', 'cve': ['CVE-2014-0224']}}
        return HygieneFinding.objects.create(**{**base, **kw})

    def test_it_is_in_the_upgrade_list_before_the_final_rescore(self):
        names = upgrade_backfills.BACKFILLS
        self.assertLess(names.index('rewrite_tls_findings'), names.index('rerate_findings'))
        self.assertEqual(names[-1], 'rerate_findings')

    def test_a_stored_finding_is_rewritten_from_its_evidence(self):
        row = self.legacy()
        out = tls_audit.rewrite_open(apply=True)
        self.assertEqual(out, {'rows': 1, 'changed': 1, 'lowered': 1})
        row.refresh_from_db()
        self.assertEqual(row.title, f'Possible OpenSSL CCS injection (CVE-2014-0224) on {WHERE}, not confirmed')
        self.assertEqual(row.severity, 2)
        self.assertTrue(row.detail.startswith('The server answered an early ChangeCipherSpec probe with a 0x00 byte'))
        self.assertEqual((row.evidence['confidence'], row.evidence['testssl_severity'], row.evidence['result']),
                         ('unconfirmed', 'critical', 'likely VULNERABLE with 00'))
        self.assertEqual(row.status, 'open')

    def test_a_dry_run_writes_nothing_and_a_second_run_finds_nothing_to_change(self):
        row = self.legacy()
        self.assertEqual(tls_audit.rewrite_open()['changed'], 1)
        row.refresh_from_db()
        self.assertEqual(row.severity, 4)
        tls_audit.rewrite_open(apply=True)
        self.assertEqual(tls_audit.rewrite_open(apply=True), {'rows': 1, 'changed': 0, 'lowered': 0})
        again = HygieneFinding.objects.get(pk=row.pk)
        self.assertEqual((again.severity, again.evidence['testssl_severity']), (2, 'critical'))  # the original rating is never forgotten

    def test_a_proven_finding_keeps_a_sensible_severity_and_says_confirmed(self):
        row = self.legacy(check_name='tlsa_heartbleed', severity=4, title=f'{WHERE}: Heartbleed is exploitable', detail='VULNERABLE',
                          evidence={'source': 'testssl.sh', 'test': 'heartbleed', 'result': 'VULNERABLE', 'cve': ['CVE-2014-0160']})
        ccs_row = self.legacy(evidence={'source': 'testssl.sh', 'test': 'CCS', 'result': 'VULNERABLE', 'cve': ['CVE-2014-0224']})
        tls_audit.rewrite_open(apply=True)
        row.refresh_from_db()
        ccs_row.refresh_from_db()
        self.assertEqual((row.severity, row.title), (4, f'Heartbleed (CVE-2014-0160) confirmed on {WHERE}'))
        self.assertEqual((ccs_row.severity, ccs_row.evidence['confidence']), (3, 'confirmed'))

    def test_closed_findings_other_checks_and_a_persons_work_are_left_alone(self):
        closed = self.legacy(status='resolved')
        spf = self.legacy(check_name='spf_missing', host='daliofamilyoffice.com', evidence={'record': 'none'})
        worked = self.legacy(check_name='tlsa_rc4', host='x.daliofamilyoffice.com:443', remediation_status='accepted_risk', remediation_note='vendor',
                             evidence={'source': 'testssl.sh', 'test': 'RC4', 'result': 'VULNERABLE, Detected ciphers: RC4-SHA', 'cve': []})
        tls_audit.rewrite_open(apply=True)
        closed.refresh_from_db()
        spf.refresh_from_db()
        worked.refresh_from_db()
        self.assertEqual((closed.severity, closed.title), (4, f'{WHERE}: CCS injection may apply'))
        self.assertEqual(spf.evidence, {'record': 'none'})
        self.assertEqual((worked.remediation_status, worked.remediation_note), ('accepted_risk', 'vendor'))
        self.assertEqual(worked.title, 'RC4 cipher suites (CVE-2013-2566, CVE-2015-2808) confirmed on x.daliofamilyoffice.com:443')

    def test_a_severity_an_endpoint_rule_lowered_stays_lowered_and_other_evidence_is_kept(self):
        row = self.legacy(check_name='tlsa_breach', severity=1,
                          evidence={'source': 'testssl.sh', 'test': 'BREACH', 'result': 'potentially VULNERABLE, gzip HTTP compression detected',
                                    'cve': ['CVE-2013-3587'], 'rating': {'from': 2, 'why': ['no session cookie']}, 'session_context': {'authenticated': False}})
        tls_audit.rewrite_open(apply=True)
        row.refresh_from_db()
        self.assertEqual(row.severity, 1)
        self.assertEqual(row.evidence['rating'], {'from': 2, 'why': ['no session cookie']})
        self.assertEqual(row.evidence['session_context'], {'authenticated': False})
        self.assertEqual(row.evidence['testssl_severity'], 'medium')

    def test_a_row_with_no_test_result_is_not_touched_and_the_run_is_bounded(self):
        bare = self.legacy(check_name='tlsa_no_handshake', evidence={'source': 'testssl.sh', 'test': 'protocols', 'result': 'TLS1: not offered'})
        odd = self.legacy(check_name='tlsa_fs', host='odd.daliofamilyoffice.com:443', evidence={'source': 'testssl.sh', 'test': 'FS'})
        for i in range(3):
            self.legacy(host=f'h{i}.daliofamilyoffice.com:443')
        self.assertEqual(tls_audit.rewrite_open(apply=True, limit=2)['rows'], 2)
        self.assertEqual(HygieneFinding.objects.filter(pk__in=[bare.pk, odd.pk], title__startswith='Possible').count(), 0)

    def test_the_command_runs_as_the_backfill_does(self):
        from django.core.management import call_command
        from io import StringIO
        self.legacy()
        out = StringIO()
        call_command('rewrite_tls_findings', stdout=out)
        self.assertIn('Dry run: 1 of 1', out.getvalue())
        call_command('rewrite_tls_findings', apply=True, stdout=out)
        self.assertIn('Applied: 1 of 1', out.getvalue())
