"""SSH, SMTP, SMB and RDP service features (cveFeed.address_features, the rules in detection_classes.FEATURE_RULES): which advisories need which
reading, what each reading does to a match (rule out, raise within the ceiling, unknown), and how the nmap fingerprint pass's and the ssh_probe
kind's readings, made of an address, reach the project's host names at that address."""
import re
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import probe_dispatch, sentinel_dispatch
from cveFeed import address_features, correlation, service_features, ssh_scan
from cveFeed.detection_classes import feature_preconditions
from cveFeed.models import CVEEntry, CVEMatch, ServiceFeature
from dashboard.models import Org, Project
from startScan.models import IpAddress, Port, Subdomain
from targetApp.models import Domain

# The advisories the rules were written for, as NVD words them: (CVE, feature, rule).
NEEDS = (
    ('CVE-2023-48795', 'ssh_terrapin', 'The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6 and other products, '
     'allows remote attackers to bypass integrity checks such that some packets are omitted (from the extension negotiation message), and a client '
     'and server may consequently end up with a connection for which some security features have been downgraded or disabled, aka a Terrapin attack.'),
    ('CVE-2008-5161', 'ssh_cbc', 'Error handling in the SSH protocol in (1) SSH Tectia Client and Server and Connector 4.0 through 4.4.11, 5.0 '
     'through 5.2.4, and 5.3 through 5.3.8; Client and Server and ConnectSecure 6.0 through 6.0.4; Server for Linux on IBM System z 6.0.4; Server '
     'for IBM z/OS 5.5.1 and earlier, 6.0.0, and 6.0.1; and Client 4.0-J through 4.3.3-J and 4.0-K through 4.3.10-K; and (2) OpenSSH 4.7p1 and '
     'possibly other versions, when using a block cipher algorithm in Cipher Block Chaining (CBC) mode, makes it easier for remote attackers to '
     'recover certain plaintext data from an arbitrary block of ciphertext in an SSH session via unknown vectors.'),
    ('CVE-2013-4548', 'ssh_aes_gcm', 'The mm_newkeys_from_blob function in monitor_wrap.c in sshd in OpenSSH 6.2 and 6.3, when an AES-GCM cipher is '
     'used, does not properly initialize memory for a MAC context data structure, which allows remote authenticated users to bypass intended '
     'ForceCommand and login-shell restrictions via packet data that provides a crafted callback address.'),
    ('CVE-2017-16943', 'smtp_chunking', 'The receive_msg function in receive.c in the SMTP daemon in Exim 4.88 and 4.89 allows remote attackers to '
     'execute arbitrary code or cause a denial of service (use-after-free) via vectors involving BDAT commands.'),
    ('CVE-2017-16944', 'smtp_chunking', 'The receive_msg function in receive.c in the SMTP daemon in Exim 4.88 and 4.89 allows remote attackers to '
     'cause a denial of service (infinite loop and stack exhaustion) via vectors involving BDAT commands and an improper check for a \'.\' character '
     'signifying the end of the content, related to the bdat_getc function.'),
    ('CVE-2023-42114', 'smtp_auth', 'Exim NTLM Challenge Out-Of-Bounds Read Information Disclosure Vulnerability. This vulnerability allows remote '
     'attackers to disclose sensitive information on affected installations of Exim. Authentication is not required to exploit this vulnerability.'
     '\n\nThe specific flaw exists within the handling of NTLM challenge requests.'),
    ('CVE-2023-42116', 'smtp_auth', 'Exim SMTP Challenge Stack-based Buffer Overflow Remote Code Execution Vulnerability. This vulnerability allows '
     'remote attackers to execute arbitrary code on affected installations of Exim.\n\nThe specific flaw exists within the handling of NTLM '
     'challenge requests.'),
    ('CVE-2020-12783', 'smtp_auth', 'Exim through 4.93 has an out-of-bounds read in the SPA authenticator that could result in SPA/NTLM '
     'authentication bypass in auths/spa.c and auths/auth-spa.c.'),
    ('CVE-2011-0411', 'smtp_starttls', 'The STARTTLS implementation in Postfix 2.4.x before 2.4.16, 2.5.x before 2.5.12, 2.6.x before 2.6.9, and '
     '2.7.x before 2.7.3 does not properly restrict I/O buffering, which allows man-in-the-middle attackers to insert commands into encrypted SMTP '
     'sessions by sending a cleartext command that is processed after TLS is in place, related to a "plaintext command injection" attack.'),
    ('CVE-2021-33515', 'smtp_starttls', 'The submission service in Dovecot before 2.3.15 allows STARTTLS command injection in lib-smtp. Sensitive '
     'information can be redirected to an attacker-controlled address.'),
    ('CVE-2017-0144', 'smbv1', 'The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; '
     'Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to '
     'execute arbitrary code via crafted packets, aka "Windows SMB Remote Code Execution Vulnerability."'),
    ('CVE-2017-11780', 'smbv1', 'The Server Message Block 1.0 (SMBv1) on Microsoft Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1 ... allows a '
     'remote code execution vulnerability when it fails to properly handle certain requests, aka "Windows SMB Remote Code Execution Vulnerability".'),
    ('CVE-2020-1301', 'smbv1', 'A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 1.0 (SMBv1) server '
     'handles certain requests, aka \'Windows SMB Remote Code Execution Vulnerability\'.'),
    ('CVE-2020-0796', 'smb_compression', 'A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 '
     '(SMBv3) protocol handles certain requests, aka \'Windows SMBv3 Client/Server Remote Code Execution Vulnerability\'.'),
    ('CVE-2020-1206', 'smb_compression', 'An information disclosure vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 '
     '(SMBv3) protocol handles certain requests, aka \'Windows SMBv3 Client/Server Information Disclosure Vulnerability\'.'),
    ('CVE-2019-0708', 'rdp_nla', 'A remote code execution vulnerability exists in Remote Desktop Services formerly known as Terminal Services when '
     'an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka \'Remote Desktop Services '
     'Remote Code Execution Vulnerability\'.'),
    ('CVE-2019-1181', 'rdp_nla', 'A remote code execution vulnerability exists in Remote Desktop Services - formerly known as Terminal Services - '
     'when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests. This vulnerability is '
     'pre-authentication and requires no user interaction.'),
)

# Advisories near these words that must need no SSH, SMTP, SMB or RDP reading.
UNRELATED = (
    ('CVE-2020-0609', 'A remote code execution vulnerability exists in Windows Remote Desktop Gateway (RD Gateway) when an unauthenticated attacker '
     'connects to the target system using RDP and sends specially crafted requests.'),
    ('CVE-2013-0169', 'The TLS protocol 1.1 and 1.2 and the DTLS protocol 1.0 and 1.2, as used in OpenSSL, OpenJDK, PolarSSL, and other products, '
     'do not properly consider timing side-channel attacks on a MAC check requirement during the processing of malformed CBC padding.'),
    ('CVE-2016-2183', 'The DES and Triple DES ciphers, as used in the TLS, SSH, and IPSec protocols and other protocols and products, have a birthday '
     'bound of approximately four billion blocks, which makes it easier for remote attackers to obtain cleartext data via a birthday attack against '
     'a long-duration encrypted session, as demonstrated by an HTTPS session using Triple DES in CBC mode, aka a "Sweet32" attack.'),
    ('CVE-2011-1926', 'The STARTTLS implementation in Cyrus IMAP Server before 2.4.7 does not properly restrict I/O buffering, which allows '
     'man-in-the-middle attackers to insert commands into encrypted sessions by sending a cleartext command that is processed after TLS is in place.'),
    ('CVE-2021-38371', 'The STARTTLS feature in Exim through 4.94.2 allows response injection (buffering) during MTA SMTP sending.'),
    ('CVE-2019-1040', 'A tampering vulnerability exists in Microsoft Windows when a man-in-the-middle attacker is able to successfully bypass NTLM MIC '
     '(Message Integrity Check) protection, aka \'Windows NTLM Tampering Vulnerability\'.'),
    ('CVE-2099-0002', 'A Windows NTLM challenge handling flaw lets an attacker relay credentials.'),
    ('CVE-2099-0003', 'The SMBv1 and SMBv2 servers mishandle a crafted request.'),
)


class RuleTests(SimpleTestCase):
    def test_each_advisory_needs_its_feature(self):
        for cve, feature, text in NEEDS:
            got = feature_preconditions('', text)
            self.assertEqual(list(got), [feature], cve)
            self.assertTrue(got[feature]['rule_out'], cve)
            self.assertTrue(got[feature]['quote'], cve)

    def test_unrelated_advisories_need_nothing(self):
        for cve, text in UNRELATED:
            self.assertEqual(feature_preconditions('', text), {}, cve)

    def test_values_that_expose_and_clear(self):
        def need(cve):
            text = next(t for c, _f, t in NEEDS if c == cve)
            return next(iter(feature_preconditions('', text).values()))
        terrapin, ntlm, nla = need('CVE-2023-48795'), need('CVE-2023-42114'), need('CVE-2019-0708')
        self.assertEqual((terrapin['exposed'], set(terrapin['clears'])), (('exposed',), {'strict_kex', 'no_affected_mode'}))
        self.assertEqual((nla['exposed'], nla['clears']), (('not_required',), ('required',)))
        self.assertTrue(service_features._exposes('plain,ntlm,tls_unread', ntlm))
        self.assertTrue(service_features._clears('plain,login', ntlm))
        self.assertTrue(service_features._clears('none', ntlm))
        self.assertFalse(service_features._clears('plain,login,tls_unread', ntlm))  # AUTH after STARTTLS was not read: never cleared
        self.assertFalse(service_features._clears('tls_unread', ntlm))

    def test_the_relevant_ports(self):
        server = service_features.server
        self.assertTrue(server('ssh_terrapin').relevant(2222, 'ssh', ''))
        self.assertFalse(server('ssh_terrapin').relevant(443, 'https', 'ssl'))
        self.assertTrue(server('smtp_chunking').relevant(587, 'submission', ''))
        self.assertFalse(server('smtp_chunking').relevant(465, 'smtp', 'ssl'))
        self.assertTrue(server('smbv1').relevant(445, 'microsoft-ds', ''))
        self.assertFalse(server('smbv1').relevant(139, 'netbios-ssn', ''))
        self.assertTrue(server('rdp_nla').relevant(3390, 'ms-wbt-server', ''))
        for key in address_features.FINGERPRINT_FEATURES + address_features.SSH_PROBE_FEATURES:
            self.assertFalse(server(key).edge_sensitive, key)


class NetCase(TestCase):
    def setUp(self):
        service_features.reset_index()
        self.addCleanup(service_features.reset_index)
        now = timezone.now()
        self.project = Project.objects.create(name='N', slug='nf', insert_date=now, org=Org.objects.create(name='N', slug='nfo'))
        self.domain = Domain.objects.create(name='example.test', project=self.project, insert_date=now)
        self.ip = IpAddress.objects.create(address='198.51.100.7')
        self.subs = []
        for name in ('mail.example.test', 'gw.example.test'):
            sub = Subdomain.objects.create(name=name, target_domain=self.domain)
            sub.ip_addresses.add(self.ip)
            self.subs.append(sub)
        self.sub = self.subs[0]
        for number, service in ((22, 'ssh'), (25, 'smtp'), (445, 'microsoft-ds'), (3389, 'ms-wbt-server')):
            self.ip.ports.add(Port.objects.create(number=number, service_name=service))

    def item(self, port, feature, value, host='198.51.100.7', detail=''):
        return {'host': host, 'port': port, 'transport': 'tcp', 'feature': feature, 'value': value, 'detail': detail}

    def cve(self, cve_id):
        text = next(t for c, _f, t in NEEDS if c == cve_id)
        return CVEEntry.objects.create(cve_id=cve_id, status='PUBLISHED', published_at=timezone.now(), title='', original_description=text,
                                       affected=[{'vendor': 'x', 'product': 'x', 'ranges': [{'introduced': '1.0', 'fixed': '9.0'}]}])

    def match(self, cve, sub=None):
        return CVEMatch.objects.create(cve_entry=cve, subdomain=sub or self.sub, source='tech', matched_product='x', matched_version='2.0',
                                       version_in_range=True, confidence=0.6, evidence={'source': 'tech', 'raw_version': '2.0'})

    def fresh(self, match):
        return CVEMatch.objects.select_related('cve_entry', 'subdomain__target_domain').get(pk=match.pk)

    def nmap(self, items):
        sentinel_dispatch._store_nmap_features(self.project, {'service_features': items}, ['198.51.100.7'])


class AddressTests(NetCase):
    def test_a_reading_of_the_address_is_stored_for_every_name_at_it(self):
        self.nmap([self.item(445, 'smbv1', 'yes', detail='accepts an SMB1 NEGOTIATE (NT LM 0.12)'), self.item(3389, 'rdp_nla', 'required'),
                   self.item(445, 'smbv1', 'yes', host='203.0.113.9')])  # an address the task did not report: not stored
        rows = sorted(ServiceFeature.objects.values_list('host', 'port', 'feature', 'value', 'source'))
        self.assertEqual(rows, [('gw.example.test', 445, 'smbv1', 'yes', 'nmap'), ('gw.example.test', 3389, 'rdp_nla', 'required', 'nmap'),
                                ('mail.example.test', 445, 'smbv1', 'yes', 'nmap'), ('mail.example.test', 3389, 'rdp_nla', 'required', 'nmap')])

    def test_a_service_read_again_without_a_feature_loses_the_old_reading(self):
        self.nmap([self.item(445, 'smbv1', 'yes'), self.item(445, 'smb_dialect', '2.0.2'), self.item(25, 'smtp_chunking', 'yes')])
        self.nmap([self.item(445, 'smb_dialect', '3.1.1')])  # SMB read again, SMB1 silent this time: its reading is unknown now
        rows = set(ServiceFeature.objects.filter(host=self.sub.name).values_list('port', 'feature', 'value'))
        self.assertEqual(rows, {(445, 'smb_dialect', '3.1.1'), (25, 'smtp_chunking', 'yes')})  # SMTP was not read this time: kept

    def test_an_address_of_another_project_and_an_old_scan_are_not_used(self):
        other = Project.objects.create(name='O', slug='of', insert_date=timezone.now(), org=self.project.org)
        odom = Domain.objects.create(name='other.test', project=other, insert_date=timezone.now())
        Subdomain.objects.create(name='x.other.test', target_domain=odom).ip_addresses.add(self.ip)
        self.assertEqual(address_features.names_at(self.project.pk, ['198.51.100.7']),
                         {'198.51.100.7': ['198.51.100.7', 'gw.example.test', 'mail.example.test']})

    def test_more_readings_than_one_ingest_takes_are_stored_in_batches(self):
        for i in range(80):
            Subdomain.objects.create(name=f'h{i}.example.test', target_domain=self.domain).ip_addresses.add(self.ip)
        self.nmap([self.item(445, 'smbv1', 'no'), self.item(445, 'smb_signing', 'required')])
        self.assertEqual(ServiceFeature.objects.filter(feature='smbv1').count(), 82)


class SshProbeTests(NetCase):
    def test_the_rows_keep_their_readings_and_the_inspection_stores_them(self):
        result = {'hosts': [{'address': '198.51.100.7', 'port': 22, 'reached': True, 'observations': [], 'check_hits': []}],
                  'service_features': [self.item(22, 'ssh_terrapin', 'exposed'), self.item(22, 'ssh_auth_methods', 'publickey,password')]}
        with mock.patch.object(probe_dispatch, '_offered', return_value=True), \
                mock.patch.object(sentinel_dispatch, 'dispatch_or_none', return_value=result), \
                mock.patch('cveFeed.probe_scope.for_ssh', return_value={}):
            rows = probe_dispatch.try_ssh_probe(self.project, [('198.51.100.7', 22)])
        row = rows[('198.51.100.7', 22)]
        self.assertEqual([i['feature'] for i in row['service_features']], ['ssh_terrapin', 'ssh_auth_methods'])
        scan = SimpleNamespace(domain_id=self.domain.pk)  # the scan files a finding only for a compromised key
        ssh_scan.store_row(self.project.pk, scan, [self.sub], '198.51.100.7', 22, row)
        self.assertEqual(set(ServiceFeature.objects.values_list('host', 'feature', 'value', 'source')),
                         {('mail.example.test', 'ssh_terrapin', 'exposed', 'ssh_probe'),
                          ('mail.example.test', 'ssh_auth_methods', 'publickey,password', 'ssh_probe')})


class MatchTests(NetCase):
    def test_terrapin_strict_kex_closes_and_exposed_raises(self):
        match = self.match(self.cve('CVE-2023-48795'))
        self.nmap([self.item(22, 'ssh_terrapin', 'strict_kex', detail='offers chacha20-poly1305@openssh.com; offers kex-strict-s-v00@openssh.com')])
        match = self.fresh(match)
        self.assertEqual((match.ai_verdict, match.ai_model), ('not_affected', 'deterministic-correlation'))
        self.assertTrue(match.ai_reason.startswith(correlation.PRECONDITION_CLOSED))
        self.assertIn('offers strict key exchange', match.ai_reason)
        self.nmap([self.item(22, 'ssh_terrapin', 'exposed')])
        match = self.fresh(match)
        self.assertEqual(match.ai_verdict, '')  # reopened
        self.assertEqual(match.evidence['preconditions']['ssh_terrapin']['state'], 'exposed')
        self.assertGreater(match.confidence, 0.6)

    def test_nla_required_closes_bluekeep_as_the_precondition_not_met(self):
        match = self.match(self.cve('CVE-2019-0708'))
        self.nmap([self.item(3389, 'rdp_nla', 'required')])
        match = self.fresh(match)
        self.assertEqual(match.ai_verdict, 'not_affected')
        self.assertIn('requires Network Level Authentication', match.ai_reason)

    def test_smbv1_refused_closes_eternalblue_and_compression_off_closes_smbghost(self):
        eternal, ghost = self.match(self.cve('CVE-2017-0144')), self.match(self.cve('CVE-2020-0796'))
        self.nmap([self.item(445, 'smbv1', 'no'), self.item(445, 'smb_compression', 'no')])
        self.assertEqual(self.fresh(eternal).ai_verdict, 'not_affected')
        self.assertEqual(self.fresh(ghost).ai_verdict, 'not_affected')

    def test_an_ntlm_list_that_starttls_may_extend_never_closes(self):
        match = self.match(self.cve('CVE-2023-42114'))
        self.nmap([self.item(25, 'smtp_auth', 'plain,login,tls_unread')])
        match = self.fresh(match)
        self.assertEqual(match.ai_verdict, '')
        self.assertEqual(match.evidence['preconditions']['smtp_auth']['state'], 'unknown')
        self.nmap([self.item(25, 'smtp_auth', 'plain,login')])
        self.assertEqual(self.fresh(match).ai_verdict, 'not_affected')

    def test_chunking_listed_raises_and_a_second_smtp_port_not_read_keeps_it_open(self):
        self.ip.ports.add(Port.objects.create(number=587, service_name='submission'))
        match = self.match(self.cve('CVE-2017-16943'))
        self.nmap([self.item(25, 'smtp_chunking', 'no')])
        match = self.fresh(match)
        self.assertEqual(match.ai_verdict, '')  # 587 was not read: unknown
        self.assertEqual(match.evidence['preconditions']['smtp_chunking']['state'], 'unknown')
        self.nmap([self.item(25, 'smtp_chunking', 'no'), self.item(587, 'smtp_chunking', 'yes')])
        match = self.fresh(match)
        self.assertEqual(match.evidence['preconditions']['smtp_chunking']['state'], 'exposed')
        self.assertLess(match.confidence, 1.0)


class IndexTests(NetCase):
    def test_the_database_prefilter_finds_every_advisory(self):
        for cve_id, _feature, _text in NEEDS:
            self.cve(cve_id)
        found = {CVEEntry.objects.get(pk=pk).cve_id: set(needs) for pk, needs in service_features.index().items()}
        self.assertEqual(found, {cve_id: {feature} for cve_id, feature, _t in NEEDS})


# Texts around the edges of the prefilter: a word it names inside a longer word, its spellings with and without the optional parts, a match in
# each of the three columns alone, and texts that name nothing.
EDGE_TEXTS = (
    ('OAuth2 tokens leak through the h2o server', '', ''),  # "h2" only inside other words: no match
    ('', 'The H2 database console allows code execution.', ''),  # H2 as a word
    ('', 'nginx with HTTP2 enabled', ''), ('', 'when the http/2 module is used', ''), ('', 'an HTTP/3 QUIC endpoint', ''),
    ('Samba SMB 1 negotiation flaw', '', ''), ('', 'SMBv1 server', ''), ('', '', 'An Ssl-Vpn portal bug.'), ('', 'SSLVPN web portal', ''),
    ('', 'PHP CGI on Windows', ''), ('', 'php-cgi argument injection', ''), ('', 'the Best Fit mapping of Windows Code Pages', ''),
    ('', 'when configured as a Gateway or an AAA virtual server', ''), ('', 'when configured as gateway', ''),
    ('', 'a CBC-mode cipher', ''), ('', 'abcbcd', ''), ('', 'A crafted PNG file causes a crash in libfoo.', ''), ('', '', ''),
    ('Plain title', 'Plain text with nothing in it.', 'The summary names WebDAV.'),
)


class PrefilterTests(NetCase):
    """``service_features._worded`` picks, in Python, the rows the database regex used to pick (``title__iregex`` and so on)."""

    def database(self):
        from django.db.models import Q

        from cveFeed.detection_classes import FEATURE_PREFILTER
        words = Q(title__iregex=FEATURE_PREFILTER) | Q(original_description__iregex=FEATURE_PREFILTER) | Q(summary__iregex=FEATURE_PREFILTER)
        return set(CVEEntry.objects.filter(words).values_list('pk', flat=True))

    def entries(self):
        for cve_id, _feature, _text in NEEDS:
            self.cve(cve_id)
        for n, (title, description, summary) in enumerate(EDGE_TEXTS):
            CVEEntry.objects.create(cve_id=f'CVE-2099-{n:05d}', status='PUBLISHED', published_at=timezone.now(), title=title,
                                    original_description=description, summary=summary)

    def test_python_picks_the_rows_the_database_regex_picks(self):
        self.entries()
        picked = {row[0] for row in service_features._worded({})}
        self.assertEqual(picked, self.database())
        self.assertGreater(len(picked), len(NEEDS))  # the edge texts that name a feature are in it
        self.assertLess(len(picked), CVEEntry.objects.count())  # and the ones that do not are not

    def test_every_range_is_read_and_a_stated_record_is_kept_whatever_its_words(self):
        self.entries()
        plain = CVEEntry.objects.get(cve_id='CVE-2099-00016')  # "A crafted PNG file": no word of the prefilter
        with mock.patch.object(service_features, 'WORDS_CHUNK', 3):
            picked = {row[0] for row in service_features._worded({plain.pk: {}})}
        self.assertEqual(picked, self.database() | {plain.pk})

    def test_the_walk_holds_no_server_side_cursor(self):
        from django.db import connection
        from django.test.utils import CaptureQueriesContext
        self.entries()
        with mock.patch.object(service_features, 'WORDS_CHUNK', 10), CaptureQueriesContext(connection) as queries:
            list(service_features._worded({}))
        sql = [q['sql'] for q in queries.captured_queries]
        self.assertFalse([q for q in sql if 'DECLARE' in q or 'FETCH' in q])
        self.assertEqual(len(sql), CVEEntry.objects.count() // 10 + 1)  # one query per range, and one that finds the end
        self.assertTrue(all('~*' not in q and 'REGEXP' not in q.upper() for q in sql))


class NeedleTests(SimpleTestCase):
    """The substring test before the regex never drops a text the regex would take."""

    def test_the_real_prefilter_has_needles(self):
        regex, needles = service_features._prefilter()
        self.assertTrue(needles)
        self.assertIn('h2', needles)
        self.assertIn('ssl-vpn', needles)
        self.assertTrue(all(n.isascii() and n == n.lower() and len(n) >= 2 for n in needles))

    def test_each_literal_spelling_of_the_prefilter_contains_a_needle(self):
        from cveFeed.detection_classes import FEATURE_PREFILTER
        _regex, needles = service_features._prefilter()
        for spelling in ('http2', 'HTTP/2', 'ngx_http_v2', 'h2c', 'terrapin', 'smb 1', 'SMB1', 'ssl vpn', 'sslvpn', 'php-cgi', 'Best fit',
                         'windows codepage', 'Windows Code Pages', 'configured as an gateway', 'port 427', 'service location protocol'):
            self.assertTrue(re.search(service_features._python_regex(FEATURE_PREFILTER).pattern, spelling, re.I), spelling)
            self.assertTrue(any(n in spelling.lower() for n in needles), spelling)

    def test_the_fold_lists_every_letter_that_matches_an_ascii_one(self):
        letter = re.compile('[a-z]', re.IGNORECASE)
        found = {cp for cp in range(0x80, 0x110000) if letter.fullmatch(chr(cp))}
        self.assertEqual(found, set(service_features._FOLD))

    def test_the_substring_test_agrees_with_the_regex(self):
        regex, needles = service_features._prefilter()
        texts = [t for row in EDGE_TEXTS for t in row] + [t for _c, _f, t in NEEDS] + [
            'CHUN\u212aING', 'NTLM over STARTTLS', 'smbv\u0131', 'S\u0130MB', 'webdav\u017f', 'Wind\u00f6ws', 'h\u2082', '\u212a']
        for text in texts:
            self.assertEqual(service_features._passes([text], regex, needles), bool(text and regex.search(text)), text)
        self.assertTrue(service_features._passes(['CHUN\u212aING'], regex, needles))  # the Kelvin sign is a K to a case-blind match

    def test_a_pattern_without_needles_sends_every_text_to_the_regex(self):
        regex = re.compile(r'\w+|x', re.I)
        self.assertIsNone(service_features._needles(regex))
        self.assertTrue(service_features._passes(['anything'], regex, None))
