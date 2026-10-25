"""The email-security checks adapted from MailFail by Black Hills Information Security (cveFeed.mailfail): each rule on plain
records, the bounded network helpers with fakes (no DNS or HTTP leaves the test), and the credit on the activity card."""
import base64
import ssl
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import hygiene as hy
from cveFeed import mailfail as mf
from cveFeed.models import AgentActivity
from dashboard.models import Org, Project
from targetApp.models import Domain


def checks(findings):
	return {f.check for f in findings}


def modulus(bits):
	return (1 << (bits - 1)) | 1  # any odd number of that size: only the size is read


def dkim_key(bits):
	key = rsa.RSAPublicNumbers(65537, modulus(bits)).public_key()
	der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
	return 'v=DKIM1; k=rsa; p=' + base64.b64encode(der).decode()


def dnskey(algorithm, bits=2048, protocol=3):
	raw = bytes([3]) + (65537).to_bytes(3, 'big') + modulus(bits).to_bytes(bits // 8, 'big')
	return f'257 {protocol} {algorithm} {base64.b64encode(raw).decode()}'


class Response:
	def __init__(self, status=200, body=b'', payload=None):
		self.status_code, self.body, self.payload = status, body, payload

	def json(self):
		return self.payload

	def raise_for_status(self):
		if self.status_code >= 400:
			raise RuntimeError(self.status_code)

	def iter_content(self, size):
		for i in range(0, len(self.body), size):
			yield self.body[i:i + size]


class RecordRuleTests(SimpleTestCase):
	def test_every_finding_credits_mailfail(self):
		finding = mf.evaluate_mx('acme.example', ['acme-example.mail.protection.outlook.com.'])[0]
		self.assertIn('Black Hills Information Security', finding.evidence['credit'])
		self.assertIn('github.com/ACK-J/MailFail', finding.evidence['credit'])

	def test_spf(self):
		self.assertEqual(checks(mf.evaluate_spf('acme.example', ['include:_spf.example.com v=spf1 -all'])), {'spf_invalid_prefix'})
		self.assertEqual(checks(mf.evaluate_spf('acme.example', ['v=spf1 include:relay.mailchannels.net -all'])), {'spf_mailchannels'})
		self.assertEqual(mf.evaluate_spf('acme.example', ['v=spf1 -all']), [])
		self.assertEqual(mf.spf_referenced_domains(['v=spf1 include:_spf.example.com ~include:mail.acme-example.ai '
		                                            'include:%{d}.macro.example redirect=spf.example.org']),
		                 ['_spf.example.com', 'mail.acme-example.ai', 'spf.example.org'])

	def test_dmarc(self):
		self.assertEqual(checks(mf.evaluate_dmarc('acme.example', ['p=reject; v=DMARC1'])), {'dmarc_invalid_prefix'})
		self.assertEqual(checks(mf.evaluate_dmarc('acme.example', ['v=DMARC1; p=reject; rua=reports@example.com; ruf=mailto:f@example.com'])),
		                 {'dmarc_rua_malformed'})
		self.assertEqual(checks(mf.evaluate_dmarc('acme.example', ['v=DMARC1; p=reject; rua=mailto:r@acme.example; fo=1'])),
		                 {'dmarc_fo_without_ruf'})
		self.assertEqual(mf.evaluate_dmarc('acme.example', ['v=DMARC1; p=reject; rua=mailto:r@acme.example']), [])
		self.assertEqual(mf.dmarc_report_domains(['v=DMARC1; p=reject; rua=mailto:a@Reports.Example.com!10m,mailto:b@acme.example; '
		                                          'ruf=mailto:c@reports.example.com']), ['reports.example.com', 'acme.example'])

	def test_report_authorization(self):
		self.assertEqual(checks(mf.evaluate_report_authorization('acme.example', 'example.com', [])), {'dmarc_report_unauthorized'})
		self.assertEqual(mf.evaluate_report_authorization('acme.example', 'example.com', ['v=DMARC1']), [])

	def test_dkim(self):
		key = dkim_key(2048)
		self.assertEqual(checks(mf.evaluate_dkim('acme.example', {'s1': key + '; t=y'})), {'dkim_testing_mode'})
		self.assertEqual(checks(mf.evaluate_dkim('acme.example', {'s1': key + '; h=sha1'})), {'dkim_sha1'})
		self.assertEqual(mf.evaluate_dkim('acme.example', {'s1': key + '; h=sha1:sha256'}), [])
		self.assertEqual(checks(mf.evaluate_dkim('acme.example', {'s1': 'v=DKIM1; k=rsa; p=bm90IGEga2V5'})), {'dkim_invalid_key'})
		self.assertEqual(mf.evaluate_dkim('acme.example', {'s1': 'v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo='}), [])
		self.assertEqual(mf.evaluate_dkim('acme.example', {'s1': 'v=DKIM1; p='}), [])  # revoked

	def test_arc(self):
		self.assertEqual(checks(mf.evaluate_arc('acme.example', {'arc': dkim_key(512)})), {'arc_weak_key'})
		self.assertEqual(checks(mf.evaluate_arc('acme.example', {'arc': dkim_key(1024)})), {'arc_short_key'})
		self.assertEqual(mf.evaluate_arc('acme.example', {'arc': dkim_key(2048)}), [])

	def test_adsp_bimi_mailchannels(self):
		self.assertEqual(checks(mf.evaluate_adsp('acme.example', ['dkim=all'])), {'adsp_present'})
		self.assertEqual(mf.evaluate_adsp('acme.example', []), [])
		self.assertEqual(checks(mf.evaluate_bimi('acme.example', ['l=https://acme.example/logo.svg; v=BIMI1'])), {'bimi_invalid'})
		self.assertEqual(checks(mf.evaluate_bimi('acme.example', ['v=BIMI1; l=https://acme.example/logo.png; a=http://acme.example/vmc.pem'])),
		                 {'bimi_logo_invalid', 'bimi_vmc_invalid'})
		self.assertEqual(mf.evaluate_bimi('acme.example', ['v=BIMI1; l=https://acme.example/logo.svg; a=https://acme.example/vmc.pem']), [])
		self.assertEqual(checks(mf.evaluate_mailchannels('acme.example', ['v=mc1 cfid=acme.example.workers.dev'])),
		                 {'mailchannels_shared_relay'})
		self.assertEqual(mf.evaluate_mailchannels('acme.example', ['v=mc1 auth=myaccountid']), [])

	def test_microsoft_direct_send_is_read_from_mx_only(self):
		finding = mf.evaluate_mx('acme.example', ['acme-example.mail.protection.outlook.com.'])[0]
		self.assertEqual((finding.check, finding.severity), ('mx_direct_send', hy.MEDIUM))
		self.assertIn('RejectDirectSend', finding.detail)
		self.assertEqual(finding.evidence['reference'], mf.DIRECT_SEND_REFERENCE)
		self.assertEqual(mf.evaluate_mx('acme.example', ['mx1.example.com.']), [])

	def test_mta_sts(self):
		self.assertEqual(checks(mf.evaluate_mta_sts('acme.example', [], None, has_mx=True)), {'mta_sts_missing'})
		self.assertEqual(mf.evaluate_mta_sts('acme.example', [], None, has_mx=False), [])
		self.assertEqual(checks(mf.evaluate_mta_sts('acme.example', ['id=1; v=STSv1'], None, True)), {'mta_sts_invalid'})
		self.assertEqual(checks(mf.evaluate_mta_sts('acme.example', ['v=STSv1; id=1'], None, True)), {'mta_sts_policy_unreachable'})
		self.assertEqual(mf.evaluate_mta_sts('acme.example', ['v=STSv1; id=1'], None, True, policy_checked=False), [])
		policy = 'version: STSv1\nmode: testing\nmx: mx.acme.example\nmax_age: 86400\n'
		self.assertEqual(checks(mf.evaluate_mta_sts('acme.example', ['v=STSv1; id=1'], policy, True)), {'mta_sts_not_enforced'})
		self.assertEqual(mf.evaluate_mta_sts('acme.example', ['v=STSv1; id=1'], policy.replace('testing', 'enforce'), True), [])

	def test_tls_reporting(self):
		self.assertEqual(checks(mf.evaluate_tls_reporting('acme.example', [], True)), {'smtp_tlsrpt_missing'})
		self.assertEqual(checks(mf.evaluate_tls_reporting('acme.example', ['v=TLSRPTv1; rua=http://acme.example/r'], True)),
		                 {'smtp_tlsrpt_invalid'})
		self.assertEqual(checks(mf.evaluate_tls_reporting('acme.example', ['rua=mailto:r@acme.example; v=TLSRPTv1'], True)),
		                 {'smtp_tlsrpt_invalid'})
		self.assertEqual(mf.evaluate_tls_reporting('acme.example', ['v=TLSRPTv1; rua=mailto:r@acme.example,https://r.acme.example/'], True), [])

	def test_dane(self):
		bad = mf.evaluate_dane('acme.example', {'mx.acme.example': ['1 1 1 ab12', '3 0 1 cd34', '3 1 2 ef56']})
		self.assertEqual(checks(bad), {'dane_misconfigured'})
		self.assertIn('usage 1', bad[0].detail)
		self.assertIn('selector 0', bad[0].detail)
		self.assertEqual(mf.evaluate_dane('acme.example', {'mx.acme.example': ['3 1 1 ab12', '2 0 1 cd34']}), [])

	def test_dnssec(self):
		self.assertEqual(mf.rsa_key_bits(dnskey(8, 2048).split()[3]), 2048)
		self.assertEqual(checks(mf.evaluate_dnssec('acme.example', [dnskey(5)])), {'dnssec_weak_algorithm'})
		self.assertEqual(checks(mf.evaluate_dnssec('acme.example', [dnskey(8, bits=512)])), {'dnssec_weak_key'})
		self.assertEqual(checks(mf.evaluate_dnssec('acme.example', [dnskey(8, protocol=2)])), {'dnssec_invalid_protocol'})
		self.assertEqual(mf.evaluate_dnssec('acme.example', [dnskey(8), '257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==']), [])


class TakeoverTests(SimpleTestCase):
	def setUp(self):
		mf._RDAP.update(at=0.0, services=None)

	def test_only_unregistered_third_party_domains_count(self):
		asked = []

		def registered(name):
			asked.append(name)
			return {'gone-example.com': False, 'unknown-example.com': None}.get(name, True)
		names = ['_spf.gone-example.com', 'mail.acme.example', 'x.unknown-example.com', 'spf.live-example.com', 'ns-example.com']
		out = mf.unregistered_domains(names, 'acme.example', has_ns=lambda name: name == 'ns-example.com', registered=registered)
		self.assertEqual(out, ['gone-example.com'])
		self.assertNotIn('acme.example', asked)  # the target's own domain is never asked about
		self.assertNotIn('ns-example.com', asked)  # name servers mean registered
		self.assertEqual(checks(mf.evaluate_takeover('acme.example', out, ['gone-example.com'])),
		                 {'spf_include_registerable', 'dmarc_report_domain_registerable'})

	def test_rdap_uses_the_registry_from_the_iana_bootstrap_and_only_a_404_means_unregistered(self):
		bootstrap = Response(payload={'services': [[['com'], ['https://rdap.registry.example/']], [['test'], ['http://plain.example/']]]})
		for status, expected in ((404, False), (200, True), (500, None), (301, None)):
			session = mock.Mock()
			session.get.side_effect = [bootstrap, Response(status)]
			mf._RDAP.update(at=0.0, services=None)
			self.assertIs(mf.rdap_registered('gone-example.com', session), expected)
			self.assertEqual(session.get.call_args_list[1].args[0], 'https://rdap.registry.example/domain/gone-example.com')
			self.assertFalse(session.get.call_args_list[1].kwargs['allow_redirects'])
		session = mock.Mock()
		session.get.side_effect = [bootstrap]
		mf._RDAP.update(at=0.0, services=None)
		self.assertIsNone(mf.rdap_registered('gone.test', session))  # a registry not on HTTPS is not asked
		self.assertIsNone(mf.rdap_registered('gone.invalidtld', session))  # no registry for that TLD


class MtaStsFetchTests(SimpleTestCase):
	ADDRS = ((2, ('203.0.113.10', 443)),)

	def conn(self, status, body=b''):
		resp = mock.Mock(status=status)
		resp.read.side_effect = lambda n: body[:n]
		connection = mock.Mock()
		connection.getresponse.return_value = resp
		return connection

	def test_a_host_resolving_to_a_blocked_address_is_never_fetched(self):
		with mock.patch('cveFeed.pinned_transport.resolve', side_effect=ValueError('blocked')), \
				mock.patch('cveFeed.pinned_transport.HTTPConnection') as factory:
			self.assertIsNone(mf.fetch_mta_sts_policy('acme.example'))
		factory.assert_not_called()

	def test_fetch_is_the_well_known_path_on_the_admitted_addresses_verified_and_bounded(self):
		with mock.patch('cveFeed.pinned_transport.resolve', return_value=self.ADDRS) as resolve, \
				mock.patch('cveFeed.pinned_transport.HTTPConnection') as factory:
			factory.return_value = self.conn(200, b'version: STSv1\nmode: enforce\n')
			self.assertIn('mode: enforce', mf.fetch_mta_sts_policy('acme.example'))
			resolve.assert_called_once_with('mta-sts.acme.example', 443)
			args, kwargs = factory.call_args
			self.assertEqual(args[:3], ('mta-sts.acme.example', 443, self.ADDRS))
			self.assertEqual(kwargs['context'].verify_mode, ssl.CERT_REQUIRED)
			self.assertEqual(factory.return_value.request.call_args.args[:2], ('GET', '/.well-known/mta-sts.txt'))
			factory.return_value = self.conn(302)  # redirects are not followed
			self.assertIsNone(mf.fetch_mta_sts_policy('acme.example'))
			factory.return_value = self.conn(200, b'x' * (mf.MAX_POLICY_BYTES + 1))
			self.assertIsNone(mf.fetch_mta_sts_policy('acme.example'))


class EmailReviewTests(SimpleTestCase):
	def test_injected_dns_runs_the_mailfail_checks_without_any_outbound_request(self):
		zone = {'acme.example': ['v=spf1 include:_spf.example.com -all'], '_dmarc.acme.example': ['v=DMARC1; p=reject; rua=mailto:r@reports.example.com'],
		        'default._bimi.acme.example': ['v=BIMI1; l=http://acme.example/logo.png'], '_mta-sts.acme.example': ['v=STSv1; id=1'],
		        'selector1._domainkey.acme.example': [dkim_key(2048) + '; t=y']}
		with mock.patch('requests.Session.request', side_effect=AssertionError('no HTTP')):  # every requests call goes through it
			findings, has_mx = hy.email_findings('acme.example', fetch=lambda n: zone.get(n, []), mx=lambda n, t: t == 'MX')
		found = checks(findings)
		self.assertTrue(has_mx)
		self.assertTrue({'dkim_testing_mode', 'bimi_logo_invalid', 'dmarc_report_unauthorized', 'smtp_tlsrpt_missing'} <= found)
		self.assertTrue({'spf_softfail', 'dmarc_quarantine'}.isdisjoint(found))  # the established checks still run unchanged
		self.assertNotIn('mta_sts_policy_unreachable', found)  # the policy file is not fetched with injected DNS

	def test_mx_dane_and_dnssec_use_the_records_reader(self):
		def records(name, rtype):
			return {('acme.example', 'MX'): ['10 acme-example.mail.protection.outlook.com.'],
			        ('_25._tcp.acme-example.mail.protection.outlook.com', 'TLSA'): ['1 1 1 ab12'],
			        ('acme.example', 'DNSKEY'): [dnskey(5)]}.get((name, rtype), [])
		findings, _ = hy.email_findings('acme.example', fetch=lambda n: [], mx=lambda n, t: t == 'MX', records=records)
		self.assertTrue({'mx_direct_send', 'dane_misconfigured', 'dnssec_weak_algorithm'} <= checks(findings))

	def test_a_failing_mailfail_check_never_breaks_the_review(self):
		with mock.patch('cveFeed.mailfail.evaluate_bimi', side_effect=RuntimeError('boom')):
			findings, _ = hy.email_findings('acme.example', fetch=lambda n: [], mx=lambda n, t: t == 'MX')
		self.assertIn('spf_missing', checks(findings))


class ActivityCreditTests(TestCase):
	def test_the_activity_card_credits_mailfail_while_and_after_it_runs(self):
		now = timezone.now()
		project = Project.objects.create(name='Acme', slug='acme', insert_date=now, org=Org.objects.create(name='Acme', slug='acme-org'))
		domain = Domain.objects.create(name='acme.example', project=project, insert_date=now)
		credited = mf.evaluate_mx('acme.example', ['acme-example.mail.protection.outlook.com.'])
		hy.run_hygiene(domain.id, probe=lambda host, port: None, emailer=lambda name: (credited, True), mx=lambda n, t: False)
		entry = AgentActivity.objects.filter(kind='hygiene', message__contains='MailFail').latest('id')
		self.assertEqual(entry.status, 'done')
		self.assertIn('Black Hills Information Security', entry.message)
		self.assertIn('acme.example: 1 issue', entry.message)
		self.assertEqual(entry.detail['credit'], mf.CREDIT)
