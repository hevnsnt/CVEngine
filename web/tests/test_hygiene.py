import base64
import datetime
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import hygiene as hy
from cveFeed.models import AgentActivity, HygieneFinding, TlsCertificate
from dashboard.models import Org, Project, ProjectMembership
from startScan.models import IpAddress, Port, Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call, create_token

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 10, 23, 12, 0, tzinfo=UTC)


class PinnedHygieneTests(SimpleTestCase):
	def test_all_tls_attempts_share_one_admitted_address_set(self):
		addresses = ((2, ('203.0.113.10', 443)),)
		with mock.patch.object(hy.pinned_transport, 'resolve', return_value=addresses) as resolve, \
				mock.patch.object(hy, '_fetch_cert', return_value={'host': 'asset.example.test'}) as fetch, \
				mock.patch.object(hy, '_chain_error', return_value='') as chain, \
				mock.patch.object(hy, '_accepts_legacy_tls', return_value=False) as legacy:
			self.assertIsNotNone(hy.probe_tls('asset.example.test', 443))
		resolve.assert_called_once_with('asset.example.test', 443)
		for probe in (fetch, chain, legacy):
			probe.assert_called_once_with('asset.example.test', 443, addresses=addresses)

	def test_failed_admission_never_opens_tls_socket(self):
		with mock.patch.object(hy.pinned_transport, 'resolve', side_effect=ValueError('blocked')), \
				mock.patch.object(hy, '_fetch_cert') as fetch:
			self.assertIsNone(hy.probe_tls('asset.example.test', 443))
		fetch.assert_not_called()

	def test_chain_verification_keeps_original_sni(self):
		addresses = ((2, ('203.0.113.10', 443)),)
		raw = mock.MagicMock()
		raw.__enter__.return_value = raw
		context = mock.MagicMock()
		with mock.patch.object(hy.pinned_transport, 'open_socket', return_value=raw) as connect, \
				mock.patch.object(hy.ssl, 'create_default_context', return_value=context):
			self.assertEqual(hy._chain_error('asset.example.test', 443, addresses=addresses), '')
		connect.assert_called_once_with(addresses, hy.TLS_TIMEOUT)
		context.wrap_socket.assert_called_once_with(raw, server_hostname='asset.example.test')


def checks(findings):
	return {f.check for f in findings}


def cert(**kw):
	base = {'host': 'www.example.com', 'port': 443, 'subject': 'www.example.com', 'sans': ['www.example.com'],
	        'not_after': NOW + datetime.timedelta(days=200), 'signature_algorithm': 'sha256 (sha256WithRSAEncryption)',
	        'key_description': 'RSA 2048', 'protocol': 'TLSv1.3', 'chain_error': '', 'legacy_tls': False}
	return {**base, **kw}


class SpfTests(TestCase):
	def test_missing_depends_on_mail(self):
		self.assertEqual(hy.evaluate_spf('a.com', [], True)[0].severity, hy.MEDIUM)
		self.assertEqual(hy.evaluate_spf('a.com', [], False)[0].severity, hy.LOW)

	def test_policy_strength(self):
		self.assertEqual(checks(hy.evaluate_spf('a.com', ['v=spf1 include:_spf.google.com -all'], True)), set())
		self.assertEqual(checks(hy.evaluate_spf('a.com', ['v=spf1 mx +all'], True)), {'spf_allow_all'})
		self.assertEqual(hy.evaluate_spf('a.com', ['v=spf1 mx +all'], True)[0].severity, hy.CRITICAL)
		self.assertEqual(checks(hy.evaluate_spf('a.com', ['v=spf1 mx ?all'], True)), {'spf_neutral'})
		self.assertEqual(checks(hy.evaluate_spf('a.com', ['v=spf1 mx ~all'], True)), {'spf_softfail'})
		self.assertEqual(checks(hy.evaluate_spf('a.com', ['v=spf1 mx'], True)), {'spf_no_all'})
		self.assertEqual(checks(hy.evaluate_spf('a.com', ['v=spf1 redirect=_spf.example.com'], True)), set())  # redirect closes it
		self.assertIn('spf_ptr', checks(hy.evaluate_spf('a.com', ['v=spf1 ptr -all'], True)))

	def test_multiple_records_and_lookup_limit(self):
		self.assertEqual(checks(hy.evaluate_spf('a.com', ['v=spf1 -all', 'v=spf1 mx -all'], True)), {'spf_multiple'})
		self.assertIn('spf_too_many_lookups', checks(hy.evaluate_spf('a.com', ['v=spf1 -all'], True, lookup_count=11)))
		self.assertNotIn('spf_too_many_lookups', checks(hy.evaluate_spf('a.com', ['v=spf1 -all'], True, lookup_count=10)))

	def test_lookup_counting_follows_includes_without_looping(self):
		zone = {'a.com': ['v=spf1 include:b.com mx a -all'], 'b.com': ['v=spf1 include:a.com ip4:1.2.3.4 exists:x.b.com -all']}
		# include:b (1), b's include:a (1, then its terms are not walked again), exists (1), mx (1), a (1)
		self.assertEqual(hy.count_spf_lookups('a.com', lambda d: zone.get(d, [])), 5)


class DmarcTests(TestCase):
	def test_missing_none_and_reject(self):
		self.assertEqual(hy.evaluate_dmarc('a.com', [], True)[0].severity, hy.HIGH)
		self.assertEqual(hy.evaluate_dmarc('a.com', [], False)[0].severity, hy.LOW)
		self.assertEqual(checks(hy.evaluate_dmarc('a.com', ['v=DMARC1; p=none; rua=mailto:d@a.com'], True)), {'dmarc_none'})
		self.assertEqual(checks(hy.evaluate_dmarc('a.com', ['v=DMARC1; p=reject; rua=mailto:d@a.com'], True)), set())

	def test_details(self):
		r = hy.evaluate_dmarc('a.com', ['v=DMARC1; p=quarantine; pct=50; sp=none'], True)
		self.assertTrue({'dmarc_quarantine', 'dmarc_partial', 'dmarc_no_reports', 'dmarc_subdomain_weak'} <= checks(r))
		self.assertEqual(checks(hy.evaluate_dmarc('a.com', ['v=DMARC1; rua=mailto:x@a.com'], True)), {'dmarc_invalid'})
		self.assertEqual(checks(hy.evaluate_dmarc('a.com', ['v=DMARC1; p=none', 'v=DMARC1; p=reject'], True)), {'dmarc_multiple'})


class DkimCaaTests(TestCase):
	@staticmethod
	def rsa_record(bits):
		from cryptography.hazmat.primitives import serialization
		from cryptography.hazmat.primitives.asymmetric import rsa
		pub = rsa.generate_private_key(public_exponent=65537, key_size=bits).public_key()
		der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
		return f'v=DKIM1; k=rsa; p={base64.b64encode(der).decode()}'

	def test_key_strength_and_revocation(self):
		self.assertEqual(hy.dkim_key_bits(self.rsa_record(2048)), 2048)
		self.assertEqual(checks(hy.evaluate_dkim('a.com', {'google': self.rsa_record(2048)}, True)), set())
		self.assertEqual(checks(hy.evaluate_dkim('a.com', {'s1': self.rsa_record(1024)}, True)), {'dkim_short_key'})
		self.assertEqual(checks(hy.evaluate_dkim('a.com', {'old': 'v=DKIM1; p='}, True)), {'dkim_not_found'})  # revoked = not present
		self.assertEqual(hy.evaluate_dkim('a.com', {'old': 'v=DKIM1; p='}, False), [])
		self.assertEqual(hy.dkim_key_bits('v=DKIM1; p=notbase64!!'), 0)

	def test_not_found_only_matters_for_mail_domains_and_is_informational(self):
		self.assertEqual(hy.evaluate_dkim('a.com', {}, False), [])
		f = hy.evaluate_dkim('a.com', {}, True)
		self.assertEqual((f[0].check, f[0].severity), ('dkim_not_found', hy.INFO))

	def test_caa(self):
		self.assertEqual(checks(hy.evaluate_caa('a.com', [])), {'caa_missing'})
		self.assertEqual(hy.evaluate_caa('a.com', ['0 issue "letsencrypt.org"']), [])

	def test_email_findings_orchestration_with_fake_dns(self):
		zone = {'a.com': ['v=spf1 mx ~all'], '_dmarc.a.com': ['v=DMARC1; p=none']}
		findings, has_mx = hy.email_findings('a.com', fetch=lambda n: zone.get(n, []), mx=lambda n, t: t == 'MX')
		self.assertTrue(has_mx)
		self.assertTrue({'spf_softfail', 'dmarc_none', 'dkim_not_found', 'caa_missing'} <= checks(findings))


class CertTests(TestCase):
	def test_expiry_bands(self):
		def code(days):
			f = hy.evaluate_cert(cert(not_after=NOW + datetime.timedelta(days=days, hours=1)), now=NOW)
			return [(x.check, x.severity) for x in f]
		self.assertEqual(code(-5), [('tls_expired', hy.CRITICAL)])
		self.assertEqual(code(3), [('tls_expiring', hy.HIGH)])
		self.assertEqual(code(20), [('tls_expiring', hy.MEDIUM)])
		self.assertEqual(code(45), [('tls_expiring', hy.LOW)])
		self.assertEqual(code(90), [])
		title = hy.evaluate_cert(cert(not_after=NOW + datetime.timedelta(days=3, hours=1)), now=NOW)[0].title
		self.assertIn('3 days left', title)

	def test_hostname_wildcards(self):
		self.assertTrue(hy.hostname_matches('a.example.com', ['*.example.com']))
		self.assertFalse(hy.hostname_matches('a.b.example.com', ['*.example.com']))  # wildcard is one label
		self.assertFalse(hy.hostname_matches('example.com', ['*.example.com']))
		self.assertTrue(hy.hostname_matches('WWW.Example.com.', ['www.example.com']))
		self.assertEqual(checks(hy.evaluate_cert(cert(sans=['other.net'], subject='other.net'), now=NOW)), {'tls_hostname_mismatch'})
		self.assertEqual(hy.evaluate_cert(cert(host='203.0.113.5', sans=['x.net'], subject='x.net'), now=NOW), [])  # IPs are not name-matched

	def test_chain_and_crypto_findings(self):
		self.assertEqual(checks(hy.evaluate_cert(cert(chain_error='self-signed certificate'), now=NOW)), {'tls_self_signed'})
		self.assertEqual(checks(hy.evaluate_cert(cert(chain_error='unable to get local issuer certificate'), now=NOW)), {'tls_untrusted_chain'})
		self.assertEqual(hy.evaluate_cert(cert(chain_error='certificate has expired'), now=NOW), [])  # reported as tls_expired already
		self.assertEqual(checks(hy.evaluate_cert(cert(signature_algorithm='sha1 (sha1WithRSAEncryption)'), now=NOW)), {'tls_weak_signature'})
		self.assertEqual(checks(hy.evaluate_cert(cert(key_description='RSA 1024'), now=NOW)), {'tls_weak_key'})
		self.assertEqual(checks(hy.evaluate_cert(cert(key_description='EC secp256r1'), now=NOW)), set())
		self.assertEqual(checks(hy.evaluate_cert(cert(legacy_tls=True), now=NOW)), {'tls_legacy_protocol'})
		self.assertEqual(hy.evaluate_cert(cert(), now=NOW), [])


class HygieneRunnerTests(TestCase):
	def setUp(self):
		now = timezone.now()
		self.project = Project.objects.create(name='H', slug='hp', insert_date=now, org=Org.objects.create(name='H', slug='h'))
		self.domain = Domain.objects.create(name='example.test', project=self.project, insert_date=now)
		sub = Subdomain.objects.create(name='www.example.test', target_domain=self.domain)
		ip = IpAddress.objects.create(address='192.0.2.7')
		sub.ip_addresses.add(ip)
		ip.ports.add(Port.objects.create(number=8443), Port.objects.create(number=22))

	def run_with(self, probe, emailer):
		return hy.run_hygiene(self.domain.id, probe=probe, emailer=emailer, mx=lambda n, t: False)

	def test_targets_are_443_everywhere_plus_other_tls_ports_only(self):
		self.assertEqual(set(hy.tls_targets(self.domain)), {('example.test', 443), ('www.example.test', 443), ('www.example.test', 8443)})

	def test_run_stores_certificates_and_findings_then_resolves_fixed_ones(self):
		soon = timezone.now() + datetime.timedelta(days=5)
		bad = lambda host, port: cert(host=host, port=port, sans=[host], subject=host, not_after=soon, chain_error='') if host == 'www.example.test' else None
		mail = lambda name: ([hy.Finding('dmarc_none', hy.MEDIUM, 'DMARC policy is p=none', host=name)], False)
		counts = self.run_with(bad, mail)
		self.assertEqual(counts['tls_hosts'], 2)  # www:443 and www:8443
		self.assertEqual(TlsCertificate.objects.filter(domain=self.domain).count(), 2)
		self.assertEqual(TlsCertificate.objects.get(host='www.example.test', port=443).days_left, 4)
		open_checks = set(HygieneFinding.objects.filter(domain=self.domain, status='open').values_list('check_name', flat=True))
		self.assertEqual(open_checks, {'tls_expiring', 'dmarc_none'})
		# the certificate is renewed and DMARC fixed: findings resolve, they are not deleted
		fixed = lambda host, port: cert(host=host, port=port, sans=[host], subject=host) if host == 'www.example.test' else None
		self.run_with(fixed, lambda name: ([], False))
		self.assertEqual(HygieneFinding.objects.filter(domain=self.domain, status='open').count(), 0)
		self.assertEqual(HygieneFinding.objects.filter(domain=self.domain, status='resolved').count(), 3)  # two expiring certificates (443 and 8443) plus DMARC
		messages = list(AgentActivity.objects.filter(kind='hygiene').order_by('id').values_list('message', flat=True))
		self.assertTrue(messages[0].startswith('Hygiene check of example.test: 2 certificates, 3 issues (worst: high)'))

	def test_a_finding_marked_fixed_that_comes_back_is_reopened(self):
		mail = lambda name: ([hy.Finding('dmarc_none', hy.MEDIUM, 'DMARC policy is p=none', host=name)], False)
		none = lambda host, port: None
		self.run_with(none, mail)
		self.run_with(none, lambda name: ([], False))  # the sweep sees it gone: resolved
		row = HygieneFinding.objects.get(domain=self.domain, check_name='dmarc_none')
		self.assertEqual(row.status, 'resolved')
		HygieneFinding.objects.filter(pk=row.pk).update(remediation_status='fixed')
		self.run_with(none, mail)  # the regression
		row.refresh_from_db()
		self.assertEqual((row.status, row.remediation_status), ('open', 'open'))
		self.assertIn('Reopened', row.remediation_note)

	def test_a_hostile_certificate_cannot_abort_the_domains_tls_review(self):
		def hostile(host, port):
			if host != 'www.example.test':
				return None
			return cert(host=host, port=port, sans=[f'n{i}.example.test' for i in range(5000)], subject='C' * 5000, issuer='I' * 5000,
						chain_error='E' * 5000)
		counts = self.run_with(hostile, lambda name: ([], False))
		self.assertEqual(counts['tls_hosts'], 2)
		row = TlsCertificate.objects.get(host='www.example.test', port=443)
		self.assertEqual((len(row.subject), len(row.issuer), len(row.chain_error)), (500, 500, 300))
		self.assertEqual(len(row.sans), hy.MAX_CERT_SANS)

	def test_ip_targets_skip_email_checks(self):
		ip_domain = Domain.objects.create(name='203.0.113.9', project=self.project, insert_date=timezone.now())
		self.assertEqual(hy.email_domains(ip_domain, lambda n, t: True), [])
		self.assertTrue(hy.is_ip('203.0.113.9') and hy.is_ip('2001:db8::1') and not hy.is_ip('example.com'))


class HygieneApiTests(TestCase):
	def setUp(self):
		now = timezone.now()
		self.pa = Project.objects.create(name='A', slug='hya', insert_date=now, org=Org.objects.create(name='HA', slug='ha'))
		self.pb = Project.objects.create(name='B', slug='hyb', insert_date=now, org=Org.objects.create(name='HB', slug='hb'))
		self.da = Domain.objects.create(name='a.test', project=self.pa, insert_date=now)
		self.db = Domain.objects.create(name='b.test', project=self.pb, insert_date=now)
		for d, days in ((self.da, 3), (self.da, 80), (self.db, 1)):
			TlsCertificate.objects.create(domain=d, host=f'h{days}.{d.name}', port=443, not_after=now + datetime.timedelta(days=days, hours=1))
		HygieneFinding.objects.create(domain=self.da, host='a.test', check_name='spf_missing', severity=2, title='No SPF record')
		HygieneFinding.objects.create(domain=self.da, host='a.test', check_name='tls_expired', severity=4, title='Expired')
		HygieneFinding.objects.create(domain=self.db, host='b.test', check_name='spf_missing', severity=2, title='B secret')
		HygieneFinding.objects.create(domain=self.da, host='old.a.test', check_name='dmarc_none', severity=2, title='Old', status='resolved')
		self.user, self.audit = User.objects.create_user('hyu', password='x'), User.objects.create_user('hya', password='x')
		ProjectMembership.objects.create(user=self.user, project=self.pa, role='user')
		ProjectMembership.objects.create(user=self.audit, project=self.pa, role='audit')
		_, self.tok = create_token(self.user, 't')
		_, self.tok_audit = create_token(self.audit, 'a')

	def test_certificates_sorted_filtered_and_scoped(self):
		status, data = call(self.tok, 'GET', '/api/v1/projects/hya/certificates')
		self.assertEqual([c['days_left'] for c in data['results']], [3, 80])  # soonest first, B's certificate absent
		status, data = call(self.tok, 'GET', '/api/v1/projects/hya/certificates?expiring_within=30')
		self.assertEqual([c['days_left'] for c in data['results']], [3])
		self.assertEqual(call(self.tok, 'GET', '/api/v1/projects/hyb/certificates')[0], 404)

	def test_findings_filters_status_and_scoping(self):
		status, data = call(self.tok, 'GET', '/api/v1/projects/hya/hygiene')
		self.assertEqual([f['check'] for f in data['results']], ['tls_expired', 'spf_missing'])  # severity order, open only, no B
		self.assertEqual([f['check'] for f in call(self.tok, 'GET', '/api/v1/projects/hya/hygiene?check=spf')[1]['results']], ['spf_missing'])
		self.assertEqual([f['severity'] for f in call(self.tok, 'GET', '/api/v1/projects/hya/hygiene?severity=critical')[1]['results']], ['critical'])
		self.assertEqual([f['check'] for f in call(self.tok, 'GET', '/api/v1/projects/hya/hygiene?status=resolved')[1]['results']], ['dmarc_none'])
		self.assertEqual(call(self.tok, 'GET', '/api/v1/projects/hyb/hygiene')[0], 404)

	def test_run_checks_queues_and_respects_roles(self):
		with mock.patch('cveFeed.tasks.run_hygiene_task.delay') as queued:
			status, data = call(self.tok, 'POST', '/api/v1/projects/hya/hygiene/run', {})
			self.assertEqual((status, data['queued']), (202, 1))
			queued.assert_called_once_with(self.da.id)
			self.assertEqual(call(self.tok_audit, 'POST', '/api/v1/projects/hya/hygiene/run', {})[0], 403)
			self.assertEqual(call(self.tok, 'POST', '/api/v1/projects/hya/hygiene/run', {'target_id': self.db.id})[0], 404)

	def test_dashboard_stats_count_expiring_certs_and_open_issues(self):
		from tests.test_tenancy import client_for
		stats = client_for(self.user).get('/cve/api/stats').json()
		self.assertEqual((stats['certs_expiring'], stats['hygiene_open']), (1, 2))  # B's data is invisible to this user
		self.assertEqual(client_for(self.user).get('/cve/hya/hygiene/').status_code, 200)
