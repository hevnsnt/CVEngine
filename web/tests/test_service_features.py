"""Service features (cveFeed.service_features): the HTTP/2 reading a Sentinel takes in the hygiene check's handshake (ALPN), the CVEs whose
advisory needs HTTP/2, and what the reading does to their matches: rule out, raise within the ceiling, or nothing when it is unknown."""
import datetime
from unittest import mock

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import probe_results
from cveFeed import correlation, detection, match_explain, service_features, triage
from cveFeed.detection_classes import feature_preconditions
from cveFeed.models import CVEDetection, CVEEntry, CVEMatch, ServiceFeature, Triage
from dashboard.models import Org, Project, ProjectMembership
from startScan.models import IpAddress, Port, Subdomain
from targetApp.models import Domain
from tests import hygiene_harness
from tests.test_agentapi import call, create_token

# the two advisories this was built for, as the feed has them
NGINX_123007 = ('F5 NGINX Plus memory corruption in HTTP/2 module via integer underflow',
                'This issue affects NGINX Plus or NGINX Open Source configurations that use HTTP/2. When NGINX processes undisclosed traffic, the '
                'flow control window can exceed the allowed threshold, potentially resulting in a heap buffer overflow typically followed by an NGINX '
                'worker segmentation fault.')
NGINX_123633 = ('F5 NGINX Open Source memory corruption in HTTP/2 module',
                'When NGINX Plus or NGINX Open Source is configured to use HTTP/2 for client connections and proxy client requests to a backend, a '
                'specially crafted request can result in use-after-free in the worker process, if this process is running low on worker_connections.')
NGINX = [{'vendor': 'F5', 'product': 'nginx', 'ranges': [{'introduced': '1.19.7', 'fixed': '1.30.7'}]}]


class PreconditionRuleTests(SimpleTestCase):
    def needs(self, title, description=''):
        return feature_preconditions(title, description).get('http2')

    def test_both_nginx_advisories_need_http2_and_quote_their_own_sentence(self):
        for title, description in (NGINX_123007, NGINX_123633):
            got = self.needs(title, description)
            self.assertIsNotNone(got)
            self.assertTrue(got['rule_out'])
            self.assertIn('HTTP/2', got['quote'])
        self.assertTrue(self.needs(*NGINX_123007)['quote'].startswith('This issue affects NGINX Plus or NGINX Open Source configurations'))

    def test_the_wordings_that_state_the_precondition(self):
        for text in ('This issue affects nginx compiled with the ngx_http_v2_module (not compiled by default) if the \'http2\' option of the '
                     '\'listen\' directive is used in a configuration file.',
                     'The Apache HTTP Server 2.4.17 and 2.4.18, when mod_http2 is enabled, does not limit the number of stream workers.',
                     'Servers are affected only when HTTP/2 is enabled.',
                     'A server with HTTP/2 enabled can be crashed.'):
            self.assertIsNotNone(self.needs('', text), text)

    def test_http2_named_only_as_the_flaws_protocol_is_no_precondition(self):
        for title, text in (('HTTP/2 Rapid Reset Attack Vulnerability', 'The HTTP/2 protocol allows a denial of service because request '
                             'cancellation can reset many streams quickly.'),
                            ('Apache Tomcat: HTTP/2 header handling DoS', 'Denial of Service due to improper input validation for HTTP/2 requests.'),
                            ('HTTP/2 push headers memory-leak', 'When an application tells libcurl it wants to allow HTTP/2 server push, ...'),
                            ('', 'A crafted method sent through HTTP/2 will bypass validation and be forwarded by mod_proxy.')):
            self.assertIsNone(self.needs(title, text), title)

    def test_a_flaw_reached_over_http1_too_needs_nothing(self):
        self.assertIsNone(self.needs('HTTP/1.1 and HTTP/2 redirects resend credentials', 'Servers configured to use HTTP/2 or HTTP/1.1 ...'))

    def test_h2c_keeps_the_precondition_but_no_reading_rules_it_out(self):
        got = self.needs('', 'The mod_http2 module in the Apache HTTP Server, when the Protocols configuration includes h2 or h2c, does not '
                             'restrict request-header length.')
        self.assertIsNotNone(got)
        self.assertFalse(got['rule_out'])

    def test_the_strategy_field_is_validated_and_kept_by_the_rules_only(self):
        clean, problems = detection.validate_strategy({'summary': 's', 'identify': 'x', 'requires_features': {'http2': True, 'ssh': True,
                                                                                                             'http3': 'yes'}})
        self.assertEqual(clean['requires_features'], {'http2': True})
        self.assertEqual(len([p for p in problems if 'requires_features' in p]), 2)
        base = {**clean}
        extra = {**clean, 'requires_features': {'http2': False}}
        self.assertEqual(detection.merge_strategies(base, extra)['requires_features'], {'http2': True})  # a model never drops it
        self.assertNotIn('requires_features', detection.merge_strategies({**clean, 'requires_features': {}}, extra))  # nor adds one


class IngestTests(SimpleTestCase):
    def cert(self, **over):
        return {'host': 'www.example.test', 'port': 443, 'found': True,
                'cert': {'subject': 's', 'issuer': 'i', 'sans': [], 'not_before': None, 'not_after': '2027-01-01T00:00:00+00:00',
                         'signature_algorithm': 'sha256', 'key_description': 'RSA 2048', 'protocol': 'TLSv1.3', 'cipher': 'X', 'chain_error': '',
                         'legacy_tls': False, **over}}

    def alpn(self, **over):
        return probe_results.clean_hygiene_check({'certs': [self.cert(**over)], 'mail': []})['certs'][0]['cert']['alpn']

    def test_only_the_four_values_pass_anything_else_is_unknown(self):
        for value in ('h2', 'http/1.1', 'none', 'unknown'):
            self.assertEqual(self.alpn(alpn=value), value)
        for value in ('H2', 'h3', 'spdy/3', 'h2' * 100, 7, True, None, ['h2'], {'v': 'h2'}):
            self.assertEqual(self.alpn(alpn=value), 'unknown', value)
        self.assertEqual(self.alpn(), 'unknown')  # a Sentinel before the field


class FeatureCase(TestCase):
    def setUp(self):
        service_features.reset_index()
        self.addCleanup(service_features.reset_index)
        now = timezone.now()
        self.project = Project.objects.create(name='F', slug='sf', insert_date=now, org=Org.objects.create(name='F', slug='sfo'))
        self.domain = Domain.objects.create(name='example.test', project=self.project, insert_date=now)
        self.sub = Subdomain.objects.create(name='www.example.test', target_domain=self.domain)
        self.ip = IpAddress.objects.create(address='192.0.2.7')
        self.sub.ip_addresses.add(self.ip)
        self.ip.ports.add(Port.objects.create(number=443, service_name='https'))
        self.cve = CVEEntry.objects.create(cve_id='CVE-2026-123007', status='PUBLISHED', affected=NGINX, published_at=now,
                                           title=NGINX_123007[0], original_description=NGINX_123007[1])
        self.other = CVEEntry.objects.create(cve_id='CVE-2099-0001', status='PUBLISHED', affected=NGINX, published_at=now,
                                             title='nginx resolver flaw', original_description='A crafted DNS response can crash the worker.')

    def match(self, cve=None, confidence=0.85, **over):
        return CVEMatch.objects.create(cve_entry=cve or self.cve, subdomain=self.sub, source='tech', matched_product='nginx',
                                       matched_version='1.25.0', version_in_range=True, confidence=confidence,
                                       evidence={'source': 'tech', 'raw_version': '1.25.0'}, **over)

    def reading(self, port, value, detail, age=0):
        ServiceFeature.objects.update_or_create(domain=self.domain, host=self.sub.name, port=port, feature='http2', defaults={
            'value': value, 'detail': detail, 'source': 'tls_alpn', 'observed_at': timezone.now() - datetime.timedelta(days=age)})

    def fresh(self, match):
        return CVEMatch.objects.select_related('cve_entry', 'subdomain__target_domain').get(pk=match.pk)


class StoreTests(FeatureCase):
    def test_the_hygiene_check_stores_the_reading_per_host_and_port_and_unknown_removes_it(self):
        def probe(alpn):
            def read(host, port):
                if host != 'www.example.test':
                    return None
                return {'host': host, 'port': port, 'subject': host, 'sans': [host], 'not_after': timezone.now() + datetime.timedelta(days=90),
                        'signature_algorithm': 'sha256', 'key_description': 'RSA 2048', 'protocol': 'TLSv1.3', 'chain_error': '',
                        'legacy_tls': False, **({'alpn': alpn} if alpn else {})}
            return read
        hygiene_harness.run_hygiene(self.domain.id, probe=probe('http/1.1'))
        row = ServiceFeature.objects.get(host='www.example.test', port=443, feature='http2')
        self.assertEqual((row.value, row.detail, row.source, row.transport), ('no', 'ALPN http/1.1', 'tls_alpn', 'tls'))
        hygiene_harness.run_hygiene(self.domain.id, probe=probe('h2'))
        self.assertEqual(ServiceFeature.objects.get(host='www.example.test', port=443).value, 'yes')
        hygiene_harness.run_hygiene(self.domain.id, probe=probe('none'))
        self.assertEqual(ServiceFeature.objects.get(host='www.example.test', port=443).detail, 'no ALPN protocol chosen')
        hygiene_harness.run_hygiene(self.domain.id, probe=probe(None))  # an older Sentinel: unknown, not "no"
        self.assertFalse(ServiceFeature.objects.filter(host='www.example.test').exists())
        hygiene_harness.run_hygiene(self.domain.id, probe=probe('h2'))
        hygiene_harness.run_hygiene(self.domain.id, probe=lambda host, port: None)  # nothing speaks TLS there any more
        self.assertFalse(ServiceFeature.objects.filter(host='www.example.test').exists())

    def test_store_takes_only_the_vocabulary(self):
        for args in (('http3', 'yes', 'tls_alpn'), ('http2', 'maybe', 'tls_alpn'), ('http2', 'yes', 'banner')):
            with self.assertRaises(ValueError):
                service_features.store(self.domain, 'www.example.test', 443, *args)
        with self.assertRaises(ValueError):
            service_features.store(self.domain, 'www.example.test', 70000, 'http2', 'yes', 'tls_alpn')


class AssessTests(FeatureCase):
    def state(self, cve=None):
        sub = Subdomain.objects.select_related('target_domain').get(pk=self.sub.pk)
        items = service_features.preconditions_for(sub, cve or self.cve)
        return items[0]['state'] if items else None

    def test_a_cve_that_needs_nothing_has_no_precondition(self):
        self.reading(443, 'no', 'ALPN http/1.1')
        self.assertIsNone(self.state(self.other))

    def test_absent_offered_and_unknown(self):
        self.assertEqual(self.state(), 'unknown')  # no reading
        self.reading(443, 'no', 'ALPN http/1.1')
        self.assertEqual(self.state(), 'absent')
        self.reading(443, 'yes', 'ALPN h2')
        self.assertEqual(self.state(), 'offered')

    def test_a_stale_reading_is_unknown(self):
        self.reading(443, 'no', 'ALPN http/1.1', age=service_features.FRESH.days + 1)
        self.assertEqual(self.state(), 'unknown')

    def test_a_known_https_port_that_was_not_read_keeps_it_unknown(self):
        self.ip.ports.add(Port.objects.create(number=4443, service_name='https'))
        self.reading(443, 'no', 'ALPN http/1.1')
        self.assertEqual(self.state(), 'unknown')
        self.reading(4443, 'no', 'ALPN http/1.1')
        self.assertEqual(self.state(), 'absent')

    def test_only_a_mail_port_read_is_not_enough_to_rule_out(self):
        self.reading(993, 'no', 'no ALPN protocol chosen')
        self.assertEqual(self.state(), 'unknown')

    def test_a_host_behind_a_cdn_reads_unknown_either_way(self):
        Subdomain.objects.filter(pk=self.sub.pk).update(is_cdn=True, cdn_name='cloudfront', cname='d111.cloudfront.net')
        self.reading(443, 'no', 'ALPN http/1.1')
        self.assertEqual(self.state(), 'unknown')
        self.reading(443, 'yes', 'ALPN h2')
        self.assertEqual(self.state(), 'unknown')

    def test_a_person_can_correct_the_rule_on_a_manual_record(self):
        self.reading(443, 'no', 'ALPN http/1.1')
        CVEDetection.objects.create(cve_entry=self.cve, source='manual', strategy={'summary': 's', 'requires_features': {'http2': False}})
        service_features.reset_index()
        self.assertIsNone(self.state())
        CVEDetection.objects.create(cve_entry=self.other, source='manual', strategy={'summary': 's', 'requires_features': {'http2': True}})
        service_features.reset_index()
        self.assertEqual(self.state(self.other), 'absent')

    def test_a_models_record_cannot_add_the_precondition(self):
        CVEDetection.objects.create(cve_entry=self.other, source='ai', strategy={'summary': 's', 'requires_features': {'http2': True}})
        self.reading(443, 'no', 'ALPN http/1.1')
        self.assertIsNone(self.state(self.other))


class MatchTests(FeatureCase):
    def test_not_offered_closes_the_match_through_the_deterministic_path_with_the_reading_named(self):
        match = self.match()
        self.reading(443, 'no', 'ALPN http/1.1')
        counts = service_features.reevaluate(self.project.pk, {self.sub.name})
        self.assertEqual(counts['closed'], 1)
        match = self.fresh(match)
        self.assertEqual((match.ai_verdict, match.ai_model, match.confidence), ('not_affected', 'deterministic-correlation', 0.0))
        self.assertTrue(match.ai_reason.startswith(correlation.PRECONDITION_CLOSED))
        self.assertIn('does not offer HTTP/2 (on 443: ALPN http/1.1)', match.ai_reason)
        self.assertIn('configurations that use HTTP/2', match.ai_reason)
        self.assertEqual(Triage.objects.get(match=match).classification, 'not_applicable')
        self.assertEqual(correlation.invalid_identity_reason(match), match.ai_reason)  # triage closes it the same way, never asking the AI
        explained = match_explain.explain(match)
        self.assertEqual((explained['confidence'], explained['basis']), ('ruled_out', 'precondition_absent'))
        # a later reading that shows HTTP/2 reopens it, unjudged, its confidence raised within the ceiling
        self.reading(443, 'yes', 'ALPN h2')
        counts = service_features.reevaluate(self.project.pk, {self.sub.name})
        self.assertEqual(counts['reopened'], 1)
        match = self.fresh(match)
        self.assertEqual((match.ai_verdict, match.ai_reason), ('', ''))
        self.assertEqual(match.confidence, 0.9)
        self.assertEqual(match.evidence['preconditions']['http2']['state'], 'offered')
        self.assertEqual(Triage.objects.get(match=match).status, 'pending')

    def test_offered_raises_the_confidence_once_and_names_the_evidence_but_never_lifts_the_ceiling(self):
        match = self.match()
        self.reading(443, 'yes', 'ALPN h2')
        self.assertEqual(service_features.reevaluate(self.project.pk, {self.sub.name})['raised'], 1)
        self.assertEqual(service_features.reevaluate(self.project.pk, {self.sub.name})['raised'], 0)  # not twice
        match = self.fresh(match)
        self.assertEqual(match.confidence, 0.9)
        self.assertEqual(match.evidence['preconditions']['http2'], {'state': 'offered', 'detail': 'on 443: ALPN h2', 'boost': 0.05})
        explained = match_explain.explain(match)
        self.assertIn('the host offers it (on 443: ALPN h2): a precondition holds, which is not proof', explained['why'])
        self.assertEqual(explained['confidence'], 'not_confirmed')
        self.assertEqual(explained['preconditions'][0]['state'], 'offered')
        d = triage.describe_cve_match(match)
        self.assertTrue(d['facts']['version_only'])
        self.assertEqual(triage.ceiling('cve_match', d['facts'])[0], 'needs_validation')  # HTTP/2 on is a precondition, not proof
        self.assertEqual(d['payload']['preconditions'][0]['host_reading'], 'offered')
        self.assertIn('configurations that use HTTP/2', d['payload']['preconditions'][0]['advisory_says'])
        self.assertEqual(d['signature_fields']['preconditions'], {'HTTP/2': 'offered'})
        # the reading goes stale: the boost goes with it
        ServiceFeature.objects.update(observed_at=timezone.now() - datetime.timedelta(days=service_features.FRESH.days + 1))
        self.assertEqual(service_features.reevaluate(self.project.pk, {self.sub.name})['lowered'], 1)
        self.assertEqual(self.fresh(match).confidence, 0.85)

    def test_unknown_changes_nothing_and_a_cve_that_needs_nothing_is_untouched(self):
        match, other = self.match(), self.match(cve=self.other)
        Subdomain.objects.filter(pk=self.sub.pk).update(is_cdn=True, cdn_name='cloudflare')
        self.reading(443, 'no', 'ALPN http/1.1')
        self.assertEqual(service_features.reevaluate(self.project.pk, {self.sub.name}), {'closed': 0, 'reopened': 0, 'raised': 0, 'lowered': 0})
        self.assertEqual(self.fresh(match).ai_verdict, '')
        self.assertEqual(self.fresh(other).evidence, {'source': 'tech', 'raw_version': '1.25.0'})

    def test_a_template_hit_is_never_closed_by_a_reading(self):
        match = self.match(template_result='vulnerable')
        self.reading(443, 'no', 'ALPN http/1.1')
        self.assertEqual(correlation.invalid_identity_reason(self.fresh(match)), '')

    def test_h2c_named_by_the_advisory_raises_but_never_rules_out(self):
        self.cve.original_description = 'The HTTP/2 module, when the Protocols configuration includes h2 or h2c, does not restrict lengths.'
        self.cve.save()
        service_features.reset_index()
        match = self.match()
        self.reading(443, 'no', 'ALPN http/1.1')
        self.assertEqual(service_features.reevaluate(self.project.pk, {self.sub.name})['closed'], 0)
        self.assertEqual(self.fresh(match).ai_verdict, '')

    def test_a_new_reading_from_the_hygiene_check_reaches_existing_matches(self):
        match = self.match()

        def probe(host, port):
            return {'host': host, 'port': port, 'subject': host, 'sans': [host], 'not_after': timezone.now() + datetime.timedelta(days=90),
                    'signature_algorithm': 'sha256', 'key_description': 'RSA 2048', 'protocol': 'TLSv1.3', 'chain_error': '', 'legacy_tls': False,
                    'alpn': 'http/1.1'} if host == 'www.example.test' else None
        hygiene_harness.run_hygiene(self.domain.id, probe=probe)
        self.assertTrue(self.fresh(match).ai_reason.startswith(correlation.PRECONDITION_CLOSED))

    def test_correlation_raises_a_new_match_where_the_host_offers_http2(self):
        self.reading(443, 'yes', 'ALPN h2')
        cve_by_id = {c.id: c for c in CVEEntry.objects.only(*correlation._CVE_FIELDS)}
        for c in cve_by_id.values():
            c.affected = correlation.clean_affected(c.affected)
        index = correlation.build_product_index(cve_by_id.values())
        rows = []
        sub = Subdomain.objects.select_related('target_domain').get(pk=self.sub.pk)
        correlation._record_matches(sub, 'nginx', '1.25.0', correlation._norm('nginx'), 'tech', index, cve_by_id, 0.0, None, rows=rows,
                                    evidence={'source': 'tech'})
        by_cve = {r['cve_entry_id']: r for r in rows}
        self.assertEqual(by_cve[self.cve.pk]['confidence'], 0.9)
        self.assertEqual(by_cve[self.cve.pk]['evidence']['preconditions']['http2']['state'], 'offered')
        self.assertEqual(by_cve[self.other.pk]['confidence'], 0.85)
        self.assertNotIn('preconditions', by_cve[self.other.pk]['evidence'])


class ShownTests(FeatureCase):
    def setUp(self):
        super().setUp()
        from cveFeed.models import TlsCertificate
        TlsCertificate.objects.create(domain=self.domain, host=self.sub.name, port=443, not_after=timezone.now() + datetime.timedelta(days=60))
        self.reading(443, 'yes', 'ALPN h2')
        self.user = User.objects.create_user('sfu', password='x')
        ProjectMembership.objects.create(user=self.user, project=self.project, role='user')
        _, self.tok = create_token(self.user, 't')

    def test_the_certificate_list_and_the_host_say_whether_http2_is_offered(self):
        status, data = call(self.tok, 'GET', '/api/v1/projects/sf/certificates')
        self.assertEqual(status, 200)
        self.assertEqual(data['results'][0]['http2']['offered'], True)
        self.assertEqual(data['results'][0]['http2']['reading'], 'ALPN h2')
        status, data = call(self.tok, 'GET', '/api/v1/projects/sf/hosts')
        self.assertEqual(status, 200)
        row = next(h for h in data['results'] if h['host'] == self.sub.name)
        self.assertEqual([(f['port'], f['feature'], f['offered'], f['fresh']) for f in row['service_features']], [(443, 'http2', True, True)])

    def test_purging_the_host_removes_its_readings(self):
        from agentapi import host_manage
        with mock.patch.object(host_manage, '_purge', wraps=host_manage._purge):
            host_manage._purge(self.project, self.sub.name)
        self.assertFalse(ServiceFeature.objects.filter(host=self.sub.name).exists())
