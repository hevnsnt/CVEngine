"""``wordpress 7.1`` means the product at that release, not any host with "7.1" somewhere in an address, banner or title."""
from urllib.parse import urlencode

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi import services
from agentapi.auth import create_token
from dashboard.models import Org, Project, ProjectMembership
from startScan.models import IpAddress, Port, Subdomain, Technology
from targetApp.models import Domain
from tests.test_agentapi import call

NOW = timezone.now()


class ParseTests(SimpleTestCase):
    def terms(self, q):
        return services.parse_search(q)

    def test_a_word_and_a_dotted_version_become_one_term(self):
        self.assertEqual(self.terms('wordpress 7.1'), [(False, 'techver', 'wordpress 7.1', False)])
        self.assertEqual(self.terms('nginx 1.24.0 php'), [(False, 'techver', 'nginx 1.24.0', False), (False, None, 'php', False)])

    def test_a_leading_v_is_dropped(self):
        self.assertEqual(self.terms('jquery v3.7.1')[0][2], 'jquery 3.7.1')

    def test_a_version_on_its_own_keeps_its_old_meaning(self):
        self.assertEqual(self.terms('7.1'), [(False, None, '7.1', False)])

    def test_a_negation_a_phrase_or_a_field_is_not_bound(self):
        self.assertEqual(self.terms('-wordpress 7.1'), [(True, None, 'wordpress', False), (False, None, '7.1', False)])
        self.assertEqual(self.terms('"apache tomcat" 9.0'), [(False, None, 'apache tomcat', True), (False, None, '9.0', False)])
        self.assertEqual(self.terms('tech:wordpress 7.1'), [(False, 'tech', 'wordpress', False), (False, None, '7.1', False)])

    def test_a_bare_integer_is_not_a_version(self):
        self.assertEqual(self.terms('port 80'), [(False, None, 'port', False), (False, None, '80', False)])

    def test_two_versions_in_a_row_are_not_bound_to_each_other(self):
        self.assertEqual(len(self.terms('7.1 8.2')), 2)


class SearchTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        org = Org.objects.create(name='Widgets', slug='widgets')
        cls.project = Project.objects.create(name='V', slug='ver-a', insert_date=NOW, org=org)
        cls.domain = Domain.objects.create(name='acme.example', project=cls.project, insert_date=NOW)
        user = User.objects.create_user('ver-user', password='x')
        ProjectMembership.objects.create(user=user, project=cls.project, role='user')
        _, cls.token = create_token(user, 'ver')

        def host(name, tech=(), ip=None, ports=(), title=''):
            sub = Subdomain.objects.create(name=name, target_domain=cls.domain, page_title=title)
            for t in tech:
                sub.technologies.add(Technology.objects.get_or_create(name=t)[0])
            if ip:
                addr = IpAddress.objects.get_or_create(address=ip)[0]
                sub.ip_addresses.add(addr)
                for number, product, version in ports:
                    addr.ports.add(Port.objects.create(number=number, service_name='http', product=product, version=version))
            return sub
        host('wp714.acme.example', tech=['WordPress:7.1.4'])
        host('wp71.acme.example', tech=['WordPress:7.1'])
        host('wp64.acme.example', tech=['WordPress:6.4.2'])
        host('wp710.acme.example', tech=['WordPress:7.10.0'])
        host('wpnone.acme.example', tech=['WordPress'])
        host('jq.acme.example', tech=['jQuery:7.1.0'])
        host('address.acme.example', ip='10.7.1.5')  # "7.1" is only inside its address
        host('titled.acme.example', title='Release 7.1 notes')
        host('nginx.acme.example', ip='203.0.113.9', ports=[(80, 'nginx', '1.24.0')])

    def names(self, q):
        status, data = call(self.token, 'GET', '/api/v1/projects/ver-a/search?' + urlencode({'q': q}))
        self.assertEqual(status, 200, data)
        return sorted(h['host'] for h in data['results'])

    def test_the_product_at_that_release_is_found_and_nothing_else_that_contains_the_number(self):
        self.assertEqual(self.names('wordpress 7.1'), ['wp71.acme.example', 'wp714.acme.example'])

    def test_a_longer_release_number_is_not_a_prefix_match(self):
        self.assertNotIn('wp710.acme.example', self.names('wordpress 7.1'))  # 7.10 is not 7.1

    def test_a_full_version_finds_that_release_only(self):
        self.assertEqual(self.names('wordpress 7.1.4'), ['wp714.acme.example'])

    def test_a_service_version_on_an_open_port_counts(self):
        self.assertEqual(self.names('nginx 1.24'), ['nginx.acme.example'])

    def test_the_result_says_what_matched(self):
        status, data = call(self.token, 'GET', '/api/v1/projects/ver-a/search?' + urlencode({'q': 'wordpress 7.1.4'}))
        self.assertEqual(data['results'][0]['matched'], ['technology WordPress:7.1.4'])

    def test_a_version_on_its_own_still_matches_the_old_way(self):
        found = self.names('7.1')
        self.assertIn('address.acme.example', found)
        self.assertIn('titled.acme.example', found)

    def test_it_combines_with_other_terms_and_negation(self):
        self.assertEqual(self.names('wordpress 7.1 -host:wp714'), ['wp71.acme.example'])
