"""A mail name whose lookup failed on the Sentinel is unknown, not "no mail here": its open SPF and DMARC findings stay open."""
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from cveFeed import hygiene
from dashboard.models import Org, Project
from targetApp.models import Domain


class UnknownMailTests(TestCase):
    def setUp(self):
        org = Org.objects.create(name='H', slug='hyg-m')
        project = Project.objects.create(name='H', slug='hyg-m-p', insert_date=timezone.now(), org=org)
        self.domain = Domain.objects.create(name='example.com', project=project, insert_date=timezone.now())

    def review(self, answer, mail):
        with mock.patch.object(hygiene, 'mail_candidates', return_value=(['example.com'], ['mail.example.com'])), \
                mock.patch('agentapi.probe_dispatch.try_hygiene', return_value=answer) as asked:
            review, waiting = hygiene._remote_review(self.domain, [], None)
        self.assertFalse(waiting)
        return review

    def test_a_name_the_scanner_could_not_look_up_is_unknown_even_when_it_is_not_an_own_name(self):
        review = self.review({'outcome': 'done', 'certs': [], 'mail': [], 'unknown_names': ['mail.example.com']}, None)
        self.assertIn('mail.example.com', review['unknown_mail'])  # the own name is unknown too: it always gets a row

    def test_a_row_that_carries_an_error_is_unknown(self):
        review = self.review({'outcome': 'done', 'certs': [], 'mail': [{'name': 'example.com', 'error': 'mx lookup failed', 'findings': [], 'has_mx': False}]}, None)
        self.assertIn('example.com', review['unknown_mail'])
        self.assertEqual(review['mail_hosts'], [])

    def test_a_name_with_no_mail_and_no_failure_is_still_just_skipped(self):
        review = self.review({'outcome': 'done', 'certs': [], 'mail': []}, None)
        self.assertNotIn('mail.example.com', review['unknown_mail'])  # an extra name with no MX was never a mail host
