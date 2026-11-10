"""A search may negate at most three terms (review 2-db-injection F1).

The review measured one request at 62 seconds of database time with fifteen negated words. Its explanation, that the negation turns into a correlated
subquery per host row, did not hold up when the same plan was measured on equal terms: its positive baseline matched no host at all, so it compared a
query that returns nothing with one that returns every host. A negated word and a positive word that match the same hosts read the same number of
blocks. What is real is that every term, negated or not, is a pass over the project's hosts, and a search of fifteen of them is the cost. The number of
negated terms is capped; the statement timeout (``tests.test_web_statement_timeout``) bounds whatever is left.
"""
from django.test import SimpleTestCase

from agentapi import services
from agentapi.services import ApiError


class NegatedTermCapTests(SimpleTestCase):
    def test_a_search_may_negate_three_terms_and_not_four(self):
        self.assertEqual(len(services.parse_search('-a -b -c')), 3)
        with self.assertRaises(ApiError) as caught:
            services.parse_search('-a -b -c -d')
        self.assertEqual(caught.exception.status, 400)
        self.assertIn('at most 3 negated terms', caught.exception.message)

    def test_filter_negations_count_and_positive_terms_do_not(self):
        self.assertEqual(len(services.parse_search('-host:a -port:22 -tech:b port:80 nginx apache')), 6)
        with self.assertRaises(ApiError):
            services.parse_search('-host:a -port:22 -tech:b -product:c port:80')

    def test_the_cap_applies_to_a_saved_search_too(self):
        with self.assertRaises(ApiError):
            services.check_search('-a -b -c -d')
