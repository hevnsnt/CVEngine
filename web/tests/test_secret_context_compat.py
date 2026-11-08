"""A Sentinel with the masked context and a server without it (and the other way round) work together: the context is an optional field of the
contract, which is not a new contract version. This module holds for BOTH servers: it is run against this branch (the context is stored, masked) and, in
the pull request's proof, against the server before it (the field is ignored: the finding is filed with no context)."""
import json

from django.test import SimpleTestCase

from agentapi import sentinel_broker as broker
from cveFeed.models import SecretFinding, SecretOccurrence
from tests.test_secret_context import CANARY, CanaryBase


class NewSentinelAnyServer(CanaryBase):
    def test_a_result_with_context_is_accepted_and_the_finding_is_filed(self):
        sent = self.sentinel_result()
        self.assertTrue(all(f.get('context') for f in sent['findings']))
        self.assertIn('context', json.dumps(sent))
        cleaned = broker.clean_result('secrets_scan', sent)  # the strict cleaner: whatever it does with the field, it does not refuse the result
        self.assertEqual(cleaned['outcome'], 'done')
        self.assertEqual(len(cleaned['findings']), 2)
        self.run_stage(sent)
        self.assertEqual(SecretFinding.objects.count(), 1)
        self.assertEqual(SecretOccurrence.objects.count(), 2)
        for occurrence in SecretOccurrence.objects.all():
            self.assertIn(occurrence.context, ('', f'"x-api-key": "AIza…{CANARY[-4:]}",', occurrence.context))  # none (an older server) or masked, never the value
            self.assertNotIn(CANARY, occurrence.context)

    def test_the_server_never_needs_the_field(self):
        for f in (sent := self.sentinel_result())['findings']:
            f.pop('context')
        self.run_stage(sent)
        self.assertEqual(SecretOccurrence.objects.count(), 2)
        self.assertEqual({o.context for o in SecretOccurrence.objects.all()}, {''})


class RouteCredentialsAnyServer(SimpleTestCase):
    def test_a_credential_with_line_and_context_is_a_credential_to_every_server(self):
        from agentapi import probe_results
        got = probe_results._route_credentials([{'type': 'google_key', 'value': CANARY, 'line': 3, 'context': 'k = "AIza…Zq9w"'}])
        self.assertEqual([(c['type'], c['value']) for c in got], [('google_key', CANARY)])
