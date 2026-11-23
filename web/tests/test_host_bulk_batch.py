"""A bulk host action resolves the project once and reads every name's row in one query (review finding C3).

``host_bulk`` called ``host_archive`` once per name: each call checked the caller's access to the project again and looked its name up with
``name__iexact`` (``UPPER(name) = UPPER(%s)``, which no index serves, so every host row of the project was read), up to 200 times. The project is now
resolved once and the newest row of every name read in one query, matched the same way; each name still answers what it answered on its own.
"""
from django.contrib.auth.models import User
from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from agentapi import host_manage
from agentapi.auth import create_token
from agentapi.services import Ctx
from cveFeed.models import HostState
from dashboard.models import Org, Project, ProjectMembership
from startScan.models import Subdomain
from targetApp.models import Domain
from tests.test_agentapi import call


class HostBulkBatchTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        org = Org.objects.create(name='Hb', slug='hb-org')
        cls.project = Project.objects.create(name='hb', slug='hb-proj', insert_date=now, org=org)
        other = Project.objects.create(name='hb-other', slug='hb-other', insert_date=now, org=org)
        cls.domain = Domain.objects.create(name='hb.example', project=cls.project, insert_date=now)
        other_domain = Domain.objects.create(name='hb-other.example', project=other, insert_date=now)
        cls.names = [f'h{i}.hb.example' for i in range(12)]
        for name in cls.names:
            Subdomain.objects.create(target_domain=cls.domain, name=name)
        Subdomain.objects.create(target_domain=cls.domain, name='Mixed.HB.example')  # stored in mixed case: still the host mixed.hb.example
        Subdomain.objects.create(target_domain=other_domain, name='elsewhere.hb.example')  # another project's host: not found here
        user = User.objects.create_user('hb-user', password='x')
        ProjectMembership.objects.create(user=user, project=cls.project, role='user')
        cls.token = create_token(user, 'agent')[1]

    def setUp(self):
        cache.clear()

    def bulk(self, hosts, action, **extra):
        with CaptureQueriesContext(connection) as ctx:
            status, out = call(self.token, 'POST', '/api/v1/projects/hb-proj/hosts/bulk', {'hosts': hosts, 'action': action, **extra})
        self.assertEqual(status, 200, out)
        return out, ctx.captured_queries

    def test_the_names_are_looked_up_once_and_each_answers_as_before(self):
        hosts = [*self.names, 'MIXED.hb.example', 'elsewhere.hb.example', 'bad*name', self.names[0]]
        out, queries = self.bulk(hosts, 'pin')
        self.assertEqual(out['hosts'], [*self.names, 'MIXED.hb.example'])
        self.assertEqual({f['host']: f['error'][:20] for f in out['failed']},
                         {'elsewhere.hb.example': 'host not found in th', 'bad*name': 'host must be one exa'})
        self.assertEqual(HostState.objects.filter(project=self.project, pinned=True).count(), 13)
        self.assertTrue(HostState.objects.get(project=self.project, host='mixed.hb.example').pinned)
        lookups = [q for q in queries if 'FROM "startScan_subdomain"' in q['sql'] and 'UPPER(' in q['sql']]
        self.assertEqual(len(lookups), 1)

    def test_archive_and_restore_answer_as_one_at_a_time(self):
        host_manage.host_archive(Ctx(user=User.objects.get(username='hb-user')), 'hb-proj', self.names[1], 'pin', pinned=True)
        out, _ = self.bulk(self.names[:4], 'archive', reason='Owner review')
        self.assertEqual(out['hosts'], [self.names[0], *self.names[2:4]])
        self.assertIn('pinned', out['failed'][0]['error'])
        archived = set(HostState.objects.filter(project=self.project, archived_at__isnull=False).values_list('host', flat=True))
        self.assertEqual(archived, {self.names[0], *self.names[2:4]})
        out, _ = self.bulk(self.names[:4], 'restore')
        self.assertEqual(out['done'], 4)
        self.assertFalse(HostState.objects.filter(project=self.project, archived_at__isnull=False).exists())

    def test_the_batch_lookup_matches_names_as_iexact_does_and_only_in_the_project(self):
        rows = host_manage._newest_rows(self.project, ['mixed.hb.example', 'bad*name', 'elsewhere.hb.example'])
        self.assertEqual({k: v.name for k, v in rows.items()}, {'MIXED.HB.EXAMPLE': 'Mixed.HB.example'})
