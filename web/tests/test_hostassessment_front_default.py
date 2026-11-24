"""cveFeed 0193: the host assessment's ``front`` column has a database default, so code that does not know the column can still insert.

0178 added ``front`` NOT NULL with only a Python default, which Django drops from the column after adding it. The code of 1.4.2 inserts host
assessments without the column, so every one it queued failed (during an update, between the migration and the restart, and after a rollback).
"""
from django.contrib.auth.models import User
from django.db import connection
from django.db.migrations.loader import MigrationLoader
from django.db.migrations.operations import AddField, RenameField
from django.db.models import NOT_PROVIDED, ManyToManyField
from django.test import TestCase
from django.utils import timezone

from cveFeed.models import HostAssessment
from dashboard.models import Org, Project
from targetApp.models import Domain

# The host assessment columns 1.4.2 knows (its model, in its own order): what its INSERT names.
OLD_COLUMNS = ('project_id', 'domain_id', 'host', 'source', 'requested_by_id', 'status', 'scan_id', 'celery_id', 'result', 'error',
               'created_at', 'started_at', 'finished_at')

# The last migration of each app in the v1.4.2 tag: everything after them runs while 1.4.2's containers may still be inserting.
RELEASED_LEAVES = {'cveFeed': '0177_service_features', 'dashboard': '0037_drop_unused_legacy_models',
                   'startScan': '0028_subdomain_technology_source', 'agentapi': '0025_dns_readings',
                   'scanEngine': '0008_drop_unused_legacy_models', 'targetApp': '0008_domain_expect_private_ca',
                   'recon_note': '0002_drop_todonote'}


class FrontDatabaseDefaultTests(TestCase):
    def setUp(self):
        now = timezone.now()
        org = Org.objects.create(name='Front default', slug='front-default-org')
        self.project = Project.objects.create(name='Front default', slug='front-default', org=org, insert_date=now)
        self.domain = Domain.objects.create(name='front-default.example', project=self.project, insert_date=now)
        self.user = User.objects.create_user('front-default-user', password='x')

    def _old_insert(self, host):
        """The INSERT 1.4.2's ORM sends for a new host assessment: every column it knows, and not ``front``."""
        values = {'project_id': self.project.pk, 'domain_id': self.domain.pk, 'host': host, 'source': 'manual',
                  'requested_by_id': self.user.pk, 'status': 'queued', 'scan_id': None, 'celery_id': '', 'result': '{}', 'error': '',
                  'created_at': timezone.now(), 'started_at': None, 'finished_at': None}
        cols = ', '.join(f'"{c}"' for c in OLD_COLUMNS)
        marks = ', '.join(['%s'] * len(OLD_COLUMNS))
        with connection.cursor() as cur:
            cur.execute(f'INSERT INTO "cveFeed_hostassessment" ({cols}) VALUES ({marks}) RETURNING id', [values[c] for c in OLD_COLUMNS])
            return cur.fetchone()[0]

    def test_an_insert_without_the_column_succeeds_and_reads_false(self):
        pk = self._old_insert('old.front-default.example')
        self.assertIs(HostAssessment.objects.get(pk=pk).front, False)

    def test_the_database_default_equals_what_the_model_default_stores(self):
        old = HostAssessment.objects.get(pk=self._old_insert('old.front-default.example'))
        new = HostAssessment.objects.create(project=self.project, domain=self.domain, host='new.front-default.example',
                                            requested_by=self.user)
        new.refresh_from_db()
        field = HostAssessment._meta.get_field('front')
        self.assertIs(field.default, False)
        self.assertIs(field.db_default, False)
        self.assertEqual(old.front, new.front)
        self.assertIs(new.front, False)
        # a person's request still stores true: the Python default does not override a value that was given
        asked = HostAssessment.objects.create(project=self.project, domain=self.domain, host='asked.front-default.example', front=True)
        asked.refresh_from_db()
        self.assertIs(asked.front, True)

    def test_the_column_carries_the_default_in_the_catalogue(self):
        with connection.cursor() as cur:
            cur.execute("SELECT is_nullable, column_default FROM information_schema.columns "
                        "WHERE table_name = 'cveFeed_hostassessment' AND column_name = 'front'")
            self.assertEqual(cur.fetchone(), ('NO', 'false'))

    def test_every_not_null_column_added_since_the_release_has_a_database_default(self):
        """What the upgrade rehearsal's schema check (.github/rehearsal/schema.sh) catches, found before a rehearsal runs: a column added after
        1.4.2 to a table 1.4.2 already had must be nullable or carry db_default, or the old code's inserts fail during the update window."""
        loader = MigrationLoader(None, ignore_no_migrations=True)
        released = set()
        for app, name in RELEASED_LEAVES.items():
            released.update(loader.graph.forwards_plan((app, name)))
        state = loader.project_state()
        old_state = loader.project_state(nodes=[(app, name) for app, name in RELEASED_LEAVES.items()], at_end=True)
        risky = []
        for key, migration in loader.graph.nodes.items():
            if key in released or key[0] not in RELEASED_LEAVES:  # third-party apps keep their own versions
                continue
            for op in migration.operations:
                if isinstance(op, AddField):
                    name = op.name
                elif isinstance(op, RenameField):
                    name = op.new_name
                else:
                    continue
                model_key = (key[0], op.model_name_lower)
                if model_key not in old_state.models or model_key not in state.models:
                    continue  # a table the old code never had, or one dropped since
                field = state.models[model_key].fields.get(name)
                if field is None or field.null or isinstance(field, ManyToManyField):
                    continue
                if field.db_default is NOT_PROVIDED:
                    risky.append(f'{key[0]}.{key[1]}: {op.model_name}.{name}')
        self.assertEqual(risky, [], 'NOT NULL columns without db_default that 1.4.2 cannot insert around')
