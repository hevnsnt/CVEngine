"""The AI host review (cveFeed.host_review): the models and settings. (``test_host_review.py`` is
the updater's container-settings check, a different feature.)"""
from django.db import IntegrityError, transaction
from django.db.models import NOT_PROVIDED
from django.test import TestCase
from django.utils import timezone

from cveFeed.models import FindingReview, HostReview, ProjectSettings, ReviewerSettings
from dashboard.models import Org, Project
from reNgine import ai_prompts, ai_profiles
from targetApp.models import Domain


class ModelTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        cls.org = Org.objects.create(name='HR', slug='hr-org')
        cls.proj = Project.objects.create(name='HR', slug='hr-proj', insert_date=now, org=cls.org)
        cls.other = Project.objects.create(name='HR2', slug='hr-proj2', insert_date=now, org=cls.org)
        cls.domain = Domain.objects.create(name='example.com', project=cls.proj, insert_date=now)

    def test_the_settings_default_to_a_review_that_starts_read_only_steps_on_its_own(self):
        self.assertEqual(ProjectSettings.objects.create(project=self.proj).host_review_mode, 'auto')
        row = ReviewerSettings.current()
        self.assertEqual((row.host_review_enabled, row.host_review_daily_max, row.host_review_auto_per_project_day), (True, 100, 50))

    def test_every_new_column_of_an_existing_table_has_a_database_default(self):
        # the previous release's code keeps inserting rows without these columns until the workers restart
        for model, names in ((ProjectSettings, ['host_review_mode']),
                             (ReviewerSettings, ['host_review_enabled', 'host_review_daily_max', 'host_review_auto_per_project_day']),
                             (FindingReview, ['demotes'])):
            for name in names:
                self.assertIsNot(model._meta.get_field(name).db_default, NOT_PROVIDED, f'{model.__name__}.{name}')

    def test_one_review_is_open_per_host_and_a_finished_one_makes_room(self):
        first = HostReview.objects.create(project=self.proj, domain=self.domain, host='www.example.com', state_key='a' * 40)
        with self.assertRaises(IntegrityError), transaction.atomic():
            HostReview.objects.create(project=self.proj, domain=self.domain, host='www.example.com', state_key='b' * 40)
        HostReview.objects.create(project=self.other, domain=self.domain, host='www.example.com', state_key='a' * 40)  # another project's host
        first.status = 'applied'
        first.save()
        again = HostReview.objects.create(project=self.proj, domain=self.domain, host='www.example.com', state_key='b' * 40)
        self.assertEqual((again.status, again.step_state, again.refs), ('queued', '', {}))

    def test_a_host_review_is_scoped_to_its_project(self):
        from tenancy.scope import SCOPES
        self.assertEqual(SCOPES['cveFeed.HostReview'], 'project_id')

    def test_the_host_review_stages_are_registered_with_a_task_an_answer_room_and_a_cache_lifetime(self):
        for stage in ('host_review', 'host_review_repair'):
            self.assertIn(stage, ai_prompts.STAGES)
            self.assertIn(stage, ai_prompts.TASKS)
            self.assertEqual(ai_profiles.STAGE_ANSWER_CAPS[stage], 6000)
            self.assertEqual(ai_profiles.STAGE_CACHE_TTL[stage], '5m')

