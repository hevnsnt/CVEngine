"""First-run wizard: one organization is "the wizard's" in every step."""
import json

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from dashboard.models import Org, OrgMembership, Project
from tests.test_tenancy import client_for


class WelcomeWizardTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser('wiz', password='x')
        self.c = client_for(self.admin)

    def post(self, path, body):
        return self.c.post(f'/cve/api/welcome/{path}', json.dumps(body), content_type='application/json')

    def test_state_and_save_project_use_the_same_organization(self):
        now = timezone.now()
        # two organizations besides Default: the older one belongs to somebody else, the newer one is this superuser's
        other = Org.objects.create(name='Other Corp', slug='other-corp')
        mine = Org.objects.create(name='Mine', slug='mine')
        OrgMembership.objects.create(user=self.admin, org=mine, role='admin')
        Project.objects.create(name='Default', slug='default-other', org=other, insert_date=now)
        shown = self.c.get('/cve/api/welcome/state').json()['org']['slug']
        self.assertEqual(shown, 'mine')
        self.assertEqual(self.post('project', {'name': 'First project'}).status_code, 200)
        self.assertEqual(Project.objects.get(name='First project').org, mine)

    def test_resubmitting_the_org_step_renames_the_wizards_organization(self):
        self.assertEqual(self.post('org', {'name': 'Acme'}).status_code, 200)
        self.assertEqual(self.post('org', {'name': 'Acme Security'}).status_code, 200)
        self.assertEqual(list(Org.objects.exclude(name='Default').values_list('name', flat=True)), ['Acme Security'])
        self.assertEqual(self.c.get('/cve/api/welcome/state').json()['org']['name'], 'Acme Security')

    def test_an_organization_with_targets_is_never_renamed(self):
        from targetApp.models import Domain
        org = Org.objects.create(name='Busy', slug='busy')
        OrgMembership.objects.create(user=self.admin, org=org, role='admin')
        project = Project.objects.create(name='P', slug='busy-p', org=org, insert_date=timezone.now())
        Domain.objects.create(name='busy.example.com', project=project, insert_date=timezone.now())
        self.assertEqual(self.post('org', {'name': 'Fresh Org'}).status_code, 200)
        self.assertTrue(Org.objects.filter(name='Busy').exists())
        self.assertTrue(Org.objects.filter(name='Fresh Org').exists())