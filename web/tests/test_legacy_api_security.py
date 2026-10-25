"""Legacy tenant boundaries. All scanner and queue calls are mocked."""
from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone
from rest_framework.exceptions import PermissionDenied

from dashboard.models import Project, ProjectMembership, SearchHistory
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain, SubScan
from targetApp.models import Domain
from tenancy import roles
from tests.test_tenancy import client_for


class LegacyApiSecurityTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        cls.actor = User.objects.create_user('legacy-user', password='dummy-test-password')
        cls.other = User.objects.create_user('other-tenant', password='dummy-test-password')
        cls.a = Project.objects.create(name='A', slug='legacy-a', insert_date=now)
        cls.b = Project.objects.create(name='B', slug='legacy-b', insert_date=now)
        ProjectMembership.objects.create(user=cls.actor, project=cls.a, role=roles.USER)
        ProjectMembership.objects.create(user=cls.actor, project=cls.b, role=roles.AUDIT)
        ProjectMembership.objects.create(user=cls.other, project=cls.b, role=roles.USER)
        roles.sync_global_role(cls.actor)
        roles.sync_global_role(cls.other)
        engine = EngineType.objects.create(engine_name='dummy', yaml_configuration='{}')
        cls.hosts = []
        for project in (cls.a, cls.b):
            domain = Domain.objects.create(name=f'{project.slug}.example', project=project, insert_date=now)
            scan = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=now)
            cls.hosts.append(Subdomain.objects.create(
                name=domain.name, target_domain=domain, scan_history=scan))

    def post(self, path, data):
        return client_for(self.actor).post(path, data, content_type='application/json')

    def test_delete_checks_actual_project_and_whole_batch(self):
        response = self.post('/api/action/subdomain/delete/', {'subdomain_ids': [h.pk for h in self.hosts]})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(Subdomain.objects.count(), 2)
        # A forged query project must not elevate the B object role.
        response = self.post('/api/action/subdomain/delete/?project=legacy-a', {'subdomain_ids': [self.hosts[1].pk]})
        self.assertEqual(response.status_code, 403)
        response = self.post('/api/action/subdomain/delete/', {'subdomain_ids': [self.hosts[0].pk]})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Subdomain.objects.filter(pk=self.hosts[0].pk).exists())
        self.assertTrue(Subdomain.objects.filter(pk=self.hosts[1].pk).exists())


    def test_history_excludes_other_users_and_unowned_legacy_rows(self):
        SearchHistory.objects.create(query='legacy-private.example')
        SearchHistory.objects.create(user=self.other, query='other-private.example')
        SearchHistory.objects.create(user=self.actor, query='my-private.example')
        response = client_for(self.actor).get('/api/search/history/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['results'], [{'query': 'my-private.example'}])

    def test_search_records_current_owner(self):
        response = client_for(self.actor).get('/api/search/', {'query': 'dummy-owner-test'})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(SearchHistory.objects.filter(user=self.actor, query='dummy-owner-test').exists())

    def test_read_viewsets_have_no_generated_write_handlers(self):
        from api.views import SubdomainsViewSet, VulnerabilityViewSet, InAppNotificationManagerViewSet
        for view in (SubdomainsViewSet, VulnerabilityViewSet, InAppNotificationManagerViewSet):
            self.assertFalse(hasattr(view, 'create'))
            self.assertFalse(hasattr(view, 'update'))
            self.assertFalse(hasattr(view, 'destroy'))

    def test_malformed_ids_are_rejected_before_database_queries(self):
        from api.permissions import writable_batch
        from rest_framework.exceptions import ValidationError
        for invalid in (True, None, 1.0, '\u00b2', '\u0661', '0', '-1', '9' * 20, '9223372036854775808'):
            with self.subTest(value=invalid), self.assertNumQueries(0):
                with self.assertRaises(ValidationError):
                    writable_batch(self.actor, Subdomain, [invalid])

    def test_unbound_objects_fail_closed(self):
        from api.permissions import object_project
        for obj in (Subdomain(target_domain=None), ScanHistory(domain=None),
                    SubScan(scan_history=None)):
            with self.subTest(model=type(obj).__name__):
                with self.assertRaises(PermissionDenied):
                    object_project(obj)
