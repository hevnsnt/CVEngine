"""The Your API keys list: newest first with Created, the first 4 and last 2 characters of a token and no more, one live name per user, revoke."""
import importlib
import json
from datetime import timedelta

from django.apps import apps
from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from agentapi.auth import create_token
from dashboard.models import ApiToken
from tests.test_tenancy import client_for

URL = '/api/v1/tokens'


class ApiKeysListTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('keys-a', password='x')
        self.other = User.objects.create_user('keys-b', password='x')
        self.c = client_for(self.user)

    def make(self, c, name, **extra):
        return c.post(URL, json.dumps({'name': name, **extra}), content_type='application/json')

    def test_the_list_is_newest_first_and_carries_created(self):
        now = timezone.now()
        old, _ = create_token(self.user, 'oldest')
        mid, _ = create_token(self.user, 'middle')
        new, _ = create_token(self.user, 'newest')
        for t, days in ((old, 30), (mid, 10), (new, 1)):
            ApiToken.objects.filter(pk=t.pk).update(created_at=now - timedelta(days=days))
        # made out of order on purpose: the id order is not the date order
        ApiToken.objects.filter(pk=old.pk).update(created_at=now - timedelta(days=1, hours=1))
        ApiToken.objects.filter(pk=new.pk).update(created_at=now - timedelta(days=40))
        rows = self.c.get(URL).json()['results']
        self.assertEqual([r['name'] for r in rows], ['oldest', 'middle', 'newest'])
        self.assertTrue(all(r['created'] for r in rows))
        self.assertEqual([r['created'] for r in rows], sorted((r['created'] for r in rows), reverse=True))

    def test_only_the_first_four_and_last_two_characters_leave_the_server(self):
        made = self.make(self.c, 'shown').json()
        raw = made['token']
        row = [r for r in self.c.get(URL).json()['results'] if r['name'] == 'shown'][0]
        self.assertEqual((row['prefix'], row['suffix']), (raw[:4], raw[-2:]))
        self.assertEqual(row['hint'], f'{raw[:4]}...{raw[-2:]}')
        body = json.dumps(self.c.get(URL).json())
        self.assertNotIn(raw[:5], body)  # not one character more at the front
        self.assertNotIn(raw[-3:], body)  # nor at the end
        stored = ApiToken.objects.get(pk=made['id'])
        self.assertEqual((stored.prefix, stored.suffix), (raw[:4], raw[-2:]))

    def test_a_key_made_before_the_ending_was_kept_shows_only_the_start(self):
        token = ApiToken.objects.create(user=self.user, name='legacy', key_hash='f' * 64, prefix='cve_AbCd')  # an old row: 8 leading characters, no ending
        row = [r for r in self.c.get(URL).json()['results'] if r['id'] == token.id][0]
        self.assertEqual((row['prefix'], row['suffix'], row['hint']), ('cve_', '', 'cve_...'))

    def test_the_migration_cuts_stored_prefixes_to_four(self):
        ApiToken.objects.create(user=self.user, name='legacy', key_hash='e' * 64, prefix='cve_AbCd')
        migration = importlib.import_module('dashboard.migrations.0034_apitoken_suffix')
        migration.keep_four(apps, None)
        self.assertEqual(ApiToken.objects.get(name='legacy').prefix, 'cve_')

    def test_a_second_key_with_the_same_name_is_refused_in_plain_words(self):
        self.assertEqual(self.make(self.c, 'remediation-agent').status_code, 201)
        for again, said in (('remediation-agent', 'remediation-agent'), ('Remediation-Agent', 'Remediation-Agent'), ('  remediation-agent  ', 'remediation-agent')):
            r = self.make(self.c, again)
            self.assertEqual(r.status_code, 409, again)
            self.assertEqual(r.json()['error'], f'You already have an API key named "{said}". Pick another name, or revoke the old one first.')
        self.assertEqual(ApiToken.objects.filter(user=self.user, name='remediation-agent').count(), 1)

    def test_the_name_is_per_user_and_a_revoked_key_frees_it(self):
        self.assertEqual(self.make(self.c, 'ci').status_code, 201)
        self.assertEqual(self.make(client_for(self.other), 'ci').status_code, 201)
        mine = ApiToken.objects.get(user=self.user, name='ci')
        self.assertEqual(self.c.delete(f'{URL}/{mine.id}').status_code, 200)
        self.assertEqual(self.make(self.c, 'ci').status_code, 201)

    def test_old_duplicates_stay_in_the_list_and_can_be_revoked(self):
        a, _ = create_token(self.user, 'dup')
        b, _ = create_token(self.user, 'dup')
        names = [r['name'] for r in self.c.get(URL).json()['results']]
        self.assertEqual(names.count('dup'), 2)
        self.assertEqual(self.c.delete(f'{URL}/{a.id}').status_code, 200)
        self.assertEqual([r['id'] for r in self.c.get(URL).json()['results'] if not r['revoked']], [b.id])
        self.assertEqual(self.make(self.c, 'dup').status_code, 409)  # still one live

    def test_read_only_is_in_the_list_and_a_host_reporter_name_can_repeat(self):
        self.make(self.c, 'viewer', read_only=True)
        self.assertTrue([r for r in self.c.get(URL).json()['results'] if r['name'] == 'viewer'][0]['read_only'])
        from dashboard.models import Org, OrgMembership, Project
        org = Org.objects.create(name='O', slug='o')
        OrgMembership.objects.create(user=self.user, org=org, role='admin')
        Project.objects.create(name='P', slug='p', org=org, insert_date=timezone.now())
        first = self.make(self.c, 'inventory reporter for p', scope='inventory', project='p')
        self.assertEqual(first.status_code, 201, first.content)
        self.assertEqual(self.make(self.c, 'inventory reporter for p', scope='inventory', project='p').status_code, 201)  # renewing a reporter keeps working

    def test_a_blank_name_is_still_a_missing_field(self):
        self.assertEqual(self.make(self.c, '   ').status_code, 400)
