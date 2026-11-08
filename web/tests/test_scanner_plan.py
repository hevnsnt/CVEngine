"""Which scanners run: the facts, the question the Update button asks, the endpoints, and the hand-over to the host (cveFeed/scanner_plan.py, docs/UPGRADE.md)."""
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import timedelta
from pathlib import Path
from unittest import mock

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from agentapi import sentinel_broker as sb
from cveFeed import scanner_plan, updater
from cveFeed.models import UpdateSettings
from tests.fake_scanner import FakeScanner, LocalFallback
from tests.test_sentinel_capability_policy import PolicyBase
from tests.test_tenancy import client_for

ROOT = Path(__file__).resolve().parents[2]
OLD, NEW = 'a' * 40, 'b' * 40
SCRUB = ('CVENGINE_BUILTIN_SCANNER', 'CVENGINE_SENTINEL_PLAN', 'CVENGINE_HOST_MEM_MB', 'SCANNER_MEM_LIMIT')


class Env:
    """No scanner settings from the machine running the tests; a temporary application directory."""

    def isolate(self):
        env = mock.patch.dict(os.environ, {}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        for key in SCRUB:
            os.environ.pop(key, None)
        self.dir = tempfile.mkdtemp()
        override = override_settings(BASE_DIR=self.dir)
        override.enable()
        self.addCleanup(override.disable)

    def path(self, name):
        return os.path.join(self.dir, name)


class LiveExternalsTests(Env, PolicyBase):
    def setUp(self):
        super().setUp()
        self.isolate()
        LocalFallback('none').apply(self)

    def test_it_is_the_set_the_last_resort_rule_holds_the_built_in_scanner_back_for(self):
        FakeScanner(kinds=['nmap', 'path_probe']).start_for(self)  # the built-in scanner: live, never counted
        live_a, live_b = self.external('Remote-1'), self.external('Remote-2')
        stale = self.external('Remote-3')
        type(stale).objects.filter(pk=stale.pk).update(last_seen=timezone.now() - sb.LIVE_WINDOW - timedelta(seconds=5))
        revoked = self.external('Remote-4')
        revoked.token.revoked = True
        revoked.token.save()
        names = sorted(a.name for a in sb.live_externals())
        self.assertEqual(names, ['Remote-1', 'Remote-2'])
        # the same agents the last-resort rule weighs: live scanners minus the built-in one
        rule = sorted(e.agent.name for e in sb._live_scanners(timezone.now()) if e.agent.pk != sb.builtin_pk())
        self.assertEqual(names, rule)
        self.assertEqual((live_a.name, live_b.name), ('Remote-1', 'Remote-2'))

    def test_the_command_prints_one_line_and_changes_nothing(self):
        self.external('Remote-1')
        self.external('Remote-2')
        from io import StringIO
        out = StringIO()
        call_command('external_sentinels', stdout=out)
        self.assertEqual(out.getvalue().strip(), 'EXTERNAL_SENTINELS_LIVE 2')

    def test_a_database_not_yet_migrated_is_counted_with_the_filter_that_names_only_old_columns(self):
        from io import StringIO
        from django.db import ProgrammingError
        self.external('Remote-1')
        self.external('Remote-2')
        stale = self.external('Remote-3')
        type(stale).objects.filter(pk=stale.pk).update(last_seen=timezone.now() - sb.LIVE_WINDOW - timedelta(seconds=5))
        with mock.patch.object(sb, 'live_externals', side_effect=ProgrammingError('column agentapi_agent.managed_settings does not exist')):
            out = StringIO()
            call_command('external_sentinels', stdout=out)
        self.assertEqual(out.getvalue().strip(), 'EXTERNAL_SENTINELS_LIVE 2')  # the same two the last-resort rule counts

    def test_with_no_sentinels_of_your_own_it_says_zero(self):
        from io import StringIO
        out = StringIO()
        call_command('external_sentinels', stdout=out)
        self.assertEqual(out.getvalue().strip(), 'EXTERNAL_SENTINELS_LIVE 0')


class DecisionTests(Env, TestCase):
    def setUp(self):
        self.isolate()

    def decide(self, mem_mb, live=0, **env):
        os.environ.update({k: v for k, v in env.items() if v is not None})
        with mock.patch.object(scanner_plan, 'host_memory_mb', return_value=mem_mb), mock.patch.object(scanner_plan, 'externals_live', return_value=live):
            return scanner_plan.decision()

    def test_the_matrix_of_when_a_question_is_worth_asking(self):
        big, small = 16384, 4608
        cases = [  # memory, live externals, needs a choice, recommended
            (big, 0, False, 'internal'), (big, 1, True, 'both'), (big, 2, True, 'external'),
            (small, 0, True, 'internal'), (small, 1, True, 'both'), (small, 2, True, 'external'),
        ]
        for mem, live, needs, recommended in cases:
            with self.subTest(mem=mem, live=live):
                d = self.decide(mem, live)
                self.assertEqual((d['needs_choice'], d['recommended']), (needs, recommended))
                self.assertEqual([o['value'] for o in d['options'] if o['recommended']], [recommended])

    def test_a_choice_already_made_asks_nothing(self):
        for key, value in (('CVENGINE_BUILTIN_SCANNER', '0'), ('CVENGINE_BUILTIN_SCANNER', '1'), ('CVENGINE_SENTINEL_PLAN', 'internal')):
            with self.subTest(key=key, value=value), mock.patch.dict(os.environ, {key: value}):
                d = self.decide(4608, 2)
                self.assertFalse(d['needs_choice'])
                self.assertTrue(d['chosen'])

    def test_a_choice_on_its_way_to_the_host_counts(self):
        scanner_plan.with_update('both')
        self.assertFalse(self.decide(4608, 2)['needs_choice'])

    def test_a_check_that_cannot_be_made_never_asks(self):
        with mock.patch.object(scanner_plan, 'host_memory_mb', return_value=4608), mock.patch.object(scanner_plan, 'externals_live', side_effect=RuntimeError('db')):
            d = scanner_plan.decision()
        self.assertFalse(d['needs_choice'])
        self.assertFalse(d['externals_known'])

    def test_the_words_say_the_memory_and_the_recommendation_plainly(self):
        d = self.decide(4608, 2)
        self.assertEqual(d['memory_line'], 'This server has 4.5 GB of memory; the built-in scanner reserves up to 1 GB.')
        labels = {o['value']: o['label'] for o in d['options']}
        self.assertEqual(labels['external'], 'Use my own Sentinels only (recommended: you have 2 live; frees up to 1 GB)')
        self.assertEqual(labels['internal'], 'Use the built-in scanner only')
        self.assertEqual(labels['both'], 'Use both')
        big = self.decide(16384, 2)
        self.assertEqual(big['memory_line'], 'This server has 16 GB of memory; the built-in scanner reserves up to 3 GB.')

    def test_an_owners_scanner_limit_is_what_the_dialog_says(self):
        d = self.decide(4608, 0, SCANNER_MEM_LIMIT='2g')
        self.assertEqual(d['scanner_limit_mb'], 2048)
        self.assertIn('up to 2 GB', d['memory_line'])

    def test_the_host_memory_override_is_for_tests_and_rehearsals(self):
        with mock.patch.dict(os.environ, {'CVENGINE_HOST_MEM_MB': '4608'}):
            self.assertEqual(scanner_plan.host_memory_mb(), 4608)
            self.assertTrue(scanner_plan.is_small_host(4608))
        self.assertFalse(scanner_plan.is_small_host(7000000 // 1024 + 1))  # 7000000 kB is the line, the same as scripts/host-fit.sh

    def test_no_text_has_a_long_dash(self):
        for live in (0, 1, 2):
            d = self.decide(4608, live)
            text = json.dumps([d['memory_line'], d['options']], ensure_ascii=False)
            self.assertNotRegex(text, '[\u2013\u2014]')

    def test_the_threshold_is_the_one_the_shell_rule_uses(self):
        shell = (ROOT / 'scripts' / 'host-fit.sh').read_text()
        self.assertIn(f'cv_fit_small_kb={scanner_plan.SMALL_HOST_KB}', shell)


class NoticeTests(Env, TestCase):
    def setUp(self):
        self.isolate()

    def write(self, **data):
        Path(self.path('.update-notice.json')).write_text(json.dumps(data))

    def test_the_notice_says_what_was_kept_and_where_to_switch(self):
        self.write(code='scanner_kept', limit='1g', externals=2, at=1.0)
        self.assertEqual(scanner_plan.notice()['text'], 'The built-in scanner was kept at 1 GB. You have 2 Sentinels of your own: '
                                                        'switch to Sentinels only in Settings > Sentinels to free the memory.')

    def test_it_goes_away_once_somebody_chose(self):
        self.write(code='scanner_kept', limit='1g', externals=2)
        with mock.patch.dict(os.environ, {'CVENGINE_SENTINEL_PLAN': 'external'}):
            self.assertIsNone(scanner_plan.notice())

    def test_a_file_that_is_not_ours_says_nothing_odd(self):
        self.write(code='scanner_kept', limit='<b>x</b>', externals='many')
        text = scanner_plan.notice()['text']
        self.assertNotIn('<b>', text)
        Path(self.path('.update-notice.json')).write_text('not json')
        self.assertIsNone(scanner_plan.notice())
        self.write(code='other')
        self.assertIsNone(scanner_plan.notice())


class EndpointTests(Env, PolicyBase):
    def setUp(self):
        super().setUp()
        self.isolate()
        self.member = User.objects.create_user('plan-member', password='x')

    URL = '/cve/api/settings/scanner_plan'

    def post(self, client, body):
        return client.post(self.URL, json.dumps(body), content_type='application/json')

    def test_it_is_for_app_admins_only(self):
        self.assertEqual(Client().get(self.URL).status_code, 302)
        member = client_for(self.member)
        self.assertEqual(member.get(self.URL).status_code, 403)
        self.assertEqual(self.post(member, {'plan': 'external'}).status_code, 403)
        self.assertFalse(os.path.exists(self.path('.scanner-plan-wanted')))

    def test_a_post_without_the_csrf_token_is_refused(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.root)
        self.assertEqual(self.post(client, {'plan': 'external'}).status_code, 403)
        self.assertFalse(os.path.exists(self.path('.scanner-plan-wanted')))

    def test_only_the_three_values_are_accepted(self):
        admin = client_for(self.root)
        for bad in ('', 'all', 'EXTERNALS', None, 3, ['external'], 'external; rm -rf /'):
            with self.subTest(bad=bad):
                self.assertEqual(self.post(admin, {'plan': bad}).status_code, 400)
        self.assertFalse(os.path.exists(self.path('.scanner-plan-wanted')))

    def test_a_choice_is_handed_to_the_host_and_audited(self):
        from dashboard.models import AuditLog
        admin = client_for(self.root)
        done = self.post(admin, {'plan': 'external'})
        self.assertEqual(done.status_code, 200)
        self.assertEqual(Path(self.path('.scanner-plan-wanted')).read_text(), 'external\n')
        self.assertTrue(done.json()['waiting'])
        self.assertEqual(done.json()['pending_plan'], 'external')
        entry = AuditLog.objects.get(action='scanner_plan.changed')
        self.assertEqual((entry.target, entry.actor_name, entry.detail['previous']), ('external', 'policy-root', 'internal'))

    def test_the_read_carries_the_facts_the_page_draws(self):
        self.external('Remote-1')
        self.external('Remote-2')
        data = client_for(self.root).get(self.URL).json()
        self.assertEqual(data['externals_live'], 2)
        self.assertEqual({o['value'] for o in data['options']}, {'internal', 'both', 'external'})
        self.assertIn('memory_line', data)
        self.assertIsNone(data['applied'])

    def test_the_hosts_answer_is_shown(self):
        Path(self.path('.scanner-plan-applied.json')).write_text(json.dumps({'plan': 'external', 'ok': True, 'note': 'done', 'at': 1.0}))
        data = client_for(self.root).get(self.URL).json()
        self.assertEqual(data['applied'], {'plan': 'external', 'ok': True, 'note': 'done', 'at': 1.0})


class ApproveWithAChoiceTests(Env, TestCase):
    def setUp(self):
        self.isolate()
        self.admin = User.objects.create_superuser('root2', 'r@x.test', 'x')
        open(self.path('.commit'), 'w').write(OLD + '\n')
        row = UpdateSettings.current()
        updater.check(row, get=_github())
        self.client = client_for(self.admin)

    def approve(self, **body):
        return self.client.post('/cve/api/settings/updates/approve', json.dumps(body), content_type='application/json')

    def test_the_choice_travels_with_the_approval_and_is_audited(self):
        from dashboard.models import AuditLog
        done = self.approve(sentinels='external')
        self.assertEqual(done.status_code, 200, done.content)
        self.assertEqual(Path(self.path('.update-sentinels')).read_text(), 'external\n')
        self.assertTrue(os.path.exists(self.path('.update-approved')))
        self.assertEqual(AuditLog.objects.get(action='update.approved').detail['sentinels'], 'external')

    def test_a_bad_choice_starts_nothing(self):
        for bad in ('all', 'EXTERNAL', 7, '../x'):
            with self.subTest(bad=bad):
                self.assertEqual(self.approve(sentinels=bad).status_code, 400)
        self.assertFalse(os.path.exists(self.path('.update-approved')))
        self.assertFalse(os.path.exists(self.path('.update-sentinels')))

    def test_an_approval_without_a_choice_is_still_allowed_and_leaves_no_stale_one(self):
        Path(self.path('.update-sentinels')).write_text('external\n')  # left by an earlier approval that was cancelled
        done = self.approve()
        self.assertEqual(done.status_code, 200)
        self.assertFalse(os.path.exists(self.path('.update-sentinels')))
        self.assertTrue(os.path.exists(self.path('.update-approved')))

    def test_cancelling_removes_the_choice_too(self):
        self.approve(sentinels='both')
        self.client.post('/cve/api/settings/updates/cancel', '{}', content_type='application/json')
        self.assertFalse(os.path.exists(self.path('.update-sentinels')))

    def test_the_updates_read_carries_the_question_and_the_notice(self):
        Path(self.path('.update-notice.json')).write_text(json.dumps({'code': 'scanner_kept', 'limit': '1g', 'externals': 2}))
        data = self.client.get('/cve/api/settings/updates').json()
        self.assertIn('needs_choice', data['scanner_choice'])
        self.assertIn('Settings > Sentinels', data['scanner_notice']['text'])


def _github():
    from tests.test_updater import fake_github
    return fake_github(compare={'status': 'ahead', 'ahead_by': 1, 'commits': []})


class HostHandOverTests(Env, TestCase):
    """What the server writes is what the host reads: scripts/update-state.py reads it without following a link and prints one of three words."""

    def setUp(self):
        self.isolate()
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__('shutil').rmtree(self.root, ignore_errors=True))
        (self.root / 'web').mkdir()
        self.dir = str(self.root / 'web')
        override = override_settings(BASE_DIR=self.dir)
        override.enable()
        self.addCleanup(override.disable)

    def host(self, *args):
        return subprocess.run([sys.executable, str(ROOT / 'scripts' / 'update-state.py'), *args], cwd=self.root, capture_output=True, text=True)

    def test_the_choice_with_an_approval_is_read_once_then_gone(self):
        scanner_plan.with_update('external')
        first = self.host('sentinels-choice')
        self.assertEqual(first.stdout.strip(), 'external', first.stderr)
        self.assertEqual(self.host('sentinels-choice').stdout.strip(), '')
        self.assertFalse((self.root / 'web' / '.update-sentinels').exists())

    def test_a_change_on_its_own_stays_until_the_host_answers(self):
        scanner_plan.request('both')
        self.assertEqual(self.host('plan-wanted').stdout.strip(), 'both')
        self.assertEqual(self.host('plan-wanted').stdout.strip(), 'both')
        done = self.host('plan-done', 'both', 'ok', 'your Sentinels and the built-in scanner')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertFalse((self.root / 'web' / '.scanner-plan-wanted').exists())
        self.assertEqual(scanner_plan.applied()['plan'], 'both')
        self.assertTrue(scanner_plan.applied()['ok'])

    def test_a_link_or_a_stray_word_is_not_a_choice(self):
        (self.root / 'secret').write_text('external\n')
        os.symlink(self.root / 'secret', self.root / 'web' / '.scanner-plan-wanted')
        self.assertEqual(self.host('plan-wanted').stdout.strip(), '')
        os.unlink(self.root / 'web' / '.scanner-plan-wanted')
        (self.root / 'web' / '.scanner-plan-wanted').write_text('everything\n')
        self.assertEqual(self.host('plan-wanted').stdout.strip(), '')

    def test_the_notice_the_host_writes_is_the_one_the_server_shows(self):
        self.assertEqual(self.host('notice', 'scanner_kept', '1g', '2').returncode, 0)
        self.assertIn('kept at 1 GB', scanner_plan.notice()['text'])
        self.assertEqual(self.host('notice', 'clear').returncode, 0)
        self.assertIsNone(scanner_plan.notice())
        self.assertNotEqual(self.host('notice', 'scanner_kept', '1g;x', '2').returncode, 0)
        self.assertNotEqual(self.host('plan-done', 'everything', 'ok').returncode, 0)
