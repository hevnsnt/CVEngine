"""The update handles what 1.5.0 left to a person (docs/UPGRADE.md, "The abuse guard no longer disables accounts").

* Accounts the old abuse guard disabled are enabled again by the update (cveFeed.guard_reenable, the update step reenable_guard_disabled_users):
  only the accounts with the guard's own audit row, never one an administrator disabled or one without that row, never one whose is_active
  something else changed since; tokens stay revoked and are listed; one audit entry per account; idempotent.
* The client address check decides by itself: nothing in front of the bundled proxy needs nothing and says so; a host proxy whose address is not
  believed yet raises an App Admin notice (status strip, Settings, Updates, the system status) with the lines to install and a Copy button, and
  the notice clears itself when the check passes. Nothing here believes a header.
"""
import io
import os
import re
from datetime import timedelta
from pathlib import Path
from unittest import mock

from django.contrib.admin.models import CHANGE, LogEntry
from django.contrib.auth.models import User
from django.contrib.contenttypes.models import ContentType
from django.core.cache import cache
from django.core.management import call_command
from django.test import Client, TestCase
from django.utils import timezone

from cveFeed import client_address, guard_reenable, reviewer, upgrade_backfills
from cveFeed.models import AdminAlert
from dashboard.models import AbuseBan, ApiToken, AuditLog
from reNgine import client_probe

ROOT = Path(__file__).resolve().parents[2]
PROXY = '172.16.238.10'  # the bundled proxy's fixed address, the default trusted proxy
SECRET = 'Zq8rT2vW9xY3bN5mK7pL4sD6fG1hJ0aEcUuu'


def old_guard_disabled(user, tokens=2, when=None):
    """What the input guard of releases before 1.5.0 did at its threshold (reNgine/input_guard.py before review r3 S1): disable the account,
    revoke every token it held, store a user ban row and write ``abuse.account_disabled`` with the account as actor."""
    when = when or timezone.now() - timedelta(days=3)
    made = []
    for n in range(tokens):
        t = ApiToken.objects.create(user=user, name=f'{user.username}-key{n}', key_hash=f'{user.username}{n}'.ljust(64, 'x')[:64], prefix='cve_',
                                    suffix='Q' + str(n))
        ApiToken.objects.filter(pk=t.pk).update(created_at=when - timedelta(days=10))
        made.append(t)
    user.is_active = False
    user.save(update_fields=['is_active'])
    ApiToken.objects.filter(user=user, revoked=False).update(revoked=True)
    AbuseBan.objects.create(user=user, username=user.username, ip='', reason='path traversal in "q" (3 strike points in 15 min)')
    row = AuditLog.objects.create(actor=user, actor_name=user.username, action='abuse.account_disabled', target=user.username,
                                  detail={'reason': 'path traversal', 'ip': '8.8.4.4'})
    AuditLog.objects.filter(pk=row.pk).update(created_at=when)
    row.refresh_from_db()
    return row, made


def run(apply=True):
    out = io.StringIO()
    call_command('reenable_guard_disabled_users', *(['--apply'] if apply else []), stdout=out)
    return out.getvalue().strip().splitlines()


class GuardReenableTests(TestCase):
    def setUp(self):
        self.victim = User.objects.create_user('clicked-a-link', password='x')
        self.guard_row, self.tokens = old_guard_disabled(self.victim)
        self.by_admin = User.objects.create_user('left-the-company', password='x', is_active=False)  # an administrator disabled it: no guard row

    def test_only_the_guard_disabled_account_comes_back(self):
        lines = run()
        self.victim.refresh_from_db()
        self.by_admin.refresh_from_db()
        self.assertTrue(self.victim.is_active)
        self.assertFalse(self.by_admin.is_active)
        self.assertRegex(lines[-1], r'^Accounts the old abuse guard disabled: 1 enabled again, 0 left disabled .* 0 enabled by an earlier run; '
                                    r'2 revoked API tokens not restored')

    def test_nothing_else_is_restored_and_the_tokens_are_listed(self):
        lines = run()
        self.assertFalse(ApiToken.objects.filter(user=self.victim, revoked=False).exists())  # tokens stay revoked
        self.assertTrue(AbuseBan.objects.filter(user=self.victim, lifted=False).exists())  # the old ban row is left as it was
        self.assertIn('clicked-a-link', lines[0])
        for t in self.tokens:
            self.assertIn(f'{t.name} ({t.hint})', lines[0])
        self.assertNotIn(self.tokens[0].key_hash, '\n'.join(lines))

    def test_one_audit_entry_per_account_that_says_tokens_were_not_restored(self):
        other = User.objects.create_user('second-victim', password='x')
        old_guard_disabled(other, tokens=0)
        run()
        rows = list(AuditLog.objects.filter(action='abuse.account_reenabled').order_by('target'))
        self.assertEqual([r.target for r in rows], ['clicked-a-link', 'second-victim'])
        entry = rows[0]
        self.assertIsNone(entry.actor)
        self.assertEqual(entry.actor_name, guard_reenable.ACTOR_NAME)
        self.assertEqual(entry.detail['guard_audit_id'], self.guard_row.pk)
        self.assertEqual(entry.detail['tokens_restored'], 0)
        self.assertEqual(entry.detail['restored'], ['is_active'])
        self.assertEqual([t['id'] for t in entry.detail['tokens_revoked_before_guard']], [t.pk for t in self.tokens])
        self.assertIn('not restored', entry.detail['note'])
        self.assertEqual(rows[1].detail['tokens_revoked_before_guard'], [])

    def test_a_token_made_after_the_guard_is_not_listed_as_its_doing(self):
        later = ApiToken.objects.create(user=self.victim, name='made-later', key_hash='l' * 64, prefix='cve_', revoked=True)
        run()
        listed = AuditLog.objects.get(action='abuse.account_reenabled').detail['tokens_revoked_before_guard']
        self.assertNotIn(later.pk, [t['id'] for t in listed])

    def test_it_is_idempotent(self):
        run()
        again = run()
        self.assertEqual(AuditLog.objects.filter(action='abuse.account_reenabled').count(), 1)
        self.assertRegex(again[-1], r': 0 enabled again, 0 left disabled .* 1 enabled by an earlier run; 0 revoked API tokens')

    def test_an_account_an_administrator_disabled_again_afterwards_stays_disabled(self):
        run()
        User.objects.filter(pk=self.victim.pk).update(is_active=False)  # disabled again later by some other path
        lines = run()
        self.victim.refresh_from_db()
        self.assertFalse(self.victim.is_active)
        self.assertIn('left disabled: clicked-a-link: this update step enabled it once already', '\n'.join(lines))
        self.assertEqual(AuditLog.objects.filter(action='abuse.account_reenabled').count(), 1)

    def test_an_administration_page_change_after_the_guard_keeps_it_disabled(self):
        AuditLog.objects.create(actor=None, actor_name='boss', action='user.update', target='clicked-a-link', detail={'fields': ['is_active']})
        run()
        self.victim.refresh_from_db()
        self.assertFalse(self.victim.is_active)

    def test_an_unrelated_administration_change_does_not_count(self):
        AuditLog.objects.create(actor=None, actor_name='boss', action='user.update', target='clicked-a-link', detail={'fields': ['first_name']})
        run()
        self.victim.refresh_from_db()
        self.assertTrue(self.victim.is_active)

    def test_a_django_admin_change_after_the_guard_keeps_it_disabled(self):
        LogEntry.objects.create(user=self.by_admin, content_type=ContentType.objects.get_for_model(User), object_id=str(self.victim.pk),
                                object_repr='clicked-a-link', action_flag=CHANGE, change_message='[]')
        run()
        self.victim.refresh_from_db()
        self.assertFalse(self.victim.is_active)

    def test_an_account_that_signed_in_after_the_guard_was_disabled_by_something_else(self):
        User.objects.filter(pk=self.victim.pk).update(last_login=self.guard_row.created_at + timedelta(hours=1))
        lines = run()
        self.victim.refresh_from_db()
        self.assertFalse(self.victim.is_active)
        self.assertIn('it signed in after the guard acted', '\n'.join(lines))

    def test_an_account_without_the_guard_row_is_never_touched_even_with_a_ban_row(self):
        AbuseBan.objects.create(user=self.by_admin, username=self.by_admin.username, ip='', reason='typed by hand')
        AuditLog.objects.create(actor=self.by_admin, actor_name='left-the-company', action='abuse.user_flagged', target='left-the-company')
        run()
        self.by_admin.refresh_from_db()
        self.assertFalse(self.by_admin.is_active)

    def test_a_dry_run_changes_nothing(self):
        lines = run(apply=False)
        self.victim.refresh_from_db()
        self.assertFalse(self.victim.is_active)
        self.assertFalse(AuditLog.objects.filter(action='abuse.account_reenabled').exists())
        self.assertIn('would enable again: clicked-a-link', lines[0])

    def test_it_is_an_update_step_and_its_count_line_reaches_the_activity_feed(self):
        self.assertIn('reenable_guard_disabled_users', upgrade_backfills.BACKFILLS)
        self.assertEqual(upgrade_backfills.run_one('reenable_guard_disabled_users'), 'done')
        self.victim.refresh_from_db()
        self.assertTrue(self.victim.is_active)
        from cveFeed.models import AgentActivity
        self.assertTrue(AgentActivity.objects.filter(message__contains='Update step reenable_guard_disabled_users applied: Accounts the old abuse '
                                                                       'guard disabled: 1 enabled again').exists())

    def test_the_update_scripts_run_it_and_log_its_lines(self):
        deploy = (ROOT / 'scripts' / 'update-deploy.sh').read_text()
        update = (ROOT / 'scripts' / 'update.sh').read_text()
        for text in (deploy, update):
            self.assertIn('exec -T web python3 manage.py reenable_guard_disabled_users --apply', text)
        self.assertIn('log "guard accounts: $line"', deploy)


def probe(label=None, remote=PROXY, xff=None):
    """One probe through the test client as the bundled proxy passes it on: the token, after the request."""
    token = client_probe.start()
    meta = {'REMOTE_ADDR': remote}
    if label is not None:
        meta['HTTP_X_CVENGINE_PROBE_FORWARDED'] = label
    if xff:
        meta['HTTP_X_FORWARDED_FOR'] = xff
    with mock.patch.dict(os.environ, {'CVENGINE_TRUSTED_PROXIES': PROXY}):  # the shipped default: the bundled proxy alone
        Client().get(f'/client-address-probe/{token}/', **meta)
    return token


def verdict(token, seen='', published=''):
    out = io.StringIO()
    call_command('client_address_probe', 'verdict', token, '--seen', seen, '--published', published, stdout=out)
    return out.getvalue().strip().removeprefix('probe: ')


class ClassifyTests(TestCase):
    def test_where_port_443_is_published(self):
        self.assertTrue(client_address.published_direct('0.0.0.0:443'))
        self.assertTrue(client_address.published_direct('[::]:443 0.0.0.0:443'))
        self.assertFalse(client_address.published_direct('127.0.0.1:18443'))
        self.assertFalse(client_address.published_direct('127.0.0.1:443'))  # loopback: a host proxy in front of it
        self.assertFalse(client_address.published_direct('0.0.0.0:8443'))
        self.assertIsNone(client_address.published_direct(''))
        self.assertIsNone(client_address.published_direct('garbage'))

    def test_every_verdict(self):
        c = client_address.classify
        self.assertEqual(c('', 'none', '', '0.0.0.0:443')[0], 'unknown')
        self.assertEqual(c('8.8.4.4', '', '', '0.0.0.0:443')[0], 'unknown')  # did not pass a labelling proxy
        self.assertEqual(c('8.8.4.4', 'tunnel', '', '')[0], 'unknown')
        self.assertEqual(c('8.8.4.4', 'none', '', '0.0.0.0:443')[0], 'direct')
        self.assertEqual(c('172.16.238.1', 'none', '', '0.0.0.0:443')[0], 'direct')
        self.assertEqual(c('172.16.238.1', 'none', '', '127.0.0.1:18443')[0], 'front_silent')
        self.assertEqual(c('172.16.238.1', 'none', '', '')[0], 'unknown')
        self.assertEqual(c('172.16.238.1', 'ignored', '', '127.0.0.1:18443')[0], 'front')
        self.assertEqual(c('172.16.238.1', 'ignored', '9.9.9.9', '')[0], 'front')
        self.assertEqual(c('172.16.238.1', 'ignored', '9.9.9.9', '0.0.0.0:443')[0], 'cdn_direct')
        self.assertEqual(c('172.16.238.1', 'wrong-secret', '', '127.0.0.1:18443')[0], 'front_old_secret')
        self.assertEqual(c('8.8.4.4', 'believed', '8.8.4.4', '127.0.0.1:18443')[0], 'ok')
        self.assertEqual(c('8.8.4.4', 'believed', '', '127.0.0.1:18443')[0], 'ok')
        self.assertEqual(c('104.16.1.1', 'believed', '8.8.4.4', '127.0.0.1:18443')[0], 'cdn')

    def test_the_direct_case_says_nothing_is_needed(self):
        kind, line = client_address.classify('8.8.4.4', 'none', '', '0.0.0.0:443')
        self.assertIn('Nothing to install', line)
        self.assertEqual(client_address.KINDS[kind][0], 'resolve')


class NoticeTests(TestCase):
    def setUp(self):
        cache.clear()
        self.admin = User.objects.create_superuser('root', password='x')

    def test_the_probe_keeps_the_proxys_label_and_only_a_known_one(self):
        self.assertEqual(client_probe.read_forwarded(probe('ignored')), 'ignored')
        self.assertEqual(client_probe.read_forwarded(probe('believed; drop table')), '')
        self.assertEqual(client_probe.read_forwarded(probe()), '')

    def test_the_label_never_changes_the_recorded_address(self):
        token = probe('believed', remote='172.16.238.1', xff='8.8.4.4')  # a peer that is not the proxy claims a believed chain
        self.assertEqual(client_probe.read(token), '172.16.238.1')

    def test_no_host_proxy_in_front_needs_nothing_and_raises_nothing(self):
        line = verdict(probe('none'), published='0.0.0.0:443')
        self.assertIn('nothing in front of the bundled proxy', line)
        self.assertFalse(AdminAlert.objects.filter(code='client_address').exists())

    def test_a_front_proxy_whose_header_is_ignored_raises_the_notice_everywhere(self):
        line = verdict(probe('ignored', xff='8.8.4.4'), published='127.0.0.1:18443')
        self.assertIn('does not believe it yet', line)
        alert = AdminAlert.objects.get(code='client_address', resolved_at__isnull=True)
        self.assertEqual(alert.facts['kind'], 'front')
        self.assertIn('sudo nginx -t', alert.detail)
        shown = {a['code']: a for a in reviewer.open_alerts()}
        self.assertTrue(shown['client_address']['snippet'])  # the status strip shows the lines and the Copy button
        c = Client()
        c.force_login(self.admin)
        state = c.get('/cve/api/settings/updates').json()
        self.assertEqual(state['client_address_notice']['kind'], 'front')
        from agentapi import system_status
        notes = []
        self.assertEqual(system_status._client_address(notes)['notice']['kind'], 'front')
        self.assertIn('client address:', notes[0])

    def test_the_notice_clears_itself_when_the_check_passes(self):
        verdict(probe('ignored'), published='127.0.0.1:18443')
        self.assertEqual(verdict(probe('believed', xff='8.8.4.4'), seen='8.8.4.4', published='127.0.0.1:18443'), 'verdict: ok, nothing to do.')
        self.assertFalse(AdminAlert.objects.filter(code='client_address', resolved_at__isnull=True).exists())
        self.assertIsNone(client_address.notice())

    def test_a_check_with_no_verdict_leaves_the_notice_as_it_is(self):
        verdict(probe('ignored'), published='127.0.0.1:18443')
        verdict(client_probe.start(), published='127.0.0.1:18443')  # the probe never arrived
        self.assertTrue(AdminAlert.objects.filter(code='client_address', resolved_at__isnull=True).exists())

    def test_recheck_from_the_server_resolves_but_never_raises(self):
        def through_proxy(label):
            def get(url):
                if '/client-address-probe/' in url:
                    token = url.rstrip('/').rsplit('/', 1)[-1]
                    probe_token = token
                    meta = {'REMOTE_ADDR': PROXY, 'HTTP_X_FORWARDED_FOR': '8.8.4.4', 'HTTP_X_CVENGINE_PROBE_FORWARDED': label}
                    with mock.patch.dict(os.environ, {'CVENGINE_TRUSTED_PROXIES': PROXY}):
                        Client().get(f'/client-address-probe/{probe_token}/', **meta)
                    return ''
                return 'ip=8.8.4.4\n'
            return get
        with mock.patch.dict(os.environ, {'DOMAIN_NAME': 'cve.example.com'}):
            self.assertEqual(client_address.recheck(get=through_proxy('ignored'))['result'], 'unchanged')
            self.assertFalse(AdminAlert.objects.filter(code='client_address').exists())  # never opened from here
            verdict(probe('ignored'), published='127.0.0.1:18443')
            self.assertEqual(client_address.recheck(get=through_proxy('believed')), {'kind': 'ok', 'result': 'resolved'})
        self.assertIsNone(client_address.notice())

    def test_the_snippet_is_for_a_person_and_holds_the_secret(self):
        c = Client()
        c.force_login(self.admin)
        with mock.patch.dict(os.environ, {'CVENGINE_UPSTREAM_SECRET': SECRET}):
            r = c.get('/cve/api/settings/client_address/snippet')
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r['Cache-Control'], 'no-store')
            self.assertIn(f'proxy_set_header X-CVEngine-Upstream "{SECRET}";', r.json()['snippet'])
            self.assertTrue(AuditLog.objects.filter(action='client_address.snippet_shown', actor=self.admin).exists())
            self.assertNotIn(SECRET, str(list(AuditLog.objects.values_list('detail', flat=True))))
            from cveFeed import settings_api
            request = mock.Mock(user=self.admin, via_agent=True)
            with self.assertRaises(settings_api.SettingsError):
                settings_api.client_address_snippet(request)
            user = User.objects.create_user('member', password='x')
            c2 = Client()
            c2.force_login(user)
            self.assertEqual(c2.get('/cve/api/settings/client_address/snippet').status_code, 403)
        with mock.patch.dict(os.environ, {'CVENGINE_UPSTREAM_SECRET': 'short'}):
            self.assertEqual(c.get('/cve/api/settings/client_address/snippet').status_code, 409)

    def test_the_snippet_lines_are_the_shipped_files_lines(self):
        shipped = (ROOT / 'config' / 'nginx' / 'host-proxy-client-address.conf').read_text()
        code = [line.strip() for line in shipped.splitlines() if line.strip() and not line.lstrip().startswith('#')]
        with mock.patch.dict(os.environ, {'CVENGINE_UPSTREAM_SECRET': SECRET}):
            ours = [line for line in client_address.snippet().splitlines() if not line.startswith('#')]
        self.assertEqual(ours, [line.replace('@CVENGINE_UPSTREAM_SECRET@', SECRET) for line in code])

    def test_the_proxy_labels_the_probe_route_only(self):
        conf = (ROOT / 'config' / 'nginx' / 'rengine.conf').read_text()
        self.assertEqual(len(re.findall(r'proxy_set_header\s+X-CVEngine-Probe-Forwarded', conf)), 1)
        probe_block = conf[conf.index('location ^~ /client-address-probe/'):]
        probe_block = probe_block[:probe_block.index('\n    }')]
        self.assertIn('X-CVEngine-Probe-Forwarded $cvengine_probe_forwarded', probe_block)
        # the chain the application gets is decided exactly as before: the label is a separate map that feeds nothing else
        self.assertEqual(len(re.findall(r'X-Forwarded-For \$cvengine_forwarded_for;', conf)), 4)

    def test_the_check_script_asks_the_server_for_the_verdict(self):
        script = (ROOT / 'scripts' / 'client-address.sh').read_text()
        self.assertIn('port proxy 443', script)
        self.assertIn('client_address_probe verdict "$token" --seen "$seen" --published "$published"', script)
