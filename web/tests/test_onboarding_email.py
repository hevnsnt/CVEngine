"""The onboarding email: outgoing mail settings, the message a new person gets, and the link that lets them choose a password."""
import json
import smtplib
import ssl
from datetime import timedelta
from unittest import mock
from urllib.parse import urlsplit

from django.contrib.auth.models import User
from django.core import mail, signing
from django.core.cache import cache
from django.db import connection
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from cveFeed import mailer
from cveFeed.models import SmtpSettings
from dashboard.models import AuditLog, Org, OrgMembership, UserProfile
from tenancy import invite
from tests.test_tenancy import client_for

GOOD = {'enabled': True, 'host': 'smtp.example.org', 'port': 587, 'security': 'starttls', 'username': 'relay',
        'password': 'relay-secret-value', 'from_address': 'cvengine@example.org', 'from_name': 'cvENGINE'}


def call(client, method, path, body=None):
    fn = getattr(client, method.lower())
    url = f'/cve/api/{path}'
    r = fn(url) if method == 'GET' else fn(url, json.dumps(body or {}), content_type='application/json')
    return r.status_code, (r.json() if r.content else None)


def configure(**changes):
    cfg = SmtpSettings.objects.first() or SmtpSettings()
    for key, value in {**GOOD, **changes}.items():
        setattr(cfg, key, value)
    cfg.save()
    return cfg


class Base(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.root = User.objects.create_superuser('root', 'root@example.org', 'pw-Secret-1')
        cls.org = Org.objects.create(name='Alpha', slug='alpha')

    def setUp(self):
        cache.clear()  # the link page counts bad links per address
        self.client = client_for(self.root)
        mail.outbox = []

    def create(self, **extra):
        body = {'username': 'newbie', 'first_name': 'Nia', 'last_name': 'Bie', 'email': 'nia@example.org', 'scope': 'org',
                'scope_id': self.org.id, 'role': 'user', **extra}
        return call(self.client, 'POST', 'admin/users', body)


class SettingsTests(Base):
    def test_saved_settings_never_return_the_password(self):
        status, data = call(self.client, 'PUT', 'settings/email', GOOD)
        self.assertEqual(status, 200)
        self.assertTrue(data['has_password'] and data['ready'])
        self.assertNotIn('password', data)
        self.assertNotIn('relay-secret-value', json.dumps(call(self.client, 'GET', 'settings/email')[1]))
        stored = SmtpSettings.objects.get()
        self.assertEqual(stored.password, 'relay-secret-value')  # readable by the server
        with connection.cursor() as cursor:
            cursor.execute('select password from "cveFeed_smtpsettings"')
            self.assertNotIn('relay-secret-value', cursor.fetchone()[0])  # encrypted in the column

    def test_a_blank_password_keeps_the_stored_one_and_clear_removes_it(self):
        call(self.client, 'PUT', 'settings/email', GOOD)
        call(self.client, 'PUT', 'settings/email', {**GOOD, 'password': ''})
        self.assertEqual(SmtpSettings.objects.get().password, 'relay-secret-value')
        call(self.client, 'PUT', 'settings/email', {'clear_password': True, 'security': 'ssl'})
        self.assertEqual(SmtpSettings.objects.get().password, '')

    def test_only_an_app_admin_may_read_or_change_it(self):
        admin = User.objects.create_user('orgadmin', password='pw-Secret-1')
        OrgMembership.objects.create(user=admin, org=self.org, role='admin')
        c = client_for(admin)
        self.assertEqual(call(c, 'GET', 'settings/email')[0], 403)
        self.assertEqual(call(c, 'PUT', 'settings/email', GOOD)[0], 403)
        self.assertEqual(call(c, 'POST', 'settings/email/test', {'to': 'a@example.org'})[0], 403)
        self.assertEqual(call(Client(), 'GET', 'settings/email')[0], 302)

    def test_bad_values_are_refused(self):
        for change, text in (({'port': 70000}, 'port'), ({'port': 'x'}, 'port'), ({'security': 'tls13'}, 'Security'),
                             ({'host': 'bad_host'}, 'server name'), ({'from_address': 'not-an-address'}, 'From address'),
                             ({'link_base': 'https://x.example.org/path'}, 'no path'), ({'link_base': 'ftp://x.example.org'}, 'link address'),
                             ({'from_name': 'Evil\r\nBcc: a@b.c'}, 'control'), ({'host': '169.254.169.254'}, 'metadata'),
                             ({'security': 'none'}, 'unencrypted'), ({'host': '', 'enabled': True}, 'turn outgoing mail on')):
            status, data = call(self.client, 'PUT', 'settings/email', {**GOOD, **change})
            self.assertEqual(status, 400, change)
            self.assertIn(text, data['error'], change)
        self.assertFalse(SmtpSettings.objects.exists())

    def test_a_relay_with_no_login_may_use_no_encryption(self):
        status, data = call(self.client, 'PUT', 'settings/email', {**GOOD, 'security': 'none', 'username': '', 'clear_password': True, 'port': 25})
        self.assertEqual(status, 200, data)
        self.assertTrue(data['ready'])

    def test_saving_is_audited_without_the_secret(self):
        call(self.client, 'PUT', 'settings/email', GOOD)
        row = AuditLog.objects.get(action='email.update')
        self.assertNotIn('relay-secret-value', json.dumps(row.detail) + row.target)

    def test_link_address_defaults_to_the_domain_name_over_https(self):
        with override_settings(DOMAIN_NAME='scanner.example.org'):
            self.assertEqual(call(self.client, 'PUT', 'settings/email', GOOD)[1]['link_effective'], 'https://scanner.example.org')
            data = call(self.client, 'PUT', 'settings/email', {**GOOD, 'link_base': 'https://cve.example.org:8443/'})[1]
        self.assertEqual(data['link_effective'], 'https://cve.example.org:8443')


class SendTests(Base):
    def setUp(self):
        super().setUp()
        configure()

    def test_a_test_message_goes_to_the_address_given_and_is_recorded(self):
        with mock.patch.object(mailer, '_connection', return_value=mail.get_connection('django.core.mail.backends.locmem.EmailBackend')):
            status, data = call(self.client, 'POST', 'settings/email/test', {'to': 'me@example.org'})
        self.assertEqual((status, data['ok']), (200, True))
        self.assertEqual(mail.outbox[0].to, ['me@example.org'])
        self.assertTrue(SmtpSettings.objects.get().state['ok'])

    def test_a_failed_send_is_explained_without_the_password_or_the_server_text(self):
        boom = smtplib.SMTPAuthenticationError(535, b'5.7.8 Bad credentials for relay-secret-value')
        with mock.patch.object(mailer, '_connection', side_effect=boom):
            data = call(self.client, 'POST', 'settings/email/test', {'to': 'me@example.org'})[1]
        self.assertFalse(data['ok'])
        self.assertIn('user name or password', data['error'])
        self.assertNotIn('relay-secret-value', json.dumps(data))

    def test_failures_read_as_plain_sentences(self):
        cases = ((ssl.SSLCertVerificationError(), 'certificate'), (TimeoutError(), 'in time'), (ConnectionRefusedError(), 'connect'),
                 (smtplib.SMTPRecipientsRefused({}), 'recipient'), (ValueError('x'), 'could not be sent'))
        for exc, word in cases:
            self.assertIn(word, mailer.explain(exc), exc)

    def test_test_needs_an_address(self):
        self.root.email = ''
        self.root.save()
        self.assertEqual(call(self.client, 'POST', 'settings/email/test', {})[0], 400)
        self.assertEqual(call(self.client, 'POST', 'settings/email/test', {'to': 'nope'})[1]['ok'], False)

    def test_certificate_checking_follows_the_setting(self):
        self.assertEqual(mailer._connection(configure(verify_certificate=True)).ssl_context.verify_mode, ssl.CERT_REQUIRED)
        loose = mailer._connection(configure(verify_certificate=False)).ssl_context
        self.assertEqual((loose.verify_mode, loose.check_hostname), (ssl.CERT_NONE, False))

    def test_the_security_choice_picks_starttls_or_ssl(self):
        self.assertEqual((mailer._connection(configure(security='starttls')).use_tls, mailer._connection(configure(security='starttls')).use_ssl), (True, False))
        ssl_backend = mailer._connection(configure(security='ssl', port=465))
        self.assertEqual((ssl_backend.use_tls, ssl_backend.use_ssl, ssl_backend.port), (False, True, 465))

    def test_mail_off_means_nothing_is_sent(self):
        configure(enabled=False)
        ok, error = mailer.send(mailer._message(mailer.row(), 'a@example.org', 's', 't', '<p>t</p>'))
        self.assertFalse(ok)
        self.assertIn('not set up', error)


@override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
class AddPersonTests(Base):
    def setUp(self):
        super().setUp()
        self.patch = mock.patch.object(mailer, '_connection', side_effect=lambda cfg: mail.get_connection('django.core.mail.backends.locmem.EmailBackend'))
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_with_mail_on_the_person_is_emailed_and_no_password_is_shown(self):
        configure()
        status, data = self.create()
        self.assertEqual(status, 201)
        self.assertTrue(data['invited'])
        self.assertNotIn('temporary_password', data)
        user = User.objects.get(username='newbie')
        self.assertFalse(user.has_usable_password())
        self.assertTrue(UserProfile.objects.get(user=user).must_change_password)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ['nia@example.org'])
        self.assertTrue(AuditLog.objects.filter(action='user.invite_sent').exists())

    def test_the_email_carries_the_username_and_a_working_link(self):
        configure()
        with override_settings(DOMAIN_NAME='scanner.example.org'):
            self.create()
        message = mail.outbox[0]
        html = message.alternatives[0][0]
        self.assertIn('newbie', message.body)
        self.assertIn('newbie', html)
        self.assertIn('Org Member in Alpha', html)
        link = next(line for line in message.body.splitlines() if line.startswith('https://scanner.example.org/invite/'))
        self.assertIn(link, html)
        page = Client().get(link.replace('https://scanner.example.org', ''))
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, 'newbie')
        self.assertTrue(message.extra_headers['Message-ID'].endswith('@example.org>'))

    def test_words_the_administrator_typed_cannot_become_markup_in_the_email(self):
        configure()
        self.create(first_name='Tom & "Jerry"')
        html = mail.outbox[0].alternatives[0][0]
        self.assertNotIn('Tom & "Jerry"', html)
        self.assertIn('Tom &amp; &quot;Jerry&quot;', html)

    def test_the_link_uses_the_configured_address_never_the_request_host(self):
        configure()
        with override_settings(DOMAIN_NAME='scanner.example.org', ALLOWED_HOSTS=['*']):
            call_client = self.client
            call_client.post('/cve/api/admin/users', json.dumps({'username': 'hosty', 'email': 'h@example.org', 'scope': 'org',
                                                                  'scope_id': self.org.id, 'role': 'user'}),
                             content_type='application/json', HTTP_HOST='evil.example.net')
        self.assertNotIn('evil.example.net', mail.outbox[0].body)
        self.assertIn('https://scanner.example.org/invite/', mail.outbox[0].body)

    def test_with_mail_off_a_temporary_password_is_shown_as_before(self):
        status, data = self.create()
        self.assertEqual(status, 201)
        self.assertFalse(data['invited'])
        self.assertTrue(data['temporary_password'])
        self.assertEqual(mail.outbox, [])
        self.assertTrue(User.objects.get(username='newbie').check_password(data['temporary_password']))

    def test_no_address_or_a_typed_password_means_no_email(self):
        configure()
        self.assertFalse(self.create(email='')[1]['invited'])
        status, data = self.create(username='typed', email='t@example.org', password='Typed-pass-9X!q')
        self.assertFalse(data['invited'])
        self.assertTrue(User.objects.get(username='typed').check_password('Typed-pass-9X!q'))
        self.assertEqual(mail.outbox, [])

    def test_a_malformed_address_is_refused(self):
        configure()
        self.assertEqual(self.create(email='no-at-sign')[0], 400)
        self.assertFalse(User.objects.filter(username='newbie').exists())

    def test_when_the_send_fails_a_temporary_password_is_the_way_in(self):
        configure()
        with mock.patch.object(mailer, '_connection', side_effect=TimeoutError()):
            status, data = self.create()
        self.assertEqual(status, 201)
        self.assertFalse(data['invited'])
        self.assertIn('in time', data['invite_error'])
        self.assertTrue(User.objects.get(username='newbie').check_password(data['temporary_password']))
        self.assertTrue(AuditLog.objects.filter(action='user.invite_failed').exists())

    def test_an_org_admin_can_invite_into_their_own_organization(self):
        configure()
        admin = User.objects.create_user('orgadmin', password='pw-Secret-1')
        OrgMembership.objects.create(user=admin, org=self.org, role='admin')
        self.client = client_for(admin)
        self.assertTrue(self.create()[1]['invited'])

    def test_resend_replaces_the_earlier_link(self):
        configure()
        self.create()
        first = next(line for line in mail.outbox[0].body.splitlines() if '/invite/' in line)
        user = User.objects.get(username='newbie')
        status, data = call(self.client, 'POST', f'admin/users/{user.id}/resend-invite')
        self.assertEqual((status, data['invited']), (200, True))
        second = next(line for line in mail.outbox[1].body.splitlines() if '/invite/' in line)
        self.assertNotEqual(first, second)
        c = Client()
        self.assertEqual(c.get(urlsplit(first).path).status_code, 410)
        self.assertEqual(c.get(urlsplit(second).path).status_code, 200)

    def test_resend_is_for_people_who_have_not_chosen_a_password(self):
        configure()
        self.create()
        user = User.objects.get(username='newbie')
        UserProfile.objects.filter(user=user).update(must_change_password=False)
        self.assertEqual(call(self.client, 'POST', f'admin/users/{user.id}/resend-invite')[0], 409)
        configure(enabled=False)
        UserProfile.objects.filter(user=user).update(must_change_password=True)
        self.assertEqual(call(self.client, 'POST', f'admin/users/{user.id}/resend-invite')[0], 409)

    def test_reset_password_emails_a_link_that_lands_on_a_reset_page(self):
        configure()
        self.create()
        user = User.objects.get(username='newbie')
        user.last_login = timezone.now()  # has signed in before
        user.set_password('Chosen-by-user-55')
        user.save()
        UserProfile.objects.filter(user=user).update(must_change_password=False)
        mail.outbox = []
        status, data = call(self.client, 'POST', f'admin/users/{user.id}/reset-password')
        self.assertEqual((status, data['invited'], data['email']), (200, True, 'nia@example.org'))
        self.assertNotIn('temporary_password', data)
        user.refresh_from_db()
        self.assertFalse(user.has_usable_password())  # the old password is dead at once
        self.assertTrue(UserProfile.objects.get(user=user).must_change_password)
        message = mail.outbox[0]
        self.assertIn('Reset your cvENGINE password', message.subject)
        self.assertIn('reset your password', message.alternatives[0][0])
        self.assertNotIn('added you', message.alternatives[0][0])
        link = next(line for line in message.body.splitlines() if '/invite/' in line)
        page = Client().get(urlsplit(link).path)
        self.assertContains(page, 'Choose a new password')
        done = Client().post(urlsplit(link).path, {'password': 'Fresh-after-reset-31', 'confirm': 'Fresh-after-reset-31'})
        self.assertEqual(done.status_code, 302)
        user.refresh_from_db()
        self.assertTrue(user.check_password('Fresh-after-reset-31'))

    def test_reset_password_falls_back_to_a_temporary_password(self):
        user = self.create()[1]
        target = User.objects.get(username='newbie')
        status, data = call(self.client, 'POST', f'admin/users/{user["id"]}/reset-password')  # mail is off
        self.assertEqual(status, 200)
        self.assertFalse(data['invited'])
        target.refresh_from_db()
        self.assertTrue(target.check_password(data['temporary_password']))
        configure()
        User.objects.filter(pk=target.pk).update(email='')  # mail is on but there is no address
        self.assertFalse(call(self.client, 'POST', f'admin/users/{target.pk}/reset-password')[1]['invited'])
        self.assertEqual(mail.outbox, [])

    def test_a_failed_reset_send_leaves_a_temporary_password(self):
        configure()
        self.create()
        user = User.objects.get(username='newbie')
        with mock.patch.object(mailer, '_connection', side_effect=TimeoutError()):
            data = call(self.client, 'POST', f'admin/users/{user.id}/reset-password')[1]
        self.assertFalse(data['invited'])
        user.refresh_from_db()
        self.assertTrue(user.check_password(data['temporary_password']))

    def test_the_people_list_says_who_is_invited_and_whether_mail_is_ready(self):
        configure()
        self.create()
        data = call(self.client, 'GET', 'admin/users')[1]
        self.assertTrue(data['email_ready'])
        self.assertTrue(next(u for u in data['results'] if u['username'] == 'newbie')['invite_pending'])
        configure(enabled=False)
        self.assertFalse(call(self.client, 'GET', 'admin/users')[1]['email_ready'])


@override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
class LinkTests(Base):
    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user('invitee', password=None, email='i@example.org', first_name='Ivy')
        UserProfile.objects.create(user=self.user, must_change_password=True)
        self.url = f'/invite/{invite.make_token(self.user)}/'
        self.anon = Client()

    def test_opening_the_link_changes_nothing(self):
        for _ in range(2):
            self.assertEqual(self.anon.get(self.url).status_code, 200)
        self.user.refresh_from_db()
        self.assertFalse(self.user.has_usable_password())
        self.assertTrue(UserProfile.objects.get(user=self.user).must_change_password)

    def test_the_page_is_private_and_does_not_leak_the_token(self):
        response = self.anon.get(self.url)
        self.assertEqual(response['Referrer-Policy'], 'no-referrer')
        self.assertIn('no-store', response['Cache-Control'])

    def test_choosing_a_password_signs_them_in(self):
        response = self.anon.post(self.url, {'password': 'Brand-new-pass-77', 'confirm': 'Brand-new-pass-77'})
        self.assertEqual((response.status_code, response['Location']), (302, '/cve/'))
        self.assertEqual(int(self.anon.session['_auth_user_id']), self.user.pk)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('Brand-new-pass-77'))
        self.assertFalse(UserProfile.objects.get(user=self.user).must_change_password)
        self.assertTrue(AuditLog.objects.filter(action='account.invite_accepted', actor=self.user).exists())
        self.assertTrue(Client().login(username='invitee', password='Brand-new-pass-77'))

    def test_two_step_sign_in_is_never_skipped_by_a_reset_link(self):
        UserProfile.objects.filter(user=self.user).update(mfa_enabled=True, mfa_secret='JBSWY3DPEHPK3PXP')
        response = self.anon.post(self.url, {'password': 'Brand-new-pass-77', 'confirm': 'Brand-new-pass-77'})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'two-step code')
        self.assertNotIn('_auth_user_id', self.anon.session)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('Brand-new-pass-77'))

    def test_the_page_words_a_first_welcome_and_a_reset_differently(self):
        self.assertContains(self.anon.get(self.url), 'Welcome, Ivy')
        self.user.last_login = timezone.now()
        self.user.save(update_fields=['last_login'])
        reset = self.anon.get(f'/invite/{invite.make_token(self.user)}/')
        self.assertContains(reset, 'Choose a new password')
        self.assertNotContains(reset, 'Welcome')

    def test_the_link_works_once(self):
        self.anon.post(self.url, {'password': 'Brand-new-pass-77', 'confirm': 'Brand-new-pass-77'})
        again = self.anon.post(self.url, {'password': 'Other-pass-88xyz', 'confirm': 'Other-pass-88xyz'})
        self.assertEqual(again.status_code, 410)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('Brand-new-pass-77'))

    def test_a_weak_or_mismatched_password_keeps_the_link_alive(self):
        self.assertEqual(self.anon.post(self.url, {'password': 'short', 'confirm': 'short'}).status_code, 400)
        mismatch = self.anon.post(self.url, {'password': 'Brand-new-pass-77', 'confirm': 'Brand-new-pass-78'})
        self.assertContains(mismatch, 'not the same', status_code=400)
        self.assertContains(self.anon.post(self.url, {'password': 'password', 'confirm': 'password'}), 'password', status_code=400)
        self.assertEqual(self.anon.get(self.url).status_code, 200)

    def test_it_expires(self):
        with mock.patch('django.core.signing.time.time', return_value=timezone.now().timestamp() + 8 * 86400):
            self.assertEqual(self.anon.get(self.url).status_code, 410)
        with mock.patch('django.core.signing.time.time', return_value=timezone.now().timestamp() + 6 * 86400):
            self.assertEqual(self.anon.get(self.url).status_code, 200)

    def test_the_lifetime_can_be_set_and_is_bounded(self):
        for value, days in (('2', 2), ('0', 1), ('999', 30), ('soon', 7)):
            with mock.patch.dict('os.environ', {'CVENGINE_INVITE_DAYS': value}):
                self.assertEqual(invite.valid_days(), days)

    def test_a_reset_by_an_administrator_ends_the_link(self):
        self.user.set_password('Typed-by-admin-12')
        self.user.save()
        self.assertEqual(self.anon.get(self.url).status_code, 410)

    def test_a_disabled_account_cannot_use_it(self):
        self.user.is_active = False
        self.user.save()
        self.assertEqual(self.anon.get(self.url).status_code, 410)

    def test_forged_or_foreign_tokens_are_refused(self):
        other = User.objects.create_user('other', password=None)
        for token in ('garbage', self.url.split('/')[2][:-3] + 'abc', signing.dumps({'u': self.user.pk, 'f': 'x'}, salt=invite.SALT),
                      signing.dumps({'u': self.user.pk, 'f': invite._fingerprint(self.user)}, salt='another.salt'),
                      signing.dumps({'u': str(self.user.pk), 'f': invite._fingerprint(self.user)}, salt=invite.SALT),
                      signing.dumps({'u': other.pk, 'f': invite._fingerprint(self.user)}, salt=invite.SALT)):
            self.assertEqual(self.anon.get(f'/invite/{token}/').status_code, 410, token)

    def test_guessing_is_slowed_down(self):
        from tenancy.views import INVITE_FAILURES
        for _ in range(INVITE_FAILURES):
            self.anon.get('/invite/nope/')
        self.assertEqual(self.anon.get('/invite/nope/').status_code, 429)

    def test_a_signed_in_person_can_open_it_too(self):
        self.assertEqual(client_for(self.root).get(self.url).status_code, 200)

