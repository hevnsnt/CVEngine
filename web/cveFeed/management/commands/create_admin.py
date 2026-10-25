"""Create the admin account with a password the person can actually find, or give a lost one a new password.

    python3 manage.py create_admin            # make admin
    python3 manage.py create_admin --reset    # make admin-password

The installer used to leave a new owner to invent a password in a prompt, with nothing saying where it went. Now the account is
made for them: the password is the one in DJANGO_SUPERUSER_PASSWORD when someone chose to set it, otherwise a random one that is
printed here, once, and never stored anywhere readable. A generated password has to be changed at first sign-in (My account),
the same way an administrator-issued temporary one does. Safe to run again: an existing account is left alone unless --reset.
"""
import os
import secrets
import string

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError

from dashboard.models import UserProfile

PLACEHOLDERS = ('', 'change-me')
ALPHABET = string.ascii_letters + string.digits  # no `$`, `#` or quotes: it survives .env, Make, and a shell


def generate_password(length=20):
    """A random password of letters and digits with at least one of each of lower, upper and digit."""
    while True:
        password = ''.join(secrets.choice(ALPHABET) for _ in range(length))
        if any(c.islower() for c in password) and any(c.isupper() for c in password) and any(c.isdigit() for c in password):
            return password


class Command(BaseCommand):
    help = "Create the admin account (printing a generated password once), or --reset a lost password."

    def add_arguments(self, parser):
        parser.add_argument('--username', default=os.environ.get('DJANGO_SUPERUSER_USERNAME') or 'admin')
        parser.add_argument('--email', default=os.environ.get('DJANGO_SUPERUSER_EMAIL') or '')
        parser.add_argument('--reset', action='store_true',
                            help='Give an existing account a new generated password (and require a change at next sign-in).')

    def handle(self, *args, **opts):
        User = get_user_model()
        username = opts['username'].strip()
        if not username:
            raise CommandError('the username must not be empty')
        user = User.objects.filter(username=username).first()
        chosen = os.environ.get('DJANGO_SUPERUSER_PASSWORD', '')
        if user and not opts['reset']:
            self.stdout.write(f'The account "{username}" already exists; nothing was changed. '
                              f'Lost its password? Run: make admin-password')
            return
        if opts['reset'] and not user:
            raise CommandError(f'there is no account named "{username}" to reset')
        use_chosen = not opts['reset'] and chosen.strip() not in PLACEHOLDERS
        password = chosen if use_chosen else generate_password()
        if use_chosen:
            try:
                validate_password(password)
            except ValidationError as exc:
                raise CommandError('DJANGO_SUPERUSER_PASSWORD is not allowed: ' + ' '.join(exc.messages))
        if user:
            user.set_password(password)
            user.save(update_fields=['password'])
        else:
            user = User.objects.create_superuser(username=username, email=opts['email'] or f'{username}@localhost', password=password)
        profile, _ = UserProfile.objects.get_or_create(user=user)
        profile.must_change_password = not use_chosen
        profile.save(update_fields=['must_change_password'])
        self._announce(username, None if use_chosen else password, reset=bool(opts['reset']))

    def _announce(self, username, generated, reset):
        domain = os.environ.get('DOMAIN_NAME') or 'your server'
        line = '=' * 66
        out = [line, f'  CVEngine admin account{" (password reset)" if reset else ""}', '',
               f'    Address   : https://{domain}/', f'    Username  : {username}']
        if generated:
            out += [f'    Password  : {generated}', '',
                    '  Copy the password now: it is shown only here.',
                    '  You will be asked to choose your own at your first sign-in.',
                    '  Lost it later? Run: make admin-password']
        else:
            out += ['    Password  : the one you set in DJANGO_SUPERUSER_PASSWORD', '']
        out.append(line)
        self.stdout.write('\n'.join(out))
