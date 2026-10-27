import re
import sys

from django.core.management.base import BaseCommand, CommandError

from cveFeed.models import OpenvasSettings

CREATED = re.compile(r"password '([^']+)'")


def password_from(text):
    """The password in what ``gvmd --create-user`` printed (``User created with password '...'``), else the whole text, trimmed."""
    text = text.strip()
    found = CREATED.search(text)
    return found.group(1) if found else text


class Command(BaseCommand):
    help = ('Save the GMP login of the OpenVAS add-on (encrypted). The password is read from standard input, never from an argument, because a '
            'command line is visible to every process: `make openvas-user` pipes the output of `gvmd --create-user` into this. Nothing is '
            'printed but the user name.')

    def add_arguments(self, parser):
        parser.add_argument('--username', required=True, help='the GVM user (the one `gvmd --create-user` made)')

    def handle(self, *args, **options):
        password = password_from(sys.stdin.read())
        if not password or len(password) > 200 or '\n' in password:
            raise CommandError('no password on standard input')
        row = OpenvasSettings.current()
        row.gmp_username, row.gmp_password = options['username'].strip()[:64], password
        row.save()
        self.stdout.write(f'GMP login saved for {row.gmp_username}. Switch the add-on on in Settings > OpenVAS.')
