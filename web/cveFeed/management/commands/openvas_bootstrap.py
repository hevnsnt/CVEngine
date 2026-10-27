from django.core.management.base import BaseCommand, CommandError

from cveFeed import openvas_scan


class Command(BaseCommand):
    help = ('Replace the default GVM login (admin / admin, which Greenbone\'s community containers create) with a generated password, set over GMP so it '
            'is never on a command line, and save it encrypted for cvENGINE. Run by `make openvas-user` inside the celery container, which is the one that '
            'has gvmd\'s socket. Prints only the user name.')

    def handle(self, *args, **options):
        try:
            username = openvas_scan.bootstrap()
        except openvas_scan.OpenvasError as exc:
            raise CommandError(str(exc))
        self.stdout.write(f'GMP login for {username} generated and saved. Switch the add-on on in Settings > OpenVAS.')
