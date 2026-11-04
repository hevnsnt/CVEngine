from django.core.management.base import BaseCommand, CommandError

from cveFeed import openvas_scan


class Command(BaseCommand):
    help = ('Replace the default GVM login (admin / admin, which Greenbone\'s community containers create) with a generated password, set over GMP so it '
            'is never on a command line, and save it encrypted for cvENGINE (on a gvmd that will not let admin change its own password, a user '
            'cvengine is created with it instead). Run by `make openvas-user` inside the celery container, which is the one that '
            'has gvmd\'s socket. Prints only the user name.')

    def handle(self, *args, **options):
        try:
            username = openvas_scan.bootstrap()
        except openvas_scan.OpenvasError as exc:
            raise CommandError(str(exc))
        self.stdout.write(f'GMP login for {username} generated and saved. Switch the add-on on in Settings > OpenVAS.')
        if username != openvas_scan.DEFAULT_LOGIN[0]:
            # gvmd would not let admin change its own password over GMP, so admin / admin still works: say how to retire it by hand
            self.stdout.write('gvmd would not change the password of its default user admin, which still has the password admin. Retire it inside '
                              "the gvmd container: docker compose exec -u gvmd openvas-gvmd sh -c 'read -r p && gvmd --user=admin --new-password=\"$p\"' "
                              '(type a password and press Enter), then docker compose restart openvas-gvmd: gvmd keeps accepting the old password '
                              'until it restarts (docs/OPENVAS.md, The default login).')
