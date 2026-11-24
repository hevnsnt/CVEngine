"""Create, grant and check the least privilege database role the application runs as (cvengine/db_roles.py, docs/CONFIGURATION.md).

    manage.py db_app_role ensure              create or update the app role and grant it (as the owner role; every migrate does this too)
    manage.py db_app_role choose [--wait N]   which role this container runs as: prints app or owner and writes it to /tmp/cvengine-db-role
                                              (the entrypoints run it; every later process of the container reads that file)
    manage.py db_app_role status              what this container runs as, one line (the update scripts print it)
    manage.py db_app_role gate                as the owner, in the one-off migrate service: create and grant the app role, check that it logs in,
                                              and exit 1 with the one-line fix when it does not (CVENGINE_DB_ALLOW_OWNER_FALLBACK=1 instead hands
                                              the owner password to the application, through the db_owner_fallback volume)
"""
import os
import sys

from django.core.management.base import BaseCommand, CommandError

from cvengine import db_roles


class Command(BaseCommand):
    help = 'Create, grant and check the least privilege database role the application runs as.'

    def add_arguments(self, parser):
        parser.add_argument('action', choices=('ensure', 'choose', 'status', 'gate'))
        parser.add_argument('--wait', type=int, default=0, help='choose: seconds to wait for the app role to log in while the owner can')
        parser.add_argument('--state-file', default=None, help='choose and status: where the choice is kept (default CVENGINE_DB_ROLE_STATE, else /tmp/cvengine-db-role)')

    def handle(self, *args, action, wait, state_file, **options):
        if action == 'ensure':
            return self._ensure()
        if action == 'gate':
            return self._gate()
        if action == 'choose':
            role, reason = db_roles.choose(wait=wait)
            try:
                db_roles.write_state(role, reason, state_file)
            except OSError as exc:
                self.stderr.write(f'db_app_role: could not record the choice: {exc}')
            if role == 'owner':
                self.stderr.write(f"db_app_role: this container connects to the database as the OWNER role {os.environ.get('POSTGRES_USER', '')}: "
                                  f'{reason}. See docs/UPGRADE.md, Database roles.')
                if not db_roles.owner_password(os.environ):
                    self.stderr.write('db_app_role: ERROR: this container has no owner password either (it is kept out of web, celery and '
                                      'celery-beat), so it cannot connect. Run  docker compose run --rm migrate  to see the one-line fix.')
            self.stdout.write(role)
            return None
        role, reason = db_roles.read_state(state_file)
        if role is None:
            current = db_roles.resolve(argv=['manage.py', 'runserver'], state_file=None)  # what a process of this container would use
            role, reason = current['role'], current['reason'] or 'no choice recorded by the entrypoint'
        user = os.environ.get('POSTGRES_USER', '') if role == 'owner' else db_roles.app_user(os.environ)
        self.stdout.write(f'{role} {user}' + (f' ({reason})' if reason else ''))
        return None

    def _gate(self):
        from django.conf import settings
        from django.db import connection

        if settings.DATABASE_ROLE != 'owner':
            raise CommandError('run this as the owner role, in the migrate service: docker compose run --rm migrate python3 manage.py db_app_role gate')

        def ensure_role(name, password):
            db_roles.ensure(connection, name, password, log=self.stdout.write)

        ok, _role, lines = db_roles.gate(ensure_role=ensure_role)
        for line in lines:
            (self.stdout if ok else self.stderr).write(line)
        if not ok:
            sys.exit(1)
        return None

    def _ensure(self):
        from django.conf import settings
        from django.db import connection

        name, password = db_roles.app_user(os.environ), db_roles.secret(os.environ, 'CVENGINE_DB_APP_PASSWORD')
        if not name or not password:
            self.stdout.write('No app role is configured (CVENGINE_DB_APP_USER or CVENGINE_DB_APP_PASSWORD is empty): the application uses the owner role.')
            return None
        if settings.DATABASE_ROLE != 'owner':
            raise CommandError('run this as the owner role (CVENGINE_DB_ROLE=owner)')
        try:
            db_roles.ensure(connection, name, password, log=self.stdout.write)
        except db_roles.RoleError as exc:
            self.stderr.write(f'db_app_role: {exc}')
            sys.exit(1)
        return None
