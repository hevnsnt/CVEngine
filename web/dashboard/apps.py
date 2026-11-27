from django.apps import AppConfig


class DashboardConfig(AppConfig):
    name = 'dashboard'

    def ready(self):
        from django.apps import apps
        from tenancy import scope, signals  # noqa: F401  (signals registers receivers)
        scope.install(apps)
        # Every migrate that runs as the owner role creates or updates the least privilege app role and grants it again, so the tables a
        # migration just created are covered too (cvengine/db_roles.py). Once per migrate: post_migrate is sent per app, after all migrations.
        from django.db.models.signals import post_migrate
        post_migrate.connect(grant_app_role, sender=self, dispatch_uid='cvengine-db-app-role')


def grant_app_role(sender, using='default', verbosity=1, stdout=None, **kwargs):
    import sys

    from cvengine import db_roles
    out = stdout or sys.stdout
    db_roles.ensure_after_migrate(using, log=(lambda m: out.write(f'  {m}\n')) if verbosity else (lambda m: None),
                                  warn=lambda m: sys.stderr.write(f'{m}\n'))
