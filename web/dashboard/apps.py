from django.apps import AppConfig


class DashboardConfig(AppConfig):
    name = 'dashboard'

    def ready(self):
        from django.apps import apps
        from tenancy import scope, signals  # noqa: F401  (signals registers receivers)
        scope.install(apps)
