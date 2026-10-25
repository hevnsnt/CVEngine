from django.apps import AppConfig


class CveFeedConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "cveFeed"
    verbose_name = "CVE Feed (cve.now)"

    def ready(self):
        """Refuse to start with the generated-templates directory inside nuclei's template root (or the reverse): that would run
        AI-written, unproven templates in the blanket nuclei pass. A clear error beats a quiet loss of the isolation."""
        from django.core.exceptions import ImproperlyConfigured

        from cveFeed import checks  # noqa: F401 - registers the system checks
        from cveFeed import templategen
        problem = templategen.templates_dir_problem()
        if problem:
            raise ImproperlyConfigured(problem)
