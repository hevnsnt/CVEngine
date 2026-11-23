from django.apps import AppConfig


class CveFeedConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "cveFeed"
    verbose_name = "CVE Feed (cve.now)"

    def ready(self):
        """Register the system checks and the internal view hooks. (The check that kept the generated-templates directory apart from nuclei's template
        root is gone with the root: the server keeps no copy of the community templates.)"""
        from cveFeed import checks  # noqa: F401 - registers the system checks
        from cveFeed import exclusions
        exclusions.connect()  # a write of an exclusion list resets its cached copies
        from cveFeed import internal_view
        internal_view.connect()
