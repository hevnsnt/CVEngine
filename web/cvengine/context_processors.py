"""Template context processors for version and edition."""

from django.conf import settings


def version_context(request):
    """Return the current version and edition for templates."""
    return {
        'CVENGINE_CURRENT_VERSION': settings.CVENGINE_CURRENT_VERSION,
        'CVENGINE_EDITION': settings.CVENGINE_EDITION,
    }
