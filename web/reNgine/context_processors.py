from django.conf import settings


def version_context(request):
    return {
        'RENGINE_CURRENT_VERSION': settings.RENGINE_CURRENT_VERSION,
        'RENGINE_EDITION': settings.RENGINE_EDITION,
    }
