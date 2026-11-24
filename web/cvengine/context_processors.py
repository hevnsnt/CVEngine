from django.conf import settings


def version_context(request):
    return {
        'CVENGINE_CURRENT_VERSION': settings.CVENGINE_CURRENT_VERSION,
        'CVENGINE_EDITION': settings.CVENGINE_EDITION,
    }
