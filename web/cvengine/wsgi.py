"""WSGI entry point loaded by the application server; it exposes `application`."""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cvengine.settings')

application = get_wsgi_application()

# Once per worker process this builds in the background what the first request
# would otherwise build. It returns at once and never raises. Setting the
# environment variable CVENGINE_WARMUP=0 turns it off.
from cveFeed import warmup  # noqa: E402

warmup.start('web')
