"""
WSGI config for reNgine project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/2.2/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'reNgine.settings')

application = get_wsgi_application()

# Build in the background, once per worker process, what the first request would otherwise build (cveFeed/warmup.py: the URL configuration and
# the shared public caches). Returns at once and never raises; CVENGINE_WARMUP=0 turns it off.
from cveFeed import warmup  # noqa: E402

warmup.start('web')
