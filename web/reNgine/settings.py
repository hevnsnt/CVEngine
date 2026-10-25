import environ

env = environ.FileAwareEnv()

import mimetypes
import os

from reNgine.init import first_run
from reNgine.utilities import RengineTaskFormatter

mimetypes.add_type("text/javascript", ".js", True)
mimetypes.add_type("text/css", ".css", True)

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#       RENGINE CONFIGURATIONS
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Take environment variables from .env file
environ.Env.read_env(os.path.join(BASE_DIR, os.pardir, '.env'))

# Root env vars
RENGINE_HOME = env('RENGINE_HOME', default='/usr/src/app')
RENGINE_RESULTS = env('RENGINE_RESULTS', default=f'{RENGINE_HOME}/scan_results')
RENGINE_CACHE_ENABLED = env.bool('RENGINE_CACHE_ENABLED', default=False)
RENGINE_RECORD_ENABLED = env.bool('RENGINE_RECORD_ENABLED', default=True)
RENGINE_RAISE_ON_ERROR = env.bool('RENGINE_RAISE_ON_ERROR', default=False)

# Common env vars
DEBUG = env.bool('DEBUG', default=False)
# Production is served behind HTTPS. Cookies must not accompany a request to the HTTP redirect listener.
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
# Start with a short HSTS lifetime. Operators can raise it after confirming
# their public TLS path; never preload or include sibling subdomains implicitly.
SECURE_HSTS_SECONDS = env.int('CVENGINE_HSTS_SECONDS', default=0 if DEBUG else 3600)
DOMAIN_NAME = env('DOMAIN_NAME', default='localhost:8000')
TEMPLATE_DEBUG = env.bool('TEMPLATE_DEBUG', default=False)
SECRET_FILE = os.path.join(RENGINE_HOME, 'secret')
DEFAULT_ENABLE_HTTP_CRAWL = env.bool('DEFAULT_ENABLE_HTTP_CRAWL', default=True)
DEFAULT_RATE_LIMIT = env.int('DEFAULT_RATE_LIMIT', default=150) # requests / second
DEFAULT_HTTP_TIMEOUT = env.int('DEFAULT_HTTP_TIMEOUT', default=5) # seconds
DEFAULT_RETRIES = env.int('DEFAULT_RETRIES', default=1)
DEFAULT_THREADS = env.int('DEFAULT_THREADS', default=30)
DEFAULT_GET_GPT_REPORT = env.bool('DEFAULT_GET_GPT_REPORT', default=True)

# Globals
from urllib.parse import urlsplit

# Host headers are used when Django builds links. Trust only the configured site
# and loopback health checks; extra public aliases must be listed explicitly.
try:
    _site_host = urlsplit('//' + DOMAIN_NAME).hostname or ''
except ValueError:
    _site_host = ''
ALLOWED_HOSTS = list(dict.fromkeys(host for host in (
    _site_host, 'localhost', '127.0.0.1', '[::1]',
    *(item.strip() for item in env('CVENGINE_ALLOWED_HOSTS', default='').split(',')),
) if host))
# Behind a TLS-terminating proxy Django sees plain http, while browsers send "Origin: https://<site>"; since Django 4
# that mismatch fails every POST with "CSRF verification failed". The shipped nginx overwrites X-Forwarded-Proto itself, so
# the app trusts it and the shipped setup works without any configuration. For any other public address (another
# hostname, a CDN, your own proxy) list the https origin(s), comma separated:
# CVENGINE_CSRF_TRUSTED_ORIGINS=https://scanner.example.com
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
CSRF_TRUSTED_ORIGINS = [o.strip() for o in env('CVENGINE_CSRF_TRUSTED_ORIGINS', default='').split(',') if o.strip()]
CSRF_FAILURE_VIEW = 'reNgine.csrf.csrf_failure'
SECRET_KEY = first_run(SECRET_FILE, BASE_DIR)

# Rengine version
# reads current version from a file called .version
VERSION_FILE = os.path.join(BASE_DIR, '.version')
if os.path.exists(VERSION_FILE):
    with open(VERSION_FILE, 'r') as f:
        _version = f.read().strip()
else:
    _version = 'unknown'

# removes v from _version if exists
if _version.startswith('v'):
    _version = _version[1:]

RENGINE_CURRENT_VERSION = _version

# Databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': env('POSTGRES_DB'),
        'USER': env('POSTGRES_USER'),
        'PASSWORD': env('POSTGRES_PASSWORD'),
        'HOST': env('POSTGRES_HOST'),
        'PORT': env('POSTGRES_PORT'),
        # 'OPTIONS':{
        #     'sslmode':'verify-full',
        #     'sslrootcert': os.path.join(BASE_DIR, 'ca-certificate.crt')
        # }
    }
}

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.humanize',
    'rest_framework',
    'rest_framework_datatables',
    'dashboard.apps.DashboardConfig',
    'targetApp.apps.TargetappConfig',
    'scanEngine.apps.ScanengineConfig',
    'startScan.apps.StartscanConfig',
    'recon_note.apps.ReconNoteConfig',
    'cveFeed.apps.CveFeedConfig',
    'django_ace',
    'django_celery_beat',
    'mathfilters',
    'drf_yasg',
    'rolepermissions'
]
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'reNgine.ip_allowlist.IpAllowlistMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'agentapi.auth.AgentTokenMiddleware',
    'reNgine.input_guard.InputGuardMiddleware',
    'login_required.middleware.LoginRequiredMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'tenancy.middleware.TenancyMiddleware',
    'tenancy.middleware.RetireClassicUiMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'reNgine.middleware.UserPreferencesMiddleware',
]
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [(os.path.join(BASE_DIR, 'templates'))],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'reNgine.context_processors.projects',
                'reNgine.context_processors.version_context',
                'reNgine.context_processors.user_preferences',
            ],
    },
}]
ROOT_URLCONF = 'reNgine.urls'
REST_FRAMEWORK = {
    'DEFAULT_RENDERER_CLASSES': (
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
        'rest_framework_datatables.renderers.DatatablesRenderer',
    ),
    'DEFAULT_FILTER_BACKENDS': (
        'tenancy.drf.ProjectScopeFilterBackend',
        'rest_framework_datatables.filters.DatatablesFilterBackend',
    ),
    'DEFAULT_PAGINATION_CLASS':(
        'rest_framework_datatables.pagination.DatatablesPageNumberPagination'
    ),
    'PAGE_SIZE': 500,
}
WSGI_APPLICATION = 'reNgine.wsgi.application'

# Password validation
# https://docs.djangoproject.com/en/2.2/ref/settings/#auth-password-validators
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.' +
                'UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.' +
                'MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.' +
                'CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.' +
                'NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/2.2/topics/i18n/
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

MEDIA_URL = '/media/'
MEDIA_ROOT = '/usr/src/scan_results/'
FILE_UPLOAD_MAX_MEMORY_SIZE = 100000000
FILE_UPLOAD_PERMISSIONS = 0o644
STATIC_URL = '/staticfiles/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "static"),
]

LOGIN_REQUIRED_IGNORE_VIEW_NAMES = [
    'login',
    'mfa_verify',
    'admin_login_redirect',
]

LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'cve_dashboard'
LOGOUT_REDIRECT_URL = 'login'

# Tool Location
TOOL_LOCATION = '/usr/src/app/tools/'

# Number of endpoints that have the same content_length
DELETE_DUPLICATES_THRESHOLD = 10

'''
CELERY settings
'''
CELERY_BROKER_URL = env("CELERY_BROKER", default="redis://redis:6379/0")
CELERY_RESULT_BACKEND = env("CELERY_BROKER", default="redis://redis:6379/0")
CELERY_ENABLE_UTC = False
CELERY_TIMEZONE = 'UTC'
CELERY_IGNORE_RESULTS = False
CELERY_EAGER_PROPAGATES_EXCEPTIONS = True
CELERY_TRACK_STARTED = True
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
# Scans run for hours and a bulk add queues dozens. A worker takes one task at a time instead of reserving a batch it cannot
# start for hours, and Redis waits hours (not its default hour) before it hands an unacknowledged task to someone else;
# otherwise queued discoveries are delivered twice and run in parallel. A worker that dies mid-pipeline gives its target
# back after CELERY_VISIBILITY_TIMEOUT seconds (12h by default); the domain lock and the service ledger make a redelivered
# pipeline safe.
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_BROKER_TRANSPORT_OPTIONS = {'visibility_timeout': env.int('CELERY_VISIBILITY_TIMEOUT', default=12 * 3600)}
'''
ROLES and PERMISSIONS
'''
ROLEPERMISSIONS_MODULE = 'reNgine.roles'
ROLEPERMISSIONS_REDIRECT_TO_LOGIN = True

'''
Cache settings
'''
RENGINE_TASK_IGNORE_CACHE_KWARGS = ['ctx']


DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

'''
LOGGING settings
'''
LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'handlers': {
        'file': {
            'level': 'ERROR',
            'class': 'logging.FileHandler',
            'filename': 'errors.log',
        },
        'null': {
            'class': 'logging.NullHandler'
        },
        'default': {
            'class': 'logging.StreamHandler',
            'formatter': 'default',
        },
        'brief': {
            'class': 'logging.StreamHandler',
            'formatter': 'brief'
        },
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'brief'
        },
        'task': {
            'class': 'logging.StreamHandler',
            'formatter': 'task'
        },
        'db': {
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'brief',
            'filename': 'db.log',
            'maxBytes': 1024,
            'backupCount': 3
        },
        'celery': {
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'simple',
            'filename': 'celery.log',
            'maxBytes': 1024 * 1024 * 100,  # 100 mb
        },
    },
    'formatters': {
        'default': {
            'format': '%(message)s'
        },
        'brief': {
            'format': '%(name)-10s | %(message)s'
        },
        'task': {
            '()': lambda : RengineTaskFormatter('%(task_name)-34s | %(levelname)s | %(message)s')
        },
        'simple': {
            'format': '%(levelname)s %(message)s',
            'datefmt': '%y %b %d, %H:%M:%S',
        }
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'level': 'ERROR' if DEBUG else 'CRITICAL',
            'propagate': True,
        },
        '': {
            'handlers': ['brief'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False
        },
        'celery': {
            'handlers': ['celery'],
            'level': 'DEBUG' if DEBUG else 'ERROR',
        },
        'celery.app.trace': {
            'handlers': ['null'],
            'propagate': False,
        },
        'celery.task': {
            'handlers': ['task'],
            'propagate': False
        },
        'celery.worker': {
            'handlers': ['null'],
            'propagate': False,
        },
        'django.server': {
            'handlers': ['console'],
            'propagate': False
        },
        'django.db.backends': {
            'handlers': ['db'],
            'level': 'INFO',
            'propagate': False
        },
        'reNgine.tasks': {
            'handlers': ['task'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False
        },
        'api.views': {
            'handlers': ['console'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False
        }
    },
}

'''
File upload settings
'''
DATA_UPLOAD_MAX_NUMBER_FIELDS = None

'''
    Caching Settings
'''


def _cache_url():
    """The shared cache: Redis, on the database after the broker's (CACHE_URL overrides). It holds the lockout counters, so it must
    be shared by every web worker and survive a worker restart; a database of its own keeps ``cache.clear()`` (factory reset) from
    wiping the Celery broker."""
    explicit = env('CACHE_URL', default='')
    if explicit:
        return explicit
    from urllib.parse import urlsplit, urlunsplit
    parts = urlsplit(env('CELERY_BROKER', default='redis://redis:6379/0'))
    try:
        db = int((parts.path or '/0').lstrip('/') or 0) + 1
    except ValueError:
        db = 1
    return urlunsplit((parts.scheme, parts.netloc, f'/{db}', '', ''))


CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': _cache_url(),
        'TIMEOUT': 60 * 30,  # 30 minutes caching will be used
    }
}
