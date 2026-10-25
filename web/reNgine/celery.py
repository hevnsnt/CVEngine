import os

import django
from celery import Celery
from celery.signals import setup_logging, worker_ready

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'reNgine.settings')
django.setup()

# Celery app
app = Celery('reNgine')
from cveFeed.scan_control import PauseAwareTask
app.Task = PauseAwareTask
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()


@setup_logging.connect()
def config_loggers(*args, **kwargs):
    from logging.config import dictConfig
    dictConfig(app.conf['LOGGING'])


@worker_ready.connect()
def restore_generated_templates(*args, **kwargs):
    """A recreated container starts without the AI-written templates that were on its disk; put back the validated ones from the
    database so an update does not make every template be regenerated. Never stops the worker from starting."""
    import logging
    log = logging.getLogger(__name__)
    try:
        from cveFeed import templategen
        result = templategen.restore_missing_files()
        if result['restored'] or result['skipped']:
            log.info('generated AI templates restored from the database: %s', result)
    except Exception:  # noqa: BLE001 - the database may not be reachable yet; the next worker start tries again
        log.exception('could not restore the generated AI templates')
