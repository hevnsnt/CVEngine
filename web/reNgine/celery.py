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


@worker_ready.connect()
def clear_untrusted_os_guesses(*args, **kwargs):
    """An install behind Docker Desktop's network stored operating system guesses that describe that network (cveFeed.os_detection);
    remove them and name each host from what its services report. Does nothing on an install that measures correctly. Never stops the
    worker from starting."""
    import logging
    try:
        from cveFeed import os_detection
        os_detection.clear_stored_guesses()
    except Exception:  # noqa: BLE001 - the database may not be reachable yet; the next worker start tries again
        logging.getLogger(__name__).exception('could not clear the untrusted operating system guesses')


@worker_ready.connect()
def start_first_run_bootstrap(*args, **kwargs):
    """A brand-new install loads its CVE feed as soon as its workers are up, not at the first scheduled run (cveFeed.tasks.
    bootstrap_first_run does nothing on an install that already has CVEs). The delay lets the other workers and beat settle.
    Never stops the worker from starting."""
    import logging
    try:
        from cveFeed.tasks import bootstrap_first_run
        bootstrap_first_run.apply_async(countdown=45)
    except Exception:  # noqa: BLE001 - the broker or database may not be reachable yet; the next worker start tries again
        logging.getLogger(__name__).exception('could not queue the first-run bootstrap')
