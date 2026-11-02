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
from reNgine.time_limits import QueueTimeLimits
app.conf.task_annotations = (QueueTimeLimits(),)  # the limits of each task's queue (reNgine/time_limits.py)
# Celery's autoscaler never runs more than one task at a time in a gevent pool while that task runs (reNgine/gevent_autoscale.py)
app.conf.worker_autoscaler = 'reNgine.gevent_autoscale:GeventAutoscaler'
# After a broker reconnect celery lowers the prefetch and restores it toward pool.num_processes, which on gevent is the greenlets running, not the
# ceiling: acks_late tasks then ran one at a time until a restart. The prefetch stays at the ceiling (set at start and by the autoscaler).
app.conf.worker_enable_prefetch_count_reduction = False
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
        from cveFeed.tasks import check_os_path
        check_os_path.apply_async(countdown=180)  # and measure the path, once the other workers are up
    except Exception:  # noqa: BLE001 - the database may not be reachable yet; the next worker start tries again
        logging.getLogger(__name__).exception('could not clear the untrusted operating system guesses')


@worker_ready.connect()
def recap_version_only_answers(*args, **kwargs):
    """Answers stored before the ceiling that says a match on a version string alone is needs_validation at most (cveFeed.triage.ceiling)
    are brought in line with it, with no model call. Idempotent. Never stops the worker from starting."""
    import logging
    try:
        from cveFeed import triage
        changed = triage.recap_version_only()
        if changed:
            logging.getLogger(__name__).info('%d version-only CVE match answers kept as needs validation', changed)
    except Exception:  # noqa: BLE001 - the database may not be reachable yet; the next worker start tries again
        logging.getLogger(__name__).exception('could not recap the version-only answers')


@worker_ready.connect()
def rescore_for_heat_cap(*args, **kwargs):
    """Host scores are stored: when the version-only heat cap changed (the 1.3.2 upgrade, or CVENGINE_VERSION_ONLY_MAX_HEAT), one full
    rescore is queued so a score never counts a version-only match as fire after its heat stopped saying so (cveFeed.scoring.
    rescore_if_heat_cap_changed). Never stops the worker from starting."""
    import logging
    try:
        from cveFeed import scoring
        scoring.rescore_if_heat_cap_changed()
    except Exception:  # noqa: BLE001 - the next worker start or the daily rescore tries again
        logging.getLogger(__name__).exception('could not check the version-only heat cap')


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
