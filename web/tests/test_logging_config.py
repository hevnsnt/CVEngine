"""The logging configuration is applied several times in one process (django.setup() again from reNgine.celery, again when a Celery worker starts), so it
must never switch off a logger that already exists: a module's own log lines would vanish from then on."""
import logging
from logging.config import dictConfig

from django.conf import settings
from django.test import SimpleTestCase


class LoggingConfigTests(SimpleTestCase):
    def test_existing_loggers_are_not_disabled(self):
        self.assertIs(settings.LOGGING['disable_existing_loggers'], False)

    def test_applying_the_configuration_again_keeps_a_module_logger_enabled(self):
        root = logging.getLogger()
        handlers, level = list(root.handlers), root.level
        self.addCleanup(lambda: (root.handlers.__setitem__(slice(None), handlers), root.setLevel(level)))
        log = logging.getLogger('cveFeed.logging_config_test')
        self.addCleanup(lambda: setattr(log, 'disabled', False))
        dictConfig(settings.LOGGING)
        self.assertFalse(log.disabled)
        with self.assertLogs('cveFeed.logging_config_test', 'WARNING'):
            log.warning('still logged')
