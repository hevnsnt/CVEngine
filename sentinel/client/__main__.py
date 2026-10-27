"""Entry point: ``python -m client`` (the Dockerfile's CMD). Loads a persisted token if one exists, otherwise
bootstraps from ``CVENGINE_SENTINEL_BLOB``, then runs the daemon's main loop until SIGTERM/SIGINT.
"""
import logging
import signal
import sys

from . import config
from . import daemon as daemon_mod
from . import httpclient

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
logger = logging.getLogger('sentinel.main')


def main():
    path = config.token_path()
    token, server_url = daemon_mod.load_token(path)
    if token:
        logger.info('using the persisted token at %s; skipping bootstrap', path)
    else:
        raw_blob = config.blob()
        if not raw_blob:
            logger.error('no persisted token at %s and CVENGINE_SENTINEL_BLOB is not set; cannot start', path)
            sys.exit(1)
        logger.info('bootstrapping from CVENGINE_SENTINEL_BLOB')
        try:
            token, server_url = daemon_mod.bootstrap(raw_blob, config.sentinel_name(), config.max_concurrent())
        except Exception:  # noqa: BLE001 - a bad blob or unreachable server is fatal at startup; say why, then exit
            logger.exception('bootstrap failed')
            sys.exit(1)
        daemon_mod.save_token(path, token, server_url)
        logger.info('bootstrap succeeded; token persisted at %s', path)

    client = httpclient.Client(server_url, token)
    engine = daemon_mod.Daemon(server_url, token, max_concurrent=config.max_concurrent(), client=client)

    def handle_signal(signum, _frame):
        logger.info('received signal %s; finishing or releasing in-flight tasks', signum)
        engine.request_stop()
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    logger.info('Sentinel %s starting, max_concurrent=%s, server=%s', config.sentinel_name(), config.max_concurrent(), server_url)
    engine.run()
    logger.info('Sentinel stopped')


if __name__ == '__main__':
    main()
