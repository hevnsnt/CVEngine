"""The reviewer's loop: ask the server what to do, review what it hands out, run the operations job when it is due, sleep, repeat.

Failures slow it down rather than stop it: no token yet, the server restarting, the provider down or refusing the key. After three model
failures in a row it waits fifteen minutes before trying again, so a wrong key never turns into a stream of paid or failing calls."""
import logging
import time

from cvengine_reviewer import jobs, llm
from cvengine_reviewer.server import Server, ServerError, latest_templates_release

logger = logging.getLogger('cvengine_reviewer')

BATCH = 10
BUSY_SLEEP = 20
IDLE_SLEEP = 300
ERROR_SLEEP = 60
BACKOFF_SLEEP = 900
MAX_FAILURES = 3


def cycle(server, state):
    """One pass. Returns how long to sleep."""
    config = server.config()
    if not config.get('enabled'):
        return IDLE_SLEEP
    worked = 0
    if config.get('ops_due') and config.get('ops'):
        try:
            result = jobs.run_ops(server, config['ops'], latest_templates_release())
            logger.info('operations: %s alert(s) diagnosed, actions run %s', result.get('alerts_updated'), result.get('actions_run'))
            state['failures'] = 0
        except llm.ModelError as exc:
            state['failures'] += 1
            logger.warning('operations: model call failed (%s)', exc.category)
    left = int(config.get('reviews_left_today') or 0)
    if left and config.get('review') and state['failures'] < MAX_FAILURES:
        for packet in server.next_findings(min(BATCH, left)):
            try:
                answer = jobs.review_one(server, config['review'], packet)
                state['failures'] = 0
            except llm.ModelError:
                state['failures'] += 1
                if state['failures'] >= MAX_FAILURES:
                    logger.warning('three model failures in a row: pausing for %s minutes', BACKOFF_SLEEP // 60)
                    return BACKOFF_SLEEP
                continue
            except ServerError as exc:
                logger.info('verdict for %s not taken: %s', packet.get('ref'), exc)
                continue
            if answer:
                worked += 1
                logger.info('reviewed %s: %s', packet.get('ref'), answer.get('outcome'))
    if state['failures'] >= MAX_FAILURES:
        state['failures'] = 0  # the back-off has passed: try again
        return BACKOFF_SLEEP
    return BUSY_SLEEP if worked else IDLE_SLEEP


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    logging.getLogger('httpx2').setLevel(logging.WARNING)
    logging.getLogger('anthropic').setLevel(logging.WARNING)
    server = Server()
    state = {'failures': 0}
    logger.info('AI reviewer started; server %s', server.base)
    while True:
        try:
            delay = cycle(server, state)
        except ServerError as exc:
            logger.info('waiting for the server: %s', exc)
            delay = ERROR_SLEEP
        except Exception:  # noqa: BLE001 - the loop must survive anything one pass throws
            logger.exception('unexpected error; trying again shortly')
            delay = ERROR_SLEEP
        time.sleep(delay)


if __name__ == '__main__':
    main()
