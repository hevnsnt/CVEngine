"""The reviewer's loop: ask the server what to do, run the pipeline's AI jobs it queued, review what it hands out, run the operations job
when it is due, sleep, repeat.

The pipeline's jobs come first and are polled often (every 15 seconds while there is nothing to do): triage, validation planning and the
rest wait for them. The finding review and the operations job keep their own slower pace.

Failures slow it down rather than stop it: no token yet, the server restarting, the provider down or refusing the key. After three
provider failures in a row it waits fifteen minutes before trying again, so a wrong key never turns into a stream of paid or failing
calls; the jobs it did not take wait in the server's queue meanwhile."""
import logging
import time
from concurrent.futures import ThreadPoolExecutor

from cvengine_reviewer import jobs, llm
from cvengine_reviewer.server import Server, ServerError, latest_templates_release

logger = logging.getLogger('cvengine_reviewer')

BATCH = 10
BUSY_SLEEP = 20
IDLE_SLEEP = 300
ERROR_SLEEP = 60
BACKOFF_SLEEP = 900
MAX_FAILURES = 3
JOB_POLL = 15          # seconds between asks for pipeline jobs while there are none
JOB_BATCH = 8          # jobs taken per ask
MAX_WORKERS = 8        # pipeline jobs run side by side (the server says how many, up to this)
# Failures of the provider itself (as against an answer that was cut off or empty): three in a row pause the work.
OUTAGE = ('auth', 'rate_limit', 'network', 'http', 'provider_auth', 'provider_rate_limit', 'provider_network', 'provider_http',
          'provider_timeout', 'provider_connect_timeout', 'provider_error')


def _failed(state, category):
    if category in OUTAGE:
        state['failures'] += 1
        if state['failures'] >= MAX_FAILURES and state['pause_until'] <= time.monotonic():
            logger.warning('three provider failures in a row: pausing for %s minutes', BACKOFF_SLEEP // 60)
            state['pause_until'] = time.monotonic() + BACKOFF_SLEEP


def run_jobs(server, config, state):
    """Take one batch of pipeline jobs and run them side by side. Returns how many were answered."""
    batch = server.next_jobs(JOB_BATCH)
    if not batch:
        return 0
    provider = config['jobs']
    workers = max(1, min(int(config.get('job_workers') or 4), MAX_WORKERS, len(batch)))
    done = 0

    def one(job):
        try:
            return jobs.run_job(server, provider, job)
        except ServerError as exc:
            logger.info('job %s: answer not taken: %s', job.get('id'), exc)
            return None, ''

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for answer, category in pool.map(one, batch):
            if category:
                _failed(state, category)
            elif answer is not None:
                state['failures'] = 0
                done += 1
    return done


def run_reviews(server, config, state):
    """The reviewer's own two jobs. Returns how long until they should run again."""
    worked = 0
    if config.get('ops_due') and config.get('ops'):
        try:
            result = jobs.run_ops(server, config['ops'], latest_templates_release())
            logger.info('operations: %s alert(s) diagnosed, actions run %s', result.get('alerts_updated'), result.get('actions_run'))
            state['failures'] = 0
        except llm.ModelError as exc:
            _failed(state, exc.category)
            logger.warning('operations: model call failed (%s)', exc.category)
    left = int(config.get('reviews_left_today') or 0)
    if left and config.get('review'):
        for packet in server.next_findings(min(BATCH, left)):
            if state['pause_until'] > time.monotonic():
                break
            try:
                answer = jobs.review_one(server, config['review'], packet)
                state['failures'] = 0
            except llm.ModelError as exc:
                _failed(state, exc.category)
                if exc.category not in OUTAGE:  # the model refused, answered nothing or was cut off twice: say so, or it is asked again every 15 minutes
                    jobs.report_unanswered(server, config['review'], packet, exc.category)
                continue
            except ServerError as exc:
                logger.info('verdict for %s not taken: %s', packet.get('ref'), exc)
                continue
            if answer:
                worked += 1
                logger.info('reviewed %s: %s', packet.get('ref'), answer.get('outcome'))
    return BUSY_SLEEP if worked else IDLE_SLEEP


def cycle(server, state):
    """One pass. Returns how long to sleep."""
    config = server.config()
    now = time.monotonic()
    if state['pause_until'] > now:
        return min(JOB_POLL * 4, state['pause_until'] - now)
    if state['failures'] >= MAX_FAILURES:
        state['failures'] = 0  # the back-off has passed: try again
    jobs_on = bool(config.get('jobs_enabled') and config.get('jobs'))
    if jobs_on and run_jobs(server, config, state):
        return 1  # more may be waiting
    if config.get('enabled') and state['review_at'] <= time.monotonic() and state['pause_until'] <= time.monotonic():
        state['review_at'] = time.monotonic() + run_reviews(server, config, state)
    if state['pause_until'] > time.monotonic():
        return BACKOFF_SLEEP
    wait = max(1, state['review_at'] - time.monotonic()) if config.get('enabled') else IDLE_SLEEP
    return min(wait, JOB_POLL) if jobs_on else min(wait, IDLE_SLEEP)


def new_state():
    return {'failures': 0, 'pause_until': 0.0, 'review_at': 0.0}


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    logging.getLogger('httpx2').setLevel(logging.WARNING)
    logging.getLogger('anthropic').setLevel(logging.WARNING)
    server = Server()
    state = new_state()
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
