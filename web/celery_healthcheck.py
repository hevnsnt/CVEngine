"""The celery container's HEALTHCHECK, and the updater's check that every lane is up (scripts/update-deploy.sh ``verify_workers``).

Healthy means all four lanes of ``celery-entrypoint.sh`` answer a ping from here AND report the queue they exist for as one they consume:
``discovery_worker`` (discovery_queue), ``cve_feed_worker`` (cve_feed_queue), ``validation_priority_worker`` (validation_priority_queue) and
``classic_worker`` (api_queue, the queue the status page, the updater and the admin worker panel recognise it by). A lane that does not answer
within the bounded wait, or answers without its queue, makes the check fail and names it, so ``docker ps`` shows "unhealthy" and the system status
page and the updater have the same answer. (The entrypoint itself is the guard that exits when a lane process is gone; this also catches a lane whose
process is alive and no longer consuming, which no process check can.)

No Django and no database: only the broker address from the environment (``CELERY_BROKER``, the one compose gives every container).

    python3 celery_healthcheck.py            # exit 0 when all four answer, else 1 and one line naming the lanes that did not
    python3 celery_healthcheck.py --json     # the same, as one JSON object
"""
import json
import os
import sys

# The layout of celery-entrypoint.sh (tests/test_celery_healthcheck.py pins it to cveFeed.admin_api.WORKERS and to the entrypoint's -n names).
LANES = {'discovery_worker': 'discovery_queue', 'cve_feed_worker': 'cve_feed_queue',
         'validation_priority_worker': 'validation_priority_queue', 'classic_worker': 'api_queue'}
PING_SECONDS = float(os.environ.get('CELERY_HEALTH_PING_SECONDS', '8'))  # one broadcast waits this long for a busy gevent worker
TRIES = int(os.environ.get('CELERY_HEALTH_TRIES', '2'))  # a lane that did not answer is asked once more before it counts


def _owns(node, lane):
    # celery names a node either `<lane>@<host>` (what -n <lane> gives) or `celery@<lane>`
    return lane in str(node).split('@')


def lane_state(replies):
    """``{lane: 'consuming' | 'no_queue' | 'no_reply'}`` from ``inspect().active_queues()``'s replies (``{node: [{'name': queue}, ...]}``)."""
    out = {}
    for lane, queue in LANES.items():
        nodes = [node for node in (replies or {}) if _owns(node, lane)]
        if not nodes:
            out[lane] = 'no_reply'
        elif any(queue in [q.get('name') for q in (replies[node] or [])] for node in nodes):
            out[lane] = 'consuming'
        else:
            out[lane] = 'no_queue'
    return out


def ask(app=None):
    """The state of every lane, asking up to ``TRIES`` times (the lanes that answered are kept)."""
    if app is None:
        from celery import Celery
        app = Celery('health', broker=os.environ.get('CELERY_BROKER') or os.environ.get('CELERY_BROKER_URL'))
    replies = {}
    state = {}
    for _ in range(max(1, TRIES)):
        for node, queues in (app.control.inspect(timeout=PING_SECONDS).active_queues() or {}).items():
            replies[node] = queues
        state = lane_state(replies)
        if all(v == 'consuming' for v in state.values()):
            break
    return state


def main(argv=None, app=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        state = ask(app)
    except Exception as exc:  # noqa: BLE001 - a broker that cannot be reached is unhealthy, said plainly
        state = {lane: 'no_reply' for lane in LANES}
        reason = f'the broker could not be reached ({type(exc).__name__})'
    else:
        reason = ''
    bad = {lane: v for lane, v in state.items() if v != 'consuming'}
    if '--json' in argv:
        print(json.dumps({'healthy': not bad, 'lanes': state, 'reason': reason}))
    elif bad:
        words = {'no_reply': 'does not answer', 'no_queue': 'answers but does not consume its queue'}
        print('; '.join(f'{lane} {words[v]}' for lane, v in bad.items()) + (f' ({reason})' if reason else ''))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
