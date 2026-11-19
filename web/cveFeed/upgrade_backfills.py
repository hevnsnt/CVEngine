"""The backfills an update brings, run by themselves once per install after the update.

cvENGINE runs headless: nobody is expected to open a shell and type a management command after an update. Every backfill command an
update ships (each is a dry run unless ``--apply``, so a person can still preview one) is listed in ``BACKFILLS`` and applied
automatically: when a worker starts (``reNgine.celery.run_pending_backfills``), the ``run_upgrade_backfills`` task works through the ones
this install has not finished, one per run, in the order listed, and records each as done (``BackgroundCursor`` lane ``bf:<name>``).

* One worker at a time: the run holds a Redis claim, and a run that finds it held returns at once.
* Each backfill is idempotent (running it again finds nothing to change), so a run cut short by a restart is simply run again.
* A backfill that fails is tried again at the next run, at most ``MAX_ATTEMPTS`` times; after that it is recorded as given up, with an
  error line in the activity feed, so a backfill that cannot succeed never loops.
* Every outcome is a line in the activity feed (and the log), with the command's own summary.
* ``CVENGINE_AUTO_BACKFILLS=0`` turns it off (the commands still work by hand).

A new backfill is added by appending its command name to ``BACKFILLS``; an install that already ran the others runs only the new one.
"""
import io
import logging
import os
import socket

logger = logging.getLogger(__name__)

# Order matters: the ranges are corrected before anything reads them, rows are reopened, merged, folded and closed before they are
# re-rated, and the rescore comes last so host scores count everything above.
BACKFILLS = (
    'apply_range_corrections',            # 1.3.5: sourced CVE range corrections on the stored CVEs (marks them for re-correlation)
    'reopen_openvas_identity_closures',   # 1.3.5 (#414): OpenVAS matches closed as "different product" by mistake
    'dedupe_findings',                    # 1.3.5: scanner and hygiene findings filed more than once
    'fold_alias_findings',                # 1.3.5: what redirect aliases share with their target host
    'close_fixed_findings',               # 1.3.5: WordPress scan findings past their fix
    'rerate_hygiene',                     # 1.3.5: hygiene findings rated by the endpoint rules
    'rerate_dangling_dns',                # 1.3.5: dangling-DNS findings rated by what an outsider can claim (read-only DNS and HTTP checks)
    'backfill_secrets_inventory',         # 1.4: the secrets stored token and bbot findings carry, filed in the inventory and masked in place
    'trim_flooded_ports',                 # 1.4: addresses that answer on every port keep the lowest 100 stored ports, as a Sentinel report does (memory)
    'recheck_template_hits',              # 1.4.2: AI-written checks' confirmations that only read a version string become version reads
    'backfill_java_runtimes',             # the Java runtime existing hosts give away without a request, and their runtime CVE matches
    'backfill_version_sources',           # the versions, runtimes, SNMP releases and bundled components existing hosts already state, and their matches
    'backfill_exact_builds',              # Cisco's exact builds (cut at 30 or dropped) and Oracle's supported versions read per line (re-correlated)
    'backfill_bare_versions',             # blocks cve.now passed on as bare versions (Linux kernel, VulDB, ...) take their record's ranges (re-correlated)
    'backfill_name_aliases',              # hosts whose technology names the alias data and name rules now connect differently (re-correlated)
    'backfill_distro_readings',           # stored banners read again for the distribution package build and release, and those hosts re-correlated
    'backfill_source_versions',           # the exact versions and CPEs stored ports, runZero, Shodan InternetDB and database replies state (re-correlated)
    'backfill_name_versions',             # Server-header tokens stored as names ("nginx/1.28.3") split into product and version (re-correlated)
    'backfill_protocol_versions',         # a connector's version read as the product's (Tomcat's "Coyote JSP engine 1.1") closes (re-correlated)
    'backfill_recog_readings',            # the products, versions and CPEs Rapid7 Recog reads in the banners hosts already store (re-correlated)
    'backfill_identities',                # service fingerprints decoded; network OS, appliance certificate, Recog and SSH identities read (re-correlated)
    'backfill_windows_builds',            # the Windows release stored NTLM and SMB script output states, and its KEV/critical candidates (re-correlated)
    'backfill_panel_versions',            # the version a stored panel template finding extracted, read as a version reading of its host (re-correlated)
    'recover_feed_gap',                   # the cve.now window a walk declared covered after the feed renamed its cursor: read again and matched
    'retype_distro_ranges',               # ranges bounded by distribution package builds (0:8.7p1-38.el9_4.4) are no longer read as upstream releases
    'repair_open_ranges',                 # open ranges made from an upper bound the CVE List record writes as text (issue 696), re-correlated
    'neutralise_screenshots',             # stored discovery screenshots named by a Sentinel (x.html, x.svg): renamed to a picture name or removed
    'backfill_shodan_cpes',               # every Shodan InternetDB CPE a reported reading ("vendor product"), CPE technologies removed (re-correlated)
    'backfill_technology_names',          # technology rows folded onto one spelling, MariaDB's "5.5.5-" prefix off port versions (re-correlated)
    'recheck_openvas_generic_checks',     # OpenVAS matches a behaviour check (TRACE enabled) confirmed on a CVE whose record names no vendor or product
    'revalidate_ai_drafts',               # AI-written checks closed only because no scanner could check them go back to validation; reasons named
    'rerate_findings',                    # 1.3.5: rescore hosts for the new heat rules, clear stale fire marks (last: counts everything above)
)
MAX_ATTEMPTS = 3
CLAIM_KEY = 'cvengine:upgrade-backfills'
CLAIM_TTL = 3900  # longer than the task's time limit, so a crashed run's claim expires on its own
DONE_PREFIX = 'bf:'      # BackgroundCursor lane present once the backfill finished (or was given up)
ATTEMPT_PREFIX = 'bfa:'  # BackgroundCursor lane whose last_pk counts the failed attempts


def enabled():
    return os.environ.get('CVENGINE_AUTO_BACKFILLS', '1').strip().lower() not in ('0', 'false', 'no', 'off')


def _lane(prefix, name):
    return (prefix + name)[:32]


def pending():
    """The backfills this install has not finished, in the order they run: a backfill that failed goes after the ones not yet tried,
    so one that keeps failing never holds the others back."""
    from cveFeed.models import BackgroundCursor
    rows = dict(BackgroundCursor.objects.filter(lane__startswith='bf').values_list('lane', 'last_pk'))
    todo = [name for name in BACKFILLS if _lane(DONE_PREFIX, name) not in rows]
    return sorted(todo, key=lambda name: rows.get(_lane(ATTEMPT_PREFIX, name), 0))  # stable: the listed order among equals


def _summary(text):
    lines = [line.strip() for line in (text or '').splitlines() if line.strip()]
    return lines[-1][:300] if lines else ''


def run_one(name, call=None):
    """Apply one backfill and record the outcome. Returns ``'done'``, ``'failed'`` (tried again later) or ``'given_up'``."""
    from django.core.management import call_command
    from cveFeed import activity
    from cveFeed.models import BackgroundCursor
    call = call or call_command
    out = io.StringIO()
    try:
        call(name, apply=True, stdout=out, stderr=out)
    except Exception as exc:  # noqa: BLE001 - one backfill's failure must not stop the others or the worker
        logger.exception('upgrade backfill %s failed', name)
        attempts, _ = BackgroundCursor.objects.get_or_create(lane=_lane(ATTEMPT_PREFIX, name))
        attempts.last_pk += 1
        attempts.save(update_fields=['last_pk', 'updated_at'])
        if attempts.last_pk < MAX_ATTEMPTS:
            activity.log('run_check', f'Update step {name} failed ({type(exc).__name__}); it is tried again at the next worker start '
                                      f'(attempt {attempts.last_pk} of {MAX_ATTEMPTS})', status='failed')
            return 'failed'
        BackgroundCursor.objects.get_or_create(lane=_lane(DONE_PREFIX, name))
        activity.log('run_check', f'Update step {name} failed {MAX_ATTEMPTS} times and was given up ({type(exc).__name__}); '
                                  f'run "python3 manage.py {name}" to see what it would change', status='failed')
        return 'given_up'
    BackgroundCursor.objects.get_or_create(lane=_lane(DONE_PREFIX, name))
    summary = _summary(out.getvalue())
    activity.log('run_check', f'Update step {name} applied' + (f': {summary}' if summary else ''))
    logger.info('upgrade backfill %s applied: %s', name, summary)
    return 'done'


def run_next(call=None):
    """Run the first pending backfill under the claim. Returns ``{'state', 'name', 'remaining'}``: ``state`` is ``off``, ``none`` (all
    done), ``held`` (another worker runs them), or the outcome of the backfill it ran."""
    from reNgine import resources
    if not enabled():
        return {'state': 'off', 'name': '', 'remaining': 0}
    todo = pending()
    if not todo:
        return {'state': 'none', 'name': '', 'remaining': 0}
    owner = f'{socket.gethostname()}:{os.getpid()}'
    with resources.redis_claim(CLAIM_KEY, owner, CLAIM_TTL) as holder:
        if holder is not True:
            return {'state': 'held', 'name': '', 'remaining': len(todo)}
        todo = pending()  # read again under the claim: another run may have finished one meanwhile
        if not todo:
            return {'state': 'none', 'name': '', 'remaining': 0}
        name = todo[0]
        state = run_one(name, call=call)
    remaining = len(pending())
    return {'state': state, 'name': name, 'remaining': remaining}
