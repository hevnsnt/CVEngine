"""Celery tasks for syncing the cve.now feed.

Autodiscovered by the reNgine.tasks celery app; routed to cve_feed_queue, which
a dedicated worker consumes (see web/celery-entrypoint.sh). Schedule it with
django_celery_beat (e.g. every 30 minutes).
"""
import logging
import os
import re
import time

from reNgine.celery import app
from cveFeed.cve_now import CVENowClient
from cveFeed.models import CVEEntry

logger = logging.getLogger(__name__)


@app.task(name='assessment_review', bind=False, queue='cve_feed_queue')
def assessment_review_task(review_id=None):
    """Three-hour AI coverage review, continued in bounded project pages."""
    from cveFeed.assessment_review import run_page
    return run_page(review_id)


@app.task(name='rediscover_archived_hosts', bind=False, queue='cve_feed_queue')
def rediscover_archived_hosts(run_id=None):
    from cveFeed.archive_rediscovery import run_page
    return run_page(run_id)


@app.task(name='review_inactive_hosts', bind=False, queue='cve_feed_queue')
def review_inactive_hosts(run_id=None):
    from cveFeed.inactive_archive import run_page
    return run_page(run_id)


@app.task(name='review_unresolved_hosts', bind=False, queue='cve_feed_queue')
def review_unresolved_hosts(run_id=None):
    """Daily, checkpointed archival of hosts that have never once resolved to a scannable IP (see
    cveFeed.unresolved_archive), a shorter and separate timeline from review_inactive_hosts' 30-day case."""
    from cveFeed.unresolved_archive import run_page
    return run_page(run_id)


@app.task(name='top_up_host_assessments', bind=False, queue='discovery_queue')
def top_up_host_assessments():
    """Every few minutes: enqueue due host assessments directly (no model call), draining a coverage backlog far
    faster than the three-hour AI review's one-due-host-per-project-per-window pace (see cveFeed.coverage_topup)."""
    from cveFeed.coverage_topup import top_up
    return top_up()


@app.task(name='wpscan_thorough', bind=False, queue='wpscan_queue')
def wpscan_thorough(project_id):
    """The thorough WPScan pass (plugins and themes in mixed mode, hours per site) for one project: see ``wpscan_scan.run_thorough``. It has a
    queue of its own so a pass that takes hours never holds up the feed workers."""
    from cveFeed import wpscan_scan
    return wpscan_scan.run_thorough(project_id)


@app.task(name='wpscan_quick', bind=False, queue='wpscan_queue')
def wpscan_quick(scan_id, hosts, attempt=1):
    """The quick WPScan pass for WordPress sites the scan's own stage could not reach in time (over its limit, out of its time budget, no memory),
    a little later each attempt: see ``wpscan_scan.run_quick``."""
    from cveFeed import wpscan_scan
    return wpscan_scan.run_quick(scan_id, hosts, attempt)


@app.task(name='testssl_sweep', bind=False, queue='testssl_queue')
def testssl_sweep():
    """Daily: the TLS audit (testssl.sh) of the targets that are due, one at a time (see ``cveFeed.testssl_scan``). It has a queue of its own so
    a minute-per-port test never holds up the feed workers."""
    from cveFeed import testssl_scan
    return testssl_scan.sweep_all()


@app.task(name='bucket_sweep', bind=False, queue='bucketscan_queue')
def bucket_sweep():
    """Daily: the cloud storage exposure check of every project's due buckets, a few requests per second (see ``cveFeed.bucket_scan``). It has a
    queue of its own so a slow, deliberately paced sweep never holds up the feed workers."""
    from cveFeed import bucket_scan
    return bucket_scan.sweep_all()

@app.task(name='vhost_sweep', bind=False, queue='vhost_queue')
def vhost_sweep():
    """Hourly: the project's known names asked at its web addresses (other sites on the same address), a few addresses per run: see
    ``cveFeed.vhost_scan``. It has a queue of its own, shared with the subdirectory sweep, so slow polite work never holds up the feed workers."""
    from cveFeed import vhost_scan
    return vhost_scan.sweep_all()


@app.task(name='subdir_apps_sweep', bind=False, queue='vhost_queue')
def subdir_apps_sweep():
    """Every 30 minutes: a few web hosts asked for the well-known application mount paths (see ``cveFeed.subdir_apps``)."""
    from cveFeed import subdir_apps
    return subdir_apps.sweep_all()


@app.task(name='openvas_sweep', bind=False, queue='openvas_queue')
def openvas_sweep():
    """Every 15 minutes while the OpenVAS add-on is switched on (the beat entry is disabled otherwise): one step of the slow GVM sweep, which
    polls the running task or starts the next due batch (see ``cveFeed.openvas_scan``). It has a queue of its own so it never holds up the
    feed workers."""
    from cveFeed import openvas_scan
    return openvas_scan.tick()


@app.task(name='supplier_sweep', bind=False, queue='supplier_queue')
def supplier_sweep():
    """Daily: the passive posture checks of every project's due third-party suppliers (TLS, email authentication, security headers, banners), a few
    requests per second at most, each supplier once a week (see ``cveFeed.supplier_scan``). A supplier is not an owned host: this never
    scans, enumerates or assesses anything. It has a queue of its own so a slow, deliberately paced sweep never holds up the feed workers."""
    from cveFeed import supplier_scan
    return supplier_scan.sweep_all()


@app.task(name='openvas_check', bind=False, queue='cve_feed_queue')
def openvas_check():
    """Settings > OpenVAS' Test connection: only a worker has the sidecar's socket (the web container has none), so the page asks here. No
    credential travels in the message: the worker reads the saved login itself."""
    from cveFeed import openvas_scan
    return openvas_scan.check_now()


@app.task(name='sync_tailscale', bind=False, queue='cve_feed_queue')
def sync_tailscale():
    """Every 15 minutes: bring each connected tailnet's devices, findings and scans up to date (see cveFeed.tailscale_sync)."""
    from cveFeed import tailscale_sync
    return tailscale_sync.sync_all()


@app.task(name='tailscale_node_state', bind=False, queue='cve_feed_queue')
def tailscale_node_state():
    """What this server's own Tailscale node reports, for Settings > Tailscale's Test connection. Only the worker can read the
    node's status file (the web container has none), so the page asks here; no credential is involved."""
    from cveFeed import tailscale_local
    from cveFeed.tailscale_api import TailscaleError
    if not tailscale_local.available():
        return {'present': False}
    try:
        state, peers = tailscale_local.read()
    except TailscaleError as exc:
        return {'present': True, 'error': str(exc)}
    shown = {k: state[k] for k in ('backend_state', 'tailnet', 'self_name', 'version', 'peers')}
    return {'present': True, 'state': shown, 'peer_count': len(peers)}


@app.task(name='sync_tailscale_link', bind=False, queue='cve_feed_queue')
def sync_tailscale_link(link_id):
    """One tailnet now, started by an administrator (Settings, REST or MCP)."""
    from cveFeed import tailscale_sync
    return tailscale_sync.sync_link(link_id)


def _known_in_batches(summaries, size=100):
    """Yield (summary, ids already stored) with one lookup per ``size`` summaries instead of one per entry."""
    from itertools import islice
    iterator = iter(summaries)
    while True:
        batch = list(islice(iterator, size))
        if not batch:
            return
        known = set(CVEEntry.objects.filter(cve_id__in=[s.get("id") for s in batch if s.get("id")]).values_list("cve_id", flat=True))
        for summary in batch:
            yield summary, known


@app.task(name="sync_cve_now_feed", bind=False, queue="cve_feed_queue")
def sync_cve_now_feed(max_new=200, catch_up_after=40, max_scan=5000, refresh_max=10):
    """Pull recent entries from cve.now and upsert the new ones.

    Walks the feed newest-first. Each id not already stored is hydrated (full
    entry: affected ranges + exploitation) and saved. The walk stops once it has
    created `max_new` records, or after `catch_up_after` consecutive
    already-known ids (we have reached territory a previous run covered), so a
    scheduled run stays cheap and incremental.
    """
    from cveFeed import activity
    from cveFeed.threat import FIRE, SMOKE
    client = CVENowClient()
    reading = activity.log('feed', 'Reading the cve.now feed', status='running')
    new_entries = []
    seen = created = skipped = failed = 0
    consecutive_existing = 0
    for summary, known in _known_in_batches(client.iter_entries(max_entries=max_scan)):
        cve_id = summary.get("id")
        if not cve_id:
            continue
        seen += 1
        if cve_id in known:
            skipped += 1
            consecutive_existing += 1
            if consecutive_existing >= catch_up_after:
                break
            continue
        consecutive_existing = 0
        try:
            entry = client.get_entry(cve_id)
            if isinstance(entry, dict) and summary.get("firstSeenAt"):
                entry.setdefault("firstSeenAt", summary["firstSeenAt"])
            obj, _ = CVEEntry.from_api(entry)
            new_entries.append(obj)
            created += 1
        except Exception as exc:  # one bad entry must not abort the sync
            failed += 1
            logger.warning(f"cve.now: failed to sync {cve_id}: {exc}")
        if created >= max_new:
            break
    # Rotate through the oldest refreshed entries that actually match inventory.
    # Freshly discovered entries remain governed by max_new above.
    refreshed = changed = 0
    from cveFeed.models import MatchVerdict
    from django.utils import timezone
    from datetime import timedelta
    from django.db.models import Q
    now = timezone.now()
    # a CVE with a match is kept current; so is a recent one the feed published with no affected data yet (the CNA's first record often
    # names no version, and the enrichment that makes it matchable arrives days later: without this it would never be read again)
    needs_refresh = Q(matches__isnull=False) | Q(affected=[], published_at__gte=now - timedelta(days=90))
    due = CVEEntry.objects.filter(needs_refresh, synced_at__lt=now - timedelta(hours=12)) \
        .distinct().order_by('synced_at', 'id')[:max(0, min(int(refresh_max), 20))]
    for old in list(due):
        try:
            entry = client.get_entry(old.cve_id)
            before = (old.affected, old.cvss, old.kev, old.epss_reached, old.exploit_db, old.original_description, old.summary)
            obj, _ = CVEEntry.from_api(entry)
            after = (obj.affected, obj.cvss, obj.kev, obj.epss_reached, obj.exploit_db, obj.original_description, obj.summary)
            refreshed += 1
            if before != after:
                changed += 1
                CVEEntry.objects.filter(pk=obj.pk).update(needs_recorrelation=True)
                MatchVerdict.objects.filter(cve_entry_id=obj.pk).delete()
        except Exception as exc:
            failed += 1
            logger.warning('cve.now: failed to refresh %s: %s', old.cve_id, exc)
    result = {"seen": seen, "created": created, "skipped": skipped, "refreshed": refreshed, "changed": changed, "failed": failed}
    logger.info(f"cve.now sync complete: {result}")
    tiers = [e.threat_tier for e in new_entries]
    pending_recorrelation = CVEEntry.objects.filter(needs_recorrelation=True).exists()
    if not created and not failed and not changed:  # a read that found nothing is noise in the AI feed
        logger.debug('cve.now: nothing new since the last read')
        activity.discard(reading)
        if pending_recorrelation:
            correlate_refreshed_cves.delay()
        return result
    activity.settle(
        reading, 'done' if not failed or created else 'failed',
        message=(f"cve.now: {created} new CVEs ({tiers.count(FIRE)} fire, {tiers.count(SMOKE)} smoke); "
                 f"{refreshed} matched advisories refreshed ({changed} changed)")
                + (f"; {failed} could not be saved (see the worker log)" if failed else ""),
        created=created, fire=tiers.count(FIRE), smoke=tiers.count(SMOKE))
    if created:
        auto_fire_new_cves.delay([e.pk for e in new_entries if getattr(e, "pk", None)])
    if pending_recorrelation:
        correlate_refreshed_cves.delay()
    return result


COVERAGE_DAYS_DEFAULT = 14
GAP_MAX_NEW = 1500
BACKFILL_ID_RE = re.compile(r'^(CVE-\d{4}-\d{4,9}|GHSA(-[a-z0-9]{4}){3}|OSV-[A-Za-z0-9-]{4,40})$', re.IGNORECASE)


def _coverage_days():
    try:
        return int(os.environ.get('CVENGINE_CVE_COVERAGE_DAYS', COVERAGE_DAYS_DEFAULT))
    except ValueError:
        return COVERAGE_DAYS_DEFAULT


def _watch_techs():
    raw = os.environ.get('CVENGINE_CVE_WATCH_TECHS', 'php')
    return [t.strip().lower() for t in raw.split(',') if t.strip()]


def _parse_time(value):
    from django.utils.dateparse import parse_datetime
    try:
        return parse_datetime(value) if value else None
    except (TypeError, ValueError):
        return None


@app.task(name='backfill_cve_now_feed', bind=False, queue='cve_feed_queue')
def backfill_cve_now_feed(days=None, max_new=400, max_scan=6000, ids=None, techs=None, pause=0.2, force=False, sleep=None):
    """Fill the gap behind the incremental sync.

    The scheduled sync walks the feed newest-first and stops after 40 known entries in a row or 200 new ones, so entries older
    than its first run were never read. This task reads them:

    * ``ids``: exactly these entries (a CVE, GHSA or OSV id), whatever the listing says.
    * ``techs``: the entries cve.now files under a technology slug (default the CVENGINE_CVE_WATCH_TECHS list, php), read from
      its per-technology feed, which lists entries the newest-first walk does not reach.
    * otherwise the last ``days`` days (CVENGINE_CVE_COVERAGE_DAYS, 14; 0 turns the scheduled run off) of the newest-first
      listing, without the known-in-a-row stop. Skipped at once, with no request, when the oldest stored entry was first seen
      before that window (``force`` walks anyway).

    Bounded per run (``max_new`` entries, ``max_scan`` listed, ``pause`` seconds between entry fetches) and safe to repeat: stored
    entries are skipped, so each run continues where the last stopped. A refusal (403) or repeated failure stops the run
    instead of retrying, so a block on the feed is never made worse."""
    import requests
    from datetime import timedelta
    from django.utils import timezone
    from cveFeed import activity
    from cveFeed.threat import FIRE, SMOKE
    pause_for = sleep or time.sleep
    explicit = bool(ids or techs)
    row = cutoff = now = None
    assumed_days, failures, set_aside = None, {}, set()
    if not explicit:
        from cveFeed import feed_watermark
        window = _coverage_days() if days is None else int(days)
        if window <= 0:
            return {'status': 'disabled'}
        now = timezone.now()
        row = feed_watermark.current()
        # a walk that read back to its floor is not repeated for a few hours, so the hourly schedule costs no request in between
        if (not force and row.covered_through is not None and not row.resume_cursor and row.checked_at
                and now - row.checked_at < feed_watermark.RECHECK):
            return {'status': 'covered', 'covered_through': row.covered_through.isoformat()}
        cutoff = feed_watermark.floor_for(row, now, window)
        if row.covered_through is None or row.covered_through > now + feed_watermark.SKEW:
            assumed_days = max(feed_watermark.LEGACY_DAYS, window)  # nothing says how far back the feed is complete: this window is a guess
        failures = dict(row.failures or {})
        set_aside = {i for i, tries in failures.items() if tries >= feed_watermark.MAX_ATTEMPTS}
        max_scan = feed_watermark.scan_budget(cutoff, now, max_scan)
        if now - cutoff > timedelta(days=2):
            max_new = max(max_new, GAP_MAX_NEW)
    client = CVENowClient()
    result = {'status': 'ok', 'listed': 0, 'wanted': 0, 'created': 0, 'failed': 0, 'blocked': False, 'invalid': []}
    wanted, first_seen = [], {}
    # how the walk ended: it read back to the floor or to the end of the listing ("reached"), or stopped at a cap with entries left
    reached, head, page_cursor = False, None, None

    def want(entry_id):
        if entry_id in set_aside and not force:
            return  # refused on every attempt of earlier runs: reported (feed_watermark.status), retried by a forced run, not read again here
        if entry_id not in first_seen and entry_id not in wanted:
            wanted.append(entry_id)

    try:
        for raw in (ids or []):
            entry_id = str(raw).strip()
            if BACKFILL_ID_RE.match(entry_id):
                want(entry_id.upper() if entry_id.upper().startswith('CVE-') else entry_id)
            else:
                result['invalid'].append(entry_id[:64])
        for tech in ((techs if techs is not None else []) if explicit else _watch_techs()):
            try:
                listed = client.tech_entry_ids(tech)
            except ValueError:
                result['invalid'].append(str(tech)[:64])
                continue
            known = set(CVEEntry.objects.filter(cve_id__in=listed).values_list('cve_id', flat=True))
            for entry_id in listed:
                if force or entry_id not in known:
                    want(entry_id)
        if not explicit:
            from cveFeed import feed_watermark
            resumed = row.resume_cursor or None  # a walk cut short by a cap or a failure continues where it was
            head = row.resume_head if resumed else None
            walked, stopped = 0, False
            for page_cursor, page in client.iter_pages(max_entries=max_scan, page_pause=0.3, cursor=resumed):
                known = set(CVEEntry.objects.filter(cve_id__in=[e.get('id') for e in page if e.get('id')]).values_list('cve_id', flat=True))
                for summary in page:
                    walked += 1
                    published = feed_watermark.published(summary)
                    if head is None and not resumed and published:
                        head = published  # the first entry of a walk from the head: what a complete walk will have covered
                    if published and published < cutoff:
                        reached = True
                        break
                    entry_id = summary.get('id')
                    if entry_id and (force or entry_id not in known):
                        want(entry_id)
                        first_seen[entry_id] = summary.get('firstSeenAt')
                    if len(wanted) >= max_new:
                        stopped = True
                        break
                if reached or stopped:
                    break
            else:
                reached = walked < max_scan  # the listing ended before the budget did: everything it lists was read
            result['listed'] = walked
    except requests.RequestException as exc:
        status = getattr(getattr(exc, 'response', None), 'status_code', None)
        result['blocked'] = status in (401, 403, 429)
        result['status'] = 'blocked' if result['blocked'] else 'failed'
        logger.warning('cve.now backfill could not read the listing: %s', exc)
        reached = False
        if not wanted:
            return result
    result['wanted'] = len(wanted)
    created_rows, refused = [], []
    for entry_id in wanted[:max_new]:
        try:
            entry = client.get_entry(entry_id)
            if isinstance(entry, dict) and first_seen.get(entry_id):
                entry.setdefault('firstSeenAt', first_seen[entry_id])
            obj, _ = CVEEntry.from_api(entry)
            created_rows.append(obj)
            result['created'] += 1
            failures.pop(entry_id, None)
        except requests.RequestException as exc:
            status = getattr(getattr(exc, 'response', None), 'status_code', None)
            result['failed'] += 1
            refused.append(entry_id)
            logger.warning('cve.now backfill: failed to fetch %s: %s', entry_id, exc)
            if status in (401, 403, 429):
                result['blocked'], result['status'] = True, 'blocked'
                break
        except Exception as exc:  # noqa: BLE001 - one bad entry must not stop the run
            result['failed'] += 1
            logger.warning('cve.now backfill: failed to save %s: %s', entry_id, exc)
            refused.append(entry_id)
        pause_for(pause)
    if row is not None:
        if result['status'] == 'ok':
            # an entry that fails run after run is set aside once (up to a few), so one bad entry cannot hold the window back for good; a feed
            # that refuses everything is not a bad entry and never gets that far (the cap), and a refusal (401/403/429) says nothing about an entry
            for entry_id in refused:
                tries = failures.get(entry_id, 0) + 1
                if tries >= feed_watermark.MAX_ATTEMPTS and entry_id not in set_aside:
                    if len(set_aside) >= feed_watermark.MAX_UNREADABLE:
                        tries = feed_watermark.MAX_ATTEMPTS - 1
                    else:
                        set_aside.add(entry_id)
                        activity.log('feed', f'cve.now backfill: {entry_id} could not be read in {tries} runs and is set aside; it is listed in the feed status', status='failed')
                failures[entry_id] = min(tries, feed_watermark.MAX_ATTEMPTS)
        if failures:
            stored = set(CVEEntry.objects.filter(cve_id__in=list(failures)).values_list('cve_id', flat=True))
            failures = {i: t for i, t in failures.items() if i not in stored}
        failures_changed = failures != (row.failures or {})
        row.failures = failures
        if feed_watermark.unreadable(row):
            result['unreadable'] = feed_watermark.unreadable(row)
        clean = result['status'] == 'ok' and not result['failed'] and result['created'] == result['wanted'] and len(wanted) <= max_new
        if reached and clean:
            # everything the feed lists back to the floor is stored: the watermark moves to the head this walk started from
            row.covered_through, row.resume_cursor, row.resume_head, row.checked_at = min(head or now, now), '', None, now
            if assumed_days:
                row.assumed_days = assumed_days
                result['window_assumed_days'] = assumed_days
                activity.log('feed', f'cve.now backfill: no seed time or earlier walk says how far back the feed was complete, so it was read back '
                             f'{assumed_days} days; anything older that is missing stays missing', status='done')
            row.save()
            result['covered_through'] = row.covered_through.isoformat()
        elif clean:
            # stopped at a cap with more to read: continue from this page next time (a failure keeps the earlier state, so nothing is skipped)
            row.resume_cursor, row.resume_head = page_cursor or '', head
            row.save()
            result['continues'] = True
        elif failures_changed:
            row.save(update_fields=['failures', 'updated_at'])
    tiers = [e.threat_tier for e in created_rows]
    if created_rows:
        activity.log('feed', f"cve.now backfill: {len(created_rows)} older CVEs read ({tiers.count(FIRE)} fire, {tiers.count(SMOKE)} smoke)"
                     + (f"; {result['failed']} could not be read" if result['failed'] else ''), status='done')
        auto_fire_new_cves.delay([e.pk for e in created_rows if getattr(e, 'pk', None)])
    return result


@app.task(name='sync_bounty_catalogue', bind=False, queue='cve_feed_queue')
def sync_bounty_catalogue(platforms=None, force=False):
    """Refresh the bug bounty program catalogue (public scope data, see cveFeed.bounty_data). The hourly schedule does nothing until
    someone with bug bounty access has loaded the catalogue once from the page (``force``), so an instance that never uses the
    feature never makes the request. ``CVENGINE_BOUNTY_CATALOGUE=0`` turns it off entirely. An unchanged file costs one conditional
    request (ETag)."""
    from django.core.cache import cache
    from django.utils import timezone

    from cveFeed import activity, bounty_data
    from cveFeed.bounty_api import CATALOGUE_REQUESTED, CATALOGUE_RUNNING
    from cveFeed.models import BountySource
    if os.environ.get('CVENGINE_BOUNTY_CATALOGUE', '1') == '0':
        cache.delete(CATALOGUE_REQUESTED)
        return {'status': 'disabled'}
    if not force and not BountySource.objects.filter(last_changed__isnull=False).exists():
        return {'status': 'not loaded yet'}
    cache.set(CATALOGUE_RUNNING, timezone.now().isoformat(), 1800)
    entry = activity.log('feed', 'Loading the bug bounty program catalogue (bounty-targets-data)', status='running') if force else None
    try:
        results = bounty_data.sync_all(platforms)
    finally:
        cache.delete(CATALOGUE_RUNNING)
        cache.delete(CATALOGUE_REQUESTED)
    failed = [r for r in results if r.get('status') == 'error']
    summary = ', '.join(f"{r['platform']} {r.get('programs', 0)}" if r.get('status') == 'updated' else f"{r['platform']} {r['status']}"
                        for r in results)
    activity.settle(entry, 'failed' if failed else 'done', message=f'Bug bounty catalogue: {summary}'
                    + (''.join(f"; {r['platform']}: {r.get('error', '')}" for r in failed)))
    return results


@app.task(name='sync_threat_intel', bind=False, queue='cve_feed_queue')
def sync_threat_intel():
    """Hourly: refresh the due threat-intelligence sources (CISA KEV, ENISA EUVD, EPSS, Exploit-DB, Metasploit, VulnCheck KEV
    with a key), reconcile every stored CVE's exploitation signals with them, and import the CVEs they name that the cve.now
    feed never delivered (cveFeed.intel). New CVEs go through the same correlation and announcement as the feed's own; hosts
    matched to a CVE whose signals changed are rescored."""
    from django.core.cache import cache

    from cveFeed import activity, intel
    from cveFeed.models import CVEMatch
    from cveFeed.threat import FIRE, SMOKE
    if not cache.add('cvengine:threat-intel', 1, timeout=2 * 3600):
        return {'skipped': 'another threat-intel run is in progress'}
    try:
        result = intel.run()
    finally:
        cache.delete('cvengine:threat-intel')
    if result.get('status') == 'disabled':
        return result
    created, changed = result['imported'], result['signals_changed']
    if changed:
        from cveFeed import scoring
        rescored = set()  # a host matched by CVEs in several chunks is scored once
        for cve_ids in scoring._chunks(changed, scoring.CHUNK):
            scoring.rescore_for_matches(CVEMatch.objects.filter(cve_entry_id__in=cve_ids)
                                        .select_related('subdomain__target_domain')
                                        .order_by('subdomain__target_domain__project_id', 'subdomain__name'), rescored)
    if created:
        auto_fire_new_cves.delay([c.pk for c in created])
    if result.get('ranges_repaired'):  # entries whose ranges were re-derived are correlated again (cveFeed.intel.repair_ranges)
        correlate_refreshed_cves.delay()
    tiers = [c.threat_tier for c in created]
    if created or changed or result['errors']:
        activity.log('feed', (f"Threat intelligence: {len(created)} CVEs imported from the CVE List ({tiers.count(FIRE)} fire, "
                              f"{tiers.count(SMOKE)} smoke), {len(changed)} stored CVEs changed exploitation signals; sources: "
                              + ', '.join(f"{intel.SOURCES[n]['label']} {count:,}" for n, count in result['sources'].items()))
                     + ''.join(f"; {intel.SOURCES[n]['label']} failed: {e}" for n, e in result['errors'].items()),
                     status='failed' if result['errors'] else 'done', imported=len(created), changed=len(changed))
    return {**result, 'imported': len(created), 'signals_changed': len(changed)}


@app.task(name='correlate_refreshed_cves', bind=False, queue='cve_feed_queue')
def correlate_refreshed_cves():
    """Recheck only materially updated CVEs and reset their dependent AI rows."""
    from cveFeed import triage
    from cveFeed.autofire import correlate_hot_cves
    from cveFeed.correlation import latest_scan_q
    from cveFeed.models import CVEMatch
    pending = list(CVEEntry.objects.filter(needs_recorrelation=True).order_by('synced_at', 'id')[:10])
    if not pending:
        return {'correlated': 0}
    correlate_hot_cves(pending)
    qs = CVEMatch.objects.filter(cve_entry__in=pending).filter(latest_scan_q('subdomain__')).select_related(
        'cve_entry', 'subdomain__target_domain').order_by('id')
    for start in range(0, qs.count(), 500):
        triage.track(list(qs[start:start + 500]))
    CVEEntry.objects.filter(pk__in=[c.pk for c in pending]).update(needs_recorrelation=False)
    return {'correlated': len(pending)}


@app.task(name="correlate_host_inventory", bind=False, queue="cve_feed_queue")
def correlate_host_inventory(inventory_id):
    """Match one host report (its packages, operating system and patch level) against the CVEs."""
    from cveFeed import host_inventory
    return host_inventory.run_correlation(inventory_id)


@app.task(name="correlate_cves", bind=False, queue="cve_feed_queue")
def correlate_cves(scan_history_id=None, project_slug=None, min_confidence=0.4, cve_limit=None):
    """Correlate stored CVE entries against discovered subdomains' technologies.

    Builds a product index from the CVE table once, then walks the in-scope
    subdomains creating CVEMatch rows. Scope: one scan (scan_history_id), one
    project (project_slug), or everything. `cve_limit` caps the CVE pool to the
    most recently published N (useful for a fresh-CVE focused pass).
    """
    from cveFeed.correlation import candidate_subdomains, close_rejected, correlate_subdomains, cve_pool
    from startScan.models import Subdomain, ScanHistory
    from cveFeed import activity, match_policy

    close_rejected()  # a CVE rejected since the last run stops being a finding
    from cveFeed import locality
    locality.refresh()  # new or changed CVEs: which are only usable from the host itself
    locality.close_local_matches()  # ...never a finding, so any open match on one is closed
    match_policy.close_policy_matches()  # a product seen without a version is a lead, not a match: close what the old rules made
    cve_by_id, index = cve_pool(cve_limit)
    scan = None
    if scan_history_id:
        scan = ScanHistory.objects.filter(id=scan_history_id).first()
        subs = Subdomain.objects.filter(scan_history=scan).prefetch_related("technologies", "ip_addresses__ports")
    else:
        # only hosts carrying something a CVE names, from each domain's latest scan: the rest cannot match
        base = Subdomain.objects.filter(target_domain__project__slug=project_slug) if project_slug else None
        subs = candidate_subdomains(index, base=base)

    checking = activity.log(
        'inventory', f'Checking {len(cve_by_id)} CVEs against the host inventory', status='running')
    subdomains, matches = correlate_subdomains(
        subs.iterator(chunk_size=500), index, cve_by_id, min_confidence=min_confidence, scan_history=scan)
    if scan or not scan_history_id:
        from cveFeed import host_inventory
        host_inventory.refresh_scope(scan=scan, project_slug=project_slug)  # what the hosts reported about themselves, on the new rows
    result = {"subdomains": subdomains, "matches": matches, "cve_pool": len(cve_by_id)}
    logger.info(f"correlate_cves complete: {result}")
    activity.settle(checking, 'done', message=(
        f'Checked {len(cve_by_id)} CVEs against {subdomains} hosts: {matches} potential '
        f'match{"es" if matches != 1 else ""}'), hosts=subdomains, matches=matches)
    return result


@app.task(name="auto_fire_new_cves", bind=False, queue="cve_feed_queue")
def auto_fire_new_cves(new_cve_pks=None):
    """AI-first loop: for each unseen FIRE/SMOKE CVE, correlate, confirm, and test the affected hosts.

    The test and the AI confirmation need auto-fire enabled in AI Settings. The announcement does not: an operator who turned
    auto-fire off still wants to hear that a fire-tier CVE matches the inventory, so with it off the feed sync's new CVEs
    (``new_cve_pks``) are still correlated and announced. The inventory is walked once for the whole batch, and the one message
    goes out after the AI has judged the matches, so it never names a match the AI then clears.
    """
    from django.utils import timezone

    from cveFeed import notify
    from cveFeed.autofire import correlate_hot_cves, fire_for_cve, hot_cves_without_run
    from dashboard.models import AIProviderSettings

    cfg = AIProviderSettings.objects.filter(auto_fire=True).first()
    cves = hot_cves_without_run()
    if not cfg:
        cves = [c for c in cves if c.pk in set(new_cve_pks or ())]  # off: only what this sync brought in, not the whole backlog
    if not cves:
        return {"fired": 0} if cfg else {"skipped": "auto-fire disabled"}
    since = timezone.now()
    leads = correlate_hot_cves(cves)
    fired = 0
    if cfg:
        from cveFeed import hit_batch
        from cveFeed.autofire import dispatch_template_test
        batch = hit_batch.start()  # the run holds the first place until everything is queued

        def dispatch(cve_pk, hosts, project_id):
            hit_batch.join(batch)
            try:
                dispatch_template_test(cve_pk, hosts, project_id, batch=batch)
            except Exception:
                hit_batch.leave(batch)
                raise
        try:
            for cve in cves:
                fire_for_cve(cve, max_hosts=cfg.auto_fire_max_scans, correlated=True, test_dispatcher=dispatch, leads=leads.get(cve.id, ()))
                fired += 1
        finally:
            hit_batch.leave(batch)  # the last test to finish (or this, if none were queued) sends the one message
    notify.fire_matches(since, cve_ids=[c.pk for c in cves])  # one message, after the verdicts
    logger.info(f"auto-fire complete: {fired} CVEs ({len(cves)} correlated)")
    return {"fired": fired} if cfg else {"skipped": "auto-fire disabled", "announced_for": len(cves)}


@app.task(name="sync_distro_fixes", bind=False, queue="cve_feed_queue")
def sync_distro_fixes_task():
    """Daily: refresh what Ubuntu and Debian say fixes the CVEs matched on their hosts (Debian security tracker, OSV), so a
    match on a patched backport is labelled "patched by distro" instead of exposed. Bounded, and a source that is unreachable
    is skipped, never an error. Correlation reads whatever is there; new data triggers one re-correlation."""
    from cveFeed import distro_sync, ledger
    if not ledger.sweep_claim("distro-sync", 3000):
        return {"skipped": "another sync is running"}
    try:
        result = distro_sync.sync_distro_fixes()
    except Exception as exc:  # noqa: BLE001 - a failed sync must never surface as a task failure
        logger.exception("distro fix sync failed")
        return {"error": str(exc)[:200]}
    if result.get("changed"):
        correlate_cves.delay()
    logger.info("distro fix sync complete: %s", result)
    return result


@app.task(name="template_test_for_cve", bind=False, queue="cve_feed_queue")
def template_test_for_cve(cve_pk, hosts, project_id=None, batch=None):
    """Stage 7: use an installed nuclei template for the CVE or AI-generate one, then test ``hosts``. Started by an auto-fire
    run (``batch``), its hits go into that run's one notification; started on its own, it announces them itself."""
    from cveFeed import hit_batch, notify
    from cveFeed.models import CVEEntry
    from cveFeed.templategen import run_cve_tests
    from reNgine.ai_settings import get_configured_provider
    from cveFeed.conductor import bounty_blocked_projects

    try:
        if project_id in bounty_blocked_projects():  # a bug bounty project that has not confirmed automated testing is not tested on its own
            return {"cve_pk": cve_pk, "skipped": "the bug bounty engagement has not confirmed automated testing"}
        cve = CVEEntry.objects.get(pk=cve_pk)
        try:
            provider = get_configured_provider()
        except Exception as exc:  # misconfigured provider: still run existing templates
            logger.warning("template_test_for_cve: no usable AI provider: %s", exc)
            provider = None
        outcome = run_cve_tests(cve, hosts, provider=provider, project=project_id)
        logger.info("template test %s: %s on %d hosts", cve.cve_id, outcome["source"], len(hosts))
        vulnerable = [r["host"] for r in outcome["results"] if r["vulnerable"]]
        pairs = [(cve.cve_id, host) for host in vulnerable]
        if batch:
            hit_batch.record(batch, pairs)
        else:
            notify.template_hits(pairs)  # one message per CVE test, never per host
        return {"cve": cve.cve_id, "source": outcome["source"], "vulnerable": vulnerable}
    finally:
        if batch:
            hit_batch.leave(batch)  # also when the test failed: the run's count must still reach zero


@app.task(name="validate_findings", bind=False, queue="cve_feed_queue")
def validate_findings(project_id, triage_ids, scan_id=None):
    """Run the validation checks (cveFeed.validation) for ``triage_ids``, all of one project: one task per project, never a list
    that mixes tenants. Started by the pipeline's triage stage (``scan_id`` then carries its stop flag) and by the validation sweep."""
    from cveFeed import validation
    try:
        return validation.run_validation(project_id, triage_ids, scan_id=scan_id)
    except Exception as exc:  # noqa: BLE001 - validation is best effort and must never surface as a task failure
        logger.exception("validation failed for project %s", project_id)
        return {"error": str(exc)[:200]}


def _skip_on_demand_validation(job, progress, cve_id, reason):
    """A queued request whose match is no longer the host's current finding is superseded work: it spends no attempt, schedules no retry
    and is not logged as a failure (the automatic path does the same, ``_skip_automatic_validation``)."""
    from django.utils import timezone
    from cveFeed import activity
    from cveFeed.models import OnDemandValidation

    text = {'historical': 'the match was replaced by a newer scan before the request ran',
            'out_of_scope': 'the host is outside the scannable project scope'}[reason]
    result = {'check_state': 'not_run', 'ai_state': 'not_run', 'reason': reason, 'next_action': text}
    OnDemandValidation.objects.filter(pk=job.pk, status='running').update(
        status='skipped', result=result, error='', next_attempt_at=None, finished_at=timezone.now())
    activity.settle(progress, 'done', f'Validation request #{job.pk} skipped for {cve_id}: {text}',
                    check_state='not_run', ai_state='not_run', reason=reason)
    return result


@app.task(name="validate_match_on_demand", bind=False, queue="validation_priority_queue")
def validate_match_on_demand(request_id):
    """Review exactly the persisted match; the task accepts no host or target from the caller."""
    from django.utils import timezone
    from cveFeed import activity, correlation, triage, validation, validation_plan
    from cveFeed.validation_authority import require_authority
    from cveFeed.correlation import latest_scan_q
    from cveFeed.models import CVEMatch, OnDemandValidation, ServiceRun, Triage
    from targetApp.target_types import scannable_hosts

    job = OnDemandValidation.objects.filter(pk=request_id, status='queued').first()
    if not job or not OnDemandValidation.objects.filter(pk=request_id, status='queued').update(
            status='running', started_at=timezone.now()):
        return {'skipped': 'request is no longer queued'}
    cve_id = CVEMatch.objects.filter(pk=job.match_id).values_list('cve_entry__cve_id', flat=True).first() or ''
    detail = {'request_id': job.pk, 'match_id': job.match_id}
    progress = activity.log('validate', f'Validation request #{job.pk} running for {cve_id}',
                            project=job.project_id, cve_id=cve_id, status='running', **detail)
    try:
        require_authority(job)
        owned = CVEMatch.objects.filter(pk=job.match_id, subdomain__target_domain__project_id=job.project_id)
        match = owned.filter(latest_scan_q('subdomain__')).select_related('cve_entry', 'subdomain__target_domain').first()
        if not match:
            # a rescan replaced the match while the job waited (or the host left the inventory): superseded work, not a worker failure.
            # The rescan's own match is queued by the next sweep, which does not count this job against it.
            return _skip_on_demand_validation(job, progress, cve_id, 'historical')
        if not match.subdomain or not scannable_hosts([match.subdomain.name], project=job.project_id):
            return _skip_on_demand_validation(job, progress, cve_id, 'out_of_scope')
        invalid_reason = correlation.invalid_identity_reason(match)
        if invalid_reason:
            correlation.close_invalid_correlation(match, invalid_reason)
            result = {'check_state': 'no_check', 'checks': {'ran': 0, 'reused': 0}, 'ai_state': 'not_needed',
                      'assessment_status': 'closed_not_applicable', 'assessment_reason': invalid_reason,
                      'check_notes': ['The product recorded for this host is not the software this advisory covers.']}
            OnDemandValidation.objects.filter(pk=job.pk, status='running').update(
                status='completed', result=result, finished_at=timezone.now())
            activity.settle(progress, 'done', f'Validation request #{job.pk}: {cve_id} closed ({correlation.closure_summary(invalid_reason)})',
                            check_state='no_check', ai_state='not_needed', assessment_status='closed_not_applicable')
            return result
        row = triage.track(triage.with_cves([match]))[0][0]
        row.review_nonce = str(job.pk)
        row.save(update_fields=['review_nonce', 'updated_at'])
        row, _ = triage.track(triage.with_cves([match]))[0]
        OnDemandValidation.objects.filter(pk=job.pk, status='running').update(evidence_signature=row.signature)
        subject = validation.subject_for(row, match)
        template = validation.resolve_template(match.cve_entry.cve_id)
        available_checks, plan_notes = validation.plan_checks(subject, row.signature, template)
        available_checks = [check for check in available_checks if check]
        planning = activity.log('confirm', f'Validation request #{job.pk}: choosing permitted checks for {cve_id}',
                                project=job.project_id, cve_id=cve_id, status='running', **detail)
        from cveFeed import host_context
        host = host_context.clipped(host_context.host_context(match.subdomain, job.project_id, focus=match.matched_product))
        plan, provider = validation_plan.plan(job.project_id, row, match.cve_entry, subject, available_checks, template, host=host)
        selected = set(plan['check_kinds'])
        checks = [check for check in available_checks if check['kind'] in selected]
        plans = [plan]
        activity.settle(planning, 'done', f'Validation request #{job.pk}: {plan["reason"]}',
                        check_kinds=plan['check_kinds'], plan_source=plan['source'])
        candidate = None
        if plan['generate_template']:
            draft_step = activity.log('write_check', f'Validation request #{job.pk}: testing an AI-written template draft for {cve_id}',
                                      project=job.project_id, cve_id=cve_id, status='running', **detail)
            candidate = validation_plan.generate_candidate(job.project_id, match.cve_entry, provider)
            activity.settle(draft_step, 'failed' if candidate['status'] in ('invalid', 'failed') else 'done',
                            f'Validation request #{job.pk}: template candidate {candidate["status"]}; '
                            'not run on the host', candidate_id=candidate.get('id'))
        if not checks and template[1] == 'no template covers this CVE':
            plan_notes.append('No permitted template covers this CVE; an AI draft requires reviewed positive fixture evidence before host execution.')
        if not checks:
            plan_notes.append(plan['reason'])
        if not any(check['kind'] == 'fact_probe' for check in available_checks):
            from cveFeed import probes
            plan_notes.append(probes.unaddressable(match.subdomain, match.cve_entry) or
                              'No version or identity probe applies: the host exposes no web service or service port to ask for this product.')
        # Refresh only this finding's planned checks, not other hosts that share its signature.
        for check in checks:
            ServiceRun.objects.filter(project_id=job.project_id, service=check['service'], asset=check['asset']).delete()
        row.validation_status, row.attempts, row.next_attempt_at = 'pending', 0, None
        row.save(update_fields=['validation_status', 'attempts', 'next_attempt_at', 'updated_at'])
        require_authority(job)
        check_result = validation.run_validation(job.project_id, [row.pk], selected_kinds=selected)
        # One bounded second decision uses observations from the first checks. A banner cannot end
        # the request while another already-approved, scoped check remains available.
        remaining = [check for check in available_checks if check['kind'] not in selected]
        if remaining and checks and not check_result.get('hits') and not check_result.get('stopped'):
            row.refresh_from_db()
            observations = [{'kind': step.get('kind'), 'result': step.get('result'), 'summary': step.get('summary')}
                            for step in (row.validation_steps or [])[-6:]]
            second_step = activity.log('confirm', f'Validation request #{job.pk}: reviewing observations and choosing the next check',
                                       project=job.project_id, cve_id=cve_id, status='running', **detail)
            second, provider = validation_plan.plan(job.project_id, row, match.cve_entry, subject, remaining, template,
                                                    provider=provider, observations=observations, host=host)
            next_kinds = set(second['check_kinds'])
            plans.append(second)
            activity.settle(second_step, 'done', f'Validation request #{job.pk}: {second["reason"]}',
                            check_kinds=second['check_kinds'], plan_source=second['source'])
            if second['generate_template'] and candidate is None:
                draft_step = activity.log('write_check', f'Validation request #{job.pk}: testing an AI-written template draft for {cve_id}',
                                          project=job.project_id, cve_id=cve_id, status='running', **detail)
                candidate = validation_plan.generate_candidate(job.project_id, match.cve_entry, provider)
                activity.settle(draft_step, 'failed' if candidate['status'] in ('invalid', 'failed') else 'done',
                                f'Validation request #{job.pk}: template candidate {candidate["status"]}; not run on the host',
                                candidate_id=candidate.get('id'))
            for check in remaining:
                if check['kind'] in next_kinds:
                    ServiceRun.objects.filter(project_id=job.project_id, service=check['service'], asset=check['asset']).delete()
            require_authority(job)
            next_result = validation.run_validation(job.project_id, [row.pk], selected_kinds=next_kinds) if next_kinds else {}
            for key in ('ran', 'reused', 'failed', 'blocked', 'capped', 'hits', 'no_check'):
                check_result[key] = check_result.get(key, 0) + next_result.get(key, 0)
            check_result['stopped'] = check_result.get('stopped') or next_result.get('stopped')
            checks += [check for check in remaining if check['kind'] in next_kinds]
        no_execution = not (check_result.get('ran') or check_result.get('reused'))
        no_check = no_execution and (bool(check_result.get('no_check')) or not checks)
        if no_execution and checks and not any(check_result.get(key) for key in ('failed', 'blocked', 'capped')):
            plan_notes.append('Planned checks did not execute; no validation coverage was established.')
        activity.log('validate', f'Validation request #{job.pk}: {check_result.get("ran", 0)} checks ran, '
                     f'{check_result.get("reused", 0)} reused, {check_result.get("capped", 0)} deferred'
                     + ('; no executable check available' if no_check else ''), project=job.project_id,
                     cve_id=cve_id, **detail)
        # Rebuild the signature after checks, so a fresh template hit is part of the AI review.
        match.refresh_from_db()
        row, described = triage.track(triage.with_cves([match]))[0]
        ai_progress = activity.log('confirm', f'Validation request #{job.pk}: AI review started for {cve_id}',
                                   project=job.project_id, cve_id=cve_id, status='running', **detail)
        try:
            require_authority(job)
            ai_result = triage.run_triage([(row, described)])
        except Exception:
            activity.settle(ai_progress, 'failed', f'Validation request #{job.pk}: AI review failed')
            raise
        row.refresh_from_db()
        ai_state = ('failed' if ai_result.get('errors') or row.status == 'error' else
                    'unavailable' if ai_result.get('not_triaged') or row.status == 'not_triaged' else
                    'deferred' if ai_result.get('queued') or row.status == 'pending' else 'completed')
        activity.settle(ai_progress, 'failed' if ai_state == 'failed' else 'done',
                        f'Validation request #{job.pk}: AI review {ai_state} for {cve_id}', ai_status=row.status)
        check_state = ('no_check' if no_check else 'not_run' if no_execution else
                       'observed' if row.validation_status == 'observed' else 'checked')
        if check_state == 'observed':
            plan_notes.append('The external checks observed service metadata only. They cannot identify software behind a frontend '
                              'or verify the affected product without specific evidence.')
        result = {'ai': ai_result, 'ai_state': ai_state, 'checks': check_result, 'check_state': check_state,
                  'plan': plan, 'plans': plans, 'template_candidate': candidate,
                  'check_notes': plan_notes, 'classification': row.classification or None,
                  'ai_status': row.status, 'validation_status': row.validation_status,
                  'assessment_status': 'unsupported_external' if no_check and not candidate else 'checked' if checks else 'inconclusive'}
        from cveFeed.hot_validation import retry_after
        broken = bool(check_result.get('failed') or check_result.get('blocked') or ai_state == 'failed')
        capped_only = bool(check_result.get('capped')) and not broken
        status = 'failed' if broken or capped_only else 'completed'  # capped: no coverage was established yet
        if capped_only:
            result['deferred_by_cap'] = True  # retried once the per-day caps reset, without spending an attempt
        OnDemandValidation.objects.filter(pk=job.pk, status='running').update(
            status=status, result=result, finished_at=timezone.now(),
            next_attempt_at=retry_after(job.attempts, capped_only) if status == 'failed' else None,
            error=('deferred until the daily validation cap resets' if capped_only else
                   'a check or AI review failed or was blocked') if status == 'failed' else '')
        activity.settle(progress, 'failed' if status == 'failed' else 'done',
                        f'Validation request #{job.pk} {status} for {cve_id}'
                        + ('; no executable check was available' if no_check else '; no check executed' if no_execution else '')
                        + f'; AI review {ai_state}', check_state=result['check_state'], ai_state=ai_state)
        return result
    except Exception as exc:
        logger.exception('on-demand validation %s failed', request_id)
        from cveFeed.hot_validation import retry_after
        OnDemandValidation.objects.filter(pk=job.pk, status='running').update(
            status='failed', error=activity.diagnostic(f'Validation request #{job.pk}', f'{type(exc).__name__}: {exc}',
                                                       type(exc).__name__)[:300], finished_at=timezone.now(),
            next_attempt_at=retry_after(job.attempts))
        activity.settle(progress, 'failed', f'Validation request #{job.pk} failed for {cve_id}: {type(exc).__name__}')
        return {'error': str(exc)[:200]}


@app.task(name='reconcile_invalid_correlations', bind=False, queue='cve_feed_queue')
def reconcile_invalid_correlations(limit=50):
    """Bounded, durable backfill of legacy product matches without running scans or spending AI calls."""
    from django.db import transaction
    from cveFeed import correlation
    from cveFeed.models import BackgroundCursor, CVEMatch

    batch_size = max(1, min(int(limit), 100))
    with transaction.atomic():
        cursor, _ = BackgroundCursor.objects.select_for_update().get_or_create(lane='invalid_correlation')
        base = CVEMatch.objects.filter(correlation.latest_scan_q('subdomain__')).select_related(
            'cve_entry', 'subdomain__target_domain').order_by('pk')
        batch = list(base.filter(pk__gt=cursor.last_pk)[:batch_size])
        if not batch:
            cursor.last_pk = 0
            batch = list(base[:batch_size])
        closed = 0
        for match in batch:
            if correlation.invalid_identity_reason(match):
                closed += int(correlation.close_invalid_correlation(match))
        if batch:
            cursor.last_pk = batch[-1].pk
        cursor.save(update_fields=['last_pk', 'updated_at'])
    return {'reviewed': len(batch), 'closed': closed, 'last_match_id': cursor.last_pk}


@app.task(name='queue_hot_validations', bind=False, queue='cve_feed_queue')
def queue_hot_validations():
    from cveFeed.hot_validation import sweep
    return sweep()


def _skip_automatic_validation(job, progress, reason):
    """A changed/closed finding is superseded work, not a broken validation worker."""
    from django.utils import timezone
    from cveFeed import activity
    from cveFeed.models import AutomaticValidation

    result = {'check_state': 'not_run', 'ai_state': 'not_run', 'reason': reason,
              'next_action': 'current evidence is eligible for the next validation sweep' if reason == 'evidence_changed'
                             else 'validation requires an open eligible finding'}
    AutomaticValidation.objects.filter(pk=job.pk, status='running').update(
        status='skipped', result=result, error='', next_attempt_at=None, finished_at=timezone.now())
    activity.settle(progress, 'done', f'Automatic validation #{job.pk} skipped: {reason.replace("_", " ")}',
                    check_state='not_run', ai_state='not_run', reason=reason)
    return result


@app.task(name='automatic_validate_finding', bind=False, queue='validation_priority_queue')
def automatic_validate_finding(job_id):
    """Review a persisted non-CVE finding; its owning project and target are never task arguments."""
    from django.utils import timezone
    from cveFeed import activity, hot_validation, triage, validation
    from cveFeed.validation_authority import require_authority
    from cveFeed.diagnostics import worker_failure
    from cveFeed.models import AutomaticValidation, Triage
    from targetApp.target_types import scannable_hosts

    job = AutomaticValidation.objects.filter(pk=job_id, status='queued').first()
    if not job or not AutomaticValidation.objects.filter(pk=job_id, status='queued').update(
            status='running', started_at=timezone.now()):
        return {'skipped': 'request is no longer queued'}
    label = 'Manual' if job.source == 'manual' else 'Automatic'
    progress = activity.log('validate', f'{label} validation #{job.pk} running for finding #{job.triage_id}',
                            project=job.project_id, status='running', job_id=job.pk, finding_id=job.triage_id)
    stage = 'load_finding'
    try:
        require_authority(job)
        from cveFeed.conductor import bounty_blocked_projects
        if job.source != 'manual' and job.project_id in bounty_blocked_projects():  # only a person's own request runs in a bug bounty project that has not confirmed automated testing
            return _skip_automatic_validation(job, progress, 'bounty_not_confirmed')
        row = Triage.objects.get(pk=job.triage_id, project_id=job.project_id)
        fresh_row = Triage.objects.select_related(
            'match__cve_entry', 'vulnerability__target_domain', 'route', 'hygiene__domain').get(pk=row.pk)
        if not (hot_validation.manual_eligible(fresh_row) if job.source == 'manual' else hot_validation.tier_for(fresh_row)):
            return _skip_automatic_validation(job, progress, 'no_longer_eligible')
        stage = f'load_{row.kind}'
        findings = triage.load_findings([row])
        if not findings:
            return _skip_automatic_validation(job, progress, 'finding_removed')
        finding = findings[0]
        stage = f'describe_{row.kind}'
        pairs = triage.track([finding])
        if not pairs or pairs[0][0].project_id != job.project_id or pairs[0][0].signature != job.signature:
            return _skip_automatic_validation(job, progress, 'evidence_changed')
        row, described = pairs[0]
        stage = 'scope_check'
        if row.host and not scannable_hosts([row.host], project=job.project_id):
            return _skip_automatic_validation(job, progress, 'out_of_scope')
        # This is a new automatic assessment of the current evidence. A prior shared verdict
        # must not short circuit its AI review, while later sweeps still deduplicate this job.
        row.review_nonce = str(job.pk)
        row.save(update_fields=['review_nonce', 'updated_at'])
        row, described = triage.track([finding])[0]
        AutomaticValidation.objects.filter(pk=job.pk, status='running').update(signature=row.signature)
        check_state = 'no_check'
        checks = {'ran': 0, 'reused': 0, 'no_check': 1}
        stage = 'approved_checks'
        if row.kind in validation.PLANNED_KINDS:
            activity.log('validate', f'Automatic validation #{job.pk}: running approved checks',
                         project=job.project_id, job_id=job.pk, finding_id=row.pk)
            require_authority(job)
            checks = validation.run_validation(job.project_id, [row.pk])
            row.refresh_from_db()
            check_state = ('no_check' if checks.get('no_check') and not checks.get('ran') else
                           'observed' if row.validation_status == 'observed' else
                           'checked' if checks.get('ran') or checks.get('reused') else 'not_run')
        else:
            activity.log('validate', f'Automatic validation #{job.pk}: no approved external check for {row.kind}',
                         project=job.project_id, job_id=job.pk, finding_id=row.pk, check_state='no_check')
        findings = triage.load_findings([row])
        row, described = triage.track(findings)[0]
        stage = 'ai_review'
        activity.log('confirm', f'Automatic validation #{job.pk}: AI review started', project=job.project_id,
                     job_id=job.pk, finding_id=row.pk)
        require_authority(job)
        ai = triage.run_triage([(row, described)])
        row.refresh_from_db()
        ai_state = ('failed' if ai.get('errors') or row.status == 'error' else
                    'unavailable' if ai.get('not_triaged') or row.status == 'not_triaged' else
                    'deferred' if ai.get('queued') or row.status == 'pending' else 'completed')
        result = {'checks': checks, 'check_state': check_state, 'ai': ai, 'ai_state': ai_state,
                  'classification': row.classification, 'validation_status': row.validation_status,
                  'priority': job.priority}
        broken = any(checks.get(key) for key in ('failed', 'blocked')) or ai_state == 'failed'
        capped_only = bool(checks.get('capped')) and not broken
        failed = broken or capped_only
        status = 'failed' if failed else 'completed'
        if capped_only:
            result['deferred_by_cap'] = True  # retried once the per-day caps reset, without spending an attempt
        retry_at = hot_validation.retry_after(job.attempts, capped_only) if failed else None  # None once the attempts are spent
        AutomaticValidation.objects.filter(pk=job.pk, status='running').update(
            status=status, result=result, finished_at=timezone.now(),
            next_attempt_at=retry_at, error='a check or AI review failed or was deferred by a cap' if failed else '')
        activity.settle(progress, 'failed' if failed else 'done',
                        f'Automatic validation #{job.pk} {status}: checks {check_state}; AI {ai_state}',
                        check_state=check_state, ai_state=ai_state)
        return result
    except Exception as exc:
        diagnostic = worker_failure(exc, stage=stage, job_id=job.pk, finding_id=job.triage_id,
                                    finding_kind=getattr(row, 'kind', None) if 'row' in locals() else None)
        logger.error('automatic validation %s failed at %s (%s; diagnostic %s)',
                     job.pk, stage, diagnostic['category'], diagnostic['id'])
        retry_at = hot_validation.retry_after(job.attempts)
        AutomaticValidation.objects.filter(pk=job.pk, status='running').update(
            status='failed', error=f'{stage}: {diagnostic["category"]}; diagnostic {diagnostic["id"]}',
            result={'ai_state': 'failed', 'diagnostic': diagnostic}, next_attempt_at=retry_at, finished_at=timezone.now())
        activity.settle(progress, 'failed', f'Automatic validation #{job.pk} failed at {stage} ({diagnostic["category"]}); diagnostic {diagnostic["id"]}',
                        stage=stage, diagnostic=diagnostic, retry_at=retry_at.isoformat() if retry_at else None)
        return {'error': 'automatic validation failed', 'diagnostic': diagnostic,
                'retry_at': retry_at.isoformat() if retry_at else None}


@app.task(name="triage_pending", bind=False, queue="cve_feed_queue")
def triage_pending(project_id=None):
    """Triage the findings that still wait (queued over a cap, a provider error, no provider before): one project, or all, oldest
    first and within the triage caps (see cveFeed.triage.sweep)."""
    from cveFeed import triage
    try:
        return triage.sweep(project_id)
    except Exception as exc:  # noqa: BLE001
        logger.exception("triage sweep failed")
        return {"error": str(exc)[:200]}


@app.task(name="triage_sweep", bind=False, queue="cve_feed_queue")
def triage_sweep():
    """Daily: triage the waiting findings of every project, one project at a time so the per-project cap is honoured. Idempotent: a
    second sweep inside half an hour (or while another runs) does nothing."""
    from cveFeed import ledger
    from dashboard.models import Project
    if not ledger.sweep_claim("triage", 1800):
        return {"projects": 0, "skipped": "another sweep is running"}
    done = 0
    for project_id in Project.objects.values_list("id", flat=True):
        triage_pending(project_id)
        done += 1
    return {"projects": done}


@app.task(name="validate_sweep", bind=False, queue="cve_feed_queue")
def validate_sweep():
    """Daily: queue the validation checks that are due, one task per project: findings never checked, checks over a cap earlier,
    failed ones whose retry time has come, and findings last validated longer ago than CVENGINE_TTL_VALIDATE (24 hours)."""
    from cveFeed import ledger, validation
    from dashboard.models import Project
    if not ledger.sweep_claim("validate", 1800):
        return {"queued": 0, "skipped": "another sweep is running"}
    queued = 0
    from cveFeed.conductor import bounty_blocked_projects
    for project_id in Project.objects.exclude(pk__in=bounty_blocked_projects()).values_list("id", flat=True):  # not a bug bounty project that has not confirmed automated testing
        ids = validation.due_ids(project_id)
        if ids:
            validate_findings.delay(project_id, ids)
            queued += 1
    return {"queued": queued}


@app.task(name="run_hygiene", bind=False, queue="cve_feed_queue")
def run_hygiene_task(domain_id):
    """Certificate, TLS and SPF/DKIM/DMARC review of one target (see cveFeed.hygiene)."""
    from cveFeed.hygiene import run_hygiene
    result = run_hygiene(domain_id)
    from cveFeed import archive_urls
    archive_urls.run_for_domain(domain_id)  # passive and weekly (ledger); never raises
    return result


HYGIENE_SWEEP_MAX = 500


@app.task(name="run_hygiene_all", bind=False, queue="cve_feed_queue")
def run_hygiene_all():
    """Daily sweep: queue a hygiene check for each target not checked in the last 24 hours, oldest first, up to
    HYGIENE_SWEEP_MAX, so expiring certificates are caught before they expire."""
    from cveFeed import ledger
    from targetApp.models import Domain
    if not ledger.sweep_claim('hygiene', 1800):
        return {"queued": 0, "skipped": "another sweep is running"}
    from cveFeed.conductor import bounty_blocked_projects
    due = ledger.stale_first('hygiene', Domain.objects.exclude(project_id__in=bounty_blocked_projects()).values_list("id", "name", "project_id"))  # not a bug bounty project that has not confirmed automated testing
    for domain_id, _name, _project in due[:HYGIENE_SWEEP_MAX]:
        run_hygiene_task.delay(domain_id)
    return {"queued": min(len(due), HYGIENE_SWEEP_MAX), "due": len(due)}


@app.task(name="watch_certificate_transparency", bind=True, queue="ctwatch_queue")
def watch_certificate_transparency(self, domain_id):
    """Check one target against crt.sh for hosts not already known (see cveFeed.ctmonitor). When crt.sh could not be reached
    (rate limit, timeout) the check is tried again later instead of the target being skipped. It has a queue of its own, off the
    feed queue that runs the work conductor, the reaper and the Sentinel feed: hundreds of lookups wait behind one shared rate limit,
    and a lookup that would sleep longer than a moment inside a slot goes back to the queue instead (``ctmonitor.CtBusy``)."""
    import random

    from cveFeed.ctmonitor import CtBusy, run_ct_watch
    try:
        result = run_ct_watch(domain_id)
    except CtBusy as busy:  # waiting for crt.sh's pacing is not a failure: it is asked again when the slot is due, with no slot held meanwhile
        raise self.retry(exc=busy, countdown=int(busy.wait) + random.randint(1, 60), max_retries=None)
    if result.get("failed") and self.request.retries < 3:
        raise self.retry(countdown=600 * (self.request.retries + 1), max_retries=3)
    return result


@app.task(name="watch_certificates_all", bind=False, queue="cve_feed_queue")
def watch_certificates_all():
    """Periodic sweep: every target is "subscribed" to certificate-transparency monitoring this way. Targets checked in the
    last 24 hours are skipped; the rest go oldest first, as many as fit in one interval (a check starts every ~3 seconds)."""
    from cveFeed import ledger
    from dashboard.models import SystemTimings
    from targetApp.models import Domain
    from targetApp.shared_domains import is_provider_domain
    from targetApp.target_types import IP, classify_target
    window = SystemTimings.current().ct_watch_minutes * 60
    if not ledger.sweep_claim('ct-watch', int(window * 0.8)):
        return {"queued": 0, "skipped": "another sweep is running"}
    # crt.sh has nothing on a bare IP, so only names are asked about
    # nor on a bare shared provider domain (jfrog.com): a tenant's host under it is watched, the provider's whole tree is not
    from cveFeed.conductor import bounty_blocked_projects
    blocked = bounty_blocked_projects()  # a bug bounty project that has not confirmed automated testing is not watched on its own
    rows = [r for r in Domain.objects.values_list("id", "name", "project_id")
            if classify_target(r[1]) != IP and not is_provider_domain(r[1]) and r[2] not in blocked]
    due = ledger.stale_first('ct-watch', rows)
    batch = due[:max(1, window // 3)]
    for i, (domain_id, _name, _project) in enumerate(batch):  # spread out: crt.sh blocks a burst, so each check starts a couple of seconds after the last
        watch_certificate_transparency.apply_async(args=[domain_id], countdown=int(i * 2.5))
    return {"queued": len(batch), "due": len(due)}


DUPLICATE_RETRIES = 3  # times a discovery message that found its own scan's lock held is asked again (run_bbot_discovery)


@app.task(name="run_bbot_discovery", bind=True, queue="discovery_queue", acks_late=True, reject_on_worker_lost=True)
def run_bbot_discovery(self, scan_id, mode="standard"):
    """Discover the scan's target with bbot, then nuclei over what was found (see cveFeed.discovery)."""
    from cveFeed.discovery import run_pipeline
    from startScan.models import ScanHistory
    if self.request.id:  # a stop revokes this id; a task still queued has none yet and is skipped when it starts
        ScanHistory.objects.filter(pk=scan_id).update(celery_ids=[self.request.id])
    out = run_pipeline(scan_id, mode)
    if out.get('status') == 'duplicate' and self.request.id and self.request.retries < DUPLICATE_RETRIES:
        # The queue gave this message back after a worker was killed (acks_late), and the dead worker's lock on the target is still alive for up
        # to LOCK_TTL seconds: acking it would leave the scan "running" with nothing behind it. Ask again once that lock would have expired; if
        # it was a live twin instead, the scan has ended by then (or it is still running and this asks again, a few times).
        from cveFeed.discovery import LOCK_TTL
        raise self.retry(countdown=LOCK_TTL + 15, max_retries=DUPLICATE_RETRIES)
    return out


@app.task(name="run_internal_scan", bind=True, queue="discovery_queue", acks_late=True, reject_on_worker_lost=True)
def run_internal_scan(self, scan_id):
    """Scan an internal target through a Sentinel inside its network, never from this server (see cveFeed.internal_scan)."""
    from cveFeed import internal_scan
    from startScan.models import ScanHistory
    if self.request.id:
        ScanHistory.objects.filter(pk=scan_id).update(celery_ids=[self.request.id])
    return internal_scan.run(scan_id)


@app.task(name="internal_scan_sweep", bind=False, queue="cve_feed_queue")
def internal_scan_sweep():
    """Daily: queue an internal scan of every declared-internal target not scanned inside CVENGINE_INTERNAL_SCAN_DAYS (default 7), in
    projects where a live network:internal Sentinel could take the work."""
    from cveFeed import internal_scan
    return internal_scan.sweep()


@app.task(name="run_internal_discovery", bind=False, queue="discovery_queue")
def run_internal_discovery(range_id):
    """Sweep one declared internal range for live hosts through a Sentinel inside it (``cveFeed.internal_discovery``). It waits on a Sentinel for each
    of up to 64 chunks, so it runs on the discovery queue like ``run_internal_scan``: on the four-slot feed queue a few ranges would keep the
    conductor, the Sentinel feed and the reaper from running for hours."""
    from cveFeed import internal_discovery
    return internal_discovery.discover_range(range_id)


@app.task(name="internal_discovery_sweep", bind=False, queue="cve_feed_queue")
def internal_discovery_sweep():
    """Daily: queue a host discovery of every declared internal range not swept inside CVENGINE_INTERNAL_DISCOVERY_DAYS (default 7), in
    projects where a live network:internal Sentinel that declares ``discover`` could take the work."""
    from cveFeed import internal_discovery
    return internal_discovery.sweep()


DEEP_SWEEP_MAX = 50  # apexes queued per run (CVENGINE_DEEP_SWEEP_MAX)
DEEP_SWEEP_PER_PROJECT = 10  # of them, at most this many for one project (CVENGINE_DEEP_SWEEP_PER_PROJECT)


@app.task(name="deep_scan_apexes", bind=False, queue="cve_feed_queue")
def deep_scan_apexes():
    """Daily: queue a deep discovery of every apex domain (``example.com``, ``example.co.uk``) that has not had one inside
    the week (CVENGINE_TTL_BBOT_DEEP). The apex is the registrable domain of each domain target, per project, and is added
    as a target when only its subdomains were. Oldest first, at most CVENGINE_DEEP_SWEEP_MAX per run, and an apex whose
    discovery is already queued or running counts as covered. Deep discovery is the thorough one: everything else is
    discovered in standard mode.

    Scope: only an apex the user plausibly owns is promoted. A host-scoped target (a tenant on a shared provider domain such
    as ``acme.jfrog.com``, a shared domain added directly, or scope_mode='host') is skipped entirely: it is covered by
    normal discovery and the provider's apex (``jfrog.com``) is never created or scanned. scope_mode='parent' forces the
    promotion for a user who really controls the parent."""
    from django.utils import timezone

    from cveFeed import activity, ledger
    from cveFeed.counts import running_window
    from cveFeed.discovery import FAILED, HOST_PIPELINE_TASK, QUEUED, RUNNING, start_discoveries
    from startScan.models import ScanHistory
    from targetApp.models import Domain
    from targetApp.shared_domains import effective_apex, is_shared_apex
    from targetApp.target_types import DOMAIN, apex_domain, classify_target

    try:
        cap = max(1, int(os.environ.get("CVENGINE_DEEP_SWEEP_MAX", DEEP_SWEEP_MAX)))
    except ValueError:
        cap = DEEP_SWEEP_MAX
    if not ledger.sweep_claim("deep-apex", 1800):
        return {"queued": 0, "skipped": "another sweep is running"}
    from cveFeed.models import BountyEngagement
    # a bug bounty project is never widened to a parent domain (the program's scope names what may be tested, and a Domain target counts as
    # a person's confirmation of it) and, until its owner confirmed automated testing, not deep-scanned either
    engaged = set(BountyEngagement._base_manager.values_list("project_id", flat=True))
    rows = list(Domain.objects.exclude(project=None).exclude(project_id__in=engaged).values_list("id", "name", "project_id", "scope_mode").order_by("id"))
    own = {(project_id, name): domain_id for domain_id, name, project_id, _mode in rows}  # a project's own row for a name
    from cveFeed.exclusions import excluded_names
    banned_by_project = {}  # project id -> the names its organization excluded for good (one read per project)

    def excluded(project_id, name):
        if project_id not in banned_by_project:
            banned_by_project[project_id] = excluded_names(project_id)
        return name.lower().rstrip(".") in banned_by_project[project_id]
    wanted = {}  # (project id, apex) -> the project's own Domain row for it, if there is one
    forced = set()  # apexes a target asked for with scope_mode='parent': promoted even when on the shared list
    for _domain_id, name, project_id, mode in rows:
        if classify_target(name) != DOMAIN or mode == Domain.SCOPE_HOST:
            continue  # scope_mode='host': never promoted to a parent
        if mode == Domain.SCOPE_PARENT:
            apex = apex_domain(name)
            if apex:
                forced.add((project_id, apex))
        else:
            # A tenant on a shared provider domain (acme.jfrog.com), or a shared domain added directly (jfrog.com), is
            # host scoped: it has no ownable parent, so the sweep skips it (normal discovery covers it) and never
            # creates or scans the provider's apex.
            apex, host_scoped = effective_apex(name)
            if host_scoped:
                continue
        if apex and not excluded(project_id, apex):  # an excluded apex is never promoted, queued or scanned
            wanted.setdefault((project_id, apex), own.get((project_id, apex)))
    due = ledger.stale_first("bbot-deep", [(key, key[1], key[0]) for key in wanted])
    busy = set(ScanHistory.objects.filter(
        scan_status__in=(QUEUED, RUNNING), start_scan_date__gte=timezone.now() - running_window(),
        domain__name__in={key[1] for key in wanted}).exclude(tasks__contains=[HOST_PIPELINE_TASK]).values_list("domain__name", "domain__project_id"))
    try:
        per_project = max(1, int(os.environ.get("CVENGINE_DEEP_SWEEP_PER_PROJECT", DEEP_SWEEP_PER_PROJECT)))
    except ValueError:
        per_project = DEEP_SWEEP_PER_PROJECT
    todo, taken = [], {}
    for key, apex, project_id in due:  # oldest first, but one project's apexes cannot fill the whole run: the others wait behind them otherwise
        if (apex, project_id) in busy or taken.get(project_id, 0) >= per_project:
            continue
        taken[project_id] = taken.get(project_id, 0) + 1
        todo.append(key)
        if len(todo) >= cap:
            break
    domains, skipped = [], 0
    for project_id, apex in todo:
        domain = Domain.objects.filter(pk=wanted[(project_id, apex)]).first() if wanted[(project_id, apex)] else None
        if domain is not None and excluded(project_id, domain.name):
            skipped += 1
            continue
        if domain is None:
            if (project_id, apex) not in forced and is_shared_apex(apex):  # belt and braces: a provider apex is never created
                skipped += 1
                continue
            from targetApp.models import org_domains
            if org_domains(project_id).filter(name=apex).exists():  # names are unique within an organization: another project of it holds this
                skipped += 1
                continue
            domain = Domain.objects.create(name=apex, project_id=project_id, insert_date=timezone.now(),
                                           description="Added for the weekly deep discovery of its subdomains")
        domains.append(domain)
    scans = start_discoveries(domains, "deep", quiet=True) if domains else []
    for project_id in {d.project_id for d in domains}:
        count = sum(1 for d in domains if d.project_id == project_id)
        activity.log("discovery", f"Weekly deep discovery: queued {count} apex domain{'s' if count != 1 else ''}", project=project_id)
    return {"queued": len(scans), "due": len(due), "skipped": skipped}


@app.task(name="work_conductor", bind=False, queue="cve_feed_queue")
def work_conductor():
    """Every minute: keep the discovery queue topped up with the most overdue targets (see cveFeed.conductor)."""
    from cveFeed import conductor
    return conductor.keep_work_queued()


@app.task(name="host_pipeline", bind=True, queue="discovery_queue")
def host_pipeline(self, domain_id, names, by_person=False):
    """New hosts of a target (found by certificate transparency or named by an agent) through nmap, the exposure check,
    nuclei and correlation, without a bbot run (see cveFeed.discovery.run_host_pipeline). ``by_person`` is set only by a rescan a
    person asked for; everything else is held to the bug bounty confirmation."""
    from cveFeed.discovery import run_host_pipeline
    return run_host_pipeline(domain_id, names, celery_id=self.request.id, by_person=by_person)


@app.task(name='assess_host', bind=True, queue='discovery_queue')
def assess_host(self, assessment_id):
    """Execute one stored, scope-checked host assessment; the broker carries no target text."""
    from cveFeed.host_assessment import execute
    return execute(assessment_id, celery_id=self.request.id)


@app.task(name="retest_hosts", bind=True, queue="discovery_queue")
def retest_hosts(self, domain_id, names, source_scan_id=None, deferred_ids=None):
    """Hosts that just changed, through the host pipeline again with the CVE checks forced (see cveFeed.retest)."""
    from datetime import timedelta
    from django.utils import timezone
    from cveFeed.discovery import SUCCESS, run_host_pipeline
    from cveFeed.models import DeferredRetest
    from cveFeed import ledger, retest
    from cveFeed.bounty_gate import Gate
    from targetApp.models import Domain
    if Gate().project_blocked(Domain.objects.values_list('project_id', flat=True).filter(pk=domain_id).first()):  # a bug bounty project that has not confirmed automated testing
        DeferredRetest.objects.filter(pk__in=deferred_ids or [], domain_id=domain_id).update(status='failed', updated_at=timezone.now())
        return {'status': 'skipped', 'error': 'the bug bounty engagement has not confirmed automated testing'}
    rows = list(DeferredRetest.objects.filter(pk__in=deferred_ids or [], domain_id=domain_id,
                                              status__in=['dispatching', 'queued']))
    if deferred_ids and len(rows) != len(set(deferred_ids)):
        return {'status': 'skipped', 'error': 'retest request is stale'}
    if rows and DeferredRetest.objects.filter(pk__in=[r.pk for r in rows], status__in=['dispatching', 'queued']).update(
            status='running', updated_at=timezone.now()) != len(rows):
        return {'status': 'skipped', 'error': 'retest request was already claimed'}
    try:
        outcome = run_host_pipeline(domain_id, names, celery_id=self.request.id, retest=True, source_scan_id=source_scan_id)
    except Exception as exc:
        logger.exception('retest host pipeline failed')
        outcome = {'status': 'failed', 'error': str(exc)[:200]}
    if rows:
        good = outcome.get('status') == SUCCESS and not outcome.get('error')
        if good:
            DeferredRetest.objects.filter(pk__in=[r.pk for r in rows]).update(status='done', updated_at=timezone.now())
            ledger.record(retest.RETEST_SERVICE, [r.host for r in rows], rows[0].project_id, outcome.get('scan_id'))
        else:
            for row in rows:
                if row.attempts >= 3:
                    status, next_at = 'failed', timezone.now()
                else:
                    status, next_at = 'pending', timezone.now() + timedelta(minutes=5 * (2 ** max(0, row.attempts - 1)))
                DeferredRetest.objects.filter(pk=row.pk).update(status=status, next_attempt_at=next_at, updated_at=timezone.now())
    elif not deferred_ids:
        from targetApp.models import Domain
        project_id = Domain.objects.values_list('project_id', flat=True).get(pk=domain_id)
        ledger.record(retest.RETEST_SERVICE, names, project_id, outcome.get('scan_id'),
                      status='done' if outcome.get('status') == SUCCESS and not outcome.get('error') else 'failed')
    return outcome


@app.task(name="retest_sweep", bind=False, queue="cve_feed_queue")
def retest_sweep():
    from cveFeed.retest import dispatch_deferred_retests
    return dispatch_deferred_retests()


@app.task(name='weekly_deep_nuclei', bind=False, queue='cve_feed_queue')
def weekly_deep_nuclei():
    """Pace one current, in-scope host through the approved broad template set.

    Beat calls this every ten minutes. A global renewable claim prevents a slow run
    from overlapping another. The cursor and successful-only seven-day ledger make
    progress durable without queuing thousands of deep jobs at once.
    """
    from cveFeed import activity, ledger, nuclei_scan
    from cveFeed.correlation import latest_scan_q
    from cveFeed.models import BackgroundCursor, HostState
    from django.db.models import Exists, OuterRef
    from startScan.models import Subdomain
    from targetApp.target_types import scannable_hosts
    from django.db import transaction
    from django.utils import timezone

    with ledger.claim('weekly-deep-nuclei', 'global') as won:
        if not won:
            return {'status': 'busy'}
        with transaction.atomic():
            cursor, _ = BackgroundCursor.objects.select_for_update().get_or_create(lane='weekly_nuclei')
            archived = HostState.objects.filter(project_id=OuterRef('target_domain__project_id'), host=OuterRef('name'),
                                                archived_at__isnull=False)
            from cveFeed.bounty_gate import Gate
            gate = Gate()  # a bug bounty project that has not confirmed automated testing is not swept; a host outside its scope is never a target
            base = Subdomain.objects.filter(scan_history__scan_status=2, target_domain__project__isnull=False).exclude(
                target_domain__project_id__in=gate.blocked).filter(latest_scan_q()).filter(~Exists(archived)).select_related(
                'scan_history__domain', 'target_domain').order_by('pk')
            rows = list(base.filter(pk__gt=cursor.last_pk)[:100])
            if not rows:
                cursor.last_pk = 0
                rows = list(base[:100])
            if not rows:
                cursor.save(update_fields=['last_pk', 'updated_at'])
                return {'status': 'no_inventory'}
        try:
            revision = nuclei_scan.approved_templates()[1]
        except Exception:
            logger.exception('weekly deep Nuclei has no approved template library')
            return {'status': 'failed', 'error': 'approved template library unavailable'}
        host_service = f'nuclei-deep-host:{revision}'
        target_service = f'nuclei-deep-target:{revision}'
        for sub in rows:
            project_id = sub.target_domain.project_id
            if sub.name in ledger.fresh(host_service, [sub.name], project_id):
                continue
            if not scannable_hosts([sub.name], project=project_id) or gate.refusal(project_id, sub.name):
                continue
            hostnames, _ips, ports = nuclei_scan.scan_targets(sub.scan_history)
            if sub.name not in hostnames:
                continue
            targets = [sub.name] + [f'{sub.name}:{port}' for host, port in sorted(ports)
                                    if host == sub.name and port not in nuclei_scan.DEFAULT_PORTS][:20]
            BackgroundCursor.objects.filter(lane='weekly_nuclei').update(last_pk=sub.pk, updated_at=timezone.now())
            run = activity.log('run_check', f'Weekly deep Nuclei checking {sub.name} ({len(targets)} targets)',
                               project=project_id, status='running', scan_id=sub.scan_history_id)
            try:
                from agentapi import sentinel_dispatch
                stream = sentinel_dispatch.wrap_nuclei_stream(sub.scan_history, 'nuclei_deep')
                outcome = nuclei_scan.run_nuclei(sub.scan_history_id, targets=targets, service_override=target_service, stream=stream)
                if outcome.get('error'):
                    activity.settle(run, 'failed', f'Weekly deep Nuclei failed on {sub.name}: {str(outcome["error"])[:180]}')
                    return {'status': 'failed', 'host': sub.name, 'error': 'Nuclei execution failed'}
                ledger.record(host_service, [sub.name], project_id, sub.scan_history)
                activity.settle(run, 'done', f'Weekly deep Nuclei completed on {sub.name}: {outcome.get("findings", 0)} new findings')
                return {'status': 'done', 'host': sub.name, 'targets': len(targets), 'findings': outcome.get('findings', 0)}
            except Exception:
                logger.exception('weekly deep Nuclei failed on host %s', sub.pk)
                activity.settle(run, 'failed', f'Weekly deep Nuclei failed on {sub.name}; see worker diagnostics')
                return {'status': 'failed', 'host': sub.name, 'error': 'Nuclei execution failed'}
        BackgroundCursor.objects.filter(lane='weekly_nuclei').update(last_pk=rows[-1].pk, updated_at=timezone.now())
        return {'status': 'no_due_host', 'reviewed': len(rows)}


@app.task(name="background_full_scan", bind=False, queue="cve_feed_queue")
def background_full_scan():
    """Every few minutes: sweep all 65,535 TCP ports of the one in-scope IP that was swept longest ago (never-swept first), under
    the lowest-priority heavy job, and let only one such sweep run at a time (see cveFeed.fullscan). CVENGINE_FULLSCAN=0 turns it off."""
    from cveFeed import fullscan, udp_scan
    result = fullscan.run()
    udp_scan.kick()  # the UDP sweep rides this firing, on a queue and a switch of its own
    return result


@app.task(name='udp_scan_sweep', bind=False, queue='udp_queue')
def udp_scan_sweep():
    """Queued by the background full scan's firing: UDP-scan the in-scope IPs that are due, one at a time, slowly (see ``cveFeed.udp_scan``).
    It has a queue of its own so a sweep that waits on silent UDP ports never holds up the feed workers."""
    from cveFeed import udp_scan
    return udp_scan.run()


@app.task(name="check_for_updates", bind=False, queue="cve_feed_queue")
def check_for_updates():
    """Twice a day: ask GitHub whether a newer version exists. An administrator decides whether to apply it
    (banner + Settings > Updates). Nothing is approved from here unless they chose Automatic there; the default is Manual."""
    from cveFeed import updater
    from cveFeed.models import UpdateSettings
    row = UpdateSettings.current()
    if not row.enabled:
        return {"status": "disabled"}
    before = row.latest_sha
    updater.check(row)
    state = updater.state(row)
    if state["status"] == "available" and row.latest_sha != before:
        from dashboard.models import AuditLog
        AuditLog.objects.create(actor=None, actor_name="updater", action="update.available", target=row.latest_sha[:7],
                                detail={"message": row.latest_message, "behind_by": row.behind_by})
    if updater.auto_approve(row):  # only when the administrator chose Automatic in Settings > Updates; the default is Manual
        from dashboard.models import AuditLog
        AuditLog.objects.create(actor=None, actor_name="updater", action="update.approved", target=row.latest_sha[:7],
                                detail={"message": row.latest_message, "behind_by": row.behind_by, "mode": "automatic"})
        state = updater.state(row)
    return {"status": state["status"], "latest": state["latest"]}


@app.task(name="feed_sentinels", bind=False, queue="cve_feed_queue")
def feed_sentinels():
    """Every minute: keep twice the Sentinels' slots of work queued behind what they are running (see ``cveFeed.coverage_topup.feed_sentinels``)."""
    from cveFeed import coverage_topup
    return coverage_topup.feed_sentinels()


@app.task(name="refresh_sentinel_version", bind=False, queue="cve_feed_queue")
def refresh_sentinel_version():
    """A few times a day (and once when a page finds nothing cached): ask GitHub for the latest Sentinel client version and how far behind each
    reported version is, for the version column of the Sentinels page (see ``agentapi.sentinel_version``)."""
    from agentapi import sentinel_version
    out = sentinel_version.refresh()
    return {"latest": (out.get("sha") or "")[:12], "error": out.get("error", "")}


@app.task(name="update_nuclei_templates", bind=False, queue="cve_feed_queue")
def update_nuclei_templates():
    """Daily: pull the current nuclei templates. CVEngine's own scans run nuclei with -duc (no update check), so without
    this the template set stays as old as the first image build and newer checks never run."""
    import subprocess
    from cveFeed import activity
    try:
        proc = subprocess.run(["nuclei", "-update-templates", "-silent", "-nc"], capture_output=True, text=True, timeout=900, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("nuclei template update failed: %s", exc)
        return {"updated": False, "error": str(exc)[:200]}
    # the line that says what happened, not a warning nuclei prints about its JSON library on a newer Go release (it was recorded as the result)
    lines = [line.strip() for line in (proc.stdout + proc.stderr).splitlines() if line.strip()]
    said = [line for line in lines if not re.match(r"(?:\[wrn\]|(?:warning|warn)\b)", line, re.I)]
    tail = said[-1:] or ["ran with no message (the templates were already current)" if proc.returncode == 0 else "no message"]
    from cveFeed.templategen import invalidate_template_index
    invalidate_template_index()
    try:  # system_status judges the refresh on this, not on the age of the files (they only change when a release is published)
        from django.core.cache import cache
        from django.utils import timezone
        from agentapi.system_status import TEMPLATE_REFRESH_KEY
        cache.set(TEMPLATE_REFRESH_KEY, {'at': timezone.now().isoformat(), 'ok': proc.returncode == 0, 'result': tail[0][:200]}, None)
    except Exception:  # noqa: BLE001 - recording the outcome never fails the refresh
        logger.warning("could not record the nuclei template refresh", exc_info=True)
    if proc.returncode == 0:
        activity.log("feed", "Updated the nuclei templates", detail_line=tail[0][:200])
    else:
        logger.warning("nuclei -update-templates exited %s: %s", proc.returncode, tail[0])
    return {"updated": proc.returncode == 0, "returncode": proc.returncode}


@app.task(name='runzero_sync_due', bind=False, queue='cve_feed_queue')
def runzero_sync_due():
    """Queue a runZero sync for every project with a token that is due one (CVENGINE_RUNZERO_SYNC_HOURS, default 6). Starts are
    spread a few seconds apart: runZero limits how fast one source address may call it."""
    from cveFeed import runzero_sync
    ids = runzero_sync.due_project_ids()
    for i, project_id in enumerate(ids):
        runzero_sync_project.apply_async(args=[project_id], countdown=i * 5)
    return {'queued': len(ids)}


@app.task(name='runzero_sync_project', bind=False, queue='cve_feed_queue')
def runzero_sync_project(project_id):
    from cveFeed import runzero_sync
    from dashboard.models import Project
    project = Project.objects.filter(pk=project_id).first()
    return runzero_sync.sync_project(project) if project else {'state': 'error', 'error': 'project not found', 'counts': {}}


@app.task(name="author_cve_detections", bind=False, queue="cve_feed_queue")
def author_cve_detections():
    """Every 30 minutes: write the shared detection record of every CVE that has none (hottest first, so new CVEs and the back
    catalogue are covered the same way), refresh rules-written checks whose CVE changed, and spend the daily AI budget on the
    CVEs attackers use. See cveFeed.detection and cveFeed.detection_author."""
    from cveFeed import detection_author
    from reNgine.ai_settings import get_configured_provider
    try:
        provider = get_configured_provider()
    except Exception:  # noqa: BLE001 - AI is optional; the rules author still runs
        logger.warning("could not build the AI provider for detection authoring", exc_info=True)
        provider = None
    rules_first = detection_author.author_all_rules()  # the whole back catalogue by itself after an update, not a small batch per run
    out = detection_author.author_pending(provider)
    out['rules_first'] = rules_first
    from cveFeed import locality
    locality.refresh(limit=100000)
    out['local_closed'] = locality.close_local_matches()  # a CVE the model just judged local-only is never a finding
    from cveFeed import match_policy
    out['no_evidence_closed'] = match_policy.close_policy_matches()
    out['template_refresh_for'] = len(detection_author.refresh_templates_for_new_hot_cves(update_nuclei_templates.delay))
    return out


@app.task(name="build_cve_seed", bind=False, queue="cve_feed_queue")
def build_cve_seed():
    """Write the whole catalog with its shared detection records to the exports folder (Settings > CVE seed), ready to publish."""
    import os
    from django.core.cache import cache
    from cveFeed import activity, detection_author, seed
    from cveFeed.settings_api import SEED_BUILDING, SEED_NAME, seed_dir
    handle = activity.log('inventory', 'Building the CVE seed', status='running')
    try:
        while detection_author.author_rules(batch=5000):
            pass
        detection_author.refresh_rules(batch=5000)
        os.makedirs(seed_dir(), exist_ok=True)
        manifest = seed.export_seed(os.path.join(seed_dir(), SEED_NAME))
        activity.settle(handle, 'done', message=f"Built the CVE seed: {manifest['count']} CVEs, {manifest['with_detection']} with a detection record")
        return {k: manifest[k] for k in ('count', 'with_detection', 'bytes')}
    except Exception:
        activity.settle(handle, 'failed', message='Building the CVE seed failed; see the worker log')
        raise
    finally:
        cache.delete(SEED_BUILDING)


@app.task(name="write_cve_guidance_now", bind=False, queue="cve_feed_queue")
def write_cve_guidance_now(count=200):
    """An administrator asked the model to write guidance for the next ``count`` CVEs now (Settings > AI model), whatever is left of the
    day's budget. Matchable CVEs first. Works in rounds of 50 so progress shows and a stop request is honoured between rounds."""
    from cveFeed import activity, detection_author
    from reNgine.ai_settings import get_configured_provider
    provider = get_configured_provider()
    if provider is None:
        return {'written': 0, 'error': 'no AI provider is configured'}
    detection_author.author_rules(batch=5000)
    done, count = 0, max(1, min(int(count), 5000))
    handle = activity.log('inventory', f'Writing CVE guidance for up to {count} CVEs', status='running')
    try:
        while done < count:
            wrote = detection_author.author_with_ai(provider, per_run=min(50, count - done), workers=4, within_budget=False)
            if not wrote:
                break
            done += wrote
    finally:
        activity.settle(handle, 'done', message=f'Wrote CVE guidance for {done} CVEs')
    from cveFeed import locality
    locality.refresh()
    locality.close_local_matches()
    return {'written': done}


@app.task(name="report_resources", bind=False, queue="cve_feed_queue")
def report_resources():
    """Every 30 seconds: publish this container's memory and budget so Settings > Resources (served by another
    container) can show it. See reNgine/resources.py."""
    from reNgine import resources
    resources.report_state()
    return {}


PRUNE_ROUNDS, PRUNE_BATCH = 20, 5000


@app.task(name="prune_asset_changes", bind=False, queue="cve_feed_queue")
def prune_asset_changes():
    """Daily: drop AssetChange rows older than CVENGINE_CHANGES_RETENTION_DAYS (default 90), 5000 ids at a time."""
    from datetime import timedelta

    from django.utils import timezone

    from cveFeed.models import AssetChange
    try:
        days = max(1, int(os.environ.get("CVENGINE_CHANGES_RETENTION_DAYS", 90)))
    except ValueError:
        days = 90
    cutoff = timezone.now() - timedelta(days=days)
    deleted = 0
    for _ in range(PRUNE_ROUNDS):
        ids = list(AssetChange.objects.filter(detected_at__lt=cutoff).values_list("id", flat=True)[:PRUNE_BATCH])
        if not ids:
            break
        AssetChange.objects.filter(id__in=ids).delete()
        deleted += len(ids)
    return {"deleted": deleted}


@app.task(name="reap_stuck_jobs", bind=False, queue="cve_feed_queue")
def reap_stuck_jobs():
    """Every 15 minutes: fail host assessments, validation jobs, scans and AI activity rows a lost worker left queued or running (cveFeed.reaper)."""
    from cveFeed import activity, reaper
    counts = reaper.reap()
    if counts:
        activity.log('validate', 'Expired stuck jobs a restarted worker left behind: '
                     + ', '.join(f'{n} {key.replace(":", " ")}' for key, n in counts.items()), status='failed', **counts)
    orphaned = reaper.expire_orphaned_running()
    if orphaned:
        activity.log('discovery', 'Closed scans/assessments a restarted worker left running with no Celery task behind: '
                     + ', '.join(f'{n} {key}' for key, n in orphaned.items()), status='failed', **orphaned)
        counts.update({f'{key}:orphaned': n for key, n in orphaned.items()})
    again = reaper.redispatch_queued_assessments()
    if again:
        activity.log('discovery', f'Queued {again} host assessment{"s" if again != 1 else ""} again: their worker message was lost, most likely in a restart',
                     status='done', requeued=again)
        counts['HostAssessment:requeued'] = again
    scans = reaper.redispatch_queued_scans()
    if scans:
        activity.log('discovery', f'Queued {scans} discovery scan{"s" if scans != 1 else ""} again: their worker message was lost, most likely in a restart',
                     status='done', requeued=scans)
        counts['ScanHistory:requeued'] = scans
    return counts


BOOTSTRAP_LOCK = "cvengine:first-run-bootstrap"


SEED_BELOW = 5000  # an instance with fewer CVEs than this is offered the published seed (once a day at most)


@app.task(name="load_cve_seed", bind=False, queue="cve_feed_queue", time_limit=3600, soft_time_limit=3300)
def load_cve_seed():
    """Import the published CVE catalog (cveFeed.seed) so a new install starts with every CVE and its detection record instead of
    hydrating them one request at a time. Never fails the caller: offline, a bad checksum or a missing release is logged and the
    incremental feed carries on as before."""
    from cveFeed import activity, seed
    if not seed.seed_enabled():
        return {"skipped": "CVENGINE_CVE_SEED is off"}
    note = activity.log("feed", "Loading the published CVE catalog (all fire, smoke and ice CVEs with their detection records)", status="running")
    try:
        counts = seed.load_published_seed()
    except Exception as exc:  # noqa: BLE001 - the feed sync that follows still works without the seed
        logger.warning("could not load the published CVE seed: %s", exc)
        activity.settle(note, "failed", message="The published CVE catalog could not be loaded; the feed will build it up gradually")
        return {"loaded": False, "error": str(exc)[:200]}
    counts.pop("manifest", None)
    activity.settle(note, "done", message=f"Loaded {counts['created']} CVEs and {counts['detections']} detection records from the published catalog")
    if counts["created"]:
        from startScan.models import Subdomain
        if Subdomain.objects.exists():  # an instance with hosts needs the new CVEs checked against them
            correlate_cves.delay()
    return {"loaded": True, **counts}


@app.task(name="bootstrap_first_run", bind=False, queue="cve_feed_queue")
def bootstrap_first_run():
    """Once, when a brand-new install's workers come up: load the CVE feed and the threat intelligence now, instead of waiting for
    the first scheduled run (up to 30 minutes for the feed, an hour for threat intelligence), so the first dashboard already has
    CVEs, tiers and matches to show. The sync tasks go on to correlate and auto-fire by themselves. "First run" means the CVE
    table is empty, so an existing install (an update, a restart) never repeats it, and a first attempt that found no network
    simply tries again the next time a worker starts. A lock keeps several workers starting together from queuing it more than once."""
    from celery import chain
    from django.core.cache import cache

    from cveFeed import activity
    if CVEEntry.objects.exists():
        if CVEEntry.objects.count() < SEED_BELOW and cache.add("cvengine:seed-offer", 1, timeout=24 * 3600):
            load_cve_seed.apply_async()  # an install that predates the seed and has only a few CVEs gets the catalog too
        return {"skipped": "the CVE feed is already loaded"}
    if not cache.add(BOOTSTRAP_LOCK, 1, timeout=1800):
        return {"skipped": "a first-run load is already under way"}
    activity.log("feed", "First start: loading the CVE feed and threat intelligence now, instead of waiting for the schedule")
    chain(load_cve_seed.si(), sync_cve_now_feed.si(), sync_threat_intel.si(), backfill_cve_now_feed.si()).apply_async()
    return {"started": True}


@app.task(name="snapshot_daily_stats", bind=False, queue="cve_feed_queue")
def snapshot_daily_stats():
    """Daily: store one point-in-time snapshot per project (cveFeed.stats_history), so Settings and the dashboard can
    show trends (exposure over time, mean time-to-fix) that nothing else in the schema keeps a record of."""
    from cveFeed import stats_history
    return {'projects': stats_history.snapshot_all_projects()}


@app.task(name="evaluate_saved_searches", bind=False, queue="cve_feed_queue")
def evaluate_saved_searches():
    """Every ten minutes: run the saved searches whose time has come (cveFeed.saved_searches), alert on new matches and record
    each outcome. Bounded per run; one run at a time, so a slow run is not doubled by the next beat."""
    from django.core.cache import cache

    from cveFeed import saved_searches
    if not cache.add("cvengine:saved-searches", 1, timeout=900):
        return {"skipped": "another evaluation is running"}
    try:
        return saved_searches.evaluate_due()
    finally:
        cache.delete("cvengine:saved-searches")


@app.task(name="weekly_maintenance", bind=False, queue="cve_feed_queue")
def weekly_maintenance():
    """Weekly: archive the AI activity feed, AI call leases and AI usage rows past their retention to a tar.gz and delete them
    (cveFeed.maintenance). One run at a time; the outcome is a line in the activity log, failed if the archive could not be
    written, in which case nothing was deleted."""
    from django.core.cache import cache

    from cveFeed import activity, maintenance
    if not cache.add('cvengine:weekly-maintenance', 1, timeout=6 * 3600):
        return {'skipped': 'another maintenance run is in progress'}
    try:
        result = maintenance.run()
    except Exception as exc:  # noqa: BLE001 - reported, and retried next week; no row was deleted
        logger.exception('weekly maintenance failed')
        activity.log('feed', activity.diagnostic('Weekly log maintenance', f'{type(exc).__name__}: {exc}', type(exc).__name__),
                     status='failed')
        return {'error': type(exc).__name__}
    finally:
        cache.delete('cvengine:weekly-maintenance')
    archived = sum(result['archived'].values())
    activity.log('feed', (f'Weekly log maintenance archived and removed {archived:,} log rows older than their retention '
                          f'({", ".join(f"{k} {v:,}" for k, v in result["archived"].items() if v)}) into '
                          f'{os.path.basename(result["archive"])}' if archived else
                          'Weekly log maintenance: no log rows were past their retention')
                 + (f'; {result["archives_removed"]} expired archive(s) deleted' if result['archives_removed'] else ''),
                 archived=result['archived'], deleted=result['deleted'])
    return result


@app.task(name="prune_scan_history", bind=False, queue="cve_feed_queue")
def prune_scan_history():
    """Daily: delete the finished scans older than CVENGINE_SCAN_HISTORY_RETENTION_DAYS (180 by default, 0 keeps everything) that no longer
    back the current inventory (cveFeed.scan_retention). One run at a time, bounded in time; a large backlog is cleared over several days."""
    from django.core.cache import cache

    from cveFeed import activity, scan_retention
    if scan_retention.retention_days() is None:
        return {"skipped": "scan history retention is off"}
    if not cache.add("cvengine:scan-retention", 1, timeout=3 * 3600):
        return {"skipped": "another retention run is in progress"}
    try:
        result = scan_retention.run()
    except Exception as exc:  # noqa: BLE001 - reported, and retried tomorrow; each scan is deleted in its own transaction
        logger.exception("scan history retention failed")
        activity.log("feed", activity.diagnostic("Scan history retention", f"{type(exc).__name__}: {exc}", type(exc).__name__), status="failed")
        return {"error": type(exc).__name__}
    finally:
        cache.delete("cvengine:scan-retention")
    if result["scans"]:
        activity.log("feed", f'Scan history retention deleted {result["scans"]:,} scan(s) older than {result["days"]} days'
                     + ("" if result["complete"] else "; more are left for the next run"), deleted=result["scans"])
    return result


@app.task(name='check_os_path', bind=False, queue='cve_feed_queue', time_limit=300, soft_time_limit=240)
def check_os_path():
    """Daily: measure whether the network path this worker scans from loses nmap's malformed OS-detection probes (cveFeed.path_probe), and
    keep the verdict where operating system detection reads it (cveFeed.os_detection). Runs in the scanning container, so it measures the
    path the scans take. Two packets to each of at most eight hosts the scans already reach; waits while scanning is paused."""
    from cveFeed import os_detection, path_probe
    return os_detection.record_path(path_probe.check())


@app.task(name='generate_report', bind=True, queue='cve_feed_queue', time_limit=3600, soft_time_limit=3300)
def generate_report(self, export_id):
    """Make one queued PDF report (cveFeed.report_export): read for the project as the user who asked, rendered in a child process,
    written under the report directory with a random name. The broker carries only the row id."""
    from cveFeed import report_export
    return report_export.execute(export_id, celery_id=self.request.id)


@app.task(name="rescore_all_hosts", bind=False, queue="cve_feed_queue")
def rescore_all_hosts():
    """Daily: recompute every host's score (the latest finished scan's hosts and the certificate watch's), per project, 500 at a
    time and at most MAX_RESCORE_HOSTS a project, least recently scored first, so "new this week" decays and CVE feed updates
    land on the score."""
    from django.db.models import F

    from cveFeed import ledger, scoring
    from cveFeed.correlation import latest_scan_q
    from dashboard.models import Project
    from startScan.models import Subdomain
    if not ledger.sweep_claim("rescore", 3600):
        return {"hosts": 0, "skipped": "another rescore is running"}
    total = 0
    for project_id in Project.objects.values_list("id", flat=True):
        names = Subdomain.objects.filter(target_domain__project_id=project_id).filter(latest_scan_q()).order_by(
            F("scored_at").asc(nulls_first=True), "id").values_list("name", flat=True)[:scoring.MAX_RESCORE_HOSTS]
        try:
            total += scoring.rescore_hosts(project_id, list(dict.fromkeys(names)))
        except Exception:  # noqa: BLE001 - one project failing must not stop the others
            logger.exception("rescore failed for project %s", project_id)
    return {"hosts": total}
