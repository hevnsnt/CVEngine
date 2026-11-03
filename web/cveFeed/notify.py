"""Notification messages for the CVE pipeline, sent through the channels configured under Settings, Notifications.

Each event is one message per call, and each call is made once per scan, per feed sync or per saved-search evaluation, never per host:
- ``fire_matches``: new fire-tier CVE matches (``send_vuln_notif``);
- ``fire_confirmed``: matches that were not proven (smoke) that evidence later turned fire (``send_vuln_notif``);
- ``cves_turned_hot``: matches already proven whose CVE joined the KEV or gained a known exploit, so they turned fire (``send_vuln_notif``);
- ``template_hits``: hosts a template test confirmed vulnerable, for a CVE that can be fire under the heat policy (``send_vuln_notif``);
- ``scan_finished``: a discovery scan ended, with a one-line summary (``send_scan_status_notif``);
- ``saved_search``: a saved search found new matches, lost some or reached its threshold (``send_interesting_notif``).

A CVE match is paged as fire once per heat rule (``CVEMatch.fire_notified_at`` with ``fire_notified_rule``, ``unannounced_q``), not once per
scan: a rescan's copy carries it (``correlation._carry_remediation``). When the heat rule changes (the update that introduced the policy, a switch
on the Heat policy card or ``CVENGINE_HEAT_POLICY``, the legacy cap), every match that is fire under the new rule and was there before the switch
is marked as announced under it without a message (``baseline_heat_policy``): the switch itself is no news, so it never pages the backlog. A mark
made under one rule never holds back a page that is new under another, and a match still waiting for its page (its scan is running, or it was
made just before the switch) is left to that page.

The senders are the reNgine helpers (Slack, Discord, Telegram, Lark), which read the one Notification row and do nothing
for a channel that is off or incomplete. Sending is best effort: a failure is logged without its text (a Telegram error
carries the bot token in its URL) and never reaches the caller.
"""
import logging
import re

logger = logging.getLogger(__name__)

CHANNEL_SENDERS = {'discord': 'send_discord_message', 'slack': 'send_slack_message', 'lark': 'send_lark_message', 'telegram': 'send_telegram_message'}
SAMPLE = 5  # names listed in a message; the count says the rest
MAX_MARK = 5000  # matches one call marks as announced (a message names a few and counts the rest)
# the stored fields a channel needs before its sender does anything; a sender for a channel without them returns silently
_CHANNEL_FIELDS = {'discord': ('discord_hook_url',), 'slack': ('slack_hook_url',), 'lark': ('lark_hook_url',),
                   'telegram': ('telegram_bot_token', 'telegram_bot_chat_id')}
_UNSAFE = re.compile(r'[^A-Za-z0-9.:_-]')


def _name(value):
    """A host or CVE id safe to place in a message: attacker-influenced text cannot add markup or mentions. Wrapped in
    backticks so Telegram's Markdown mode does not trip on underscores."""
    return '`' + _UNSAFE.sub('?', str(value))[:100] + '`'


def _label(value):
    """A person-chosen name (a saved search, a project) safe to place in a message: spaces stay, markup characters do not."""
    return '`' + re.sub(r'[^A-Za-z0-9 .:_-]', '?', str(value))[:80] + '`'


def _names(hosts):
    shown = ', '.join(_name(h) for h in hosts[:SAMPLE])
    more = len(hosts) - SAMPLE
    return shown + (f' and {more} more' if more > 0 else '')


def _settings():
    from scanEngine.models import Notification
    return Notification.objects.first()


def enabled_channels():
    """Names of the channels Settings, Notifications has switched on (never their addresses or tokens)."""
    try:
        row = _settings()
        return [c for c in CHANNEL_SENDERS if row and getattr(row, f'send_to_{c}')]
    except Exception:  # noqa: BLE001
        return []


def _set_up(row, channel):
    """True when the channel is switched on and has the address (or token) its sender needs."""
    return bool(getattr(row, f'send_to_{channel}') and all(getattr(row, f) for f in _CHANNEL_FIELDS.get(channel, ())))


def _send(text, flag, channels=()):
    """Send one message to every enabled channel (or only to those of ``channels``, which the Notification row must still have
    on and complete) when the Notification row allows this kind of event. Returns True when at least one channel took the message, False when
    no channel was set up for this kind of event (nothing was tried), and None when channels were tried and every one failed."""
    try:
        row = _settings()
        if not (row and getattr(row, flag) and (row.send_to_slack or row.send_to_discord or row.send_to_telegram or row.send_to_lark)):
            return False
        from reNgine import common_func
        sent = tried = 0
        for channel, name in CHANNEL_SENDERS.items():
            if (channels and channel not in channels) or not _set_up(row, channel):
                continue  # a silent sender must not count as a delivery
            tried += 1
            try:
                getattr(common_func, name)(text)
                sent += 1
            except Exception as exc:  # noqa: BLE001 - one channel failing must not stop the others
                logger.warning('notification via %s failed (%s)', name, type(exc).__name__)
        return True if sent else (None if tried else False)
    except Exception as exc:  # noqa: BLE001 - notifications never break a scan or a feed sync
        logger.warning('notification failed (%s)', type(exc).__name__)
        return False


def _listing(pairs, total):
    shown = ', '.join(f'{cve} on {host}' for cve, host in pairs[:SAMPLE])
    more = total - min(total, SAMPLE)
    return shown + (f' and {more} more' if more > 0 else '')


def fire_matches(since, scan=None, cve_ids=None):
    """One message for the fire-tier CVE matches created since ``since``: those of one scan, or, with no scan, those a feed sync's
    new CVEs (``cve_ids``, when given) made on the inventory. A feed match belongs to the scan whose host row it sits on, so it is
    not filtered on the scan; the caller runs this after the AI has judged them.

    A page needs the match to be fire on the host (``threat.match_heat``). Under the KEV heat policy that is a KEV or exploited CVE whose
    version is proven (``match_policy.version_proven``: hard evidence, or the version read from the component itself); a version we only
    infer is smoke and a CVE that is neither on the KEV nor exploited is ice, so neither is paged. Under ``legacy`` a version in the affected
    range alone is smoke (CVENGINE_VERSION_ONLY_MAX_HEAT), so only a match with hard evidence is paged. A match the AI left uncertain (the
    AI's false-positive call lands there when no hard evidence can close it, and triage never rates a version-only match higher) is not
    announced unless a template hit, the distribution tracker or, under the KEV policy, a version read from the component proves it; it
    stays open, is tested, and a hit is announced by ``template_hits``. Matches the version rules out, the AI judged not affected or the
    host's distribution has patched are left out."""
    try:
        from django.db.models import Q

        from cveFeed import match_policy
        from cveFeed.models import CVEEntry, CVEMatch
        from cveFeed.threat import FIRE, HEAT_RANK, LEGACY_POLICY, fire_tier_q, heat_policy, match_heat_rank_expr
        rows = CVEMatch.objects.filter(created_at__gte=since)
        rows = rows.filter(scan_history=scan) if scan is not None else rows
        if cve_ids is not None:
            rows = rows.filter(cve_entry_id__in=list(cve_ids))
        proven = Q(template_result='vulnerable') | Q(distro_status='vulnerable')
        if heat_policy() != LEGACY_POLICY:
            proven |= match_policy.version_read_from_component_q()  # the version is read from the component: fire on a KEV CVE
        rows = rows.exclude(version_in_range=False).exclude(ai_verdict='not_affected').exclude(distro_status='patched').filter(
            Q(version_in_range=True) | proven).exclude(Q(ai_verdict='uncertain') & ~proven).exclude(match_policy.version_unknown_q()).filter(
            cve_entry_id__in=CVEEntry.objects.filter(fire_tier_q()).values('id'))
        # and fire on the host: a match whose version is not proven shows smoke (and one that is not hot ice), so it is not paged as fire;
        # when evidence later makes it fire it is paged by ``template_hits`` (a template hit) or ``fire_confirmed`` (anything else)
        rows = rows.annotate(heat_rank=match_heat_rank_expr()).filter(heat_rank=HEAT_RANK[FIRE]).filter(unannounced_q())
        # each match is paged as fire once (a guarded claim: what a concurrent call claimed first is not counted or sent here)
        claimed = _claim(rows.values_list('pk', flat=True)[:MAX_MARK])
        if claimed is None:
            return False
        total = claimed.count()
        hosts = claimed.values('subdomain_id').distinct().count()
        sample = list(claimed.order_by('-cve_entry__cvss', 'id').values_list('cve_entry__cve_id', 'subdomain__name')[:SAMPLE])
        where = f' in {_name(scan.domain.name)}' if scan is not None else ''
        text = (f'CVEngine: {total} new fire-tier CVE match{"es" if total != 1 else ""} on {hosts} host{"s" if hosts != 1 else ""}'
                f'{where}: {_listing([(_name(c), _name(h)) for c, h in sample], total)}')
        return _send(text, 'send_vuln_notif')
    except Exception as exc:  # noqa: BLE001
        logger.warning('fire match notification failed (%s)', type(exc).__name__)
        return False


def fire_confirmed(match_ids):
    """One message for the CVE matches that hard evidence just turned fire on the host (``threat.match_heat``). ``match_ids`` are only the
    matches that were not proven (``threat.unproven``: smoke at most) just before the evidence was written: the caller checks that before its write
    (``scoring.evidence_arrived``), so a match that was already fire (a distribution listing, a template hit) is never paged again
    because more evidence reached it. A template hit is announced by ``template_hits`` and is left out here.

    Each match is paged as fire once per heat rule: ``CVEMatch.fire_notified_at`` is claimed by a guarded UPDATE (``unannounced_q``, one ``now``), so two
    workers never both send it. Copies of the finding on older scans' host rows are claimed too but never announced: only the current
    inventory's rows (``latest_scan_q``) are counted and named, and hosts are counted by name. Never raises."""
    try:
        from cveFeed.correlation import latest_scan_q
        from cveFeed.models import CVEMatch
        from cveFeed.threat import FIRE, HEAT_RANK, match_heat_rank_expr
        ids = sorted({int(i) for i in match_ids if i})[:MAX_MARK]
        if not ids:
            return False
        fire = list(CVEMatch.objects.filter(unannounced_q(), pk__in=ids).exclude(template_result='vulnerable')
                    .exclude(ai_verdict='not_affected').exclude(remediation_status__in=('fixed', 'accepted_risk')).exclude(distro_status='patched')
                    .annotate(heat_rank=match_heat_rank_expr()).filter(heat_rank=HEAT_RANK[FIRE]).values_list('pk', flat=True))
        claimed = _claim(fire)
        if claimed is None:
            return False
        current = claimed.filter(latest_scan_q('subdomain__'))
        total = current.count()
        if not total:
            return False
        sample = list(current.order_by('-cve_entry__cvss', 'id').values_list('cve_entry__cve_id', 'subdomain__name')[:SAMPLE])
        hosts = current.values('subdomain__name').distinct().count()
        text = (f'CVEngine: {total} CVE match{"es" if total != 1 else ""} confirmed, now fire-tier, on {hosts} '
                f'host{"s" if hosts != 1 else ""}: {_listing([(_name(c), _name(h)) for c, h in sample], total)}')
        return _send(text, 'send_vuln_notif')
    except Exception as exc:  # noqa: BLE001
        logger.warning('fire confirmation notification failed (%s)', type(exc).__name__)
        return False


MAX_TURNED_HOT_ROUNDS = 40  # claims of MAX_MARK matches one cves_turned_hot call makes; what is left waits for the next call
TURNED_HOT_PENDING = 'cvengine:notify:turned-hot-pending'  # cache key: the CVEs whose proven matches one call could not finish


def cves_turned_hot(cve_ids):
    """One message for the CVE matches that turned fire because their CVE joined the KEV or gained a known exploit (``cve_ids``: the CVEs
    whose signals just went from neither to either; ``intel.reconcile``, the cve.now refresh and the forced backfill report them). Under the
    KEV heat policy only: a match whose version is proven is fire now and is paged once (claimed like every page); one we only infer is smoke
    and is not paged (it is validated first, in the fire lane, and paged when proof turns it fire). A template hit on such a CVE is paged here
    too: ``template_hits`` left it out while the CVE was ice. Only the current inventory's rows are counted and named; a match the AI ruled out,
    fixed, accepted as a risk or patched by the distribution is left out. Every such match is claimed, ``MAX_MARK`` at a time, up to
    ``MAX_TURNED_HOT_ROUNDS`` claims; the CVEs of a call that could not finish are kept (cache) and carried by the next call, so none is lost.
    Under ``legacy`` nothing is sent from here (the legacy behaviour is unchanged). Never raises."""
    try:
        from django.core.cache import cache

        from cveFeed.correlation import latest_scan_q
        from cveFeed.models import CVEMatch
        from cveFeed.threat import FIRE, HEAT_RANK, LEGACY_POLICY, heat_policy, match_heat_rank_expr
        if heat_policy() == LEGACY_POLICY:
            return False
        try:
            pending = list(cache.get(TURNED_HOT_PENDING) or [])
        except Exception:  # noqa: BLE001 - a cache outage must not stop the page
            pending = []
        ids = sorted({int(i) for i in [*(cve_ids or ()), *pending] if i})
        if not ids:
            return False
        rows = (CVEMatch.objects.filter(unannounced_q(), cve_entry_id__in=ids).filter(latest_scan_q('subdomain__'))
                .exclude(ai_verdict='not_affected').exclude(remediation_status__in=('fixed', 'accepted_risk')).exclude(distro_status='patched')
                .annotate(heat_rank=match_heat_rank_expr()).filter(heat_rank=HEAT_RANK[FIRE]))
        claimed_ids, left = [], False
        for _round in range(MAX_TURNED_HOT_ROUNDS):
            batch = list(rows.values_list('pk', flat=True)[:MAX_MARK])
            if not batch:
                break
            claimed = _claim(batch)
            if claimed is not None:
                claimed_ids += list(claimed.values_list('pk', flat=True))
        else:
            left = rows.exists()
        try:
            if left:
                cache.set(TURNED_HOT_PENDING, ids, timeout=7 * 24 * 3600)
            elif pending:
                cache.delete(TURNED_HOT_PENDING)
        except Exception:  # noqa: BLE001
            logger.warning('could not keep the CVEs whose turned-fire matches are still to be paged')
        if not claimed_ids:
            return False
        claimed = CVEMatch.objects.filter(pk__in=claimed_ids)
        total = len(claimed_ids)
        sample = list(claimed.order_by('-cve_entry__cvss', 'id').values_list('cve_entry__cve_id', 'subdomain__name')[:SAMPLE])
        hosts = claimed.values('subdomain__name').distinct().count()
        text = (f'CVEngine: {total} CVE match{"es" if total != 1 else ""} turned fire-tier on {hosts} host{"s" if hosts != 1 else ""}: the CVE '
                f'is now on the KEV or has a known exploit: {_listing([(_name(c), _name(h)) for c, h in sample], total)}')
        return _send(text, 'send_vuln_notif')
    except Exception as exc:  # noqa: BLE001
        logger.warning('turned-hot notification failed (%s)', type(exc).__name__)
        return False


def unannounced_q(rule=None):
    """CVE matches not yet paged (or marked) as fire under ``rule`` (``threat.heat_signature()``, the rule in force, by default): never paged,
    or paged under another rule. A mark made under one rule never holds back a page that is new under another."""
    from django.db.models import Q

    from cveFeed.threat import heat_signature
    return Q(fire_notified_at__isnull=True) | ~Q(fire_notified_rule=rule or heat_signature())


def mark_announced(match_ids):
    """Mark these CVE matches as paged as fire without sending anything, when they are fire now: what was already true when the heat policy
    took effect, or what turned fire only because correlation now records what proves it (``correlation.save_matches``). Returns how many were
    marked. Never raises."""
    try:
        from cveFeed.models import CVEMatch
        from cveFeed.threat import FIRE, HEAT_RANK, match_heat_rank_expr
        ids = sorted({int(i) for i in match_ids or () if i})
        if not ids:
            return 0
        from django.utils import timezone

        from cveFeed.threat import heat_signature
        rule = heat_signature()
        fire = (CVEMatch.objects.filter(unannounced_q(rule), pk__in=ids).annotate(heat_rank=match_heat_rank_expr())
                .filter(heat_rank=HEAT_RANK[FIRE]).values('pk'))
        return CVEMatch.objects.filter(unannounced_q(rule), pk__in=fire).update(fire_notified_at=timezone.now(), fire_notified_rule=rule)
    except Exception as exc:  # noqa: BLE001
        logger.warning('could not mark matches as announced (%s)', type(exc).__name__)
        return 0


BASELINE_LANE = 'heat_baseline'  # BackgroundCursor.lane: last_pk holds which heat rule the pages were last baselined to (BASELINE_SIGNATURES)
BASELINE_SIGNATURES = ('kev', 'legacy:fire', 'legacy:smoke', 'legacy:ice')  # threat.heat_signature() values; the stored number is index + 1
BASELINE_GRACE_HOURS = 6  # a match made this recently is left to the page its run sends at its end (a feed sync judges its matches first)
UNFINISHED_SCAN = (-1, 1)  # ScanHistory.scan_status initiated, running: its matches are paged when it ends (discovery.fire_matches)


def baseline_code(signature):
    """The number ``BackgroundCursor.last_pk`` stores for a heat rule (0: none recorded)."""
    return BASELINE_SIGNATURES.index(signature) + 1 if signature in BASELINE_SIGNATURES else len(BASELINE_SIGNATURES) + 1


def baseline_heat_policy():
    """When the heat rule (``threat.heat_signature``: the policy, and under legacy the version-only cap) differs from the one the pages were last
    baselined to, mark every CVE match that is fire under the rule now and not announced under it as announced under it (``fire_notified_at`` and
    ``fire_notified_rule``), without a message, and record the rule. So a policy switch never pages the backlog: a page is always about something
    that changed while the rule was in force (new matches, ``fire_confirmed``, ``cves_turned_hot``), a smoke match is still paged when proof turns
    it fire, and a mark under this rule never holds back a page that is new under another (``unannounced_q``).

    Matches still waiting for their page are left to it: those of a scan that has not finished (``fire_matches`` pages them when it ends), and
    those made in the last ``BASELINE_GRACE_HOURS`` (a feed sync pages its new matches after the AI has judged them). The update itself is
    baselined by migration 0137 (frozen rules of its own); this runs at worker start and on the 30 second tick. One cheap read when nothing
    changed, and one locked row so two workers never both do it. Returns how many matches it marked."""
    from datetime import timedelta

    from django.db import transaction
    from django.db.models import Q
    from django.utils import timezone

    from cveFeed.models import BackgroundCursor, CVEMatch
    from cveFeed.threat import FIRE, HEAT_RANK, heat_signature, match_heat_rank_expr
    signature = heat_signature()
    code = baseline_code(signature)
    if BackgroundCursor.objects.filter(lane=BASELINE_LANE, last_pk=code).exists():
        return 0
    now = timezone.now()
    with transaction.atomic():
        cursor, _ = BackgroundCursor.objects.select_for_update().get_or_create(lane=BASELINE_LANE)
        if cursor.last_pk == code:
            return 0
        waiting = Q(created_at__gte=now - timedelta(hours=BASELINE_GRACE_HOURS)) | Q(scan_history__scan_status__in=UNFINISHED_SCAN)
        fire = (CVEMatch.objects.filter(unannounced_q(signature)).exclude(waiting).annotate(heat_rank=match_heat_rank_expr())
                .filter(heat_rank=HEAT_RANK[FIRE]).values('pk'))
        marked = CVEMatch.objects.filter(unannounced_q(signature), pk__in=fire).update(fire_notified_at=now, fire_notified_rule=signature)
        cursor.last_pk = code
        cursor.save(update_fields=['last_pk', 'updated_at'])
    if marked:
        logger.info('heat rule %s: %d fire CVE matches marked as announced (the switch itself pages nothing)', signature, marked)
    return marked


def _claim(ids):
    """Mark these CVE matches as paged as fire, guarded (only rows not marked yet, all with one ``now``), and return the queryset of the
    rows THIS call marked (None when it marked none): what another worker claimed first is never sent twice."""
    from django.utils import timezone

    from cveFeed.models import CVEMatch
    from cveFeed.threat import heat_signature
    ids = list(ids)
    if not ids:
        return None
    now, rule = timezone.now(), heat_signature()
    if not CVEMatch.objects.filter(unannounced_q(rule), pk__in=ids).update(fire_notified_at=now, fire_notified_rule=rule):
        return None
    return CVEMatch.objects.filter(pk__in=ids, fire_notified_at=now, fire_notified_rule=rule)


def _hot_only(hits):
    """The (CVE id, host) pairs whose CVE can be fire on a host under the heat policy: all of them under ``legacy``; under ``kev`` every
    pair but those of a stored CVE that is neither on the KEV nor exploited (ice). A CVE that is not stored, or a lookup that fails, keeps
    the pair: a genuine hit is never held back for want of data (a message too many beats a missed one)."""
    try:
        from cveFeed.models import CVEEntry
        from cveFeed.threat import LEGACY_POLICY, heat_policy, hot_q
        if not hits or heat_policy() == LEGACY_POLICY:
            return hits
        wanted = {str(cve).upper() for cve, _host in hits}
        cold = {c.upper() for c in CVEEntry.objects.filter(cve_id__in=wanted).exclude(hot_q()).values_list('cve_id', flat=True)}
        return [(cve, host) for cve, host in hits if str(cve).upper() not in cold]
    except Exception as exc:  # noqa: BLE001
        logger.warning('could not read which template hits are hot (%s)', type(exc).__name__)
        return hits


def _version_only_pairs(hits):
    """The (CVE id, host) pairs of ``hits`` that a version-class template matched: a stored match of the pair was recorded as
    ``templategen.VERSION_ONLY_RESULT`` and none of its matches has hard evidence (``match_policy.hard_evidence_q``). Such a match is
    version-only (it read a version, not the flaw), so the "hit" is not announced as a confirmed vulnerability. A pair
    with no stored match, or whose match simply has no result recorded yet, is not one of them: a genuine hit is never held back."""
    from django.db.models import BooleanField, Case, Value, When

    from cveFeed.match_policy import hard_evidence_q
    from cveFeed.models import CVEMatch
    from cveFeed.templategen import VERSION_ONLY_RESULT
    rows = (CVEMatch.objects.filter(cve_entry__cve_id__in={c for c, _ in hits}, subdomain__name__in={h for _, h in hits})
            .annotate(hard=Case(When(hard_evidence_q(), then=Value(True)), default=Value(False), output_field=BooleanField()))
            .values_list('cve_entry__cve_id', 'subdomain__name', 'template_result', 'hard'))
    version, hard = set(), set()
    for cve, host, result, is_hard in rows:
        if result == VERSION_ONLY_RESULT:
            version.add((cve, host))
        if is_hard:
            hard.add((cve, host))
    return version - hard


def template_hits(hits, scan=None):
    """One message for the (CVE id, host) pairs a template test confirmed vulnerable (in one scan, or by one CVE's test). A pair a
    version-class template matched, whose matches are still version-only, is left out (``_version_only_pairs``): it read a version, it did not
    confirm the flaw (the callers already leave those hits out; this is the last check before a page). Under the KEV heat policy only a CVE on
    the KEV or with a known exploit is announced: a confirmed CVE that is neither is ice, and ice never pages (the hit is recorded and shown all
    the same). A version-class hit that proves the version of a KEV match turns it fire and is paged by ``fire_confirmed`` instead
    (``templategen.record_outcomes``)."""
    hits = list(dict.fromkeys(hits))
    if hits:
        try:
            capped = _version_only_pairs(hits)
        except Exception as exc:  # noqa: BLE001 - the guard never stops a genuine hit's message
            logger.warning('template hit heat check failed (%s)', type(exc).__name__)
            capped = set()
        hits = [pair for pair in hits if pair not in capped]
    hits = _hot_only(hits)
    if not hits:
        return False
    cves = len({cve for cve, _ in hits})
    where = f' in {_name(scan.domain.name)}' if scan is not None else ''
    text = (f'CVEngine: template test confirmed {len(hits)} vulnerable host{"s" if len(hits) != 1 else ""} '
            f'across {cves} CVE{"s" if cves != 1 else ""}{where}: '
            f'{_listing([(_name(c), _name(h)) for c, h in hits], len(hits))}')
    return _send(text, 'send_vuln_notif')


def scan_finished(scan, results):
    """One line for a finished discovery scan; ``results`` is what the pipeline stages returned."""
    try:
        from startScan.models import Subdomain
        results = results or {}
        hosts = Subdomain.objects.filter(scan_history=scan).count()
        matches = (results.get('correlation') or {}).get('matches', 0)
        findings = (results.get('nuclei_targeted') or {}).get('findings', 0)
        exposed = (results.get('db_exposure') or {}).get('exposed', 0)
        text = (f'CVEngine: discovery of {_name(scan.domain.name)} finished (scan #{scan.id}): {hosts} host{"s" if hosts != 1 else ""}, '
                f'{matches} CVE match{"es" if matches != 1 else ""}, {findings} nuclei finding{"s" if findings != 1 else ""}, '
                f'{exposed} exposed database{"s" if exposed != 1 else ""}')
        return _send(text, 'send_scan_status_notif')
    except Exception as exc:  # noqa: BLE001
        logger.warning('scan finished notification failed (%s)', type(exc).__name__)
        return False


def saved_search(search, new, gone, count, reached):
    """One message for one evaluation of a saved search: the hosts that newly match (``new``, names), the hosts that stopped
    matching (``gone``), and whether the match ``count`` reached the search's threshold. Names are listed up to SAMPLE, the count
    says the rest; the link opens the search on the Hosts page. Only what the search asked to hear about is passed in."""
    try:
        from urllib.parse import quote

        from django.conf import settings
        parts = []
        if new:
            parts.append(f'{len(new)} new host{"s" if len(new) != 1 else ""}: {_names(new)}')
        if gone:
            parts.append(f'{len(gone)} host{"s" if len(gone) != 1 else ""} no longer match{"" if len(gone) != 1 else "es"}: {_names(gone)}')
        if reached:
            parts.append(f'{count} matches, which reaches the threshold of {search.threshold}')
        link = f'https://{settings.DOMAIN_NAME}/cve/{search.project.slug}/hosts/?q={quote(search.query, safe="")}'.replace('_', '%5F')  # Telegram Markdown reads _ as italics
        text = f'CVEngine saved search {_label(search.name)} in {_label(search.project.name)}: {"; ".join(parts)}. {link}'
        return _send(text, 'send_interesting_notif', search.channels or ())
    except Exception as exc:  # noqa: BLE001
        logger.warning('saved search notification failed (%s)', type(exc).__name__)
        return False
