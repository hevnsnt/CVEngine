"""Notification messages for the CVE pipeline, sent through the channels configured under Settings, Notifications.

Four events, each one message per call and each call made once per scan, per feed sync or per saved-search evaluation, never per host:
- ``fire_matches``: new fire-tier CVE matches (``send_vuln_notif``);
- ``template_hits``: hosts a template test confirmed vulnerable (``send_vuln_notif``);
- ``scan_finished``: a discovery scan ended, with a one-line summary (``send_scan_status_notif``);
- ``saved_search``: a saved search found new matches, lost some or reached its threshold (``send_interesting_notif``).

The senders are the reNgine helpers (Slack, Discord, Telegram, Lark), which read the one Notification row and do nothing
for a channel that is off or incomplete. Sending is best effort: a failure is logged without its text (a Telegram error
carries the bot token in its URL) and never reaches the caller.
"""
import logging
import re

logger = logging.getLogger(__name__)

CHANNEL_SENDERS = {'discord': 'send_discord_message', 'slack': 'send_slack_message', 'lark': 'send_lark_message', 'telegram': 'send_telegram_message'}
SAMPLE = 5  # names listed in a message; the count says the rest
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


def _send(text, flag, channels=()):
    """Send one message to every enabled channel (or only to those of ``channels``, which the Notification row must still have
    on) when the Notification row allows this kind of event. Returns True when at least one channel took the message, False when no channel
    was set up for this kind of event (nothing was tried), and None when channels were tried and every one failed."""
    try:
        row = _settings()
        if not (row and getattr(row, flag) and (row.send_to_slack or row.send_to_discord or row.send_to_telegram or row.send_to_lark)):
            return False
        from reNgine import common_func
        sent = tried = 0
        for channel, name in CHANNEL_SENDERS.items():
            if channels and channel not in channels:
                continue
            tried += 1
            try:
                getattr(common_func, name)(text)
                sent += 1
            except Exception as exc:  # noqa: BLE001 - one channel failing must not stop the others
                logger.warning('notification via %s failed (%s)', name, type(exc).__name__)
        return True if sent or not tried else None
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

    A page needs evidence that the vulnerability exists: the host's version in the affected range, a template hit, or the
    distribution tracker calling it vulnerable. A match the AI left uncertain (the AI's false-positive call lands there when no
    hard evidence can close it) is not announced unless a template hit or the distribution tracker proves it; it stays open, is
    tested, and a hit is announced by ``template_hits``. Matches the version rules out, the AI judged not affected or the host's
    distribution has patched are left out."""
    try:
        from django.db.models import Q

        from cveFeed.models import CVEEntry, CVEMatch
        from cveFeed.threat import fire_tier_q
        rows = CVEMatch.objects.filter(created_at__gte=since)
        rows = rows.filter(scan_history=scan) if scan is not None else rows
        if cve_ids is not None:
            rows = rows.filter(cve_entry_id__in=list(cve_ids))
        proven = Q(template_result='vulnerable') | Q(distro_status='vulnerable')
        rows = rows.exclude(version_in_range=False).exclude(ai_verdict='not_affected').exclude(distro_status='patched').filter(
            Q(version_in_range=True) | proven).exclude(Q(ai_verdict='uncertain') & ~proven).filter(
            cve_entry_id__in=CVEEntry.objects.filter(fire_tier_q()).values('id'))
        total = rows.count()
        if not total:
            return False
        sample = list(rows.order_by('-cve_entry__cvss', 'id').values_list('cve_entry__cve_id', 'subdomain__name')[:SAMPLE])
        hosts = rows.values('subdomain_id').distinct().count()
        where = f' in {_name(scan.domain.name)}' if scan is not None else ''
        text = (f'CVEngine: {total} new fire-tier CVE match{"es" if total != 1 else ""} on {hosts} host{"s" if hosts != 1 else ""}'
                f'{where}: {_listing([(_name(c), _name(h)) for c, h in sample], total)}')
        return _send(text, 'send_vuln_notif')
    except Exception as exc:  # noqa: BLE001
        logger.warning('fire match notification failed (%s)', type(exc).__name__)
        return False


def template_hits(hits, scan=None):
    """One message for the (CVE id, host) pairs a template test confirmed vulnerable (in one scan, or by one CVE's test)."""
    hits = list(dict.fromkeys(hits))
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
