"""Cloudflare Radar's Zero Wire briefings: a public RSS feed of short security briefings, read every six hours so email reports can name this week's.

Like the other feed syncs (``cveFeed.intel``) this fetches one fixed public address with the same time-outs and proxy settings, reads no more than
``MAX_BYTES`` of it and never contacts a scan target. The feed is third-party text and is treated as data and nothing else:

- only what a report needs is kept: the title, the link, a short summary (the feed's one-sentence ``description``, tags removed), the CVE ids the briefing
  names and its tags. The briefing's own HTML (``content:encoded``) is read once for the CVE ids and then dropped: it is never stored or shown;
- no feed text is ever sent to an AI model, and nothing here is passed to anything that runs it;
- a link is kept only when it is ``https://radar.cloudflare.com/zero-wire/...`` exactly;
- XML with a DOCTYPE or an entity declaration is refused (no entity expansion can run), and the response and the number of items are capped.

An App Admin can switch the sync off (``ReportingSettings.zero_wire_enabled``, on by default); with it off nothing is fetched. A hosted install
that sets ``CVENGINE_HOSTED_LICENSE_SAFE`` (``cveFeed.license_safe``) never fetches it either: the feed is CC BY-NC 4.0. A failure is logged,
shown to the App Admin and retried at the next run: the digest uses whatever is stored.
"""
import html
import logging
import re
import xml.etree.ElementTree as ET
from datetime import timedelta, timezone as dt_timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

from django.utils import timezone

from cveFeed.report_data import clean

logger = logging.getLogger(__name__)

FEED_URL = 'https://radar.cloudflare.com/zero-wire/feed'
HOST, PATH = 'radar.cloudflare.com', '/zero-wire/'
MAX_BYTES = 2 * 1024 * 1024
MAX_ITEMS = 50
SUMMARY_MAX, TITLE_MAX = 400, 200
MAX_CVES, MAX_CATEGORIES, CATEGORY_MAX = 30, 15, 40
KEEP_DAYS = 400
CVE_RE = re.compile(r'CVE-\d{4}-\d{4,}', re.I)
TAG_RE = re.compile(r'<[^>]*>')
SLUG_RE = re.compile(r'^[A-Za-z0-9._-]{1,100}$')
CONTENT = '{http://purl.org/rss/1.0/modules/content/}encoded'


class FeedError(Exception):
    """The feed could not be read (the message is a short sentence safe to show an App Admin)."""


def safe_link(value):
    """``value`` when it is an https link on radar.cloudflare.com under /zero-wire/ (no credentials, no port), else ''."""
    try:
        parts = urlsplit(str(value or '').strip())
        port = parts.port
    except ValueError:
        return ''
    if parts.scheme != 'https' or parts.hostname != HOST or port is not None or parts.username or parts.password or not parts.path.startswith(PATH):
        return ''
    if len(parts.path) <= len(PATH) or len(value.strip()) > 300:
        return ''
    return parts._replace(query='', fragment='').geturl()


def _plain(text, limit):
    """Feed text as one short line of plain text: tags removed, entities read once, control characters dropped, clipped."""
    return clean(html.unescape(TAG_RE.sub(' ', str(text or ''))), limit)


def _when(value):
    try:
        moment = parsedate_to_datetime(str(value or '').strip())
    except (TypeError, ValueError):
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=dt_timezone.utc)


def parse(raw):
    """The briefings of a feed document as ``[{guid, slug, title, link, published_at, summary, cve_ids, categories}]``, newest feed order, at most MAX_ITEMS.
    Raises FeedError for a document that is too big, has a DOCTYPE or an entity declaration, or is not RSS."""
    if len(raw) > MAX_BYTES:
        raise FeedError('the feed is larger than the limit')
    lowered = raw.lower() if isinstance(raw, bytes) else raw.lower().encode('utf-8', 'ignore')
    if b'<!doctype' in lowered or b'<!entity' in lowered:
        raise FeedError('the feed uses a document type declaration, which is refused')
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise FeedError('the feed is not valid XML') from exc
    channel = root.find('channel')
    if root.tag != 'rss' or channel is None:
        raise FeedError('the feed is not an RSS feed')
    out = []
    for item in channel.findall('item')[:MAX_ITEMS]:
        link = safe_link(item.findtext('link'))
        published = _when(item.findtext('pubDate'))
        slug = link.rsplit('/', 1)[-1] if link else ''
        if not link or published is None or not SLUG_RE.match(slug):
            continue  # a link off the Zero Wire address, or an item with no date: not kept
        guid = clean(item.findtext('guid') or link, 200)
        cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(item.findtext(CONTENT) or '')))[:MAX_CVES]  # the briefing is read for these and dropped
        cats = list(dict.fromkeys(c for c in (_plain(e.text, CATEGORY_MAX) for e in item.findall('category')) if c))[:MAX_CATEGORIES]
        out.append({'guid': guid, 'slug': slug, 'title': _plain(item.findtext('title'), TITLE_MAX), 'link': link, 'published_at': published,
                    'summary': _plain(item.findtext('description'), SUMMARY_MAX), 'cve_ids': cves, 'categories': cats})
    return out


def fetch(get=None):
    """The feed's bytes, read no further than MAX_BYTES (the same fixed-address fetch and time-outs as the intelligence feeds). ``get``: a test's stand-in."""
    from cveFeed import intel
    try:
        resp = intel._get(FEED_URL, get=get)
        if resp.status_code != 200:
            resp.close()
            raise FeedError(f'Zero Wire answered {resp.status_code}')
        chunks, size = [], 0
        try:
            for chunk in resp.iter_content(64 * 1024):
                size += len(chunk)
                if size > MAX_BYTES:
                    raise FeedError('the feed is larger than the limit')
                chunks.append(chunk)
        finally:
            resp.close()
        return b''.join(chunks)
    except FeedError:
        raise
    except Exception as exc:  # noqa: BLE001 - any network failure is one short sentence
        logger.warning('Zero Wire fetch failed (%s)', type(exc).__name__)
        raise FeedError('Zero Wire could not be reached') from exc


def sync(now=None, get=None):
    """Read the feed and store its briefings (upserted by guid). Does nothing, and fetches nothing, while the switch is off. Returns a small dict."""
    from cveFeed.models import ReportingSettings, ZeroWireBriefing
    now = now or timezone.now()
    from cveFeed import license_safe
    if license_safe.enabled():  # the feed is CC BY-NC 4.0: a hosted install never reads it
        return {'skipped': 'Zero Wire is ' + license_safe.REASON}
    row = ReportingSettings.current()
    if not row.zero_wire_enabled:
        return {'skipped': 'switched off'}
    try:
        items = parse(fetch(get=get))
    except FeedError as exc:
        _record(error=str(exc)[:200])
        return {'error': str(exc)}
    for item in items:
        ZeroWireBriefing.objects.update_or_create(guid=item['guid'], defaults={k: v for k, v in item.items() if k != 'guid'})
    ZeroWireBriefing.objects.filter(published_at__lt=now - timedelta(days=KEEP_DAYS)).delete()
    _record(synced_at=now, error='')
    return {'briefings': len(items)}


def _record(synced_at=None, error=''):
    from cveFeed.models import ReportingSettings
    row = ReportingSettings.objects.first() or ReportingSettings()
    if synced_at:
        row.zero_wire_synced_at = synced_at
    row.zero_wire_error = error
    row.save()
