"""Certificate Transparency monitoring: every target domain is "subscribed" to crt.sh so a certificate
issued for a new subdomain shows up here on its own, without waiting for the next active discovery pass.

This is purely passive: one read-only HTTPS GET to a public CT log aggregator per check, the same source
bbot's own ``crt`` module uses. Nothing is sent to the target itself.
"""
import json
import logging
import os
import random
import re
import threading
import time

import requests

logger = logging.getLogger(__name__)

CRT_SH_URL = 'https://crt.sh/'
REQUEST_TIMEOUT = 45          # crt.sh is slow on big domains
MIN_GAP = (1.5, 2.5)          # seconds between lookups, across every worker: crt.sh blocks bursts
MAX_ATTEMPTS = 4
MAX_BYTES = 32 * 1024 * 1024  # a reply larger than this is refused unread: %.domain of a big target can be hundreds of MB
MAX_BACKOFF = 120             # never wait longer than this on one retry, whatever Retry-After says
MAX_NEW_PER_RUN = 200  # a cap, not a truncation of what gets recorded over time: the rest show up next run
_LABEL = r'[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
_HOSTNAME_RE = re.compile(rf'^(\*\.)?({_LABEL}\.)+[a-z]{{2,63}}$')


def _clean_name(raw, domain):
    """One line of crt.sh's name_value -> a lowercase hostname under ``domain``, or None if unusable."""
    name = raw.strip().lower().rstrip('.')
    if name.startswith('*.'):
        name = name[2:]
    if not name or not _HOSTNAME_RE.match(name) and name != domain:
        return None
    if name != domain and not name.endswith(f'.{domain}'):
        return None  # crt.sh substring search can surface unrelated certs; keep only this domain's own tree
    return name


def parse_ct_entries(entries, domain):
    """``entries`` is crt.sh's decoded JSON (a list of certs, each with a ``name_value`` of one or more
    newline-separated names). Returns the deduplicated, in-scope hostnames."""
    names = set()
    for entry in entries:
        for raw in str(entry.get('name_value', '')).splitlines():
            name = _clean_name(raw, domain)
            if name:
                names.add(name)
    return names


# --- politeness: one lookup at a time, spaced out, backing off when crt.sh says so ------------------------------------

_SLOT_LUA = """
local nxt = tonumber(redis.call('GET', KEYS[1]) or '0')
local at = math.max(tonumber(ARGV[1]), nxt)
redis.call('SET', KEYS[1], at + tonumber(ARGV[2]), 'EX', 900)
return tostring(at)
"""
_PUSH_LUA = """
local nxt = tonumber(redis.call('GET', KEYS[1]) or '0')
redis.call('SET', KEYS[1], math.max(nxt, tonumber(ARGV[1])), 'EX', 900)
return 1
"""
_local = {'next': 0.0}
_local_lock = threading.Lock()
_SLOT_KEY = 'cvengine:crtsh:next'


def _redis():
    from reNgine import resources
    return getattr(resources.get_store(), 'r', None)


def reserve_slot(gap, now=time.time):
    """Seconds to wait before this lookup may go. Slots are handed out in order and ``gap`` apart, shared by every worker
    process when Redis is there, else per process."""
    client = _redis()
    if client is not None:
        try:
            at = float(client.eval(_SLOT_LUA, 1, _SLOT_KEY, now(), gap))
            return max(0.0, at - now())
        except Exception:  # noqa: BLE001 - a Redis hiccup must not stop the monitor
            pass
    with _local_lock:
        at = max(now(), _local['next'])
        _local['next'] = at + gap
        return max(0.0, at - now())


def push_back(seconds, now=time.time):
    """Everyone waits at least this long before the next lookup (crt.sh asked us to slow down)."""
    until = now() + seconds
    client = _redis()
    if client is not None:
        try:
            client.eval(_PUSH_LUA, 1, _SLOT_KEY, until)
            return
        except Exception:  # noqa: BLE001
            pass
    with _local_lock:
        _local['next'] = max(_local['next'], until)


def _retry_after(resp):
    try:
        return min(float(resp.headers.get('Retry-After')), MAX_BACKOFF)
    except (TypeError, ValueError, AttributeError):
        return None


def _read_json(resp):
    """The decoded JSON of a streamed reply, read at most MAX_BYTES (ValueError above that or when it is not JSON)."""
    body, size = [], 0
    try:
        for chunk in resp.iter_content(65536):
            size += len(chunk)
            if size > MAX_BYTES:
                raise ValueError(f'the reply is larger than {MAX_BYTES // (1024 * 1024)} MB')
            body.append(chunk)
    finally:
        resp.close()
    return json.loads(b''.join(body).decode('utf-8', 'replace') or '[]')


def _fetch(domain, timeout=REQUEST_TIMEOUT, sleep=time.sleep):
    """Entries for ``domain`` from crt.sh, or None when it could not be reached after several polite attempts. A shared provider
    domain (``jfrog.com``) is never queried: ``%.jfrog.com`` is every customer of the provider, not this target's tree."""
    from targetApp.shared_domains import is_provider_domain
    if is_provider_domain(domain):
        logger.info('crt.sh lookup for %s skipped: a shared provider domain, not an owned scope', domain)
        return []
    for attempt in range(MAX_ATTEMPTS):
        sleep(reserve_slot(random.uniform(*MIN_GAP)))
        last = attempt + 1 == MAX_ATTEMPTS
        try:
            resp = requests.get(CRT_SH_URL, params={'q': f'%.{domain}', 'output': 'json'}, timeout=timeout, stream=True)
        except requests.Timeout as exc:
            logger.warning('crt.sh lookup for %s timed out (attempt %s of %s): %s', domain, attempt + 1, MAX_ATTEMPTS, exc)
            if last:
                return None
            push_back(min(2 ** attempt * 5, MAX_BACKOFF))
            continue
        except requests.RequestException as exc:
            logger.warning('crt.sh lookup failed for %s: %s', domain, exc)
            return None
        status = resp.status_code if isinstance(getattr(resp, 'status_code', None), int) else 200
        if status == 429 or status >= 500:
            wait = _retry_after(resp) or min(2 ** attempt * 10, MAX_BACKOFF)
            logger.info('crt.sh answered %s for %s; backing off %.0fs (attempt %s of %s)', status, domain, wait, attempt + 1, MAX_ATTEMPTS)
            if last:
                logger.warning('crt.sh lookup failed for %s: HTTP %s after %s attempts', domain, status, MAX_ATTEMPTS)
                return None
            push_back(wait)
            continue
        try:
            resp.raise_for_status()
            entries = _read_json(resp)
        except (requests.RequestException, ValueError, RecursionError) as exc:
            logger.warning('crt.sh lookup failed for %s: %s', domain, exc)
            return None
        return entries if isinstance(entries, list) else []
    return None


def fetch_ct_names(domain, timeout=REQUEST_TIMEOUT):
    """Every hostname crt.sh has a certificate for under ``domain``. An empty set when crt.sh cannot be reached: a watcher
    that cannot reach it must not fail the discovery it is layered on top of."""
    entries = _fetch(domain, timeout)
    return set() if entries is None else parse_ct_entries(entries, domain)


def run_ct_watch(domain_id, fetch=fetch_ct_names):
    """Check one target's certificate history for hosts CVEngine does not already know about."""
    from django.utils import timezone

    from cveFeed import activity
    from cveFeed.models import DiscoveryEvent
    from startScan.ip_rows import get_or_create_first
    from startScan.models import Subdomain
    from targetApp.models import Domain
    domain = Domain.objects.get(pk=domain_id)
    known = set(Subdomain.objects.filter(target_domain=domain).values_list('name', flat=True))
    if fetch is fetch_ct_names:  # the real lookup: tell "unreachable" apart from "nothing found" so the task can try again later
        entries = _fetch(domain.name)
        if entries is None:
            return {'checked': 0, 'new': 0, 'failed': True}
        found = parse_ct_entries(entries, domain.name)
    else:
        found = fetch(domain.name)
    from cveFeed import ledger
    ledger.record('ct-watch', [domain.name], domain.project_id)  # the sweep skips targets checked in the last 24 hours
    from cveFeed.exclusions import drop_excluded
    new_names = drop_excluded(domain.project_id, sorted(found - known))[:MAX_NEW_PER_RUN]  # an excluded host is never re-created
    if not new_names:
        return {'checked': len(found), 'new': 0}
    created = []
    for name in new_names:
        sub, was_created = get_or_create_first(
            Subdomain, target_domain=domain, name=name,
            defaults={'is_imported_subdomain': True, 'discovered_date': timezone.now()})
        if was_created:
            created.append(sub)
            DiscoveryEvent.objects.create(scan=None, domain=domain, type='DNS_NAME', label=name, host=name,
                                          parent_host=domain.name, module='ct-monitor')
    if created:
        from cveFeed.bounty_gate import Gate
        gate = Gate()  # a bug bounty project is recorded but not scanned on its own: not before its owner confirmed automated testing, not outside the program's scope
        to_scan = [s.name for s in created if gate.allows(domain.project_id, s.name)]
        try:  # the new hosts get fingerprinted and checked now, not at the next full discovery
            from cveFeed.tasks import host_pipeline
            if to_scan:
                host_pipeline.delay(domain.id, to_scan)
        except Exception:  # noqa: BLE001 - a queue problem must not lose the finds, which are already recorded
            logger.exception('could not queue the pipeline for %s new host(s) of %s', len(created), domain.name)
        activity.log('discovery', (
            f'Certificate transparency: {len(created)} new host{"s" if len(created) != 1 else ""} for {domain.name} '
            f'({", ".join(s.name for s in created[:3])}{", ..." if len(created) > 3 else ""})'),
            project=domain.project_id)
    return {'checked': len(found), 'new': len(created)}
