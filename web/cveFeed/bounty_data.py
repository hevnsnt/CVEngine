"""The bug bounty program catalogue: public scope data of HackerOne, Bugcrowd, Intigriti and YesWeHack.

Source: the hourly data dumps of https://github.com/arkadiyt/bounty-targets-data (MIT), which the maintainer refreshes every 30
minutes from each platform's public program pages. One JSON file per platform, fetched over HTTPS from a fixed address with an
ETag so an unchanged file costs one small request. A file that does not parse, is far smaller than the last one, or is too large is
refused and the stored catalogue stays as it was. Nothing in the data is trusted: names and identifiers are cut to a length and a
safe alphabet, and the UI renders every value as plain text.

``normalize_*`` are pure and tested without a database. ``sync_platform`` writes the catalogue and the scope-change radar.
"""
import hashlib
import ipaddress
import json
import logging
import re
from datetime import timedelta

logger = logging.getLogger(__name__)

BASE = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/"
SOURCES = {
    "hackerone": BASE + "hackerone_data.json",
    "bugcrowd": BASE + "bugcrowd_data.json",
    "intigriti": BASE + "intigriti_data.json",
    "yeswehack": BASE + "yeswehack_data.json",
}
USER_AGENT = "CVEngine bounty catalogue (+https://github.com/hevnsnt/CVEngine)"
MAX_BYTES = 120 * 1024 * 1024
MAX_PROGRAMS = 5000
MAX_ASSETS_PER_PROGRAM = 20000
SHRINK_LIMIT = 0.5  # a file with fewer than this share of the stored programs is treated as truncated, not as a change
CHANGE_RETENTION_DAYS = 180

CONTROL = re.compile(r"[\x00-\x1f\x7f]")
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
WILDCARD_RE = re.compile(r"^\*\.(" + HOST_RE.pattern[len("^(?=.{1,253}$)"):-1] + r")$")
SPLIT = re.compile(r"[,;\s]+")
MOBILE_TYPES = {"google_play_app_id", "apple_store_app_id", "other_apk", "android", "ios", "mobile-application-android",
                "mobile-application-ios", "mobile-application", "testflight", "windows_app_store_app_id", "apple_store_app_id"}
CODE_TYPES = {"source_code", "code"}
SEVERITIES = ("none", "low", "medium", "high", "critical")


def clean_text(value, limit):
    return CONTROL.sub(" ", str(value if value is not None else "")).strip()[:limit]


def _number(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, dict):
        value = value.get("value")
    return int(value) if isinstance(value, (int, float)) and 0 <= value < 10 ** 9 else None


def _currency(value):
    return clean_text(value.get("currency"), 8).upper() if isinstance(value, dict) else ""


def _hours(value):
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value < 10 ** 7 else None


# --- assets -------------------------------------------------------------------------------------

def _strip_url(text):
    """(host-ish text, path) of an identifier that may carry a scheme, credentials, a port or a path."""
    rest = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", text)
    rest = rest.split("#", 1)[0].split("?", 1)[0]
    authority, _, path = rest.partition("/")
    authority = authority.rsplit("@", 1)[-1]
    if authority.startswith("[") and "]" in authority:  # a bracketed IPv6 literal
        authority = authority[1:authority.index("]")]
    elif authority.count(":") == 1:
        authority = authority.split(":", 1)[0]
    return authority.strip().rstrip(".").lower(), ("/" + path).rstrip("/") if path.strip("/") else ""


CIDR_RE = re.compile(r"^[0-9a-fA-F:.]+/\d{1,3}$")
RANGE_RE = re.compile(r"^([0-9a-fA-F:.]+)\s*-\s*([0-9a-fA-F:.]+)$")
MAX_RANGE_CIDRS = 64


def _network_assets(text):
    """``[("cidr", ...)]`` for a CIDR block or an "a.b.c.d - e.f.g.h" range, else None. A range is split into the CIDR blocks that
    cover it exactly, so a host is matched by membership and never by a guess."""
    text = text.strip()
    try:
        if CIDR_RE.match(text):
            nets = [ipaddress.ip_network(text, strict=False)]
        else:
            m = RANGE_RE.match(text)
            if not m:
                return None
            nets = list(ipaddress.summarize_address_range(ipaddress.ip_address(m.group(1)), ipaddress.ip_address(m.group(2))))
            if not 0 < len(nets) <= MAX_RANGE_CIDRS:
                return [("other", text[:500])]
    except (ValueError, TypeError):
        return [("other", text[:500])]  # "10.0.0.0/33", a reversed range: not a network, but not a host name either
    if any(n.prefixlen < (8 if n.version == 4 else 24) for n in nets):
        return [("other", text[:500])]  # a block that wide is a typo or the whole internet, never a scope this tool should read
    return [("cidr", str(n)) for n in nets]


def _one_asset(text, raw_type):
    kind_hint = (raw_type or "").strip().lower()
    nets = _network_assets(text)
    if nets:
        return nets
    if kind_hint in MOBILE_TYPES:
        return [("mobile", text[:500])] if text else None
    if kind_hint in CODE_TYPES:
        return [("code", text[:500])] if text else None
    host, path = _strip_url(text)
    if not host or "/" in host or " " in host:
        return None
    try:
        return [("ip", str(ipaddress.ip_address(host)))]
    except ValueError:
        pass
    if host.startswith("*."):
        return [("wildcard", host) if WILDCARD_RE.match(host) and not path else ("other", text[:500])]
    if "*" in host:
        return [("other", text[:500])]  # api-*.example.com and similar: a pattern this matcher does not interpret
    if not HOST_RE.match(host):
        return None
    return [("url", host + path) if path else ("domain", host)]


def normalize_asset(raw_type, identifier):
    """``[(kind, identifier)]`` for one scope entry: a list because one entry may name several hosts ("a.com, b.com"). Entries
    that name nothing a scanner could use (prose, an unparseable value) come back as ``[("other", text)]`` so the program still
    shows that its scope has a part this tool cannot read; an empty value gives ``[]``."""
    text = CONTROL.sub(" ", str(identifier or "")).strip()
    if not text or len(text) > 2000 or not re.search(r"[A-Za-z0-9]", text):
        return []  # empty, too long, or redacted (a row of block characters names nothing)
    one = _one_asset(text, raw_type)
    if one:
        return one
    pieces = [p for p in SPLIT.split(text) if p]
    if 1 < len(pieces) <= 20:
        found = [_one_asset(p, raw_type) for p in pieces]
        if all(found):
            return list(dict.fromkeys(x for group in found for x in group))
    return [("other", text[:500])]


def _asset(row_type, identifier, in_scope, eligible, severity, instruction):
    out = []
    for kind, ident in normalize_asset(row_type, identifier):
        if len(ident) > 500:  # longer than the column: a cut-off host or URL would name something else, so it is only shown as text
            kind, ident = "other", ident[:500]
        out.append({"kind": kind, "identifier": ident, "raw_type": clean_text(row_type, 64), "in_scope": bool(in_scope),
                    "eligible_for_bounty": eligible, "max_severity": severity if severity in SEVERITIES else "",
                    "instruction": clean_text(instruction, 1000)})
    return out


# --- programs -----------------------------------------------------------------------------------

def _program(platform, handle, name, **kw):
    handle = clean_text(handle, 200)
    if not handle:
        return None
    return {"platform": platform, "handle": handle, "name": clean_text(name or handle, 300), "url": clean_text(kw.get("url"), 500),
            "offers_bounties": kw.get("offers_bounties"), "min_bounty": kw.get("min_bounty"), "max_bounty": kw.get("max_bounty"),
            "currency": kw.get("currency", ""), "safe_harbor": clean_text(kw.get("safe_harbor"), 16).lower(),
            "managed": bool(kw.get("managed")), "state": clean_text(kw.get("state"), 32),
            "response_efficiency": kw.get("response_efficiency"), "first_response_hours": kw.get("first_response_hours"),
            "resolved_hours": kw.get("resolved_hours"), "assets": kw.get("assets", [])[:MAX_ASSETS_PER_PROGRAM]}


def _targets(row):
    t = row.get("targets") if isinstance(row, dict) else None
    t = t if isinstance(t, dict) else {}
    return [x for x in (t.get("in_scope") or []) if isinstance(x, dict)], [x for x in (t.get("out_of_scope") or []) if isinstance(x, dict)]


def normalize_hackerone(row):
    inside, outside = _targets(row)
    assets = []
    for a in inside:
        assets += _asset(a.get("asset_type"), a.get("asset_identifier"), a.get("eligible_for_submission", True) is not False,
                         a.get("eligible_for_bounty"), a.get("max_severity"), a.get("instruction"))
    for a in outside:
        assets += _asset(a.get("asset_type"), a.get("asset_identifier"), False, None, "", a.get("instruction"))
    return _program("hackerone", row.get("handle"), row.get("name"), url=row.get("url") or f"https://hackerone.com/{row.get('handle')}",
                    offers_bounties=row.get("offers_bounties") if isinstance(row.get("offers_bounties"), bool) else None,
                    managed=row.get("managed_program"), state=row.get("submission_state"),
                    response_efficiency=_number(row.get("response_efficiency_percentage")),
                    first_response_hours=_hours(row.get("average_time_to_first_program_response")),
                    resolved_hours=_hours(row.get("average_time_to_report_resolved")), assets=assets)


def normalize_bugcrowd(row):
    inside, outside = _targets(row)
    url = clean_text(row.get("url"), 500)
    handle = url.rstrip("/").rsplit("/", 1)[-1] if url else ""
    assets = []
    for group, flag in ((inside, True), (outside, False)):
        for a in group:
            ident = a.get("uri") or a.get("target") or a.get("name") or ""
            assets += _asset(a.get("type"), ident, flag, None, "", a.get("name") if a.get("uri") else "")
    payout = _number(row.get("max_payout"))
    return _program("bugcrowd", handle, row.get("name"), url=url, offers_bounties=(payout > 0) if payout is not None else None,
                    max_bounty=payout, safe_harbor=row.get("safe_harbor") or "", managed=row.get("managed_by_bugcrowd"),
                    state="open", assets=assets)


def normalize_intigriti(row):
    inside, outside = _targets(row)
    assets = []
    for group, flag in ((inside, True), (outside, False)):
        for a in group:
            impact = clean_text(a.get("impact"), 64).lower()
            assets += _asset(a.get("type"), a.get("endpoint"), flag, None if not flag or not impact else impact != "no bounty",
                             "", a.get("description"))
    low, high = row.get("min_bounty"), row.get("max_bounty")
    top = _number(high)
    handle = f"{clean_text(row.get('company_handle'), 80)}/{clean_text(row.get('handle'), 80)}" if row.get("company_handle") else row.get("handle")
    return _program("intigriti", handle, row.get("name"), url=row.get("url"), offers_bounties=(top > 0) if top is not None else None,
                    min_bounty=_number(low), max_bounty=top, currency=_currency(high) or _currency(low), state=row.get("status"),
                    assets=assets)


def normalize_yeswehack(row):
    inside, outside = _targets(row)
    assets = []
    for group, flag in ((inside, True), (outside, False)):
        for a in group:
            assets += _asset(a.get("type"), a.get("target"), flag, None, "", "")
    top = _number(row.get("max_bounty"))
    slug = clean_text(row.get("id"), 120)
    return _program("yeswehack", slug, row.get("name"), url=f"https://yeswehack.com/programs/{slug}" if slug else "",
                    offers_bounties=(top > 0) if top is not None else None, min_bounty=_number(row.get("min_bounty")), max_bounty=top,
                    managed=row.get("managed"), state="disabled" if row.get("disabled") else ("public" if row.get("public") else "private"),
                    assets=assets)


NORMALIZERS = {"hackerone": normalize_hackerone, "bugcrowd": normalize_bugcrowd, "intigriti": normalize_intigriti,
               "yeswehack": normalize_yeswehack}


def normalize_payload(platform, payload):
    """The normalized programs of one platform's file. A row that is not an object, or has no usable handle, is skipped."""
    if not isinstance(payload, list):
        raise ValueError("the data file is not a list of programs")
    out = []
    for row in payload[:MAX_PROGRAMS]:
        if not isinstance(row, dict):
            continue
        try:
            program = NORMALIZERS[platform](row)
        except (TypeError, ValueError, AttributeError):
            continue
        if program:
            seen = set()
            program["assets"] = [a for a in program["assets"] if (a["identifier"], a["raw_type"], a["in_scope"]) not in seen
                                 and not seen.add((a["identifier"], a["raw_type"], a["in_scope"]))]
            out.append(program)
    return out


def content_hash(program):
    parts = [program["name"], program["url"], str(program["offers_bounties"]), str(program["min_bounty"]), str(program["max_bounty"]),
             program["safe_harbor"], program["state"]]
    parts += sorted(f"{a['kind']}|{a['identifier']}|{a['raw_type']}|{int(a['in_scope'])}|{a['eligible_for_bounty']}|{a['max_severity']}"
                    for a in program["assets"])
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()


# --- fetching and storing -----------------------------------------------------------------------

def fetch(url, etag="", get=None):
    """``(payload, etag)``, or ``(None, etag)`` when the file has not changed. Only the fixed addresses in SOURCES are fetched."""
    import requests
    if url not in SOURCES.values():
        raise ValueError("not a catalogue address")
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if etag:
        headers["If-None-Match"] = etag
    resp = (get or requests.get)(url, headers=headers, timeout=(10, 90), stream=True, allow_redirects=False)
    try:
        if resp.status_code == 304:
            return None, etag
        if resp.status_code != 200:
            raise ValueError(f"the data host answered {resp.status_code}")
        chunks, size = [], 0
        for chunk in resp.iter_content(1024 * 1024):
            size += len(chunk)
            if size > MAX_BYTES:
                raise ValueError("the data file is larger than the limit")
            chunks.append(chunk)
        return json.loads(b"".join(chunks)), (resp.headers.get("ETag") or "")[:200]
    finally:
        resp.close()


def _sync_program(program, existing, assets_by_program, now, first_run, changes):
    """Insert or update one program and its assets; append scope changes. Returns the new BountyProgram row's counters."""
    from cveFeed.models import BountyAsset, BountyProgram, BountyScopeChange
    digest = content_hash(program)
    row = existing.get(program["handle"])
    fields = {k: program[k] for k in ("name", "url", "offers_bounties", "min_bounty", "max_bounty", "currency", "safe_harbor", "managed",
                                      "state", "response_efficiency", "first_response_hours", "resolved_hours")}
    in_scope = [a for a in program["assets"] if a["in_scope"]]
    counts = {"in_scope_count": len(in_scope), "bounty_scope_count": sum(1 for a in in_scope if a["eligible_for_bounty"])}
    if row is None:
        row = BountyProgram.objects.create(platform=program["platform"], handle=program["handle"], content_hash=digest,
                                           first_seen_at=now, **fields, **counts)
        BountyAsset.objects.bulk_create([BountyAsset(program=row, first_seen_at=now, **a) for a in program["assets"]], batch_size=1000)
        if not first_run:
            changes.append(BountyScopeChange(program=row, kind="program_added", detected_at=now))
        return
    if row.content_hash == digest and row.removed_at is None:
        return
    came_back = row.removed_at is not None
    for k, v in {**fields, **counts}.items():
        setattr(row, k, v)
    row.content_hash, row.removed_at = digest, None
    old = {(a.identifier, a.raw_type, a.in_scope): a for a in assets_by_program.get(row.pk, [])}
    new = {(a["identifier"], a["raw_type"], a["in_scope"]): a for a in program["assets"]}
    add, update, scope_moved = [], [], False
    for key, a in new.items():
        have = old.get(key)
        if have is None:
            twin = old.get((key[0], key[1], not key[2]))  # the same entry on the other side of the in/out line
            add.append(BountyAsset(program=row, first_seen_at=now, **a))
            changes.append(BountyScopeChange(program=row, kind="asset_flipped" if twin and twin.removed_at is None else "asset_added",
                                             asset_kind=a["kind"], identifier=a["identifier"], in_scope=a["in_scope"], detected_at=now))
            scope_moved = True
            continue
        if have.removed_at is not None:
            have.removed_at = None
            changes.append(BountyScopeChange(program=row, kind="asset_added", asset_kind=a["kind"], identifier=a["identifier"],
                                             in_scope=a["in_scope"], detected_at=now))
            scope_moved = True
        have.eligible_for_bounty, have.max_severity, have.instruction, have.kind = (
            a["eligible_for_bounty"], a["max_severity"], a["instruction"], a["kind"])
        update.append(have)
    for key, have in old.items():
        if key not in new and have.removed_at is None:
            have.removed_at = now
            update.append(have)
            if (have.identifier, have.raw_type, not have.in_scope) not in new:
                changes.append(BountyScopeChange(program=row, kind="asset_removed", asset_kind=have.kind, identifier=have.identifier,
                                                 in_scope=have.in_scope, detected_at=now))
                scope_moved = True
    if came_back and not first_run:
        changes.append(BountyScopeChange(program=row, kind="program_added", detected_at=now))
    if scope_moved and not first_run:
        row.last_scope_change_at = now
    row.save()
    BountyAsset.objects.bulk_create(add, batch_size=1000)
    BountyAsset.objects.bulk_update(update, ["eligible_for_bounty", "max_severity", "instruction", "kind", "removed_at"], batch_size=1000)


def sync_platform(platform, fetcher=fetch, now=None):
    """Bring one platform's catalogue up to date. Returns a small status dict and never raises: a failed fetch is recorded on the
    BountySource row and leaves the stored catalogue untouched."""
    from django.db import transaction
    from django.utils import timezone
    from cveFeed.models import BountyAsset, BountyProgram, BountyScopeChange, BountySource
    now = now or timezone.now()
    source, _ = BountySource.objects.get_or_create(platform=platform)

    def fail(message):
        source.last_checked, source.last_error = now, clean_text(message, 300)
        source.save(update_fields=["last_checked", "last_error"])
        logger.warning("bounty catalogue %s: %s", platform, message)
        return {"platform": platform, "status": "error", "error": source.last_error}

    try:
        payload, etag = fetcher(SOURCES[platform], source.etag)
    except Exception as exc:  # noqa: BLE001 - any fetch or parse problem must leave the catalogue as it was
        return fail(f"fetch failed: {exc}")
    if payload is None:
        source.last_checked, source.last_error = now, ""
        source.save(update_fields=["last_checked", "last_error"])
        return {"platform": platform, "status": "unchanged"}
    try:
        programs = normalize_payload(platform, payload)
    except ValueError as exc:
        return fail(str(exc))
    stored = BountyProgram.objects.filter(platform=platform, removed_at__isnull=True).count()
    if not programs and stored:
        return fail("the data file has no programs; the stored catalogue was kept")
    if stored and len(programs) < stored * SHRINK_LIMIT:
        return fail(f"the data file lists {len(programs)} programs against {stored} stored; treated as truncated and ignored")
    first_run = not BountyProgram.objects.filter(platform=platform).exists()
    changes = []
    with transaction.atomic():
        existing = {p.handle: p for p in BountyProgram.objects.filter(platform=platform)}
        by_program = {}
        for a in BountyAsset.objects.filter(program__platform=platform).iterator(chunk_size=5000):
            by_program.setdefault(a.program_id, []).append(a)
        listed = set()
        for program in programs:
            listed.add(program["handle"])
            _sync_program(program, existing, by_program, now, first_run, changes)
        for handle, row in existing.items():
            if handle not in listed and row.removed_at is None:
                row.removed_at = now
                row.save(update_fields=["removed_at", "updated_at"])
                changes.append(BountyScopeChange(program=row, kind="program_removed", detected_at=now))
        BountyScopeChange.objects.bulk_create(changes, batch_size=1000)
        BountyScopeChange.objects.filter(detected_at__lt=now - timedelta(days=CHANGE_RETENTION_DAYS)).delete()
        source.etag, source.last_checked, source.last_changed, source.last_error = etag, now, now, ""
        source.programs = len(programs)
        source.assets = sum(len(p["assets"]) for p in programs)
        source.save()
    return {"platform": platform, "status": "updated", "programs": len(programs), "changes": len(changes), "first_run": first_run}


def sync_all(platforms=None, fetcher=fetch, now=None):
    return [sync_platform(p, fetcher=fetcher, now=now) for p in (platforms or SOURCES)]
