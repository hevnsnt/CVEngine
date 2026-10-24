"""Correlate stored cve.now entries against the discovered asset inventory.

Deterministic candidate generation first: match each discovered Technology (and
its version, when reNgine captured one) against the product/package names and
version ranges in `CVEEntry.affected`. Candidates become `CVEMatch` rows with a
heuristic confidence; the user's chosen AI model can then confirm each one
(`ai_confirm_match`), which is what makes exposure precise rather than noisy.

The version/name helpers are pure Python (no Django import) so they are unit
testable on their own.
"""
import logging
import re

from cveFeed import distro as distro_lib

logger = logging.getLogger(__name__)

_VER_RE = re.compile(r"(\d+(?:\.\d+)*)")
_MIN_TOKEN = 3  # ignore 1-2 char product tokens to avoid noise
# Cloud-provider and generic service labels identify infrastructure, not a vulnerable product.
# A concrete product (for example Multi Model Server) must be observed separately.
GENERIC_PRODUCT_TOKENS = frozenset({
    'aws', 'awsservice', 'amazonaws', 'amazonwebservices', 'amazonwebservice',
    'azure', 'azureservice', 'microsoftazure', 'googlecloud', 'googlecloudservice',
    'cloudservice', 'webservice', 'service',
})


def split_name_version(tech_name):
    """reNgine stores tech as 'Name' or 'Name:version' (httpx tech-detect)."""
    if not tech_name:
        return "", ""
    name = tech_name.strip()
    if ":" in name:
        base, _, ver = name.rpartition(":")
        if ver and ver[0].isdigit():
            return base.strip(), ver.strip()
    return name, ""


_EPOCH_RE = re.compile(r"^\s*\d+:(?=\d)")  # a dpkg/rpm epoch: "1:8.9p1-3ubuntu0.6"
_HASH_RE = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)  # a git commit, not a version
# a pre-release marker straight after the numbers: 2.0-beta9, 1.0rc1, 9.0.0-M1, 3.0.0.dev4. It sorts before the release, so it
# becomes a negative component (2.0-beta9 -> (2, 0, -3, 9) < (2, 0)). The bare letters a/b/m need a number after them: "1.0.2a"
# is OpenSSL's patch letter, not an alpha.
_PRE_RE = re.compile(r"^[-_.~+ ]?(?:(alpha|beta|rc|cr|pre|dev|snapshot)|(a|b|m))[-_. ]?(\d+)?", re.IGNORECASE)
_PRE_RANK = {"dev": -6, "snapshot": -6, "alpha": -5, "a": -5, "beta": -4, "b": -4, "m": -3, "pre": -2, "cr": -1, "rc": -1}


def parse_version(value, strict=False):
    """Best-effort dotted version -> tuple of ints, else None.

    A leading epoch ("1:") is dropped, a "v" prefix ignored, and a pre-release marker becomes a negative component so
    2.0-beta9 sorts before 2.0. A commit hash is not a version. With ``strict`` (a bound from a feed, not a banner) the text must
    start with a digit, so a ref like "main" or a hash can never be read as version 3."""
    if not value:
        return None
    text = _EPOCH_RE.sub("", str(value)).strip()
    if text[:1] in ("v", "V") and text[1:2].isdigit():
        text = text[1:]
    if _HASH_RE.match(text) and not text.isdigit():
        return None
    match = _VER_RE.match(text) if strict else _VER_RE.search(text)
    if not match:
        return None
    try:
        parts = [int(part) for part in match.group(1).split(".")]
    except ValueError:
        return None
    pre = _PRE_RE.match(text[match.end():])
    if pre and (pre.group(1) or pre.group(3)):
        parts += [_PRE_RANK[(pre.group(1) or pre.group(2)).lower()], int(pre.group(3) or 0)]
    return tuple(parts)


def _vcmp(a, b):
    """Compare two version tuples, zero-padded so (1,18) == (1,18,0)."""
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def version_in_range(ver, rng):
    """Return True / False / None(unknown) for ver within an affected range dict. A range with no usable bound is unknown,
    never "in range": only a real bound can put a version inside it."""
    if ver is None:
        return None
    if str(rng.get("type") or "SEMVER").upper() not in ("SEMVER", "ECOSYSTEM"):
        return None  # a GIT range is commit hashes: it cannot be compared with a version
    bounds = [(rng.get(key), parse_version(rng.get(key), strict=True)) for key in ("introduced", "fixed", "lastAffected")]
    if any(raw and parsed is None for raw, parsed in bounds):
        return None  # a bound that is not a version ("unspecified", a hash) makes the whole range unknown, never "in range"
    introduced, fixed, last = (parsed for _raw, parsed in bounds)
    if introduced is None and fixed is None and last is None:
        return None  # no usable bound: the range says nothing about this version
    if introduced is not None and _vcmp(ver, introduced) < 0:
        return False
    if fixed is not None and _vcmp(ver, fixed) >= 0:
        return False
    if last is not None and _vcmp(ver, last) > 0:
        return False
    return True


def _norm(value):
    return re.sub(r"[^a-z0-9]", "", (value or "").lower())


def affected_product_tokens(affected_item):
    """Normalized product/package tokens for one affected entry.

    The vendor is never a token, alone or joined to the product: "apache" or "microsoft" would make every CVE of the
    vendor a candidate for a host running any product of it (an Apache HTTP Server host is not a Log4j host), and a
    vendor+product token would match a bare "Apache" banner to Log4j and Tomcat. The vendor is only used to
    disambiguate (see _vendor_ok)."""
    tokens = set()
    for key in ("product", "package"):
        token = _norm(affected_item.get(key))
        if len(token) >= _MIN_TOKEN and token not in GENERIC_PRODUCT_TOKENS:
            tokens.add(token)
    return tokens


# Names scanners report that differ from the feed's product naming: normalized tech token -> product tokens naming the
# same software. Dropping the vendor token must not create false negatives for these. Aliases are the only widening.
PRODUCT_ALIASES = {
    "apachehttpd": {"httpserver", "apache2"},
    "apachehttpserver": {"httpserver", "apache2"},
    "httpd": {"httpserver", "apache2"},
    "apache": {"httpserver", "apache2"},
    "microsoftiishttpd": {"internetinformationservices", "iis"},
    "microsoftiis": {"internetinformationservices", "iis"},
    "iis": {"internetinformationservices"},
    "eximsmtpd": {"exim"},
    "iscbind": {"bind"},
    "bind9": {"bind"},
}


def tech_tokens(token):
    """The tech token plus the product tokens it is an alias of."""
    return {token} | PRODUCT_ALIASES.get(token, set())


def parse_cpe(cpe):
    """'cpe:/a:apache:http_server:2.4.52' (2.2) or 'cpe:2.3:a:apache:http_server:2.4.52:...' -> (vendor, product,
    version) with vendor/product normalized like the index tokens; None for an OS/hardware CPE or an unparseable one."""
    text = (cpe or "").strip().lower()
    if text.startswith("cpe:2.3:"):
        parts = text.split(":")[2:]
    elif text.startswith("cpe:/"):
        parts = text[5:].split(":")
    else:
        return None
    if len(parts) < 3 or parts[0] != "a":
        return None
    product = _norm(parts[2])
    version = parts[3] if len(parts) > 3 and parts[3] not in ("*", "-") else ""
    if len(product) < _MIN_TOKEN:
        return None
    return _norm(parts[1]), product, version


def name_matches_token(tech_token, product_token):
    """A discovered tech token plausibly refers to an affected product token."""
    if (len(tech_token) < _MIN_TOKEN or len(product_token) < _MIN_TOKEN
            or tech_token in GENERIC_PRODUCT_TOKENS or product_token in GENERIC_PRODUCT_TOKENS):
        return False
    return tech_token in product_token or product_token in tech_token


def confidence_for(ver, in_range, kev):
    """Heuristic 0..1 confidence before any AI confirmation.

    Version confirmed in range is strong; unknown version is a weak-to-medium
    candidate; out of range is zero (dropped). KEV nudges it up.
    """
    if in_range is False:
        return 0.0
    base = 0.85 if in_range is True else (0.5 if ver is None else 0.4)
    if kev:
        base = min(1.0, base + 0.1)
    return round(base, 2)


# --- Django-dependent orchestration (imports models lazily) --------------------

class ProductIndex(dict):
    """token -> set of CVEEntry ids, with a memo of the fuzzy token -> candidate ids lookups so a product seen on many
    hosts is resolved once. Built by build_product_index and never mutated afterwards (the memo relies on that)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.memo = {}


def build_product_index(cves):
    """Map a normalized product token -> set of CVEEntry ids, for fast lookup.

    `cves` is any iterable of CVEEntry (a queryset or a list).
    """
    index = ProductIndex()
    for cve in cves:
        for item in (cve.affected or []):
            for token in affected_product_tokens(item):
                index.setdefault(token, set()).add(cve.id)
    return index


def _fuzzy_ids(token, product_index):
    """CVE ids whose product/package token plausibly names ``token`` (memoized per index)."""
    memo = getattr(product_index, "memo", None)
    if memo is not None and token in memo:
        return memo[token]
    ids = set()
    for product_token, found in product_index.items():
        if name_matches_token(token, product_token):
            ids |= found
    if memo is not None:
        memo[token] = ids
    return ids


def _vendor_ok(item, *hints):
    """True when the item names no vendor, or its vendor contains one of the (normalized) hints."""
    vendor = _norm(item.get("vendor"))
    return not vendor or any(h in vendor or vendor in h for h in hints)


# alias target -> vendor words that must appear when the item names a vendor (Oracle's "HTTP Server" is not Apache's)
_ALIAS_VENDOR = {"httpserver": ("apache",), "apache2": ("apache",)}


def _item_hits(item, token, aliases=(), cpe_product=None, cpe_vendor=""):
    """Whether one affected entry names the discovered product. With a CPE the product must equal it (and the vendor,
    when the entry has one, must agree); otherwise fuzzy token containment, plus exact alias names."""
    own = {_norm(item.get(k)) for k in ("product", "package")} - {""}
    if cpe_product:
        return cpe_product in own and _vendor_ok(item, cpe_vendor, cpe_vendor[:6])
    tokens = affected_product_tokens(item)
    if any(name_matches_token(token, t) for t in tokens):
        return True
    for alias in aliases:
        if alias in tokens and (alias not in _ALIAS_VENDOR or _vendor_ok(item, *_ALIAS_VENDOR[alias])):
            return True
    return False


def _bounded(rng):
    return version_in_range((0,), rng) is not None  # a range with at least one usable bound


def _match_candidates(name, ver, token, product_index, cve_by_id, cpe=None, details=None):
    """Yield (cve, matched_product, in_range) for CVEs plausibly affecting a
    discovered product `token` (normalized) at version `ver` (tuple or None).

    Only the ranges of the affected entry that names the product are tested, never another product of the same vendor.
    An entry with no usable version bound gives in_range None (unknown), never True. ``cpe`` (nmap's 'cpe:/a:vendor:
    product:version') names the product exactly; it is tried first and the name match is the fallback.

    ``details``, when given, is a dict that receives ``{cve.id: {"affected_index", "range"}}``: which affected entry and which
    range decided the result (the evidence stored on the match).

    Reads only the pre-built product_index / cve_by_id; shared by the technology
    fingerprint path and the nmap/Port service path so both score identically.
    """
    cpe_parts = parse_cpe(cpe)
    candidate_ids, cpe_product, cpe_vendor = set(), None, ""
    if cpe_parts:
        cpe_vendor, cpe_product, _ = cpe_parts
        candidate_ids = set(product_index.get(cpe_product, ()))
        if not candidate_ids:
            cpe_product = None
    aliases = tuple(sorted(PRODUCT_ALIASES.get(token, ())))
    if not cpe_product:
        candidate_ids = set(_fuzzy_ids(token, product_index))
        for alias in aliases:
            candidate_ids |= product_index.get(alias, set())

    for cid in candidate_ids:
        cve = cve_by_id[cid]
        hit = [(i, item) for i, item in enumerate(cve.affected or []) if _item_hits(item, token, aliases, cpe_product, cpe_vendor)]
        if not hit:
            continue
        in_range, matched_product = None, name
        if ver is not None:
            in_range, unknown = False, False
            for index, item in hit:
                ranges = [r for r in (item.get("ranges") or []) if _bounded(r)]
                if not ranges:
                    unknown = True  # the advisory names the product but no version bound: nothing to test against
                    continue
                for rng in ranges:
                    result = version_in_range(ver, rng)
                    if result is True:
                        in_range = True
                        matched_product = item.get("product") or item.get("package") or name
                        if details is not None:
                            details[cve.id] = {"affected_index": index, "range": {k: str(v)[:60] for k, v in rng.items()
                                                                                  if k in ("introduced", "fixed", "lastAffected")}}
                        break
                    if result is None:
                        unknown = True
                if in_range is True:
                    break
            if in_range is not True and unknown:
                in_range = None
        if details is not None and cve.id not in details and hit:
            details[cve.id] = {"affected_index": hit[0][0], "range": {}}
        yield cve, matched_product, in_range


def _has_version_ranges(cve, token):
    """Whether any affected entry naming this product carries a real version range (so a version-less sighting cannot be
    placed in or out of it). Advisories without ranges name the product only, and a host running it stays a candidate."""
    aliases = tuple(PRODUCT_ALIASES.get(token, ()))
    for item in (cve.affected or []):
        if _item_hits(item, token, aliases) and any(_bounded(r) for r in (item.get("ranges") or [])):
            return True
    return False


def _is_ice(cve):
    from cveFeed.threat import ICE, classify_threat_tier
    return classify_threat_tier(
        kev=getattr(cve, "kev", None), epss_reached=getattr(cve, "epss_reached", None),
        exploit_db=getattr(cve, "exploit_db", None), cvss=getattr(cve, "cvss", None)) == ICE


class DbFixLookup:
    """DistroFix rows for (distro, package, CVE) as {release, fixed_version, status} dicts, each read from the database once.
    Correlation takes any callable with this signature, so tests inject a fake instead of filling the table."""

    def __init__(self):
        self.memo = {}

    def __call__(self, distro, package, cve_id):
        key = (distro, package, cve_id)
        if key not in self.memo:
            from cveFeed.models import DistroFix
            self.memo[key] = [{"release": r.release, "fixed_version": r.fixed_version, "status": r.status}
                              for r in DistroFix.objects.filter(distro=distro, package=package, cve_id=cve_id)]
        return self.memo[key]


def port_distro(port):
    """The distro info of a Port row: what nmap persisted, else read from its banner fields now (rows older than the distro
    columns). The package name is derived, never stored."""
    info = {"distro": getattr(port, "distro", "") or "", "release": getattr(port, "distro_release", "") or "",
            "package_release": getattr(port, "package_release", "") or "", "upstream_version": getattr(port, "upstream_version", "") or ""}
    if not info["distro"]:
        info = distro_lib.parse_distro(port.product, port.version, getattr(port, "service_extra", ""), [getattr(port, "cpe", "")])
    info["package"] = distro_lib.package_for(port.product, info["distro"], info["upstream_version"]) if info["distro"] else ""
    return info


def _record_matches(subdomain, name, version, token, source, product_index,
                    cve_by_id, min_confidence, scan_history, rows=None, cpe="", distro=None, fix_lookup=None, evidence=None):
    """Work out the CVEMatch rows for one discovered product on a subdomain and append them to ``rows``
    (written in a batch by ``save_matches``). Returns the number of matches found."""
    if not version and cpe:  # nmap sometimes names the version only in the CPE
        version = (parse_cpe(cpe) or ("", "", ""))[2]
    ver = parse_version(version)
    found = 0
    details = {}
    for cve, matched_product, in_range in _match_candidates(
            name, ver, token, product_index, cve_by_id, cpe=cpe, details=details):
        confidence = confidence_for(ver, in_range, cve.kev)
        if confidence < min_confidence or confidence <= 0.0:
            continue
        if ver is None and in_range is None and _is_ice(cve) and _has_version_ranges(cve, token):
            continue  # a cold CVE with a version range, and no version to test against it: noise, not a lead
        status, fixed = distro_lib.NO_DATA, ""
        if distro and distro.get("distro") and in_range is True:
            # Upstream says in range; the distro may have backported the fix. Never dropped: a patched match is kept,
            # at low confidence and labelled, so a wrong distro reading can only demote it, not hide it.
            rows_for = fix_lookup(distro["distro"], distro.get("package", ""), getattr(cve, "cve_id", "")) \
                if fix_lookup and distro.get("package") else []
            status, fixed = distro_lib.judge(distro, rows_for)
            if status == distro_lib.PATCHED:
                confidence = 0.2
            elif status == distro_lib.VULNERABLE:
                confidence = 0.95  # the distro's own tracker lists this package release as affected: the strongest evidence there is
        rows.append({
            "cve_entry_id": cve.id, "subdomain_id": subdomain.id, "source": source,
            "matched_product": matched_product[:255], "matched_version": version[:100],
            "version_in_range": in_range, "confidence": confidence,
            "scan_history_id": scan_history.id if scan_history else subdomain.scan_history_id,
            "distro_status": status, "distro_fixed_version": fixed[:64],
            "evidence": {**(evidence or {}), "raw_version": version[:100], **details.get(cve.id, {}),
                         **({"distro": {k: v for k, v in distro.items() if v}} if distro and distro.get("distro") else {})},
        })
        found += 1
    return found


def signature_of(obj):
    """What a verdict depends on: the CVE, the product and version found, whether it is in range, and how it was found."""
    return (getattr(obj, "cve_entry_id"), obj.matched_product, obj.matched_version, obj.version_in_range, obj.source)


def invalid_identity_reason(match):
    """A reason to close this *candidate correlation*, never a claim that the host lacks backend software.

    A frontend banner or missing version is not negative evidence. Only the identity that originally
    produced the match is compared with the advisory's named products, using the same aliases as
    candidate generation. Conflicting positive evidence prevents automatic closure.
    """
    if (match.template_result == 'vulnerable' or match.distro_status == 'vulnerable'
            or match.version_in_range is True):
        return ''
    affected = match.cve_entry.affected or []
    if not any(isinstance(item, dict) and affected_product_tokens(item) for item in affected):
        return ''
    token = _norm(match.matched_product)
    if not token:
        return ''
    cve = match.cve_entry
    index = build_product_index([cve])
    if any(_match_candidates(match.matched_product, None, token, index, {cve.pk: cve},
                             cpe=(match.evidence or {}).get('cpe') or '')):
        return ''
    if token in GENERIC_PRODUCT_TOKENS:
        basis = 'the recorded fingerprint is a generic cloud or service label, not the affected product'
    else:
        basis = 'the recorded product identity does not match an affected product in the advisory'
    return ('Closed automatically: invalid product correlation; ' + basis + '. This closes this candidate match only; '
            'it does not establish that the software is absent elsewhere on the host.')


def close_invalid_correlation(match, reason=None):
    """Persist a scoped, auditable closure and a reusable deterministic verdict for bad product links."""
    from django.utils import timezone
    from cveFeed import activity, scoring, triage
    from cveFeed.models import CVEMatch, MatchVerdict, TriageVerdict

    reason = reason or invalid_identity_reason(match)
    if not reason:
        return False
    if match.ai_verdict == 'not_affected' and (match.ai_reason or '').startswith('Closed automatically: invalid product correlation'):
        return False
    pairs = triage.track([match])
    if not pairs:
        return False
    row, _ = pairs[0]
    verdict, _ = TriageVerdict.objects.update_or_create(kind='cve_match', signature=row.signature, defaults={
        'classification': 'not_applicable', 'reason': reason, 'model_classification': '', 'model_reason': '',
        'overridden': False, 'model': 'deterministic-correlation', 'invalid_output': False})
    row.verdict, row.status, row.classification, row.reason = verdict, 'triaged', 'not_applicable', reason
    row.save(update_fields=['verdict', 'status', 'classification', 'reason', 'updated_at'])
    CVEMatch.objects.filter(pk=match.pk).update(ai_verdict='not_affected', ai_reason=reason, ai_model='deterministic-correlation',
                                               confidence=0.0, updated_at=timezone.now())
    match.ai_verdict, match.ai_reason, match.ai_model, match.confidence = 'not_affected', reason, 'deterministic-correlation', 0.0
    MatchVerdict.objects.update_or_create(cve_entry=match.cve_entry, matched_product=match.matched_product,
        matched_version=match.matched_version, version_in_range=match.version_in_range, source=match.source,
        defaults={'ai_verdict': 'not_affected', 'ai_reason': reason, 'ai_model': 'deterministic-correlation'})
    activity.log('confirm', f'{match.cve_entry.cve_id}: invalid product correlation closed for this asset',
                 project=row.project_id, cve_id=match.cve_entry.cve_id, match_id=match.pk,
                 finding_id=row.pk, decision='closed_not_applicable', reason=reason)
    scoring.rescore_for_matches([match])
    from django.db import transaction
    from cveFeed.views import bump_stats_revision
    transaction.on_commit(bump_stats_revision)
    return True


def _seedable(verdict, row):
    """The stored verdict a new or moved match may start from: never a clearing one (not_affected) for a version in the affected range
    that no distribution has patched, whose evidence the verdict was not reached on (the signature does not carry the distro result)."""
    if verdict and verdict.ai_verdict == "not_affected":
        if row["version_in_range"] is True and row["distro_status"] != distro_lib.PATCHED:
            return None
        if (row["version_in_range"] is not False and row["distro_status"] != distro_lib.PATCHED
                and not (verdict.ai_reason or '').startswith('Closed automatically: invalid product correlation')):
            return None
    return verdict


_MATCH_FIELDS = ("matched_version", "version_in_range", "confidence", "scan_history_id", "distro_status", "distro_fixed_version",
                 "evidence")


def save_matches(rows, covered=None):
    """Upsert CVEMatch rows in two statements: bulk_create(ignore_conflicts) for the new ones, bulk_update for the
    existing ones whose evidence changed. Remediation fields are never touched. When the version or its range result
    changes, the AI verdict of the old evidence is replaced by the stored verdict for the new one (or cleared), so the new
    signature is judged, not inherited.

    ``covered`` is ``(subdomain_ids, cve_ids)``: the hosts these rows were computed for and the CVE pool they were checked
    against. Matches of those hosts and CVEs that the rows no longer contain (the version moved out of range, the product is
    gone) are closed: deleted, or, when a person has already worked the match, kept as not_affected with their remediation
    state, so a stale exposure is never reported and a person's decision is never lost."""
    from django.utils import timezone

    from cveFeed.models import CVEMatch, MatchVerdict

    unique = {(r["cve_entry_id"], r["subdomain_id"], r["source"], r["matched_product"]): r for r in rows}
    touched = set()  # hosts whose verdict was reset or whose match was closed: their score must follow
    if covered:
        touched |= close_stale(unique, covered)
    if not unique:
        if touched:
            from cveFeed import scoring
            scoring.rescore_subdomain_ids(touched)
        return 0
    existing = {
        (m.cve_entry_id, m.subdomain_id, m.source, m.matched_product): m
        for m in CVEMatch.objects.filter(subdomain_id__in={k[1] for k in unique}).only(
            "id", "cve_entry_id", "subdomain_id", "source", "matched_product", "ai_verdict", "ai_reason", "ai_model",
            *_MATCH_FIELDS)}
    fresh, changed = [], []
    now = timezone.now()
    verdicts = {}
    moved = {k for k, r in unique.items() if k in existing and (
        existing[k].matched_version != r["matched_version"] or existing[k].version_in_range != r["version_in_range"]
        or existing[k].distro_status != r["distro_status"]
        or ((existing[k].ai_reason or '').startswith('Closed automatically:') and
            any(getattr(existing[k], field) != r[field] for field in _MATCH_FIELDS)))}
    if any(key not in existing for key in unique) or moved:  # a new match of a kind the AI already judged starts out judged
        verdicts = {signature_of(v): v for v in MatchVerdict.objects.filter(
            cve_entry_id__in={k[0] for k in unique if k not in existing or k in moved})}
    for key, row in unique.items():
        match = existing.get(key)
        signature = (row["cve_entry_id"], row["matched_product"], row["matched_version"], row["version_in_range"], row["source"])
        if match is None:
            verdict = _seedable(verdicts.get(signature), row)
            extra = ({"ai_verdict": verdict.ai_verdict, "ai_reason": verdict.ai_reason, "ai_model": verdict.ai_model}
                     if verdict else {})
            fresh.append(CVEMatch(**row, **extra))
        elif any(getattr(match, f) != row[f] for f in _MATCH_FIELDS):
            for f in _MATCH_FIELDS:
                setattr(match, f, row[f])
            if key in moved:
                verdict = _seedable(verdicts.get(signature), row)
                match.ai_verdict = verdict.ai_verdict if verdict else ""
                match.ai_reason = verdict.ai_reason if verdict else ""
                match.ai_model = verdict.ai_model if verdict else ""
            match.updated_at = now
            changed.append(match)
    if fresh:
        CVEMatch.objects.bulk_create(fresh, ignore_conflicts=True, batch_size=1000)
    if changed:
        CVEMatch.objects.bulk_update(changed, [*_MATCH_FIELDS, "ai_verdict", "ai_reason", "ai_model", "updated_at"], batch_size=1000)
    touched |= {k[1] for k in moved}
    if touched:
        from cveFeed import scoring
        scoring.rescore_subdomain_ids(touched)
    return len(unique)


_CORRELATED_SOURCES = ("tech", "port")


def close_stale(current, covered):
    """Close the matches of ``covered`` hosts and CVEs that ``current`` (the keys just computed) no longer contains. Returns the
    ids of the hosts that had one closed."""
    from django.utils import timezone

    from cveFeed.models import CVEMatch

    subdomain_ids, cve_ids = covered
    if not subdomain_ids:
        return set()
    stale_keep, hosts = [], set()
    for m in CVEMatch.objects.filter(subdomain_id__in=list(subdomain_ids), source__in=_CORRELATED_SOURCES).only(
            "id", "cve_entry_id", "subdomain_id", "source", "matched_product", "ai_verdict", "ai_reason"):
        if m.cve_entry_id not in cve_ids or (m.cve_entry_id, m.subdomain_id, m.source, m.matched_product) in current:
            continue
        if m.ai_verdict == 'not_affected' and (m.ai_reason or '').startswith('Closed automatically:'):
            continue
        stale_keep.append(m)
        hosts.add(m.subdomain_id)
    if stale_keep:
        CVEMatch.objects.filter(pk__in=[m.pk for m in stale_keep]).update(
            ai_verdict="not_affected", confidence=0.0, updated_at=timezone.now(),
            ai_reason="Closed automatically: the host no longer matches this CVE (the version moved out of the affected range "
                      "or the product is gone).")
        from cveFeed import activity
        from startScan.models import Subdomain
        projects = dict(Subdomain.objects.filter(pk__in=hosts).values_list('id', 'target_domain__project_id'))
        for match in stale_keep:
            if projects.get(match.subdomain_id):
                activity.log('confirm', 'CVE candidate closed after its product or version disappeared from inventory',
                             project=projects[match.subdomain_id], match_id=match.pk, decision='closed_not_applicable')
    return hosts


def collect_subdomain_matches(subdomain, product_index, cve_by_id, min_confidence=0.0, scan_history=None, rows=None,
                              fix_lookup=None):
    """The CVEMatch rows for one subdomain, appended to ``rows`` (a new list when omitted). Returns the rows.

    Two deterministic sources are correlated against the CVE product index:
    - "tech": reNgine's httpx technology fingerprints (stored as name[:version]).
    - "port": the Shodan-style nmap -sV service data on the host's open ports
      (Port.product / Port.version), reached via the subdomain's IP addresses.
    """
    rows = [] if rows is None else rows
    fix_lookup = fix_lookup or DbFixLookup()

    # Technology fingerprints (httpx tech-detect).
    for tech in subdomain.technologies.all():
        name, version = split_name_version(tech.name)
        token = _norm(name)
        if len(token) < _MIN_TOKEN:
            continue
        _record_matches(
            subdomain, name, version, token, "tech",
            product_index, cve_by_id, min_confidence, scan_history, rows, evidence={"source": "tech", "source_id": tech.id})

    # nmap -sV service data on the host's open ports (Shodan-style inventory).
    from startScan.models import open_ports
    for ip in subdomain.ip_addresses.all():
        for port in open_ports(ip):
            name = (port.product or "").strip()
            token = _norm(name)
            if len(token) < _MIN_TOKEN:
                continue
            version = (port.version or "").strip()
            _record_matches(
                subdomain, name, version, token, "port",
                product_index, cve_by_id, min_confidence, scan_history, rows, cpe=port.cpe or "",
                distro=port_distro(port), fix_lookup=fix_lookup,
                evidence={"source": "port", "source_id": port.id, "ip": ip.address, "port": port.number,
                          "service_extra": (port.service_extra or "")[:255], "cpe": (port.cpe or "")[:255],
                          "method": ((port.extra or {}).get("method") or "")})
    return rows


def correlate_subdomain(subdomain, product_index, cve_by_id, min_confidence=0.0, scan_history=None, fix_lookup=None):
    """Create/update CVEMatch rows for one subdomain. Returns number of matches."""
    return save_matches(collect_subdomain_matches(
        subdomain, product_index, cve_by_id, min_confidence=min_confidence, scan_history=scan_history, fix_lookup=fix_lookup),
        covered=({subdomain.id}, set(cve_by_id)))


def correlate_subdomains(subdomains, product_index, cve_by_id, min_confidence=0.0, scan_history=None, batch=500,
                         fix_lookup=None):
    """Correlate an iterable of subdomains, writing the matches ``batch`` hosts at a time.
    Returns (hosts walked, matches recorded)."""
    hosts = matches = 0
    rows, ids = [], set()
    pool = set(cve_by_id)
    fix_lookup = fix_lookup or DbFixLookup()
    for sub in subdomains:
        hosts += 1
        ids.add(sub.id)
        collect_subdomain_matches(sub, product_index, cve_by_id, min_confidence, scan_history, rows, fix_lookup)
        if hosts % batch == 0:
            matches += save_matches(rows, covered=(ids, pool))
            rows, ids = [], set()
    return hosts, matches + save_matches(rows, covered=(ids, pool))


# One product index per process, rebuilt only when the CVE table changes (a new or re-synced entry moves the key).
_INDEX_CACHE = {"key": None, "value": None}
_CVE_FIELDS = ("id", "cve_id", "affected", "kev", "epss_reached", "exploit_db", "cvss")


def cve_pool(cve_limit=None):
    """(cve_by_id, product_index) for the stored CVEs, cached per process. Never loads ``raw`` or the prose columns."""
    from django.db.models import Count, Max

    from cveFeed.models import CVEEntry

    stamp = CVEEntry.objects.aggregate(n=Count("id"), latest=Max("synced_at"))
    key = (cve_limit, stamp["n"], stamp["latest"])
    if _INDEX_CACHE["key"] == key:
        return _INDEX_CACHE["value"]
    qs = CVEEntry.objects.only(*_CVE_FIELDS).order_by("-published_at")
    if cve_limit:
        qs = qs[:cve_limit]
    cve_by_id = {c.id: c for c in qs}
    value = (cve_by_id, build_product_index(cve_by_id.values()))
    _INDEX_CACHE.update(key=key, value=value)
    return value


def _index_hit(token, product_index):
    return any(name_matches_token(token, product_token) for product_token in product_index)


def latest_scan_q(prefix=""):
    """The rows of each domain's current inventory: hosts are stored once per scan, so listings, matches and auto-fire must read
    one scan's copy, not every scan's. That is the domain's latest successful full scan, plus the successful host-pipeline scans
    (a rescan, a re-test, new hosts from certificate transparency) that ran after it, plus rows with no scan. A host-pipeline scan
    holds only the hosts it ran on, so it adds to the inventory instead of replacing it; when a host appears in more than one of
    these scans, the newest row wins. A domain that has never had a successful full scan keeps all its rows (newest per host),
    so a first scan in progress (or one that failed part way) does not hide the hosts it found. ``prefix`` reaches the host
    from another model ("subdomain__" for a CVEMatch)."""
    from django.db.models import Exists, F, Max, OuterRef, Q, Subquery
    from django.db.models.functions import Coalesce

    from cveFeed.discovery import HOST_PIPELINE_TASK
    from startScan.models import ScanHistory, Subdomain

    done = ScanHistory.objects.filter(scan_status=2)
    full = done.exclude(tasks__contains=[HOST_PIPELINE_TASK])
    latest_full = full.values("domain_id").annotate(last=Max("id")).values("last")
    newest_full_of = full.filter(domain_id=OuterRef("domain_id")).order_by("-id").values("id")[:1]
    after_full = done.filter(tasks__contains=[HOST_PIPELINE_TASK]).annotate(
        full_id=Coalesce(Subquery(newest_full_of), 0)).filter(id__gt=F("full_id")).values("id")
    newer_row = Subdomain.objects.filter(scan_history_id__in=after_full, target_domain_id=OuterRef(prefix + "target_domain_id"),
                                         name=OuterRef(prefix + "name"), scan_history_id__gt=OuterRef(prefix + "scan_history_id"))
    return ((Q(**{prefix + "scan_history_id__in": latest_full}) | Q(**{prefix + "scan_history_id__in": after_full})
             | Q(**{prefix + "scan_history__isnull": True})
             | ~Q(**{prefix + "target_domain_id__in": full.values("domain_id")}))
            & ~Q(Exists(newer_row)))


def candidate_subdomains(product_index, base=None):
    """Subdomains worth correlating against ``product_index``: hosts carrying a technology or an nmap product that
    matches one of its tokens, from each domain's latest successful scan plus the scan-less rows certificate
    transparency created. Older scans' copies of the same host are skipped. Returns a queryset."""
    from django.db.models import Max, Q

    from cveFeed.models import CVEMatch
    from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Technology

    tech_ids, tokens = [], {}
    for tech_id, tech_name in Technology.objects.values_list("id", "name").iterator():
        token = _norm(split_name_version(tech_name)[0])
        if len(token) < _MIN_TOKEN:
            continue
        if token not in tokens:
            tokens[token] = _index_hit(token, product_index)
        if tokens[token]:
            tech_ids.append(tech_id)
    products = set()
    for product in Port.objects.exclude(product="").values_list("product", flat=True).distinct():
        token = _norm(product.strip())
        if len(token) >= _MIN_TOKEN and _index_hit(token, product_index):
            products.add(product)

    by_tech = Subdomain.technologies.through.objects.filter(technology_id__in=tech_ids).values("subdomain_id")
    ips = IpAddress.ports.through.objects.filter(port__product__in=products).values("ipaddress_id")
    by_port = Subdomain.ip_addresses.through.objects.filter(ipaddress_id__in=ips).values("subdomain_id")
    latest = ScanHistory.objects.filter(scan_status=2).values("domain_id").annotate(last=Max("id")).values("last")
    matched = CVEMatch.objects.filter(source__in=_CORRELATED_SOURCES).values("subdomain_id")  # re-checked so a stale match closes
    qs = (Subdomain.objects if base is None else base).filter(Q(id__in=by_tech) | Q(id__in=by_port) | Q(id__in=matched)).filter(
        Q(scan_history_id__in=latest) | Q(scan_history__isnull=True))
    return qs.prefetch_related("technologies", "ip_addresses__ports")


def ai_confirm_match(match, provider=None):
    """Triage one CVEMatch with the user's chosen AI model and store the result as the legacy ``ai_verdict``.

    The model's answer goes through the same rules as every finding (cveFeed.triage.apply_rules): confirmed, likely and
    needs_validation map to affected, affected and uncertain; likely_false_positive and not_applicable map to not_affected, but never
    for a match with hard evidence (a version inside the affected range, a template hit, a distribution tracker listing the package as
    affected), which stays at least uncertain. ``provider`` defaults to the one configured in AIProviderSettings; with none configured
    (or on a provider error) the match is returned unconfirmed, so deterministic correlation still works without an API key.
    This is the stateless single-match form; auto-fire and the pipeline use cveFeed.triage, which also shares one answer per signature.
    """
    from reNgine.ai_providers import AIProviderError, triage_finding
    try:
        if provider is None:
            from reNgine.ai_settings import get_configured_provider
            provider = get_configured_provider()
        if provider is None:
            return match
        from cveFeed import activity, triage
        cve = match.cve_entry
        host = match.subdomain.name if match.subdomain else ""
        described = triage.describe_cve_match(match)
        domain = getattr(match.subdomain, 'target_domain', None)
        project = getattr(domain, 'project_id', None)
        with activity.step('confirm', f'Asking {provider.name} whether {host or "a host"} is affected by {cve.cve_id}',
                           project=project, cve_id=cve.cve_id) as handle:
            answer = triage_finding(provider, 'cve_match', described['payload'])
            outcome = triage.apply_rules('cve_match', described['facts'], answer['parsed'])
            handle.done_message = (f'{host}: {outcome["classification"].replace("_", " ")} for {cve.cve_id}'
                                   f' ({outcome["reason"][:120]})')
    except AIProviderError as e:
        logger.warning("AI confirmation skipped for match %s: %s", match.pk, e)
        return match
    match.ai_verdict = triage.verdict_for(outcome["classification"])
    match.ai_reason = outcome["reason"][:2000]
    match.ai_model = answer["model"]
    match.save(update_fields=["ai_verdict", "ai_reason", "ai_model", "updated_at"])
    from cveFeed import scoring
    scoring.rescore_for_matches([match])  # a verdict moves the host's score
    return match
