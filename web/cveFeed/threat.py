"""CVEngine threat tiers: fire / smoke / ice.

A fast, deterministic pre-classification of a CVE from its exploitation and
severity signals, so the pipeline can prioritize what the AI looks at first:

  fire  🔥  actively dangerous now: CISA KEV, Exploit-DB, a critical score (CVSS 9+), or high EPSS + CVSS
  smoke 💨  emerging / warning signs: high CVSS, or EPSS threshold reached
  ice   🧊  cold, low-priority watch: everything else

Thresholds are intentionally in one place and easy to retune.

A tier is about a CVE in general. On a host, a match is rated by ``match_heat``: a match with no hard evidence (a version string alone,
``match_policy.is_version_only``) never shows hotter than ``version_only_max_heat()`` (smoke by default, KEV or not), while
``validation_heat`` keeps the uncapped rating, which is what orders validation: a known-exploited version-only match is still
validated first, because validation is how it earns fire.
"""
import os

FIRE = "fire"
SMOKE = "smoke"
ICE = "ice"

HIGH_CVSS = 7.0
CRITICAL_CVSS = 9.0  # cve.now calls this critical too


def classify_threat_tier(kev=None, epss_reached=None, exploit_db=None, cvss=None):
    """Return 'fire', 'smoke' or 'ice' from a CVE's exploitation/severity signals."""
    score = cvss or 0.0
    if kev or exploit_db or score >= CRITICAL_CVSS or (epss_reached and score >= HIGH_CVSS):
        return FIRE
    if score >= HIGH_CVSS or epss_reached:
        return SMOKE
    return ICE


def fire_tier_q(prefix=""):
    """The database form of ``classify_threat_tier(...) == FIRE`` over CVEEntry rows. ``prefix`` reaches the CVE from another
    model ("cve_entry__" for a CVEMatch)."""
    from django.db.models import Q
    p = prefix
    return (Q(**{p + "kev": True}) | Q(**{p + "exploit_db": True}) | Q(**{p + "cvss__gte": CRITICAL_CVSS})
            | (Q(**{p + "epss_reached": True}) & Q(**{p + "cvss__gte": HIGH_CVSS})))


def hot_tier_q():
    """CVEEntry rows that are fire or smoke: what auto-fire acts on, and what the dashboard counts as hot."""
    from django.db.models import Q
    return fire_tier_q() | Q(cvss__gte=HIGH_CVSS) | Q(epss_reached=True)


VERSION_ONLY_MAX_HEAT_ENV = "CVENGINE_VERSION_ONLY_MAX_HEAT"
DEFAULT_VERSION_ONLY_MAX_HEAT = SMOKE


def version_only_max_heat():
    """The hottest a version-only CVE match may show (``match_policy.is_version_only``): CVENGINE_VERSION_ONLY_MAX_HEAT, one of fire (the
    behaviour before 1.3.2: a version-only match inherits its CVE's tier), smoke (the default) or ice; anything else is the default. Read on
    every use, so it needs no migration: every heat is computed when it is read, and a change applies to stored matches at once (host scores
    at their next rescore)."""
    value = (os.environ.get(VERSION_ONLY_MAX_HEAT_ENV) or "").strip().lower()
    return value if value in (FIRE, SMOKE, ICE) else DEFAULT_VERSION_ONLY_MAX_HEAT


def match_temperature(tier, cvss=None, ai_verdict=None, distro_status=None, version_unknown=False, version_only=False):
    """How hot a CVE is *on one of your hosts*. The feed tier says how dangerous the CVE is in general; a match says it is on
    your asset, so a high score (7.0 or more) that the AI confirmed affects the host reads as fire too. A match the host's
    distribution has patched (a backported fix) is ice however dangerous the CVE is, and so is one whose CVE publishes no affected
    version range (``match_policy.is_version_unknown``): it waits for review at the lowest priority, KEV or not. A ``version_only``
    match (no hard evidence: ``match_policy.has_hard_evidence``) is held to ``version_only_max_heat()``: fire needs evidence about the
    host, not a version string inside a known-exploited CVE's range."""
    if distro_status == "patched" or version_unknown:
        return ICE
    if tier == FIRE:
        heat = FIRE
    elif ai_verdict == 'affected' and (cvss or 0.0) >= HIGH_CVSS:
        heat = FIRE
    else:
        heat = tier
    if version_only:
        cap = version_only_max_heat()
        if HEAT_RANK.get(heat, 0) > HEAT_RANK[cap]:
            heat = cap
    return heat


def feed_tier(cve):
    """``classify_threat_tier`` of a CVEEntry."""
    return classify_threat_tier(kev=cve.kev, epss_reached=cve.epss_reached, exploit_db=cve.exploit_db, cvss=cve.cvss)


def match_heat(match, capped=True):
    """The heat a CVEMatch shows (its ``cve_entry`` loaded; load ``triage`` with it to save a query): ``match_temperature`` with the
    version-only cap. Every list, count, score, map, report, alert and API reads a match's heat from here or from its database form
    ``match_heat_rank_expr``. ``capped=False`` is ``validation_heat``."""
    from cveFeed import match_policy
    cve = match.cve_entry
    heat = match_temperature(feed_tier(cve), cve.cvss, match.ai_verdict, match.distro_status, match_policy.version_unknown(match))
    if capped:
        cap = version_only_max_heat()
        # the cap only matters above it, so the hard-evidence test (which may read the Triage row) runs only then
        if HEAT_RANK.get(heat, 0) > HEAT_RANK[cap] and match_policy.is_version_only(match):
            heat = cap
    return heat


def validation_heat(match):
    """The uncapped heat of a CVEMatch: what orders validation (``hot_validation``) and agent validation work. A known-exploited match that
    rests on its version alone shows smoke but is validated in the fire lane, first: a validation hit is the hard evidence that makes it fire."""
    return match_heat(match, capped=False)


SEVERITY_HEAT = {4: FIRE, 3: FIRE, 2: SMOKE, 1: ICE}
HEAT_RANK = {FIRE: 3, SMOKE: 2, ICE: 1}


def match_heat_rank_expr(capped=True):
    """The database form of ``HEAT_RANK[match_heat(...)]`` over CVEMatch rows (3 fire, 2 smoke, 1 ice), so a list can filter, count and
    order matches by how hot they are on the host without loading them. ``capped=False`` is the form of ``validation_heat``."""
    from django.db.models import Case, IntegerField, Q, Value, When
    from cveFeed.match_policy import version_only_q, version_unknown_q
    fire = fire_tier_q("cve_entry__") | Q(ai_verdict="affected", cve_entry__cvss__gte=HIGH_CVSS)
    smoke = Q(cve_entry__cvss__gte=HIGH_CVSS) | Q(cve_entry__epss_reached=True)
    whens = [When(distro_status="patched", then=Value(HEAT_RANK[ICE])),
             When(version_unknown_q(), then=Value(HEAT_RANK[ICE]))]
    cap = version_only_max_heat() if capped else FIRE
    if cap != FIRE:  # a version-only match that would rate above the cap rates at the cap
        whens.append(When(version_only_q() & (fire if cap == SMOKE else fire | smoke), then=Value(HEAT_RANK[cap])))
    whens += [When(fire, then=Value(HEAT_RANK[FIRE])), When(smoke, then=Value(HEAT_RANK[SMOKE]))]
    return Case(*whens, default=Value(HEAT_RANK[ICE]), output_field=IntegerField())


def severity_heat_rank_expr(field="severity"):
    """The database form of ``HEAT_RANK.get(SEVERITY_HEAT.get(severity), 0)``: critical and high 3, medium 2, low 1, info 0."""
    from django.db.models import Case, IntegerField, Value, When
    return Case(*[When(**{field: sev}, then=Value(HEAT_RANK[heat])) for sev, heat in SEVERITY_HEAT.items()],
                default=Value(0), output_field=IntegerField())


def host_heat(status, tiers, severities):
    """A host's worst threat temperature: the hottest of its CVE matches' tiers and its open findings' severities
    (critical and high read as fire, medium as smoke, low as ice); otherwise clean, or unscanned if nothing has probed it."""
    temps = [t for t in tiers if t in HEAT_RANK] + [SEVERITY_HEAT[v] for v in severities if v in SEVERITY_HEAT]
    if temps:
        return max(temps, key=HEAT_RANK.get)
    return 'unscanned' if status == 'unscanned' else 'clean'
