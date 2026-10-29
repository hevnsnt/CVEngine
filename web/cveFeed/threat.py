"""CVEngine threat tiers: fire / smoke / ice.

A fast, deterministic pre-classification of a CVE from its exploitation and
severity signals, so the pipeline can prioritize what the AI looks at first:

  fire  🔥  actively dangerous now: CISA KEV, Exploit-DB, a critical score (CVSS 9+), or high EPSS + CVSS
  smoke 💨  emerging / warning signs: high CVSS, or EPSS threshold reached
  ice   🧊  cold, low-priority watch: everything else

Thresholds are intentionally in one place and easy to retune.
"""

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


def match_temperature(tier, cvss=None, ai_verdict=None, distro_status=None, version_unknown=False):
    """How hot a CVE is *on one of your hosts*. The feed tier says how dangerous the CVE is in general; a match says it is on
    your asset, so a high score (7.0 or more) that the AI confirmed affects the host reads as fire too. A match the host's
    distribution has patched (a backported fix) is ice however dangerous the CVE is, and so is one whose CVE publishes no affected
    version range (``match_policy.is_version_unknown``): it waits for review at the lowest priority, KEV or not."""
    if distro_status == "patched" or version_unknown:
        return ICE
    if tier == FIRE:
        return FIRE
    score = cvss or 0.0
    if ai_verdict == 'affected' and score >= HIGH_CVSS:
        return FIRE
    return tier


SEVERITY_HEAT = {4: FIRE, 3: FIRE, 2: SMOKE, 1: ICE}
HEAT_RANK = {FIRE: 3, SMOKE: 2, ICE: 1}


def match_heat_rank_expr():
    """The database form of ``HEAT_RANK[match_temperature(classify_threat_tier(...), ...)]`` over CVEMatch rows (3 fire, 2 smoke,
    1 ice), so a list can filter, count and order matches by how hot they are on the host without loading them."""
    from django.db.models import Case, IntegerField, Q, Value, When
    from cveFeed.match_policy import version_unknown_q
    return Case(
        When(distro_status="patched", then=Value(HEAT_RANK[ICE])),
        When(version_unknown_q(), then=Value(HEAT_RANK[ICE])),
        When(fire_tier_q("cve_entry__"), then=Value(HEAT_RANK[FIRE])),
        When(Q(ai_verdict="affected", cve_entry__cvss__gte=HIGH_CVSS), then=Value(HEAT_RANK[FIRE])),
        When(Q(cve_entry__cvss__gte=HIGH_CVSS) | Q(cve_entry__epss_reached=True), then=Value(HEAT_RANK[SMOKE])),
        default=Value(HEAT_RANK[ICE]), output_field=IntegerField())


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
