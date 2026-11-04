"""CVEngine threat tiers: fire / smoke / ice.

The heat policy (``heat_policy()``, ``CVENGINE_HEAT_POLICY`` or Settings, configMaxxing, **Heat policy**) decides what the three words mean.

``kev`` (the default), the owner's rule:

  fire  🔥  on the KEV (or with a known exploit) AND the version is PROVEN on the host (``match_policy.version_proven``)
  smoke 💨  on the KEV (or with a known exploit) and we only THINK the version is there (a version-only inference)
  ice   🧊  not on the KEV and no known exploit, whatever its CVSS or EPSS (and, as before, a match the distribution patched or whose CVE
            publishes no affected version range)

"Hot" (``is_hot``) is ``kev`` (CISA KEV, ENISA EUVD or VulnCheck KEV: exploited in the wild, which is itself an exploit) or ``exploit_db``
(Exploit-DB or a Metasploit module). CVSS and EPSS stay visible everywhere (columns, sorting, badges, the AI's context) but never set heat. A
CVE in general (the feed, ``classify_threat_tier``) is fire when hot and ice otherwise: smoke needs a host, it is the "we think it is here"
of a match.

``legacy`` (rollback): the rule before the policy existed. A CVE is fire when it is KEV, has an exploit, has CVSS 9 or more, or EPSS reached
with CVSS 7 or more; smoke with CVSS 7 or more or EPSS reached; else ice. A match with no hard evidence is held to
``version_only_max_heat()`` (``CVENGINE_VERSION_ONLY_MAX_HEAT``, smoke by default), and an AI-confirmed CVSS 7+ match reads fire.

``validation_heat`` is the heat a match would have once proven: what orders validation (``hot_validation``), OpenVAS and agent validation
work, so a known-exploited match whose version is not proven is validated first, in the fire lane.

A heat a person set by hand (``Triage.heat_override``: ``agentapi.services.set_finding_heat``, the REST route and the MCP tool) wins over
all of the above, under either policy, for a CVE match and a scanner finding alike: ``match_heat`` (capped and not, so ``validation_heat``
too), ``finding_heat``, their database forms and the reasons ("set to smoke by alice: ..."), until it is cleared.

What is only about *finding* and *testing* a CVE (auto-fire, which CVEs a host's CVE template pass tests, correlation's end-of-life branch
rule) reads ``attention_tier``, the legacy rating, under either policy: the heat policy decides what a finding is worth, never what is
looked for.
"""
import os

FIRE = "fire"
SMOKE = "smoke"
ICE = "ice"

HIGH_CVSS = 7.0
CRITICAL_CVSS = 9.0  # cve.now calls this critical too

KEV_POLICY = "kev"
LEGACY_POLICY = "legacy"
HEAT_POLICY_ENV = "CVENGINE_HEAT_POLICY"
HEAT_POLICY_VALUES = {KEV_POLICY: 1, LEGACY_POLICY: 0}  # the number the tunable stores (cveFeed.tunables, key heat_policy)
DEFAULT_HEAT_POLICY = KEV_POLICY


def heat_policy():
    """``kev`` (the default) or ``legacy``: what an App Admin saved on Settings, configMaxxing (Heat policy), else ``CVENGINE_HEAT_POLICY``
    (``kev`` or ``legacy``), else ``kev``. Read on every use (``cveFeed.tunables``), so a change applies to every list, count and API at
    once; stored host scores follow at the next tick (``scoring.rescore_if_heat_cap_changed``). Never raises."""
    try:
        from cveFeed import tunables
        number = tunables.value('heat_policy', HEAT_POLICY_VALUES[DEFAULT_HEAT_POLICY])
    except Exception:  # noqa: BLE001 - a settings read must never stop a list or a scan
        number = HEAT_POLICY_VALUES[DEFAULT_HEAT_POLICY]
    return LEGACY_POLICY if number == HEAT_POLICY_VALUES[LEGACY_POLICY] else KEV_POLICY


def is_hot(kev=None, exploit_db=None):
    """Whether a CVE is "on the KEV, with an exploit" in the owner's sense: listed as exploited in the wild (any KEV source), or with a public
    exploit (Exploit-DB, Metasploit). CVSS and EPSS play no part."""
    return bool(kev) or bool(exploit_db)


def hot_q(prefix=""):
    """The database form of ``is_hot`` over CVEEntry rows (``prefix`` "cve_entry__" from a CVEMatch)."""
    from django.db.models import Q
    return Q(**{prefix + "kev": True}) | Q(**{prefix + "exploit_db": True})


def attention_tier(kev=None, epss_reached=None, exploit_db=None, cvss=None):
    """The legacy fire / smoke / ice rating from a CVE's exploitation and severity signals (KEV, exploit, CVSS, EPSS). It is the CVE's tier
    under the ``legacy`` policy, and under either policy what decides which CVEs are looked for and tested (auto-fire, the CVE template pass,
    correlation's end-of-life branch rule): detection is not narrowed by the heat policy."""
    score = cvss or 0.0
    if kev or exploit_db or score >= CRITICAL_CVSS or (epss_reached and score >= HIGH_CVSS):
        return FIRE
    if score >= HIGH_CVSS or epss_reached:
        return SMOKE
    return ICE


def classify_threat_tier(kev=None, epss_reached=None, exploit_db=None, cvss=None, policy=None):
    """Return 'fire', 'smoke' or 'ice' for a CVE in general. ``kev`` policy: fire when hot (``is_hot``), else ice. ``legacy``:
    ``attention_tier``."""
    if (policy or heat_policy()) == LEGACY_POLICY:
        return attention_tier(kev, epss_reached, exploit_db, cvss)
    return FIRE if is_hot(kev, exploit_db) else ICE


def attention_fire_q(prefix=""):
    """The database form of ``attention_tier(...) == FIRE``."""
    from django.db.models import Q
    p = prefix
    return (hot_q(p) | Q(**{p + "cvss__gte": CRITICAL_CVSS})
            | (Q(**{p + "epss_reached": True}) & Q(**{p + "cvss__gte": HIGH_CVSS})))


def attention_hot_q():
    """CVEEntry rows whose ``attention_tier`` is fire or smoke: what auto-fire acts on, under either heat policy."""
    from django.db.models import Q
    return attention_fire_q() | Q(cvss__gte=HIGH_CVSS) | Q(epss_reached=True)


def fire_tier_q(prefix="", policy=None):
    """The database form of ``classify_threat_tier(...) == FIRE`` over CVEEntry rows. ``prefix`` reaches the CVE from another
    model ("cve_entry__" for a CVEMatch)."""
    if (policy or heat_policy()) == LEGACY_POLICY:
        return attention_fire_q(prefix)
    return hot_q(prefix)


def hot_tier_q(policy=None):
    """CVEEntry rows that are fire or smoke (``classify_threat_tier``): what the dashboard's feed bars count as hot. Under the ``kev`` policy a
    CVE in general is fire or ice, so this is ``hot_q``."""
    if (policy or heat_policy()) == LEGACY_POLICY:
        return attention_hot_q()
    return hot_q()


VERSION_ONLY_MAX_HEAT_ENV = "CVENGINE_VERSION_ONLY_MAX_HEAT"
DEFAULT_VERSION_ONLY_MAX_HEAT = SMOKE


def version_only_max_heat():
    """``legacy`` policy only: the hottest a version-only CVE match may show (``match_policy.is_version_only``): CVENGINE_VERSION_ONLY_MAX_HEAT,
    one of fire (the behaviour before 1.3.2: a version-only match inherits its CVE's tier), smoke (the default) or ice; anything else is the
    default. Under the ``kev`` policy it is not read: the owner's rule says what an unproven match shows (smoke, when hot). Read on every use,
    so it needs no migration."""
    value = (os.environ.get(VERSION_ONLY_MAX_HEAT_ENV) or "").strip().lower()
    return value if value in (FIRE, SMOKE, ICE) else DEFAULT_VERSION_ONLY_MAX_HEAT


def heat_signature():
    """What the stored host scores depend on beyond the matches themselves: the policy, and under ``legacy`` the version-only cap. A worker
    that sees a signature different from the one it last recorded queues one full rescore (``scoring.rescore_if_heat_cap_changed``)."""
    policy = heat_policy()
    return f"{LEGACY_POLICY}:{version_only_max_heat()}" if policy == LEGACY_POLICY else KEV_POLICY


def match_temperature(tier, cvss=None, ai_verdict=None, distro_status=None, version_unknown=False, version_only=False, proven=None,
                      policy=None):
    """How hot a CVE is *on one of your hosts*, from plain inputs. ``tier`` is the CVE's own tier (``classify_threat_tier`` under the same
    policy). A match the host's distribution has patched (a backported fix) is ice however dangerous the CVE is, and so is one whose CVE
    publishes no affected version range (``match_policy.is_version_unknown``).

    ``kev`` policy: a hot CVE (tier fire) is fire on the host when ``proven`` (``match_policy.version_proven``; when not given, "has hard
    evidence", ``not version_only``), else smoke; a CVE that is not hot is ice, proven or not. ``legacy``: a high score (7.0 or more) the AI
    confirmed reads fire too, and a ``version_only`` match is held to ``version_only_max_heat()``."""
    if distro_status == "patched" or version_unknown:
        return ICE
    if (policy or heat_policy()) != LEGACY_POLICY:
        if tier != FIRE:
            return ICE
        return FIRE if (proven if proven is not None else not version_only) else SMOKE
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


def feed_tier(cve, policy=None):
    """``classify_threat_tier`` of a CVEEntry."""
    return classify_threat_tier(kev=cve.kev, epss_reached=cve.epss_reached, exploit_db=cve.exploit_db, cvss=cve.cvss, policy=policy)


def manual_heat(finding):
    """The heat a person set on a CVE match or a scanner finding (``Triage.heat_override``), or '' when none is set. Reads the Triage row a
    ``select_related``/``prefetch_related`` of ``triage`` loaded; otherwise one query (the heat functions read that row anyway)."""
    from django.core.exceptions import ObjectDoesNotExist
    try:
        row = finding.triage
    except (ObjectDoesNotExist, AttributeError):
        return ""
    value = getattr(row, "heat_override", "") or ""
    return value if value in HEAT_RANK else ""


def manual_heat_reason(finding):
    """"set to smoke by alice: <their reason>" for a finding whose heat a person set (``manual_heat``), else ''. The user is
    ``heat_override_by`` (load ``triage__heat_override_by`` with a list to save a query per overridden row)."""
    heat = manual_heat(finding)
    if not heat:
        return ""
    row = finding.triage
    by = getattr(row, "heat_override_by", None) if getattr(row, "heat_override_by_id", None) else None
    who = by.username if by is not None else "a user no longer here"
    reason = (getattr(row, "heat_override_reason", "") or "").strip()
    return f"set to {heat} by {who}" + (f": {reason}" if reason else "")


def _manual_whens(prefix=""):
    """The leading ``When``s of a heat rank expression: a heat a person set wins (``prefix`` reaches the finding's Triage row)."""
    from django.db.models import Value, When
    return [When(**{prefix + "triage__heat_override": heat}, then=Value(HEAT_RANK[heat])) for heat in (FIRE, SMOKE, ICE)]


def match_heat(match, capped=True):
    """The heat a CVEMatch shows (its ``cve_entry`` loaded; load ``triage`` with it to save a query). Every list, count, score, map, report,
    alert and API reads a match's heat from here or from its database form ``match_heat_rank_expr``. ``capped=False`` is ``validation_heat``:
    the heat the match would have once proven (``kev``), or without the version-only cap (``legacy``). A heat a person set
    (``manual_heat``) wins over both."""
    from cveFeed import match_policy
    manual = manual_heat(match)
    if manual:
        return manual
    cve = match.cve_entry
    policy = heat_policy()
    if policy != LEGACY_POLICY:
        if match.distro_status == "patched" or match_policy.version_unknown(match) or not is_hot(cve.kev, cve.exploit_db):
            return ICE
        return FIRE if not capped or match_policy.version_proven(match) else SMOKE
    heat = match_temperature(feed_tier(cve, policy), cve.cvss, match.ai_verdict, match.distro_status, match_policy.version_unknown(match),
                             policy=policy)
    if capped:
        cap = version_only_max_heat()
        # the cap only matters above it, so the hard-evidence test (which may read the Triage row) runs only then
        if HEAT_RANK.get(heat, 0) > HEAT_RANK[cap] and match_policy.is_version_only(match):
            heat = cap
    return heat


def validation_heat(match):
    """The heat a CVEMatch would have once proven: what orders validation (``hot_validation``) and agent validation work, and what OpenVAS
    selects hosts by. A known-exploited match whose version is not proven shows smoke but is validated in the fire lane, first: proof is what
    makes it fire. Under the ``kev`` policy a match that is not hot is ice here too (proving it would not change its heat)."""
    return match_heat(match, capped=False)


def unproven(match, validation_status=None):
    """Whether a CVEMatch lacks what fire needs under the current policy, read BEFORE new evidence is written, so the caller pages only a real
    smoke-to-fire change (``scoring.evidence_arrived``, ``notify.fire_confirmed``). ``kev``: not ``match_policy.version_proven``; ``legacy``:
    ``match_policy.is_version_only``. ``validation_status`` overrides the Triage row's (``''``: as if no validation had hit yet)."""
    from cveFeed import match_policy
    if heat_policy() == LEGACY_POLICY:
        if validation_status is None:
            return match_policy.is_version_only(match)
        return not match_policy.has_hard_evidence(getattr(match, 'source', ''), getattr(match, 'evidence', None),
                                                  getattr(match, 'template_result', '') or '', getattr(match, 'distro_status', '') or '',
                                                  validation_status)
    return not match_policy.version_proven(match, validation_status=validation_status)


REASON_PATCHED = "the host's distribution has patched it"
REASON_VERSION_UNKNOWN = "the CVE publishes no affected version range: kept for review"
REASON_NOT_HOT = "not on the KEV and no known exploit"


def heat_reason(match, heat=None):
    """One short sentence that says WHY a CVEMatch shows its heat, for tooltips, host reasons, the REST/MCP ``heat_reason`` field and the AI's
    context: "on the KEV; version proven (...)", "on the KEV; version not proven", "not on the KEV and no known exploit", "the host's
    distribution has patched it", ... ``heat`` is ``match_heat(match)`` when the caller has it. For a heat a person set: "set to smoke by
    alice: <their reason>" (``manual_heat_reason``)."""
    from cveFeed import match_policy
    manual = manual_heat_reason(match)
    if manual:
        return manual
    cve = match.cve_entry
    heat = heat or match_heat(match)
    if match.distro_status == "patched":
        return REASON_PATCHED
    if match_policy.version_unknown(match):
        return REASON_VERSION_UNKNOWN
    if heat_policy() == LEGACY_POLICY:
        why = "legacy heat policy: KEV, a public exploit, CVSS and EPSS"
        if heat != validation_heat(match):
            why += f"; version only, shown as {heat} until a check confirms it"
        return why
    if not is_hot(cve.kev, cve.exploit_db):
        return REASON_NOT_HOT
    hot = "on the KEV" if cve.kev else "a public exploit is known"
    if heat == FIRE:
        return f"{hot}; {match_policy.proof_of(match) or 'version proven'}"
    return f"{hot}; version not proven"

SEVERITY_HEAT = {4: FIRE, 3: FIRE, 2: SMOKE, 1: ICE}
HEAT_RANK = {FIRE: 3, SMOKE: 2, ICE: 1}


def match_heat_rank_expr(capped=True):
    """The database form of ``HEAT_RANK[match_heat(...)]`` over CVEMatch rows (3 fire, 2 smoke, 1 ice), so a list can filter, count and
    order matches by how hot they are on the host without loading them. ``capped=False`` is the form of ``validation_heat``. A heat a
    person set wins (the Triage row is joined, never read per row)."""
    from django.db.models import Case, IntegerField, Q, Value, When
    from cveFeed.match_policy import version_only_q, version_proven_q, version_unknown_q
    whens = [*_manual_whens(),
             When(distro_status="patched", then=Value(HEAT_RANK[ICE])),
             When(version_unknown_q(), then=Value(HEAT_RANK[ICE]))]
    if heat_policy() != LEGACY_POLICY:
        hot = hot_q("cve_entry__")
        if capped:
            whens.append(When(hot & version_proven_q(), then=Value(HEAT_RANK[FIRE])))
            whens.append(When(hot, then=Value(HEAT_RANK[SMOKE])))
        else:
            whens.append(When(hot, then=Value(HEAT_RANK[FIRE])))
        return Case(*whens, default=Value(HEAT_RANK[ICE]), output_field=IntegerField())
    fire = attention_fire_q("cve_entry__") | Q(ai_verdict="affected", cve_entry__cvss__gte=HIGH_CVSS)
    smoke = Q(cve_entry__cvss__gte=HIGH_CVSS) | Q(cve_entry__epss_reached=True)
    cap = version_only_max_heat() if capped else FIRE
    if cap != FIRE:  # a version-only match that would rate above the cap rates at the cap
        whens.append(When(version_only_q() & (fire if cap == SMOKE else fire | smoke), then=Value(HEAT_RANK[cap])))
    whens += [When(fire, then=Value(HEAT_RANK[FIRE])), When(smoke, then=Value(HEAT_RANK[SMOKE]))]
    return Case(*whens, default=Value(HEAT_RANK[ICE]), output_field=IntegerField())


# ----------------------------------------------------------------------------- scanner findings (startScan.Vulnerability)
#
# A scanner finding that names CVEs (a nuclei CVE template, the CVE template pass, OpenVAS, WPScan, node2shell) is a CVE on the host, so under the
# ``kev`` policy it follows the CVE rule, not its severity: one of its CVEs on the KEV or with a known exploit and the finding confirmed is fire
# (the finding itself is a behavioural check: the template or the active test matched the flaw on the host); hot but not confirmed (an OpenVAS
# result below its quality bar, tagged qod-unconfirmed, or a WPScan finding, which reads a plugin's version) is smoke, fire once a validation
# reproduced it; none of its CVEs hot (or none stored by this instance) is ice, whatever its severity. A finding that names no CVE (an exposure,
# a misconfiguration, a default login) has no KEV listing to read and keeps its severity heat (critical and high fire, medium smoke, low ice).
# Informational findings have no heat, as before. Under ``legacy`` every finding keeps its severity heat.

UNCONFIRMED_TAG = "qod-unconfirmed"  # cveFeed.openvas_scan: a result below CONFIRMED_QOD, a version or banner inference
VERSION_READ_SOURCES = ("wpscan",)  # scanners whose CVE findings rest on a version they read, not on a check of the flaw


CVE_NAME_BLANKS = " \t\n\r\x0b\x0c"  # what is trimmed off a stored CVE name, in Python and in SQL (BTRIM) alike


def finding_cve_names(vuln):
    """The CVE ids a Vulnerability names, trimmed and upper-cased, empty ones left out (its ``cve_ids``; a prefetch of ``cve_ids`` saves the
    query). ``finding_heat_rank_expr`` reads them the same way."""
    names = {(c.name or "").strip(CVE_NAME_BLANKS).upper() for c in vuln.cve_ids.all()}
    return sorted(n for n in names if n)


def hot_cve_names(names):
    """The ids among ``names`` of stored CVEs that are hot (``is_hot``): one query."""
    from cveFeed.models import CVEEntry
    names = {str(n).upper() for n in names if n}
    if not names:
        return set()
    return set(CVEEntry.objects.filter(hot_q(), cve_id__in=names).values_list("cve_id", flat=True))


def finding_confirmed(vuln):
    """Whether a scanner finding is a confirmation of its flaw: a validation reproduced it, or the scanner itself checked the flaw (not an
    OpenVAS result below its quality bar, not a version-reading scanner such as WPScan). Reads prefetched ``tags`` and ``triage`` when loaded."""
    from cveFeed.match_policy import _validation_status
    if _validation_status(vuln) == "hit":
        return True
    if (getattr(vuln, "source", "") or "") in VERSION_READ_SOURCES:
        return False
    return UNCONFIRMED_TAG not in {t.name for t in vuln.tags.all()}


def finding_heat(vuln, capped=True, hot_names=None, policy=None):
    """The heat a scanner finding (a ``startScan.Vulnerability``) shows on its host, or None when it has none (informational). ``hot_names``: the
    hot CVE ids among the findings' CVEs when the caller looked them up for many at once (``hot_cve_names``). ``capped=False`` is the heat once
    confirmed (what OpenVAS orders hosts by). The database form is ``finding_heat_rank_expr``. A heat a person set (``manual_heat``) wins,
    under either policy, capped or not."""
    manual = manual_heat(vuln)
    if manual:
        return manual
    severity_heat = SEVERITY_HEAT.get(vuln.severity)
    if severity_heat is None or (policy or heat_policy()) == LEGACY_POLICY:
        return severity_heat
    names = finding_cve_names(vuln)
    if not names:
        return severity_heat
    hot = hot_names if hot_names is not None else hot_cve_names(names)
    if not any(n in hot for n in names):
        return ICE
    return FIRE if not capped or finding_confirmed(vuln) else SMOKE


def finding_heat_reason(vuln, heat, hot_names=None):
    """Why a scanner finding that names CVEs has its heat under the KEV policy, else '' (a finding without CVEs is rated by its severity).
    A heat a person set says who set it and why, under either policy (``manual_heat_reason``)."""
    manual = manual_heat_reason(vuln)
    if manual:
        return manual
    if heat is None or heat_policy() == LEGACY_POLICY:
        return ""
    names = finding_cve_names(vuln)
    if not names:
        return ""
    if heat == ICE:
        return REASON_NOT_HOT
    if heat == FIRE:
        return "on the KEV or a public exploit is known; confirmed by the scanner" if finding_confirmed(vuln) else \
            "on the KEV or a public exploit is known"
    return "on the KEV or a public exploit is known; not confirmed (a version or banner inference)"


def finding_heat_rank_expr(capped=True, prefix=""):
    """The database form of ``HEAT_RANK.get(finding_heat(...), 0)`` over Vulnerability rows (3 fire, 2 smoke, 1 ice, 0 none): what the Findings
    list, its heat facet, the reports and the graph read for scanner findings. ``prefix`` reaches the finding from another model
    ("vulnerability__" from a Triage row: the validation lanes). A heat a person set wins, under either policy."""
    from django.db.models import CharField, Case, Exists, F, Func, IntegerField, OuterRef, Q, Value, When
    from django.db.models.functions import Upper

    from cveFeed.models import CVEEntry
    from startScan.models import CveId, VulnerabilityTags
    p = prefix
    severity = severity_heat_rank_expr(p + "severity")
    manual = _manual_whens(p)
    if heat_policy() == LEGACY_POLICY:
        return Case(*manual, default=severity, output_field=IntegerField())
    trimmed = Func(F("name"), Value(CVE_NAME_BLANKS), function="BTRIM", output_field=CharField())
    names = CveId.objects.filter(cve_ids=OuterRef(p + "pk")).annotate(upper=Upper(trimmed)).exclude(upper="")
    carries = Exists(names)
    hot = Exists(names.filter(upper__in=CVEEntry.objects.filter(hot_q()).values("cve_id")))
    unconfirmed = (Q(**{p + "source__in": VERSION_READ_SOURCES})
                   | Q(Exists(VulnerabilityTags.objects.filter(vuln_tags=OuterRef(p + "pk"), name=UNCONFIRMED_TAG))))
    confirmed = Q(**{p + "triage__validation_status": "hit"}) | ~unconfirmed
    whens = [*manual, When(~Q(**{p + "severity__in": list(SEVERITY_HEAT)}), then=Value(0)),
             When(Q(carries) & ~Q(hot), then=Value(HEAT_RANK[ICE]))]
    if capped:
        whens += [When(Q(hot) & confirmed, then=Value(HEAT_RANK[FIRE])), When(Q(hot), then=Value(HEAT_RANK[SMOKE]))]
    else:
        whens.append(When(Q(hot), then=Value(HEAT_RANK[FIRE])))
    return Case(*whens, default=severity, output_field=IntegerField())


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
