"""The heat re-rating of 1.3.5: what the new rules change on the findings that are open now (``manage.py rerate_findings``).

Heat is not stored: every list, count, card, report and page reads it live (``threat.match_heat``, ``threat.finding_heat`` and their
database forms), so deploying 1.3.5 changes it at once, for every open finding. This module is the preview of that change, and the
follow-up of the few things that ARE stored:

* the heat each open CVE match and scanner finding shows under the rules before 1.3.5 (``before_match_heat``, ``before_finding_heat``: the
  pre-change logic, kept here unchanged and used for nothing else) against the heat it shows now, counted per project as from -> to;
* host scores (``Subdomain.score``, ``HostState.score``), stored by ``scoring.rescore_hosts``; the daily pass catches up anyway, ``--apply``
  rescores the hosts whose findings changed heat at once;
* fire page marks (``CVEMatch.fire_notified_at``): a match paged as fire under the old rules that is not fire any more keeps its mark, so
  when real proof turns it fire later it would not be paged. ``--apply`` clears the mark of every copy of such a match (never sends anything);
* Triage classifications above the CVE's ``validation.max_remote_state`` (``triage.remote_limit``), stored by triage before 1.3.5 (a page's
  jQuery read from its file was confirmed though the strategy says a check from outside decides it likely at most). ``--apply`` holds them
  to the limit; it changes no heat (likely and confirmed rate the same), only what the finding says.

A dry run (the default) writes nothing. Every count is of the current inventory (``correlation.latest_scan_q``), open findings only (not
ruled out, not closed: ``counts.match_is_live``, ``counts.finding_is_live``). Safe to run again.
"""
from collections import Counter

from cveFeed import match_policy, threat
from cveFeed.threat import FIRE, HEAT_RANK, ICE, LEGACY_POLICY, SEVERITY_HEAT, SMOKE

HEATS = (FIRE, SMOKE, ICE)


# ----------------------------------------------------------------------------- the rules before 1.3.5 (for the "before" column only)

def before_match_heat(match, policy):
    """The heat a CVEMatch showed under 1.3.4: under ``kev`` fire when hot and its version proven (``match_policy.version_proven``, a version
    read from the component counted), no Triage cap; under ``legacy`` the version-only cap alone (Exploit-DB could lift a version-only
    match to fire when the cap allowed it). A heat a person set (``threat.manual_heat``) wins before and after alike."""
    manual = threat.manual_heat(match)
    if manual:
        return manual
    cve = match.cve_entry
    if policy != LEGACY_POLICY:
        if match.distro_status == "patched" or match_policy.version_unknown(match) or not threat.is_hot(cve.kev, cve.exploit_db):
            return ICE
        return FIRE if match_policy.version_proven(match) else SMOKE
    heat = threat.match_temperature(threat.feed_tier(cve, policy), cve.cvss, match.ai_verdict, match.distro_status,
                                    match_policy.version_unknown(match), policy=policy)
    cap = threat.version_only_max_heat()
    if HEAT_RANK.get(heat, 0) > HEAT_RANK[cap] and match_policy.is_version_only(match):
        heat = cap
    return heat


def before_finding_heat(vuln, hot_names, policy):
    """The heat a scanner finding showed under 1.3.4: its severity, or under ``kev`` the CVE rule for one that names CVEs; no validation gate
    and no Triage cap. A heat a person set wins before and after alike."""
    manual = threat.manual_heat(vuln)
    if manual:
        return manual
    severity_heat = SEVERITY_HEAT.get(vuln.severity)
    if severity_heat is None or policy == LEGACY_POLICY:
        return severity_heat
    names = threat.finding_cve_names(vuln)
    if not names:
        return severity_heat
    if not any(n in hot_names for n in names):
        return ICE
    return FIRE if threat.finding_confirmed(vuln) else SMOKE


# ----------------------------------------------------------------------------- the report

def _open_matches(project):
    from cveFeed.closure import CLOSED
    from cveFeed.correlation import latest_scan_q
    from cveFeed.counts import RULED_OUT
    from cveFeed.models import CVEMatch
    return (CVEMatch.objects.filter(subdomain__target_domain__project=project).filter(latest_scan_q('subdomain__'))
            .exclude(ai_verdict=RULED_OUT).exclude(remediation_status__in=CLOSED)
            .select_related('cve_entry__detection', 'triage', 'subdomain').order_by('pk'))


def _open_findings(project):
    from cveFeed.closure import CLOSED
    from startScan.models import Vulnerability
    return (Vulnerability.objects.filter(target_domain__project=project, open_status=True, severity__in=list(SEVERITY_HEAT))
            .exclude(remediation_status__in=CLOSED).select_related('subdomain', 'triage').prefetch_related('cve_ids', 'tags').order_by('pk'))


def _over_the_limit(match):
    """``(limit, prefixed reason)`` when this match's Triage row is classified above ``triage.remote_limit`` without a validation hit, else
    None."""
    from cveFeed import triage
    row = threat._triage_row(match)
    if row is None or row.validation_status == 'hit' or not row.classification:
        return None
    limited, reason = triage._remote_clamp('cve_match', triage.remote_facts(match), row.classification, row.reason or '', row.validation_status)
    return (limited, reason) if limited != row.classification else None


def project_report(project, apply=False):
    """The re-rating of one project: ``{'cve': Counter((before, after)), 'scanner': Counter(...), 'classification': n, 'unmark': n,
    'hosts': n}`` (changed findings only). With ``apply`` the stored follow-ups are written (see the module docstring); heat itself needs no
    write."""
    policy = threat.heat_policy()
    report = {'cve': Counter(), 'scanner': Counter(), 'classification': 0, 'unmark': 0, 'hosts': 0}
    hosts, clamps = set(), []
    for m in _open_matches(project).iterator(chunk_size=500):
        before, after = before_match_heat(m, policy), threat.match_heat(m)
        if before != after:
            report['cve'][(before, after)] += 1
            hosts.add(m.subdomain.name.lower())
        over = _over_the_limit(m)
        if over:
            clamps.append((m, *over))
    findings = list(_open_findings(project))
    hot = threat.hot_cve_names({n for v in findings for n in threat.finding_cve_names(v)}) if policy != LEGACY_POLICY else set()
    for v in findings:
        before, after = before_finding_heat(v, hot, policy), threat.finding_heat(v, hot_names=hot)
        if before != after:
            report['scanner'][(before, after)] += 1
            if v.subdomain_id:
                hosts.add(v.subdomain.name.lower())
    report['classification'] = len(clamps)
    report['hosts'] = len(hosts)
    marked = _paged_not_fire(project)
    report['unmark'] = marked.count()
    if apply:
        _apply(project, clamps, marked, hosts)
    return report


def _paged_not_fire(project):
    """Every copy (any scan) of the project's CVE matches paged as fire under the rule in force that is not fire now."""
    from cveFeed.models import CVEMatch
    from cveFeed.notify import unannounced_q
    return (CVEMatch.objects.filter(subdomain__target_domain__project=project).exclude(unannounced_q())
            .annotate(heat_rank=threat.match_heat_rank_expr()).exclude(heat_rank=HEAT_RANK[FIRE]))


def _apply(project, clamps, marked, hosts):
    from django.utils import timezone

    from cveFeed import scoring, triage
    from cveFeed.models import CVEMatch, Triage
    now = timezone.now()
    rows, verdicts = [], []
    for match, limit, reason in clamps:
        row = match.triage
        row.classification, row.reason, row.updated_at = limit, reason[:700], now
        rows.append(row)
        verdict = triage.verdict_for(limit)
        if verdict and match.ai_verdict != verdict:
            match.ai_verdict, match.updated_at = verdict, now
            verdicts.append(match)
    Triage.objects.bulk_update(rows, ['classification', 'reason', 'updated_at'], batch_size=triage.CHUNK)
    CVEMatch.objects.bulk_update(verdicts, ['ai_verdict', 'updated_at'], batch_size=triage.CHUNK)
    # a cleared mark sends nothing: it only lets real proof of the flaw page the match later (notify.fire_confirmed)
    CVEMatch.objects.filter(pk__in=list(marked.values_list('pk', flat=True))).update(fire_notified_at=None, fire_notified_rule='')
    if hosts:
        scoring.rescore_hosts(project.id, sorted(hosts))
    from cveFeed.views import bump_stats_revision
    bump_stats_revision()


def run(project_slugs=None, apply=False):
    """``{project slug: project_report}`` for every project (or those named)."""
    from dashboard.models import Project
    projects = Project.objects.order_by('slug')
    if project_slugs:
        projects = projects.filter(slug__in=list(project_slugs))
    return {p.slug: project_report(p, apply=apply) for p in projects}


def transitions_text(counter):
    """"fire->smoke 39, smoke->ice 4" (hottest first), or "none"."""
    order = {h: i for i, h in enumerate((*HEATS, None))}
    items = sorted(counter.items(), key=lambda kv: (order.get(kv[0][0], 9), order.get(kv[0][1], 9)))
    return ', '.join(f'{a or "none"}->{b or "none"} {n}' for (a, b), n in items) or 'none'
