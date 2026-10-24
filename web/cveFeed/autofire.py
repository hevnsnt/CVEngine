"""Auto-fire: when a new FIRE/SMOKE CVE arrives, correlate it against the
inventory, let the AI confirm the matches, pick the affected domains, and test the
kept hosts for the CVE. No full scan is started: discovery and fingerprinting already
ran once per host. The human monitors; this is the loop that acts.

``select_hosts`` is pure so it is unit-testable without a database.
"""
import logging

from cveFeed.threat import FIRE, SMOKE

logger = logging.getLogger(__name__)

HOT_TIERS = (FIRE, SMOKE)
MIN_DETERMINISTIC_CONFIDENCE = 0.7  # used when no AI verdict exists
CANDIDATE_LIMIT = 500
DEFAULT_MAX_HOSTS = 200  # hosts tested per CVE


def keep_match(ai_verdict, confidence, distro_status=""):
    """Whether a match should drive a scan: a match the host's distribution has patched never does, then the AI's call wins,
    else the heuristic."""
    if distro_status == "patched":
        return False
    if ai_verdict:
        return ai_verdict in ("affected", "uncertain")
    return confidence >= MIN_DETERMINISTIC_CONFIDENCE


def select_hosts(matches, max_hosts):
    """Pick the hosts to test from (domain_id, domain_name, host, verdict, confidence) tuples: each host once at its
    strongest evidence (confirmed first, then confidence), strongest first, capped at ``max_hosts``."""
    best = {}
    for domain_id, name, host, verdict, confidence in matches:
        if domain_id is None or not host or not keep_match(verdict, confidence):
            continue
        rank = (verdict == "affected", confidence)
        if (domain_id, host) not in best or rank > best[(domain_id, host)][0]:
            best[(domain_id, host)] = (rank, name)
    ordered = sorted(best.items(), key=lambda kv: kv[1][0], reverse=True)
    return [(domain_id, name, host) for (domain_id, host), (_, name) in ordered[:max_hosts]]


def hot_cves_without_run(limit=CANDIDATE_LIMIT):
    """FIRE and SMOKE CVEs that have not fired yet, newest first. The tier is decided by the database, and only the columns
    correlation and the AI prompt read are loaded (never ``raw``)."""
    from cveFeed.models import CVEEntry
    from cveFeed.threat import hot_tier_q
    return list(CVEEntry.objects.filter(autofire__isnull=True).filter(hot_tier_q()).only(
        "id", "cve_id", "title", "summary", "original_description", "cvss", "affected", "kev", "epss_reached", "exploit_db",
        "published_at").order_by("-published_at")[:limit])


def dispatch_template_test(cve_pk, hosts, project_id=None, batch=None):
    """Queue one CVE's template test. ``batch`` (see cveFeed.hit_batch) makes its hits part of one run's single notification."""
    from cveFeed.tasks import template_test_for_cve
    if batch is None:
        template_test_for_cve.delay(cve_pk, hosts, project_id)
    else:
        template_test_for_cve.delay(cve_pk, hosts, project_id, batch)


def correlate_hot_cves(cves, chunk_size=500):
    """Correlate every CVE in ``cves`` against the inventory in one walk of the subdomains."""
    from cveFeed.correlation import build_product_index, candidate_subdomains, correlate_subdomains

    index = build_product_index(cves)
    by_id = {c.id: c for c in cves}
    correlate_subdomains(candidate_subdomains(index).iterator(chunk_size=chunk_size), index, by_id,
                         min_confidence=0.4, batch=chunk_size)


def confirm_matches(matches, cve, provider=None):
    """Triage the matches of one CVE (cveFeed.triage): hosts with the same evidence share one AI answer, which is stored (TriageVerdict,
    and MatchVerdict for correlation), and the legacy ai_verdict of each match follows the classification. Returns the number of
    questions actually asked."""
    from cveFeed import triage
    return triage.triage_matches(matches, cve, provider=provider)


def fire_for_cve(cve, engine_id=None, max_hosts=DEFAULT_MAX_HOSTS, provider=None, test_dispatcher=dispatch_template_test,
                 correlated=False):
    """Correlate one CVE, AI-confirm, pick the hosts (at most ``max_hosts``), test them. Records an AutoFireRun.

    ``engine_id`` is kept so old callers still work; no scan is started, so it is ignored. With
    ``correlated=True`` the caller already ran ``correlate_hot_cves``, so the inventory is not walked again.
    """
    from cveFeed.models import AutoFireRun, CVEMatch

    from cveFeed import activity
    run = AutoFireRun(cve_entry=cve, tier=cve.threat_tier)
    hunting = activity.log('target', f'{cve.cve_id} is {run.tier.upper()}: looking for exposed hosts',
                           cve_id=cve.cve_id, status='running')
    project_ids = set()
    try:
        if not correlated:
            correlate_hot_cves([cve])
        from cveFeed.correlation import latest_scan_q
        matches = list(CVEMatch.objects.filter(cve_entry=cve).filter(latest_scan_q("subdomain__")).select_related("subdomain__target_domain"))
        confirm_matches(matches, cve, provider=provider)
        from cveFeed import scoring
        scoring.rescore_for_matches(matches)  # verdicts move the hosts' scores
        run.matches_found = len(matches)
        project_ids = {m.subdomain.target_domain.project_id for m in matches
                       if m.subdomain and m.subdomain.target_domain and m.subdomain.target_domain.project_id}
        rows = [
            (m.subdomain.target_domain_id if m.subdomain else None,
             m.subdomain.target_domain.name if m.subdomain and m.subdomain.target_domain else "",
             m.subdomain.name if m.subdomain else "", m.ai_verdict, m.confidence)
            for m in matches if keep_match(m.ai_verdict, m.confidence, m.distro_status)]
        picked = select_hosts(rows, max_hosts)
        targets = list(dict.fromkeys((domain_id, name) for domain_id, name, _ in picked))  # strongest domain first
        if not targets:
            run.status = "no_targets"
        project_of = {m.subdomain.target_domain_id: m.subdomain.target_domain.project_id
                      for m in matches if m.subdomain and m.subdomain.target_domain}
        hosts_of = {}
        for domain_id, _name, host in picked:
            hosts_of.setdefault(domain_id, set()).add(host)
        for domain_id, name in targets:
            run.targets.append(name)
            # Tenant data: each entry goes to the project that owns the host, never to a shared (project-less) row.
            count = len(hosts_of.get(domain_id, ()))
            activity.log('scan', f'Testing {count} host(s) of {name} for {cve.cve_id}', cve_id=cve.cve_id,
                         project=project_of.get(domain_id))
        if targets and test_dispatcher:
            # One test per project with only that project's hosts: the run logs "Validated finding: <host>" into the project
            # it is dispatched for, so mixing tenants would show one project another's hostnames.
            from targetApp.target_types import scannable_hosts
            by_project = {}
            for domain_id, hosts in hosts_of.items():
                by_project.setdefault(project_of.get(domain_id), set()).update(hosts)
            for project_id, hosts in sorted(by_project.items(), key=lambda kv: (kv[0] is None, kv[0] or 0)):
                allowed = scannable_hosts(sorted(hosts), project=project_id)  # a stored name may point somewhere a scanner must not go now
                if len(allowed) < len(hosts):
                    activity.log('scan', f'Left {len(hosts) - len(allowed)} host(s) out of the {cve.cve_id} test: they resolve to an '
                                 f'address that must not be scanned', cve_id=cve.cve_id, project=project_id)
                if allowed:
                    test_dispatcher(cve.pk, allowed, project_id)
    except Exception as exc:  # one CVE failing must not stop the batch
        logger.exception("auto-fire failed for %s", cve.cve_id)
        run.status = "error"
        run.error = str(exc)[:1000]
    run.save()
    if run.status == 'error':
        activity.settle(hunting, 'failed', message=f'{cve.cve_id}: auto-fire hit an error')
    elif run.status == 'no_targets':
        activity.settle(hunting, 'done', message=f'{cve.cve_id} ({run.tier}): no exposed hosts in your inventory')
    else:
        # `hunting` has no project, so every tenant can read it: counts only, no host names.
        activity.settle(hunting, 'done', message=(
            f'{cve.cve_id} ({run.tier}): identified {len(run.targets)} target{"s" if len(run.targets) != 1 else ""} '
            f'across {len(project_ids)} project{"s" if len(project_ids) != 1 else ""}'))
    return run
