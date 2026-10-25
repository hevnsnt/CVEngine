"""Bug bounty API behind /cve/api/bounty/ (session + CSRF, never part of the agent API).

Who may call it: an App Admin, or a user an App Admin authorized (UserProfile.bugbounty_enabled). The middleware already refuses
other users on this path; ``dispatch`` checks again, so the rule does not depend on one layer. Everything that belongs to a project
(engagements, reports, imported targets) resolves the project through agentapi.services.get_one_project, the same tenancy check the
rest of the app uses, and reads and writes only rows of that project. The program catalogue is public data and has no owner.

Nothing here sends anything to a platform except ``reports/<id>/submit``, which needs the report to pass every blocking check, the
user's own credential, and the program handle typed back as confirmation.
"""
import json
import re
from datetime import timedelta

from django.core.cache import cache
from django.db import transaction
from django.db.models import Count, Max, Q, Sum
from django.http import JsonResponse
from django.utils import timezone

from agentapi import services
from agentapi.services import ApiError
from cveFeed import bounty_report, bounty_scope, bounty_submit
from cveFeed.admin_api import audit
from cveFeed.models import (BountyAsset, BountyCredential, BountyEngagement, BountyEngagementTarget, BountyProgram, BountyReport,
                            BountyReportEvent, BountyScopeChange, BountySource)

PAGE = 25
MAX_BODY = 2 * 1024 * 1024
REFRESH_COOLDOWN = 300
MAX_IMPORT = 200
MATCH_TARGET_CAP = 500
SUBMIT_PLATFORMS = ("hackerone",)
EVENT_KINDS = ("created", "edited", "status", "submitted", "uncertain", "bounty", "note")


def allowed(user):
    """True for an App Admin or a user an App Admin authorized."""
    if not (user and user.is_authenticated and user.is_active):
        return False
    if user.is_superuser:
        return True
    from dashboard.models import UserProfile
    return UserProfile.objects.filter(user=user, bugbounty_enabled=True).exists()


def _body(request):
    if len(request.body or b"") > MAX_BODY:
        raise ApiError(413, "request too large")
    try:
        data = json.loads(request.body or b"{}")
    except json.JSONDecodeError:
        raise ApiError(400, "body must be valid JSON")
    return data if isinstance(data, dict) else {}


def _int(value, name, default=None):
    if value in (None, ""):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ApiError(400, f"{name} must be a number")


def _iso(value):
    return value.isoformat() if value else None


def _project(request, data, write=False):
    slug = (data.get("project") if isinstance(data, dict) else None) or request.GET.get("project") or ""
    if not slug:
        raise ApiError(400, "pick a project")
    return services.get_one_project(services.Ctx(user=request.user), slug, write=write)[0]


def _event(report, kind, note="", actor=None):
    BountyReportEvent.objects.create(report=report, kind=kind, note=str(note)[:2000], actor=actor)


# --- serializers --------------------------------------------------------------------------------

def program_dict(p, detail=False):
    out = {"id": p.id, "platform": p.platform, "handle": p.handle, "name": p.name, "url": p.url, "offers_bounties": p.offers_bounties,
           "min_bounty": p.min_bounty, "max_bounty": p.max_bounty, "currency": p.currency, "safe_harbor": p.safe_harbor,
           "managed": p.managed, "state": p.state, "response_efficiency": p.response_efficiency,
           "first_response_hours": p.first_response_hours, "resolved_hours": p.resolved_hours, "in_scope": p.in_scope_count,
           "bounty_scope": p.bounty_scope_count, "first_seen": _iso(p.first_seen_at), "scope_changed": _iso(p.last_scope_change_at),
           "removed": bool(p.removed_at)}
    if detail:
        out["updated"] = _iso(p.updated_at)
    return out


def asset_dict(a):
    return {"kind": a.kind, "identifier": a.identifier, "type": a.raw_type, "in_scope": a.in_scope,
            "eligible_for_bounty": a.eligible_for_bounty, "max_severity": a.max_severity, "instruction": a.instruction,
            "first_seen": _iso(a.first_seen_at)}


def engagement_dict(e):
    p = e.program
    return {"id": e.id, "program": program_dict(p), "status": e.status, "policy_url": e.policy_url or p.url, "policy_ack_at": _iso(e.policy_ack_at),
            "policy_ack_by": e.policy_ack_by.username if e.policy_ack_by_id else None,
            "scope_changed_since_ack": bool(e.policy_ack_at and e.ack_content_hash != p.content_hash),
            "automated_ok": e.automated_ok, "notes": e.notes, "targets": e.targets.count(), "updated": _iso(e.updated_at),
            "reports": e.reports.count()}


def _program_context(report):
    p, e = report.program, report.engagement
    if p is None:
        return {"policy_ack": bool(e and e.policy_ack_at), "automated_ok": bool(e and e.automated_ok)}
    return {"removed": bool(p.removed_at), "state": p.state, "offers_bounties": p.offers_bounties,
            "policy_ack": bool(e and e.policy_ack_at), "automated_ok": bool(e and e.automated_ok),
            "scope_changed_since_ack": bool(e and e.policy_ack_at and e.ack_content_hash != p.content_hash)}


def _report_fields(r):
    return {"title": r.title, "severity": r.severity, "cvss_score": r.cvss_score, "cvss_vector": r.cvss_vector, "cwe": r.cwe, "vrt": r.vrt,
            "asset": r.asset, "location_url": r.location_url, "summary": r.summary, "steps": r.steps, "impact": r.impact,
            "remediation": r.remediation, "references": r.references, "evidence": r.evidence or {}, "checklist": r.checklist or {}}


def verdict_for(report):
    if report.program_id is None:
        return None
    target = report.asset or report.location_url
    return bounty_scope.ScopeIndex(report.program.assets.filter(removed_at__isnull=True)).check(target)


def report_dict(r, full=False):
    out = {"id": r.id, "title": r.title, "status": r.status, "severity": r.severity, "platform": r.platform,
           "program": r.program_name or r.program_handle, "program_id": r.program_id, "engagement_id": r.engagement_id, "asset": r.asset,
           "platform_report_id": r.platform_report_id, "platform_url": r.platform_url, "submitted_at": _iso(r.submitted_at),
           "bounty_amount": f"{float(r.bounty_amount):.2f}" if r.bounty_amount is not None else None, "bounty_currency": r.bounty_currency,
           "updated": _iso(r.updated_at), "created": _iso(r.created_at)}
    if full:
        dup = list(BountyReport.objects.filter(project_id=r.project_id, asset=r.asset, title=r.title).exclude(pk=r.pk)
                   .exclude(status="closed").values_list("id", flat=True)[:3]) if r.asset and r.title else []
        verdict = verdict_for(r)
        findings = bounty_report.lint({**_report_fields(r)}, verdict, _program_context(r), dup)
        out.update(_report_fields(r))
        out.update({"vrt_label": bounty_report.vrt_entry(r.vrt) if r.vrt else None, "finding_kind": r.finding_kind, "finding_id": r.finding_id, "warnings": r.warnings or [], "scope": verdict.as_dict() if verdict else None,
                    "checks": findings, "can_submit": r.platform in SUBMIT_PLATFORMS and not bounty_report.blockers(findings)
                    and r.status in ("draft", "ready") and not r.platform_report_id,
                    "next_states": list(bounty_report.TRANSITIONS.get(r.status, ())),
                    "events": [{"kind": e.kind, "note": e.note, "at": _iso(e.at), "by": e.actor.username if e.actor_id else None}
                               for e in r.events.select_related("actor")[:200]],
                    "checklist_items": [{"key": k, "label": label} for k, label in bounty_report.CHECKLIST]})
    return out


# --- status and catalogue -----------------------------------------------------------------------

def status(request, user):
    sources = {s.platform: s for s in BountySource.objects.all()}
    creds = {c.platform: c.username for c in BountyCredential.objects.filter(user=user)}
    return {"user": {"username": user.username, "is_app_admin": user.is_superuser},
            "catalogue": [{"platform": p, "label": label, "loaded": p in sources and bool(sources[p].last_changed),
                           "programs": sources[p].programs if p in sources else 0, "assets": sources[p].assets if p in sources else 0,
                           "checked": _iso(sources[p].last_checked) if p in sources else None,
                           "changed": _iso(sources[p].last_changed) if p in sources else None,
                           "error": sources[p].last_error if p in sources else ""} for p, label in BountyProgram.PLATFORMS],
            "source": "https://github.com/arkadiyt/bounty-targets-data", "credentials": creds,
            "vrt_release": bounty_report.vrt()["release_date"], "platforms_with_submit": list(SUBMIT_PLATFORMS)}


def catalogue_refresh(request, user):
    import os
    if os.environ.get("CVENGINE_BOUNTY_CATALOGUE", "1") == "0":
        raise ApiError(409, "the bug bounty catalogue is turned off on this instance (CVENGINE_BOUNTY_CATALOGUE=0)")
    if not cache.add("bounty-catalogue-refresh", 1, REFRESH_COOLDOWN):
        raise ApiError(429, "the catalogue was refreshed a moment ago; the source updates about every 30 minutes")
    from cveFeed.tasks import sync_bounty_catalogue
    sync_bounty_catalogue.delay(force=True)
    audit(user, "bounty.catalogue_refresh", "bounty-targets-data")
    return {"queued": True}, 202


def _program_qs(params):
    qs = BountyProgram.objects.filter(removed_at__isnull=True)
    if params.get("platform") in dict(BountyProgram.PLATFORMS):
        qs = qs.filter(platform=params["platform"])
    q = (params.get("q") or "").strip()[:100]
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(handle__icontains=q)
                       | Q(pk__in=BountyAsset.objects.filter(identifier__icontains=q, removed_at__isnull=True).values("program_id")[:5000]))
    if params.get("bounty") == "1":
        qs = qs.filter(offers_bounties=True)
    if params.get("harbor") in ("full", "partial"):
        qs = qs.filter(safe_harbor=params["harbor"]) if params["harbor"] == "full" else qs.filter(safe_harbor__in=("full", "partial"))
    days = _int(params.get("scope_days"), "scope_days")
    if days:
        qs = qs.filter(last_scope_change_at__gte=timezone.now() - timedelta(days=min(days, 365)))
    new_days = _int(params.get("new_days"), "new_days")
    if new_days:
        qs = qs.filter(pk__in=BountyScopeChange.objects.filter(kind="program_added", detected_at__gte=timezone.now() - timedelta(days=min(new_days, 365)))
                       .values("program_id"))
    if params.get("min_payout"):
        qs = qs.filter(max_bounty__gte=_int(params["min_payout"], "min_payout"))
    return qs


SORTS = {"changed": ["-last_scope_change_at", "name"], "payout": ["-max_bounty", "name"], "scope": ["-in_scope_count", "name"],
         "name": ["name"], "response": ["first_response_hours", "name"]}


def programs_list(request, user):
    params = request.GET
    qs = _program_qs(params).order_by(*SORTS.get(params.get("sort"), SORTS["changed"]))
    page = max(1, _int(params.get("page"), "page", 1))
    total = qs.count()
    rows = list(qs[(page - 1) * PAGE:page * PAGE])
    mine = set()
    project = None
    if params.get("project"):
        project = _project(request, {})
        mine = set(BountyEngagement.objects.filter(project=project, program__in=rows).values_list("program_id", flat=True))
    return {"count": total, "page": page, "page_size": PAGE, "results": [{**program_dict(p), "engaged": p.id in mine} for p in rows]}


def program_detail(request, user, program_id):
    p = BountyProgram.objects.filter(pk=program_id).first()
    if not p:
        raise ApiError(404, "program not found")
    assets = list(p.assets.filter(removed_at__isnull=True).order_by("-in_scope", "kind", "identifier")[:3000])
    changes = list(p.changes.all()[:50])
    out = {**program_dict(p, detail=True), "assets": [asset_dict(a) for a in assets], "assets_truncated": p.assets.filter(removed_at__isnull=True).count() > 3000,
           "changes": [{"kind": c.kind, "asset_kind": c.asset_kind, "identifier": c.identifier, "in_scope": c.in_scope, "at": _iso(c.detected_at)} for c in changes]}
    if request.GET.get("project"):
        eng = BountyEngagement.objects.filter(project=_project(request, {}), program=p).select_related("program", "policy_ack_by").first()
        out["engagement"] = engagement_dict(eng) if eng else None
    return out


def changes_list(request, user):
    params = request.GET
    days = min(_int(params.get("days"), "days", 7), 180)
    qs = BountyScopeChange.objects.filter(detected_at__gte=timezone.now() - timedelta(days=days), program__removed_at__isnull=True).select_related("program")
    if params.get("kind") in BountyScopeChange.KINDS:
        qs = qs.filter(kind=params["kind"])
    if params.get("platform") in dict(BountyProgram.PLATFORMS):
        qs = qs.filter(program__platform=params["platform"])
    if params.get("bounty") == "1":
        qs = qs.filter(program__offers_bounties=True)
    if params.get("in_scope") == "1":
        qs = qs.filter(in_scope=True)
    if params.get("project") and params.get("mine") == "1":
        qs = qs.filter(program_id__in=BountyEngagement.objects.filter(project=_project(request, {})).values("program_id"))
    page = max(1, _int(params.get("page"), "page", 1))
    total = qs.count()
    rows = list(qs[(page - 1) * 50:page * 50])
    return {"count": total, "page": page, "page_size": 50, "days": days,
            "results": [{"kind": c.kind, "asset_kind": c.asset_kind, "identifier": c.identifier, "in_scope": c.in_scope, "at": _iso(c.detected_at),
                         "program": program_dict(c.program)} for c in rows]}


def _parents(name):
    parts = name.split(".")
    return [".".join(parts[i:]) for i in range(1, len(parts) - 1)]


def matches(request, user):
    """The project's own domain targets that a program lists, with the scope verdict of each. IP targets are not matched here."""
    from targetApp.models import Domain
    project = _project(request, {})
    names = list(Domain.objects.filter(project=project).order_by("name").values_list("name", flat=True)[:MATCH_TARGET_CAP])
    names = [n.lower() for n in names if bounty_scope.parse_host(n) and bounty_scope.parse_host(n)[0] == "domain"]
    cand = set()
    for n in names:
        cand.add(n)
        cand.add("*." + n)
        for parent in _parents(n):
            cand.update((parent, "*." + parent))
    program_ids = set(BountyAsset.objects.filter(identifier__in=list(cand), removed_at__isnull=True, program__removed_at__isnull=True)
                      .values_list("program_id", flat=True)[:2000])
    programs = {p.id: p for p in BountyProgram.objects.filter(pk__in=program_ids)}
    by_prog = {}
    for a in BountyAsset.objects.filter(program_id__in=list(programs), removed_at__isnull=True).iterator(chunk_size=2000):
        by_prog.setdefault(a.program_id, []).append(a)
    results = []
    for pid, p in programs.items():
        index = bounty_scope.ScopeIndex(by_prog.get(pid, []))
        hits = []
        for n in names:
            v = index.check(n)
            if v.state in (bounty_scope.IN, bounty_scope.OUT, bounty_scope.AMBIGUOUS) and v.asset:
                hits.append({"target": n, **v.as_dict()})
        if hits:
            results.append({"program": program_dict(p), "targets": hits[:50], "count": len(hits)})
    results.sort(key=lambda r: (-sum(1 for t in r["targets"] if t["state"] == "in_scope"), r["program"]["name"].lower()))
    return {"results": results[:200], "targets_checked": len(names)}


def scope_check(request, user):
    data = _body(request)
    program = BountyProgram.objects.filter(pk=_int(data.get("program_id"), "program_id")).first()
    if not program:
        raise ApiError(404, "program not found")
    hosts = [str(h)[:500] for h in (data.get("hosts") or [data.get("host")]) if h][:50]
    if not hosts:
        raise ApiError(400, "give a host")
    index = bounty_scope.ScopeIndex(program.assets.filter(removed_at__isnull=True))
    return {"program": program_dict(program), "results": [{"host": h, **index.check(h).as_dict()} for h in hosts]}


# --- engagements --------------------------------------------------------------------------------

def engagements_list(request, user):
    project = _project(request, {})
    rows = BountyEngagement.objects.filter(project=project).select_related("program", "policy_ack_by").order_by("-updated_at")[:500]
    return {"results": [engagement_dict(e) for e in rows]}


def engagements_create(request, user):
    data = _body(request)
    project = _project(request, data, write=True)
    program = BountyProgram.objects.filter(pk=_int(data.get("program_id"), "program_id"), removed_at__isnull=True).first()
    if not program:
        raise ApiError(404, "program not found")
    eng, created = BountyEngagement.objects.get_or_create(project=project, program=program, defaults={"created_by": user, "policy_url": program.url})
    if created:
        audit(user, "bounty.engagement_create", f"{program.platform}:{program.handle}", org=project.org, project=project.slug)
    return engagement_dict(eng), (201 if created else 200)


def _engagement(request, data, engagement_id, write=False):
    project = _project(request, data, write=write)
    eng = BountyEngagement.objects.filter(pk=engagement_id, project=project).select_related("program", "policy_ack_by").first()
    if not eng:
        raise ApiError(404, "engagement not found")
    return project, eng


def engagements_update(request, user, engagement_id):
    data = _body(request)
    project, eng = _engagement(request, data, engagement_id, write=True)
    if "status" in data:
        if data["status"] not in BountyEngagement.STATUSES:
            raise ApiError(400, "status must be one of " + ", ".join(BountyEngagement.STATUSES))
        if data["status"] == "active" and not eng.policy_ack_at:
            raise ApiError(409, "record that you read the program's policy before you mark it active")
        eng.status = data["status"]
    if "notes" in data:
        eng.notes = str(data["notes"])[:20000]
    if "policy_url" in data:
        url = str(data["policy_url"]).strip()[:500]
        if url and not re.match(r"^https://", url):
            raise ApiError(400, "the policy address must start with https://")
        eng.policy_url = url
    if "automated_ok" in data:
        if not isinstance(data["automated_ok"], bool):
            raise ApiError(400, "automated_ok must be true or false")
        if data["automated_ok"] and not eng.policy_ack_at:
            raise ApiError(409, "record that you read the policy first")
        eng.automated_ok = data["automated_ok"]
        audit(user, "bounty.automated_ok", f"{eng.program.platform}:{eng.program.handle}", org=project.org, project=project.slug, value=data["automated_ok"])
    if data.get("acknowledge") is True:
        eng.policy_ack_at, eng.policy_ack_by, eng.ack_content_hash = timezone.now(), user, eng.program.content_hash
        audit(user, "bounty.policy_ack", f"{eng.program.platform}:{eng.program.handle}", org=project.org, project=project.slug)
    eng.save()
    return engagement_dict(eng)


def engagements_delete(request, user, engagement_id):
    project, eng = _engagement(request, {}, engagement_id, write=True)
    if eng.reports.exclude(status="closed").exists():
        raise ApiError(409, "this engagement has open reports; close them first")
    eng.delete()
    return {"deleted": True}


def engagement_import(request, user, engagement_id):
    """Preview or run: the program's in-scope entries as targets of the project. Running needs the policy acknowledgement; discovery
    starts only when the person confirmed the policy allows automated scanning."""
    data = _body(request)
    project, eng = _engagement(request, data, engagement_id, write=True)
    from targetApp.target_types import is_scannable_ip
    plan = bounty_scope.import_plan(eng.program.assets.filter(removed_at__isnull=True), scannable=lambda ip: is_scannable_ip(ip))
    if data.get("dry_run", True) is not False:
        return {"dry_run": True, "targets": plan["targets"][:2000], "skipped": plan["skipped"][:500], "total": len(plan["targets"]),
                "discovery": eng.automated_ok}
    if not eng.policy_ack_at:
        raise ApiError(409, "record that you read the program's policy before you import its scope")
    wanted = data.get("values")
    pool = {t["value"]: t for t in plan["targets"]}
    chosen = [v for v in (wanted if isinstance(wanted, list) else list(pool)) if isinstance(v, str) and v in pool]
    if not chosen:
        raise ApiError(400, "no importable targets selected")
    if len(chosen) > MAX_IMPORT:
        raise ApiError(400, f"{len(chosen)} targets selected; the limit is {MAX_IMPORT} per import")
    result = services.add_targets(services.Ctx(user=user), project.slug, chosen, discover=bool(eng.automated_ok))
    from targetApp.models import Domain
    have = {d.name: d for d in Domain.objects.filter(project=project, name__in=chosen)}
    for value in chosen:
        if value in have:
            BountyEngagementTarget.objects.get_or_create(engagement=eng, value=value, defaults={"domain": have[value], "asset_identifier": pool[value]["asset"][:500]})
    audit(user, "bounty.import_targets", f"{eng.program.platform}:{eng.program.handle}", org=project.org, project=project.slug,
          requested=len(chosen), created=result.get("created", 0), discovery=bool(eng.automated_ok))
    return {"dry_run": False, "requested": len(chosen), "created": result.get("created", 0), "already_exists": len(result.get("already_exists", [])),
            "invalid": result.get("invalid", [])[:50], "discovery_started": bool(result.get("discovery_started"))}


# --- reports ------------------------------------------------------------------------------------

def _vuln_dict(v):
    host = v.subdomain.name if getattr(v, "subdomain", None) else (v.target_domain.name if getattr(v, "target_domain", None) else "")
    triage = getattr(v, "triage", None)
    return {"name": v.name, "severity": v.severity, "description": v.description, "impact": v.impact, "remediation": v.remediation,
            "http_url": v.http_url, "curl_command": v.curl_command, "request": v.request, "response": v.response, "template_id": v.template_id,
            "matcher_name": v.matcher_name, "extracted_results": list(v.extracted_results or []), "tags": [t.name for t in v.tags.all()],
            "references": [r.url for r in v.references.all()], "cve_ids": [c.name for c in v.cve_ids.all()], "cwe_ids": [c.name for c in v.cwe_ids.all()],
            "cvss_score": v.cvss_score, "cvss_metrics": v.cvss_metrics, "host": host,
            "triage": getattr(triage, "classification", "") if triage else ""}


def findings_list(request, user):
    """The project's scanner findings a report can start from, worst first, each marked with the reports already drafted from it."""
    from startScan.models import Vulnerability
    project = _project(request, {})
    qs = services._scoped(Vulnerability.objects.all(), project, "target_domain__project").select_related("subdomain", "target_domain")
    if request.GET.get("severity") == "actionable" or not request.GET.get("severity"):
        qs = qs.exclude(severity__lte=0)
    q = (request.GET.get("q") or "").strip()[:100]
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(http_url__icontains=q) | Q(subdomain__name__icontains=q))
    qs = qs.order_by("-severity", "-id")
    page = max(1, _int(request.GET.get("page"), "page", 1))
    total = qs.count()
    rows = list(qs[(page - 1) * PAGE:page * PAGE])
    drafted = {}
    for rid, fid in BountyReport.objects.filter(project=project, finding_kind="vuln", finding_id__in=[v.id for v in rows]).values_list("id", "finding_id"):
        drafted.setdefault(fid, []).append(rid)
    return {"count": total, "page": page, "page_size": PAGE, "results": [
        {"id": v.id, "name": v.name, "severity": services.SEVERITY_NAMES.get(v.severity, "unknown"), "url": v.http_url,
         "host": v.subdomain.name if v.subdomain else (v.target_domain.name if v.target_domain else ""), "reports": drafted.get(v.id, [])} for v in rows]}


def reports_list(request, user):
    project = _project(request, {})
    qs = BountyReport.objects.filter(project=project)
    if request.GET.get("status") in BountyReport.STATUSES:
        qs = qs.filter(status=request.GET["status"])
    elif request.GET.get("open") == "1":
        qs = qs.filter(status__in=("draft", "ready") + BountyReport.OPEN_STATUSES)
    if request.GET.get("engagement"):
        qs = qs.filter(engagement_id=_int(request.GET["engagement"], "engagement"))
    return {"results": [report_dict(r) for r in qs.select_related("program")[:500]]}


@transaction.atomic
def reports_create(request, user):
    data = _body(request)
    project = _project(request, data, write=True)
    eng = None
    program = None
    if data.get("engagement_id"):
        eng = BountyEngagement.objects.filter(pk=_int(data["engagement_id"], "engagement_id"), project=project).select_related("program").first()
        if not eng:
            raise ApiError(404, "engagement not found")
        program = eng.program
    elif data.get("program_id"):
        program = BountyProgram.objects.filter(pk=_int(data["program_id"], "program_id")).first()
        if not program:
            raise ApiError(404, "program not found")
        eng = BountyEngagement.objects.filter(project=project, program=program).first()
    fields, notes, kind, fid = {}, [], "", None
    if data.get("vulnerability_id"):
        from startScan.models import Vulnerability
        v = services._scoped(Vulnerability.objects.all(), project, "target_domain__project").filter(pk=_int(data["vulnerability_id"], "vulnerability_id")) \
            .select_related("subdomain", "target_domain").prefetch_related("tags", "references", "cve_ids", "cwe_ids").first()
        if not v:
            raise ApiError(404, "finding not found")
        kind, fid = "vuln", v.id
        if program and BountyReport.objects.filter(project=project, program=program, finding_kind=kind, finding_id=fid).exists():
            raise ApiError(409, "a report for this finding and program already exists")
        d = bounty_report.draft_from_vulnerability(_vuln_dict(v))
        notes = d.pop("notes")
        if getattr(getattr(v, "triage", None), "classification", "") in services.FALSE_POSITIVES:
            notes.append("The scanner's own triage classified this finding as a likely false positive. Reproduce it before you write anything more.")
        fields = d
    try:
        fields.update(bounty_report.clean_fields({k: v for k, v in data.items() if k in bounty_report.FIELD_LIMITS}))
    except ValueError as exc:
        raise ApiError(400, str(exc))
    if not fields.get("title"):
        fields["title"] = ""
    r = BountyReport.objects.create(project=project, engagement=eng, program=program, platform=program.platform if program else str(data.get("platform", ""))[:16],
                                    program_handle=program.handle if program else "", program_name=program.name if program else "",
                                    finding_kind=kind, finding_id=fid, warnings=notes, created_by=user, checklist={}, **fields)
    _event(r, "created", "from scanner finding" if kind else "blank draft", user)
    return report_dict(r, full=True), 201


def _report(request, data, report_id, write=False):
    project = _project(request, data, write=write)
    r = BountyReport.objects.filter(pk=report_id, project=project).select_related("program", "engagement").first()
    if not r:
        raise ApiError(404, "report not found")
    return project, r


def reports_get(request, user, report_id):
    return report_dict(_report(request, {}, report_id)[1], full=True)


@transaction.atomic
def reports_update(request, user, report_id):
    data = _body(request)
    project = _project(request, data, write=True)
    r = BountyReport.objects.select_for_update(of=("self",)).filter(pk=report_id, project=project).select_related("program", "engagement").first()
    if not r:
        raise ApiError(404, "report not found")
    if r.status in ("submitted", "triaged", "needs_info", "resolved", "duplicate", "informative", "not_applicable", "spam", "closed") \
            and any(k in data for k in bounty_report.FIELD_LIMITS):
        raise ApiError(409, "a submitted report's text is final here; keep your changes in a follow-up comment on the platform")
    try:
        fields = bounty_report.clean_fields(data)
    except ValueError as exc:
        raise ApiError(400, str(exc))
    for key, value in fields.items():
        setattr(r, key, value)
    if fields:
        _event(r, "edited", ", ".join(sorted(k for k in fields if k != "checklist")) or "checklist", user)
    if "status" in data:
        new = data["status"]
        if new not in bounty_report.TRANSITIONS.get(r.status, ()):
            raise ApiError(409, f"a report cannot go from {r.status} to {new}")
        if new == "submitted":
            raise ApiError(409, "use submit, or mark-submitted if you sent it on the platform yourself")
        if new == "ready" and bounty_report.blockers(bounty_report.lint(_report_fields(r), verdict_for(r), _program_context(r))):
            raise ApiError(409, "the report still has blocking problems; see its checks")
        _event(r, "status", f"{r.status} to {new}", user)
        r.status = new
    for key in ("bounty_currency", "platform_url"):
        if key in data:
            value = str(data[key] or "").strip()[:500]
            if key == "platform_url" and value and not re.match(r"^https://", value):
                raise ApiError(400, "the report address must start with https://")
            setattr(r, key, value.upper()[:8] if key == "bounty_currency" else value)
    if "bounty_amount" in data:
        try:
            amount = None if data["bounty_amount"] in (None, "") else round(float(data["bounty_amount"]), 2)
        except (TypeError, ValueError):
            raise ApiError(400, "bounty_amount must be a number")
        if amount is not None and not 0 <= amount < 10 ** 9:
            raise ApiError(400, "bounty_amount is out of range")
        r.bounty_amount = amount
        _event(r, "bounty", f"{amount} {r.bounty_currency}".strip(), user)
    if "note" in data and str(data["note"]).strip():
        _event(r, "note", str(data["note"]).strip()[:2000], user)
    r.save()
    return report_dict(r, full=True)


def reports_delete(request, user, report_id):
    project, r = _report(request, {}, report_id, write=True)
    if r.status not in ("draft", "ready", "closed") or r.platform_report_id:
        raise ApiError(409, "only an unsent draft can be deleted; close a submitted report instead")
    r.delete()
    return {"deleted": True}


def reports_redact(request, user, report_id):
    """Mask credentials and tokens in the report text and attachments. Returns how many were masked."""
    data = _body(request)
    project = _project(request, data, write=True)
    with transaction.atomic():
        r = BountyReport.objects.select_for_update(of=("self",)).filter(pk=report_id, project=project).first()
        if not r:
            raise ApiError(404, "report not found")
        if r.status not in ("draft", "ready"):
            raise ApiError(409, "a submitted report cannot be changed")
        total = 0
        for field in ("steps", "summary", "impact"):
            text, n = bounty_report.redact(getattr(r, field), bounty_report.FIELD_LIMITS[field])
            setattr(r, field, text)
            total += n
        ev = {}
        for k, v in (r.evidence or {}).items():
            text, n = bounty_report.redact(v)
            ev[k], total = text, total + n
        r.evidence = ev
        r.save()
        if total:
            _event(r, "edited", f"masked {total} secret(s)", user)
    return {"masked": total, "report": report_dict(r, full=True)}


def reports_export(request, user, report_id):
    _, r = _report(request, {}, report_id)
    fields = _report_fields(r)
    fmt = request.GET.get("format", "md")
    if fmt == "md":
        return {"format": "md", "content": bounty_report.to_markdown(fields)}
    if fmt in ("bugcrowd", "intigriti", "yeswehack", "hackerone"):
        return {"format": fmt, "fields": [{"name": n, "value": v} for n, v in bounty_report.platform_fields(fields, fmt)],
                "url": r.program.url if r.program_id else ""}
    raise ApiError(400, "format must be md, hackerone, bugcrowd, intigriti or yeswehack")


def _submit_guard(r, findings):
    if r.platform not in SUBMIT_PLATFORMS:
        raise ApiError(409, f"submit from here works for {', '.join(SUBMIT_PLATFORMS)}; copy the fields into {r.platform or 'the platform'} and use mark-submitted")
    if r.status not in ("draft", "ready") or r.platform_report_id:
        raise ApiError(409, "this report was already submitted")
    block = bounty_report.blockers(findings)
    if block:
        raise ApiError(409, "the report has blocking problems: " + " | ".join(b["message"] for b in block[:3]))


def reports_submit(request, user, report_id):
    """Send to HackerOne under the caller's own account. The caller types the program handle back; the row is locked so two clicks
    cannot send twice."""
    data = _body(request)
    project = _project(request, data, write=True)
    with transaction.atomic():
        r = BountyReport.objects.select_for_update(of=("self",)).filter(pk=report_id, project=project).select_related("program", "engagement").first()
        if not r:
            raise ApiError(404, "report not found")
        if not r.program_id or str(data.get("confirm", "")).strip() != r.program.handle:
            raise ApiError(400, f"type the program handle ({r.program.handle if r.program_id else 'none'}) to confirm")
        findings = bounty_report.lint(_report_fields(r), verdict_for(r), _program_context(r))
        _submit_guard(r, findings)
        if r.events.filter(kind="uncertain").exists() and data.get("checked_platform") is not True:
            raise ApiError(409, "an earlier attempt may have reached HackerOne. Check your reports there, then submit again with that confirmed")
        cred = BountyCredential.objects.filter(user=user, platform=r.platform).first()
        if not cred:
            raise ApiError(409, "add your HackerOne API credentials under My accounts first; reports are sent only under your own account")
        payload = bounty_report.hackerone_payload(_report_fields(r), r.program.handle)
        failure = None
        try:
            out = bounty_submit.submit_hackerone(payload, cred.username, cred.token)
        except bounty_submit.SubmitError as exc:
            failure = exc
            if exc.uncertain:
                _event(r, "uncertain", exc.message, user)  # kept: the block ends normally, so this row is committed
        if failure is None:
            now = timezone.now()
            r.platform_report_id, r.platform_url, r.status, r.submitted_at, r.submitted_by = out["id"], out["url"], "submitted", now, user
            r.save()
            cred.last_used_at = now
            cred.save(update_fields=["last_used_at"])
            _event(r, "submitted", f"HackerOne report {out['id']}", user)
            audit(user, "bounty.submit", f"hackerone:{r.program.handle}", org=project.org, project=project.slug, report=r.pk, platform_report=out["id"])
    if failure is not None:
        raise ApiError(400 if failure.status in (401, 403, 404, 422) and not failure.uncertain else 502, failure.message)
    return report_dict(r, full=True)


def reports_mark_submitted(request, user, report_id):
    """Record a report sent by hand on a platform (or on one without a submit path here)."""
    data = _body(request)
    project = _project(request, data, write=True)
    with transaction.atomic():
        r = BountyReport.objects.select_for_update(of=("self",)).filter(pk=report_id, project=project).select_related("program", "engagement").first()
        if not r:
            raise ApiError(404, "report not found")
        if r.status not in ("draft", "ready") or r.platform_report_id:
            raise ApiError(409, "this report is already marked submitted")
        url = str(data.get("platform_url", "")).strip()[:500]
        if url and not re.match(r"^https://", url):
            raise ApiError(400, "the report address must start with https://")
        rid = str(data.get("platform_report_id", "")).strip()[:64]
        if rid and not re.fullmatch(r"[\w-]{1,64}", rid):
            raise ApiError(400, "the report id may hold only letters, digits, - and _")
        r.platform_url, r.platform_report_id, r.status, r.submitted_at, r.submitted_by = url, rid, "submitted", timezone.now(), user
        r.save()
        _event(r, "submitted", "marked as sent by hand" + (f": {url}" if url else ""), user)
    return report_dict(r, full=True)


def stats(request, user):
    project = _project(request, {})
    reports = BountyReport.objects.filter(project=project)
    by_status = {row["status"]: row["n"] for row in reports.values("status").annotate(n=Count("id"))}
    paid = list(reports.filter(bounty_amount__isnull=False).values("bounty_currency").annotate(total=Sum("bounty_amount"), n=Count("id")))
    now = timezone.now()
    stale = []
    for r in reports.filter(status__in=BountyReport.OPEN_STATUSES, submitted_at__isnull=False).select_related("program")[:200]:
        last = r.events.aggregate(m=Max("at"))["m"] or r.submitted_at
        days = (now - last).days
        if r.status == "needs_info" and r.platform == "hackerone" and days >= 20:
            stale.append({"id": r.id, "title": r.title, "days": days, "why": "HackerOne closes a report left in Needs More Info for 30 days"})
        elif days >= 30:
            stale.append({"id": r.id, "title": r.title, "days": days, "why": "no change for a month; a polite follow-up on the platform is reasonable"})
    engs = BountyEngagement.objects.filter(project=project).values("status").annotate(n=Count("id"))
    changed = BountyEngagement.objects.filter(project=project, policy_ack_at__isnull=False).select_related("program")
    return {"reports": by_status, "paid": [{"currency": p["bounty_currency"] or "", "total": str(p["total"]), "count": p["n"]} for p in paid],
            "engagements": {row["status"]: row["n"] for row in engs}, "stale": stale[:20],
            "scope_changed": [{"engagement_id": e.id, "program": e.program.name} for e in changed if e.ack_content_hash != e.program.content_hash][:20]}


# --- the user's own platform accounts -----------------------------------------------------------

def credential_set(request, user, platform):
    if platform not in SUBMIT_PLATFORMS:
        raise ApiError(404, "no submit integration for that platform")
    data = _body(request)
    username, token = str(data.get("username", "")).strip()[:200], str(data.get("token", "")).strip()
    if not username or not token or len(token) > 500:
        raise ApiError(400, "give your API identifier and token")
    BountyCredential.objects.update_or_create(user=user, platform=platform, defaults={"username": username, "token": token})
    audit(user, "bounty.credential_set", platform)
    return {"platform": platform, "username": username, "verified": bounty_submit.check_hackerone(username, token)}


def credential_clear(request, user, platform):
    BountyCredential.objects.filter(user=user, platform=platform).delete()
    audit(user, "bounty.credential_clear", platform)
    return {"deleted": True}


def credential_test(request, user, platform):
    cred = BountyCredential.objects.filter(user=user, platform=platform).first()
    if not cred:
        raise ApiError(404, "no credentials saved")
    return {"verified": bounty_submit.check_hackerone(cred.username, cred.token)}


def taxonomy(request, user):
    q = (request.GET.get("q") or "").strip().lower()[:80]
    rows = bounty_report.vrt()["entries"]
    if q:
        rows = [r for r in rows if q in r[1].lower()]
    return {"release_date": bounty_report.vrt()["release_date"], "results": [{"id": r[0], "label": r[1], "priority": r[2]} for r in rows[:40]]}


def playbook(request, user):
    from cveFeed.bounty_playbook import PLAYBOOK
    return PLAYBOOK


# --- routing ------------------------------------------------------------------------------------

ROUTES = [
    ("GET", r"status", status), ("POST", r"catalogue/refresh", catalogue_refresh),
    ("GET", r"programs", programs_list), ("GET", r"programs/(?P<program_id>\d+)", program_detail),
    ("GET", r"changes", changes_list), ("GET", r"matches", matches), ("POST", r"scope-check", scope_check),
    ("GET", r"engagements", engagements_list), ("POST", r"engagements", engagements_create),
    ("PATCH", r"engagements/(?P<engagement_id>\d+)", engagements_update), ("DELETE", r"engagements/(?P<engagement_id>\d+)", engagements_delete),
    ("POST", r"engagements/(?P<engagement_id>\d+)/import", engagement_import),
    ("GET", r"findings", findings_list),
    ("GET", r"reports", reports_list), ("POST", r"reports", reports_create), ("GET", r"reports/(?P<report_id>\d+)", reports_get),
    ("PATCH", r"reports/(?P<report_id>\d+)", reports_update), ("DELETE", r"reports/(?P<report_id>\d+)", reports_delete),
    ("POST", r"reports/(?P<report_id>\d+)/redact", reports_redact), ("GET", r"reports/(?P<report_id>\d+)/export", reports_export),
    ("POST", r"reports/(?P<report_id>\d+)/submit", reports_submit), ("POST", r"reports/(?P<report_id>\d+)/mark-submitted", reports_mark_submitted),
    ("GET", r"stats", stats), ("GET", r"taxonomy", taxonomy), ("GET", r"playbook", playbook),
    ("PUT", r"credentials/(?P<platform>[a-z]+)", credential_set), ("DELETE", r"credentials/(?P<platform>[a-z]+)", credential_clear),
    ("POST", r"credentials/(?P<platform>[a-z]+)/test", credential_test),
]
COMPILED = [(m, re.compile(f"^{p}/?$"), fn) for m, p, fn in ROUTES]


def dispatch(request, path):
    if not allowed(request.user):
        return JsonResponse({"error": "bug bounty features are not enabled for this user; an App Admin can authorize you"}, status=403)
    path, methods = path.strip("/"), []
    for method, regex, fn in COMPILED:
        match = regex.match(path)
        if not match:
            continue
        methods.append(method)
        if method != request.method:
            continue
        try:
            result = fn(request, request.user, **match.groupdict())
        except ApiError as exc:
            return JsonResponse({"error": exc.message}, status=exc.status)
        data, code = result if isinstance(result, tuple) else (result, 200)
        return JsonResponse(data, status=code)
    return JsonResponse({"error": "method not allowed" if methods else "not found"}, status=405 if methods else 404)
