"""The review of AI-written scan templates (``GeneratedTemplate``) by an App Admin or an agent: read them, judge them, retire or revise them.

A template is per CVE and global: it runs against every tenant's hosts. So reading its text and status is open to any member, while the
outcomes it recorded are shown per caller (the API layer, ``agentapi.generated_templates``, passes only the matches of the caller's projects),
and every change is for an App Admin.

* ``report``: what can be said offline. The static safety gate (``templategen.static_check``), the static evidence class
  (``templategen.template_evidence``), the template against its own fixture and the benign and 404 pages (``templatefixture``), and each stored
  confirmation read again (``templategen.hit_evidence`` on the response kept with it, as ``recheck_template_hits`` does), with plain findings.
* ``keep``: records the review.
* ``retire``: the row becomes ``invalid`` (``validation.approved_template`` never hands it to a host again) and every confirmation it recorded
  (``CVEMatch.template_result='vulnerable'`` under its id) is read again: a hit whose stored response shows only the version string becomes
  ``version_only`` (``templategen.version_hit_corrected``), any other is withdrawn to no template result (``templategen.retired_check_corrected``).
  Either way the finding the check filed is closed automatically as a false positive unless a person changed it, and the match's triage starts
  over. A match's remediation status is never touched.
* ``revise``: never an edit in place (one template id always means one text). A new draft row with its own id (``<cve id>-r<n>``, found by the
  template index for its CVE) supersedes the old one and goes through the same automatic lifecycle as an AI draft (``templatevalidate``); it
  is never run on a host before it is valid, and when it becomes valid the row it supersedes is retired (``revision_promoted``).

Every verdict is a ``GeneratedTemplateReview`` row (who, when, verdict, reason, what it did) and an audit row.
"""
import logging
import os
import re

from django.db import transaction
from django.utils import timezone

from cveFeed import activity, templatefixture, templategen

logger = logging.getLogger(__name__)

MAX_REASON = 2000
MAX_REPORT_HITS = 200  # stored confirmations read again in one report
MAX_CHAIN = 50  # rows followed along a revision chain
RESULTS = ("vulnerable", templategen.VERSION_ONLY_RESULT, "no_match", "error")
_ID_LINE = re.compile(r"^id[ \t]*:[^\n]*$", re.M)


class ReviewRefused(Exception):
    """A verdict or a revision that cannot be taken, with the HTTP status and the plain reason."""

    def __init__(self, status, message):
        super().__init__(message)
        self.status, self.message = status, message


# ----------------------------------------------------------------------------- reading

def static_gate(tmpl):
    """``{ok, reason}`` of the static safety gate AI drafts pass (``templategen.static_check``), on the text as it is stored."""
    if not tmpl.yaml:
        return {"ok": False, "reason": "no template text was stored (the AI provider call failed)"}
    try:
        ok, reason = templategen.static_check(tmpl.yaml, expected_cve_id=tmpl.cve_entry.cve_id)
    except Exception as exc:  # noqa: BLE001 - an unreadable stored text is a failed gate, never an error page
        ok, reason = False, f"the gate could not read it ({type(exc).__name__})"
    return {"ok": bool(ok), "reason": reason or ""}


def evidence_of(tmpl):
    """``version`` or ``behavior`` (``templategen.template_evidence``), or None for a row with no text."""
    return templategen.template_evidence(tmpl.yaml) if tmpl.yaml else None


def recorded_matches(tmpl):
    """The CVE matches this row's runs recorded, in every project: those of its CVE under its template id. Only a row that was installed
    (``path`` set: it passed every gate and its file was written) ever ran; an AI attempt that was rejected under the same id never did."""
    from cveFeed.models import CVEMatch
    if not tmpl.path or not tmpl.template_id:
        return CVEMatch.objects.none()
    return CVEMatch.objects.filter(cve_entry_id=tmpl.cve_entry_id, template_id=tmpl.template_id)


def _yaml_id(text):
    try:
        return str((templategen.load_template(text) or {}).get("id") or "")[:200]
    except Exception:  # noqa: BLE001 - an unreadable text has no id of its own
        return ""


def template_ids(tmpl):
    """The ids a finding of this template may carry: the row's id and the one in its text (they are the same for every row written today)."""
    return {t for t in (tmpl.template_id, _yaml_id(tmpl.yaml)) if t}


def hit_reading(tmpl, project_id, host, match_ids):
    """``(stored, evidence)`` of the confirmation this template recorded on ``host``: whether a response was kept with it (on its finding or
    its validation step, ``templategen.stored_hit``), and ``templategen.hit_evidence`` of that response (None when none was kept)."""
    ids = template_ids(tmpl)
    hit = templategen.stored_hit(project_id, host, tmpl.cve_entry.cve_id, ids, match_ids)
    if hit is None:
        return False, None
    outcome = {"host": host, "vulnerable": True, "hit": {**hit, "template-id": _yaml_id(tmpl.yaml)}}
    return True, templategen.hit_evidence(tmpl.yaml, outcome)


def fixture_check(tmpl):
    """The template against its own fixture and the two pages nothing should match, offline (``templatefixture``): ``{source, vulnerable,
    not_affected, benign, not_found, error}``. ``vulnerable`` and ``not_affected`` are None when no fixture is stored."""
    out = {"source": None, "vulnerable": None, "not_affected": None, "benign": None, "not_found": None, "error": ""}
    if not tmpl.yaml:
        out["error"] = "no template text"
        return out
    fixture = tmpl.fixture if isinstance(tmpl.fixture, dict) else None
    out["source"] = "ai" if fixture else ("submitted" if isinstance(tmpl.submitted_fixture, dict) else None)
    fixture = fixture or (tmpl.submitted_fixture if isinstance(tmpl.submitted_fixture, dict) else None)
    try:
        if fixture:
            affected = templatefixture.clean_fixture(fixture.get("vulnerable"))
            fixed = templatefixture.clean_fixture(fixture.get("not_affected"))
            out["vulnerable"] = templatefixture.matches(tmpl.yaml, affected) if affected else None
            out["not_affected"] = templatefixture.matches(tmpl.yaml, fixed) if fixed else None
        out["benign"] = templatefixture.matches(tmpl.yaml, templatefixture.BENIGN)
        out["not_found"] = templatefixture.matches(tmpl.yaml, templatefixture.NOT_FOUND)
    except templatefixture.Unsupported as exc:
        out["error"] = f"a matcher cannot be evaluated offline ({exc})"
    except Exception as exc:  # noqa: BLE001 - a text the evaluator cannot read is reported, never raised
        out["error"] = f"the template could not be evaluated offline ({type(exc).__name__})"
    return out


def _generic_words(tmpl):
    """The bare server words (``templategen.GENERIC_WORDS``: Apache, nginx, ...) the template's word matchers rely on, when a word matcher
    holds nothing else."""
    try:
        doc = templategen.load_template(tmpl.yaml) or {}
    except Exception:  # noqa: BLE001
        return []
    if not isinstance(doc, dict):
        return []
    words = []
    for proto in templategen.PROTOCOL_SECTIONS:
        blocks = doc.get(proto)
        for block in blocks if isinstance(blocks, list) else []:
            for matcher in (block.get("matchers") or []) if isinstance(block, dict) else []:
                if isinstance(matcher, dict) and templategen._is_generic(matcher):
                    words += [str(w) for w in matcher.get("words") or []]
    return sorted(set(words), key=str.lower)


def report(tmpl, matches):
    """The review report of ``tmpl`` over ``matches`` (a CVEMatch queryset already cut down to what the caller may see): the gate, the
    evidence class, the fixture check, each stored confirmation read again and plain findings. Reads only; runs nothing on a host."""
    gate = static_gate(tmpl)
    evidence = evidence_of(tmpl)
    fixture = fixture_check(tmpl)
    hits = []
    groups = {}
    confirmed = matches.filter(template_result="vulnerable").order_by("id").values_list(
        "pk", "subdomain__name", "subdomain__target_domain__project_id", "subdomain__target_domain__project__slug")[:MAX_REPORT_HITS]
    for pk, host, project_id, slug in confirmed:
        groups.setdefault((project_id, slug, host), []).append(pk)
    for (project_id, slug, host), ids in groups.items():
        stored, reading = hit_reading(tmpl, project_id, host, ids)
        hits += [{"match_id": pk, "project": slug, "host": host, "stored_response": stored, "hit_evidence": reading,
                  "would_be": (templategen.VERSION_ONLY_RESULT if reading == templategen.VERSION_EVIDENCE else "vulnerable" if stored
                               else None)} for pk in ids]
    findings = []
    if not gate["ok"]:
        findings.append(f"fails the static safety gate: {gate['reason']}")
    if evidence == templategen.VERSION_EVIDENCE:
        findings.append("decides on the version string only: a hit reads the version again, which a distribution's backported fix does not "
                        "change, so it is no proof of the flaw")
    generic = _generic_words(tmpl)
    if generic:
        names = ", ".join(f'"{w}"' for w in generic)
        findings.append(f"its only product marker is {names}, a word every such server sends: it would run on, and match, any "
                        f"{generic[0]} server whose banner shows an affected version, patched or not")
    if fixture["benign"]:
        findings.append("matches the benign page, so it would flag hosts that are not affected")
    if fixture["not_found"]:
        findings.append("matches a 404 page, so it would flag hosts that are not affected")
    if fixture["vulnerable"] is False:
        findings.append("does not match the affected response of its own fixture")
    if fixture["not_affected"]:
        findings.append("also matches the fixed release's response of its own fixture")
    if fixture["source"] is None and tmpl.yaml:
        findings.append("has no stored fixture to test it against")
    if fixture["error"]:
        findings.append(fixture["error"])
    read_as_version = sum(1 for h in hits if h["hit_evidence"] == templategen.VERSION_EVIDENCE)
    if read_as_version:
        findings.append(f"{read_as_version} of its {len(hits)} confirmation(s) you can see only read the version string: read again today "
                        "they are version reads, not confirmations")
    unstored = sum(1 for h in hits if not h["stored_response"])
    if unstored:
        findings.append(f"{unstored} of its confirmation(s) you can see kept no response, so they cannot be read again; retiring the template "
                        "withdraws them")
    if not findings:
        findings.append("nothing found offline; this does not prove the check shows the flaw")
    return {"static_gate": gate, "evidence": evidence, "fixture_check": fixture, "hits": hits, "findings": findings}


def chain(tmpl):
    """Every row of ``tmpl``'s revision chain, oldest first: the rows it supersedes and the revisions of it, at most MAX_CHAIN."""
    from cveFeed.models import GeneratedTemplate
    root, seen = tmpl, {tmpl.pk}
    while root.supersedes_id and root.supersedes_id not in seen and len(seen) < MAX_CHAIN:
        seen.add(root.supersedes_id)
        parent = GeneratedTemplate.objects.filter(pk=root.supersedes_id).first()
        if parent is None:
            break
        root = parent
    rows, frontier, ids = [root], [root.pk], {root.pk}
    while frontier and len(rows) < MAX_CHAIN:
        found = list(GeneratedTemplate.objects.filter(supersedes_id__in=frontier).exclude(pk__in=ids).order_by("created_at", "id")
                     .select_related("revised_by")[:MAX_CHAIN - len(rows)])
        rows += found
        frontier = [r.pk for r in found]
        ids |= set(frontier)
    return sorted(rows, key=lambda r: (r.created_at, r.pk))


# ----------------------------------------------------------------------------- verdicts

def _clean_reason(reason, required):
    if reason is None:
        reason = ""
    if not isinstance(reason, str):
        raise ReviewRefused(400, "reason must be text")
    reason = " ".join(reason.split())
    if required and not reason:
        raise ReviewRefused(400, "give a reason: it is kept with the review and shown on the template")
    if len(reason) > MAX_REASON:
        raise ReviewRefused(400, f"reason must be at most {MAX_REASON} characters")
    return reason


def _name(actor):
    return getattr(actor, "username", "") or ""


def _record(tmpl, actor, verdict, reason, outcome):
    from cveFeed.models import GeneratedTemplateReview
    from tenancy import audit
    review = GeneratedTemplateReview.objects.create(template=tmpl, reviewer=actor if getattr(actor, "pk", None) else None,
                                                    reviewer_name=_name(actor)[:150], verdict=verdict, reason=reason, outcome=outcome)
    audit.record(actor if getattr(actor, "pk", None) else None, f"generated_template.{verdict}", tmpl.template_id or f"#{tmpl.pk}",
                 template=tmpl.pk, cve=tmpl.cve_entry.cve_id, reason=reason[:500], **{k: v for k, v in outcome.items() if k != "matches"})
    return review


def keep(tmpl, reason, actor):
    """Record that the template was looked at and stays as it is."""
    reason = _clean_reason(reason, required=False)
    return _record(tmpl, actor, "keep", reason, {"status": tmpl.status})


def withdraw_confirmations(tmpl):
    """Read again every confirmation ``tmpl`` recorded, in every project (it ran against every tenant's hosts): a hit whose kept response
    shows only the version string becomes ``version_only`` (``templategen.version_hit_corrected``), any other goes back to no template result
    (``templategen.retired_check_corrected``). Both close the finding the check filed (unless a person changed it) and start the triage over.
    The match's remediation status is never touched. Returns the counts and the match ids."""
    from cveFeed.models import CVEMatch
    counts = {"version_only": 0, "cleared": 0, "findings_closed": 0, "matches": []}
    groups = {}
    for pk, host, project_id in recorded_matches(tmpl).filter(template_result="vulnerable").values_list(
            "pk", "subdomain__name", "subdomain__target_domain__project_id"):
        groups.setdefault((project_id, host), []).append(pk)
    ids_of_template = template_ids(tmpl)
    cve = tmpl.cve_entry
    for (project_id, host), ids in sorted(groups.items(), key=lambda kv: (kv[0][0], kv[0][1] or "")):
        _stored, reading = hit_reading(tmpl, project_id, host, ids)
        moved = list(CVEMatch.objects.filter(pk__in=ids, template_result="vulnerable", template_id=tmpl.template_id).values_list("pk", flat=True))
        if not moved:
            continue
        if reading == templategen.VERSION_EVIDENCE:
            CVEMatch.objects.filter(pk__in=moved).update(template_result=templategen.VERSION_ONLY_RESULT)
            closed = templategen.version_hit_corrected(cve, host, project_id, ids_of_template, moved)
            counts["version_only"] += len(moved)
        else:
            CVEMatch.objects.filter(pk__in=moved).update(template_result="")
            closed = templategen.retired_check_corrected(cve, host, project_id, ids_of_template, moved)
            counts["cleared"] += len(moved)
        counts["findings_closed"] += len(closed)
        counts["matches"] += moved
    return counts


def retire(tmpl, reason, actor=None):
    """Retire ``tmpl``: ``invalid`` with the reason (never run again), then its confirmations are read again (``withdraw_confirmations``).
    ``actor`` None is the system (a valid revision superseded it). Returns the review row."""
    from cveFeed.models import GeneratedTemplate
    reason = _clean_reason(reason, required=True)
    now = timezone.now()
    who = _name(actor) or "the system"
    with transaction.atomic():
        row = GeneratedTemplate.objects.select_for_update().select_related("cve_entry").get(pk=tmpl.pk)
        before = row.status
        note = f"retired by {who}: {reason}"
        row.status, row.validation_reason, row.validated_at = GeneratedTemplate.STATUS_INVALID, note[:400], now
        row.validation_stage, row.validation_next_at = "", None
        row.validation_output = (row.validation_output + "\nreview: " + note).strip()[-6000:]
        row.save(update_fields=["status", "validation_reason", "validated_at", "validation_stage", "validation_next_at", "validation_output"])
    counts = withdraw_confirmations(row)
    activity.log("validate", f"The AI-written check {row.template_id or '#%d' % row.pk} for {row.cve_entry.cve_id} was retired by {who}: "
                             f"{reason[:200]}. It never runs again; {counts['version_only']} confirmation(s) are now version reads and "
                             f"{counts['cleared']} were withdrawn", cve_id=row.cve_entry.cve_id)
    tmpl.refresh_from_db()
    return _record(row, actor, "retire", reason, {"status_before": before, **counts})


# ----------------------------------------------------------------------------- revisions

def _next_revision_id(cve):
    """A free revision id for ``cve``: ``<cve id>-r<n>``, n past every revision already made, unused by any row and by any file."""
    from cveFeed.models import GeneratedTemplate
    base = cve.cve_id.lower()
    numbers = [int(t.rsplit("-r", 1)[1]) for t in GeneratedTemplate.objects.filter(cve_entry=cve, template_id__startswith=f"{base}-r")
               .values_list("template_id", flat=True) if templategen.revision_base(t) == base]
    number = max(numbers + [1]) + 1
    for _ in range(1000):
        candidate = templategen.revision_id(base, number)
        taken = GeneratedTemplate.objects.filter(template_id=candidate).exists() or \
            os.path.lexists(os.path.join(templategen.GENERATED_DIR, f"{candidate}.yaml"))
        if templategen.ID_RE.fullmatch(candidate) and not taken:
            return candidate
        number += 1
    raise ReviewRefused(409, "no free revision id is left for this CVE")


def _with_id(text, new_id):
    """``text`` with its top-level ``id`` set to ``new_id``, nothing else changed (checked by reading both)."""
    found = _ID_LINE.findall(text)
    if len(found) != 1:
        raise ReviewRefused(400, 'put the template id on one top-level line ("id: ..."); the revision is given an id of its own')
    revised = _ID_LINE.sub(f"id: {new_id}", text, count=1)
    try:
        before, after = templategen.load_template(text), templategen.load_template(revised)
    except Exception:  # noqa: BLE001 - the gate already read ``text``; this is belt and braces
        raise ReviewRefused(400, "the template could not be read again with its new id")
    rest = lambda doc: {k: v for k, v in doc.items() if k != "id"}  # noqa: E731
    if not isinstance(after, dict) or after.get("id") != new_id or rest(after) != rest(before):
        raise ReviewRefused(400, 'put the template id on one top-level line ("id: ..."); the revision is given an id of its own')
    return revised


def check_fixture(text, fixture):
    """A reviser's fixture, cleaned (``templatefixture.clean_fixture``) and checked offline the way the automatic fixture gate checks the AI's:
    the template must match the affected response and must not match the fixed one, the benign page or a 404. Raises ReviewRefused."""
    if not isinstance(fixture, dict):
        raise ReviewRefused(400, "fixture must be an object {vulnerable, not_affected}, each {status, headers, body}")
    affected = templatefixture.clean_fixture(fixture.get("vulnerable"))
    fixed = templatefixture.clean_fixture(fixture.get("not_affected"))
    if affected is None or fixed is None:
        raise ReviewRefused(400, "fixture must give both vulnerable and not_affected, each {status, headers, body}")
    try:
        hit = templatefixture.matches(text, affected)
        wrong = [name for name, response in (("the fixed response", fixed), ("a benign page", templatefixture.BENIGN),
                                             ("a 404 page", templatefixture.NOT_FOUND)) if templatefixture.matches(text, response)]
    except templatefixture.Unsupported as exc:
        raise ReviewRefused(400, f"the fixture cannot be checked: the template uses a matcher that cannot be tested offline ({exc})")
    if wrong:
        raise ReviewRefused(400, f"the template also matches {' and '.join(wrong)}, so it would flag hosts that are not affected")
    if not hit:
        raise ReviewRefused(400, "the template does not match the affected response of the fixture")
    return {"vulnerable": affected, "not_affected": fixed}


def revise(tmpl, text, reason, actor, fixture=None):
    """A new draft that supersedes ``tmpl``, with ``text`` (untrusted: size-capped, read only with ``safeyaml``, never run here). The static
    gate refuses it at once with its reason; otherwise the draft takes the automatic lifecycle (``templatevalidate``) like any AI draft and
    runs on no host before it is valid. Returns ``(revision, review)``."""
    from cveFeed.models import GeneratedTemplate
    reason = _clean_reason(reason, required=True)
    if not isinstance(text, str) or not text.strip():
        raise ReviewRefused(400, "yaml must be the template text")
    if len(text.encode("utf-8", "replace")) > templategen.MAX_TEMPLATE_BYTES:
        raise ReviewRefused(400, f"the template is larger than {templategen.MAX_TEMPLATE_BYTES} bytes")
    cve = tmpl.cve_entry
    ok, why = templategen.static_check(text, expected_cve_id=cve.cve_id)
    if not ok:
        raise ReviewRefused(400, f"static gate: {why}")
    with transaction.atomic():
        old = GeneratedTemplate.objects.select_for_update().select_related("cve_entry").get(pk=tmpl.pk)
        pending = old.revisions.filter(status__in=(GeneratedTemplate.STATUS_DRAFT, GeneratedTemplate.STATUS_VALID)).order_by("-id").first()
        if pending is not None:
            raise ReviewRefused(409, f"revision #{pending.pk} ({pending.template_id}, {pending.status}) already supersedes this template: "
                                     "revise that one instead")
        new_id = _next_revision_id(cve)
        revised = _with_id(text, new_id)
        ok, why = templategen.static_check(revised, expected_cve_id=cve.cve_id)
        if not ok:
            raise ReviewRefused(400, f"static gate: {why}")
        if old.yaml and _same_document(old.yaml, revised):
            raise ReviewRefused(400, "the revision is the same template as the one it would supersede")
        given = check_fixture(revised, fixture) if fixture is not None else None
        who = _name(actor) or "an agent"
        row = GeneratedTemplate.objects.create(
            cve_entry=cve, template_id=new_id, yaml=revised, status=GeneratedTemplate.STATUS_DRAFT, supersedes=old,
            revised_by=actor if getattr(actor, "pk", None) else None, revision_reason=reason, submitted_fixture=given,
            validation_output=f"revision of #{old.pk} ({old.template_id or 'no id'}) by {who}: {reason}"[:6000],
            validation_reason="waiting for automatic validation")
    review = _record(old, actor, "revise", reason, {"revision": row.pk, "revision_template_id": new_id, "fixture_given": given is not None})
    activity.log("write_check", f"{who} revised the AI-written check for {cve.cve_id}: the revision {new_id} is validated automatically "
                                "before it runs on any host", cve_id=cve.cve_id)
    return row, review


def _same_document(a, b):
    try:
        one, two = templategen.load_template(a), templategen.load_template(b)
    except Exception:  # noqa: BLE001
        return False
    if not (isinstance(one, dict) and isinstance(two, dict)):
        return False
    return {k: v for k, v in one.items() if k != "id"} == {k: v for k, v in two.items() if k != "id"}


def revision_promoted(revision):
    """``revision`` passed every gate (``templatevalidate.promote``): the row it supersedes is retired by the system, so its confirmations
    are read again and ``validation.resolve_template`` picks the revision."""
    from cveFeed.models import GeneratedTemplate
    old = GeneratedTemplate.objects.filter(pk=revision.supersedes_id).select_related("cve_entry").first()
    if old is None or old.status != GeneratedTemplate.STATUS_VALID:
        return None
    return retire(old, f"superseded by revision #{revision.pk} ({revision.template_id}), which passed every automatic gate", actor=None)
