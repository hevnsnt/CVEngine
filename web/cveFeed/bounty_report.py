"""Turning a scanner finding into a bug bounty report a program can act on, and checking it before it leaves.

What a program asks for, from the platforms' own guidance:
  HackerOne ("Quality Reports"): a clear title, numbered steps to reproduce with URLs, parameters and roles, expected versus
    actual behaviour, the impact, and supporting material; check scope and duplicates first. The API requires team_handle, title,
    vulnerability_information and impact; severity_rating, weakness_id and structured_scope_id are optional.
  Bugcrowd ("Reporting a Bug"): summary title, target, technical severity (a VRT category), the URL or location, and a
    description with replication steps, risk and impact; attachments are optional; a submission cannot be edited after it is sent.
Everything here is a pure function over plain dicts, so it is tested without a database.

Nothing in a draft is invented. A field the finding cannot fill is left empty and shows up as a blocker or a warning; the person
decides what to write. A scanner hit is a lead, not a verified bug, so the checklist asks the person to confirm they reproduced it.
"""
import json
import os
import re

SEVERITY_NAMES = {0: "none", 1: "low", 2: "medium", 3: "high", 4: "critical"}
PLATFORM_SEVERITIES = ("none", "low", "medium", "high", "critical")
STATUSES = ("draft", "ready", "submitted", "triaged", "needs_info", "resolved", "duplicate", "informative", "not_applicable",
            "spam", "closed")
# Where a report may go next from a given state. A person moves a submitted report along as the program answers.
TRANSITIONS = {
    "draft": ("ready", "closed"),
    "ready": ("draft", "submitted", "closed"),
    "submitted": ("triaged", "needs_info", "resolved", "duplicate", "informative", "not_applicable", "spam", "closed"),
    "triaged": ("needs_info", "resolved", "duplicate", "informative", "not_applicable", "closed"),
    "needs_info": ("submitted", "triaged", "resolved", "duplicate", "informative", "not_applicable", "spam", "closed"),
    "resolved": ("closed",), "duplicate": ("closed",), "informative": ("closed",), "not_applicable": ("closed",),
    "spam": ("closed",), "closed": (),
}
CHECKLIST = (
    ("reproduced", "I reproduced this myself, by hand, and the steps below work."),
    ("policy_read", "I read the program's policy and this target and test are allowed."),
    ("minimal_access", "I touched no more data than the proof needs, and none of it belongs to other people."),
    ("redacted", "I removed other people's data and my own credentials from every attachment."),
    ("duplicate_checked", "I searched the program's disclosed reports for the same issue."),
)
FIELD_LIMITS = {"title": 300, "severity": 16, "cvss_vector": 120, "cwe": 200, "vrt": 200, "asset": 500, "location_url": 2000,
                "summary": 20000, "steps": 40000, "impact": 20000, "remediation": 20000, "references": 10000}
EVIDENCE_LIMIT = 24000
MIN_TITLE = 20


# --- taxonomy -----------------------------------------------------------------------------------

_VRT = None


def vrt():
    """The bundled Bugcrowd VRT (Apache-2.0): ``{"release_date", "entries": [[id, label, priority]]}``."""
    global _VRT
    if _VRT is None:
        with open(os.path.join(os.path.dirname(__file__), "data", "vrt.json"), encoding="utf-8") as fh:
            _VRT = json.load(fh)
        _VRT["by_id"] = {row[0]: row for row in _VRT["entries"]}
    return _VRT


def vrt_entry(vrt_id):
    row = vrt()["by_id"].get(str(vrt_id or ""))
    return {"id": row[0], "label": row[1], "priority": row[2]} if row else None


# Scanner tags and CWE numbers that map cleanly to a VRT entry. Anything not listed stays unsuggested rather than guessed.
VRT_BY_TAG = {
    "sqli": "server_side_injection.sql_injection", "rce": "server_side_injection.remote_code_execution_rce",
    "xxe": "server_side_injection.xml_external_entity_injection_xxe", "ssrf": "server_security_misconfiguration.server_side_request_forgery_ssrf",
    "xss": "cross_site_scripting_xss", "lfi": "server_security_misconfiguration.path_traversal",
    "traversal": "server_security_misconfiguration.path_traversal", "redirect": "unvalidated_redirects_and_forwards.open_redirect",
    "default-login": "server_security_misconfiguration.using_default_credentials", "takeover": "server_security_misconfiguration.misconfigured_dns.subdomain_takeover",
    "idor": "broken_access_control.idor", "exposure": "sensitive_data_exposure",
    "tech": "server_security_misconfiguration.fingerprinting_banner_disclosure",
}
VRT_BY_CWE = {
    "CWE-89": "server_side_injection.sql_injection", "CWE-78": "insecure_os_firmware.command_injection", "CWE-611": "server_side_injection.xml_external_entity_injection_xxe",
    "CWE-918": "server_security_misconfiguration.server_side_request_forgery_ssrf", "CWE-79": "cross_site_scripting_xss",
    "CWE-22": "server_security_misconfiguration.path_traversal", "CWE-601": "unvalidated_redirects_and_forwards.open_redirect",
    "CWE-798": "sensitive_data_exposure.sensitive_data_hardcoded", "CWE-639": "broken_access_control.idor",
    "CWE-1104": "using_components_with_known_vulnerabilities.outdated_software_version",
}


def suggest_vrt(tags=(), cwes=(), name=""):
    """A VRT id for the finding, or "". CWE wins over a tag; both must name an entry that exists in the bundled taxonomy."""
    for cwe in cwes:
        key = "CWE-" + re.sub(r"\D", "", str(cwe)) if re.search(r"\d", str(cwe)) else ""
        if VRT_BY_CWE.get(key) and vrt_entry(VRT_BY_CWE[key]):
            return VRT_BY_CWE[key]
    for tag in tags:
        if VRT_BY_TAG.get(str(tag).lower()) and vrt_entry(VRT_BY_TAG[str(tag).lower()]):
            return VRT_BY_TAG[str(tag).lower()]
    if re.search(r"outdated|end[- ]of[- ]life|eol", name or "", re.I):
        return "using_components_with_known_vulnerabilities.outdated_software_version"
    return ""


# --- redaction ----------------------------------------------------------------------------------

def _mask(value, keep=4):
    value = value.strip()
    return value[:keep] + f"[redacted {max(len(value) - keep, 0)} chars]" if len(value) > keep + 4 else "[redacted]"


_SECRET_PATTERNS = (
    # Header names are matched anywhere in a line: the same request shows up as raw HTTP and inside `curl -H '...'`.
    (re.compile(r"(?i)\b((?:proxy-)?authorization[ \t]*:[ \t]*(?:[A-Za-z][\w-]*[ \t]+)?)([^\s'\"]+)"), lambda m: m.group(1) + _mask(m.group(2))),
    (re.compile(r"(?i)\b((?:set-)?cookie\s*:\s*)([^\r\n'\"]+)"), lambda m: m.group(1) + re.sub(r"(=)([^;\s]{4,})", lambda c: c.group(1) + _mask(c.group(2)), m.group(2))),
    (re.compile(r"(?i)\b(x-[\w-]*(?:token|key|secret|auth)[\w-]*\s*:\s*)([^\s'\"\r\n]+)"), lambda m: m.group(1) + _mask(m.group(2))),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S), lambda m: "[private key removed]"),
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), lambda m: m.group(0)[:8] + "[redacted]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), lambda m: m.group(0)[:10] + "[redacted jwt]"),
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{10,}|AIza[0-9A-Za-z_-]{30,})\b"), lambda m: m.group(0)[:6] + "[redacted]"),
    (re.compile(r"(?i)(\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b[\"']?\s*[:=]\s*[\"']?)([^\s\"'&,;<>]{4,})"),
     lambda m: m.group(1) + _mask(m.group(2), 2)),
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]+:)([^/\s@]{3,})(@)"), lambda m: m.group(1) + "[redacted]" + m.group(3)),
)


def redact(text, limit=EVIDENCE_LIMIT):
    """``(text, count)``: credentials and tokens masked (a short prefix stays so the program can tell what leaked), capped in size.
    This is a safety net, not a guarantee; the checklist still asks the person to look at every attachment."""
    text = str(text or "")
    count = 0
    for pattern, repl in _SECRET_PATTERNS:
        text, n = pattern.subn(repl, text)
        count += n
    if len(text) > limit:
        text = text[:limit] + "\n[truncated]"
    return text, count


SECRET_LEFT = re.compile(r"(?i)(-----BEGIN [A-Z ]*PRIVATE KEY|\bAKIA[0-9A-Z]{16}\b|\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.|\bgh[pousr]_[A-Za-z0-9]{30,})")


# --- drafting -----------------------------------------------------------------------------------

def _clip(value, key):
    return str(value or "").strip()[:FIELD_LIMITS.get(key, 2000)]


def draft_from_vulnerability(vuln):
    """The report fields a scanner finding supports. ``vuln`` is a plain dict (see ``vuln_to_dict`` in bounty_api):
    name, severity (0-4), description, impact, remediation, http_url, curl_command, request, response, template_id, matcher_name,
    extracted_results, tags, references, cve_ids, cwe_ids, cvss_score, cvss_metrics, host. Returns the draft fields and a list of
    notes about what was left for the person to write."""
    notes = []
    url = _clip(vuln.get("http_url"), "location_url")
    host = _clip(vuln.get("host"), "asset")
    name = _clip(vuln.get("name"), "title")
    title = f"{name} on {host}" if name and host and host.lower() not in name.lower() else name
    steps = []
    curl, _ = redact(vuln.get("curl_command"), 4000)
    request, _ = redact(vuln.get("request"), 6000)
    response, _ = redact(vuln.get("response"), 8000)
    found = [str(x) for x in (vuln.get("extracted_results") or []) if str(x).strip()][:10]
    if curl.strip():
        steps.append("Send this request to the affected location:\n\n```\n" + curl.strip() + "\n```")
    elif request.strip():
        steps.append("Send this HTTP request to the affected location:\n\n```http\n" + request.strip() + "\n```")
    elif url:
        steps.append(f"Request `{url}`.")
    if found:
        steps.append("The scanner extracted:\n\n```\n" + redact("\n".join(found), 2000)[0] + "\n```")
    if vuln.get("template_id"):
        steps.append(f"Detected by scanner template `{str(vuln['template_id'])[:200]}`"
                     + (f", matcher `{str(vuln['matcher_name'])[:200]}`." if vuln.get("matcher_name") else "."))
    if not steps:
        notes.append("The finding carries no request, so the steps are empty.")
    steps_text = "\n\n".join(f"{i}. {s}" if "\n" not in s else f"{i}. {s.replace(chr(10), chr(10) + '   ')}" for i, s in enumerate(steps, 1))
    steps_text += ("\n\n" if steps_text else "") + "TODO: add what you observed and how someone else confirms it (expected versus actual behaviour)."
    cwes = [str(c) for c in (vuln.get("cwe_ids") or [])][:6]
    cves = [str(c) for c in (vuln.get("cve_ids") or [])][:6]
    refs = [str(r) for r in (vuln.get("references") or []) if re.match(r"^https?://", str(r))][:20]
    if cves:
        refs = [f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves if re.match(r"^CVE-\d{4}-\d{4,}$", c)] + refs
    evidence = {}
    if response.strip():
        evidence["response"] = response
    severity = SEVERITY_NAMES.get(vuln.get("severity"), "") if isinstance(vuln.get("severity"), int) else ""
    desc = _clip(vuln.get("description"), "summary")
    if not desc:
        notes.append("The finding has no description; write a summary.")
    impact = _clip(vuln.get("impact"), "impact")
    if not impact:
        notes.append("The scanner gave no impact. Say what an attacker gains here; a program will not guess it.")
    return {
        "title": title, "severity": severity, "cvss_score": vuln.get("cvss_score"), "cvss_vector": _clip(vuln.get("cvss_metrics"), "cvss_vector"),
        "cwe": ", ".join(cwes)[:200], "vrt": suggest_vrt(vuln.get("tags") or (), cwes, name), "asset": host, "location_url": url,
        "summary": desc, "steps": steps_text, "impact": impact, "remediation": _clip(vuln.get("remediation"), "remediation"),
        "references": "\n".join(dict.fromkeys(refs)), "evidence": evidence, "notes": notes,
    }


def clean_fields(data):
    """The editable report fields from a request body, trimmed to their limits. Unknown keys are dropped."""
    out = {}
    for key, limit in FIELD_LIMITS.items():
        if key in data:
            out[key] = str(data[key] if data[key] is not None else "").replace("\x00", "")[:limit]
    if "severity" in out and out["severity"] not in PLATFORM_SEVERITIES + ("",):
        raise ValueError("severity must be none, low, medium, high or critical")
    if "vrt" in out and out["vrt"] and not vrt_entry(out["vrt"]):
        raise ValueError("unknown VRT category")
    if "cvss_score" in data:
        value = data["cvss_score"]
        if value in (None, ""):
            out["cvss_score"] = None
        else:
            try:
                score = float(value)
            except (TypeError, ValueError):
                raise ValueError("cvss_score must be a number")
            if not 0 <= score <= 10:
                raise ValueError("cvss_score must be between 0 and 10")
            out["cvss_score"] = round(score, 1)
    if "checklist" in data:
        raw = data["checklist"] if isinstance(data["checklist"], dict) else {}
        out["checklist"] = {key: bool(raw.get(key)) for key, _ in CHECKLIST}
    return out


# --- checks -------------------------------------------------------------------------------------

GENERIC_TITLE = re.compile(r"^(?:xss|sqli|sql injection|rce|csrf|idor|ssrf|open redirect|vulnerability|bug|issue|security issue|\w{1,12})(?:\s+found)?(?:\s+in\s+(?:the\s+)?\w[\w .-]{0,24})?$", re.I)


def severity_for_score(score):
    """CVSS qualitative rating (FIRST): 0 none, 0.1-3.9 low, 4.0-6.9 medium, 7.0-8.9 high, 9.0-10 critical."""
    if score is None:
        return ""
    return "none" if score == 0 else "low" if score < 4 else "medium" if score < 7 else "high" if score < 9 else "critical"


def lint(report, verdict=None, program=None, duplicates=()):
    """Everything a reviewer would object to, as ``[{level, code, message}]``. Level ``block`` stops submission to a platform;
    ``warn`` is shown and does not. ``report`` is a dict of the report fields plus ``checklist``; ``verdict`` is a
    bounty_scope.Verdict (or its dict); ``program`` a dict with removed, state, offers_bounties, automated allowed; ``duplicates``
    the ids of this project's other reports on the same asset and title."""
    out = []

    def add(level, code, message):
        out.append({"level": level, "code": code, "message": message})

    title = (report.get("title") or "").strip()
    if len(title) < MIN_TITLE:
        add("block", "title_short", "The title is too short. Say the bug class, where it is and what it allows (\"Stored XSS in profile bio runs script for every visitor\").")
    elif GENERIC_TITLE.match(title):
        add("warn", "title_generic", "The title names only the bug class. Programs triage by title first; add the location and the effect.")
    steps = (report.get("steps") or "").strip()
    if not steps:
        add("block", "steps_missing", "No steps to reproduce. A program cannot validate what it cannot repeat.")
    elif "TODO" in steps:
        add("block", "steps_todo", "The steps still contain a TODO. Finish them or remove the line.")
    elif not re.search(r"(?m)^\s*\d+[.)]\s", steps):
        add("warn", "steps_unnumbered", "The steps are not numbered. Numbered steps are what both HackerOne and Bugcrowd ask for.")
    impact = (report.get("impact") or "").strip()
    if not impact:
        add("block", "impact_missing", "No impact. Say what an attacker gains, against whom, and what it takes.")
    elif len(impact) < 60:
        add("warn", "impact_thin", "The impact is a sentence. Describe the attacker, the victim and the damage.")
    if not (report.get("asset") or "").strip():
        add("block", "asset_missing", "No affected asset. Name the host or application the report is about.")
    if not (report.get("summary") or "").strip():
        add("warn", "summary_missing", "No summary. One short paragraph helps the person who triages many reports a day.")
    for field in ("title", "summary", "steps", "impact", "references"):
        if SECRET_LEFT.search(report.get(field) or ""):
            add("block", "secret_in_text", f"The {field} text still contains something that looks like a live credential or key. Mask it.")
            break
    evidence = report.get("evidence") or {}
    if any(SECRET_LEFT.search(str(v)) for v in evidence.values()):
        add("block", "secret_in_evidence", "An attachment still contains something that looks like a live credential or key. Mask it.")
    if not evidence and not re.search(r"```|https?://\S+\.(png|jpe?g|gif|mp4|webm)", steps, re.I):
        add("warn", "no_evidence", "No proof attached. A request and response, a screenshot or a short recording moves a report faster.")
    sev = (report.get("severity") or "").strip()
    score = report.get("cvss_score")
    if sev and score is not None and severity_for_score(score) and severity_for_score(score) != sev:
        add("warn", "severity_mismatch", f"Severity {sev} does not match CVSS {score} ({severity_for_score(score)}). Programs read an inflated rating as noise.")
    if not sev:
        add("warn", "severity_missing", "No severity. Pick the one your impact paragraph supports.")
    entry = vrt_entry(report.get("vrt")) if report.get("vrt") else None
    if entry and entry["priority"] == 5:
        add("warn", "vrt_p5", f"Bugcrowd's VRT rates \"{entry['label']}\" priority 5, its lowest. Many programs close this class as informational or exclude it; check the policy's exclusions before you send it.")
    if verdict is not None:
        v = verdict.as_dict() if hasattr(verdict, "as_dict") else dict(verdict)
        if v["state"] == "out_of_scope":
            add("block", "out_of_scope", f"Out of scope: {v['reason']}. Do not submit it.")
        elif v["state"] == "not_listed":
            add("block", "not_listed", f"Not in the program's scope: {v['reason']}.")
        elif v["state"] == "ambiguous":
            add("warn", "scope_ambiguous", f"Scope is not clear: {v['reason']}. Read the policy and, if in doubt, ask the program before you submit.")
    if program is not None:
        if program.get("removed"):
            add("block", "program_removed", "The platform no longer lists this program.")
        elif program.get("state") and str(program["state"]).lower() in ("soft_launched", "disabled", "paused", "closed"):
            add("warn", "program_state", f"The program's state is {program['state']}.")
        if program.get("offers_bounties") is False:
            add("info", "no_bounty", "This program does not pay. It is a disclosure program.")
        if not program.get("policy_ack"):
            add("block", "policy_unacknowledged", "Record that you read the program's policy on the engagement first.")
        elif program.get("scope_changed_since_ack"):
            add("warn", "scope_changed", "The program's scope changed after you acknowledged its policy. Read it again.")
        if not program.get("automated_ok"):
            add("warn", "automated_unconfirmed", "You did not confirm the policy allows automated scanning. Many programs forbid it; a report from a banned scan is refused.")
    checklist = report.get("checklist") or {}
    missing = [label for key, label in CHECKLIST if not checklist.get(key)]
    if missing:
        add("block", "checklist", f"{len(missing)} of {len(CHECKLIST)} checks are not ticked.")
    if duplicates:
        add("warn", "duplicate_local", f"Another report in this project covers the same asset with this title (#{', #'.join(str(d) for d in list(duplicates)[:3])}).")
    return out


def blockers(findings):
    return [f for f in findings if f["level"] == "block"]


# --- rendering ----------------------------------------------------------------------------------

def _section(title, body):
    body = (body or "").strip()
    return f"## {title}\n\n{body}\n" if body else ""


def to_markdown(report):
    """The report as Markdown, in the order both HackerOne and Bugcrowd ask for."""
    parts = [f"# {report.get('title', '').strip()}\n"]
    meta = []
    for label, key in (("Asset", "asset"), ("Location", "location_url"), ("Severity", "severity"), ("Weakness", "cwe")):
        if (report.get(key) or "").strip():
            meta.append(f"- **{label}:** {report[key].strip()}")
    if report.get("cvss_score") is not None:
        meta.append(f"- **CVSS:** {report['cvss_score']}" + (f" ({report['cvss_vector']})" if report.get("cvss_vector") else ""))
    if report.get("vrt") and vrt_entry(report["vrt"]):
        meta.append(f"- **VRT:** {vrt_entry(report['vrt'])['label']}")
    if meta:
        parts.append("\n".join(meta) + "\n")
    parts.append(_section("Summary", report.get("summary")))
    parts.append(_section("Steps to reproduce", report.get("steps")))
    ev = report.get("evidence") or {}
    if ev.get("response"):
        parts.append(_section("Evidence", "```http\n" + str(ev["response"]).strip() + "\n```"))
    parts.append(_section("Impact", report.get("impact")))
    parts.append(_section("Suggested fix", report.get("remediation")))
    if (report.get("references") or "").strip():
        parts.append(_section("References", "\n".join("- " + line.strip() for line in report["references"].splitlines() if line.strip())))
    return "\n".join(p for p in parts if p).strip() + "\n"


def hackerone_payload(report, team_handle):
    """The body of ``POST /v1/hackers/reports`` (required: team_handle, title, vulnerability_information, impact)."""
    body = to_markdown({**report, "title": "", "impact": ""}).lstrip("# \n")
    attrs = {"team_handle": team_handle, "title": report["title"].strip()[:300], "vulnerability_information": body.strip(),
             "impact": (report.get("impact") or "").strip()}
    if report.get("severity") in PLATFORM_SEVERITIES:
        attrs["severity_rating"] = report["severity"]
    return {"data": {"type": "report", "attributes": attrs}}


def platform_fields(report, platform):
    """Field-by-field text for pasting into a platform's own form, named as that platform names them."""
    entry = vrt_entry(report.get("vrt")) if report.get("vrt") else None
    if platform == "bugcrowd":
        return [("Summary title", report.get("title", "")), ("Target", report.get("asset", "")),
                ("Technical severity (VRT)", entry["label"] if entry else ""), ("URL / location of vulnerability", report.get("location_url", "")),
                ("Description", to_markdown({**report, "title": ""}).lstrip("# \n"))]
    return [("Title", report.get("title", "")), ("Asset", report.get("asset", "")), ("Severity", report.get("severity", "")),
            ("Description and steps", to_markdown({**report, "title": ""}).lstrip("# \n")), ("Impact", report.get("impact", ""))]
