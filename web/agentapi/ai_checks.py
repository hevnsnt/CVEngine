"""AI-written checks on the owner's own Sentinels: the rules that decide where a ``nuclei_validate`` task may go and what it may carry.

``nuclei_validate`` runs an AI-written draft (mode ``validate``: ``nuclei -validate`` and a benign loopback page it must not match, no host) or an
approved template against the hosts of one project (mode ``test``). ``path_probe`` measures the path a scanner's packets leave from. Both went only to
the built-in scanner (``sentinel_broker.BUILTIN_KINDS``): it is the server's own container, so running AI-written text there crossed no new trust
boundary, while a Sentinel is a machine on a customer network. That left an install that scans only with its own Sentinels with no AI-written checks
at all (review findings D8, C6). The kinds stay on the built-in scanner while it is in use (``builtin_in_use``); with none they go to the project's
own Sentinels whose contract version is at least ``external_since`` (``sentinel_contract.external_since``), under these rules:

- **Only what the server approved is sent** (``approval_problem``, applied by ``sentinel_dispatch`` before any task exists and again by the broker at
  hand-out and when the Sentinel asks). The two modes: ``validate`` is the AI validating its own draft before promotion (``nuclei -validate`` and a
  benign loopback page, no host); ``test`` runs an approved check against hosts. For a Sentinel that is not the built-in scanner (review D3) each
  is bound to an approval record of its exact text (so its exact sha256), looked up again every time, so a revoked one is never sent: ``validate``
  needs a ``GeneratedTemplate`` draft row holding exactly that text, a task filed under a project that owns a target matched to the draft's CVE (the
  tenant) and no targets; ``test`` needs a valid generated row with a reviewed positive fixture or an installed template file holding exactly
  that text (``validation.approved_template``), and every target a host of the task's own project. Arbitrary read-only text is never approved.
  On the built-in scanner (the server's own container) the gate is as before: the static gate for a draft, ``validation.approved_template``'s
  file rules for a test (the all-templates setting counts there only).
- **Read-only, the task's own target and port, and the allowlist**, for anything a Sentinel other than the built-in scanner may run
  (``external_problem``): the server's read-only classification (``validation.readonly_problem``: GET, HEAD or OPTIONS, no body, payloads, fuzzing,
  raw socket data, code, file, browser, flow, workflow or out-of-band step, every destination a placeholder for the target),
  ``validation.own_target_problem`` (no literal port, no ``port`` key) and the whole-document allowlist (``cveFeed.check_allowlist``: YAML that
  nuclei's parser reads alike, known keys only, only side-effect-free helpers in any expression, one plain request per raw block, no steering or
  credential header). The Sentinel applies the same rules itself (``cvengine_scanner.checks``; one shared corpus is tested on both sides).
- **Bound by hash**: every task names ``template_sha256``, the sha256 of its text (``target``). The broker refuses to hand out a task whose text and
  hash disagree or that no longer passes (``task_problem``); a Sentinel asks separately which hash, mode and sorted targets the server approves for
  the task it holds (``sentinel_broker.approved_check``) and runs the text only when its own hash of the file it wrote agrees with both and the
  targets are its task's; its result must name the same hash (``result_problem``), or it is rejected and nothing of it is kept. What the hash
  protects against (review D4): a check changed in transit, a task edited after dispatch (the server hashes its stored text again and checks the
  approval again before it answers), a file changed on disk on the Sentinel before the run. What it does not: a compromised server, which makes
  both the task and the answer; against that the Sentinel's own allowlist and target limit are the defence.
- **Scoped**: the task is filed under the hosts' own project and offered only to a Sentinel whose scope covers it (``SentinelEff.refusal``), never
  carries a stored sign-in, and its result keeps only the hosts it named, with a hit that names another host not counted
  (``sentinel_broker._bind_to_task``).
- **Bounded**: unchanged from the built-in scanner's run (at most 20,000 bytes for a draft, 200,000 for an installed template, 64 targets, nuclei at
  10 requests a second, no retries, no interactsh, no template update; the Sentinel's own time limits).
"""
import hashlib
import hmac
import re

KIND = 'nuclei_validate'
MODES = ('validate', 'test')
SHA256 = re.compile(r'^[0-9a-f]{64}$')
NOT_READ_ONLY = ('not tested: this check is not read-only, and only the built-in scanner may run such a check; this install scans with its own '
                 'Sentinels')


def digest(text):
    """The sha256 (lowercase hex) of ``text`` as UTF-8: what a task names as ``template_sha256`` and what the Sentinel computes from its file."""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def builtin_in_use():
    """Whether the install runs its built-in scanner: switched on (``CVENGINE_BUILTIN_SCANNER``) and enrolled. Then ``nuclei_validate`` and ``path_probe``
    stay on it, as before; with none they may go to the project's own Sentinels."""
    from agentapi import builtin_scanner, sentinel_broker
    return builtin_scanner.enabled() and sentinel_broker.builtin_pk() is not None


def offered_outside(kind, reported):
    """Whether a Sentinel that is not the built-in scanner and declared contract version ``reported`` may ever be offered ``kind`` (``external_since``)."""
    from agentapi import sentinel_contract
    since = sentinel_contract.external_since(kind)
    return since is not None and (1 if reported is None else reported) >= since


def target(mode, text, targets=None):
    """The ``nuclei_validate`` target for ``text``: its mode, the text and its hash, and for a test the targets."""
    out = {'mode': mode, 'template': text, 'template_sha256': digest(text)}
    if mode == 'test':
        out['targets'] = list(targets or [])
    return out


def _approved_generated(text):
    """Whether ``text`` is exactly an unchanged valid generated template with a reviewed positive fixture that passes the static gate again."""
    from cveFeed import templategen
    from cveFeed.models import GeneratedTemplate
    row = (GeneratedTemplate.objects.filter(yaml=text, status=GeneratedTemplate.STATUS_VALID, positive_fixture_verified_at__isnull=False)
           .exclude(positive_fixture_source='').select_related('cve_entry').first())
    return row is not None and templategen.static_check(text, expected_cve_id=row.cve_entry.cve_id)[0]


def approval_problem(mode, text, builtin=True, project=None, targets=None):
    """Why the server does not approve ``text`` for a check in ``mode``, or "".

    On the built-in scanner (``builtin``), as before: ``validate``, the static gate of a draft; ``test``, an approved generated template, else a
    read-only installed one, else any installed one when Settings allows every template (the text comes from ``validation.approved_template``).
    For a Sentinel that is not the built-in scanner: the content rules (``content_problem``) and then the approval record of exactly this text,
    bound to the task's tenant and targets (``binding_problem``)."""
    from cveFeed import templategen, validation
    if mode not in MODES or not isinstance(text, str) or not text:
        return 'template not validated: not a check'
    if not builtin:
        return content_problem(mode, text) or binding_problem(mode, text, project, targets)
    if mode == 'validate':
        ok, why = templategen.static_check(text)
        return '' if ok else f'template not validated: {why}'
    if _approved_generated(text):
        return ''
    problem = validation.readonly_problem(text)
    if problem and builtin and validation.all_templates_allowed():
        return ''
    return problem


def content_problem(mode, text):
    """Why the text of a check may not go to a Sentinel that is not the built-in scanner, whatever approved it: for a draft the static gate, then
    read-only (``NOT_READ_ONLY`` for a test template that is not), own target and port, and the allowlist (``external_problem``)."""
    from cveFeed import templategen
    if mode == 'validate':
        ok, why = templategen.static_check(text)
        if not ok:
            return f'template not validated: {why}'
    elif not validation_readonly(text):
        return NOT_READ_ONLY
    return external_problem(text)


def draft_rows(text):
    """The ``GeneratedTemplate`` draft rows that hold exactly ``text``: the AI's own drafts, before promotion."""
    from cveFeed.models import GeneratedTemplate
    return GeneratedTemplate.objects.filter(yaml=text, status=GeneratedTemplate.STATUS_DRAFT).select_related('cve_entry')


def draft_projects(text):
    """The ids of the projects that own a target matched to the CVE of a draft holding exactly ``text`` (the tenants a draft may be checked for),
    oldest first."""
    from cveFeed.models import CVEMatch
    cves = list(draft_rows(text).values_list('cve_entry_id', flat=True))
    if not cves:
        return []
    return sorted(set(CVEMatch.objects.filter(cve_entry_id__in=cves, subdomain__target_domain__project__isnull=False)
                      .values_list('subdomain__target_domain__project_id', flat=True)))


def _approved_installed(text):
    """Whether ``text`` is exactly an installed template file the server approves now (``validation.approved_template``), found by the CVE its id or
    classification names."""
    from cveFeed import templategen, validation
    from cveFeed.safeyaml import load_template
    try:
        doc = load_template(text)
    except Exception:  # noqa: BLE001 - any template that does not load is not an installed one
        return False
    if not isinstance(doc, dict):
        return False
    info = doc.get('info') if isinstance(doc.get('info'), dict) else {}
    classification = info.get('classification') if isinstance(info.get('classification'), dict) else {}
    named = [doc.get('id'), *(classification.get('cve-id') if isinstance(classification.get('cve-id'), list) else [classification.get('cve-id')])]
    cves = {m.upper() for value in named if isinstance(value, str) for m in re.findall(r'(?i)CVE-\d{4}-\d{4,7}', value)}
    for cve_id in sorted(cves):
        for path in templategen.find_existing_template(cve_id):
            approved, problem = validation.approved_template(path, cve_id)
            if not problem and approved == text:
                return True
    return False


def hosts_problem(project, targets):
    """Why ``targets`` are not all hosts of ``project`` (its targets and subdomains), or "": a test runs only on its own tenant's hosts."""
    from startScan.models import Subdomain
    from targetApp.models import Domain
    from agentapi.sentinel_broker import _bare
    if project is None or not isinstance(targets, list) or not targets or not all(isinstance(t, str) for t in targets):
        return 'not tested: the check names no hosts of a project'
    names = {_bare(t) for t in targets}
    if '' in names:
        return 'not tested: the check names a host it cannot read'
    known = {n.lower() for n in Subdomain.objects.filter(target_domain__project=project, name__in=list(names)).values_list('name', flat=True)}
    known |= {n.lower() for n in Domain.objects.filter(project=project, name__in=list(names)).values_list('name', flat=True)}
    missing = sorted(names - known)
    return f'not tested: {missing[0][:80]} is not a host of the project this check is filed under' if missing else ''


def binding_problem(mode, text, project, targets):
    """Why no approval record binds exactly ``text`` to this task (review D3), or "". ``validate``: a draft row holding exactly the text, filed under a
    project that owns a target matched to the draft's CVE, no targets. ``test``: a valid generated row with a reviewed positive fixture or an
    installed template file holding exactly the text, and every target a host of the task's project."""
    project_id = getattr(project, 'pk', project)
    if mode == 'validate':
        if targets:
            return 'template not validated: a draft check names no hosts'
        if not draft_rows(text).exists():
            return 'template not validated: no AI draft holds exactly this text (sha256), or it is no longer a draft'
        if project_id is None or project_id not in draft_projects(text):
            return 'template not validated: the draft is not for a target of the project this check is filed under'
        return ''
    if not (_approved_generated(text) or _approved_installed(text)):
        return 'template not validated: no approval holds exactly this text (sha256), or it was withdrawn'
    return hosts_problem(project, targets)


def same_hash(a, b):
    """Whether two sha256 hex strings are equal, compared in constant time (``hmac.compare_digest``)."""
    return isinstance(a, str) and isinstance(b, str) and a.isascii() and b.isascii() and hmac.compare_digest(a, b)


def validation_readonly(text):
    """Whether the server's read-only classification passes ``text`` (``validation.readonly_problem``)."""
    from cveFeed import validation
    return validation.readonly_problem(text) == ''


def external_problem(text):
    """Why ``text`` may not run on a Sentinel that is not the built-in scanner, or "": read-only, and only the task's own target and port."""
    from cveFeed import check_allowlist, validation
    return validation.readonly_problem(text) or validation.own_target_problem(text) or check_allowlist.allowlist_problem(text)


def task_problem(task, builtin):
    """Why the ``nuclei_validate`` task ``task`` may not be handed to (or answered for) a Sentinel, or "": its target names a hash that matches its
    text, the server approves the text for its mode now (for a Sentinel other than the built-in scanner, ``builtin`` false: the content rules and
    the approval record of exactly this text for this task's project and targets, looked up again now, so a withdrawn approval is never sent), and it
    names no stored sign-in. A task built by ``sentinel_dispatch`` passes; one changed after it was made, or whose approval was withdrawn, does not."""
    body = task.target if isinstance(task.target, dict) else {}
    mode, text, sha = body.get('mode'), body.get('template'), body.get('template_sha256')
    if not isinstance(text, str) or not isinstance(sha, str) or not SHA256.match(sha) or not same_hash(digest(text), sha):
        return 'the check does not match its template hash'
    problem = approval_problem(mode, text, builtin=builtin, project=task.project_id, targets=body.get('targets'))
    if not problem and not builtin:
        problem = 'the check names a stored sign-in' if task.secret_ref else ''
    return problem


def result_problem(task, result, builtin):
    """Why a ``nuclei_validate`` result may not be kept, or "": it must name the hash of the check it was sent (``template_sha256``). The built-in
    scanner of an older image names none, and is believed as before; any hash that is named must be the task's."""
    sent = (task.target or {}).get('template_sha256') if isinstance(task.target, dict) else None
    echoed = result.get('template_sha256')
    if echoed is None and (builtin or sent is None):
        return ''
    if not same_hash(echoed, sent):
        return 'the result does not name the check it was sent (template_sha256)'
    return ''
