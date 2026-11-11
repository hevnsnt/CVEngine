"""AI-written checks on the owner's own Sentinels: the rules that decide where a ``nuclei_validate`` task may go and what it may carry.

``nuclei_validate`` runs an AI-written draft (mode ``validate``: ``nuclei -validate`` and a benign loopback page it must not match, no host) or an
approved template against the hosts of one project (mode ``test``). ``path_probe`` measures the path a scanner's packets leave from. Both went only to
the built-in scanner (``sentinel_broker.BUILTIN_KINDS``): it is the server's own container, so running AI-written text there crossed no new trust
boundary, while a Sentinel is a machine on a customer network. That left an install that scans only with its own Sentinels with no AI-written checks
at all (review findings D8, C6). The kinds stay on the built-in scanner while it is in use (``builtin_in_use``); with none they go to the project's
own Sentinels whose contract version is at least ``external_since`` (``sentinel_contract.external_since``), under these rules:

- **Only what the server approved is sent** (``approval_problem``, applied by ``sentinel_dispatch`` before any task exists): a draft that passed the
  static gate (``templategen.static_check``); for a test, an unchanged valid generated template with a reviewed positive fixture or a read-only
  installed one (``cveFeed.validation.approved_template``'s rules; the all-templates setting counts for the built-in scanner only).
- **Read-only and the task's own target and port**, for anything a Sentinel other than the built-in scanner may run (``external_problem``): the
  server's read-only classification (``validation.readonly_problem``: GET, HEAD or OPTIONS, no body, payloads, fuzzing, raw socket data, code, file,
  browser, flow, workflow or out-of-band step, every destination a placeholder for the target) and ``validation.own_target_problem`` (no literal
  port, no ``port`` key). The Sentinel applies the same rules itself (``cvengine_scanner.checks``; one shared corpus is tested on both sides).
- **Bound by hash**: every task names ``template_sha256``, the sha256 of its text (``target``). The broker refuses to hand out a task whose text and
  hash disagree or that no longer passes (``task_refusal``); a Sentinel asks separately which hash the server approves for the task it holds
  (``sentinel_broker.approved_check``) and runs the text only when its own hash of the file it wrote agrees with both; its result must name the same
  hash (``result_problem``), or it is rejected and nothing of it is kept.
- **Scoped**: the task is filed under the hosts' own project and offered only to a Sentinel whose scope covers it (``SentinelEff.refusal``), never
  carries a stored sign-in, and its result keeps only the hosts it named, with a hit that names another host not counted
  (``sentinel_broker._bind_to_task``).
- **Bounded**: unchanged from the built-in scanner's run (at most 20,000 bytes for a draft, 200,000 for an installed template, 64 targets, nuclei at
  10 requests a second, no retries, no interactsh, no template update; the Sentinel's own time limits).
"""
import hashlib
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


def approval_problem(mode, text, builtin=True):
    """Why the server does not approve ``text`` for a check in ``mode``, or "". ``validate``: the static gate of a draft. ``test``: an approved
    generated template, else a read-only installed one, else (the built-in scanner only) any installed one when Settings allows every template."""
    from cveFeed import templategen, validation
    if mode not in MODES or not isinstance(text, str) or not text:
        return 'template not validated: not a check'
    if mode == 'validate':
        ok, why = templategen.static_check(text)
        return '' if ok else f'template not validated: {why}'
    if _approved_generated(text):
        return ''
    problem = validation.readonly_problem(text)
    if problem and builtin and validation.all_templates_allowed():
        return ''
    return problem


def validation_readonly(text):
    """Whether the server's read-only classification passes ``text`` (``validation.readonly_problem``)."""
    from cveFeed import validation
    return validation.readonly_problem(text) == ''


def external_problem(text):
    """Why ``text`` may not run on a Sentinel that is not the built-in scanner, or "": read-only, and only the task's own target and port."""
    from cveFeed import validation
    return validation.readonly_problem(text) or validation.own_target_problem(text)


def task_problem(task, builtin):
    """Why the ``nuclei_validate`` task ``task`` may not be handed to (or answered for) a Sentinel, or "": its target names a hash that matches its
    text, the server approves the text for its mode now, and, for a Sentinel other than the built-in scanner (``builtin`` false), it is read-only,
    keeps to its own target and port and names no stored sign-in. A task built by ``sentinel_dispatch`` passes; one changed after it was made does not."""
    body = task.target if isinstance(task.target, dict) else {}
    mode, text, sha = body.get('mode'), body.get('template'), body.get('template_sha256')
    if not isinstance(text, str) or not isinstance(sha, str) or not SHA256.match(sha) or digest(text) != sha:
        return 'the check does not match its template hash'
    problem = approval_problem(mode, text, builtin=builtin)
    if not problem and not builtin:
        problem = external_problem(text) or ('the check names a stored sign-in' if task.secret_ref else '')
    return problem


def result_problem(task, result, builtin):
    """Why a ``nuclei_validate`` result may not be kept, or "": it must name the hash of the check it was sent (``template_sha256``). The built-in
    scanner of an older image names none, and is believed as before; any hash that is named must be the task's."""
    sent = (task.target or {}).get('template_sha256') if isinstance(task.target, dict) else None
    echoed = result.get('template_sha256')
    if echoed is None and (builtin or sent is None):
        return ''
    if echoed != sent:
        return 'the result does not name the check it was sent (template_sha256)'
    return ''
