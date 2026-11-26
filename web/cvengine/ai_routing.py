"""Which model each AI stage runs on: the main model, or the bulk model.

The stages that run thousands of times a day on routine evidence (triage of a finding, the plan of a validation, a CVE's detection record, the
template tag choice, the finding reviewer) run on the bulk model, a cheaper model of the same provider. The stages that read a whole host or write
something a person keeps (the host review and its repair, the assessment review, an AI-written template, the local check suggestions) keep the
main model. ``STAGE_MODEL`` is the one table; a stage it does not name keeps the main model. docs/AI-REVIEWER.md lists the same table.

The bulk model is ``AIProviderSettings.bulk_model`` when an App Admin chose one on Settings > AI model, else the provider's cheapest current
model: ``pick_cheapest_newest`` of the provider's model list when one was read in this process (the Settings page reads it), else the profile's
own default (``claude-haiku-5-5`` for Anthropic, ``gpt-5.4-nano`` for OpenAI). A self-hosted server (vLLM, Ollama, LM Studio, OpenRouter) has no
default, so its bulk model is the main model unless one is chosen. ``AIProviderSettings.use_bulk_model`` (default on) switches the routing off:
every stage then uses the main model, as before. A model chosen for one job (the tag choice model, the finding reviewer's model) wins over the bulk
model, because it is the more specific choice.

The server sends no request here: the name goes into the job's options (``model``), which the reviewer container already obeys.
"""
import time

BULK, MAIN = 'bulk', 'main'

# stage (AIUsage.stage, AIJob.stage) -> which model. Keep docs/AI-REVIEWER.md "Which model each stage uses" in step.
STAGE_MODEL = {
    'finding_triage': BULK,
    'finding_triage_repair': BULK,
    'validation_plan': BULK,
    'cve_detection': BULK,
    'nuclei_targeting': BULK,
    'finding_review': BULK,
    'host_review': MAIN,
    'host_review_repair': MAIN,
    'assessment_review': MAIN,
    'template_generation': MAIN,
    'local_check_suggestion': MAIN,
}

LIST_TTL = 3600
_listed = {}  # (provider, base_url) -> (expires, cheapest model id or None), from a model list the Settings page read


def _key(name, base_url):
    return (str(name or ''), str(base_url or '').strip().rstrip('/').lower())


def remember(name, base_url, raw_models):
    """Keep the cheapest current model of a list that was just read (the Settings page reads one), and return it."""
    from cvengine.ai_providers import pick_cheapest_newest
    try:
        choice = pick_cheapest_newest([m for m in raw_models or [] if isinstance(m, dict)])
    except Exception:  # noqa: BLE001 - a list of an unexpected shape names no model
        choice = None
    _listed[_key(name, base_url)] = (time.time() + LIST_TTL, choice)
    return choice


def forget():
    _listed.clear()


def cheapest(row):
    """The provider's cheapest current model as known without a request: a list read in the last hour, else the profile's default, else ''."""
    from cvengine.ai_profiles import PROFILES
    cached = _listed.get(_key(row.provider, row.base_url))
    if cached and cached[0] > time.time() and cached[1]:
        return cached[1]
    profile = PROFILES.get(row.provider)
    return (profile.default_model if profile else '') or ''


def bulk_model(row):
    """The bulk model's name for the provider row ``row``: the chosen one, else the cheapest current model, else the main model."""
    if row is None:
        return ''
    return (getattr(row, 'bulk_model', '') or '').strip() or cheapest(row) or (row.model or '')


def routed(row):
    """Whether the high-volume stages run on the bulk model now."""
    return bool(row is not None and getattr(row, 'use_bulk_model', True))


def stage_kind(stage):
    return STAGE_MODEL.get(str(stage or ''), MAIN)


def model_for_stage(stage, row):
    """The model a stage's job is sent with, or '' for the main model (the job then carries no model and the container uses the configured
    one, exactly as before)."""
    if not routed(row) or stage_kind(stage) != BULK:
        return ''
    name = bulk_model(row)
    return '' if name == (row.model or '') else name
