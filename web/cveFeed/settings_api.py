"""Admin settings API behind the /cve/settings/ page.

Instance-wide configuration, so: superusers only (also enforced by the tenancy
middleware), session auth with CSRF, and deliberately NOT part of the agent
REST API or MCP. Secrets are write-only: responses say whether one is set,
never what it is, and an empty value on update keeps the stored one.
"""
import json
import re

import yaml
from django.http import JsonResponse

from dashboard.models import (AIProviderSettings, ChaosAPIKey, HackerOneAPIKey, NetlasAPIKey, OpenAiAPIKey)
from scanEngine.models import EngineType, Notification, Proxy, VulnerabilityReportSetting

MAX_YAML_BYTES = 100_000


class SettingsError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status, self.message = status, message


def _body(request):
    try:
        data = json.loads(request.body or b'{}')
    except json.JSONDecodeError:
        raise SettingsError(400, 'body must be valid JSON')
    if not isinstance(data, dict):
        raise SettingsError(400, 'body must be a JSON object')
    return data


def _text(data, key, current='', secret=False, max_len=500):
    """Return the new value for a text field; None/'' on a secret keeps ``current``."""
    if key not in data:
        return current
    value = data[key]
    if value is None:
        return current
    value = str(value).strip()
    if secret and value == '':
        return current
    if len(value) > max_len:
        raise SettingsError(400, f'{key} is too long')
    return value


# --- AI -----------------------------------------------------------------------

def ai_get(request):
    cfg = AIProviderSettings.objects.first() or AIProviderSettings()
    from reNgine.ai_providers import DEFAULT_MODELS, KEYLESS, SELECTABLE
    return {'provider': cfg.provider, 'model': cfg.model, 'base_url': cfg.base_url, 'enabled': cfg.enabled,
            'verified_at': cfg.verified_at.isoformat() if cfg.verified_at else None,
            'selectable': list(SELECTABLE), 'keyless': list(KEYLESS),
            'has_key': bool(cfg.api_key), 'auto_fire': cfg.auto_fire, 'auto_fire_engine_id': cfg.auto_fire_engine_id,
            'auto_fire_max_scans': cfg.auto_fire_max_scans, 'default_models': DEFAULT_MODELS,
            'providers': [p for p, _ in AIProviderSettings.PROVIDER_CHOICES]}


def ai_put(request):
    from reNgine.ai_providers import DEFAULT_MODELS
    data = _body(request)
    cfg = AIProviderSettings.objects.first() or AIProviderSettings()
    old_connection = (cfg.provider, cfg.model, cfg.base_url, cfg.api_key)
    provider = data.get('provider', cfg.provider)
    if provider not in DEFAULT_MODELS:
        raise SettingsError(400, 'unknown provider')
    cfg.provider = provider
    cfg.model = _text(data, 'model', cfg.model, max_len=200)
    cfg.base_url = _text(data, 'base_url', cfg.base_url)
    if cfg.base_url and not re.match(r'^https?://', cfg.base_url.strip(), re.I):
        raise SettingsError(400, 'the server URL must start with http:// or https://')
    if provider in ('ollama', 'vllm') and data.get('enabled') and not cfg.base_url.strip():
        raise SettingsError(400, f'{provider} needs the server address (a Tailscale or remote address, or http://localhost:11434 if it runs on this server)')
    cfg.api_key = _text(data, 'api_key', cfg.api_key, secret=True)
    if cfg.api_key == old_connection[3] and (cfg.provider, (cfg.base_url or '').strip()) != (old_connection[0], (old_connection[2] or '').strip()):
        cfg.api_key = ''  # a stored key is never sent to a different service or address: type it again for the new one
    if (cfg.provider, cfg.model, cfg.base_url, cfg.api_key) != old_connection:
        cfg.verified_at, cfg.verified_provider, cfg.verified_model = None, '', ''
    if 'enabled' in data:
        cfg.enabled = bool(data['enabled'])
    if 'auto_fire' in data:
        cfg.auto_fire = bool(data['auto_fire'])
    if 'auto_fire_engine_id' in data:
        engine = data['auto_fire_engine_id']
        if engine in (None, ''):
            cfg.auto_fire_engine_id = None
        elif EngineType.objects.filter(id=engine).exists():
            cfg.auto_fire_engine_id = int(engine)
        else:
            raise SettingsError(400, 'unknown scan engine')
    if 'auto_fire_max_scans' in data:
        try:
            cfg.auto_fire_max_scans = max(1, min(int(data['auto_fire_max_scans']), 5000))
        except (TypeError, ValueError):
            raise SettingsError(400, 'auto_fire_max_scans must be a number')
    cfg.save()
    return ai_get(request)


def ai_models(request):
    """The models the chosen provider offers, for the model picker. Uses the key typed in the form, else the stored
    one (only when the provider is unchanged, so a stored key is never sent to a different service)."""
    from reNgine.ai_providers import AIProviderError, SELECTABLE, get_provider, pick_cheapest_newest
    data = _body(request)
    cfg = AIProviderSettings.objects.first() or AIProviderSettings()
    provider = data.get('provider') or cfg.provider
    base_url = str(data.get('base_url') or '').strip() or (cfg.base_url if provider == cfg.provider else '')
    same_service = provider == cfg.provider and base_url.strip() == (cfg.base_url or '').strip()
    key = str(data.get('api_key') or '').strip() or (cfg.api_key if same_service else '')  # the stored key goes only where it was saved for
    try:
        listed = get_provider(provider, api_key=key or None, base_url=base_url or None).list_models()
    except AIProviderError as exc:
        raise SettingsError(400, f'could not list models: {exc}')
    recommended = '' if provider in SELECTABLE else (pick_cheapest_newest(listed) or '')
    return {'models': [{'id': m['id'], 'price': m['price']} for m in listed[:500]], 'recommended': recommended}


def ai_test(request):
    from reNgine.ai_providers import AIProviderError
    from reNgine.ai_settings import get_configured_provider
    cfg = AIProviderSettings.objects.first()
    if not cfg:
        raise SettingsError(400, 'save the AI settings first')
    try:
        from reNgine.ai_providers import get_provider
        provider = get_provider(cfg.provider, model=cfg.model or None, api_key=cfg.api_key or None,
                                base_url=cfg.base_url or None)
        from reNgine.ai_providers import usage_stage
        with usage_stage('connection_test'):
            reply = provider.complete('Reply with the single word: ok', 'ping')
    except AIProviderError as exc:
        cfg.verified_at, cfg.verified_provider, cfg.verified_model = None, '', ''
        cfg.save(update_fields=['verified_at', 'verified_provider', 'verified_model'])
        raise SettingsError(400, f'connection failed: {exc}')
    from django.utils import timezone
    cfg.verified_at, cfg.verified_provider, cfg.verified_model = timezone.now(), cfg.provider, provider.model
    cfg.save(update_fields=['verified_at', 'verified_provider', 'verified_model'])
    return {'ok': True, 'reply': reply[:80]}


def ai_usage_get(request):
    from cveFeed.ai_usage import snapshot
    days = request.GET.get('days', '7')
    if days not in ('1', '7', '30'):
        raise SettingsError(400, 'days must be 1, 7, or 30')
    return snapshot(int(days))


def ai_usage_rate_put(request):
    from cveFeed.ai_usage import set_rate
    return set_rate(_body(request))


# --- API vault ------------------------------------------------------------------

KEY_MODELS = {'openai': OpenAiAPIKey, 'netlas': NetlasAPIKey, 'chaos': ChaosAPIKey, 'hackerone': HackerOneAPIKey}


def keys_get(request):
    out = {name: {'has_key': model.objects.exclude(key='').exists()} for name, model in KEY_MODELS.items()}
    h1 = HackerOneAPIKey.objects.first()
    out['hackerone']['username'] = h1.username if h1 else ''
    return out


def keys_put(request):
    data = _body(request)
    for name, model in KEY_MODELS.items():
        if name not in data:
            continue
        entry = data[name] or {}
        if entry.get('clear'):
            model.objects.all().delete()
            continue
        row = model.objects.first() or model()
        row.key = _text(entry, 'key', row.key, secret=True)
        if name == 'hackerone':
            row.username = _text(entry, 'username', row.username)
        if row.key:
            row.save()
    return keys_get(request)


# --- notifications -----------------------------------------------------------------

NOTIFY_FLAGS = ('send_to_slack', 'send_to_lark', 'send_to_discord', 'send_to_telegram', 'send_scan_status_notif',
                'send_interesting_notif', 'send_vuln_notif', 'send_subdomain_changes_notif', 'send_scan_output_file',
                'send_scan_tracebacks')
NOTIFY_SECRETS = ('slack_hook_url', 'lark_hook_url', 'discord_hook_url', 'telegram_bot_token', 'telegram_bot_chat_id')


def notifications_get(request):
    row = Notification.objects.first() or Notification()
    out = {flag: bool(getattr(row, flag)) for flag in NOTIFY_FLAGS}
    out.update({f'has_{name}': bool(getattr(row, name)) for name in NOTIFY_SECRETS})
    return out


def notifications_put(request):
    data = _body(request)
    row = Notification.objects.first() or Notification()
    for flag in NOTIFY_FLAGS:
        if flag in data:
            setattr(row, flag, bool(data[flag]))
    for name in NOTIFY_SECRETS:
        if data.get(f'clear_{name}'):
            setattr(row, name, '')
        else:
            setattr(row, name, _text(data, name, getattr(row, name) or '', secret=True, max_len=200))
    row.save()
    return notifications_get(request)


# --- proxy -------------------------------------------------------------------------

def proxy_get(request):
    row = Proxy.objects.first() or Proxy()
    return {'use_proxy': bool(row.use_proxy), 'proxies': row.proxies or ''}


def proxy_put(request):
    data = _body(request)
    row = Proxy.objects.first() or Proxy()
    if 'use_proxy' in data:
        row.use_proxy = bool(data['use_proxy'])
    if 'proxies' in data:
        lines = [ln.strip() for ln in str(data['proxies']).splitlines() if ln.strip()]
        bad = [ln for ln in lines if not re.match(r'^(https?|socks[45]h?)://\S+$', ln)]
        if bad:
            raise SettingsError(400, f'not a proxy URL (http, https or socks): {bad[0][:60]}')
        row.proxies = '\n'.join(lines)
    row.save()
    return proxy_get(request)


# --- reports -----------------------------------------------------------------------

REPORT_TEXT = {'company_name': 100, 'company_address': 200, 'company_email': 100, 'company_website': 100,
               'footer_text': 200, 'executive_summary_description': 5000}
REPORT_FLAGS = {'show_executive_summary': 'show_executive_summary', 'show_footer': 'show_footer', 'show_banner': 'show_rengine_banner'}


def report_get(request):
    row = VulnerabilityReportSetting.objects.first() or VulnerabilityReportSetting()
    out = {k: getattr(row, k) or '' for k in REPORT_TEXT}
    out['primary_color'] = row.primary_color or '#FFB74D'
    out['secondary_color'] = row.secondary_color or '#212121'
    out.update({name: bool(getattr(row, field)) for name, field in REPORT_FLAGS.items()})
    return out


def report_put(request):
    data = _body(request)
    row = VulnerabilityReportSetting.objects.first() or VulnerabilityReportSetting()
    for key, limit in REPORT_TEXT.items():
        if key in data:
            value = str(data[key] or '')
            if len(value) > limit:
                raise SettingsError(400, f'{key.replace("_", " ")} is too long (at most {limit} characters)')
            setattr(row, key, value)
    for key in ('primary_color', 'secondary_color'):
        if key in data:
            if not re.fullmatch(r'#[0-9a-fA-F]{6}', str(data[key])):
                raise SettingsError(400, 'colours look like #FFB74D')
            setattr(row, key, data[key])
    for name, field in REPORT_FLAGS.items():
        if name in data:
            setattr(row, field, bool(data[name]))
    row.save()
    return report_get(request)


# --- scan engines ------------------------------------------------------------------

def _engine(e):
    return {'id': e.id, 'name': e.engine_name, 'default': bool(e.default_engine), 'yaml': e.yaml_configuration}


def engines_list(request):
    return {'results': [_engine(e) for e in EngineType.objects.order_by('engine_name')]}


def _valid_engine_yaml(text):
    if not text or len(text.encode()) > MAX_YAML_BYTES:
        raise SettingsError(400, 'engine YAML is empty or too large')
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SettingsError(400, f'invalid YAML: {str(exc)[:200]}')
    if not isinstance(doc, dict):
        raise SettingsError(400, 'engine YAML must be a mapping of tasks to settings')


def engines_create(request):
    data = _body(request)
    name = _text(data, 'name', max_len=200)
    if not name:
        raise SettingsError(400, 'name is required')
    text = data.get('yaml') or ''
    _valid_engine_yaml(text)
    return _engine(EngineType.objects.create(engine_name=name, yaml_configuration=text, default_engine=False)), 201


def engines_update(request, engine_id):
    engine = EngineType.objects.filter(id=engine_id).first()
    if not engine:
        raise SettingsError(404, 'engine not found')
    data = _body(request)
    if 'name' in data:
        engine.engine_name = _text(data, 'name', engine.engine_name, max_len=200) or engine.engine_name
    if 'yaml' in data:
        _valid_engine_yaml(data['yaml'])
        engine.yaml_configuration = data['yaml']
    engine.save()
    return _engine(engine)


def engines_delete(request, engine_id):
    from startScan.models import ScanHistory
    engine = EngineType.objects.filter(id=engine_id).first()
    if not engine:
        raise SettingsError(404, 'engine not found')
    # ScanHistory.scan_type cascades, so deleting a used engine would delete scan history
    if ScanHistory._base_manager.filter(scan_type=engine).exists():
        raise SettingsError(409, 'this engine has scans; deleting it would delete their history')
    if AIProviderSettings.objects.filter(auto_fire_engine_id=engine.id).exists():
        raise SettingsError(409, 'this engine is used by auto-fire')
    engine.delete()
    return {'deleted': True}


# --- ip allowlist ---------------------------------------------------------------

def _client_ip(request):
    from reNgine.client_ip import client_ip
    return client_ip(request)


def _valid_cidr(value):
    import ipaddress
    try:
        return str(ipaddress.ip_network((value or '').strip(), strict=False))
    except ValueError:
        raise SettingsError(400, f'not a valid IP or CIDR: {value!r}')


def _covers(ip_str, cidrs):
    import ipaddress
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def ip_allowlist_get(request):
    from dashboard.models import IpAccessControl, IpAllowlistEntry
    cfg = IpAccessControl.current()
    entries = IpAllowlistEntry.objects.order_by('id')
    return {'enabled': cfg.enabled, 'your_ip': _client_ip(request),
            'entries': [{'id': e.id, 'cidr': e.cidr, 'label': e.label, 'created_at': e.created_at} for e in entries]}


def ip_allowlist_put(request):
    from dashboard.models import IpAccessControl, IpAllowlistEntry
    from reNgine import ip_allowlist as ipa
    data = _body(request)
    cfg = IpAccessControl.current()
    if 'enabled' in data:
        want = bool(data['enabled'])
        if want:
            cidrs = list(IpAllowlistEntry.objects.values_list('cidr', flat=True))
            if not cidrs:
                raise SettingsError(400, 'add at least one allowed IP/CIDR before enabling')
            if not _covers(_client_ip(request), cidrs):
                raise SettingsError(400, f'your current IP ({_client_ip(request)}) is not on the allowlist; add it first or you will be locked out')
        cfg.enabled = want
        cfg.save()
        ipa.invalidate_cache()
    return ip_allowlist_get(request)


def ip_allowlist_entry_create(request):
    from dashboard.models import IpAllowlistEntry
    from reNgine import ip_allowlist as ipa
    data = _body(request)
    cidr = _valid_cidr(_text(data, 'cidr', max_len=64))
    label = _text(data, 'label', max_len=200)
    entry = IpAllowlistEntry.objects.create(cidr=cidr, label=label,
        created_by=request.user if request.user.is_authenticated else None)
    ipa.invalidate_cache()
    return {'id': entry.id, 'cidr': entry.cidr, 'label': entry.label, 'created_at': entry.created_at}, 201


def ip_allowlist_entry_delete(request, entry_id):
    from dashboard.models import IpAccessControl, IpAllowlistEntry
    from reNgine import ip_allowlist as ipa
    entry = IpAllowlistEntry.objects.filter(id=entry_id).first()
    if not entry:
        raise SettingsError(404, 'entry not found')
    cfg = IpAccessControl.current()
    if cfg.enabled:
        remaining = list(IpAllowlistEntry.objects.exclude(id=entry.id).values_list('cidr', flat=True))
        if not _covers(_client_ip(request), remaining):
            raise SettingsError(400, 'deleting this entry would lock your current IP out; disable the allowlist first')
    entry.delete()
    ipa.invalidate_cache()
    return {'deleted': True}


# --- resources -----------------------------------------------------------------------

def resources_get(request):
    from reNgine import resources
    return resources.cluster_snapshot()


# --- updates -------------------------------------------------------------------------

def _update_row():
    from cveFeed.models import UpdateSettings
    return UpdateSettings.current()


def updates_get(request):
    from cveFeed import updater
    return updater.state(_update_row())


def updates_put(request):
    from cveFeed import updater
    data = _body(request)
    row = _update_row()
    repo = str(data.get('repo', row.repo)).strip()
    branch = str(data.get('branch', row.branch)).strip()
    if not updater.valid_repo(repo):
        raise SettingsError(400, 'repository must look like owner/name')
    if not updater.valid_branch(branch):
        raise SettingsError(400, 'that is not a valid branch name')
    if (repo, branch) != (row.repo, row.branch):  # a different source: forget what the old one said
        row.latest_sha = row.latest_message = row.latest_url = row.dismissed_sha = ''
        row.behind_by, row.commits, row.latest_date = None, [], None
        updater.cancel_approval(row)
    row.repo, row.branch = repo, branch
    if 'mode' in data:
        from cveFeed.admin_api import audit
        mode = str(data['mode'])
        if mode not in updater.MODES:
            raise SettingsError(400, 'updates are installed manually or automatically')
        if mode != updater.read_mode():
            updater.set_mode(mode)
            audit(request.user, 'update.mode_changed', mode)
            if mode == 'manual' and row.approved_by == 'automatic':
                updater.cancel_approval(row)  # an approval nobody gave is withdrawn when the administrator takes control back
    row.token = _text(data, 'token', row.token, secret=True)
    if 'enabled' in data:
        row.enabled = bool(data['enabled'])
    row.save()
    return updater.state(row)


def updates_check(request):
    from cveFeed import updater
    row = _update_row()
    updater.check(row)
    if updater.auto_approve(row):
        from cveFeed.admin_api import audit
        audit(request.user, 'update.approved', row.latest_sha[:7], message=row.latest_message, behind_by=row.behind_by, mode='automatic')
    return updater.state(row)


def updates_approve(request):
    from cveFeed import updater
    from cveFeed.admin_api import audit
    row = _update_row()
    try:
        updater.approve(row, request.user)
    except updater.UpdateError as exc:
        raise SettingsError(400, str(exc))
    audit(request.user, 'update.approved', row.latest_sha[:7], message=row.latest_message, behind_by=row.behind_by)
    return updater.state(row)


def updates_cancel(request):
    from cveFeed import updater
    from cveFeed.admin_api import audit
    row = _update_row()
    updater.cancel_approval(row)
    audit(request.user, 'update.approval_cancelled', row.latest_sha[:7])
    return updater.state(row)


def updates_dismiss(request):
    from cveFeed import updater
    row = _update_row()
    updater.dismiss(row)
    return updater.state(row)


# --- factory reset ------------------------------------------------------------------

RESET_MAX_FAILURES = 5
RESET_LOCK_SECONDS = 600


def factory_reset_get(request):
    from cveFeed import factory_reset
    return {'phrase': factory_reset.CONFIRM_PHRASE, **factory_reset.plan(request.user)}


def factory_reset_post(request):
    """Wipe the instance back to a new install. Needs the exact phrase and the administrator's password (a few wrong
    passwords lock the button for ten minutes), and refuses while scans are running unless told to go ahead."""
    from cveFeed import factory_reset
    from tenancy import throttle
    data = _body(request)
    if data.get('confirm') != factory_reset.CONFIRM_PHRASE:
        raise SettingsError(400, f'type {factory_reset.CONFIRM_PHRASE} exactly to confirm')
    key = f'factory-reset-fail:{request.user.pk}'
    if throttle.exceeded(key, RESET_MAX_FAILURES):
        raise SettingsError(429, 'too many wrong passwords; try again in a few minutes')
    if not request.user.check_password(str(data.get('password') or '')):
        throttle.count(key, RESET_LOCK_SECONDS)
        raise SettingsError(403, 'that is not your password')
    running = factory_reset.running_scans()
    if running and not data.get('force'):
        raise SettingsError(409, f'{running} scan(s) are still running or queued; abort them first, or tick "reset anyway"')
    removed = factory_reset.reset(request.user, keep_session_key=request.session.session_key)
    return {'ok': True, 'removed': removed, 'redirect': '/cve/welcome/'}


# --- routing -----------------------------------------------------------------------

ROUTES = [
    ('GET', r'ai', lambda r, **k: ai_get(r)), ('PUT', r'ai', lambda r, **k: ai_put(r)),
    ('GET', r'ai/usage', lambda r, **k: ai_usage_get(r)),
    ('PUT', r'ai/usage/rate', lambda r, **k: ai_usage_rate_put(r)),
    ('POST', r'ai/test', lambda r, **k: ai_test(r)),
    ('POST', r'ai/models', lambda r, **k: ai_models(r)),
    ('GET', r'factory_reset', lambda r, **k: factory_reset_get(r)), ('POST', r'factory_reset', lambda r, **k: factory_reset_post(r)),
    ('GET', r'resources', lambda r, **k: resources_get(r)),
    ('GET', r'updates', lambda r, **k: updates_get(r)), ('PUT', r'updates', lambda r, **k: updates_put(r)),
    ('POST', r'updates/check', lambda r, **k: updates_check(r)), ('POST', r'updates/approve', lambda r, **k: updates_approve(r)),
    ('POST', r'updates/cancel', lambda r, **k: updates_cancel(r)), ('POST', r'updates/dismiss', lambda r, **k: updates_dismiss(r)),
    ('GET', r'keys', lambda r, **k: keys_get(r)), ('PUT', r'keys', lambda r, **k: keys_put(r)),
    ('GET', r'notifications', lambda r, **k: notifications_get(r)),
    ('PUT', r'notifications', lambda r, **k: notifications_put(r)),
    ('GET', r'proxy', lambda r, **k: proxy_get(r)), ('PUT', r'proxy', lambda r, **k: proxy_put(r)),
    ('GET', r'reports', lambda r, **k: report_get(r)), ('PUT', r'reports', lambda r, **k: report_put(r)),
    ('GET', r'engines', lambda r, **k: engines_list(r)), ('POST', r'engines', lambda r, **k: engines_create(r)),
    ('PUT', r'engines/(?P<engine_id>\d+)', lambda r, engine_id, **k: engines_update(r, int(engine_id))),
    ('DELETE', r'engines/(?P<engine_id>\d+)', lambda r, engine_id, **k: engines_delete(r, int(engine_id))),
    ('GET', r'ip_allowlist', lambda r, **k: ip_allowlist_get(r)), ('PUT', r'ip_allowlist', lambda r, **k: ip_allowlist_put(r)),
    ('POST', r'ip_allowlist/entries', lambda r, **k: ip_allowlist_entry_create(r)),
    ('DELETE', r'ip_allowlist/entries/(?P<entry_id>\d+)', lambda r, entry_id, **k: ip_allowlist_entry_delete(r, int(entry_id))),
]
COMPILED = [(m, re.compile(f'^{p}/?$'), fn) for m, p, fn in ROUTES]


def dispatch(request, path):
    if not (request.user.is_authenticated and request.user.is_superuser):
        return JsonResponse({'error': 'superuser only'}, status=403)
    path = path.strip('/')
    methods = []
    for method, regex, fn in COMPILED:
        match = regex.match(path)
        if not match:
            continue
        methods.append(method)
        if method != request.method:
            continue
        try:
            result = fn(request, **match.groupdict())
        except SettingsError as exc:
            return JsonResponse({'error': exc.message}, status=exc.status)
        data, status = result if isinstance(result, tuple) else (result, 200)
        return JsonResponse(data, status=status)
    if methods:
        return JsonResponse({'error': 'method not allowed'}, status=405)
    return JsonResponse({'error': 'not found'}, status=404)
