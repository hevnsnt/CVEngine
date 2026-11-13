"""Every instance setting an App Admin can change in the web UI, for an agent: the same handlers, the same validation, the same audit trail.

cvENGINE is meant to be driven by agents as well as people (owner, 2026-11-09). The Settings and Administration pages are thin clients of two
route tables (``cveFeed.settings_api.ROUTES`` and ``cveFeed.admin_api.ROUTES``). This bridge calls those very handlers with a request built
from the MCP caller, so there is one definition of every limit, one place a secret is masked, and nothing to drift: a setting added to a
table without a line here fails ``tests.test_settings_bridge`` until it is exposed (or listed in ``NOT_EXPOSED`` with the reason).

Rules that hold for every entry:
- only an App Admin (settings tables) or an administrator (admin tables) may call it, exactly as in the UI;
- a change needs a token that is not read only (``require_write_token``);
- a secret is never returned: the handlers already answer with "saved: yes or no", and the test checks it.
"""
import json
import re

from django.test import RequestFactory

from agentapi.services import ApiError, require_write_token

# name: (api, method, route pattern as written in the table, what it is, what the path id means)
# The route pattern is matched literally against the table, so a renamed route fails the test instead of silently dropping out.
ENTRIES = {
    # --- settings tables (App Admin) -----------------------------------------------------------------------------------------------------------------
    'ai': ('settings', 'ai', 'The AI provider: which provider and model, whether it is on, the keys saved (never shown), prompts version.', None),
    'ai_usage': ('settings', 'ai/usage', 'AI model usage: calls, errors, tokens, cost where priced, rejected AI-written checks.', None),
    'ai_usage_rate': ('settings', 'ai/usage/rate', 'The price of one model (so cost can be shown). Change only.', None),
    'ai_test': ('settings', 'ai/test', 'Test the AI connection with one small call. Action.', None),
    'ai_models': ('settings', 'ai/models', 'List the models the provider offers for the key saved. Action.', None),
    'reviewer': ('settings', 'reviewer', 'The AI reviewer of AI-written checks: its model and whether it is on.', None),
    'scan_policy': ('settings', 'scan_policy', 'What the scanners may run (every template check, or only read-only ones) and whether checks that send credentials (default logins) may run (off by default).', None),
    'scan_concurrency': ('settings', 'scan_concurrency', 'How many scans and assessments run at once.', None),
    'tunables': ('settings', 'tunables', 'The throughput settings (the ones auto-tuning manages), with the pinned value of each.', None),
    'autotune': ('settings', 'autotune', 'Auto-tuning: mode and advisor. (Also set_tuning_mode.)', None),
    'updates': ('settings', 'updates', 'Update settings: automatic or manual, the channel, the update window, the Sentinel update choice.', None),
    'updates_check': ('settings', 'updates/check', 'Check for a new version now. Action.', None),
    'updates_approve': ('settings', 'updates/approve', 'Approve the waiting update: this is the Update button. The server shows its maintenance page and restarts. Action.', None),
    'updates_cancel': ('settings', 'updates/cancel', 'Cancel an update that has not started. Action.', None),
    'updates_dismiss': ('settings', 'updates/dismiss', 'Dismiss the update notice. Action.', None),
    'scanner_plan': ('settings', 'scanner_plan', 'Where scanning runs: Sentinels of your own only, or also the built-in scanner. Change applies on the next update step.', None),
    'keys': ('settings', 'keys', 'The service keys saved (CVE sources, OpenAI, Anthropic, and so on): which are saved, never their values.', None),
    'notifications': ('settings', 'notifications', 'Where notifications go (webhook and chat targets) and which events.', None),
    'email': ('settings', 'email', 'Outgoing mail (SMTP): host, port, sender, whether a password is saved (never shown).', None),
    'email_test': ('settings', 'email/test', 'Send one test mail to the address given. Action.', None),
    'proxy': ('settings', 'proxy', 'The outgoing proxy for the server.', None),
    'reports': ('settings', 'reports', 'Report settings (branding, footer).', None),
    'openvas': ('settings', 'openvas', 'The OpenVAS add-on: on or off and its limits.', None),
    'openvas_project': ('settings', 'openvas/projects/(?P<project_id>\\d+)', 'OpenVAS for one project. The id is the project id.', 'project_id'),
    'openvas_queue': ('settings', 'openvas/projects/(?P<project_id>\\d+)/queue', 'What OpenVAS has queued for one project. The id is the project id.', 'project_id'),
    'ip_allowlist': ('settings', 'ip_allowlist', 'The allowed source addresses for the whole web interface and whether the allowlist is enforced.', None),
    'ip_allowlist_entry_add': ('settings', 'ip_allowlist/entries', 'Add an address or range to the allowlist. Action.', None),
    'ip_allowlist_entry': ('settings', 'ip_allowlist/entries/(?P<entry_id>\\d+)', 'One allowlist entry. The id is the entry id.', 'entry_id'),
    'tailscale': ('settings', 'tailscale', 'Tailscale sync per project: which are connected (never the key).', None),
    'tailscale_project': ('settings', 'tailscale/(?P<project_id>\\d+)', 'Tailscale sync for one project. The id is the project id.', 'project_id'),
    'tailscale_test': ('settings', 'tailscale/(?P<project_id>\\d+)/test', 'Test the Tailscale connection of one project. Action.', 'project_id'),
    'tailscale_sync': ('settings', 'tailscale/(?P<project_id>\\d+)/sync', 'Sync one project\'s Tailscale devices now. Action.', 'project_id'),
    'alerts': ('settings', 'alerts', 'The notices the server is showing (cvENGINE reports problems).', None),
    'alert_dismiss': ('settings', 'alerts/(?P<alert_id>\\d{1,12})/dismiss', 'Dismiss one notice. The id is the notice id. Action.', 'alert_id'),
    'resources': ('settings', 'resources', 'CPU, memory and disk of this server and what the settings are sized for.', None),
    'config_maxxing': ('settings', 'config_maxxing', 'The throughput settings sized for this server (configMaxxing), with their measured state.', None),
    'config_maxxing_reset': ('settings', 'config_maxxing/reset', 'Return every throughput setting to the size the server suggests. Action.', None),
    'cve_seed': ('settings', 'cve_seed', 'The CVE seed export: whether one exists and when it was built.', None),
    'cve_seed_build': ('settings', 'cve_seed/build', 'Build a CVE seed export. Action.', None),
    'cve_guidance_run': ('settings', 'cve_guidance/run', 'Run the CVE guidance job now. Action.', None),
    # --- admin tables (administrators; the instance ones need an App Admin) -----------------------------------------------------------------------------
    'timings': ('admin', 'timings', 'Timings: CVE feed interval, daily hygiene hour (UTC), certificate transparency interval, discovery and template-scan run limits.', None),
    'scan_control': ('admin', 'scan-control', 'The scanning pause (and its reason).', None),
    'watchdog': ('admin', 'watchdog', 'The watchdog: what it watches, what it changed, its switches. A POST changes a switch or asks for an action.', None),
    'audit': ('admin', 'audit', 'The audit log of administrative changes (last 200).', None),
    'activity': ('admin', 'activity', 'Retained activity and errors (paged; page and page_size in the query).', None),
    'health': ('admin', 'health', 'Scheduler detail.', None),
    'org_api_keys': ('admin', 'orgs/(?P<org_id>\\d+)/api-keys', 'The API keys saved for one organization (never their values). The id is the organization id.', 'org_id'),
    'org_api_key': ('admin', 'orgs/(?P<org_id>\\d+)/api-keys/(?P<service>[-\\w]+)', 'One organization API key. The id is "org_id/service", for example "3/shodan".', 'org_id/service'),
    'org_excluded_addresses': ('admin', 'orgs/(?P<org_id>\\d+)/excluded-addresses', 'The organization\'s "do not scan these addresses" list. The id is the organization id.', 'org_id'),
    'org_excluded_address': ('admin', 'orgs/(?P<org_id>\\d+)/excluded-addresses/(?P<entry_id>\\d+)', 'One excluded address. The id is "org_id/entry_id".', 'org_id/entry_id'),
}

# Routes that are in the tables on purpose without a tool. Each carries the reason; a new route with no entry and no reason fails the test.
NOT_EXPOSED = {
    ('settings', 'factory_reset'): 'destroys the instance; not something an agent should be able to do on one call. A person does it in the UI.',
    ('settings', 'egress/connections\\.csv'): 'a CSV download; list_egress_connections returns the same data.',
    ('settings', 'cve_seed/import'): 'uploads a file; it needs a person at the browser.',
    ('settings', 'cve_seed/download/(?P<which>seed|manifest)'): 'a file download.',
    ('settings', 'autotune/decisions'): 'list_tuning_decisions.',
    ('settings', 'autotune/decisions/(?P<decision_id>\\d+)/apply'): 'apply_tuning_suggestion.',
    ('settings', 'autotune/decisions/(?P<decision_id>\\d+)/revert'): 'revert_tuning_decision.',
    ('settings', 'autotune/release'): 'release_tuning_pin.',
}
# Entries an agent may read but not change. The allowlist is the perimeter: its handlers refuse a change that would lock the caller out by looking at the
# caller's address, and an agent has no address of its own (the bridge's request is built here), so it must not be able to move the perimeter at all.
# A person does it in the web interface, where the guard sees the real address.
READ_ONLY_FOR_AGENTS = {
    'ip_allowlist': 'the allowed addresses are the perimeter of the instance; an agent can read the list, a person changes it in the web interface.',
    'ip_allowlist_entry_add': 'the allowed addresses are the perimeter of the instance; a person changes them in the web interface.',
    'ip_allowlist_entry': 'the allowed addresses are the perimeter of the instance; a person changes them in the web interface.',
    'updates_approve': 'approving an update restarts the whole instance; an agent may check for one and read its state, a person presses the button.',
}
# What the handlers see as the caller's address. Not a loopback address: nothing that trusts the caller's address may take the bridge for the local machine.
BRIDGE_ADDRESS = ''
# Owner rule: no check that sends credentials runs unless a person turned it on. An agent may switch such a setting off and read it, never switch it on: a
# person does that in the web interface. {setting name: the fields of its body an agent may not set to true}
# The same rule for everything that costs money or widens what is scanned (owner rule, WP4: an agent can lower such a thing, never switch it on).
AGENT_CANNOT_ENABLE = {'scan_policy': ('allow_credential_checks', 'nuclei_all_templates'), 'ai': ('enabled', 'auto_fire'), 'reviewer': ('enabled',),
                       'openvas': ('enabled',), 'openvas_project': ('enabled',), 'tailscale_project': ('enabled', 'auto_scan', 'use_local')}
# A value an agent may not send for an entry: {entry: {field: the values refused}}. Automatic updates install without a person pressing the button; the
# two scanner plans that keep the built-in scanner running spend the host's memory.
AGENT_CANNOT_SET = {'updates': {'mode': ('automatic',)}, 'scanner_plan': {'plan': ('internal', 'both')}}
# Numbers of an entry's body that cost money or work: an agent may only lower them. {entry: {field: how the current number is read}}
AGENT_LOWER_ONLY = {'ai': ('plan_daily_total', 'plan_daily_per_project', 'cve_guidance_daily', 'auto_fire_max_scans'), 'reviewer': ('review_daily_max',)}
# Tunables an agent may only lower: every cap (``caution='cap'``, which includes each AI spend cap) and the two switches that widen what is scanned or sent.
# ``validate_min_gap_hours`` is the other way round (a shorter gap spends more), so an agent may only raise it. A cap of 0 turns the pacing off: more, not less.
TUNABLE_ONLY_RAISE = ('validate_min_gap_hours',)
TUNABLE_SWITCHES = ('planner_enabled', 'sentinel_bbot_keys')
TUNABLE_ZERO_IS_UNLIMITED = ('egress_port25_per_hour',)
WRITE_METHODS = ('PUT', 'PATCH', 'POST')
NOT_EXPOSED[('admin', 'openvas')] = 'the same add-on settings as the openvas entry (settings table).'
IDENTITY_ROUTES_NOT_YET = ('users', 'memberships', 'orgs', 'projects')  # people, roles and organizations: a separate slice, owner to say how far an agent may go


def _tables():
    from cveFeed import admin_api, settings_api
    return {'settings': settings_api.ROUTES, 'admin': admin_api.ROUTES}


def _find(api, pattern, method):
    for m, p, fn in _tables()[api]:
        if p == pattern and m == method:
            return fn
    return None


def _methods(api, pattern):
    return [m for m, p, _ in _tables()[api] if p == pattern]


def catalogue():
    out = []
    for name, (api, pattern, text, ident) in ENTRIES.items():
        methods = _methods(api, pattern)
        out.append({'name': name, 'what': text, 'id': ident, 'read': 'GET' in methods,
                    'change': name not in READ_ONLY_FOR_AGENTS and next((m for m in methods if m in WRITE_METHODS), None) is not None,
                    'remove': name not in READ_ONLY_FOR_AGENTS and 'DELETE' in methods})
    return out


def _admin_gate(ctx, api):
    from tenancy import roles
    if api == 'settings':
        if not (ctx.user.is_authenticated and ctx.user.is_superuser):
            raise ApiError(403, 'App Admin only')
    elif not (ctx.user.is_authenticated and roles.is_admin_anywhere(ctx.user)):
        raise ApiError(403, 'administrators only')


def _groups(pattern, ident):
    """Turn the single id the caller sends ("3/shodan") into the named groups the route pattern wants."""
    names = re.findall(r'\(\?P<(\w+)>', pattern)
    if not names:
        return {}
    parts = [p for p in str(ident or '').split('/') if p != '']
    if len(parts) != len(names):
        raise ApiError(400, f'send id as {"/".join(names)}')
    return dict(zip(names, parts))


def _path_for(pattern, groups):
    path = pattern
    for key, value in groups.items():
        path = re.sub(r'\(\?P<%s>[^)]*\)' % key, str(value), path, count=1)
        if not re.fullmatch(r'[-\w]{1,64}', str(value)):
            raise ApiError(400, f'{key} is not valid')
    return path


def _call(ctx, name, method, values=None, ident=None, query=None):
    entry = ENTRIES.get(name)
    if not entry:
        raise ApiError(404, f'no setting called {name}; see list_settings')
    api, pattern, _text, _ident = entry
    _admin_gate(ctx, api)
    fn = _find(api, pattern, method)
    if fn is None:
        raise ApiError(405, f'{name} does not take {method}')
    if method != 'GET':
        require_write_token(ctx)
        if name in READ_ONLY_FOR_AGENTS:
            raise ApiError(403, f'{name} is not available to agents: {READ_ONLY_FOR_AGENTS[name]}')
    if method != 'GET' and isinstance(values, dict):
        for field in AGENT_CANNOT_ENABLE.get(name, ()):
            if values.get(field) not in (None, False):  # anything but off: a string or a number is refused by the handler, and must not slip past here
                raise ApiError(403, f'{field} can only be switched on by a person in the web interface; an agent may switch it off')
    if method != 'GET' and isinstance(values, dict):
        _agent_body_rules(ctx, name, values)
    groups = _groups(pattern, ident)
    path = '/cve/api/%s/%s/' % (api, _path_for(pattern, groups))
    factory = RequestFactory(REMOTE_ADDR=BRIDGE_ADDRESS)
    if method == 'GET':
        request = factory.get(path, {k: str(v) for k, v in (query or {}).items()})
    else:
        body = json.dumps(values if values is not None else {})
        request = factory.generic(method, path, body, content_type='application/json')
    request.user = ctx.user
    if method == 'PUT' and name in ('scan_concurrency', 'tunables') and isinstance(values, dict) and isinstance(values.get('values'), dict) and values['values']:
        return _throughput_write(ctx, name, method, fn, request, values, groups)
    return _run(ctx, name, api, fn, request, groups)


def _run(ctx, name, api, fn, request, groups):
    from cveFeed import admin_api, settings_api
    error_types = (settings_api.SettingsError, admin_api.AdminError)
    try:
        result = fn(request, **groups) if api == 'settings' else fn(request, ctx.user, **groups)
    except error_types as exc:
        raise ApiError(exc.status, exc.message)
    if hasattr(result, 'status_code') and hasattr(result, 'content'):
        raise ApiError(400, f'{name} is a download; use the web interface')
    data, status = result if isinstance(result, tuple) else (result, 200)
    return data if status < 400 else {'error': data, 'status': status}


def _current_body_number(name, field):
    """The number an entry's body field holds now (for the lower-only rule)."""
    if name == 'ai':
        from dashboard.models import AIProviderSettings
        row = AIProviderSettings.objects.first()
        return getattr(row, field, None) if row is not None else None
    from cveFeed import reviewer
    return getattr(reviewer.settings_row(), field, None)


def _agent_body_rules(ctx, name, values):
    """What an agent may not send, checked before anything is written (a person's own writes, in the web interface, never come here)."""
    for field, refused in AGENT_CANNOT_SET.get(name, {}).items():
        if values.get(field) in refused:
            raise ApiError(403, f'{field} {values.get(field)!r} can only be chosen by a person in the web interface; an agent may choose the other way')
    if name == 'autotune' and 'agent_policy' in values:
        raise ApiError(403, 'what agents may do to the throughput settings is a person\'s decision: change it in Settings, Auto-tuning')
    for field in AGENT_LOWER_ONLY.get(name, ()):
        if field not in values:
            continue
        new, now = values[field], _current_body_number(name, field)
        if isinstance(new, bool) or not isinstance(new, int) or (isinstance(now, int) and new > now):
            raise ApiError(403, f'{field} is a limit on what this instance spends: an agent may only lower it (now {now}); a person raises it in the web interface')


def _tunable_rules(values):
    """The lower-only rules for the tunables of one write (see ``TUNABLE_*``); raises 403 for the first number that would raise one."""
    from cveFeed import tunables
    for key, new in values.items():
        t = tunables.BY_KEY.get(key)
        if t is None:
            continue
        now = tunables.value(key)
        if key in TUNABLE_ONLY_RAISE:
            if new is None or (isinstance(new, int) and not isinstance(new, bool) and new < now):
                raise ApiError(403, f'{t.label}: a shorter gap spends more, so an agent may only lengthen it (now {now}); a person shortens it in the web interface')
            continue
        if not (t.caution == 'cap' or key in TUNABLE_SWITCHES):
            continue
        number = tunables.resolve(key, {})['value'] if new is None else new
        if isinstance(number, bool) or not isinstance(number, (int, float)):
            continue  # the handler refuses a value that is not a number
        def reach(n):  # a cap of 0 on these keys means no cap
            return float('inf') if key in TUNABLE_ZERO_IS_UNLIMITED and n == 0 else n
        if reach(number) > reach(now):
            raise ApiError(403, f'{t.label} is a limit on cost or scope: an agent may only lower it (now {now}); a person raises it in the web interface')


def _throughput_write(ctx, name, method, fn, request, values, groups):
    """AM-3: the keys auto-tune manages go to the engine (``autotune.agent_change``); everything else of the same write goes to the page's handler.
    The reply is the page's own answer plus ``agent_changes`` (one result per managed key) and ``agent_summary`` in plain words."""
    from cveFeed import autotune
    inner = values.get('values')
    managed = autotune.by_key()
    mine = {k: v for k, v in inner.items() if k in managed and managed[k].registry == name}
    rest = {k: v for k, v in inner.items() if k not in mine}
    if name == 'tunables':
        _tunable_rules(rest)
    if not mine:
        return _run(ctx, name, ENTRIES[name][0], fn, request, groups)
    who = _who(ctx)
    data = None
    if rest:
        request = RequestFactory(REMOTE_ADDR=BRIDGE_ADDRESS).generic(method, request.path, json.dumps({**values, 'values': rest}), content_type='application/json')
        request.user = ctx.user
        data = _run(ctx, name, ENTRIES[name][0], fn, request, groups)
    try:
        results = autotune.agent_change(ctx.user, mine, who)
    except PermissionError as exc:
        raise ApiError(403, str(exc))
    if data is None:
        data = _run(ctx, name, ENTRIES[name][0], _find(ENTRIES[name][0], ENTRIES[name][1], 'GET'), _get_request(ctx, name), groups)
    summary = ' '.join(r['text'] for r in results.values())
    if not rest and all(r['status'] == 'refused' for r in results.values()):
        off = autotune.agent_policy() == 'off'
        raise ApiError(403 if off else 409, summary, agent_changes=results)
    return {**data, 'agent_changes': results, 'agent_summary': summary}


def _get_request(ctx, name):
    api, pattern, _t, _i = ENTRIES[name]
    request = RequestFactory(REMOTE_ADDR=BRIDGE_ADDRESS).get('/cve/api/%s/%s/' % (api, pattern))
    request.user = ctx.user
    return request


def _who(ctx):
    """How the agent is named in a decision's reason and the activity line: the registered agent's name, else the token's."""
    from tenancy import audit
    info = audit.describe_token(ctx.token)
    return info.get('agent_name') or info.get('name') or 'an agent'


_READABLE = ('ip_allowlist', 'ip_allowlist_entry_add', 'ip_allowlist_entry')


def list_settings(ctx):
    return {'settings': catalogue(),
            'how': 'get_setting(name) reads it; change_setting(name, values) changes it with the same limits as the web page; '
                   'entries marked with an id take it as "id" (for example "3/shodan"). Secrets are never returned.',
            'not_exposed': [{'api': a, 'route': r, 'why': why} for (a, r), why in NOT_EXPOSED.items()]
                           + [{'api': ENTRIES[n][0], 'route': ENTRIES[n][1], 'why': ('can be read, not changed by an agent: ' if n in _READABLE else 'not available to agents: ') + why} for n, why in READ_ONLY_FOR_AGENTS.items()]}


def get_setting(ctx, name, ident=None, query=None):
    return _call(ctx, name, 'GET', ident=ident, query=query)


def change_setting(ctx, name, values=None, ident=None, remove=False):
    entry = ENTRIES.get(name)
    if not entry:
        raise ApiError(404, f'no setting called {name}; see list_settings')
    methods = _methods(entry[0], entry[1])
    if remove:
        method = 'DELETE' if 'DELETE' in methods else None
    else:
        method = next((m for m in methods if m in WRITE_METHODS), None)
    if method is None:
        raise ApiError(405, f'{name} cannot be {"removed" if remove else "changed"}; see list_settings')
    if values is not None and not isinstance(values, dict):
        raise ApiError(400, 'values must be an object')
    return _call(ctx, name, method, values=values, ident=ident)
