"""Functional smoke of an updated install, run inside the web container: `manage.py shell < smoke.py`.

The rehearsal's other checks say the containers run and the migrations are applied; this says the application WORKS on the new schema:
the MCP endpoint and its token lookup (the first thing to fail when a table or column is missing answers 500 to every call), tools that read
the tables the update changed, and the main pages. Any 5xx or tool error is a failure; the exit status is the number of failures."""
import json
import sys

from django.conf import settings
from django.contrib.auth.models import User
from django.test import Client

from agentapi.auth import create_token

failures = []


def check(ok, what, detail=''):
    print(('ok   ' if ok else 'FAIL ') + what + (f'  [{detail}]' if detail and not ok else ''))
    if not ok:
        failures.append(what)


admin = User.objects.filter(is_superuser=True).order_by('id').first()
check(admin is not None, 'an administrator exists')
try:
    token, raw = create_token(admin, 'rehearsal-smoke')
except Exception as exc:  # noqa: BLE001 - a missing table or column is the failure this exists to name
    check(False, 'an API token can be created (the token table matches the code)', f'{type(exc).__name__}: {str(exc).splitlines()[0][:160]}')
    print('SMOKE FAILURES:', len(failures))
    sys.exit(len(failures))
try:
    client = Client(HTTP_HOST='localhost')

    def rpc(method, params=None, rid=1):
        response = client.post('/mcp/', json.dumps({'jsonrpc': '2.0', 'id': rid, 'method': method, 'params': params or {}}),
                               content_type='application/json', HTTP_AUTHORIZATION=f'Bearer {raw}', secure=True)
        return response.status_code, (response.json() if response.content else None)

    status, data = rpc('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {'name': 'smoke', 'version': '1'}})
    check(status == 200 and 'result' in (data or {}), 'MCP initialize', f'{status} {str(data)[:120]}')
    status, data = rpc('tools/list')
    tools = [t['name'] for t in (data or {}).get('result', {}).get('tools', [])]
    check(status == 200 and len(tools) > 20, 'MCP lists its tools', f'{status}, {len(tools)} tools')
    for name, args in (('whoami', {}), ('list_projects', {}), ('get_system_status', {}), ('list_cves', {'page_size': 3}),
                       ('list_hosts', {'project': 'rehearsal', 'page_size': 3}), ('list_cve_matches', {'project': 'rehearsal', 'page_size': 3}),
                       ('list_activity', {'project': 'rehearsal', 'page_size': 3}), ('list_agents', {})):
        if name not in tools:
            check(False, f'MCP tool {name} exists')
            continue
        status, data = rpc('tools/call', {'name': name, 'arguments': args}, rid=2)
        result = (data or {}).get('result') or {}
        check(status == 200 and not result.get('isError'), f'MCP tool {name}', f'{status} {str(data)[:160]}')
    status, _ = client.post('/mcp/', '{}', content_type='application/json', secure=True).status_code, None
    check(status in (400, 401, 403), 'MCP refuses a call without a token (not a 500)', str(status))

    ui = Client(HTTP_HOST='localhost')
    ui.force_login(admin)
    for path in ('/', '/cve/', '/cve/graph/', '/cve/account/', '/cve/about/', '/cve/admin/', '/cve/bounty/', '/cve/settings/', '/cve/agents/',
                 '/cve/_all/keys/', '/cve/welcome/'):
        response = ui.get(path, secure=True)
        check(response.status_code < 500, f'page {path}', str(response.status_code))
finally:
    token.delete()
print('SMOKE FAILURES:', len(failures))
sys.exit(len(failures))
