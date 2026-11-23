"""The MCP page (/cve/mcp/, rail entry MCP): how to connect an AI agent to cvENGINE's MCP server, what to ask it, and the History of every tool
call made as you (``agentapi.mcp_log``; an App Admin sees everyone's). The connection snippets name this server's own address, so they can be
pasted as they are; the key is a placeholder the person replaces with one made on the API keys page."""
from django.core.paginator import Paginator

PAGE_SIZE = 50
KEY = '<your API key>'


def clients(url):
    """``[{id, name, where, note, code}]``: one setup per agent people use, each naming this server's MCP address."""
    return [
        {'id': 'claude-code', 'name': 'Claude Code', 'where': 'In a terminal',
         'note': 'Adds the server for your user. Run /mcp inside Claude Code to check that it connected.',
         'code': f'claude mcp add --transport http cvengine {url} \\\n  --header "Authorization: Bearer {KEY}"'},
        {'id': 'claude-desktop', 'name': 'Claude Desktop', 'where': 'claude_desktop_config.json (Settings, Developer, Edit config)',
         'note': 'Claude Desktop reaches a remote server with a header through the mcp-remote bridge, which needs Node.js. Restart Claude Desktop '
                 'after saving.',
         'code': ('{\n  "mcpServers": {\n    "cvengine": {\n      "command": "npx",\n'
                  f'      "args": ["-y", "mcp-remote", "{url}", "--header", "Authorization:${{AUTH_HEADER}}"],\n'
                  f'      "env": {{ "AUTH_HEADER": "Bearer {KEY}" }}\n    }}\n  }}\n}}')},
        {'id': 'cursor', 'name': 'Cursor', 'where': '~/.cursor/mcp.json (or .cursor/mcp.json in a project)',
         'note': 'Cursor lists the server under Settings, MCP once the file is saved.',
         'code': ('{\n  "mcpServers": {\n    "cvengine": {\n'
                  f'      "url": "{url}",\n      "headers": {{ "Authorization": "Bearer {KEY}" }}\n    }}\n  }}\n}}')},
        {'id': 'vscode', 'name': 'VS Code (Copilot agent mode)', 'where': '.vscode/mcp.json in your workspace',
         'note': 'Start the server from the file\'s Start link, then pick its tools in the chat\'s tool list.',
         'code': ('{\n  "servers": {\n    "cvengine": {\n      "type": "http",\n'
                  f'      "url": "{url}",\n      "headers": {{ "Authorization": "Bearer {KEY}" }}\n    }}\n  }}\n}}')},
        {'id': 'curl', 'name': 'Test it with curl', 'where': 'Any terminal',
         'note': 'Lists the tools your key can call. A 401 means the key is wrong or revoked.',
         'code': (f'curl -s {url} \\\n  -H "Authorization: Bearer {KEY}" \\\n  -H "Content-Type: application/json" \\\n'
                  "  -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}'")},
    ]


# What to ask an agent once it is connected, and the tools it will reach for. ``writes``: needs a key with write access.
EXAMPLES = [
    {'ask': 'What should I fix first in the acme project?', 'tools': ['list_situations', 'get_situation'], 'writes': False,
     'what': 'Ranks every host by its worst open problem and explains the top ones.'},
    {'ask': 'Which of my hosts run WordPress 7.1, and are any of them exposed?', 'tools': ['search_hosts'], 'writes': False,
     'what': 'Uses the same search as the Hosts page: wordpress 7.1 means the product and that version.'},
    {'ask': 'Explain CVE-2024-23897 and tell me which of my hosts it affects.', 'tools': ['get_cve', 'list_cve_matches'], 'writes': False,
     'what': 'Reads the CVE, its guidance and the matches on your hosts, with how sure each match is.'},
    {'ask': "Summarise this week's threats for my organization.", 'tools': ['get_threat_digest'], 'writes': False,
     'what': 'The same briefing the email reports send, with how many of your hosts each one reaches.'},
    {'ask': 'Show me the open findings on www.example.com and what each one means.', 'tools': ['list_findings', 'get_finding'], 'writes': False,
     'what': 'Each finding with its evidence, its heat and the AI triage reason.'},
    {'ask': 'Mark finding 4549 as fixed: we closed FTP on that host today.', 'tools': ['update_finding_status'], 'writes': True,
     'what': 'Changes the status with your note; the change is in the finding\'s audit trail under your key\'s name.'},
    {'ask': 'Rescan www.example.com now.', 'tools': ['rescan_hosts'], 'writes': True,
     'what': 'Queues the host on a Sentinel, like the Rescan button.'},
    {'ask': 'Is cvENGINE healthy? Are the Sentinels keeping up?', 'tools': ['get_system_status', 'list_sentinels'], 'writes': False,
     'what': 'Queues, workers, Sentinels and anything that needs attention.'},
]

FIX_LOOP = ('An agent that fixes things, such as one working in your code or on your servers, can register what it looks after and ask for the '
            'findings that are its to fix: register_assets, then get_remediation_work, then update_remediation_status when the fix is in. '
            'An agent that takes assigned work registers with register_agent, waits for an administrator to approve it, then loops '
            'get_next_task, accept_task and report_task_result.')


def history(request):
    """The History table's context: the calls the viewer may read (``agentapi.mcp_log.visible_to``), filtered by the query string (tool,
    outcome ok|failed, writes=1, key, user for an App Admin) and paged."""
    from agentapi import mcp_log
    rows = mcp_log.visible_to(request.user)
    base = rows
    q = request.GET
    tool = (q.get('tool') or '').strip()[:64]
    outcome = q.get('outcome') if q.get('outcome') in ('ok', 'failed') else ''
    writes = q.get('writes') == '1'
    key = (q.get('key') or '').strip()[:100]
    user = (q.get('user') or '').strip()[:150] if request.user.is_superuser else ''
    if tool:
        rows = rows.filter(tool=tool)
    if outcome:
        rows = rows.filter(ok=outcome == 'ok')
    if writes:
        rows = rows.filter(writes=True)
    if key:
        rows = rows.filter(token_name=key) if key != '(browser)' else rows.filter(token_name='')
    if user:
        rows = rows.filter(username=user)
    page = Paginator(rows.order_by('-at', '-id'), PAGE_SIZE).get_page(q.get('page'))
    return {
        'calls': page, 'total': page.paginator.count,
        'filters': {'tool': tool, 'outcome': outcome, 'writes': writes, 'key': key, 'user': user},
        'filtered': bool(tool or outcome or writes or key or user),
        **_choices(request.user, base),
        'query': _query_without_page(q),
    }


CHOICES_SECONDS = 60  # how long the filter menus of one viewer are kept: three DISTINCT reads of the whole call log (an App Admin's) per page view


def _choices(user, base):
    """The filter menus (tools, keys and, for an App Admin, users seen in the calls ``user`` may read), kept ``CHOICES_SECONDS`` per viewer: the
    menus list what was seen, so a value a minute late only shows in the menu later; the table itself is read on every view."""
    from django.core.cache import cache

    def read():
        choices = base.order_by()
        return {'tools_seen': sorted(set(choices.values_list('tool', flat=True).distinct()[:200])),
                'keys_seen': sorted({k or '(browser)' for k in choices.values_list('token_name', flat=True).distinct()[:200]}),
                'users_seen': sorted(set(choices.values_list('username', flat=True).distinct()[:200])) if user.is_superuser else []}
    key = f'cve:mcp-choices:{user.pk}:{int(bool(user.is_superuser))}'  # per viewer: what one may read is never another's menu
    try:
        got = cache.get(key)
    except Exception:  # noqa: BLE001 - a cache outage reads them directly
        return read()
    if got is None:
        got = read()
        try:
            cache.set(key, got, CHOICES_SECONDS)
        except Exception:  # noqa: BLE001
            pass
    return got


def _query_without_page(q):
    keep = q.copy()
    keep.pop('page', None)
    return keep.urlencode()
