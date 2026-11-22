"""What cvENGINE sends to AI models, and what an AI agent connected over MCP can read: the text of the "AI and your data" page (/cve/ai/).

Every AI stage the product names (``reNgine.ai_prompts.STAGES``) is described here, job by job: when it runs, what it sends, what it never sends,
what it can change by itself and the switch that stops it. ``tests/test_ai_disclosure.py`` fails when a stage is added without an entry, so a new
AI job cannot ship without saying what it sends. ``state()`` reads the live settings, so the page says which jobs are on for this install now.

The text was checked against the code that builds each prompt (``ai_providers.triage_parts``, ``host_context``, ``host_review.build``,
``reviewer.build_packet`` and ``reviewer.snapshot``, ``validation_plan.plan``, ``detection_author.user_parts``, ``templategen``, ``autotune``,
``rdp_shot``, ``nuclei_templates``) and the MCP server (``agentapi.mcp``). Change one and the other together."""
import os

# Stages that no code calls any more: their rows stay in the usage ledger, so they stay in STAGES, but nothing sends them.
RETIRED = {'nuclei_tag_selection'}

# A job that runs whenever a provider is on unless its own switch says otherwise; ``key`` names the check in ``_on``.
JOBS = [
    {
        'id': 'finding_triage', 'stages': ('finding_triage', 'finding_triage_repair'), 'group': 'findings',
        'title': 'Triage of a finding',
        'purpose': 'Reads one finding (a CVE match, a scanner result, an exposed database, a hygiene issue) and says whether it is real, how bad it '
                   'is and how to fix it.',
        'when': 'After scans, the hygiene check and validation, and in an hourly sweep. One question covers every host with the same evidence. '
                'Capped at 100 a run, 500 a project a day and 2,000 a day.',
        'sends': ['The finding: product, version, CPE, matched range, template name and matcher, URL path (not the host), HTTP status code, '
                  'extracted values (secrets masked), hygiene evidence such as an SPF record',
                  'For a CVE match: the CVE text, its guidance and the host context (below)',
                  'For a web route: the page title, content type and cookie names, and counts of sensitive data types (never a sample)',
                  'On a retry after a rejected answer: the model\'s own previous answer'],
        'never': ['Raw HTTP requests, response bodies, headers or cookie values', 'Fields named host, IP, URL, password, token, key or secret',
                  'The host\'s own name (replaced with [host])'],
        'changes': 'Stores its verdict and remediation text on the finding. It does not close findings by itself.',
        'switch': 'Runs whenever an AI provider is on. It has no switch of its own: turn the provider off, or lower its daily limits '
                  '(Settings, AI spend).',
    },
    {
        'id': 'validation_plan', 'stages': ('validation_plan',), 'group': 'findings',
        'title': 'Validation plan',
        'purpose': 'Chooses which approved, read-only checks would settle whether a CVE really applies to a host.',
        'when': 'When a CVE match is validated: automatically every few minutes for hot CVEs, on "Validate now", and over the API. At most '
                '200 a day in total and 20 a project a day (Settings, AI). An answer is reused for 24 hours.',
        'sends': ['The CVE (id, title, description cut to 500 characters, CVSS, affected ranges, reference links) and its guidance',
                  'The evidence for the match: product, version, range and port',
                  'The names of the checks it may choose from', 'The host context (below)',
                  'Up to 6 earlier check results with their summaries (the host\'s own name replaced with [host])'],
        'never': ['The host name or its IP addresses as fields'],
        'changes': 'Picks which approved checks run. It cannot add a check of its own.',
        'switch': 'Set the daily validation-plan limits to 0 in Settings. Without a provider a fixed plan is used.',
    },
    {
        'id': 'local_check_suggestion', 'stages': ('local_check_suggestion',), 'group': 'findings',
        'title': 'Local check suggestions',
        'purpose': 'Suggests read-only commands an administrator could run on the host to confirm a CVE that cannot be checked from outside.',
        'when': 'During validation, once per CVE match that has no outside check. Counted against the triage limits.',
        'sends': ['The CVE id and title, the affected vendors and products, the matched product name'],
        'never': ['The host name, IP addresses or anything the host said'],
        'changes': 'Nothing runs them. They are shown as suggestions, and only commands that pass a read-only check are kept.',
        'switch': 'Runs whenever an AI provider is on.',
    },
    {
        'id': 'host_review', 'stages': ('host_review', 'host_review_repair'), 'group': 'reviewer',
        'title': 'Host review',
        'purpose': 'Reads every open result of one host together and proposes the next step for it.',
        'when': 'In a sweep every 10 minutes for hosts whose results changed (at most one a host a day, 100 hosts a day), and on '
                '"Review this host now".',
        'sends': ['Up to 60 findings of the host with their heat, severity, validation results and status',
                  'Why each finding has its heat. When a person set it, their note is included, but not who they are',
                  'The host context (below) and each finding\'s triage details',
                  'Exposed secrets as counts by kind only, screenshots as their page title only'],
        'never': ['Secret values, screenshot images, the host\'s own name'],
        'changes': 'Writes a note and a proposed step. A "false positive" closes a finding by itself only if "Let the host review close false '
                   'positives by itself" is on (off by default).',
        'switch': 'Off by default. In Settings, AI reviewer, both "Review findings and check operations with the AI reviewer" and "Review '
                  'whole hosts with the AI" must be on. Each project can also turn it off.',
    },
    {
        'id': 'finding_review', 'stages': ('finding_review',), 'group': 'reviewer',
        'title': 'Finding review',
        'purpose': 'A second look at findings an earlier triage was unsure about.',
        'when': 'Continuously in batches of 10 while the AI reviewer is on. At most 300 a day.',
        'sends': ['The same finding details and host context as triage', 'The earlier triage reason (up to 800 characters)',
                  'Why the finding has its heat (a person\'s note, but not who they are)', 'Secrets masked as in every other job'],
        'never': ['Raw HTTP responses, cookie values, the host\'s own name'],
        'changes': 'Closes a finding as a false positive only if "Close the findings it finds to be false positives" is on (off by default) and '
                   'the server\'s own checks allow it.',
        'switch': 'Off by default. Settings, AI reviewer, "Review findings and check operations with the AI reviewer".',
    },
    {
        'id': 'operations_check', 'stages': ('operations_check',), 'group': 'reviewer',
        'title': 'Operations check',
        'purpose': 'Explains why part of the install is unhealthy (queues stuck, Sentinels silent, scans failing) and what to do.',
        'when': 'At most four times a day (03, 09, 15 and 21 UTC), and only when a health check is not ok.',
        'sends': ['Health check results and measurements: queue sizes, memory, database and Redis size, AI failure counts',
                  'Sentinel names, and the latest error and activity messages of failing tasks (up to 200-300 characters each). '
                  'These messages can name hosts.',
                  'Auto-tuning\'s recent decisions and their reasons'],
        'never': ['Findings, secret values (masked)'],
        'changes': 'Adds its explanation to the alert. It may start the "feed Sentinels" action when the check offers it. Tuning proposals '
                   'are only suggestions unless the agent policy is set to Auto.',
        'switch': 'Off by default. Settings, AI reviewer, "Review findings and check operations with the AI reviewer".',
    },
    {
        'id': 'rdp_screenshot', 'stages': ('rdp_screenshot',), 'group': 'findings',
        'title': 'Reading an RDP login screen',
        'purpose': 'Reads the login screen of a Remote Desktop server that does not require network-level sign-in, to see whether an account '
                   'is shown as signed in.',
        'when': 'During a scan, for up to 10 such hosts a scan, once a host a day.',
        'sends': ['The full screenshot of the login screen as an image. Whatever it shows (machine name, domain, a user name) is sent as is.'],
        'never': ['The host\'s name or address as text', 'Blank screens'],
        'changes': 'Stores the user name and a short summary, and records an informational finding when an account is shown signed in.',
        'switch': 'On whenever an AI provider is on. Turn it off with CVENGINE_RDP_SHOT=0 in the server\'s .env.',
    },
    {
        'id': 'nuclei_targeting', 'stages': ('nuclei_targeting',), 'group': 'findings',
        'title': 'Choosing detection templates',
        'purpose': 'Picks which nuclei template tags fit the software found on each host.',
        'when': 'In the scan\'s AI-targeted template stage, up to 25 host profiles a request, at most 400 a day. An answer is reused for 7 days.',
        'sends': ['Hosts numbered 0, 1, 2 ..., each with up to 40 software names (no versions)', 'The list of installed template tags'],
        'never': ['Host names, IP addresses, versions, findings'],
        'changes': 'Decides which installed templates the scan runs on those hosts.',
        'switch': 'Runs whenever an AI provider is on. Without one, a fixed table picks the templates.',
    },
    {
        'id': 'cve_detection', 'stages': ('cve_detection',), 'group': 'improve',
        'title': 'CVE guidance (detection records)',
        'purpose': 'Writes, for one CVE, how to recognise it, how to confirm it safely and what a false positive looks like. One record is '
                   'shared by every project.',
        'when': 'Twice an hour, for the CVEs attackers use first (KEV, public exploits, high EPSS or CVSS). 25 a day by default; '
                '"Write guidance now" in Settings can ask for up to 5,000 at once.',
        'sends': ['Public CVE data only: id, title, description, CVSS, exploit flags, affected products and ranges, up to 6 reference links',
                  'When an administrator adds guidance to a CVE: their text'],
        'never': ['Hosts, findings, projects or anything a scan found'],
        'changes': 'Updates the shared record, which then feeds triage and the checks offered to agents. Matches of that CVE are re-triaged. '
                   'An AI answer can never mark a CVE "local only" and close matches by itself.',
        'switch': 'Set "CVE guidance written by the model per day" to 0 in Settings. Rules-written records are kept either way.',
    },
    {
        'id': 'template_generation', 'stages': ('template_generation',), 'group': 'improve',
        'title': 'Writing detection templates',
        'purpose': 'Drafts a nuclei template for a CVE that has no installed one.',
        'when': 'When a validation or a host review needs a template that does not exist. At most 10 a day and one attempt a CVE a week.',
        'sends': ['Public CVE data only: id, title, description, CVSS, affected ranges, references'],
        'never': ['Hosts, findings or projects. The CVE is chosen because one of your hosts matched it, but the request does not say which.'],
        'changes': 'Only a draft. It never runs on a host until every check below has passed.',
        'switch': 'Runs whenever an AI provider is on and validation asks for it. Its daily limit cannot go below 1.',
    },
    {
        'id': 'template_validation', 'stages': ('template_validation',), 'group': 'improve',
        'title': 'Testing AI-written templates',
        'purpose': 'Writes a harmless test response for a draft template and reviews the draft a second time.',
        'when': 'Every 5 minutes for waiting drafts, two calls a draft, up to 3 tries. Drafts expire after 7 days.',
        'sends': ['The CVE data, the draft template and the AI-written test responses'],
        'never': ['Hosts, findings or projects'],
        'changes': 'A draft that passes every check becomes a template that runs automatically on matching hosts of the project that needed it, '
                   'with no person approving it.',
        'switch': 'Off by default. Settings, AI reviewer, "Validate AI-written checks automatically".',
    },
    {
        'id': 'autotune_advisor', 'stages': ('autotune_advisor',), 'group': 'improve',
        'title': 'Auto-tuning advisor',
        'purpose': 'Suggests throughput settings (how many scans, how many workers) from how loaded the server and Sentinels are.',
        'when': 'Every 3 hours at most, 8 times a day.',
        'sends': ['Numbers only: setting values and their ranges, memory, CPU and database load, queue lengths, per-Sentinel counts keyed by id'],
        'never': ['Hosts, findings, projects, Sentinel names'],
        'changes': 'In Auto mode (the default), accepted advice is applied by itself, checked, and reverted if things get worse.',
        'switch': 'Settings, configMaxxing, Auto-tuning: turn off "Ask the AI advisor", or set the mode to Suggest or Off.',
    },
    {
        'id': 'connection_test', 'stages': ('connection_test',), 'group': 'improve',
        'title': 'Connection test',
        'purpose': 'Checks that the provider answers.',
        'when': 'Only when an administrator presses Test or saves the AI settings.',
        'sends': ['The word "ping"'],
        'never': ['Anything else'],
        'changes': 'Nothing.',
        'switch': 'Runs only on demand.',
    },
]

GROUPS = [
    ('findings', 'Reading your findings', 'These jobs read what scans found on your hosts. This is where your data goes.'),
    ('reviewer', 'The AI reviewer', 'Optional jobs that take a second look at hosts and findings, and at the health of the install. All are off '
                                    'until an administrator turns them on.'),
    ('improve', 'Self-improvement', 'Jobs that improve cvENGINE itself: CVE guidance, new detection templates and tuning. They send public CVE '
                                    'data or numbers, not your scan results.'),
]

# What the host context (sent with triage of a CVE match, validation plans, host reviews and finding reviews) carries.
HOST_CONTEXT = {
    'sends': ['Technologies and versions, JavaScript library paths',
              'Open ports with service, product, version, banner (160 characters), HTTP status, title and server, TLS certificate subject and issuer',
              'Up to 30 response headers (for example Server, X-Powered-By, Content-Security-Policy), never cookies',
              'Hosting, CDN or WAF provider, host labels, OS guesses, facts from runZero',
              'From the host inventory reporter: OS, kernel and the number of packages',
              'Earlier check results and other CVE matches on the host, WordPress plugins and themes'],
    'never': ['The host\'s own name, its domain and its CNAME (replaced with [host])',
              'Tailscale device names, addresses and owners', 'Cookie values'],
    'caveat': 'Other names and IP addresses that appear inside a banner, a header, a page title or a certificate are not removed.',
}

PROTECTIONS = [
    'Secrets are masked before anything leaves: private keys, cloud and API keys, tokens, passwords in URLs, Authorization headers and '
    'webhook addresses.',
    'The host\'s own name, domain and CNAME are replaced with [host]. Host names and IP addresses are not sent as fields.',
    'Text a scanned host wrote is cleaned, cut to a fixed length and fenced, and instructions aimed at an AI are stripped and flagged.',
    'Prompts and answers are not written to logs. A question waits in the database only until it is answered (unanswered ones are deleted '
    'after 30 days). The usage ledger keeps counts, never text.',
    'The model is given no tools: it cannot browse, run commands or read the database. Every answer is checked against a fixed format '
    'before it is used.',
    'The AI reviewer runs in its own locked-down container with no database password, and reaches cvENGINE only through its own API.',
]

STILL_SENT = [
    'Names and IP addresses of other machines that appear inside banners, headers, page titles and certificates.',
    'The full RDP login screen image, including any names it shows.',
    'A note a person wrote when they set a finding\'s heat by hand.',
    'Error and activity messages in the operations check, which can name hosts and Sentinels.',
    'Product names, versions and CVE ids of your hosts: what makes a finding a finding.',
]

MCP = {
    'intro': 'An AI agent you connect over MCP (Claude Code, an IDE assistant, your own agent) works with an API key from the API keys page. '
             'Everything a tool returns goes into that agent\'s conversation, and so to the agent\'s own AI provider, under that provider\'s '
             'terms. cvENGINE does not choose that provider and cannot see what it keeps.',
    'reaches': [
        'An API key acts as the person who made it, with their roles, across every project they can open. It cannot be limited to one project.',
        'Hosts, ports, products, versions, certificates and host exports (the full CSV), findings and CVE matches.',
        'Scanner request and response excerpts up to 4,096 characters each, as the host sent them. Token and secret templates are masked.',
        'Host inventory reports: OS, installed packages and versions, listening services, containers and security settings.',
        'Tailscale devices (project admins): names, addresses, OS and the owner\'s login, usually an email address.',
        'Report recipients\' email addresses, audit log entries (administrators).',
    ],
    'never': [
        'Values of exposed secrets (only a mask and a fingerprint are stored at all).',
        'Stored sign-in values (only their names), API keys, passwords and webhook addresses in settings (only "set" or "not set").',
        'Screenshots (only their title and status), and other people\'s email addresses in the member list.',
    ],
    'controls': [
        'Make a read-only key for an agent that only needs to read. A read-only key cannot change anything.',
        'A key with write access can start scans, change finding status, add and delete targets and hosts in one call, with no confirmation. '
        'Agents cannot turn features on, raise limits, store keys or switch on secret validation.',
        'Every tool call an agent makes, reads included, is in the History on the MCP page (when, which key, the tool and its arguments, '
        'never the result), kept 90 days. Every change is also in the audit log with the key\'s name.',
        'Every tool result carries a notice that text from scanned hosts is data, not instructions.',
        'Revoke a key on the API keys page. Keys are also revoked when their owner\'s password changes.',
    ],
}

HOW_TO_STOP = [
    ('Send nothing to any AI model', 'Turn the AI provider off (Settings, AI). Every job waits and nothing is sent. Scans, CVE matching, '
                                     'rules-written guidance and installed templates keep working.'),
    ('Keep data on your own network', 'Choose Ollama, vLLM or LM Studio and run the model on a machine you control. The data then goes only '
                                      'to that server.'),
    ('Stop the AI reviewer container', 'Set CVENGINE_REVIEWER=0 in the server\'s .env. Every AI job waits; only the connection test still works.'),
    ('Turn off one job', 'Use the switch named for each job above.'),
    ('Limit AI agents', 'Give agents read-only API keys, or none, and revoke keys you no longer use.'),
]


def stage_ids():
    """Every stage this page describes."""
    return {s for job in JOBS for s in job['stages']}


def _flag(name, default='1'):
    return os.environ.get(name, default).strip().lower() not in ('0', 'false', 'no', 'off')


def state(include_counts=False):
    """The install's AI state as the page shows it: the provider (``kind`` 'off', 'hosted' or 'self_hosted'), whether the reviewer container
    may send anything, and ``{job id: (on, why)}``. ``include_counts`` adds the calls of the last 30 days per job (App Admins only)."""
    from cveFeed import ai_jobs, reviewer
    from reNgine.ai_profiles import PROFILES
    row = ai_jobs.provider_row()
    profile = PROFILES.get(getattr(row, 'provider', None)) if row is not None else None
    container = reviewer.env_enabled()
    out = {'kind': 'off', 'provider': '', 'host': '', 'container': container, 'jobs': {}, 'counts': None}
    if row is not None and profile is not None:
        from urllib.parse import urlsplit
        out['kind'] = 'self_hosted' if profile.needs_url else 'hosted'
        out['provider'] = profile.label
        out['host'] = urlsplit((row.base_url or '').strip() or profile.default_base).hostname or ''
        out['model'] = row.model or profile.default_model
    rs = _row(reviewer.settings_row)
    from cveFeed import autotune
    at = _row(autotune.settings_row)
    on = row is not None and container
    checks = {
        'finding_triage': (on, ''),
        'validation_plan': (on and bool(getattr(row, 'plan_daily_total', 0)), 'its daily limit is 0'),
        'local_check_suggestion': (on, ''),
        'host_review': (on and bool(rs and rs.enabled and rs.host_review_enabled), 'off in Settings'),
        'finding_review': (on and bool(rs and rs.enabled), 'off in Settings'),
        'operations_check': (on and bool(rs and rs.enabled), 'off in Settings'),
        'rdp_screenshot': (on and _flag('CVENGINE_RDP_SHOT'), 'CVENGINE_RDP_SHOT=0'),
        'nuclei_targeting': (on, ''),
        'cve_detection': (on and bool(getattr(row, 'cve_guidance_daily', 0)), 'its daily limit is 0'),
        'template_generation': (on, ''),
        'template_validation': (on and bool(rs and rs.template_validation_enabled), 'off in Settings'),
        'autotune_advisor': (on and bool(at and at.advisor and at.mode != 'off') and _flag('CVENGINE_AUTOTUNE'), 'off in Settings'),
        'connection_test': (row is not None, ''),
    }
    for job in JOBS:
        ok, why = checks[job['id']]
        if row is None:
            why = 'no AI provider'
        elif not container and job['id'] != 'connection_test':
            why = 'the AI reviewer container is off'
        out['jobs'][job['id']] = (ok, '' if ok else why)
    if include_counts:
        out['counts'] = _counts()
    return out


def _row(getter):
    try:
        return getter()
    except Exception:  # noqa: BLE001 - the page still explains everything; only the live state is unknown
        return None


def _counts():
    from datetime import timedelta

    from django.db.models import Count
    from django.utils import timezone

    from cveFeed.models import AIUsage
    since = timezone.now() - timedelta(days=30)
    by_stage = dict(AIUsage.objects.filter(started_at__gte=since).values_list('stage').annotate(n=Count('id')).values_list('stage', 'n'))
    return {job['id']: sum(by_stage.get(s, 0) for s in job['stages']) for job in JOBS}


def page_context(user):
    """The template's context: the jobs by group with their live state, and the rest of the page's text."""
    admin = bool(getattr(user, 'is_superuser', False))
    live = state(include_counts=admin)
    groups = []
    for key, title, intro in GROUPS:
        jobs = []
        for job in JOBS:
            if job['group'] != key:
                continue
            on, why = live['jobs'][job['id']]
            jobs.append({**job, 'on': on, 'why': why, 'calls': (live['counts'] or {}).get(job['id']) if admin else None})
        groups.append({'key': key, 'title': title, 'intro': intro, 'jobs': jobs})
    return {'ai': live, 'ai_groups': groups, 'ai_admin': admin, 'host_context': HOST_CONTEXT, 'protections': PROTECTIONS,
            'still_sent': STILL_SENT, 'mcp': MCP, 'how_to_stop': HOW_TO_STOP,
            'ai_jobs_on': sum(1 for on, _why in live['jobs'].values() if on), 'ai_jobs_total': len(JOBS)}
