# AI and your data

This page says what cvENGINE sends to AI models, what an AI agent connected over MCP can read, and how to send less or nothing. The same text is in the app at **AI and your data** (`/cve/ai/`, linked from a card on the AI Model Usage page and from About). Every signed-in person can read that page. It also shows which AI jobs are on for the install, and App Admins see each job's calls over the last 30 days.

The in-app text lives in `web/cveFeed/ai_disclosure.py`. `web/tests/test_ai_disclosure.py` fails when an AI stage is added to `cvengine/ai_prompts.STAGES` without a description there, so no AI job ships without saying what it sends.

## Where the data goes

- **The provider.** Requests go to the one provider an App Admin chooses in Settings:
  - **Hosted:** Anthropic, OpenAI or OpenRouter. The data leaves your network.
  - **Self-hosted:** Ollama, vLLM or LM Studio. The data goes only to that server.
  - Profiles: `cvengine/ai_profiles.PROFILES`.
- **Who sends it.** The AI reviewer container makes every model call, except the Settings connection test and the model list ([AI-REVIEWER.md](AI-REVIEWER.md)). The server queues a job (`cveFeed/ai_jobs.enqueue`); the container takes it, calls the provider and posts the answer back.
- **The API key.** It is stored encrypted and never returned to the browser. It is used only for the provider and host it was saved for. The container receives it to make the calls.
- **No agreement.** cvENGINE has no agreement with any provider about retention or training. Check your provider's terms, or host the model yourself.

## Master switches

| Switch | Default | Effect |
|---|---|---|
| AI provider (Settings, AI) | off | Off: no AI job is queued; every stage falls back to its rules |
| `CVENGINE_REVIEWER=0` | on | Jobs wait and are never sent; only the connection test works |
| AI budget (Settings, AI model, or `CVENGINE_AI_MONTHLY_BUDGET_USD` and `CVENGINE_AI_DAILY_BUDGET_USD`) | none | Once the monthly or daily dollar budget is spent, no AI job is handed out and the finding review and operations check stop until the next UTC day or month ([AI-USAGE.md](AI-USAGE.md#ai-budget)) |
| Settings, AI reviewer, "Review findings and check operations with the AI reviewer" | off | Gates the finding review, the operations check and (with its own switch) the host review. **It does not gate the pipeline jobs** (triage, validation plans, CVE guidance, templates, RDP reading, template targeting), which run whenever a provider is on |

## The jobs

| Job (stage) | Default | Sends | Can change by itself |
|---|---|---|---|
| Triage (`finding_triage`, `_repair`) | on with a provider | The finding's details, minus host, URL, request, response, cookie, token and key fields. For a CVE match, also the CVE and the host context. A repair also sends the model's previous answer. `ai_providers.triage_parts`, `triage.describe` | Its verdict and remediation text, never a closure |
| Validation plan (`validation_plan`) | on with a provider; 200 a day, 20 a project | The CVE (description cut to 500 characters), the match evidence, the allowed checks, the host context, and up to 6 earlier check summaries with the host's names replaced. `validation_plan.plan` | Which approved checks run |
| Local check suggestions (`local_check_suggestion`) | on with a provider | The CVE id and title, affected products, the matched product | Nothing; read-only commands are shown as suggestions |
| Host review (`host_review`, `_repair`) | **off** | Up to 60 findings with heat, status and validation results; the heat reason (a person's note, never their login); the host context; secrets as counts only; screenshots as titles only; the newest notes people and agents wrote on the host and its findings, fenced as data. Capped at 80,000 characters. `host_review.build` | A note; closes false positives only with its own auto-close switch (off) |
| Finding review (`finding_review`) | **off** | The finding, the host context, the earlier triage reason (800 characters), the heat reason, and the newest notes on the finding and its host (fenced as data, never instructions). Secret-masked like every other job. `reviewer.build_packet` | Closes false positives only with auto-close (off) and the server's close gate |
| Operations check (`operations_check`) | **off** | Health checks and measurements, Sentinel names, and the latest error and activity messages of failing tasks (200–300 characters each), which can name hosts. Also auto-tuning decisions. Secret-masked. `reviewer.snapshot` | Its alert text; the `feed_sentinels` action; tuning proposals stay suggestions unless the agent policy is Auto |
| RDP login screen (`rdp_screenshot`) | on with a provider (`CVENGINE_RDP_SHOT`) | **The full screenshot image**, unredacted, up to 4 MB. No host name or address as text. `rdp_shot` | Stores the user name shown and an informational finding |
| Template targeting (`nuclei_targeting`) | on with a provider | Software names per host (numbered, no host names or IPs, no versions), plus the installed template tags. `nuclei_templates` | Which installed templates a scan runs |
| CVE guidance (`cve_detection`) | on with a provider; 25 a day | Public CVE data only, plus an administrator's guidance text when they add some. `detection_author.user_parts` | The shared per-CVE record; re-triage of that CVE's matches |
| Template drafts (`template_generation`) | on with a provider; 10 a day, minimum 1 | Public CVE data only. `templategen` | A draft only; it never runs until it passes validation |
| Template validation (`template_validation`) | **off** | CVE data, the draft and its AI-written test responses | A passing draft becomes a template that runs on the requesting project's matching hosts, with no person approving |
| Auto-tuning advisor (`autotune_advisor`) | on (advisor) in Auto mode | Numbers only: settings, load, queues, per-Sentinel counts by id. `autotune` | In Auto mode, applies accepted values, verified and reverted on regression |
| Connection test (`connection_test`) | on demand | The word "ping" | Nothing |

`nuclei_tag_selection` is retired: no code calls it.

## The host context

Triage of CVE matches, validation plans, host reviews and finding reviews send `host_context` (cut to 9,000 characters). It contains:
- technologies and versions;
- ports with service, product, version, banner, HTTP status, title and server, and TLS certificate subject and issuer;
- up to 30 kept response headers (never cookies);
- hosting, CDN or WAF provider, labels, OS guesses and runZero facts;
- inventory OS, kernel and package count;
- earlier check results (not in triage: see below), other CVE matches, WordPress plugins.

Triage leaves the earlier check results out. They are the last steps of the host's most recently validated findings, so every validation of any finding on a host changed them, and with them the evidence signature of every other match on that host: each was asked again and validated again. The validation planner still reads them.

The host's own name, domain and CNAME are replaced with `[host]`. Tailscale names, addresses and owners are left out. **Other names and IP addresses inside banners, headers, titles and certificates are not removed.**

## Protections

- **Secret masking.** `cveFeed/secret_redaction.redact_text` masks private keys, cloud and API keys, tokens, URL passwords, `password=` and `api_key=` pairs, Authorization headers and webhooks.
  - It runs on every queued job (`ai_jobs._clean_parts`), on the finding review packet and on the operations snapshot.
  - It also runs on answers, except for template validation.
- **Host names.** The host's own names are replaced in every finding field, host context string and earlier check summary.
- **Injection defences.** Scanned-host text is strictly cleaned, cut and fenced, and instructions aimed at an AI are stripped and flagged (`triage.strip_instructions`, `injection_guard`).
- **No prompts kept.**
  - Prompts and answers are not logged.
  - An `AIJob` keeps its question only until it is answered. An unanswered job is deleted 30 days after it ends.
  - The usage ledger (`AIUsage`) keeps counts only.
- **No tools for the model.** It has no browsing, commands or database, and every answer is schema-checked.

## AI agents over MCP

An agent reads with an API key that acts as its owner across every project they can open. Everything a tool returns goes to the agent's own AI provider.

**What an agent can read**
- hosts and host exports;
- findings with request and response excerpts up to 4,096 characters (masked only for token and secret templates);
- host inventory packages and services;
- Tailscale devices with the owner's login (project admins);
- report recipients;
- audit rows (administrators).

**What an agent never gets**
- exposed secret values (never stored);
- stored sign-in values;
- settings keys, passwords and webhooks (only "set" or "not set");
- screenshot images.

**Write keys and agent rules**
- A write key can change and delete in one call, with no confirmation.
- Agents cannot turn features on, raise limits, store keys or enable secret validation ([AGENT-API.md](AGENT-API.md)).
- Every tool call, reads included, is in the History on the **MCP** page (`/cve/mcp/`, kept 90 days, never the result). Changes are also audited with the key's name.
- Every result carries an untrusted-text notice.
- Use read-only keys for agents that only read.

See also: [AI-REVIEWER.md](AI-REVIEWER.md), [AI-USAGE.md](AI-USAGE.md), [AGENT-API.md](AGENT-API.md).
