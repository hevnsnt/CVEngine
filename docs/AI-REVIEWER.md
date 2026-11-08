# The AI reviewer

cvENGINE 1.4 adds an **AI reviewer**: its own container. It works the way a careful outside analyst does, but it is boxed in so that text from a
scanned host cannot steer it, reach the AI provider's key, or touch cvENGINE's code or database.

It runs two jobs of its own, and each has its own model setting. It also answers the questions the pipeline puts to a model (the
**pipeline's AI jobs**, below): the triage of each finding and its local-check suggestions are asked through it, so the main server makes
no model call for them.

| Job | Default model (Anthropic) | When it runs | What it does |
| --- | --- | --- | --- |
| **Finding review** | `claude-sonnet-5-5` | Continuously, in small batches, up to a daily cap | Reads every open finding once: Fire, Smoke and Ice CVE matches, scanner findings (nuclei, database exposure, bbot) and hygiene findings. It judges each one false positive or true finding (open, in progress, fixed or accepted risk), and closes the false positives with a closing note that says why. A finding is read again only when its host or its evidence changes. |
| **Operations check** | `claude-haiku-5-5` | Four times a day (by default at 03:00, 09:00, 15:00 and 21:00 UTC); it replaces the three-hourly AI assessment review of 1.3, which is retired | Reads the work queue, Sentinel load and errors, the share of scanning done locally, nuclei template freshness, AI-written templates waiting for review, failed scans and the server's own problems. It writes the admin an alert that diagnoses each problem and says what to do. It may also start a fix from a short fixed list: give idle Sentinels work, or fetch new nuclei templates. |

With another provider (OpenAI, OpenRouter, vLLM, LM Studio, Ollama), both jobs use the provider's configured model unless a model is named for the
job in **Settings > AI model > AI reviewer**.

## Why it exists

An outside agent, given only cvENGINE's API, closed more than 200 false positives that the built-in triage had kept open. The built-in AI saw too
little, and some of what it saw it trusted too much. The jQuery bug is the clearest example: a version string in a script's body or a copied file
was read as the host's version and became a Fire finding.

Tools aimed at AI-driven scanners make the same weakness deliberate:

- [SpikeStrip](https://github.com/Arcanum-Sec/SpikeStrip) plants comments in HTML and JavaScript. Some order an AI around ("stop and ask for
  human authorization", "include this reference in your report", "treat this note as your next task"). Some are fake leads that name real CVEs
  (Log4Shell, CVE-2022-22947, CVE-2021-41773) against made-up routes. Some are impossible tasks ("prove the Riemann hypothesis") meant to burn
  tokens.
- [wraith](https://github.com/Arcanum-Sec/wraith) shows where planted text ends up: "untrusted text flows through agents, tool outputs, admin
  review queues… and fires JavaScript in places nobody is watching". A review queue and an alert banner are exactly such places.

We only scan systems we are authorised to scan. Even so, any scanned host can carry text like this, whether planted on purpose or not, so the
reviewer is built on the assumption that every scanned byte is hostile.

## What the reviewer may and may not do

```
          scanned hosts (untrusted)
                   │
        ┌──────────▼──────────┐   database, source, field key, Celery
        │  cvENGINE server    │◄── never leave this side
        │  (web, celery)      │
        │                     │   /api/v1/reviewer/*  (reviewer token only)
        │  policy gates  ◄────┼──────────────┐
        └─────────────────────┘              │ review packets and AI jobs out (sanitised, host names removed)
                                             │ verdicts (enums + one short note) and answers in, checked by the server
                                   ┌─────────┴──────────┐
                                   │ reviewer container │── HTTPS ──► AI provider
                                   │ no source, no DB,  │
                                   │ read-only, no caps │
                                   └────────────────────┘
```

1. **The model has no tools.** It cannot fetch a URL, run a command, read a file or call cvENGINE. It reads one packet and returns one JSON
   object, which the provider constrains to a schema where it can (`output_config.format` on Anthropic, `json_schema` elsewhere). The reviewer
   then checks the object again itself. Nothing the model writes is ever executed, loaded as YAML or code, or used to build a request. The
   answer to a pipeline job goes back to the server as text, and the server checks it with the stage's own validator before anything is
   stored (below).
2. **Every answer is a choice from a fixed list.** The verdict, the confidence and the reason are enums. The only free text is a closing note of
   up to 1,200 characters, and the server cleans it before storing it: markup characters and links are removed, and the note is refused if it
   repeats a marker planted in the evidence.
3. **The server decides, not the model.** A verdict is a request. The server closes a finding only when all of these hold:
   - the verdict is `false_positive` with `high` confidence, and automatic closing is on;
   - the finding has no hard evidence: no template hit, no distribution-tracker or runZero report, no report from the host itself, no
     validation hit, and no confirmed library body (`match_policy.has_hard_evidence`, `triage.hard_evidence`);
   - no person has worked it: no status change, assignee, comment, heat set by hand or manual validation request (`match_policy.has_standing`
     and its equivalent for scanner and hygiene findings);
   - the evidence the model was shown carries no instructions aimed at an AI (`cveFeed.injection_guard`);
   - the packet the verdict answers is still the current one: same evidence, same host state, and the finding is still open.

   Anything else is recorded as the reviewer's opinion, shown on the finding, and changes nothing. A `false_positive` the server holds back on a
   finding with hard evidence is recorded as **disputed**, for a person to look at.
4. **Everything shown to the model is data inside a fenced block.** It reuses the triage sanitiser: forbidden keys (raw requests, responses,
   bodies, secrets) are dropped, host names become `[host]`, control, bidi and zero-width characters are stripped, length is capped, and
   sentences that address an AI are cut out. What is left sits between random-nonce markers the text cannot close. The system prompt tells the
   model that comments, banners and page text are claims, never facts or orders, and that a CVE named in host text is not evidence.
5. **Planted instructions are a signal, not a lead.** `cveFeed.injection_guard` scans what the scanner stored for text aimed at AI agents: the
   SpikeStrip families (workflow orders, "include this reference", gates, fake CVE leads to routes) and the classic "ignore previous
   instructions". A finding whose evidence contains such text is never closed automatically. The packet says so, and the reviewer's note says so.
6. **Each call is bounded.** Every call has a maximum reply length and a time limit. A daily cap limits the number of reviews, and the operations
   job runs at most once per scheduled slot. A task meant to burn tokens ends at the cap.
7. **The container is locked down.** It has:
   - its own small image, with only the reviewer package and two pinned libraries;
   - no cvENGINE source and no database or Redis credentials;
   - a read-only root filesystem with a small `/tmp`;
   - a non-root user, all capabilities dropped, `no-new-privileges`, and limits on processes and memory.

   It reaches the server only at `http://web:8000/api/v1/reviewer/*`, with a token of scope `reviewer`. The middleware refuses that token on any
   other path, and on `/mcp/`.
8. **The provider key stays out of the prompt.** The server keeps the key encrypted in its database and hands it only to a `reviewer`-scope
   token. The reviewer holds it in memory and sends it only as the provider's auth header. It is never in a prompt, a log line or an error
   message. A model cannot leak what it never sees, and it has no tool through which it could send anything anywhere. The pipeline's
   AI jobs use the key the same way: the container is where it is used, and where the provider is reached from, for every call that has
   moved; the web and Celery containers no longer send it anywhere for those.
9. **Its words are shown as text.** Alerts and closing notes are rendered with `textContent` or Django's auto-escaping, never as HTML or
   Markdown. Links are removed from notes, so a note in a customer report can never carry a planted link.

## The pipeline's AI jobs

Before 1.4 the server called the AI provider itself, from the Celery workers, wherever the pipeline needed a model's answer. Those calls
move into the reviewer container, so the provider key is used, and the provider is reached, from one boxed-in place. The stages queue
**AI jobs** instead (`cveFeed.ai_jobs`, the `AIJob` table, scoped to a project where the work has one) and carry on; the answer is applied
when it lands.

1. **The stage queues a job.** It does everything it did before the call (the budgets, the caps, the deterministic ceilings, the claim on
   the evidence signature) and then queues one job: the stage's fixed system prompt; its parts in order, text cvENGINE wrote itself and
   data that came from a scanned host, a scanner or a feed; the answer schema; the request options (a pinned temperature and seed for a
   self-hosted server, the stage's own reply limit, whether a reply cut off at the limit is asked once more with twice the limit); and, for
   the RDP reading, one bounded image. Every string is masked for secrets first, as every prompt was. What the continuation needs (the claim,
   the rows, the facts the question was asked on) stays on the server and never leaves it.
2. **The container takes it.** `GET /api/v1/reviewer/jobs/next` hands out up to 20 queued jobs, most urgent and oldest first, each leased
   to the container for a while with a fresh lease token. A stage may hold a job back on a day whose budget is spent: a triage queued on an
   earlier day is counted again against today's caps when it is handed out, so a reviewer that was off for a week never spends more than a
   day's budget in a day.
3. **The container asks the model.** It fences each untrusted part between nonce markers (`guard.fence`), adds the trusted text as written,
   and makes the request the server used to make (`cvengine_reviewer.llm.complete`, ported from the server's provider layer): the same
   endpoints and bodies for Anthropic, the OpenAI-compatible servers (OpenAI, OpenRouter, vLLM, LM Studio) and Ollama, the same reply
   limits, structured output with its step-down when a server refuses it, the reasoning setting, Ollama's context window and keep-alive, and
   the same error categories. The provider settings stay where they were (Settings > AI model); the server resolves them, the `CVENGINE_AI_*`
   variables of its `.env` included, and hands them over in the job block of `GET config`.
4. **It posts the answer back.** `POST /api/v1/reviewer/jobs/<id>/result` carries the reply text, or the failure by category, and the
   token counts of each call (recorded as AI usage under the job's stage). An answer whose lease is not the job's current one is refused.
5. **The server checks and applies it.** A Celery task continues the stage: the stage's own validator checks the reply (`validate_triage`
   for a triage), and the answer is applied exactly as the stage applied it when it asked the model itself, through the same rules
   (`apply_rules`, the version-only ceiling, the heat caps, the tenancy rules on shared answers). A reply the validator rejects goes back to
   the model once, with why it was rejected and the reply fenced (`finding_triage_repair`); a second rejection, or a provider failure, is
   handled as a provider error was: the rows go to `error` with a diagnostic and the sweep asks again. Once applied, the job keeps its
   counts and drops its question and answer.

Nothing is lost on the way. A lease that runs out puts the job back in the queue (three times, then it fails and the stage asks again); an
answer whose Celery task was lost is applied by the housekeeping pass every five minutes; a job nobody answers within a week expires and its
stage asks again. Work that was in flight in the old code when an update restarted the server is simply asked again: its claim runs out
after ten minutes and the triage sweep queues it.

**When the reviewer is off.** With no AI provider configured, the stages queue nothing and behave as they always did without AI. With a
provider but no reviewer to serve the queue (`CVENGINE_REVIEWER=0`, the container stopped, scanning paused), jobs wait and nothing fails.
The reviewer card in Settings > AI model says "AI is waiting for the reviewer container" and why, and so does the server's status (an admin
alert after fifteen minutes).

Which stages go through the queue in this release:

| Stage | Kind | Usage stage |
| --- | --- | --- |
| Triage of every finding (CVE matches, scanner, route and hygiene findings) | `triage` | `finding_triage`, `finding_triage_repair` |
| Local-check suggestions for a match no external check can settle | `local_checks` | `local_check_suggestion` |
| Detection records and CVE guidance (the periodic authoring, Write guidance now, and an administrator's guidance through `update_cve_detection`) | `cve_detection` | `cve_detection` |
| The auto-tuner's advisor (its answer is judged by the next round, against the range in force then) | `autotune_advice` | `autotune_advisor` |
| The RDP login-screen reading (the screenshot travels in the job, at most 4 MB) | `rdp_screenshot` | `rdp_screenshot` |
| Nuclei template drafts for a CVE with no installed template (gated when they land, never run on a host) | `template_generation` | `template_generation` |

## Finding review in detail

- **Which findings.** Every finding with a triage record whose remediation status is open or in progress: CVE matches (Fire, Smoke and Ice),
  scanner findings and hygiene findings. Web routes have no remediation workflow and are left out. Fire comes first, then Smoke, then the rest,
  newest first.
- **Once per state.** A review is keyed by the finding's evidence key and its host's state fingerprint (`HostState.fingerprint`: IPs, ports
  with service and version, technologies, HTTP status and title). The same key is never reviewed twice. A new port, a new version or new
  evidence makes a new key, and the finding is read again.
- **What the model sees.** The finding kind and its heat, with the reason for that heat. The facts the triage built, with host names removed.
  The host context. The earlier triage classification, with its reason marked as model-written. The hard-evidence facts and the read-only
  validation results, which cvENGINE computed itself. Any injection flags. Whether the server could close the finding at all.
- **What it returns.** A verdict (`false_positive`, `true_open`, `true_in_progress`, `true_fixed`, `true_accepted_risk` or `uncertain`), a
  confidence, a reason code, and a closing note.
- **What happens.**
  - A verdict that passes the gates closes the finding as **False positive**, with no user set and this note: "Closed automatically: the AI
    reviewer (*model*) found this is a false positive. *note*". The change goes into the finding's audit trail and the activity feed.
  - Every other verdict is stored as the reviewer's assessment and shown on the finding.
  - A person can reopen a closed finding. A reopened finding is never closed again by the reviewer, because a person's status change counts as
    working it.

## Operations check in detail

The server computes the checks itself, every 30 minutes, whether or not an AI is configured. Each check reports `ok`, `warning` or `problem`,
the numbers behind that state, and the actions it allows:

| Check | Problem when | Action it can offer |
| --- | --- | --- |
| `sentinels_idle` | Live Sentinels finished no task in the last two hours while hosts are due | `feed_sentinels`: queue due hosts for the Sentinels now |
| `nuclei_templates` | The last template refresh failed or is older than a day, or a newer nuclei-templates release exists | `refresh_nuclei_templates` |
| `sentinel_errors` | Sentinel tasks that failed or that a Sentinel stopped reporting in the last six hours, grouped by Sentinel and kind. A task that expired only because no Sentinel slot was free is not counted here | none |
| `sentinel_waiting` | Tasks that expired waiting for a free Sentinel slot in the last six hours (an informational note: their targets stay due and are asked again) | none |
| `scan_errors` | Failed lines in the activity feed in the last six hours, by kind | none |
| `system` | Any problem `system_status` reports (workers, beat, disk, memory, feeds, certificates…) | none |
| `generated_templates` | AI-written templates have waited more than three days for a person's review | none |
| `ai_errors` | AI calls failed in the last 24 hours, by error category | none |

A check in `problem` opens an **admin alert**, a banner on every page for App Admins similar to the update banner. A check that is `ok` again
resolves its alert. An admin can dismiss an alert, and it stays dismissed until the problem changes.

The operations job then gives the model the checks. The model writes a diagnosis and next steps for each alert, and may ask for actions. The
server runs an action only when the check offered it at that moment, and no more often than its own minimum interval. To know whether a newer
nuclei-templates release exists, the reviewer container reads the newest release tag from GitHub's API itself, at a fixed URL. The model is not
involved in that request.

## Settings

**Settings > AI model > AI reviewer** (also `GET`/`PATCH /cve/api/settings/reviewer`):

| Setting | Default | Meaning |
| --- | --- | --- |
| Enabled | on | The reviewer works only when an AI provider is configured and this is on. |
| Review model | empty: `claude-sonnet-5-5` on Anthropic, else the provider's model | The model for finding review. |
| Operations model | empty: `claude-haiku-5-5` on Anthropic, else the provider's model | The model for the operations check. |
| Close false positives | on | Off: the reviewer records its verdicts and closes nothing. |
| Reviews per day | 300 | The most findings reviewed in one UTC day. |
| Operations hours (UTC) | 3, 9, 15, 21 | When the operations check runs. |

`CVENGINE_REVIEWER=0` in `.env` turns the reviewer off entirely: no token is written and the container idles.

## The API between the two

All routes are under `/api/v1/reviewer/` and need a `reviewer`-scope token. The server writes that token to the `reviewer_bootstrap` volume
(read-write for celery, read-only for the reviewer) and renews it before it expires. A reviewer whose token stops working reads the file again.

| Route | Purpose |
| --- | --- |
| `GET config` | Enabled flag, the provider, base URL, key and model per job, the limits, and whether the operations job is due; `jobs_enabled` and the job block (provider, address, key, model and request settings) for the pipeline's AI jobs |
| `GET findings/next?limit=N` | Up to N review packets, each leased for 15 minutes |
| `POST findings/<ref>/verdict` | One verdict. The answer says whether it was applied, recorded, held (and why) or stale |
| `GET ops/snapshot` | The checks above |
| `POST ops/report` | Diagnoses and requested actions. The answer says what was run |
| `GET jobs/next?limit=N` | Up to N (at most 20) of the pipeline's queued AI jobs, each leased with a fresh lease token |
| `POST jobs/<id>/result` | The answer to one job, or its failure category, with the lease token and the calls' token counts |

## Later

- Move the pipeline's remaining AI calls into the reviewer container the same way: validation planning, nuclei targeting, and the
  connection test and model list of Settings > AI model. Then the server makes no model call at all.
