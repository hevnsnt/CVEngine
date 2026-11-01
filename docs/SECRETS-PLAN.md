# Exposed secrets for 1.4: a secrets inventory built on Kingfisher

Status: plan for `1.4-develop`. Nothing in the Kingfisher work is built yet. It sits next to [SCANNER-ARCHITECTURE.md](SCANNER-ARCHITECTURE.md) (the 1.4
one-scanner plan from PR #278) and follows that plan's decisions: the scanning moves into the Sentinel, the built-in Sentinel does any work that touches a
credential, the shared code lives in `cvengine_scanner`, and the server decides policy and stores results. Slices S1 to S7 below target `1.4-develop`.
Slice S0 is a data-handling bug fix, not a Kingfisher feature, and is not part of this branch's work: its first half (stop secrets reaching the AI provider,
gate bbot's trufflehog) is being done separately on `develop` for 1.3.2, and its at-rest masking half is planned for 1.3.3 or 1.4 (section 12).

Sources read: `hevnsnt/CVEngine` `origin/develop` @ `c06b407`, `origin/1.4-develop` @ `e0f8c74`, `hevnsnt/cvengine-sentinel` @ `458997d`,
`mongodb/kingfisher` @ `67c1ad7` (v2.16.0), `projectdiscovery/nuclei-templates` HEAD (sparse checkout of `http/exposures/tokens` and `file/keys`),
and bbot 3.0.2 as installed from PyPI (the version `web/Dockerfile:15` pins). Citations are `file:line` on `origin/1.4-develop` @ `e0f8c74` (re-based from `develop`, where the lines differ in the files that diverged); `develop` is named
where a claim is about it. **Proven** means
the code or the docs show it. **Assumption** means it is inferred and has to be checked.

---

## 1. The case that started this: "Google API Key" on am.eu.fs.viq.zebra.com

### 1.1 What found it (proven)

- **Detector.** The nuclei template `http/exposures/tokens/google/google-api-key.yaml` (upstream: `severity: low`,
  `tags: exposure,token,google,vuln`). It makes **two** GET requests, `{{BaseURL}}` and `{{BaseURL}}/hopfully404`. It has no matcher, only a body regex
  extractor `AIza[0-9A-Za-z\-_]{35}`. The second request goes to a made-up path, and that is why the AI's reason talks about a 404 page: the key is in a page
  shell the site serves on every path. This is the usual sign of a browser key (Maps or Firebase web config), not of a leaked server secret.
- **Why the template was allowed to run.** The approved-template snapshot (`cveFeed/nuclei_scan.py:128-195`) keeps every template that passes
  `validation.readonly_problem` (`cveFeed/validation.py:94-160`): plain GET/HEAD, no payloads, no OAST. All 218 upstream `http/exposures/tokens/*` templates
  are plain GETs. The `file/keys/*` templates (156 of them, also secret regexes) are excluded, because `file` is in `templategen.FORBIDDEN_PROTOCOLS`
  (`cveFeed/templategen.py:41`) and in `validation.READONLY_FORBIDDEN_KEYS` (`cveFeed/validation.py:51-52`).
- **Which pass ran it.** It could only be one of two:
  - the **weekly deep nuclei** pass (`cveFeed/tasks.py:1407-1484`). It is untagged and runs every approved template at `info` and above (`BASE_FLAGS`,
    `cveFeed/nuclei_scan.py:34-35`) against `host` plus `host:port`, and it is dispatched as the Sentinel kind `nuclei_deep` (`tasks.py:1467`);
  - the **AI-targeted** pass (`cveFeed/nuclei_scan.py:730-800`, kind `nuclei_targeted`), if the static table, the template index or the model picked the
    `google` tag. `exposure` is in `NOISE_TAGS` (`cveFeed/nuclei_templates.py:259`), so it is never offered, although a model answer naming it is still
    accepted against the installed tags.

  The light pass is ruled out: it is forced to `-tags tech -severity info` (`nuclei_scan.py:42`, `agentapi/sentinel_dispatch.py:467-468`). The finding row
  does not record which pass produced it (gap G9). The activity log tells them apart: "nuclei targeted scan of <host>: …" versus "Weekly deep Nuclei
  checking <host>".
- **How the finding was saved.** `parse_nuclei_result` (`reNgine/tasks.py:337-363`) keeps `extracted_results`, the raw `request` and `response`, and the
  `curl_command`. `save_vulnerability` (`reNgine/tasks.py:534-610`) deduplicates on `VULNERABILITY_KEY = (target_domain, scan_history, subdomain, endpoint,
  source, template_id, name, http_url, matcher_name)` (`reNgine/tasks.py:510-511`).
- **Why there are 4 findings (assumption).** Rows differ by `http_url` (matched-at) and by scan. With two request paths, each scanned base URL gives at least
  two rows (`/` and `/hopfully404`). A second base (a non-default port target, `nuclei_scan.build_targets`) or a second scan doubles that. Listing the 4 rows'
  `http_url` and `scan_history` (MCP `get_finding`) settles it. Either way, it is **one key**, and nothing groups it.
- **Where "Credentials served on /" (+25) comes from (proven).** This is a second, independent detector. The route check
  (`cveFeed/route_auth.py`, stage `route_auth_scan`, `cveFeed/discovery.py:652-655`) GETs `/` and runs `analyse` (`route_auth.py:273-284`), which calls
  `sensitive.scan_text` on up to 64 KB of the body (`ROUTE_SAMPLE_BYTES`, `route_auth.py:40`). `PATTERNS['google_key']` (`cveFeed/sensitive.py:22`) matches,
  any credential type scores 25 (`sensitive.py:159-171`), and scoring prints "Credentials served on /" (`cveFeed/scoring.py:97-103`). This path stores no
  value: only the type, the count and a sample with the length and the public prefix (`sensitive.py:92-110`).
- **What the AI saw.** `describe_vulnerability` (`cveFeed/triage.py:358-394`) puts `extracted_results` (the raw key) into the triage payload. The
  `TRIAGE_FORBIDDEN_KEYS` list (`reNgine/ai_providers.py:755-756`) does not include `extracted_results`, and the strict character filter keeps the
  characters a typical key is made of: letters, digits and `_ - . / + =` (`_SAFE_CHARS`, `ai_providers.py:180`). **The full key was sent to the AI provider.** See G1.

### 1.2 How this specific case would come out under this plan

The inventory gets one `SecretFinding`: provider Google, kind `google-api-key`, masked `AIza…` plus the last 4 characters, class P (browser key, possibly
public by design). It carries occurrences for every URL and source (nuclei ×4, route check ×1, later Kingfisher). Severity is info, with the reason "a browser
key served in the page shell; Google API keys are meant to be embedded and are protected by referrer and API restrictions; confirm the restrictions in the
Cloud console". If the project opted in to validation (section 5), Kingfisher's read-only Google validator reports whether the key is referrer-restricted and
whether it can reach the Gemini API, and severity rises only when it is unrestricted. The route score drops from 25 to 5, because a class-P credential is not
a leaked server secret. The AI never sees the key.

---

## 2. What exists today: every secret, credential and exposure detector (proven)

| # | Detector | Where | What it reads | What it stores | Gaps |
|---|---|---|---|---|---|
| D1 | Route sensitive-data scan | `cveFeed/sensitive.py`, called from `route_auth.analyse` (`route_auth.py:273-284`) | Up to 64 KB of each route body. At most 20 URLs per host (`MAX_URLS_PER_HOST`, `route_auth.py:34`): the 10 `COMMON_PATHS` plus 12 EndPoint paths, 2 bases per host | `RouteAuth.sensitive` holds counts and a masked sample, never the value (`sensitive.py:1-5`). Scores 25 for any credential (`sensitive.py:164-165`) | 7 credential regexes only (AWS key ID, AIza, Slack, GitHub classic, Stripe live, JWT, PEM header). `.js` and `.map` are excluded from the paths (`STATIC_EXT`, `route_auth.py:48`). No provider diagnosis beyond a label, no cross-host identity, a browser key scores like a server secret. `google_key`'s trailing `\b` misses keys that end in `-` |
| D2 | Front-page scripts | `route_auth._read_scripts` (`route_auth.py:351-372`), `fingerprint.script_sources` (`cveFeed/fingerprint.py:139-156`) | Up to 4 same-host scripts of `/` only (`route_auth.py:209`), 64 KB each | Library fingerprints only | **The fetched JS is never scanned for secrets.** Cross-origin scripts are never fetched. Source maps are never fetched |
| D3 | nuclei token templates | `nuclei_scan._run_nuclei` (`nuclei_scan.py:400-518`), Sentinel `nuclei_targeted` / `nuclei_deep` | 211 of the 218 upstream templates GET `{{BaseURL}}` only (counted on upstream HEAD; the installed set may differ) | `Vulnerability.extracted_results` = **raw key** (`startScan/models.py:439`), `response` = **raw body** (`models.py:457`) | Root page only, one row per URL and scan, the full value shown everywhere (G2) |
| D4 | bbot `badsecrets` (standard and deep) | bbot `web` preset, `-rf safe` (`reNgine/bbot.py:30`). In 3.0.2 the `web` flag covers baddns, badsecrets, bucket_amazon/google/firebase/microsoft, filedownload, git, graphql_introspection, http, ntlm, oauth, robots, securitytxt, sslcert | HTTP responses bbot fetches | FINDING text "Known Secret Found … Secret: [<value>]" saved as `Vulnerability.description` (`reNgine/tasks.py:195-208`) | Raw secret at rest and in the AI prompt (G1) |
| D5 | bbot `excavate` JWT extractor | built into bbot (`excavate.JWTExtractor`) | All responses | A FINDING "contains JSON Web Token" | Noise, no decoding |
| D6 | bbot `trufflehog` (**deep mode only**) | `kitchen-sink` includes `code-enum` (`reNgine/bbot.py:31`). bbot's trufflehog defaults to `only_verified: True`, never passes `--no-verification`, and watches `HTTP_RESPONSE`, `CODE_REPOSITORY` and `FILESYSTEM` with `scope_distance_modifier = 2` | Every HTTP body, plus code repositories, Docker images and Postman workspaces up to 2 hops out | Description includes "Raw result: [<secret>]" | **Live third-party verification of every found secret, with no cvENGINE gate** (G3). Raw secret at rest and to the AI |
| D7 | bbot bucket modules | `web` preset (D4) | Bucket names bbot derives | `STORAGE_BUCKET` events shown in the live feed only (`bbot.py:39-40`). Open ones arrive as LOW FINDINGs | Not linked to `bucket_scan` |
| D8 | Bucket scanner | `cveFeed/bucket_scan.py`, `bucket_probe.py` (background sweep, `cveFeed/tasks.py:83`) | References from CNAMEs, storage server headers, EndPoint URLs, RouteAuth redirects and **stored nuclei responses** (`bucket_scan.py:301-318`), plus name guesses | `bkt_*` hygiene findings. The probe is anonymous, verified HTTPS, GET/HEAD to documented S3/GCS/Azure endpoints only (`bucket_probe.py:131-171`), one listing page, one HEAD, never an object body | No Firebase RTDB, Firestore or registries. Never reads page or JS bodies (they are not stored). Sentinel-run nuclei drops `response` (`agentapi/sentinel_dispatch.py:446-452`), so with Sentinels the "scanner response" tier is empty |
| D9 | Triage | `cveFeed/triage.py:358-394`, `reNgine/ai_providers.py:855-867` | Vulnerability rows and routes | Payload goes to the AI provider | Route payload is clean: counts only (`triage.py:402-413`). **Nuclei `extracted_results` and the bbot `description` carry raw secrets** |

Other places a raw secret shows up today (proven):

- `how_found` "Extracted" and response excerpts up to 4096 characters in `finding_detail`, which serves REST, MCP and the UI (`agentapi/services.py:3265`, `3370-3375`).
- Report exports (`cveFeed/report_data.py:212`).
- Bug-bounty drafts (`cveFeed/bounty_report.py:159`, `cveFeed/bounty_api.py:510`).
- The Sentinel result path, which carries up to 20 × 300 characters of `extracted_results` (`agentapi/sentinel_broker.py:1762-1769`). That is acceptable in
  transit, but it ends up in the same columns.

Logs and activity lines carry only names and severities (`nuclei_scan.py:486-492`), and the bbot stderr redaction covers only cvENGINE's own API keys
(`reNgine/bbot.py:302-317`).

Existing safety machinery this plan reuses:

- `reNgine/crypto_fields.py`: Fernet field encryption, a dedicated `CVENGINE_FIELD_KEY`, `rotate_field_key`.
- `tenancy/scope.py` (`SCOPES`): per-model project isolation.
- `cveFeed/bounty_gate.Gate` (`bounty_gate.py:63-90`), `conductor.bounty_blocked_projects` (`conductor.py:49-58`): bounty scope and automated-testing
  confirmation.
- `exclusions.excluded_names`, `route_auth.host_allowed` (the SSRF gate), `pinned_transport`, `egress_proxy`.
- The Sentinel secure read: `POST /sentinel/tasks/<id>/secret`, dormant on 1.4-develop (SCANNER-ARCHITECTURE.md "Signed-in work").
- Approved-bundle distribution (`agentapi/template_bundle.py`), the ledger TTLs (`cveFeed/ledger.py`), `fake_scanner` tests (1.4-develop).

## 3. Gaps

- **G1. Secrets reach the AI provider.** Nuclei `extracted_results` (`triage.py:364`, `387-388`) and the bbot `description` (`triage.py:379-381`) send raw
  secrets. `_triage_clean` keeps up to 3000 characters per string (`ai_providers.py:855-859`).
- **G2. Secrets stored and shown in clear.** `Vulnerability.extracted_results`, `response`, `description`, `how_found`, PDF and CSV exports, bounty drafts,
  MCP `get_finding`.
- **G3. bbot deep mode verifies third-party credentials live**, outside every cvENGINE gate, including credentials found up to two hops out of scope (D6).
- **G4. Coverage is shallow.**
  - 7 regexes in D1, and nuclei only on `/`.
  - Missing: AWS secret keys (only the AKIA IDs), GCP service-account JSON, Firebase config objects, Stripe restricted keys (`rk_` is covered, `pk_live`
    and `sk_test` are not), Slack webhooks, GitHub fine-grained `github_pat_`, GitLab `glpat-`, Twilio, SendGrid `SG.`, Mailgun, Mapbox `sk.`, npm, PyPI,
    OpenAI and Anthropic keys, Azure storage connection strings and SAS `sig=`, database URLs with passwords, `ENCRYPTED PRIVATE KEY` PEMs (not matched by
    `sensitive.py:27`), basic-auth URLs and `.env` bodies.
  - JS bundles are fetched but not scanned. Source maps are never fetched.
- **G5. No identity across hosts or scans.** The same key on 30 hosts is 30 or more rows (D1 per route, D3 per URL and scan).
- **G6. No inventory, no provider diagnosis** (who issued the key, what kind it is, the likely blast radius), and no status (public by design, revoked, false
  positive).
- **G7. No liveness or scope**, and no safe, gated way to get them (G3 is the unsafe way that exists).
- **G8. Discovered resources are not followed.** No Firebase RTDB, Firestore or registry checks. Storage links in JS and page bodies never reach
  `bucket_scan`. Sentinel-run nuclei loses the response tier (D8).
- **G9. A finding does not record which nuclei pass produced it**, and the severity of a browser key is the template's own (`low`) with nothing to adjust
  it. The route score overweights browser keys (25).

## 4. Goals and non-goals

**Goals**

1. One project-scoped **secrets inventory**. A secret is one row however many hosts, URLs, scans and detectors saw it. Each row has the provider, kind,
   masked preview, keyed fingerprint, occurrences, first and last seen, confidence, status and severity, with the reason for the severity.
2. **Kingfisher** is the detection engine (owner decision). It runs over HTTP bodies the scanner fetches anyway, plus same-origin JS bundles and their source
   maps. Bounded, `--no-validate` by default.
3. **Static provider diagnosis** from the rule ID and the key format, with severity rules that tell browser keys that are public by design apart from server
   secrets.
4. **Optional, gated, read-only liveness** using only Kingfisher's own validators, on an allow-list, from the built-in scanner only.
5. **Follow discovered resources** (storage buckets, Firebase RTDB, source maps) into `bucket_scan` and a new scope-guarded resource-exposure check.
6. **No secret value** in the UI, REST, MCP, logs, AI prompts or exports by default. Values are encrypted at rest only when the opt-in requires it.
7. **Fix G1, G2 and G3 first**, independent of Kingfisher.

**Non-goals**

- No `kingfisher revoke`, ever. The client refuses the subcommand, and the contract has no field for it.
- No Kingfisher remote sources (`scan s3://…`, `gs://…`, Azure blob, Docker, Hugging Face, GitHub orgs). They download contents, which breaks the "never
  download contents" rule for storage.
- No use of a found credential beyond Kingfisher's allow-listed read-only validator. No API exploration and no "what can I read with it".
- No crawling, spidering or brute force. Only URLs the pipeline already knows, plus same-origin scripts and their declared maps.
- No AI involvement in secrets: no triage call, no prompt, no spend.
- No reveal-value button in 1.4.
- No secret scanning of git repositories or the org's GitHub (bbot `code-enum` territory). That would be a separate design.

## 5. Safety policy

### 5.1 Detection (always on when the feature is on)

- Kingfisher runs with `--no-validate --no-update-check`. As defence in depth, the run's proxy environment points at a closed local port
  (`HTTPS_PROXY=http://127.0.0.1:9`, `NO_PROXY=` empty), so any unexpected egress fails closed. A Sentinel CI test proves the no-validate run sends no
  packets (it runs in a network namespace with no route and must finish with exit code 0, 200 or 205).
- The fetcher is the same bounded, anonymous GET the route check uses (no cookies or credentials, no redirects followed, pinned resolution, the SSRF floor,
  the bounty `Gate`, exclusions, the per-host request gap). It only fetches:
  - URLs on hosts in the task's scope policy;
  - same-origin `<script src>` targets of pages already probed;
  - `sourceMappingURL` targets on the same origin as their script.
  Caps: 8 scripts per host, 2 MB per script, 8 MB per map, 32 MB in total per task.

### 5.2 Validation (off by default; three locks)

1. **Project opt-in** `secrets_validation`. Only an Org Owner or App Admin can turn it on. The switch shows the attestation "the targets of this project and
   the cloud and SaaS accounts behind them are ours, and we authorise read-only credential checks against them". Who accepted it and the attestation text are
   recorded in the audit log.
2. **Gates.** A project in a bug-bounty engagement **never** validates, whatever its confirmation. Program rules almost always forbid using found
   credentials, and cvENGINE cannot read a program's exceptions reliably. `Gate.refusal(project, host)` must also pass for the host where the secret was found.
3. **Per-rule allow-list.** Only Kingfisher rule IDs whose validator is a read-only identity or metadata call are listed in
   `web/cveFeed/data/secrets_validation_allowlist.json` as `{rule_id: sha256(validator block)}`. A CI test extracts the validator blocks from the pinned
   Kingfisher rule bundle (`kingfisher-rule-bundle.tgz`, attested like the binary). If a hash changes, the rule leaves the allow-list until a person
   re-reviews it.

   Rules for the list: no POST except named identity endpoints (for example Slack `auth.test`), no billable method, no write. The first list covers AWS
   access key + secret (`sts:GetCallerIdentity`), GitHub PAT (`GET /user`), GitLab PAT (`GET /user`), Slack (`auth.test`), the Google API key (Kingfisher's
   `getProjectConfig` and the `models` list: read-only, non-billable) and SendGrid (`GET /v3/scopes`). Each one is checked against its rule text in the pin
   PR.

Mechanics:

- Validation runs only in the **built-in scanner**: a validating task carries `validate: true`, and the broker's `refusal` keeps it from external
  Sentinels, like `secret_ref`.
- It runs at detection time, as a second Kingfisher pass over the same temp directory: `--rule <allow-listed ids>`, `--validation-rps 1`,
  `--validation-timeout 10`, `--validation-retries 0`, `--tls-mode strict`, `--allow-internal-ips` off. At most one validation per distinct secret per
  7 days (server-side ledger `secrets-validate`).
- **Access map (blast radius) is not in 1.4.** It enumerates the key owner's IAM and resources, which is real use of the credential. It moves to the 1.5
  backlog with its own fourth lock.
- Audit lines: `secrets.validation.requested` and `secrets.validation.result`. They record the project, the inventory ID, the rule ID and the outcome, never
  the value, never the provider response. Kingfisher's `validation.response` is dropped at the Sentinel and again in `clean_result`.

### 5.3 Third-party credentials

A key found on an in-scope host can belong to a vendor (an analytics or maps account), not to the target. The attestation in 5.2 covers only the
organization's own accounts. That is why validation is opt-in per project, why its allow-list is identity-only, and why bounty projects never validate.

**Legal note (not legal advice).** Authenticating to someone else's account with a credential issued to them, even read-only, can be unauthorised access
under the US CFAA (18 U.S.C. 1030), the UK Computer Misuse Act 1990 s.1 and EU Directive 2013/40/EU art. 3. The provider also logs the call against the key
owner's account. Detection without validation is ordinary observation of what a site serves.

### 5.4 Resource exposure (section 9)

- Anonymous and read-only, on documented provider endpoints only. Never an object body, never a write.
- "Public listing" is answered with one listing page, as `bucket_probe` does today.
- A Firebase RTDB answer stores only "readable / locked / missing", never a key name.
- Third-party (`reference`-tier) resources keep the existing tier rules: medium at most unless the name carries the project's label
  (`bucket_scan.py` docstring, lines 17-22).

### 5.5 Redaction

The value exists:

- in Sentinel memory and the task temp directory (removed when the task ends, however it ends);
- in the result body over the authenticated TLS channel;
- in server memory for the duration of `persist_secrets_result`;
- encrypted at rest **only** when 5.2 is on: `SecretFinding.value_enc` (`EncryptedTextField`), purged 30 days after the last validation or immediately when
  the status becomes `revoked` or `false_positive`.

Everywhere else the value is `masked` (format prefix + `…` + last 4; a PEM shows its header only, as in `sensitive.sample`) or the fingerprint.

## 6. Architecture

### 6.1 Where it runs: a new Sentinel kind `secrets_scan` (recommended; no server-side path)

The options were scanning on the server over stored bodies, or a Sentinel kind. **Recommendation: a Sentinel kind, with no local fallback.**

- **Bodies are not stored.** `route_auth.analyse` drops the body after classification (`route_auth.py:273-284`). Only nuclei responses are kept, and only for
  local runs. "Scanning stored bodies" would mean storing bodies first, which this plan does not want.
- **1.4 is moving every fetch to the scanner.** Route probes, bucket probes and probes leave the server (SCANNER-ARCHITECTURE.md §C, phase 7). The server
  image is losing its scan tools (phase 8), so adding a Rust binary to it goes the wrong way.
- **The scanner is the vantage point.** It enforces the scope policy on every hop.
- **Parity is automatic.** External Sentinels get detection. The built-in gets validation too.

Shape:

- **Kind** `secrets_scan`, `kind_since` = the contract version that ships it. Recommendation: the 1.4 contract bump that adds the new kinds. The contract on `1.4-develop` is at version 2 (it added `waf`), so that is
  v3; if v3 is already taken when this lands, take the next number. A bump is stated in the CHANGELOG, as the contract file requires.
- **No local run.** `CVENGINE_LOCAL_FALLBACK` never lists it. With no live Sentinel declaring it, the stage reads as waiting, as the existing
  `scanner_state` does. Until then, D1 and D3 still feed the inventory (S1), so a server without a scanner still gets an inventory.
- **Dispatch.** A new pipeline stage `secrets_scan` runs right after `route_auth_scan` (`cveFeed/discovery.py:652-655`), so it can use the routes just
  probed. The target is one task per batch of up to 25 hosts:
  - per host, the probed URLs (RouteAuth rows with a 2xx or 404 status and a text content type, up to 20) and the root page's same-host script URLs (stored
    by S2 in `RouteAuth.evidence['script_urls']`, up to 8; today they are popped and lost, `route_auth.py:357`);
  - the scope policy (in-scope names, exclusions, range floor);
  - the limits;
  - `validate` and the allow-listed rule IDs (built-in only);
  - the custom-rules bundle sha256.
- **Ledger.** Service `secrets-scan`, TTL 7 days per host (`CVENGINE_TTL_SECRETS`). The weekly re-check rides the host refresh feed.
- **Phase-7 convergence.** When the route and probe stage moves into the Sentinel, it calls the same `cvengine_scanner.secrets.scan_dir()` over the bodies
  it already holds. `secrets_scan` then fetches only scripts and maps, so the extra traffic drops to near zero.

### 6.2 Kingfisher invocation (in `cvengine_scanner/secrets.py`, used by `client/tools.py run_secrets_scan`)

```
kingfisher scan <task_tmp>/in --format json --output <task_tmp>/out.json
  --no-validate --no-update-check --no-dedup --git-history=none --no-extract-archives --no-binary
  --max-file-size 8 --confidence medium --validation-filter all --no-rule-cache --jobs 2
  [--rules-path <task_tmp>/custom.yml] [--skip-word … --skip-regex …]
```

Flags were checked against `docs/CONFIG.md` and `docs/USAGE.md` at v2.16.0. The PR adds a CI test that runs `kingfisher scan --help` on the pinned binary and
fails on any flag that is missing.

- **`--no-dedup` is required.** Kingfisher's default dedup groups identical credentials across paths (`docs/FINGERPRINT.md`), which would lose the URL of
  every occurrence after the first. cvENGINE deduplicates on its own fingerprint.
- **Inputs.** One file per fetched body, named `<n>.<ext>`, plus `manifest.json` mapping `n` to URL, status and content type. Text types only, the same as
  `sensitive.is_text`.
- **Paths, not stdin.** The output's `finding.path` maps back to the URL. Stdin (`-`) would lose the attribution.
- **Limits.**
  - Wall clock: 300 s per task, killed with the process group, the same way `heavy_process` and `client._run` do.
  - Output: `out.json` is read up to 16 MB, at most 500 findings (a `truncated` flag is set when more), the secret field capped at 1 KB (8 KB for a PEM).
  - The whole result stays under the client's `MAX_RESULT_BYTES` (`client/daemon.py:65`).
- **Memory.** Not measured in this research; running the downloaded binary was not permitted here. **S3 must measure peak RSS** of the full rule set on a
  32 MB input before choosing:
  - the Sentinel's default per-kind `max_concurrent` for `secrets_scan` (recommendation: 1);
  - the image's documented memory addition (expected about 200 to 400 MB, an assumption).
  
  The server's `heavy_job` does not apply because there is no server path. If one is ever added, it must be `heavy_job('secrets', cost=<measured>)` with
  `MAX_CONCURRENT 1` (`reNgine/resources.py:41-54`).
- **Exit codes.** 0, 200 and 205 are success, 3 means "no inputs", anything else is an error with Kingfisher's last stderr line (`docs/USAGE.md` "Exit
  Codes").

### 6.3 Shipping the binary

- **Images.**
  - The **Sentinel image**, which the 1.4 plan makes the built-in scanner: `ARG KINGFISHER_VERSION=2.16.0`, `ARG KINGFISHER_SHA256_AMD64`,
    `ARG KINGFISHER_SHA256_ARM64`, then download `kingfisher-linux-{x64,arm64}.tgz` and check it with `sha256sum -c`, the same pattern as Go, nmap and
    testssl in `cvengine-sentinel/Dockerfile:9-28`.
  - The archive carries its own `CHECKSUM.txt` and NOTICE files. Keep `notices/` in the image under `/usr/share/doc/kingfisher/` (Apache-2.0 and the
    Vectorscan NOTICE).
  - The server image gets **no** Kingfisher.
- **Attestation.** It is verified in CI, not in the Docker build (which stays offline and reproducible). A new step in the Sentinel repo's pin workflow
  runs it (cvENGINE's `tool-release-gate.yml` only runs `scripts/check_tool_versions.py` for pins held in this repository, and Kingfisher's pin is not one of them):

  `gh attestation verify kingfisher-linux-{x64,arm64}.tgz --repo mongodb/kingfisher --signer-workflow mongodb/kingfisher/.github/workflows/release.yml --source-ref refs/tags/v$VERSION --bundle multiple.intoto.jsonl`

  It then asserts that the sha256 of the verified file equals the `ARG`. This is the exact procedure Kingfisher documents (`docs/INSTALLATION.md` "Verifying
  release artifacts"). The same is done for `kingfisher-rule-bundle.tgz`, which the allow-list test reads (5.2).
- **Pin check.** `scripts/check_tool_versions.py` reads pins only from files in this repository (the `TOOLS` table, lines 100-115, which holds
  `web/Dockerfile`, `web/requirements.txt`, `docker-compose.yml` and `build-pr.yml` pins). It does not read the Sentinel Dockerfile, although
  SCANNER-ARCHITECTURE.md "Why" says it checks both; the built-in scanner is built from a pinned Sentinel commit (`docker-compose.yml`). So the Kingfisher
  "newest release" check lives in the Sentinel repo's own workflow (S3), as a `latest_github_tag` check on
  `https://api.github.com/repos/mongodb/kingfisher/tags?per_page=30`. If the script later learns to read the Sentinel Dockerfile at the pinned commit, add a
  `TOOLS` row for `ARG KINGFISHER_VERSION=([0-9.]+)` then.
- **SBOM and notices.** The server image gets no Kingfisher, so `scripts/generate_sbom.py tools()` (which reads `web/Dockerfile`) does not list it. The
  component (`pkg:github/mongodb/kingfisher@v...`, hashes for amd64 and arm64) goes into the Sentinel image's SBOM when phase 2 publishes that image by
  digest, and `THIRD-PARTY.md` gets an entry with the Apache-2.0 licence when the built-in scanner ships it.
- **PyPI `kingfisher-bin` is not used.** It is a second supply path. One verified tarball per architecture is enough.
- **Updates.** Through the normal pin bump and nothing else. `--no-update-check` is always passed, and `kingfisher self-update` is never called; the client
  refuses argv containing `self-update` or `revoke`.

### 6.4 Results contract (`sentinel_contract.json`)

**Targets half**

```
{hosts:[{host, urls:[≤20], script_urls:[≤8]}],
 scope:{names:[…], exclusions:[…]},
 limits:{max_scripts_per_host:8, max_script_bytes:2097152, max_map_bytes:8388608, max_total_bytes:33554432, follow_sourcemaps:true},
 validate:false, validate_rules:[], rules_bundle_sha256:null}
```

**Results half**

```
{findings:[{rule_id, rule_name, url, line, confidence, entropy, secret, validation:{outcome}, validation_meta:{…allow-listed keys…}}],
 fetched:[{url, status, bytes, content_type, kind: page|script|sourcemap, sourcemap_of?}],
 references:[{kind: s3|gcs|azure|firebase_rtdb|firebase_storage|gcr|ecr|ghcr|dockerhub, value, url}],
 stats:{files, bytes, findings, truncated, kingfisher_version, rules_loaded}}
```

- `references` are extracted in the scanner from the same bodies, using `bucket_scan.refs_from_text`, which moves into `cvengine_scanner` with the bucket
  probe (§C) plus a Firebase pattern.
- `clean_result` server checks:
  - `rule_id` must match `^[a-z0-9][a-z0-9._-]{0,119}$`;
  - `url` must be one of the task's fetched URLs;
  - `secret` must be a string of 8 to 8192 characters;
  - `validation.outcome` must be one of Kingfisher's six (`docs/USAGE.md:2127-2139`) or `not_attempted`;
  - `validation_meta` keeps only allow-listed keys (`restriction`, `active_google_key`, `gemini_access`, `account_type`), with string values ≤ 60
    characters;
  - everything else is dropped, `validation.response` always.

## 7. Data model (server, `cveFeed`)

```
SecretFinding                      # the inventory row: one per project and secret
  project FK, domain FK (first)    # tenancy/scope.py: 'cveFeed.SecretFinding': 'project_id'
  fingerprint  char(64)            # HMAC-SHA256(fp_key, normalised value); unique (project, fingerprint)
  fp_version   smallint            # bumps if normalisation or key changes
  provider     char(40)            # 'Google', 'AWS', 'Stripe' ... from secrets_catalog
  kind         char(60)            # 'google-api-key', 'aws-access-key-pair', 'firebase-web-config' ...
  klass        char(1)             # P publishable/browser, S server secret, I identifier only
  rule_ids     ArrayField(char)    # every detector rule that matched it (kingfisher ids, 'nuclei:google-api-key', 'route:google_key')
  masked       char(80)            # 'AIza…x7Qz', 'AKIA…MPLE', 'PEM RSA PRIVATE KEY'
  length       int
  confidence   char(10)            # max of occurrences
  severity     smallint, severity_basis char(300)
  status       char(20)            # unverified | live | inactive | inconclusive | public_by_design | accepted | revoked | false_positive
  status_by FK user null, status_at, status_note text
  validation_outcome char(20), validated_at, validation_meta JSON (sanitised, ≤1 KB)
  value_enc    EncryptedTextField null   # only while projects's secrets_validation is on (5.5)
  first_seen, last_seen, occurrence_count, host_count
  remediation_status / assignee   # same workflow fields as Vulnerability and HygieneFinding (STATUS_KINDS)

SecretOccurrence                   # where it was seen
  finding FK, project FK, domain FK, scan FK null
  host char(255), url char(2000)   # query string dropped
  source char(20)                  # kingfisher | nuclei | route | bbot
  rule_id char(120), line int null
  vulnerability FK null            # the nuclei/bbot row it came from
  first_seen, last_seen, retired_at null
  unique (finding, url, source, rule_id)

ResourceRef                        # a resource a body points at
  project FK, domain FK, host, found_url
  kind char(20), identifier char(255)   # bucket / db name / registry repo
  secret FK null                   # e.g. a Firebase config's databaseURL next to its apiKey
  first_seen, last_seen
```

- **Fingerprint key.** A random 32-byte key generated once per install and stored encrypted (`SecretFingerprintKey` singleton, `EncryptedCharField`). It is
  not derived from `SECRET_KEY`, because then `rotate_field_key` would split every inventory row. A database dump alone then cannot confirm a guessed
  secret.
- **Kingfisher's own fingerprint is not stored.** It is an unkeyed XXH3-64 of the secret plus byte offsets (`docs/FINGERPRINT.md`). It is not useful as an
  identity across URLs, and it is a weak hash of the value.
- **Normalisation.** Strip surrounding quotes and whitespace. An AWS pair is fingerprinted on the secret half, so the same pair seen with different key IDs is
  still one secret.
- **Migration.** One schema migration. There is no data migration of existing rows: S1's backfill command reads the existing `Vulnerability` and `RouteAuth`
  rows lazily.

## 8. Mapping and severity

### 8.1 `cveFeed/secrets_catalog.py` (pure, tested)

The catalog maps a rule-ID pattern to `(provider, kind, klass, base severity, remediation, docs link)`. For example:

- `betterleaks.gcp-api-key`, `nuclei:google-api-key` and `route:google_key` map to Google, `google-api-key`, P;
- `*aws-access-token*` maps to AWS, `aws-access-key-id`, I, upgraded to `aws-access-key-pair` (S) when a secret-key rule matched in the same file;
- `*private-key*` maps to no provider, `private-key`, S.

An unknown Kingfisher rule falls back to the provider token from its ID, class S, medium, and is flagged "uncatalogued". A CI test lists the uncatalogued IDs
in the pinned bundle as a warning, never as a failure.

### 8.2 Severity (deterministic, no AI)

| Class | Unverified | `live` (opt-in) | `inactive` | Notes |
|---|---|---|---|---|
| P: browser keys (Google API key, Firebase web config, Stripe `pk_live`, Mapbox `pk.`, Algolia search-only, Sentry DSN, reCAPTCHA site key, OAuth client ID) | info, "likely public by design" | low, raised to medium if `validation_meta` shows no restriction and access to a sensitive or billable API (for Google, `gemini_access: true` with no referrer or IP restriction) | info | the person can mark it `public_by_design` |
| S: server secrets (AWS key pair, GCP service-account key, Azure storage key or SAS, Stripe `sk_live` and `rk_live`, Slack bot and user tokens, GitHub and GitLab PATs, Twilio, SendGrid, Mailgun, OpenAI and Anthropic keys, PEM private keys, DB URLs with a password) | high | critical | low ("rotate and remove anyway") | a secret in a source map or bundle is the same severity as one in HTML |
| I: identifiers (AWS key ID alone, Slack or Discord webhooks treated as medium, JWT) | low (JWT: medium if not expired by its `exp` claim, which is decoded without verifying the signature) | n/a | n/a | |

Status overrides severity:

- `public_by_design`, `accepted` and `false_positive` count for nothing in the score.
- `revoked` resolves the finding when it is no longer seen.

Host scoring changes in `sensitive.sensitive_score` and `scoring._sensitive_line`:

- class-S credentials score 25;
- class-P credentials alone score 5;
- the line reads "Server credential served on /" or "Browser key served on /".

When the inventory has the secret, `scoring` reads the worst open `SecretFinding` of the host instead of the route sample, capped at the existing
`SENSITIVE_CAP`.

### 8.3 Existing nuclei token findings (fast path kept, linked)

- The templates keep running. They are cheap and need no Sentinel.
- When a nuclei finding comes from a token template (template path under `http/exposures/tokens/` or tags ⊇ {`token`}) or from a bbot badsecrets or
  trufflehog finding, `save_vulnerability`'s caller:
  1. computes the fingerprint and upserts a `SecretFinding` and a `SecretOccurrence(source='nuclei', vulnerability=v)`;
  2. replaces `extracted_results` with the masked value;
  3. sets `response` to the status line and headers only, with the body removed.
- The finding detail shows "Tracked in Secrets: AIza…x7Qz (Google API key, likely public by design)", and its severity follows the inventory row.
- The 4 rows stay, linked to one inventory row. The finding list can group them (rows whose `SecretOccurrence` points to the same finding).
- The route detector D1 feeds the inventory in the same way at `_persist` (`route_auth.py:664-722`). The value is in memory there, so the fingerprint is
  computed before the body is dropped, and the stored sample stays as it is.

## 9. Following discovered resources (S5)

- **Storage buckets.** `references` from `secrets_scan` (S3, GCS, Azure, Firebase Storage `<project>.appspot.com` and `<project>.firebasestorage.app`) are
  stored as `ResourceRef`. `bucket_scan.collect` (`bucket_scan.py:271-343`) gains a fourth reference source, "page and script content". Firebase Storage is
  checked as GCS. Tiers, severities, `name_match`, exclusions and pacing are unchanged.
- **Firebase RTDB.** `bucket_probe.check_firebase(db)`:
  - one GET of `https://<db>.firebaseio.com/.json?shallow=true&limitToFirst=1&orderBy=%22$key%22` (also the `*.firebasedatabase.app` regional hosts),
    added to `_ENDPOINTS` (`bucket_probe.py:131-134`), on the same verified-HTTPS fetch;
  - 200 with a JSON object or `null` means readable, stored as "public read", key names never stored;
  - 401 "Permission denied" means locked, an observation only;
  - 404 or "Firebase error" means missing, a low takeover-style note only for a `cname` or `reference` tier with `name_match`.
  
  Check name `bkt_firebase_read`: high when `name_match`, else medium.
- **Firestore and registries** (GCR, Artifact Registry, ECR Public, GHCR, Docker Hub tag listing) are deferred to 1.5. Their anonymous checks need care,
  because listing tags is reading.
- **Source maps.** A map that is served is itself a hygiene finding `src_sourcemap_public` (info; low when it contains `sourcesContent`). Its contents are
  scanned by Kingfisher inside the same task.
- **Scope.** Every reference passes `bucket_scan`'s existing rules plus `Gate`. A resource on a non-storage host (an arbitrary URL in a bundle) is **not**
  fetched. It is recorded as a `ResourceRef(kind='url')` for the person to look at, never followed.

## 10. Rule customisation

- **Custom rules** (App Admin, instance-wide; per-project in 1.5). Kingfisher YAML is stored server-side (≤ 64 KB) and checked in Python against a strict
  subset of the schema (`docs/RULES.md` §1: `name`, `id` under `custom.`, `pattern`, `min_entropy`, `confidence`, `keywords`, `examples`; **no
  `validation` block**). It is packed and served like the template bundle (`agentapi/template_bundle.py` precedent:
  `GET /api/v1/sentinel/secret-rules/bundle`, sha256 in the task), and run with `--rules-path`. Custom rules never validate.
- **Placeholders.** An instance-level `skip_words` and `skip_regex` list is passed as `--skip-word` and `--skip-regex`. It ships with `EXAMPLE`,
  `PLACEHOLDER`, `your-api-key`, `xxxxxxxx` and the AWS documentation keys.
- **Allowlist of known-public keys** lives in the inventory: status `public_by_design` or `accepted` on the `SecretFinding`, keyed by fingerprint, so it holds
  across hosts and scans. Kingfisher's baseline files are **not** used: their fingerprints include byte offsets (`docs/BASELINE.md`, `FINGERPRINT.md`), which
  change whenever a page changes.

## 11. Interfaces

- **UI.** A Secrets page per project (and All projects):
  - table columns: provider, kind, masked, status, severity, hosts, occurrences, first and last seen, validation;
  - filters on status, class and provider;
  - a detail drawer with occurrences, severity basis, remediation and the status workflow with notes;
  - the host page gets a "Secrets" chip.
- **REST.**
  - `GET projects/<slug>/secrets` (filters as above, paged);
  - `GET projects/<slug>/secrets/<id>`;
  - `POST …/secrets/<id>/status` (Member and up, audited);
  - `POST …/secrets/<id>/validate` (opt-in gated, Owner and App Admin, queues a built-in task, audited).
- **MCP.** `list_secrets`, `get_secret`, `set_secret_status`, `request_secret_validation`, with the same rules. Descriptions state that no value is ever
  returned.
- **Search.** `secret:` (any, P, S, live, provider name) in `search_hosts` (`agentapi/services.py:1707-1708`, `1887`, `2003-2004` pattern).
- **Reports.** A "Secrets" section with masked values only. `how_found` "Extracted" uses masked values for token findings.
- **Tenancy.** Add `cveFeed.SecretFinding`, `cveFeed.SecretOccurrence` and `cveFeed.ResourceRef` to `tenancy/scope.py SCOPES` (all `project_id`). An
  isolation test sits beside the existing ones.
- **AI spend: none.** Secrets have no triage call. `Triage` rows are not created for `SecretFinding`, and the triage payload builder never reads it.

## 12. PR breakdown (S1 to S7 on `1.4-develop`; S0 is separate)

Sizes are rough added lines including tests.

### Wave A: fixes and the inventory, no scanner dependency (can land now)

| PR | Content | Size | Risk |
|---|---|---|---|
| **S0** Stop leaking secrets (two halves) | **S0a**, being done separately on `develop` for 1.3.2 and not part of this branch's work: (a) `cveFeed/secrets_redact.py`: a value redactor built from `sensitive.PATTERNS` plus about 25 common formats, applied in `describe_vulnerability` to `extracted_results` and `description`, and in `_triage_clean` as defence in depth; token-template and bbot secret findings send `{provider, kind, masked}` only. (c) bbot deep mode: trufflehog excluded (`-em trufflehog`) or run only under the gates, until this plan replaces it (G3). **S0b**, at-rest masking, planned for 1.3.3 or 1.4: (b) mask `extracted_results`, `description` and the response body of token and bbot-secret findings at save time, plus a one-off management command that masks existing rows; (d) `how_found`, report and bounty-draft use masked values. S0b and the save-time masking of 8.3 are the same helper: whichever lands first owns it. | ~400 | Low. Masking a stored value cannot be undone: the command runs only with `--apply`, after a dry run |
| **S1** Inventory core | Models (§7), migration, tenancy entries, `secrets_catalog`, fingerprint key, severity engine, feeders from D1 (route `_persist`), D3 (nuclei token templates) and D4 (bbot), backfill command, scoring change (8.2) | ~1,300 | Medium: scoring changes host heat; a release note is needed |
| **S2** Inventory UI, REST, MCP and search | §11, without the validate endpoint | ~900 | Low |

### Wave B: Kingfisher in the scanner (after contract v3 and the built-in scanner)

| PR | Content | Size | Risk |
|---|---|---|---|
| **S3** (sentinel repo) Kingfisher in the image and library | Dockerfile pins and sha256 (amd64, arm64); `cvengine_scanner/secrets.py` (argv builder, manifest, JSON parser, caps, no-egress env); `client/tools.py run_secrets_scan` (bounded fetcher reusing `client/scope.py`, script and map discovery, temp dir lifecycle); refusal of `revoke` and `self-update`; RSS measurement; no-network CI test; `--help` flag test | ~900 | Medium: a new binary; memory unknown until measured |
| **S4** Server half of `secrets_scan` | Contract kind and fixtures, `clean_result`, `persist_secrets_result` into S1's models, pipeline stage after `route_auth_scan`, `RouteAuth.evidence['script_urls']`, ledger service, `kind_since`, the fake-scanner test (`assert_ran_nowhere_locally`), the bump of the pinned Sentinel commit in `docker-compose.yml`, the `THIRD-PARTY.md` entry | ~800 | Medium |
| **S5** Resource exposure | `ResourceRef` feed into `bucket_scan.collect`, `check_firebase`, the source-map hygiene check, tests on recorded responses | ~600 | Medium: third-party endpoints; reuses the existing pacing |

### Wave C: gated extras

| PR | Content | Size | Risk |
|---|---|---|---|
| **S6** Opt-in validation | Project setting and attestation, the three locks (5.2), allow-list JSON and its hash test against the attested rule bundle, built-in-only refusal, second Kingfisher pass, `value_enc` with purge, audit lines, the validate endpoint and MCP tool | ~900 | **High**: legal and safety. Needs a second reviewer and the allow-list reviewed rule by rule |
| **S7** Custom rules and skip words | Section 10 | ~500 | Low |

- **Sequencing.** S0a is already on its way to `develop` for 1.3.2 and reaches `1.4-develop` through the normal merge of `develop`; S0b follows in 1.3.3 or 1.4. S1 and S2 any time; they need no scanner. S3 and S4 after the contract v3 bump and alongside the other new-kind waves; they use
  the built-in scanner but also run on external Sentinels for detection. S5 after S4, and before or with phase 7, when `bucket_probe` moves into the
  scanner (write `check_firebase` in `cvengine_scanner` if that move has landed). S6 last in 1.4, or slip to 1.5 if the built-in secure-read work slips.
- **Deferred to 1.5:** access-map (blast radius), re-validation from stored values through the secure read, Firestore and registry checks, per-project custom
  rules, a reveal-value flow.

## 13. Test plan

- **Pure.**
  - Catalog mapping for every rule ID in the pinned bundle: known or "uncatalogued", never a crash.
  - Masking (never more than prefix + 4; a PEM shows its header only).
  - Normalisation and HMAC, including that the fingerprint survives a field-key rotation.
  - The severity table.
  - `secrets_redact` over the Kingfisher rules' own `examples` as test vectors: no vector may survive in a triage payload, a `how_found`, an export or an
    MCP answer.
- **Contract.** Fixtures for targets and results. `clean_result` drops `validation.response`, foreign URLs, oversize secrets and unknown keys. Results bounds
  equal the server limits (existing `tests/test_sentinel_contract.py` pattern).
- **Fake scanner** (1.4-develop `web/tests/fake_scanner.py`). The stage dispatches, persists, deduplicates across hosts and never runs locally. Scanner
  offline: the stage waits and the hosts stay due.
- **Sentinel client.**
  - Real Kingfisher in CI over synthetic pages with canonical fake keys (`AKIAIOSFODNN7EXAMPLE`, the Kingfisher rule examples).
  - A no-network namespace for `--no-validate`.
  - Timeouts, output and file caps, temp-dir removal on kill.
  - Same-origin-only map following.
  - `revoke` and `self-update` refused.
- **Gates.** A bounty project never validates. An external Sentinel is never offered `validate: true`. Allow-list hash drift removes a rule. Every
  validation writes its audit lines.
- **Tenancy.** Inventory rows are invisible across projects, and one fingerprint in two projects gives two rows.
- **Resource exposure.** Recorded Firebase and GCS responses: readable, locked, missing. No key name stored.
- **Regression.** `test_sensitive.py`, `test_scoring.py` (with the new browser-key line), `test_bucket_scan.py`, `test_triage.py` (payload never holds a
  value).

## 14. Decisions on the open questions (a recommendation for each)

1. **Server-side scan or Sentinel kind?** A Sentinel kind with no local fallback (6.1). The server never parses hostile bodies with a new binary.
2. **Store the value?** No by default. Encrypted only while validation is on, purged after 30 days (5.5).
3. **Fingerprint identity.** A keyed HMAC with a stored install key, not Kingfisher's offset-bound XXH3 (7).
4. **Validate by default?** No. Three locks. Bounty projects never. Built-in scanner only (5.2).
5. **Access map in 1.4?** No. It uses the credential to enumerate resources. Moved to 1.5 with its own lock.
6. **Keep the nuclei token templates?** Yes, as the fast path, masked and linked (8.3).
7. **bbot trufflehog in deep mode?** Exclude or gate it now (S0a, on `develop` for 1.3.2). Kingfisher replaces it, under policy.
8. **Kingfisher remote sources (S3, GCS, Docker)?** Never. They download contents.
9. **Custom rule validation?** Never in 1.4.
10. **Which contract version?** The 1.4 bump that adds the new kinds (v3, the contract being at 2 today). If v3 is taken, the next one.
11. **Source of the binary?** Verified GitHub release tarballs pinned by sha256 per architecture, with attestation checked in CI. Not PyPI.
12. **Should Google browser keys alert?** Info, "likely public by design", until validation or a person says otherwise. The route score drops from 25 to 5.
13. **Does S0 wait for 1.4?** No. S0a fixes a live leak to the AI provider (G1) and the ungated live verification (G3), and is being done separately on `develop`
    for 1.3.2. The at-rest masking half (S0b, G2) is planned for 1.3.3, or for 1.4 together with S1.

## 15. Proven versus assumed (summary)

- **Proven from code:**
  - every `file:line` above;
  - the raw key in the triage payload, `how_found`, exports and bounty drafts;
  - bbot deep mode verifying via trufflehog (bbot 3.0.2 module source, `reNgine/bbot.py:31`);
  - route bodies not stored, and JS fetched but not secret-scanned;
  - `file/keys` templates excluded;
  - the token templates hitting `/` only (upstream count).
- **Proven from Kingfisher docs at v2.16.0:**
  - flags, exit codes and validation outcomes;
  - the fingerprint includes offsets, and the default dedup drops paths;
  - the release tarballs for linux x64 and arm64 with the `gh attestation verify` procedure;
  - the Google API key validator endpoints (`identitytoolkit getProjectConfig`, the Gemini `models` list) in `generated/rules/betterleaks.yml`.
- **From the coordinator (not re-counted here):** about 1,051 rules, about 516 with live validation, the Apache-2.0 licence, and that MongoDB maintains it.
- **Assumptions:**
  - the reason for exactly 4 rows;
  - which nuclei pass produced them;
  - Kingfisher's memory footprint (measured in S3);
  - that every allow-listed validator is read-only (checked rule by rule in S6);
  - that `HTTPS_PROXY` closes Kingfisher's egress (a test in S3 proves it).
