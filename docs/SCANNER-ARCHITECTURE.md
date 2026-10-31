# One scanner for cvENGINE: the plan for 1.4

Status: in progress, on the `1.4-develop` branch. Built so far, all of it off unless switched on: the result contract
(`web/agentapi/sentinel_contract.json`), the built-in scanner as an opt-in compose service with its enrollment, the
`CVENGINE_LOCAL_FALLBACK` switch with the derived "scanner offline" state, and a dormant secure read of a stored credential.
The sections below say which parts of each are not built. To try the built-in scanner, see [BUILTIN-SCANNER.md](BUILTIN-SCANNER.md).

## Quick start for the built-in scanner

Testing the built-in scanner (off by default, and the image is not published yet) is written up in
[BUILTIN-SCANNER.md](BUILTIN-SCANNER.md): build the Sentinel image, switch the service on, check it shows as online. The three `.env`
settings it uses are in `.env.example` as comments (`COMPOSE_PROFILES=builtin-scanner`, `CVENGINE_BUILTIN_SCANNER=1`, and
`CVENGINE_LOCAL_FALLBACK=none`, which is set only after the scanner is live). `sudo ./install.sh --builtin-scanner` writes the first
two for you; a plain install changes nothing.

## Why

cvENGINE and the Sentinel are two code bases that do the same scanning. The Sentinel image repeats the server's tool pins
(its Dockerfile says "keep them equal on purpose", and `scripts/check_tool_versions.py` checks both). Command lines, output
parsers and scan policy exist twice and have drifted more than once (the 1.3.1 client handoff, the policy parity work). A fix
made on one side has to be carried across by hand.

## Decisions

1. The Sentinel stays its own repository. Deploying one is "point Docker at the repo and it builds".
2. The scanners leave cvENGINE. Every install runs a built-in Sentinel as a compose service, shown as "CVEngine Scanner".
   External Sentinels remain for networks the server cannot reach. There is one scanner code base.
3. bbot discovery and the HTTP probes move into the Sentinel too, not only the tool wrappers.
4. Signed-in (authenticated) work is done only by the built-in Sentinel, through a secure read: the stored credential is never
   in a task row and never reaches an external Sentinel.
5. OpenVAS is not part of the built-in scanner. It is installed only when it is enabled in Settings.
6. The Sentinel repository owns the shared scanner code. cvENGINE pins a release of it, the way it pins nuclei or WPScan.

## What exists today

The server runs these locally and dispatches some of them to a Sentinel (`web/agentapi/sentinel_dispatch.py`). Line counts are
rough sizes of the work.

### A. Tool wrappers that are already Sentinel task kinds

| Module | Tool | Notes |
|---|---|---|
| `cveFeed/nmap_scan.py` (545) | nmap | parser `parse_xml` is duplicated in `client/tools.py` |
| `cveFeed/naabu_scan.py` (221) | naabu | |
| `cveFeed/nuclei_scan.py` (781), `nuclei_templates.py` (401) | nuclei | three kinds; flags and `host_of` are duplicated; signed-in passes never dispatch |
| `cveFeed/wpscan_scan.py` (977) | WPScan | one task per site |
| `cveFeed/testssl_scan.py` (483) | testssl.sh | one task per host and port |
| `cveFeed/udp_scan.py` (608) | nmap -sU | raw XML is the one result the server parses itself |
| `cveFeed/openvas_scan.py` | GVM | opt-in; keeps its own compose profile |
| `cveFeed/internal_discovery.py` | nmap -sn | the `discover` kind, internal ranges only |

### B. Tool work that is not a Sentinel kind yet

| Module | What it runs | Needed kind |
|---|---|---|
| `cveFeed/fullscan.py` (380) | nmap, all 65,535 ports of one IP | `nmap_full` |
| `cveFeed/probes.py` (821, lines near 223 and 599) | nmap NSE scripts | part of the probe kinds |
| `cveFeed/waf_scan.py` (146) | wafw00f | `waf` (contract-ready since contract version 2, not wired: no dispatch, the local scan still runs) |
| `cveFeed/node2shell_scan.py` (146) | vendored detector | `node2shell` |
| `cveFeed/rdp_shot.py` (269) | xfreerdp screenshot | `rdp_shot` returns a blob; the AI reading stays on the server |
| `cveFeed/db_exposure.py` | one credential-less connect per database | `db_probe` |
| `cveFeed/path_probe.py` (169) | checks that the scan path does not alter packets | must run in the scanner: it tests the vantage point scans leave from |
| `reNgine/bbot.py`, `cveFeed/discovery.py` (875) | bbot, a streaming producer for up to six hours, screenshots as files | a streamed job type |

### C. In-process network probes (Python in server workers)

| Module | What it does | Decision |
|---|---|---|
| `cveFeed/probes.py` | version and identity probes | move (batched `http_probe` stage task) |
| `cveFeed/route_auth.py` (750), `auth_routes.py` | route state, anonymous and signed in | move; signed-in half built-in only |
| `cveFeed/vhost_scan.py` (499), `subdir_apps.py` | other sites on an address; apps under a path | move |
| `cveFeed/bucket_scan.py` (558), `bucket_probe.py` (427) | public cloud storage | move |
| `cveFeed/supplier_scan.py` (647) | third-party supplier posture | move |
| `cveFeed/zombie.py` | does a retired name's address still answer | move |
| `cveFeed/hygiene.py` | DNS, TLS, SPF/DKIM/DMARC | the network helpers move; the evaluators are pure and stay |
| `cveFeed/pinned_transport.py`, `egress_proxy.py`, `legacy_tls.py` | admission, proxy and TLS 1.0 client for the above | move with them |
| DNS resolution in `discovery.resolve_names` | names to addresses | move: the scanner's view of DNS is the right one |

### D. Pure code shared by both sides (becomes the library)

`fingerprint.py` (pure), `cms.py`, `versions.py`, `soft404.py`, nmap and nuclei parsers, nuclei flag builders, scan policy
constants (`-etags dos`, UDP port list, probe ports), `heavy_process.py` (the supervised runner).

### E. Stays on the server

Correlation, triage, validation, the CVE feeds (`intel.py`, `distro_sync.py`), the work conductor and its fairness rules,
bug-bounty gates, exclusions and range safety, tenancy, persistence, reports (`report_pdf.py`), integrations (runZero, Tailscale
API, mail, bounty), and the passive third-party lookups (`ctmonitor.py` for crt.sh, `archive_urls.py` for the Internet Archive),
which send nothing to the target and need no vantage point.

### Open items from the inventory

- `cveFeed/templategen.py` runs nuclei to validate AI-written templates, and `cveFeed/tasks.py` runs `nuclei -update-templates`.
  Decide: a `nuclei_validate` kind and the approved-template bundle built by the scanner, or keep a nuclei binary on the server.
- `reNgine/resources.py` and `reNgine/tasks.py` still start subprocesses (legacy `run_command`); check what remains of them.
- Anything run from `fullscan`, `probes` and `route_auth` that today shares Redis claims or ledgers with the server needs those
  claims moved to the server side of the contract (the server takes the claim, the task carries the answer).

## Target shape

- **Scanner library** (`cvengine_scanner`, in the Sentinel repo, pip-installable): runners, parsers, flags, policy constants, the
  scope floor, the contract schema and fixtures. cvENGINE pins it by tag and imports what it needs (policy constants to build
  targets, fixtures in tests). One copy.
- **Scanner service**: the Sentinel image, published to a registry by digest with an SBOM, amd64 and arm64.
  It contains the tools, the daemon and the library. It does not contain the GVM stack, git, Go or a docker socket.
- **Built-in scanner**: a compose service with `restart: unless-stopped`, a healthcheck, a memory limit, `NET_RAW`, automatic
  enrolment at instance scope from a bootstrap secret in a shared volume, `self_update` off, and re-enrolment when its token
  expires. External Sentinels enrol the way they do today. The service, the hand-over of the blob and the healthcheck exist as an
  opt-in profile (see "The built-in scanner's enrollment" below).
- **Transport**: HTTP pull for the built-in as well, with the same token, validation and trust model. A second channel would
  be a second code path. Latency is cut inside the one path: a Redis notify wakes the long poll and the dispatcher in place of
  polling every half second, and the long-poll waiter cap is lifted for the built-in token (built: the instance cap, and a Sentinel's token is never counted against its user's cap).
- **Parsing**: the scanner turns tool output into normalised facts and the server validates them (`clean_result`), for every
  kind. The raw-XML exception for UDP goes away, and the server stops parsing hostile XML in its own process.
- **Policy**: the server decides what to scan (conductor, bounty gate, exclusions, internal ranges, SSRF). The scanner keeps its
  own floor and enforces the scope policy carried in the task on every hop.
- **Probes**: a probe stage is one task for a batch of hosts, carrying a scope policy (exclusion list, in-scope domains, range
  floor). The scanner enforces it on every hop and reports the hosts it touched. Today each hop asks the database.
- **bbot**: a streamed job type. Partial results are posted as the run goes, screenshots travel as blobs, and the server
  can stop it. It does not fit "one result per task".
- **Signed-in work**: the built-in fetches a stored credential through a single-use read tied to one task, written to the audit
  log, callable only by the trusted built-in agent. The credential is never in a task row, and an external Sentinel is never
  offered a signed-in task.
  - *Built (server side, dormant):* `POST /api/v1/sentinel/tasks/<id>/secret` (`agentapi.sentinel_broker.read_secret`). The task
    carries `secret_ref` (an `AuthCredential` reference) and `secret_read_at`. Only the built-in agent, for its own claimed or
    running task, may call it. An atomic update of `secret_read_at` is won before anything is decrypted, so it answers once
    (409 after). Every call is audited as `sentinel.secret.read`. The broker leaves a `secret_ref` task out of next-task, queue and
    capacity for every other Sentinel. Rate limited.
  - *Not built:* the scanner client that calls it, and any dispatch of signed-in work (nothing sets `secret_ref`; the dispatch
    wrappers still keep `secret_file` passes on the server).
- **Updates**: the release manifest pins `(server tag, scanner digest)` and the updater swaps the pair with rollback. The
  built-in never updates itself. The version check compares against the digest the server expects, not GitHub's head.
- **Contract**: the file gains a `targets` half (server to scanner) next to `results`, a `contract_version` declared at
  registration and heartbeat, and a minimum contract version per kind. The server supports the current and previous
  contract for external Sentinels and sends a kind only to a Sentinel that can run it.

## Phases (strangler, never a big bang)

0. Result contract, fixtures and tests. Done in PR 276.
1. This inventory, kept current as work lands.
2. Publish the Sentinel image by digest with an SBOM. Add the `targets` half and `contract_version` to the contract. Contract half done: the `targets` half, `contract_version` declared at registration and heartbeat, `kind_since` and `min_supported_contract_version`, and the server offers a kind only to a Sentinel whose version can run it. The Sentinel client sending `info.contract_version` and the published image are not done. Contract version 2 adds the `waf` kind (schema, fixtures, a server-side `persist_waf_result`); it is dormant, offered only to a Sentinel that declares 2, and no stage dispatches it.
3. The built-in scanner service in compose, enrolled automatically, shown in system status. Done as an opt-in profile: System status carries `scanning.builtin_scanner` and the Sentinels page marks its card Built-in.
4. Make waiting non-fatal before any fallback is deleted. Today a stage waits eight seconds for any Sentinel to claim a task and
   then falls back or fails, so every scanner restart would fail scans. Add a "scanner offline" pause that reuses the existing
   pause the conductor honours, re-queue stages with a delay instead of failing them, and show a banner.
5. Move one kind at a time behind `CVENGINE_LOCAL_FALLBACK=<kinds>` (the switch exists: unset or `all` is today's behavior, `none` or a list of kinds takes kinds off the list; see the note below), delete each local path after the telemetry shows no fallbacks
   for a set number of days. Add the missing kinds from section B as they move.
6. Extract the shared library and delete the server's copies of the parsers and flags.
7. Probes and bbot: the scope-policy task and the streamed job type, then move them.
8. Drop the scan tools, Go and bbot from the server image.

### Fallback telemetry: the gate for deleting a local path

Step 5 deletes a local path only after the telemetry shows no fallbacks. `sentinel_dispatch._no_local` is the one place the decision "no Sentinel took it,
the local run is allowed" is made, and when `CVENGINE_LOCAL_FALLBACK` allows the kind it writes one row to `agentapi.ScannerFallback` (`agentapi/scanner_fallback.py`):
kind, project and a reason, never a target or an address. A kind that is off the list waits instead and records nothing, as does a Sentinel that answers and
an internal task (which never had a local run). The reasons are `no_scanner` (nothing live could take it, including the last Sentinel leaving while the task
queued), `not_claimed_in_time`, `slot_busy` (every slot stayed in use until the queue budget ran out), `failed_then_local`, `completion_timeout` (claimed, never
reported), `over_chunk` (the naabu addresses beyond one task, which run here) and `disabled_everywhere` (a `no_scanner` with a cause: a live Sentinel has the kind and the capability policy keeps it off every one; the column is a plain `CharField(24)` with no `choices`, so it needed no migration). Recording is one INSERT in its own savepoint, catches every error and logs the
first failure of a process once; it can never fail or slow a scan. The weekly maintenance prunes rows older than 30 days.

`python manage.py scanner_fallbacks --days N [--kind K]` prints the counts by kind and reason and when each kind last ran locally. The system status carries
`scanning.scanner.fallbacks`: `{days: 7, by_kind: {kind: {count, last_at}}}`. An App Admin also gets `ready_to_delete`, the kinds with no fallback in the last
`SOAK_HOURS` (72) hours and a live built-in scanner that declares the kind; anyone else sees the counts only. That is the gate, together with the fake-scanner
tests: a kind in `ready_to_delete` has soaked and may have its local path deleted. Two things it does not see: the clock starts when the table is first deployed
(an empty table says nothing about the days before it, so read the soak from the upgrade on), and the by-design local runs that are not a fallback from a
Sentinel (a signed-in nuclei pass, and the remaining targets of an nmap chunk a Sentinel did not report) are not recorded, so those paths need their own
migration before their kind is deleted.

## Risks

1. The scanner becomes a hard dependency. Healthcheck, restart policy, status line, and non-fatal waiting come first (phase 4).
2. The kinds list is longer than the eight that exist (section B). Deleting a local path before its kind exists breaks it.
3. Version coupling: two updaters must not exist, and "behind" must mean "not the digest this release expects".
4. The image is not reproducible today (it installs WPScan and updates it at build time). Pin and publish by digest first.
5. Per-task overhead at 10,000 hosts: testssl, UDP and WPScan are one task per target, each with rows and an activity line.
   Batch them in contract version 2.
6. Egress proxy, Tailscale and `CVENGINE_ALLOW_PRIVATE_TARGETS` lab installs apply to local scans and not to dispatched ones;
   they must reach the built-in through the managed settings channel.
7. Server tests that exercise scanning need a fake scanner. Addressed by `web/tests/fake_scanner.py`: a real built-in Sentinel that
   serves tasks through the broker (contract fixtures by default; fail, timeout, idle and offline on request), with
   `assert_ran_nowhere_locally(self, kind)` and `LocalFallback('none')`. A delete PR proves its kind with the pattern in
   `web/tests/test_fake_scanner.py`: real stage entry point, fake serving the result, assert what was stored and that no local runner or
   heavy job ran; then the fake offline, where the stage waits and the target stays due.

## Single-box install

Add about 2 GB of memory and 1.5 GB of disk. If the scanner is offline, scans pause with a banner and are never marked failed.
Air-gapped installs get a release bundle with both image tarballs, the CVE seed and the template bundle, with the version
check off for the built-in.

## The built-in scanner's enrollment (server half, built)

`CVENGINE_BUILTIN_SCANNER=1` switches it on; with `COMPOSE_PROFILES=builtin-scanner` compose also starts the `scanner` service. The server
(`agentapi/builtin_scanner.py`, run every five minutes by `ensure_builtin_scanner`, or by hand with `manage.py ensure_builtin_scanner`) keeps one
instance-wide enrollment ready, owned by the oldest App Admin, valid 24 hours and renewed when under two hours are left, and writes it as a
provisioning blob to `/var/lib/cvengine-scanner/blob` (mode 0600, handed to uid 10001) on the `scanner_bootstrap` volume that only celery (writes) and
the scanner (reads, read-only) mount. The scanner redeems it through the ordinary bootstrap call; the server forces the name "CVEngine Scanner", removes the
file at its next run, and writes a new blob if the scanner is later lost (token revoked or expired). `web` is added to `ALLOWED_HOSTS` only while the
setting is on, because the scanner reaches the server as `http://web:8000` (`CVENGINE_SCANNER_SERVER_URL` overrides). Until the image is published, compose
builds it (`make scanner-build`) from a pinned Sentinel commit (`CVENGINE_SCANNER_SOURCE` overrides). Celery writes the first blob at start-up instead of waiting for beat, and a
scanner with no saved token waits up to ten minutes for the blob before it starts. What is not built: the published
Sentinel image (`CVENGINE_SCANNER_IMAGE`) and the client re-reading the blob after its token expires.

It is shown in System status as `scanning.builtin_scanner` (`builtin_scanner.status()`: `enabled`, `enrolled`, `live`, `agent_id`, `name`,
`last_seen`; just `{'enabled': False}` while the switch is off), with a `problems` line for an App Admin when it is on and not enrolled ten minutes after the
server wrote its enrollment, or enrolled and not heard from for three minutes. Every Sentinel row of the Sentinels page and the agent list carries `builtin`;
the card of the built-in scanner shows a Built-in chip and no Update now button. The steps to try it are in [BUILTIN-SCANNER.md](BUILTIN-SCANNER.md).

## `CVENGINE_LOCAL_FALLBACK`

Unset (or `all`), every kind may still run on this server when no Sentinel takes it: nothing changes. `none` or a comma list of kinds
(`nmap,naabu`) names the kinds that may; any other kind is never run here. A stage that needs one raises
`resources.ScannerUnavailable` (a `MemoryBusy`) where it used to run the tool locally. Every stage that can see it waits: it records
nothing in the ledger (not `failed`, not `done`, so the target stays due and its claim is released), the stage is not marked
failed, and its activity line says "no scanner could take this work (<kind>)", never that memory was short. That covers the nmap
fast scan, the naabu sweep (nmap keeps its default ports), the nuclei light, targeted and weekly deep passes, WPScan, testssl and
UDP. Only `ScannerUnavailable` is caught that way: a real `MemoryBusy` from the memory gate is still a failed stage, which is the
signal the adaptive capacity review reads, and a stopped scan (`ScanAborted`) is handled as before. When no Sentinel is live at all
for a project the wrapper raises before the stage body starts, so the pipeline catches it at the wrapper
(`discovery._waiting_for_scanner`, `run_wpscan`). Signed-in nuclei passes still run here by design until the secure read exists.

A name in the list that is not a kind (`nmpa` for `nmap`) is ignored, which reads as `none` for that kind and so strands it. It is never silent: the server logs one warning per
process for each distinct value, the status's `scanner` block carries `unknown_kinds`, and for an App Admin `problems` says "CVENGINE_LOCAL_FALLBACK names kinds
that do not exist: ...; check the spelling". The semantics do not change; the name is still ignored.

Moving a kind also changes where its scans start from (risk 6): the built-in scanner container does not get this server's egress proxy (Settings > Proxy), the Tailscale network namespace
the sidecar shares with celery, or `CVENGINE_ALLOW_PRIVATE_TARGETS`. Until those reach it through the managed settings channel, `scanner_state.vantage_warnings()` warns (it never refuses): when the
policy takes a kind off and a proxy is configured, the `tailscale` profile is on, or private targets are allowed, `scanning.scanner.vantage` lists a sentence per cause ("CVENGINE_LOCAL_FALLBACK moves
<kinds> to the built-in scanner, which does not use ...") and an App Admin gets each in `problems`. The proxy sentence names only the kinds whose tools take a proxy. Internal ranges are not a cause: they are
Sentinel-only already.


### The "scanner offline" reading

Waiting is visible, not a pause. `agentapi/scanner_state.py` derives, from the Sentinels' own heartbeats and with nothing written, which kinds
are waiting: the kinds `CVENGINE_LOCAL_FALLBACK` takes off this server (`waiting_kinds()`) for which no live, active Sentinel on the instance declares
the capability right now. It is cached for 15 seconds, and with the variable unset it is empty and costs no query. `state()` adds `never_seen`: the
waiting kinds for which no Sentinel that could run them has ever registered, in any status (revoked and suspended ones count as seen). That is the
foot-gun: `CVENGINE_LOCAL_FALLBACK=none` on a server with no scanner strands every kind, and it is a `problems` line in the system status.

It is shown as a `scanning.scanner` block in the system status, a note ("Scanner offline: ... Nothing has failed; it resumes automatically when a scanner
reconnects.") and, for an App Admin, the never-seen sentence, and as a strip on every page (`static/cve/scannerbar.js`, `/cve/api/scanner`) with a
colour and wording of its own, never the scanning pause's. The sweeps that run on their own schedules and would dispatch, raise, catch and log an
activity line every tick (the testssl sweep, the UDP sweep, the WPScan quick pass) return `{'skipped': 'no scanner is online for <kind>; the targets stay
due'}` before doing any of that. The WPScan quick pass asks again at the same attempt, so a returning scanner finds it and its tries are not spent.
It never writes `ScanControl`, never stops a running scan and never holds back local work: the CVE feed, bbot discovery (which runs here, so the work
conductor goes on starting it and only records `scanner_waiting` with its round), the internal-range Sentinel-only path and the thorough WPScan pass (never
dispatched) are untouched. The OpenVAS tick already waits for a Sentinel only. A kind a Sentinel keeps failing (`failing_kinds`) is withheld from it
for a cool-off and so also reads as waiting.

A kind can also wait because it is **turned off**, not because a scanner is gone: a live Sentinel has it and its capability policy (the administrator's, the instance default of its class, or its own machine) denies it. `state()` then carries `disabled` (only when not empty): the waiting kinds that a live Sentinel has and denies, with no other active Sentinel that has them offline. The banner splits the two: "Scanner offline: ..." is only for kinds really waiting for a scanner (`offline_kinds()`), and "OpenVAS is turned off on every Sentinel that has it. Nothing has failed; the work stays due until one is turned back on" (`disabled_message`, also in `messages`) for the others; a sweep's skipped text says the same. `waiting_kinds()` is still every waiting kind, so the sweeps stay off both.

### The capability policy

`agentapi/sentinel_policy.py` is the per-Sentinel, per-kind policy: `allow` (the default for a declared kind), `deny` (what `disabled_kinds` always meant) or `prefer`, and a per-kind `max_concurrent`. It lives in `Agent.managed_settings['kinds']` (the same `{value, at, by}` envelope as every managed setting, so last write wins and each change is audited with the map before and after) and, for kinds a Sentinel has no policy for, in `SentinelDefaults.builtin_kinds` (shipped as OpenVAS denied) and `external_kinds`. Resolution per Sentinel and kind: the machine's veto (`disabled_kinds` it reported; the server cannot lift it), the Sentinel's own policy, the instance default of its class (built-in or external), allow. Only a kind the Sentinel declares can be allowed or preferred (`409` otherwise).

`sentinel_broker.effective_capabilities` leaves out every denied kind, so `_claimable`, `refusal`, `capacity_state` and `eligible_sentinels` need no other rule. `_try_claim` then orders: deny, the per-kind cap (a queued task whose kind is at its cap for this Sentinel is skipped, a later task of another kind may be taken), then prefer (a task younger than `CVENGINE_SENTINEL_PREFER_DEFER_SECONDS`, default 60, is held back from a Sentinel that does not prefer its kind while another live Sentinel that does is in scope, not updating and has room). `capacity_state` counts the slots of a kind as the sum over the eligible Sentinels of the smaller of their free slots and their headroom under the cap. With `why=True`, a `none` carries `reason` (`disabled`, `offline`, `withheld`, `inactive`, `outdated` or `never`) and a sentence naming each Sentinel that has the kind, which `dispatch_or_none` and the stages pass into the stage message and `ScannerFallback.reason` (`disabled_everywhere` for `disabled`). The OpenVAS tick logs one line per tick naming the state instead of passing silently over a project. The wire format to a Sentinel is unchanged: `settings.disabled_kinds` in the registration and heartbeat replies is derived from the policy (every denied kind), so a client that predates the policy keeps honouring it. Least-loaded balancing across Sentinels is a separate piece of work.

