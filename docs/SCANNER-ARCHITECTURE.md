# One scanner for cvENGINE: the plan for 1.4

Status: in progress, on the `1.4-develop` branch. Built: the result contract (`web/agentapi/sentinel_contract.json`), the Sentinel image
published by digest, the built-in scanner as a default compose service that enrols, re-enrols, updates and rolls back with nobody running
anything, `CVENGINE_LOCAL_FALLBACK` (unset, the built-in scanner's kinds never run on the server once it has enrolled) with the derived
"scanner offline" state and non-fatal waiting, signed-in nuclei through the secure read, and the server's vantage point delivered to the
built-in scanner. The phases below say what is left. How the built-in scanner works for an operator is in [BUILTIN-SCANNER.md](BUILTIN-SCANNER.md).

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

### B. Tool work that became Sentinel kinds in contract version 3

Built in 1.4: each module asks for a scanner first (`sentinel_dispatch.scanner_or_local`) and runs here only when no scanner takes the work and
`CVENGINE_LOCAL_FALLBACK` lets the kind run here; otherwise the stage waits and its targets stay due. The server keeps every decision (scope, exclusions,
the finding) and the scanner runs the tool. A Sentinel declares these kinds only to a server whose contract has them (`server_knows`).

| Module | What it runs | Kind | Notes |
|---|---|---|---|
| `cveFeed/fullscan.py` | nmap, all 65,535 ports of one IP; `-sV` on the new ports | `nmap_full`, then `nmap_verify` | the raw report is read by `nmap_scan.parse_xml` and cut to the address asked about (`sentinel_dispatch.nmap_hosts`); waiting is not the address's failure, so no back-off |
| `cveFeed/probes.py` | the nmap probe (`--version-all` and the safe scripts) | `nmap_verify` | the scripts are named in the task; a Sentinel runs only names on the reviewed list `cvengine_scanner.flags.NSE_SCRIPTS`, the one list both sides import |
| `cveFeed/waf_scan.py` | wafw00f | `waf` | one task per site at the address the server vetted; the result goes through the same product rules as a local run |
| `cveFeed/node2shell_scan.py` | the vendored detector | `node2shell` | the detector is vendored in the client the way it is here |
| `cveFeed/rdp_shot.py` | the RDP pre-authentication screenshot | `rdp_shot` | deleted locally (`NEVER_LOCAL`): the capture client is gone from the server. The PNG comes back (at most 4 MB; the signature and the image size in its header are checked before anything opens it); the AI reading stays on the server |
| `cveFeed/db_exposure.py` | one credential-less connect per database | `db_probe` | the finding is made here; `open: null` (no client for that database on the scanner) runs here when it may |
| `cveFeed/path_probe.py` | the plain SYN and the FIN+PSH+URG probe | `path_probe` | built-in scanner only (`sentinel_broker.BUILTIN_KINDS`): it measures the path the scans leave from. One task per project that holds the addresses |
| `cveFeed/templategen.py` | `nuclei -validate`, the benign loopback fixture, an approved template's test | `nuclei_validate` | built-in scanner only. The test is filed under the hosts' own project and never carries a signed-in run; with no scanner and no local nuclei, no AI template is written |
| `reNgine/discovery_events.py`, `cveFeed/discovery.py` | the discovery, a streaming producer for up to six hours | `bbot_discovery` | deleted locally (`NEVER_LOCAL`): a streamed task, also contract version 3 (see **bbot** under Target shape); the server keeps the modes table and the rules that name and file what comes back |

### C. In-process network probes (Python in server workers)

| Module | What it does | Decision |
|---|---|---|
| `cveFeed/probes.py` | version and identity probes | moved: the `http_probe` kind (contract 3), a batch of planned probes per task; the scanner runs them (`cvengine_scanner.probes.version_probes`), the server keeps the plan, the ledger and what is stored; the local path stays behind `CVENGINE_LOCAL_FALLBACK` |
| `cveFeed/route_auth.py` (750), `auth_routes.py` | route state, anonymous and signed in | move; signed-in half built-in only |
| `cveFeed/vhost_scan.py` (499), `subdir_apps.py` | other sites on an address; apps under a path | moved: the `vhost_probe` kind (an address, its default response and each of the project's own names as the Host header) and the `subdir_probe` kind (a web host, the curated mount paths, the directories its own URLs and `robots.txt`/`sitemap.xml` show), contract 3; the server keeps the choice of names and hosts, the ledger, the verdict rules (recomputed from the reported fingerprints) and what is stored; a name, address or host the scanner did not answer stays due; the local path stays behind `CVENGINE_LOCAL_FALLBACK` |
| `cveFeed/bucket_scan.py` (558), `bucket_probe.py` (427) | public cloud storage | moved: the `bucket_check` kind (contract 3), a batch of the sweep's due buckets per task; the server keeps the candidates, the ledger, the global rate (sent as the task's `rate`) and the evaluation; the local path stays behind `CVENGINE_LOCAL_FALLBACK` |
| `cveFeed/supplier_scan.py` (647) | third-party supplier posture | move |
| `cveFeed/zombie.py` | does a retired name's address still answer | moved: the `alive_check` kind (contract 3), the web check and then the bare connects of `changes._retire`; a check the scanner could not answer never retires a host; the local path stays behind `CVENGINE_LOCAL_FALLBACK` |
| `cveFeed/hygiene.py` | DNS, TLS, SPF/DKIM/DMARC | the network helpers move; the evaluators are pure and stay |
| `cveFeed/pinned_transport.py`, `egress_proxy.py`, `legacy_tls.py` | admission, proxy and TLS 1.0 client for the above | copied into the library (`cvengine_scanner.probes.transport`, `egress_proxy`, `legacy_tls`), held to the task's scope policy; a Sentinel takes its probe proxy from its own `CVENGINE_SENTINEL_PROBE_PROXY`, never from the server; the server's copies stay for the local paths |
| DNS resolution in `discovery.resolve_names` | names to addresses | moved: the `dns_resolve` kind (contract 3) for `run_host_pipeline`; the local lookup stays behind `CVENGINE_LOCAL_FALLBACK` and for the retire check's lookups (`changes._retire`) |

### D. Pure code shared by both sides (becomes the library)

`fingerprint.py` (pure), `cms.py`, `versions.py`, `soft404.py`, nmap and nuclei parsers, nuclei flag builders, scan policy
constants (`-etags dos`, UDP port list, probe ports), `heavy_process.py` (the supervised runner).

Status (phase 6). The library (`cvengine_scanner`, hevnsnt/cvENGINE-sentinel#34) holds all of the above except `heavy_process.py`, which
runs processes and stays on the server until phase 8. The server pins the library in `web/requirements.txt` and no longer has its own
`cveFeed/fingerprint.py`, `cms.py`, `versions.py`, `soft404.py` or `reNgine/nmap_service.py`; `nmap_scan.parse_xml` is the library's reader,
re-exported under its old name. Two parts stay on the server because they are not pure:
- reading a page's scripts (`cveFeed/js_libraries.py`: `script_sources`, `from_script_urls`, `from_script_body`). It fetches files, and it
  hands what it read to the library's `fingerprint.from_response` as `from_scripts` pairs;
- the CMS version evidence a probe stored (`cveFeed/cms_evidence.py`: `attested`, `superseded`). It reads `ProbeObservation` rows and
  applies the library's `cms.disproven` to them.

The flag builders and policy constants are the library's too (`cvengine_scanner.flags`), and the server has no copies of them:
- the nuclei run (`nuclei_flags`, with `-etags dos` always, `NUCLEI_SEVERITIES`, `NUCLEI_DEFAULT_PORTS`, `host_of`);
- the nmap fingerprint and full-port flags, the reviewed NSE scripts and `reviewed_scripts`, `EXTRA_PORTS` and `TOP_PORTS`;
- the UDP sweep (`udp_nmap_flags`, `UDP_PORTS`), `port_argument`, `CLOSED_PROBE_PORTS`, `MAX_OPEN_PER_IP`;
- the version probe's per-service scripts (`probe_nmap_flags`) and `KERNEL_MARKERS`.

A server module still names a constant where its own callers read it (`nmap_scan.FAST_FLAGS`, `udp_scan.DEFAULT_PORTS`, `naabu_scan.port_argument`).
Each of those names is an import of the library's value, never a copy.

### E. Stays on the server

Correlation, triage, validation, the CVE feeds (`intel.py`, `distro_sync.py`), the work conductor and its fairness rules,
bug-bounty gates, exclusions and range safety, tenancy, persistence, reports (`report_pdf.py`), integrations (runZero, Tailscale
API, mail, bounty), and the passive third-party lookups (`ctmonitor.py` for crt.sh, `archive_urls.py` for the Internet Archive),
which send nothing to the target and need no vantage point.

### Open items from the inventory

- `cveFeed/templategen.py` runs nuclei to validate AI-written templates and to test approved ones: decided, the `nuclei_validate` kind (contract
  version 3, built-in scanner only). Still on the server: the maintainer's approval of a reviewed draft (`approve_reviewed_template`, a loopback
  fixture), the signed-in template run (`auth_nuclei`, which needs the secure read), and `nuclei -update-templates` in `cveFeed/tasks.py`.
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
  expires. External Sentinels enrol the way they do today. Built, on by default (see "The built-in scanner's enrollment" below).
- **Transport**: HTTP pull for the built-in as well, with the same token, validation and trust model. A second channel would
  be a second code path. Latency is cut inside the one path: a Redis notify wakes the long poll and the dispatcher in place of
  polling every half second, and the long-poll waiter cap is lifted for the built-in token (built: the instance cap, and a Sentinel's token is never counted against its user's cap; the notify is built too, see "Asynchronous stages" below).
- **Parsing**: the scanner turns tool output into normalised facts and the server validates them (`clean_result`), for every
  kind. The raw-XML exception for UDP goes away, and the server stops parsing hostile XML in its own process.
- **Policy**: the server decides what to scan (conductor, bounty gate, exclusions, internal ranges, SSRF). The scanner keeps its
  own floor and enforces the scope policy carried in the task on every hop.
- **Probes**: a probe stage is one task for a batch of hosts, carrying a scope policy (exclusion list, in-scope domains, range
  floor). The scanner enforces it on every hop and reports the hosts it touched. Today each hop asks the database.
- **bbot**: a streamed job type. Partial results are posted as the run goes, screenshots travel as blobs, and the server
  can stop it. It does not fit "one result per task".
  - *Built (server side):* the `bbot_discovery` kind, contract version 3, with `$defs/partials` (the batches) and `$defs/scope_policy` (what the
    scanner may touch). `POST /api/v1/sentinel/tasks/<id>/partial` (`agentapi.sentinel_stream.report_partial`) takes numbered batches once and in
    order, holds them to the task's scope and stores them as `SentinelPartial` rows; `sentinel_stream.dispatch_stream` (the discovery stage) reads
    them in order and persists each through `cveFeed.discovery`'s own flush, then the final result closes the run. A stop of the scan ends the task
    at its next batch (409). `run_discovery` hands the run to a Sentinel that declares the kind; the kind is in `NEVER_LOCAL`, so with none able to take it
    the scan waits (`ScannerUnavailable`) and the target stays due. A project's bbot module keys go by reference (`secret_ref` `bbotkeys:<project id>`) to the built-in
    scanner only, read once through the secure read. See [AGENT-API.md](AGENT-API.md) ("Streamed work").
- **Signed-in work**: the built-in fetches a stored credential through a single-use read tied to one task, written to the audit
  log, callable only by the trusted built-in agent. The credential is never in a task row, and an external Sentinel is never
  offered a signed-in task.
  - *Built (server side, dormant):* `POST /api/v1/sentinel/tasks/<id>/secret` (`agentapi.sentinel_broker.read_secret`). The task
    carries `secret_ref` (an `AuthCredential` reference) and `secret_read_at`. Only the built-in agent, for its own claimed or
    running task, may call it. An atomic update of `secret_read_at` is won before anything is decrypted, so it answers once
    (409 after). Every call is audited as `sentinel.secret.read`. The broker leaves a `secret_ref` task out of next-task, queue and
    capacity for every other Sentinel. Rate limited.
  - *Built (dispatch and client):* the signed-in nuclei pass (`cveFeed.auth_nuclei.run_authenticated`) sends one task per credential and
    chunk with `secret_ref` set (`sentinel_dispatch.signed_in_stream`), offered only to a built-in scanner whose image reports the
    `secret_read` feature (`SentinelEff.reads_secrets`); the task the scanner receives says `signed_in: true`. The client reads the credential
    once, runs nuclei with a 0600 secrets file on a memory file system (`-sf`, `-dr`), wipes it and redacts any echo (cvENGINE-sentinel
    `client/signed_in.py`); any other Sentinel refuses such a task. Without such a scanner the pass runs on the server as before when nuclei
    may run there, and waits otherwise. The signed-in CVE template check (`templategen`) still runs nuclei on the server: it belongs with the
    template validation open item below.
- **Updates**: the release manifest pins `(server tag, scanner digest)` and the updater swaps the pair with rollback. The
  built-in never updates itself. The version check compares against the digest the server expects, not GitHub's head.
- **Contract**: the file gains a `targets` half (server to scanner) next to `results`, a `contract_version` declared at
  registration and heartbeat, and a minimum contract version per kind. The server supports the current and previous
  contract for external Sentinels and sends a kind only to a Sentinel that can run it.

## Phases (strangler, never a big bang)

0. Result contract, fixtures and tests. Done in PR 276.
1. This inventory, kept current as work lands.
2. Publish the Sentinel image by digest with an SBOM. Add the `targets` half and `contract_version` to the contract. Done. The image: the Sentinel repository's `publish.yml` pushes `ghcr.io/hevnsnt/cvengine-sentinel` for amd64 and arm64 with an SBOM and provenance on every push to `main` and every tag, prints the digest, and checks the image has no git, Go, GVM stack or docker socket; WPScan and its gems are installed from a lockfile with checksums and nothing is updated at build time. cvENGINE pins it by digest in `scanner.lock.json` (`scripts/scanner_lock.py`). The contract: the `targets` half, `contract_version` declared at registration and heartbeat, `kind_since` and `min_supported_contract_version`, and the server offers a kind only to a Sentinel whose version can run it. The Sentinel client sends `info.contract_version` (2) and runs the `waf` kind (hevnsnt/cvENGINE-sentinel#25, #28: it asks a server for `waf` only when the server's contract has it, so a 1.3 server is unaffected). Contract version 2 adds the `waf` kind (schema, fixtures, a server-side `persist_waf_result`), offered only to a Sentinel that declares 2; the wafw00f stage dispatches it since 1.4. Contract version 3 adds `nmap_full`, `nmap_verify`, `node2shell`, `rdp_shot`, `db_probe`, `path_probe` and `nuclei_validate` (section B); the frozen fixtures of version 2 are in `tests/fixtures/sentinel_results/v2/`.
3. The built-in scanner service in compose, enrolled automatically, shown in system status. Done, on by default (`CVENGINE_BUILTIN_SCANNER=0` turns it off and revokes it): a default compose service on the pinned image, sharing celery's network namespace, with a health check on its heartbeats and a watchdog that restarts it; it reads its enrollment from the shared volume and re-enrols by itself when its token is refused; `install.sh`, `make up`, `scripts/update.sh`, the web updater and `apply-update.sh` pull the pinned image, start it after celery and roll back to the previous image when it sends no heartbeat ([UPDATES.md](UPDATES.md#the-built-in-scanner)); the upgrade rehearsal checks it comes up and enrols. System status carries `scanning.builtin_scanner` and the Sentinels page marks its card Built-in.
4. Make waiting non-fatal before any fallback is deleted. Done. A stage whose kind may not run here and that no scanner took waits
   (`resources.ScannerUnavailable`): nothing is marked failed or recorded, the strip on every page says the scanner is offline, and the
   hosts of a scan or host run during which a stage waited are queued again as a deferred re-test (`cveFeed.scanner_wait`, due
   `CVENGINE_SCANNER_REQUEUE_MINUTES` later and held back while a scanner is still missing), so a scanner restart costs a delay, never a
   failed scan. It is a derived state, not the pause: the conductor keeps starting discovery, which runs on the server.
5. Move one kind at a time behind `CVENGINE_LOCAL_FALLBACK=<kinds>` (unset, the built-in scanner's kinds, `sentinel_dispatch.BUILTIN_SCANNER_KINDS`, are taken off this server once it has enrolled; `all` is the 1.3 behaviour; a kind joins that list in the change that teaches the built-in scanner to run it; see the note below), delete each local path after the telemetry shows no fallbacks
   for a set number of days. The kinds of section B exist since contract version 3 (1.4), so each can now be moved like the others.
6. Extract the shared library and delete the server's copies of the parsers and flags. The library is done (hevnsnt/cvENGINE-sentinel#34),
   and the server imports it for the fingerprint readers, the nmap parser, and the scan flags and policy constants (section D). Open: one
   source of truth for the result contract (the server still holds its own `sentinel_contract.json`, which the library's CI compares with it).
7. Probes and bbot: the scope-policy task and the streamed job type, then move them. bbot: the streamed job type and its scope policy are built (see
   **bbot** above); the local run is deleted (T8).
   Probes in progress: contract version 3 has the scope policy
   for probe tasks (`$defs/probe_scope`: the names a task may ask, what is excluded, the server's address rules), computed by
   `cveFeed.probe_scope` when a task is built and enforced by the scanner (`cvengine_scanner.probes.policy`) at every hop, redirects and script
   reads included, which reports the hosts it touched and the hops it refused. Moved: the version and identity probes (`http_probe`), the
   discovery and retire-check lookups (`dns_resolve`), the zombie check (`alive_check`), the cloud storage checks (`bucket_check`), the virtual host and subdirectory application checks (`vhost_probe`, `subdir_probe`), with the pure readers they share (`versions`, `fingerprint`, `cms`, `wp_core`, `js_libraries`, `soft404`,
   `sensitive`) copied into the library. Not moved yet: the route check and its signed-in half, suppliers and the
   hygiene network helpers.
8. Drop the scan tools, Go and bbot from the server image.

Exposed secrets (Kingfisher as a new Sentinel kind, `secrets_scan`, with a project inventory) is planned as its own set of PRs on top of these phases in [SECRETS-PLAN.md](SECRETS-PLAN.md).

### Fallback telemetry: the gate for deleting a local path

Step 5 deletes a local path only after the telemetry shows no fallbacks. `sentinel_dispatch._no_local` is the one place the decision "no Sentinel took it,
the local run is allowed" is made, and when `CVENGINE_LOCAL_FALLBACK` allows the kind it writes one row to `agentapi.ScannerFallback` (`agentapi/scanner_fallback.py`):
kind, project and a reason, never a target or an address. A kind that is off the list waits instead and records nothing, as does a Sentinel that answers and
an internal task (which never had a local run). The reasons are `no_scanner` (nothing live could take it, including the last Sentinel leaving while the task
queued), `not_claimed_in_time`, `slot_busy` (every slot stayed in use until the queue budget ran out), `failed_then_local`, `completion_timeout` (claimed, never
reported), `over_chunk` (a chunk of an nmap, naabu or nuclei stage that was never sent to a Sentinel because an earlier chunk of the same stage went unclaimed, so the stage stopped sending and it runs here; each chunk that runs here is one row, every chunk of a stage now goes to a Sentinel side by side through `dispatch_many`; a chunk never sent because no live Sentinel was left, including the last one leaving while an earlier chunk queued, is `no_scanner`), `partial_result` (the nmap stage's leftover: a Sentinel finished the chunk but reported no host row for some addresses, or did not report every port naabu found on one, so those are fingerprinted here; one row per stage; also a background UDP scan whose Sentinel report named no host for the address) and `disabled_everywhere` (a `no_scanner` with a cause: a live Sentinel has the kind and the capability policy keeps it off every one; the column is a plain `CharField(24)` with no `choices`, so it needed no migration). Recording is one INSERT in its own savepoint, catches every error and logs the
first failure of a process once; it can never fail or slow a scan. The weekly maintenance prunes rows older than 30 days.

`python manage.py scanner_fallbacks --days N [--kind K]` prints the counts by kind and reason and when each kind last ran locally. The system status carries
`scanning.scanner.fallbacks`: `{days: 7, by_kind: {kind: {count, last_at}}}`. An App Admin also gets `ready_to_delete`, the kinds with no fallback in the last
`SOAK_HOURS` (72) hours and a live built-in scanner that declares the kind; anyone else sees the counts only. That is the gate, together with the fake-scanner
tests: a kind in `ready_to_delete` has soaked and may have its local path deleted. Two things it does not see: the clock starts when the table is first deployed
(an empty table says nothing about the days before it, so read the soak from the upgrade on), and the by-design local runs that are not a fallback from a
Sentinel (a signed-in nuclei pass) are not recorded, so that path needs its own migration before its kind is deleted. The addresses of an nmap chunk a
Sentinel finished without covering them are a fallback like any other (`partial_result`): recorded when nmap may run here, left due when it may not.

## Risks

1. The scanner becomes a hard dependency. Addressed: a health check on its heartbeats, a watchdog restart, the status line and strip, non-fatal waiting with re-queueing (phase 4), a rollback of a new image that does not heartbeat, and the default taking kinds off the server only once the built-in scanner has enrolled (a host whose image never came up keeps scanning locally). `CVENGINE_LOCAL_FALLBACK=all` is the escape hatch.
2. The kinds list is longer than the eight that exist (section B). Deleting a local path before its kind exists breaks it.
3. Version coupling: two updaters must not exist, and "behind" must mean "not the digest this release expects". Addressed: the built-in scanner's self-update is forced off, and the server's update scripts swap the digest `scanner.lock.json` pins.
4. The image was not reproducible (it installed WPScan and updated it at build time). Addressed: WPScan and its gems come from a lockfile with checksums, nothing is updated at build time, and the image is published and pinned by digest.
5. Per-task overhead at 10,000 hosts: testssl, UDP and WPScan are one task per target, each with rows and an activity line.
   Batch them in contract version 2.
6. Egress proxy, Tailscale and `CVENGINE_ALLOW_PRIVATE_TARGETS` lab installs applied to local scans and not to dispatched ones. Addressed:
   the built-in scanner shares celery's network namespace (so the Tailscale sidecar's route, and the host network and macvlan overlays, are
   its own), and its settings reply carries `vantage` (`sentinel_settings.builtin_vantage`: the proxies, the bypass list, whether private
   addresses go through the proxy, and the private ranges the server may scan), derived at every reply, stored nowhere and sent to the
   built-in scanner alone, which applies it to nuclei, WPScan, testssl.sh, wafw00f and its scope floor. An external Sentinel ignores it. Its
   nmap OS guesses are judged as this server's own (they cross the same path). `vantage_warnings` now speaks only of a built-in image too old
   to apply them.

   Why share celery's namespace rather than route through the sidecar: routing the tailnet from another container needs forwarding and
   address translation inside celery's namespace and still leaves the host network and macvlan overlays behind; a second Tailscale node
   needs a second key. Sharing the namespace gives exact parity with no new privilege for celery. What it costs: the scanner's raw-socket
   tools could see celery's own traffic (to Redis and PostgreSQL), which they could already reach on the bridge network with the same
   capability, and the scanner must be recreated after celery, which every update path and `make up` do (as for the Tailscale sidecar).
7. Server tests that exercise scanning need a fake scanner. Addressed by `web/tests/fake_scanner.py`: a real built-in Sentinel that
   serves tasks through the broker (contract fixtures by default; fail, timeout, idle and offline on request), with
   `assert_ran_nowhere_locally(self, kind)` and `LocalFallback('none')`. A delete PR proves its kind with the pattern in
   `web/tests/test_fake_scanner.py`: real stage entry point, fake serving the result, assert what was stored and that no local runner or
   heavy job ran; then the fake offline, where the stage waits and the target stays due.

## Single-box install

Add about 2 GB of memory (`SCANNER_MEM_LIMIT`; 1 GB on a host under about 7 GB, [DEPLOYMENT.md](DEPLOYMENT.md#memory)) and 1.5 GB of disk. If the scanner is offline, the work that needs it waits with a strip on every page, is never marked failed, and is queued again for when it is back.
Air-gapped installs get a release bundle with both image tarballs, the CVE seed and the template bundle, with the version
check off for the built-in.

## The built-in scanner's enrollment (server half, built)

It is on unless `CVENGINE_BUILTIN_SCANNER=0` (which makes the next run revoke the scanner's token and remove any blob), and `scanner` is a default compose service. The server
(`agentapi/builtin_scanner.py`, run every five minutes by `ensure_builtin_scanner`, or by hand with `manage.py ensure_builtin_scanner`) keeps one
instance-wide enrollment ready, owned by the oldest App Admin, valid 24 hours and renewed when under two hours are left, and writes it as a
provisioning blob to `/var/lib/cvengine-scanner/blob` (mode 0600, handed to uid 10001) on the `scanner_bootstrap` volume that only celery (writes) and
the scanner (reads, read-only) mount. The scanner redeems it through the ordinary bootstrap call; the server forces the name "CVEngine Scanner", removes the
file at its next run, and writes a new blob if the scanner is later lost (token revoked or expired). `web` is added to `ALLOWED_HOSTS` only while the
setting or the AI reviewer is on, because both reach the server as `http://web:8000` (`CVENGINE_SCANNER_SERVER_URL` overrides; the host network overlay sets
`http://127.0.0.1:8000`). Celery writes the first blob at start-up instead of waiting for beat, and the installer writes it right after the admin account
exists. The scanner reads the blob from the file itself (`CVENGINE_SENTINEL_BLOB_FILE`) and waits for it with no token; when the server refuses its token
later it forgets it and enrols again with the next blob, never trying a spent one twice. The image is the digest `scanner.lock.json` pins
(`CVENGINE_SCANNER_IMAGE` runs another; `make scanner-build` builds the pinned commit from source).

It is shown in System status as `scanning.builtin_scanner` (`builtin_scanner.status()`: `enabled`, `enrolled`, `live`, `agent_id`, `name`,
`last_seen`; just `{'enabled': False}` while the switch is off), with a `problems` line for an App Admin when it is on and not enrolled ten minutes after the
server wrote its enrollment, or enrolled and not heard from for three minutes. Every Sentinel row of the Sentinels page and the agent list carries `builtin`;
the card of the built-in scanner shows a Built-in chip and no Update now button. The steps to try it are in [BUILTIN-SCANNER.md](BUILTIN-SCANNER.md).

## `CVENGINE_LOCAL_FALLBACK`

Unset, every kind except the built-in scanner's (`sentinel_dispatch.BUILTIN_SCANNER_KINDS`: nmap, naabu, the three nuclei passes, testssl, the UDP sweep and WPScan) may still run on this server once the built-in scanner has enrolled, and every kind before that or with the scanner turned off (`default_fallback_kinds`). `all` is every kind, as in 1.3. `none` or a comma list of kinds
(`nmap,naabu`) names the kinds that may; any other kind is never run here. A stage that needs one raises
`resources.ScannerUnavailable` (a `MemoryBusy`) where it used to run the tool locally. Every stage that can see it waits: it records
nothing in the ledger (not `failed`, not `done`, so the target stays due and its claim is released; the one exception is the nmap fast scan,
which marks `done` an address a Sentinel already fingerprinted in full, so only the rest stay due, an address a Sentinel finished without a host row
or without every port naabu found among them: it is never fingerprinted here), the stage is not marked failed, and its activity line says "no scanner could take this work (<kind>)", never that memory was short. That covers the nmap
fast scan, the naabu sweep (nmap keeps its default ports), the nuclei light, targeted and weekly deep passes, WPScan, testssl,
UDP, and the kinds of contract version 3: wafw00f, node2shell, the RDP screenshot and the database check (the stage returns `skipped`), the
background full sweep (the address is swept later, with no back-off), the nmap probe (counted as held), the path check (no verdict) and the
template check (no AI template is written, an approved template's test reports the hosts as not tested). Only `ScannerUnavailable` is caught that way: a real `MemoryBusy` from the memory gate is still a failed stage, which is the
signal the adaptive capacity review reads, and a stopped scan (`ScanAborted`) is handled as before. When no Sentinel is live at all
for a project the wrapper raises before the stage body starts, so the pipeline catches it at the wrapper
(`discovery._waiting_for_scanner`, `run_wpscan`). Signed-in nuclei passes follow the same rule, through the built-in scanner's secure read. The hosts of a run during which a stage waited are queued again (`cveFeed.scanner_wait`).

A name in the list that is not a kind (`nmpa` for `nmap`) is ignored, which reads as `none` for that kind and so strands it. It is never silent: the server logs one warning per
process for each distinct value, the status's `scanner` block carries `unknown_kinds`, and for an App Admin `problems` says "CVENGINE_LOCAL_FALLBACK names kinds
that do not exist: ...; check the spelling". The semantics do not change; the name is still ignored.

Moving a kind does not change where its scans start from (risk 6): the built-in scanner shares celery's network namespace and is sent this server's egress proxy and private-target
setting (`sentinel_settings.builtin_vantage`). `scanner_state.vantage_warnings()` warns (it never refuses) only when the enrolled built-in scanner's image does not report the `vantage` feature, so
it would ignore them: then, when the policy takes a kind off and a proxy is configured, the `tailscale` profile is on, or private targets are allowed, `scanning.scanner.vantage` lists a sentence per
cause and an App Admin gets each in `problems`. The proxy sentence names only the kinds whose tools take a proxy. Internal ranges are not a cause: they are Sentinel-only already.


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
It never writes `ScanControl`, never stops a running scan and never holds back local work: the CVE feed, the discovery start (the run is on a Sentinel, so the
conductor goes on starting it and only records `scanner_waiting` with its round), the internal-range Sentinel-only path and the thorough WPScan pass (never
dispatched) are untouched. The OpenVAS tick already waits for a Sentinel only. A kind a Sentinel keeps failing (`failing_kinds`) is withheld from it
for a cool-off and so also reads as waiting.

A kind can also wait because it is **turned off**, not because a scanner is gone: a live Sentinel has it and its capability policy (the administrator's, the instance default of its class, or its own machine) denies it. `state()` then carries `disabled` (only when not empty): the waiting kinds that a live Sentinel has and denies, with no other active Sentinel that has them offline. The banner splits the two: "Scanner offline: ..." is only for kinds really waiting for a scanner (`offline_kinds()`), and "OpenVAS is turned off on every Sentinel that has it. Nothing has failed; the work stays due until one is turned back on" (`disabled_message`, also in `messages`) for the others; a sweep's skipped text says the same. `waiting_kinds()` is still every waiting kind, so the sweeps stay off both.

### The capability policy

`agentapi/sentinel_policy.py` is the per-Sentinel, per-kind policy: `allow` (the default for a declared kind), `deny` (what `disabled_kinds` always meant) or `prefer`, and a per-kind `max_concurrent`. It lives in `Agent.managed_settings['kinds']` (the same `{value, at, by}` envelope as every managed setting, so last write wins and each change is audited with the map before and after) and, for kinds a Sentinel has no policy for, in `SentinelDefaults.builtin_kinds` (shipped as OpenVAS denied) and `external_kinds`. Resolution per Sentinel and kind: the machine's veto (`disabled_kinds` it reported; the server cannot lift it), the Sentinel's own policy, the instance default of its class (built-in or external), allow. Only a kind the Sentinel declares can be allowed or preferred (`409` otherwise).

`sentinel_broker.effective_capabilities` leaves out every denied kind, so `_claimable`, `refusal`, `capacity_state` and `eligible_sentinels` need no other rule. `_try_claim` then orders: deny, the per-kind cap (a queued task whose kind is at its cap for this Sentinel is skipped, a later task of another kind may be taken), then prefer (a task younger than `prefer_defer_for(kind)`, which is `CVENGINE_SENTINEL_PREFER_DEFER_SECONDS` (default 60, a ceiling) and for every kind but OpenVAS at most the stage claim window less two seconds so a preference never costs a stage its Sentinel, is held back from a Sentinel that does not prefer its kind while another live Sentinel that does is in scope, not updating and has room). `capacity_state` counts the slots of a kind as the sum over the eligible Sentinels of the smaller of their free slots and their headroom under the cap. With `why=True`, a `none` carries `reason` (`disabled`, `offline`, `withheld`, `inactive`, `outdated` or `never`) and a sentence naming each Sentinel that has the kind, which `dispatch_or_none` and the stages pass into the stage message and `ScannerFallback.reason` (`disabled_everywhere` for `disabled`). The OpenVAS tick logs one line per tick naming the state instead of passing silently over a project. The wire format to a Sentinel is unchanged: `settings.disabled_kinds` in the registration and heartbeat replies is derived from the policy (every denied kind), so a client that predates the policy keeps honouring it. After prefer, `_try_claim` balances: a task younger than `balance_defer_for(kind)` (`CVENGINE_SENTINEL_BALANCE_DEFER_SECONDS`, default 60; the same stage-window rule as `prefer_defer_for`, `_stage_window`: at most the claim window less two seconds for every kind but OpenVAS) is passed over by a Sentinel that holds tasks while `_lighter_elsewhere` finds another live Sentinel with a strictly lower `held / max_concurrent` that `_can_take` the task (live, not updating, free slot, per-kind cap, and the same `refusal` as `_preferred_elsewhere`: scope, hosts, credential, internal network, capability). The candidates (`_peers`) and what they hold are read once per `(project, kind)` for one pass (one query for the Sentinels, one for their tasks), with the rights shared with the prefer check, and the answer is memoised like the prefer answer, so a pass over many queued tasks does not query per task; a Sentinel that holds nothing skips the check altogether. A Sentinel that prefers the kind is never held back (prefer wins), the built-in scanner is a symmetric peer (signed-in work is refused to the others by `refusal`), and `CVENGINE_SENTINEL_BALANCE=0` is the kill switch. `activity_metrics` (the last hour's utilisation, finished tasks and queue wait of each Sentinel and kind, and the queue depth by kind) feeds `GET sentinels/live` (`load` per Sentinel, `kinds`) and the system status (`sentinels.load`).

## Asynchronous stages (queue Q4)

Built. A stage that hands work to a Sentinel no longer holds its Celery worker while the Sentinel works. Before this, the stage created the
`SentinelTask` and polled it every half second until it was reported or a budget ran out, so the scans in flight were capped by the number of
workers. Now the stage writes its waits to an `agentapi.StageRun` row and returns; the worker takes other work. When the last task of the run
ends (reported done or failed, expired, cancelled, released), a completion callback continues the stage from where it stopped, persists the
results as before, and goes on with the next stage. `CVENGINE_ASYNC_STAGES=0` brings back the blocking wait.

**What waits this way.** Every stage that blocked: the nmap fast scan (its naabu sweep and its nmap fingerprint are two waits), the nuclei
technology and AI-targeted passes, WPScan (in the pipeline and the quick pass), the weekly deep nuclei pass, the testssl.sh sweep, the UDP sweep,
an internal scan and an internal range's discovery. Their entry points are `discovery._run_pipeline` and `run_host_pipeline` (adapters `pipeline`
and `pipeline.host`, which also serve host assessments and re-tests through continuations), `internal_scan.run` (`pipeline.internal`),
`internal_discovery.discover_range` (`internal.discover`), `testssl_scan.sweep_all` (`sweep.testssl`), `udp_scan.run` (`sweep.udp`),
`tasks.weekly_deep_nuclei` (`nuclei.weekly`) and `wpscan_scan.run_quick` (`wpscan.quick`). OpenVAS never blocked (each tick polls its task);
its task is now watched (`stage_runs.watch`, adapter `openvas.import`), so a report is imported as soon as it arrives instead of at the next tick. A bbot discovery on a Sentinel (`sentinel_stream.dispatch_stream`, a streamed task) still waits in its worker, because it stores each batch as it arrives; moving it to a run is the `watch` pattern below, with the batches stored by the callback.

**How a stage is continued: replay.** A stage is unchanged code that calls `dispatch_or_none` or `dispatch_many`. Inside a run those calls are
keyed by kind and target (`stage_runs.task_key`; a WPScan token and the nuclei template policy are left out of the key). The first pass that
asks for a key creates the task and stops (`stage_runs.Suspend`, a `BaseException`, so a stage's own `except Exception` never takes it for a
failure). The callback runs the same stage again; this time the call finds its task over and ends it exactly as the blocking wait did:

- the same activity line is closed (`Sentinel X checked in nmap work for ...`, or `No Sentinel picked up ...`);
- `_no_local` makes the same decision: `ScannerUnavailable` for a kind `CVENGINE_LOCAL_FALLBACK` keeps off this server (the stage says it
  waits, records nothing in the ledger, releases its claim), or one `ScannerFallback` row with the same reason (`not_claimed_in_time`,
  `slot_busy`, `failed_then_local`, `completion_timeout`, `over_chunk`, `no_scanner`, `partial_result`) and the local run;
- `dispatch_many` keeps its window (the free slots, the stage's share, `CVENGINE_STAGE_PARALLEL`), refills it when any chunk ends, stops
  sending when a chunk goes unclaimed or the last Sentinel leaves, and yields nothing until every chunk is over, so a stage never handles a
  chunk's result twice. A nuclei pass sends all its targets in one call when it runs this way, so its findings and counts are saved once.

What a stage does before its waits is done again on each pass, so it must be safe to repeat. The ledger makes the scan stages so (a naabu sweep
that was recorded is not run again). For the rest the engine keeps what an earlier pass did: a pipeline stage that finished returns the result
it had and its `ScanActivity` row is not made twice (`discovery._stage`); `stage_runs.once(name, fn)` keeps a step that must not repeat (the AI
targeting plan, an inter-stage carry-forward, the internal scan's address row); an activity line an earlier pass wrote is not written again;
a fallback row is written once per decision; and a Redis claim taken inside a pass (the ledger's, a sweep's, the discovery lock of the target)
belongs to the run and is held, not released, while the run waits, then taken back by the next pass.

**The budgets.** The claim budget (8 s), the queue budget for a busy fleet, the completion budget counted from the claim, the reap of a Sentinel
that stopped heartbeating, the last Sentinel leaving and a stop of the scan (which cancels fanned-out chunks, as before) are kept by
`stage_runs.drive`: a Celery countdown at the moment the next budget ends, at least once a minute, on `cve_feed_queue`. A stop of a scan
(`resources.request_abort`) drives its runs at once.

**Restarts.** Nothing lives only in a worker. `stage_runs.tick` (beat, every minute, `stage_runs_tick`, and the 15-minute `reap_stuck_jobs`)
drives a waiting run whose deadline passed without a drive, queues again the callback of a ready run that never started, and makes ready again a
run whose pass lost its worker (its lease, renewed every minute while a pass works, ran out); that callback replays the stage. The orphan reaper
(`reaper.expire_orphaned_running`) leaves a scan or host assessment alone while a run carries it. During an update, old workers' blocking waits
finish as before; the new table is new, so nothing old writes to it. The callback, the drive and the tick are exempt from the pause gate: they
finish work already in flight, as a blocked worker did.

**Wake-ups (`agentapi.sentinel_notify`).** A queued task (any creator: a `post_save` hook) pushes a token on
`cvengine:sentinel:wake:agent:<id>` of every live Sentinel that could take it; a claimed or ended task pushes one on
`cvengine:sentinel:wake:task:<id>` and, when it ended, on the agent key of the Sentinel whose slot it freed. The long poll (`next_task`) and the
blocking dispatcher wait with `BLPOP` on those keys instead of sleeping one second or half a second. Each wait still wakes by itself after the
safety interval (`CVENGINE_SENTINEL_WAKE_POLL_SECONDS`, default 5); a long poll whose task is held back for a preferring or less loaded
Sentinel looks again after one second, as before, since that task becomes free by time alone. Without Redis the waits sleep as before. A reported
result wakes its `StageRun` directly: `task_ended` queues the callback in the same request.

**Metrics.** `stage_runs.metrics()`: `waiting` and `waiting_by_kind` (the stage a pipeline waits in, such as `nmap_scan`, or the adapter for a
sweep), `oldest_wait_seconds`, `ready`, `callback_latency_p50_seconds` and `_p95_seconds` (last task ended to callback started, last hour),
`slots_freed` (the workers the waiting runs would hold if they blocked: one each), `freed_seconds_1h` and `resumed_1h`. They are in the system
status (`sentinels.stage_runs`, and a `problems` line when a stage has waited four hours) and in `GET sentinels/live` (`stage_runs`, over the
caller's projects), shown as a line under the summary of the Sentinels page.

### Writing an adapter for a new kind

A new stage (the WAF fingerprint, `nmap_full`, the probe kinds, `secrets_scan`) gets all of this by calling `dispatch_or_none` or
`dispatch_many` from a stage that is entered through `stage_runs.run`. The adapter is three things:

```python
from agentapi import stage_runs

def run_for_scan(scan_id, runner=None):
    if runner is not None:                       # a test's seam: no StageRun, the stage waits in its worker
        return _run(scan_id, runner)
    return stage_runs.run('waf.scan', {'scan_id': scan_id},       # JSON only: ids and flags, never a credential
                          first=lambda: _run(scan_id, None), scan=scan_id)

def _resume(context):                            # the completion callback: the same work, from the context
    return _run(context['scan_id'], None)

stage_runs.adapter('waf.scan', queue='discovery_queue')(_resume)  # the queue the work belongs on
```

and the module goes in `stage_runs.ADAPTER_MODULES`, so a worker that did not import it can still run its callback. Inside a pipeline stage
(`discovery._run_stages`) nothing more is needed: the `pipeline` adapter replays the pipeline and `_stage` keeps the finished stages. A caller
that does something with the result passes `then=('<continuation>', {args})` and registers it with `@stage_runs.continuation`; `run` returns
`stage_runs.is_waiting(result)` while it waits. Code before the dispatch must be safe to repeat: use the ledger, `stage_runs.once`, and
`stage_runs.remember` / `recall` for a sweep's place in its list (see `testssl_scan.sweep`). A job that creates its own tasks (a streamed bbot job)
uses `stage_runs.watch(adapter, task_ids, context)` to be called back when they end.

