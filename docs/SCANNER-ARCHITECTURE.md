# One scanner for cvENGINE: the plan for 1.4

Status: design, on the `1.4-develop` branch. Nothing in this file is built yet except the result contract
(`web/agentapi/sentinel_contract.json`).

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
| `cveFeed/waf_scan.py` (146) | wafw00f | `waf` |
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
  expires. External Sentinels enrol the way they do today.
- **Transport**: HTTP pull for the built-in as well, with the same token, validation and trust model. A second channel would
  be a second code path. Latency is cut inside the one path: a Redis notify wakes the long poll and the dispatcher in place of
  polling every half second, and the long-poll waiter cap is lifted for the built-in token.
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
- **Updates**: the release manifest pins `(server tag, scanner digest)` and the updater swaps the pair with rollback. The
  built-in never updates itself. The version check compares against the digest the server expects, not GitHub's head.
- **Contract**: the file gains a `targets` half (server to scanner) next to `results`, a `contract_version` declared at
  registration and heartbeat, and a minimum contract version per kind. The server supports the current and previous
  contract for external Sentinels and sends a kind only to a Sentinel that can run it.

## Phases (strangler, never a big bang)

0. Result contract, fixtures and tests. Done in PR 276.
1. This inventory, kept current as work lands.
2. Publish the Sentinel image by digest with an SBOM. Add the `targets` half and `contract_version` to the contract. Contract half done: the `targets` half, `contract_version` declared at registration and heartbeat, `kind_since` and `min_supported_contract_version`, and the server offers a kind only to a Sentinel whose version can run it. The Sentinel client sending `info.contract_version` and the published image are not done.
3. The built-in scanner service in compose, enrolled automatically, shown in system status.
4. Make waiting non-fatal before any fallback is deleted. Today a stage waits eight seconds for any Sentinel to claim a task and
   then falls back or fails, so every scanner restart would fail scans. Add a "scanner offline" pause that reuses the existing
   pause the conductor honours, re-queue stages with a delay instead of failing them, and show a banner.
5. Move one kind at a time behind `CVENGINE_LOCAL_FALLBACK=<kinds>` (the switch exists: unset or `all` is today's behavior, `none` or a list of kinds takes kinds off the list; see the note below), delete each local path after the telemetry shows no fallbacks
   for a set number of days. Add the missing kinds from section B as they move.
6. Extract the shared library and delete the server's copies of the parsers and flags.
7. Probes and bbot: the scope-policy task and the streamed job type, then move them.
8. Drop the scan tools, Go and bbot from the server image.

## Risks

1. The scanner becomes a hard dependency. Healthcheck, restart policy, status line, and non-fatal waiting come first (phase 4).
2. The kinds list is longer than the eight that exist (section B). Deleting a local path before its kind exists breaks it.
3. Version coupling: two updaters must not exist, and "behind" must mean "not the digest this release expects".
4. The image is not reproducible today (it installs WPScan and updates it at build time). Pin and publish by digest first.
5. Per-task overhead at 10,000 hosts: testssl, UDP and WPScan are one task per target, each with rows and an activity line.
   Batch them in contract version 2.
6. Egress proxy, Tailscale and `CVENGINE_ALLOW_PRIVATE_TARGETS` lab installs apply to local scans and not to dispatched ones;
   they must reach the built-in through the managed settings channel.
7. Server tests that exercise scanning need a fake scanner.

## Single-box install

Add about 2 GB of memory and 1.5 GB of disk. If the scanner is offline, scans pause with a banner and are never marked failed.
Air-gapped installs get a release bundle with both image tarballs, the CVE seed and the template bundle, with the version
check off for the built-in.

## `CVENGINE_LOCAL_FALLBACK`

Unset (or `all`), every kind may still run on this server when no Sentinel takes it: nothing changes. `none` or a comma list of kinds
(`nmap,naabu`) names the kinds that may; any other kind is never run here. A stage that needs one raises
`resources.ScannerUnavailable` (a `MemoryBusy`, so stages that already treat that as "not the target's failure, it stays due" wait
correctly: testssl, UDP and WPScan do today) where it used to run the tool locally. The nmap, naabu and nuclei stages record a
failure for it as they do for any error until their handlers are written, so a kind is taken off the list only in the same
change that gives its stage a handler. Signed-in nuclei passes still run here by design until the secure read exists.

