# Sentinels

A Sentinel is a scanner you run on a machine of your own. It checks in with cvENGINE, takes scan work off a project's queue, runs the tool there, and sends the typed result back. cvENGINE stores that result exactly as if it had run the tool itself.

Why run one:

- **Another vantage point.** Scan your internet-facing targets from a different network or region than the cvENGINE server.
- **Private networks.** The cvENGINE server never scans a private address. A Sentinel inside an office LAN, a VPC or a VPN is the only way to cover one ([Internal networks](#internal-networks)).
- **Heavy scanners elsewhere.** nmap, nuclei and especially OpenVAS are hungry. A Sentinel takes that load off the server.

A project with no live Sentinel scans on the server, as it always did.

## What a Sentinel runs

Eleven kinds of work, each a capability the Sentinel declares (the list is `kind_since` in the [contract](../web/agentapi/sentinel_contract.json); the code reads it from there):

| Kind                                             | Work                                                                         |
| ------------------------------------------------ | ---------------------------------------------------------------------------- |
| `nmap`, `naabu`                                  | The service fingerprint pass and the port sweep                              |
| `nuclei_light`, `nuclei_targeted`, `nuclei_deep` | The HTTP and technology pass, the AI-targeted pass, and the weekly deep pass |
| `testssl`                                        | The TLS audit (one `host:port` per task)                                     |
| `nmap_udp`                                       | The UDP exposure sweep                                                       |
| `wpscan`                                         | WPScan on WordPress sites                                                    |
| `openvas`                                        | A Greenbone scan, only when the [OpenVAS add-on](OPENVAS.md) is on           |
| `discover`                                       | A live-host sweep of a declared internal network                             |
| `waf`                                            | WAF fingerprinting (contract version 2; no stage dispatches it yet)          |

Everything else (bbot, bucket checks, vhost and subdirectory sweeps, the weekly thorough WPScan pass, and any Nuclei pass that uses a stored sign-in) always runs on the server.

## External or internal, full or light

You choose two things when you provision a Sentinel, and can change both later.

- **Where it runs.** External (the default) is a Sentinel on the internet side, for the same targets the server scans. Internal means it sits inside a private network. The server grants it the capability `network:internal` from the choice made at provisioning; what a Sentinel says about itself never grants it, and an administrator can change it later (`PATCH agents/{id}` with `settings: {network}`, or the card's **Settings**). Resetting `network` to `null` restores the provisioned grant, or external when there is no matching enrollment. An external setting on the Sentinel itself limits an internal grant, so it receives no internal work until its machine reports internal. Only a Sentinel with both the server grant and a compatible machine setting is offered work for an address in a declared internal range.
- **Size.** Full also runs its own OpenVAS stack (several GB, hours of feed sync on first start). Light skips it and never takes OpenVAS work.

## Get one

1. Open **Sentinels** (the Agents group in the side rail). In **Provision a Sentinel**, pick a scope, **Where it runs** and **Size**, then press **Provision**.
2. Copy the blob. It is one string holding a single-use secret that expires in 30 minutes.
3. On the machine that will scan (it needs Docker and outbound HTTPS to cvENGINE), clone the client from its own repository, [hevnsnt/cvengine-sentinel](https://github.com/hevnsnt/cvengine-sentinel), put the blob in `CVENGINE_SENTINEL_BLOB` in its `.env`, and run `docker compose up -d`. The page also shows the equivalent one-line `./setup.sh` command.
4. Watch it appear on the Sentinels page. The client keeps its own token in a Docker volume, so a restart never needs the blob again.

The client is a Docker Compose service. An AI agent can do all of this with the `generate_sentinel_enrollment` MCP tool.

**Scopes.** A project enrollment (needs the admin role in the project or its organization) covers one project. An organization enrollment (admin of that organization) covers every project of it, present and future. An instance enrollment (App Admin only) covers every project on the server. The scope comes from the secret, never from what the Sentinel says about itself.

## Approve, suspend, revoke

A Sentinel enrolled by an administrator starts active. One registered by anyone else waits for approval (**Approve** on its card). **Suspend** stops new work and releases what it holds at once, and **Reinstate** brings it back. **Revoke** is permanent. All three work from the Sentinels page and from the project's Sentinels tab (on the rows you may manage).

## The Sentinels pages

The **Sentinels** page groups cards by the organizations each Sentinel covers (an instance-wide one sits under Every organization). Each card has:

- A status orb and word: Working, Idle, Offline (not heard from for three minutes), Waiting for approval, or Suspended.
- Its version, an **Update now** button and an update status. In **Settings** you can change its name, where it runs, its size, what it may take (below), and how many tasks it runs at once. The most recent change wins, whether made here or in the Sentinel's own `.env`.
- A chip for each kind it has, in three styles: allowed (with "preferred" and a cap when set), denied (strikethrough; hover for who denied it, or that it is turned off on the machine) and withheld (it kept failing, or its client is too old; hover for the time it is tried again). A kind the Sentinel does not declare has no chip.
- The tasks it holds now and its last five, each with kind, host, project and outcome (completed, partial, failed, lost).
- Counts for the last hour and day, and its average task time.

The self-update mode (Off, Manual or Automatic) is a setting too, with an instance-wide default. It is changed through the API or MCP, not that dialog (see [AGENT-API.md](AGENT-API.md#sentinels-scan-stage-agents)). Off never changes the Sentinel's code, Manual updates it only when you press Update now, Automatic updates it when a new version is out. cvENGINE also checks whether each Sentinel is behind the latest client every six hours.

A project gets a **Sentinels** tab once a Sentinel covering it has registered: those Sentinels, the project's recent work, and its internal networks.

## Internal networks

A project administrator declares a private network on the project's Sentinels tab: a range inside `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10` or `fc00::/7`, at most a /16. Declaring it only allows addresses inside it to become that project's targets. Nothing on the server scans them.

From there an internal Sentinel does the work:

- **Discovery.** A `discover` task per /24 sweeps the range for live hosts, weekly, and on demand through the API (`POST projects/{slug}/internal-ranges/{id}/discover`). Each answering address becomes a target. IPv6 ranges are not swept, and a host that stops answering is never deleted. A chunk nobody answered is an error on the range, not an empty network.
- **Scan.** Each internal target gets one pipeline, every step run by the Sentinel: a host record, an nmap fingerprint, a TLS audit of each TLS port, the UDP sweep, the nuclei technology pass, WPScan of WordPress sites, the AI-targeted nuclei pass, then CVE correlation. A scan starts by hand or from the daily sweep (7 days between scans of a target).
- **No local fallback.** With no internal Sentinel online the scan fails and says so, and the next sweep tries again. A quiet internal network is never shown as clean.
- **Never runs.** Route checks, probes, hygiene checks, database exposure checks and screenshots do not run for these hosts at all.

**Example: an office LAN.** Declare `10.20.0.0/24` on the project. Provision an internal Sentinel (project scope, Where it runs: Internal), run it on a machine in that LAN, and it appears active. The first discovery sweep finds the live hosts, which are scanned over the next sweeps.

**Example: offload OpenVAS.** Provision a Full Sentinel at organization scope on a roomy machine. With the add-on on, OpenVAS batches go to it, and an App Admin can turn on Sentinel-only mode so they never run on the server ([OPENVAS.md](OPENVAS.md)).

## What each Sentinel may take (capability policy)

A Sentinel *declares* what it can do (the tools it found, whether its OpenVAS stack is ready, and what its own machine turned off with `CVENGINE_SENTINEL_DISABLE`). The administrator chooses what cvENGINE hands it, per Sentinel and per kind, **for the built-in scanner exactly as for an external one**. In the card's **Settings**, "What it may take" has a row per kind:

- **Allow** offers the kind. This is what a declared kind gets when nothing is set.
- **Deny** never offers it: it is not claimed, not dispatched to it and a task of the kind it holds is released when you deny it.
- **Prefer** offers it and, for up to a minute (`CVENGINE_SENTINEL_PREFER_DEFER_SECONDS`, default 60, a ceiling; `0` turns it off) and never longer than the claim window a stage waits for a Sentinel (6 s by default) except for OpenVAS, whose tasks no stage waits for, holds a queued task of the kind back from every Sentinel that does not prefer it while a preferring one is live, in scope, not updating and has room. If the preferring Sentinel does not take the task in that time, the others may.
- **Max** caps how many tasks of that kind the Sentinel runs at once, inside its own limit. A queued task of a kind at its cap waits while the Sentinel takes other work.

Only what the Sentinel declares can be enabled: a kind whose tool is missing or off on the machine shows "not available on this Sentinel (tool missing or off on the machine)" and offers nothing, and a kind turned off on the machine shows "turned off on the machine": the server cannot lift that, only a change on the machine can. **Use default** removes a Sentinel's own policy for a kind.

**Instance defaults** apply to a Sentinel with no policy of its own for a kind: one set for the built-in scanner (`builtin_kinds`, shipped as OpenVAS denied, so a fresh built-in scanner does not run OpenVAS until you allow it there) and one for every other Sentinel (`external_kinds`, empty by default: every declared kind is allowed). An App Admin sets them with `PUT sentinels/defaults` or `set_sentinel_defaults` ([AGENT-API.md](AGENT-API.md#sentinels-scan-stage-agents)). The order is: the machine's veto, the Sentinel's own policy, the default of its class, allow.

**Example: OpenVAS only on the Remote Sentinel.** Leave the shipped default (OpenVAS denied on the built-in scanner). The Remote Sentinel declares OpenVAS and has no policy against it, so only it takes OpenVAS work; the built-in scanner keeps everything else. If you deny it on both, the work stays due and every message says so ("OpenVAS is not enabled on any live Sentinel (off on CVEngine Scanner; off on Remote-1)").

## When no Sentinel is live

Before a stage runs its tool, it asks for a live, eligible Sentinel with the right capability. With none, the stage runs on the server, as before. With one, the work is queued and the stage waits: 8 seconds for a Sentinel with a free slot to claim it, 5 minutes for a slot when every Sentinel is at its limit, then a per-kind ceiling for the run itself (counted from the claim). On a timeout or failure the stage runs locally.

Two exceptions never run locally: targets inside an internal network, and OpenVAS while Sentinel-only mode is on. Each dispatch shows as a line in the AI activity feed. Timings are in [CONFIGURATION.md](CONFIGURATION.md).

The message says why a kind has nowhere to go: **disabled** (a live Sentinel has it and the capability policy keeps it off), **offline** (a Sentinel that has it is not heard from), **withheld** (it keeps failing the kind, or its client is too old), **inactive** (pending or suspended) or **never** (no Sentinel declares it), for example "OpenVAS is not enabled on any live Sentinel (off on CVEngine Scanner; Remote-1 has it but is offline); the targets stay due". A kind turned off on every Sentinel that has it also shows on the page strip as "OpenVAS is turned off on every Sentinel that has it", not as an offline scanner.

## Security model

A Sentinel is exactly as untrusted as any other agent ([TENANCY.md](TENANCY.md)).

- **Results are typed and clipped.** Each kind has one fixed shape. Strings are clipped, lists capped, and anything unexpected is a `400`. Nothing it reports is run or used to build a command.
- **It sees little.** A task carries only its own target. A Sentinel never receives stored sign-ins, another project's data or database access. WPScan's API token travels in its task and is scrubbed once the task ends.
- **Its own token.** A Sentinel's token has the scope `sentinel`: it reaches the Sentinel routes and nothing else (not the rest of the API, not MCP), so it is not its administrator's token. It lasts 90 days, and a heartbeat renews the same token in place when under 60 days are left. A Sentinel that was off for longer must be enrolled again.
- **Scope and leases.** It can only claim work in its enrolled scope and capabilities. A claimed task must be accepted within two minutes. A running task is kept by the heartbeat (which can also list the task ids it is running, so a task it dropped ends early) and lost after five minutes without one.
- **Results are bound to the task.** Ports and findings for an address that was not dispatched are dropped. A result body can be up to 24 MB; every other route takes 4 MB.
- **Nuclei runs the server's policy.** On a Sentinel Nuclei skips denial-of-service templates (`-etags dos`) and uses the approved-template snapshot the server runs, fetched from `GET /api/v1/sentinel/template-policy` and its `/bundle`.
- **Input guard.** Result and heartbeat bodies skip the attack-string scan, since they hold what scanned hosts said. Registration, bootstrap and every address are still checked.

### Secure read of a stored sign-in (built-in scanner only)

A task that needs a stored sign-in carries only a reference to it (`secret_ref`, such as `authcred:12`), never its value. `POST /api/v1/sentinel/tasks/<id>/secret` returns the decrypted credential (`{credential: {headers, cookie, target, host, origins, allow_untrusted_certificate, expires_at, revision}, task_id}`, `Cache-Control: no-store`) with these rules:

- Only the built-in scanner may call it, with its own token, for a task assigned to it that is `claimed` or `running` and names a credential. An external Sentinel, a person's token (full or read only) or a Sentinel's token for another agent's task is refused: `403` for a caller that is not the built-in scanner, `404` for a task that is not its own or not signed in.
- It works once per task. The server wins an atomic update of `secret_read_at` before it decrypts anything, so a second or concurrent read is a `409` and returns nothing.
- Every call, granted or refused, is written to the audit log as `sentinel.secret.read` with the task, the Sentinel, the credential reference and the outcome. The value is never in the audit log, a task row, an activity line or a log. It is limited to 6 calls a minute per token.
- A task with a `secret_ref` is never offered to any Sentinel but the built-in one (next task, queue counts and capacity all leave it out for the others).

Not built yet: the scanner client that calls this endpoint, and the dispatch of signed-in work. Nothing sets `secret_ref` today, so signed-in Nuclei passes still run on the server as before.

## The result contract

What a Sentinel sends back for each task kind is written down once, as a JSON Schema: [`web/agentapi/sentinel_contract.json`](../web/agentapi/sentinel_contract.json) (`contract_version` inside). The Sentinel repo copies the file at the version it targets and validates its own results against it, so a field the server needs is not a thing a client author finds out about from a rejected result. The server still clips and validates everything it receives (`clean_result`); the contract is what a correct client keeps to, so nothing a good Sentinel sends is ever clipped or dropped.

The tests tie the file to the server: every task kind has a schema, one fixture per kind (`web/tests/fixtures/sentinel_results/`) is valid and passes through the server unchanged, and every list bound, string length and enum in the file equals the broker's own limit, so changing one side alone fails CI. A change a client must follow bumps `contract_version` and is named in the CHANGELOG. This covers results (Sentinel to server); the targets the server hands out are the next piece.

A Sentinel says which contract it speaks: `info.contract_version` (a whole number, 1 to 1000) in its registration and heartbeat. A client from before the field is taken to speak version 1. The file lists `kind_since` (the version that introduced each kind) and `min_supported_contract_version` (the server speaks the current contract and the one before it), and a Sentinel is offered only the kinds its version can run; one older than the server still speaks is offered nothing and shows as `unsupported`. Every register and heartbeat answer carries `contract: {version, min_supported}` so the client can see for itself that it is behind, and the Sentinels list shows each one's `contract_version` and `contract_state` (`current`, `previous`, `unsupported`, `newer` or `unreported`).

Contract version 2 adds one kind, `waf` (wafw00f against the root of one web host): the target is `{host, ip, port, scheme}` and the result is `{outcome, products: [{name, manufacturer?}], generic}`, at most 20 products with names cut to 100 characters. It is dormant groundwork: the server can validate and store a `waf` result (`cveFeed.waf_scan.persist_waf_result`, the same code a local run stores through), but nothing creates `waf` tasks yet and the local scan keeps running as before. `waf` is offered only to a Sentinel that declares `contract_version` 2 or higher and lists `waf` in its capabilities; a Sentinel that declares 1, or nothing, is never offered it even if it lists it. The kinds a version-1 Sentinel can run are unchanged, and `min_supported_contract_version` stays 1, so a Sentinel declaring 1 now shows as `previous`.

## Troubleshooting

- **"No Sentinel picked up work in time; it ran locally."** The Sentinel is offline, suspended, pending, out of scope, lacks the capability, or is busy. Check its card and the project's Sentinels tab. Internal targets need an internal Sentinel (one the server granted `network:internal`).
- **A task shows "lost (the Sentinel stopped answering)".** Its lease ran out: the Sentinel stopped heartbeating, or was suspended or revoked. Check its logs with `docker compose logs -f`. The stage already moved on.
- **The enrollment secret is refused (`403`).** It expired, was already used, or is mistyped. Provision again.
- **A Sentinel answers `401` after being off a long time.** Its token (90 days) expired. Enroll it again with a new secret.
- **Version shows `unknown`.** The Sentinel reports no version, or cvENGINE cannot reach GitHub (`CVENGINE_SENTINEL_VERSION_CHECK`). The API warns when self-update is Manual or Automatic but no updater runs on that machine.
- **Update now is refused.** Self-update is Off for that Sentinel.

See also: [ARCHITECTURE.md](ARCHITECTURE.md#sentinels) for the design, [AGENT-API.md](AGENT-API.md#sentinels-scan-stage-agents) for the API, [FRONTEND.md](FRONTEND.md#sentinels) for the pages, [documentation index](README.md).
