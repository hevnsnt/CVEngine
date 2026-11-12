# Sentinels

A Sentinel is a scanner you run on any machine of your own. It checks in with cvENGINE, takes scan work off a project's queue, runs the tool there, and sends the typed result back. cvENGINE validates and clips that result and stores it through the same code for every Sentinel.

Why run one:

- **Scale out.** Deploy one or a hundred. Each Sentinel checks in and takes work, so scanning spreads across as many machines as you have. Every Sentinel adds its own CPU, memory and network path.
- **Private networks.** The cvENGINE server never scans a private address. A Sentinel inside an office LAN, a VPC or a VPN is the only way to cover one ([Internal networks](#internal-networks)).
- **Another vantage point.** Scan your internet-facing targets from a different network or region than the cvENGINE server.

The server runs no scan of its own. Every install starts a built-in scanner next to it (a Sentinel, [BUILTIN-SCANNER.md](BUILTIN-SCANNER.md)), so a new install scans at once; external Sentinels add scale, private networks and other vantage points, and take work ahead of it ([below](#the-built-in-scanner-is-the-last-resort)).

## What a Sentinel runs

Thirty-six kinds of work (`contract_version` 4), each a capability the Sentinel declares. The list is `kind_since` in the contract, `cvengine_scanner/contract/sentinel_contract.json` in the [Sentinel repository](https://github.com/hevnsnt/cvENGINE-sentinel) (ten kinds since contract version 1, one since 2, twenty-five since 3); the code reads it from the installed library, and `tests/test_docs_accuracy.py` fails when this table and the contract disagree. **The server runs none of them**: every kind but `discover` is in `sentinel_dispatch.NEVER_LOCAL`, and `discover` is Sentinel-only by design.

| Kind                                             | Work (the tool that does it)                                                 |
| ------------------------------------------------ | ---------------------------------------------------------------------------- |
| `nmap`, `naabu`                                  | The service fingerprint pass and the port sweep (nmap, naabu)                |
| `nmap_full`                                      | The background full-port sweep (nmap) |
| `nmap_verify`                                    | Service detection with the reviewed NSE scripts on named ports (nmap) |
| `nmap_udp`                                       | The UDP exposure sweep (nmap)                                                |
| `nuclei_light`, `nuclei_targeted`, `nuclei_deep` | The HTTP and technology pass, the AI-targeted pass, and the weekly deep pass (nuclei) |
| `nuclei_validate`                                | The test of an AI-written template (nuclei; the built-in scanner while there is one, else your own Sentinels of contract 4 under the checks in [AI-REVIEWER.md](AI-REVIEWER.md#ai-written-checks-on-your-own-sentinels)) |
| `testssl`                                        | The TLS audit, one `host:port` per task (testssl.sh)                         |
| `wpscan`, `wpscan_thorough`                      | WPScan on a WordPress site: the quick pass, and the thorough pass of hours per site (WPScan) |
| `waf`                                            | WAF fingerprinting of a web host (wafw00f)          |
| `bbot_discovery`                                 | Discovery of subdomains and addresses, a streamed task (bbot, with gowitness) |
| `web_screenshot`                                 | Screenshots of a host's web pages, at most six pages per task (Playwright's headless Chromium) |
| `rdp_shot`                                       | The RDP pre-authentication screenshot (aardwolf) |
| `secrets_scan`                                   | Exposed secrets in the pages and scripts the route check read, `--no-validate` (Kingfisher) |
| `ssh_probe`                                      | A read-only inspection of SSH services: banner, host key types and sizes, offered authentication methods, algorithm lists, and the badkeys blocklist of compromised host keys (sshamble, one fixed check). No login or credential is ever sent |
| `node2shell`                                     | The read-only check for CVE-2026-111497 (vendored node2shell detector) |
| `db_probe`                                       | One credential-less connection to a database port, to read its greeting |
| `http_probe`, `route_probe`                      | The version and identity probes, and the anonymous web route check (Python, in the client) |
| `route_probe_signed`                             | The web route check signed in: reads a stored sign-in once and sends it only where it was stored for (built-in scanner only) |
| `vhost_probe`, `subdir_probe`                    | Other sites on an address, and applications under a path |
| `page_read`                                      | A validation re-test's HEAD of a URL or re-read of a host's front pages and scripts, the control GET of the result screen and the readme titles of a WordPress site's plugins |
| `bucket_check`                                   | The anonymous checks of cloud storage |
| `supplier_check`                                 | A third-party supplier's DNS, certificate, pages and MTA-STS file |
| `hygiene_check`, `dangling_dns_check`            | DNS, mail and certificate hygiene (SPF, DMARC, DKIM, CAA, MailFail), and the zone-cut checks of dangling-DNS findings |
| `dns_resolve`, `identity_check`                  | Name lookups for discovery, and the alias, name server, reverse name and certificate-name reads of a name or address |
| `alive_check`                                    | Whether a retired name's last known addresses still answer |
| `path_probe`                                     | The plain SYN and the FIN+PSH+URG probe that measure the path scans leave from (the built-in scanner while there is one, else your own Sentinels, each measuring its own path) |
| `openvas`                                        | A Greenbone scan, only when the [OpenVAS add-on](OPENVAS.md) is on           |
| `discover`                                       | A live-host sweep of a declared internal network                             |

Three kinds stay with the built-in scanner while the install has one (`sentinel_broker.BUILTIN_KINDS`): `path_probe`, `nuclei_validate` and `route_probe_signed`. `route_probe_signed` never leaves it (it reads a stored sign-in); with no built-in scanner, `path_probe` and `nuclei_validate` go to the project's own Sentinels whose contract version is at least the kind's `external_since` (`path_probe` 3, `nuclei_validate` 4). The server itself keeps the plans, the schedules, the budgets and the storing and judging of what comes back.

## External or internal, full or light

You choose two things when you provision a Sentinel, and can change both later.

- **Where it runs.** External (the default) is a Sentinel on the internet side, for the same targets the server scans. Internal means it sits inside a private network. The server grants it the capability `network:internal` from the choice made at provisioning; what a Sentinel says about itself never grants it, and an administrator can change it later (`PATCH agents/{id}` with `settings: {network}`, or the card's **Settings**). Resetting `network` to `null` restores the provisioned grant, or external when there is no matching enrollment. An external setting on the Sentinel itself limits an internal grant, so it receives no internal work until its machine reports internal. Only a Sentinel with both the server grant and a compatible machine setting is offered work for an address in a declared internal range.
- **Size.** Full also runs its own OpenVAS stack (several GB, hours of feed sync on first start). Light skips it and never takes OpenVAS work.

## Get one

1. Open **Scanners** in the left rail, then its **Sentinels** tab. In **Provision a Sentinel**, pick a scope, **Where it runs** and **Size**, then press **Provision**.
2. Copy the blob. It is one string holding a single-use secret that expires in 30 minutes.
3. On the machine that will scan (it needs Docker and outbound HTTPS to cvENGINE), clone the client from its own repository, [hevnsnt/cvengine-sentinel](https://github.com/hevnsnt/cvengine-sentinel), put the blob in `CVENGINE_SENTINEL_BLOB` in its `.env`, and run `docker compose up -d`. The page does this for you: after Provision it shows one command to paste on that machine (it clones the client, or reuses a clone already there, runs `setup.sh` with the blob, names the Sentinel after the machine and starts it), and a finished prompt to hand an AI agent with a shell on that machine, with the blob and your choices already in it. The same two strings are in the enrollment reply as `setup.one_liner` and `setup.agent_prompt`.
4. Watch it appear on the Sentinels page. The client keeps its own token in a Docker volume, so a restart never needs the blob again.

The client is a Docker Compose service. An AI agent can do all of this with the `generate_sentinel_enrollment` MCP tool.

**Scopes.** A project enrollment (needs the admin role in the project or its organization) covers one project. An organization enrollment (admin of that organization) covers every project of it, present and future. An instance enrollment (App Admin only) covers every project on the server. The scope comes from the secret, never from what the Sentinel says about itself.

## Approve, suspend, revoke

A Sentinel enrolled by an administrator starts active. One registered by anyone else waits for approval (**Approve** on its card). **Suspend** stops new work and releases what it holds at once, and **Reinstate** brings it back. **Revoke** is permanent. All three work from the Sentinels page and from the project's Sentinels tab (on the rows you may manage). A revoked Sentinel leaves those pages; **API keys, Agents in your organizations, Manage, Delete** removes it for good and revokes its token.

**Held back.** A new Sentinel (or other agent) of a user whose other agent an administrator suspended or revoked in the last 30 days starts suspended, so a revoked agent cannot come back under a new token. Its card reads `Suspended:` and then which agent caused it, its status and since when, and what to do: **Reinstate** the new one to use it, and reinstate or delete the old one so the next one starts normally. When the old one is revoked, the card also has **Delete <its name>**. Every such suspension is in the audit log (`agent.hold`). It never applies to an App Admin (their Sentinels, instance-wide ones included, start active whatever happened to an older one), to an agent that was itself only held back this way, to a deleted agent, or to a decision older than `CVENGINE_AGENT_HOLD_DAYS` days ([CONFIGURATION.md](CONFIGURATION.md#sentinels); `0` keeps it for as long as the old agent stays suspended or revoked). An organization admin is held back like anyone else, also for a Sentinel from an enrollment they generated: they cannot reinstate their own agent, so another administrator decides. After the window their new Sentinel still waits for approval while the old one stays revoked or suspended. A card shows **Reinstate**, **Delete**, **Suspend** and **Revoke** only to someone who may use them (not on your own Sentinel unless you are an App Admin, and not for a user who also works for an organization you do not administer); such a viewer also sees a general reason instead of the other agent's name. Details in [AGENT-API.md](AGENT-API.md#agents-and-assigned-work).

## The Sentinels pages

The **Sentinels** page groups cards by the organizations each Sentinel covers (an instance-wide one sits under Every organization). Each card has:

- A status orb and word: Working, Idle, Offline (not heard from for three minutes), Waiting for approval, or Suspended. A suspension with a reason reads `Suspended: <reason>` on that line.
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

### Sharing work between Sentinels (least loaded first)

With more than one live Sentinel for a project (the built-in scanner and an external one, or two external ones) the work is shared by load, not by who happens to ask first. A Sentinel's **load** is the tasks it holds now (claimed or running) over the tasks it may run at once, so a Sentinel set to 8 carries twice the tasks of one set to 4 at the same load. When a Sentinel asks for work and another **live, eligible** Sentinel is strictly less loaded and has room for the task, the task is left for that one for a short while: up to `CVENGINE_SENTINEL_BALANCE_DEFER_SECONDS` (default 60, a ceiling) and, for every kind a scan stage waits on, never longer than the claim window the stage waits for a Sentinel less two seconds (6 s by default), so balancing never costs a stage its Sentinel; OpenVAS tasks, which no stage waits for, keep the whole value. If the lighter Sentinel does not take the task in that time, the busier one may. Equal loads hold nothing back (the first to ask takes it), and the built-in scanner takes no part in it: it is the last resort ([below](#the-built-in-scanner-is-the-last-resort)), and signed-in work still goes only to it.

It never waits for a Sentinel that could not take the task: one that is not live, is updating itself, is at its limit, has the kind denied, withheld or at its per-kind cap, or whose scope, host patterns or internal-network rules keep it from the task. A preference wins over load (a task is held for a Sentinel that **prefers** its kind first, and a Sentinel that prefers a kind is never held back for a lighter one). With one live Sentinel nothing changes. `CVENGINE_SENTINEL_BALANCE=0` turns balancing off.

Each Sentinel card shows how busy it has been: a bar with the share of the last hour its slots were busy (the time the tasks it ran took, over an hour of every slot it has), the tasks it finished in that hour and how long the tasks it took had waited in the queue (typical and worst). The same figures, per Sentinel and per kind, with the queue depth by kind, are in `GET sentinels/live` and in the system status ([AGENT-API.md](AGENT-API.md#sentinels-scan-stage-agents)).

Only what the Sentinel declares can be enabled: a kind whose tool is missing or off on the machine shows "not available on this Sentinel (tool missing or off on the machine)" and offers nothing, and a kind turned off on the machine shows "turned off on the machine": the server cannot lift that, only a change on the machine can. **Use default** removes a Sentinel's own policy for a kind.

**Instance defaults** apply to a Sentinel with no policy of its own for a kind: one set for the built-in scanner (`builtin_kinds`, shipped as OpenVAS denied, so a fresh built-in scanner does not run OpenVAS until you allow it there) and one for every other Sentinel (`external_kinds`, empty by default: every declared kind is allowed). An App Admin sets them with `PUT sentinels/defaults` or `set_sentinel_defaults` ([AGENT-API.md](AGENT-API.md#sentinels-scan-stage-agents)). The order is: the machine's veto, the Sentinel's own policy, the default of its class, allow.

**Example: OpenVAS only on the Remote Sentinel.** Leave the shipped default (OpenVAS denied on the built-in scanner). The Remote Sentinel declares OpenVAS and has no policy against it, so only it takes OpenVAS work; the built-in scanner keeps everything else. If you deny it on both, the work stays due and every message says so ("OpenVAS is not enabled on any live Sentinel (off on CVEngine Scanner; off on Remote-1)").

### The built-in scanner is the last resort

When you add an external Sentinel, the built-in scanner steps back for the work it can take. A queued task that a live, eligible external Sentinel could run is left to it; the built-in scanner takes it only if no such Sentinel exists, or if the task has waited more than `CVENGINE_BUILTIN_FALLBACK_SECONDS` (default 120 seconds, `0` = at once) because the externals are full or not claiming. An external that is not heard from for three minutes, is suspended, has the kind off, is updating or does not cover the project or address is not "there" for the task, and the built-in scanner takes it without waiting. Kinds only the built-in scanner runs (scan path check, template check, signed-in route checks) and signed-in work are never held. A task never waits past its stage's queue budget: the grace is cut to leave the built-in scanner one claim window. Setting the built-in scanner to **prefer** a kind lifts the wait for it; **prefer** among external Sentinels and least-loaded sharing work as before. The Sentinels page lists the built-in scanner last as **Built-in, last resort**, with a plain explanation and how many tasks it and the external Sentinels each finished in the last 24 hours. Details: [SCANNER-ARCHITECTURE.md](SCANNER-ARCHITECTURE.md#the-built-in-scanner-is-the-last-resort).

## When no Sentinel is live

Before a stage hands work over, it asks for a live, eligible Sentinel with the right capability. With none, the stage waits: it records nothing, is not marked failed, and its targets stay due until a scanner is back (a strip on every page says so). With one, the work is queued and the stage waits: 8 seconds for a Sentinel with a free slot to claim it, 5 minutes for a slot when every Sentinel is at its limit, then a per-kind ceiling for the run itself (counted from the claim). On a timeout or failure the targets stay due and are tried again; nothing runs on the server.

Targets inside an internal network need a Sentinel that holds `network:internal`; OpenVAS needs one that declares `openvas`. Each dispatch shows as a line in the AI activity feed. Timings are in [CONFIGURATION.md](CONFIGURATION.md).

The message says why a kind has nowhere to go: **disabled** (a live Sentinel has it and the capability policy keeps it off), **offline** (a Sentinel that has it is not heard from), **withheld** (it keeps failing the kind, or its client is too old), **inactive** (pending or suspended) or **never** (no Sentinel declares it), for example "OpenVAS is not enabled on any live Sentinel (off on CVEngine Scanner; Remote-1 has it but is offline); the targets stay due". A kind turned off on every Sentinel that has it also shows on the page strip as "OpenVAS is turned off on every Sentinel that has it", not as an offline scanner.

No scan kind runs on the server (see [SCANNER-ARCHITECTURE.md](SCANNER-ARCHITECTURE.md): a stage with no Sentinel able to take its work waits and its targets stay due). What the server's own code still connects to is governed: on a cloud server, connections to port 25 are counted and paced (`CVENGINE_LOCAL_PORT_BUDGETS`, never more than 400 charged in any 60 minutes by default, never skipped; [Cloud hosts and port 25](CONFIGURATION.md#cloud-hosts-and-port-25)). Sentinels themselves are never paced: they run on other networks. For SMTP checks on a provider that blocks or throttles port 25, put a Sentinel on a network that allows it.

### Future: Sentinel egress capabilities

Not built (planned): a Sentinel would declare which egress ports it can reach, found by itself with a canary connection at start-up (for example, whether outbound port 25 works from its network), and the server would route the stages that need port 25 only to Sentinels that can reach it, instead of to any Sentinel with the tool. Today any eligible Sentinel takes the work, and a Sentinel whose own network blocks port 25 reports that port as filtered.

### The Sentinel's own watchdog

Each Sentinel watches itself (hung tools, a memory budget two long runs hold, orphan processes, a stuck heartbeat, a full disk); the page lists what it did lately
under its card ("Watchdog 2 min ago: stopped a hung nuclei (deep) scan: no output or CPU for 30 minutes"). Waiting for memory is shown amber, because it is
normal back-pressure, and red only past 20 minutes. Details: [SCANNER-ARCHITECTURE.md](SCANNER-ARCHITECTURE.md#the-sentinel-watchdog-and-the-sentinels-page).

## Security model

A Sentinel is exactly as untrusted as any other agent ([TENANCY.md](TENANCY.md)).

- **Results are typed and clipped.** Each kind has one fixed shape. Strings are clipped, lists capped, and anything unexpected is a `400`. Nothing it reports is run or used to build a command.
- **It sees little.** A task carries only its own target. An external Sentinel never receives stored sign-ins (only the built-in scanner reads one, through the secure read below), another project's data or database access. The one thing it may be sent besides its target is a project's discovery API keys, for that project's `bbot_discovery` tasks only and only as described in [Discovery API keys on your Sentinels](#discovery-api-keys-on-your-sentinels). WPScan's API token travels in its task and is scrubbed once the task ends.
- **Its own token.** A Sentinel's token has the scope `sentinel`: it reaches the Sentinel routes and nothing else (not the rest of the API, not MCP), so it is not its administrator's token. It lasts 90 days, and a heartbeat renews the same token in place when under 60 days are left. A Sentinel that was off for longer must be enrolled again.
- **Scope and leases.** It can only claim work in its enrolled scope and capabilities. A claimed task must be accepted within two minutes. A running task is kept by the heartbeat (which can also list the task ids it is running, so a task it dropped ends early) and lost after five minutes without one.
- **Results are bound to the task.** Ports and findings for an address that was not dispatched are dropped. A result body can be up to 24 MB; every other route takes 4 MB.
- **Nuclei runs the server's policy.** On a Sentinel Nuclei skips denial-of-service templates (`-etags dos`) and uses the approved-template snapshot the server runs, fetched from `GET /api/v1/sentinel/template-policy` and its `/bundle`.
- **Nuclei sends a port only the templates of the protocol that speaks there.** The task labels each `host:port` (`services`: `web`, `unknown`, or a protocol class such as `ssh`, `smtp`, `imap`, `tls`) from what the server observed (nmap, the stored http result, the port number) and carries a `budget` (`pause_ms`, `seconds`, `web_rate`). Web ports get the web templates (the raw tcp and javascript ones are left out) first, at most 25 requests a second to any one web host (`-per-host-rate-limit`; a deep pass of one host is up to six times slower than at the global 150 a second). Every other `host:port` runs on its own, one template at a time, with a pause of at least 500 ms between template runs (5.5 s on ssh) and at most 300 seconds. nuclei's own rate limit paces only http and dns, so the pause is the pace. A service port is default deny: the Sentinel runs on it only a template on the allowlist its library ships (`cvengine_scanner/data/nuclei_service_allowlist.json`: template id and the sha256 of the file, for the nuclei-templates release the image pins), so nothing that sends credentials, guesses a password, can lock an account or changes state on the target runs there, and no setting turns it on. A template that is not listed, or whose file differs from the recorded hash, does not run on a service port; the Sentinel's own release gate fails when the pinned release is not the one the list was generated for. The web pass is not held to this yet: under the all-templates policy (the default) it runs http default-login and payload templates. A port whose service has no class, or that nothing is known about, gets the generic network templates and never an http template. A task holds at most 6 non-web ports; the server sends the rest in further tasks, and a port a Sentinel could not fully check (out of time part way, some template runs failed, no template listing) is reported with the reason and stays due, but is asked again at most once a day (the ledger's `nuclei-failed` back-off, 24 hours), until a later run checks it in full. A port nothing named that answers with an SSH banner on connect is treated as ssh. A task can make the budget gentler, never harsher (`cvengine_scanner.flags.NUCLEI_SERVICE_BUDGET`). Measured in a lab: an ssh port got 44 connections, at most 2 open at once, 4 in a second. A Sentinel that predates this ignores the labels, so keep Sentinels updated.
- **Input guard.** Result and heartbeat bodies skip the attack-string scan, since they hold what scanned hosts said. Registration, bootstrap and every address are still checked.

### Secure read of a stored sign-in (built-in scanner only)

A task that needs a stored sign-in carries only a reference to it (`secret_ref`, such as `authcred:12`), never its value. `POST /api/v1/sentinel/tasks/<id>/secret` returns the decrypted credential (`{credential: {headers, cookie, target, host, origins, allow_untrusted_certificate, expires_at, revision}, task_id}`, `Cache-Control: no-store`) with these rules:

- Only the built-in scanner may call it, with its own token, for a task assigned to it that is `claimed` or `running` and names a credential. An external Sentinel, a person's token (full or read only) or a Sentinel's token for another agent's task is refused: `403` for a caller that is not the built-in scanner, `404` for a task that is not its own or not signed in.
- It works once per task. The server wins an atomic update of `secret_read_at` before it decrypts anything, so a second or concurrent read is a `409` and returns nothing.
- Every call, granted or refused, is written to the audit log as `sentinel.secret.read` with the task, the Sentinel, the credential reference and the outcome. The value is never in the audit log, a task row, an activity line or a log. It is limited to 6 calls a minute per token.
- A task with a `secret_ref` is never offered to any Sentinel but the built-in one, and only to a built-in scanner image that reads stored sign-ins (its heartbeat's `info.features` has `secret_read`): next task, queue counts and capacity all leave it out for the others. The task a Sentinel receives says `signed_in: true` and nothing more.

The signed-in Nuclei pass of a target with a stored sign-in sets it: one `nuclei_*` task per credential and chunk of up to 64 origins (`agentapi.sentinel_dispatch.signed_in_stream`). The built-in scanner reads the credential once for the task, runs Nuclei with it from a 0600 file on a memory file system, and wipes it afterwards. Without a built-in scanner that can, the pass waits for one: it never runs on the server.

### Discovery API keys on your Sentinels

A project can store API keys for bbot's discovery modules (Shodan, Censys and the like, Settings, API keys). They live encrypted on the server. Until now a discovery of a project that had keys ran only on the built-in scanner, so the keys never left the server, and on an instance without a built-in scanner it never ran. The owner of an instance can now let its own Sentinels run those discoveries.

**What leaves the server, and when.** The keys of one project, only to a Sentinel enrolled on this instance, only for a `bbot_discovery` task of that same project, only once per task, and only the modules and options bbot will use. A task carries the reference `bbotkeys:<project id>`, never a key; the Sentinel reads the keys with the same single-use `POST /api/v1/sentinel/tasks/<id>/secret` as above (the server decrypts only after winning the atomic single-use update, the response is `Cache-Control: no-store`). Nothing else is ever sent: not another project's keys, not a stored sign-in, nothing for another task kind.

**One gate.** `sentinel_stream.key_delivery_decision` decides, and the claim, the refusal, the secure read, the capacity answer and the explanations all use it. The built-in scanner is allowed as before. Any other Sentinel needs all of: an active, unrevoked Sentinel token, the project in its scope, `info.features` naming `bbot_keys` in its heartbeat (the Sentinel client reports it; an older client does not and is never sent a key: the server is gated on that feature, not on a version number), the instance setting **Send discovery API keys to my Sentinels** on (Settings, configMaxxing, Discovery API keys; `CVENGINE_SENTINEL_BBOT_KEYS`, on by default) and its own opt-out off (Sentinel settings, Discovery API keys: Never send). Every other task kind with a reference, every reference of another project and every stored-sign-in reference is refused for every Sentinel but the built-in scanner.

**On the Sentinel.** The keys are held in memory and in a `keys.yml` (mode 600) in a fresh private directory while bbot runs; they are never on a command line, in the environment, in the heartbeat or in a log. Every key is masked in bbot's error output, in each batch posted and in the final result. The directory is removed when the run ends, and one a crashed run left is removed at the next start. If a Sentinel host is compromised while a discovery runs, that project's keys are exposed: that is the trade-off of turning this on. Turn the instance setting off to keep the keys on the server; the built-in scanner then runs such discoveries, or they wait.

**Audit.** The read is audited as `sentinel.secret.read` (reference and outcome), and a granted read adds one `sentinel.discovery_keys.delivered` row: "discovery keys delivered to <Sentinel> for <project> (providers: shodan_dns, ...)". Provider (module) names only, never a value. The task row keeps the reference and the time of the read, never a key, and no result, partial batch, activity line or audit row carries one (tests hold this with a canary).

**When a discovery cannot run.** It is dispatched to the live Sentinels the gate allows, or to the built-in scanner. With none, the scan waits for a scanner and says why, in plain words: your Sentinels are set not to receive the keys (instance setting off), the Sentinel is set not to receive them (its own opt-out), or the Sentinel is too old to receive them safely (it must report `bbot_keys`: update it). The same Sentinel with the setting on and a current client takes the discovery with no other change.

## The result contract

What a Sentinel sends back for each task kind is written down once, as a JSON Schema: `cvengine_scanner/contract/sentinel_contract.json` in the scanner library of the [Sentinel repository](https://github.com/hevnsnt/cvENGINE-sentinel) (`contract_version` inside). The library is the single source of truth: the server installs it, pinned by commit sha in `web/requirements.txt`, and reads the file from the install (`agentapi/sentinel_contract.py`); it keeps no copy. The Sentinel validates its own results against the same file, so a field the server needs is not a thing a client author finds out about from a rejected result. The server still clips and validates everything it receives (`clean_result`); the contract is what a correct client keeps to, so nothing a good Sentinel sends is ever clipped or dropped.

**How a contract change lands.** Sentinel pull request first (the schema, its fixtures and the Sentinel's own contract tests, merged to the Sentinel `main`), then a server pull request that bumps the sha in `web/requirements.txt` to that merge commit and carries the server side (the broker's limits, the cleaners, the fixtures under `web/tests/fixtures/`). The server's `tests.test_sentinel_contract` fails until both sides agree. The pin is a commit sha, not a release tag, so landing a contract change needs no Sentinel release or version change. That pin is the known-good floor CI uses; the server image installs the newest Sentinel `main` over it when it is built (the `SENTINEL_REF` build argument, [UPDATES.md](UPDATES.md#the-sentinel-library-in-the-server-image)), and the About and Sentinels pages say which commit the contract was read from.

The tests tie the file to the server: every task kind has a schema, one fixture per kind (`web/tests/fixtures/sentinel_results/`) is valid and passes through the server unchanged, and every list bound, string length and enum in the file equals the broker's own limit, so changing one side alone fails CI. A change a client must follow bumps `contract_version` and is named in the CHANGELOG. This covers results (Sentinel to server); the targets the server hands out are the next piece.

A Sentinel says which contract it speaks: `info.contract_version` (a whole number, 1 to 1000) in its registration and heartbeat. A client from before the field is taken to speak version 1. The file lists `kind_since` (the version that introduced each kind) and `min_supported_contract_version` (the server speaks the current contract and the one before it), and a Sentinel is offered only the kinds its version can run; one older than the server still speaks is offered nothing and shows as `unsupported`. Every register and heartbeat answer carries `contract: {version, min_supported}` so the client can see for itself that it is behind, and the Sentinels list shows each one's `contract_version` and `contract_state` (`current`, `previous`, `unsupported`, `newer` or `unreported`).

Contract version 2 adds one kind, `waf` (wafw00f against the root of one web host): the target is `{host, ip, port, scheme}` and the result is `{outcome, products: [{name, manufacturer?}], generic}`, at most 20 products with names cut to 100 characters. The server stores a `waf` result through `cveFeed.waf_fingerprint.persist_waf_result`, and the WAF stage dispatches it. `waf` is offered only to a Sentinel that declares `contract_version` 2 or higher and lists `waf` in its capabilities; a Sentinel that declares 1, or nothing, is never offered it even if it lists it. `min_supported_contract_version` stays 1, so a Sentinel declaring 1 shows as `previous`.

Contract version 4 adds no kind. A `nuclei_validate` target carries `template_sha256` (the sha256 of its template text, required), its result may name the same hash, and the new top-level table `external_since` names the contract version from which a Sentinel other than the built-in scanner may be offered a kind the built-in scanner used to keep (`nuclei_validate` 4, `path_probe` 3). A contract-4 Sentinel runs a check only after asking `GET sentinel/tasks/{id}/check` which hash its server approves for the task ([AI-REVIEWER.md](AI-REVIEWER.md#ai-written-checks-on-your-own-sentinels)). The frozen fixtures of version 3 are in `web/tests/fixtures/sentinel_results/v3/`.

## Troubleshooting

- **"No scanner could take this work" or a task that was not picked up in time.** The targets stay due and the stage tries again. The Sentinel is offline, suspended, pending, out of scope, lacks the capability, or is busy. Check its card and the project's Sentinels tab. Internal targets need an internal Sentinel (one the server granted `network:internal`).
- **A task shows "lost (the Sentinel stopped answering)".** Its lease ran out: the Sentinel stopped heartbeating, or was suspended or revoked. Check its logs with `docker compose logs -f`. The stage already moved on.
- **The enrollment secret is refused (`403`).** It expired, was already used, or is mistyped. Provision again.
- **A Sentinel answers `401` after being off a long time.** Its token (90 days) expired. Enroll it again with a new secret.
- **Version shows `unknown`.** The Sentinel reports no version, or cvENGINE cannot reach GitHub (`CVENGINE_SENTINEL_VERSION_CHECK`). The API warns when self-update is Manual or Automatic but no updater runs on that machine.
- **Update now is refused.** Self-update is Off for that Sentinel.

See also: [ARCHITECTURE.md](ARCHITECTURE.md#sentinels) for the design, [AGENT-API.md](AGENT-API.md#sentinels-scan-stage-agents) for the API, [FRONTEND.md](FRONTEND.md#sentinels) for the pages, [documentation index](README.md).
