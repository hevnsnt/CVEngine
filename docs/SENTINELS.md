# Sentinels

A Sentinel is a scanner you run on any machine of your own. It checks in with cvENGINE, takes scan work off a project's queue, runs the tool there, and sends the typed result back. cvENGINE stores that result exactly as if it had run the tool itself.

Why run one:

- **Scale out.** Deploy one or a hundred. Each Sentinel checks in and takes work, so scanning spreads across as many machines as you have. Every Sentinel adds its own CPU, memory and network path.
- **Private networks.** The cvENGINE server never scans a private address. A Sentinel inside an office LAN, a VPC or a VPN is the only way to cover one ([Internal networks](#internal-networks)).
- **Another vantage point.** Scan your internet-facing targets from a different network or region than the cvENGINE server.

A project with no live Sentinel scans on the server, as it always did.

## What a Sentinel runs

Ten kinds of work, each a capability the Sentinel declares:

| Kind                                             | Work                                                                         |
| ------------------------------------------------ | ---------------------------------------------------------------------------- |
| `nmap`, `naabu`                                  | The service fingerprint pass and the port sweep                              |
| `nuclei_light`, `nuclei_targeted`, `nuclei_deep` | The HTTP and technology pass, the AI-targeted pass, and the weekly deep pass |
| `testssl`                                        | The TLS audit (one `host:port` per task)                                     |
| `nmap_udp`                                       | The UDP exposure sweep                                                       |
| `wpscan`                                         | WPScan on WordPress sites                                                    |
| `openvas`                                        | A Greenbone scan, only when the [OpenVAS add-on](OPENVAS.md) is on           |
| `discover`                                       | A live-host sweep of a declared internal network                             |

Everything else (bbot, bucket checks, vhost and subdirectory sweeps, the weekly thorough WPScan pass, and any Nuclei pass that uses a stored sign-in) always runs on the server.

## External or internal, full or light

You choose two things when you provision a Sentinel, and can change both later.

- **Where it runs.** External (the default) is a Sentinel on the internet side, for the same targets the server scans. Internal means it sits inside a private network. The server grants it the capability `network:internal` from the choice made at provisioning; what a Sentinel says about itself never grants it, and an administrator can change it later (`PATCH agents/{id}` with `settings: {network}`, or the card's **Settings**). Resetting `network` to `null` restores the provisioned grant, or external when there is no matching enrollment. An external setting on the Sentinel itself limits an internal grant, so it receives no internal work until its machine reports internal. Only a Sentinel with both the server grant and a compatible machine setting is offered work for an address in a declared internal range.
- **Size.** Full also runs its own OpenVAS stack (several GB, hours of feed sync on first start). Light skips it and never takes OpenVAS work.

## Get one

1. Open **Sentinels** (the Agents group in the side rail). In **Provision a Sentinel**, pick a scope, **Where it runs** and **Size**, then press **Provision**.
2. Copy the blob. It is one string holding a single-use secret that expires in 30 minutes.
3. On the machine that will scan (it needs Docker and outbound HTTPS to cvENGINE), clone the client from its own repository, [hevnsnt/cvengine-sentinel](https://github.com/hevnsnt/cvengine-sentinel), put the blob in `CVENGINE_SENTINEL_BLOB` in its `.env`, and run `docker compose up -d`. The page does this for you: after Provision it shows one command to paste on that machine (it clones the client, or reuses a clone already there, runs `setup.sh` with the blob, names the Sentinel after the machine and starts it), and a finished prompt to hand an AI agent with a shell on that machine, with the blob and your choices already in it. The same two strings are in the enrollment reply as `setup.one_liner` and `setup.agent_prompt`.
4. Watch it appear on the Sentinels page. The client keeps its own token in a Docker volume, so a restart never needs the blob again.

The client is a Docker Compose service. An AI agent can do all of this with the `generate_sentinel_enrollment` MCP tool.

**Scopes.** A project enrollment (needs the admin role in the project or its organization) covers one project. An organization enrollment (admin of that organization) covers every project of it, present and future. An instance enrollment (App Admin only) covers every project on the server. The scope comes from the secret, never from what the Sentinel says about itself.

## Approve, suspend, revoke

A Sentinel enrolled by an administrator starts active. One registered by anyone else waits for approval (**Approve** on its card). **Suspend** stops new work and releases what it holds at once, and **Reinstate** brings it back. **Revoke** is permanent. All three work from the Sentinels page and from the project's Sentinels tab (on the rows you may manage). A revoked Sentinel leaves those pages; **Administration, Agents, Manage, Delete** removes it for good and revokes its token.

**Held back.** A new Sentinel (or other agent) of a user whose other agent an administrator suspended or revoked in the last 30 days starts suspended, so a revoked agent cannot come back under a new token. Its card reads `Suspended:` and then which agent caused it, its status and since when, and what to do: **Reinstate** the new one to use it, and reinstate or delete the old one so the next one starts normally. When the old one is revoked, the card also has **Delete <its name>**. Every such suspension is in the audit log (`agent.hold`). It never applies to an App Admin (their Sentinels, instance-wide ones included, start active whatever happened to an older one), to an agent that was itself only held back this way, to a deleted agent, or to a decision older than `CVENGINE_AGENT_HOLD_DAYS` days ([CONFIGURATION.md](CONFIGURATION.md#sentinels); `0` keeps it for as long as the old agent stays suspended or revoked). An organization admin is held back like anyone else, also for a Sentinel from an enrollment they generated: they cannot reinstate their own agent, so another administrator decides. After the window their new Sentinel still waits for approval while the old one stays revoked or suspended. A card shows **Reinstate**, **Delete**, **Suspend** and **Revoke** only to someone who may use them (not on your own Sentinel unless you are an App Admin, and not for a user who also works for an organization you do not administer); such a viewer also sees a general reason instead of the other agent's name. Details in [AGENT-API.md](AGENT-API.md#agents-and-assigned-work).

## The Sentinels pages

The **Sentinels** page groups cards by the organizations each Sentinel covers (an instance-wide one sits under Every organization). Each card has:

- A status orb and word: Working, Idle, Offline (not heard from for three minutes), Waiting for approval, or Suspended. A suspension with a reason reads `Suspended: <reason>` on that line.
- Its version, an **Update now** button and an update status. In **Settings** you can change its name, where it runs, its size, which kinds it never takes, and how many tasks it runs at once. The most recent change wins, whether made here or in the Sentinel's own `.env`.
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

## When no Sentinel is live

Before a stage runs its tool, it asks for a live, eligible Sentinel with the right capability. With none, the stage runs on the server, as before. With one, the work is queued and the stage waits: 8 seconds for a Sentinel with a free slot to claim it, 5 minutes for a slot when every Sentinel is at its limit, then a per-kind ceiling for the run itself (counted from the claim). On a timeout or failure the stage runs locally.

Two exceptions never run locally: targets inside an internal network, and OpenVAS while Sentinel-only mode is on. Each dispatch shows as a line in the AI activity feed. Timings are in [CONFIGURATION.md](CONFIGURATION.md).

## Security model

A Sentinel is exactly as untrusted as any other agent ([TENANCY.md](TENANCY.md)).

- **Results are typed and clipped.** Each kind has one fixed shape. Strings are clipped, lists capped, and anything unexpected is a `400`. Nothing it reports is run or used to build a command.
- **It sees little.** A task carries only its own target. A Sentinel never receives stored sign-ins, another project's data or database access. WPScan's API token travels in its task and is scrubbed once the task ends.
- **Its own token.** A Sentinel's token has the scope `sentinel`: it reaches the Sentinel routes and nothing else (not the rest of the API, not MCP), so it is not its administrator's token. It lasts 90 days, and a heartbeat renews the same token in place when under 60 days are left. A Sentinel that was off for longer must be enrolled again.
- **Scope and leases.** It can only claim work in its enrolled scope and capabilities. A claimed task must be accepted within two minutes. A running task is kept by the heartbeat (which can also list the task ids it is running, so a task it dropped ends early) and lost after five minutes without one.
- **Results are bound to the task.** Ports and findings for an address that was not dispatched are dropped. A result body can be up to 24 MB; every other route takes 4 MB.
- **Nuclei runs the server's policy.** On a Sentinel Nuclei skips denial-of-service templates (`-etags dos`) and uses the approved-template snapshot the server runs, fetched from `GET /api/v1/sentinel/template-policy` and its `/bundle`.
- **Input guard.** Result and heartbeat bodies skip the attack-string scan, since they hold what scanned hosts said. Registration, bootstrap and every address are still checked.

## Troubleshooting

- **"No Sentinel picked up work in time; it ran locally."** The Sentinel is offline, suspended, pending, out of scope, lacks the capability, or is busy. Check its card and the project's Sentinels tab. Internal targets need an internal Sentinel (one the server granted `network:internal`).
- **A task shows "lost (the Sentinel stopped answering)".** Its lease ran out: the Sentinel stopped heartbeating, or was suspended or revoked. Check its logs with `docker compose logs -f`. The stage already moved on.
- **The enrollment secret is refused (`403`).** It expired, was already used, or is mistyped. Provision again.
- **A Sentinel answers `401` after being off a long time.** Its token (90 days) expired. Enroll it again with a new secret.
- **Version shows `unknown`.** The Sentinel reports no version, or cvENGINE cannot reach GitHub (`CVENGINE_SENTINEL_VERSION_CHECK`). The API warns when self-update is Manual or Automatic but no updater runs on that machine.
- **Update now is refused.** Self-update is Off for that Sentinel.

See also: [ARCHITECTURE.md](ARCHITECTURE.md#sentinels) for the design, [AGENT-API.md](AGENT-API.md#sentinels-scan-stage-agents) for the API, [FRONTEND.md](FRONTEND.md#sentinels) for the pages, [documentation index](README.md).
