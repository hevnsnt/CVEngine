# Tailscale

Attach your cvENGINE to a Tailscale tailnet and its devices become targets automatically. They are scanned like any other host, and they are checked for Tailscale-specific problems: clients with known security fixes, key expiry, stale devices, broad subnet routes, an allow-all policy, broad SSH rules.

Nothing here changes an install that does not use it. The Tailscale service is off unless you turn it on, and without it the integration still lists devices and finds what the API shows, it just cannot scan them.

## How it works

Two separate things talk to Tailscale, with two separate credentials.

| | What it is | Credential | Needed for |
| --- | --- | --- | --- |
| **The scanner's node** | A `tailscaled` sidecar (the compose `tailscale` profile) that joins your tailnet as one more device | An auth key, in `.env.tailscale` | Scans reaching `100.x` addresses |
| **The tailnet reader** | The Tailscale control-plane API, read-only | An OAuth client (or an API access token), stored encrypted in Settings | The full device list, client versions, key-expiry settings, the policy file |

Either is useful alone. Without the API credential, cvENGINE reads what its own node can see (a status file the sidecar publishes, the `tailscale status --json` data): the peers it is allowed to reach, their addresses, OS, tags, online state and routes. Without the node, it lists and checks every device through the API but cannot scan any of them.

A sync runs every 15 minutes (and on **Sync now**) for each connected tailnet:

1. Read the tailnet from the API and from the local node, and merge them.
2. Import the devices into the chosen project as targets (see below), mark offline ones, and archive the ones that left.
3. Store the Tailscale facts, run the Tailscale checks and keep their findings current.
4. With auto-scan on, queue the normal discovery, nmap and nuclei pipeline for new and changed online devices, up to the per-run cap.

### How scans reach the tailnet

The `tailscale` service joins the **celery container's network namespace** (`network_mode: "service:celery"`). Every scan (bbot, nmap, naabu, nuclei, the validation probes) runs in the celery container, so putting `tailscaled` in that namespace puts the `tailscale0` interface and the `100.64.0.0/10` route exactly where the scanners are. Nothing else changes: no routing rules, no extra privileges for celery (the sidecar holds `NET_ADMIN` and `/dev/net/tun`, celery does not), no change for the web, database or Redis containers. The alternatives were worse:

- Userspace networking (`TS_USERSPACE=true`) offers only an outbound proxy, not an interface, and nmap cannot scan through a SOCKS5 proxy.
- Routing celery through a gateway container needs `NET_ADMIN` inside celery to add the route.
- Putting celery in the sidecar's namespace instead (`network_mode` on celery) would need a compose override that removes celery's networks, which depends on a recent Compose and breaks `extra_hosts`.

**How cvENGINE reads the node, and why not through its socket.** tailscaled's control socket stays inside the sidecar. A read-only mount does not stop a connection to a unix socket, and every container runs as root, which tailscaled treats as a local administrator: whoever could connect could reconfigure the node. So the sidecar instead rewrites `status.json` (the output of `tailscale status --json`, with the login URL removed) every 15 seconds into the `tailscale_status` volume, which **only the celery container mounts, read-only**. The web container has no Tailscale mount at all; Settings > Tailscale's Test connection asks a worker (a task that carries no credential). A status file older than 90 seconds counts as no node, which is how a dead sidecar shows. The volume exists whether or not the profile is on and is empty without it.

**Already have the Docker host on the tailnet?** Then containers can usually reach `100.x` through the host and you do not need the sidecar. In Settings > Tailscale set "How scans reach the tailnet" to **Already routed**. cvENGINE cannot check that, so it takes your word; if scans still fail the route is missing.

### Which addresses may be scanned

`100.64.0.0/10` and `fd7a:115c:a1e0::/48` are internal ranges, and cvENGINE refuses internal ranges unless `CVENGINE_ALLOW_PRIVATE_TARGETS=1`, which opens every private network. The Tailscale integration does not use that switch. Instead:

- An address is scannable **only for the project that owns the device, and only while all of this holds**: it is the tailnet address of a device the integration imported for that project and the device's target is named by that very address; the link is switched on, synced successfully (ok or partial) within the last 30 minutes (two sync intervals) and can reach its tailnet; for a link that depends on this server's own node, that node is up right now (a fresh status that says Running, re-checked every 30 seconds, so a dead sidecar stops tailnet scanning at once instead of letting the packets leave by the Docker default route); and no device of another link carries the same address. A failed sync withdraws the authority until the next good one. Any other address in the range is refused as before.
- **There is no default.** `is_scannable_ip` refuses these ranges unless the caller names the project (`project=`), and every scan stage that knows its project passes it (discovery, nmap, nuclei, the database exposure check, the full port sweep, change tracking, route checks, TLS checks). The IPv6 `fd7a:` address is recorded but the target is named by the IPv4 one, so only that is scannable. An address unwrapped from an IPv4-mapped, NAT64 or 6to4 spelling never carries it.
- An address a DNS name resolved to never gets it, and neither does one a person typed: Add targets, the bug bounty import and the legacy bulk import (including the HackerOne URL import) refuse every internal literal in every spelling, and `bbot` port events for another project's host never store a tailnet device's ports.
- Loopback, link-local, multicast and cloud metadata addresses (including `100.100.100.200`) are never allowed, and `100.100.100.0/24` (Tailscale's resolver) is never a device. `CVENGINE_BLOCKED_CIDRS` still wins.
- Tailnets reuse the `100.x` range, so an address that devices of two connected tailnets both carry is ambiguous and authorises nothing; the second tailnet's device is not imported.
- Connecting, changing and disconnecting are Settings actions (App Admin only) and are in the audit log (`tailscale.link.enable`, `.update`, `.remove`, `tailscale.sync`).

## Set it up

### 1. Prepare the tailnet

Create a tag for the scanner and let it reach the devices. In the policy file (Access controls):

```json
"tagOwners": { "tag:cvengine": ["autogroup:admin"], "tag:scan-target": ["autogroup:admin"] },
"grants": [
  { "src": ["tag:cvengine"], "dst": ["tag:scan-target"], "ip": ["*"] }
]
```

Give the scanner only what you intend to scan: tag the devices to be scanned (here `tag:scan-target`) and grant `tag:cvengine` access to that tag, not to `*`. The scanner can only reach what the policy lets it reach, and (see Security notes below) so can every tool that runs in the scanner's container. Nothing should have a grant whose destination is `tag:cvengine`; the node also runs with `--shields-up`. A device the policy hides from the scanner is listed but cannot be scanned.

### 2. Create the credentials

**The scanner's node** (Settings > Keys > Generate auth key in the Tailscale admin console): tick **Pre-approved** if device approval is on, add the tag `tag:cvengine`, and leave Reusable off. Or use an OAuth client with the `auth_keys` write scope and tag `tag:cvengine`; its secret then also goes in `TS_AUTHKEY`, and you set `TAILSCALE_EXTRA_ARGS=--advertise-tags=tag:cvengine`.

**The tailnet reader** (Settings > OAuth clients): create a client with only these read-only scopes:

- `devices:core:read`: the device list
- `devices:routes:read`: advertised and approved routes
- `policy_file:read` (it requires `devices:posture_attributes:read` and `devices:core:read`): the policy file, for the tailnet-wide findings

An API access token also works, but it expires after at most 90 days and carries the full reach of the person who made it. Prefer the OAuth client: it can be scoped and revoked.

### 3. Start the scanner's node

```
printf 'TS_AUTHKEY=tskey-auth-xxxx\n' > .env.tailscale      # the key from step 2
echo 'COMPOSE_PROFILES=tailscale' >> .env
echo 'TAILSCALE_HOSTNAME=cvengine' >> .env                   # the name shown in your admin console
docker compose up -d                                         # or: make up
docker compose exec tailscale tailscale status
```

The key is in `.env.tailscale`, not `.env`, because every variable in `.env` is handed to every container. It is only used to enrol: once the node is signed in, its state (the `tailscale_state` volume) keeps it signed in, and you can delete the file. Updates keep the profile when `COMPOSE_PROFILES` is in `.env`. Without `.env.tailscale` (and without an already enrolled node) the service stops with a message saying so, instead of printing an interactive login URL. It starts with `--shields-up`, so other devices cannot connect into the scanner's network namespace; `TAILSCALE_EXTRA_ARGS` adds flags to that (for example `--advertise-tags=tag:cvengine`).

The service needs the `/dev/net/tun` device and `NET_ADMIN`; on a host or container platform that provides neither (some managed container hosts), use the **Already routed** option instead. The sidecar's image is pinned to a version tag (`tailscale/tailscale:v1.104.2`) on purpose, because it runs inside the scanner's namespace. To update, change the tag in `docker-compose.yml` or set `TAILSCALE_IMAGE` in `.env`, check the [security bulletins](https://tailscale.com/security-bulletins) for the version you want, and run `docker compose up -d tailscale`. If you start the dev stack (`docker-compose.dev.yml`) the profile is not in it.

### 4. Connect the tailnet

Settings > Tailscale > **Connect a tailnet**:

- **Project**: the project the devices become targets of. One tailnet per project.
- **OAuth client id and secret** (or an access token): stored encrypted, never shown again. A blank field keeps the stored value.
- **Test connection** reads the device list and the policy without saving anything and says which part failed (credentials, a missing scope, no node).
- **Auto-scan** queues the normal pipeline for new and changed online devices. Off by default: devices are imported and checked, and the conductor scans them in its turn like any target.
- **Most devices one sync imports or queues** (default 100): the cap. New devices beyond it follow on the next sync; devices already imported are always kept up to date.
- **Filters**: only devices with these tags, never devices with these tags, only these operating systems.

The card shows the tailnet name, how many devices there are, how many are imported, online, offline and departed, the last sync, and the last error. **Sync now** queues a sync at once (at most one by hand per minute for a tailnet, from Settings, REST or MCP together); **Disconnect** archives the devices (the targets, findings and history stay) and ends the scan authority.

## What is imported

Each device becomes a **target named by its tailnet IPv4 address** (its IPv6 `fd7a:` address only when it has no IPv4), the form every scanner already handles as a bare IP. The MagicDNS name, OS and client version are in the target's description, and the device's facts are stored with it:

MagicDNS name, host name, addresses, OS, client version, update-available flag, tags, owning user, key expiry (and whether it is disabled), last seen, online state, advertised and approved routes, whether it is an exit node, and whether Tailscale SSH is offered. They show as chips on the host (`Tailscale device`, `ts tag:server`, `tailscale offline`, `tailscale subnet router`, `tailscale exit node`, `tailscale ssh`, `ts os linux`, `ts client 1.98.1`), the owner is filled in on the host's asset information when it is empty, and the REST and MCP device list carries all of it.

**Never imported:** devices shared in from another tailnet (they belong to someone else), devices that are not authorized, this server's own node, devices matching your skip filters, and anything an organization admin excluded (**Remove & exclude**): the exclusion is checked against the MagicDNS name, the host name and the address.

**Departed devices.** A device that leaves the tailnet (or stops matching the filters) keeps its row and its history. Its host is archived with the reason `Tailscale sync: ...` (never a pinned host, never one a person archived), its Tailscale findings are resolved, and its address stops being scannable. If it returns it is restored. An empty answer from Tailscale never retires anything.

## What is checked

Findings are hygiene findings: they appear under Findings with the remediation workflow (status, assignee, comments), the REST and MCP `hygiene` kinds, and the host. Each has a title, the reason for its severity, evidence, a fix, and a stable key (target, host and check name), so a finding stays one finding across syncs, is resolved when the condition clears and reopens if a fixed finding comes back. A check that depends on something a source did not report makes no finding.

| Check | Severity | Decided from | Why |
| --- | --- | --- | --- |
| `ts_client_security_update` | LOW to HIGH | Client version against [Tailscale's security bulletins](https://tailscale.com/security-bulletins) | The version is older than the bulletin's fixed release and the feature it needs is present on the device. Rated by cvENGINE, since Tailscale publishes no severity |
| `ts_update_available` | INFO | The API's `updateAvailable` flag | The control plane says a newer client exists |
| `ts_key_expiry_disabled` | LOW | API `keyExpiryDisabled` on a device with no tags | A user-owned device whose key never expires keeps access if lost or abandoned |
| `ts_stale_device` | LOW | Last seen 90 days or more ago, not connected | An unused authorised device is unwatched attack surface; deleting it in the control plane is what contains it |
| `ts_broad_subnet_router` | MEDIUM | Approved routes of /16 or wider (IPv4) | One device bridges a whole network into the tailnet |
| `ts_exit_node` | INFO | Both default routes approved | Worth knowing: peers' internet traffic can pass through it |
| `ts_remote_admin_exposed` | LOW or MEDIUM | Ports a scan found open on the device's tailnet address: telnet 23, Docker API 2375, VNC 5900, RDP 3389, SMB 445 | Every peer the policy lets in can try it. Whether it is authenticated is not tested |
| `ts_acl_allow_all` | MEDIUM or HIGH | Policy: an `accept` rule or grant from `*` (HIGH) or `autogroup:member` (MEDIUM) to everything | One compromised device can reach every service, which is how a worm spreads. The default policy of a new tailnet is exactly this |
| `ts_ssh_accept_broad` | MEDIUM | Policy: a Tailscale SSH `accept` rule that allows `root` or accepts every member | Widens who can open a root-capable session (see below) |
| `ts_tag_owners_broad` | MEDIUM | Policy: `tagOwners` that name `autogroup:member` | Any member can enrol a device with that tag and inherit its rules |
| `ts_funnel_broad` | MEDIUM | Policy: the `funnel` node attribute for `*` or `autogroup:member` | Any member can put a service on the public internet |

The bulletin check uses the bulletins whose affected clients and fixed release Tailscale states: TS-2026-004, -006 and -009 (Tailscale SSH on Linux or another Unix, fixed in 1.98.9), TS-2026-010 (SSH `acceptEnv`, 1.102.1), TS-2026-011 (4via6 subnet routers, 1.102.3, decided from an approved `fd7a:115c:a1e0:b1a::/64` route) and TS-2026-013 (all clients, 1.104.2). A bulletin that depends on a feature the data does not show (Serve, Funnel, Services, the web interface, macOS MDM) is left out, never assumed. The list is in `web/cveFeed/tailscale_checks.py`.

### Tailworm

The request that started this integration pointed at [tailworm.com](https://tailworm.com/), a security assessment published in October 2026 by Erica Windisch of Cyberdione Labs. It reports, against Tailscale 1.104.2 and headscale 0.29.5: Tailscale SSH socket forwarding running as root in `tailscaled` (reaching root-only sockets such as Docker's, replacing root-owned sockets, and winning races against the path allowlist), unrestricted egress choice through experimental `conn25` app connectors, memory exhaustion in the SSH library, headscale and DERP, and several `tailscale serve` and Funnel issues, plus the point that `check` mode on SSH rules gates only session establishment. Be clear about what this integration does with it:

- It is a single researcher's report. It names no fixed releases, no CVEs and no Tailscale advisory, and Tailscale has not confirmed it. cvENGINE did not reproduce any of it.
- What can be decided from a tailnet's own data is checked, and the findings say they rest on the report: broad or root SSH `accept` rules, the tag-ownership and Funnel-entitlement policy items, an allow-all policy, expiry and stale devices. Its recommended mitigations (per-pair grants, deleting devices at the control plane, enabling key expiry) are in the remediation text.
- Most of it cannot be seen from outside a device: whether a node runs `tailscale serve --tcp` to the LocalAPI socket, `TS_SERVE_ALLOW_ALL_INTERFACES`, which users hold `conn25` entitlements, the memory behaviour of `tailscaled`. These need host access and are not guessed at. The same goes for headscale: the report says forwarding cannot be disabled in v0.29.5, but the control-plane API here is Tailscale's; with a headscale control server only the local-node view (peers the node can see) is available.
- The overlapping fixes Tailscale did publish (TS-2026-004 and TS-2026-009 for SSH socket forwarding and root bypasses, TS-2026-005 for Serve and Unix sockets) are the bulletin check above. TS-2026-005 needs a non-root operator on a host running Serve, which no source here reports, so it is not applied.

Not checked, and why: `autoApprovers` (an approval is not a finding without knowing the intended range), `check`-mode periods (all valid values are the vendor's own), Tailnet Lock status, device approval and the other tailnet settings (no read endpoint or field name was verified against Tailscale's current API reference).

## REST and MCP

For project administrators (an organization admin of the project's organization, or an App Admin); everyone else, including project members and the audit role, gets `403`. Nothing returns a credential.

| | REST | MCP tool |
| --- | --- | --- |
| Connection status | `GET /api/v1/projects/{slug}/tailscale` | `tailscale_status` |
| Imported devices | `GET /api/v1/projects/{slug}/tailscale/devices?state=active\|offline\|departed\|all&q=` | `list_tailscale_devices` |
| Sync now | `POST /api/v1/projects/{slug}/tailscale/sync` | `sync_tailscale` |

Connecting, changing and disconnecting a tailnet, and its credentials, are Settings (App Admin) only. The findings are in the normal findings API: `type=hygiene` and checks starting with `ts_`.

## Security notes

- **The scanner's namespace is on your tailnet.** `tailscale0` lives in the celery container's network namespace, so every process in that container can reach whatever the scanner node's policy allows, not only the checks that go through cvENGINE's own address gate. cvENGINE's gate covers its in-process probes and the addresses it hands to nmap and nuclei, but the external scanner tools (nuclei, httpx, bbot) follow redirects and resolve names themselves, and their own protection against being steered at internal addresses has known gaps that existed before this integration. With the node attached, a scanned site that redirects to, or a name that rebinds to, a tailnet address can be followed by those tools. Treat the scanner node as a machine that an attacker-controlled web page might be able to aim at your tailnet: **scope its policy to what you mean to scan** (the example above), give no one a rule that reaches it, and prefer a dedicated tag.
- **Nothing connects in.** The node runs with `--shields-up`. The control socket is not mounted anywhere else, and the only thing celery gets is a read-only status file.
- **Host routing is taken as given.** With "Already routed" cvENGINE cannot verify the route, does not know which tailnet the Docker host is in, and does not exclude the Docker host's own tailnet address from being scanned if it appears as a device. Use it only when you know the host's tailnet is the one you connected.
- **Credentials.** The OAuth client or token is stored encrypted and never leaves the web and worker containers; the node's auth key is only in `.env.tailscale`.
- **Untrusted data.** Everything from Tailscale (names, hostnames, OS strings, tags, users, routes) is typed and clipped before it is stored: host names keep only name characters, a user must look like an email address, tags must look like tags, addresses must lie in the tailnet ranges.

## Troubleshooting

- **"Scans cannot reach this tailnet yet"**: the scanner's own node is not running in this tailnet, or its status file is stale. Check `docker compose ps tailscale` and `docker compose logs tailscale` (a missing `.env.tailscale` is reported there), that `.env` has `COMPOSE_PROFILES=tailscale`, that the key was valid, and that the policy lets `tag:cvengine` reach the devices. With API credentials the check is that the scanner's node appears in the API's device list; a node in a different tailnet does not count.
- **"the credentials lack a scope"**: add the scope named above to the OAuth client. The device list works without `policy_file:read`; the sync then reports the policy as not read and skips the tailnet-wide findings.
- **A device is listed but its scan fails**: the policy does not let the scanner's tag reach it, or the device is offline. Offline devices are not queued.
- **A device is missing**: it is shared in, unauthorized, filtered, excluded or beyond the cap (the card and the sync result say how many were skipped and why), or another connected tailnet already holds its address.
- **Rotating the credentials**: save a new client secret in Settings; a blank field keeps the old one. `make rotate-field-key` re-encrypts the stored credentials with the rest.

## Limits

- Needs Docker Compose with `network_mode: service:` and a host that gives containers `/dev/net/tun` and `NET_ADMIN`. The compose profile was written against Tailscale's documented container variables (`TS_AUTHKEY`, `TS_STATE_DIR`, `TS_USERSPACE`, `TS_SOCKET`, `TS_EXTRA_ARGS`, `TS_ACCEPT_DNS`, `TS_AUTH_ONCE`, `TS_HOSTNAME`).
- One tailnet per project, and the scanner's node is in one tailnet.
- `fd7a:` IPv6 addresses are recorded but the pipeline scans the IPv4 address. The full-port naabu sweep skips tailnet devices (nmap's top ports and the extra service ports still run).
- A sync that fails (credentials, a missing scope, no source) stops tailnet scanning for that project until the next good sync.
- The control-plane API is Tailscale's; headscale is not supported through it.
- Tailscale's API field names are read defensively: a field that is missing is unknown and produces no finding.
