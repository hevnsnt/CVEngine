# The built-in scanner

Every install runs a scanner next to the server: the cvENGINE Sentinel, as the `scanner` compose service, shown as **CVEngine Scanner**. The server enrolls it with nobody typing a secret, and from then on the scan tools run in it, not on the server: the nmap fast scan, the naabu sweep, the nuclei light, targeted and deep passes (signed-in ones included), testssl, the UDP sweep and the WPScan quick pass. The design is in [SCANNER-ARCHITECTURE.md](SCANNER-ARCHITECTURE.md); the variables are in [CONFIGURATION.md](CONFIGURATION.md#built-in-scanner).

It needs nothing from you. A new install starts it (`sudo ./install.sh`), an update from 1.3 adds it, and every update after that replaces its image and checks it came up.

## What it is

- **The image** is `ghcr.io/hevnsnt/cvengine-sentinel`, pinned by digest in `scanner.lock.json` at the top of the repository. A release runs exactly the scanner it was tested with: a tag that moves changes nothing. The Sentinel repository publishes it for amd64 and arm64 with an SBOM and provenance, and it contains no git, Go, GVM stack or docker socket. While the lock names no published digest, the image is built from the Sentinel commit the lock names (`make scanner-build`, below).
- **Its network** is the celery container's: the service joins celery's network namespace (`network_mode: service:celery`). Its scans leave from exactly where the server's own did, from the same address, through the Tailscale sidecar's route when that profile is on (the sidecar lives in the same namespace), and on the host network or macvlan overlays when you use one. It reaches the server as `http://web:8000` (on the host network overlay, `http://127.0.0.1:8000`, which that overlay publishes on loopback). Nothing connects to it.
- **Where it scans from, for the rest:** the server sends it, in its settings, the egress proxy of **Settings > Proxy** and the private networks the server's own scans may reach (all of private space with `CVENGINE_ALLOW_PRIVATE_TARGETS`, the tailnet with the Tailscale profile). nuclei, WPScan, testssl.sh and wafw00f go through the proxy as they did on the server; nmap, naabu and the UDP sweep use raw sockets and go direct, as on the server. No other Sentinel is ever sent these settings or honours them.
- **Its rights** are those of any Sentinel enrolled for the whole instance, with one addition: it alone may run signed-in work (below). Its capability policy is on its card on the Sentinels page; a fresh built-in scanner ships with OpenVAS denied (it has no GVM stack; the server's own OpenVAS add-on runs that).
- **Its memory** is limited to 2 GB (`SCANNER_MEM_LIMIT`; the installer writes 1 GB on a host with less than about 7 GB). See [DEPLOYMENT.md](DEPLOYMENT.md#memory).
- **It never updates itself.** The server's updater replaces its image ([UPDATES.md](UPDATES.md#the-built-in-scanner)).

## What moves, and what does not

What moves to the scanner is the work that already is a Sentinel task kind: the nmap fast scan, the naabu sweep, the nuclei light, targeted and deep passes, testssl, the UDP sweep, the WPScan quick pass and the thorough WPScan pass (kind `wpscan_thorough`, hours per site, one at a time per project), and since 1.4 (contract version 3) the all-ports nmap sweep and the version pass after it, the nmap script probe of a single port, wafw00f, the node2shell check, the database exposure probes, the RDP login-screen screenshot (the AI reading of it stays on the server), the scan path check and the AI template check. The last two go only to the built-in scanner. With `CVENGINE_LOCAL_FALLBACK=none` those are never run on the server again; a stage that needs one waits for a scanner instead.

What does **not** move yet, and so still runs on the server (the celery container) whatever the scanner does:

- bbot discovery (the work conductor goes on starting it);
- the HTTP and version probes and the other in-process probes: route and signed-out checks, other sites on an address (vhost), applications under a path, cloud storage buckets, suppliers, retired-name checks, DNS and mail hygiene;
- signed-in nuclei passes and signed-in template tests, which use a stored credential;
- the maintainer's approval of a reviewed AI template (a loopback fixture) and `nuclei -update-templates`.

So "scanner offline" does not mean no traffic leaves the server: those checks keep going while the scanner is down, and only the kinds taken off the list wait. The full inventory is in [SCANNER-ARCHITECTURE.md](SCANNER-ARCHITECTURE.md#what-exists-today).

## How it enrols, and re-enrols

The server (`agentapi/builtin_scanner.py`, at celery's start and then every five minutes) keeps one instance-wide enrollment ready, owned by the oldest App Admin, and writes it as a provisioning blob to `/var/lib/cvengine-scanner/blob` on the `scanner_bootstrap` volume, which only celery (writes) and the scanner (reads) mount. The scanner reads it from that file (`CVENGINE_SENTINEL_BLOB_FILE`), redeems it once and keeps its token in the `scanner_state` volume. The installer writes the first blob right after it creates the admin account, so a new install has its scanner enrolled within a minute or two.

When the server stops accepting the scanner's token (it expired, or was revoked), the scanner forgets it and enrols again with the next blob the server writes, which it does as soon as it sees the scanner lost: no person is involved and the container does not restart. A blob the scanner already redeemed, or one the server refused, is never tried twice.

## Health and restarts

The container's health check passes while the scanner's heartbeats reach the server; it fails after three minutes without one (`docker compose ps` shows `unhealthy`). Docker itself never restarts a container for being unhealthy, so the scanner watches its own heartbeats too: after three minutes without one it exits, and `restart: unless-stopped` starts a fresh process. While it waits for its first enrollment it counts as healthy.

## When the scanner is away

A scan never fails because the scanner is restarting or gone. Once the built-in scanner has enrolled, its kinds never run on the server again (`CVENGINE_LOCAL_FALLBACK` unset). A stage that needs one waits instead: nothing is marked failed and nothing is recorded, so its targets stay due. A strip on every page says **Scanner offline: ... work is waiting. Nothing has failed; it resumes automatically when a scanner reconnects.**, System status carries `scanning.scanner.offline: true` and, for an App Admin, a `problems` line. The hosts of a scan whose stage waited are queued again (a deferred re-test, due ten minutes later, `CVENGINE_SCANNER_REQUEUE_MINUTES`, and held back for as long as a scanner is still missing), so the work runs soon after the scanner is back and not at the target's next scheduled scan.

What still runs on the server whatever the scanner does: bbot discovery, the HTTP and version probes and the other in-process checks, the all-ports nmap sweep and its version pass, the nmap script probes of single ports, wafw00f, the node2shell check, the database exposure probes, the RDP login-screen screenshots and the signed-in CVE template check (`templategen`). Those move in later phases ([SCANNER-ARCHITECTURE.md](SCANNER-ARCHITECTURE.md#what-exists-today)).

`CVENGINE_LOCAL_FALLBACK=all` in `.env` (then `make up`) lets every kind run on the server again, the way 1.3 did: the escape hatch while you sort a scanner out.

## Signed-in work

A nuclei pass that uses a stored sign-in (**Targets**, a target's stored sign-in) runs on the built-in scanner too. The task names the credential by a reference only; the scanner reads it once, through `POST /api/v1/sentinel/tasks/<id>/secret`, which the server answers once per task and writes to the audit log (`sentinel.secret.read`). It holds the credential in memory and, for the run, in a 0600 file on a memory file system, and wipes it afterwards. No other Sentinel is ever offered such a task, and a built-in scanner image too old to read sign-ins is not offered it either. Without a scanner that can, the pass waits like any other (or runs on the server, with `CVENGINE_LOCAL_FALLBACK=all`).

## Checking it

```bash
docker compose ps scanner                                      # running, and (healthy) once it heartbeats
docker compose logs --tail=50 scanner                          # or: make scanner-logs
docker compose exec scanner python3 -m client.control heartbeat && echo "reaches the server"
```

The log of a first start shows `bootstrapping from the enrollment file`, `bootstrap succeeded; token persisted at /var/lib/cvengine-sentinel/token.json`, a warning that it talks to the server over plain http (expected: the compose network), then `Sentinel CVEngine Scanner starting`. Lines that start `heartbeat failed`, `poll failed` or `could not register` mean it cannot reach the server.

In the interface, **Sentinels** shows a card named **CVEngine Scanner** with a **Built-in** chip, checking in, with no **Update now** button. System status (`GET /api/v1/system/status`, or the `get_system_status` tool) has:

```json
"scanning": { "builtin_scanner": { "enabled": true, "enrolled": true, "live": true, "agent_id": 3, "name": "CVEngine Scanner", "last_seen": "..." } }
```

Everyone sees `enabled`, `enrolled` and `live`; the rest is for an App Admin, who also gets a line in `problems` when the scanner is not enrolled ten minutes after the server wrote its enrollment, or is enrolled and not checking in. The Sentinels list API marks its row `builtin: true`.

To see that nothing runs on the server during a scan:

```bash
docker compose exec celery sh -c 'pgrep -af "nmap|naabu|nuclei|testssl|wpscan" || echo none'
```

Expect `none`, or only the work that stays on the server by design (above): nmap with `-p-` or `--version-intensity 5`, the single-port nmap script probes, nuclei run by the CVE template check, and WPScan with `--plugins-detection mixed`. Count what the scanner did, by kind and outcome:

```bash
docker compose exec -T celery python3 manage.py shell -c "
from django.db.models import Count
from agentapi.models import SentinelTask
for r in SentinelTask.objects.values('kind', 'status').annotate(n=Count('id')).order_by('kind', 'status'):
    print(r['kind'], r['status'], r['n'])"
```

## Building it from source

`make scanner-build` builds the image from the Sentinel commit `scanner.lock.json` names (10 to 25 minutes; on arm64 nmap is compiled) and tags it `cvengine-sentinel-local:<version>` and `cvengine-sentinel-local:latest`. It is the fallback when the published image cannot be pulled (an offline host, a registry that refuses): set `CVENGINE_SCANNER_IMAGE=cvengine-sentinel-local:latest` in `.env` and run `make up`. An image set there is used as it is: never pulled over, never rolled back. Remove the line to go back to the pinned image. Building needs outbound HTTPS to the Ubuntu mirrors, nmap.org, go.dev and the Go module proxy, GitHub, testssl.sh, PyPI and rubygems.

## Turning it off

`CVENGINE_BUILTIN_SCANNER=0` in `.env`, then `make up`. The server stops writing enrollments and revokes the scanner's token (its tasks go back to the queue and the card shows revoked), `make up` and the updates remove the container, and every scan kind may run on the server again. `sudo ./install.sh --no-builtin-scanner` installs without it. Remove the line (and `make up`) to turn it back on: it enrols again as a new Sentinel.
