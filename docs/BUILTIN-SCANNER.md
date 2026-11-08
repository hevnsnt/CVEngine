# The built-in scanner

Every install runs a scanner next to the server: the cvENGINE Sentinel, as the `scanner` compose service, shown as **CVEngine Scanner**. The server enrolls it with nobody typing a secret, and from then on every scan tool runs in it, not on the server: nmap, naabu, nuclei (signed-in passes included), testssl.sh, WPScan, wafw00f, bbot, Kingfisher, sshamble, the screenshot browser and the in-process web, DNS and mail probes. The design is in [SCANNER-ARCHITECTURE.md](SCANNER-ARCHITECTURE.md); the variables are in [CONFIGURATION.md](CONFIGURATION.md#built-in-scanner).

It needs nothing from you. `sudo ./install.sh` takes `--sentinels=internal|both|external` for automation (on a terminal one optional question offers the same choice; the setup wizard in the browser covers the rest; `external` leaves it out entirely, nothing pulled or started, and scans wait until an external Sentinel is enrolled). A new install starts it (`sudo ./install.sh`), an update from 1.3 adds it, and every update after that replaces its image and checks it came up.

## What it is

- **The image** is `ghcr.io/hevnsnt/cvengine-sentinel:main`. The scanner **follows the newest published Sentinel**: `main` is the tag the Sentinel repository's publish workflow moves at every build of its `main` branch, which only receives code after its checks (all of its CI checks, image smoke tests included) have passed. The images are built for amd64 and arm64 and carry an SBOM and build provenance; they contain no git, Go, GVM stack or docker socket. That is all this says: nothing is reviewed by a person between a merge to the Sentinel's `main` and your scanner, and the checks are the gate. `scanner.lock.json` at the top of the repository is no longer a pin. It is the **known-good floor**: the Sentinel commit and result-contract version this release was tested with (and, for provenance, the digest that commit was published as). It sets what the update routine will accept (below) and which commit `make scanner-build` builds. A fix merged to the Sentinel reaches a fresh install, and an installed one at its next update or scheduled Scanner update, with nobody re-pinning anything.
- **Its network** is the celery container's: the service joins celery's network namespace (`network_mode: service:celery`). Its scans leave from exactly where the server's own did, from the same address, through the Tailscale sidecar's route when that profile is on (the sidecar lives in the same namespace), and on the host network or macvlan overlays when you use one. It reaches the server as `http://web:8000` (on the host network overlay, `http://127.0.0.1:8000`, which that overlay publishes on loopback). Nothing connects to it.
- **Where it scans from, for the rest:** the server sends it, in its settings, the egress proxy of **Settings > Proxy** and the private networks the server's own scans may reach (all of private space with `CVENGINE_ALLOW_PRIVATE_TARGETS`, the tailnet with the Tailscale profile). nuclei, WPScan, testssl.sh and wafw00f go through the proxy as they did on the server; nmap, naabu and the UDP sweep use raw sockets and go direct, as on the server. No other Sentinel is ever sent these settings or honours them.
- **Its rights** are those of any Sentinel enrolled for the whole instance, with one addition: it alone may run signed-in work (below). Its capability policy is on its card on the Sentinels page; a fresh built-in scanner ships with OpenVAS denied (it has no GVM stack, and the server runs no OpenVAS of its own: the add-on is a Greenbone stack on a Sentinel, [OPENVAS.md](OPENVAS.md)).
- **Its memory** is limited to 3 GB (`SCANNER_MEM_LIMIT`; the installer writes 1 GB on a host with less than about 7 GB). See [DEPLOYMENT.md](DEPLOYMENT.md#memory).
- **It does not update itself from inside.** Its own self-update is off. The server's updates and the Scanner update (below) replace its image from the host, and keep the new one only once it has checked in ([UPDATES.md](UPDATES.md#the-built-in-scanner)).

## What runs in it

Everything. All 36 task kinds of the result contract run on a Sentinel, and every kind but `discover` (internal ranges, an external Sentinel's work by design) is in `sentinel_dispatch.NEVER_LOCAL`, so none has a local path ([the list](SENTINELS.md#what-a-sentinel-runs)). The tools are nmap, naabu, nuclei, testssl.sh, WPScan, wafw00f, bbot, Kingfisher (secret detection), sshamble (the SSH host key check only) and Playwright's headless Chromium, plus the client's own probes. Three kinds go only to the built-in scanner: the scan path check (`path_probe`), the AI template test (`nuclei_validate`) and the signed-in route check (`route_probe_signed`). Signed-in nuclei passes are built-in only too.

What stays on the server is what it does with a report, not a request to a target: the plans, the schedules, the budgets, the storing and judging of results, `nuclei -update-templates` and the template set (the server image keeps the one nuclei binary for that), and the reading of the AI answers. The AI reading of an RDP screenshot travels to the AI reviewer container. So "scanner offline" means no scan traffic at all: the stages wait and their targets stay due ([When the scanner is away](#when-the-scanner-is-away)).

## The path of last resort

The built-in scanner is where work goes when nothing else can take it, not the first choice. While an external Sentinel is live and eligible for a task (the kind, the project, the address, a slot not required), the built-in scanner leaves the task to it. It takes the task when no such external exists, when the task has waited `CVENGINE_BUILTIN_FALLBACK_SECONDS` (default 120 seconds, `0` = at once) because the externals are full or not claiming, and always for the kinds only it runs: the scan path check, the template check, signed-in route checks, and signed-in or validating work. With only the built-in scanner (no external Sentinel enrolled) nothing changes: it takes every task at once. The Sentinels tab shows its card as **Built-in, last resort** with the number of tasks it handled against the externals' in the last 24 hours. The whole rule is in [SCANNER-ARCHITECTURE.md](SCANNER-ARCHITECTURE.md#the-built-in-scanner-is-the-last-resort).

## How it enrols, and re-enrols

The server (`agentapi/builtin_scanner.py`, at celery's start and then every five minutes) keeps one instance-wide enrollment ready, owned by the oldest App Admin, and writes it as a provisioning blob to `/var/lib/cvengine-scanner/blob` on the `scanner_bootstrap` volume, which only celery (writes) and the scanner (reads) mount. The scanner reads it from that file (`CVENGINE_SENTINEL_BLOB_FILE`), redeems it once and keeps its token in the `scanner_state` volume. The installer writes the first blob right after it creates the admin account, so a new install has its scanner enrolled within a minute or two.

When the server stops accepting the scanner's token (it expired, or was revoked), the scanner forgets it and enrols again with the next blob the server writes, which it does as soon as it sees the scanner lost: no person is involved and the container does not restart. A blob the scanner already redeemed, or one the server refused, is never tried twice.

## Health and restarts

The container's health check passes while the scanner's heartbeats reach the server; it fails after three minutes without one (`docker compose ps` shows `unhealthy`). Docker itself never restarts a container for being unhealthy, so the scanner watches its own heartbeats too: after three minutes without one it exits, and `restart: unless-stopped` starts a fresh process. While it waits for its first enrollment it counts as healthy.

## When the scanner is away

A scan never fails because the scanner is restarting or gone. No kind runs on the server (since 1.4 there is no local path for any of them). A stage that needs a scanner waits instead: nothing is marked failed and nothing is recorded, so its targets stay due. A strip on every page says **Scanner offline: ... work is waiting. Nothing has failed; it resumes automatically when a scanner reconnects.**, System status carries `scanning.scanner.offline: true` and, for an App Admin, a `problems` line. The hosts of a scan whose stage waited are queued again (a deferred re-test, due ten minutes later, `CVENGINE_SCANNER_REQUEUE_MINUTES`, and held back for as long as a scanner is still missing), so the work runs soon after the scanner is back and not at the target's next scheduled scan.

Nothing is scanned on the server whatever the scanner does: every scan kind, the HTTP and version probes and the other checks that used to run in-process included, is a Sentinel's work. With no scanner able to take it a stage waits and its targets stay due, as above.

`CVENGINE_LOCAL_FALLBACK` is ignored since 1.4: it used to let a kind run on the server when no scanner took it, and no kind has a local path any more. Remove it from `.env`; setting it changes nothing, and neither does anything warn about it.

## Signed-in work

A nuclei pass that uses a stored sign-in (**Targets**, a target's stored sign-in) runs on the built-in scanner too. The task names the credential by a reference only; the scanner reads it once, through `POST /api/v1/sentinel/tasks/<id>/secret`, which the server answers once per task and writes to the audit log (`sentinel.secret.read`). It holds the credential in memory and, for the run, in a 0600 file on a memory file system, and wipes it afterwards. No other Sentinel is ever offered such a task, and a built-in scanner image too old to read sign-ins is not offered it either. Without a scanner that can, the pass waits like any other: it has no local path (`sentinel_dispatch.NEVER_LOCAL`), whatever `CVENGINE_LOCAL_FALLBACK` says.

## Checking it

```bash
docker compose ps scanner                                      # running, and (healthy) once it heartbeats
docker compose logs --tail=50 scanner                          # or: make scanner-logs
docker compose exec scanner python3 -m client.control heartbeat && echo "reaches the server"
```

The log of a first start shows `bootstrapping from the enrollment file`, `bootstrap succeeded; token persisted at /var/lib/cvengine-sentinel/token.json`, a warning that it talks to the server over plain http (expected: the compose network), then `Sentinel CVEngine Scanner starting`. Lines that start `heartbeat failed`, `poll failed` or `could not register` mean it cannot reach the server.

In the interface, **Scanners**, on its **Sentinels** tab, shows a card named **CVEngine Scanner** with a **Built-in** chip, checking in, with no **Update now** button. System status (`GET /api/v1/system/status`, or the `get_system_status` tool) has:

```json
"scanning": { "builtin_scanner": { "enabled": true, "enrolled": true, "live": true, "agent_id": 3, "name": "CVEngine Scanner", "last_seen": "..." } }
```

Everyone sees `enabled`, `enrolled` and `live`; the rest is for an App Admin, who also gets a line in `problems` when the scanner is not enrolled ten minutes after the server wrote its enrollment, or is enrolled and not checking in. The Sentinels list API marks its row `builtin: true`.

To see that nothing runs on the server during a scan:

```bash
docker compose exec celery sh -c 'pgrep -af "nmap|naabu|nuclei|testssl|wpscan" || echo none'
```

Expect `none`: the server image has none of these tools except nuclei, and the server runs it only to update and read templates. Count what the scanner did, by kind and outcome:

```bash
docker compose exec -T celery python3 manage.py shell -c "
from django.db.models import Count
from agentapi.models import SentinelTask
for r in SentinelTask.objects.values('kind', 'status').annotate(n=Count('id')).order_by('kind', 'status'):
    print(r['kind'], r['status'], r['n'])"
```

## Keeping it current: the Scanner update

Every update of the server pulls the newest image, and so does a schedule, so a Sentinel fix reaches you between server updates too. The routine is `scripts/scanner-update.sh` (`make scanner-update`):

1. It pulls `ghcr.io/hevnsnt/cvengine-sentinel:main`. A pull that fails (offline, the registry refuses) changes nothing: the running scanner stays.
2. When the pulled image is the one already running, it stops there. Otherwise it lets the scanner finish the tasks it holds (up to 15 minutes, `CVENGINE_SCANNER_DRAIN_SECONDS`; a scanner that is still busy is updated at the next run), starts the new container, and waits (up to 5 minutes, `CVENGINE_SCANNER_READY_SECONDS`) until it is healthy **and** has checked in with a contract version the server accepts: not below the floor in `scanner.lock.json`, not older than the server still speaks.
3. If it is not, the **previous image comes back** (it was kept as `cvengine-sentinel-rollback:previous` and is started from this host, never from the registry), the reason is logged, and the scanner reports it to the server, so the Sentinels page shows the failed update with its reason. The next run tries the newest image again.

With the updater timer (`scripts/install-auto-deploy.sh`) the routine runs about daily whatever the update mode (`CVENGINE_SCANNER_UPDATE_HOURS`, default 24, `0` turns the schedule off). A host that does not use the updater runs it from cron, one line in the checkout:

```
17 4 * * *  cd /opt/cvengine && scripts/scanner-update.sh >> /var/log/cvengine-scanner-update.log 2>&1
```

A plain `docker compose pull scanner && docker compose up -d scanner` also works, without the health and check-in wait and without a rollback. Compose's `pull_policy` for the scanner is `missing` on purpose (a registry that cannot be reached must not stop `docker compose up` for the whole stack); a host that wants `docker compose up` itself to pull each time sets `CVENGINE_SCANNER_PULL_POLICY=always` in `.env` and accepts that an outage fails that `up`.

**To hold the scanner at one version,** set `CVENGINE_SCANNER_IMAGE` in `.env` to a digest (`ghcr.io/hevnsnt/cvengine-sentinel@sha256:...`) or a tag, then `make up`. An image set there is used as it is: never pulled over, never updated by the routine, never rolled back. Remove the line to follow the newest image again. A digest holds exactly; a tag holds whatever is on the host (nothing pulls it again).

What the Sentinels page and **Settings, System status** show for it: the running commit, whether it is the newest build the server saw (the server looks at the Sentinel repository about twice a day), how many commits behind when it is not, since when that build has run (*last updated*), and, for a scanner whose contract is older than this server speaks, *This scanner is older than this server needs, update it*: the server offers such a scanner no work. A scanner on a newer contract than the server (fine) keeps getting the kinds this server knows, and fields the server does not read are ignored.

## Asked to update by the server

With **Keep Sentinels on the newest version** on (Settings, Sentinels; the default), the server asks for the Scanner update itself: when the built-in scanner reports a build behind the newest published one, no long task runs on it, the newest build's contract is one this server speaks and the last request is more than 6 hours old, the server writes `web/.scanner-update-requested` and the host watcher (`scripts/update-watch.sh`, the same process that carries out the Approve button) runs `scripts/scanner-update.sh`. That is the routine above: pull, wait for the scanner to finish its tasks, swap, wait for the check-in, roll back if the new image does not check in. Without a listening host watcher nothing is asked and the Sentinels page says so; the daily timer and `make scanner-update` still work. If the scanner has not reported a new version 90 minutes later it is flagged on the Sentinels page with the reason and not asked again until an administrator acts (the scanner's card has no **Update now**: run `make scanner-update`). Each request is a `sentinel.update_requested` audit entry. The scanner's daemon is never told to update itself. See [UPDATES.md](UPDATES.md#keeping-sentinels-on-the-newest-version).

## Building it from source

`make scanner-build` builds the image from the floor commit `scanner.lock.json` names, the commit this release was tested with (10 to 25 minutes; on arm64 nmap is compiled), and tags it `cvengine-sentinel-local:<version>` and `cvengine-sentinel-local:latest`. It is the way to run when the published image cannot be pulled (an offline host, a registry that refuses): set `CVENGINE_SCANNER_IMAGE=cvengine-sentinel-local:latest` in `.env` and run `make up`. An image set there is used as it is, which also means it stays at that commit until you change it. Remove the line to go back to the newest published image. Building needs outbound HTTPS to the Ubuntu mirrors, nmap.org, go.dev and the Go module proxy, GitHub, testssl.sh, PyPI and rubygems.

## Turning it off

`CVENGINE_BUILTIN_SCANNER=0` in `.env`, then `make up`. The server stops writing enrollments and revokes the scanner's token (its tasks go back to the queue and the card shows revoked) and `make up` and the updates remove the container. Nothing then scans until an external Sentinel is enrolled: no kind runs on the server. `sudo ./install.sh --sentinels=external` (or `--no-builtin-scanner`) installs without it. Remove the line (and `make up`) to turn it back on: it enrols again as a new Sentinel.
