# Test the built-in scanner (1.4)

The built-in scanner is the cvENGINE Sentinel running as a compose service next to the server, shown as **CVEngine Scanner**. The server enrolls it with nobody typing a secret, and it takes scan work the way any Sentinel does. It is optional and off by default: with `CVENGINE_BUILTIN_SCANNER` unset and no `builtin-scanner` profile, nothing described here exists. The design is in [SCANNER-ARCHITECTURE.md](SCANNER-ARCHITECTURE.md); the variables are in [CONFIGURATION.md](CONFIGURATION.md#built-in-scanner-optional-off-by-default).

This page is a recipe for trying it on a test box. It is for public targets only: the built-in scanner is an external scanner (it sits next to the server, not inside a private network), so work for a declared internal range still goes only to a Sentinel inside that network.

## What moves, and what does not

What moves to the scanner is the work that already is a Sentinel task kind: the nmap fast scan, the naabu sweep, the nuclei light, targeted and deep passes, testssl, the UDP sweep and the WPScan quick pass. With `CVENGINE_LOCAL_FALLBACK=none` those are never run on the server again; a stage that needs one waits for a scanner instead.

What does **not** move yet, and so still runs on the server (the celery container) whatever the scanner does:

- bbot discovery (the work conductor goes on starting it);
- the HTTP and version probes and the other in-process probes: route and signed-out checks, other sites on an address (vhost), applications under a path, cloud storage buckets, suppliers, retired-name checks, DNS and mail hygiene;
- the all-ports nmap sweep (`-p-`), the version pass that follows it and the nmap script probes of single ports;
- wafw00f and the node2shell check;
- the thorough WPScan pass;
- the database exposure probes (one credential-less connect per database) and the RDP login-screen screenshots;
- signed-in nuclei passes, which use a stored credential.

So "scanner offline" does not mean no traffic leaves the server: those checks keep going while the scanner is down, and only the kinds taken off the list wait. The full inventory is in [SCANNER-ARCHITECTURE.md](SCANNER-ARCHITECTURE.md#what-exists-today).

## The recipe

You need a Linux Docker host with at least 10 GB of RAM (or lower `CELERY_MEM_LIMIT`: the scanner container is limited to 2 GB on top of the usual stack), about 2 GB of free disk, and outbound HTTPS while the image builds: the Ubuntu base image and packages, nmap.org, go.dev and the Go module proxy, GitHub (the Sentinel source and the nuclei templates), testssl.sh, PyPI and rubygems.

**1. Get the 1.4 code, and leave updates alone.**

```bash
git fetch && git checkout 1.4-develop && git pull
```

Under **Settings, Updates, How updates are installed**, choose **Manual** (it is the default; a missing `web/.update-mode` counts as Manual). Manual installs nothing until an administrator clicks Approve, so nothing moves your checkout during the test. The update check follows the branch named under **Update source** (by default `master`), so the bar at the top may offer an update that is not the code you are testing: do not Approve it, and do not run `scripts/update.sh` (it takes only `master`). See [UPDATES.md](UPDATES.md).

**2. Switch it on in `.env`.**

```bash
COMPOSE_PROFILES=builtin-scanner      # append to an existing list: tailscale,openvas,builtin-scanner
CVENGINE_BUILTIN_SCANNER=1
```

Leave `CVENGINE_LOCAL_FALLBACK` unset for now: until the scanner is live, the server must still be able to run everything itself.

**3. Build the scanner image.** It takes 10 to 25 minutes (on arm64 nmap is compiled).

```bash
make scanner-build        # docker compose --profile builtin-scanner build scanner
```

The image is built from a pinned commit of [hevnsnt/cvENGINE-sentinel](https://github.com/hevnsnt/cvENGINE-sentinel) (`CVENGINE_SCANNER_SOURCE`) and tagged `cvengine-sentinel-local:latest` (`CVENGINE_SCANNER_IMAGE`). If compose cannot build from the git URL, build it by hand under the same name:

```bash
git clone https://github.com/hevnsnt/cvENGINE-sentinel.git
git -C cvENGINE-sentinel checkout <the commit in docker-compose.yml, scanner, build, context>
docker build -t cvengine-sentinel-local:latest cvENGINE-sentinel
```

**4. Start it and watch it enroll.**

```bash
make up                                   # the core services; they pick up the new .env lines
docker compose up -d scanner              # make up never starts a profile service
docker compose exec celery python3 manage.py ensure_builtin_scanner
docker compose logs -f scanner            # or: make scanner-logs
```

`make up` names only the six core services, so the scanner is started by compose itself. `ensure_builtin_scanner` prints `built-in scanner: <state>`: `blob_written` (a one-time enrollment was written for the scanner), `waiting` (one is already there and still good), `enrolled` (the scanner has redeemed it and is known), `no_admin` (there is no App Admin yet to own it: run `make admin` first) or `disabled` (the switch is off in the container, so `CVENGINE_BUILTIN_SCANNER=1` did not reach it). It has to run in `celery`, the only container that can write the volume the scanner reads. The server also runs it every five minutes by itself, and a scanner that finds no blob and no saved token waits for one (its log says "waiting for the server to write the enrollment") instead of exiting.

The scanner's log should show, in order (each line starts with the time and level, for example `INFO sentinel.main: ...`):

```text
bootstrapping from CVENGINE_SENTINEL_BLOB
bootstrap succeeded; token persisted at /var/lib/cvengine-sentinel/token.json
WARNING sentinel.http: INSECURE: talking to the server over plain http because CVENGINE_SENTINEL_ALLOW_INSECURE=1; ...
Sentinel CVEngine Scanner starting, max_concurrent=<n>, server=http://web:8000
```

The warning is expected: the scanner reaches the server as `http://web:8000` over the compose network. After that you may see `settings from the server: ...` and `capabilities changed: ...`; once there is work, `task <id> accepted: <kind> (...)` and `task <id> finished: <kind>, <outcome>, <seconds>s`. Lines that start `heartbeat failed`, `poll failed` or `could not register` mean it cannot reach the server.

In the interface, open **Sentinels**: a card named **CVEngine Scanner** with a **Built-in** chip appears under **Every organization**, checking in. It has no **Update now** button, because the built-in scanner never updates itself. The same state is in System status (`GET /api/v1/system/status`, or the `get_system_status` tool):

```json
"scanning": { "builtin_scanner": { "enabled": true, "enrolled": true, "live": true, "agent_id": 3, "name": "CVEngine Scanner", "last_seen": "..." } }
```

Everyone sees `enabled`, `enrolled` and `live`; the rest is for an App Admin, who also gets a line in `problems` when the switch is on and the scanner is not enrolled after ten minutes, or is enrolled and not checking in. With the switch off the block is `{"enabled": false}`. In the Sentinels list API (`GET sentinels/live`, `GET agents`) the row carries `builtin: true`. The row's `contract_state` reads `unreported` until the client declares a contract version; that field is not drawn on the page and is harmless.

**5. Take the server out of the scanning path, then scan.** Only after the card is live, add to `.env`:

```bash
CVENGINE_LOCAL_FALLBACK=none
```

and apply it with `docker compose up -d` (a plain one: it recreates the containers whose `.env` changed and keeps the profile service). From now on a stage that needs a scanner kind waits for one instead of running the tool here. Add a **public** target (an address or domain you may scan) and start a scan. In **Activity** the hand-off reads `Handed nmap work for <host> to a Sentinel`, then `Sentinel CVEngine Scanner checked in nmap work for <host>`; the scanner's log shows the matching `task ... accepted` and `finished` lines, and the card on the Sentinels page shows the task running and its counters.

**6. Check that nothing ran locally.** During a scan:

```bash
docker compose exec celery sh -c 'pgrep -af "nmap|naabu|nuclei|testssl|wpscan" || echo none'
```

Expect `none`, or only work that stays on the server by design (see above): nmap with `-p-` or `--version-intensity 5` (the all-ports sweep and its version pass; the single-port script probes are nmap too), nuclei with `-sf` (a signed-in pass) and WPScan with `--plugins-detection mixed` (the thorough pass). The fast nmap pass (`--version-intensity 7`, `-O`), `-sU`, naabu, testssl and the nuclei light, targeted and deep passes must not appear. Then look at **Activity**: no line may say `ran locally`, `fell back to local` or `local execution`. And count what the scanner did, by kind and outcome:

```bash
docker compose exec -T celery python3 manage.py shell -c "
from django.db.models import Count
from agentapi.models import SentinelTask
for r in SentinelTask.objects.values('kind', 'status').annotate(n=Count('id')).order_by('kind', 'status'):
    print(r['kind'], r['status'], r['n'])"
```

`done` rows for `nmap`, `naabu` and `nuclei_*` are the proof; `expired` or `failed` rows are worth reading in the Sentinels page's recent tasks.

**7. Take the scanner away.**

```bash
docker compose stop scanner
```

Within a few minutes (the scanner counts as gone three minutes after its last check-in) the card goes offline, a strip appears on every page ("Scanner offline: ... work is waiting. Nothing has failed; it resumes automatically when a scanner reconnects."), and System status gets `scanning.scanner.offline: true` and, for an App Admin, a `problems` line for the built-in scanner. Activity shows lines such as `no scanner could take this work (nmap); the targets stay due until one can`. Nothing is marked failed, scanning is not paused, and the work that stays on the server carries on. Start it again with `docker compose up -d scanner`: it reuses its saved token, the strip goes away by itself and the waiting targets are scanned.

**8. A restart keeps the token.**

```bash
docker compose restart scanner
docker compose logs --tail=20 scanner
```

The log shows `using the persisted token at /var/lib/cvengine-sentinel/token.json; skipping bootstrap` and no new enrollment: the token lives in the `scanner_state` volume.

**9. Roll back.** Remove `COMPOSE_PROFILES=builtin-scanner` (or the `builtin-scanner` entry of the list), `CVENGINE_BUILTIN_SCANNER` and `CVENGINE_LOCAL_FALLBACK` from `.env`, then:

```bash
docker compose --profile builtin-scanner rm -sf scanner     # stop and remove the container
docker compose up -d --remove-orphans                       # the server containers without the lines
docker volume ls --filter name=scanner_                     # optional: remove scanner_state and scanner_bootstrap with docker volume rm
```

Then **Revoke** the CVEngine Scanner card on the Sentinels page, so its token is dead. Targets that waited simply run on the server again at the next pass.

Going back to `develop` needs no database restore. The 1.4 branch adds three migrations, none of which removes or tightens anything: `agentapi` 0008 adds a boolean with a database default to the enrollment table, `agentapi` 0009 adds two nullable columns to the Sentinel task table, and `cveFeed` 0129 adds one schedule row (`cvengine-ensure-builtin-scanner`). The older code ignores the new columns, and Django does not mind migrations applied that it does not know. One loose end: the schedule row stays, and an older release does not have the task it names, so its worker logs `Received unregistered task of type 'ensure_builtin_scanner'` every five minutes. Remove the row once:

```bash
docker compose exec -T web python3 manage.py shell -c "
from django_celery_beat.models import PeriodicTask
print(PeriodicTask.objects.filter(name='cvengine-ensure-builtin-scanner').delete())"
```

Move the checkout back by hand (`git checkout develop && git pull && make up`): the in-app updater does not go back to an older branch for you.
