# Hosted mode

What a cvENGINE server needs to be run for a customer by someone else: a DigitalOcean Droplet and volume per customer, reached only through a Cloudflare Worker (the edge), under the customer's own names. Everything here is **off by default**. A normal self-hosted install never reads any of it: the proxy's stock edge-auth file has no entries, `CVENGINE_HOSTED` is unset, and nothing names `docker-compose.hosted.yml` until a hosted server's `.env` does.

The provisioner (`cvengine-live/provisioner`) builds servers from a golden image and drives the scripts below over SSH. This file is the contract between the two. Script names, arguments and JSON shapes are fixed; change them on both sides together.

## Names

| Name | Who uses it | Notes |
| --- | --- | --- |
| `s-<rand8>.cvengine.live` | the edge, the provisioner | The server's own (origin) name. DNS only, never given to a customer. It is `DOMAIN_NAME`, so Django accepts it as `Host`, and the certificate on the proxy is for it (Let's Encrypt, DNS-01, **RSA key**, installed by the provisioner into `secrets/certs/`). |
| `scanner.cvengine.live` | the customer's browser | The edge forwards it with `X-Forwarded-Host`. `CVENGINE_CSRF_TRUSTED_ORIGINS=https://scanner.cvengine.live` makes Django's Origin check pass. |
| `api-<slug>.cvengine.live` | the scanner fleet | `CVENGINE_PUBLIC_API_URL`: the `server_url` of Sentinel enrollments. Set by `cvl-personalize.sh`. |

The edge sends `Host: s-<rand8>.cvengine.live` (a Worker's `fetch` always does), `X-Forwarded-Host` (the public name), `X-Forwarded-Proto: https`, `X-CVL-Edge-Auth` (the secret) and `X-CVL-Client-IP`.

## Threat model of the edge secret

The origin listens on the Internet, so something must stop anyone but the edge from reaching the application. Two layers, neither alone:

1. The cloud firewall (tag `cvl`): 443 from Cloudflare's ranges and the provisioner only, 22 from the provisioner only.
2. nginx refuses (403) every request that lacks `X-CVL-Edge-Auth` with the current secret (or, during a rotation, the previous one), including the health probe from outside.

nginx compares the header with a `map`. That is a hash lookup: **not constant time, and not case sensitive** (a 43-character secret loses about 30 of its 256 bits to the case folding). nginx has no constant-time comparison. A timing attack over the Internet against a 256-bit random value is not practical, and the firewall removes the attacker's network position; but do not treat the secret as the only control, and never use a short or human-chosen value. `gen-edge-auth.sh` accepts only 32 to 128 characters of `A-Z a-z 0-9 _ -` (the Worker's own tokens are 43), so a secret can never carry nginx syntax.

The client address is believed from `X-CVL-Client-IP` **only** when the secret matched, and only if it looks like an address; otherwise the header is ignored (a spoof without the secret changes nothing, and is refused with 403 anyway except on the loopback probe, which gets the real peer). With it believed, nginx sets `X-Forwarded-For` to `<that address>, <peer>` for the application and drops whatever `X-Forwarded-For` the request carried; `reNgine/client_ip.py` then picks the address as it always does. The application never receives the edge headers (nginx blanks them). The allowlist, the abuse guard and the sign-in lockout therefore see the customer's real visitors.

Docker's userland proxy should be off (`/etc/docker/daemon.json`: `{"userland-proxy": false}`; the golden image sets it, `cvl-firstboot.sh` warns when it is not): nothing here depends on the peer address, but the firewall and nginx then see real peers. The only exemption from the secret is a request from `127.0.0.1` itself for `/` or `/health` (a local probe); the local readiness checks send the secret anyway.

## Files

| Path | What |
| --- | --- |
| `config/nginx/edge-auth.conf.example` | The stock file: no entries, so hosted mode is off. Mounted by `docker-compose.yml` at `/etc/nginx/edge-auth.conf`. |
| `config/nginx/rengine.conf` | `include /etc/nginx/edge-auth.conf;` inside `map $http_x_cvl_edge_auth $cvl_edge_ok` (a `map` is only allowed at the top level, so the hook sits there and the server block reads the result with `if ($cvl_edge_deny) { return 403; }`). |
| `docker-compose.hosted.yml` | The overlay: bind volumes on `/mnt/cvl-data`, restart policies, only 443 published, the generated edge file mounted over the stock one. |
| `hosted/gen-edge-auth.sh` | Writes `/etc/cvl/edge-auth.conf` and `/etc/cvl/edge-header` from `/etc/cvl/edge-secret` (and `edge-secret.previous`), in place so the single-file bind mount follows. |
| `scripts/hosted-edge.sh` | Sourced by `install.sh` and `scripts/update.sh`: on a hosted server their local readiness checks send `-H @/etc/cvl/edge-header`, so they are not refused. Nothing is added when hosted mode is off. The watchdog and the other updaters work through `docker compose exec` and need nothing. |
| `web/agentapi/fleet_token.py`, `manage.py ensure_fleet_token` | The scanner fleet's Sentinel identity (below). |
| `/etc/cvl/` (700) | `edge-secret`, `edge-secret.previous`, `edge-auth.conf`, `edge-header`: all 600. |
| `/var/lib/cvl/` (700) | `origin-host`, `ready`, `personalized` (the slug). |
| `/mnt/cvl-data/` | The volume: `postgres/`, `scan_results/`. |

Everything can be moved with `CVL_ETC`, `CVL_STATE`, `CVL_DATA`, `CVL_REPO` (the tests do).

## Scripts and their contracts

All run as root, print progress and errors on **stderr**, exit non-zero on failure, and never print or log a secret. Stdout is the contract.

### `hosted/cvl-firstboot.sh`  (no arguments, no stdin; stdout empty)

Run by cloud-init on the first boot of a Droplet made from the golden image (a warm pool server). Idempotent. Mounts the volume at `/mnt/cvl-data` (the first `/dev/disk/by-id/scsi-0DO_Volume_*`, or `CVL_VOLUME_DEVICE`; formats ext4 only when it holds no filesystem; refuses to run without a volume unless `CVL_ALLOW_NO_VOLUME=1`), runs `scripts/init-env.sh` with `DOMAIN_NAME=s-<rand8>.cvengine.live` (the name is written to `/var/lib/cvl/origin-host`; `CVL_ORIGIN_HOST` sets it), sets `CVENGINE_HOSTED=1`, `CVENGINE_CSRF_TRUSTED_ORIGINS=https://scanner.cvengine.live`, `CVENGINE_HSTS_SECONDS=31536000`, `CVENGINE_COMPOSE_FILES=docker-compose.yml,docker-compose.hosted.yml` (so the updater, the watchdog and the certificate renewal keep the overlay) and `CVENGINE_BUILTIN_SCANNER=0` (a hosted server is scanned by the external fleet; the built-in scanner and the AI reviewer are not started), writes a **random placeholder edge secret** (nobody knows it, so the proxy refuses everything until the provisioner sets the real one), starts the stack, migrates, imports the CVE catalog (`manage.py import_cve_seed`, which downloads the published seed) and writes `/var/lib/cvl/ready` last.

It uses `docker compose` with the layout from `.env`, never `make up` (which reads only `docker-compose.yml` and would drop the overlay). The proxy starts with the installer's private certificate; the provisioner replaces it (`secrets/certs/rengine.pem`, `rengine_rsa.key`, `rengine_chain.pem`, then `docker compose up -d --force-recreate proxy`).

### `hosted/cvl-set-edge-secret.sh`  (secret on stdin)

```
cvl-set-edge-secret.sh [--no-reload]                  rotate: new secret on stdin becomes current, the old current is kept as previous
cvl-set-edge-secret.sh --no-previous [--no-reload]    first set (a claimed pool server): new secret on stdin, no previous
cvl-set-edge-secret.sh --drop-previous [--no-reload]  nothing on stdin: end the overlap
```

stdout: `{"ok":true,"previous":<bool>,"reloaded":<bool>}`. The secret is on stdin, never in an argument. A rotation is: the Worker is told the new secret **after** this returns (both secrets are accepted meanwhile), then ten minutes later `--drop-previous`. `nginx -t` runs before the reload; a rejected file is not applied and the script fails. No reload when the proxy is not running or with `--no-reload`.

### `hosted/cvl-personalize.sh`  (JSON on stdin)

```
stdin : {"customer_slug": "acme", "email": "owner@acme.example", "username": "admin"}   # username optional; other keys ignored
stdout: {"username":"admin","password":"<one-time>","fleet_token":"cve_...","api_base":"https://api-acme.cvengine.live"}
```

Requires `ready` and hosted mode. Sets `CVENGINE_PUBLIC_API_URL=api_base` (recreating `web` when it changed), creates the first App Admin with `manage.py create_admin` (a generated password; the account must change it at first sign-in) and runs `ensure_fleet_token --user <username>`. Stdout is exactly that one line. A retry with the same slug resets the admin password and rotates the fleet token (the earlier values stop working); another slug is refused, because a server belongs to one customer. Bad input (the slug must be a DNS label of at most 58 characters, one email address) is refused with nothing on stdout.

### `hosted/cvl-export.sh`  (arguments; credentials in the environment)

```
cvl-export.sh --key <object key> [--bucket B] [--endpoint URL] [--recipient age1...] [--no-quiesce]
env: CVL_S3_BUCKET, CVL_S3_ENDPOINT (https://nyc3.digitaloceanspaces.com), CVL_AGE_RECIPIENT, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
stdout: {"ok":true,"bucket":"...","key":"...","bytes":N}
```

`pg_dump -Fc` piped through `age -r <public key>` into `aws s3 cp -`: no plaintext dump touches the disk or the bucket, and a missing recipient is refused. The golden image therefore needs the `aws` CLI and `age`. Unless `--no-quiesce`, celery, celery-beat and web are stopped first (the final export before deprovision; they are not restarted). The object is read back with `head-object`. Restore with `age -d | pg_restore`.

### `manage.py ensure_fleet_token`  (inside `web`; only with `CVENGINE_HOSTED=1`)

```
ensure_fleet_token [--user NAME] [--max-concurrent N]   create, or rotate the token of the existing identity
ensure_fleet_token --revoke                             revoke for good (a later plain run issues a new token)
ensure_fleet_token --disable | --enable                 suspend / resume (the provisioner's suspend and resume jobs)
```

stdout: one JSON line `{"state":"created|rotated|disabled|enabled|revoked|absent","agent_id":..,"token":"cve_..." (create and rotate only, shown once),...}`. The identity is an `Agent` (`kind='scanner'`, `network='external'`) with an `ApiToken` of the `sentinel` scope, which can call the Sentinel endpoints and nothing else. Its capabilities are every task kind except the built-in scanner's own (`path_probe`, `nuclei_validate`, `route_probe_signed`), never `network:internal`, and the same list is the administrator's limit on it, so it cannot widen itself by registering. It is found by its token name `fleet:cvl`, so a Sentinel that enrolled itself under the same display name is never adopted. `--disable` revokes the token and suspends the Agent (its tasks go back to the queue); `--enable` undoes exactly that, and refuses when an administrator suspended it or it was revoked.

## Golden image

Ubuntu 24.04. Build once per release, snapshot, and use the snapshot for the warm pool and for on-demand builds.

1. `apt-get install docker-ce docker-compose-plugin make git python3 openssl curl age awscli`. Docker Compose 2.24 or newer is required (the overlay uses `!override`/`!reset`).
2. `/etc/docker/daemon.json`: `{"userland-proxy": false}`; restart Docker.
3. Check out cvENGINE at the release tag to `/opt/cvengine` and **build the images only**: `docker compose -f docker-compose.yml -f docker-compose.hosted.yml build` (and `pull` the stock images). Never `up` the stack on the image: a started stack would create the named volumes with the wrong driver options, and would put secrets on it.
4. Make sure there is nothing that must not be shared: no `.env`, no `secrets/`, no `/etc/cvl`, no `/var/lib/cvl`, no SSH host keys (cloud-init regenerates them), no shell history, no `web/.watchdog-*` files. `docker volume ls` must be empty.
5. Install a systemd unit (or a cloud-init `runcmd`) that runs `/opt/cvengine/hosted/cvl-firstboot.sh` once.
6. Optionally install the update watcher afterwards (`scripts/install-updater.sh`): it reads `CVENGINE_COMPOSE_FILES` from `.env`, so it keeps the overlay.

## Updating a hosted server

`scripts/update.sh` and the watcher use the layout in `.env`, so the overlay stays. The update's local readiness check sends the edge header from `/etc/cvl/edge-header`. After a rotation the file is rewritten in place, so no restart is needed.

## Tests

`web/tests/test_hosted_mode.py` (Django test runner, no network, no Docker daemon; nginx is run for real when a binary or the `nginx:alpine` image is available, and shellcheck when installed). It proves the default-off behaviour (stock file, base compose, scripts without hosted mode) and each contract above, with stubs for `docker`, `aws`, `age` and the mount tools.
