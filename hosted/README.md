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
| `hosted/cvl-set-sso-keys.sh`, `hosted/cvl-sso-mode.sh` | Single sign-on: install the public key set, flip the mode (see "Single sign-on"). |
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

## Single sign-on

Off by default: a hosted server without SSO behaves exactly as before. The site (cvengine.live) is the one gate in front of every server, so it requires MFA before it will mint an assertion; cvENGINE trusts an assertion only for a site user that was linked to a local account at personalise time. The contracts below are frozen (`docs/SSO-PLAN.md` in cvengine-live, "Interface contract"); change them on both sides together.

### Switches

| Where | Name | Meaning |
| --- | --- | --- |
| `.env` (first boot writes the defaults) | `CVENGINE_SSO=0` | accept assertions at `/sso/exchange` (inert unless `CVENGINE_HOSTED` is also on) |
| | `CVENGINE_SSO_ENFORCE=0` | refuse the local password login (`/login/` POST, `/admin/login/`) |
| | `CVENGINE_SSO_ISSUER`, `CVENGINE_SSO_AUDIENCE` | `https://cvengine.live`, and this server's origin URL (`https://s-<rand8>.cvengine.live`, exactly the site's `servers.origin_url`) |
| | `CVENGINE_SSO_MAX_AUTH_AGE`, `CVENGINE_SSO_STEPUP_AGE` | 43200 and 900 seconds |
| | `CVENGINE_SSO_BREAKGLASS_UNTIL` | Unix seconds; absent normally. Set only by `cvl-sso-mode.sh --breakglass` |
| host | `/etc/cvl/sso-keys.json` (mode 600) | the key set; mounted read-only at the same path in `web` (`CVL_SSO_KEYS_FILE` moves the host side) |

`docker-compose.hosted.yml` passes the `CVENGINE_SSO*` names to `web` only when `.env` defines them, and has no default that enables anything.

### Combined behaviour (what the two halves do together)

| Mode | `.env` | Browser at the scanner host | Local login |
| --- | --- | --- | --- |
| Off (default, and what first boot writes) | `CVENGINE_SSO=0` | the edge's own handoff, then the local login as before | works; cookies are `sessionid` and `csrftoken` |
| Phase A (SSO, local login kept) | `CVENGINE_SSO=1` | `/_cvl/start` sets the browser nonce and sends the visitor to cvengine.live; the edge exchanges the assertion at `/sso/exchange` and relays the session cookie | works, and the login page also offers "Sign in with cvengine.live" (`/_cvl/start?next=...`) |
| Phase B (enforced) | `CVENGINE_SSO=1`, `CVENGINE_SSO_ENFORCE=1` | the same | refused: `/login/`, `/admin/login/`, the second-step page and an invite's automatic sign-in answer 302 to `/_cvl/start?next=<validated next>`; `cvl-personalize.sh` leaves the password out of its JSON |

Where the visitor goes: a normal sign-in always goes through `/_cvl/start` (the edge sets the browser nonce there). `/_cvl/sso` is only for a live scanner session: the binding flush of a page request redirects to `/_cvl/sso?next=...`, and the step-up refusal (HTTP 403, JSON `recent_auth_required`) carries `reauth_url` = `/_cvl/sso?prompt=stepup&next=<urlencoded validated path>`. `next` must match `^/(?![/\\])[^\s]{0,2047}$` and Django's own host check, else the landing page `/cve/` is used.

Order of rollout: the site's MFA first; this release with `CVENGINE_SSO=0`; phase A on an internal test server (`cvl-set-sso-keys.sh`, then `cvl-sso-mode.sh --sso on`); link every owner (`cvl-personalize.sh` with `sso_subject`, or `manage.py link_sso_identity --email=E --subject=S` by hand); then phase B per server (`--enforce on`, refused with no key installed).

**Rollback.** Phase B to A: `cvl-sso-mode.sh --enforce off` (the local login works again at once after the web restart). Off: `cvl-sso-mode.sh --sso off` (also clears enforcement and break-glass); or stop the site minting (`sso_enabled=0`), after which the double login resumes. Both change the cookie names, so **every existing session is dropped and everyone signs in once more** (turning SSO on does the same). Phase A keeps the local login, so nobody is locked out while testing.

**Key rotation (every 90 days).** 1. Push a JWKS with the new key as `next` and the current key unchanged to every server (`sso_keys` job, or `cvl-set-sso-keys.sh`). 2. Switch the site's signing key (`current` in `SSO_SIGNING_KEYS`). 3. Push again: new key `current`, old key `retiring`. 4. After at least 24 hours (longer than any assertion or session lifetime that matters) push without the old key. The application re-reads the file when it changes, so no restart. Emergency revoke: push a JWKS without the bad kid and with a trusted key; an empty, half-written or unreadable file refuses every assertion (fail closed) and is read again on the next call, so a read that lands in the middle of the in-place rewrite costs at most that one sign-in.

**Break-glass.** `cvl-sso-mode.sh --breakglass <1-60>` writes `CVENGINE_SSO_BREAKGLASS_UNTIL` = now + minutes as Unix seconds (digits only) into `.env` and recreates `web`; `--breakglass off` removes it. The settings read it as an integer; the application treats it as open only while it is in the future and at most 3600 s ahead of now. While open, under enforcement, the local login works for a request that came through the edge (nginx set `X-CVL-Edge-Verified: 1`), needs the local password and local MFA (an account without MFA is refused), and every step is audited (`sso.breakglass_*`) and logged. A change needs the web restart the script performs; setting the variable by hand has no effect until `web` is recreated.

### JWKS file `/etc/cvl/sso-keys.json`

```json
{"keys":[{"kid":"k-2026-01","kty":"OKP","crv":"Ed25519","x":"<base64url of the 32-byte public key, no padding>","status":"current"}]}
```

`status` is `current`, `next` or `retiring`; the verifier accepts all three. A revoked key is not listed: it is removed. Only PUBLIC keys ever reach a server. First boot writes `{"keys":[]}` (every assertion then fails closed).

### `hosted/cvl-set-sso-keys.sh`  (JWKS on stdin)

```
cvl-set-sso-keys.sh           the JWKS on stdin replaces the installed set
cvl-set-sso-keys.sh --check   nothing on stdin: validate and list what is installed
```

stdout: `{"ok":true,"kids":["k-2026-01"]}`. Validation is strict and all-or-nothing: `keys` is an array of at most 8 (zero is allowed); each has a `kid` (1 to 128 of `A-Za-z0-9._:-`, unique), `kty` `OKP`, `crv` `Ed25519`, `x` the unpadded canonical base64url of exactly 32 bytes, and `status` current, next or retiring (`revoked`, or anything else, is refused). Other members are dropped. The file is rewritten in place (same inode, so the single-file bind mount follows; an identical set is not touched) and the application re-reads it, so no restart. Only kids are printed or logged. The provisioner runs it at personalise time and for each `sso_keys` job.

**Rotation:** push a JWKS with the new key as `next` to every server; switch the site's signing to it and push again with the new key `current` and the old `retiring`; after 24 hours push without the old key. **Emergency revoke:** push a JWKS without the compromised kid (and with at least one trusted key, or SSO is closed for everyone); assertions signed by it then fail at once.

### `hosted/cvl-sso-mode.sh`  (arguments)

```
cvl-sso-mode.sh --sso on|off  --enforce on|off  --breakglass <minutes 1-60>|off   (any combination, at least one)
```

stdout: `{"ok":true,"sso":true,"enforce":false,"breakglass_until":null}` (`breakglass_until` is Unix seconds while the window is open). Edits `.env` in place and recreates only `web`, and only when a value changed. `--enforce on` is refused unless SSO is on (after this command's own `--sso`) and the installed key set has at least one key; `--sso off` also turns enforcement and break-glass off; break-glass needs SSO on. Break-glass lets the local login work again for at most an hour and still needs the edge secret, the local password and the local TOTP.

### `hosted/cvl-personalize.sh` additions

Optional input `sso_subject` (the site user id, 8 to 64 of `A-Za-z0-9_-`). When present and `CVENGINE_SSO` is on, after `create_admin` it runs `manage.py link_sso_identity --email=<email> --subject=<sso_subject>` (a failure fails the script). With `CVENGINE_SSO_ENFORCE` on the `password` key is left out of the JSON; the other keys are unchanged. Retries stay idempotent.

### First boot

`cvl-firstboot.sh` now checks the clock first (`timedatectl show -p NTPSynchronized --value` must say `yes`; it waits up to 120 s, then fails with a message): assertions live 60 seconds and are rejected beyond 30 seconds of skew. It also creates the empty key set and the SSO-off `.env` defaults, never over a value already there.

### Exchange and headers (nginx side)

The edge calls `POST <origin>/sso/exchange` with `X-CVL-Edge-Auth`, `X-CVL-Client-IP`, `X-CVL-SSO-Exchange: 1`, `Content-Type: application/json`, body `{"assertion":"<jws>"}`; answers: 204 plus `Set-Cookie` (`__Host-cve_s`), 400, 401 `{"error":"invalid_assertion"}`, 403 `{"error":"not_linked"}`, 404 when SSO is off or the edge is not verified, 405 for a non-POST. Back-channel logout: `POST <origin>/sso/backchannel-logout`, body `{"logout_token":"<jws>"}`, 204 or 401. The application requires `X-CVL-Edge-Verified: 1` and `X-CVL-SSO-Exchange: 1` (both exactly `1`, both set only by nginx behind a valid secret) on both endpoints and answers 404 otherwise. The session cookie is `__Host-cve_s` with `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/` and no `Domain`. The proxy passes `/sso/*` like any path; it is the edge that never lets a browser reach it.

`config/nginx/rengine.conf` sets, in every proxied location, headers the application can trust only because nginx wrote them:

| Header to the application | Value |
| --- | --- |
| `X-CVL-Edge-Verified` | `1` when the edge secret matched, else `0` (also `0` on a stock install). Always overwrites a client copy |
| `X-CVL-SSO-Sub` | the edge's site user id, only when the secret matched and it is 1 to 64 of `A-Za-z0-9_-`; otherwise the header is not sent |
| `X-CVL-SSO-Sid` | the edge's 32-hex family hash, only when the secret matched and it has that shape; otherwise not sent |
| `X-CVL-SSO-Exchange` | `1` only when the secret matched and the edge sent exactly `1`; otherwise not sent |
| `X-CVL-Edge-Auth`, `X-CVL-Client-IP` | never sent (for this proxy only) |

A client-supplied copy of any of these is replaced or blanked, and a header with underscores (`X_CVL_...`) is dropped by nginx (`underscores_in_headers off`). nginx cannot clear a wildcard: an `X-CVL-*` name this file does not list is not touched, so every new `X-CVL-*` header the application reads needs a line here and a test in `web/tests/test_hosted_sso_edge.py`. Django flushes an SSO-born session whose stored sub or sid differs from these headers or whose headers are missing.

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

`web/tests/test_hosted_mode.py`, `web/tests/test_hosted_sso_edge.py` (nginx, compose and scripts), `web/tests/test_hosted_sso.py` (the application) and `web/tests/test_hosted_sso_integration.py` (scripts and application together; see `docs/HOSTED-SSO-REVIEW.md`) (Django test runner, no network, no Docker daemon; nginx is run for real when a binary or the `nginx:alpine` image is available, and shellcheck when installed). It proves the default-off behaviour (stock file, base compose, scripts without hosted mode) and each contract above, with stubs for `docker`, `aws`, `age` and the mount tools.
