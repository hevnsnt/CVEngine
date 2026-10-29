# Deployment

cvENGINE is one Docker Compose deployment: `db`, `redis`, `web`, `celery`, `celery-beat`, and `proxy` ([ARCHITECTURE.md](ARCHITECTURE.md)). Two optional parts ship in the same file as Compose profiles and are **off by default**: a `tailscale` service ([TAILSCALE.md](TAILSCALE.md)) and the OpenVAS add-on, 15 Greenbone containers on a network of their own ([OPENVAS.md](OPENVAS.md)). Until you switch one on, none of its containers exist, run, publish a port or use memory. Sentinels, the scanner agents you run on other machines, are not part of this stack: each runs from its own repository and calls this server over HTTPS on 443. The [install steps](#install) are below. Size the server for your scans: 4 GB of RAM is the least (the installer warns below that) and 8 GB is comfortable, and heavy jobs queue by memory use ([CONFIGURATION.md](CONFIGURATION.md#memory-and-workers)). Images build for amd64 and arm64.

## Ports

| Port | Bound to | Service |
| --- | --- | --- |
| 443 | all interfaces | `proxy`, the HTTPS front door |
| 8082 | all interfaces | `proxy`, redirects to HTTPS |
| 8000 | `127.0.0.1` | `web`, for your own reverse proxy |
| 5432 | `127.0.0.1` | `db` |

Firewall 443 and 8082 to the people who need them. The development stack has no proxy and publishes 8000 and 5432 on `127.0.0.1` only. The optional `tailscale` and `openvas` profiles publish no ports at all.

## Install

On a Linux server (Debian or Ubuntu is easiest; 4 GB of RAM at the least and 8 GB for comfort, and 20 GB of free disk):

```bash
git clone https://github.com/hevnsnt/CVEngine.git
cd CVEngine
sudo ./install.sh
```

It asks nothing. It checks the machine, installs what is missing, generates every secret, detects the address to use, creates the HTTPS certificate, builds and starts cvENGINE (the first build takes several minutes), waits until it answers, and prints the address, your username, and a generated password. Copy the password from the terminal: it is shown once, and you choose your own at your first sign-in. If you lose it, `make admin-password` prints a new one for the `admin` account (use `sudo` if the installer ran as root). To use a name instead of the detected address, run `sudo ./install.sh --domain scanner.example.com`.

**First sign-in.** Open the printed address. Browsers warn about the private certificate authority until you trust `secrets/certs/ca.crt` (copy it from the server to the computer whose browser you use). After you choose your own password, the setup wizard (superusers only) creates your organization and project, offers an optional AI model (paste an Anthropic, OpenAI, or OpenRouter key; set up Ollama or vLLM later in Settings), adds your first target if you confirm you are authorized to test it (discovery starts the moment you add it), and offers optional Shodan, VirusTotal, and SecurityTrails keys. The CVE feed starts loading about a minute after the workers come up.

**Step by step.** To run the steps yourself (any Linux with [Docker Engine](https://docs.docker.com/engine/install/), the Compose plugin, `git`, `make`, and `python3`, in a `git clone`, not a release archive):

```bash
./scripts/init-env.sh    # creates .env: generates its passwords and sets DOMAIN_NAME to this machine's address
make certs               # HTTPS certificate for the built-in proxy
make up                  # build and start
# wait until https://<your address>/ answers (follow it with: make logs), then:
make admin               # create your admin account: its password is generated and printed once
```

To choose the password yourself instead, put it in `DJANGO_SUPERUSER_PASSWORD` in `.env` before `make up`, or run `make username`. To serve it on the Internet under a real name with a trusted certificate, see [HOSTING-ONLINE.md](HOSTING-ONLINE.md).

## Linux, Mac, and Windows

`install.sh` asks nothing. It checks that this is Linux, that it is root (it re-runs itself through `sudo`), the architecture, memory (it warns below about 3.5 GB), free disk on the checkout's filesystem (it warns below about 14 GiB), that ports 443 and 8082 are free (it stops if not), and whether Docker's registry and GitHub answer (it only warns). On Debian and Ubuntu it installs curl, make, python3, git, openssl, and the Compose plugin with `apt`. Docker comes from `get.docker.com` on any distribution that script supports. On other Linux it stops at the first missing one of those tools and names it, so install them and run it again, or follow the README steps. It needs Compose 2.24 or newer but does not check the version. When a step fails it prints the last 25 log lines of `web`, `proxy`, and `db`. It also installs the update watcher into root's crontab, so the Approve button works straight away (it only warns when `crontab` is missing, and skips it when automatic deployment is installed).

Running it again keeps `.env`, the certificate (unless the address changed), and your data, then rebuilds and restarts from the code in your checkout. It does not fetch new code or wait for scans ([UPDATES.md](UPDATES.md)). `make admin` then says the account already exists and changes nothing.

On macOS or Windows, install Docker Desktop (with the WSL 2 backend on Windows), clone the repository, and run the README steps from a shell where `make` works, such as the macOS terminal or a WSL 2 distribution. Without `make`, the commands are plain Compose calls:

```bash
./scripts/init-env.sh
docker compose -f docker-compose.setup.yml run --rm certs
docker compose up -d --build
# wait until web has finished migrating (docker compose logs -f web), then:
docker compose exec -T web python3 manage.py create_admin
```

`.env` must exist first, because the database will not start with an empty password. A plain `docker compose up` does not record the installed commit for the updater, so the in-app update check shows it as unknown (`make up` records it). It also does not install the update watcher: run `sudo scripts/install-updater.sh` once so the Approve button works.

Give Docker Desktop at least the memory recommended above.

## HTTPS

`make certs` creates a private certificate authority and a certificate in `secrets/certs/` for `DOMAIN_NAME` (a hostname or an IP address), `localhost`, `127.0.0.1`, and anything in `CERT_EXTRA_SANS`. `install.sh` runs it only when the certificate is missing or does not match the address. Run it before `make up`, and again after changing `DOMAIN_NAME`. The built-in proxy serves HTTPS (TLS 1.2 and 1.3, HTTP/2) on 443 and redirects plain HTTP on 8082 to it. It accepts request bodies up to 4 MB. Browsers warn until you trust `secrets/certs/ca.crt`, which you copy from the server.

The files in `secrets/certs/` are `ca.crt`, `ca.key`, `ca.srl`, `rengine.pem`, `rengine_chain.pem`, and `rengine_rsa.key`. Both certificates use RSA 4096 and are valid for 3,650 days. A new authority's key is encrypted with `AUTHORITY_PASSWORD`. Every `make certs` issues a fresh server key and reuses the authority, so browsers that trust `ca.crt` keep trusting it. An authority made by an older version keeps an unencrypted key until you delete `ca.key` and `ca.crt` and run `make certs` again, after which browsers need the new `ca.crt`.

For a public site with a browser-trusted certificate (Let's Encrypt, Cloudflare), follow [HOSTING-ONLINE.md](HOSTING-ONLINE.md).

To use your own proxy or CDN, point it at the web service (`127.0.0.1:8000` on the host) and have it set `X-Forwarded-Proto` and `X-Forwarded-For`, replacing any values from the client. Then add `CVENGINE_CSRF_TRUSTED_ORIGINS` (your https address) to `.env` and run `make up`.

**Client addresses.** The IP allowlist and the abuse guard need the real client address. CVEngine reads it from `X-Forwarded-For`, but only when the peer connecting to the web container is listed in `CVENGINE_TRUSTED_PROXIES`. That setting names the addresses the web container sees *connecting to it*, not your proxy's public or LAN address. A proxy on the Docker host reaches the container through the Docker bridge gateway, which the default `172.16.0.0/12` already covers, so for a proxy on the same host you set nothing. Do not replace the default with your proxy's own network: the gateway is then untrusted, `X-Forwarded-For` is ignored, and every request appears to come from the gateway. If you need to trust more, add to the default (`172.16.0.0/12,203.0.113.0/24`): the address the container sees if your proxy does not arrive through the bridge, and the networks of any further hops (a CDN edge) that append to `X-Forwarded-For` instead of replacing it. Your outermost proxy must overwrite any `X-Forwarded-For` the client sent.

Django sends an HSTS header with a one-hour lifetime by default and does not include subdomains or ask for preloading. Raise `CVENGINE_HSTS_SECONDS` only once your public TLS path is reliable.

## AI models

cvENGINE runs no model itself. In **Settings, AI model**, choose Anthropic, OpenAI, OpenRouter, [Ollama](https://github.com/ollama/ollama), [vLLM](https://github.com/vllm-project/vllm), or [LM Studio](https://lmstudio.ai). For Ollama, vLLM and LM Studio enter your server's **Base URL**, press **Load models**, choose one, tick **Use this model to confirm CVE matches**, and **Save**.

- **A remote machine**, the usual case on a VPS: use any address the server can reach, such as a Tailscale `100.x` address (`http://100.64.0.5:11434`). MagicDNS names do not resolve inside containers. Keep the port on your tailnet or behind a firewall, since Ollama has no authentication.
- **The same machine**: enter `http://localhost:11434`. cvENGINE maps `localhost`, `127.0.0.1`, and `::1` to the Docker host. Ollama must then listen beyond 127.0.0.1 (for example `OLLAMA_HOST=0.0.0.0`) while staying firewalled.
- **vLLM** works the same way with its `/v1` URL, such as `http://100.64.0.5:8000/v1`. An API key is optional.
- **LM Studio** serves an OpenAI-compatible API on port 1234: use `http://100.64.0.5:1234/v1` (or `http://localhost:1234/v1` on the same machine). Start the server in LM Studio's Developer tab, or headless with `lms server start` (or the `llmster` daemon). LM Studio listens on localhost only until you switch on serving on the local network in its server settings, and a server reached over a tailnet or network should have authentication on: LM Studio 0.4 and later can require an API token (Server Settings, Manage Tokens), which you enter here as the **API key**. Leave the key blank when authentication is off. With just-in-time loading on (the default), **Load models** lists every model you have downloaded, embedding models excluded, and the first request for a model loads it, which can take a minute or more for a large one (cvENGINE waits up to five minutes). With it off, only models you have already loaded are listed. Screenshot reading needs a vision model.

## Backups

Back up the database, `.env` and the secret file, but keep the keys apart from the dump. The dump holds the database only: scan result files (screenshots and raw output) live in the `scan_results` Docker volume, and the optional add-ons keep their state in volumes of their own (`tailscale_state` and the `openvas_*` volumes), so none of those are in it. `web/secret` also keys the hashes of the session table and the recovery codes, so a restore without it signs everyone out and breaks new recovery codes. Stored secrets are encrypted with `CVENGINE_FIELD_KEY` from `.env` (older values with a key derived from `web/secret`), so a restored database needs the same keys. A dump stored in the same archive, bucket or folder as those keys gives away every stored API key, webhook URL and two-step seed to anyone who can read that place, which is exactly what the encryption is there to prevent: put `.env` and `web/secret` in a password manager or another store with different access, and the database dumps wherever backups normally go. Keep every copy private (mode 0600).

```bash
docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' | gzip > cvengine-$(date +%F).sql.gz
cp web/secret cvengine-secret.bak
```

To restore, put the original `.env` (with `CVENGINE_FIELD_KEY`) and `web/secret` in place, start only the database (`docker compose up -d db`), load the dump, then start everything with `make up`:

```bash
gunzip -c cvengine-2026-01-01.sql.gz | docker compose exec -T db sh -c 'psql -U "$POSTGRES_USER" "$POSTGRES_DB"'
```

Automatic deployment takes its own backup before every update ([UPDATES.md](UPDATES.md#automatic-deployment)).

## Make targets

`make help` lists them. They all use `docker-compose.yml` alone, and the ones that name services (`stop`, `restart`, `rm`, `logs`, `images`, `build`, `up`) act on the six core services only.

| Target | What it does |
| --- | --- |
| `make up` | Creates `.env` if it is missing, clears a leftover maintenance flag, moves a PostgreSQL 12 database to 18 ([UPGRADE.md](UPGRADE.md)), records the installed commit, then builds and starts the six core services. |
| `make build` | Records the installed commit and builds the images. |
| `make certs` | Creates the HTTPS certificate ([HTTPS](#https)). Refuses while the database or certificate password still says `change-me`. |
| `make admin`, `make admin-password` | Create the admin account with a generated password, or reset that account's password and print a new one. |
| `make username`, `make changepassword` | Create an admin account of your own choosing, or change a user's password. |
| `make migrate` | Applies migrations. |
| `make down`, `make stop`, `make restart`, `make rm` | Take the stack down, stop, restart or remove its containers. Volumes stay. |
| `make logs`, `make images` | Follow the logs (last 1000 lines), or show the images. |
| `make test` | Runs the test suite in the running `celery` container. |
| `make redis-auth`, `make rotate-field-key` | One-time hardening of an older install ([CONFIGURATION.md](CONFIGURATION.md#templates-and-secrets), [UPGRADE.md](UPGRADE.md#upgrading-to-12)). |
| `make openvas-up`, `make openvas-user`, `make openvas-down` | Start the optional OpenVAS add-on, save its generated login, stop it. The app does the same from Administration, OpenVAS ([OPENVAS.md](OPENVAS.md)). |
| `make export-cve-seed` | Writes this instance's CVE catalog to `web/cve-seed.jsonl.gz` ([PIPELINE.md](PIPELINE.md#seeding-the-catalog)). |
| `make inventory-sync` | Copies the host inventory reporter scripts to the copies the server hands out (a development task). |

## Development stack

A single-machine stack on `http://localhost:8000` with Django's auto-reloading server:

```bash
./scripts/init-env.sh
docker compose -f docker-compose.dev.yml build web celery celery-beat
docker compose -f docker-compose.dev.yml up -d db redis web celery celery-beat
# wait until web has finished migrating, then:
docker compose -f docker-compose.dev.yml exec web python3 manage.py createsuperuser
```

`make admin` only targets the production file, so use `createsuperuser` here.

## Updating

Three options, all of which keep the database and broker running: automatic deployment, approval in the app, or `scripts/update.sh` by hand. Manual updates wait for active tasks (or stop scans with `--stop-scans`), automatic deployment stops and requeues scans, and an approved update waits for running scans for 5 minutes by default and then interrupts what is left. The optional `tailscale` and `openvas` services are neither started nor stopped by an update. See [UPDATES.md](UPDATES.md). `make up` always uses `docker-compose.yml` alone, so on an install with its own overlay use `scripts/update.sh` or `docker compose` with your files instead. Moving an older install across the PostgreSQL 18 change is covered in [UPGRADE.md](UPGRADE.md).

## Factory reset

**Settings, Factory reset** (superusers only) returns the instance to a fresh install and restarts the setup wizard. It recreates a "Default" organization and project, ends every other session (yours stays), and records one `system.factory_reset` audit row after clearing the log. Five wrong passwords lock the button for 10 minutes. It removes every organization, project, target, host, scan, result file, other user, token (so every Sentinel is removed with its token and has to be enrolled again), and setting, plus the CVE feed, the audit log, and scheduled scans. It keeps your own account, the scan engines, wordlists, and installed tools. You must type `FACTORY RESET` and your password, and it refuses while scans are running unless you tick "reset anyway". It cannot be undone, so take a backup first.

## Uninstall

`scripts/uninstall.sh` lists the containers, volumes, and networks of this install's Compose project (named by `CVENGINE_COMPOSE_PROJECT`, then `COMPOSE_PROJECT_NAME`, then the checkout directory) and, once you type yes, deletes them and their locally built images. That includes all scan results. Other applications, including other reNgine installs, are not touched. `.env`, `secrets/`, `web/secret`, and `backups/` stay, and so do the update watcher and the automatic-deployment timer: run `sudo scripts/install-updater.sh --remove` and `sudo scripts/install-auto-deploy.sh --remove` first. It needs access to Docker, not necessarily `sudo`.

See also: [CONFIGURATION.md](CONFIGURATION.md), [documentation index](README.md).
