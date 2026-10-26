# Deployment

cvENGINE is one Docker Compose deployment: `db`, `redis`, `web`, `celery`, `celery-beat`, and `proxy` ([ARCHITECTURE.md](ARCHITECTURE.md)). The [README quick start](../README.md#quick-start) covers the install steps. Size the server for your scans: 4 GB of RAM is the least (the installer warns below that) and 8 GB is comfortable, and heavy jobs queue by memory use ([CONFIGURATION.md](CONFIGURATION.md#memory-and-workers)). Images build for amd64 and arm64.

## Ports

| Port | Bound to | Service |
| --- | --- | --- |
| 443 and 8082 | all interfaces | `proxy`, the HTTPS front door |
| 8000 | `127.0.0.1` | `web`, for your own reverse proxy |
| 5432 | `127.0.0.1` | `db` |

Firewall 443 and 8082 to the people who need them. The development stack publishes 8000 on all interfaces, so keep it off untrusted networks.

## Linux, Mac, and Windows

`install.sh` asks nothing. It checks that this is Linux, that it is root (it re-runs itself through `sudo`), the architecture, memory (it warns below about 3.5 GB), free disk on the checkout's filesystem (it warns below about 14 GiB), that ports 443 and 8082 are free (it stops if not), and whether Docker's registry and GitHub answer (it only warns). On Debian and Ubuntu it installs curl, make, python3, git, openssl, and the Compose plugin with `apt`. Docker comes from `get.docker.com` on any distribution that script supports. On other Linux it stops and names the missing tools, so install them and run it again, or follow the README steps. It needs Compose 2.24 or newer but does not check the version. When a step fails it prints the log lines of the failing service.

Running it again keeps `.env`, the certificate (unless the address changed), and your data, then rebuilds and restarts from the code in your checkout. It does not fetch new code or wait for scans ([UPDATES.md](UPDATES.md)).

On macOS or Windows, install Docker Desktop (with the WSL 2 backend on Windows), clone the repository, and run the README steps from a shell where `make` works, such as the macOS terminal or a WSL 2 distribution. Without `make`, the commands are plain Compose calls:

```bash
./scripts/init-env.sh
docker compose -f docker-compose.setup.yml run --rm certs
docker compose up -d --build
# wait until web has finished migrating (docker compose logs -f web), then:
docker compose exec -T web python3 manage.py create_admin
```

`.env` must exist first, because the database will not start with an empty password. A plain `docker compose up` does not record the installed commit for the updater, so the in-app update check shows it as unknown. `make up` records it.

Give Docker Desktop at least the memory recommended above.

## HTTPS

`make certs` creates a private certificate authority and a certificate in `secrets/certs/` for `DOMAIN_NAME` (a hostname or an IP address), `localhost`, `127.0.0.1`, and anything in `CERT_EXTRA_SANS`. `install.sh` runs it only when the certificate is missing or does not match the address. Run it before `make up`, and again after changing `DOMAIN_NAME`. The built-in proxy serves HTTPS (TLS 1.2) on 443 and redirects plain HTTP on 8082 to it. Browsers warn until you trust `secrets/certs/ca.crt`, which you copy from the server.

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

Back up the database, `.env` and the secret file, but keep the keys apart from the dump. Stored secrets are encrypted with `CVENGINE_FIELD_KEY` from `.env` (older values with a key derived from `web/secret`), so a restored database needs the same keys. A dump stored in the same archive, bucket or folder as those keys gives away every stored API key, webhook URL and two-step seed to anyone who can read that place, which is exactly what the encryption is there to prevent: put `.env` and `web/secret` in a password manager or another store with different access, and the database dumps wherever backups normally go. Keep every copy private (mode 0600).

```bash
docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' | gzip > cvengine-$(date +%F).sql.gz
cp web/secret cvengine-secret.bak
```

To restore, start a fresh stack with the original `web/secret` in place, then load the dump into the empty database:

```bash
gunzip -c cvengine-2026-01-01.sql.gz | docker compose exec -T db sh -c 'psql -U "$POSTGRES_USER" "$POSTGRES_DB"'
```

Automatic deployment takes its own backup before every update ([UPDATES.md](UPDATES.md#automatic-deployment)).

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

Three options, all of which keep the database and broker running: automatic deployment, approval in the app, or `scripts/update.sh` by hand. Manual updates wait for active tasks (or stop scans with `--stop-scans`), automatic deployment stops and requeues scans, and an approved update waits for running scans. See [UPDATES.md](UPDATES.md). Moving an older install across the PostgreSQL 18 change is covered in [UPGRADE.md](UPGRADE.md).

## Factory reset

**Settings, Factory reset** (superusers only) returns the instance to a fresh install and restarts the setup wizard. It removes every organization, project, target, host, scan, result file, other user, token, and setting, plus the CVE feed, the audit log, and scheduled scans. It keeps your own account, the scan engines, wordlists, and installed tools. You must type `FACTORY RESET` and your password, and it refuses while scans are running unless you tick "reset anyway". It cannot be undone, so take a backup first.

## Uninstall

`scripts/uninstall.sh` lists the containers, volumes, and networks of this install's Compose project (named by `CVENGINE_COMPOSE_PROJECT`, then `COMPOSE_PROJECT_NAME`, then the checkout directory) and, once you type yes, deletes them and their locally built images. That includes all scan results. Other applications, including other reNgine installs, are not touched. `.env`, `secrets/`, `web/secret`, and `backups/` stay. It needs access to Docker, not necessarily `sudo`.

See also: [CONFIGURATION.md](CONFIGURATION.md), [documentation index](README.md).
