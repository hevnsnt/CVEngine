# Deployment

CVEngine is one Docker Compose deployment: `db`, `redis`, `web`, `celery`, `celery-beat`, and `proxy`. See [ARCHITECTURE.md](ARCHITECTURE.md) for what each service does and the [README quick start](../README.md#quick-start) for the five install commands. Size the server for your scans: 8 GB of RAM is recommended, and heavy jobs queue by memory use ([CONFIGURATION.md](CONFIGURATION.md)).

## Mac and Windows

`install.sh` is for Linux. On macOS or Windows, install Docker Desktop (Compose 2.24 or newer, and the WSL 2 backend on Windows), clone the repository, and follow the README steps from a shell where `make` works: the macOS terminal, or a WSL 2 distribution. Without `make`, the commands are plain Docker Compose calls:

```bash
docker compose -f docker-compose.setup.yml run --rm certs
docker compose up -d --build
docker compose exec web python3 manage.py createsuperuser
```

Give Docker Desktop at least as much memory as the Linux guidance in [CONFIGURATION.md](CONFIGURATION.md).

## HTTPS

`make certs` creates a private certificate authority and a certificate for `DOMAIN_NAME` in `secrets/certs/`. Run it before `make up`. The built-in proxy serves HTTPS on port 443, and browsers warn until you trust `secrets/certs/ca.crt`.

To use your own proxy or CDN, point it at the web service (`127.0.0.1:8000` on the host) and have it set `X-Forwarded-Proto` and `X-Forwarded-For`, replacing any values from the client. Then add `CVENGINE_CSRF_TRUSTED_ORIGINS` (your https address) to `.env` and run `make up`.

**Client addresses.** The IP allowlist and the abuse guard need the real client address. CVEngine reads it from `X-Forwarded-For`, but only when the peer connecting to the web container is listed in `CVENGINE_TRUSTED_PROXIES`. That setting names the addresses the web container sees *connecting to it*, not your proxy's public or LAN address. A proxy on the Docker host reaches the container through the Docker bridge gateway, which the default `172.16.0.0/12` already covers, so for a proxy on the same host you set nothing. Do not replace the default with your proxy's own network: the gateway is then untrusted, `X-Forwarded-For` is ignored, and every request appears to come from the gateway. If you need to trust more, add to the default (`172.16.0.0/12,203.0.113.0/24`): the address the container sees if your proxy does not arrive through the bridge, and the networks of any further hops (a CDN edge) that append to `X-Forwarded-For` instead of replacing it. Your outermost proxy must overwrite any `X-Forwarded-For` the client sent.

Django sends an HSTS header on HTTPS responses with a one-hour default lifetime. Verify your public TLS path before raising `CVENGINE_HSTS_SECONDS`; CVEngine does not include subdomains or request browser preloading. The bundled proxy redirects HTTP to HTTPS. A custom proxy must provide its own redirect and overwrite `X-Forwarded-Proto` so Django can identify secure requests.

## AI models

CVEngine does not run a model itself. In **Settings, AI model**, choose a provider (Anthropic, OpenAI, OpenRouter, Ollama, or vLLM). For Ollama and vLLM, enter the **Base URL** of your server, press **Load models**, and choose one. Then tick **Use this model to confirm CVE matches** and press **Save**.

- **A remote machine**, the usual case on a VPS: enter any address the server can reach, such as a Tailscale address (`http://100.64.0.5:11434`). Use the `100.x` address, because MagicDNS names do not resolve inside containers. Keep the port on your tailnet or behind a firewall, since Ollama has no authentication.
- **The same machine**: enter `http://localhost:11434`. CVEngine maps `localhost`, `127.0.0.1`, and `::1` to the Docker host. Ollama must then listen beyond 127.0.0.1 (for example `OLLAMA_HOST=0.0.0.0`) while staying firewalled.
- **vLLM** works the same way with its `/v1` URL, such as `http://100.64.0.5:8000/v1`. An API key is optional.

## Backups

Back up the database and the secret file together. Stored secrets are encrypted with a key derived from `web/secret`, so a restored database needs the same file.
Keep both backups private (mode 0600). CVEngine creates `web/secret` with private permissions on startup.

```bash
docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' | gzip > cvengine-$(date +%F).sql.gz
cp web/secret cvengine-secret.bak
```

## Development stack

A single-machine stack on `http://localhost:8000`, with Django's auto-reloading server. It publishes port 8000 on all interfaces, so keep it off untrusted networks.

```bash
docker compose -f docker-compose.dev.yml build web celery celery-beat
docker compose -f docker-compose.dev.yml up -d db redis web celery celery-beat
docker compose -f docker-compose.dev.yml exec web python3 manage.py createsuperuser
```

## Updating

Run `scripts/update.sh` from a clean checkout (`--check` first shows what it will do), or approve updates in the app ([UPDATES.md](UPDATES.md)). Both keep the database and broker running and let active work finish before restarting. If a host proxy or your own Compose overlay sits in front of CVEngine, set it once in `.env` as described in [custom Compose layouts](UPDATES.md#custom-compose-layouts). Moving an older install across the PostgreSQL 18 change is covered in [UPGRADE.md](UPGRADE.md).

## Factory reset

**Settings, Factory reset** (superusers only) returns the instance to a fresh install and restarts the setup wizard. It removes every organization, project, target, host, scan, result file, other user, token, and setting, plus the CVE feed, the audit log, and scheduled scans. It keeps your own account, the scan engines, wordlists, and installed tools. You must type `FACTORY RESET` and your password, and it refuses while scans are running unless you tick "reset anyway". It cannot be undone, so take a backup first.

See also: [CONFIGURATION.md](CONFIGURATION.md), [documentation index](README.md).

Updater coordination and pending stopped scans are stored outside the writable application mount, under `git rev-parse --git-path cvengine-update`. Keep that directory private to the host operator. `scripts/update.sh --check` inspects readiness without creating update state; the actual update shares its lock with `scripts/apply-update.sh`.
