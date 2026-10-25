# Deployment

cvENGINE is one Docker Compose deployment: `db`, `redis`, `web`, `celery`, `celery-beat`, and `proxy` ([ARCHITECTURE.md](ARCHITECTURE.md)). The [README quick start](../README.md#quick-start) covers the install steps. Size the server for your scans: 8 GB of RAM is recommended, and heavy jobs queue by memory use ([CONFIGURATION.md](CONFIGURATION.md#memory-and-workers)). Images build for amd64 and arm64.

## Ports

| Port | Bound to | Service |
| --- | --- | --- |
| 443 and 8082 | all interfaces | `proxy`, the HTTPS front door |
| 8000 | `127.0.0.1` | `web`, for your own reverse proxy |
| 5432 | `127.0.0.1` | `db` |

Firewall 443 and 8082 to the people who need them. The development stack publishes 8000 on all interfaces, so keep it off untrusted networks.

## Linux, Mac, and Windows

`install.sh` is for Debian and Ubuntu: it installs curl, Docker, Compose, and make, then runs the setup. On any other Linux, install Docker (Compose 2.24 or newer) and make yourself and follow the README steps.

On macOS or Windows, install Docker Desktop (with the WSL 2 backend on Windows), clone the repository, and run the README steps from a shell where `make` works, such as the macOS terminal or a WSL 2 distribution. Without `make`, the commands are plain Compose calls:

```bash
docker compose -f docker-compose.setup.yml run --rm certs
docker compose up -d --build
docker compose exec web python3 manage.py createsuperuser
```

Give Docker Desktop at least the memory recommended above.

## HTTPS

`make certs` creates a private certificate authority and a certificate for `DOMAIN_NAME` in `secrets/certs/`. Run it before `make up`. The built-in proxy serves HTTPS on 443 and redirects HTTP; browsers warn until you trust `secrets/certs/ca.crt`.

To use your own proxy or CDN, point it at `127.0.0.1:8000` and have it set `X-Forwarded-Proto` and `X-Forwarded-For`, replacing any values from the client. Add `CVENGINE_CSRF_TRUSTED_ORIGINS` (your https address) to `.env` and run `make up`. Leave `CVENGINE_TRUSTED_PROXIES` at its default when the proxy runs on the Docker host, and set it only for a proxy on another network. A custom proxy must also provide its own HTTP to HTTPS redirect.

Django sends an HSTS header with a one-hour lifetime by default and does not include subdomains or ask for preloading. Raise `CVENGINE_HSTS_SECONDS` only once your public TLS path is reliable.

## AI models

cvENGINE runs no model itself. In **Settings, AI model**, choose Anthropic, OpenAI, OpenRouter, [Ollama](https://github.com/ollama/ollama), or [vLLM](https://github.com/vllm-project/vllm). For Ollama and vLLM enter your server's **Base URL**, press **Load models**, choose one, tick **Use this model to confirm CVE matches**, and **Save**.

- **A remote machine**, the usual case on a VPS: use any address the server can reach, such as a Tailscale `100.x` address (`http://100.64.0.5:11434`). MagicDNS names do not resolve inside containers. Keep the port on your tailnet or behind a firewall, since Ollama has no authentication.
- **The same machine**: enter `http://localhost:11434`. cvENGINE maps `localhost`, `127.0.0.1`, and `::1` to the Docker host. Ollama must then listen beyond 127.0.0.1 (for example `OLLAMA_HOST=0.0.0.0`) while staying firewalled.
- **vLLM** works the same way with its `/v1` URL, such as `http://100.64.0.5:8000/v1`. An API key is optional.

## Backups

Back up the database and the secret file together. Stored secrets are encrypted with a key derived from `web/secret`, so a restored database needs the same file. Keep both private (mode 0600).

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
docker compose -f docker-compose.dev.yml build web celery celery-beat
docker compose -f docker-compose.dev.yml up -d db redis web celery celery-beat
docker compose -f docker-compose.dev.yml exec web python3 manage.py createsuperuser
```

## Updating

Three options, all of which keep the database and broker running and let active work finish: automatic deployment, approval in the app, or `scripts/update.sh` by hand. See [UPDATES.md](UPDATES.md). Moving an older install across the PostgreSQL 18 change is covered in [UPGRADE.md](UPGRADE.md).

## Factory reset

**Settings, Factory reset** (superusers only) returns the instance to a fresh install and restarts the setup wizard. It removes every organization, project, target, host, scan, result file, other user, token, and setting, plus the CVE feed, the audit log, and scheduled scans. It keeps your own account, the scan engines, wordlists, and installed tools. You must type `FACTORY RESET` and your password, and it refuses while scans are running unless you tick "reset anyway". It cannot be undone, so take a backup first.

## Uninstall

`sudo scripts/uninstall.sh` stops and deletes every Docker container, volume, network, and image whose name contains `rengine`, which is the default `COMPOSE_PROJECT_NAME`. That includes all scan results. If you renamed the project it removes nothing of yours, and it removes other reNgine installs on the same host. To remove only this stack, run `docker compose down -v` in the checkout.

See also: [CONFIGURATION.md](CONFIGURATION.md), [documentation index](README.md).
