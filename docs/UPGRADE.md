# Upgrading from an older install

Older installs (reNgine and pre-release cvENGINE builds) ran PostgreSQL 12. The current release runs PostgreSQL 18, which cannot open a version 12 data directory, so the data is dumped and loaded into a new volume. The old volume is not converted or deleted. A fresh install needs none of this.

1. Back up the database, then `git pull`. Do not use the in-app updater or automatic deployment until the move is done.
2. `make up`. It moves the database to PostgreSQL 18, keeps a dump in `backups/`, then rebuilds and starts everything. The first build takes a while because nmap is compiled. For a development install, run `scripts/upgrade-postgres.sh --dev` and then `docker compose -f docker-compose.dev.yml up -d --build`.
3. When you have checked the data, remove the old volume: `docker volume rm <project>_postgres_data` (the project is `COMPOSE_PROJECT_NAME` in `.env`, default `rengine`).

To roll back, check out the previous commit and start it. It still uses the untouched old volume, without anything written since the upgrade.

## Accepted host names

The current release accepts only the host of `DOMAIN_NAME`, loopback (for health checks), and the names in `CVENGINE_ALLOWED_HOSTS`. Any other name gets **400 Bad Request** on every page. Before you update:

- Reached by the name in `DOMAIN_NAME`: nothing to do.
- Reached by another name or an IP address: add each to `.env`, comma separated, and run `make up`: `CVENGINE_ALLOWED_HOSTS=scanner.internal.example,192.0.2.10`.
- `DOMAIN_NAME` unset or still an example value: set it to the server's public name.

`python3 manage.py check` prints warning `cvengine.W001` when `DOMAIN_NAME` would leave only loopback accepted. Do not use `*` on an Internet-facing installation.

## Shared provider domains

An earlier build promoted a tenant such as `acme.jfrog.com` to `jfrog.com` in the weekly deep-discovery sweep. The update's migration deletes targets that sweep created on the shared-domain list, with their scans, hosts, and findings, because that data was outside your scope. A shared domain you added yourself is kept and set to `host` scope. Deleted targets do not come back on rollback, so back up first if you want that data.

See also: [DEPLOYMENT.md](DEPLOYMENT.md), [CONFIGURATION.md](CONFIGURATION.md), [documentation index](README.md).
