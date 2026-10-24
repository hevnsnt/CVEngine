# Upgrading from an older install

Installs made before 23 October 2026 ran PostgreSQL 12. The current release runs PostgreSQL 18, which cannot open a version 12 data directory, so the data is dumped and loaded into a new volume. The old volume is not converted or deleted. A fresh install needs none of this.

1. Schedule a maintenance window, back up the database, stop the old stack with `docker compose down` (without `-v`), then update the code with `git pull`. The routine host updater does not perform a PostgreSQL major-version move; complete step 2 explicitly before resuming routine updates.
2. Move the database:

   ```bash
   scripts/upgrade-postgres.sh          # production compose file; `make up` runs this for you
   scripts/upgrade-postgres.sh --dev    # docker-compose.dev.yml
   ```

   A copy of the dump is kept in `backups/`. The script stops the `db` container (and any other container using the old volume) before it starts PostgreSQL 12 on that volume, and it works with a `.env` that does not set `COMPOSE_PROJECT_NAME`, `POSTGRES_USER` or `POSTGRES_DB` (defaults `rengine`).
3. Rebuild and start. The images change completely and the first build takes a while because nmap is compiled:

   ```bash
   make up
   ```

   For a development install, run `docker compose -f docker-compose.dev.yml up -d --build`.
4. When you have checked the data, remove the old volume with `docker volume rm <project>_postgres_data` (the project name is `COMPOSE_PROJECT_NAME` in `.env`, default `rengine`). Until you do, `scripts/upgrade-postgres.sh` just reports that the upgrade is already done and exits successfully. `make up` invokes this one-time upgrade helper; routine updater scripts do not.

To roll back, check out the previous commit and start it. It still uses the untouched old volume.

## Scope of targets on shared provider domains

Earlier versions promoted a tenant such as `acme.jfrog.com` to `jfrog.com` in the weekly deep-discovery sweep and enumerated the whole provider. The update fixes that, and its database migration cleans up after it:

- A target on the shared-domain list (for example `jfrog.com`, `atlassian.net`) whose description is "Added for the weekly deep discovery of its subdomains" was created by the sweep. It is **deleted on migrate**, together with its scans, hosts and findings, because that data was outside your scope. The migration logs how many it removed.
- A shared domain you added yourself (any other description) is **kept** and its scope mode is set to `host`, so it stops enumerating the provider.
- Rolling back does not bring deleted targets back. Take a database backup first if you want to keep that data.

If you really control a parent domain that is on the list, set the target's scope mode to `parent` on the Targets page. The list is `SHARED_DOMAINS` in `web/targetApp/shared_domains.py`; see [PIPELINE.md](PIPELINE.md).

## Refill the CVE feed

The database move keeps the CVE feed. To fill the feed faster on a fresh install or after a factory reset, run:

```bash
docker compose exec celery python3 manage.py sync_cve_now --max-new 3000 --catch-up-after 500
```

## CVENGINE_NMAP_FULL is superseded

The opt-in full `-p-` sweep inside the discovery pipeline is gone: it made a scan take far too long. Setting `CVENGINE_NMAP_FULL` now does nothing. A background task sweeps all TCP ports of one in-scope IP every 10 minutes instead, never-swept IPs first (see Background full port scan in [PIPELINE.md](PIPELINE.md)); `CVENGINE_FULLSCAN=0` turns it off. The migrations add two columns to IP addresses and the beat schedule `cvengine-background-full-scan`.

See also: [DEPLOYMENT.md](DEPLOYMENT.md), [CONFIGURATION.md](CONFIGURATION.md), [documentation index](README.md).
