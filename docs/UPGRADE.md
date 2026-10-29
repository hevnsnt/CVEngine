# Upgrading from an older install

Older installs (reNgine and pre-release cvENGINE builds) ran PostgreSQL 12. The current release runs PostgreSQL 18, which cannot open a version 12 data directory, so the data is dumped and loaded into a new volume. The old volume is not converted or deleted. A fresh install needs none of this.

1. Back up the database, then `git pull`. Do not use the in-app updater or automatic deployment until the move is done.
2. `make up`. It moves the database to PostgreSQL 18, keeps a dump in `backups/`, then rebuilds and starts everything. The first build takes a while on an arm64 machine because nmap is compiled there (an x86-64 build installs the official nmap binary instead). For a development install, run `scripts/upgrade-postgres.sh --dev` and then `docker compose -f docker-compose.dev.yml up -d --build`.
3. When you have checked the data, remove the old volume: `docker volume rm <project>_postgres_data` (the project is `COMPOSE_PROJECT_NAME` in `.env`, default `rengine`).

To roll back, check out the previous commit and start it. It still uses the untouched old volume, without anything written since the upgrade.

## Upgrading to 1.2

An update takes a database dump, applies the migrations (a migration is never rolled back; when one fails the update says what state the database is in and keeps the dump, see [UPDATES.md](UPDATES.md)) and ends every session once, so everyone signs in again. Three protections are new-install only, because an update cannot switch them on without recreating services:

- **Redis password.** New installs generate `REDIS_PASSWORD` and every service uses it. On an older install Redis stays open to the Docker network until you run `make redis-auth` when scanning is idle. It recreates Redis, web, the workers, and the proxy, and queued tasks are lost.
- **Secret-encryption key.** New installs generate `CVENGINE_FIELD_KEY` in `.env`. An older install keeps reading its stored secrets with the key derived from `web/secret` until you run `make rotate-field-key`, which re-encrypts them under a new key and keeps the old one as `CVENGINE_FIELD_KEY_PREVIOUS` until you have a backup taken after the rotation. Back up `.env` and keep it apart from database dumps.
- **Web interface certificate.** A 10-year certificate made by an earlier installer is replaced once by the first automatic renewal check after the update, with a 397-day one (same key, same authority, same names); from then on it renews itself 30 days before it ends ([Deployment](DEPLOYMENT.md#https)). Nothing has to be copied to browsers again.
- **Certificate authority key.** An authority made by an older version keeps an unencrypted `ca.key`. To replace it, delete `ca.key` and `ca.crt` in `secrets/certs` and run `make certs`. Browsers then need the new `ca.crt`.

The in-app updater of a server installed before v1.2.0 has no watcher, so Approve does nothing there until you run `cd /opt/cvengine && git pull --ff-only && sudo scripts/install-updater.sh` once ([UPDATES.md](UPDATES.md)). On an install with its own Compose overlay, update with `scripts/update.sh` or the in-app updater, never `make up`.

## Accepted host names

The current release accepts only the host of `DOMAIN_NAME`, loopback (for health checks), and the names in `CVENGINE_ALLOWED_HOSTS`. Any other name gets **400 Bad Request** on every page. Before you update:

- Reached by the name in `DOMAIN_NAME`: nothing to do.
- Reached by another name or an IP address: add each to `.env`, comma separated, and run `make up`: `CVENGINE_ALLOWED_HOSTS=scanner.internal.example,192.0.2.10`.
- `DOMAIN_NAME` unset or still an example value: set it to the server's public name.

`python3 manage.py check` prints warning `cvengine.W001` when `DOMAIN_NAME` would leave only loopback accepted. Do not use `*` on an Internet-facing installation.

## Shared provider domains

An earlier build promoted a tenant such as `acme.jfrog.com` to `jfrog.com` in the weekly deep-discovery sweep. The update's migration deletes targets that sweep created on the shared-domain list, with their scans, hosts, and findings, because that data was outside your scope. A shared domain you added yourself is kept and set to `host` scope. Deleted targets do not come back on rollback, so back up first if you want that data.

## Dropped legacy tables and columns

The update's migrations delete schema that nothing writes or reads any more, since the old classic screens and the legacy `/api` routes are gone. The data in them is deleted with them and is not restored by a rollback of the code, so the database backup the update script takes before migrating is the way back:

- Tables: the old per-target **Organization** (`targetApp_organization`, not the organization/project tenancy), the classic **To-do notes** (`recon_note_todonote`), **Wordlist**, **Configuration** and the interesting-keyword lookup (`scanEngine_wordlist`, `scanEngine_configuration`, `scanEngine_interestinglookupmodel`), the old GPT vulnerability reports and **S3 bucket** results (`startScan_gptvulnerabilityreport`, `startScan_s3bucket`) with their link tables.
- Columns: `startScan_scanhistory.cfg_out_of_scope_subdomains`, `cfg_starting_point_path`, `cfg_excluded_paths` and `cfg_imported_subdomains`, and `cveFeed_cveentry.raw` (the cve.now entry stored a second time; the modelled columns already hold what is used).
- The scan report no longer has an "Interesting subdomains" section: its keyword list could only be filled in through the Django admin.

Scans, targets, hosts, findings and CVE data are untouched. A tool of your own that read one of these tables or columns needs the backup, or its data taken before the update.

See also: [DEPLOYMENT.md](DEPLOYMENT.md), [CONFIGURATION.md](CONFIGURATION.md), [documentation index](README.md).
