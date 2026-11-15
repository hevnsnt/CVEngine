# cvengine.live

The marketing site and early-access list for hosted cvENGINE, on Cloudflare Workers.

- `src/page.html`: the page content (edit this one).
- `build.sh`: wraps it into `public/index.html` (and writes `public/404.html`).
- `src/worker.js`: serves `public/` and saves early-access requests at `POST /api/early-access` into D1.
- `schema.sql`: the D1 table.
- `wrangler.jsonc`: the Worker, its static assets, the D1 binding and the `cvengine.live` custom domain.

## Cost on the Workers Free plan

- Static asset requests (the page itself) are free and unlimited.
- Only `/api/early-access` runs the Worker, so the Free plan's daily Worker request allowance is far more than an early-access form needs.
- D1 on the Free plan allows 100,000 rows written a day and 5 GB of storage. One request writes one row.

## Deploy

Needs Node.js and a Cloudflare account that holds the `cvengine.live` zone.

```bash
npx wrangler login                                   # opens a browser to authorise Wrangler
npx wrangler d1 create cvengine-live                 # copy the printed database_id into wrangler.jsonc
npx wrangler d1 execute cvengine-live --remote --file=schema.sql
./build.sh
npx wrangler deploy                                  # publishes the Worker and attaches cvengine.live
```

Try it locally first with `./build.sh && npx wrangler d1 execute cvengine-live --local --file=schema.sql && npx wrangler dev`.

## Read the early-access list

```bash
npx wrangler d1 execute cvengine-live --remote \
  --command "SELECT email, company, domain, addresses, created_at FROM early_access ORDER BY created_at DESC"
```

## Not here yet

Payment and automatic provisioning of a cvENGINE server and Sentinel per customer. Those need machines that run around the clock with persistent disks, which Cloudflare Workers and Containers do not provide (see the hosting notes in the conversation that created this project).

## Deploying from a Claude Code cloud session

This folder lives on the `claude/determined-ritchie-bgkl84` branch of the CVEngine repo only so it is not lost; it is not part of cvENGINE itself and should move to its own repository.

The session needs two environment variables (set in the cloud environment's settings, never pasted into chat):

- `CLOUDFLARE_API_TOKEN`: a token with Account: Workers Scripts Edit, D1 Edit, Account Settings Read; Zone (cvengine.live): Workers Routes Edit, DNS Edit, Zone Read.
- `CLOUDFLARE_ACCOUNT_ID`: the account that holds the `cvengine.live` zone.

Then run the Deploy steps above with `npx -y wrangler@4` in place of `npx wrangler` (skip `wrangler login`).
