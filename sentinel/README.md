# CVEngine Sentinel

A Sentinel is a small Docker Compose service you run on a machine on your own network. It registers itself with your
CVEngine instance, pulls nmap, naabu and nuclei work off a project's scan queue, runs it locally, and reports typed
results back. There is no separate download or per-OS package: the client lives in this directory of the repository
and runs identically on Linux, macOS and Windows hosts through Docker.

See [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md#sentinels) for the design and [docs/AGENT-API.md](../docs/AGENT-API.md#sentinels-scan-stage-agents)
for the REST contract this client speaks. Nothing it runs is ever built from, or interprets, text the server sends:
see `client/tools.py`'s header for the argv discipline every tool call follows.

## Set up

1. Clone this repository onto the machine that will do the scanning (the same one you would otherwise have run nmap
   on by hand):
   ```
   git clone https://github.com/hevnsnt/CVEngine.git
   cd CVEngine
   ```
2. On your CVEngine instance's **Sentinels** page (`/cve/sentinels/`), pick the project and click **Provision**. Copy
   the one-time blob it shows (it is single-use and expires in 30 minutes). You need the admin role in the project or
   its organization to do this; see [docs/FRONTEND.md](../docs/FRONTEND.md#sentinels).
3. Create `sentinel/.env` from the example and paste the blob in:
   ```
   cp sentinel/.env.example sentinel/.env
   ```
   ```ini
   # sentinel/.env
   CVENGINE_SENTINEL_BLOB=eyJlbnJvbGxtZW50X3Rva2VuIjoi...
   # CVENGINE_SENTINEL_NAME=office-scanner
   # CVENGINE_SENTINEL_MAX_CONCURRENT=2
   ```
4. Start it:
   ```
   docker compose -f sentinel/docker-compose.yml up -d
   ```

The first start decodes the blob, bootstraps (trades the one-time secret for this Sentinel's own token) and saves
that token to the `sentinel-state` Docker volume. Every start after that uses the saved token directly: the blob in
`.env` is read only once and can be removed from `.env` (or left; it is ignored once a token is persisted).

## Check it registered

Open the **Sentinels** page on your CVEngine instance. The new Sentinel appears by its name (the container's
hostname, or `CVENGINE_SENTINEL_NAME` if you set one), `pending` until an administrator approves it, then `active`
and `live` once it starts heartbeating. From there it is administered exactly like any other agent: **Suspend** /
**Revoke**, and `GET /api/v1/agents?kind=scanner` / `GET /api/v1/agents/{id}` if you prefer the API or MCP tools
(`list_sentinels`, `get_sentinel`).

```
docker compose -f sentinel/docker-compose.yml logs -f
```
shows the bootstrap result and every task it picks up; the token itself is never logged.

## Stop and remove it

```
docker compose -f sentinel/docker-compose.yml down
```
stops the container; its persisted token stays in the `sentinel-state` volume, so starting it again does not need a
new blob. To remove it for good, also drop the volume and revoke it server-side:

```
docker compose -f sentinel/docker-compose.yml down -v
```

and, on the **Sentinels** page (or `PATCH /api/v1/agents/{id}` with `{"status": "revoked"}`), **Revoke** the Sentinel
so its token can never be used again, even if a copy of `sentinel-state` survives somewhere. Revoking also hands back
any task it was mid-run on to the queue immediately.

## Configuration

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `CVENGINE_SENTINEL_BLOB` | Only for the first start | - | The one-time provisioning blob from the Sentinels page. Ignored once a token is persisted. |
| `CVENGINE_SENTINEL_NAME` | No | the container's hostname | The Sentinel's name on the Sentinels page. |
| `CVENGINE_SENTINEL_MAX_CONCURRENT` | No | `1` | How many nmap/naabu/nuclei runs this Sentinel executes at once. |

`docker-compose.yml` adds `NET_RAW`/`NET_ADMIN` (not `--privileged`), which nmap's OS detection and naabu's SYN
scanning need; it runs on the Docker bridge network by default, so if your targets are elsewhere on your LAN rather
than reachable through that bridge, uncomment `network_mode: host` in `docker-compose.yml`.

## What it will and will not do

A Sentinel only ever runs one of four whitelisted tools (nmap, naabu, nuclei in its light or targeted pass) against
the exact address, host or target list a `SentinelTask` names, built as a fixed argv list, never a shell command. It
never evaluates or interprets any text the server sends as code or as a command, and it reports typed, bounded
results back; see `client/tools.py` for the validation every target list passes through before a tool ever runs
against it.
