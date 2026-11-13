# Hosting cvENGINE online

How to put an install on the Internet under a real name (for example `scanner.example.com`) with a certificate browsers trust. The installer's own certificate comes from a private authority, so every browser warns until it is trusted; that is fine on a LAN and wrong for a public site.

You need a server that already runs cvENGINE ([install steps](DEPLOYMENT.md#install)), a domain you control, and the ability to open ports on the server's firewall (or, with [option C](#c-through-a-cloudflare-tunnel-no-inbound-port), a Cloudflare account instead of an open port).

## 1. Point the name at the server

Create a DNS `A` record (and `AAAA` if the server has IPv6) for the name, such as `scanner.example.com`, pointing at the server's public address. Open TCP **443** in the firewall. Port 8082 only redirects to HTTPS (see below) and can stay closed.

## 2. Tell cvENGINE the name

```bash
./scripts/init-env.sh scanner.example.com   # sets DOMAIN_NAME in .env
```

(or run `sudo ./install.sh --domain scanner.example.com`, which also works on a re-run; the old name then gets 400). `DOMAIN_NAME` is the host Django accepts, the name in notification links, and the name on the certificate. Any other name or IP address gets **400 Bad Request** unless it is listed in `CVENGINE_ALLOWED_HOSTS` ([CONFIGURATION.md](CONFIGURATION.md)).

Keep `DOMAIN_NAME` a bare name. The bundled proxy already makes `https://scanner.example.com` pass Django's CSRF check; `CVENGINE_CSRF_TRUSTED_ORIGINS` is only for a second public address or a proxy of your own.

## 3. Choose how the certificate is made

### A. A Let's Encrypt certificate on the bundled proxy

The proxy reads three files from `secrets/certs/`:

| File | Put there |
| --- | --- |
| `rengine.pem` | the certificate **and** its intermediates (Let's Encrypt's `fullchain.pem`) |
| `rengine_rsa.key` | the private key (`privkey.pem`) |
| `rengine_chain.pem` | the intermediates only (`chain.pem`) |

**The key must be RSA.** The proxy's cipher list is RSA-only (`aRSA` in `config/nginx/rengine.conf`) for TLS 1.2, and the proxy speaks TLS 1.2 and 1.3, so an ECDSA certificate (certbot's default since 2.0) makes TLS 1.2 handshakes fail. Ask for RSA explicitly.

Port 80 is not used by the stack, so certbot can answer the challenge itself while the proxy keeps running:

```bash
sudo apt install certbot            # or: snap install --classic certbot
sudo certbot certonly --standalone --key-type rsa -d scanner.example.com
```

(This needs port 80 open to the Internet while it runs. If you cannot open it, use a DNS challenge instead: `certbot certonly --manual --preferred-challenges dns --key-type rsa -d scanner.example.com`, or your DNS provider's certbot plugin.)

Install the files and restart the proxy:

```bash
L=/etc/letsencrypt/live/scanner.example.com
sudo install -m 600 $L/fullchain.pem secrets/certs/rengine.pem
sudo install -m 600 $L/privkey.pem   secrets/certs/rengine_rsa.key
sudo install -m 644 $L/chain.pem     secrets/certs/rengine_chain.pem
docker compose up -d --force-recreate proxy
```

The automatic renewal of the private certificate (`scripts/renew-certs.sh`, [Deployment](DEPLOYMENT.md#https)) never replaces a certificate the private authority did not issue, so it leaves these files alone; Settings > Updates and `get_system_status` still warn when such a certificate has fewer than 30 days left. Do not run `make certs` afterwards: it writes the private authority's certificate over these files. `sudo ./install.sh` is safe to run again, because it only regenerates the certificate when the name on it no longer matches `DOMAIN_NAME`.

**Renewal.** Let's Encrypt certificates last 90 days. Put the copy and restart in a certbot deploy hook so renewal needs no one:

```bash
sudo tee /etc/letsencrypt/renewal-hooks/deploy/cvengine.sh >/dev/null <<'HOOK'
#!/bin/sh
L=/etc/letsencrypt/live/scanner.example.com
D=/path/to/CVEngine
install -m 600 $L/fullchain.pem $D/secrets/certs/rengine.pem
install -m 600 $L/privkey.pem   $D/secrets/certs/rengine_rsa.key
install -m 644 $L/chain.pem     $D/secrets/certs/rengine_chain.pem
cd $D && docker compose up -d --force-recreate proxy
HOOK
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/cvengine.sh
sudo certbot renew --dry-run
```

With the standalone challenge, certbot needs port 80 free at renewal time too; that holds as long as nothing else on the host uses it.

### B. Behind Cloudflare (or another CDN)

Proxy the name through Cloudflare (orange cloud) and set **SSL/TLS mode** to **Full (strict)**, so the connection to your server is encrypted and verified. The origin needs a certificate Cloudflare accepts:

- Create a **Cloudflare Origin CA** certificate for the name (RSA, up to 15 years), save it as `secrets/certs/rengine.pem` with its key as `rengine_rsa.key`, and put Cloudflare's origin CA root in `rengine_chain.pem`. Then `docker compose up -d --force-recreate proxy`. Browsers never see this certificate; Cloudflare's own does the talking to them. Or use a Let's Encrypt certificate as in A.
- **Full** (not strict) also works with the installer's private certificate, but it does not verify the origin, so prefer strict.

Things to know when a CDN is in front:

- Only port 443 is needed from Cloudflare. Consider restricting the firewall to [Cloudflare's address ranges](https://www.cloudflare.com/ips/).
- The bundled proxy overwrites `X-Forwarded-For` with the address it sees connecting, which is Cloudflare's edge. The **IP allowlist** and the abuse guard therefore see Cloudflare's addresses, not your users'. Do not rely on the allowlist for access control behind a CDN; use Cloudflare Access or firewall rules instead.
- Static files are versioned by content (`?v=<hash>` on every stylesheet and script). A versioned URL is sent with `Cache-Control: public, max-age=31536000, immutable`, so Cloudflare and browsers keep it for a year; an update changes the URL of every file that changed, so Cloudflare cannot serve one release's stylesheet with another release's pages. Any other `/staticfiles/` URL (the fonts) is sent with `no-cache`. You do not need to purge the cache after an update. If your own proxy or CDN rewrites `Cache-Control` or strips the query string from `/staticfiles/` URLs, keep the query string in the cache key, or a new release can be served an old file.
- A scan of your own CDN-fronted name finds the CDN, not your server.

### C. Through a Cloudflare Tunnel (no inbound port)

For a server that cannot or should not open a port, such as a machine at home. `cloudflared` runs on the server (or beside it in Docker) and makes an outbound connection to Cloudflare; visitors reach `scanner.example.com` at Cloudflare, which sends the request down that connection. Nothing listens on the Internet side, so steps 1 (DNS `A` record) and the firewall rule do not apply. Sentinels on other machines use the same public name as everyone else and need nothing special.

**Prerequisites.** A domain whose DNS is on Cloudflare, a Cloudflare account with Zero Trust (the free plan is enough), and `cloudflared` installed on the server. cvENGINE already running ([install steps](DEPLOYMENT.md#install)) with `DOMAIN_NAME=scanner.example.com` as in step 2.

**Point `cloudflared` at the bundled proxy, not at the web service.** The proxy is the part that serves `/staticfiles/` with its cache headers, hands out scan screenshots and results (the application answers with an `X-Accel-Redirect` header that only this proxy understands, and Cloudflare removes that header from a direct reply), and shows the maintenance page while an update runs. Aimed straight at `127.0.0.1:8000`, a tunnel would lose all three and the pages would load without their styles. The proxy also speaks HTTPS with the certificate `make certs` made, which `cloudflared` can verify, so no unverified hop is needed.

**1. Give the tunnel its own door on the proxy.** The proxy has a second HTTPS listener inside its container, port 8443, with the same certificate and the same pages. It is the only listener that can believe an `X-Forwarded-For` it is sent, and only from a peer you list (below). Port 443 never believes one, whatever any file says. Make `docker-compose.tunnel.yml` in the cvENGINE folder: it publishes **only** that port, **only** on the server's loopback (443 and 8082 are no longer published at all), and mounts your list of trusted peers:

```yaml
services:
  proxy:
    ports: !override
      - "127.0.0.1:8443:8443"
    volumes:
      - ./config/nginx/trusted-upstreams.local.conf:/etc/nginx/trusted-upstreams.conf:ro
```

Why two conditions: Docker can show an outside visitor to the proxy as the bridge's gateway address (its userland proxy does this for IPv6 and for some hairpin cases), so "the peer is the gateway" alone does not prove the request came from `cloudflared`. If the overlay is ever left out (a `make up`, a forgotten `-f`), port 443 is published on every address again, and it still believes nobody.

Then tell the updater about the overlay in `.env`, so it is used by every update, the watchdog and the certificate renewal:

```
DOMAIN_NAME=scanner.example.com
CVENGINE_COMPOSE_FILES=docker-compose.yml,docker-compose.tunnel.yml
```

Start with an empty list (nobody trusted), then fill it in once you know the address:

```bash
cp config/nginx/trusted-upstreams.conf config/nginx/trusted-upstreams.local.conf   # the stock file only holds comments
docker compose -f docker-compose.yml -f docker-compose.tunnel.yml up -d
```

`config/nginx/trusted-upstreams.local.conf` names the one address the proxy sees `cloudflared` connect from, and nothing wider:

- **`cloudflared` on the server itself (recommended).** A connection to `127.0.0.1:8443` reaches the proxy through the Docker bridge, so the proxy sees the bridge's gateway. Print it:

  ```bash
  docker network inspect $(docker network ls -q --filter name=rengine_network) --format '{{.Name}} {{(index .IPAM.Config 0).Gateway}}'
  ```

  It looks like `172.18.0.1`. Put that address in the file as `172.18.0.1 1;` (your own number), then `docker compose -f docker-compose.yml -f docker-compose.tunnel.yml exec proxy nginx -s reload`. Anything else on this machine that can reach `127.0.0.1:8443` is believed too, so keep the machine's other users to those you trust.
- **`cloudflared` as a container on the Compose network.** Use that container's address, printed by `docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' <container>`. It can change when the container is recreated, which is why the server-side install is easier to keep right.

Do not list a range such as `172.16.0.0/12`, and do not list Cloudflare's addresses. `CVENGINE_TRUSTED_PROXIES` needs no change: its default, `172.16.0.0/12`, already covers the proxy's own address, which is what the web container sees (add your own subnet to it, never replace it, only if you run Docker with an address pool outside that range).

From now on name both files whenever you run `docker compose` by hand, and do not use `make up` or re-run `install.sh`: both read only `docker-compose.yml`, so they would publish 443 on every address again (harmless to the addresses the server believes, but the tunnel overlay is gone and the open port is back). The updater, the in-app update, the watchdog and the certificate renewal use the setting in `.env`; the updater also refuses to run when a Compose file like `docker-compose.tunnel.yml` sits in the folder and `.env` does not name it.

**2. Create the tunnel.** With `cloudflared tunnel login`, `cloudflared tunnel create cvengine` and `cloudflared tunnel route dns cvengine scanner.example.com`, then copy `secrets/certs/ca.crt` to `/etc/cloudflared/cvengine-ca.crt` and write `/etc/cloudflared/config.yml`:

```yaml
tunnel: cvengine
credentials-file: /etc/cloudflared/<tunnel-id>.json
ingress:
  - hostname: scanner.example.com
    service: https://127.0.0.1:8443
    originRequest:
      originServerName: scanner.example.com
      caPool: /etc/cloudflared/cvengine-ca.crt
  - service: http_status:404
```

`originServerName` is the name on the certificate (it is `DOMAIN_NAME`), and `caPool` is the installer's private authority, so `cloudflared` verifies the proxy. Do not use `noTLSVerify`. Leave `httpHostHeader` unset: the application must see the public name in `Host`. With a Let's Encrypt certificate on the proxy (A above) `caPool` is not needed. Then `sudo cloudflared service install` (or run `cloudflared tunnel run cvengine`). If `cloudflared` runs as a container on the Compose network instead, add it as a service in `docker-compose.tunnel.yml` with the same `config.yml` and credentials mounted and point the ingress at `https://proxy:443`; the rest is the same. (The container form was not run here.)

**3. Check that the server sees each visitor's own address, before any Sentinel uses the tunnel.** Do this first: every address the server believes (the allowlist, the abuse guard's bans, the sign-in lockout) depends on it. Sign in at `https://scanner.example.com`, open **Settings > IP allowlist**: the line "your current IP" is the address the server took for you. It must be your own public address (the one a "what is my IP" page shows), not a `172.` address. Check it again from a second network, such as a phone off Wi-Fi: it must show a different address. To see what the proxy itself saw connect, make one request and run `docker compose -f docker-compose.yml -f docker-compose.tunnel.yml logs --tail 5 proxy`: the first field of each line is the peer, and it must be the address in `trusted-upstreams.local.conf`.

If it shows a `172.` address (or `127.0.0.1`), the server is treating every visitor as one address. Do not turn the allowlist on and do not point Sentinels at the name yet. Work through these in order:

- The first field in the proxy log is not the address in the file: put the address from the log in the file and reload the proxy (`... exec proxy nginx -s reload`).
- The log line is missing: the request did not come through port 8443. Check that `cloudflared` points at `https://127.0.0.1:8443`, not at 443, and that the overlay is the one running (`docker compose -f docker-compose.yml -f docker-compose.tunnel.yml ps` shows `127.0.0.1:8443->8443/tcp`).
- The address is right but the page still shows `172.`: Cloudflare is not sending `X-Forwarded-For`, usually because its "Remove visitor IP headers" transform is on. Turn it off.
- Still wrong: stop here and leave the tunnel unused; a wrong address is worse than a slow one. Empty `trusted-upstreams.local.conf` (reload the proxy) so nothing is believed, and leave the allowlist off.

Until it is right, one visitor's lockout is everyone's.

**How the address is chosen, and what a visitor can fake.** Cloudflare adds the address that connected to it at the end of `X-Forwarded-For`; if the visitor sent one of its own, it stays in front of that. The bundled proxy keeps the chain from a listed peer and adds the peer at the end, and the application takes the last address that is not a trusted proxy, so what a visitor writes at the front is never picked. A request on port 443, or from a peer that is not listed, has its `X-Forwarded-For` thrown away, as always. Cookies, CSRF and `ALLOWED_HOSTS` need nothing extra: the proxy tells Django the request was HTTPS, the public name is `DOMAIN_NAME`, and secure cookies are on. HSTS is sent by the application as before.

**What does not work, or works differently.**

- **Request size.** Cloudflare refuses a request body over 100 MB on the Free and Pro plans (200 MB Business). Only one route can be that large: **Settings > CVE catalog seed > Import a seed file** (the application and the proxy accept 256 MB; a seed is about 14 MB today). If a seed is ever larger than your plan allows, import it on the server: copy the file there and run `docker compose run --rm -v "$PWD/cve-seed.jsonl.gz:/seed/cve-seed.jsonl.gz:ro" --entrypoint python3 web manage.py import_cve_seed /seed/cve-seed.jsonl.gz` (a `.manifest.json` beside the file is checked first). A Sentinel's result is at most 24 MB and a pasted target list at most 2 MB, both far below the limit.
- **Slow requests.** Cloudflare waits at most 125 seconds for the first byte of an answer (100 seconds in some older documentation, so plan for 100) and then shows its own error 524 page. A Sentinel's long poll holds for at most 20 seconds, so it is not affected. The one request that can run longer is adding many targets in one go (**Add targets** with thousands of lines, up to 300 seconds); on a large paste the browser may show a 524 although the server goes on and finishes. Check the target list before you paste it again, and add large lists in batches of a few hundred lines. Report PDFs are built by a background job and downloaded afterwards, scans, seed builds and the AI reviewer are background jobs too, and nothing in cvENGINE uses a WebSocket or a long-lived stream, so none of those meets the limit.
- **IP allowlist.** It works on the real visitor address as long as step 3 shows the right one. A Sentinel is checked the same way, so a Sentinel's VPS address must be on the list if you turn it on.
- **Other limits.** Cloudflare's own bot and firewall rules in front can block a Sentinel or an MCP client; they see the same requests as a browser would. Add a skip rule for `/api/v1/` and `/mcp/` if they do.
- **Cloudflare Access.** An Access policy in front of the name would block Sentinels and MCP clients, which send a bearer token and no cookies or Cloudflare headers. Give these paths a **Bypass** policy (they carry their own token): `/api/v1/` (the Sentinel calls `/api/v1/sentinels/bootstrap` and `/api/v1/sentinel/...`; the REST API and the AI reviewer use the rest of `/api/v1/`) and `/mcp/`. Keep Access on everything else, and keep the IP allowlist and two-step sign-in on. A service token (a `Service Auth` policy) needs the client to send Cloudflare's headers, which neither a Sentinel nor a plain MCP client does.

**Updates.** The updater works as before: it checks that the site answers on the proxy's published loopback port (8443 here; it looks for 443 first and then 8443), not through Cloudflare. While it migrates, the proxy shows the maintenance page (Cloudflare passes it on; it is sent with `no-store`, and a Sentinel just retries). For the few seconds the proxy itself restarts, `cloudflared` has nothing to connect to and Cloudflare shows its own 502 page instead. Nothing needs purging in Cloudflare after an update ([static files](#b-behind-cloudflare-or-another-cdn) are versioned). The first update after you add `CVENGINE_COMPOSE_FILES` is the check that the overlay is kept; look at `docker compose ps` afterwards.

**Moving an existing install.** Keep the same `DOMAIN_NAME` so Sentinels, MCP clients and bookmarks keep working, and switch DNS last. Do step 1 and 2 first, but create the tunnel's route under a temporary name (`cloudflared tunnel route dns cvengine test.example.com`, and `test.example.com` as a second `hostname:` in the ingress). Add `CVENGINE_ALLOWED_HOSTS=test.example.com` and `CVENGINE_CSRF_TRUSTED_ORIGINS=https://test.example.com` to `.env` for the test (`docker compose ... up -d web`) and do step 3 there. Only when the address is right: remove those two lines, delete the old `A`/`AAAA` record for the real name and run `cloudflared tunnel route dns cvengine scanner.example.com` (`--overwrite-dns` if you leave the record in place), close TCP 443 on the firewall once the tunnel answers, and watch **Scanners > Sentinels** until every Sentinel checks in again (about a minute). Nothing is re-enrolled: the address in a Sentinel's enrollment is the public name. A Let's Encrypt certificate already on the proxy can stay (drop `caPool`); the installer's certificate and its `caPool` line also work.

**What Cloudflare can see.** The tunnel ends at Cloudflare: your visitors' HTTPS connection is decrypted there and sent on to you over the tunnel. Everything that passes, including findings, scan results, the contents of the pages, session cookies and the API tokens of Sentinels and MCP clients, is readable by Cloudflare while it passes, and its logs and settings can change what happens to it. That is the same exposure as the proxied DNS in B, and the price of having no open port. If it is not acceptable, keep the server on a private network and reach it over a VPN instead.

### D. Your own reverse proxy

If you already run Caddy, nginx, or Traefik on the host and want it to own port 443, it must forward to the web service on `127.0.0.1:8000`, set `X-Forwarded-Proto` and `X-Forwarded-For` itself (replacing anything the client sent), and keep the `Host` header. Then list your public address in `CVENGINE_CSRF_TRUSTED_ORIGINS` (`https://scanner.example.com`) and read **Client addresses** in [DEPLOYMENT.md](DEPLOYMENT.md#https). The bundled proxy also binds 443 on the host, so the two cannot run side by side without changing the proxy's published ports; this recipe has not been tested end to end, so try it on a staging host first.

## 4. Check it

```bash
curl -sSI https://scanner.example.com/ | head -3
echo | openssl s_client -connect scanner.example.com:443 -servername scanner.example.com 2>/dev/null | openssl x509 -noout -issuer -subject -dates
```

The first should answer `HTTP/2 302` (or `200`) with no certificate warning; the second shows your certificate authority and its expiry date. Then open the site, sign in, and change the generated admin password if you have not already.

## 5. Before you rely on it

- **Raise HSTS** once HTTPS works reliably everywhere: `CVENGINE_HSTS_SECONDS=31536000` in `.env`, then `make up`. It starts at one hour so a mistake is forgiven; a browser holds a longer value for that long.
- **Keep Docker's published ports tight.** Only 443 (and 8082 for the redirect) should be reachable. The database and `web` ports are bound to `127.0.0.1`; leave them that way.
- **Turn on two-step sign-in** for the admin accounts ([TENANCY.md](TENANCY.md)) and set an IP allowlist under **Settings** if the users come from known addresses (not behind a CDN, see above).
- **Sentinels call the public name.** A Sentinel you enroll gets `https://` plus `DOMAIN_NAME` as its server address, so that name must resolve and answer on 443 from the machine the Sentinel runs on (an internal network included). Enroll Sentinels after you settle the name, because the address is fixed in the enrollment ([AGENT-API.md](AGENT-API.md#sentinels-scan-stage-agents)).
- **Back up** the database, and `.env` with `web/secret`, in different places ([DEPLOYMENT.md](DEPLOYMENT.md#backups)). A restored database needs the same keys, but a dump kept next to them is readable by anyone who can read the backup.
- **Plain `http://` goes nowhere on port 80.** The redirect to HTTPS lives on 8082, so type or bookmark `https://`, or forward port 80 to 8082 in your firewall if you want `http://` links to work.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| **400 Bad Request** on every page | The name in the address bar is not `DOMAIN_NAME` or in `CVENGINE_ALLOWED_HOSTS`. Fix `.env`, then `make up`. |
| **CSRF verification failed** on sign-in | The page is reached by an address other than the bundled proxy's own (a CDN rule, a second name). Add its `https://` origin to `CVENGINE_CSRF_TRUSTED_ORIGINS`. |
| Browser still warns about the certificate | The proxy is still serving the private certificate. Check the files in `secrets/certs/` and recreate the proxy (`docker compose up -d --force-recreate proxy`). |
| Handshake fails, `ssl_error_no_cypher_overlap` or `sslv3 alert handshake failure` | The key is ECDSA. Request an RSA certificate (`--key-type rsa`). |
| Cloudflare error 525 or 526 | Origin certificate missing, expired, or not valid for the name; with **Full (strict)** it must be one Cloudflare accepts. |
| Works, then fails after about 90 days | Renewal did not copy the new files. Run `sudo certbot renew --dry-run` and check the deploy hook. |
