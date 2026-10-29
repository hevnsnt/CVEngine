# Hosting cvENGINE online

How to put an install on the Internet under a real name (for example `scanner.example.com`) with a certificate browsers trust. The installer's own certificate comes from a private authority, so every browser warns until it is trusted; that is fine on a LAN and wrong for a public site.

You need a server that already runs cvENGINE ([install steps](DEPLOYMENT.md#install)), a domain you control, and the ability to open ports on the server's firewall.

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
- Static files are versioned by content and sent with `Cache-Control: no-cache`, so Cloudflare cannot serve one release's stylesheet with another release's pages. You do not need to purge the cache after an update.
- A scan of your own CDN-fronted name finds the CDN, not your server.

### C. Your own reverse proxy

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
