# Deployment

cvENGINE is one Docker Compose deployment: `db`, `redis`, `web`, `celery`, `celery-beat`, and `proxy` ([ARCHITECTURE.md](ARCHITECTURE.md)). Two optional parts ship in the same file as Compose profiles and are **off by default**: a `tailscale` service ([TAILSCALE.md](TAILSCALE.md)) and the OpenVAS add-on, 15 Greenbone containers on a network of their own ([OPENVAS.md](OPENVAS.md)). Until you switch one on, none of its containers exist, run, publish a port or use memory. Sentinels, the scanner agents you run on other machines, are not part of this stack: each runs from its own repository and calls this server over HTTPS on 443. The [install steps](#install) are below. Size the server for your scans: 4 GB of RAM is the least (the installer warns below that) and 8 GB is comfortable, and heavy jobs queue by memory use ([CONFIGURATION.md](CONFIGURATION.md#memory-and-workers)). Images build for amd64 and arm64.

## Ports

| Port | Bound to | Service |
| --- | --- | --- |
| 443 | all interfaces | `proxy`, the HTTPS front door |
| 8082 | all interfaces | `proxy`, redirects to HTTPS |
| 8000 | `127.0.0.1` | `web`, for your own reverse proxy |
| 5432 | `127.0.0.1` | `db` |

Firewall 443 and 8082 to the people who need them. The development stack has no proxy and publishes 8000 and 5432 on `127.0.0.1` only. The optional `tailscale` and `openvas` profiles publish no ports at all.

## Install

On a Linux server (Debian or Ubuntu is easiest; 4 GB of RAM at the least and 8 GB for comfort, and 20 GB of free disk):

```bash
git clone https://github.com/hevnsnt/CVEngine.git
cd CVEngine
sudo ./install.sh
```

It asks nothing. It checks the machine, installs what is missing, generates every secret, detects the address to use, creates the HTTPS certificate, builds and starts cvENGINE (the first build takes several minutes), waits until it answers, and prints the address, your username, and a generated password. Copy the password from the terminal: it is shown once, and you choose your own at your first sign-in. If you lose it, `make admin-password` prints a new one for the `admin` account (use `sudo` if the installer ran as root). To use a name instead of the detected address, run `sudo ./install.sh --domain scanner.example.com`.

**First sign-in.** Open the printed address. Browsers warn about the private certificate authority until you trust `secrets/certs/ca.crt` (copy it from the server to the computer whose browser you use). After you choose your own password, the setup wizard (superusers only) creates your organization and project, offers an optional AI model (paste an Anthropic, OpenAI, or OpenRouter key; set up Ollama or vLLM later in Settings), adds your first target if you confirm you are authorized to test it (discovery starts the moment you add it), and offers optional Shodan, VirusTotal, and SecurityTrails keys. The CVE feed starts loading about a minute after the workers come up.

**Step by step.** To run the steps yourself (any Linux with [Docker Engine](https://docs.docker.com/engine/install/), the Compose plugin, `git`, `make`, and `python3`, in a `git clone`, not a release archive):

```bash
./scripts/init-env.sh    # creates .env: generates its passwords and sets DOMAIN_NAME to this machine's address
make certs               # HTTPS certificate for the built-in proxy
make up                  # build and start
# wait until https://<your address>/ answers (follow it with: make logs), then:
make admin               # create your admin account: its password is generated and printed once
```

To choose the password yourself instead, put it in `DJANGO_SUPERUSER_PASSWORD` in `.env` before `make up`, or run `make username`. To serve it on the Internet under a real name with a trusted certificate, see [HOSTING-ONLINE.md](HOSTING-ONLINE.md).

## Linux, Mac, and Windows

`install.sh` asks nothing. It checks that this is Linux, that it is root (it re-runs itself through `sudo`), the architecture, memory (it warns below about 3.5 GB), free disk on the checkout's filesystem (it warns below about 14 GiB), that ports 443 and 8082 are free (it stops if not), and whether Docker's registry and GitHub answer (it only warns). On Debian and Ubuntu it installs curl, make, python3, git, openssl, and the Compose plugin with `apt`. Docker comes from `get.docker.com` on any distribution that script supports. On other Linux it stops at the first missing one of those tools and names it, so install them and run it again, or follow the README steps. It needs Compose 2.24 or newer and stops, naming the requirement, when the installed one is older. When a step fails it prints the last 25 log lines of `web`, `proxy`, and `db`. It also installs the update watcher into root's crontab, so the Approve button works straight away (it only warns when `crontab` is missing, and skips it when automatic deployment is installed).

Running it again keeps `.env`, the certificate (unless the address changed), and your data, then rebuilds and restarts from the code in your checkout. It does not fetch new code or wait for scans ([UPDATES.md](UPDATES.md)). `make admin` then says the account already exists and changes nothing.

On macOS or Windows, install Docker Desktop (with the WSL 2 backend on Windows), clone the repository, and run the README steps from a shell where `make` works, such as the macOS terminal or a WSL 2 distribution. Without `make`, the commands are plain Compose calls:

```bash
./scripts/init-env.sh
docker compose -f docker-compose.setup.yml run --rm certs
docker compose up -d --build
# wait until web has finished migrating (docker compose logs -f web), then:
docker compose exec -T web python3 manage.py create_admin
```

`.env` must exist first, because the database will not start with an empty password. A plain `docker compose up` does not record the installed commit for the updater, so the in-app update check shows it as unknown (`make up` records it). It also does not install the update watcher: run `sudo scripts/install-updater.sh` once so the Approve button works.

Give Docker Desktop at least the memory recommended above.

Docker Desktop is fine for trying cvENGINE and for scanning the public internet, with one limit: nmap's operating system detection cannot work from it. See [Operating system detection and the scan path](#operating-system-detection-and-the-scan-path) below.

## Operating system detection and the scan path

nmap finds a host's operating system from how it answers sixteen crafted probes, some malformed on purpose (a segment with FIN, PSH and URG set, a segment to a closed port with an odd option layout). That only works if the probes arrive as sent and the answers return as sent. nmap's own guide says so: "NAT gateways, firewalls, and especially port forwarding can confuse OS detection", and the cure it gives is to scan "from the same network segment" as the target. The scanners run in the `celery` container, so what matters is the network path that container has. Two paths damage it.

**Docker's default bridge network (Linux).** Every connection is translated with iptables and conntrack. A probe with an impossible flag combination is marked `INVALID` by conntrack, is not translated, leaves with the container's private address, and its answer has nowhere to go. Measured here with real Docker (Engine 29.9.2, nmap 7.94, one Linux target, the same scan from each path):

| Path of the scanning container | Top guess | `T7` probe (FIN+PSH+URG) | Distance |
| --- | --- | --- | --- |
| Default bridge network | Linux 5.3 - 5.4 (94%), then HP P2000 G3 NAS device (93%) | lost | 2 hops |
| `network_mode: host` | Linux 5.3 - 5.4 (97%) | answered | 1 hop |
| macvlan (its own address on the LAN) | Linux 5.3 - 5.4 (97%) | answered | 1 hop |

The guess is only a little worse on a good day, and wrong on a bad one (the NAS ranked first in other runs). The same loss breaks nmap's `-sN`, `-sF` and `-sX` scans.

**Docker Desktop (macOS, Windows).** The container's traffic never reaches the target: Docker's user-space stack (`vpnkit`, now `com.docker.backend`) creates a virtual TCP/IP stack for each remote address, sees the SYN, makes the real connection from the host, and answers the container itself ("How Docker Desktop Networking Works Under the Hood"). Open ports, services and banners are right, because the real connection is made. Every operating system guess describes that stack: one install saw "Google Fuchsia" on an Ubuntu server and a NAS, and an Apple OS X release on a Dell iDRAC. No Docker network setting changes this. Docker's documentation says macvlan "is not supported on Docker Desktop for Mac or Windows", and that Desktop's host networking "works on layer 4": protocols below TCP and UDP are not supported.

### What cvENGINE does about it

- It **measures the path**. Once a day, from the scanning container, `check_os_path` sends a plain SYN and the FIN+PSH+URG probe to a closed port of up to eight hosts the scans already reach (each on a different /16, using the closed port nmap itself found), and notes whether each drew a reset. A path that answers the plain probe and loses the odd one on most hosts is a translating path. Run in the three containers above it said `interfering` on the default bridge and `direct` on host networking and on macvlan. It sends two packets to a host nmap already sends the same probe to. It needs at least three hosts on three different /16 networks that the scans fingerprinted lately, so a lab that is one LAN never gets a verdict and detection fails open: guesses are believed unless the VM kernel is recognised.
- It **recognises Docker Desktop** from the VM kernel (`linuxkit` on macOS, `microsoft-standard-WSL2` on Windows, OrbStack; also `moby` and `boot2docker`, the kernels of the early Docker for Mac and of docker-machine), which no probe can tell apart. A VM that runs an ordinary distribution kernel (Colima, Podman machine, Rancher Desktop on macOS) has no name to recognise; there only the daily measurement can tell, or `CVENGINE_OS_DETECTION=distrust`.
- When either is true, a packet-based guess made by this server's scanner is **not stored and not given to the AI**, and guesses stored earlier are removed. A guess a Sentinel measured on its own network (stored with `os_source` set to `sentinel`) is kept and given to the AI: it did not cross this path. A Sentinel guess stored by an earlier version has no such mark until the host's next Sentinel scan, and is treated as a local one until then. The host still gets an operating system from what survives any path, because a full TCP connection does cross it: the distribution in an SSH or HTTP banner, the operating system CPE and `ostype` from service detection, and the Windows build from SMB and RDP. It is marked as service detection and not as a packet measurement. A host whose services say nothing about the system has none.
- `get_system_status` (and the status page) report it under `os_detection`: whether guesses are believed, why not, the measurement, and what to do.
- `CVENGINE_OS_DETECTION` overrides everything: `trust` believes the guesses anyway, `distrust` never does.

### Getting packet-based detection back

Take the translation out of the scanner's path.

- **Linux host or VPS (the usual install):** use one of the two overlays. Both were run for real, with the results above.
  - `docker-compose.hostnet.yml` puts the `celery` container on the host's network (`docker compose -f docker-compose.yml -f docker-compose.hostnet.yml up -d`). Redis is published on the host's loopback for it (`CVENGINE_REDIS_HOST_PORT`, default 6379) and PostgreSQL already is. Do not combine it with the `tailscale` profile, which joins the celery container's network namespace: run Tailscale on the host instead. Needs Docker Compose 2.24 or later.
  - `docker-compose.macvlan.yml` gives `celery` its own address on your LAN, with the bridge network kept for Redis and PostgreSQL (set `CVENGINE_SCANNER_IP`, `CVENGINE_SCANNER_SUBNET`, `CVENGINE_SCANNER_GATEWAY` and `CVENGINE_SCANNER_PARENT` in `.env`). Needs Docker Engine 28 or later (`gw_priority`). The switch port must accept more than one MAC address; Wi-Fi access points usually do not, so use `ipvlan` in layer 2 mode there. A macvlan container cannot reach the Docker host itself (a kernel restriction).
  - Rootless Docker and Podman use a user-space network stack and behave like Docker Desktop.
- **macOS and Windows:** Docker Desktop cannot send these probes at any setting. The options that hold up are a [Sentinel](SENTINELS.md) on a Linux machine or VM on the network to be measured (it runs with host networking, and a Sentinel on Docker Desktop reports `os_reliable: false`), or running the whole stack on a Linux machine. A Linux VM with a bridged network adapter running Docker Engine should work (Lima's `socket_vmnet` bridged mode gives the VM an address from the LAN's own DHCP server; Colima has a bridged mode too), but that was not run here, and a Wi-Fi interface is a poor bridge target because access points refuse extra MAC addresses: use Ethernet.
- Commercial scanners say the same: Tenable "does not recommend deploying Tenable Nessus behind a NAT device unless it is scanning the internal network", and runZero asks for host networking and a native explorer.

## HTTPS

`make certs` creates a private certificate authority and a certificate in `secrets/certs/` for `DOMAIN_NAME` (a hostname or an IP address), `localhost`, `127.0.0.1`, and anything in `CERT_EXTRA_SANS`. `install.sh` runs it only when the certificate is missing or does not match the address. Run it before `make up`, and again after changing `DOMAIN_NAME` or `CERT_EXTRA_SANS`. It is safe to run again at any time: it issues a certificate only when one is needed (none yet, the names changed, fewer than 30 days left, or an older 10-year one), and `CERT_FORCE=1 make certs` issues one regardless. The built-in proxy serves HTTPS (TLS 1.2 and 1.3, HTTP/2) on 443 and redirects plain HTTP on 8082 to it. It accepts request bodies up to 4 MB. Browsers warn until you trust `secrets/certs/ca.crt`, which you copy from the server.

The files in `secrets/certs/` are `ca.crt`, `ca.key`, `ca.srl`, `rengine.pem`, `rengine_chain.pem`, and `rengine_rsa.key`. Both certificates use RSA 4096. The authority is valid for 3,650 days; the server certificate for **397 days** (browsers refuse a longer one). A new authority's key is encrypted with `AUTHORITY_PASSWORD`. A new server certificate reuses the server key, the authority and the names, so browsers that trust `ca.crt` keep trusting it and nothing has to be copied again. An authority made by an older version keeps an unencrypted key until you delete `ca.key` and `ca.crt` and run `make certs` again, after which browsers need the new `ca.crt`.

**Renewal is automatic.** `scripts/renew-certs.sh` runs the same certs service twice a day and issues a new certificate when fewer than 30 days remain, so there is no expiry day and no browser warning window. It is started by the update watcher (`scripts/install-updater.sh`, which `install.sh` sets up: a cron entry that runs every minute, and the script does nothing until its next check is due), by the automatic-deployment timer, and just before an update recreates the proxy, so any of them is enough. A new certificate is written over the old files in place, and the proxy is told to reload (`nginx -s reload`: no restart, no dropped connection; if the reload fails it recreates the proxy once). The authority and its password are never touched. A certificate someone else issued (Let's Encrypt, a Cloudflare origin certificate, see [HOSTING-ONLINE.md](HOSTING-ONLINE.md)) is never replaced by this: it is reported as not renewed here, and renewing it stays with its issuer.

An install made before this release holds a 10-year server certificate: it is replaced once, by the first check after the update (same key, same authority, same names), with 397 days. The first check runs within minutes of the watcher's next cron tick.

**Seeing it.** **Settings > Updates** shows how many days the certificate has left and turns into a warning when a renewal failed, fewer than 30 days remain, it has expired, or no check has run for days. `get_system_status` (`GET system/status`, App Admin) reports the same under `system.certificate` (`not_after`, `days_left`, `state`, when it was last checked and renewed, the last error) and adds a line to `problems` when something needs attention. Nothing is shown on an install that does not report (no cron and no update): run `scripts/renew-certs.sh` yourself to check and publish once. The script's log is `cert.log` in `.git/cvengine-update` (and `.git/cvengine-auto-deploy` for the timer). `CVENGINE_CERT_CHECK_SECONDS` (default 43200) and `CVENGINE_CERT_RETRY_SECONDS` (default 3600, the wait after a failure) change the schedule.

For a public site with a browser-trusted certificate (Let's Encrypt, Cloudflare), follow [HOSTING-ONLINE.md](HOSTING-ONLINE.md).

To use your own proxy or CDN, point it at the web service (`127.0.0.1:8000` on the host) and have it set `X-Forwarded-Proto` and `X-Forwarded-For`, replacing any values from the client. Then add `CVENGINE_CSRF_TRUSTED_ORIGINS` (your https address) to `.env` and run `make up`.

**Client addresses.** The IP allowlist and the abuse guard need the real client address. CVEngine reads it from `X-Forwarded-For`, but only when the peer connecting to the web container is listed in `CVENGINE_TRUSTED_PROXIES`. That setting names the addresses the web container sees *connecting to it*, not your proxy's public or LAN address. A proxy on the Docker host reaches the container through the Docker bridge gateway, which the default `172.16.0.0/12` already covers, so for a proxy on the same host you set nothing. Do not replace the default with your proxy's own network: the gateway is then untrusted, `X-Forwarded-For` is ignored, and every request appears to come from the gateway. If you need to trust more, add to the default (`172.16.0.0/12,203.0.113.0/24`): the address the container sees if your proxy does not arrive through the bridge, and the networks of any further hops (a CDN edge) that append to `X-Forwarded-For` instead of replacing it. Your outermost proxy must overwrite any `X-Forwarded-For` the client sent.

Django sends an HSTS header with a one-hour lifetime by default and does not include subdomains or ask for preloading. Raise `CVENGINE_HSTS_SECONDS` only once your public TLS path is reliable.

## AI models

cvENGINE runs no model itself. In **Settings, AI model**, choose Anthropic, OpenAI, OpenRouter, [Ollama](https://github.com/ollama/ollama), [vLLM](https://github.com/vllm-project/vllm), or [LM Studio](https://lmstudio.ai). For Ollama, vLLM and LM Studio enter your server's **Base URL**, press **Load models**, choose one, tick **Use this model to confirm CVE matches**, and **Save**.

**Base URL for every provider.** Anthropic and OpenAI have one too, optional and empty by default (the vendor's own address): set it for a gateway or proxy such as LiteLLM, which then receives the key you type. For Anthropic a bare address (`https://gateway.example`, or one ending in `/v1`) is the server and the messages endpoint is under it; an address with any other path is used as written. A key is stored for one provider at one host: changing the provider or the host (the vendor's own address counts as a host) clears the stored key, and you type it again for the new service. **A key is never guessed onto a vendor.** On first-run setup a key is recognised only by a prefix that names one vendor (`sk-ant-` Anthropic, `sk-or-` OpenRouter, `sk-proj-` OpenAI); a bare `sk-...` key is issued by several vendors (DeepSeek and others), so you choose the provider and nothing is sent until you do.

**Reasoning.** `CVENGINE_AI_REASONING` (`off`, `low`, `medium`, `high`, `max`; unset sends nothing) turns on a model's reasoning in the way its provider takes it: `reasoning_effort` for OpenAI's o-series and gpt-5 models, adaptive thinking and an effort for Claude 4.6 and later (`budget_tokens` for Claude 3.7 to 4.5), `think` for Ollama. It is not sent to vLLM, LM Studio or OpenRouter: set reasoning on the server. See [Configuration](CONFIGURATION.md#ai-requests) for each mapping, and raise `CVENGINE_AI_MAX_TOKENS` with it, because thinking is paid from the reply limit.

- **A remote machine**, the usual case on a VPS: use any address the server can reach, such as a Tailscale `100.x` address (`http://100.64.0.5:11434`). MagicDNS names do not resolve inside containers. Keep the port on your tailnet or behind a firewall, since Ollama has no authentication.
- **The same machine**: enter `http://localhost:11434`. cvENGINE maps `localhost`, `127.0.0.1`, and `::1` to the Docker host. Ollama must then listen beyond 127.0.0.1 (for example `OLLAMA_HOST=0.0.0.0`) while staying firewalled.
- **vLLM** works the same way with its `/v1` URL, such as `http://100.64.0.5:8000/v1`. An API key is optional.
- **LM Studio** serves an OpenAI-compatible API on port 1234: use `http://100.64.0.5:1234/v1` (or `http://localhost:1234/v1` on the same machine). Start the server in LM Studio's Developer tab, or headless with `lms server start` (or the `llmster` daemon). LM Studio listens on localhost only until you switch on serving on the local network in its server settings, and a server reached over a tailnet or network should have authentication on: LM Studio 0.4 and later can require an API token (Server Settings, Manage Tokens), which you enter here as the **API key**. Leave the key blank when authentication is off. With just-in-time loading on (the default), **Load models** lists every model you have downloaded, embedding models excluded, and the first request for a model loads it, which can take a minute or more for a large one (cvENGINE waits up to five minutes). With it off, only models you have already loaded are listed. Screenshot reading needs a vision model.

### Local models

Everything below is what the code does with a model on your own server (Ollama, vLLM, LM Studio); for any other OpenAI-compatible server (llama.cpp's `llama-server`, LiteLLM, a gateway) choose the **vLLM** provider and give its address. Only Ollama, vLLM and LM Studio are treated as self-hosted: they get the default reply limit, and a triage gets temperature 0, a fixed seed and a JSON Schema. The **OpenAI** provider with another Base URL is sent only what the operator set, because a proxy in front of OpenAI may front a hosted reasoning model that refuses a temperature.

- **Context size.** A finding triage sends about 7,000 characters of instructions and evidence (roughly 2,000 tokens, counted at four characters to a token) and asks for at most 400 back, so 4096 tokens of context is the least that works and 8192 is comfortable. The other stages (CVE detection records, template writing, the validation plan, Nuclei targeting with up to 150 offered tags, the three-hour review) send longer prompts that were not measured here: give them 16k or more. Ollama sizes its window by the machine's memory (4k tokens under 24 GiB) and cuts a longer prompt at its start without an error: set `CVENGINE_OLLAMA_NUM_CTX`, and cvENGINE logs a warning when a prompt used 95% of it. vLLM takes `--max-model-len`, LM Studio the model's context length setting.
- **Reasoning off.** cvENGINE sends no switch for reasoning unless you set `CVENGINE_AI_REASONING`, and then only to Ollama (`think`, for qwen3, deepseek-r1, gpt-oss and magistral models); vLLM and LM Studio never get one: turn reasoning off in the server or the model's settings, or pick a model without it. A reasoning model spends its reply limit thinking (its `<think>` block is dropped before the answer is read, but it counts against the limit), and a limit of 400 or 2048 ends before the answer. If you want to keep it, raise `CVENGINE_AI_MAX_TOKENS` (the value replaces the defaults, the triage's too).
- **JSON output.** A triage request carries the triage's JSON Schema (`response_format` to vLLM and LM Studio, `format` to Ollama), and the reply is validated whatever the server did. A server that refuses the schema is asked in JSON mode and then plainly, and remembered for an hour (`CVENGINE_AI_STRUCTURED=off` never sends it). The other stages ask for JSON in the prompt and take the last object in the reply.
- **Limits.** `CVENGINE_AI_MAX_TOKENS` (default 2048, 400 for a triage), `CVENGINE_AI_TIMEOUT` (default 120 seconds, 300 for LM Studio, which may load a model on the first request), `CVENGINE_AI_CONNECT_TIMEOUT` (10 seconds), `CVENGINE_OLLAMA_NUM_CTX`, `CVENGINE_AI_STRUCTURED`. See [Configuration](CONFIGURATION.md).
- **When a reply is cut off.** A triage that hit its limit (the server said `length`) is asked once more with twice the limit (800, or twice yours up to 32768). If that is cut off too, the call fails with the category `output_truncated`, the finding is not triaged by that attempt, and the failure is recorded with the AI usage of that stage. A reply with no text at all is `empty_response`. The other stages do not retry: the call fails and the stage carries on as it does for any model error.

## Scan more targets at once

cvENGINE scans as much as the machine can hold without running out of memory, and by default that is not much: a handful of scanners at a time, and a few discovery scans in flight. On a small machine that is right. On a bigger one, or when you watch the queue and only one or two targets move at a time, you can allow more.

**Where.** Sign in as an App Admin, open **Settings**, then **configMaxxing** (collapsed in the left column until you click it; the address is `/cve/settings/#configmaxxing`), then **Scan concurrency**. Each number shows its default, the environment variable behind it if you set one, and who changed it and when; **Reset to default** puts one back, and **Reset all configMaxxing settings to defaults** puts everything back. No restart is needed for the scanner limits and the discovery scans kept running; they apply within seconds. The number of hosts assessed at once is the ceiling of the discovery worker's autoscaler: the page resizes the running worker and shows the ceiling the worker reports (the worker may briefly run a few more than the ceiling, it is not an exact cap), and if the worker does not confirm the change it says so and the number takes effect after the next restart or update.

**What the numbers mean.**

- **Scanners at once** (one number for each of nmap, nuclei, bbot, naabu and the others): how many runs of that kind are allowed together in the scanning container. More runs of a kind finish more targets sooner, and use more CPU and memory.
- **Hosts assessed at once** (`DISCOVERY_CONCURRENCY`): how many discovery tasks and host assessments run together. Each assessment works through one host from start to finish, so this is the number of hosts being assessed at one time. Most of an assessment is waiting (on a scanner's turn, or on a Sentinel), so this can be higher than the number of CPUs.
- **Hosts per assessment batch** (`CVENGINE_ASSESS_BATCH`): how many hosts of one target are carried through one assessment run together, so a Sentinel is handed a batch instead of one host at a time. It only matters where a Sentinel covers the project; leave it at 8 unless a Sentinel sits idle with hosts waiting.
- **Discovery scans kept running** (`CVENGINE_WORK_DEPTH`): how many scans of whole targets the work conductor keeps going or queued. Raise it when you have many targets and the scanners are not busy; `0` stops cvENGINE from starting scans on its own.

**The memory gate still applies.** Whatever you choose, a scanner starts only when its memory estimate fits the scanning container's budget (75% of `CELERY_MEM_LIMIT`), so raising a number past what the machine can carry makes runs wait for memory; it does not make the machine run out. The page shows the container's budget and warns when your choices could want much more than it. If the warning appears, give the container more memory (`CELERY_MEM_LIMIT` in `.env`, then `make up`) before you raise the numbers further.

**Safe starting values.** Change a few numbers, watch **Settings, Resources** for a day (the memory used, anything waiting for memory, anything stopped for memory), then go on. The AI review every three hours may lower a number when memory is short and raise it again, but never above the number you saved.

| Machine | `CELERY_MEM_LIMIT` | nmap | nuclei, nuclei light | bbot standard, passive | bbot deep | hosts assessed at once | discovery scans kept running |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 4 vCPU, 8 GB | `4g` (the default) | 2 (default) to 3 | 1 | 2 | 1 | 8 (default) | 3 (default) to 4 |
| 8 vCPU, 16 GB | `8g` | 4 | 2 | 3 | 1 | 12 | 6 |
| 16 vCPU, 32 GB | `16g` | 6 | 3 | 4 | 2 | 16 | 10 |

Leave the other scanner kinds at their defaults unless a particular queue is the one that is slow. The slow background sweeps (`nmap-full-bg`, `nmap-udp-bg`) are meant to wait behind everything else, and a higher number sends more probes at the same address.

**More concurrency sends more traffic to your targets.** Ten nmap scans at once are ten times the packets. Check that the networks and the devices you scan can take it (small routers and printers often cannot), and that your scope allows it.

**The best way to scale is a second machine.** A Sentinel scans from its own machine with its own CPU, memory and network path, takes work from this server and reports back, so it adds capacity instead of squeezing more out of one container. Add one before you push the numbers on a single server far above the table ([Sentinels](SENTINELS.md)).

## Backups

Back up the database, `.env` and the secret file, but keep the keys apart from the dump. The dump holds the database only: scan result files (screenshots and raw output) live in the `scan_results` Docker volume, and the optional add-ons keep their state in volumes of their own (`tailscale_state` and the `openvas_*` volumes), so none of those are in it. `web/secret` also keys the hashes of the session table and the recovery codes, so a restore without it signs everyone out and breaks new recovery codes. Stored secrets are encrypted with `CVENGINE_FIELD_KEY` from `.env` (older values with a key derived from `web/secret`), so a restored database needs the same keys. A dump stored in the same archive, bucket or folder as those keys gives away every stored API key, webhook URL and two-step seed to anyone who can read that place, which is exactly what the encryption is there to prevent: put `.env` and `web/secret` in a password manager or another store with different access, and the database dumps wherever backups normally go. Keep every copy private (mode 0600).

```bash
docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' | gzip > cvengine-$(date +%F).sql.gz
cp web/secret cvengine-secret.bak
```

To restore, put the original `.env` (with `CVENGINE_FIELD_KEY`) and `web/secret` in place, start only the database (`docker compose up -d db`), load the dump, then start everything with `make up`:

```bash
gunzip -c cvengine-2026-01-01.sql.gz | docker compose exec -T db sh -c 'psql -U "$POSTGRES_USER" "$POSTGRES_DB"'
```

Every updater takes a database dump just before it migrates (`scripts/update.sh` and the in-app updater keep the last 3 in `.git/cvengine-update/backups`, mode 0700, and stop the update when a dump fails; `CVENGINE_UPDATE_BACKUPS=0` in `.env` turns that off; automatic deployment makes its own in `.git/cvengine-auto-deploy/backups`, [UPDATES.md](UPDATES.md#automatic-deployment)). These dumps stay on the same disk as the database: copy them elsewhere if the disk is what you are protecting against.

## Make targets

`make help` lists them. They all use `docker-compose.yml` alone, and the ones that name services (`stop`, `restart`, `rm`, `logs`, `images`, `build`, `up`) act on the six core services only.

| Target | What it does |
| --- | --- |
| `make up` | Creates `.env` if it is missing, clears a leftover maintenance flag, moves a PostgreSQL 12 database to 18 ([UPGRADE.md](UPGRADE.md)), records the installed commit, then builds and starts the six core services. |
| `make build` | Records the installed commit and builds the images. |
| `make certs` | Creates the HTTPS certificate ([HTTPS](#https)). Refuses while the database or certificate password still says `change-me`. |
| `make admin`, `make admin-password` | Create the admin account with a generated password, or reset that account's password and print a new one. |
| `make username`, `make changepassword` | Create an admin account of your own choosing, or change a user's password. |
| `make migrate` | Applies migrations. |
| `make down`, `make stop`, `make restart`, `make rm` | Take the stack down, stop, restart or remove its containers. Volumes stay. |
| `make logs`, `make images` | Follow the logs (last 1000 lines), or show the images. |
| `make test` | Runs the test suite in the running `celery` container. |
| `make redis-auth`, `make rotate-field-key` | One-time hardening of an older install ([CONFIGURATION.md](CONFIGURATION.md#templates-and-secrets), [UPGRADE.md](UPGRADE.md#upgrading-to-12)). |
| `make openvas-up`, `make openvas-user`, `make openvas-down` | Start the optional OpenVAS add-on, save its generated login, stop it. The app does the same from Administration, OpenVAS ([OPENVAS.md](OPENVAS.md)). |
| `make export-cve-seed` | Writes this instance's CVE catalog to `web/cve-seed.jsonl.gz` ([PIPELINE.md](PIPELINE.md#seeding-the-catalog)). |
| `make inventory-sync` | Copies the host inventory reporter scripts to the copies the server hands out (a development task). |

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

Three options, all of which keep the database and broker running: automatic deployment, approval in the app, or `scripts/update.sh` by hand. Manual updates wait for active tasks (or stop scans with `--stop-scans`), automatic deployment stops and requeues scans, and an approved update waits for running scans for 5 minutes by default and then interrupts what is left. The optional `tailscale` and `openvas` services are neither started nor stopped by an update. See [UPDATES.md](UPDATES.md). `make up` always uses `docker-compose.yml` alone, so on an install with its own overlay use `scripts/update.sh` or `docker compose` with your files instead. Moving an older install across the PostgreSQL 18 change is covered in [UPGRADE.md](UPGRADE.md). Every start of the worker container adds the built-in engine rows, keywords and tool rows the install does not have yet and never overwrites one that is there (the engine rows are kept only so that existing agents keep working: no scan reads them).

## Factory reset

**Settings, Factory reset** (superusers only) returns the instance to a fresh install and restarts the setup wizard. It recreates a "Default" organization and project, ends every other session (yours stays), and records one `system.factory_reset` audit row after clearing the log. Five wrong passwords lock the button for 10 minutes. It removes every organization, project, target, host, scan, result file, other user, token (so every Sentinel is removed with its token and has to be enrolled again), and setting, plus the CVE feed, the audit log, and scheduled scans. It keeps your own account, the scan engines, and installed tools. You must type `FACTORY RESET` and your password, and it refuses while scans are running unless you tick "reset anyway". It cannot be undone, so take a backup first.

## Uninstall

`scripts/uninstall.sh` lists the containers, volumes, and networks of this install's Compose project (named by `CVENGINE_COMPOSE_PROJECT`, then `COMPOSE_PROJECT_NAME`, then the checkout directory) and, once you type yes, deletes them and their locally built images. That includes all scan results. Other applications, including other reNgine installs, are not touched. `.env`, `secrets/`, `web/secret`, and `backups/` stay, and so do the update watcher and the automatic-deployment timer: run `sudo scripts/install-updater.sh --remove` and `sudo scripts/install-auto-deploy.sh --remove` first. It needs access to Docker, not necessarily `sudo`.

See also: [CONFIGURATION.md](CONFIGURATION.md), [documentation index](README.md).
