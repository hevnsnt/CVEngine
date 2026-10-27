# Host inventory: let a host tell cvENGINE what it is

cvENGINE scans from outside. It can see a banner that says `OpenSSH 8.9`, but not the exact operating system build, the kernel, the packages
installed, the patches applied, or what listens only on a private address. So it never matches a **local-only** CVE (a kernel or Win32k
privilege escalation, a local file-parsing bug) to a host, and it cannot tell a patched backport from a vulnerable package.

A **host inventory report** fixes that from the inside. A small script runs on the machine (Linux, macOS, Windows), reads what the operating
system knows about itself, and posts it to cvENGINE over HTTPS. cvENGINE keeps the latest report per machine, ties it to the host it already
scans, puts the exact operating system on the host page, and checks the reported packages and build against the CVEs, including the local-only
ones that an outside scan can never decide.

Nothing here changes a host. The scripts only read.

## Quick start

1. Open **Hosts**, then **Host inventory** (or **Agent access**, then **Set up host reporting**). Pick the platform.
2. **Create a reporter token.** It belongs to one project and can only post that project's inventory reports (see [Safety](#safety)).
3. Copy the command for the platform and run it on the machine (as root or Administrator for the fullest report). The dialog fills in your
   server address and the project. The command asks for the token (paste it when it asks): **no command contains the token**, so it never
   lands in shell history or the process list. Run the script once with `--dry-run` first to read exactly what would be sent.

Linux and macOS:

```sh
(umask 077; cat > cvengine-inventory.token) \
  && curl -fsS --cacert ca.crt https://cvengine.example.test/staticfiles/cve/inventory/cvengine-inventory.sh -o cvengine-inventory.sh \
  && sh cvengine-inventory.sh --server https://cvengine.example.test --project my-project --token-file cvengine-inventory.token --ca-file ca.crt
```

(Paste the token, press Enter, then Ctrl-D. The file is readable only by you; move it to `/etc/cvengine-inventory.token` for scheduled runs.)

Windows (PowerShell 5.1 or 7):

```powershell
$env:CVENGINE_TOKEN = [System.Net.NetworkCredential]::new('', (Read-Host 'Token' -AsSecureString)).Password; Invoke-WebRequest https://cvengine.example.test/staticfiles/cve/inventory/cvengine-inventory.ps1 -OutFile cvengine-inventory.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\cvengine-inventory.ps1 -Server https://cvengine.example.test -Project my-project -CaFile .\ca.crt
```

`ca.crt` is the installer's certificate authority (`secrets/certs/ca.crt` on the server). Leave the option out when the server has a publicly
trusted certificate. A Python 3.6+ script, `cvengine-inventory.py`, reports the same thing on Linux and macOS with the standard library only.

The scripts live in `scripts/inventory/` and are served at `/staticfiles/cve/inventory/` (copies in `web/static/cve/inventory/`; `make
inventory-sync` refreshes them, and a test fails if they differ).

Every script can print, without applying, what it needs to run on a schedule: `--install-cron` (a cron line and a systemd timer) or `-Schedule`
(a scheduled task). A minute derived from the host name and a random delay spread a fleet over the hour.

## What each script collects

Per platform, from the primary documentation of each tool. "Read" means a listing command or a metadata file, never a change.

| | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Operating system | `/etc/os-release` (`ID`, `ID_LIKE`, `NAME`, `VERSION_ID`, `VERSION_CODENAME`, `PRETTY_NAME`, `CPE_NAME`), `uname -r`, `uname -m` | `sw_vers` (name, version, build), `uname` | CIM `Win32_OperatingSystem` and the `CurrentVersion` registry key: caption, release (`DisplayVersion`), build `10.0.<BuildNumber>.<UBR>`, edition |
| Boot and last update | `/proc/stat` `btime`; newest rpm install time, or the package database's modification time | `sysctl kern.boottime` | `LastBootUpTime`; newest installed update date |
| Packages | `dpkg-query -W` (with the source package), `rpm -qa --qf` (epoch, source rpm, install time), `apk list -I`, `pacman -Q`, `snap list`, `flatpak list`, `brew list --versions` | application `Info.plist` versions under `/Applications`, `pkgutil` receipts (not Apple's), `brew` | the `Uninstall` registry keys (HKLM 64 and 32 bit, and each signed-in user's loaded hive) |
| Patches | none (packages carry it) | none | `Get-HotFix` plus the Windows Update Agent's **local** history (`IUpdateSearcher::QueryHistory`, installs minus uninstalls) |
| Listening ports | `ss -tulnp`, else `netstat -tuln` | `lsof -nP -iTCP -sTCP:LISTEN -iUDP` | `Get-NetTCPConnection -State Listen`, `Get-NetUDPEndpoint` (process name only) |
| Services, roles | running systemd services | none | running services; `Get-WindowsFeature` on Server |
| Containers | image names from `docker ps` and `podman ps` | none | none |
| Pending reboot | `/var/run/reboot-required`, `needs-restarting -r` | none | CBS `RebootPending`, Windows Update `RebootRequired`, the Update Agent's `RebootRequired` |
| Installed kernels | `linux-image-*` packages, `rpm -q kernel` | none | none |
| Security posture | firewall (firewalld, ufw, nftables active), SELinux, AppArmor, unattended-upgrades or dnf-automatic, LUKS present, Secure Boot | Application Firewall, SIP, Gatekeeper, FileVault | Defender state and signature age, other antivirus, firewall profiles, BitLocker, Secure Boot, update policy |
| Addresses | `ip -o addr`, else `hostname -I`, `ifconfig` | `ifconfig` | .NET `NetworkInterface` |
| MAC addresses | only with `--macs` / `-IncludeMacs` | same | same |

Choices that are worth knowing:

- **Windows build.** `Get-ComputerInfo` takes several seconds and gathers far more than is needed, so the script reads `Win32_OperatingSystem`
  and the registry instead. The build is `major.minor.build.UBR`; the UBR (update build revision) is what a monthly cumulative update moves, so
  it is the patch level.
- **Windows updates.** `Get-HotFix` is `Win32_QuickFixEngineering`, which "returns only the updates supplied by Component Based Servicing"
  (Microsoft's documentation for the cmdlet), so updates installed by Windows Update or MSI are missing from it. The script adds the Windows
  Update Agent's local history database and applies uninstalls. It does **not** ask Windows Update or WSUS which updates are pending.
- **Windows software.** The `Uninstall` keys cover what `Get-Package`'s Programs provider reads, and `Get-Package` can bootstrap package
  providers, which is a change to the host. It is not used.
- **macOS applications.** The script reads each `Info.plist` instead of `system_profiler SPApplicationsDataType`, which is slow.
- **os-release is read, not sourced.** The file is shell syntax, but sourcing it would run whatever it contains. It is parsed as data.
- **No cloud metadata.** The instance metadata endpoints (169.254.169.254 and friends) are never queried.
- **The machine id** (`/etc/machine-id`, the IOKit platform UUID, the registry `MachineGuid`) is sent only as
  `sha256("cvengine-inventory-v1:" + id)`. systemd's `machine-id(5)` says the raw id "should be considered confidential" and must not be used
  directly by applications, which should hash it with an application-specific key.

**Never collected:** passwords, keys, tokens, certificates, shell or PowerShell history, environment variables, event or system logs, file
contents other than the OS metadata above, user accounts, network shares, browser data, process command lines (a listening socket's process
*name* only).

## Safety

- **Read-only.** Fixed commands that list things; no shell is built from data; nothing is installed, started, stopped or written (the shell
  script writes one temporary file in a private directory and removes it). A test reads the PowerShell script for any cmdlet that changes
  state.
- **The token is never a command-line argument, and never in a command you copy.** Arguments are visible to every user in `ps` and are saved
  in shell history and PowerShell's PSReadLine history; so is `CVENGINE_TOKEN=cve_... sh ...`. The generated commands read the token from the
  keyboard (into a file only you can read, or a secure string); an environment variable (`CVENGINE_TOKEN`) or a root-only file (`--token-file`,
  `-TokenFile`) are how the scripts take it. They refuse `--token`, warn when the token file is readable by other users, refuse a token with
  anything but the characters a token has (a newline would add a setting to curl's configuration), and give `curl` the token on its standard
  input (`-K -`) so it is not in `curl`'s argument list either.
- **TLS is verified by default,** TLS 1.2 or newer, https only (an `http://` server is refused before any token is read). `--ca-file` trusts
  the installer's private authority for this one request (the host name must still match). `--insecure` turns verification off, prints a loud
  warning, and exists for a lab. Redirects are never followed, so the token only goes to the address you gave.
- **A reporter token can only post inventory.** Create it from **Host inventory**, or with `POST /api/v1/tokens` `{name, scope: "inventory",
  project}` from a signed-in session. It is bound to one project and checked before any route or MCP tool runs: the only request it may make is
  `POST /api/v1/projects/<its project>/inventory`. Everything else, including reading inventory and `/mcp/`, is `403`. It still acts as the user
  who created it, so it needs that user to be able to write to the project, and it stops working with that user. It **expires after 365 days**
  (create a new one to renew it; the dialog and the API say when). A token with a scope this code does not know can do nothing at all, and
  `POST /api/v1/tokens` refuses a scope other than `full` or `inventory` (400) instead of minting a full token.
  **What a leaked token can do.** It cannot read anything or touch any other route. Within its one project it can report as machines: it can
  report for any machine that no other token already owns, so it can invent machines (they fill the small unmatched allowance, below), show an
  operating system and packages for a host nobody else reports for (which also raises findings on that host), and, if the project allows
  `create_hosts`, have its own claimed name or its own address added as a target (capped per day). It cannot take over a host that another
  machine reports for, cannot update or close another token's machine, and cannot change any other project's data. Revoke it on **Agent access**.
  A fleet that shares one token trusts every machine holding it with the machines that report by host name only (no machine id); machines that
  send a machine id are told apart by it.
- **A machine belongs to the token that first reported it.** A report for a machine another token owns is a `409`; an administrator deletes
  the report to let another token take it over (a signed-in administrator may update any report). A new machine never takes a host another
  machine's fresh report already speaks for: it is held as unmatched, with the host it wanted shown to the administrator, until the old
  report goes stale or the administrator adopts it. An address alone never moves an established match, and addresses that many machines share
  (container bridges `172.16.0.0/12`, VirtualBox and libvirt NAT, carrier-grade NAT `100.64.0.0/10`) are never used to match a host.
- **Rate and size limits.** At most 12 reports an hour from one machine through one token (a fleet sharing a token is not limited by its size),
  10,000 an hour per token and 20,000 per project over all machines, 2 MiB per report, 15,000 packages, 5,000 machines per project, of which
  at most 500 may be tied to no host (reports nobody adopts are dropped after 30 days; **Delete every unmatched report** or `POST
  .../inventory/delete-unmatched` clears them at once).
- **A report is untrusted data.** A compromised machine can send anything. The server accepts one fixed shape, cleans every string (Unicode
  compatibility-normalised; every character that is not printable is dropped, which is all control characters including the C1 set and its
  terminal escapes, bidirectional and zero-width marks, soft hyphens, word joiners, Unicode tag characters that can hide an instruction from a
  language model, private-use and unassigned characters, and variation selectors; length caps), validates every field with a known form (addresses, hashes, dates, ports), refuses a
  list over its cap rather than cutting it short, drops and counts what does not validate, and stores nothing it did not ask for. Package
  names are shown as text only. A report body is exempt from the request input guard's attack-string scan (a package called `a; rm -rf /` must
  not get its reporter's owner locked out); its schema check replaces that scan, and the address and query string are still scanned.
- **Tenancy.** Everything is scoped to the project. A report is matched only against its own project's hosts; another project's host with the
  same name or address is invisible. Address rows belong to the whole organization, so a report changes only the address rows this project's own
  scans linked to the host it is tied to: an address it merely lists, which belongs to another project's host, is never touched. The ingest
  answer never says which host a report matched, and a refused report says only that it was not accepted (the reason is in the audit log, so a
  token cannot be used to probe which host names the organization excluded).
- **Audit.** The audit log records token creation, a machine's first report, a change of its operating system or of the host it is tied to,
  adoption and deletion (a daily report that changed nothing is not an entry, the report history keeps those).

## The report: inventory v1

JSON, UTF-8, `POST /api/v1/projects/{slug}/inventory`, `Authorization: Bearer <token>`.

```json
{
  "schema": "cvengine-inventory/1",
  "script": {"name": "cvengine-inventory.sh", "version": "1.0.0"},
  "collected_at": "2026-10-27T03:12:00Z",
  "host": {"hostname": "web01", "fqdn": "web01.example.test", "machine_id": "<64 hex: the app-specific hash>", "ips": ["192.0.2.10"], "macs": []},
  "os": {"family": "linux", "id": "ubuntu", "id_like": ["debian"], "name": "Ubuntu", "version": "22.04", "codename": "jammy",
         "pretty": "Ubuntu 22.04.3 LTS", "kernel": "5.15.0-91-generic", "arch": "x86_64", "last_boot": "...", "last_update": "..."},
  "packages": [{"n": "libssl3", "v": "3.0.2-0ubuntu1.10", "e": "dpkg", "a": "amd64", "s": "openssl"}],
  "patches": [{"i": "KB5034441", "t": "2026-01-09", "d": "Security Update"}],
  "services": [{"p": "tcp", "a": "*", "n": 22, "x": "sshd"}],
  "runtime": {"reboot_required": false, "kernels_installed": ["5.15.0-91-generic"], "containers": [{"rt": "docker", "image": "nginx:1.25"}],
              "units": ["ssh.service"], "features": []},
  "security": {"firewall": "ufw active", "selinux": "enforcing"}
}
```

| Field | Rule |
| --- | --- |
| `schema` | must be `cvengine-inventory/1`; another major version is refused with a message to update the server or the script |
| text | every string is normalised and stripped of anything not printable; a package version from `dpkg`, `rpm`, `apk` or `pacman` must look like a version (no spaces), else it is dropped; dates and times take ASCII digits only |
| `host` | at least one of `hostname`, `fqdn`, `machine_id` or a usable address; `ips` up to 64, loopback, link-local, multicast and unspecified dropped; `macs` up to 16 |
| `os.family` | `linux`, `windows` or `macos`; `os.name` is required |
| `packages` | up to 15,000; `e` (ecosystem) one of `dpkg rpm apk pacman snap flatpak brew win macpkg macapp`; `n` up to 200, `v` printable ASCII up to 100; exact duplicates collapse, other versions of one package stay (installed kernels) |
| `patches` | up to 2,000; `i` an id such as `KB5034441`, `t` a date |
| `services` | up to 1,000 listening sockets; `p` `tcp` or `udp`, `n` 1 to 65535, `a` an address or `*` |
| `runtime` | `reboot_required` true, false or null; up to 20 `kernels_installed`, 200 `containers`, 1,000 `units`, 500 `features` |
| `security` | an allowlist of keys (`firewall`, `selinux`, `apparmor`, `auto_updates`, `disk_encryption`, `antivirus`, `antivirus_signature_age_days`, `secure_boot`, `sip`, `gatekeeper`); anything else is dropped |
| body | 2 MiB; nesting at most 8 deep; unknown keys are never stored |

A report over a cap is `413`; a malformed one is `400`. An item that does not validate is dropped and counted (`dropped` in the answer).

The answer is `201` for a machine's first report and `200` after, `{"accepted": true, "outcome": "new|changed|updated", "status":
"matched|created|unmatched", "packages": 812, "dropped": {}, "stale_after_days": 14}`.

### Package normalisation

Each package is stored compactly and normalised when read, in the form of a [package URL](https://github.com/package-url/purl-spec) (purl):
name, version, ecosystem, distribution and release (from `os-release`), architecture and source package.

```
pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?arch=amd64&distro=ubuntu-22.04
pkg:rpm/rhel/curl@7.76.1-26.el9?arch=x86_64&distro=rhel-9.3&epoch=1
pkg:apk/alpine/curl@8.5.0-r0?arch=x86_64&distro=alpine-3.19.1
pkg:generic/7-Zip%2023.01%20%28x64%29@23.01?ecosystem=win
```

`deb`, `rpm` and `apk` follow the registered purl types (vendor as the namespace, `arch` and, for rpm, `epoch` qualifiers; `distro` as in the
examples of the spec). A catalogue that has no registered type (snap, flatpak, Homebrew, Windows and macOS software) is `pkg:generic` with an
`ecosystem` qualifier, so no type is invented. Pacman uses `alpm`, which is not covered by the pages this was checked against and should be
confirmed against the spec before relying on it.

## How a report finds its host

In order, within the report's own project, against the hosts of the current inventory:

1. **Name.** The report's FQDN, then its host name, equals a scanned name.
2. **Address.** A scanned host resolves to the report's addresses (never a CDN address; names on the same addresses are one host, shown under
   the project's own target name). The host with the most addresses in common wins.
3. **Short name.** The host name is the first label of exactly one scanned name.

A host that matches nothing is recorded as **unmatched** and listed in the Host inventory dialog, where an administrator ties it to a host
already scanned, or adds the machine as a target (which starts discovery). The project setting *A report from a host nobody scans yet adds it
as a target* (`inventory.create_hosts`, off by default) does that automatically, with extra checks, because a report only says what the
machine claims to be: the name must be inside a domain the project already has or must resolve to the address the report came from (a machine
reporting by address alone must come from that address), and at most 20 hosts a day are added per project. A name or domain the organization
excluded is refused (the report itself is a `409`, nothing is stored), and an address the scanner refuses (private ranges unless
`CVENGINE_ALLOW_PRIVATE_TARGETS`) leaves the report unmatched. An administrator's own **Add as target** is not held to those checks. A tie made
by hand is kept across later reports.

A host speaks through one fresh report at a time. A second machine that matches the same host is held as unmatched (the dialog shows which
host it wanted) and an administrator decides: adopt it (then the newest report drives the host's CVE matches) or delete it. An address match
is weak: it is used only for a machine with no match yet, never to move or replace one. It still depends on the sender, so the host page
lists the report with how it was matched.

## What it is used for

- **Host page.** An **Inventory** tab: operating system, build, kernel, last boot, reboot pending, security posture, listening services,
  installed updates, the packages (filter and page through them, with their purl), and the summarised history of the last 20 reports (what
  was added, removed, changed). A badge shows the report's age and turns orange when it is stale.
- **Operating system.** The host-reported system replaces the network scan's guess (`os_guess`, accuracy 100) for the machine's addresses, and
  an nmap run does not overwrite it for 60 days. Each listening process is noted on the matching open port the scan already found; no port is
  created from a report (a socket nobody can reach from outside is not an exposed port).
- **CVE matches.** See below.
- **REST and MCP.** `GET projects/{slug}/inventory`, `.../inventory/{id}` and `.../hosts/{host}/inventory`; MCP `list_host_inventories` and
  `get_host_inventory` (the package list is paged: at most 200 a page).

### How the CVE matching works

The matching is in `cveFeed/inventory_match.py`. It is the one place a local-only CVE can become a finding, and only from the host's own
report.

1. The report is turned into components: the operating system (the Windows build `10.0.22631.4460`, matched to the feed's product names such as
   `Windows 11 Version 23H2`; macOS; the running Linux kernel) and every package, looked up by its **source package** first (`libssl3` is built
   from `openssl`) and then its own name.
2. Each component is looked up in two pools: the local-only CVEs, and all the others. Names must match **exactly** (or a listed alias): `php`
   never finds `phpMyAdmin`.
3. A match needs the version **inside a real affected range**. A product named with no usable range, or a version that cannot be compared,
   makes no match, so a record that merely says "Windows" does not match every Windows host.
4. A match is a normal CVE match with `source: host` and evidence `host_reported: true`, shown everywhere with a **Reported by the host**
   label and "(reported by the host)" in lists. The `local_only` rule is unchanged for everything else: the external correlation never reads the
   local pool, and the sweep that closes scan matches of local-only CVEs leaves host-reported ones alone.
5. **Distribution backports.** Ubuntu, Debian and RHEL fix CVEs without changing the upstream version, so an upstream range cannot decide a
   package. When cvENGINE holds the distribution's fixed version for the CVE and package (the tracker data behind `distro_status`), it judges
   the package release against it: patched is kept at confidence 0.2 and labelled, vulnerable is 0.95. Without that data a distribution package
   is at most 0.6. **The kernel of a backporting distribution is not matched at all** (its version number says nothing about its patches); the
   report says so. The kernel of Arch, Alpine, Fedora and other upstream-tracking systems is matched.
6. A CVE an external scan already matched on the host gets the host's evidence added to that match instead of a second row.
7. **Staleness.** A report older than the project's `inventory.stale_days` (default 14, 1 to 365) creates nothing and closes nothing: it is
   skipped as a whole. A fresh report that no longer lists an affected version closes only the matches that same report made earlier
   ("Closed automatically: the host's latest inventory report no longer lists an affected version", work a person did on a match is kept), and
   a version that returns reopens it.
8. The matches follow the host: a new scan makes new host rows, and the correlation pass after each scan puts the host-reported matches (and
   their remediation state) on the new row; every CVE feed sync re-checks every fresh report.

### What it cannot do

- It does not know a vendor's backports beyond the distribution tracker data cvENGINE holds, so a distribution package without that data is
  moderate confidence, and a host-reported finding can be a false positive for a package the distribution patched. That is stated on the match.
- It does not match Windows updates (KB ids) to CVEs: the feed does not carry them, only version ranges. The patch list is shown, and the build
  number is what is matched.
- It does not query pending updates, vulnerability scanners on the host, or anything over the network from the host's side.
- It does not match language package managers (pip, npm, gem) or container image contents. Containers are listed by image name only.
- macOS and Windows reporting could not be exercised against real systems where this was built; see the notes in the changelog.

## Settings

Per project (the Host inventory dialog, `GET/PUT projects/{slug}/settings` `{"inventory": {"create_hosts": false, "stale_days": 14}}`, MCP
`set_project_settings`):

| Setting | Default | |
| --- | --- | --- |
| `create_hosts` | off | add an unknown reporting host as a target and start discovery |
| `stale_days` | 14 | a report older than this creates no findings and closes none |

## Exit codes of the scripts

| Code | Meaning |
| --- | --- |
| 0 | sent, or a dry run |
| 1 | bad usage or configuration (no token, an `http://` server, an unreadable file) |
| 2 | nothing could be collected, or not a supported system |
| 3 | could not reach the server, or its certificate is not trusted (try `--ca-file`) |
| 4 | the server refused the report: read its message |
| 5 | the server kept failing (5xx, 429) after the retries |

Retries (default 3) back off 2, 4, 8 seconds with a little random spread; a refusal (4xx other than 408 and 429) and an untrusted certificate
are never retried.

## Sources

- `os-release(5)` and `machine-id(5)`, freedesktop.org systemd manual: file locations, shell-compatible syntax, and the instruction that the
  machine id is confidential and must be hashed with an application-specific key.
- `dpkg-query(1)`: `-W`, `-f`, the `source:Package` and `db:Status-Abbrev` fields.
- The package URL specification (package-url/purl-spec): the `deb`, `rpm` and `apk` types, namespace and qualifiers.
- Microsoft Learn: `Get-HotFix` (it uses `Win32_QuickFixEngineering`, which returns only CBS-supplied updates);
  `IUpdateSearcher::QueryHistory` (the Windows Update Agent's local event history).
- The pending-reboot registry keys (`Component Based Servicing\RebootPending`, `WindowsUpdate\Auto Update\RebootRequired`) are described by
  community scripts, not an official page; `PendingFileRenameOperations` is left out because antivirus products set it.
