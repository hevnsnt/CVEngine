# Handoff for the cvengine-sentinel client agent (cvENGINE 1.3.1)

Audience: the agent that maintains `hevnsnt/cvengine-sentinel`. Source: the 1.3.1 server fixes in `hevnsnt/CVEngine`
(PRs #205 to #242). Most of 1.3.1 is server-only. This document lists what the Sentinel must change or confirm, with the
server code that now depends on it, and what needs no change.

Rules that apply to everything below: no em dashes in code, docs, comments or commit messages; no client names, IPs or
personal emails in code, docs or tests (use `192.0.2.x`, `example.com`); a Sentinel result is untrusted input to the server, so
the server clips and validates it, but a correct client keeps the server from having to.

Priority:

| # | Change | Why it matters | Server PR |
|---|--------|----------------|-----------|
| 1 | Send `os_reliable: false` from a Sentinel on Docker Desktop | OS guesses from there describe Docker's gateway, not the target | #240 |
| 2 | nmap: report failure as `outcome: "error"`, never as `hosts: []` | An empty list reads as "nothing found" | #233, #223 |
| 3 | nmap: always return a host row for every requested address | Internal scans fail without one; external falls back to a local scan | #229, #230, #241 |
| 4 | nmap with `-O` needs a closed port in its port plan | No closed port means no OS detection | #241 |
| 5 | naabu: keep tarpit addresses (do not drop or clip them) | Server decides, nmap then uses default ports | #237, #242 |
| 6 | Apply the effective `network` value from the heartbeat | Server grant is authoritative; local value can only lower it | #231 |
| 7 | Update scripts: rollback trap and containment test | Only if the Sentinel repo carries copies of these scripts | #222, #211 |

---

## 1. `os_reliable: false` when running on Docker Desktop (#240, #214)

### Problem

nmap's OS guess (`-O`) only holds if its probes cross the network unchanged. Docker Desktop (macOS, Windows) runs
containers in a VM behind vpnkit or gvisor, which answers probes itself. The guess then describes the gateway. Real
effect: an Ubuntu server and a NAS were stored as Google Fuchsia and an iDRAC as Apple OS X. The default Linux Docker
bridge also loses the malformed probe nmap sends (FIN+PSH+URG, "T7"), so it ranks wrong too.

### What the server does now

`web/agentapi/sentinel_broker.py::_clean_nmap_result` keeps one explicit opt-out through sanitization:

```python
return {'hosts': out, 'os_reliable': body.get('os_reliable') is not False}
```

`sentinel_dispatch.try_nmap` and `internal_scan._nmap` pass it on:

```python
totals = persist_inventory(inventory, org_id=org_id, os_reliable=result.get('os_reliable') is not False)
```

When `os_reliable` is false, `persist_inventory` does not store the packet-based OS guess and the AI never sees it as a fact.
Anything other than the boolean `false` (missing, null, 0) means reliable, so the client must send the literal `false`.

### What the Sentinel must do

Detect Docker Desktop at startup (the server's own detector is `web/cveFeed/os_detection.py`; port its logic) and
send the flag in every nmap task result.

Detection signals (any one is enough). The server reads the kernel release (`platform.release()`, the VM kernel inside a container) and looks for any of these
markers, case-insensitive (`KERNEL_MARKERS` in `web/cveFeed/os_detection.py`):

- `linuxkit` (Docker Desktop on macOS)
- `microsoft` or `wsl2` (Docker Desktop on Windows, kernel `...-microsoft-standard-WSL2`)
- `orbstack` (OrbStack on macOS)

Result body example, nmap task, Sentinel on Docker Desktop:

```json
{
  "outcome": "done",
  "hosts": [
    {
      "ip": "192.0.2.10",
      "os_guess": "Google Fuchsia",
      "ports": [
        {"number": 22, "protocol": "tcp", "service_name": "ssh", "product": "OpenSSH", "version": "9.6", "state": "open"}
      ]
    }
  ],
  "os_reliable": false
}
```

Not on Docker Desktop: omit the field or send `true`. Do not send `false` for a Linux host with host networking.

Recommendation to put in the Sentinel's docs: run a Sentinel on a Linux host or VM. The server repo ships
`docker-compose.hostnet.yml` (host networking) and `docker-compose.macvlan.yml` (own LAN address), both measured
to give exact OS results with real nmap. Consider shipping equivalent overlays in the Sentinel compose layout.

Optional: the server's daily `check_os_path` (`web/cveFeed/path_probe.py`) sends a plain SYN and a FIN+PSH+URG packet to a
closed port and compares. The Sentinel can run the same check and set `os_reliable` from the measurement instead of only
from the platform. The platform signal alone is acceptable.

---

## 2. nmap failure must be an error, not an empty result (#233, #223)

### Problem

Before #233 a failed nmap (nonzero exit, truncated XML, no `<nmaprun>`) was turned into "no hosts, no ports", which the
server stored as a clean scan. A host whose scan failed looked like a host with nothing open.

### What the server does now

For a local nmap run, an exit status other than 0, a missing `<nmaprun>`, or a missing `<finished ... exit="success">`
is a failed scan. Stage test doubles were changed from `''` to valid report XML for the same reason.

### What the Sentinel must do

Apply the same rule in the nmap runner, so the server can tell a failed task from an empty one:

```python
proc = run_nmap(args, timeout=...)
report = parse_xml(proc.stdout)            # None when missing or not parseable
finished = report is not None and report.find('runstats/finished[@exit="success"]') is not None
if proc.returncode != 0 or not finished:
    return {'outcome': 'error', 'error': f'nmap exit {proc.returncode}: {proc.stderr[-200:]}'}
return {'outcome': 'done', 'hosts': hosts, 'os_reliable': not docker_desktop_detected()}
```

Wrong (do not do this):

```python
except Exception:
    return {'outcome': 'done', 'hosts': []}     # server reads this as "scanned, found nothing"
```

An error body is `{outcome: "error", error: "<short reason>"}`. The server clips the text. Reporting twice is harmless.

---

## 3. Return a host row for every requested address (#229, #230, #241)

The server decides what a Sentinel covered by which host rows come back.

External scan (`sentinel_dispatch.try_nmap`): an address with no host row keeps its whole local fallback scan. An address
with a row counts as covered, and the ports in that row count as "scanned":

```python
reported = {}
for host in inventory:
    reported.setdefault(host['ip'], set()).update(p.get('number') for p in host['ports'])
for ip in targets:
    if ip not in reported:
        remaining.append(ip)                       # local nmap runs it
    elif local_ports is not None and ip in local_ports:
        missing = sorted(set(local_ports[ip]) - reported[ip])
        if missing:                                # naabu found ports the Sentinel did not scan
            local_ports[ip] = missing              # local top-up scans just those
            remaining.append(ip)
```

So a Sentinel that omits `ports` for a host, or scans fewer ports than naabu found, makes the server run a second local pass. Report
every port you scanned and found open, with `state` set.

Internal scan (`internal_scan._nmap`): there is no local fallback, because the server has no route. If no host row matches the requested
address the scan fails with `the Sentinel reported nothing for the address`. For a host that is down, still return a row:

```json
{"outcome": "done", "hosts": [{"ip": "10.0.0.5", "os_guess": "", "ports": []}], "os_reliable": true}
```

Result limits, clipped by the server: at most 64 host rows (`MAX_ADDRESSES`), at most 500 ports per host
(`MAX_PORTS_PER_HOST`). Only rows whose `ip` is an IP literal and is one of the requested addresses are kept. Rows for addresses that
were not requested are dropped.

UDP (internal pipeline, #230): the task kind is `nmap_udp` and the server reads the raw nmap XML from the top level of the result,
`{"outcome": "done", "xml": "<nmaprun>...</nmaprun>"}`, parses it, and needs a host with the requested address in it. An empty or
unparseable `xml`, or one with no host row for the address, fails the UDP step with `the Sentinel reported nothing for the address`.

---

## 4. `-O` needs a closed port in the port plan (#241)

### Problem (reproduced with real nmap)

With `-O --osscan-limit`, nmap runs OS detection only when it saw at least one open and one closed TCP port. When the
server first ran naabu and then nmap with `-p <open ports only>`, nmap never saw a closed port, so no host was ever
fingerprinted. naabu on is the default, so this affected nearly every install.

### What the server does now

`cveFeed/naabu_scan.py`:

```python
CLOSED_PROBE_PORTS = (1, 3)   # nearly always closed

def flags_for(ports_by_ip, base_flags, os_probe=True):
    # when -O is in the flags and ports exist, the probe ports are appended: -p 1,3,22,8443,9200
```

The top-up group (ports a Sentinel missed) is scanned with `os_probe=False`, so a weaker local guess cannot overwrite the
Sentinel's own OS guess (`keeps_reported_os`).

### What the Sentinel must do

If the Sentinel builds its own port plan (for example from the `ports` list in the task target or from a naabu pass it runs
itself) and passes `-O`, add one or two closed ports to the plan, as above, or scan a port range that is certain to include a
closed port. Otherwise nmap prints no OS match and `os_guess` stays empty.

Check with a real run, not with a mock:

```
nmap -O --osscan-limit -p 22,8443 192.0.2.10      # no OS line
nmap -O --osscan-limit -p 1,3,22,8443 192.0.2.10  # OS match
```

Possible future work, not required: the server can put naabu's port plan in the nmap task target and accept `os_accuracy` back.
Say so if the Sentinel wants that and the server will add it.

---

## 5. naabu results: keep tarpit addresses (#237, #242)

### Problem

An address that answers on every port (a tarpit, or a firewall that accepts everything) yields thousands of "open" ports.
Storing them is wrong, and dropping the address reads as "nothing open". The server's limit is
`naabu_scan.MAX_OPEN_PER_IP = 500`. Above it the address is handed to nmap's default ports instead.

Before the fix in #242, the server clipped a Sentinel's list to 500 first, so a 65535-port tarpit arrived as a believable 500-port list
and the check never fired.

### What the server does now (`sentinel_broker._clean_naabu_result`)

```python
if values is None or len(values) > MAX_OPEN_PER_IP:
    out[ip] = None          # kept as None: not clipped, not dropped
    continue
clean = sorted({v for v in values[:MAX_PORTS_PER_HOST] if isinstance(v, int) and not isinstance(v, bool) and 0 < v < 65536})
if clean:
    out[ip] = clean
```

### What the Sentinel must do

- Never truncate the open-port list of an address yourself to fit a limit. Send the whole list (up to what the
  result route accepts) or `null`.
- Never drop an address because it has many open ports.
- An address with no open ports can be omitted or sent as an empty list.

Result body example:

```json
{
  "outcome": "done",
  "ports": {
    "192.0.2.20": [22, 443],
    "192.0.2.21": null
  }
}
```

`192.0.2.21` is a tarpit: the server stores no ports for it and nmap scans its default ports.

---

## 6. The network grant and the heartbeat `settings` (#231, #151)

`network:internal` is granted by the server, not by what the Sentinel declares. In
`web/agentapi/sentinel_settings.py`:

```python
def effective_network(agent):
    """internal only when the server says the Sentinel is inside a private network (Agent.network) AND the machine's own
    setting does not say otherwise: a Sentinel's local configuration is a limit, so it can lower itself to external but never
    raise itself to internal."""
    if agent.network != 'internal':
        return 'external'
    return 'external' if ((agent.reported_settings or {}).get('network') or {}).get('value') == 'external' else 'internal'
```

Resetting a managed `network` value (`None`) now restores the enrollment's network instead of leaving the old grant.

What the Sentinel must do:

- Keep reporting its local `network` setting in `reported_settings` (for example from `CVENGINE_SENTINEL_NETWORK`). Setting
  `external` locally lowers the grant; setting `internal` locally never raises it.
- Read `settings.values.network` from the heartbeat reply and apply it. It is the effective value:

  ```json
  {"settings": {"values": {"network": {"value": "internal"}, "disabled_kinds": {"value": []}}, "rev": "..."}}
  ```

- Honour `settings.values.disabled_kinds` (a list of kinds) and never claim or declare those. Since the per-Sentinel capability policy (1.4) the server derives
  it: it is every kind an administrator (or the instance default of its class, for the built-in scanner OpenVAS until changed) denies, plus the machine's own
  list. The policy itself (`allow`, `deny`, `prefer`, per-kind caps) stays on the server, which enforces the caps and the preference where it hands out work,
  so nothing else is sent and a client that already honours `disabled_kinds` needs no change.
- Stop assuming the local value is what the server is using. An internal Sentinel that is demoted by the server must stop
  claiming internal work at its next heartbeat. A client older than 1.3 cannot enforce the template policy; keep the self-update
  path working so the Sentinels page can move it forward.

---

## 7. Update scripts, if the Sentinel repo shares them (#222, #211, #239)

Only relevant if `cvengine-sentinel` carries copies of `update.sh`, `apply-update.sh`, `update-watch.sh`, `auto-deploy.sh` or `update-state.py`.

- #222, rollback trap before the fetched-script preflight: the trap that restores the previous tree must be installed before
  the fetched script is checked, otherwise a failed preflight leaves a half-updated tree. See `scripts/apply-update.sh` in the
  server repo.
- #211, a fork with local commits kept the update banner on forever. The containment test is now
  `git merge-base --is-ancestor <latest> HEAD` instead of `latest == HEAD`; a tree that has the latest commit inside it
  is current. A tree that cannot fast-forward is reported as `diverged`, and a failed comparison is `unknown`, never "behind".
  `scripts/update-state.py upstream` writes `.upstream-state.json`; the host side watcher reads it. See `docs/UPDATES.md`.

---

## What needs no client change

All of these are server-side only: #205 (CVE List range lower bound), #206 (revalidation twins), #207 (feed watermark, seed gap),
#208 (Nuclei template index), #209 (OpenAI-compatible providers), #210 (version-only evidence ceiling), #212 (public address
from the address alone), #213 (catch-all web servers, `soft404`), #224 to #228, #232, #234 to #236, #238 (partial bbot
discovery now continues), #239 (viewer-scoped OpenVAS queue in `agentapi/sentinel_broker.py`), #241 server half (the closed
probe port for local passes), #242.

## How to check your work against a real server

1. Enroll a Sentinel with a test project, run an nmap task and look at the Sentinels page task row (outcome wording, task id,
   host).
2. Docker Desktop: confirm `System status` on the server shows the OS path verdict as `interfering` after a day, or run a task and
   confirm the host's OS is not stored from the packet guess.
3. Force a failure (point the runner at a missing nmap binary, or a bad argument) and confirm the task row says failed, not done.
4. Run a naabu task against an address that accepts every port; the host must end up with nmap default-port results and no
   500-port list.
5. Server tests that pin these shapes: `tests/test_sentinels.py` (`NaabuResultTests`), `tests/test_sentinel_dispatch.py`,
   `tests/test_hard_naabu.py`, `tests/test_internal_scan.py`.
