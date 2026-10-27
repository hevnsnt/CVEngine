"""Extract Shodan-style service inventory from nmap `-sV` / `-O` XML output.

Pure parsing of the xmltodict representation of an nmap run into per-host,
per-port service records (product / version / CPE / extrainfo / OS guess). No
Django imports, so it is unit-testable on its own; the DB write that puts this
onto the `Port` / `IpAddress` rows lives in `reNgine.tasks`.

Note: reNgine stores one `Port` row per port *number* (shared across hosts via
`IpAddress.ports`), so the persisted service fields are a best-effort snapshot
per port number. Per-host service separation would need a per-host port record.
"""


def _as_list(value):
    """nmap/xmltodict collapses single children to a dict; normalize to a list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _host_ip(host):
    """First IPv4/IPv6 address of an nmap <host> element, or None."""
    for addr in _as_list(host.get("address")):
        if isinstance(addr, dict) and addr.get("@addrtype") in ("ipv4", "ipv6"):
            return addr.get("@addr")
    return None


def _os_alternatives(host, limit=3):
    """The best ``limit`` OS guesses of a host as ``[{name, accuracy, cpe}]``: nmap ranks many guesses and the first is often only a few
    points ahead of a different family, so the runners-up are kept for whoever reads the guess."""
    out = []
    for match in _as_list((host.get("os") or {}).get("osmatch"))[:limit]:
        if not isinstance(match, dict):
            continue
        classes = [c for c in _as_list(match.get("osclass")) if isinstance(c, dict)]
        cpes = [x for c in classes for x in _as_list(c.get("cpe")) if isinstance(x, str)]
        out.append({"name": str(match.get("@name", ""))[:100], "accuracy": match.get("@accuracy"), "cpe": (cpes or [""])[0][:120]})
    return out


def _host_os(host):
    """Best OS match (name, accuracy) from an nmap <host><os> element, if any."""
    os_el = host.get("os") or {}
    matches = _as_list(os_el.get("osmatch"))
    if not matches:
        return "", None
    best = matches[0]
    name = best.get("@name", "") or ""
    accuracy = best.get("@accuracy")
    try:
        accuracy = int(accuracy) if accuracy is not None else None
    except (TypeError, ValueError):
        accuracy = None
    return name, accuracy


SCRIPT_OUTPUT_CAP = 4000  # one NSE script's text, stored on the port; keeps a chatty script from bloating the row
BANNER_CAP = 1024


def _scripts(element):
    """{script id: output text} from an nmap element's <script id= output=> children (a <port> or a <hostscript>)."""
    out = {}
    for script in _as_list((element or {}).get("script")):
        if not isinstance(script, dict):
            continue
        sid = script.get("@id")
        if not sid:
            continue
        out[str(sid)] = str(script.get("@output", "") or "")[:SCRIPT_OUTPUT_CAP]
    return out


def _banner_from(scripts, service):
    """The service banner for a port: the `banner` NSE script's text if it ran, else nmap's service fingerprint probe
    (``servicefp``), which is the raw bytes the service replied with. Cleaned of the NSE label and capped. '' when neither."""
    raw = scripts.get("banner") or service.get("@servicefp") or ""
    return raw.strip()[:BANNER_CAP]


def parse_ssl_cert(text):
    """``{subject, issuer, sans, not_before, not_after, key, signature}`` from the ssl-cert script's output (``Subject: commonName=...``
    lines); only the fields it printed, each clipped. {} for output that is not a certificate."""
    out = {}
    for raw in str(text or "").splitlines():
        key, _, value = raw.strip().partition(":")
        value = value.strip()
        if not value:
            continue
        if key == "Subject":
            out["subject"] = value[:300]
        elif key == "Issuer":
            out["issuer"] = value[:300]
        elif key == "Subject Alternative Name":
            out["sans"] = [part.strip()[:200] for part in value.split(",") if part.strip()][:40]
        elif key == "Not valid before":
            out["not_before"] = value[:40]
        elif key == "Not valid after":
            out["not_after"] = value[:40]
        elif key == "Public Key type":
            out["key_type"] = value[:20]
        elif key == "Public Key bits":
            out["key_bits"] = value[:10]
        elif key == "Signature Algorithm":
            out["signature"] = value[:60]
    return out if "subject" in out else {}


def _service_record(port):
    """One port's service record from an nmap <port> element, including any NSE <script> output and a banner."""
    service = port.get("service") or {}
    cpes = [c for c in _as_list(service.get("cpe")) if isinstance(c, str)]
    portid = str(port.get("@portid", ""))
    scripts = _scripts(port)
    return {
        "number": int(portid) if portid.isdigit() else None,
        "protocol": port.get("@protocol", "") or "",
        "state": (port.get("state") or {}).get("@state", "") or "",
        "service_name": service.get("@name", "") or "",
        "product": service.get("@product", "") or "",
        "version": service.get("@version", "") or "",
        "service_extra": service.get("@extrainfo", "") or "",
        "ostype": service.get("@ostype", "") or "",
        "method": service.get("@method", "") or "",  # "probed" (it answered) or "table" (guessed from the port number)
        "tunnel": service.get("@tunnel", "") or "",  # "ssl": the service speaks TLS (name="http" tunnel="ssl" is HTTPS)
        "hostname": service.get("@hostname", "") or "",  # a name the service gave for itself (SMTP and IMAP greetings, SSH banners)
        "devicetype": service.get("@devicetype", "") or "",
        "confidence": service.get("@conf", "") or "",  # nmap's 1-10 certainty that the product and version are right
        "cpe": cpes[0] if cpes else "",
        "cpes": cpes,
        "scripts": scripts,
        "banner": _banner_from(scripts, service),
        "tls": parse_ssl_cert(scripts.get("ssl-cert")),
    }


def _scanned_ports(nmaprun, protocol="tcp"):
    """The set of ``protocol`` port numbers a run actually probed, from its <scaninfo services="1,3-4,6-7,...">; None when the report
    does not say. Used to tell "closed since last time" (probed, not reported open) from "not looked at"."""
    ports = set()
    found = False
    for info in _as_list((nmaprun or {}).get("scaninfo")):
        if not isinstance(info, dict) or info.get("@protocol", "tcp") != protocol:
            continue
        found = True
        for part in str(info.get("@services", "")).split(","):
            lo, _, hi = part.strip().partition("-")
            if lo.isdigit() and (not hi or hi.isdigit()):
                ports.update(range(int(lo), int(hi or lo) + 1))
    return ports if found and ports else None


def _scanned_tcp_ports(nmaprun):
    return _scanned_ports(nmaprun, "tcp")


def _extraports_states(host):
    """States of the ports nmap summarised instead of listing (<extraports state="closed" count="990">)."""
    ports = host.get("ports") or {}
    return [e.get("@state", "") for e in _as_list(ports.get("extraports")) if isinstance(e, dict)]


def extract_nmap_inventory(nmap_results):
    """nmap xmltodict dict -> list of host dicts with service-enriched ports.

    Each host dict: {"ip", "os_guess", "os_accuracy", "ports": [service_record], "status", "extraports", "scanned"}:
    ``status`` is the host state (up/down), ``extraports`` the states of the unlisted ports and ``scanned`` the TCP ports
    the run probed and ``scanned_udp`` the UDP ports (None when unknown), so a caller can close ports that were probed and not found
    open.
    Ports without a numeric id are dropped.
    """
    run = (nmap_results or {}).get("nmaprun", {})
    scanned = _scanned_tcp_ports(run)
    scanned_udp = _scanned_ports(run, "udp")
    hosts = _as_list(run.get("host"))
    inventory = []
    for host in hosts:
        if not isinstance(host, dict):
            continue
        os_guess, os_accuracy = _host_os(host)
        records = []
        for port in _as_list((host.get("ports") or {}).get("port")):
            if not isinstance(port, dict):
                continue
            rec = _service_record(port)
            if rec["number"] is None:
                continue
            records.append(rec)
        inventory.append({
            "ip": _host_ip(host),
            "os_guess": os_guess,
            "os_accuracy": os_accuracy,
            "os_matches": _os_alternatives(host),
            "ports": records,
            "hostscripts": _scripts(host.get("hostscript")),  # smb-os-discovery, nbstat: attach to the host, not a port
            "status": (host.get("status") or {}).get("@state", "up") if isinstance(host.get("status"), dict) else "up",
            "extraports": _extraports_states(host),
            "scanned": scanned,
            "scanned_udp": scanned_udp,
        })
    return inventory
