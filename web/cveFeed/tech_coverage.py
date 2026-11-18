"""Technology coverage: which technology names cvENGINE detects connect to a CVE record, and which do not.

A correct version is wasted when the technology's name never reaches the name the CVE record uses ("Cisco Adaptive Security Appliance
Software" next to the record's "Cisco Adaptive Security Appliance (ASA) Software" and NVD's ``adaptive_security_appliance_software``). This
module measures that, with the matcher correlation itself uses (``correlation.named_hits``: CPE first, then the name, then the aliases of
``data/product_aliases.json``), so what it reports is what correlation would do:

* ``unmatched``: names (with the hosts they are seen on) that connect to no affected entry of any stored CVE. Some name no software at all
  (a CDN, a header check); the rest are naming gaps. ``near`` lists the catalogue products that share a word with the name, the usual fix.
* ``unversioned``: names seen without a version that do connect, ranked by how many CVEs exist for the product: leads for a version source.
* ``services``: names that are not software a host runs (a CDN, a load balancer, a hosting platform, an analytics script, a protocol:
  ``data/service_names.json``), with the hosts they are seen on. They never carry a CVE, so they are kept out of ``unmatched``.
* ``ambiguous``: names that connect to products of more than one vendor ("IOS" reaches Cisco's IOS and Apple's iOS). A vendor named after
  the product itself ("nginx" for nginx) and spellings of one vendor ("apache", "apachesoftwarefoundation") count once.

Read-only: it writes nothing. ``report`` is pure (sightings and a CVE pool in, a dict out), so the management command can run it against a
seed file and a list of names without a database (``manage.py technology_coverage --seed ... --names ...``); ``sightings_from_db`` reads the
current hosts' technologies and port products. Over the API it is an App Admin read (``agentapi.tuning``-style 403 for anyone else): the names
are counted across every tenant, so no other role may see them.
"""
import json
import os
from collections import Counter

from cveFeed import correlation
from cveFeed import match_policy

DEFAULT_LIMIT = 50
MAX_LIMIT = 500
MAX_NEAR = 3
MAX_PRODUCTS = 5
MAX_NAME = 200


SERVICES_FILE = os.path.join(os.path.dirname(__file__), "data", "service_names.json")
SERVICE_NAMES = {}  # normalized name -> kind ("cdn", "hosting", ...)


def load_services(path=SERVICES_FILE):
    """Read the names that are not software (``data/service_names.json``) into ``SERVICE_NAMES``. Returns the parsed document."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    SERVICE_NAMES.clear()
    SERVICE_NAMES.update({correlation._norm(name): entry.get("kind") or "service"
                          for entry in doc.get("services", ()) for name in entry.get("names", ())})
    return doc


load_services()


def service_kind(name, raw=""):
    """The kind of service a name is ("cdn", "hosting", ...) when it is not software a host runs, else "". ``raw`` is the name as stored,
    before a ``product/version`` token was split ("awselb/2.0", "http/3")."""
    for text in (name, raw):
        kind = SERVICE_NAMES.get(correlation._norm(text)) if text else None
        if kind:
            return kind
    return ""


def _key_vendor(vendor):
    return correlation._norm(vendor, True)


def catalogue_labels(cve_by_id):
    """``(labels, stats)``: product token -> the ``vendor:product`` spellings the records use for it, most common first, and the size of the
    catalogue (CVEs, affected entries, distinct vendor:product pairs)."""
    spelled = {}
    pairs, items = set(), 0
    for cve in cve_by_id.values():
        for item in cve.affected or []:
            items += 1
            vendor = str(item.get("vendor") or "").strip()
            for key in ("product", "package"):
                product = str(item.get(key) or "").strip()
                if not product:
                    continue
                token = correlation._norm(product, True)
                spelled.setdefault(token, Counter())[f"{vendor}:{product}" if vendor else product] += 1
                pairs.add((_key_vendor(vendor), token))
    labels = {token: [label for label, _n in counts.most_common(2)] for token, counts in spelled.items()}
    return labels, {"cves": len(cve_by_id), "affected_entries": items, "vendor_products": len(pairs)}


def _vendor_groups(vendors, products):
    """The distinct vendors among ``vendors`` (normalized vendor -> CVE ids): spellings of one vendor folded together ("apache" and
    "apachesoftwarefoundation"), a vendor named after the product itself ("nginx" for nginx) left out, a feed's placeholder ignored."""
    real = {v: ids for v, ids in vendors.items()
            if v and v not in correlation._NO_VENDOR and not any(len(p) >= 3 and (p in v or v in p) for p in products)}
    groups = []
    for vendor in sorted(real, key=len):
        same = correlation.VENDOR_CLASSES.get(vendor, frozenset())
        for group in groups:
            if any(g in same or (len(g) >= 3 and (g in vendor or vendor in g)) for g in group["vendors"]):
                group["vendors"].append(vendor)
                group["cves"] |= real[vendor]
                break
        else:
            groups.append({"vendors": [vendor], "cves": set(real[vendor])})
    return groups


def connect(name, cpe, product_index, cve_by_id):
    """What one detected name connects to: ``{"cves": set of ids, "kev": n, "vendors": {vendor: set of ids}, "products": Counter of
    "vendor:product", "tokens": product tokens}``. Empty for a name too short to match or an operating system sighting (decided by the
    host's own report, never by name: ``match_policy.is_os_sighting``)."""
    out = {"cves": set(), "kev": 0, "vendors": {}, "products": Counter(), "tokens": set()}
    token = correlation._norm(name)
    if len(token) < correlation._MIN_TOKEN or match_policy.is_os_sighting(name, cpe):
        return out
    for cve, hit in correlation.named_hits(token, product_index, cve_by_id, cpe=cpe or None):
        out["cves"].add(cve.id)
        out["kev"] += 1 if getattr(cve, "kev", False) else 0
        for _i, item in hit:
            vendor = str(item.get("vendor") or "").strip()
            product = str(item.get("product") or item.get("package") or "").strip()
            out["vendors"].setdefault(_key_vendor(vendor), set()).add(cve.id)
            out["products"][f"{vendor}:{product}" if vendor else product] += 1
            out["tokens"].add(correlation._norm(product, True))
    return out


def _near(token, product_index, labels):
    """The catalogue products that share a word with an unmatched name, the most CVEs first: where an alias would point."""
    words = {w for split in correlation._words_for(token) for w in split if len(w) >= 3 and w not in correlation.GENERIC_WORDS}
    if not words or not hasattr(product_index, "candidate_tokens"):
        return []
    scored = []
    for product_token in product_index.candidate_tokens(token):
        shared = words & {w for split in correlation._words_for(product_token) for w in split}
        if shared:
            scored.append((-len(shared), -len(product_index[product_token]), product_token))
    return [{"product": (labels.get(t) or [t])[0], "cves": -n} for _s, n, t in sorted(scored)[:MAX_NEAR]]


def normalise_sighting(name, version="", source="tech", cpe="", hosts=1):
    """One sighting as correlation reads it: a technology stored as ``Name:version``, a CPE, a banner token or a ``product/version``
    Server-header token is split the same way (``correlation.read_technology``: an earlier build's "ASP.NET" CLR line and the technology template's "AspNet
    Version Disclosure" are read as the .NET Framework's CLR line), a port product the same way (``correlation.split_port_product``), and a
    protocol's version (Microsoft-HTTPAPI/2.0) is no version. ``raw`` keeps the name as stored, for ``service_kind``."""
    from cvengine_scanner import versions
    raw = str(name or "").strip()[:MAX_NAME]
    if source == "tech":
        base, ver = correlation.split_name_version(raw)
        ver = ver or correlation.stated_version(base, str(version or "").strip())
        base, ver = versions.legacy_aspnet(correlation.tech_name(base), ver)  # correlation.read_technology, with the version given apart
    else:
        base, ver, _rest = correlation.split_port_product(raw, version)
    if not ver and cpe:
        ver = correlation.stated_version(base, (correlation.parse_cpe(cpe) or ("", "", ""))[2])
    return {"name": base.strip(), "version": ver, "source": source, "cpe": (cpe or "").strip(), "hosts": int(hosts or 0), "raw": raw}


def _merge(sightings):
    """Sightings folded per (name, CPE): host counts with and without a version, and the sources that reported the name."""
    merged = {}
    for s in sightings:
        if not s.get("name"):
            continue
        key = (s["name"], s.get("cpe") or "")
        row = merged.setdefault(key, {"name": s["name"], "cpe": key[1], "sources": set(), "hosts": 0, "versioned": 0, "unversioned": 0,
                                      "versions": Counter(), "raw": set()})
        row["sources"].add(s.get("source") or "tech")
        row["raw"].add(s.get("raw") or s["name"])
        row["hosts"] += s["hosts"]
        if s.get("version"):
            row["versioned"] += s["hosts"]
            row["versions"][s["version"]] += s["hosts"]
        else:
            row["unversioned"] += s["hosts"]
    return list(merged.values())


def _limit(value):
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = DEFAULT_LIMIT
    return max(1, min(MAX_LIMIT, number))


def report(sightings, cve_by_id, product_index, limit=DEFAULT_LIMIT):
    """The coverage report for ``sightings`` (``normalise_sighting`` dicts) against a CVE pool (``correlation.cve_pool`` or one read from a
    seed). Deterministic: ties are broken by name."""
    limit = _limit(limit)
    labels, catalogue = catalogue_labels(cve_by_id)
    rows = _merge(sightings)
    unmatched, unversioned, ambiguous, services = [], [], [], []
    connected_hosts = total_hosts = os_names = 0
    for row in rows:
        total_hosts += row["hosts"]
        token = correlation._norm(row["name"])
        if match_policy.is_os_sighting(row["name"], row["cpe"]):
            os_names += 1
            continue
        base = {"name": row["name"], "sources": sorted(row["sources"]), "hosts": row["hosts"], **({"cpe": row["cpe"]} if row["cpe"] else {})}
        kind = next(filter(None, (service_kind(row["name"], raw) for raw in sorted(row["raw"]))), "")
        if kind:  # a CDN, a hosting platform, an analytics script: not software the host runs, so never a naming gap
            services.append({**base, "kind": kind})
            continue
        found = connect(row["name"], row["cpe"], product_index, cve_by_id)
        if not found["cves"]:
            unmatched.append({**base, "versioned_hosts": row["versioned"],
                              "near": _near(token, product_index, labels) if len(token) >= correlation._MIN_TOKEN else []})
            continue
        connected_hosts += row["hosts"]
        products = [p for p, _n in found["products"].most_common(MAX_PRODUCTS)]
        if row["unversioned"]:
            unversioned.append({**base, "unversioned_hosts": row["unversioned"], "versioned_hosts": row["versioned"],
                                "cves": len(found["cves"]), "kev": found["kev"], "products": products})
        groups = _vendor_groups(found["vendors"], found["tokens"] | {token})
        if len(groups) > 1:
            ambiguous.append({**base, "cves": len(found["cves"]),
                              "vendors": sorted(({"vendor": "/".join(g["vendors"]), "cves": len(g["cves"])} for g in groups),
                                                key=lambda v: (-v["cves"], v["vendor"])),
                              "products": products})
    unmatched.sort(key=lambda r: (-r["hosts"], r["name"].lower()))
    services.sort(key=lambda r: (-r["hosts"], r["name"].lower()))
    unversioned.sort(key=lambda r: (-r["cves"], -r["unversioned_hosts"], r["name"].lower()))
    ambiguous.sort(key=lambda r: (-min(v["cves"] for v in r["vendors"][:2]), -r["hosts"], r["name"].lower()))
    return {
        "catalogue": catalogue,
        "names": len(rows), "host_sightings": total_hosts, "os_sightings": os_names,
        "connected_names": len(rows) - len(unmatched) - len(services) - os_names, "connected_host_sightings": connected_hosts,
        "unmatched_count": len(unmatched), "unversioned_count": len(unversioned), "ambiguous_count": len(ambiguous),
        "services_count": len(services),
        "unmatched": unmatched[:limit], "unversioned": unversioned[:limit], "ambiguous": ambiguous[:limit], "services": services[:limit],
        "limit": limit,
    }


# ----------------------------------------------------------------------------- inputs

def sightings_from_db(project=None):
    """The technology names and port products of each domain's current hosts (``correlation.latest_scan_q``), with the number of hosts each
    is seen on, as ``normalise_sighting`` dicts. ``project`` (a Project) narrows to one project. Three aggregate queries, whatever the size."""
    from django.db.models import Count

    from startScan.models import OPEN_PORT_STATES, Port, Subdomain, Technology
    current = Subdomain.objects.filter(correlation.latest_scan_q())
    if project is not None:
        current = current.filter(target_domain__project=project)
    current = current.values("id")
    out = []
    for row in (Technology.objects.filter(technologies__in=current).values("name")
                .annotate(hosts=Count("technologies", distinct=True)).order_by("name")):
        out.append(normalise_sighting(row["name"], source="tech", hosts=row["hosts"]))
    for row in (Port.objects.filter(ports__ip_addresses__in=current, state__in=OPEN_PORT_STATES).exclude(product="").exclude(product__isnull=True)
                .values("product", "version", "cpe").annotate(hosts=Count("ports__ip_addresses", distinct=True)).order_by("product")):
        out.append(normalise_sighting(row["product"], row["version"] or "", source="port", cpe=row["cpe"] or "", hosts=row["hosts"]))
    return out


class _Cve:
    """A CVE read from a seed line: only what correlation reads."""
    __slots__ = ("id", "cve_id", "affected", "kev", "epss_reached", "exploit_db", "cvss")

    def __init__(self, pk, raw):
        self.id = pk
        self.cve_id = str(raw.get("cve_id") or "")
        self.affected = correlation.clean_affected(raw.get("affected"))
        self.kev = bool(raw.get("kev"))
        self.epss_reached = raw.get("epss_reached")
        self.exploit_db = raw.get("exploit_db")
        self.cvss = raw.get("cvss")


def pool_from_seed(path):
    """``(cve_by_id, product_index)`` from a seed file (``cveFeed.seed`` format 1: a manifest line, then one CVE per line). A rejected CVE is
    left out, as ``correlation.cve_pool`` leaves it out. Nothing is stored."""
    from cveFeed import seed
    cve_by_id = {}
    for raw in seed.iter_lines(path):
        if not isinstance(raw, dict) or "cve_id" not in raw or "reject" in str(raw.get("status") or "").lower():
            continue
        pk = len(cve_by_id) + 1
        cve_by_id[pk] = _Cve(pk, raw)
    return cve_by_id, correlation.build_product_index(cve_by_id.values())


def sightings_from_file(path):
    """Sightings from a JSON file: a list of names, or of ``{"name", "version", "source": "tech"|"port", "cpe", "hosts"}``."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    out = []
    for entry in data if isinstance(data, list) else []:
        if isinstance(entry, str):
            out.append(normalise_sighting(entry))
        elif isinstance(entry, dict) and entry.get("name"):
            out.append(normalise_sighting(entry["name"], entry.get("version") or "", entry.get("source") or "tech", entry.get("cpe") or "",
                                          entry.get("hosts", 1)))
    return out
