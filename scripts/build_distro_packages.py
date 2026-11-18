"""Build web/cveFeed/data/distro_packages.json: which Ubuntu and Debian release published each build of the packages cvENGINE reads
from banners (cveFeed.distro_releases).

Ubuntu: Launchpad's publishing history of each source package (https://api.launchpad.net/1.0/ubuntu/+archive/primary,
getPublishedSources): the version frozen in each series' Release pocket (the last one published there) and every version published to
-updates and -security, for 14.04 and later. Debian: the versions in each stable suite now (https://sources.debian.org/api/src/<package>/)
and every +debNuM / ~debNuM build ever uploaded (https://snapshot.debian.org/mr/package/<package>/). Each (distribution, release, package)
is cited: the Launchpad page of the package in that series, or its Debian package tracker page.

Run by hand when a release ships (it needs the network; only package names are sent), and commit the output:

    python3 scripts/build_distro_packages.py web/cveFeed/data/distro_packages.json
"""
import json
import re
import sys
import time
import urllib.request

UBUNTU_PACKAGES = ["openssh", "apache2", "nginx", "openssl", "php7.0", "php7.2", "php7.4", "php8.1", "php8.3", "php8.4",
                   "exim4", "bind9", "dovecot", "proftpd-dfsg", "vsftpd"]
DEBIAN_PACKAGES = ["openssh", "apache2", "nginx", "openssl", "php7.0", "php7.3", "php7.4", "php8.2", "php8.4",
                   "exim4", "bind9", "dovecot", "proftpd-dfsg", "vsftpd"]
POCKETS = {"Release", "Updates", "Security"}
DEBIAN = {"jessie": "8", "stretch": "9", "buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14"}


def get(url):
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "distro-table-builder"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read())
        except Exception as exc:  # noqa: BLE001
            print("retry", url, exc, file=sys.stderr)
            time.sleep(2 + attempt * 3)
    raise SystemExit("failed " + url)


def series_versions():
    out = {}
    url = "https://api.launchpad.net/1.0/ubuntu/series"
    while url:
        d = get(url)
        for e in d["entries"]:
            out[e["self_link"]] = (e["name"], e["version"])
        url = d.get("next_collection_link")
    return out


def strip_epoch(v):
    return re.sub(r"^\d+:", "", v)


def split(v):
    v = strip_epoch(v)
    up, _, rev = v.rpartition("-")
    return (up, rev) if up else (v, "")


def ubuntu_base(rev):
    m = re.match(r"^(.*?ubuntu\d+)", rev)
    return m.group(1) if m else rev


def main():
    series = series_versions()
    table = {"ubuntu": {}, "debian": {}}
    for pkg in UBUNTU_PACKAGES:
        url = ("https://api.launchpad.net/1.0/ubuntu/+archive/primary?ws.op=getPublishedSources&source_name=%s&exact_match=true&ws.size=300"
               % pkg)
        seen = set()
        frozen = {}
        while url:
            d = get(url)
            for e in d["entries"]:
                if e["pocket"] not in POCKETS or not e.get("date_published"):
                    continue
                name, version = series.get(e["distro_series_link"], ("", ""))
                if not version or float(version) < 14.04:
                    continue
                if e["pocket"] == "Release":
                    # the Release pocket changes all through a series' development: only the last version published there shipped
                    if e["status"] != "Deleted" and (version not in frozen or e["date_published"] > frozen[version][0]):
                        frozen[version] = (e["date_published"], e["source_package_version"])
                    continue
                seen.add((version, e["source_package_version"]))
            url = d.get("next_collection_link")
        seen |= {(version, v) for version, (_d, v) in frozen.items()}
        entry = table["ubuntu"].setdefault(pkg, {})
        for release, full in seen:
            up, rev = split(full)
            entry.setdefault(up, {}).setdefault(rev, set()).add(release)
        print(pkg, len(seen), file=sys.stderr)
    for pkg in DEBIAN_PACKAGES:
        seen = set()
        cur = get("https://sources.debian.org/api/src/%s/" % pkg)
        for v in cur.get("versions", []):
            for suite in v.get("suites", []):
                if suite in DEBIAN:
                    seen.add((DEBIAN[suite], v["version"]))
        snap = get("https://snapshot.debian.org/mr/package/%s/" % pkg)
        for v in snap.get("result", []):
            m = re.search(r"[+~]deb(\d+)u\d+", v["version"])
            if m and m.group(1) in DEBIAN.values():
                seen.add((m.group(1), v["version"]))
        entry = table["debian"].setdefault(pkg, {})
        for release, full in seen:
            up, rev = split(full)
            entry.setdefault(up, {}).setdefault(rev, set()).add(release)
        print(pkg, len(seen), file=sys.stderr)
    names = {v: n for n, v in series.values()}
    out = {"ubuntu": {}, "debian": {}}
    citations = {}
    for distro, pkgs in table.items():
        for pkg, ups in sorted(pkgs.items()):
            out[distro][pkg] = {}
            for up, bases in sorted(ups.items()):
                out[distro][pkg][up] = {b: sorted(r, key=lambda x: float(x)) for b, r in sorted(bases.items())}
                for rels in bases.values():
                    for r in rels:
                        key = f"{distro}/{r}/{pkg}"
                        if distro == "ubuntu":
                            citations[key] = f"https://launchpad.net/ubuntu/{names[r]}/+source/{pkg}"
                        else:
                            citations[key] = f"https://tracker.debian.org/pkg/{pkg}"
    about = ("Which Ubuntu and Debian release published each build: {distro: {source package: {upstream version: {revision: [releases]}}}}. "
             "Built by scripts/build_distro_packages.py from Launchpad's publishing history (Ubuntu) and sources.debian.org / "
             "snapshot.debian.org (Debian), on " + time.strftime("%Y-%m-%d") + ". citations: the source of each (distro, release, package).")
    json.dump({"_about": about, "ubuntu": out["ubuntu"], "debian": out["debian"], "citations": dict(sorted(citations.items()))},
              open(sys.argv[1], "w"), indent=None, separators=(",", ":"), sort_keys=False)


if __name__ == "__main__":
    main()
