# Better detection of WAFs and edge appliances (research note, not shipped)

Todo #72: "Is there a better technology (a new tool, a new test, a new flag for nuclei, nmap or bbot) to detect WAF versions?"

Written without web access (the search service was out of credits), so it rests on what the repository already runs and on how these
tools are documented to work. Every item marked **to verify** needs one run against a real host before anything is built on it.

## What the pipeline knows today

- bbot's `WAF Detection` finding becomes a host label `WAF` (`reNgine/bbot.py`, `label_for`). The label keeps no vendor, product or version.
  Whether bbot's event text names the vendor is **to verify** (capture one raw event from a host behind a known WAF).
- Technology names come from bbot's httpx run and from nuclei's `tech-detect` template (`nuclei_scan.py`), stored as `Name` or `Name:version`.
- nmap `-sV` service banners, and nuclei CVE templates, are the only other sources of product and version.
- Correlation matches CVEs to a product name and a version. A bare category word ("WAF") must not match a product (fixed in this change).

So the gap is not matching, it is that a firewall or VPN appliance usually arrives as a category with no product, and almost never with a version.

## Why this is hard

A WAF or edge appliance is built to say as little as possible. The vendor is often visible (a block page, a cookie name, a header, the TLS
certificate), the **version almost never is** on an unauthenticated request. Plan for "product known, version unknown" and make the product-only
case useful, instead of chasing versions that are not exposed.

## Options, cheapest first

1. **Keep what bbot already says.** If the event text names the product, store it as the technology (`Cloudflare`, `F5 BIG-IP ASM`) next to
   the `WAF` label. No new scan. **To verify** what the text contains.
2. **wafw00f in the pipeline.** It fingerprints the vendor and product from response behaviour (headers, cookies, block pages, how it reacts
   to a benign-looking probe). It does not report versions. The web app already calls it (`api/views.py`), so it is installed. It sends a few
   extra requests that look like attacks to the WAF, so it belongs in the same opt-in tier as other active checks. **To verify** its output format.
3. **nuclei technology and fingerprint templates, with their version extractors.** Nuclei ships `http/technologies` (including a WAF detection
   template) and many product-panel templates that extract a version from a login page, a JS file name or a response header. The existing
   `tech-detect` pass reads only the matcher name. Reading the extractor output as well would turn "Fortinet panel" into "Fortinet panel 7.2.4"
   where the page leaks it. Smallest change, uses what is installed. **To verify** how many installed templates carry an extractor.
4. **httpx fingerprints: favicon hash and JARM.** A favicon hash identifies a product family when the appliance serves its default icon (VPN
   gateways, firewalls and mail gateways usually do); JARM fingerprints the TLS stack and separates products that look alike over HTTP. Both are
   one request each. They give a product, and sometimes a major version band, never an exact version. **To verify** that the httpx bbot runs
   has these flags, or run httpx directly for hosts bbot labelled `WAF`.
5. **TLS certificate subject and issuer.** Many appliances ship a certificate whose subject or issuer names the vendor and model. nmap's
   `ssl-cert` script and the certificate bbot already collects carry this at no extra cost. Product only.
6. **nmap `http-waf-detect` and `http-waf-fingerprint` (NSE).** The same idea as wafw00f inside the nmap pass that already runs, but the
   NSE policy (`NSE script filter`) would have to admit them, and they are noisier. Prefer wafw00f.
7. **Version from a CVE-specific template.** For a known-exploited edge product, a nuclei template that reads the exact version (many do, for
   the KEV-listed Fortinet, Ivanti, Citrix and Palo Alto bugs) is the only dependable way to a version. That is what validation already does for
   a matched CVE, and it is the right place for a version, not discovery.

## Recommendation

1. Do options 1, 3 and 5 first. They add no scanning and no new tool; they only stop discarding what is already collected.
2. Add option 4 (favicon and JARM) as a second pass for hosts that carry the `WAF` label or an appliance-looking technology.
3. Treat options 2 and 6 as opt-in and only for authorized targets, because they send attack-looking probes.
4. Leave exact versions to option 7, and say "version unknown" in the UI instead of guessing. A product with no version should produce a
   lower-confidence match that asks for validation, which is how matching already treats a missing version.

## A small experiment before building

Pick five hosts behind known products (a Cloudflare site, a FortiGate, a Palo Alto GlobalProtect portal, an F5, and a plain nginx). For each,
record: the raw bbot events, the nuclei `tech-detect` and extractor output, the httpx favicon hash and JARM, the certificate subject, and
wafw00f's answer. The table says which source names the product, and for how many a version appears. That decides the order of the work.
