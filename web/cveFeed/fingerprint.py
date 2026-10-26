"""What one HTTP response says it runs, read from what the route check already fetched: the Server and X-Powered-By headers, the
generator meta tag, and a few markers in the sampled page. Pure functions, no network.

Names use the form the rest of the scanner stores, "Name" or "Name:version", so the correlation engine reads them like any other
detected technology. A target controls its own headers and pages, so every name is cut to a safe alphabet and length and the list
is capped; the evidence for each says where it came from."""
import re

MAX_FINGERPRINTS = 20
MAX_NAME = 60
SAFE_NAME = re.compile(r"[^A-Za-z0-9 .+#_-]")
VERSION = re.compile(r"\d[A-Za-z0-9.+_-]{0,30}")

# Server header product -> stored name. The first word of the header is the product, "/" separates its version.
SERVER_PRODUCTS = {
    "nginx": "nginx", "apache": "Apache HTTP Server", "microsoft-iis": "Microsoft IIS", "openresty": "OpenResty",
    "litespeed": "LiteSpeed", "caddy": "Caddy", "gunicorn": "Gunicorn", "kestrel": "Kestrel", "tomcat": "Apache Tomcat", "apache-coyote": "Apache Tomcat", "apache tomcat": "Apache Tomcat",
    "jetty": "Jetty", "lighttpd": "lighttpd", "envoy": "Envoy", "traefik": "Traefik", "haproxy": "HAProxy",
    "netlify": "Netlify", "vercel": "Vercel", "cloudflare": "Cloudflare", "cloudfront": "Amazon CloudFront",
    "amazons3": "Amazon S3", "github.com": "GitHub Pages", "akamaighost": "Akamai", "fastly": "Fastly",
    "varnish": "Varnish", "gws": "Google Web Server", "awselb": "AWS Elastic Load Balancing", "heroku": "Heroku",
}
POWERED_BY_PRODUCTS = {
    "php": "PHP", "asp.net": "ASP.NET", "express": "Express", "next.js": "Next.js", "craft cms": "Craft CMS",
    "seomatic": "SEOmatic", "wp engine": "WP Engine", "phusion passenger": "Phusion Passenger", "servd": "Servd",
    "laravel": "Laravel", "drupal": "Drupal", "plesk": "Plesk", "nuxt": "Nuxt.js", "django": "Django",
}
# Tags are found first with a pattern that cannot run past the next '<' and then read attribute by attribute: a page full of
# '<meta ' with no '>' used to make the one-pattern forms quadratic, and the scanned host controls the page.
_META_TAG_RE = re.compile(r"<meta\b[^<>]{0,2000}>", re.IGNORECASE)
_GENERATOR_NAME_RE = re.compile(r"""\bname=["']generator["']""", re.IGNORECASE)
_CONTENT_ATTR_RE = re.compile(r"""\bcontent=["']([^"']{1,120})["']""", re.IGNORECASE)


def generator_content(text):
    """The ``content`` of the first ``<meta name="generator">`` tag, or ""."""
    for tag in _META_TAG_RE.findall(text or ""):
        if _GENERATOR_NAME_RE.search(tag):
            content = _CONTENT_ATTR_RE.search(tag)
            if content:
                return content.group(1)
    return ""


# page markers: (regex, name, source)
BODY_MARKERS = (
    (re.compile(r"__NEXT_DATA__|/_next/static/"), "Next.js", "page:_next"),
    (re.compile(r"/_nuxt/"), "Nuxt.js", "page:_nuxt"),
    (re.compile(r"/wp-content/|/wp-includes/"), "WordPress", "page:wp-content"),
    (re.compile(r"Drupal\.settings|/sites/default/files/"), "Drupal", "page:drupal"),
    (re.compile(r"cdn\.shopify\.com"), "Shopify", "page:shopify-cdn"),
    (re.compile(r"/static/CACHE/|csrfmiddlewaretoken"), "Django", "page:django"),
    (re.compile(r"(?:href|src|action)=[\"'][^\"'\s]*\.php(?:[?#\"'])", re.IGNORECASE), "PHP", "page:.php link"),
)


def _clean(name):
    return SAFE_NAME.sub("", name).strip()[:MAX_NAME]


def _versioned(name, version):
    name = _clean(name)
    if not name:
        return ""
    found = VERSION.match(version or "")
    return f"{name}:{found.group(0)}" if found else name


def _parse_products(value, table, source):
    """Entries of a Server or X-Powered-By style header: "PHP/8.2.30", "nginx/1.25.3 (Ubuntu)", "Craft CMS"."""
    out = []
    for part in re.split(r",", value or ""):
        part = part.strip()
        if not part:
            continue
        head = re.split(r"[ (]", part, maxsplit=1)[0] if "/" in part.split(" ")[0] else part
        product, _, version = head.partition("/")
        key = product.strip().lower()
        if key in table:
            out.append((_versioned(table[key], version), source))
        elif source == "header:x-powered-by" and key and not SAFE_NAME.search(product) and len(product.strip()) <= 30:
            out.append((_versioned(product, version), source))  # an unlisted product is still what the site says it runs
    return out


def from_response(server="", powered_by="", body="", content_type="", scripts=(), script_bodies=()):
    """``[{'name', 'source'}]`` for one response, de-duplicated, at most MAX_FINGERPRINTS, in the order found. ``scripts`` are the
    script URLs the page loads and ``script_bodies`` the text of ones read from the same host."""
    found = []
    found += _parse_products(server, SERVER_PRODUCTS, "header:server")
    found += _parse_products(powered_by, POWERED_BY_PRODUCTS, "header:x-powered-by")
    text = body or ""
    if text and (not content_type or "html" in content_type):
        value = generator_content(text).strip()
        if value:
            product = re.match(r"([A-Za-z][A-Za-z0-9 .!+_-]*?)(?:[ /]+(\d[\w.+-]*))?(?:\s|$|[-(,])", value + " ")
            if product:
                found.append((_versioned(product.group(1).rstrip(" .!-"), product.group(2) or ""), "meta:generator"))
        for pattern, name, source in BODY_MARKERS:
            if pattern.search(text):
                found.append((name, source))
        angular = ANGULAR_ATTR.search(text)
        if angular:
            found.append((_versioned("Angular", angular.group(1)), "page:ng-version"))
    found += from_script_urls(scripts)
    for script_text in script_bodies:
        found += from_script_body(script_text)
    out, seen = [], set()
    for name, source in found:
        if name and name.lower() not in seen:
            seen.add(name.lower())
            out.append({"name": name, "source": source})
    # a versioned name replaces the same product listed without one ("PHP" from a link, "PHP:8.2.30" from a header)
    versioned = {f["name"].split(":")[0].lower() for f in out if ":" in f["name"]}
    out = [f for f in out if ":" in f["name"] or f["name"].lower() not in versioned]
    return out[:MAX_FINGERPRINTS]


# JavaScript libraries, read from the names of the scripts a page loads (no request) and from the comment banner at the top of a
# script the same host serves. Old versions of these are among the most common findings on a public site.
LIB_NAMES = {"jquery": "jQuery", "bootstrap": "Bootstrap", "angular": "AngularJS", "angularjs": "AngularJS", "react": "React",
             "react-dom": "React", "vue": "Vue.js", "lodash": "Lodash", "moment": "Moment.js", "underscore": "Underscore.js",
             "swiper": "Swiper", "datatables": "DataTables"}
_SCRIPT_TAG_RE = re.compile(r"<script\b[^<>]{0,2000}>", re.IGNORECASE)
_SRC_ATTR_RE = re.compile(r"""\bsrc=["']([^"'>\s]{1,300})["']""", re.IGNORECASE)


def script_srcs(body):
    """The ``src`` of every ``<script>`` tag that has one, in page order."""
    found = []
    for tag in _SCRIPT_TAG_RE.findall(body or ""):
        src = _SRC_ATTR_RE.search(tag)
        if src:
            found.append(src.group(1))
    return found
_LIB_FILE = re.compile(r"(?:^|[/@._-])(jquery|bootstrap|angular(?:js)?|react(?:-dom)?|vue|lodash|moment|underscore|swiper|datatables)"
                       r"(?:[.-]min|[.-]slim|[.-]bundle)*?[-@./ ]v?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
_LIB_QUERY = re.compile(r"/(jquery|bootstrap|angular(?:js)?|react|vue|lodash|moment|underscore)[^/?]*\.js\?(?:[^#]*&)?(?:ver|v|version)=(\d+\.\d+(?:\.\d+)?)",
                        re.IGNORECASE)
_BANNER = (
    (re.compile(r"jQuery(?: JavaScript Library)? v(\d+\.\d+(?:\.\d+)?)"), "jQuery"),
    (re.compile(r"Bootstrap v(\d+\.\d+\.\d+)"), "Bootstrap"),
    (re.compile(r"AngularJS v(\d+\.\d+\.\d+)"), "AngularJS"),
    (re.compile(r"@license React v(\d+\.\d+\.\d+)|React v(\d+\.\d+\.\d+)"), "React"),
    (re.compile(r"Vue\.js v(\d+\.\d+\.\d+)"), "Vue.js"),
    (re.compile(r"(?:lodash|Lodash)[^\n]{0,40}?(\d+\.\d+\.\d+)"), "Lodash"),
    (re.compile(r"//! version\s*:\s*(\d+\.\d+\.\d+)[^\n]{0,80}\n//! (?:license|locale)|Moment\.js[^\n]{0,20}?(\d+\.\d+\.\d+)"), "Moment.js"),
    (re.compile(r"Underscore\.js (\d+\.\d+\.\d+)"), "Underscore.js"),
)
ANGULAR_ATTR = re.compile(r"ng-version=[\"'](\d+\.\d+\.\d+)[\"']")


def script_sources(body, page_url, limit=4):
    """``(all script URLs, same-host ones to read)`` of a page: absolute URLs, at most ``limit`` to fetch. A script on another
    host (a CDN) is identified by its name only, never fetched."""
    from urllib.parse import urljoin, urlsplit
    page = urlsplit(page_url or "")
    every, local = [], []
    for src in script_srcs(body):
        try:
            absolute = urljoin(page_url, src.strip())
            parts = urlsplit(absolute)
        except ValueError:
            continue
        if parts.scheme not in ("http", "https") or not parts.hostname or absolute in every:
            continue
        every.append(absolute)
        if parts.hostname.lower() == (page.hostname or "").lower() and parts.port == page.port and len(local) < limit:
            local.append(absolute)
    return every[:40], local


def from_script_urls(urls):
    """``[(name, source)]`` from the names of the scripts a page loads: ``jquery-3.4.1.min.js``, ``/ajax/libs/vue/3.3.4/vue.js``,
    ``jquery.min.js?ver=3.4.1``."""
    out = []
    for url in urls:
        match = _LIB_FILE.search(url) or _LIB_QUERY.search(url)
        if match:
            name = LIB_NAMES.get(match.group(1).lower())
            if name:
                out.append((_versioned(name, match.group(2)), "script:name"))
    return out


def from_script_body(text):
    """``[(name, source)]`` from the comment banner at the top of one script (first 4 KB)."""
    head = (text or "")[:4096]
    out = []
    for pattern, name in _BANNER:
        match = pattern.search(head)
        if match:
            version = next((g for g in match.groups() if g), "")
            if version:
                out.append((_versioned(name, version), "script:banner"))
    return out


def extend(found, pairs):
    """``found`` (the ``[{'name', 'source'}]`` list) with more ``(name, source)`` pairs added: a name already there is left alone, a
    versioned name replaces the same product listed without one, and the list stays within MAX_FINGERPRINTS."""
    out = list(found or [])
    seen = {f["name"].lower() for f in out}
    for name, source in pairs:
        if name and name.lower() not in seen:
            seen.add(name.lower())
            out.append({"name": name, "source": source})
    versioned = {f["name"].split(":")[0].lower() for f in out if ":" in f["name"]}
    out = [f for f in out if ":" in f["name"] or f["name"].lower() not in versioned]
    return out[:MAX_FINGERPRINTS]


CATEGORIES = {
    "language": ("php", "python", "ruby", "java", "node.js", "asp.net", "perl"),
    "web server": ("nginx", "apache http server", "apache", "microsoft iis", "openresty", "litespeed", "caddy", "gunicorn", "kestrel",
                   "apache tomcat", "jetty", "lighttpd", "envoy", "traefik", "haproxy", "google web server", "varnish"),
    "cdn": ("cloudflare", "amazon cloudfront", "akamai", "fastly"),
    "hosting": ("netlify", "vercel", "github pages", "heroku", "amazon s3", "aws elastic load balancing", "wp engine", "servd",
                "firebase hosting", "render"),
    "cms": ("wordpress", "drupal", "craft cms", "joomla", "shopify", "datocms", "ghost", "contentful", "strapi", "typo3"),
    "javascript library": ("jquery", "bootstrap", "angularjs", "lodash", "moment.js", "underscore.js", "datatables", "swiper"),
    "framework": ("next.js", "nuxt.js", "django", "laravel", "express", "react", "vue.js", "angular", "svelte", "symfony", "rails"),
    "analytics": ("google tag manager", "google analytics", "hotjar", "segment"),
}
_CATEGORY_OF = {name: category for category, names in CATEGORIES.items() for name in names}


def categorize(name):
    """The kind of technology a stored name is ('web server', 'language', 'cms', 'cdn', 'hosting', 'framework', 'analytics'),
    or '' for one that is not in the table."""
    base = re.sub(r"[-_]+", " ", (name or "").split(":")[0].strip().lower())
    return _CATEGORY_OF.get(base, "")
