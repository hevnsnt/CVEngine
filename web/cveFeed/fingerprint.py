"""What one HTTP response says it runs, read from what the route check already fetched: the Server and X-Powered-By headers, the
generator meta tag, and a few markers in the sampled page. Pure functions, no network.

Names use the form the rest of the scanner stores, "Name" or "Name:version", so the correlation engine reads them like any other
detected technology. A target controls its own headers and pages, so every name is cut to a safe alphabet and length and the list
is capped; the evidence for each says where it came from."""
import re

MAX_FINGERPRINTS = 12
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
GENERATOR_RE = re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]*content=[\"']([^\"']{1,120})[\"']"
                          r"|<meta[^>]+content=[\"']([^\"']{1,120})[\"'][^>]*name=[\"']generator[\"']", re.IGNORECASE)
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


def from_response(server="", powered_by="", body="", content_type=""):
    """``[{'name', 'source'}]`` for one response, de-duplicated, at most MAX_FINGERPRINTS, in the order found."""
    found = []
    found += _parse_products(server, SERVER_PRODUCTS, "header:server")
    found += _parse_products(powered_by, POWERED_BY_PRODUCTS, "header:x-powered-by")
    text = body or ""
    if text and (not content_type or "html" in content_type):
        match = GENERATOR_RE.search(text)
        if match:
            value = (match.group(1) or match.group(2) or "").strip()
            product = re.match(r"([A-Za-z][A-Za-z0-9 .!+_-]*?)(?:[ /]+(\d[\w.+-]*))?(?:\s|$|[-(,])", value + " ")
            if product:
                found.append((_versioned(product.group(1).rstrip(" .!-"), product.group(2) or ""), "meta:generator"))
        for pattern, name, source in BODY_MARKERS:
            if pattern.search(text):
                found.append((name, source))
    out, seen = [], set()
    for name, source in found:
        if name and name.lower() not in seen:
            seen.add(name.lower())
            out.append({"name": name, "source": source})
    # a versioned name replaces the same product listed without one ("PHP" from a link, "PHP:8.2.30" from a header)
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
    "framework": ("next.js", "nuxt.js", "django", "laravel", "express", "react", "vue.js", "angular", "svelte", "symfony", "rails"),
    "analytics": ("google tag manager", "google analytics", "hotjar", "segment"),
}
_CATEGORY_OF = {name: category for category, names in CATEGORIES.items() for name in names}


def categorize(name):
    """The kind of technology a stored name is ('web server', 'language', 'cms', 'cdn', 'hosting', 'framework', 'analytics'),
    or '' for one that is not in the table."""
    base = re.sub(r"[-_]+", " ", (name or "").split(":")[0].strip().lower())
    return _CATEGORY_OF.get(base, "")
