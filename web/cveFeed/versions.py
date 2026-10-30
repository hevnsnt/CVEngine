"""Reading versions out of what a service says about itself: Server and X-* headers, generator tags and CPE strings. Pure
functions, no network and no database, so every rule is tested on real header samples.

A version is only ever returned when the text states one. A header that names a product without a number ("nginx", "Apache"),
a version that belongs to a protocol and not the product ("Apache-Coyote/1.1") or a banner behind an edge that rewrites it are
returned without a version: the caller records the product as a lead for a probe, never a guess.

Names use the form the rest of the scanner stores, "Name" or "Name:version" (see ``correlation.split_name_version``)."""
import re

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

MAX_COMPONENTS = 8
EDGE_PRODUCTS = frozenset({'Cloudflare', 'Amazon CloudFront', 'Akamai', 'Fastly', 'Netlify', 'Vercel', 'GitHub Pages', 'Amazon S3',
                           'AWS Elastic Load Balancing', 'Heroku'})
MAX_NAME = 40
# the comment after a product in a Server header names the distribution that built it: "nginx/1.24.0 (Ubuntu)"
DISTRO_WORDS = (('ubuntu', 'ubuntu'), ('debian', 'debian'), ('centos', 'centos'), ('red hat', 'rhel'), ('rhel', 'rhel'),
                ('fedora', 'fedora'), ('alpine', 'alpine'), ('amazon', 'amazon'), ('suse', 'suse'), ('rocky', 'rocky'),
                ('almalinux', 'almalinux'), ('oracle', 'oracle'), ('freebsd', 'freebsd'), ('win64', 'windows'), ('win32', 'windows'))
# products whose "/x.y" is the version of a protocol or connector, not of the software: never a version of the product
PROTOCOL_VERSIONS = frozenset({'apache-coyote', 'microsoft-httpapi', 'microsoft-iis-httpapi', 'tornadoserver-protocol'})
# extra software that an Apache or nginx Server header lists after the web server itself (modules and runtimes)
MODULE_PRODUCTS = {
    'openssl': 'OpenSSL', 'php': 'PHP', 'python': 'Python', 'perl': 'Perl', 'ruby': 'Ruby', 'mod_wsgi': 'mod_wsgi', 'mod_ssl': 'mod_ssl',
    'mod_perl': 'mod_perl', 'mod_fcgid': 'mod_fcgid', 'mod_jk': 'mod_jk', 'mod_python': 'mod_python', 'mod_security': 'ModSecurity',
    'mod_qos': 'mod_qos', 'mod_bwlimited': 'mod_bwlimited', 'phusion_passenger': 'Phusion Passenger', 'passenger': 'Phusion Passenger',
    'proxy_html': 'proxy_html', 'dav': 'mod_dav', 'svn': 'mod_dav_svn', 'jboss': 'JBoss', 'wildfly': 'WildFly',
}
_TOKEN = re.compile(r"([A-Za-z][A-Za-z0-9_.+-]*)(?:/([^\s()]+))?|\(([^)]{0,80})\)")
_JETTY = re.compile(r"\bJetty\((\d[\w.-]{0,30})\)")


_STATED = re.compile(r"[vV]?(\d[A-Za-z0-9.+_-]{0,30})")


def _version(text):
    """The version a text states, or ''. A bare major ("Drupal 10", "PHP/8") is no version: it parses as (10,) and would sit inside every
    "before 10.2" range as if it had been read, so it is left as an unstated version. A leading "v" (Perl/v5.16.3) is not part of it."""
    found = _STATED.match(text or '')
    number = found.group(1).rstrip('.') if found else ''
    return number if '.' in number else ''


def _stored(name, version):
    name = SAFE_NAME.sub('', name).strip()[:MAX_NAME]
    return f'{name}:{version}' if name and version else name


def distro_of(comment):
    """The distribution a Server header comment names ("Ubuntu", "CentOS", "Red Hat Enterprise Linux"), or ''."""
    lowered = (comment or '').lower()
    return next((distro for word, distro in DISTRO_WORDS if word in lowered), '')


def parse_server_header(value):
    """``{'components': [{'name', 'version', 'product'}], 'distro': str}`` for one Server header value.

    The first product is the web server; later ``Name/version`` tokens are modules and runtimes (OpenSSL, PHP, mod_wsgi) and are kept
    too: an Apache header lists the PHP and OpenSSL versions the site runs. ``name`` is the stored form ("Apache HTTP Server:2.4.41"),
    ``product`` the bare product. A product with no stated version is returned without one; a protocol version is never one."""
    text = re.sub(r'\bApache[ -]Tomcat\b', 'Tomcat', str(value or '')[:500])  # "Apache Tomcat/9.0.50" is Tomcat, not the Apache web server
    components, distro, seen = [], '', set()
    jetty = _JETTY.search(text)
    if jetty:
        components.append({'name': _stored('Jetty', _version(jetty.group(1))), 'product': 'Jetty', 'version': _version(jetty.group(1))})
        seen.add('jetty')
        text = _JETTY.sub('Jetty', text)
    for index, match in enumerate(_TOKEN.finditer(text)):
        token, version, comment = match.groups()
        if comment is not None:
            distro = distro or distro_of(comment)
            continue
        key = token.lower()
        if key in seen:
            continue
        if key in PROTOCOL_VERSIONS:
            product = SERVER_PRODUCTS.get(key) or SERVER_PRODUCTS.get(key.split('-')[0])
            version = ''
        else:
            product = SERVER_PRODUCTS.get(key) or (MODULE_PRODUCTS.get(key) if components or jetty else None)
        if not product and version and components and re.match(r'^mod_[a-z0-9_]{1,26}$', key):
            product = token  # an Apache module that states a version: "mod_foo/1.2"
        # any other name after the web server is the host's own say-so ("nginx/1.25.3 Log4j/2.14.1 Struts/2.3.30"): it is not a technology
        if not product:
            continue
        seen.add(key)
        number = _version(version)
        components.append({'name': _stored(product, number), 'product': product, 'version': number})
        if product in EDGE_PRODUCTS or len(components) >= MAX_COMPONENTS:
            break  # what follows an edge's name describes the edge's own answer, not the software behind it
    return {'components': components, 'distro': distro}


# ----------------------------------------------------------------------------- other headers

_VIA = re.compile(r"\(([A-Za-z][A-Za-z0-9 ._-]{1,30})/(\d[\w.]{0,20})\)")
_GENERATOR_HEADER = re.compile(r"^([A-Za-z][A-Za-z0-9 .!+_-]*?)(?:[ /]+(\d[\w.+-]*))?(?:\s|$|[-(,;])")
# header -> (product, how the version is read). A header whose mere presence names the product has no version.
HEADER_FACTS = (
    ('x-aspnet-version', 'ASP.NET', 'value'),
    ('x-aspnetmvc-version', 'ASP.NET MVC', 'value'),
    ('x-drupal-cache', 'Drupal', None),
    ('x-drupal-dynamic-cache', 'Drupal', None),
    ('x-umbraco-version', 'Umbraco', 'value'),
    ('x-magento-tags', 'Magento', None),
    ('x-magento-cache-debug', 'Magento', None),
    ('x-nextjs-cache', 'Next.js', None),
    ('x-nextjs-matched-path', 'Next.js', None),
    ('x-nextjs-prerender', 'Next.js', None),
    ('x-pingback', 'WordPress', None),
    ('x-litespeed-cache', 'LiteSpeed', None),
)
# headers kept as host metadata (never cookies or anything that can carry a session): short, clipped, lowercase names
KEPT_HEADERS = ('server', 'x-powered-by', 'via', 'x-generator', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-drupal-cache', 'x-umbraco-version', 'x-magento-tags', 'x-magento-cache-debug',
                'x-nextjs-cache', 'x-nextjs-matched-path', 'x-vercel-id', 'x-nf-request-id', 'cf-ray', 'cf-cache-status', 'x-amz-cf-id',
                'x-amz-cf-pop', 'x-served-by', 'x-fastly-request-id', 'x-akamai-transformed', 'x-azure-ref', 'x-sucuri-id', 'x-iinfo',
                'x-envoy-upstream-service-time', 'x-cache', 'x-pingback', 'link', 'x-litespeed-cache', 'strict-transport-security',
                'content-security-policy', 'x-frame-options', 'x-content-type-options', 'x-xss-protection', 'referrer-policy',
                'permissions-policy', 'x-robots-tag', 'content-type', 'x-request-id', 'x-kubernetes-pf-flowschema-uid', 'x-powered-cms')
HEADER_CLIP = 200
# a header that names the edge in front of the host: the Server header, Via and these vendor headers describe the edge, not the origin
EDGE_HEADERS = (
    ('cf-ray', 'Cloudflare'), ('cf-cache-status', 'Cloudflare'), ('x-amz-cf-id', 'Amazon CloudFront'), ('x-amz-cf-pop', 'Amazon CloudFront'),
    ('x-akamai-transformed', 'Akamai'), ('x-fastly-request-id', 'Fastly'), ('x-azure-ref', 'Azure Front Door'),
    ('x-sucuri-id', 'Sucuri'), ('x-iinfo', 'Imperva'), ('x-vercel-id', 'Vercel'), ('x-nf-request-id', 'Netlify'),
)
EDGE_SERVERS = {'cloudflare': 'Cloudflare', 'cloudfront': 'Amazon CloudFront', 'akamaighost': 'Akamai', 'akamainetstorage': 'Akamai',
                'fastly': 'Fastly', 'vercel': 'Vercel', 'netlify': 'Netlify', 'sucuri/cloudproxy': 'Sucuri', 'awselb/2.0': 'AWS ELB'}


def keep_headers(headers):
    """The headers worth keeping as metadata, lowercase names, each clipped. ``headers`` is any mapping or ``(name, value)`` pairs; a
    repeated header keeps its first value. Cookies are never kept."""
    items = headers.items() if hasattr(headers, 'items') else headers
    out = {}
    for name, value in items or ():
        key = str(name).lower().strip()
        if key in KEPT_HEADERS and key not in out:
            out[key] = re.sub(r'\s+', ' ', str(value)).strip()[:HEADER_CLIP]
    return out


def edges_from_headers(headers):
    """The CDN, WAF or hosting edges these response headers name, as a sorted list of provider names. The Server and Via headers of such a
    response describe the edge, so the origin software behind it is not visible from here."""
    lowered = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    found = {provider for header, provider in EDGE_HEADERS if header in lowered}
    server = lowered.get('server', '').strip().lower()
    found |= {provider for prefix, provider in EDGE_SERVERS.items() if server.startswith(prefix)}
    via = lowered.get('via', '').lower()
    for word, provider in (('cloudfront', 'Amazon CloudFront'), ('varnish', 'Varnish cache'), ('akamai', 'Akamai'), ('fastly', 'Fastly')):
        if word in via and provider != 'Varnish cache':  # a Varnish cache can be the site's own
            found.add(provider)
    return sorted(found)


def parse_headers(headers):
    """``[{'name', 'source'}]`` for everything the response headers state: the Server header's products and modules, X-Powered-By, the
    ASP.NET version headers, X-Generator, Via and headers whose presence names a framework. A hit that states no version has none."""
    lowered = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    out = []
    server = parse_server_header(lowered.get('server', ''))
    out += [(c['name'], 'header:server') for c in server['components']]
    for part in lowered.get('x-powered-by', '').split(','):
        product, _, version = part.strip().partition('/')
        key = product.strip().lower()
        if key in POWERED_BY_PRODUCTS:
            out.append((_stored(POWERED_BY_PRODUCTS[key], _version(version)), 'header:x-powered-by'))
        elif key and not SAFE_NAME.search(product) and len(product.strip()) <= 30:
            out.append((_stored(product.strip(), _version(version)), 'header:x-powered-by'))
    for header, product, how in HEADER_FACTS:
        if header in lowered:
            out.append((_stored(product, _version(lowered[header]) if how == 'value' else ''), f'header:{header}'))
    for match in _VIA.finditer(lowered.get('via', '')):
        out.append((_stored(match.group(1), _version(match.group(2))), 'header:via'))
    generator = _GENERATOR_HEADER.match(lowered.get('x-generator', '').strip() + ' ')
    if generator:
        out.append((_stored(generator.group(1).rstrip(' .!-'), _version(generator.group(2) or '')), 'header:x-generator'))
    if 'rel="https://api.w.org/"' in lowered.get('link', '').replace("'", '"'):
        out.append(('WordPress', 'header:link'))
    seen, result = set(), []
    for name, source in out:
        if name and name.lower() not in seen:
            seen.add(name.lower())
            result.append({'name': name, 'source': source})
    versioned = {r['name'].split(':')[0].lower() for r in result if ':' in r['name']}
    return [r for r in result if ':' in r['name'] or r['name'].lower() not in versioned][:MAX_COMPONENTS * 2]


# ----------------------------------------------------------------------------- generator tags

_META = re.compile(r"<meta\b[^<>]{0,2000}>", re.IGNORECASE)
_NAME_GEN = re.compile(r"""\bname=["']generator["']""", re.IGNORECASE)
_CONTENT = re.compile(r"""\bcontent=["']([^"']{1,160})["']""", re.IGNORECASE)
_GENERATOR_VALUE = re.compile(r"^(?:Powered by\s+)?([A-Za-z][A-Za-z0-9 .!+_-]*?)(?:[ /]+(?:ver:)?v?(\d[\w.+-]*))?(?:\s|$|[-(,;])")
# plugin and theme markers that WordPress pages carry in comments: "This site is optimized with the Yoast SEO plugin v21.7"
_PLUGIN_COMMENT = re.compile(r"<!--[^>]{0,200}?\b(Yoast SEO|All in One SEO(?: Pro)?|Rank Math(?: SEO)?|WP Rocket|W3 Total Cache|LiteSpeed Cache"
                             r"|Site Kit by Google|Jetpack)\b[^>]{0,120}?\b(?:plugin\s+)?v?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
MAX_GENERATORS = 8


def parse_generator(value):
    """``(product, version)`` of one generator value ("WordPress 6.4.2", "Elementor 3.18.3; features: ...", "Joomla! - Open Source ..."), or None."""
    parsed = _GENERATOR_VALUE.match(str(value or '').strip() + ' ')
    return (parsed.group(1).rstrip(' .!-'), parsed.group(2) or '') if parsed else None


def generator_tags(html):
    """``[(product, version)]`` for every ``<meta name="generator">`` tag (a WordPress page carries several: the core, a page builder, a
    shop plugin) and for the plugin comments a few popular plugins print. The version is '' when the tag states none."""
    found = []
    for tag in _META.findall(html or ''):
        if not _NAME_GEN.search(tag):
            continue
        content = _CONTENT.search(tag)
        parsed = parse_generator(content.group(1)) if content else None
        if parsed:
            found.append(parsed)
        if len(found) >= MAX_GENERATORS:
            break
    for match in _PLUGIN_COMMENT.finditer((html or '')[:200_000]):
        found.append((match.group(1), match.group(2)))
    return found[:MAX_GENERATORS * 2]


# ----------------------------------------------------------------------------- technology names

_CPE_PART = re.compile(r"^cpe:(?:/|2\.3:)a:([^:]*):([^:]*)(?::([^:]*))?", re.IGNORECASE)


def normalize_technology(name):
    """A scanner's technology string in the stored form: "Bootstrap:v3.3.7" loses its "v", a CPE ("cpe:/a:apache:http_server:2.4.41",
    what Shodan's InternetDB hands bbot) becomes "http_server:2.4.41" so the product name and version are separate like any other
    technology, and a trailing ":" goes. Anything else is returned stripped. Pure."""
    text = str(name or '').strip()
    cpe = _CPE_PART.match(text)
    if cpe:
        product = cpe.group(2).replace('_', ' ').strip()
        version = cpe.group(3) or ''
        version = '' if version in ('*', '-') else version
        return f'{product}:{version}' if product and version else product
    base, sep, version = text.rpartition(':')
    if sep and version[:1] in ('v', 'V') and version[1:2].isdigit():
        return f'{base.strip()}:{version[1:].strip()}'
    return text.rstrip(':').strip()
