"""The catalogue of version sources: where a product, a platform or a language runtime states its exact version to anyone who asks, and how
to read it. Pure data and pure readers: nothing here touches the network or the database (``cveFeed.version_sources`` plans, dispatches,
stores and correlates; the Sentinel kind ``version_read`` only fetches).

Why a catalogue. cvENGINE missed CVEs in components it never put a version on, although Grafana, Jira, Kibana, Vault, Docker, Kubernetes or a
Prometheus exporter say their exact version anonymously. Each such place is one ``Source`` entry below. Adding a product is one entry and a
test (``tests/test_version_sources.py``, a real-shaped answer and a wrong-shaped one); the Sentinel needs no release, because it only runs
the GETs the server lists and hands back the parts of each answer the entry names (``Request``).

An entry is asked only of a host already identified as its product (``leads``: a technology or a port product) or on a port whose number
belongs to it and whose service the port scan left generic (``ports``): never a sweep of every path on every host. Every request is a GET of a fixed
path; nothing is sent that a browser would not send, no credential ever (no default login, no token).

Reading an answer. A reader accepts only the exact shape its source answers with (the JSON fields it must have, of the right types, and a
version that looks like one), so a login page, a catch-all page, an error or another product's answer never gives a reading. An entry whose
answer shape is thin (Gitea's one-field ``{"version": ...}``, SonarQube's plain-text number, a ``*_info`` metric) also asks a control path
that cannot exist next to it: when the control path gives a reading too, the host answers every path that way and nothing is read
(``cvengine_scanner.soft404`` compares whole bodies, which never leave the Sentinel here, so the same reader is the comparison).

A reading is ``{component, label, kind, version, confidence, line_only, evidence, url, source}``:

  kind        ``product`` (an application or platform: stored as a technology too, so correlation matches it like any product, version only)
              or ``runtime`` (a language runtime: Python, Go, Node.js, PHP, Ruby, .NET Framework, Erlang/OTP; matched by the runtime's own
              vendor and product in the CVE record, ``RUNTIMES``), and ``java`` (a Java runtime reading for ``cveFeed.java_runtime``)
  confidence  ``exact`` (the software states its own version), ``inferred`` (a line or a presence that follows from what it states: an ASP.NET
              build's .NET Framework line, Python behind gunicorn), ``weak`` (a presence that may be something else): the Java runtime's rules
  line_only   only a line is known (``4.8``, OTP ``26``): never a version inside a range, at most a version-unknown candidate

Sources dropped (not anonymous, or no reliable anonymous answer; see docs/PIPELINE.md#version-sources): GitLab ``/api/v4/version`` (needs a
token; the sign-in page's ``gon.version`` is published only to signed-in users, ``/help`` hides the release from anonymous callers, and
``gon.revision`` or the webpack manifest's hash name a commit or a build that no table here maps to a release), RabbitMQ ``/api/overview`` (the management API always authenticates; RabbitMQ and its Erlang/OTP line are read from its Prometheus
endpoint instead), Keycloak (current releases state no version anonymously; the resource path carries a random hash), Polarion (no documented
anonymous source), and the kubelet (its ``/healthz`` may be served outside the authorization filter, so it cannot tell an open kubelet, and
``/pods`` is not asked).
"""
import re
from dataclasses import dataclass, field

MAX_REQUESTS = 4          # a read entry's requests, the control path included (the contract's bound)
MAX_FIELDS = 12
MAX_EVIDENCE = 300
CONTROL_PREFIX = 'cvengine-control-'
# the headers every request also asks for: the passive readers run over every answer (a Server header names Nexus, X-Jenkins Jenkins ...)
COMMON_HEADERS = ('server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-jenkins')
CONFIDENCES = ('exact', 'inferred', 'weak')
DIGEST_KIND = 'version_digest'  # the Sentinel kind of an entry with a digest read (contract 8; cveFeed.edge_builds)
ROWS_KIND = 'version_rows'      # the Sentinel kind of an entry with a rows read (contract 9): only the named version rows of a status page

_VERSION = re.compile(r'^v?(\d{1,4}(?:\.\d{1,9}){1,3})(?:[-+_.~]([0-9A-Za-z][0-9A-Za-z.+~_-]{0,40}))?$')
_CONTROL = re.compile(r'[\x00-\x1f\x7f-\x9f  ​-‏‪-‮﻿]+')


def clip(text, limit=MAX_EVIDENCE):
    """Untrusted text from a host as a reading carries it: control and bidirectional characters removed, whitespace collapsed, clipped."""
    return re.sub(r'\s+', ' ', _CONTROL.sub(' ', str(text if text is not None else ''))).strip()[:limit]


def version_of(text, keep_suffix=True):
    """The version a value states (``10.2.3``, ``v1.27.3-eks-a5565ad`` -> ``1.27.3-eks-a5565ad``), or ''. A bare major (``17``) is no version."""
    found = _VERSION.match(clip(text, 80))
    if not found:
        return ''
    return found.group(1) + (f'-{found.group(2)}' if keep_suffix and found.group(2) else '')


@dataclass(frozen=True)
class Request:
    path: str
    read: str = 'json'                 # json | text | metrics | headers | digest | rows (cvengine_scanner.probes.version_read; digest: contract 8,
                                       # rows: contract 9, ``fields`` then names the rows)
    fields: tuple = ()
    find: str = ''
    headers: tuple = ()                # the response headers to return instead of COMMON_HEADERS (at most 6: ETag and Last-Modified of an asset)

    def spec(self, path=None):
        out = {'path': path or self.path, 'read': self.read, 'headers': list(self.headers or COMMON_HEADERS)}
        if self.fields:
            out['fields'] = list(self.fields)
        if self.find:
            out['find'] = self.find
        return out


@dataclass(frozen=True)
class Exposure:
    template: str
    name: str
    severity: int                      # 0 info, 1 low, 2 medium, 3 high, 4 critical (Vulnerability.severity)
    description: str
    impact: str
    remediation: str
    twins: tuple = ()                  # template check ids that already report the same exposure: then it is not filed twice
    rate: object = None                # rate(answers) -> the severity of what this answer shows is open, or None when it shows the door shut
                                       # (a key or a sign-in asked for): nothing is filed and an earlier finding is closed. Without it: ``severity``


@dataclass(frozen=True)
class Source:
    id: str
    label: str
    kind: str                          # product | platform | metrics | runtime: what the entry is about (the readings carry their own kind)
    requests: tuple
    reader: object                     # reader(answers) -> [reading]; ``answers`` aligned with ``requests``, None for a request without an answer
    leads: str = ''                    # a technology or port product matching this (case-insensitive) warrants the entry
    ports: tuple = ()                  # an open TCP port with one of these numbers, whose service the port scan left generic, warrants it too
    control: bool = False              # also ask a control path next to the first request (a thin answer shape)
    statuses: tuple = (200,)           # the statuses whose answer is read
    exposure: Exposure = None          # an anonymous answer of the right shape is itself a finding
    verified: str = ''                 # where the path and the answer shape were checked (vendor documentation or source)
    note: str = ''
    discovered: bool = False           # asked only at a page a scan already found on the host (``version_sources.discovered_pages``), never at
                                       # its own path: ``requests[0].path`` is a placeholder the found page's path replaces (``at_page``)
    servers: str = ''                  # the web frameworks (a port product: uvicorn, aiohttp, Node.js) the product runs on: on one of the entry's
                                       # own ``ports``, a service named one of these warrants it as a generic one would (``ai_servers.APP_SERVERS``)

    def lead_re(self):
        return re.compile(self.leads, re.I) if self.leads else None

    @property
    def task_kind(self):
        """The Sentinel kind that runs this entry: ``version_digest`` (contract 8) when a request reads a digest, ``version_rows`` (contract 9)
        when one reads rows, else ``version_read``."""
        if any(r.read == 'digest' for r in self.requests):
            return DIGEST_KIND
        return ROWS_KIND if any(r.read == 'rows' for r in self.requests) else 'version_read'

    def at_page(self, path):
        """This (``discovered``) entry asked at ``path``, a page a scan found on the host: the same entry with its first request moved there."""
        from dataclasses import replace
        return replace(self, requests=(replace(self.requests[0], path=path),) + tuple(self.requests[1:]))


# ----------------------------------------------------------------------------- reading helpers

def reading(component, label, version, kind='product', confidence='exact', line_only=False, evidence='', url='', source=''):
    return {'component': component, 'label': label, 'kind': kind, 'version': clip(version, 60), 'confidence': confidence,
            'line_only': bool(line_only), 'evidence': clip(evidence), 'url': clip(url, 300), 'source': source}


def _json(answer, statuses=(200,)):
    """The JSON fields of one answer, when it is an answer of one of ``statuses`` that parsed as a JSON object, else None."""
    if not isinstance(answer, dict) or answer.get('error') or answer.get('status') not in statuses:
        return None
    doc = answer.get('json')
    return doc if isinstance(doc, dict) else None


def _str(doc, key, limit=200):
    value = doc.get(key)
    return clip(value, limit) if isinstance(value, str) and value.strip() else ''


def _is(doc, key, kind):
    value = doc.get(key)
    if kind == 'object':
        return isinstance(value, dict) and value.get('type') == 'object'
    if kind == 'array':
        return isinstance(value, dict) and value.get('type') == 'array'
    if kind == 'bool':
        return isinstance(value, bool)
    if kind == 'num':
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if kind == 'str':
        return isinstance(value, str) and bool(value.strip())
    return key in doc


def _shape(doc, **kinds):
    return doc is not None and all(_is(doc, key.replace('__', '.'), kind) for key, kind in kinds.items())


def go_version(text):
    """The Go release a binary was built with (``go1.21.5`` -> ``1.21.5``), or ''. A devel build (``devel go1.22-...``) states none."""
    found = re.match(r'^go(\d+\.\d+(?:\.\d+)?)(?:rc\d+|beta\d+)?$', clip(text, 40))
    return found.group(1) if found else ''


def go_reading(text, url, source, evidence=''):
    version = go_version(text)
    return reading('go', 'Go', version, kind='runtime', evidence=evidence or f'built with {clip(text, 40)}', url=url, source=source) if version else None


# ----------------------------------------------------------------------------- readers, one per source

def read_jira(answers):
    doc = _json(answers[0])
    if not _shape(doc, version='str', versionNumbers='array', buildNumber='num'):
        return []
    if _str(doc, 'deploymentType').lower() == 'cloud':
        return []  # Atlassian's cloud: no installed version
    version = version_of(doc['version'], keep_suffix=False)
    return [reading('jira', 'Jira', version, evidence=f'serverInfo version {doc["version"]}, build {doc.get("buildNumber")}',
                    url='/rest/api/2/serverInfo', source='jira')] if version else []


APPLINK_TYPES = {'confluence': ('confluence', 'Confluence'), 'jira': ('jira', 'Jira'), 'stash': ('bitbucket', 'Bitbucket'),
                 'bamboo': ('bamboo', 'Bamboo'), 'crowd': ('crowd', 'Crowd'), 'fecru': ('fisheye', 'FishEye')}


def read_applinks(answers):
    """Atlassian's application links manifest (XML): ``<typeId>`` names the product, ``<version>`` its release."""
    answer = answers[0]
    if not isinstance(answer, dict) or answer.get('error') or answer.get('status') != 200:
        return []
    text = str(answer.get('text') or '')
    if not re.match(r'^(?:<\?xml[^>]{0,100}\?>\s*)?<manifest>', text):
        return []
    type_id = re.search(r'<typeId>([a-z]{1,20})</typeId>', text)
    version = re.search(r'<version>([0-9][0-9A-Za-z.+_-]{0,40})</version>', text)
    if not (type_id and version) or type_id.group(1) not in APPLINK_TYPES:
        return []
    component, label = APPLINK_TYPES[type_id.group(1)]
    value = version_of(version.group(1), keep_suffix=False)
    return [reading(component, label, value, evidence=f'applinks manifest typeId {type_id.group(1)} version {version.group(1)}',
                    url='/rest/applinks/1.0/manifest', source='atlassian-applinks')] if value else []


def read_grafana(answers):
    doc = _json(answers[0])
    if not _shape(doc, version='str', database='str'):
        return []
    version = version_of(doc['version'])
    return [reading('grafana', 'Grafana', version, evidence=f'api/health version {doc["version"]}, database {doc["database"]}',
                    url='/api/health', source='grafana')] if version else []


def read_kibana(answers):
    doc = _json(answers[0])
    if not _shape(doc, version__number='str', status='object'):
        return []  # an unauthenticated status is redacted to the overall level and states no version
    version = version_of(doc['version.number'], keep_suffix=False)
    return [reading('kibana', 'Kibana', version, evidence=f'api/status version.number {doc["version.number"]}', url='/api/status',
                    source='kibana')] if version else []


def read_sonarqube(answers):
    answer = answers[0]
    if not isinstance(answer, dict) or answer.get('error') or answer.get('status') != 200:
        return []
    if not str(answer.get('content_type') or '').startswith('text/plain'):
        return []
    text = clip(answer.get('text'), 60)
    if not re.fullmatch(r'\d{1,2}\.\d{1,3}(?:\.\d{1,3})?(?:\.\d{1,7})?', text):
        return []
    parts = text.split('.')
    return [reading('sonarqube', 'SonarQube', '.'.join(parts[:3]), evidence=f'api/server/version {text}', url='/api/server/version', source='sonarqube')]


def read_nexus(answers):
    answer = answers[0]
    if not isinstance(answer, dict) or answer.get('error'):
        return []
    found = re.match(r'^Nexus/(\d+\.\d+\.\d+)(?:-(\d{1,3}))? \(([A-Z]{2,4})\)$', clip((answer.get('headers') or {}).get('server'), 80))
    if not found:
        return []
    return [reading('nexus', 'Nexus Repository Manager', found.group(1), evidence=f'Server: {clip(answer["headers"]["server"], 80)}',
                    url='/service/rest/v1/status', source='nexus')]


def read_gitea(answers):
    doc = _json(answers[0])
    if not _shape(doc, version='str') or len(doc) != 1:
        return []
    raw = doc['version']
    forgejo = re.match(r'^(\d+\.\d+\.\d+)(?:-[0-9A-Za-z.]+)?\+gitea-(\d+\.\d+\.\d+)', raw)
    if forgejo:
        return [reading('forgejo', 'Forgejo', forgejo.group(1), evidence=f'api/v1/version {raw}', url='/api/v1/version', source='gitea')]
    version = version_of(raw, keep_suffix=False)
    return [reading('gitea', 'Gitea', version, evidence=f'api/v1/version {raw}', url='/api/v1/version', source='gitea')] if version else []


def read_consul(answers):
    doc = _json(answers[0])
    if not _shape(doc, Config__Version='str', Member='object'):
        return []
    version = version_of(doc['Config.Version'], keep_suffix=False)
    return [reading('consul', 'Consul', version, evidence=f'agent/self Config.Version {doc["Config.Version"]}', url='/v1/agent/self',
                    source='consul')] if version else []


VAULT_STATUSES = (200, 429, 472, 473, 474, 501, 503)  # active, standby, DR secondary, performance standby, unhealthy standby, uninitialized, sealed


def read_vault(answers):
    doc = _json(answers[0], VAULT_STATUSES)
    if not _shape(doc, version='str', initialized='bool', sealed='bool'):
        return []
    version = version_of(doc['version'], keep_suffix=False)  # 1.15.2+ent: the release, the edition is not a version
    return [reading('vault', 'Vault', version, evidence=f'sys/health version {doc["version"]}, sealed {doc["sealed"]}',
                    url='/v1/sys/health', source='vault')] if version else []


def read_traefik(answers):
    doc = _json(answers[0])
    if not _shape(doc, Version='str', Codename='str'):
        return []
    version = version_of(doc['Version'])
    return [reading('traefik', 'Traefik', version, evidence=f'api/version {doc["Version"]} ({doc["Codename"]})', url='/api/version',
                    source='traefik')] if version else []


def read_envoy(answers):
    doc = _json(answers[0])
    if not _shape(doc, version='str', state='str', command_line_options='object'):
        return []
    parts = doc['version'].split('/')
    version = version_of(parts[1], keep_suffix=False) if len(parts) >= 2 else ''
    return [reading('envoy', 'Envoy', version, evidence=f'server_info version {doc["version"]}', url='/server_info',
                    source='envoy-admin')] if version else []


def read_jenkins(answers):
    answer = answers[0]
    if not isinstance(answer, dict) or answer.get('error'):
        return []
    found = re.fullmatch(r'(\d+\.\d{1,4}(?:\.\d{1,3})?)', clip((answer.get('headers') or {}).get('x-jenkins'), 40))
    return [reading('jenkins', 'Jenkins', found.group(1), evidence=f'X-Jenkins: {found.group(1)}', url='/login', source='jenkins')] if found else []


def read_artifactory(answers):
    doc = _json(answers[0])
    if not _shape(doc, version='str', revision='str'):
        return []
    version = version_of(doc['version'], keep_suffix=False)
    return [reading('artifactory', 'Artifactory', version, evidence=f'api/system/version {doc["version"]} revision {doc["revision"]}',
                    url='/artifactory/api/system/version', source='artifactory')] if version else []


def read_kubernetes(answers):
    doc = _json(answers[0])
    if not _shape(doc, major='str', minor='str', gitVersion='str', goVersion='str', platform='str'):
        return []
    version = version_of(doc['gitVersion'])
    if not version:
        return []
    out = [reading('kubernetes', 'Kubernetes', version, kind='product', evidence=f'/version gitVersion {doc["gitVersion"]}', url='/version',
                   source='kubernetes-api')]
    go = go_reading(doc['goVersion'], '/version', 'kubernetes-api', f'kube-apiserver built with {doc["goVersion"]}')
    return out + ([go] if go else [])


def read_docker(answers):
    doc = _json(answers[0])
    if not _shape(doc, Version='str', ApiVersion='str', GoVersion='str', Os='str'):
        return []
    version = version_of(doc['Version'])
    if not version:
        return []
    out = [reading('docker', 'Docker', version.split('+')[0], evidence=f'/version Version {doc["Version"]} API {doc["ApiVersion"]}', url='/version',
                   source='docker-api')]
    go = go_reading(doc['GoVersion'], '/version', 'docker-api', f'dockerd built with {doc["GoVersion"]}')
    return out + ([go] if go else [])


def read_etcd(answers):
    doc = _json(answers[0])
    if not _shape(doc, etcdserver='str', etcdcluster='str'):
        return []
    version = version_of(doc['etcdserver'])
    return [reading('etcd', 'etcd', version, evidence=f'/version etcdserver {doc["etcdserver"]}', url='/version', source='etcd')] if version else []


def read_nomad(answers):
    doc = _json(answers[0])
    if not _shape(doc, config__Version__Version='str'):
        return []
    version = version_of(doc['config.Version.Version'])
    return [reading('nomad', 'Nomad', version, evidence=f'agent/self config.Version.Version {doc["config.Version.Version"]}',
                    url='/v1/agent/self', source='nomad')] if version else []


def nomad_acl_enabled(answers):
    doc = _json(answers[0]) if answers else None
    value = (doc or {}).get('config.ACL.Enabled')
    return value if isinstance(value, bool) else None


def rate_nomad(answers):
    """A Nomad agent with ACLs on answers anonymously only when its anonymous policy may read the agent: medium, not critical."""
    return 2 if nomad_acl_enabled(answers) is True else 4


def read_aspnet_error(answers):
    """The version block of a classic ASP.NET error page ("Microsoft .NET Framework Version:4.0.30319; ASP.NET Version:4.8.4718.0"): the
    ASP.NET build names the .NET Framework release line (4.8, 4.7.2 ...). A line, not a patch level: inferred, line only."""
    answer = answers[0]
    if not isinstance(answer, dict) or answer.get('error'):
        return []
    found = re.match(r'^Microsoft \.NET Framework Version:\s?(\d\.\d\.\d{4,5})(?:\.\d+)?; ASP\.NET Version:\s?(\d\.\d)\.(\d{3,5})\.\d+',
                     clip(answer.get('text'), 200))
    if not found:
        return []
    line = DOTNET_LINES.get((found.group(2), int(found.group(3)) // 1000 if found.group(2) == '4.8' else 0), found.group(2))
    return [reading('dotnet-framework', '.NET Framework', line, kind='runtime', confidence='inferred', line_only=True,
                    evidence=f'ASP.NET error page: .NET Framework {found.group(1)}, ASP.NET {found.group(2)}.{found.group(3)}',
                    url='/cvengine-probe-404.aspx', source='aspnet-error')]


# ASP.NET 4.x builds: 4.8.4xxx is .NET Framework 4.8 and 4.8.9xxx is 4.8.1 (Microsoft's "versions and dependencies" table); older lines
# print their own ASP.NET version (4.7.3xxx is 4.7.2 and later, which the line 4.7 covers)
DOTNET_LINES = {('4.8', 9): '4.8.1'}


# ----------------------------------------------------------------------------- on-premises Microsoft servers, Tomcat, WebLogic

# MicrosoftSharePointTeamServices: "16.0.0.10417" is build 16.0.10417 (the header puts a 0 third and leaves the revision out, Censys, "Around 1600
# SharePoint servers vulnerable to attack"). The build number tells the product line apart (Microsoft's SharePoint update history: 2016 runs
# 16.0.4327 to 16.0.5xxx, 2019 16.0.10337 on, Subscription Edition 16.0.14326 on); the revision is not stated, so a CVE fixed by exactly the
# update the farm runs (16.0.10417.20018 for a 16.0.10417 farm) still reads as in range: a version reading needs validation anyway. A build past
# the table (SharePoint Online sends 16.0.0.2xxxx) or under it names no line: a hint, never matched. 2013 and 2010 cannot be told from their
# Foundation editions: the Server name is used.
_SHAREPOINT = re.compile(r'^(1[456])\.0\.0\.(\d{4,5})(?=$|[\s:;,])')
SHAREPOINT_LINES = ((14, 4000, 10000, 'Microsoft SharePoint Server 2010'), (15, 4000, 10000, 'Microsoft SharePoint Server 2013'),
                    (16, 4000, 10000, 'Microsoft SharePoint Enterprise Server 2016'), (16, 10000, 14000, 'Microsoft SharePoint Server 2019'),
                    (16, 14000, 23000, 'Microsoft SharePoint Server Subscription Edition'))


def sharepoint_reading(value, url, source):
    """The SharePoint build a ``MicrosoftSharePointTeamServices`` value states, on the product line its build belongs to, or None."""
    said = clip(value, 80)
    found = _SHAREPOINT.match(said)
    if not found:
        return None
    major, build = int(found.group(1)), int(found.group(2))
    version = f'{major}.0.{build}'
    line = next((label for m, low, high, label in SHAREPOINT_LINES if m == major and low <= build < high), '')
    if not line:
        return reading('sharepoint', 'Microsoft SharePoint', version, confidence='inferred', line_only=True, url=url, source=source,
                       evidence=f'MicrosoftSharePointTeamServices: {said} (build {version}, outside every on-premises line)')
    return reading('sharepoint', line, version, url=url, source=source, evidence=f'MicrosoftSharePointTeamServices: {said} (build {version}, {line})')


def read_sharepoint(answers):
    """The ``MicrosoftSharePointTeamServices`` header a SharePoint web application sends with every answer (a 401 or a redirect to its sign-in
    page included): another product never sends it."""
    answer = answers[0]
    if not isinstance(answer, dict) or answer.get('error'):
        return []
    got = sharepoint_reading((answer.get('headers') or {}).get('microsoftsharepointteamservices'), '/', 'sharepoint')
    return [got] if got else []


# Exchange builds: (major, minor) -> the line, and each cumulative update's build (Microsoft, "Exchange Server build numbers and release dates").
# A security update keeps its cumulative update's build and raises the revision: 15.2.1544.13 is CU14 with a security update.
EXCHANGE_LINES = {(14, 3): '2010', (15, 0): '2013', (15, 1): '2016', (15, 2): '2019'}
EXCHANGE_SE_BUILD = 2562  # Exchange Server Subscription Edition RTM is 15.2.2562.17: a 15.2 build from it on is SE, not 2019
EXCHANGE_UPDATES = {
    (15, 2): {221: 'RTM', 330: 'CU1', 397: 'CU2', 464: 'CU3', 529: 'CU4', 595: 'CU5', 659: 'CU6', 721: 'CU7', 792: 'CU8', 858: 'CU9', 922: 'CU10',
              986: 'CU11', 1118: 'CU12', 1258: 'CU13', 1544: 'CU14', 1748: 'CU15', 2562: 'RTM'},
    (15, 1): {225: 'RTM', 396: 'CU1', 466: 'CU2', 544: 'CU3', 669: 'CU4', 845: 'CU5', 1034: 'CU6', 1261: 'CU7', 1415: 'CU8', 1466: 'CU9', 1531: 'CU10',
              1591: 'CU11', 1713: 'CU12', 1779: 'CU13', 1847: 'CU14', 1913: 'CU15', 1979: 'CU16', 2044: 'CU17', 2106: 'CU18', 2176: 'CU19',
              2242: 'CU20', 2308: 'CU21', 2375: 'CU22', 2507: 'CU23'},
    (15, 0): {516: 'RTM', 620: 'CU1', 712: 'CU2', 775: 'CU3', 847: 'SP1', 913: 'CU5', 995: 'CU6', 1044: 'CU7', 1076: 'CU8', 1104: 'CU9', 1130: 'CU10',
              1156: 'CU11', 1178: 'CU12', 1210: 'CU13', 1236: 'CU14', 1263: 'CU15', 1293: 'CU16', 1320: 'CU17', 1347: 'CU18', 1365: 'CU19',
              1367: 'CU20', 1395: 'CU21', 1473: 'CU22', 1497: 'CU23'},
}
_EXCHANGE_BUILD = re.compile(r'^(1[45])\.(\d)\.(\d{1,4})(?:\.(\d{1,4}))?$')


def exchange_reading(text, url, source, said):
    """The Exchange build ``text`` states (``15.2.1544.4``, ``15.02.1544.004``), on its line and with its cumulative update named, or None. A
    whole build (four parts) is exact; three parts (the OWA resource path of recent releases) name the cumulative update but not its security
    update level: an inferred line, never matched."""
    found = _EXCHANGE_BUILD.match(clip(text, 40))
    if not found:
        return None
    major, minor, build = int(found.group(1)), int(found.group(2)), int(found.group(3))
    line = EXCHANGE_LINES.get((major, minor))
    if not line:
        return None
    if (major, minor) == (15, 2) and build >= EXCHANGE_SE_BUILD:
        line = 'Subscription Edition'
    update = EXCHANGE_UPDATES.get((major, minor), {}).get(build, '')
    label = f'Microsoft Exchange Server {line}'
    named = f'{label}{" " + update if update else ""}'
    if found.group(4) is None:
        return reading('exchange', label, f'{major}.{minor}.{build}', confidence='inferred', line_only=True, url=url, source=source,
                       evidence=f'{said}: build {major}.{minor}.{build} ({named}; the security update level is not stated)')
    return reading('exchange', label, f'{major}.{minor}.{build}.{int(found.group(4))}', url=url, source=source, evidence=f'{said} ({named})')


# The product lines a name states. Microsoft's records name SharePoint and Exchange per line ("Microsoft SharePoint Server 2019", "Microsoft
# SharePoint Enterprise Server 2016", "Microsoft Exchange Server 2019 Cumulative Update 14") and start every SharePoint line at 16.0.0, while name
# matching reads all of them as one product (the year is an edition word): a 2016 build would sit inside a 2019 range. ``line_conflict`` keeps
# a host whose name states one line off an affected entry that names another.
_LINE_FAMILIES = (('sharepoint', re.compile(r'\bsharepoint\b')), ('exchange', re.compile(r'\bexchange server\b')))
_LINE_NAMES = re.compile(r'\b(subscription edition|2010|2013|2016|2019)\b')


def product_line(name):
    """``(family, line)`` a SharePoint or Exchange name states (``('sharepoint', '2019')``, ``('exchange', 'subscription edition')``), or None."""
    text = re.sub(r'[_\s]+', ' ', str(name or '').lower())
    family = next((key for key, pattern in _LINE_FAMILIES if pattern.search(text)), None)
    found = _LINE_NAMES.search(text) if family else None
    return (family, found.group(1)) if found else None


def line_conflict(line, item):
    """Whether an affected entry (``item``) names a line of the family ``line`` (``product_line`` of the host's name) other than that one. An
    entry that names no line conflicts with nothing."""
    if not line or not isinstance(item, dict):
        return False
    other = product_line(item.get('product') or item.get('package'))
    return bool(other and other[0] == line[0] and other[1] != line[1])


_OWA_PATH = re.compile(r'/owa/auth/(1[45]\.\d\.\d{1,4}(?:\.\d{1,4})?)/(?:themes|scripts|resources|current)/', re.I)
_EXPORTTOOL = re.compile(r'^name="microsoft\.exchange\.ediscovery\.exporttool(?:\.application)?"\s+version="(1[45]\.\d\.\d{1,4}\.\d{1,4})"')
EXCHANGE_LOGON = '/owa/auth/logon.aspx'
EXCHANGE_EXPORTTOOL = '/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application'


def read_exchange(answers):
    """Exchange's build, anonymously: the eDiscovery export tool's ClickOnce manifest (Exchange 2013 and later: ``<assemblyIdentity
    name="microsoft.exchange.ediscovery.exporttool.application" version="15.2.986.5" ...>``, the whole build), the ``X-OWA-Version`` header of
    the Outlook on the web sign-in page, or the build in its resource paths (``/owa/auth/15.2.1544/themes/...``). The whole build wins; a
    three-part path alone is the cumulative update, inferred. Never a sign-in attempt."""
    logon = answers[0] if answers else None
    tool = answers[1] if len(answers) > 1 else None
    found = []
    if isinstance(tool, dict) and not tool.get('error') and tool.get('status') == 200:
        hit = _EXPORTTOOL.match(clip(tool.get('text'), 300))
        if hit:
            found.append(exchange_reading(hit.group(1), EXCHANGE_EXPORTTOOL, 'exchange-owa', f'export tool manifest version {hit.group(1)}'))
    if isinstance(logon, dict) and not logon.get('error'):
        header = clip((logon.get('headers') or {}).get('x-owa-version'), 40)
        if header:
            found.append(exchange_reading(header, EXCHANGE_LOGON, 'exchange-owa', f'X-OWA-Version: {header}'))
        path = _OWA_PATH.search(clip(logon.get('text'), 1024)) if logon.get('status') == 200 else None
        if path:
            found.append(exchange_reading(path.group(1), EXCHANGE_LOGON, 'exchange-owa', f'sign-in page resource path /owa/auth/{path.group(1)}/'))
    found = [r for r in found if r]
    exact = [r for r in found if r['confidence'] == 'exact']
    return (exact or found)[:1]


_TOMCAT_NOTES = re.compile(r'^Apache Tomcat Version (\d{1,2}\.\d{1,2}\.\d{1,3}(?:-M\d{1,3})?) Release Notes\b')


def read_tomcat_notes(answers):
    """Tomcat's ``/docs/RELEASE-NOTES.txt`` (the documentation web application, deployed and open to every address by default): its title
    line, "Apache Tomcat Version 9.0.85" over "Release Notes". Only a plain-text 200 answer whose excerpt starts with that title reads."""
    answer = answers[0]
    if not isinstance(answer, dict) or answer.get('error') or answer.get('status') != 200:
        return []
    if not str(answer.get('content_type') or '').startswith('text/plain'):
        return []
    found = _TOMCAT_NOTES.match(clip(answer.get('text'), 200))
    if not found:
        return []
    return [reading('tomcat', 'Apache Tomcat', found.group(1), evidence=f'RELEASE-NOTES.txt: Apache Tomcat Version {found.group(1)}',
                    url='/docs/RELEASE-NOTES.txt', source='tomcat-release-notes')]


_WEBLOGIC = re.compile(r'^WebLogic Server Version: (\d{1,2}\.\d{1,2}\.\d{1,2}\.\d{1,2}(?:\.\d{1,2})?)(?=[\s<]|$)')


def read_weblogic_console(answers):
    """The WebLogic administration console's sign-in page (``/console/login/LoginForm.jsp``) states the server's release in its footer
    ("WebLogic Server Version: 12.2.1.4.0"). An HTML 200 answer whose excerpt starts with that footer reads; nothing is posted to the form."""
    answer = answers[0]
    if not isinstance(answer, dict) or answer.get('error') or answer.get('status') != 200:
        return []
    if not str(answer.get('content_type') or '').startswith('text/html'):
        return []
    found = _WEBLOGIC.match(clip(answer.get('text'), 200))
    if not found:
        return []
    return [reading('weblogic', 'Oracle WebLogic Server', found.group(1), evidence=f'console sign-in page footer: WebLogic Server Version: {found.group(1)}',
                    url='/console/login/LoginForm.jsp', source='weblogic-console')]

# metric name -> (component, label, kind): the *_build_info of software cvENGINE can match by name
BUILD_INFO = {
    'prometheus_build_info': ('prometheus', 'Prometheus', 'product'), 'alertmanager_build_info': ('alertmanager', 'Alertmanager', 'product'),
    'node_exporter_build_info': ('node_exporter', 'node_exporter', 'product'), 'blackbox_exporter_build_info': ('blackbox_exporter', 'blackbox_exporter', 'product'),
    'pushgateway_build_info': ('pushgateway', 'Pushgateway', 'product'), 'grafana_build_info': ('grafana', 'Grafana', 'product'),
    'loki_build_info': ('loki', 'Loki', 'product'), 'traefik_build_info': ('traefik', 'Traefik', 'product'),
    'etcd_server_version': ('etcd', 'etcd', 'product'), 'vault_build_info': ('vault', 'Vault', 'product'),
    'consul_build_info': ('consul', 'Consul', 'product'), 'minio_software_version_info': ('minio', 'MinIO', 'product'),
    'coredns_build_info': ('coredns', 'CoreDNS', 'product'), 'kubernetes_build_info': ('kubernetes', 'Kubernetes', 'product'),
}
METRIC_LABELS = frozenset({'version', 'vendor', 'runtime', 'revision', 'goversion', 'implementation'})  # the Sentinel's own list, and *_version
_SAMPLE = re.compile(r'^([A-Za-z_:][A-Za-z0-9_:]{0,120})\{((?:[A-Za-z_][A-Za-z0-9_]{0,60}="[A-Za-z0-9 ._+~:()/,-]{0,80}",?){0,12})\}$')
_PAIR = re.compile(r'([A-Za-z_][A-Za-z0-9_]{0,60})="([A-Za-z0-9 ._+~:()/,-]{0,80})"')


def metric_lines(answer):
    """``[(name, {label: value})]`` of the ``*_info`` samples a metrics answer carried (the Sentinel rebuilt them; read again strictly here)."""
    if not isinstance(answer, dict) or answer.get('error') or answer.get('status') != 200:
        return []
    out = []
    for line in (answer.get('lines') or [])[:40]:
        found = _SAMPLE.match(str(line or '')[:400])
        if not found or not found.group(1).endswith('_info'):
            continue
        labels = dict(_PAIR.findall(found.group(2)))
        if any(not (k in METRIC_LABELS or k.endswith('_version')) for k in labels):
            continue  # a label the Sentinel never passes on: not a sample it rebuilt
        out.append((found.group(1), labels))
    return out


def read_metrics(answers, url='/metrics', source='prometheus-metrics'):
    """The versions a metrics page's ``*_info`` samples state: the Go release (``go_info``, a ``*_build_info``'s goversion), the Java runtime
    (``jvm_info``, ``jvm_runtime_info``), Python (``python_info``), Node.js (``nodejs_version_info``), RabbitMQ and its Erlang/OTP line
    (``rabbitmq_build_info``) and the software a known ``*_build_info`` names. Never a label beyond these."""
    out = []
    for name, labels in metric_lines(answers[0] if answers else None):
        version = labels.get('version', '')
        if name == 'go_info':
            got = go_reading(version, url, source, f'go_info version {version}')
            out += [got] if got else []
        elif name in ('jvm_info', 'jvm_runtime_info'):
            if version:
                out.append({**reading('java', 'Java runtime', version, kind='java', evidence=f'{name} version {version}, vendor '
                                      f'{labels.get("vendor", "")}, runtime {labels.get("runtime", "")}', url=url, source=source),
                            'vendor': clip(labels.get('vendor'), 60), 'runtime': clip(labels.get('runtime'), 120)})
        elif name == 'python_info':
            value = version_of(version, keep_suffix=False)
            if value and labels.get('implementation', 'CPython') in ('CPython', ''):
                out.append(reading('python', 'Python', value, kind='runtime', evidence=f'python_info version {version}', url=url, source=source))
        elif name == 'nodejs_version_info':
            value = version_of(version, keep_suffix=False)
            if value:
                out.append(reading('nodejs', 'Node.js', value, kind='runtime', evidence=f'nodejs_version_info version {version}', url=url, source=source))
        elif name == 'rabbitmq_build_info':
            value = version_of(labels.get('rabbitmq_version', ''), keep_suffix=False)
            if value:
                out.append(reading('rabbitmq', 'RabbitMQ', value, evidence=f'rabbitmq_build_info rabbitmq_version {labels["rabbitmq_version"]}',
                                   url=url, source=source))
            otp = re.fullmatch(r'(\d{2})(?:\.\d+){0,3}', labels.get('erlang_version', ''))
            if otp:
                out.append(reading('erlang', 'Erlang/OTP', otp.group(0), kind='runtime', confidence='exact', line_only='.' not in otp.group(0),
                                   evidence=f'rabbitmq_build_info erlang_version {labels["erlang_version"]}', url=url, source=source))
        elif name in BUILD_INFO:
            component, label, kind = BUILD_INFO[name]
            value = version_of(version)
            if value:
                out.append(reading(component, label, value, kind=kind, evidence=f'{name} version {version}', url=url, source=source))
        if name.endswith('_build_info') and labels.get('goversion'):
            got = go_reading(labels['goversion'], url, source, f'{name} goversion {labels["goversion"]}')
            out += [got] if got else []
    return _unique(out)


def read_expvar(answers):
    """Go's expvar page (``/debug/vars``): ``cmdline`` (an array, never its values: they can carry secrets) and ``memstats`` prove it is
    one. It states no Go release; a ``version`` an application publishes there names no product cvENGINE can match. It proves Go only."""
    doc = _json(answers[0])
    if not _shape(doc, cmdline='array', memstats='object'):
        return []
    return [reading('go', 'Go', '', kind='runtime', confidence='weak', evidence='expvar /debug/vars answers (cmdline, memstats)', url='/debug/vars',
                    source='go-expvar')]


def _unique(readings):
    seen, out = set(), []
    for r in readings:
        if r is None:
            continue
        key = (r['component'], r['version'], r['kind'])
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out


# ----------------------------------------------------------------------------- status pages: only their version rows (contract 9)

def _rows(answer, content_type=''):
    """The rows a ``rows`` read of one answer carries (``{name: value}``), when it is a 200 answer (of ``content_type`` when given), else None."""
    if not isinstance(answer, dict) or answer.get('error') or answer.get('status') != 200 or not isinstance(answer.get('rows'), dict):
        return None
    if content_type and not str(answer.get('content_type') or '').startswith(content_type):
        return None
    return {clip(k, 60): clip(v, 120) for k, v in answer['rows'].items() if isinstance(k, str) and isinstance(v, str)}


_APACHE_DESCRIPTION = re.compile(r'^Apache/(\d+\.\d+\.\d+)(?: \(([A-Za-z0-9 ._-]{1,40})\))?((?: [A-Za-z][A-Za-z0-9_.+-]{0,40}/[A-Za-z0-9._+~-]{1,40}){0,16})$')


def apache_description(text, url, source, evidence):
    """The readings Apache's full server description states (``Apache/2.4.57 (Debian) OpenSSL/3.0.11 PHP/8.2.12``: ``ap_get_server_description``,
    whatever ``ServerTokens`` says): the web server, and each module or runtime it lists with a whole release (the shared Server header parser,
    ``cvengine_scanner.versions.parse_server_header``). A language runtime (PHP, Python) is a runtime reading; anything else a product. []
    for any other shape."""
    from cvengine_scanner import versions
    said = clip(text, 400)
    if not _APACHE_DESCRIPTION.match(said):
        return []
    out = []
    for component in versions.parse_server_header(said)['components']:
        stated = re.sub(r'-fips$', '', component['version'] or '', flags=re.I)  # a FIPS build of a release (RHEL's OpenSSL/1.0.2k-fips) is that release
        version = stated if re.fullmatch(r'\d{1,4}(?:\.\d{1,9}){1,3}[a-z]{0,2}(?:[-+~][0-9A-Za-z.+~-]{1,40})?', stated) else ''
        if not version:
            continue
        product = component['product']
        runtime = {'PHP': ('php', 'PHP'), 'Python': ('python', 'Python')}.get(product)
        if runtime:
            out.append(reading(runtime[0], runtime[1], version, kind='runtime', evidence=evidence, url=url, source=source))
        else:
            out.append(reading(re.sub(r'[^a-z0-9_]+', '-', product.lower()).strip('-'), product, version, evidence=evidence, url=url, source=source))
    return _unique(out)


def read_server_status(answers):
    """Apache's ``/server-status?auto`` (mod_status, 2.4.13 and later): the ``ServerVersion`` line is the full server description, modules
    included. Only a plain-text 200 answer with that line in Apache's own shape is read: a catch-all page, a login page or the HTML report
    (asked without ``?auto``) gives nothing."""
    rows = _rows(answers[0], 'text/plain')
    if not rows or 'ServerVersion' not in rows:
        return []
    return apache_description(rows['ServerVersion'], '/server-status?auto', 'apache-server-status', f'server-status ServerVersion: {rows["ServerVersion"]}')


# the phpinfo rows a version is read from (php-src: main.c "PHP Version", ext/openssl "OpenSSL Library Version", ext/curl "cURL Information",
# ext/libxml "libXML Loaded Version" / "libXML Compiled Version", ext/pcre "PCRE Library Version", ext/sqlite3 "SQLite Library",
# sapi/apache2handler "Apache Version"): never "System" (the host name), the configure line, the environment, cookies or variables
PHPINFO_ROWS = ('PHP Version', 'OpenSSL Library Version', 'cURL Information', 'libXML Loaded Version', 'libXML Compiled Version',
                'PCRE Library Version', 'SQLite Library', 'Apache Version')
_PHP_VERSION = re.compile(r'^(\d+\.\d+\.\d+)((?:-|~|\+)[A-Za-z0-9.+~-]{1,40})?$')
_OPENSSL_ROW = re.compile(r'^(OpenSSL|LibreSSL|BoringSSL) (\d+\.\d+\.\d+[a-z]{0,2})(?:-[A-Za-z0-9]{1,12})?(?: |$)')
_PCRE_ROW = re.compile(r'^(\d{1,2})\.(\d{1,2})(?: |$)')


def read_phpinfo(answers):
    """A phpinfo page a scan already found (``discovered``): the PHP release (``PHP Version``, the Core module's row) and the libraries it states
    with theirs: OpenSSL (or LibreSSL), curl, libxml2 (the loaded library; the compiled-in headers' version is only inferred), PCRE or PCRE2,
    SQLite and the Apache it runs under. The page's ``PHP Version`` row must hold a whole release, or nothing is read. The Sentinel hands back
    only these rows (``version_rows``): nothing else of the page, which carries the environment, cookies and credentials, leaves it."""
    rows = _rows(answers[0])
    php = _PHP_VERSION.match((rows or {}).get('PHP Version', ''))
    if not php:
        return []
    url, source = '/phpinfo', 'phpinfo'
    out = [reading('php', 'PHP', php.group(1) + (php.group(2) or ''), kind='runtime', evidence=f'phpinfo PHP Version {rows["PHP Version"]}',
                   url=url, source=source)]
    found = _OPENSSL_ROW.match(rows.get('OpenSSL Library Version', ''))
    if found:
        out.append(reading(found.group(1).lower(), found.group(1), found.group(2), evidence=f'phpinfo OpenSSL Library Version {rows["OpenSSL Library Version"]}',
                           url=url, source=source))
    curl = version_of(rows.get('cURL Information', ''), keep_suffix=False)
    if curl and curl.count('.') == 2:
        out.append(reading('curl', 'curl', curl, evidence=f'phpinfo cURL Information {rows["cURL Information"]}', url=url, source=source))
    loaded = re.fullmatch(r'(\d)(\d{2})(\d{2})', rows.get('libXML Loaded Version', ''))  # xmlParserVersion: 20914 is 2.9.14
    compiled = version_of(rows.get('libXML Compiled Version', ''), keep_suffix=False)
    if loaded:
        out.append(reading('libxml2', 'libxml2', f'{int(loaded.group(1))}.{int(loaded.group(2))}.{int(loaded.group(3))}',
                           evidence=f'phpinfo libXML Loaded Version {rows["libXML Loaded Version"]}', url=url, source=source))
    elif compiled and compiled.count('.') == 2:
        out.append(reading('libxml2', 'libxml2', compiled, confidence='inferred', evidence=f'phpinfo libXML Compiled Version {compiled} (the headers PHP '
                           'was built with; the loaded library is not stated)', url=url, source=source))
    pcre = _PCRE_ROW.match(rows.get('PCRE Library Version', ''))
    if pcre:
        label = 'PCRE2' if int(pcre.group(1)) >= 10 else 'PCRE'
        out.append(reading(label.lower(), label, f'{pcre.group(1)}.{pcre.group(2)}', evidence=f'phpinfo PCRE Library Version {rows["PCRE Library Version"]}',
                           url=url, source=source))
    sqlite = version_of(rows.get('SQLite Library', ''), keep_suffix=False)
    if sqlite and sqlite.count('.') == 2:
        out.append(reading('sqlite', 'SQLite', sqlite, evidence=f'phpinfo SQLite Library {sqlite}', url=url, source=source))
    if rows.get('Apache Version', '').startswith('Apache/'):
        out += [r for r in apache_description(rows['Apache Version'], url, source, f'phpinfo Apache Version {rows["Apache Version"]}')
                if r['component'] not in ('php',)]  # PHP is read from its own row
    return _unique(out)


# ----------------------------------------------------------------------------- the catalogue

_K8S_REMEDIATION = ('Keep the API server off networks that do not need it (a private endpoint, an allow-list of client addresses), and keep anonymous '
                    'access at the default public-info role or switch it off (--anonymous-auth=false).')

SOURCES = (
    Source('jira', 'Jira', 'product', (Request('/rest/api/2/serverInfo', fields=('version', 'versionNumbers', 'buildNumber', 'deploymentType')),),
           read_jira, leads=r'\bjira\b', verified='https://docs.atlassian.com/software/jira/docs/api/REST/9.12.0/#api/2/serverInfo-getServerInfo',
           note='answers anonymously unless the instance forbids anonymous access; Jira Cloud is skipped'),
    Source('atlassian-applinks', 'Atlassian application links manifest', 'product', (Request('/rest/applinks/1.0/manifest', read='text'),),
           read_applinks, leads=r'confluence|bitbucket|\bstash\b|bamboo|\bcrowd\b|fisheye|crucible',
           verified='https://support.atlassian.com/atlassian-knowledge-base/kb/creating-an-application-link-between-atlassian-products-results-in-a-warning-about/',
           note='the XML manifest every Atlassian server product answers for application links: typeId and version'),
    Source('grafana', 'Grafana', 'product', (Request('/api/health', fields=('version', 'database', 'commit')),), read_grafana, leads=r'grafana',
           verified='https://grafana.com/docs/grafana/latest/developer-resources/api-reference/http-api/api-legacy/other/'),
    Source('kibana', 'Kibana', 'product', (Request('/api/status', fields=('version.number', 'version.build_number', 'status')),), read_kibana,
           leads=r'kibana', verified='https://github.com/elastic/kibana/blob/main/src/core/packages/status/server-internal/src/routes/status.ts',
           note='only with status.allowAnonymous: an unauthenticated caller is otherwise given a redacted status with no version'),
    Source('sonarqube', 'SonarQube', 'product', (Request('/api/server/version', read='text'),), read_sonarqube, leads=r'sonarqube|sonar\b',
           control=True, verified='https://sonarqube.ow2.org/web_api/api/server (GET api/server/version, plain text, no authentication)'),
    Source('nexus', 'Nexus Repository Manager', 'product', (Request('/service/rest/v1/status', read='headers'),), read_nexus,
           leads=r'\bnexus\b|sonatype', verified='https://github.com/sonatype/nexus-public (EnvironmentFilter: Server "Nexus/<version> (<edition>)")'),
    Source('gitea', 'Gitea or Forgejo', 'product', (Request('/api/v1/version', fields=('version',)),), read_gitea, leads=r'gitea|forgejo',
           control=True, verified='https://github.com/go-gitea/gitea/blob/main/routers/api/v1/misc/version.go (ServerVersion {"version"})'),
    Source('consul', 'Consul', 'product', (Request('/v1/agent/self', fields=('Config.Version', 'Config.Revision', 'Member')),), read_consul,
           leads=r'\bconsul\b', ports=(8500,), verified='https://github.com/hashicorp/consul/blob/main/agent/agent_endpoint.go (Self.Config.Version)',
           note='answers anonymously when ACLs are off or the anonymous token may read the agent; DebugConfig is never read'),
    Source('vault', 'Vault', 'product', (Request('/v1/sys/health', fields=('version', 'initialized', 'sealed', 'standby')),), read_vault,
           leads=r'\bvault\b', ports=(8200,), statuses=VAULT_STATUSES, verified='https://developer.hashicorp.com/vault/api-docs/system/health',
           note='unauthenticated by design; every health status code carries the body'),
    Source('traefik', 'Traefik', 'product', (Request('/api/version', fields=('Version', 'Codename', 'startDate')),), read_traefik,
           leads=r'traefik', verified='https://github.com/traefik/traefik/blob/master/pkg/version/version.go (/api/version)'),
    Source('envoy-admin', 'Envoy admin interface', 'platform', (Request('/server_info', fields=('version', 'state', 'command_line_options')),),
           read_envoy, leads=r'envoy', ports=(9901,), verified='https://www.envoyproxy.io/docs/envoy/latest/operations/admin',
           exposure=Exposure('envoy-admin-exposed', 'Envoy admin interface reachable without authentication', 3,
                             'The Envoy proxy\'s admin interface answers from the network. It has no authentication.',
                             'Anyone who reaches it can read the proxy\'s whole configuration (/config_dump), its clusters and statistics, and send '
                             'the POST requests that drain its listeners or shut it down.',
                             'Bind the admin interface to 127.0.0.1 (admin.address) or a Unix socket, or block the port at the firewall.')),
    Source('jenkins', 'Jenkins', 'product', (Request('/login', read='headers'),), read_jenkins, leads=r'jenkins|hudson',
           verified='https://www.jenkins.io/doc/book/security/ (every response carries X-Jenkins with the core version)'),
    Source('artifactory', 'Artifactory', 'product', (Request('/artifactory/api/system/version', fields=('version', 'revision', 'addons')),),
           read_artifactory, leads=r'artifactory|jfrog', verified='https://docs.jfrog.com/administration/reference/getartifactoryversion',
           note='"requires a valid user (can be anonymous)": only an instance with anonymous access answers'),
    Source('kubernetes-api', 'Kubernetes API server', 'platform',
           (Request('/version', fields=('major', 'minor', 'gitVersion', 'goVersion', 'platform')),), read_kubernetes,
           leads=r'kubernetes|kube-apiserver|\bk8s\b', ports=(6443,), verified='https://kubernetes.io/docs/reference/access-authn-authz/rbac/ '
           '(system:public-info-viewer grants /version to system:unauthenticated)',
           exposure=Exposure('kubernetes-api-reachable', 'Kubernetes API server reachable', 1,
                             'A Kubernetes API server answers from the network. Its /version is readable without credentials by default '
                             '(the system:public-info-viewer role), so this is the reachability of the control plane, not an open cluster.',
                             'The control plane is a target for credential attacks and for every API server vulnerability of its release.',
                             _K8S_REMEDIATION)),
    Source('docker-api', 'Docker Engine API', 'platform',
           (Request('/version', fields=('Version', 'ApiVersion', 'MinAPIVersion', 'GoVersion', 'Os', 'Arch')),), read_docker,
           leads=r'\bdocker\b', ports=(2375, 2376), verified='https://docs.docker.com/reference/api/engine/version/v1.43/ (GET /version)',
           exposure=Exposure('docker-api-exposed', 'Docker Engine API open without authentication', 4,
                             'The Docker daemon\'s API answers from the network without a client certificate.',
                             'Anyone who reaches it can start a privileged container that mounts the host\'s file system: full control of the host.',
                             'Stop the daemon listening on TCP (remove -H tcp:// from its start options or "hosts" from daemon.json), or require '
                             'TLS client certificates (--tlsverify), and block ports 2375 and 2376 at the firewall.',
                             twins=('docker-api', 'exposed-docker-api', 'docker-daemon-exposed'))),
    Source('etcd', 'etcd', 'platform', (Request('/version', fields=('etcdserver', 'etcdcluster')),), read_etcd, leads=r'\betcd\b', ports=(2379,),
           verified='https://github.com/etcd-io/etcd/blob/main/api/version/version.go (Versions {"etcdserver", "etcdcluster"})',
           exposure=Exposure('etcd-client-exposed', 'etcd client API reachable without a client certificate', 3,
                             'An etcd member answers its client API from the network without asking for a client certificate.',
                             'Unless etcd\'s own authentication is on, anyone who reaches it can read and change every key, which for a '
                             'Kubernetes cluster includes its secrets.',
                             'Require client certificates (--client-cert-auth with --trusted-ca-file), switch etcd authentication on, and keep the '
                             'client port off networks that do not need it.')),
    Source('nomad', 'Nomad', 'platform', (Request('/v1/agent/self', fields=('config.Version.Version', 'config.ACL.Enabled', 'member.Tags.build')),),
           read_nomad, leads=r'\bnomad\b', ports=(4646,), verified='https://github.com/hashicorp/nomad/blob/main/command/agent/agent_endpoint.go '
           '(agentSelf.config.Version; ACL agent:read)',
           exposure=Exposure('nomad-api-exposed', 'Nomad API answers anonymous requests', 4,
                             'A Nomad agent answers its HTTP API without a token.',
                             'With ACLs off, anyone who reaches it can submit a job: code execution on every client node.',
                             'Turn ACLs on (acl { enabled = true }) and bootstrap them, require mTLS for the HTTP API, and keep port 4646 off '
                             'networks that do not need it.', rate=rate_nomad)),
    Source('prometheus-metrics', 'Prometheus metrics', 'metrics', (Request('/metrics', read='metrics'),), read_metrics,
           leads=r'prometheus|exporter|alertmanager|pushgateway', ports=(9090, 9091, 9093, 9100, 9115, 15692), control=True,
           verified='https://prometheus.io/docs/instrumenting/exposition_formats/ (client_golang go_info and *_build_info, client_java jvm_info, '
           'client_python python_info, prom-client nodejs_version_info, rabbitmq_prometheus rabbitmq_build_info)',
           exposure=Exposure('prometheus-metrics-exposed', 'Prometheus metrics readable without authentication', 0,
                             'A /metrics page answers from the network without credentials.',
                             'Metric names and labels describe the software, its versions, its hosts and its traffic, which helps an attacker plan.',
                             'Serve /metrics only to the Prometheus server (an allow-list, a separate port that is not exposed, or authentication).',
                             twins=('prometheus-metrics', 'prometheus-exporter', 'node-exporter-metrics', 'prometheus-exporter-detect',
                                    'metrics-endpoint-exposure'))),
    Source('go-expvar', 'Go expvar debug page', 'metrics', (Request('/debug/vars', fields=('cmdline', 'memstats')),), read_expvar,
           leads=r'golang|go net/http|\bgo\b', control=False, verified='https://pkg.go.dev/expvar (cmdline and memstats are always published)',
           exposure=Exposure('go-expvar-exposed', 'Go expvar debug page readable without authentication', 1,
                             'The Go standard library\'s debug page /debug/vars answers from the network.',
                             'It publishes the process\'s command line, which can carry passwords or tokens, and its memory statistics.',
                             'Do not register expvar\'s handler on a public listener (import _ "expvar" registers it on the default mux), or serve it '
                             'only on a local debug port.', twins=('golang-expvar', 'expvar-exposure', 'golang-expvar-exposure'))),
    Source('sharepoint', 'Microsoft SharePoint', 'product',
           (Request('/', read='headers', headers=('microsoftsharepointteamservices', 'server', 'x-powered-by', 'x-aspnet-version')),), read_sharepoint,
           leads=r'sharepoint', verified='https://censys.com/blog/around-1600-sharepoint-servers-vulnerable-to-attack/ (MicrosoftSharePointTeamServices '
           '"16.0.0.4351" is build 16.0.4351); https://learn.microsoft.com/en-us/officeupdates/sharepoint-updates (builds per product line)',
           note='every answer of a SharePoint web application carries the header, a 401 or a redirect to its sign-in page included'),
    Source('exchange-owa', 'Microsoft Exchange (Outlook on the web)', 'product',
           (Request(EXCHANGE_LOGON, read='text', find='/owa/auth/', headers=('x-owa-version', 'server', 'x-powered-by', 'x-aspnet-version')),
            Request(EXCHANGE_EXPORTTOOL, read='text', find='name="microsoft.exchange.ediscovery.exporttool')), read_exchange,
           leads=r'^(?!.*\b(?:smtpd|imapd|pop3d|pop3|imap)\b).*(?:microsoft exchange|exchange server|outlook web|\bowa\b)',
           verified='https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/remote/http/exchange.rb (exchange_get_version: '
           'the sign-in page and the export tool manifest); https://learn.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates',
           note='the sign-in page is only fetched, never posted to; the export tool manifest is a static ClickOnce file (Exchange 2013 and later)'),
    Source('tomcat-release-notes', 'Apache Tomcat release notes', 'product', (Request('/docs/RELEASE-NOTES.txt', read='text', find='Apache Tomcat Version '),),
           read_tomcat_notes, leads=r'tomcat|coyote',
           verified='https://github.com/apache/tomcat/blob/main/RELEASE-NOTES ("Apache Tomcat Version @VERSION@" over "Release Notes", served by the '
           'docs web application at /docs/RELEASE-NOTES.txt)',
           note='only an install that kept the documentation web application; the error page footer is the error-page probe\'s (cveFeed.probes)'),
    Source('weblogic-console', 'Oracle WebLogic Server console', 'product',
           (Request('/console/login/LoginForm.jsp', read='text', find='WebLogic Server Version: '),), read_weblogic_console, leads=r'weblogic',
           verified='https://cloud.projectdiscovery.io/library/CVE-2020-2883 (ProjectDiscovery\'s public check reads "WebLogic Server '
           'Version: <release>" from the sign-in page /console/login/LoginForm.jsp)',
           note='only a domain whose administration console answers on the asked port; the T3 handshake would need a Sentinel kind of its own'),
    Source('aspnet-error', 'ASP.NET error page version block', 'runtime',
           (Request('/cvengine-probe-404.aspx', read='text', find='Microsoft .NET Framework Version:'),), read_aspnet_error,
           leads=r'asp\.?net|microsoft[- ]iis|\biis\b',
           verified='https://learn.microsoft.com/en-us/dotnet/framework/migration-guide/versions-and-dependencies (ASP.NET builds per release)',
           note='only a site that shows detailed errors to remote users (customErrors off) prints the block'),
)
SOURCES = SOURCES + __import__('cveFeed.edge_builds', fromlist=['sources']).sources()  # the edge appliances' builds (cveFeed.edge_builds)
# status pages read row by row (contract 9, version_rows): only the version rows ever leave the Sentinel
SOURCES = SOURCES + (
    Source('apache-server-status', 'Apache server-status', 'platform', (Request('/server-status?auto', read='rows', fields=('ServerVersion',)),),
           read_server_status, leads=r'^(?:apache(?: http server| httpd)?|httpd)$',
           verified='https://github.com/apache/httpd/blob/2.4.x/modules/generators/mod_status.c (the "?auto" report prints "ServerVersion: " '
           'ap_get_server_description(), the full description whatever ServerTokens says; added to ?auto in 2.4.13, CHANGES)',
           note='asked only of a host already identified as Apache HTTP Server; a plain-text 200 answer with the ServerVersion line is the only shape read',
           exposure=Exposure('apache-server-status-exposed', 'Apache server-status page readable without authentication', 1,
                             'Apache\'s mod_status report (/server-status) answers from the network without credentials.',
                             'It names the exact Apache, OpenSSL and module releases even when the Server header hides them, and with ExtendedStatus on '
                             'it lists the client addresses and the URLs being requested, which can carry session tokens.',
                             'Restrict the handler to the addresses that need it (<Location "/server-status"> Require ip 127.0.0.1 ... </Location>) or '
                             'disable mod_status.', twins=('apache-server-status', 'apache-server-status-localhost', 'server-status-localhost'))),
    Source('phpinfo', 'phpinfo page', 'runtime', (Request('/phpinfo.php', read='rows', fields=PHPINFO_ROWS),), read_phpinfo, discovered=True,
           verified='https://github.com/php/php-src (main/main.c PHP_MINFO core "PHP Version"; ext/openssl, ext/curl, ext/libxml, ext/pcre, '
           'ext/sqlite3 and sapi/apache2handler MINFO rows)',
           note='asked only at a phpinfo page a scan already found on the host (a template check\'s phpinfo finding, or a crawled page titled '
           '"phpinfo()"), never at a guessed path; only the version rows come back',
           exposure=Exposure('phpinfo-exposed', 'phpinfo page readable without authentication', 1,
                             'A PHP information page (phpinfo()) answers from the network without credentials.',
                             'It prints the exact PHP and library releases, the server\'s paths and configuration, and the environment, which often '
                             'holds database passwords, API keys and session cookies.',
                             'Delete the page, or restrict it to the addresses that need it.',
                             twins=('phpinfo-files', 'phpinfo', 'php-info', 'phpinfo-page', 'phpinfo-detect'))),
)
# AI model servers and agent dashboards: Ollama, llama.cpp, vLLM, LM Studio, KoboldCpp, Gradio, Langflow, ComfyUI, LiteLLM, Ray, Open WebUI,
# Flowise, AnythingLLM, OpenClaw and Hermes Agent (cveFeed.ai_servers)
SOURCES = SOURCES + __import__('cveFeed.ai_servers', fromlist=['sources']).sources()
BY_ID = {s.id: s for s in SOURCES}
assert all(len(s.requests) + int(s.control) <= MAX_REQUESTS for s in SOURCES)


def control_path(source, token):
    """The control path next to ``source``'s first request: the same directory, a name no site serves (``token``: 12 hex digits)."""
    first = source.requests[0].path.split('?', 1)[0]
    return first.rsplit('/', 1)[0] + '/' + CONTROL_PREFIX + token


def request_specs(source, token):
    """The ``version_read`` requests of one entry: its own, then the control path when it asks one."""
    out = [r.spec() for r in source.requests]
    if source.control:
        out.append(source.requests[0].spec(path=control_path(source, token)))
    return out


def read_entry(source, answers):
    """What one entry's answers say: ``{'state', 'readings', 'exposed'}``.

    ``state`` is ``read`` (a reading), ``absent`` (every request answered and none in the expected shape: the product is not there, or does
    not say), ``catch_all`` (the control path read the same way: nothing is believed) or ``unknown`` (a request got no answer: nothing is
    concluded). ``exposed`` is True when the entry's exposure answered in its shape, False when a complete read shows it does not, None when
    it cannot be told. An exposure that rates its answer (``Exposure.rate``) also gives ``severity``, and a product that answered with its door
    shut (a key or a sign-in asked for) is ``exposed`` False."""
    own = list(answers[:len(source.requests)]) + [None] * max(0, len(source.requests) - len(answers))
    complete = all(isinstance(a, dict) and not a.get('error') and a.get('status') for a in own)
    readings = [r for r in (source.reader(own) or []) if r]
    if source.control and readings:
        control = answers[len(source.requests)] if len(answers) > len(source.requests) else None
        if not isinstance(control, dict) or control.get('error') or not control.get('status'):
            return {'state': 'unknown', 'readings': [], 'exposed': None}
        if source.reader([control] + [None] * (len(source.requests) - 1)):
            return {'state': 'catch_all', 'readings': [], 'exposed': False}
    if readings and source.exposure and source.exposure.rate:
        severity = source.exposure.rate(own)
        return {'state': 'read', 'readings': readings, 'exposed': severity is not None, **({'severity': severity} if severity is not None else {})}
    if readings:
        return {'state': 'read', 'readings': readings, 'exposed': True if source.exposure else None}
    if complete:
        return {'state': 'absent', 'readings': [], 'exposed': False if source.exposure else None}
    return {'state': 'unknown', 'readings': [], 'exposed': None}


# ----------------------------------------------------------------------------- what a host already says (no request)

# Server and X-Powered-By products that state a language runtime: the runtime and how far its presence goes
_PY_SERVER = re.compile(r'\b(?:Werkzeug|SimpleHTTP|BaseHTTP|WSGIServer|TwistedWeb|CherryPy|Tornado(?:Server)?)/[\w.]+\s+(?:C?Python)/(\d+\.\d+\.\d+)', re.I)
_PY_ONLY = re.compile(r'(?:^|\s)Python/(\d+\.\d+\.\d+)\b')
_PY_PRESENT = re.compile(r'^(?:gunicorn|uvicorn|hypercorn|waitress|daphne|Werkzeug|TornadoServer)\b', re.I)
_RUBY_SERVER = re.compile(r'\bWEBrick/[\d.]+ \(Ruby/(\d+\.\d+\.\d+)/', re.I)
_RUBY_PRESENT = re.compile(r'\b(?:Phusion[ _]Passenger|Passenger)\b', re.I)
_PHP = re.compile(r'(?:^|[\s,])PHP/(\d+\.\d+\.\d+)([-~+][\w.+~-]{1,40})?', re.I)
_ASPNET_CLR = re.compile(r'^(4\.0\.30319|2\.0\.50727|1\.1\.4322)$')
CLR_LINES = {'4.0.30319': '4', '2.0.50727': '3.5', '1.1.4322': '1.1'}  # the .NET Framework lines a CLR build serves (4.x; 2.0 to 3.5; 1.1)
_JENKINS = re.compile(r'^(\d+\.\d{1,4}(?:\.\d{1,3})?)$')
_NEXUS = re.compile(r'^Nexus/(\d+\.\d+\.\d+)(?:-\d{1,3})? \([A-Z]{2,4}\)$')


def from_headers(headers, url='/'):
    """The readings response headers give away, no request made: a language runtime in a Server or X-Powered-By header (Python behind
    Werkzeug, Ruby behind WEBrick, PHP, the .NET Framework line X-AspNet-Version names, Python under gunicorn or uvicorn, ASP.NET), and the
    products whose own header states their version (X-Jenkins, Nexus's Server, SharePoint's MicrosoftSharePointTeamServices, Exchange's
    X-OWA-Version). ``headers`` maps lowercase names to values."""
    lowered = {str(k).lower(): clip(v, 300) for k, v in (headers or {}).items()}
    server, powered = lowered.get('server', ''), lowered.get('x-powered-by', '')
    out = []
    found = _PY_SERVER.search(server) or _PY_ONLY.search(server)
    if found:
        out.append(reading('python', 'Python', found.group(1), kind='runtime', evidence=f'Server: {server}', url=url, source='header'))
    elif _PY_PRESENT.match(server):
        out.append(reading('python', 'Python', '', kind='runtime', confidence='inferred', evidence=f'Server: {server}', url=url, source='header'))
    found = _RUBY_SERVER.search(server)
    if found:
        out.append(reading('ruby', 'Ruby', found.group(1), kind='runtime', evidence=f'Server: {server}', url=url, source='header'))
    elif _RUBY_PRESENT.search(server) or _RUBY_PRESENT.search(powered):
        out.append(reading('ruby', 'Ruby', '', kind='runtime', confidence='weak', evidence=f'Phusion Passenger: {server or powered}', url=url,
                           source='header'))
    for text in (powered, server):
        found = _PHP.search(text)
        if found:
            out.append(reading('php', 'PHP', found.group(1) + (found.group(2) or ''), kind='runtime', evidence=f'{text}', url=url, source='header'))
            break
    clr = lowered.get('x-aspnet-version', '')
    if _ASPNET_CLR.match(clr):
        out.append(reading('dotnet-framework', '.NET Framework', CLR_LINES[clr], kind='runtime', confidence='inferred', line_only=True,
                           evidence=f'X-AspNet-Version: {clr} (the CLR of .NET Framework {CLR_LINES[clr]}{".x" if clr.startswith("4") else ""})',
                           url=url, source='header'))
    elif re.match(r'^ASP\.NET\b', powered):
        out.append(reading('dotnet-framework', '.NET Framework', '', kind='runtime', confidence='weak', evidence=f'X-Powered-By: {powered}', url=url,
                           source='header'))
    found = _JENKINS.match(lowered.get('x-jenkins', ''))
    if found:
        out.append(reading('jenkins', 'Jenkins', found.group(1), evidence=f'X-Jenkins: {found.group(1)}', url=url, source='header'))
    found = _NEXUS.match(server)
    if found:
        out.append(reading('nexus', 'Nexus Repository Manager', found.group(1), evidence=f'Server: {server}', url=url, source='header'))
    if lowered.get('microsoftsharepointteamservices'):
        out.append(sharepoint_reading(lowered['microsoftsharepointteamservices'], url, 'header'))
    if lowered.get('x-owa-version'):
        out.append(exchange_reading(lowered['x-owa-version'], url, 'header', f'X-OWA-Version: {lowered["x-owa-version"]}'))
    return _unique(out)


def from_technology(name, version):
    """The runtime reading a stored technology is (``Python:3.11.4`` from an Apache Server header's modules, ``PHP:8.2.12``), or None. The
    technology itself is still matched as one (source tech); the reading lets the runtime rules see the host's runtime."""
    token = re.sub(r'[^a-z0-9]', '', (name or '').lower())
    runtime = {'python': ('python', 'Python'), 'php': ('php', 'PHP'), 'ruby': ('ruby', 'Ruby'), 'nodejs': ('nodejs', 'Node.js'),
               'go': ('go', 'Go'), 'golang': ('go', 'Go')}.get(token)
    if runtime and version_of(version):
        return reading(runtime[0], runtime[1], version, kind='runtime', evidence=f'technology {clip(name, 40)} {clip(version, 40)}', source='technology')
    if token == 'netframeworkclr' and _ASPNET_CLR.match((version or '').strip()):
        line = CLR_LINES[version.strip()]
        return reading('dotnet-framework', '.NET Framework', line, kind='runtime', confidence='inferred', line_only=True,
                       evidence=f'technology .NET Framework CLR {version}', source='technology')
    return None


def header_lines(text):
    """``{name: value}`` of the ``Name: value`` lines of a stored header dump (the port scan's http-headers script output)."""
    out = {}
    for name, value in re.findall(r'(?im)^\s*([A-Za-z][A-Za-z0-9-]{0,40})\s*:\s*(.{1,300})$', str(text or '')[:8000]):
        out.setdefault(name.lower(), value.strip())
    return out


# ----------------------------------------------------------------------------- what an SNMP agent says (sysDescr)

# The UDP sweep's snmp-sysdescr script (cveFeed.udp_scan: one GET of sysDescr with the community "public") stores what the agent answered on
# the UDP 161 port row. Each pattern below is a format seen in public snmpwalk output or the vendor's documentation, cited in SNMP_FORMATS;
# the version is read only when the string states it outright. Left out because their sysDescr states no version: MikroTik RouterOS
# ("RouterOS CCR1036-12G-4S"), FortiGate (an empty string), Palo Alto Networks (the vendor name), Synology and QNAP (a Linux kernel line,
# read as one), and the HP, Brother, Xerox and Ricoh printers (a model, a JetDirect ROM or a date code that no CVE record lists).
SNMP_FORMATS = {
    'cisco-ios': 'Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 12.2(44)SE6, RELEASE SOFTWARE (fc1) '
                 '(https://www.zabbix.com/forum/zabbix-troubleshooting-and-problems/40096-snmpv3-problem-in-zabbix-2-2)',
    'cisco-ios-xe': 'Cisco IOS Software [Amsterdam], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a (https://ignaonline.com/snmp-v3-on-'
                    'cisco-ios-xe-full-monitoring-setup-with-librenms-and-grafana/); 3.x: Cisco IOS Software, IOS-XE Software, Catalyst L3 Switch '
                    'Software (CAT3K_CAA-UNIVERSALK9-M), Version 03.03.03SE RELEASE SOFTWARE (fc2) (https://bugs.racktables.org/view.php?id=1423)',
    'cisco-nx-os': 'Cisco NX-OS(tm) n5000, Software (n5000-uk9), Version 5.1(3)N2(1b), RELEASE SOFTWARE (https://docs.infoblox.com/space/nios91x/2396389719)',
    'cisco-asa': 'Cisco Adaptive Security Appliance Version 9.16(4)18 (https://community.cisco.com/t5/network-security/fpr2130-stoped-to-answer-the-'
                 'snmp-on-some-mibs/td-p/4867332; Cisco\'s own sample: https://www.cisco.com/c/en/us/support/docs/security/firepower-ngfw/'
                 '217884-verify-firepower-software-versions.html)',
    'junos': 'Juniper Networks, Inc. vmx internet router, kernel JUNOS 17.1R2.7, Build date: ... (https://iosonounrouter.wordpress.com/2018/08/03/'
             'polling-junos-via-snmpv3/; Juniper\'s sample: https://apps.juniper.net/cli-explorer/info/show-snmp-mib/)',
    'arubaos-switch': 'Aruba JL255A 2930F-24G-PoE+-4SFP+ Switch, revision WC.16.10.0003, ROM WC.16.01.0008 (https://support.hpe.com/hpesc/public/'
                      'docDisplay?docId=sf000096322en_us)',
    'edgeos': 'EdgeOS v2.0.9-hotfix.2.5402463.210511.1316 (https://community.ui.com/questions/be51b68f-deeb-420e-a6ac-7f5f56538603)',
    'apc-nmc': 'APC Web/SNMP Management Card (MB:v4.0.1 PF:v5.1.7 PN:apc_hw05_aos_517.bin AF1:v5.1.7 AN1:apc_hw05_sumx_517.bin MN:AP9630 ...) '
               '(https://networkupstools.org/ddl/APC/Smart-UPS_5000_RM.html)',
    'linux': 'Linux web1 5.15.0-91-generic #101-Ubuntu SMP ... x86_64 (net-snmp\'s default sysDescr is the uname fields: '
             'https://github.com/net-snmp/net-snmp/blob/master/agent/mibgroup/mibII/system_mib.c)',
    'windows': 'Hardware: Intel64 Family 6 Model 85 Stepping 7 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free) '
               '(https://github.com/iabdullah215/INE-Labs/blob/main/INE/eJPT/ine.ejpt.lab.21.md; builds: '
               'https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info)',
}
SNMP_URL = 'udp/161 sysDescr'
ASA_NAME = 'Cisco Adaptive Security Appliance (ASA) Software'  # correlation's aliases reach the Secure Firewall name and NVD's CPE product
_IOS_BUILD = r'\d{2}\.\d\(\d{1,3}[a-z]?\)[A-Z]{0,4}\d{0,3}[a-z]?'       # 15.0(2)SE11, 12.2(55)SE5, 15.2(4)M7, 15.2(7)E3
_XE_IMAGE = re.compile(r'IOSXE|IOS-XE|IOSD', re.I)                       # an IOS XE image, or the IOS daemon inside one, names itself so
_AFTER = r'(?=[,.\s]|$)'
_IOS = re.compile(rf'^Cisco IOS Software, ([^,]{{1,80}}?) Software \(([A-Za-z0-9_-]{{1,60}})\), Version ({_IOS_BUILD}){_AFTER}')
_IOS_XE_NAMED = re.compile(r'^Cisco IOS Software \[[A-Za-z ]{1,30}\], [^,]{1,80}? Software \(([A-Za-z0-9_-]{1,60})\), '
                           rf'Version (1[6-9]\.\d{{1,2}}\.\d{{1,2}}[a-z]?){_AFTER}')
_IOS_XE_3 = re.compile(r'^Cisco IOS Software, IOS-XE Software, [^,]{1,80}? Software \(([A-Za-z0-9_-]{1,60})\), Version '
                       rf'0?(\d)\.0?(\d{{1,2}})\.0?(\d{{1,2}})\.?([a-z]?[A-Z]{{1,3}}){_AFTER}')
_IOS_XE = re.compile(rf'^Cisco IOS XE Software, Version (1[6-9]\.\d{{1,2}}\.\d{{1,2}}[a-z]?){_AFTER}')
_NXOS = re.compile(r'^Cisco NX-OS\(tm\) ([a-z0-9]{1,20}), Software \(([a-z0-9_-]{1,40})\), '
                   rf'Version (\d{{1,2}}\.\d\(\d{{1,2}}[a-z]?\)(?:[A-Z]\d{{1,2}}\(\d{{1,2}}[a-z]?\))?){_AFTER}')
_ASA = re.compile(rf'^Cisco Adaptive Security Appliance Version (\d\.\d{{1,2}})\((\d{{1,2}})\)(\d{{1,3}})?{_AFTER}')
_JUNOS = re.compile(r'^Juniper Networks, Inc\. ([a-z0-9-]{2,40}) .{0,80}?\bkernel JUNOS (\d{1,2}\.\d)(R\d{1,2}(?:-S\d{1,2})?|X\d{2}-D\d{1,3})'
                    r'(?:\.\d{1,3})?(-EVO)?(?=[\s,#]|$)')
_ARUBA = re.compile(r'^(?:HP|HPE|Aruba|ProCurve) (J[A-Z0-9]{4,6}) [^,]{1,80}? Switch, revision [A-Z]{1,2}\.(1[5-9]\.\d{2}\.\d{4}), ROM ')
_EDGEOS = re.compile(r'^EdgeOS v(\d\.\d{1,2}\.\d{1,2})(?:-hotfix\.(\d{1,2}))?\.\d{5,9}\.\d{6}\.\d{4}(?=\s|$)')
_APC = re.compile(r'^APC Web/SNMP Management Card \(MB:v[\d.]{3,12} PF:v(\d{1,2}\.\d{1,2}\.\d{1,2}) PN:[\w.]{1,40} AF1:v[\d.]{3,12} AN1:[\w.]{1,40} '
                  r'MN:([A-Z]{2}\d{3,5}[A-Z]?)\b')
_LINUX = re.compile(r'^Linux ([A-Za-z0-9._-]{1,64}) (\d\.\d{1,2}(?:\.\d{1,3})?)([-+~][A-Za-z0-9.+~_-]{0,60})? #\S{1,40}')
_WINDOWS = re.compile(r'^Hardware: .{1,120}? - Software: Windows Version (\d{1,2}\.\d) \(Build (\d{4,5})(?: [A-Za-z ]{1,40})?\)')
# The builds the Windows SNMP service reports and the releases they are (Microsoft's release information). Every build from Windows 8.1 on
# reports version 6.3; the build tells the release, never its monthly update.
WINDOWS_BUILDS = {7600: 'Windows 7 or Windows Server 2008 R2', 7601: 'Windows 7 SP1 or Windows Server 2008 R2 SP1', 9200: 'Windows 8 or Windows Server 2012',
                  9600: 'Windows 8.1 or Windows Server 2012 R2', 10240: 'Windows 10 1507', 14393: 'Windows 10 1607 or Windows Server 2016',
                  17763: 'Windows 10 1809 or Windows Server 2019', 19041: 'Windows 10 2004', 19042: 'Windows 10 20H2', 19043: 'Windows 10 21H1',
                  19044: 'Windows 10 21H2', 19045: 'Windows 10 22H2', 20348: 'Windows Server 2022', 22000: 'Windows 11 21H2',
                  22621: 'Windows 11 22H2', 22631: 'Windows 11 23H2', 26100: 'Windows 11 24H2 or Windows Server 2025'}


def cisco_cpe_version(build):
    """A Cisco build as NVD's CPE names spell it: lowercase, parentheses kept (``15.2(4)M7`` -> ``15.2(4)m7``; the CPE 2.3 string escapes
    them, ``15.2\\(4\\)m7``). ASA builds are dotted instead (``9.16(4)18`` -> ``9.16.4.18``), as Cisco's own records and NVD list them."""
    return clip(build, 40).lower()


def _cpe(part, vendor, product, version):
    return f'cpe:2.3:{part}:{vendor}:{product}:' + re.sub(r'([()])', r'\\\1', version) + ':*:*:*:*:*:*:*'


def from_sysdescr(text, enterprise=''):
    """The readings an SNMP agent's sysDescr states (``SNMP_FORMATS``), or []. A network operating system or firmware is a product reading,
    ``exact`` (the agent names its own release); a Linux kernel is a ``weak`` hint (a distribution's kernel carries backported fixes its
    version does not show, and a kernel says nothing of the appliance around it); a Windows build is an ``inferred`` line (the release, never
    its update level). Neither hint is ever matched by version. A Cisco IOS or NX-OS build (``15.2(4)M7``, ``9.3(8)``) keeps the text the
    device prints and carries the CPE NVD names it by; correlation matches it only to a build an advisory lists (``builds``). ``text`` is untrusted: control characters are dropped and it is clipped before
    any pattern sees it. ``enterprise`` (snmp-info's engine ID vendor) is kept as evidence only."""
    said = clip(text, 400)
    vendor = clip(enterprise, 40)
    evidence = f'sysDescr: {said}' + (f' (SNMP engine of {vendor})' if vendor else '')

    def one(component, label, version, cpe='', **kw):
        got = reading(component, label, version, evidence=evidence, url=SNMP_URL, source='snmp', **kw)
        return [{**got, 'cpe': cpe} if cpe else got]

    found = _ASA.match(said)
    if found:
        version = '.'.join(x for x in found.groups() if x)  # 9.16(4)18 is 9.16.4.18
        return one('cisco-asa', ASA_NAME, version, _cpe('a', 'cisco', 'adaptive_security_appliance_software', version))
    found = _NXOS.match(said)
    if found:
        if found.group(1) == 'aci' or found.group(2).startswith('aci'):
            return []  # ACI mode names its own release train, not an NX-OS release
        return one('cisco-nx-os', 'Cisco NX-OS', found.group(3), _cpe('o', 'cisco', 'nx-os', cisco_cpe_version(found.group(3))))
    found = _IOS_XE_NAMED.match(said) or _IOS_XE.match(said)
    if found:
        version = found.group(found.lastindex)
        return one('cisco-ios-xe', 'Cisco IOS XE', version, _cpe('o', 'cisco', 'ios_xe', version.lower()))
    found = _IOS_XE_3.match(said)
    if found:
        version = f'{found.group(2)}.{int(found.group(3))}.{int(found.group(4))}{found.group(5)}'  # 03.06.06E is 3.6.6E, as Cisco lists it
        return one('cisco-ios-xe', 'Cisco IOS XE', version, _cpe('o', 'cisco', 'ios_xe', version.lower()))
    found = _IOS.match(said)
    if found:
        if _XE_IMAGE.search(found.group(2)):
            return []  # the IOS daemon of an IOS XE 3.x release: the build it names is not the IOS XE release
        return one('cisco-ios', 'Cisco IOS', found.group(3), _cpe('o', 'cisco', 'ios', cisco_cpe_version(found.group(3))))
    found = _JUNOS.match(said)
    if found:
        evo = bool(found.group(4))
        version = found.group(2) + found.group(3) + ('-EVO' if evo else '')  # 17.1R2.7 is release 17.1R2, build 7
        return one('junos-evolved' if evo else 'junos', 'Junos OS Evolved' if evo else 'Junos OS', version)
    found = _ARUBA.match(said)
    if found:
        return one('arubaos-switch', 'ArubaOS-Switch', found.group(2))
    found = _EDGEOS.match(said)
    if found:
        return one('edgeos', 'EdgeOS', found.group(1) + (f'-hotfix.{found.group(2)}' if found.group(2) else ''))
    found = _APC.match(said)
    if found:
        return one('apc-nmc', 'APC Network Management Card', found.group(1))
    found = _WINDOWS.match(said)
    if found:
        build = int(found.group(2))
        base = '10.0' if found.group(1) == '6.3' and build >= 10000 else found.group(1)
        release = WINDOWS_BUILDS.get(build, '')
        got = one('windows', 'Windows', f'{base}.{build}', confidence='inferred', line_only=True)
        got[0]['evidence'] = clip(f'build {build}' + (f' ({release})' if release else '') + f'; {evidence}')
        return got
    found = _LINUX.match(said)
    if found:
        return one('linux-kernel', 'Linux kernel', found.group(2) + (found.group(3) or ''), confidence='weak')
    return []


# ----------------------------------------------------------------------------- the runtimes and the CVE records that name them

@dataclass(frozen=True)
class Runtime:
    """How a CVE record names a language runtime (its vendor and product, normalised: letters and digits, lowercase), and whether a host
    where it is clearly present but its version unknown is a version-unknown candidate (``unknown``), as a Java host is."""
    label: str
    vendors: tuple
    products: tuple
    unknown: bool
    commands: tuple = field(default=())   # (platform, command, what it shows): the host owner's reads of the version
    any_product_of: tuple = ()            # vendors whose every product is the runtime (the Go CNA names each standard library package)
    never_products: tuple = ()            # product prefixes that are not the runtime (the Go toolchain's cmd/*)


RUNTIMES = {
    'python': Runtime('Python', ('python', 'pythonsoftwarefoundation', 'psf'), ('python', 'cpython'), True,
                      (('linux', 'python3 -VV', 'The interpreter\'s exact release and build.'),
                       ('linux', 'ps -o pid,args -C gunicorn,uvicorn,python3', 'The Python processes: which interpreter the application runs.'),
                       ('linux', 'readlink -f /proc/<PID>/exe && "$(readlink -f /proc/<PID>/exe)" -VV', 'The interpreter that process runs, and its version.'),
                       ('container', 'docker exec <CONTAINER> python3 -VV', 'The same question inside a container.'))),
    'go': Runtime('Go', ('golang', 'gostandardlibrary', 'go'), ('go', 'golang'), False,
                  (('linux', 'go version <BINARY>', 'The Go release the binary was built with (needs the go tool, or strings <BINARY> | grep -m1 "^go1").'),),
                  any_product_of=('gostandardlibrary',), never_products=('cmd',)),
    'nodejs': Runtime('Node.js', ('nodejs', 'node', 'openjsfoundation'), ('nodejs', 'node'), False,
                      (('linux', 'node --version', 'The Node.js release.'),)),
    'php': Runtime('PHP', ('php', 'phpgroup'), ('php',), False, (('linux', 'php -v', 'The PHP release.'),)),
    'ruby': Runtime('Ruby', ('rubylang', 'ruby'), ('ruby',), True,
                    (('linux', 'ruby -v', 'The Ruby release.'), ('linux', 'passenger-config about ruby-command', 'The Ruby that Passenger runs.'))),
    'dotnet-framework': Runtime('.NET Framework', ('microsoft',), ('netframework', 'microsoftnetframework'), True,
                                (('windows', 'reg query "HKLM\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full" /v Release',
                                  'The installed .NET Framework 4.x release (528040 or more: 4.8; 533320 or more: 4.8.1).'),
                                 ('windows', 'Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10',
                                  'The latest updates: .NET Framework fixes ship in the monthly cumulative updates.'))),
    'erlang': Runtime('Erlang/OTP', ('erlang', 'ericsson'), ('erlangotp', 'otp', 'erlang'), True,
                      (('linux', 'erl -noshell -eval \'io:format("~s~n", [erlang:system_info(otp_release)]), halt().\'', 'The OTP release line.'),
                       ('linux', 'cat "$(dirname "$(readlink -f "$(command -v erl)")")/../releases/*/OTP_VERSION"', 'The exact OTP version.'))),
}


def _token(text):
    return re.sub(r'[^a-z0-9]', '', str(text or '').lower())


def runtime_of_item(item):
    """The runtime (a ``RUNTIMES`` key) one affected entry of a CVE names, or None: its vendor must be the runtime's and its product (or
    package) the runtime's own name; for the Go CNA's records, any standard library package but the toolchain's ``cmd/...``."""
    if not isinstance(item, dict):
        return None
    vendor = _token(item.get('vendor'))
    products = {_token(item.get(k)) for k in ('product', 'package')} - {''}
    for key, runtime in RUNTIMES.items():
        if vendor not in runtime.vendors:
            continue
        if vendor in runtime.any_product_of and products and not any(p.startswith(runtime.never_products) for p in products if runtime.never_products):
            return key
        if any(p in runtime.products or (key == 'dotnet-framework' and p.startswith('netframework')) for p in products):
            return key
    return None
