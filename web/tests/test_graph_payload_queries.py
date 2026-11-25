"""The asset graph's payload (``cveFeed.views.graph_payload``, served by GET /cve/api/graph) is read in a fixed number of statements, and says exactly
what it said before. The function as it was before the change is copied verbatim below as the oracle and compared with the new one on a fixture of
several organizations, projects, targets, scans and hosts (shared addresses, other names of one host, CVE matches live, ruled out and closed, findings
of every severity and state, aliases, notes, discovery edges, hygiene), under every scope the endpoint builds it for, with and without the node cap.

The new form reads the hosts with only the columns drawn and LIVE_HOST_Q as an EXISTS (no DISTINCT over every column of the host), the addresses as
values, the live CVE matches of the hosts and of their other names in one statement, their findings in one statement, and the projects with their
hygiene counts in one statement: 26 statements and 1.15 s on the live install before, fewer and faster after."""
from unittest import mock

from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from cveFeed import views
from cveFeed.discovery import NUCLEI_SCAN_ACTIVITY_NAMES
from cveFeed.models import CVEEntry, CVEMatch, DiscoveryEvent, HostProfile, HygieneFinding, Triage
from cveFeed.threat import HEAT_RANK, host_heat, match_heat
from cveFeed.views import _host_tip, _tier, asset_status
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, ScanActivity, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tenancy import scope

GRAPH_NODE_CAP = views.GRAPH_NODE_CAP


# ---------------------------------------------------------------------------------------------------------------- the oracle: the code before the change
def old_graph_payload(domain_id=None, scan_id=None):
    """Nodes/edges for the asset graph: domain > subdomain > ip, and subdomain > cve. Only live hosts are drawn (they resolved
    to an IP, or something saw them answer); names that never resolved are left out. Ports belong on the host's detail card."""
    from startScan.models import Subdomain, Vulnerability
    from cveFeed import internal_view
    from cveFeed.graph_overview import root_for

    from django.db.models import Prefetch
    # a match needs its CVE's tier fields only: never the prose columns
    # (and what decides whether it is version-only: its source, evidence and Triage validation status, threat.match_heat)
    matches = CVEMatch.objects.only('subdomain_id', 'ai_verdict', 'evidence', 'version_in_range', 'template_result', 'distro_status', 'source', 'cve_entry__cve_id', 'cve_entry__kev',
                                    'cve_entry__epss_reached', 'cve_entry__exploit_db', 'cve_entry__cvss', 'remediation_status', 'triage__validation_status', 'triage__heat_override', 'triage__status', 'triage__classification').select_related('cve_entry', 'triage')
    # the addresses in id order, as the new form reads them: the prefetch join had no order of its own (the only change to the copy)
    subs = Subdomain.objects.select_related('target_domain__project__org').prefetch_related(
        Prefetch('ip_addresses', queryset=IpAddress.objects.order_by('id')), Prefetch('cve_matches', queryset=matches))
    if domain_id:
        subs = subs.filter(target_domain_id=domain_id)
    if scan_id:
        subs = subs.filter(scan_history_id=scan_id)  # one scan asked for by id: exactly its rows
    else:
        from cveFeed.counts import rep_ids, snapshot_rep_ids
        # otherwise each host once: the row the Hosts page shows. The collapse runs once; the drawn hosts and the per-project totals below read its ids
        subs = subs.filter(pk__in=snapshot_rep_ids() if not domain_id else rep_ids(domain_id))
    nodes, edges = {}, set()
    by_name = {}

    def node(node_id, kind, label, **extra):
        if len(nodes) < GRAPH_NODE_CAP or node_id in nodes:
            nodes.setdefault(node_id, {'id': node_id, 'kind': kind, 'label': label, **extra})
            return True
        return False

    from cveFeed.counts import CLOSED, LIVE_HOST_Q, match_is_live
    from django.db.models import F
    subs = subs.filter(LIVE_HOST_Q).distinct()
    # the riskiest hosts first, then by name: past the node cap the drawn hosts are the ones that matter, and the same ones on every poll
    sub_list = list(subs.order_by(F('score').desc(nulls_last=True), 'name', 'pk')[:GRAPH_NODE_CAP])
    sub_ids = [s.pk for s in sub_list]
    # "scanned" = at least one finding exists at all, even an info-only one (something looked); a
    # second query narrows to the ones severe enough, open, and not ruled out, to call "vulnerable".
    scanned_ids = set(Vulnerability.objects.filter(subdomain_id__in=sub_ids).values_list('subdomain_id', flat=True))
    vulnerable_ids = set(Vulnerability.objects.filter(
        subdomain_id__in=sub_ids, open_status=True, severity__gte=1).exclude(remediation_status__in=CLOSED).values_list('subdomain_id', flat=True))
    vulnerable_ids |= {s.pk for s in sub_list if any(match_is_live(m) for m in s.cve_matches.all())}

    # each open finding's severity (the tip) and heat (threat.finding_heat_rank_expr: under the KEV policy a finding that names CVEs follows the
    # CVE rule, any other its severity)
    from cveFeed.threat import finding_heat_rank_expr
    heat_names = {rank: heat for heat, rank in HEAT_RANK.items()}
    severities, finding_heats = {}, {}
    for sub_id, severity, rank in Vulnerability.objects.filter(subdomain_id__in=sub_ids, open_status=True, severity__gte=1).exclude(remediation_status__in=CLOSED) \
            .annotate(heat_rank=finding_heat_rank_expr()).values_list('subdomain_id', 'severity', 'heat_rank'):
        severities.setdefault(sub_id, []).append(severity)
        if rank in heat_names:
            finding_heats.setdefault(sub_id, []).append(heat_names[rank])

    # one host, several names: the evidence of the other names on the same addresses counts for the host drawn
    from cveFeed.counts import host_siblings
    siblings = host_siblings(sub_ids)
    sibling_ids = {i for rows in siblings.values() for i, _ in rows}
    sibling_matches, sibling_findings = {}, {}
    if sibling_ids:
        for m in CVEMatch.objects.filter(subdomain_id__in=sibling_ids).exclude(ai_verdict='not_affected').exclude(remediation_status__in=CLOSED).only(
                'subdomain_id', 'ai_verdict', 'evidence', 'version_in_range', 'template_result', 'distro_status', 'source', 'cve_entry__cve_id', 'cve_entry__kev', 'cve_entry__epss_reached',
                'cve_entry__exploit_db', 'cve_entry__cvss', 'remediation_status', 'triage__validation_status', 'triage__heat_override', 'triage__status', 'triage__classification').select_related('cve_entry', 'triage'):
            sibling_matches.setdefault(m.subdomain_id, []).append(m)
        for sid, severity, name, rank in Vulnerability.objects.filter(subdomain_id__in=sibling_ids, open_status=True, severity__gte=1).exclude(remediation_status__in=CLOSED) \
                .annotate(heat_rank=finding_heat_rank_expr()).values_list('subdomain_id', 'severity', 'name', 'heat_rank'):
            sibling_findings.setdefault(sid, []).append((severity, name, heat_names.get(rank)))
    own_findings = {}
    if sibling_ids:
        for sid, severity, name in Vulnerability.objects.filter(subdomain_id__in=sub_ids, open_status=True, severity__gte=1).exclude(remediation_status__in=CLOSED) \
                .values_list('subdomain_id', 'severity', 'name'):
            own_findings.setdefault(sid, set()).add((severity, name))

    from startScan.models import ScanActivity
    nuclei_done = set(ScanActivity.objects.filter(scan_of_id__in={s.scan_history_id for s in sub_list if s.scan_history_id},
                                                  name__in=NUCLEI_SCAN_ACTIVITY_NAMES, status=2).values_list('scan_of_id', flat=True))
    # the alias and note a person gave each host (one query): the node's label stays the name, the tooltip and card add them
    from types import SimpleNamespace
    from agentapi.services import alias_and_note
    from cveFeed.models import HostProfile
    wanted = {s.name.lower() for s in sub_list} | {n.lower() for rows in siblings.values() for _, n in rows}
    tags = {(row.project_id, row.host): {'alias': row.alias, 'note': row.note}
            for row in HostProfile.objects.filter(host__in=wanted).exclude(alias='', note='')}
    cut = False  # the node cap stopped the drawing before every host was in
    for sub in sub_list:
        sid = f'sub:{sub.pk}'
        status = asset_status(sub, scanned_ids, vulnerable_ids, nuclei_done)
        live = [m for m in sub.cve_matches.all() if match_is_live(m)]
        sev = list(severities.get(sub.pk, []))
        temps = list(finding_heats.get(sub.pk, []))
        sibs = siblings.get(sub.pk, [])
        have = {m.cve_entry.cve_id for m in live}
        seen_findings = set(own_findings.get(sub.pk, ()))
        for other_id, _ in sibs:
            for m in sibling_matches.get(other_id, []):
                if m.cve_entry.cve_id not in have:
                    have.add(m.cve_entry.cve_id)
                    live.append(m)
            for severity, name, temp in sibling_findings.get(other_id, []):
                if (severity, name) not in seen_findings:
                    seen_findings.add((severity, name))
                    sev.append(severity)
                    if temp:
                        temps.append(temp)
        if status != 'vulnerable' and (live or sev):
            status = 'vulnerable'
        tiers = [match_heat(m) for m in live] + temps
        heat = host_heat(status, tiers, [])
        given = alias_and_note(sub, [SimpleNamespace(name=n, target_domain=sub.target_domain) for _, n in sibs], tags)
        if not node(sid, 'subdomain', sub.name, target=sub.target_domain.name if sub.target_domain_id else '',
                    **{k: given[k] for k in ('alias', 'note') if given[k]},
                    project=sub.target_domain.project.slug if sub.target_domain_id and sub.target_domain.project_id else '',
                    status=status, heat=heat, score=sub.score, info=_host_tip(sub, live, sev, [n for _, n in sibs if n.lower() != sub.name.lower()]),
                    internal=internal_view.is_internal(sub.target_domain.project_id if sub.target_domain_id else None, sub.name),
                    network=internal_view.network_of(sub.target_domain.project_id if sub.target_domain_id else None, sub.name)):
            cut = True
            break
        by_name[sub.name.lower()] = sid
        if sub.target_domain_id and node(f'dom:{sub.target_domain_id}', 'domain', sub.target_domain.name,
                **{k: getattr(sub.target_domain, k) for k in ('alias', 'note') if getattr(sub.target_domain, k)},
                project=sub.target_domain.project.slug if sub.target_domain.project_id else '',
                project_name=sub.target_domain.project.name if sub.target_domain.project_id else '',
                root=root_for(sub.target_domain)):
            edges.add((f'dom:{sub.target_domain_id}', sid))
        for ip in sub.ip_addresses.all():
            if node(f'ip:{ip.pk}', 'ip', ip.address):
                edges.add((sid, f'ip:{ip.pk}'))
        for match in sub.cve_matches.all():
            if not match_is_live(match):
                continue
            cve = match.cve_entry
            if node(f'cve:{cve.pk}', 'cve', cve.cve_id, tier=_tier(cve)):
                edges.add((sid, f'cve:{cve.pk}'))
    # the discovery's own relationships (which host revealed which); scoped the same as the node query above,
    # and otherwise spans every scan the caller can see so the whole project's history draws as one graph.
    events = DiscoveryEvent.objects.exclude(parent_host='')
    if scan_id:
        events = events.filter(scan_id=scan_id)
    elif domain_id:
        events = events.filter(domain_id=domain_id)  # includes CT-monitor finds, which have no scan
    # only an edge between two drawn hosts is ever kept, so read only those (a name in the case the host row spells it and lower case, which
    # is how the discovery reports it), in a fixed order: an arbitrary 1500 of every pair ever stored dropped edges of drawn hosts at random
    drawn = {n for s in sub_list for n in (s.name, s.name.lower())}
    events = events.filter(host__in=drawn, parent_host__in=drawn)
    for parent, host in events.values_list('parent_host', 'host').distinct().order_by('parent_host', 'host')[:GRAPH_NODE_CAP]:
        a, b = by_name.get((parent or '').lower()), by_name.get((host or '').lower())
        if a and b and a != b:
            edges.add((a, b))
    drawn_hosts = sum(1 for n in nodes.values() if n['kind'] == 'subdomain')
    capped = cut or len(sub_list) >= GRAPH_NODE_CAP  # counted only when the cap may have cut the list
    total_hosts, per_project = drawn_hosts, {}
    if capped:
        from django.db.models import Count
        per_project = dict(sorted({slug or '': n for slug, n in subs.order_by().values_list('target_domain__project__slug').annotate(n=Count('pk', distinct=True))}.items()))  # sorted, as the real one is: a GROUP BY has no order of its own
        total_hosts = max(sum(per_project.values()), drawn_hosts)
    return {'nodes': list(nodes.values()), 'edges': [{'from': a, 'to': b} for a, b in sorted(edges)],
            'hosts': {'drawn': drawn_hosts, 'total': total_hosts, 'projects': per_project},
            'projects': _old_graph_projects(domain_id, scan_id)}


def _old_graph_projects(domain_id=None, scan_id=None):
    """``{slug: {'name', 'hygiene'}}`` for every project the caller sees: its open, actionable hygiene findings (the dashboard's Hygiene
    tile), which the graph hangs off the project's cloud beside its fire, smoke and ice hosts. Hygiene findings belong to a target, not
    a host row, so they are counted here rather than from the drawn hosts. One query."""
    from django.db.models import Count
    from cveFeed import counts
    from dashboard.models import Project
    hygiene = counts.actionable_hygiene(HygieneFinding.objects.all())
    if domain_id:
        hygiene = hygiene.filter(domain_id=domain_id)
    if scan_id:
        hygiene = hygiene.none()  # one scan's graph: its hosts only
    found = dict(hygiene.order_by().values_list('domain__project__slug').annotate(n=Count('id')))
    return {slug: {'name': name, 'hygiene': found.get(slug, 0)} for slug, name in Project.objects.values_list('slug', 'name')}


# ---------------------------------------------------------------------------------------------------------------- the fixture


def build_world(tag='gf', hosts=6):
    """Three projects in two organizations, two targets each, an older and a newer full scan of every target (the graph draws the current
    copy), and on each target: hosts with and without addresses, one answering over HTTP only, one that never resolved (not drawn), a second
    name on the address of the first host (one host, two names: the second is its sibling), a CDN address two names share (never merged), a
    scanless row, CVE matches live, ruled out and closed (some with a Triage row), findings of every severity, open, closed and fixed, a finding
    that names a CVE, aliases and notes, discovery edges and hygiene findings."""
    from startScan.models import CveId
    n = next(_WORLDS)  # each world its own addresses and CVE ids
    now = timezone.now()
    engine = EngineType.objects.create(engine_name=f'{tag}-engine')
    orgs = [Org.objects.create(name=f'{tag} org {i}', slug=f'{tag}-org-{i}') for i in range(2)]
    cves = [CVEEntry.objects.create(cve_id=f'CVE-2099-{n:02d}{i:02d}', cvss=[9.8, 7.5, 5.0, 3.1, None][i % 5],
                                    kev=i % 3 == 0, exploit_db=i % 2 == 0, epss_reached=i % 4 == 0, published_at=now) for i in range(10)]
    cdn = IpAddress.objects.create(address=f'203.0.113.{n}', is_cdn=True)
    confidence = iter(range(10_000, 0, -1))  # every match its own confidence: the model's order (-confidence, -created_at) has no ties
    out = {'projects': [], 'domains': [], 'scans': []}
    for p_i, org in enumerate((orgs[0], orgs[0], orgs[1])):
        project = Project.objects.create(name=f'{tag} project {p_i}', slug=f'{tag}{p_i}', insert_date=now, org=org)
        out['projects'].append(project)
        for d_i in range(2):
            domain = Domain.objects.create(name=f'd{d_i}.p{p_i}.{tag}.example.test', project=project, insert_date=now,
                                           alias='Main site' if d_i == 0 else '', note='the target note' if (p_i + d_i) % 2 else '')
            out['domains'].append(domain)
            older = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=now, scan_status=2)
            scan = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=now, scan_status=2)
            out['scans'].append(scan)
            if d_i == 0:
                ScanActivity.objects.create(scan_of=scan, title='Nuclei', name=NUCLEI_SCAN_ACTIVITY_NAMES[0], time=now, status=2)
            HygieneFinding.objects.create(domain=domain, host=domain.name, check_name='spf_missing', severity=2 + d_i, title='SPF missing')
            HygieneFinding.objects.create(domain=domain, host=domain.name, check_name='tls_expired', severity=3, title='TLS expired', status='resolved')
            HygieneFinding.objects.create(domain=domain, host=domain.name, check_name='dmarc_none', severity=1, title='DMARC none', remediation_status='fixed')
            subs = []
            for h in range(hosts):
                name = f'h{h}.d{d_i}.p{p_i}.{tag}.example.test' if h != 4 else f'Mixed{h}.D{d_i}.p{p_i}.{tag}.example.test'
                Subdomain.objects.create(name=name, target_domain=domain, scan_history=older, http_status=200, score=1)  # the older copy
                score = [50, 0, 10, 30, 30, 0, 7, 7][h % 8] if h < 8 else h
                sub = Subdomain.objects.create(name=name, target_domain=domain, scan_history=scan, http_status=200 if h % 3 == 0 else 0, score=score,
                                               score_detail=[{'label': 'Exposed', 'points': 20, 'kind': 'exposure'}, {'label': 'KEV', 'points': 30}] if h % 2 == 0 else [])
                subs.append(sub)
                if h % 6 != 5:  # every sixth host never resolved (and answers nothing unless h % 3 == 0)
                    sub.ip_addresses.add(IpAddress.objects.create(address=f'10.{n}.{p_i * 10 + d_i * 2}.{h + 1}'))
                    if h % 4 == 1:
                        sub.ip_addresses.add(IpAddress.objects.create(address=f'10.{n}.{p_i * 10 + d_i * 2 + 1}.{h + 1}'))
                if h == 3:
                    sub.ip_addresses.add(cdn)
                for k in range(h % 4):
                    match = CVEMatch.objects.create(cve_entry=cves[(h + k + p_i) % len(cves)], subdomain=sub, confidence=next(confidence),
                                                    source=['version', 'nuclei', 'version'][k % 3], version_in_range=k % 2 == 0,
                                                    ai_verdict=['', 'not_affected', 'affected', ''][(h + k) % 4], evidence='banner' if k else '',
                                                    remediation_status=['open', 'open', 'fixed', 'accepted_risk'][(h * k) % 4])
                    if k == 1:
                        Triage.objects.create(project=project, domain=domain, host=sub.name, kind='cve_match', match=match, status='triaged',
                                              classification='confirmed' if h % 2 else 'needs_validation', validation_status='hit' if h % 2 else 'none',
                                              heat_override='fire' if h == 2 else '')
                for k, severity in enumerate((0, 1, 2, 3, 4)[: h % 6]):
                    v = Vulnerability.objects.create(name=f'finding {k}', severity=severity, subdomain=sub, target_domain=domain, scan_history=scan,
                                                     open_status=k != 3, **({'remediation_status': 'fixed'} if k == 2 and h % 2 else {}))
                    if k == 4:
                        v.cve_ids.add(CveId.objects.get_or_create(name=cves[0].cve_id)[0])
                    if k == 1 and h % 2:
                        Triage.objects.create(project=project, domain=domain, host=sub.name, kind='nuclei', vulnerability=v, status='triaged',
                                              classification='confirmed', validation_status='hit')
            # a second name on the first host's address: one host, the other name is its sibling, with evidence of its own
            first = subs[0]
            twin = Subdomain.objects.create(name=f'www.{first.name}', target_domain=domain, scan_history=scan, http_status=0, score=-5)
            twin.ip_addresses.add(*first.ip_addresses.all())
            CVEMatch.objects.create(cve_entry=cves[7], subdomain=twin, confidence=next(confidence), source='version')
            CVEMatch.objects.create(cve_entry=cves[8], subdomain=twin, confidence=next(confidence), source='nuclei', ai_verdict='not_affected')
            Vulnerability.objects.create(name='twin finding', severity=3, subdomain=twin, target_domain=domain, scan_history=scan, open_status=True)
            Vulnerability.objects.create(name='twin finding low', severity=1, subdomain=twin, target_domain=domain, scan_history=scan, open_status=True)
            Vulnerability.objects.create(name='twin closed', severity=4, subdomain=twin, target_domain=domain, scan_history=scan, open_status=False)
            # a second name behind the CDN address: never merged with the first
            Subdomain.objects.create(name=f'cdn.{domain.name}', target_domain=domain, scan_history=scan, http_status=0, score=3).ip_addresses.add(cdn)
            # a row with no scan (certificate transparency), answering over HTTP
            Subdomain.objects.create(name=f'ct.{domain.name}', target_domain=domain, http_status=301, score=2)
            HostProfile.objects.create(project=project, host=first.name.lower(), alias=f'{tag} box {p_i}{d_i}', note='racked')
            HostProfile.objects.create(project=project, host=twin.name.lower(), alias='', note='the twin note')
            HostProfile.objects.create(project=project, host=subs[2].name.lower(), alias='', note='')
            for parent, host in ((first.name, subs[1].name), (subs[1].name, subs[2].name.upper()), (subs[2].name, subs[-1].name.lower()),
                                 (subs[3].name, subs[3].name), ('', subs[0].name), (subs[0].name, 'nowhere.example.test')):
                DiscoveryEvent.objects.create(domain=domain, scan=scan, type='DNS_NAME', host=host, parent_host=parent)
            DiscoveryEvent.objects.create(domain=domain, scan=None, type='DNS_NAME', host=subs[-1].name, parent_host=subs[0].name)  # certificate transparency
    return out


_WORLDS = __import__('itertools').count(1)
SCOPES = ('all', 'p0', 'p1', 'p0+p2', 'none')


class GraphPayloadEquivalenceTests(TestCase):
    """The new graph_payload says exactly what the old one said, under every scope and filter and at every node cap."""

    @classmethod
    def setUpTestData(cls):
        cls.world = build_world()

    def setUp(self):
        cache.clear()  # the host collapse and the internal-network table are cached; every case starts cold

    def scoped(self, which):
        projects = self.world['projects']
        return {'all': None, 'p0': {projects[0].id}, 'p1': {projects[1].id}, 'p0+p2': {projects[0].id, projects[2].id}, 'none': set()}[which]

    def both(self, which, cap=None, **kwargs):
        import json
        allowed = self.scoped(which)
        tokens = scope.set_scope(allowed) if allowed is not None else None
        try:
            with mock.patch.object(views, 'GRAPH_NODE_CAP', cap or GRAPH_NODE_CAP), \
                    mock.patch(f'{__name__}.GRAPH_NODE_CAP', cap or GRAPH_NODE_CAP):
                cache.clear()
                old = old_graph_payload(**kwargs)
                cache.clear()
                new = views.graph_payload(**kwargs)
        finally:
            if tokens:
                scope.reset_scope(tokens)
        self.assertEqual(new, old, (which, cap, kwargs))
        self.assertEqual(json.dumps(new), json.dumps(old), 'the same order of nodes, keys and projects too')
        return new

    def test_the_whole_inventory_under_every_scope(self):
        for which in SCOPES:
            with self.subTest(which):
                payload = self.both(which)
                if which != 'none':
                    self.assertTrue(any(n['kind'] == 'subdomain' for n in payload['nodes']))
        payload = self.both('all')
        kinds = {n['kind'] for n in payload['nodes']}
        self.assertEqual(kinds, {'subdomain', 'domain', 'ip', 'cve'})  # the fixture reaches every kind of node
        subs = [n for n in payload['nodes'] if n['kind'] == 'subdomain']
        self.assertTrue(any(n.get('alias') for n in subs) and any(n.get('note') for n in subs))
        self.assertTrue(any(n['info']['aliases'] for n in subs), 'a host drawn with its other name')
        self.assertEqual({n['status'] for n in subs}, {'vulnerable', 'scanned', 'unscanned'})
        self.assertTrue(any(e['from'].startswith('sub:') and e['to'].startswith('sub:') for e in payload['edges']), 'a discovery edge')
        self.assertTrue(any(p['hygiene'] for p in payload['projects'].values()))

    def test_one_target_and_one_scan(self):
        for which in ('all', 'p0', 'p1'):
            for domain in self.world['domains'][:3]:
                with self.subTest(which=which, domain=domain.name):
                    self.both(which, domain_id=domain.id)
            for scan in self.world['scans'][:3]:
                with self.subTest(which=which, scan=scan.id):
                    self.both(which, scan_id=scan.id)
            with self.subTest(which=which, domain_and_scan=True):
                self.both(which, domain_id=self.world['domains'][0].id, scan_id=self.world['scans'][0].id)

    def test_past_the_node_cap_at_every_point_of_the_drawing(self):
        for cap in (1, 2, 3, 5, 8, 13, 21, 34, 55, 89):
            for which in ('all', 'p0+p2'):
                with self.subTest(cap=cap, which=which):
                    payload = self.both(which, cap=cap)
                    self.assertLessEqual(len(payload['nodes']), cap)
        payload = self.both('all', cap=13)
        self.assertGreater(payload['hosts']['total'], payload['hosts']['drawn'])  # the per-project totals are counted
        self.assertTrue(payload['hosts']['projects'])


class GraphPayloadQueryCountTests(TestCase):
    """A fixed number of statements, fewer than before, however many hosts, matches, findings and other names are drawn."""

    def count(self, fn):
        fn()  # the first call fills the process-wide caches (content types, the internal-network table, settings)
        with CaptureQueriesContext(connection) as q:
            fn()
        return len(q)

    def test_fewer_statements_than_before_and_a_fixed_number(self):
        build_world('qa', hosts=4)
        cache.clear()
        small, before = self.count(views.graph_payload), self.count(old_graph_payload)
        build_world('qb', hosts=8)
        build_world('qc', hosts=8)
        cache.clear()
        bigger, before_bigger = self.count(views.graph_payload), self.count(old_graph_payload)
        self.assertEqual(small, bigger, 'three times the hosts, matches, findings and other names: the same statements')
        self.assertLessEqual(bigger, before_bigger - 5, (bigger, before_bigger))
        self.assertLessEqual(bigger, GRAPH_QUERY_BOUND, bigger)

    def test_past_the_cap_one_more_statement_counts_the_hosts_per_project(self):
        build_world('qd', hosts=6)
        cache.clear()
        under = self.count(views.graph_payload)
        with mock.patch.object(views, 'GRAPH_NODE_CAP', 10):
            capped = self.count(views.graph_payload)
        self.assertEqual(capped, under + 1)

    def test_one_target_and_one_scan_cost_the_same_handful(self):
        world = build_world('qe', hosts=6)
        cache.clear()
        self.assertLessEqual(self.count(lambda: views.graph_payload(domain_id=world['domains'][0].id)), GRAPH_QUERY_BOUND)
        self.assertLessEqual(self.count(lambda: views.graph_payload(scan_id=world['scans'][0].id)), GRAPH_QUERY_BOUND)


class GraphEndpointTests(TestCase):
    """GET /cve/api/graph serves the same payload, narrowed to the project asked for."""

    @classmethod
    def setUpTestData(cls):
        from django.contrib.auth.models import User
        cls.world = build_world('ep', hosts=4)
        cls.user = User.objects.create_user('gf-root', password='x', is_superuser=True)

    def setUp(self):
        cache.clear()
        views.clear_stats_cache()
        self.client.force_login(self.user)

    def test_the_endpoint_serves_the_oracle_payload_of_the_project(self):
        project = self.world['projects'][1]
        response = self.client.get(f'/cve/api/graph?project={project.slug}')
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        payload.pop('version')
        tokens = scope.set_scope({project.id})
        try:
            cache.clear()
            expected = views.compact_graph(old_graph_payload())  # sent as compact_graph leaves it (tests/test_graph_payload_size.py)
        finally:
            scope.reset_scope(tokens)
        self.assertEqual(payload, expected)
        self.assertEqual({n['project'] for n in payload['nodes'] if n['kind'] == 'subdomain'}, {project.slug})


# Statements of one graph_payload over the whole inventory, measured on the fixture (the old form: 25; on the live install 26 before, 20 after,
# one of them the per-project count past the node cap): 6 for the host collapse (counts.rep_ids), 1 for the hosts, 1 for their addresses, 5 for the
# other names of each host (counts.host_siblings), 1 for the live CVE matches of both, 1 for the findings of both, 1 for the nuclei steps, 1 for the
# aliases and notes, 1 for the discovery edges, 1 for the projects and their hygiene.
GRAPH_QUERY_BOUND = 19

