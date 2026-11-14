"""A bare-word search is an OR over many relations; each branch is its own semi-join (``services._host_has``). The hosts it finds are exactly the hosts the
single big join found, for every kind of term, and the cost of the term does not grow with how many relations the word touches."""
from django.db.models import Exists, OuterRef
from django.test import TestCase
from django.utils import timezone

from agentapi import services
from cveFeed.models import CVEEntry, CVEMatch, HostProfile
from dashboard.models import Org, Project
from scanEngine.models import EngineType
from startScan.models import IpAddress, Port, ScanHistory, Subdomain, Technology, Vulnerability
from targetApp.models import Domain


class HostHasTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        cls.project = Project.objects.create(name='B', slug='sb', insert_date=now, org=Org.objects.create(name='B', slug='sb-org'))
        domain = Domain.objects.create(name='sb.example.test', project=cls.project, insert_date=now)
        scan = ScanHistory.objects.create(domain=domain, scan_type=EngineType.objects.create(engine_name='sb'), start_scan_date=now, scan_status=2)
        cve = CVEEntry.objects.create(cve_id='CVE-2099-55', cvss=5.0, published_at=now)

        def host(name, **kw):
            return Subdomain.objects.create(name=name, target_domain=domain, scan_history=scan, http_status=200, **kw)

        def addr(sub, address, ports=(), **kw):
            ip, _ = IpAddress.objects.get_or_create(address=address, defaults=kw)
            sub.ip_addresses.add(ip)
            for number, state, product in ports:
                ip.ports.add(Port.objects.create(number=number, service_name='http', state=state, product=product))
            return ip

        host('nginx.sb.example.test')                                            # the name
        host('t1.sb.example.test', page_title='Welcome to nginx!')               # the title
        addr(host('t2.sb.example.test'), '192.0.2.10', os_guess='nginx appliance')  # the address's OS guess
        addr(host('t3.sb.example.test'), '192.0.2.11', ports=[(80, 'open', 'nginx')])   # an open port's product
        addr(host('t4.sb.example.test'), '192.0.2.12', ports=[(80, 'closed', 'nginx')])  # a closed port: not on the host
        addr(host('t5.sb.example.test'), '192.0.2.13', ports=[(8080, 'open', 'x'), (81, 'closed', 'y')])
        t6 = host('t6.sb.example.test', webserver='nginx/1.2')                   # the Server header
        t7 = host('t7.sb.example.test')
        t7.technologies.add(Technology.objects.create(name='nginx:1.18'))        # a technology
        Vulnerability.objects.create(name='nginx misconfig', severity=1, source='nuclei', subdomain=host('t8.sb.example.test'), target_domain=domain,
                                     scan_history=scan, open_status=True)
        CVEMatch.objects.create(cve_entry=cve, subdomain=host('t9.sb.example.test'), confidence=0.9, source='version')
        t10 = host('t10.sb.example.test')
        HostProfile.objects.create(project=cls.project, host=t10.name, note='behind nginx')
        host('plain.sb.example.test')
        cls.t6 = t6

    def hosts(self, q, whole):
        rows = Subdomain.objects.all()
        if whole:
            found = Exists(Subdomain.objects.filter(q, pk=OuterRef('pk')))
            rows = rows.filter(found)
        else:
            rows = rows.filter(services._host_has(q))
        return sorted(rows.values_list('name', flat=True))

    def test_every_branch_of_a_bare_word_finds_what_the_whole_join_found(self):
        for query in ('nginx', 'NGINX', 'welcome', '192.0.2.1', 'http', 'CVE-2099', 'misconfig', 'sb.example', 'nosuchword', 'behind',
                      'tech:nginx', 'port:80', 'port:81', 'product:nginx', 'service:http', 'os:appliance', 'cve:2099', 'vuln:nginx', 'host:t1', 'ip:192.0.2.12'):
            for neg, field, value, quoted in services.parse_search(query):
                q = services._term_q(field, value, quoted, self.project)
                self.assertEqual(self.hosts(q, whole=False), self.hosts(q, whole=True), query)

    def test_nginx_finds_the_hosts_it_should(self):
        found = {r['name'] for r in services._search_matches(self.project, services.parse_search('nginx')).values('name')}
        self.assertEqual(found, {'nginx.sb.example.test', 't1.sb.example.test', 't2.sb.example.test', 't3.sb.example.test', 't6.sb.example.test',
                                 't7.sb.example.test', 't8.sb.example.test', 't10.sb.example.test'})  # t4: its only nginx port is closed

    def test_a_negated_word_is_the_rest(self):
        names = {r['name'] for r in services._search_matches(self.project, services.parse_search('-nginx')).values('name')}
        self.assertIn('plain.sb.example.test', names)
        self.assertNotIn('t3.sb.example.test', names)
        self.assertIn('t4.sb.example.test', names)

    def test_an_and_branch_keeps_its_conditions_on_one_port_row(self):
        names = {r['name'] for r in services._search_matches(self.project, services.parse_search('port:81')).values('name')}
        self.assertEqual(names, set())  # port 81 exists on t5 but is closed, and t5's open port is 8080
