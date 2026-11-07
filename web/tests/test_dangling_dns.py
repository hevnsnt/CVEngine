"""Dangling-DNS findings (bbot's baddns) rated by what an outsider can claim: cveFeed.dangling_dns, its use when bbot findings are stored, the
rerate_dangling_dns backfill, and the ownership check before bucket names are guessed (cveFeed.domain_ownership).

Every fixture is synthetic (example.com/.net/.org, documentation addresses) and keeps only the shape of a stored bad input. No test sends a DNS
or HTTP request: the network is a fake (FakeDns) that answers like authoritative servers do."""
import io
import os
from unittest import mock

from django.core.management import call_command
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from cveFeed import dangling_dns as dd
from cveFeed import domain_ownership as own
from dashboard.models import Org, Project
from reNgine import discovery_events as bbot_lib
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.fake_scanner import FakeScanner

GCLOUD = [f'ns-cloud-c{i}.googledomains.com' for i in range(1, 5)]


def baddns(head, trigger, signature='GENERIC', confidence='LOW', indicator='DNSWalk Analysis', module='NS'):
    """A description the way bbot's baddns module writes it."""
    return (f'{head}. Confidence: [{confidence}] Signature: [{signature}] Indicator: [{indicator}] Trigger: [{", ".join(trigger)}] '
            f'baddns Module: [{module}]')


NS_HEAD = 'Dangling NS Records (NS records without SOA) with known impact'
NX_HEAD = 'Dangling CNAME, possible subdomain takeover (NXDOMAIN technique)'
HTTP_HEAD = 'Dangling CNAME, probable subdomain takeover (HTTP String Match)'


class FakeDns:
    """Authoritative DNS in memory. ``zones``: zone -> {'ns': [hosts], 'children': {name: [hosts]}, 'cnames': {name: target}}. A server answers
    for the deepest zone it serves (a referral for a delegated child, a CNAME, the SOA, NS, or no data) and REFUSED for a zone it does not
    serve, like a self-service provider whose account holds no such zone. ``silent`` hosts never answer; ``servfail`` hosts answer SERVFAIL."""

    def __init__(self, zones, addresses, silent=(), servfail=(), registered=None, http=None):
        self.zones, self.ips, self.silent, self.servfail = zones, addresses, set(silent), set(servfail)
        self.host_of = {ip: host for host, ips in addresses.items() for ip in ips}
        self.registered_map, self.http = registered or {}, http
        self.asked, self.http_calls = [], []

    def ns(self, name):
        return list(self.zones.get(name, {}).get('ns', []))

    def addresses(self, host):
        return list(self.ips.get(host, []))

    def ask(self, server, qname, rdtype):
        self.asked.append((server, qname, rdtype))
        host = self.host_of.get(server)
        if host in self.silent:
            return None
        if host in self.servfail:
            return dd.Reply('SERVFAIL')
        served = [z for z, data in self.zones.items() if host in data.get('ns', []) and (qname == z or qname.endswith('.' + z))]
        if not served:
            return dd.Reply('REFUSED')
        zone = max(served, key=len)
        data = self.zones[zone]
        for child, hosts in data.get('children', {}).items():
            if qname == child or qname.endswith('.' + child):
                return dd.Reply('NOERROR', authority=[(child, 'NS', h) for h in hosts])
        if qname in data.get('cnames', {}):
            return dd.Reply('NOERROR', aa=True, answer=[(qname, 'CNAME', data['cnames'][qname])])
        if qname == zone and rdtype == 'SOA':
            return dd.Reply('NOERROR', aa=True, answer=[(zone, 'SOA', f'ns.{zone} hostmaster.{zone} 1 2 3 4 5')])
        if qname == zone and rdtype == 'NS':
            return dd.Reply('NOERROR', aa=True, answer=[(zone, 'NS', h) for h in data['ns']])
        return dd.Reply('NOERROR', aa=True, authority=[(zone, 'SOA', f'ns.{zone} hostmaster.{zone} 1 2 3 4 5')])

    def registered(self, domain):
        return self.registered_map.get(domain)

    def http_control(self, host):
        self.http_calls.append(host)
        return self.http


def registry_and_client(children=None, client_children=None, cnames=None, apex='example.com'):
    """The .com registry delegating ``apex`` to its own healthy servers, which delegate ``client_children``."""
    tld = apex.rsplit('.', 1)[1]
    zones = {tld: {'ns': ['a.registry.example.net'], 'children': {apex: ['ns1.example.net', 'ns2.example.net'], **(children or {})}},
             apex: {'ns': ['ns1.example.net', 'ns2.example.net'], 'children': client_children or {}, 'cnames': cnames or {}}}
    addresses = {'a.registry.example.net': ['192.0.2.1'], 'ns1.example.net': ['192.0.2.2'], 'ns2.example.net': ['192.0.2.3'],
                 **{h: [f'198.51.100.{i}'] for i, h in enumerate(GCLOUD, start=1)},
                 'ns1.dns-host.example.org': ['198.51.100.20'], 'ns2.dns-host.example.org': ['198.51.100.21']}
    return zones, addresses


class ParseTests(SimpleTestCase):
    def test_the_three_rated_kinds_and_their_trigger(self):
        p = dd.parse(baddns(NS_HEAD, GCLOUD, signature='cloud.google.com'))
        self.assertEqual((p.kind, p.signature, p.triggers), (dd.KIND_NS, 'cloud.google.com', GCLOUD))
        self.assertEqual(dd.parse(baddns(NX_HEAD, ['x.example.net'], module='CNAME')).kind, dd.KIND_NXDOMAIN)
        self.assertEqual(dd.parse(baddns(HTTP_HEAD, ['email.example.com', 'mailgun.org'], module='CNAME')).triggers,
                         ['email.example.com', 'mailgun.org'])
        self.assertIsNone(dd.parse(baddns('No DMARC record found', ['_dmarc.example.com'], module='DMARC')))
        self.assertIsNone(dd.parse('Subdomain takeover: dangling CNAME'))

    def test_a_stored_note_is_not_read_as_baddns_text_and_is_replaced_not_stacked(self):
        text = baddns(NS_HEAD, GCLOUD)
        once = dd.with_note(text, dd.Rating(note='first'))
        twice = dd.with_note(once, dd.Rating(note='second'))
        self.assertEqual(twice, text + dd.NOTE_MARKER + 'second')
        self.assertEqual(dd.parse(twice).triggers, GCLOUD)

    def test_provider_list_is_conservative_data(self):
        self.assertEqual(dd.claimable_provider('app-1.azurewebsites.net'), 'Microsoft Azure')
        self.assertEqual(dd.claimable_provider('ACME.GitHub.io.'), 'GitHub Pages')
        for target in ('internal-lb-0123456789.us-east-1.elb.amazonaws.com', 'tenant.enterprise.buf.build', 'org-env.apigee.net',
                       'x.secureserver.net', 'mailgun.org', 'notgithub.io'):
            self.assertIsNone(dd.claimable_provider(target), target)
        self.assertEqual(dd.self_service_provider(GCLOUD), 'Google Cloud DNS')
        self.assertEqual(dd.self_service_provider(['ns-1.awsdns-01.org', 'ns-2.awsdns-02.co.uk']), 'AWS Route 53')
        self.assertIsNone(dd.self_service_provider(['ns-cloud-c1.googledomains.com', 'ns1.example.net']))  # every server must be at one


class ReplyTests(SimpleTestCase):
    def test_a_referral_and_a_refusal_read_from_dns_messages(self):
        import dns.message
        referral = dns.message.from_text(
            'id 1\nopcode QUERY\nrcode NOERROR\nflags QR\n;QUESTION\nd.example.com. IN NS\n;ANSWER\n;AUTHORITY\n'
            'd.example.com. 300 IN NS ns-cloud-c1.googledomains.com.\nd.example.com. 300 IN NS ns-cloud-c2.googledomains.com.\n;ADDITIONAL\n')
        reply = dd.reply_from(referral)
        self.assertEqual((reply.rcode, reply.aa), ('NOERROR', False))
        self.assertEqual(reply.values('d.example.com.', 'NS'), GCLOUD[:2])
        refused = dd.reply_from(dns.message.from_text('id 2\nopcode QUERY\nrcode REFUSED\nflags QR\n;QUESTION\nd.example.com. IN SOA\n'))
        self.assertEqual(refused.rcode, 'REFUSED')
        cname = dd.reply_from(dns.message.from_text(
            'id 3\nopcode QUERY\nrcode NOERROR\nflags QR AA\n;QUESTION\nv.example.com. IN NS\n;ANSWER\nv.example.com. 60 IN CNAME a.up.railway.app.\n'))
        self.assertEqual((cname.aa, cname.values('v.example.com', 'CNAME', ('answer',))), (True, ['a.up.railway.app']))


class NameServerRatingTests(SimpleTestCase):
    """Item 6 (under-rated): a delegation to a self-service DNS provider that no account serves is a zone takeover. Item 17: it is evaluated at
    the client's own zone cut, and a provider zone reached through a CNAME is not the client's delegation."""

    def assess(self, host, net, trigger=GCLOUD):
        return dd.assess({'host': host, 'module': 'baddns', 'description': baddns(NS_HEAD, trigger, signature='cloud.google.com')}, net=net)

    def test_a_sub_zone_delegated_to_google_cloud_dns_that_every_server_refuses_is_fire(self):
        zones, addresses = registry_and_client(client_children={'d.fs.app.example.com': GCLOUD})
        net = FakeDns(zones, addresses)
        rating = self.assess('dev.d.fs.app.example.com', net)
        self.assertEqual((rating.severity, rating.drop, rating.zone), (dd.FIRE_SEVERITY, False, 'd.fs.app.example.com'))
        self.assertIn('Google Cloud DNS', rating.note)
        soa = [a for a in net.asked if a[2] == 'SOA']
        self.assertEqual(sorted(s for s, _q, _t in soa), [f'198.51.100.{i}' for i in range(1, 5)])  # every delegated server was asked
        self.assertEqual({q for _s, q, _t in soa}, {'d.fs.app.example.com'})  # for the zone at the cut, not the matched name

    def test_an_apex_the_registry_delegates_to_google_cloud_dns_that_refuses_it_is_fire(self):
        zones = {'org': {'ns': ['a.registry.example.net'], 'children': {'example.org': GCLOUD}}}
        addresses = {'a.registry.example.net': ['192.0.2.1'], **{h: [f'198.51.100.{i}'] for i, h in enumerate(GCLOUD, start=1)}}
        rating = self.assess('www.example.org', FakeDns(zones, addresses))
        self.assertEqual((rating.severity, rating.zone), (dd.FIRE_SEVERITY, 'example.org'))

    def test_servfail_counts_like_refused(self):
        zones, addresses = registry_and_client(client_children={'d.example.com': GCLOUD})
        rating = self.assess('d.example.com', FakeDns(zones, addresses, servfail=GCLOUD[:2]))
        self.assertEqual(rating.severity, dd.FIRE_SEVERITY)

    def test_a_name_that_is_a_cname_into_a_provider_zone_is_not_the_clients_delegation(self):
        zones, addresses = registry_and_client(cnames={'vision.example.com': 'abc123.up.railway.app'})
        rating = self.assess('vision.example.com', FakeDns(zones, addresses), trigger=['ns1.railway.app'])
        self.assertTrue(rating.drop)
        self.assertIn('CNAME to abc123.up.railway.app', rating.note)

    def test_a_lame_delegation_at_a_provider_that_is_not_self_service_stays_smoke(self):
        zones, addresses = registry_and_client(client_children={'old.example.com': ['ns1.dns-host.example.org', 'ns2.dns-host.example.org']})
        rating = self.assess('old.example.com', FakeDns(zones, addresses), trigger=['ns1.dns-host.example.org'])
        self.assertEqual(rating.severity, dd.SMOKE_SEVERITY)

    def test_a_delegation_that_is_served_is_ice(self):
        zones, addresses = registry_and_client(client_children={'d.example.com': GCLOUD})
        zones['d.example.com'] = {'ns': GCLOUD}
        rating = self.assess('d.example.com', FakeDns(zones, addresses))
        self.assertEqual(rating.severity, dd.ICE_SEVERITY)

    def test_a_name_inside_a_healthy_zone_with_no_cut_of_its_own_is_ice(self):
        zones, addresses = registry_and_client()
        self.assertEqual(self.assess('app.example.com', FakeDns(zones, addresses)).severity, dd.ICE_SEVERITY)

    def test_a_server_that_does_not_answer_leaves_baddns_rating(self):
        zones, addresses = registry_and_client(client_children={'d.example.com': GCLOUD})
        self.assertIsNone(self.assess('d.example.com', FakeDns(zones, addresses, silent=GCLOUD[3:])))
        self.assertIsNone(self.assess('d.example.com', FakeDns(zones, addresses, silent=['a.registry.example.net'])))

    def test_the_checks_can_be_turned_off(self):
        zones, addresses = registry_and_client(client_children={'d.example.com': GCLOUD})
        with mock.patch.dict(os.environ, {'CVENGINE_DANGLING_DNS_CHECKS': '0'}):
            self.assertIsNone(self.assess('d.example.com', FakeDns(zones, addresses)))


class CnameRatingTests(SimpleTestCase):
    """Item 6 (over-rated): an NXDOMAIN CNAME is ice unless the target is at a claimable provider or its registrable domain is unregistered.
    Item 18: an HTTP string match the provider shows for every host name is dropped."""

    def nx(self, target, **net):
        return dd.assess({'host': 'pda.example.com', 'module': 'baddns', 'description': baddns(NX_HEAD, [target], confidence='MEDIUM',
                                                                                                    indicator='Generic Dangling CNAME', module='CNAME')},
                         net=FakeDns({}, {}, **net))

    def test_targets_no_outsider_can_create_are_ice(self):
        for target, domain in (('internal-lb-0123456789.us-east-1.elb.amazonaws.com', 'amazonaws.com'),
                               ('tenant.enterprise.buf.build', 'buf.build'), ('org-prod.apigee.net', 'apigee.net'),
                               ('pda.example.net', 'example.net'), ('x.secureserver.net', 'secureserver.net'), ('gone.example.com', 'example.com')):
            rating = self.nx(target, registered={domain: True})
            self.assertEqual((rating.severity, rating.drop), (dd.ICE_SEVERITY, False), target)
            self.assertIn(f'{domain} is registered', rating.note)

    def test_a_target_at_a_claimable_provider_keeps_its_rating(self):
        rating = self.nx('old-app.azurewebsites.net')
        self.assertIsNone(rating.severity)
        self.assertIn('Microsoft Azure', rating.note)

    def test_a_target_whose_domain_is_unregistered_keeps_its_rating(self):
        rating = self.nx('www.lapsed-example.net', registered={'lapsed-example.net': False})
        self.assertIsNone(rating.severity)
        self.assertIn('not registered', rating.note)

    def test_unknown_registration_changes_nothing(self):
        self.assertIsNone(self.nx('www.example.net'))

    def http(self, chain, answer):
        net = FakeDns({}, {}, http=answer)
        rating = dd.assess({'host': 'email.mail.example.com', 'module': 'baddns', 'description': baddns(
            HTTP_HEAD, chain, signature='Mailgun Takeover Detection', confidence='HIGH', indicator='status 404', module='CNAME')}, net=net)
        return rating, net

    def test_a_mailgun_404_that_a_random_host_name_also_gets_is_dropped(self):
        body = b'404 page not found\n'
        rating, net = self.http(['mailgun.org'], ((404, body), (404, body), 'cvengine-control-ab12.email.mail.example.com'))
        self.assertTrue(rating.drop)
        self.assertEqual(net.http_calls, ['email.mail.example.com'])
        self.assertIn('random host name', rating.note)

    def test_the_host_name_echoed_in_a_page_does_not_make_it_different(self):
        control = 'cvengine-control-ab12.email.mail.example.com'
        rating, _net = self.http(['mailgun.org'], ((404, b'<p>No site at email.mail.example.com</p>'), (404, f'<p>No site at {control}</p>'.encode()), control))
        self.assertTrue(rating.drop)

    def test_a_host_specific_answer_keeps_the_finding(self):
        rating, _net = self.http(['mailgun.org'], ((404, b'Domain not configured: claim it'), (404, b'404 page not found'), 'cvengine-control-1.x'))
        self.assertIsNone(rating)
        self.assertIsNone(self.http(['mailgun.org'], None)[0])  # no answer: unchanged

    def test_a_claimable_provider_is_not_controlled(self):
        rating, net = self.http(['acme.github.io'], ((404, b'same'), (404, b'same'), 'c'))
        self.assertIsNone(rating)
        self.assertEqual(net.http_calls, [])


class Stored(TestCase):
    def setUp(self):
        org = Org.objects.create(name='D', slug='d-dd')
        self.project = Project.objects.create(name='P', slug='p-dd', insert_date=timezone.now(), org=org)
        self.domain = Domain.objects.create(name='example.com', project=self.project, insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='e', yaml_configuration='x', default_engine=True)
        self.scan = ScanHistory.objects.create(domain=self.domain, scan_type=engine, start_scan_date=timezone.now(), scan_status=1, tasks=[],
                                               results_dir='x')
        self.ctx = {'scan_history_id': self.scan.id, 'domain_id': self.domain.id, 'subdomain_id': None, 'subscan_id': None}
        mock.patch('reNgine.tasks.geo_localize.delay').start()
        mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False).start()
        mock.patch('agentapi.sentinel_dispatch._resolves', return_value=True).start()
        self.addCleanup(mock.patch.stopall)
        zones, addresses = registry_and_client(client_children={'d.fs.app.example.com': GCLOUD},
                                               cnames={'vision.example.com': 'abc123.up.railway.app'})
        self.net = FakeDns(zones, addresses)

    def scanner(self, descriptions):
        """The fake built-in scanner, rating each asked finding with the rules of ``dangling_dns.assess`` over the in-memory DNS (``self.net``): what a
        Sentinel's probe does with the real network. ``descriptions`` maps a host to the baddns text the server holds for it."""
        def answer(task):
            rows = []
            for check in task['target']['checks']:
                rating = dd.assess({'host': check['host'], 'description': descriptions[check['host']], 'module': 'baddns'}, net=self.net)
                rows.append({'id': check['id'], 'state': 'unknown'} if rating is None else
                            {'id': check['id'], 'state': 'rated', 'severity': rating.severity, 'drop': rating.drop, 'note': rating.note, 'zone': rating.zone})
            return {'outcome': 'done', 'ratings': rows, 'touched': [], 'refused': []}
        return FakeScanner(kinds=['dangling_dns_check'], responders={'dangling_dns_check': answer})

    def event(self, host, description):
        return {'type': 'FINDING', 'id': host, 'host': host, 'module': 'baddns', 'data': None,
                'data_json': {'host': host, 'severity': 'MEDIUM', 'description': description}}

    def persist(self, *events):
        from reNgine.tasks import persist_bbot_result
        from tests.discovery_fixtures import fold_findings
        result = fold_findings(events)
        with self.scanner({e['host']: e['data_json']['description'] for e in events}):
            persist_bbot_result(result, ctx=self.ctx)


class StoredFindingTests(Stored):
    def test_a_claimable_delegation_is_stored_hot_with_its_host_and_a_provider_zone_is_not_stored(self):
        self.persist(self.event('dev.d.fs.app.example.com', baddns(NS_HEAD, GCLOUD, signature='cloud.google.com')),
                     self.event('vision.example.com', baddns('Dangling NS Records (NS records without SOA)', ['ns1.railway.app'])))
        v = Vulnerability.objects.get()
        self.assertEqual((v.severity, v.subdomain.name, v.http_url), (3, 'dev.d.fs.app.example.com', 'dev.d.fs.app.example.com'))
        self.assertIn(dd.NOTE_MARKER + 'd.fs.app.example.com is delegated to Google Cloud DNS', v.description)
        from cveFeed.threat import finding_heat
        self.assertEqual(finding_heat(v), 'fire')

    def test_a_stale_cname_is_stored_as_ice_and_the_row_key_does_not_change(self):
        description = baddns(NX_HEAD, ['internal-lb-1.us-east-1.elb.amazonaws.com'], confidence='MEDIUM', module='CNAME')
        self.net.registered_map = {'amazonaws.com': True}
        self.persist(self.event('pda.example.com', description))
        self.persist(self.event('pda.example.com', description))  # seen again: the same row
        v = Vulnerability.objects.get()
        self.assertEqual((v.severity, v.matcher_name), (1, bbot_lib.finding_key(description)))
        from cveFeed.threat import finding_heat
        self.assertEqual(finding_heat(v), 'ice')


class RerateCommandTests(Stored):
    def row(self, host, description, severity=2, sub=True):
        subdomain = Subdomain.objects.create(scan_history=self.scan, target_domain=self.domain, name=host) if sub else None
        return Vulnerability.objects.create(name='x', severity=severity, description=description, source='bbot', type='bbot', template_id='baddns',
                                            target_domain=self.domain, scan_history=self.scan, subdomain=subdomain, http_url=host)

    def run_command(self, *args):
        out = io.StringIO()
        with self.scanner({v.subdomain.name if v.subdomain_id else v.http_url: v.description for v in Vulnerability.objects.all()}):
            call_command('rerate_dangling_dns', *args, stdout=out)
        return out.getvalue()

    def test_dry_run_reports_and_writes_nothing_then_apply_writes(self):
        ns = self.row('dev.d.fs.app.example.com', baddns(NS_HEAD, GCLOUD), sub=False)  # stored with no host
        cname = self.row('vision.example.com', baddns('Dangling NS Records (NS records without SOA)', ['ns1.railway.app']))
        closed = self.row('other.d.fs.app.example.com', baddns(NS_HEAD, GCLOUD))
        closed.remediation_status = 'false_positive'
        closed.save()
        report = self.run_command()
        self.assertIn('dry run', report)
        self.assertIn('p-dd: examined: 2, host filled: 1, medium -> high: 1, medium -> info: 1', report)
        ns.refresh_from_db()
        self.assertEqual((ns.severity, ns.subdomain_id), (2, None))
        report = self.run_command('--apply')
        self.assertIn('written: 2', report)
        ns.refresh_from_db()
        cname.refresh_from_db()
        closed.refresh_from_db()
        self.assertEqual((ns.severity, ns.subdomain.name, cname.severity, closed.severity), (3, 'dev.d.fs.app.example.com', 0, 2))
        self.assertIn('is a CNAME to abc123.up.railway.app', cname.description)


class OwnershipTests(SimpleTestCase):
    """Item 21: no bucket names are guessed from a domain that shows another owner."""

    class Lookup:
        def __init__(self, records, registrants=None):
            self.recs, self.regs = records, registrants or {}

        def records(self, name, rtype):
            return self.recs.get((name, rtype), [])

        def registrant(self, domain):
            return self.regs.get(domain, '')

    INFRA = {('example.com', 'NS'): ['ns1.example-dns.net.', 'ns2.example-dns.org.'], ('example.com', 'MX'): ['10 smtp.example-retail.net.'],
             ('example-client.com', 'NS'): ['ns1.markmonitor.com.'], ('example-client.com', 'MX'): ['10 aspmx.l.google.com.']}

    def test_another_companys_name_and_mail_servers_mean_another_owner(self):
        reason = own.foreign_owner('example.com', ['example-client.com'], self.Lookup(self.INFRA))
        self.assertIn('example-dns.net', reason)
        self.assertIn('example-retail.net', reason)

    def test_a_different_published_registrant_means_another_owner_and_the_same_one_means_the_same(self):
        regs = {'example.com': 'Example Retail, Inc.', 'example-client.com': 'Example Client LLC'}
        self.assertIn('"Example Retail, Inc."', own.foreign_owner('example.com', ['example-client.com'], self.Lookup({}, regs)))
        regs['example-client.com'] = 'EXAMPLE RETAIL INC'
        self.assertIsNone(own.foreign_owner('example.com', ['example-client.com'], self.Lookup(self.INFRA, regs)))

    def test_no_verdict_without_positive_evidence(self):
        lookup = self.Lookup({**self.INFRA, ('example.com', 'MX'): ['10 aspmx.l.google.com.']})  # mail at a shared provider
        self.assertIsNone(own.foreign_owner('example.com', ['example-client.com'], lookup))
        shared = self.Lookup({**self.INFRA, ('example.com', 'NS'): ['ns1.markmonitor.com.']})  # what the client's other domain uses
        self.assertIsNone(own.foreign_owner('example.com', ['example-client.com'], shared))
        self.assertIsNone(own.foreign_owner('example.com', [], self.Lookup(self.INFRA)))  # nothing to compare with
        redacted = self.Lookup({}, {'example.com': 'REDACTED FOR PRIVACY', 'example-client.com': 'Example Client LLC'})
        self.assertIsNone(own.foreign_owner('example.com', ['example-client.com'], redacted))

        class Failing(self.Lookup):
            def records(self, name, rtype):
                return None
        self.assertIsNone(own.foreign_owner('example.com', ['example-client.com'], Failing({})))


class BucketGuessOwnershipTests(TestCase):
    def setUp(self):
        org = Org.objects.create(name='B', slug='b-own')
        self.project = Project.objects.create(name='BP', slug='bp-own', insert_date=timezone.now(), org=org)
        for name in ('example.com', 'example-client.com'):
            Domain.objects.create(name=name, project=self.project, insert_date=timezone.now())
        mock.patch.dict(os.environ, {'CVENGINE_BUCKETS_GUESS': '1'}).start()
        self.addCleanup(mock.patch.stopall)

    def test_no_names_are_guessed_from_a_domain_of_another_owner(self):
        from cveFeed import bucket_scan as bs
        asked, skipped = [], {}

        def check(domain, others):
            asked.append((domain, others))
            return 'it is registered to another company' if domain == 'example.com' else None
        candidates, complete = bs.collect(self.project.id, owner_check=check, skipped=skipped)
        names = {c.name for c in candidates if c.tier == 'guess'}
        self.assertFalse(names & {n for _p, n in bs.guess_names('example', 'example.com')})  # nothing from the other owner's domain
        self.assertIn('example-client', names)
        self.assertEqual(skipped, {'example.com': 'it is registered to another company'})
        self.assertIn(('example.com', ['example-client.com']), asked)
        self.assertIn('guess', complete)

    def test_the_sweep_says_why_and_an_earlier_guess_finding_for_that_domain_resolves(self):
        from cveFeed import bucket_scan as bs
        from cveFeed.models import HygieneFinding
        from tests.test_bucket_scan import Net
        domain = Domain.objects.get(name='example.com')
        old = HygieneFinding.objects.create(domain=domain, host='example-assets.storage.googleapis.com', check_name='bkt_listing', severity=2,
                                            title='Google Cloud Storage bucket example-assets lists its objects to anyone (name guess, ownership unconfirmed)',
                                            evidence={'tier': 'guess'})
        with mock.patch.dict(os.environ, {'CVENGINE_BUCKETS_MAX_PER_SWEEP': '1'}):
            out = bs.sweep(self.project.id, fetch=Net(), dns=lambda host: False,
                           owner_check=lambda d, others: 'another registrant' if d == 'example.com' else None)
        self.assertEqual(out['not_guessed'], ['example.com'])
        old.refresh_from_db()
        self.assertEqual(old.status, 'resolved')
