from django.test import SimpleTestCase, TestCase

from cveFeed import db_intel, service_intel
from startScan.models import Port, Subdomain
from tests.test_route_auth import RouteFixture

MYSQL_INFO = """Protocol: 10
Version: 5.0.51a-3ubuntu5.1
Thread ID: 7
Capabilities flags: 40968
Some Capabilities: ConnectWithDatabase, SupportsTransactions, Support41Auth
Status: Autocommit
Salt: bYyt\\NQ/4V6IN+*3`imj"""

REDIS_INFO = """Version            2.2.11
Architecture       64 bits
Process ID         17821
Used CPU (sys)     2.37
Used CPU (user)    1.02
Connected clients  1
Connected slaves   0
Used memory        780.16K
Role               master
Bind addresses:
  192.168.121.101
Active channels:
  testChannel
  bidChannel
Client connections:
  192.168.171.101
  72.14.177.105"""

MEMCACHED_INFO = """Process ID: 18568
Uptime: 6950 seconds
Server time: 2018-03-02T03:35:09
Architecture: 64 bit
Used CPU (user): 0.172010
Used CPU (system): 0.200012
Current connections: 10
Total connections: 78
Maximum connections: 1024
TCP Port: 11211
UDP Port: 11211
Authentication: no"""

MONGODB_INFO = """MongoDB Build info
  ok = 1
  bits = 64
  version = 1.3.1-
  gitVersion = d1f0ffe23bcd667f4ed18a27b5fd31a0beab5535
  sysInfo = Linux example 2.6.21.7-2.ec2.v1.2.fc8xen #1 SMP x86_64
Server status
  opcounters
    delete = 0
    insert = 3
  connections
    available = 19999
    current = 1
  uptime = 747
  ok = 1"""

COUCHDB_ADMIN_PARTY = """httpd
  requests (number of HTTP requests)
    current = 5
    count = 1617
Authentication : NOT enabled ('admin party')"""

COUCHDB_SECURE = """httpd
  requests (number of HTTP requests)
    current = 1
    count = 1
Authentication : enabled"""

MS_SQL_NTLM = """Target_Name: ACTIVESQL
NetBIOS_Domain_Name: ACTIVESQL
NetBIOS_Computer_Name: DB-TEST2
DNS_Domain_Name: somedomain.com
DNS_Computer_Name: db-test2.somedomain.com
DNS_Tree_Name: somedomain.com
Product_Version: 6.1.7601"""

MS_SQL_INFO = """Windows server name: WINXP
192.168.100.128\\PROD:
  Instance name: PROD
  Version:
    name: Microsoft SQL Server 2000 SP3
    number: 8.00.760
    Product: Microsoft SQL Server 2000
    Service pack level: SP3
    Post-SP patches applied: No
  TCP port: 1278
  Clustered: No"""


class ParseTests(SimpleTestCase):
    def test_mysql_info_reads_version_and_protocol(self):
        facts = db_intel.parse_mysql_info(MYSQL_INFO)
        self.assertEqual(facts, {'version': '5.0.51a-3ubuntu5.1', 'protocol': '10'})
        self.assertNotIn('Salt', facts)  # the handshake salt is not metadata worth keeping

    def test_redis_info_reads_version_role_and_architecture_not_the_address_lists(self):
        facts = db_intel.parse_redis_info(REDIS_INFO)
        self.assertEqual(facts, {'version': '2.2.11', 'role': 'master', 'architecture': '64 bits'})

    def test_memcached_info_reads_uptime_architecture_and_authentication(self):
        facts = db_intel.parse_memcached_info(MEMCACHED_INFO)
        self.assertEqual(facts, {'uptime': '6950 seconds', 'architecture': '64 bit', 'authentication': 'no'})

    def test_mongodb_info_reads_the_build_version_only(self):
        self.assertEqual(db_intel.parse_mongodb_info(MONGODB_INFO), {'version': '1.3.1-'})

    def test_couchdb_stats_reads_admin_party(self):
        facts = db_intel.parse_couchdb_stats(COUCHDB_ADMIN_PARTY)
        self.assertEqual(facts['admin_party'], True)
        self.assertIn('admin party', facts['auth'])

    def test_couchdb_stats_secure_instance_is_not_admin_party(self):
        facts = db_intel.parse_couchdb_stats(COUCHDB_SECURE)
        self.assertEqual(facts, {'auth': 'enabled', 'admin_party': False})

    def test_ms_sql_ntlm_reads_the_same_fields_rdp_ntlm_does(self):
        facts = db_intel.parse_ms_sql_ntlm(MS_SQL_NTLM)
        self.assertEqual((facts['computer_name'], facts['domain'], facts['fqdn']),
                          ('DB-TEST2', 'ACTIVESQL', 'db-test2.somedomain.com'))
        self.assertEqual(facts['os'], 'Windows Server 2008 R2 / Windows 7')

    def test_ms_sql_info_reads_the_first_instance(self):
        facts = db_intel.parse_ms_sql_info(MS_SQL_INFO)
        self.assertEqual(facts, {'windows_server': 'WINXP', 'version': 'Microsoft SQL Server 2000 SP3', 'version_number': '8.00.760'})

    def test_nothing_in_nothing_out(self):
        self.assertEqual(db_intel.parse_mysql_info(''), {})
        self.assertEqual(db_intel.parse_redis_info(None), {})
        self.assertEqual(db_intel.parse_mongodb_info(''), {})
        self.assertEqual(db_intel.parse_couchdb_stats(''), {})
        self.assertEqual(db_intel.parse_ms_sql_info(''), {})


class ApplyDbFactsTests(TestCase):
    def test_fills_empty_version_and_product(self):
        port = Port.objects.create(number=3306, service_name='mysql', extra={'scripts': {'mysql-info': MYSQL_INFO}})
        self.assertTrue(db_intel.apply_db_facts(port))
        port.refresh_from_db()
        self.assertEqual(port.version, '5.0.51a-3ubuntu5.1')
        self.assertEqual(port.product, 'MySQL')
        self.assertEqual(port.extra['db']['mysql-info'], {'version': '5.0.51a-3ubuntu5.1', 'protocol': '10'})

    def test_never_overrides_what_dash_sv_already_found(self):
        port = Port.objects.create(number=3306, service_name='mysql', product='MySQL', version='8.0.35',
                                   extra={'scripts': {'mysql-info': MYSQL_INFO}})
        db_intel.apply_db_facts(port)
        port.refresh_from_db()
        self.assertEqual(port.version, '8.0.35')  # -sV's own finding is kept, not the script's

    def test_several_db_scripts_on_one_port_all_recorded(self):
        port = Port.objects.create(number=6379, service_name='redis',
                                   extra={'scripts': {'redis-info': REDIS_INFO, 'banner': 'ignored'}})
        db_intel.apply_db_facts(port)
        port.refresh_from_db()
        self.assertEqual(set(port.extra['db']), {'redis-info'})
        self.assertEqual(port.product, 'Redis')

    def test_no_matching_script_output_is_a_no_op(self):
        port = Port.objects.create(number=443, service_name='https', extra={'scripts': {'http-title': 'Example'}})
        self.assertFalse(db_intel.apply_db_facts(port))

    def test_rerun_with_unchanged_output_does_not_resave(self):
        port = Port.objects.create(number=3306, service_name='mysql', extra={'scripts': {'mysql-info': MYSQL_INFO}})
        db_intel.apply_db_facts(port)
        self.assertFalse(db_intel.apply_db_facts(port))


class ApplyMssqlHostFactsTests(RouteFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.scan_obj = self.scan(names=('sql.rt.test',), ports=())
        self.sub = Subdomain.objects.get(scan_history=self.scan_obj)
        self.ip = self.sub.ip_addresses.get()

    def test_fills_the_mssql_port_from_the_host_wide_script(self):
        self.ip.fingerprint = {'scripts': {'ms-sql-info': MS_SQL_INFO}}
        self.ip.save()
        port = Port.objects.create(number=1433, service_name='ms-sql-s')
        self.ip.ports.add(port)
        self.assertTrue(db_intel.apply_mssql_host_facts(self.ip))
        port.refresh_from_db()
        self.assertEqual(port.version, 'Microsoft SQL Server 2000 SP3')
        self.assertEqual(port.product, 'Microsoft SQL Server')
        self.assertEqual(port.extra['db']['ms-sql-info']['version_number'], '8.00.760')

    def test_a_port_that_is_not_mssql_is_untouched(self):
        self.ip.fingerprint = {'scripts': {'ms-sql-info': MS_SQL_INFO}}
        self.ip.save()
        port = Port.objects.create(number=443, service_name='https')
        self.ip.ports.add(port)
        self.assertFalse(db_intel.apply_mssql_host_facts(self.ip))
        port.refresh_from_db()
        self.assertEqual(port.extra, {})

    def test_no_script_output_is_a_no_op(self):
        self.assertFalse(db_intel.apply_mssql_host_facts(self.ip))


class RecordServiceFindingsWiringTests(RouteFixture, TestCase):
    def test_db_facts_are_applied_while_recording_service_findings(self):
        scan = self.scan(names=('redis.rt.test',), ports=())
        sub = Subdomain.objects.get(scan_history=scan)
        ip = sub.ip_addresses.get()
        ip.ports.add(Port.objects.create(number=6379, service_name='redis', extra={'scripts': {'redis-info': REDIS_INFO}}))
        service_intel.record_service_findings(scan)
        port = Port.objects.get(number=6379)
        self.assertEqual(port.version, '2.2.11')
        self.assertEqual(port.product, 'Redis')
