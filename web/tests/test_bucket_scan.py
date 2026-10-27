import json
import os
import ssl
from datetime import timedelta
from unittest import mock
from urllib.parse import urlsplit

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from agentapi.auth import create_token
from cveFeed import bucket_probe as bp, bucket_scan as bs, hygiene
from cveFeed.models import BountyEngagement, BountyProgram, HostExclusion, HygieneFinding, ProbeObservation, ServiceRun
from dashboard.models import Org, Project, ProjectMembership
from startScan.models import EndPoint, Subdomain, Vulnerability
from targetApp.models import Domain
from tests.test_agentapi import call

Response = bp.Response

# Canned answers in the documented formats: S3 (ListBucketResult, Error), Google Cloud Storage (JSON objects listing and error), Azure Blob
# (EnumerationResults and the storage error body).
S3_LIST = '''<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>ex-static</Name><Prefix></Prefix><Marker></Marker><MaxKeys>20</MaxKeys><IsTruncated>true</IsTruncated>
<Contents><Key>css/site.css</Key><LastModified>2026-01-01T00:00:00.000Z</LastModified><ETag>&quot;d41d8cd98f00b204e9800998ecf8427e&quot;</ETag><Size>12</Size><StorageClass>STANDARD</StorageClass></Contents>
<Contents><Key>img/a&amp;b.png</Key><LastModified>2026-01-01T00:00:00.000Z</LastModified><ETag>&quot;d41d8cd98f00b204e9800998ecf8427e&quot;</ETag><Size>9</Size><StorageClass>STANDARD</StorageClass></Contents>
</ListBucketResult>'''
S3_EMPTY = '<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>ex-empty</Name><Prefix></Prefix><Marker></Marker><MaxKeys>20</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>'
S3_DENIED = '<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>Access Denied</Message><RequestId>4442587FB7D0A2F9</RequestId><HostId>7tDt0ksZ1y</HostId></Error>'
S3_NOSUCH = '<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message><BucketName>ex-gone</BucketName><RequestId>0D4C1A12D5E5A6B1</RequestId><HostId>q8Wb</HostId></Error>'
S3_REDIRECT = ('<?xml version="1.0" encoding="UTF-8"?><Error><Code>PermanentRedirect</Code><Message>The bucket you are attempting to access must be addressed using '
               'the specified endpoint. Please send all future requests to this endpoint.</Message><Endpoint>ex-eu.s3.eu-west-1.amazonaws.com</Endpoint><Bucket>ex-eu</Bucket></Error>')
GCS_LIST = json.dumps({'kind': 'storage#objects', 'nextPageToken': 'CgtmaWxlMDEudHh0', 'items': [{'name': 'public/readme.txt'}, {'name': 'public/logo.png'}]})
GCS_EMPTY = json.dumps({'kind': 'storage#objects'})
GCS_MISSING = json.dumps({'error': {'code': 404, 'message': 'The specified bucket does not exist.', 'errors': [{'message': 'The specified bucket does not exist.', 'domain': 'global', 'reason': 'notFound'}]}})
GCS_DENIED = json.dumps({'error': {'code': 401, 'message': "Anonymous caller does not have storage.objects.list access to the Google Cloud Storage bucket. Permission 'storage.objects.list' denied on resource (or it may not exist).", 'errors': [{'reason': 'required'}]}})
AZ_LIST = '''<?xml version="1.0" encoding="utf-8"?><EnumerationResults ServiceEndpoint="https://exstore.blob.core.windows.net/" ContainerName="media"><MaxResults>20</MaxResults>
<Blobs><Blob><Name>banner.jpg</Name><Properties><Last-Modified>Mon, 05 Jan 2026 10:00:00 GMT</Last-Modified><Content-Length>1024</Content-Length></Properties></Blob><BlobPrefix><Name>old/</Name></BlobPrefix></Blobs><NextMarker /></EnumerationResults>'''
AZ_NOCONTAINER = '<?xml version="1.0" encoding="utf-8"?><Error><Code>ContainerNotFound</Code><Message>The specified container does not exist.</Message></Error>'
AZ_NOPUBLIC = '<?xml version="1.0" encoding="utf-8"?><Error><Code>PublicAccessNotPermitted</Code><Message>Public access is not permitted on this storage account.</Message></Error>'


def xml(status, body, **headers):
    return Response(status, {k.replace('_', '-'): v for k, v in headers.items()}, body.encode())


class Net:
    """A fake storage platform: it answers a request by its URL and remembers every one. A URL it has no answer for gets what the
    platform says for a bucket that is not there."""

    def __init__(self, **routes):
        self.routes, self.calls = {}, []
        for url, answer in routes.items():
            self.routes[url.replace('|', '/')] = answer

    def __call__(self, method, url):
        self.calls.append((method, url))
        got = self.routes.get(f'{method} {url}') or self.routes.get(url)
        if isinstance(got, Exception):
            raise got
        if got is not None:
            return got
        if method == 'HEAD':
            return Response(404)
        if urlsplit(url).hostname == 'storage.googleapis.com':
            return xml(404, GCS_MISSING)
        return xml(404, S3_NOSUCH)

    @property
    def urls(self):
        return [u for _m, u in self.calls]


S3 = 'https://ex-static.s3.amazonaws.com/?max-keys=20'
S3_HEAD = 'HEAD https://ex-static.s3.amazonaws.com/css/site.css'


class ParseTests(SimpleTestCase):
    def test_s3_endpoints_in_every_documented_shape(self):
        shapes = {'ex-static.s3.amazonaws.com': 'ex-static', 'ex-static.s3-us-west-2.amazonaws.com': 'ex-static', 'ex-static.s3.us-west-2.amazonaws.com': 'ex-static',
                  'ex-static.s3.dualstack.us-west-2.amazonaws.com': 'ex-static', 'ex-static.s3-website-us-east-1.amazonaws.com': 'ex-static',
                  'ex-static.s3-website.eu-west-1.amazonaws.com': 'ex-static', 'www.example.test.s3-website-us-east-1.amazonaws.com': 'www.example.test'}
        for host, bucket in shapes.items():
            self.assertEqual(bs.refs_from_host(host), [bs.Ref('s3', bucket)], host)
        self.assertEqual(bs.refs_from_url('https://s3.us-east-2.amazonaws.com/ex-static/a/b.png'), [bs.Ref('s3', 'ex-static')])
        self.assertEqual(bs.refs_from_host('s3-website-us-east-1.amazonaws.com'), [])  # no bucket named
        self.assertEqual(bs.refs_from_host('ec2-203-0-113-5.compute-1.amazonaws.com'), [])  # not storage
        self.assertEqual(bs.refs_from_host('ex.s3.amazonaws.com.evil.test'), [])  # a look-alike is not an endpoint

    def test_gcs_endpoints(self):
        self.assertEqual(bs.refs_from_url('https://storage.googleapis.com/ex-assets/img/a.png'), [bs.Ref('gcs', 'ex-assets')])
        self.assertEqual(bs.refs_from_url('https://ex-assets.storage.googleapis.com/a.png'), [bs.Ref('gcs', 'ex-assets')])
        self.assertEqual(bs.refs_from_url('https://storage.cloud.google.com/ex-assets/a.png'), [bs.Ref('gcs', 'ex-assets')])
        self.assertEqual(bs.refs_from_url('https://storage.googleapis.com/storage/v1/b/ex-assets/o?alt=media'), [bs.Ref('gcs', 'ex-assets')])
        self.assertEqual(bs.refs_from_url('https://storage.googleapis.com/'), [])
        self.assertEqual(bs.refs_from_cname('assets.example.test', 'c.storage.googleapis.com.'), [bs.Ref('gcs', 'assets.example.test')])

    def test_azure_endpoints_name_the_container_only_when_the_url_does(self):
        self.assertEqual(bs.refs_from_url('https://exstore.blob.core.windows.net/media/banner.jpg'), [bs.Ref('azure', 'exstore', 'media')])
        self.assertEqual(bs.refs_from_host('exstore.blob.core.windows.net'), [bs.Ref('azure', 'exstore', '')])
        self.assertEqual(bs.refs_from_host('exstore.z13.web.core.windows.net'), [bs.Ref('azure', 'exstore', '')])

    def test_text_is_read_for_storage_urls_only(self):
        text = 'src="https://ex-static.s3.amazonaws.com/app.js" and //exstore.blob.core.windows.net/media/x.css but https://example.test/a'
        self.assertEqual(bs.refs_from_text(text), [bs.Ref('s3', 'ex-static'), bs.Ref('azure', 'exstore', 'media')])

    def test_the_documented_s3_listing_and_errors(self):
        keys, more = bp.parse_s3_listing(S3_LIST.encode())
        self.assertEqual((keys, more), (['css/site.css', 'img/a&b.png'], True))
        self.assertEqual(bp.parse_s3_listing(S3_EMPTY.encode()), ([], False))
        self.assertIsNone(bp.parse_s3_listing(S3_DENIED.encode()))

    def test_a_listing_that_declares_entities_is_read_as_text_never_expanded(self):
        body = ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "AAAAAAAAAAAAAAAAAAAA">]><ListBucketResult><Contents><Key>&a;</Key></Contents></ListBucketResult>').encode()
        self.assertEqual(bp.parse_s3_listing(body)[0], ['&a;'])

    def test_a_listing_is_cut_to_the_first_page(self):
        body = '<ListBucketResult>' + ''.join(f'<Contents><Key>k{i}</Key></Contents>' for i in range(50)) + '</ListBucketResult>'
        keys, more = bp.parse_s3_listing(body.encode())
        self.assertEqual((len(keys), more), (bp.MAX_KEYS, True))

    def test_gcs_and_azure_documents(self):
        self.assertEqual(bp.parse_gcs_listing(GCS_LIST.encode()), (['public/readme.txt', 'public/logo.png'], True))
        self.assertEqual(bp.parse_gcs_listing(GCS_EMPTY.encode()), ([], False))
        self.assertIsNone(bp.parse_gcs_listing(GCS_MISSING.encode()))
        self.assertEqual(bp.gcs_error(GCS_MISSING.encode())[0], 404)
        self.assertEqual(bp.parse_azure_listing(AZ_LIST.encode()), (['banner.jpg'], False))  # a BlobPrefix is a folder, not an object
        self.assertIsNone(bp.parse_azure_listing(AZ_NOCONTAINER.encode()))

    def test_guesses_are_few_and_valid(self):
        names = bs.guess_names('example', 'example.test')
        self.assertLessEqual(len({n for _p, n in names if '.' not in n}), 41)
        self.assertIn(('s3', 'example-backup'), names)
        self.assertIn(('gcs', 'example-assets'), names)
        self.assertIn(('s3', 'www.example.test'), names)
        self.assertNotIn(('gcs', 'example.test'), names)
        self.assertFalse([1 for p, _n in names if p == 'azure'])  # an Azure account is never guessed
        self.assertEqual(bs.domain_labels(['www.example.test', 'ab.test', '203.0.113.5', 'acme.jfrog.com']), {'example': 'example.test'})
        self.assertEqual(len(bs.SUFFIXES), 40)


class RedactionTests(SimpleTestCase):
    def test_secret_looking_segments_are_replaced(self):
        for name in ('exports/AKIAIOSFODNN7EXAMPLE/dump.csv', 'logs/token=abcDEF123/x.log', 'cfg/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig/x',
                     'uploads/ghp_abcdefghijklmnopqrstuvwxyz0123456789/a', 'k/Qx9Zr2LmN8pT4vB7cD1fG6hJ3kS5wY/a.json', 'a/AIzaSyA-1234567890abcdefghijklmnopqrstu/b'):
            self.assertIn(bp.REDACTED, bp.redact_name(name), name)
        self.assertEqual(bp.redact_name('exports/AKIAIOSFODNN7EXAMPLE/dump.csv'), 'exports/[redacted]/dump.csv')

    def test_ordinary_names_survive(self):
        for name in ('css/site.css', 'images/2026/01/photo-final.jpg', 'a3f5c9e1b7d24680a3f5c9e1b7d24680.bin', '123e4567-e89b-12d3-a456-426614174000.pdf',
                     'reports/quarterly-report-2026-q1.pdf'):
            self.assertEqual(bp.redact_name(name), name)

    def test_control_characters_and_length_are_bounded(self):
        self.assertEqual(bp.redact_name('a\nb'), 'a?b')
        self.assertEqual(len(bp.redact_name('x' * 900)), bp.MAX_NAME)

    def test_sensitive_looking_names(self):
        for name in ('backup/2026-01.tar.gz', 'db/users.sql', 'prod.env', 'keys/server.pem', 'terraform.tfstate', 'dumps/customers.csv', 'id_rsa'):
            self.assertTrue(bp.is_sensitive_name(name), name)
        for name in ('css/site.css', 'img/logo.png', 'docs/handbook.pdf'):
            self.assertFalse(bp.is_sensitive_name(name), name)

    def test_the_object_that_is_asked_for_is_never_a_folder_or_sensitive(self):
        self.assertEqual(bp.pick_object(['backup/', 'backup/db.sql', 'img/a.png']), 'img/a.png')
        self.assertIsNone(bp.pick_object(['db.sql', 'keys/id_rsa']))


class ProbeTests(SimpleTestCase):
    def test_a_public_s3_listing_is_read_once_and_one_object_is_asked_for_with_head(self):
        net = Net(**{S3: xml(200, S3_LIST), S3_HEAD: Response(200)})
        verdict = bp.check('s3', 'ex-static', fetch=net)
        self.assertEqual((verdict.state, verdict.objects, verdict.object_read), ('public', ['css/site.css', 'img/a&b.png'], True))
        self.assertEqual(net.calls, [('GET', S3), ('HEAD', 'https://ex-static.s3.amazonaws.com/css/site.css')])  # the listing and one HEAD: nothing else

    def test_a_refused_object_is_recorded_as_refused(self):
        verdict = bp.check('s3', 'ex-static', fetch=Net(**{S3: xml(200, S3_LIST), S3_HEAD: Response(403)}))
        self.assertEqual((verdict.state, verdict.object_read), ('public', False))

    def test_a_listing_of_only_sensitive_names_tests_no_object(self):
        body = '<ListBucketResult><Contents><Key>db/users.sql</Key></Contents><Contents><Key>keys/id_rsa</Key></Contents></ListBucketResult>'
        net = Net(**{S3: xml(200, body)})
        verdict = bp.check('s3', 'ex-static', fetch=net)
        self.assertEqual((verdict.state, verdict.object_read), ('public', None))
        self.assertEqual([m for m, _u in net.calls], ['GET'])

    def test_a_private_bucket_and_a_missing_one(self):
        self.assertEqual(bp.check('s3', 'ex-static', fetch=Net(**{S3: xml(403, S3_DENIED)})).state, 'private')
        verdict = bp.check('s3', 'ex-static', fetch=Net(**{S3: xml(404, S3_NOSUCH)}))
        self.assertEqual((verdict.state, verdict.code), ('missing', 'NoSuchBucket'))

    def test_a_bucket_in_another_region_is_followed_once_by_the_region_the_platform_names(self):
        net = Net(**{'https://ex-eu.s3.amazonaws.com/?max-keys=20': xml(301, S3_REDIRECT, x_amz_bucket_region='eu-west-1'),
                     'https://ex-eu.s3.eu-west-1.amazonaws.com/?max-keys=20': xml(403, S3_DENIED)})
        verdict = bp.check('s3', 'ex-eu', fetch=net)
        self.assertEqual((verdict.state, verdict.region, len(net.calls)), ('private', 'eu-west-1', 2))

    def test_a_redirect_to_something_that_is_not_a_region_is_not_followed(self):
        net = Net(**{'https://ex-eu.s3.amazonaws.com/?max-keys=20': xml(301, S3_REDIRECT, x_amz_bucket_region='evil.test/x')})
        self.assertEqual((bp.check('s3', 'ex-eu', fetch=net).state, len(net.calls)), ('unknown', 1))

    def test_a_dotted_bucket_uses_path_style(self):
        net = Net()
        bp.check('s3', 'www.example.test', fetch=net)
        self.assertEqual(net.urls, ['https://s3.amazonaws.com/www.example.test/?max-keys=20'])

    def test_gcs_listing_private_and_missing(self):
        url = 'https://storage.googleapis.com/storage/v1/b/ex-assets/o?maxResults=20&fields=kind,nextPageToken,items(name)'
        net = Net(**{url: xml(200, GCS_LIST), 'HEAD https://storage.googleapis.com/ex-assets/public/readme.txt': Response(200)})
        verdict = bp.check('gcs', 'ex-assets', fetch=net)
        self.assertEqual((verdict.state, verdict.truncated, verdict.object_read), ('public', True, True))
        self.assertEqual(bp.check('gcs', 'ex-assets', fetch=Net(**{url: xml(401, GCS_DENIED)})).state, 'private')
        self.assertEqual(bp.check('gcs', 'ex-assets', fetch=Net(**{url: xml(404, GCS_MISSING)})).state, 'missing')

    def test_an_empty_public_gcs_bucket_is_still_a_public_listing(self):
        url = 'https://storage.googleapis.com/storage/v1/b/ex-assets/o?maxResults=20&fields=kind,nextPageToken,items(name)'
        verdict = bp.check('gcs', 'ex-assets', fetch=Net(**{url: xml(200, GCS_EMPTY)}))
        self.assertEqual((verdict.state, verdict.objects, verdict.object_read), ('public', [], None))

    def test_azure_account_by_dns_and_container_by_listing(self):
        url = 'https://exstore.blob.core.windows.net/media?restype=container&comp=list&maxresults=20'
        net = Net(**{url: xml(200, AZ_LIST), 'HEAD https://exstore.blob.core.windows.net/media/banner.jpg': Response(200)})
        verdict = bp.check('azure', 'exstore', 'media', fetch=net, dns=lambda host: True)
        self.assertEqual((verdict.state, verdict.objects, verdict.object_read), ('public', ['banner.jpg'], True))
        self.assertEqual(bp.check('azure', 'exstore', 'media', fetch=Net(**{url: xml(409, AZ_NOPUBLIC)}), dns=lambda host: True).state, 'private')
        self.assertEqual(bp.check('azure', 'exstore', 'media', fetch=Net(**{url: xml(404, AZ_NOCONTAINER)}), dns=lambda host: True).state, 'private')

    def test_an_azure_account_without_an_address_is_missing_and_no_http_request_is_made(self):
        net = Net()
        verdict = bp.check('azure', 'exstore', 'media', fetch=net, dns=lambda host: False)
        self.assertEqual((verdict.state, verdict.code, net.calls), ('missing', 'NXDOMAIN', []))

    def test_an_azure_account_with_no_container_to_ask_about_is_not_listed(self):
        net = Net()
        verdict = bp.check('azure', 'exstore', '', fetch=net, dns=lambda host: True)
        self.assertEqual((verdict.state, net.calls), ('private', []))

    def test_no_dns_answer_is_unknown_not_missing(self):
        self.assertEqual(bp.check('azure', 'exstore', '', fetch=Net(), dns=lambda host: None).state, 'unknown')

    def test_a_network_failure_or_a_refused_address_is_unknown(self):
        self.assertEqual(bp.check('s3', 'ex-static', fetch=Net(**{S3: OSError('reset')})).state, 'unknown')
        self.assertEqual(bp.check('s3', 'ex-static', fetch=Net(**{S3: ValueError('probe destination is prohibited')})).state, 'unknown')
        self.assertEqual(bp.check('s3', 'ex-static', fetch=Net(**{S3: xml(503, '<Error><Code>SlowDown</Code></Error>')})).state, 'unknown')


class DnsTests(SimpleTestCase):
    def exists(self, outcome):
        import dns.resolver

        class Resolver:
            def resolve(self, host, rtype):
                if isinstance(outcome, type) and issubclass(outcome, Exception):
                    raise outcome()
                return outcome
        with mock.patch('cveFeed.hygiene._resolver', return_value=Resolver()):
            return bp.dns_exists('exstore.blob.core.windows.net')

    def test_only_nxdomain_says_the_account_is_gone(self):
        import dns.exception
        import dns.resolver
        self.assertIs(self.exists(dns.resolver.NXDOMAIN), False)
        self.assertIs(self.exists(['203.0.113.7']), True)
        self.assertIs(self.exists(dns.resolver.NoAnswer), True)
        self.assertIsNone(self.exists(dns.exception.Timeout))  # a slow resolver is not a takeover
        self.assertIsNone(self.exists(dns.resolver.NoNameservers))


class ScheduleTests(TestCase):
    def test_the_daily_sweep_is_scheduled_on_its_own_queue_and_the_queue_is_served_and_reported(self):
        from django_celery_beat.models import PeriodicTask

        from agentapi import system_status
        from cveFeed import tasks
        task = PeriodicTask.objects.get(name='cvengine-bucket-sweep')
        self.assertEqual((task.task, task.queue, task.enabled, task.crontab.hour), ('bucket_sweep', 'bucketscan_queue', True, '1'))
        self.assertEqual(tasks.bucket_sweep.queue, 'bucketscan_queue')
        self.assertIn('bucketscan_queue', system_status.QUEUES)
        entry = open(os.path.join(os.path.dirname(__file__), '..', 'celery-entrypoint.sh')).read()
        self.assertIn(',bucketscan_queue"', entry)
        with mock.patch('cveFeed.bucket_scan.sweep_all', return_value={'checked': 0}) as sweep:
            self.assertEqual(tasks.bucket_sweep(), {'checked': 0})
        sweep.assert_called_once_with()


class FetchTests(SimpleTestCase):
    """The one function that touches the network: what it refuses before anything is sent."""

    def refused(self, method, url):
        with mock.patch('cveFeed.pinned_transport.resolve') as resolve, mock.patch('cveFeed.pinned_transport.HTTPConnection') as connection:
            with self.assertRaises(ValueError):
                bp.http_fetch(method, url, paced=False)
        resolve.assert_not_called()
        connection.assert_not_called()

    def test_only_get_and_head(self):
        for method in ('POST', 'PUT', 'DELETE', 'OPTIONS'):
            self.refused(method, 'https://ex-static.s3.amazonaws.com/')

    def test_only_https_on_443_to_a_documented_storage_endpoint(self):
        for url in ('http://ex-static.s3.amazonaws.com/', 'https://ex-static.s3.amazonaws.com:8443/', 'https://www.example.test/', 'https://example.test/s3.amazonaws.com',
                    'https://ex-static.s3.amazonaws.com.evil.test/', 'https://203.0.113.5/', 'https://user:pw@ex-static.s3.amazonaws.com/',
                    'https://evil.test@ex-static.s3.amazonaws.com.evil.test/', 'https://ec2-203-0-113-5.compute-1.amazonaws.com/', 'https://x.cloudfront.net/'):
            self.refused('GET', url)

    def test_the_endpoint_list(self):
        for host in ('s3.amazonaws.com', 'ex-static.s3.amazonaws.com', 's3.eu-west-1.amazonaws.com', 'ex-static.s3.eu-west-1.amazonaws.com', 'storage.googleapis.com',
                     'exstore.blob.core.windows.net'):
            self.assertTrue(bp.endpoint_allowed(host), host)
        for host in ('ex.static.s3.amazonaws.com', 'exstore.z13.web.core.windows.net', 'ex-static.storage.googleapis.com', 'example.test', ''):
            self.assertFalse(bp.endpoint_allowed(host), host)

    def test_a_storage_name_that_resolves_to_a_prohibited_address_is_never_connected_to(self):
        with mock.patch('cveFeed.pinned_transport.resolve', side_effect=ValueError('probe destination is prohibited')), \
                mock.patch('cveFeed.pinned_transport.HTTPConnection') as connection:
            with self.assertRaises(ValueError):
                bp.http_fetch('GET', 'https://ex-static.s3.amazonaws.com/', paced=False)
        connection.assert_not_called()

    def test_a_request_goes_to_the_vetted_address_on_443_with_certificate_checks_and_no_credentials(self):
        addresses = ((2, ('203.0.113.9', 443)),)
        response = mock.Mock(status=200)
        response.getheader.side_effect = lambda name: {'x-amz-bucket-region': 'us-east-1'}.get(name)
        response.read.return_value = b'<ListBucketResult/>'
        with mock.patch('cveFeed.pinned_transport.resolve', return_value=addresses) as resolve, \
                mock.patch('cveFeed.pinned_transport.HTTPConnection') as connection, mock.patch.object(bp, 'pacer') as pacer:
            connection.return_value.getresponse.return_value = response
            got = bp.http_fetch('GET', 'https://ex-static.s3.amazonaws.com/?max-keys=20')
        resolve.assert_called_once_with('ex-static.s3.amazonaws.com', 443)
        args, kwargs = connection.call_args
        self.assertEqual(args[:3], ('ex-static.s3.amazonaws.com', 443, addresses))
        self.assertEqual(kwargs['context'].verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(kwargs['context'].check_hostname)
        method, path = connection.return_value.request.call_args[0]
        self.assertEqual((method, path), ('GET', '/?max-keys=20'))
        sent = {k.lower() for k in connection.return_value.request.call_args[1]['headers']}
        self.assertFalse(sent & {'authorization', 'cookie', 'x-amz-security-token', 'x-ms-version'})
        pacer.return_value.wait.assert_called_once()  # every request waits for its turn at the global rate
        self.assertEqual((got.status, got.headers['x-amz-bucket-region'], got.body), (200, 'us-east-1', b'<ListBucketResult/>'))
        connection.return_value.close.assert_called_once()

    def test_a_head_reads_no_body(self):
        response = mock.Mock(status=200)
        response.getheader.return_value = ''
        with mock.patch('cveFeed.pinned_transport.resolve', return_value=((2, ('203.0.113.9', 443)),)), \
                mock.patch('cveFeed.pinned_transport.HTTPConnection') as connection:
            connection.return_value.getresponse.return_value = response
            bp.http_fetch('HEAD', 'https://ex-static.s3.amazonaws.com/a.png', paced=False)
        response.read.assert_not_called()


class PacerTests(SimpleTestCase):
    def test_requests_are_spaced_by_the_rate(self):
        clock, slept = [100.0], []

        def sleep(seconds):
            slept.append(seconds)
            clock[0] += seconds
        pacer = bp.Pacer(rate=2, clock=lambda: clock[0], sleep=sleep, client=False)
        pacer._redis = lambda: None  # this process alone
        for _ in range(5):
            pacer.wait()
        self.assertEqual(round(sum(slept), 3), 2.0)  # five requests at two a second: the first at once, then four half-second gaps
        self.assertEqual(len(slept), 4)

    def test_the_gate_is_shared_through_redis(self):
        class Redis:
            def __init__(self):
                self.taken = 3
                self.sets = []

            def set(self, key, value, nx, px):
                self.sets.append((key, px))
                if self.taken:
                    self.taken -= 1
                    return None
                return True

            def pttl(self, key):
                return 250
        redis, slept = Redis(), []
        bp.Pacer(rate=2, sleep=slept.append, client=redis).wait()
        self.assertEqual((len(redis.sets), redis.sets[0]), (4, ('cvengine:buckets:pace', 500)))
        self.assertEqual(len(slept), 3)

    def test_the_rate_is_clamped(self):
        for value, expected in (('100', 5.0), ('0', 0.1), ('abc', 2.0), ('1', 1.0)):
            with mock.patch.dict(os.environ, {'CVENGINE_BUCKETS_RPS': value}):
                self.assertEqual(bp.request_rate(), expected)


class Fixture:
    def setUp(self):
        org = Org.objects.create(name='B', slug='b')
        self.org = org
        self.project = Project.objects.create(name='BP', slug='bp', insert_date=timezone.now(), org=org)
        self.domain = Domain.objects.create(name='example.test', project=self.project, insert_date=timezone.now())
        for patch in (mock.patch('targetApp.target_types.resolves_to_blocked', return_value=False), mock.patch('reNgine.tasks.geo_localize.delay'),
                      mock.patch('cveFeed.tasks.run_hygiene_task.delay'), mock.patch.dict(os.environ, {'CVENGINE_BUCKETS_GUESS': '0'})):
            patch.start()
        self.addCleanup(mock.patch.stopall)
        self.dns = lambda host: True
        self.net = Net()

    def host(self, name, cname='', webserver='', http_url=''):
        return Subdomain.objects.create(name=name, target_domain=self.domain, cname=cname, webserver=webserver, http_url=http_url)

    def sweep(self, net=None, **kw):
        self.net = net if net is not None else self.net
        return bs.sweep(self.project.id, fetch=self.net, dns=kw.pop('dns', self.dns))

    def finding(self, host, check='bkt_listing'):
        return HygieneFinding.objects.get(domain=self.domain, host=host, check_name=check)

    def expire(self):
        ServiceRun.objects.filter(service__in=(bs.SERVICE, bs.FAILED_SERVICE)).delete()


class OwnershipAndSeverityTests(Fixture, TestCase):
    def test_a_public_listing_of_a_bucket_a_host_points_at_is_high_with_confirmed_ownership(self):
        self.host('static.example.test', cname='ex-static.s3-website-us-east-1.amazonaws.com.')
        out = self.sweep(Net(**{S3: xml(200, S3_LIST), S3_HEAD: Response(200)}))
        self.assertEqual((out['checked'], out['public']), (1, 1))
        found = self.finding('static.example.test')
        self.assertEqual((found.severity, found.status, found.remediation_status), (3, 'open', 'open'))
        self.assertEqual((found.evidence['tier'], found.evidence['object_read'], found.evidence['referenced_by']), ('cname', 'allowed', ['static.example.test']))
        self.assertIn('confirmed', found.evidence['ownership'])
        self.assertEqual(found.evidence['objects'], ['css/site.css', 'img/a&b.png'])
        self.assertTrue(found.evidence['more_objects'])
        self.assertIn('Block public access', found.evidence['remediation'])
        self.assertNotIn('name guess', found.title)

    def test_a_listing_with_backup_database_or_key_names_is_critical(self):
        self.host('static.example.test', cname='ex-static.s3.amazonaws.com')
        body = '<ListBucketResult><Contents><Key>backup/prod-2026-01.sql.gz</Key></Contents><Contents><Key>img/a.png</Key></Contents></ListBucketResult>'
        self.sweep(Net(**{S3: xml(200, body), 'HEAD https://ex-static.s3.amazonaws.com/img/a.png': Response(403)}))
        found = self.finding('static.example.test')
        self.assertEqual((found.severity, found.evidence['sensitive_looking_names'], found.evidence['object_read']), (4, 1, 'refused'))

    def test_secret_looking_names_are_redacted_everywhere_they_are_stored_and_contents_are_never_fetched(self):
        self.host('static.example.test', cname='ex-static.s3.amazonaws.com')
        secret = 'AKIAIOSFODNN7EXAMPLE'
        body = f'<ListBucketResult><Contents><Key>exports/{secret}/users.csv</Key></Contents><Contents><Key>img/a.png</Key></Contents></ListBucketResult>'
        net = Net(**{S3: xml(200, body), 'HEAD https://ex-static.s3.amazonaws.com/exports/AKIAIOSFODNN7EXAMPLE/users.csv': Response(200)})
        self.sweep(net)
        found = self.finding('static.example.test')
        stored = json.dumps([found.evidence, found.title, found.detail])
        self.assertNotIn(secret, stored)
        self.assertEqual(found.evidence['objects'], ['exports/[redacted]/users.csv', 'img/a.png'])
        self.assertTrue(all(m in ('GET', 'HEAD') for m, _u in net.calls))
        self.assertEqual([m for m, _u in net.calls].count('GET'), 1)  # the listing, once: no object content is ever fetched

    def test_only_the_first_twenty_names_are_kept(self):
        self.host('static.example.test', cname='ex-static.s3.amazonaws.com')
        body = '<ListBucketResult>' + ''.join(f'<Contents><Key>img/{i}.png</Key></Contents>' for i in range(60)) + '</ListBucketResult>'
        self.sweep(Net(**{S3: xml(200, body)}))
        self.assertEqual(len(self.finding('static.example.test').evidence['objects']), 20)

    def test_a_name_guess_that_lists_is_medium_and_says_ownership_is_unconfirmed(self):
        with mock.patch.dict(os.environ, {'CVENGINE_BUCKETS_GUESS': '1'}):
            backups = 'https://example-backup.s3.amazonaws.com/?max-keys=20'
            body = '<ListBucketResult><Contents><Key>db/prod.sql</Key></Contents></ListBucketResult>'
            out = self.sweep(Net(**{backups: xml(200, body)}))
        found = self.finding('example-backup.s3.amazonaws.com')
        self.assertEqual((found.severity, found.evidence['tier'], out['public']), (2, 'guess', 1))  # never critical, whatever the names look like
        self.assertIn('name guess, ownership unconfirmed', found.title)
        self.assertIn('verify the bucket is yours', found.detail.lower())
        self.assertEqual(found.evidence['sensitive_looking_names'], 1)

    def test_a_reference_is_high_only_when_the_name_carries_the_projects_own_label(self):
        self.host('www.example.test')
        EndPoint.objects.create(target_domain=self.domain, subdomain=Subdomain.objects.get(name='www.example.test'), http_url='https://example-media.s3.amazonaws.com/a.png')
        EndPoint.objects.create(target_domain=self.domain, subdomain=Subdomain.objects.get(name='www.example.test'), http_url='https://vendor-widgets.s3.amazonaws.com/w.js')
        own, vendor = 'https://example-media.s3.amazonaws.com/?max-keys=20', 'https://vendor-widgets.s3.amazonaws.com/?max-keys=20'
        self.sweep(Net(**{own: xml(200, S3_LIST), vendor: xml(200, S3_LIST)}))
        self.assertEqual(self.finding('example-media.s3.amazonaws.com').severity, 3)
        other = self.finding('vendor-widgets.s3.amazonaws.com')
        self.assertEqual(other.severity, 2)
        self.assertIn('ownership is unconfirmed', other.evidence['severity_basis'])

    def test_a_bucket_that_exists_and_is_private_is_info_only_not_a_finding(self):
        self.host('static.example.test', cname='ex-static.s3.amazonaws.com')
        out = self.sweep(Net(**{S3: xml(403, S3_DENIED)}))
        self.assertEqual((out['private'], HygieneFinding.objects.count()), (1, 0))
        obs = ProbeObservation.objects.get(project=self.project, probe='storage-bucket')
        self.assertEqual((obs.outcome, obs.host, obs.evidence['state']), ('hidden', 'static.example.test', 'private'))

    def test_a_dangling_cname_is_a_high_takeover(self):
        self.host('static.example.test', cname='ex-gone.s3-website-us-east-1.amazonaws.com')
        out = self.sweep()
        found = self.finding('static.example.test', 'bkt_takeover')
        self.assertEqual((out['takeover'], found.severity, found.evidence['provider_answer']), (1, 3, 'NoSuchBucket'))
        self.assertIn('Anyone can register', found.detail)
        self.assertEqual(self.net.urls, ['https://ex-gone.s3.amazonaws.com/?max-keys=20'])  # the REST endpoint over HTTPS, never the HTTP website endpoint

    def test_an_azure_account_that_no_longer_exists_is_a_takeover_and_one_that_does_is_not(self):
        self.host('files.example.test', cname='exstore.blob.core.windows.net')
        self.sweep(dns=lambda host: False)
        self.assertEqual(self.finding('files.example.test', 'bkt_takeover').severity, 3)
        self.assertEqual(self.net.calls, [])  # DNS alone said so
        self.expire()
        self.sweep(dns=lambda host: True)
        self.assertEqual(HygieneFinding.objects.get(check_name='bkt_takeover').status, 'resolved')

    def test_a_gcs_name_with_a_dot_needs_a_verified_domain_so_its_takeover_is_medium(self):
        self.host('assets.example.test', cname='c.storage.googleapis.com')
        self.sweep()
        self.assertEqual(self.finding('assets.example.test', 'bkt_takeover').severity, 2)
        self.assertIn('verified owner', self.finding('assets.example.test', 'bkt_takeover').evidence['severity_basis'])

    def test_a_host_served_by_s3_but_with_no_bucket_of_its_name_is_not_a_takeover(self):
        self.host('cdn.example.test', webserver='AmazonS3')  # a CDN in front may read a bucket with another name
        out = self.sweep()
        self.assertEqual((out['missing'], HygieneFinding.objects.count()), (1, 0))

    def test_a_host_served_by_s3_whose_namesake_bucket_lists_is_high(self):
        self.host('cdn.example.test', webserver='AmazonS3')
        self.sweep(Net(**{'https://s3.amazonaws.com/cdn.example.test/?max-keys=20': xml(200, S3_LIST)}))
        found = self.finding('cdn.example.test')
        self.assertEqual((found.severity, found.evidence['tier']), (3, 'served'))

    def test_a_missing_name_guess_is_nothing(self):
        with mock.patch.dict(os.environ, {'CVENGINE_BUCKETS_GUESS': '1'}):
            out = self.sweep()
        self.assertEqual((out['public'], out['takeover'], HygieneFinding.objects.count(), ProbeObservation.objects.count()), (0, 0, 0, 0))

    def test_an_azure_container_is_listed_only_when_a_url_of_the_project_names_it(self):
        self.host('www.example.test')
        EndPoint.objects.create(target_domain=self.domain, http_url='https://exstore.blob.core.windows.net/media/banner.jpg')
        net = Net(**{'https://exstore.blob.core.windows.net/media?restype=container&comp=list&maxresults=20': xml(200, AZ_LIST),
                     'HEAD https://exstore.blob.core.windows.net/media/banner.jpg': Response(200)})
        self.sweep(net)
        found = self.finding('exstore.blob.core.windows.net/media')
        self.assertEqual((found.evidence['container'], found.evidence['provider'], found.severity), ('media', 'azure', 2))  # the name says nothing of the project


class CandidateTests(Fixture, TestCase):
    def collect(self):
        return {c.asset: c for c in bs.collect(self.project.id)[0]}

    def test_every_source_is_read_and_the_strongest_tier_wins(self):
        self.host('static.example.test', cname='ex-static.s3.amazonaws.com')
        www = self.host('www.example.test', http_url='https://exstore.blob.core.windows.net/media/x.css')
        EndPoint.objects.create(target_domain=self.domain, subdomain=www, http_url='https://ex-static.s3.amazonaws.com/a.png')
        EndPoint.objects.create(target_domain=self.domain, subdomain=www, http_url='https://ex-crawl.s3.amazonaws.com/a.png')
        from cveFeed.models import RouteAuth
        RouteAuth.objects.create(project=self.project, domain=self.domain, host='www.example.test', url='https://www.example.test/login', path='/login',
                                 auth_state='sso', redirect_to='https://storage.googleapis.com/ex-sso/login.html')
        Vulnerability.objects.create(name='x', severity=1, subdomain=www, target_domain=self.domain, http_url='https://www.example.test/',
                                     response='<img src="https://ex-resp.s3.eu-west-1.amazonaws.com/p.png">')
        found = self.collect()
        self.assertEqual({a: c.tier for a, c in found.items()}, {
            's3:ex-static': 'cname', 's3:ex-crawl': 'reference', 'azure:exstore:media': 'reference', 'gcs:ex-sso': 'reference', 's3:ex-resp': 'reference'})
        self.assertEqual(sorted(found['s3:ex-static'].hosts), ['static.example.test', 'www.example.test'])
        self.assertEqual(found['s3:ex-static'].host, 'static.example.test')  # the CNAME host, not the host that only links to it

    def test_a_removed_cname_is_read_from_the_newest_row_of_the_host(self):
        old = self.host('static.example.test', cname='ex-static.s3.amazonaws.com')
        self.host('static.example.test', cname='')  # the newer scan sees no CNAME
        self.assertEqual(self.collect(), {})
        self.assertTrue(old.pk)

    def test_hosts_the_organization_excluded_lead_nowhere(self):
        self.host('static.example.test', cname='ex-static.s3.amazonaws.com')
        self.host('old.example.test', cname='ex-old.s3.amazonaws.com')
        HostExclusion.objects.create(org=self.org, host='old.example.test')
        self.assertEqual(set(self.collect()), {'s3:ex-static'})

    def test_a_bucket_named_like_an_excluded_name_is_not_checked(self):
        self.host('static.example.test', cname='ex-static.s3.amazonaws.com')
        HostExclusion.objects.create(org=self.org, host='ex-static.s3.amazonaws.com')
        self.assertEqual(self.collect(), {})

    def test_guesses_come_from_the_domain_labels_and_skip_excluded_and_shared_domains(self):
        Domain.objects.create(name='acme.jfrog.com', project=self.project, insert_date=timezone.now())
        Domain.objects.create(name='203.0.113.5', project=self.project, insert_date=timezone.now())
        with mock.patch.dict(os.environ, {'CVENGINE_BUCKETS_GUESS': '1'}):
            found = self.collect()
        self.assertIn('s3:example-backup', found)
        self.assertIn('gcs:example-logs', found)
        self.assertTrue(all(c.tier == 'guess' and 'example' in c.name for c in found.values()))
        self.assertFalse([c for c in found.values() if 'jfrog' in c.name or 'acme' in c.name])
        self.assertLessEqual(len(found), 2 * 41 + 2)
        HostExclusion.objects.create(org=self.org, host='example-backup')
        with mock.patch.dict(os.environ, {'CVENGINE_BUCKETS_GUESS': '1'}):
            self.assertNotIn('s3:example-backup', self.collect())

    def test_guesses_can_be_turned_off(self):
        self.assertEqual(self.collect(), {})

    def test_a_full_endpoint_read_marks_the_reference_tier_incomplete(self):
        EndPoint.objects.create(target_domain=self.domain, http_url='https://ex-crawl.s3.amazonaws.com/a.png')
        with mock.patch.object(bs, 'ENDPOINT_LIMIT', 1):
            self.assertNotIn('reference', bs.collect(self.project.id)[1])
        self.assertIn('reference', bs.collect(self.project.id)[1])


class SweepTests(Fixture, TestCase):
    def setUp(self):
        super().setUp()
        self.host('static.example.test', cname='ex-static.s3.amazonaws.com')
        self.listing = Net(**{S3: xml(200, S3_LIST), S3_HEAD: Response(200)})

    def test_a_bucket_is_checked_once_per_window_then_again(self):
        self.assertEqual(self.sweep(self.listing)['checked'], 1)
        self.assertEqual(self.sweep()['checked'], 0)  # its ledger window has not run out
        self.assertEqual(len(self.listing.calls), 2)
        ServiceRun.objects.filter(service='buckets').update(finished_at=timezone.now() - timedelta(days=8))
        self.assertEqual(self.sweep()['checked'], 1)
        self.assertEqual(HygieneFinding.objects.count(), 1)  # the same finding, updated

    def test_the_window_is_a_week_by_default_and_can_be_set(self):
        from cveFeed import ledger
        self.assertEqual(ledger.ttl('buckets'), 7 * 24 * 3600)
        with mock.patch.dict(os.environ, {'CVENGINE_TTL_BUCKETS': '24'}):
            self.assertEqual(ledger.ttl('buckets'), 24 * 3600)

    def test_a_bucket_that_turns_private_resolves_its_finding_and_a_fixed_one_that_returns_reopens(self):
        self.sweep(self.listing)
        HygieneFinding.objects.update(remediation_status='fixed', remediation_note='blocked public access')
        self.expire()
        self.sweep(Net(**{S3: xml(403, S3_DENIED)}))
        found = self.finding('static.example.test')
        self.assertEqual((found.status, found.remediation_status), ('resolved', 'fixed'))
        self.assertIsNotNone(found.resolved_at)
        self.assertEqual(ProbeObservation.objects.get(probe='storage-bucket').outcome, 'hidden')
        self.expire()
        self.sweep(self.listing)  # a regression
        found = self.finding('static.example.test')
        self.assertEqual((found.status, found.remediation_status), ('open', 'open'))
        self.assertIn('Reopened', found.remediation_note)

    def test_resolving_is_idempotent(self):
        self.sweep(self.listing)
        self.expire()
        private = Net(**{S3: xml(403, S3_DENIED)})
        self.sweep(private)
        first = self.finding('static.example.test').resolved_at
        self.expire()
        self.sweep(private)
        self.assertEqual(self.finding('static.example.test').resolved_at, first)
        self.assertEqual(HygieneFinding.objects.count(), 1)

    def test_a_dangling_cname_that_is_removed_resolves_its_takeover(self):
        self.sweep(Net(**{S3: xml(404, S3_NOSUCH)}))
        self.assertEqual(self.finding('static.example.test', 'bkt_takeover').status, 'open')
        self.host('static.example.test', cname='')  # the record was deleted: the right fix
        self.sweep()
        self.assertEqual(self.finding('static.example.test', 'bkt_takeover').status, 'resolved')

    def test_a_check_that_got_no_answer_changes_nothing_and_is_not_repeated_at_once(self):
        self.sweep(self.listing)
        self.expire()
        self.assertEqual(self.sweep(Net(**{S3: OSError('timed out')}))['unknown'], 1)
        self.assertEqual(self.finding('static.example.test').status, 'open')
        self.assertEqual(ServiceRun.objects.filter(service='buckets-failed').count(), 1)
        self.assertEqual(self.sweep()['checked'], 0)  # tomorrow, not the next sweep

    def test_a_failure_leaves_no_provider_text_in_the_log_or_the_activity_feed(self):
        from cveFeed.models import AgentActivity
        with self.assertLogs('cveFeed.bucket_probe', level='INFO') as logs:
            self.sweep(Net(**{S3: OSError('secret provider text 203.0.113.9')}))
        self.assertNotIn('203.0.113.9', ' '.join(logs.output))
        self.assertFalse(AgentActivity.objects.filter(message__contains='203.0.113.9').exists())

    def test_nothing_is_requested_while_scanning_is_paused(self):
        with mock.patch('reNgine.resources.global_pause_requested', return_value=True):
            out = self.sweep(self.listing)
        self.assertIn('paused', out['skipped'])
        self.assertEqual((self.listing.calls, ServiceRun.objects.count()), ([], 0))

    def test_a_pause_that_starts_mid_sweep_stops_it(self):
        self.host('b.example.test', cname='ex-b.s3.amazonaws.com')
        answers = iter([False, True, True])
        with mock.patch('reNgine.resources.global_pause_requested', side_effect=lambda **kw: next(answers)):
            out = self.sweep(self.listing)
        self.assertEqual((out['checked'], 'paused' in out['skipped']), (1, True))

    def test_a_host_excluded_while_the_sweep_runs_is_not_requested(self):
        HostExclusion.objects.create(org=self.org, host='static.example.test')
        out = self.sweep(self.listing)
        self.assertEqual((out['checked'], self.listing.calls), (0, []))

    def test_an_exclusion_made_after_the_candidates_were_read_still_stops_the_request(self):
        real = bs.collect

        def collect_then_exclude(project_id):
            found = real(project_id)
            HostExclusion.objects.create(org=self.org, host='static.example.test')  # an operator excludes the host while the sweep runs
            return found
        with mock.patch.object(bs, 'collect', collect_then_exclude):
            out = self.sweep(self.listing)
        self.assertEqual((out['checked'], self.listing.calls), (0, []))

    def test_an_excluded_domain_name_is_never_a_candidate_for_guesses(self):
        HostExclusion.objects.create(org=self.org, host='example.test', include_subdomains=True)
        with mock.patch.dict(os.environ, {'CVENGINE_BUCKETS_GUESS': '1'}):
            self.assertEqual(self.sweep(self.listing)['checked'], 0)
        self.assertEqual(self.listing.calls, [])

    def test_a_project_whose_bounty_engagement_has_not_confirmed_automated_testing_is_skipped(self):
        program = BountyProgram.objects.create(platform='hackerone', handle='ex', name='Example')
        BountyEngagement.objects.create(project=self.project, program=program, status='active', automated_ok=False)
        out = self.sweep(self.listing)
        self.assertIn('automated testing', out['skipped'])
        self.assertEqual(self.listing.calls, [])

    def test_the_sweep_can_be_turned_off(self):
        with mock.patch.dict(os.environ, {'CVENGINE_BUCKETS': '0'}):
            self.assertIn('turned off', self.sweep(self.listing)['skipped'])
            self.assertIn('turned off', bs.sweep_all(fetch=self.listing)['skipped'])
        self.assertEqual(self.listing.calls, [])

    def test_each_sweep_is_capped_per_project_strongest_tier_first_and_the_rest_waits(self):
        self.host('b.example.test', cname='ex-b.s3.amazonaws.com')
        with mock.patch.dict(os.environ, {'CVENGINE_BUCKETS_MAX_PER_SWEEP': '1', 'CVENGINE_BUCKETS_GUESS': '1'}):
            self.assertEqual(self.sweep(self.listing)['checked'], 1)
            self.assertEqual(self.sweep()['checked'], 1)
            self.assertEqual(self.sweep()['checked'], 1)
        assets = sorted(r.asset for r in ServiceRun.objects.filter(service='buckets'))
        self.assertEqual(len(assets), 3)  # the two buckets of the project's own hosts came before any name guess; the third sweep began on the guesses
        self.assertEqual([a for a in assets if 'example' not in a], ['s3:ex-b', 's3:ex-static'])

    def test_every_request_of_a_sweep_is_a_get_or_head_to_a_documented_storage_endpoint(self):
        from urllib.parse import urlsplit
        self.host('b.example.test', cname='ex-b.s3.amazonaws.com')
        self.host('files.example.test', cname='exstore.blob.core.windows.net')
        self.host('assets.example.test', cname='c.storage.googleapis.com')
        with mock.patch.dict(os.environ, {'CVENGINE_BUCKETS_GUESS': '1'}):
            self.sweep(self.listing)
            self.expire()
            self.sweep()
        self.assertGreater(len(self.net.calls), 5)
        for method, url in self.net.calls:
            self.assertIn(method, ('GET', 'HEAD'))
            parts = urlsplit(url)
            self.assertEqual((parts.scheme, parts.port), ('https', None), url)
            self.assertTrue(bp.endpoint_allowed(parts.hostname), url)
        self.assertFalse([u for _m, u in self.net.calls if 'example.test/' in u.split('?')[0] and 'amazonaws' not in u and 'googleapis' not in u and 'windows' not in u])

    def test_a_project_is_swept_by_one_worker_at_a_time(self):
        with mock.patch('reNgine.resources.redis_claim') as claim:
            claim.return_value.__enter__.return_value = 'another worker'
            out = self.sweep(self.listing)
        self.assertIn('another bucket sweep', out['skipped'])
        self.assertEqual(self.listing.calls, [])

    def test_the_daily_sweep_goes_through_every_project_and_one_sweep_at_a_time(self):
        with mock.patch('cveFeed.ledger.sweep_claim', return_value=True):  # the real key lives in Redis for hours: a test must not depend on it
            out = bs.sweep_all(fetch=self.listing, dns=self.dns)
        self.assertEqual((out['checked'], out['public']), (1, 1))
        with mock.patch('cveFeed.ledger.sweep_claim', return_value=False):
            self.assertIn('another sweep', bs.sweep_all(fetch=self.listing)['skipped'])

    def test_run_hygiene_leaves_these_findings_alone(self):
        self.sweep(self.listing)
        out = hygiene.run_hygiene(self.domain.id, probe=lambda host, port: None, emailer=lambda name: ([], []), mx=lambda n, t: False)
        self.assertIsNotNone(out)
        self.assertEqual(self.finding('static.example.test').status, 'open')


class FindingPathTests(TestCase):
    """The findings are ordinary hygiene findings: the existing API, roles and remediation workflow apply unchanged."""

    @classmethod
    def setUpTestData(cls):
        now = timezone.now()
        org, other = Org.objects.create(name='BK', slug='bk-org'), Org.objects.create(name='BK2', slug='bk-org-2')
        cls.proj = Project.objects.create(name='BK Project', slug='bk-proj', insert_date=now, org=org)
        cls.other = Project.objects.create(name='BK Other', slug='bk-other', insert_date=now, org=other)
        cls.domain = Domain.objects.create(name='bk.example', project=cls.proj, insert_date=now)
        mk = lambda n: User.objects.create_user(n, password='x')
        cls.alice, cls.carol, cls.mallory = mk('bkalice'), mk('bkcarol'), mk('bkmallory')
        ProjectMembership.objects.create(user=cls.alice, project=cls.proj, role='user')
        ProjectMembership.objects.create(user=cls.carol, project=cls.proj, role='audit')
        ProjectMembership.objects.create(user=cls.mallory, project=cls.other, role='user')
        cls.t_alice, cls.t_carol, cls.t_mallory = (create_token(u, 'agent')[1] for u in (cls.alice, cls.carol, cls.mallory))
        cls.row = HygieneFinding.objects.create(domain=cls.domain, host='bk-assets.s3.amazonaws.com', check_name='bkt_listing', severity=2,
                                                title='AWS S3 bucket bk-assets lists its objects to anyone (name guess, ownership unconfirmed)',
                                                evidence={'tier': 'guess'})

    def test_members_read_it_and_other_organizations_cannot(self):
        path = f'/api/v1/projects/bk-proj/findings/hygiene/{self.row.id}'
        status, data = call(self.t_carol, 'GET', path)
        self.assertEqual(status, 200)
        self.assertIn('bk-assets', json.dumps(data))
        self.assertIn(call(self.t_mallory, 'GET', path)[0], (403, 404))
        status, listing = call(self.t_alice, 'GET', '/api/v1/projects/bk-proj/hygiene?check=bkt_')
        self.assertEqual((status, [r['check'] for r in listing['results']]), (200, ['bkt_listing']))
        self.assertIn(call(self.t_mallory, 'GET', '/api/v1/projects/bk-proj/hygiene?check=bkt_')[0], (403, 404))

    def test_remediation_status_works_and_an_auditor_cannot_change_it(self):
        path = f'/api/v1/projects/bk-proj/findings/hygiene/{self.row.id}'
        status, data = call(self.t_alice, 'PATCH', path, {'status': 'accepted_risk', 'note': 'not our bucket'})
        self.assertEqual((status, data['remediation_status']), (200, 'accepted_risk'))
        self.assertEqual(call(self.t_carol, 'PATCH', path, {'status': 'fixed'})[0], 403)
        self.assertIn(call(self.t_mallory, 'PATCH', path, {'status': 'fixed'})[0], (403, 404))
