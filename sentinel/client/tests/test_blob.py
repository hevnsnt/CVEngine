import base64
import unittest

from client import blob


class DecodeBlobTests(unittest.TestCase):
    def test_round_trips_a_real_payload(self):
        payload = {'enrollment_token': 'senr_abc123', 'server_url': 'https://cve.example.test',
                   'expires_at': '2030-01-01T00:00:00Z', 'project': 'demo'}
        encoded = blob.encode_blob(payload)
        self.assertEqual(blob.decode_blob(encoded), payload)

    def test_is_standard_base64_with_no_custom_framing(self):
        payload = {'enrollment_token': 'senr_xyz', 'server_url': 'https://cve.example.test'}
        encoded = blob.encode_blob(payload)
        # What a reader of agentapi.sentinel_broker.encode_enrollment_blob gets is exactly standard base64 of compact
        # JSON: decoding it with nothing but the standard library proves there is no extra framing either side adds.
        self.assertEqual(__import__('json').loads(base64.b64decode(encoded)), payload)

    def test_rejects_empty_or_missing_blob(self):
        for bad in (None, '', '   ', 42, []):
            with self.assertRaises(blob.BlobError):
                blob.decode_blob(bad)

    def test_rejects_invalid_base64(self):
        with self.assertRaises(blob.BlobError):
            blob.decode_blob('not valid base64 at all !!!')

    def test_rejects_base64_that_is_not_json(self):
        garbage = base64.b64encode(b'not json').decode()
        with self.assertRaises(blob.BlobError):
            blob.decode_blob(garbage)

    def test_rejects_json_that_is_not_an_object(self):
        not_an_object = base64.b64encode(b'"just a string"').decode()
        with self.assertRaises(blob.BlobError):
            blob.decode_blob(not_an_object)

    def test_rejects_an_object_missing_required_fields(self):
        missing_server_url = base64.b64encode(b'{"enrollment_token": "senr_x"}').decode()
        with self.assertRaises(blob.BlobError):
            blob.decode_blob(missing_server_url)

    def test_the_error_message_never_contains_the_raw_blob(self):
        # The blob may itself be (or contain) a live secret; a BlobError must never echo it back, e.g. into a log line.
        secret_looking_blob = 'senr_super_secret_value_that_must_never_be_logged'
        try:
            blob.decode_blob(secret_looking_blob)
            self.fail('expected a BlobError')
        except blob.BlobError as exc:
            self.assertNotIn(secret_looking_blob, str(exc))


if __name__ == '__main__':
    unittest.main()
