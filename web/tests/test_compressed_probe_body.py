"""Regression tests: the route probe decodes bodies compressed despite an identity request."""

import gzip
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from django.test import SimpleTestCase

from tests import library_http

PAGE = (
    b"<html><head><title>Packed Page</title></head>"
    b"<body><p>Printer Model X100</p></body></html>"
)
LARGE_PAGE = PAGE + b"A" * (80 * 1024)


def _raw_deflate(data):
    comp = zlib.compressobj(wbits=-15)
    return comp.compress(data) + comp.flush()


ROUTES = {
    "/gz": ("gzip", gzip.compress(PAGE)),
    "/zl": ("deflate", zlib.compress(PAGE)),
    "/raw": ("deflate", _raw_deflate(PAGE)),
    "/large": ("gzip", gzip.compress(LARGE_PAGE)),
    "/broken": ("gzip", b"definitely not gzip"),
    "/none": ("gzip", b""),
}


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        route = ROUTES.get(self.path)
        if route is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        encoding, payload = route
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Encoding", encoding)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def log_message(self, format, *args):
        pass


class CompressedProbeBodyTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        super().tearDownClass()

    def setUp(self):
        library_http.allow_loopback(self)

    def _url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def test_supported_encodings_are_decoded(self):
        for path in ("/gz", "/zl", "/raw"):
            with self.subTest(path=path):
                result = library_http.probe_url(self._url(path))
                self.assertEqual(result["title"], "Packed Page")
                self.assertIn("Printer Model", result["body"])
                self.assertEqual(result["bytes"], len(result["body"].encode("utf-8")))

    def test_large_body_is_capped_after_decoding(self):
        result = library_http.probe_url(self._url("/large"))
        cap = library_http.http.ROUTE_SAMPLE_BYTES
        self.assertEqual(result["title"], "Packed Page")
        self.assertEqual(result["bytes"], cap)
        self.assertEqual(len(result["body"]), cap)

    def test_corrupt_stream_raises_value_error(self):
        with self.assertRaisesRegex(ValueError, "invalid compressed probe response"):
            library_http.probe_url(self._url("/broken"))

    def test_empty_compressed_body_is_empty_text(self):
        result = library_http.probe_url(self._url("/none"))
        self.assertEqual(result["body"], "")
