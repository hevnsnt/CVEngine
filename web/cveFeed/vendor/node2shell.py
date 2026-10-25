# Vendored, trimmed copy of the detection core of assetnote/node2shell-scanner, MIT licensed:
#   https://github.com/assetnote/node2shell-scanner/blob/bf2dc38797f262d11e8c630b3fcc6a013a70da97/scanner.py
# Credit: Assetnote Security Research Team (https://www.assetnote.io/). Not modified except to remove the CLI
# (argparse, colored terminal output, file I/O, the tqdm progress bar) so only check_vulnerability() and what it
# calls remain; the detection logic itself (the bytes it sends, the comparisons it makes) is unchanged.
#
# "node2shell scanner for CVE-2026-111497." Sends a few small, deliberately malformed or encoded POST bodies plus
# one large (about 23 MB) Brotli-encoded body to learn whether the target's HTTP handling reaches the same response
# class for the large body as for an ordinary small one; a target is reported vulnerable only when that holds and
# two control requests establish distinct, stable response classes first. No command is ever executed and no
# credential is ever sent; see cveFeed.node2shell_scan for how and when CVEngine runs this.
"""node2shell scanner for CVE-2026-111497 (detection core only; see the header above)."""

import asyncio
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import SplitResult, quote, urlsplit, urlunsplit

import h11

CVE = "CVE-2026-111497"
VALID_EMPTY_BROTLI = bytes.fromhex("3b")
MALFORMED_BROTLI = bytes.fromhex("ff")
UNSUPPORTED_BODY = b"x"
PROBE_REPETITIONS = (1 << 21) - 1
PROBE_PREFIX = bytes.fromhex(
    "8b000046a440861f6aaf2f0409414a104902a57a74f8fdaf473dea518f7ad4a31e"
)
PROBE_UNIT = bytes.fromhex("f5a8473dea518f7ad4a31e")
PROBE_SUFFIX = bytes.fromhex(
    "528fe2072020202020202020202020202020202020202020202020202020202020"
    "2020202020202020202020202020202020202020202020202020202020202020"
    "2020202003"
)
PROBE_BYTES = 23_068_764
RESPONSE_LIMIT = 1 << 20
EVIDENCE_LIMIT = 2048
CONNECT_TIMEOUT = 10
EXPECT_CONTINUE_TIMEOUT = 1
UPLOAD_CHUNK_SIZE = 64 << 10
READ_BUFFER_HIGH_WATER = 256 << 10
READ_BUFFER_LOW_WATER = 64 << 10
WRITE_BUFFER_HIGH_WATER = 256 << 10
WRITE_BUFFER_LOW_WATER = 64 << 10
MAX_RESPONSE_HEADER_BYTES = 10 << 20
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 "
    "Safari/537.36 Node2Shell/1.0.0"
)
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
}

assert (
    len(PROBE_PREFIX) + len(PROBE_UNIT) * PROBE_REPETITIONS + len(PROBE_SUFFIX)
    == PROBE_BYTES
)


@dataclass
class HTTPResult:
    status_code: Optional[int] = None
    reason: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    bytes_sent: int = 0
    responded: bool = False
    truncated: bool = False
    error: Optional[str] = None

    @property
    def content_type(self) -> str:
        return header_value(self.headers, "Content-Type")

    @property
    def powered_by(self) -> str:
        return header_value(self.headers, "X-Powered-By")


@dataclass
class ConnectionEnd:
    error: Optional[Exception]


class HTTPTransportError(Exception):
    """Raised when a well-formed HTTP exchange cannot be completed."""


class DuplexHTTPProtocol(asyncio.Protocol):
    def __init__(self) -> None:
        self.transport: Optional[asyncio.Transport] = None
        self.incoming = asyncio.Queue()
        self.writable = asyncio.Event()
        self.writable.set()
        self.buffered_bytes = 0
        self.reading_paused = False
        self.ended = False
        self.end_error: Optional[Exception] = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        transport.set_write_buffer_limits(  # type: ignore[attr-defined]
            high=WRITE_BUFFER_HIGH_WATER,
            low=WRITE_BUFFER_LOW_WATER,
        )

    def data_received(self, data: bytes) -> None:
        if not data:
            return
        self.buffered_bytes += len(data)
        self.incoming.put_nowait(data)
        if (
            self.buffered_bytes >= READ_BUFFER_HIGH_WATER
            and not self.reading_paused
            and self.transport is not None
        ):
            self.transport.pause_reading()
            self.reading_paused = True

    def eof_received(self) -> Optional[bool]:
        self.finish(None)
        return False

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self.finish(exc)

    def pause_writing(self) -> None:
        self.writable.clear()

    def resume_writing(self) -> None:
        self.writable.set()

    def finish(self, error: Optional[Exception]) -> None:
        if self.ended:
            return
        self.ended = True
        self.end_error = error
        self.writable.set()
        self.incoming.put_nowait(ConnectionEnd(error))

    async def write(self, data: bytes) -> None:
        await self.writable.wait()
        if self.ended or self.transport is None:
            raise self.end_error or BrokenPipeError("connection closed while uploading")
        self.transport.write(data)
        await asyncio.sleep(0)

    async def read(self) -> bytes:
        item = await self.incoming.get()
        if isinstance(item, ConnectionEnd):
            if item.error is not None:
                raise item.error
            return b""

        self.buffered_bytes -= len(item)
        if (
            self.reading_paused
            and self.buffered_bytes <= READ_BUFFER_LOW_WATER
            and self.transport is not None
            and not self.ended
        ):
            self.transport.resume_reading()
            self.reading_paused = False
        return item

    def abort(self) -> None:
        if self.transport is not None:
            self.transport.abort()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def header_value(headers: Dict[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return ""


def remove_header(headers: Dict[str, str], name: str) -> None:
    for key in list(headers):
        if key.lower() == name.lower():
            del headers[key]


def normalize_url(raw_url: str) -> str:
    value = raw_url.strip()
    if not value:
        raise ValueError("invalid or empty URL")
    if "://" not in value:
        value = "https://" + value
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
        raise ValueError("invalid HTTP URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(
            "credentials in URLs are not supported; use an Authorization header"
        )
    _ = parsed.port  # Validate the port before scanning.
    return urlunsplit(
        (parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.query, "")
    )


def safe_url_label(raw_url: str) -> str:
    value = raw_url.strip()
    candidate = value if "://" in value else "https://" + value
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return "<invalid URL>"
    if not parsed.netloc:
        return "<invalid URL>"
    return urlunsplit(
        (parsed.scheme, parsed.netloc.rsplit("@", 1)[-1], parsed.path, parsed.query, "")
    )


def replace_path(target_url: str, path_value: str) -> str:
    target = urlsplit(target_url)
    custom = urlsplit(path_value if path_value.startswith("/") else "/" + path_value)
    return urlunsplit(
        (target.scheme, target.netloc, custom.path or "/", custom.query, "")
    )


def request_target(parsed: SplitResult) -> bytes:
    path = quote(
        parsed.path or "/",
        safe="/%:@!$&'()*+,;=-._~",
        encoding="utf-8",
        errors="strict",
    )
    if parsed.query:
        path += "?" + quote(
            parsed.query,
            safe="/?%:@!$&'()*+,;=-._~",
            encoding="utf-8",
            errors="strict",
        )
    return path.encode("ascii")


def host_header(parsed: SplitResult) -> str:
    if parsed.hostname is None:
        raise ValueError("target URL does not contain a hostname")
    hostname = parsed.hostname.encode("idna").decode("ascii")
    if ":" in hostname:
        hostname = f"[{hostname}]"
    if parsed.port is not None:
        hostname += f":{parsed.port}"
    return hostname


def request_headers(
    custom_headers: Dict[str, str],
    content_encoding: str,
    content_type: Optional[str],
    expect_continue: bool,
) -> Dict[str, str]:
    headers = dict(custom_headers)
    for name in (
        "Accept-Encoding",
        "Content-Encoding",
        "Content-Length",
        "Content-Type",
        "Expect",
        "Transfer-Encoding",
    ):
        remove_header(headers, name)
    if not header_value(headers, "User-Agent"):
        headers["User-Agent"] = DEFAULT_USER_AGENT
    headers["Accept-Encoding"] = "identity"
    headers["Content-Encoding"] = content_encoding
    if content_type is not None:
        headers["Content-Type"] = content_type
    if expect_continue:
        headers["Expect"] = "100-continue"
    return headers


def wire_headers(
    parsed: SplitResult, headers: Dict[str, str], content_length: int
) -> List[Tuple[bytes, bytes]]:
    supplied_host = header_value(headers, "Host")
    encoded = [(b"Host", (supplied_host or host_header(parsed)).encode("latin-1"))]
    for name, value in headers.items():
        if name.lower() != "host":
            encoded.append((name.encode("ascii"), value.encode("latin-1")))
    encoded.append((b"Content-Length", str(content_length).encode("ascii")))
    return encoded


def response_headers(raw_headers: List[Tuple[bytes, bytes]]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    names: Dict[str, str] = {}
    for raw_name, raw_value in raw_headers:
        name = raw_name.decode("ascii")
        value = raw_value.decode("latin-1")
        lowered = name.lower()
        if lowered in names:
            headers[names[lowered]] += ", " + value
        else:
            names[lowered] = name
            headers[name] = value
    return headers


def fixed_body_chunks(body: bytes) -> Iterable[bytes]:
    yield body


def probe_chunks() -> Iterable[bytes]:
    yield PROBE_PREFIX
    repetitions_per_chunk = max(1, UPLOAD_CHUNK_SIZE // len(PROBE_UNIT))
    block = PROBE_UNIT * repetitions_per_chunk
    full_chunks, remaining = divmod(PROBE_REPETITIONS, repetitions_per_chunk)
    for _ in range(full_chunks):
        yield block
    if remaining:
        yield PROBE_UNIT * remaining
    yield PROBE_SUFFIX


async def upload_body(
    connection: h11.Connection,
    protocol: DuplexHTTPProtocol,
    chunks: Iterable[bytes],
    continue_event: asyncio.Event,
    expect_continue: bool,
    result: HTTPResult,
) -> None:
    if expect_continue:
        try:
            await asyncio.wait_for(
                continue_event.wait(), timeout=EXPECT_CONTINUE_TIMEOUT
            )
        except asyncio.TimeoutError:
            pass

    for chunk in chunks:
        data = connection.send(h11.Data(data=chunk))
        if data:
            await protocol.write(data)
        result.bytes_sent += len(chunk)
    data = connection.send(h11.EndOfMessage())
    if data:
        await protocol.write(data)


async def read_response(
    connection: h11.Connection,
    protocol: DuplexHTTPProtocol,
    continue_event: asyncio.Event,
    result: HTTPResult,
) -> None:
    body = bytearray()
    while True:
        event = connection.next_event()
        if event is h11.NEED_DATA:
            connection.receive_data(await protocol.read())
            continue
        if event is h11.PAUSED:
            raise HTTPTransportError("unexpected additional HTTP response")
        if isinstance(event, h11.InformationalResponse):
            if event.status_code == 100:
                continue_event.set()
            elif event.status_code == 101:
                raise HTTPTransportError("HTTP protocol upgrades are not supported")
            continue
        if isinstance(event, h11.Response):
            result.responded = True
            result.status_code = event.status_code
            result.reason = event.reason.decode("latin-1")
            result.headers = response_headers(list(event.headers))
            continue
        if isinstance(event, h11.Data):
            if not result.responded:
                raise HTTPTransportError(
                    "received response body before response headers"
                )
            remaining = RESPONSE_LIMIT - len(body)
            body.extend(event.data[: max(0, remaining)])
            if len(event.data) > remaining:
                result.body = bytes(body)
                result.truncated = True
                return
            continue
        if isinstance(event, h11.EndOfMessage):
            if not result.responded:
                raise HTTPTransportError("response ended before response headers")
            result.body = bytes(body)
            return
        if isinstance(event, h11.ConnectionClosed):
            raise HTTPTransportError("connection closed before the response completed")


async def exchange_post(
    target_url: str,
    chunks: Iterable[bytes],
    content_length: int,
    headers: Dict[str, str],
    verify_ssl: bool,
    expect_continue: bool,
    result: HTTPResult,
) -> None:
    parsed = urlsplit(target_url)
    if parsed.hostname is None:
        raise ValueError("target URL does not contain a hostname")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    options = {}
    if parsed.scheme == "https":
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(["http/1.1"])
        if not verify_ssl:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        options = {
            "ssl": context,
            "server_hostname": parsed.hostname,
            "ssl_handshake_timeout": CONNECT_TIMEOUT,
        }

    loop = asyncio.get_running_loop()
    transport, base_protocol = await asyncio.wait_for(
        loop.create_connection(
            DuplexHTTPProtocol,
            host=parsed.hostname,
            port=port,
            happy_eyeballs_delay=0.25,
            **options,
        ),
        timeout=CONNECT_TIMEOUT,
    )
    protocol = base_protocol
    if not isinstance(protocol, DuplexHTTPProtocol):
        transport.abort()
        raise HTTPTransportError("failed to initialize HTTP transport")

    upload_task = None
    try:
        connection = h11.Connection(
            h11.CLIENT, max_incomplete_event_size=MAX_RESPONSE_HEADER_BYTES
        )
        request = h11.Request(
            method=b"POST",
            target=request_target(parsed),
            headers=wire_headers(parsed, headers, content_length),
        )
        data = connection.send(request)
        if data:
            await protocol.write(data)

        continue_event = asyncio.Event()
        if not expect_continue:
            continue_event.set()
        upload_task = asyncio.create_task(
            upload_body(
                connection,
                protocol,
                chunks,
                continue_event,
                expect_continue,
                result,
            )
        )
        await read_response(connection, protocol, continue_event, result)
    finally:
        if upload_task is not None:
            if not upload_task.done():
                upload_task.cancel()
            await asyncio.gather(upload_task, return_exceptions=True)
        protocol.abort()


def send_post(
    target_url: str,
    chunks: Iterable[bytes],
    content_length: int,
    content_encoding: str,
    content_type: Optional[str],
    custom_headers: Dict[str, str],
    timeout: int,
    verify_ssl: bool,
    expect_continue: bool = False,
) -> HTTPResult:
    result = HTTPResult()
    headers = request_headers(
        custom_headers, content_encoding, content_type, expect_continue
    )
    try:
        asyncio.run(
            asyncio.wait_for(
                exchange_post(
                    target_url,
                    chunks,
                    content_length,
                    headers,
                    verify_ssl,
                    expect_continue,
                    result,
                ),
                timeout=timeout,
            )
        )
    except ssl.SSLError as exc:
        result.error = f"SSL error: {exc}"
    except asyncio.TimeoutError:
        result.error = "request timed out"
    except h11.RemoteProtocolError as exc:
        result.error = f"response read failed: {exc}"
    except (
        h11.LocalProtocolError,
        HTTPTransportError,
        ValueError,
        UnicodeError,
    ) as exc:
        result.error = f"request failed: {exc}"
    except OSError as exc:
        result.error = f"connection error: {exc}"
    return result


def same_exact(left: HTTPResult, right: HTTPResult) -> bool:
    return (
        left.error is None
        and right.error is None
        and not left.truncated
        and not right.truncated
        and left.status_code == right.status_code
        and left.content_type.casefold() == right.content_type.casefold()
        and left.body == right.body
    )


def matches(left: HTTPResult, right: HTTPResult, comparison: str) -> bool:
    if comparison == "status":
        return (
            left.error is None
            and right.error is None
            and left.status_code == right.status_code
        )
    return same_exact(left, right)


def redact_header(name: str, value: str) -> str:
    return "<redacted>" if name.lower() in SENSITIVE_HEADERS else value


def response_dump(response: HTTPResult) -> Optional[str]:
    if response.status_code is None:
        return None
    lines = [f"HTTP/1.1 {response.status_code} {response.reason}".rstrip()]
    lines.extend(
        f"{name}: {redact_header(name, value)}"
        for name, value in response.headers.items()
    )
    excerpt = response.body[:EVIDENCE_LIMIT].decode("utf-8", errors="replace")
    return "\r\n".join(lines) + "\r\n\r\n" + excerpt


def response_metadata(response: HTTPResult) -> dict:
    return {
        "status_code": response.status_code,
        "content_type": response.content_type or None,
        "response_bytes": len(response.body),
        "response_truncated": response.truncated,
        "bytes_sent": response.bytes_sent,
        "error": response.error,
    }


def request_evidence(target_url: str, custom_headers: Dict[str, str]) -> dict:
    return {
        "method": "POST",
        "url": target_url,
        "headers": {
            name: redact_header(name, value) for name, value in custom_headers.items()
        },
        "controls": [
            "ff (Content-Encoding: br; no Content-Type)",
            "3b (Content-Encoding: br; Content-Type: application/json)",
            "ff (Content-Encoding: br; Content-Type: application/json)",
            "x (Content-Encoding: x; Content-Type: application/json)",
        ],
        "probe": {
            "content_encoding": "br",
            "content_type": "application/json",
            "content_length": PROBE_BYTES,
            "expect": "100-continue",
        },
    }


def base_result(host: str) -> dict:
    return {
        "host": host,
        "vulnerable": None,
        "verdict": "ERROR",
        "status_code": None,
        "error": None,
        "reason": None,
        "comparison": None,
        "powered_by": None,
        "request": None,
        "response": None,
        "responses": {},
        "tested_url": None,
        "timestamp": utc_now(),
    }


def scan_url(
    host: str,
    target_url: str,
    timeout: int,
    verify_ssl: bool,
    custom_headers: Dict[str, str],
) -> dict:
    result = base_result(host)
    result["tested_url"] = target_url
    result["request"] = request_evidence(target_url, custom_headers)

    def record(name: str, response: HTTPResult) -> HTTPResult:
        result["responses"][name] = response_metadata(response)
        result["status_code"] = response.status_code
        result["response"] = response_dump(response)
        if response.powered_by and not result["powered_by"]:
            result["powered_by"] = response.powered_by
        return response

    def finish(vulnerable: Optional[bool], verdict: str, reason: str) -> dict:
        result["vulnerable"] = vulnerable
        result["verdict"] = verdict
        result["reason"] = reason
        result["error"] = reason if vulnerable is None else None
        return result

    def failed(stage: str, response: HTTPResult) -> Optional[dict]:
        if response.error:
            return finish(
                None,
                "INCONCLUSIVE",
                f"{stage} request failed: {response.error}",
            )
        return None

    bypass = record(
        "content_type_bypass",
        send_post(
            target_url,
            fixed_body_chunks(MALFORMED_BROTLI),
            len(MALFORMED_BROTLI),
            "br",
            None,
            custom_headers,
            timeout,
            verify_ssl,
        ),
    )
    if failure := failed("content-type bypass", bypass):
        return failure

    valid = record(
        "valid_empty_brotli",
        send_post(
            target_url,
            fixed_body_chunks(VALID_EMPTY_BROTLI),
            len(VALID_EMPTY_BROTLI),
            "br",
            "application/json",
            custom_headers,
            timeout,
            verify_ssl,
        ),
    )
    if failure := failed("valid Brotli control", valid):
        return failure
    if bypass.status_code != valid.status_code:
        return finish(
            False,
            "NO SIGNAL",
            "content-type bypass and valid Brotli controls returned different statuses",
        )

    malformed = record(
        "malformed_brotli",
        send_post(
            target_url,
            fixed_body_chunks(MALFORMED_BROTLI),
            len(MALFORMED_BROTLI),
            "br",
            "application/json",
            custom_headers,
            timeout,
            verify_ssl,
        ),
    )
    if failure := failed("malformed Brotli control", malformed):
        return failure

    if valid.status_code != malformed.status_code:
        comparison = "status"
    elif same_exact(bypass, valid) and not same_exact(valid, malformed):
        comparison = "exact-response"
    else:
        return finish(
            False,
            "NO SIGNAL",
            "the controls did not establish distinct route and malformed-Brotli response classes",
        )
    result["comparison"] = comparison

    unsupported = record(
        "unsupported_encoding",
        send_post(
            target_url,
            fixed_body_chunks(UNSUPPORTED_BODY),
            len(UNSUPPORTED_BODY),
            "x",
            "application/json",
            custom_headers,
            timeout,
            verify_ssl,
        ),
    )
    if failure := failed("unsupported encoding control", unsupported):
        return failure
    if matches(unsupported, valid, comparison):
        return finish(
            False,
            "NO SIGNAL",
            "the unsupported encoding control matched the route response class",
        )

    probe = record(
        "cve_probe",
        send_post(
            target_url,
            probe_chunks(),
            PROBE_BYTES,
            "br",
            "application/json",
            custom_headers,
            timeout,
            verify_ssl,
            expect_continue=True,
        ),
    )
    if failure := failed("CVE probe", probe):
        return failure
    if probe.bytes_sent != PROBE_BYTES:
        return finish(
            False,
            "NO SIGNAL",
            f"the probe was not fully uploaded ({probe.bytes_sent}/{PROBE_BYTES} bytes)",
        )

    final_valid = record(
        "final_valid_empty_brotli",
        send_post(
            target_url,
            fixed_body_chunks(VALID_EMPTY_BROTLI),
            len(VALID_EMPTY_BROTLI),
            "br",
            "application/json",
            custom_headers,
            timeout,
            verify_ssl,
        ),
    )
    if failure := failed("final valid Brotli control", final_valid):
        return failure
    if not matches(valid, final_valid, comparison):
        return finish(
            False,
            "NO SIGNAL",
            "the route response class changed after the probe",
        )

    if matches(probe, valid, comparison):
        return finish(
            True,
            "VULNERABLE",
            f"the {PROBE_BYTES}-byte {CVE} probe reached the learned route response class",
        )
    if matches(probe, malformed, comparison):
        return finish(
            False,
            "NO SIGNAL",
            "the probe reached the malformed-Brotli response class",
        )
    return finish(
        False,
        "NO SIGNAL",
        "the probe matched neither learned response class",
    )


def check_vulnerability(
    host: str,
    timeout: int = 60,
    verify_ssl: bool = True,
    custom_headers: Optional[Dict[str, str]] = None,
    paths: Optional[List[str]] = None,
) -> dict:
    display_host = safe_url_label(host)
    try:
        normalized = normalize_url(host)
    except ValueError as exc:
        result = base_result(display_host)
        result["error"] = str(exc)
        result["reason"] = str(exc)
        return result

    targets = (
        [replace_path(normalized, path) for path in paths] if paths else [normalized]
    )
    fallback: Optional[dict] = None
    for target_url in targets:
        result = scan_url(
            normalized,
            target_url,
            timeout,
            verify_ssl,
            custom_headers or {},
        )
        if result["vulnerable"] is True:
            return result
        if fallback is None or result["vulnerable"] is None:
            fallback = result
    return fallback or base_result(normalized)
