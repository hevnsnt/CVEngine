"""Shodan-style RDP login-screen capture: for a server nmap already confirmed is RDP and showed will accept a connection
without Network Level Authentication (``cveFeed.service_intel.rdp_without_nla``), take one screenshot of the
pre-authentication screen and ask the configured AI model to read who, if anyone, it shows signed in.

This is never attempted against a server that requires NLA: CredSSP must complete, with real credentials, before the
server sends any graphical frame, so there is nothing to capture and nothing is guessed. ``aardwolf`` (a headless,
pure-Python RDP client) connects with the "none" auth method, which sends no credentials at all, and the capture is
discarded unless it is a real, non-blank frame. The username the AI reads back is not a secret; it is exactly what the
screen already shows to anyone who can reach the port.

The capture is bounded (connect timeout, a short wait for the frame, a hard wall-clock cap), one per host and port per
window (the service ledger, ``CVENGINE_TTL_RDP_SHOT``), and runs in its own thread so the asyncio event loop it needs
never touches the gevent hub the Celery worker runs on.
"""
import concurrent.futures
import io
import json
import logging
import os
import re

from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

SERVICE = 'rdp-shot'
CONNECT_TIMEOUT = 8      # seconds to complete the RDP security and MCS handshake
SCREEN_WAIT = 5          # seconds to let the server paint its pre-authentication screen once connected
VIDEO_WIDTH, VIDEO_HEIGHT = 1024, 768
MAX_IMAGE_BYTES = 4 * 1024 * 1024
MAX_HOSTS_PER_SCAN = 10  # a screenshot is comparatively expensive (a live RDP session plus an AI call); bound it per scan

VISION_SYSTEM = ('You read unauthenticated screenshots of Windows Remote Desktop (RDP) login screens for a security '
                  'scanner. Reply with exactly one line of JSON and nothing else.')
VISION_PROMPT = (
    'This screenshot was captured before any credentials were sent, by a scanner that never attempted to sign in. Say '
    'whether the screen plainly shows an account already signed in or mid sign-in (not just a username field waiting to '
    'be typed into), and what that account is called exactly as shown. Reply with exactly one JSON object: '
    '{"signed_in": true or false, "username": "", "description": ""}. "username" is empty unless "signed_in" is true. '
    '"description" is one short, factual sentence about what the screen shows. Never invent a name that is not visible, '
    'and never suggest or attempt a password.')
_JSON_RE = re.compile(r'\{.*\}', re.DOTALL)


def rdp_shot_timeout():
    try:
        return max(1, int(os.environ.get('CVENGINE_TTL_RDP_SHOT', 24)))
    except ValueError:
        return 24


def max_hosts():
    try:
        return max(1, int(os.environ.get('CVENGINE_RDP_SHOT_MAX_HOSTS', MAX_HOSTS_PER_SCAN)))
    except ValueError:
        return MAX_HOSTS_PER_SCAN


def enabled():
    return os.environ.get('CVENGINE_RDP_SHOT', '1').strip().lower() not in ('0', 'false', 'no', 'off')


def available():
    try:
        import aardwolf  # noqa: F401
    except ImportError:
        return False
    return True


async def _capture_async(host, port, wait):
    from aardwolf.commons.factory import RDPConnectionFactory
    from aardwolf.commons.iosettings import RDPIOSettings
    from aardwolf.commons.queuedata.constants import VIDEO_FORMAT

    io_settings = RDPIOSettings()
    io_settings.video_width, io_settings.video_height = VIDEO_WIDTH, VIDEO_HEIGHT
    io_settings.video_bpp_min, io_settings.video_bpp_max = 15, 32
    io_settings.video_out_format = VIDEO_FORMAT.PNG
    io_settings.clipboard_use_pyperclip = False
    # "none": the same no-credentials handshake as "plain", for a server that does not insist on CredSSP (NLA).
    factory = RDPConnectionFactory.from_url(f'rdp+none://{host}:{port}', io_settings)
    connection = factory.get_connection(io_settings)
    try:
        _, err = await connection.connect()
        if err is not None:
            raise err
        import asyncio
        await asyncio.sleep(wait)
        if not connection.desktop_buffer_has_data:
            return None
        image = connection.get_desktop_buffer(VIDEO_FORMAT.PIL)
        buf = io.BytesIO()
        image.save(buf, 'PNG')
        return buf.getvalue()
    finally:
        try:
            await connection.terminate()
        except Exception:  # noqa: BLE001 - teardown must never mask or replace a real capture
            pass


def capture(host, port, connect_timeout=CONNECT_TIMEOUT, wait=SCREEN_WAIT):
    """PNG bytes of the server's pre-authentication screen, no credentials sent, or ``None`` if it never painted
    anything within the wait. Raises on a connection or protocol error. Runs its own asyncio loop on a dedicated thread
    (never the calling gevent greenlet), with a hard wall-clock cap on top of the connect and paint timeouts."""
    import asyncio

    def run():
        return asyncio.run(_capture_async(host, port, wait))
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(run).result(timeout=connect_timeout + wait + 15)


def is_meaningful(png_bytes):
    """False for an empty or single flat color capture (a timing miss or a server that sent nothing to look at), so a
    blank frame is never stored or sent to the AI model."""
    try:
        from PIL import Image
        with Image.open(io.BytesIO(png_bytes)) as image:
            extrema = image.convert('L').getextrema()
        return extrema[0] != extrema[1]
    except Exception:  # noqa: BLE001 - an unreadable image is not a meaningful one
        return False


def save_image(scan, address, port, png_bytes):
    """Write the capture under this scan's media directory, the same Shodan-style layout as the web screenshot, and
    return ``(path relative to MEDIA_ROOT, difference hash)``."""
    from cveFeed import shots
    dest_dir = os.path.join(settings.MEDIA_ROOT, f'{scan.domain.name}_{scan.id}', 'rdp')
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, f'{address.replace(":", "_")}_{port}.png')
    with open(dest, 'wb') as f:
        f.write(png_bytes)
    return os.path.relpath(dest, settings.MEDIA_ROOT), shots.dhash_file(dest)


def _parse_vision_reply(text):
    match = _JSON_RE.search(text or '')
    if not match:
        return None
    try:
        obj = json.loads(match.group(0))
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    signed_in = bool(obj.get('signed_in'))
    return {'logged_in_user': str(obj.get('username') or '')[:300] if signed_in else '',
            'summary': str(obj.get('description') or '')[:500]}


def read_logged_in_user(png_bytes):
    """Ask the configured AI model what the login screen shows. Returns ``{'summary', 'logged_in_user'}`` or
    ``{'error'}``. Never raises: a model that is unconfigured, lacks vision, or answers oddly is reported, not fatal."""
    from reNgine.ai_providers import AIProviderError, usage_stage
    from reNgine.ai_settings import get_configured_provider
    try:
        provider = get_configured_provider()
    except AIProviderError as e:
        return {'error': str(e)}
    if provider is None:
        return {'error': 'No AI model is configured'}
    try:
        with usage_stage('rdp_screenshot'):
            reply = provider.complete_vision(VISION_SYSTEM, VISION_PROMPT, png_bytes)
    except AIProviderError as e:
        return {'error': str(e)}
    parsed = _parse_vision_reply(reply)
    if parsed is None:
        return {'error': 'the AI model did not answer in the expected format'}
    return parsed


def rdp_candidates(scan):
    """``[(Subdomain, address, port number)]`` for this scan's open ports that nmap showed accept RDP without NLA."""
    from cveFeed import service_intel
    from startScan.models import Subdomain, open_ports
    out = []
    for sub in Subdomain.objects.filter(scan_history=scan).prefetch_related('ip_addresses__ports'):
        for ip in sub.ip_addresses.all():
            for port in open_ports(ip):
                if service_intel.is_rdp_port(port) and service_intel.rdp_without_nla(port):
                    out.append((sub, ip.address, port.number))
    return out


def run_for_scan(scan_id, capturer=capture, reader=read_logged_in_user, force=False):
    """Screenshot every confirmed, NLA-free RDP server this scan found, store the image, and have the AI read who it
    shows signed in. A capture or read failure is recorded and never raised; it leaves any previous screenshot in
    place. Returns a summary dict."""
    from cveFeed import ledger
    from cveFeed.models import RdpScreenshot
    from startScan.models import ScanHistory
    if not enabled():
        return {'attempted': 0, 'skipped': 'disabled'}
    if capturer is capture and not available():
        return {'attempted': 0, 'skipped': 'aardwolf is not installed'}
    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
    project = scan.domain.project_id
    candidates = rdp_candidates(scan)
    if not candidates:
        return {'attempted': 0}
    assets = [f'{addr}:{port}' for _sub, addr, port in candidates]
    covered = set() if force else ledger.fresh(SERVICE, assets, project)
    todo = [(sub, addr, port) for (sub, addr, port), asset in zip(candidates, assets) if asset not in covered][:max_hosts()]
    attempted = captured = read_ok = 0
    for sub, addr, port in todo:
        attempted += 1
        asset = f'{addr}:{port}'
        try:
            png = capturer(addr, port)
        except Exception as exc:  # noqa: BLE001 - one bad target must never interrupt the scan
            logger.info('rdp screenshot failed for %s: %s', asset, exc)
            ledger.record(SERVICE, [asset], project, scan, 'failed')
            continue
        if not png or len(png) > MAX_IMAGE_BYTES or not is_meaningful(png):
            ledger.record(SERVICE, [asset], project, scan, 'failed')
            continue
        rel_path, image_hash = save_image(scan, addr, port, png)
        captured += 1
        ai = reader(png)
        RdpScreenshot.objects.update_or_create(
            project_id=project, host=sub.name, port=port,
            defaults={'domain_id': scan.domain_id, 'address': addr, 'image_path': rel_path, 'image_hash': image_hash,
                      'logged_in_user': ai.get('logged_in_user', ''), 'ai_summary': ai.get('summary', ''),
                      'ai_error': ai.get('error', ''), 'captured_at': timezone.now()})
        if 'error' not in ai:
            read_ok += 1
        if ai.get('logged_in_user'):
            _record_logged_in_finding(scan, sub, addr, port, ai)
        ledger.record(SERVICE, [asset], project, scan)
    return {'attempted': attempted, 'captured': captured, 'read': read_ok, 'reused': len(covered)}


def _record_logged_in_finding(scan, sub, address, port, ai):
    """An informational finding when the screen shows an account already signed in: notable (an idle session, or a
    screen someone forgot to lock), but not itself the vulnerability (the NLA finding already covers that)."""
    from reNgine.tasks import save_vulnerability
    username = ai['logged_in_user']
    save_vulnerability(
        target_domain=scan.domain, scan_history=scan, subdomain=sub, http_url=f'rdp://{address}:{port}',
        name='RDP login screen shows a signed-in account', severity=0, source='rdp-screenshot',
        template_id='rdp-screenshot-signed-in', type='rdp',
        description=f'The RDP login screen was captured without sending any credentials, and shows "{username}" already '
                    f'signed in. {ai.get("summary", "")}'.strip(),
        remediation='Lock or sign out idle sessions, and keep RDP off the internet behind a VPN or gateway.',
        tags=['rdp', 'screenshot'])
